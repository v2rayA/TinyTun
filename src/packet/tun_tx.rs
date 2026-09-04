use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use log::warn;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::packet::shared::TUN_WRITE_ENQUEUE_TIMEOUT;

/// Number of parallel TUN writers.  More writers increase parallelism but also
/// increase the chance of out-of-order writes for the same flow if routing is
/// not deterministic.  We hash by flow key so each flow maps to one writer.
const TUN_WRITER_COUNT: usize = 4;
/// Capacity of each per-writer input channel.
const TUN_WRITER_QUEUE_CAPACITY: usize = 512;

/// A multi-channel TUN packet transmitter.
///
/// Reverse-path packets are spread across several `tokio::task`s that each
/// own one half of a split `mpsc` channel.  A packet is routed to a writer
/// based on a flow hash (source/destination IP and ports when available) so
/// that packets belonging to the same flow are emitted in order.
#[derive(Clone)]
pub struct TunPacketTx {
    writers: Arc<Vec<mpsc::Sender<Vec<u8>>>>,
}

impl TunPacketTx {
    /// Create a new multi-writer transmitter backed by a single TUN device.
    pub fn new(tun_writer: Arc<tun_rs::AsyncDevice>) -> Self {
        let mut writers = Vec::with_capacity(TUN_WRITER_COUNT);

        for _ in 0..TUN_WRITER_COUNT {
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(TUN_WRITER_QUEUE_CAPACITY);
            let writer = tun_writer.clone();
            tokio::spawn(async move {
                while let Some(packet) = rx.recv().await {
                    if let Err(err) = writer.send(&packet).await {
                        warn!("Failed to write packet to TUN from writer queue: {}", err);
                    }
                }
            });
            writers.push(tx);
        }

        Self {
            writers: Arc::new(writers),
        }
    }

    /// Send a raw packet to the TUN device.
    ///
    /// The packet must be a valid IPv4 or IPv6 packet; ports are extracted from
    /// the transport header when present to keep flow affinity.
    pub async fn send(&self, packet: Vec<u8>) -> Result<()> {
        let idx = Self::packet_writer_index(&packet);
        match timeout(TUN_WRITE_ENQUEUE_TIMEOUT, self.writers[idx].send(packet)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(anyhow::anyhow!(
                "failed to enqueue packet for TUN write: {}",
                err
            )),
            Err(_) => Err(anyhow::anyhow!("timed out enqueuing packet for TUN write")),
        }
    }

    /// Send a packet whose routing key is already known (e.g. from a flow key).
    ///
    /// This avoids re-parsing the IP/transport header when the caller already
    /// has the 4-tuple.
    pub async fn send_with_hash(
        &self,
        packet: Vec<u8>,
        src: IpAddr,
        dst: IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<()> {
        let idx = Self::flow_writer_index(src, dst, src_port, dst_port);
        match timeout(TUN_WRITE_ENQUEUE_TIMEOUT, self.writers[idx].send(packet)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(anyhow::anyhow!(
                "failed to enqueue packet for TUN write: {}",
                err
            )),
            Err(_) => Err(anyhow::anyhow!("timed out enqueuing packet for TUN write")),
        }
    }

    /// Pick a writer for a raw IP packet.
    fn packet_writer_index(packet: &[u8]) -> usize {
        if packet.len() < 20 {
            return 0;
        }

        let version = packet[0] >> 4;
        match version {
            4 if packet.len() >= 20 => {
                let header_len = ((packet[0] & 0x0f) as usize) * 4;
                if packet.len() >= header_len + 4 {
                    let src =
                        std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                    let dst =
                        std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                    let protocol = packet[9];
                    let (src_port, dst_port) = Self::extract_ports(packet, header_len, protocol);
                    Self::flow_writer_index(IpAddr::V4(src), IpAddr::V4(dst), src_port, dst_port)
                } else {
                    Self::hash_ipv4_only(packet)
                }
            }
            6 if packet.len() >= 40 => {
                let src = std::net::Ipv6Addr::from([
                    packet[8], packet[9], packet[10], packet[11], packet[12], packet[13],
                    packet[14], packet[15], packet[16], packet[17], packet[18], packet[19],
                    packet[20], packet[21], packet[22], packet[23],
                ]);
                let dst = std::net::Ipv6Addr::from([
                    packet[24], packet[25], packet[26], packet[27], packet[28], packet[29],
                    packet[30], packet[31], packet[32], packet[33], packet[34], packet[35],
                    packet[36], packet[37], packet[38], packet[39],
                ]);
                let protocol = packet[6];
                let (src_port, dst_port) = Self::extract_ports(packet, 40, protocol);
                Self::flow_writer_index(IpAddr::V6(src), IpAddr::V6(dst), src_port, dst_port)
            }
            _ => Self::hash_bytes(packet),
        }
    }

    fn extract_ports(packet: &[u8], header_len: usize, protocol: u8) -> (u16, u16) {
        let transport = &packet[header_len.min(packet.len())..];
        if (protocol == 6 || protocol == 17) && transport.len() >= 4 {
            let src_port = u16::from_be_bytes([transport[0], transport[1]]);
            let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
            (src_port, dst_port)
        } else {
            (0, 0)
        }
    }

    fn flow_writer_index(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        src.hash(&mut hasher);
        dst.hash(&mut hasher);
        src_port.hash(&mut hasher);
        dst_port.hash(&mut hasher);
        (hasher.finish() as usize) % TUN_WRITER_COUNT
    }

    fn hash_ipv4_only(packet: &[u8]) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        hasher.write(&packet[12..20]);
        (hasher.finish() as usize) % TUN_WRITER_COUNT
    }

    fn hash_bytes(packet: &[u8]) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        hasher.write(packet);
        (hasher.finish() as usize) % TUN_WRITER_COUNT
    }
}
