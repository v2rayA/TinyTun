use std::hash::{Hash, Hasher};
use std::sync::Arc;

use anyhow::Result;
use log::{debug, error, info};
use tokio::sync::mpsc;
use tokio::time::{interval, MissedTickBehavior};

use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};

use crate::config::Config;
use crate::dns_router::DnsRouter;
use crate::packet;
use crate::packet::shared::ParsedIpPacket;
use crate::packet::tcp::TcpHandler;
use crate::packet::tun_tx::TunPacketTx;
use crate::packet::udp::UdpHandler;
use crate::socks5_client::Socks5Client;

#[derive(Clone)]
pub struct PacketProcessor {
    pub config: Arc<Config>,
    pub outbound_interface: Option<Arc<str>>,
    pub tcp_handler: Arc<TcpHandler>,
    pub udp_handler: Arc<UdpHandler>,
}

#[derive(Debug)]
enum PacketProcessError {
    TooShort,
    ParseError(String),
}

impl std::fmt::Display for PacketProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketProcessError::TooShort => write!(f, "packet too short"),
            PacketProcessError::ParseError(msg) => write!(f, "parse error: {}", msg),
        }
    }
}

impl std::error::Error for PacketProcessError {}

/// Per-packet task submitted to the worker pool.
///
/// The IP header is parsed once by the reader loop; workers reuse `parsed`
/// so the transport handlers do not re-parse it.
struct WorkerPacket {
    data: Vec<u8>,
    parsed: ParsedIpPacket,
}

impl PacketProcessor {
    const TCP_SESSION_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
    const DYNAMIC_BYPASS_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
    const UDP_SESSION_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
    const PROCESS_CACHE_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
    const PROCESS_CACHE_MAX_ENTRIES: usize = 1024;
    /// Capacity of each per-worker input queue.  A full queue creates back-pressure
    /// on the reader but does not block other workers.
    const WORKER_QUEUE_CAPACITY: usize = 1024;

    pub fn new(
        config: Config,
        tun_writer: Arc<tun_rs::AsyncDevice>,
        outbound_interface: Option<String>,
        enable_user_space_process_exclusion: bool,
    ) -> Result<Self> {
        let config = Arc::new(config);
        let outbound_interface_arc = outbound_interface.as_deref().map(Arc::<str>::from);
        let socks5_client = Arc::new(Socks5Client::new(
            config.socks5.clone(),
            outbound_interface.clone(),
        ));
        let dns_router = Arc::new(DnsRouter::new(
            config.dns.clone(),
            &config,
            outbound_interface.clone(),
        )?);
        let tun_packet_tx = TunPacketTx::new(tun_writer);

        let tcp_handler = Arc::new(TcpHandler::new(
            config.clone(),
            socks5_client.clone(),
            outbound_interface_arc.clone(),
            tun_packet_tx.clone(),
            enable_user_space_process_exclusion,
        ));

        let udp_handler = Arc::new(UdpHandler::new(
            config.clone(),
            socks5_client.clone(),
            dns_router.clone(),
            outbound_interface_arc.clone(),
            tun_packet_tx.clone(),
            enable_user_space_process_exclusion,
        ));

        Ok(Self {
            config,
            outbound_interface: outbound_interface_arc,
            tcp_handler,
            udp_handler,
        })
    }

    /// Expose the dynamic bypass IPs handle for use by the route manager
    /// during interface monitoring and shutdown cleanup.
    pub fn dynamic_bypass_ips_handle(
        &self,
    ) -> Arc<dashmap::DashMap<std::net::IpAddr, std::time::Instant>> {
        self.tcp_handler.dynamic_bypass_ips.clone()
    }

    pub async fn process_packets(&self, tun_reader: Arc<tun_rs::AsyncDevice>) -> Result<()> {
        info!("Starting packet processing");

        let mut buffer = vec![0; self.config.tun.mtu as usize];

        // Drive periodic maintenance with dedicated timers instead of
        // checking elapsed() on every packet in the hot path.
        let mut tcp_cleanup_tick = interval(Self::TCP_SESSION_CLEANUP_INTERVAL);
        let mut dynamic_cleanup_tick = interval(Self::DYNAMIC_BYPASS_CLEANUP_INTERVAL);
        let mut udp_cleanup_tick = interval(Self::UDP_SESSION_CLEANUP_INTERVAL);
        let mut process_cache_cleanup_tick = interval(Self::PROCESS_CACHE_CLEANUP_INTERVAL);

        tcp_cleanup_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        dynamic_cleanup_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        udp_cleanup_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        process_cache_cleanup_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Consume the first immediate tick so intervals match previous behavior
        // (first cleanup happens after the configured delay).
        tcp_cleanup_tick.tick().await;
        dynamic_cleanup_tick.tick().await;
        udp_cleanup_tick.tick().await;
        process_cache_cleanup_tick.tick().await;

        // Spawn a pool of packet workers.  The reader loop only reads from TUN
        // and dispatches packets; slow paths (process lookup, DNS resolution,
        // route installation, session setup) run inside workers and cannot
        // block the next TUN recv().
        let worker_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .max(2);

        let mut worker_txs = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let (tx, mut rx) = mpsc::channel::<WorkerPacket>(Self::WORKER_QUEUE_CAPACITY);
            let processor = self.clone();
            tokio::spawn(async move {
                while let Some(task) = rx.recv().await {
                    if let Err(e) = processor.process_packet(&task.data, &task.parsed).await {
                        error!("Error processing packet: {}", e);
                    }
                }
            });
            worker_txs.push(tx);
        }

        loop {
            tokio::select! {
                _ = tcp_cleanup_tick.tick() => {
                    self.tcp_handler.cleanup_expired_tcp_sessions().await;
                }
                _ = dynamic_cleanup_tick.tick() => {
                    packet::route::cleanup_expired_dynamic_bypass_routes(
                        &self.tcp_handler.dynamic_bypass_ips,
                        &self.config,
                    )
                    .await;
                }
                _ = udp_cleanup_tick.tick() => {
                    self.udp_handler.cleanup_expired_udp_sessions().await;
                }
                _ = process_cache_cleanup_tick.tick() => {
                    packet::bypass::cleanup_process_lookup_cache(
                        &self.tcp_handler.process_name_cache,
                        Self::PROCESS_CACHE_MAX_ENTRIES,
                    )
                    .await;
                }
                read_result = tun_reader.recv(&mut buffer) => {
                    let bytes_read = read_result?;

                    if bytes_read == 0 {
                        continue;
                    }

                    let packet = &buffer[..bytes_read];
                    let parsed = match Self::parse_ip_packet(packet) {
                        Ok(Some(p)) => p,
                        Ok(None) => continue,
                        Err(e) => {
                            error!("Error parsing packet: {}", e);
                            continue;
                        }
                    };

                    let worker_idx = Self::packet_worker_index(&parsed, packet, worker_count);
                    let task = WorkerPacket {
                        data: packet.to_vec(),
                        parsed,
                    };

                    if let Err(e) = worker_txs[worker_idx].send(task).await {
                        error!("Packet worker channel closed: {}", e);
                        return Err(anyhow::anyhow!("packet worker channel closed"));
                    }
                }
            }
        }
    }

    fn parse_ip_packet(packet: &[u8]) -> Result<Option<ParsedIpPacket>, PacketProcessError> {
        if packet.len() < 20 {
            return Err(PacketProcessError::TooShort);
        }

        let ip_version = packet[0] >> 4;
        let parsed = match ip_version {
            4 => {
                let ip_header = Ipv4HeaderSlice::from_slice(packet)
                    .map_err(|e| PacketProcessError::ParseError(e.to_string()))?;
                ParsedIpPacket {
                    src: ip_header.source_addr().into(),
                    dst: ip_header.destination_addr().into(),
                    protocol: ip_header.protocol().0,
                    header_len: (ip_header.ihl() as usize) * 4,
                }
            }
            6 => {
                if packet.len() < 40 {
                    return Err(PacketProcessError::TooShort);
                }

                let ip_header = Ipv6HeaderSlice::from_slice(packet)
                    .map_err(|e| PacketProcessError::ParseError(e.to_string()))?;
                ParsedIpPacket {
                    src: ip_header.source_addr().into(),
                    dst: ip_header.destination_addr().into(),
                    protocol: ip_header.next_header().0,
                    header_len: 40,
                }
            }
            _ => return Ok(None),
        };

        Ok(Some(parsed))
    }

    /// Pick a worker for a packet.
    ///
    /// TCP and UDP packets are routed by 4-tuple so that every packet of the
    /// same flow is handled by the same worker, preserving in-order processing.
    /// Non-transport packets are spread by destination IP.
    fn packet_worker_index(parsed: &ParsedIpPacket, packet: &[u8], worker_count: usize) -> usize {
        let transport = &packet[parsed.header_len.min(packet.len())..];
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        parsed.src.hash(&mut hasher);
        parsed.dst.hash(&mut hasher);

        match parsed.protocol {
            6 | 17 if transport.len() >= 4 => {
                let src_port = u16::from_be_bytes([transport[0], transport[1]]);
                let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
                src_port.hash(&mut hasher);
                dst_port.hash(&mut hasher);
            }
            _ => {}
        }

        (hasher.finish() as usize) % worker_count
    }

    async fn process_packet(
        &self,
        packet: &[u8],
        parsed: &ParsedIpPacket,
    ) -> Result<(), PacketProcessError> {
        // Check if we should skip this IP
        let dest_ip = parsed.dst;
        let is_transport = parsed.protocol == 6 || parsed.protocol == 17;
        let is_static_bypass = self.config.should_skip_ip(dest_ip);
        if is_static_bypass {
            // When an outbound interface is configured, TCP/UDP packets for
            // statically-bypassed IPs are forwarded transparently through the
            // physical NIC inside the protocol handlers rather than silently
            // dropped.  Non-TCP/UDP traffic and the no-interface case still
            // drop immediately (rely on routing to have excluded those flows).
            let can_direct = self.outbound_interface.is_some() && is_transport;
            if !can_direct {
                debug!("Skipping packet to {}", dest_ip);
                return Ok(());
            }
        }

        // Handle different protocols
        match parsed.protocol {
            6 => {
                self.tcp_handler
                    .handle_tcp_packet(packet, parsed, is_static_bypass)
                    .await
                    .map_err(|e| PacketProcessError::ParseError(e.to_string()))?;
                Ok(())
            }
            17 => {
                self.udp_handler
                    .handle_udp_packet(packet, parsed, is_static_bypass)
                    .await
                    .map_err(|e| PacketProcessError::ParseError(e.to_string()))?;
                Ok(())
            }
            _ => {
                debug!("Unsupported protocol number: {}", parsed.protocol);
                Ok(())
            }
        }
    }
}
