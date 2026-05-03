use anyhow::Result;
use etherparse::PacketBuilder;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::packet::shared::{
    FlowKey, DEFAULT_TCP_WINDOW, DEFAULT_TTL, TUN_WRITE_ENQUEUE_TIMEOUT,
};

/// Build a TCP/IP packet with the given parameters.
///
/// Returns `None` when the address family is mixed (e.g. IPv4 src + IPv6 dst),
/// which should never happen in normal operation.
pub fn build_tcp_packet(
    flow_key: &FlowKey,
    sequence_number: u32,
    acknowledgment_number: u32,
    window: u16,
    syn: bool,
    fin: bool,
    rst: bool,
    psh: bool,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let mut builder = match (flow_key.dst.ip(), flow_key.src.ip()) {
        (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
            PacketBuilder::ipv4(dst.octets(), src.octets(), DEFAULT_TTL)
                .tcp(flow_key.dst.port(), flow_key.src.port(), sequence_number, window)
                .ack(acknowledgment_number)
        }
        (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
            PacketBuilder::ipv6(dst.octets(), src.octets(), DEFAULT_TTL)
                .tcp(flow_key.dst.port(), flow_key.src.port(), sequence_number, window)
                .ack(acknowledgment_number)
        }
        _ => return None,
    };

    if syn {
        builder = builder.syn();
    }
    if fin {
        builder = builder.fin();
    }
    if rst {
        builder = builder.rst();
    }
    if psh {
        builder = builder.psh();
    }

    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    if builder.write(&mut packet, payload).is_err() {
        return None;
    }
    Some(packet)
}

/// Build and enqueue a TCP control packet (SYN, FIN, RST, or pure ACK).
pub async fn inject_tcp_control(
    tun_packet_tx: &mpsc::Sender<Vec<u8>>,
    flow_key: &FlowKey,
    sequence_number: u32,
    acknowledgment_number: u32,
    syn: bool,
    fin: bool,
    rst: bool,
) -> Result<()> {
    let packet = build_tcp_packet(
        flow_key,
        sequence_number,
        acknowledgment_number,
        DEFAULT_TCP_WINDOW,
        syn,
        fin,
        rst,
        false,
        &[],
    )
    .ok_or_else(|| {
        anyhow::anyhow!(
            "mixed address family in TCP control packet for flow {:?}",
            flow_key
        )
    })?;

    enqueue_tun_packet_with_timeout(tun_packet_tx.clone(), packet)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "failed to enqueue tcp control packet for TUN write: {}",
                err
            )
        })?;
    Ok(())
}

/// Write a packet to the TUN device via the channel.
pub async fn write_tun_packet_with(
    tun_packet_tx: mpsc::Sender<Vec<u8>>,
    packet: Vec<u8>,
) -> Result<()> {
    enqueue_tun_packet_with_timeout(tun_packet_tx, packet).await
}

/// Enqueue a packet for TUN write with a timeout.
pub async fn enqueue_tun_packet_with_timeout(
    tun_packet_tx: mpsc::Sender<Vec<u8>>,
    packet: Vec<u8>,
) -> Result<()> {
    match timeout(TUN_WRITE_ENQUEUE_TIMEOUT, tun_packet_tx.send(packet)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(anyhow::anyhow!(
            "failed to enqueue packet for TUN write: {}",
            err
        )),
        Err(_) => Err(anyhow::anyhow!(
            "timed out enqueuing packet for TUN write"
        )),
    }
}
