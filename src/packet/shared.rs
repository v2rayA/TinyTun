use std::collections::BTreeMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use crate::process_lookup::TransportProtocol;

// ── Named constants ─────────────────────────────────────────────────────────

/// IPv4 header (20) + TCP header (20) overhead.
pub const IPV4_TCP_HEADER_OVERHEAD: usize = 40;
/// IPv6 header (40) + TCP header (20) overhead.
pub const IPV6_TCP_HEADER_OVERHEAD: usize = 60;
/// Minimum TCP payload per packet (MTU-derived lower bound).
pub const MIN_TCP_PAYLOAD: usize = 256;
/// Maximum TCP payload per packet (MTU-derived upper bound).
pub const MAX_TCP_PAYLOAD: usize = 1460;
/// Default read buffer lower bound.
pub const READ_BUF_MIN: usize = 2048;
/// Default read buffer upper bound.
pub const READ_BUF_MAX: usize = 4096;
/// Default IPv4/IPv6 TTL for injected TCP packets.
pub const DEFAULT_TTL: u8 = 64;
/// Default TCP receive window for injected packets.
pub const DEFAULT_TCP_WINDOW: u16 = 65535;
/// Timeout for enqueuing a packet to the TUN writer channel.
pub const TUN_WRITE_ENQUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(5);
/// Maximum bytes in the TCP reorder buffer before it is cleared.
pub const TCP_REORDER_BUFFER_LIMIT: usize = 64 * 1024;

// ── Type definitions ────────────────────────────────────────────────────────

/// Parsed IP packet header information.
pub struct ParsedIpPacket {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub header_len: usize,
}

/// Key for looking up process information for a network flow.
#[derive(Clone, Debug, Eq)]
pub struct ProcessLookupKey {
    pub protocol: TransportProtocol,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl PartialEq for ProcessLookupKey {
    fn eq(&self, other: &Self) -> bool {
        self.protocol == other.protocol && self.src == other.src && self.dst == other.dst
    }
}

impl Hash for ProcessLookupKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.protocol.hash(state);
        self.src.hash(state);
        self.dst.hash(state);
    }
}

/// Entry in the process lookup cache.
#[derive(Clone, Debug)]
pub struct ProcessLookupEntry {
    pub process_name: Option<String>,
    pub recorded_at: Instant,
}

/// A TCP session with its state and forward channel.
pub struct TcpSession {
    pub state: Arc<tokio::sync::Mutex<TcpFlowState>>,
    /// Channel used to pass forward payloads to the per-session writer task,
    /// keeping the main packet loop non-blocking.
    pub forward_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

/// Key for identifying a UDP flow.
#[derive(Clone, Debug, Eq)]
pub struct UdpFlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl PartialEq for UdpFlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.src == other.src && self.dst == other.dst
    }
}

impl Hash for UdpFlowKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.src.hash(state);
        self.dst.hash(state);
    }
}

/// Entry in the UDP session table.
#[derive(Clone)]
pub struct UdpSessionEntry {
    pub session: Arc<tokio::sync::Mutex<crate::socks5_client::Socks5UdpSession>>,
    pub last_activity: Instant,
}

/// State of a TCP flow.
#[derive(Debug)]
pub struct TcpFlowState {
    pub client_next_seq: u32,
    pub server_next_seq: u32,
    pub server_acked_seq: u32,
    pub client_window: u16,
    pub reorder_buffer: BTreeMap<u32, Vec<u8>>,
    pub reorder_bytes: usize,
    pub lifecycle: TcpLifecycle,
    pub last_activity: Instant,
}

/// Lifecycle state of a TCP connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpLifecycle {
    SynReceived,
    Established,
    FinSent,
    Closed,
}

/// Key for identifying a TCP flow.
#[derive(Clone, Debug, Eq)]
pub struct FlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl PartialEq for FlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.src == other.src && self.dst == other.dst
    }
}

impl Hash for FlowKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.src.hash(state);
        self.dst.hash(state);
    }
}

// ── Pure utility functions ──────────────────────────────────────────────────

/// Compare TCP sequence numbers: returns `true` if `candidate` is at or after
/// `reference` in the TCP sequence space (handles wraparound).
pub fn seq_at_or_after(candidate: u32, reference: u32) -> bool {
    (candidate.wrapping_sub(reference) as i32) >= 0
}

/// Collect in-order TCP payload from a segment, buffering out-of-order data.
pub fn collect_in_order_payload(
    state: &mut TcpFlowState,
    seg_start: u32,
    payload: &[u8],
) -> Vec<u8> {
    let expected = state.client_next_seq;
    let seg_end = seg_start.wrapping_add(payload.len() as u32);

    if seq_at_or_after(expected, seg_end) {
        // Fully duplicate/retransmitted bytes.
        return Vec::new();
    }

    let mut trimmed_start = 0usize;
    if seq_at_or_after(expected, seg_start) {
        trimmed_start = expected.wrapping_sub(seg_start) as usize;
    }

    if trimmed_start >= payload.len() {
        return Vec::new();
    }

    let normalized_seq = seg_start.wrapping_add(trimmed_start as u32);
    let normalized = payload[trimmed_start..].to_vec();

    if normalized_seq != expected {
        // Cache out-of-order segment and wait for gap fill.
        let keep_new = match state.reorder_buffer.get(&normalized_seq) {
            Some(existing) => normalized.len() > existing.len(),
            None => true,
        };

        if keep_new {
            if let Some(existing) = state.reorder_buffer.insert(normalized_seq, normalized.clone()) {
                state.reorder_bytes = state.reorder_bytes.saturating_sub(existing.len());
            }
            state.reorder_bytes = state.reorder_bytes.saturating_add(normalized.len());
        }

        if state.reorder_bytes > TCP_REORDER_BUFFER_LIMIT {
            // Bound memory under packet loss/reordering storms.
            state.reorder_buffer.clear();
            state.reorder_bytes = 0;
        }

        return Vec::new();
    }

    let mut out = normalized;
    state.client_next_seq = state.client_next_seq.wrapping_add(out.len() as u32);

    while let Some(next_chunk) = state.reorder_buffer.remove(&state.client_next_seq) {
        state.reorder_bytes = state.reorder_bytes.saturating_sub(next_chunk.len());
        state.client_next_seq = state.client_next_seq.wrapping_add(next_chunk.len() as u32);
        out.extend_from_slice(&next_chunk);
    }

    out
}

/// Extract the DNS transaction ID from a raw DNS payload.
pub fn dns_txid(payload: &[u8]) -> Option<u16> {
    if payload.len() >= 2 {
        Some(u16::from_be_bytes([payload[0], payload[1]]))
    } else {
        None
    }
}

/// Normalize a DNS response to match the original query's transaction ID.
pub fn normalize_dns_response_for_query(query: &[u8], mut response: Vec<u8>) -> Vec<u8> {
    if query.len() >= 2 && response.len() >= 2 {
        // Force transaction id to match original captured request.
        response[0] = query[0];
        response[1] = query[1];
    }

    if response.len() >= 4 {
        // Ensure QR=1 (response), keep the rest of flags from upstream.
        response[2] |= 0x80;
    }

    response
}

/// Build a DNS SERVFAIL response for a given query.
pub fn build_dns_servfail_response(query: &[u8]) -> Vec<u8> {
    let mut resp = Vec::with_capacity(query.len().max(12));

    let txid = if query.len() >= 2 {
        [query[0], query[1]]
    } else {
        [0x00, 0x00]
    };

    let qdcount = if query.len() >= 6 {
        u16::from_be_bytes([query[4], query[5]])
    } else {
        0
    };

    // Header: QR=1, RD copied, RA=1, RCODE=2(SERVFAIL)
    let rd = if query.len() >= 3 { query[2] & 0x01 } else { 0 };
    let flags_hi = 0x80 | rd;
    let flags_lo = 0x80 | 0x02;

    resp.extend_from_slice(&txid);
    resp.push(flags_hi);
    resp.push(flags_lo);
    resp.extend_from_slice(&qdcount.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    if qdcount > 0 && query.len() > 12 {
        // Echo original question section so client can correlate the failure quickly.
        resp.extend_from_slice(&query[12..]);
    }

    resp
}

/// Check whether a UDP destination is proxyable (not multicast, link-local, etc.).
pub fn is_proxyable_udp_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_multicast()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4 == Ipv4Addr::new(255, 255, 255, 255))
        }
        IpAddr::V6(v6) => {
            !(v6.is_multicast()
                || v6.is_unicast_link_local()
                || v6.is_unspecified())
        }
    }
}
