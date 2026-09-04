use std::io::ErrorKind;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::{DashMap, DashSet};
use log::{debug, warn};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use etherparse::{UdpHeader, UdpHeaderSlice};

use crate::config::Config;
use crate::dns_router::DnsRouter;
use crate::packet;
use crate::packet::shared::{
    ParsedIpPacket, ProcessLookupEntry, ProcessLookupKey, UdpFlowKey, UdpSessionEntry,
};
use crate::process_lookup::{ProcessLookupOptions, TransportProtocol};
use crate::socks5_client::{Socks5Client, Socks5UdpSession};

// ── Constants ─────────────────────────────────────────────────────────────────

const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const UDP_TIMEOUT_BACKOFF: Duration = Duration::from_secs(30);
const DNS_TASK_CONCURRENCY_LIMIT: usize = 32;
/// Upper bound on concurrently cached UDP ASSOCIATE sessions.  Each session
/// pins one TCP control connection and one UDP socket.
const UDP_MAX_SESSIONS: usize = 256;
/// Upper bound on concurrently cached direct (interface-bound) UDP sessions.
const DIRECT_UDP_MAX_SESSIONS: usize = 128;
/// Per-session receive buffer; sized for the largest possible UDP payload so a
/// datagram is never silently truncated.
const MAX_UDP_DATAGRAM_SIZE: usize = 65_536;

/// Entry in the direct (excluded-flow, interface-bound) UDP session table.
pub(crate) struct DirectUdpSessionEntry {
    /// Connected, interface-pinned UDP socket for the flow.
    socket: Arc<tokio::net::UdpSocket>,
    last_activity: Instant,
    /// Signals the per-session relay task to stop when the entry is removed.
    cancel: CancellationToken,
    /// Global session-count slot, held for the lifetime of the entry.
    _slot: Option<OwnedSemaphorePermit>,
}

// ── UdpHandler ────────────────────────────────────────────────────────────────

pub struct UdpHandler {
    pub config: Arc<Config>,
    pub socks5_client: Arc<Socks5Client>,
    pub dns_router: Arc<DnsRouter>,
    pub outbound_interface: Option<Arc<str>>,
    pub enable_user_space_process_exclusion: bool,
    pub tun_packet_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub udp_sessions: Arc<DashMap<UdpFlowKey, UdpSessionEntry>>,
    pub pending_udp_sessions: Arc<DashSet<UdpFlowKey>>,
    pub udp_timeout_backoff: Arc<DashMap<UdpFlowKey, Instant>>,
    pub udp_session_slots: Arc<Semaphore>,
    pub direct_udp_sessions: Arc<DashMap<UdpFlowKey, DirectUdpSessionEntry>>,
    pub direct_udp_session_slots: Arc<Semaphore>,
    pub dns_task_limiter: Arc<Semaphore>,
    pub process_name_cache: Arc<DashMap<ProcessLookupKey, ProcessLookupEntry>>,
    pub process_lookup_options: ProcessLookupOptions,
    pub dynamic_bypass_ips: Arc<DashMap<IpAddr, Instant>>,
}

impl UdpHandler {
    pub fn new(
        config: Arc<Config>,
        socks5_client: Arc<Socks5Client>,
        dns_router: Arc<DnsRouter>,
        outbound_interface: Option<Arc<str>>,
        tun_packet_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        enable_user_space_process_exclusion: bool,
    ) -> Self {
        let process_lookup_options = ProcessLookupOptions::from_config(&config);
        Self {
            config,
            socks5_client,
            dns_router,
            outbound_interface,
            enable_user_space_process_exclusion,
            tun_packet_tx,
            udp_sessions: Arc::new(DashMap::new()),
            pending_udp_sessions: Arc::new(DashSet::new()),
            udp_timeout_backoff: Arc::new(DashMap::new()),
            udp_session_slots: Arc::new(Semaphore::new(UDP_MAX_SESSIONS)),
            direct_udp_sessions: Arc::new(DashMap::new()),
            direct_udp_session_slots: Arc::new(Semaphore::new(DIRECT_UDP_MAX_SESSIONS)),
            dns_task_limiter: Arc::new(Semaphore::new(DNS_TASK_CONCURRENCY_LIMIT)),
            process_name_cache: Arc::new(DashMap::new()),
            process_lookup_options,
            dynamic_bypass_ips: Arc::new(DashMap::new()),
        }
    }

    pub async fn handle_udp_packet(
        &self,
        packet: &[u8],
        ip_packet: &ParsedIpPacket,
        is_static_bypass: bool,
    ) -> Result<()> {
        if packet.len() < ip_packet.header_len {
            return Err(anyhow::anyhow!("IP header length exceeds packet size"));
        }

        let udp_data = &packet[ip_packet.header_len..];

        if udp_data.len() < 8 {
            return Err(anyhow::anyhow!("UDP data too short"));
        }

        let udp_header = UdpHeaderSlice::from_slice(udp_data)?;
        let source_port = udp_header.source_port();
        let dest_port = udp_header.destination_port();

        // Check if we should skip this port
        if self.config.should_skip_port(dest_port) {
            debug!("Skipping UDP packet to port {}", dest_port);
            return Ok(());
        }

        let source_addr = std::net::SocketAddr::new(ip_packet.src, source_port);
        let target_addr = std::net::SocketAddr::new(ip_packet.dst, dest_port);

        if !packet::shared::is_proxyable_udp_destination(target_addr.ip()) {
            debug!(
                "Skipping local-scope UDP flow {}:{} -> {}:{}",
                ip_packet.src, source_port, ip_packet.dst, dest_port
            );
            return Ok(());
        }

        let is_direct_flow = if is_static_bypass {
            true
        } else if !self.enable_user_space_process_exclusion {
            false
        } else {
            packet::bypass::should_exclude_process_flow(
                &self.config,
                &self.process_name_cache,
                &self.process_lookup_options,
                TransportProtocol::Udp,
                source_addr,
                target_addr,
            )
            .await
        };

        if is_direct_flow {
            // ── Preferred path: direct UDP exchange via physical NIC ───────────
            // Socket-level interface binding is only available on Linux/macOS.
            // On other platforms this block is excluded at compile time and
            // execution falls through to the route-based bypass below.
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if let Some(iface) = self.outbound_interface.clone() {
                let udp_flow_key = UdpFlowKey {
                    src: source_addr,
                    dst: target_addr,
                };
                let udp_payload = udp_data[UdpHeader::LEN..].to_vec();

                // ── Fast path: reuse a cached direct session. ──────────────
                // The send is a non-blocking `try_send` on the connected
                // socket; responses arrive via the session's relay task.
                if let Some(mut entry) = self.direct_udp_sessions.get_mut(&udp_flow_key) {
                    entry.last_activity = Instant::now();
                    let socket = entry.socket.clone();
                    drop(entry);
                    if socket.try_send(&udp_payload).is_ok() {
                        return Ok(());
                    }
                    debug!(
                        "Direct UDP send failed for excluded flow {}:{} -> {}:{}",
                        ip_packet.src, source_port, ip_packet.dst, dest_port
                    );
                    return Ok(());
                }

                // ── Slow path: open a direct (interface-bound) session. ────
                let slot = match self.direct_udp_session_slots.clone().try_acquire_owned() {
                    Ok(slot) => slot,
                    Err(_) => {
                        match timeout(
                            Duration::from_millis(100),
                            self.direct_udp_session_slots.clone().acquire_owned(),
                        )
                        .await
                        {
                            Ok(Ok(slot)) => slot,
                            Ok(Err(_)) => {
                                debug!(
                                    "Dropping excluded UDP packet (session slot error) {}:{} -> {}:{}",
                                    ip_packet.src, source_port, ip_packet.dst, dest_port
                                );
                                return Ok(());
                            }
                            Err(_) => {
                                debug!(
                                    "Dropping excluded UDP packet (session limit, timed out waiting) {}:{} -> {}:{}",
                                    ip_packet.src, source_port, ip_packet.dst, dest_port
                                );
                                return Ok(());
                            }
                        }
                    }
                };

                let tun_packet_tx = self.tun_packet_tx.clone();
                let direct_udp_sessions = self.direct_udp_sessions.clone();
                let src_ip = ip_packet.src;
                let dst_ip = ip_packet.dst;

                tokio::spawn(async move {
                    let socket = match packet::direct::open_direct_udp(target_addr, &iface).await {
                        Ok(socket) => Arc::new(socket),
                        Err(err) => {
                            warn!(
                                "Open direct UDP failed for excluded flow {}:{} -> {}:{}: {}",
                                src_ip, source_port, dst_ip, dest_port, err
                            );
                            return;
                        }
                    };

                    let cancel = CancellationToken::new();
                    Self::spawn_direct_udp_relay_task(
                        socket.clone(),
                        udp_flow_key.clone(),
                        cancel.clone(),
                        tun_packet_tx,
                    );

                    direct_udp_sessions.insert(
                        udp_flow_key.clone(),
                        DirectUdpSessionEntry {
                            socket: socket.clone(),
                            last_activity: Instant::now(),
                            cancel,
                            _slot: Some(slot),
                        },
                    );

                    let _ = socket.try_send(&udp_payload);
                    debug!(
                        "Opened direct UDP session for excluded flow {}:{} -> {}:{} with {} bytes",
                        src_ip, source_port, dst_ip, dest_port, udp_payload.len()
                    );
                });

                debug!(
                    "{} UDP {}:{} -> {}:{}: direct forwarding via physical NIC",
                    if is_static_bypass {
                        "Static bypass"
                    } else {
                        "Excluded process"
                    },
                    ip_packet.src,
                    source_port,
                    ip_packet.dst,
                    dest_port
                );
                return Ok(());
            }

            // ── Fallback: no outbound interface or unsupported platform ─────────
            if is_static_bypass {
                debug!(
                    "Static bypass UDP {}:{} -> {}:{}: dropped (no outbound interface configured)",
                    ip_packet.src, source_port, ip_packet.dst, dest_port
                );
                return Ok(());
            }

            // ── Fallback: route-based bypass ───────────────────────────────────
            if self.config.tun.auto_route {
                if let Err(err) = packet::route::ensure_dynamic_bypass_for_ip(
                    &self.dynamic_bypass_ips,
                    &self.config,
                    &self.outbound_interface,
                    target_addr.ip(),
                )
                .await
                {
                    warn!(
                        "Failed to install dynamic bypass route for excluded UDP flow {}:{} -> {}:{}: {}",
                        ip_packet.src,
                        source_port,
                        ip_packet.dst,
                        dest_port,
                        err
                    );
                }
            }

            debug!(
                "Excluded process flow (UDP) {}:{} -> {}:{}: route-based bypass",
                ip_packet.src, source_port, ip_packet.dst, dest_port
            );
            return Ok(());
        }

        if dest_port == self.config.dns.listen_port {
            let dns_permit = match self.dns_task_limiter.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(100),
                        self.dns_task_limiter.clone().acquire_owned(),
                    )
                    .await
                    {
                        Ok(Ok(permit)) => permit,
                        Ok(Err(_)) => {
                            debug!(
                                "Dropping DNS packet (semaphore error) {}:{} -> {}:{}",
                                ip_packet.src, source_port, ip_packet.dst, dest_port
                            );
                            return Ok(());
                        }
                        Err(_) => {
                            debug!(
                                "Dropping DNS packet (rate limit, timed out waiting) {}:{} -> {}:{}",
                                ip_packet.src, source_port, ip_packet.dst, dest_port
                            );
                            return Ok(());
                        }
                    }
                }
            };

            let udp_payload = udp_data[UdpHeader::LEN..].to_vec();
            let dns_router = self.dns_router.clone();
            let tun_packet_tx = self.tun_packet_tx.clone();
            let src_ip = ip_packet.src;
            let dst_ip = ip_packet.dst;

            tokio::spawn(async move {
                let _permit = dns_permit;

                let dns_txid = packet::shared::dns_txid(&udp_payload);
                let response_payload = match dns_router.resolve(&udp_payload).await {
                    Ok(resp) => {
                        packet::shared::normalize_dns_response_for_query(&udp_payload, resp)
                    }
                    Err(err) => {
                        warn!(
                            "DNS forwarding failed for {}:{}: {}; returning spoofed SERVFAIL",
                            dst_ip, dest_port, err
                        );
                        packet::shared::build_dns_servfail_response(&udp_payload)
                    }
                };

                let response_packet = match packet::packet_build::build_udp_packet(
                    std::net::SocketAddr::new(dst_ip, dest_port),
                    std::net::SocketAddr::new(src_ip, source_port),
                    &response_payload,
                ) {
                    Some(packet) => packet,
                    None => return,
                };
                let response_len = response_packet.len();
                if packet::packet_build::write_tun_packet_with(&tun_packet_tx, response_packet)
                    .await
                    .is_err()
                {
                    return;
                }

                debug!(
                    "Captured DNS query txid={} for {}:{}; re-queried upstream and spoofed reply injected ({} bytes)",
                    dns_txid
                        .map(|id| format!("0x{:04x}", id))
                        .unwrap_or_else(|| "n/a".to_string()),
                    dst_ip,
                    dest_port,
                    response_len
                );
            });

            return Ok(());
        }

        let udp_payload = udp_data[UdpHeader::LEN..].to_vec();
        let udp_flow_key = UdpFlowKey {
            src: source_addr,
            dst: target_addr,
        };

        if self.is_udp_flow_in_backoff(&udp_flow_key) {
            debug!(
                "Skipping UDP proxy during backoff for {}:{} -> {}:{}",
                ip_packet.src, source_port, ip_packet.dst, dest_port
            );
            return Ok(());
        }

        // ── Fast path: reuse a cached UDP ASSOCIATE session. ───────────────
        // The send is a non-blocking `try_send_to`; responses are drained and
        // injected by the session's relay task, so no task is spawned and no
        // offer/response serialisation occurs on the packet hot path.
        if let Some(mut entry) = self.udp_sessions.get_mut(&udp_flow_key) {
            entry.last_activity = Instant::now();
            let session = entry.session.clone();
            drop(entry);
            Self::try_send_udp_frame(&session, udp_flow_key.dst, &udp_payload);
            return Ok(());
        }

        // ── Slow path: no cached session yet, open a UDP ASSOCIATE. ────────
        let slot = match self.udp_session_slots.clone().try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                match timeout(
                    Duration::from_millis(100),
                    self.udp_session_slots.clone().acquire_owned(),
                )
                .await
                {
                    Ok(Ok(slot)) => slot,
                    Ok(Err(_)) => {
                        debug!(
                            "Dropping UDP packet (session slot error) {}:{} -> {}:{}",
                            ip_packet.src, source_port, ip_packet.dst, dest_port
                        );
                        return Ok(());
                    }
                    Err(_) => {
                        debug!(
                            "Dropping UDP packet (session limit, timed out waiting) {}:{} -> {}:{}",
                            ip_packet.src, source_port, ip_packet.dst, dest_port
                        );
                        return Ok(());
                    }
                }
            }
        };

        let socks5_client = self.socks5_client.clone();
        let udp_sessions = self.udp_sessions.clone();
        let pending_udp_sessions = self.pending_udp_sessions.clone();
        let udp_timeout_backoff = self.udp_timeout_backoff.clone();
        let tun_packet_tx = self.tun_packet_tx.clone();
        let src_ip = ip_packet.src;
        let dst_ip = ip_packet.dst;

        tokio::spawn(async move {
            let pending_for_cleanup = pending_udp_sessions.clone();

            let session = match Self::open_udp_session_guarded(
                socks5_client,
                udp_sessions.clone(),
                pending_udp_sessions,
                udp_flow_key.clone(),
            )
            .await
            {
                Ok(session) => session,
                Err(err) => {
                    // The future may have been cancelled before it could clear
                    // its pending marker; sweep a stale entry if present.
                    pending_for_cleanup.remove(&udp_flow_key);
                    Self::mark_udp_flow_backoff_shared(
                        udp_timeout_backoff.clone(),
                        udp_flow_key.clone(),
                    );
                    warn!(
                        "UDP ASSOCIATE failed for {}:{} -> {}:{}: {}",
                        src_ip, source_port, dst_ip, dest_port, err
                    );
                    return;
                }
            };

            let cancel = CancellationToken::new();
            Self::spawn_udp_relay_task(
                session.udp_socket.clone(),
                udp_flow_key.clone(),
                cancel.clone(),
                tun_packet_tx,
            );

            udp_sessions.insert(
                udp_flow_key.clone(),
                UdpSessionEntry {
                    session: session.clone(),
                    last_activity: Instant::now(),
                    cancel,
                    _slot: Some(slot),
                },
            );

            Self::try_send_udp_frame(&session, udp_flow_key.dst, &udp_payload);
            debug!(
                "Opened UDP ASSOCIATE for {}:{} -> {}:{} with {} bytes",
                src_ip, source_port, dst_ip, dest_port, udp_payload.len()
            );
        });

        Ok(())
    }

    /// Fire-and-forget a datagram through the cached SOCKS5 UDP session.
    ///
    /// The relay frame is built here and pushed with `try_send_to` so the
    /// packet hot path never blocks.  A full kernel send buffer is treated as
    /// a dropped datagram, which is exactly how UDP is expected to behave.
    fn try_send_udp_frame(session: &Socks5UdpSession, target: std::net::SocketAddr, payload: &[u8]) {
        let frame = Socks5Client::build_udp_request(target, payload);
        match session.udp_socket.try_send_to(&frame, session.relay_addr) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                debug!(
                    "UDP relay send buffer full for {} -> {}; dropping datagram",
                    target, session.relay_addr
                );
            }
            Err(e) => {
                debug!(
                    "UDP relay send failed for {} -> {}: {}",
                    target, session.relay_addr, e
                );
            }
        }
    }

    /// Open a UDP ASSOCIATE session, guarding against concurrent creations for
    /// the same flow (each attempt pins a TCP control connection and a UDP
    /// socket, and on Windows abandoned socket pairs burn ephemeral ports).
    async fn open_udp_session_guarded(
        socks5_client: Arc<Socks5Client>,
        udp_sessions: Arc<DashMap<UdpFlowKey, UdpSessionEntry>>,
        pending_udp_sessions: Arc<DashSet<UdpFlowKey>>,
        flow_key: UdpFlowKey,
    ) -> Result<Arc<Socks5UdpSession>> {
        // A racing creation task may have won while this task waited for its
        // session slot; prefer the already-open session if present.
        if let Some(entry) = udp_sessions.get(&flow_key) {
            return Ok(entry.session.clone());
        }

        let is_already_pending = !pending_udp_sessions.insert(flow_key.clone());
        if is_already_pending {
            return Err(anyhow::anyhow!(
                "UDP ASSOCIATE already in progress for {} -> {}",
                flow_key.src,
                flow_key.dst
            ));
        }

        let result = socks5_client.open_udp_session(flow_key.dst).await;
        pending_udp_sessions.remove(&flow_key);
        Ok(result.map(Arc::new)?)
    }

    /// Spawn a relay task that continuously drains the session's UDP socket and
    /// injects each response back into the TUN as a packet from the flow target
    /// to the flow source.  Besides removing per-packet spawns, this also keeps
    /// unsolicited server->client datagrams (e.g. QUIC or games) instead of
    /// dropping them while no request is in flight.
    fn spawn_udp_relay_task(
        udp_socket: Arc<tokio::net::UdpSocket>,
        flow_key: UdpFlowKey,
        cancel: CancellationToken,
        tun_packet_tx: mpsc::Sender<Vec<u8>>,
    ) {
        tokio::spawn(async move {
            let mut recv_buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
            loop {
                let recv_result = tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = udp_socket.recv_from(&mut recv_buf) => result,
                };

                let Ok((n, _src)) = recv_result else {
                    break;
                };

                let Ok((_, payload)) = Socks5Client::parse_udp_response(&recv_buf[..n]) else {
                    continue;
                };

                let Some(response_packet) = packet::packet_build::build_udp_packet(
                    flow_key.dst,
                    flow_key.src,
                    &payload,
                ) else {
                    continue;
                };

                if packet::packet_build::write_tun_packet_with(&tun_packet_tx, response_packet)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    /// Relay task for direct (excluded-flow) sessions: raw datagrams from the
    /// connected outbound socket are injected into the TUN as packets from the
    /// flow target to the flow source.  Unlike the SOCKS5 relay above there is
    /// no relay framing to strip — every received datagram is application data.
    fn spawn_direct_udp_relay_task(
        udp_socket: Arc<tokio::net::UdpSocket>,
        flow_key: UdpFlowKey,
        cancel: CancellationToken,
        tun_packet_tx: mpsc::Sender<Vec<u8>>,
    ) {
        tokio::spawn(async move {
            let mut recv_buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
            loop {
                let recv_result = tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = udp_socket.recv_from(&mut recv_buf) => result,
                };

                let Ok((n, _src)) = recv_result else {
                    break;
                };

                let Some(response_packet) =
                    packet::packet_build::build_udp_packet(flow_key.dst, flow_key.src, &recv_buf[..n])
                else {
                    continue;
                };

                if packet::packet_build::write_tun_packet_with(&tun_packet_tx, response_packet)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    pub async fn cleanup_expired_udp_sessions(&self) {
        let now = Instant::now();

        // Cancelled tokens, then a sweep of the map itself.  Cancelling before
        // removal lets the relay tasks drop their socket/control references.
        let removed = Self::sweep_idle_sessions(&self.udp_sessions, now);
        if removed > 0 {
            debug!("Cleaned up {} idle UDP ASSOCIATE sessions", removed);
        }

        // Same sweep for direct (excluded-flow) sessions.
        let removed_direct = Self::sweep_idle_direct_sessions(&self.direct_udp_sessions, now);
        if removed_direct > 0 {
            debug!("Cleaned up {} idle direct UDP sessions", removed_direct);
        }

        let now = Instant::now();
        self.udp_timeout_backoff.retain(|_, until| *until > now);
    }

    fn sweep_idle_sessions(
        sessions: &DashMap<UdpFlowKey, UdpSessionEntry>,
        now: Instant,
    ) -> usize {
        let expired: Vec<CancellationToken> = sessions
            .iter()
            .filter(|entry| now.duration_since(entry.value().last_activity) >= UDP_SESSION_IDLE_TIMEOUT)
            .map(|entry| entry.value().cancel.clone())
            .collect();

        for token in &expired {
            token.cancel();
        }

        let before = sessions.len();
        sessions.retain(|_, entry| now.duration_since(entry.last_activity) < UDP_SESSION_IDLE_TIMEOUT);
        before.saturating_sub(sessions.len())
    }

    fn sweep_idle_direct_sessions(
        sessions: &DashMap<UdpFlowKey, DirectUdpSessionEntry>,
        now: Instant,
    ) -> usize {
        let expired: Vec<CancellationToken> = sessions
            .iter()
            .filter(|entry| now.duration_since(entry.value().last_activity) >= UDP_SESSION_IDLE_TIMEOUT)
            .map(|entry| entry.value().cancel.clone())
            .collect();

        for token in &expired {
            token.cancel();
        }

        let before = sessions.len();
        sessions
            .retain(|_, entry| now.duration_since(entry.last_activity) < UDP_SESSION_IDLE_TIMEOUT);
        before.saturating_sub(sessions.len())
    }

    fn is_udp_flow_in_backoff(&self, flow_key: &UdpFlowKey) -> bool {
        let now = Instant::now();
        self.udp_timeout_backoff
            .get(flow_key)
            .is_some_and(|until| *until > now)
    }

    fn mark_udp_flow_backoff_shared(
        udp_timeout_backoff: Arc<DashMap<UdpFlowKey, Instant>>,
        flow_key: UdpFlowKey,
    ) {
        udp_timeout_backoff.insert(flow_key, Instant::now() + UDP_TIMEOUT_BACKOFF);
    }
}
