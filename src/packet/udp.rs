use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashMap;
use log::{debug, warn};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

use etherparse::{PacketBuilder, UdpHeader, UdpHeaderSlice};

use crate::config::Config;
use crate::dns_router::DnsRouter;
use crate::packet;
use crate::packet::shared::{
    ParsedIpPacket, ProcessLookupEntry, ProcessLookupKey, UdpFlowKey, UdpSessionEntry,
};
use crate::process_lookup::{ProcessLookupOptions, TransportProtocol};
use crate::socks5_client::{Socks5Client, Socks5UdpSession};

// ── Constants ─────────────────────────────────────────────────────────────────

const UDP_PROXY_TIMEOUT: Duration = Duration::from_millis(1200);
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const UDP_TIMEOUT_BACKOFF: Duration = Duration::from_secs(30);
const DNS_TASK_CONCURRENCY_LIMIT: usize = 32;
const UDP_TASK_CONCURRENCY_LIMIT: usize = 64;

// ── UdpHandler ────────────────────────────────────────────────────────────────

pub struct UdpHandler {
    pub config: Arc<Config>,
    pub socks5_client: Arc<Socks5Client>,
    pub dns_router: Arc<DnsRouter>,
    pub outbound_interface: Option<String>,
    pub tun_packet_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub udp_sessions: Arc<DashMap<UdpFlowKey, UdpSessionEntry>>,
    pub pending_udp_sessions: Arc<Mutex<HashSet<UdpFlowKey>>>,
    pub udp_timeout_backoff: Arc<DashMap<UdpFlowKey, Instant>>,
    pub udp_task_limiter: Arc<Semaphore>,
    pub dns_task_limiter: Arc<Semaphore>,
    pub process_name_cache: Arc<Mutex<HashMap<ProcessLookupKey, ProcessLookupEntry>>>,
    pub process_lookup_options: ProcessLookupOptions,
    pub dynamic_bypass_ips: Arc<DashMap<IpAddr, Instant>>,
}

impl UdpHandler {
    pub fn new(
        config: Arc<Config>,
        socks5_client: Arc<Socks5Client>,
        dns_router: Arc<DnsRouter>,
        outbound_interface: Option<String>,
        tun_packet_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let process_lookup_options = ProcessLookupOptions::from_config(&config);
        Self {
            config,
            socks5_client,
            dns_router,
            outbound_interface,
            tun_packet_tx,
            udp_sessions: Arc::new(DashMap::new()),
            pending_udp_sessions: Arc::new(Mutex::new(HashSet::new())),
            udp_timeout_backoff: Arc::new(DashMap::new()),
            udp_task_limiter: Arc::new(Semaphore::new(UDP_TASK_CONCURRENCY_LIMIT)),
            dns_task_limiter: Arc::new(Semaphore::new(DNS_TASK_CONCURRENCY_LIMIT)),
            process_name_cache: Arc::new(Mutex::new(HashMap::new())),
            process_lookup_options,
            dynamic_bypass_ips: Arc::new(DashMap::new()),
        }
    }

    pub async fn handle_udp_packet(&self, packet: &[u8], ip_packet: &ParsedIpPacket) -> Result<()> {
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
                ip_packet.src,
                source_port,
                ip_packet.dst,
                dest_port
            );
            return Ok(());
        }

        let is_static_bypass = self.config.should_skip_ip(target_addr.ip());
        let is_direct_flow = if is_static_bypass {
            true
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
                let udp_permit = match self.udp_task_limiter.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        debug!(
                            "Dropping excluded UDP packet (rate limit) {}:{} -> {}:{}",
                            ip_packet.src, source_port, ip_packet.dst, dest_port
                        );
                        return Ok(());
                    }
                };

                let udp_payload = udp_data[UdpHeader::LEN..].to_vec();
                let tun_packet_tx = self.tun_packet_tx.clone();
                let src_ip = ip_packet.src;
                let dst_ip = ip_packet.dst;

                tokio::spawn(async move {
                    let _permit = udp_permit;

                    match timeout(
                        UDP_PROXY_TIMEOUT,
                        packet::direct::direct_udp_exchange(target_addr, udp_payload, iface),
                    )
                    .await
                    {
                        Ok(Ok(response_payload)) => {
                            let response_builder = match (dst_ip, src_ip) {
                                (IpAddr::V4(dst), IpAddr::V4(src)) => {
                                    PacketBuilder::ipv4(dst.octets(), src.octets(), 64)
                                        .udp(dest_port, source_port)
                                }
                                (IpAddr::V6(dst), IpAddr::V6(src)) => {
                                    PacketBuilder::ipv6(dst.octets(), src.octets(), 64)
                                        .udp(dest_port, source_port)
                                }
                                _ => return,
                            };
                            let mut response_packet =
                                Vec::with_capacity(response_builder.size(response_payload.len()));
                            if response_builder
                                .write(&mut response_packet, &response_payload)
                                .is_err()
                            {
                                return;
                            }
                            let _ = packet::packet_build::write_tun_packet_with(
                                tun_packet_tx,
                                response_packet,
                            )
                            .await;
                            debug!(
                                "Direct UDP exchange completed for excluded flow {}:{} -> {}:{}",
                                src_ip, source_port, dst_ip, dest_port
                            );
                        }
                        Ok(Err(err)) => {
                            debug!(
                                "Direct UDP exchange failed for excluded flow {}:{} -> {}:{}: {}",
                                src_ip, source_port, dst_ip, dest_port, err
                            );
                        }
                        Err(_) => {
                            debug!(
                                "Direct UDP exchange timed out for excluded flow {}:{} -> {}:{}",
                                src_ip, source_port, dst_ip, dest_port
                            );
                        }
                    }
                });

                debug!(
                    "{} UDP {}:{} -> {}:{}: direct forwarding via physical NIC",
                    if is_static_bypass { "Static bypass" } else { "Excluded process" },
                    ip_packet.src, source_port, ip_packet.dst, dest_port
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
                ip_packet.src,
                source_port,
                ip_packet.dst,
                dest_port
            );
            return Ok(());
        }

        if dest_port == self.config.dns.listen_port {
            let dns_permit = match self.dns_task_limiter.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    debug!(
                        "Dropping DNS packet due to task concurrency limit {}:{} -> {}:{}",
                        ip_packet.src,
                        source_port,
                        ip_packet.dst,
                        dest_port
                    );
                    return Ok(());
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
                    Ok(resp) => packet::shared::normalize_dns_response_for_query(&udp_payload, resp),
                    Err(err) => {
                        warn!(
                            "DNS forwarding failed for {}:{}: {}; returning spoofed SERVFAIL",
                            dst_ip,
                            dest_port,
                            err
                        );
                        packet::shared::build_dns_servfail_response(&udp_payload)
                    }
                };

                let response_builder = match (dst_ip, src_ip) {
                    (IpAddr::V4(dst), IpAddr::V4(src)) => {
                        PacketBuilder::ipv4(dst.octets(), src.octets(), 64).udp(dest_port, source_port)
                    }
                    (IpAddr::V6(dst), IpAddr::V6(src)) => {
                        PacketBuilder::ipv6(dst.octets(), src.octets(), 64).udp(dest_port, source_port)
                    }
                    _ => return,
                };

                let mut response_packet = Vec::with_capacity(response_builder.size(response_payload.len()));
                if response_builder.write(&mut response_packet, &response_payload).is_err() {
                    return;
                }
                let response_len = response_packet.len();
                if packet::packet_build::write_tun_packet_with(tun_packet_tx, response_packet)
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

        if self.is_udp_flow_in_backoff(&udp_flow_key).await {
            debug!(
                "Skipping UDP proxy during backoff for {}:{} -> {}:{}",
                ip_packet.src,
                source_port,
                ip_packet.dst,
                dest_port
            );
            return Ok(());
        }

        let udp_permit = match self.udp_task_limiter.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                debug!(
                    "Dropping UDP packet due to task concurrency limit {}:{} -> {}:{}",
                    ip_packet.src,
                    source_port,
                    ip_packet.dst,
                    dest_port
                );
                return Ok(());
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
            let _permit = udp_permit;

            // Keep a reference so the timeout branch can clean up a stale
            // pending-session entry if the future is cancelled mid-way.
            let pending_for_cleanup = pending_udp_sessions.clone();

            let response_payload = match timeout(
                UDP_PROXY_TIMEOUT,
                Self::proxy_udp_with_reused_session_shared(
                    socks5_client,
                    udp_sessions,
                    pending_udp_sessions,
                    udp_flow_key.clone(),
                    udp_payload,
                ),
            )
            .await
            {
                Ok(Ok(resp)) => {
                    Self::clear_udp_backoff_shared(udp_timeout_backoff.clone(), &udp_flow_key)
                        .await;
                    resp
                }
                Ok(Err(err)) => {
                    Self::mark_udp_flow_backoff_shared(
                        udp_timeout_backoff.clone(),
                        udp_flow_key.clone(),
                    )
                    .await;
                    warn!(
                        "UDP proxying failed for {}:{} -> {}:{}: {}",
                        src_ip,
                        source_port,
                        dst_ip,
                        dest_port,
                        err
                    );
                    return;
                }
                Err(_) => {
                    // The future was dropped by timeout; it may not have had a
                    // chance to remove the flow key from pending_udp_sessions.
                    pending_for_cleanup.lock().await.remove(&udp_flow_key);
                    Self::mark_udp_flow_backoff_shared(
                        udp_timeout_backoff.clone(),
                        udp_flow_key.clone(),
                    )
                    .await;
                    warn!(
                        "UDP proxy timeout for {}:{} -> {}:{}",
                        src_ip,
                        source_port,
                        dst_ip,
                        dest_port
                    );
                    return;
                }
            };

            let response_builder = match (dst_ip, src_ip) {
                (IpAddr::V4(dst), IpAddr::V4(src)) => {
                    PacketBuilder::ipv4(dst.octets(), src.octets(), 64).udp(dest_port, source_port)
                }
                (IpAddr::V6(dst), IpAddr::V6(src)) => {
                    PacketBuilder::ipv6(dst.octets(), src.octets(), 64).udp(dest_port, source_port)
                }
                _ => return,
            };

            let mut response_packet = Vec::with_capacity(response_builder.size(response_payload.len()));
            if response_builder.write(&mut response_packet, &response_payload).is_err() {
                return;
            }
            let response_len = response_packet.len();
            if packet::packet_build::write_tun_packet_with(tun_packet_tx, response_packet)
                .await
                .is_err()
            {
                return;
            }

            debug!(
                "Proxied UDP flow {}:{} -> {}:{} and injected {} bytes back to TUN",
                src_ip,
                source_port,
                dst_ip,
                dest_port,
                response_len
            );
        });

        Ok(())
    }

    async fn proxy_udp_with_reused_session_shared(
        socks5_client: Arc<Socks5Client>,
        udp_sessions: Arc<DashMap<UdpFlowKey, UdpSessionEntry>>,
        pending_udp_sessions: Arc<Mutex<HashSet<UdpFlowKey>>>,
        flow_key: UdpFlowKey,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if let Some(session) = Self::get_cached_udp_session_shared(udp_sessions.clone(), &flow_key).await {
            match Self::exchange_udp_on_session_shared(udp_sessions.clone(), session, &flow_key, &payload).await {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    debug!(
                        "Existing UDP ASSOCIATE session failed for {} -> {}: {}; recreating",
                        flow_key.src,
                        flow_key.dst,
                        err
                    );
                    Self::remove_udp_session_shared(udp_sessions.clone(), &flow_key).await;
                }
            }
        }

        // Guard against concurrent tasks for the same flow all racing into
        // open_udp_session simultaneously. Each call opens a TCP control socket + UDP
        // socket to the SOCKS5 proxy; on Windows every abandoned socket pair enters
        // TIME_WAIT and consumes ephemeral ports, exhausting the ~16 k port pool fast.
        let is_already_pending = {
            let mut pending = pending_udp_sessions.lock().await;
            if pending.contains(&flow_key) {
                true
            } else {
                pending.insert(flow_key.clone());
                false
            }
        };

        if is_already_pending {
            return Err(anyhow::anyhow!(
                "UDP ASSOCIATE already in progress for {} -> {}",
                flow_key.src,
                flow_key.dst
            ));
        }

        let open_result = socks5_client.open_udp_session(flow_key.dst).await;

        {
            let mut pending = pending_udp_sessions.lock().await;
            pending.remove(&flow_key);
        }

        let session = open_result.map(|s| Arc::new(Mutex::new(s)))?;

        {
            udp_sessions.insert(
                flow_key.clone(),
                UdpSessionEntry {
                    session: session.clone(),
                    last_activity: Instant::now(),
                },
            );
        }

        Self::exchange_udp_on_session_shared(udp_sessions, session, &flow_key, &payload).await
    }

    async fn exchange_udp_on_session_shared(
        udp_sessions: Arc<DashMap<UdpFlowKey, UdpSessionEntry>>,
        session: Arc<Mutex<Socks5UdpSession>>,
        flow_key: &UdpFlowKey,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let response = {
            let mut guard = session.lock().await;
            guard.exchange(flow_key.dst, payload).await
        };

        match response {
            Ok(resp) => {
                if let Some(mut entry) = udp_sessions.get_mut(flow_key) {
                    entry.last_activity = Instant::now();
                }
                Ok(resp)
            }
            Err(err) => {
                udp_sessions.remove(flow_key);
                Err(err.into())
            }
        }
    }

    async fn get_cached_udp_session_shared(
        udp_sessions: Arc<DashMap<UdpFlowKey, UdpSessionEntry>>,
        flow_key: &UdpFlowKey,
    ) -> Option<Arc<Mutex<Socks5UdpSession>>> {
        if let Some(mut entry) = udp_sessions.get_mut(flow_key) {
            entry.last_activity = Instant::now();
            return Some(entry.session.clone());
        }
        None
    }

    async fn remove_udp_session_shared(
        udp_sessions: Arc<DashMap<UdpFlowKey, UdpSessionEntry>>,
        flow_key: &UdpFlowKey,
    ) {
        udp_sessions.remove(flow_key);
    }

    pub async fn cleanup_expired_udp_sessions(&self) {
        let removed = {
            let now = Instant::now();
            let before = self.udp_sessions.len();
            self.udp_sessions.retain(|_, entry| now.duration_since(entry.last_activity) < UDP_SESSION_IDLE_TIMEOUT);
            before.saturating_sub(self.udp_sessions.len())
        };

        if removed > 0 {
            debug!("Cleaned up {} idle UDP ASSOCIATE sessions", removed);
        }

        {
            let now = Instant::now();
            self.udp_timeout_backoff.retain(|_, until| *until > now);
        }
    }

    async fn is_udp_flow_in_backoff(&self, flow_key: &UdpFlowKey) -> bool {
        let now = Instant::now();
        self.udp_timeout_backoff
            .get(flow_key)
            .is_some_and(|until| *until > now)
    }

    async fn mark_udp_flow_backoff_shared(
        udp_timeout_backoff: Arc<DashMap<UdpFlowKey, Instant>>,
        flow_key: UdpFlowKey,
    ) {
        udp_timeout_backoff.insert(flow_key, Instant::now() + UDP_TIMEOUT_BACKOFF);
    }

    async fn clear_udp_backoff_shared(
        udp_timeout_backoff: Arc<DashMap<UdpFlowKey, Instant>>,
        flow_key: &UdpFlowKey,
    ) {
        udp_timeout_backoff.remove(flow_key);
    }
}
