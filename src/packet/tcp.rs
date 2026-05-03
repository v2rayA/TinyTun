use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashMap;
use log::{debug, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, timeout};

use etherparse::{PacketBuilder, TcpHeaderSlice};

use crate::config::Config;
use crate::dns_router::DnsRouter;
use crate::packet;
use crate::packet::shared::{
    collect_in_order_payload, seq_at_or_after, FlowKey, ParsedIpPacket, ProcessLookupEntry,
    ProcessLookupKey, TcpFlowState, TcpLifecycle, TcpSession,
};
use crate::process_lookup::{ProcessLookupOptions, TransportProtocol};
use crate::socks5_client::Socks5Client;

// ── Constants ─────────────────────────────────────────────────────────────────

const TCP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const TCP_FIN_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

// ── TcpHandler ────────────────────────────────────────────────────────────────

pub struct TcpHandler {
    pub config: Arc<Config>,
    pub socks5_client: Arc<Socks5Client>,
    pub dns_router: Arc<DnsRouter>,
    pub outbound_interface: Option<String>,
    pub tun_packet_tx: mpsc::Sender<Vec<u8>>,
    pub tcp_sessions: Arc<DashMap<FlowKey, Arc<TcpSession>>>,
    pub pending_connections: Arc<Mutex<HashSet<FlowKey>>>,
    pub process_name_cache: Arc<Mutex<HashMap<ProcessLookupKey, ProcessLookupEntry>>>,
    pub process_lookup_options: ProcessLookupOptions,
    pub dynamic_bypass_ips: Arc<DashMap<IpAddr, Instant>>,
}

impl TcpHandler {
    pub fn new(
        config: Arc<Config>,
        socks5_client: Arc<Socks5Client>,
        dns_router: Arc<DnsRouter>,
        outbound_interface: Option<String>,
        tun_packet_tx: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let process_lookup_options = ProcessLookupOptions::from_config(&config);
        Self {
            config,
            socks5_client,
            dns_router,
            outbound_interface,
            tun_packet_tx,
            tcp_sessions: Arc::new(DashMap::new()),
            pending_connections: Arc::new(Mutex::new(HashSet::new())),
            process_name_cache: Arc::new(Mutex::new(HashMap::new())),
            process_lookup_options,
            dynamic_bypass_ips: Arc::new(DashMap::new()),
        }
    }

    pub async fn handle_tcp_packet(&self, packet: &[u8], ip_packet: &ParsedIpPacket) -> Result<()> {
        if packet.len() < ip_packet.header_len {
            return Err(anyhow::anyhow!("IP header length exceeds packet size"));
        }

        let tcp_data = &packet[ip_packet.header_len..];

        if tcp_data.len() < 20 {
            return Err(anyhow::anyhow!("TCP data too short"));
        }

        let tcp_header = TcpHeaderSlice::from_slice(tcp_data)?;
        let source_port = tcp_header.source_port();
        let dest_port = tcp_header.destination_port();

        // Check if we should skip this port
        if self.config.should_skip_port(dest_port) {
            debug!("Skipping TCP packet to port {}", dest_port);
            return Ok(());
        }

        let target_addr = SocketAddr::new(ip_packet.dst, dest_port);
        let source_addr = SocketAddr::new(ip_packet.src, source_port);
        let flow_key = FlowKey {
            src: source_addr,
            dst: target_addr,
        };

        let tcp_header_len = tcp_header.data_offset() as usize * 4;
        if tcp_data.len() < tcp_header_len {
            return Err(anyhow::anyhow!("TCP header length exceeds packet size"));
        }

        let payload = &tcp_data[tcp_header_len..];

        // ── Non-SYN fast path ─────────────────────────────────────────────────
        // For data / ACK / FIN / RST packets, check the session table first.
        // Admitted sessions bypass the process-exclusion check entirely, which
        // eliminates async Mutex contention on the process cache for every
        // data packet on an established connection.
        if !tcp_header.syn() {
            let session = self.tcp_sessions.get(&flow_key).map(|entry| entry.value().clone());

            if let Some(session) = session {
                let is_ack_only_or_window_update =
                    payload.is_empty() && !tcp_header.fin() && !tcp_header.rst();

                if tcp_header.rst() || tcp_header.fin() {
                    if tcp_header.fin() {
                        let (sequence_number, acknowledgment_number) = {
                            let mut state = session.state.lock().await;
                            if seq_at_or_after(
                                tcp_header.sequence_number(),
                                state.client_next_seq,
                            ) {
                                state.client_next_seq = state.client_next_seq.wrapping_add(1);
                            }
                            let seq = state.server_next_seq;
                            state.server_next_seq = state.server_next_seq.wrapping_add(1);
                            state.lifecycle = TcpLifecycle::FinSent;
                            state.last_activity = Instant::now();
                            (seq, state.client_next_seq)
                        };
                        packet::packet_build::inject_tcp_control(
                            &self.tun_packet_tx,
                            &flow_key,
                            sequence_number,
                            acknowledgment_number,
                            false,
                            true,
                            false,
                        )
                        .await?;
                    }

                    if tcp_header.rst() {
                        let mut state = session.state.lock().await;
                        state.lifecycle = TcpLifecycle::Closed;
                        self.tcp_sessions.remove(&flow_key);
                        return Ok(());
                    }
                }

                if tcp_header.ack() {
                    let should_close = {
                        let mut state = session.state.lock().await;
                        state.client_window = tcp_header.window_size();
                        // Complete three-way handshake if still in SynReceived.
                        if state.lifecycle == TcpLifecycle::SynReceived {
                            state.lifecycle = TcpLifecycle::Established;
                        }
                        if seq_at_or_after(
                            tcp_header.acknowledgment_number(),
                            state.server_acked_seq,
                        ) {
                            state.server_acked_seq = tcp_header.acknowledgment_number();
                        }
                        if state.lifecycle == TcpLifecycle::FinSent
                            && tcp_header.acknowledgment_number() == state.server_next_seq
                        {
                            state.lifecycle = TcpLifecycle::Closed;
                            true
                        } else {
                            false
                        }
                    };
                    if should_close {
                        self.tcp_sessions.remove(&flow_key);
                        return Ok(());
                    }
                }

                let lifecycle = { session.state.lock().await.lifecycle };
                if lifecycle == TcpLifecycle::Closed || lifecycle == TcpLifecycle::FinSent {
                    return Ok(());
                }

                if is_ack_only_or_window_update {
                    return Ok(());
                }

                if !payload.is_empty() {
                    let forward_payload = {
                        let mut state = session.state.lock().await;
                        let merged = collect_in_order_payload(
                            &mut state,
                            tcp_header.sequence_number(),
                            payload,
                        );
                        state.last_activity = Instant::now();
                        merged
                    };

                    if forward_payload.is_empty() {
                        debug!(
                            "Buffered/dropped non-forwardable TCP segment {}:{} -> {}:{}",
                            ip_packet.src, source_port, ip_packet.dst, dest_port
                        );
                        return Ok(());
                    }

                    if session.forward_tx.try_send(forward_payload).is_err() {
                        let (sequence_number, acknowledgment_number) = {
                            let state = session.state.lock().await;
                            (state.server_next_seq, state.client_next_seq)
                        };
                        let _ = packet::packet_build::inject_tcp_control(
                            &self.tun_packet_tx,
                            &flow_key,
                            sequence_number,
                            acknowledgment_number,
                            false,
                            false,
                            true,
                        )
                        .await;
                        self.tcp_sessions.remove(&flow_key);
                        warn!(
                            "TCP forward channel full for flow {:?}: resetting connection",
                            flow_key
                        );
                        return Ok(());
                    }
                }

                debug!(
                    "TCP flow active {}:{} -> {}:{}",
                    ip_packet.src, source_port, ip_packet.dst, dest_port
                );
                return Ok(());
            }

            // Non-SYN with no session: silently drop unless a connect is pending.
            {
                let pending = self.pending_connections.lock().await;
                if !pending.contains(&flow_key) {
                    debug!(
                        "Dropping unknown non-SYN TCP packet {}:{} -> {}:{}",
                        ip_packet.src, source_port, ip_packet.dst, dest_port
                    );
                }
            }
            return Ok(());
        }

        // ── SYN path ──────────────────────────────────────────────────────────
        // Determine if this flow should bypass SOCKS5 and go directly via the
        // physical NIC.  Static bypass IPs (skip_ips) always take this path;
        // excluded processes only do so after the async name lookup confirms it.
        let is_static_bypass = self.config.should_skip_ip(target_addr.ip());
        let is_direct_flow = if is_static_bypass {
            true // skip the async process-name lookup for static bypass IPs
        } else {
            packet::bypass::should_exclude_process_flow(
                &self.config,
                &self.process_name_cache,
                &self.process_lookup_options,
                TransportProtocol::Tcp,
                source_addr,
                target_addr,
            )
            .await
        };
        if is_direct_flow {
            // ── Preferred path: transparent direct proxy via physical NIC ──────
            // Socket-level interface binding (SO_BINDTODEVICE on Linux,
            // IP_BOUND_IF on macOS) is only available on those two platforms.
            // On Windows, FreeBSD, etc. this entire block is excluded at
            // compile time and execution falls through to the route-based
            // bypass below, which installs a /32 host route and sends RST.
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if let Some(iface) = self.outbound_interface.clone() {
                {
                    let mut pending = self.pending_connections.lock().await;
                    if pending.contains(&flow_key) {
                        return Ok(());
                    }
                    pending.insert(flow_key.clone());
                }

                let tun_packet_tx = self.tun_packet_tx.clone();
                let tcp_sessions: Arc<DashMap<FlowKey, Arc<TcpSession>>> = self.tcp_sessions.clone();
                let pending_connections = self.pending_connections.clone();
                let mtu = self.config.tun.mtu as usize;
                let client_isn = tcp_header.sequence_number();
                let fk = flow_key.clone();

                tokio::spawn(async move {
                    let connect_result = timeout(
                        TCP_CONNECT_TIMEOUT,
                        packet::direct::open_direct_tcp(fk.dst, &iface),
                    )
                    .await;

                    {
                        let mut pending = pending_connections.lock().await;
                        pending.remove(&fk);
                    }

                    match connect_result {
                        Ok(Ok(stream)) => {
                            let (reader, writer) = stream.into_split();
                            let writer = Arc::new(Mutex::new(writer));
                            let (forward_tx, forward_rx) = mpsc::channel::<Vec<u8>>(64);

                            let session = Arc::new(TcpSession {
                                state: Arc::new(Mutex::new(TcpFlowState {
                                    client_next_seq: client_isn.wrapping_add(1),
                                    server_next_seq: 1,
                                    server_acked_seq: 1,
                                    client_window: 65535,
                                    reorder_buffer: BTreeMap::new(),
                                    reorder_bytes: 0,
                                    lifecycle: TcpLifecycle::SynReceived,
                                    last_activity: Instant::now(),
                                })),
                                forward_tx,
                            });

                            let syn_ack_seq = {
                                let mut state = session.state.lock().await;
                                let seq = state.server_next_seq;
                                state.server_next_seq = seq.wrapping_add(1);
                                seq
                            };

                            tcp_sessions.insert(fk.clone(), session.clone());

                            Self::spawn_forward_writer_task(
                                fk.clone(),
                                forward_rx,
                                writer,
                                session.state.clone(),
                                tcp_sessions.clone(),
                                tun_packet_tx.clone(),
                            );

                            Self::spawn_reverse_tcp_task(
                                fk.clone(),
                                reader,
                                session,
                                tcp_sessions,
                                tun_packet_tx.clone(),
                                mtu,
                            );

                            let _ = packet::packet_build::inject_tcp_control(
                                &tun_packet_tx,
                                &fk,
                                syn_ack_seq,
                                client_isn.wrapping_add(1),
                                true,
                                false,
                                false,
                            )
                            .await;
                            debug!("Direct TCP proxy established for excluded flow {:?}", fk);
                        }
                        Ok(Err(err)) => {
                            warn!("Direct TCP connect failed for excluded flow {:?}: {}", fk, err);
                            let _ = packet::packet_build::inject_tcp_control(
                                &tun_packet_tx,
                                &fk,
                                0,
                                client_isn.wrapping_add(1),
                                false,
                                false,
                                true,
                            )
                            .await;
                        }
                        Err(_) => {
                            warn!("Direct TCP connect timed out for excluded flow {:?}", fk);
                            let _ = packet::packet_build::inject_tcp_control(
                                &tun_packet_tx,
                                &fk,
                                0,
                                client_isn.wrapping_add(1),
                                false,
                                false,
                                true,
                            )
                            .await;
                        }
                    }
                });

                debug!(
                    "{} TCP {}:{} -> {}:{}: direct-proxying via physical NIC",
                    if is_static_bypass { "Static bypass" } else { "Excluded process" },
                    ip_packet.src, source_port, ip_packet.dst, dest_port
                );
                return Ok(());
            }

            // ── Fallback: no outbound interface, or interface binding not ─────
            // ── supported on this platform (Windows, FreeBSD, …)  ────────────
            if is_static_bypass {
                // Static bypass IP arrived at TUN but direct forwarding is
                // unavailable.  The routing table should already route this IP
                // around TUN; RST so the app fails fast rather than hanging.
                let _ = packet::packet_build::inject_tcp_control(
                    &self.tun_packet_tx,
                    &flow_key,
                    0,
                    tcp_header.sequence_number().wrapping_add(1),
                    false,
                    false,
                    true,
                )
                .await;
                debug!(
                    "Static bypass TCP {}:{} -> {}:{}: RST (no outbound interface configured)",
                    ip_packet.src, source_port, ip_packet.dst, dest_port
                );
                return Ok(());
            }

            // ── Fallback: route-based bypass (RST + reconnect) ────────────────
            // No outbound interface is configured; install a kernel /32 route so
            // the app's next reconnect goes via the physical NIC directly.
            // Defensively remove any ghost session.
            let had_session = self.tcp_sessions.remove(&flow_key).is_some();

            let mut should_reset = !self.config.tun.auto_route || had_session;

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
                        "Failed to install dynamic bypass route for excluded flow {}:{} -> {}:{}: {}",
                        ip_packet.src, source_port, ip_packet.dst, dest_port, err
                    );
                    should_reset = true;
                }
            }

            if should_reset {
                let _ = packet::packet_build::inject_tcp_control(
                    &self.tun_packet_tx,
                    &flow_key,
                    0,
                    tcp_header.sequence_number().wrapping_add(1),
                    false,
                    false,
                    true,
                )
                .await;
            }
            debug!(
                "Excluded process flow (TCP) {}:{} -> {}:{}: route-based bypass",
                ip_packet.src, source_port, ip_packet.dst, dest_port
            );
            return Ok(());
        }

        // SYN retransmit for an already-admitted connection?
        if let Some(session) = self.tcp_sessions.get(&flow_key).map(|entry| entry.value().clone()) {
            let resend_syn_ack = {
                let mut state = session.state.lock().await;
                state.last_activity = Instant::now();
                if state.lifecycle == TcpLifecycle::SynReceived {
                    Some((state.server_next_seq.wrapping_sub(1), state.client_next_seq))
                } else {
                    None
                }
            };
            if let Some((sequence_number, acknowledgment_number)) = resend_syn_ack {
                packet::packet_build::inject_tcp_control(
                    &self.tun_packet_tx,
                    &flow_key,
                    sequence_number,
                    acknowledgment_number,
                    true,
                    false,
                    false,
                )
                .await?;
            }
            return Ok(());
        }

        // Fresh SYN: spawn a SOCKS5 connection in the background.
        {
            let mut pending = self.pending_connections.lock().await;
            if pending.contains(&flow_key) {
                return Ok(());
            }
            pending.insert(flow_key.clone());
        }

        let socks5_client = self.socks5_client.clone();
        let tun_packet_tx = self.tun_packet_tx.clone();
        let tcp_sessions: Arc<DashMap<FlowKey, Arc<TcpSession>>> = self.tcp_sessions.clone();
        let pending_connections = self.pending_connections.clone();
        let mtu = self.config.tun.mtu as usize;
        let client_isn = tcp_header.sequence_number();
        let fk = flow_key.clone();

        tokio::spawn(async move {
            let connect_result = timeout(
                TCP_CONNECT_TIMEOUT,
                socks5_client.connect(fk.dst),
            )
            .await;

            {
                let mut pending = pending_connections.lock().await;
                pending.remove(&fk);
            }

            match connect_result {
                Ok(Ok(stream)) => {
                    let (reader, writer) = stream.into_split();
                    let writer = Arc::new(Mutex::new(writer));
                    let (forward_tx, forward_rx) = mpsc::channel::<Vec<u8>>(64);

                    let session = Arc::new(TcpSession {
                        state: Arc::new(Mutex::new(TcpFlowState {
                            client_next_seq: client_isn.wrapping_add(1),
                            server_next_seq: 1,
                            server_acked_seq: 1,
                            client_window: 65535,
                            reorder_buffer: BTreeMap::new(),
                            reorder_bytes: 0,
                            lifecycle: TcpLifecycle::SynReceived,
                            last_activity: Instant::now(),
                        })),
                        forward_tx,
                    });

                    let syn_ack_seq = {
                        let mut state = session.state.lock().await;
                        let seq = state.server_next_seq;
                        state.server_next_seq = seq.wrapping_add(1);
                        seq
                    };

                    tcp_sessions.insert(fk.clone(), session.clone());

                    Self::spawn_forward_writer_task(
                        fk.clone(),
                        forward_rx,
                        writer,
                        session.state.clone(),
                        tcp_sessions.clone(),
                        tun_packet_tx.clone(),
                    );

                    Self::spawn_reverse_tcp_task(
                        fk.clone(),
                        reader,
                        session,
                        tcp_sessions,
                        tun_packet_tx.clone(),
                        mtu,
                    );

                    let _ = packet::packet_build::inject_tcp_control(
                        &tun_packet_tx,
                        &fk,
                        syn_ack_seq,
                        client_isn.wrapping_add(1),
                        true,
                        false,
                        false,
                    )
                    .await;
                }
                Ok(Err(err)) => {
                    warn!("SOCKS5 connect failed for {:?}: {}", fk, err);
                    let _ = packet::packet_build::inject_tcp_control(
                        &tun_packet_tx,
                        &fk,
                        0,
                        client_isn.wrapping_add(1),
                        false,
                        false,
                        true,
                    )
                    .await;
                }
                Err(_) => {
                    warn!("SOCKS5 connect timed out for {:?}", fk);
                    let _ = packet::packet_build::inject_tcp_control(
                        &tun_packet_tx,
                        &fk,
                        0,
                        client_isn.wrapping_add(1),
                        false,
                        false,
                        true,
                    )
                    .await;
                }
            }
        });

        Ok(())
    }

    /// Spawn a task that drains the per-session forward channel and writes
    /// each payload to the SOCKS5 TCP stream in order, then ACKs it back to
    /// the TUN-side client.  Running this separately keeps the main packet
    /// loop non-blocking even when the SOCKS5 connection is congested.
    fn spawn_forward_writer_task(
        flow_key: FlowKey,
        mut forward_rx: mpsc::Receiver<Vec<u8>>,
        writer: Arc<Mutex<OwnedWriteHalf>>,
        state: Arc<Mutex<TcpFlowState>>,
        sessions: Arc<DashMap<FlowKey, Arc<TcpSession>>>,
        tun_packet_tx: mpsc::Sender<Vec<u8>>,
    ) {
        tokio::spawn(async move {
            while let Some(payload) = forward_rx.recv().await {
                let write_result = {
                    let mut w = writer.lock().await;
                    w.write_all(&payload).await
                };

                if let Err(err) = write_result {
                    let (sequence_number, acknowledgment_number) = {
                        let s = state.lock().await;
                        (s.server_next_seq, s.client_next_seq)
                    };
                    let _ = packet::packet_build::inject_tcp_control(
                        &tun_packet_tx,
                        &flow_key,
                        sequence_number,
                        acknowledgment_number,
                        false,
                        false,
                        true,
                    )
                    .await;
                    sessions.remove(&flow_key);
                    warn!("TCP write failed for flow {:?}: {}", flow_key, err);
                    return;
                }

                // ACK the data that was just forwarded to SOCKS5.
                let (ack_seq, ack_ack) = {
                    let mut s = state.lock().await;
                    s.last_activity = Instant::now();
                    if s.lifecycle == TcpLifecycle::SynReceived {
                        s.lifecycle = TcpLifecycle::Established;
                    }
                    (s.server_next_seq, s.client_next_seq)
                };
                let _ = packet::packet_build::inject_tcp_control(
                    &tun_packet_tx,
                    &flow_key,
                    ack_seq,
                    ack_ack,
                    false,
                    false,
                    false,
                )
                .await;
            }
        });
    }

    fn spawn_reverse_tcp_task(
        flow_key: FlowKey,
        mut reader: OwnedReadHalf,
        session: Arc<TcpSession>,
        sessions: Arc<DashMap<FlowKey, Arc<TcpSession>>>,
        tun_packet_tx: mpsc::Sender<Vec<u8>>,
        mtu: usize,
    ) {
        tokio::spawn(async move {
            let header_overhead = match (flow_key.dst.ip(), flow_key.src.ip()) {
                (IpAddr::V6(_), IpAddr::V6(_)) => 60, // IPv6(40) + TCP(20)
                _ => 40, // IPv4(20) + TCP(20)
            };
            let max_payload_per_packet = mtu.saturating_sub(header_overhead).clamp(256, 1460);
            // Keep per-flow read buffer bounded near MTU scale to reduce memory under many flows.
            let read_buf_len = mtu.saturating_mul(2).clamp(2048, 4096);
            let mut buffer = vec![0u8; read_buf_len];

            loop {
                let read_size = match reader.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(err) => {
                        warn!("Reverse TCP read failed for flow {:?}: {}", flow_key, err);
                        break;
                    }
                };

                let payload = &buffer[..read_size];
                let mut chunk_write_failed = false;
                for chunk in payload.chunks(max_payload_per_packet) {
                    // Respect the client's advertised TCP receive window to avoid
                    // overrun-induced stalls on high-throughput downloads.
                    loop {
                        let (terminated, can_send) = {
                            let state = session.state.lock().await;
                            if state.lifecycle == TcpLifecycle::Closed || state.lifecycle == TcpLifecycle::FinSent {
                                (true, false)
                            } else {
                                let in_flight = state.server_next_seq.wrapping_sub(state.server_acked_seq) as usize;
                                let wnd = usize::from(state.client_window).max(1);
                                (false, in_flight + chunk.len() <= wnd)
                            }
                        };

                        if terminated {
                            chunk_write_failed = true;
                            break;
                        }

                        if can_send {
                            break;
                        }

                        sleep(Duration::from_millis(2)).await;
                    }

                    if chunk_write_failed {
                        break;
                    }

                    let (sequence_number, acknowledgment_number) = {
                        let mut state = session.state.lock().await;
                        if state.lifecycle == TcpLifecycle::SynReceived {
                            state.lifecycle = TcpLifecycle::Established;
                        }
                        let seq = state.server_next_seq;
                        let ack = state.client_next_seq;
                        state.server_next_seq = state.server_next_seq.wrapping_add(chunk.len() as u32);
                        state.last_activity = Instant::now();
                        (seq, ack)
                    };

                    let builder = match (flow_key.dst.ip(), flow_key.src.ip()) {
                        (IpAddr::V4(dst), IpAddr::V4(src)) => PacketBuilder::ipv4(dst.octets(), src.octets(), 64)
                            .tcp(flow_key.dst.port(), flow_key.src.port(), sequence_number, 65535)
                            .ack(acknowledgment_number)
                            .psh(),
                        (IpAddr::V6(dst), IpAddr::V6(src)) => PacketBuilder::ipv6(dst.octets(), src.octets(), 64)
                            .tcp(flow_key.dst.port(), flow_key.src.port(), sequence_number, 65535)
                            .ack(acknowledgment_number)
                            .psh(),
                        _ => break,
                    };

                    let mut packet = Vec::with_capacity(builder.size(chunk.len()));
                    if let Err(err) = builder.write(&mut packet, chunk) {
                        warn!("Failed to build reverse TCP packet for flow {:?}: {}", flow_key, err);
                        continue;
                    }

                    let write_result = tun_packet_tx.send(packet).await;

                    if let Err(err) = write_result {
                        warn!("Failed to write reverse TCP packet to TUN for flow {:?}: {}", flow_key, err);
                        chunk_write_failed = true;
                        break;
                    }
                }

                if chunk_write_failed {
                    break;
                }
            }

            let (should_send_fin, sequence_number, acknowledgment_number) = {
                let mut state = session.state.lock().await;
                if state.lifecycle == TcpLifecycle::Established {
                    let seq = state.server_next_seq;
                    state.server_next_seq = state.server_next_seq.wrapping_add(1);
                    state.lifecycle = TcpLifecycle::FinSent;
                    state.last_activity = Instant::now();
                    (true, seq, state.client_next_seq)
                } else {
                    (false, 0, 0)
                }
            };

            if should_send_fin {
                let builder = match (flow_key.dst.ip(), flow_key.src.ip()) {
                    (IpAddr::V4(dst), IpAddr::V4(src)) => PacketBuilder::ipv4(dst.octets(), src.octets(), 64)
                        .tcp(flow_key.dst.port(), flow_key.src.port(), sequence_number, 65535)
                        .ack(acknowledgment_number)
                        .fin(),
                    (IpAddr::V6(dst), IpAddr::V6(src)) => PacketBuilder::ipv6(dst.octets(), src.octets(), 64)
                        .tcp(flow_key.dst.port(), flow_key.src.port(), sequence_number, 65535)
                        .ack(acknowledgment_number)
                        .fin(),
                    _ => return,
                };

                let mut fin_packet = Vec::with_capacity(builder.size(0));
                if builder.write(&mut fin_packet, &[]).is_ok() {
                    let _ = tun_packet_tx.send(fin_packet).await;
                }
            }

            let should_remove = {
                let state = session.state.lock().await;
                state.lifecycle == TcpLifecycle::Closed
            };

            if should_remove {
                sessions.remove(&flow_key);
            }
        });
    }

    pub async fn cleanup_expired_tcp_sessions(&self) {
        let snapshot: Vec<(FlowKey, Arc<TcpSession>)> = {
            let table = &self.tcp_sessions;
            table
                .iter()
                .map(|entry| {
                    let (flow_key, session) = entry.pair();
                    (flow_key.clone(), session.clone())
                })
                .collect()
        };

        let now = Instant::now();
        let mut expired = Vec::new();

        for (flow_key, session) in snapshot {
            let state = session.state.lock().await;
            let is_fin_wait_expired = state.lifecycle == TcpLifecycle::FinSent
                && now.duration_since(state.last_activity) >= TCP_FIN_WAIT_TIMEOUT;
            if state.lifecycle == TcpLifecycle::Closed
                || is_fin_wait_expired
                || now.duration_since(state.last_activity) >= TCP_SESSION_IDLE_TIMEOUT
            {
                expired.push(flow_key);
            }
        }

        if expired.is_empty() {
            return;
        }

        for flow_key in expired {
            self.tcp_sessions.remove(&flow_key);
        }
    }
}
