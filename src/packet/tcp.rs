use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::{DashMap, DashSet};
use log::{debug, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};
use tokio::sync::{mpsc, mpsc::error::TryRecvError, Mutex};
use tokio::time::timeout;

use etherparse::{PacketBuilder, TcpHeaderSlice};

use crate::config::Config;
use crate::packet;
use crate::packet::shared::{
    collect_in_order_payload, seq_at_or_after, FlowKey, ParsedIpPacket, ProcessLookupEntry,
    ProcessLookupKey, TcpFlowState, TcpLifecycle, TcpSession, IPV4_TCP_HEADER_OVERHEAD,
    IPV6_TCP_HEADER_OVERHEAD, MAX_TCP_PAYLOAD, MIN_TCP_PAYLOAD, READ_BUF_MAX, READ_BUF_MIN,
};
use crate::process_lookup::{ProcessLookupOptions, TransportProtocol};
use crate::socks5_client::Socks5Client;

// ── Constants ─────────────────────────────────────────────────────────────────

const TCP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const TCP_FIN_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const TCP_ACK_COALESCE_DELAY: Duration = Duration::from_millis(2);
const TCP_ACK_MAX_BATCH_WRITES: usize = 8;

// ── TcpHandler ────────────────────────────────────────────────────────────────

pub struct TcpHandler {
    pub config: Arc<Config>,
    pub socks5_client: Arc<Socks5Client>,
    pub outbound_interface: Option<Arc<str>>,
    pub enable_user_space_process_exclusion: bool,
    pub tun_packet_tx: mpsc::Sender<Vec<u8>>,
    pub tcp_sessions: Arc<DashMap<FlowKey, Arc<TcpSession>>>,
    pub pending_connections: Arc<DashSet<FlowKey>>,
    pub process_name_cache: Arc<DashMap<ProcessLookupKey, ProcessLookupEntry>>,
    pub process_lookup_options: ProcessLookupOptions,
    pub dynamic_bypass_ips: Arc<DashMap<IpAddr, Instant>>,
}

impl TcpHandler {
    pub fn new(
        config: Arc<Config>,
        socks5_client: Arc<Socks5Client>,
        outbound_interface: Option<Arc<str>>,
        tun_packet_tx: mpsc::Sender<Vec<u8>>,
        enable_user_space_process_exclusion: bool,
    ) -> Self {
        let process_lookup_options = ProcessLookupOptions::from_config(&config);
        Self {
            config,
            socks5_client,
            outbound_interface,
            enable_user_space_process_exclusion,
            tun_packet_tx,
            tcp_sessions: Arc::new(DashMap::new()),
            pending_connections: Arc::new(DashSet::new()),
            process_name_cache: Arc::new(DashMap::new()),
            process_lookup_options,
            dynamic_bypass_ips: Arc::new(DashMap::new()),
        }
    }

    pub async fn handle_tcp_packet(
        &self,
        packet: &[u8],
        ip_packet: &ParsedIpPacket,
        is_static_bypass: bool,
    ) -> Result<()> {
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
            let session = self
                .tcp_sessions
                .get(&flow_key)
                .map(|entry| entry.value().clone());

            if let Some(session) = session {
                let is_ack_only_or_window_update =
                    payload.is_empty() && !tcp_header.fin() && !tcp_header.rst();
                let mut forward_payload: Option<Vec<u8>> = None;
                let mut send_fin: Option<(u32, u32)> = None;
                let mut remove_session = false;
                let mut should_return_early = false;
                let mut merged_payload_empty = false;
                let mut should_notify_reverse = false;

                {
                    let mut state = session.state.lock().await;

                    if tcp_header.fin() {
                        let client_ns = state.client_next_seq.load(Ordering::Relaxed);
                        if seq_at_or_after(tcp_header.sequence_number(), client_ns) {
                            state
                                .client_next_seq
                                .store(client_ns.wrapping_add(1), Ordering::Relaxed);
                        }
                        let seq = state.server_next_seq.load(Ordering::Relaxed);
                        state
                            .server_next_seq
                            .store(seq.wrapping_add(1), Ordering::Relaxed);
                        state.lifecycle = TcpLifecycle::FinSent;
                        state.last_activity = Instant::now();
                        send_fin = Some((seq, state.client_next_seq.load(Ordering::Relaxed)));
                        should_notify_reverse = true;
                    }

                    if tcp_header.rst() {
                        state.lifecycle = TcpLifecycle::Closed;
                        remove_session = true;
                        should_return_early = true;
                        should_notify_reverse = true;
                    }

                    if tcp_header.ack() {
                        let prev_window = state.client_window.load(Ordering::Relaxed);
                        let new_window = tcp_header.window_size();
                        state.client_window.store(new_window, Ordering::Relaxed);
                        if new_window != prev_window {
                            should_notify_reverse = true;
                        }

                        // Complete three-way handshake if still in SynReceived.
                        if state.lifecycle == TcpLifecycle::SynReceived {
                            state.lifecycle = TcpLifecycle::Established;
                        }

                        let srv_acked = state.server_acked_seq.load(Ordering::Relaxed);
                        if seq_at_or_after(tcp_header.acknowledgment_number(), srv_acked) {
                            state
                                .server_acked_seq
                                .store(tcp_header.acknowledgment_number(), Ordering::Relaxed);
                            should_notify_reverse = true;
                        }

                        if state.lifecycle == TcpLifecycle::FinSent
                            && tcp_header.acknowledgment_number()
                                == state.server_next_seq.load(Ordering::Relaxed)
                        {
                            state.lifecycle = TcpLifecycle::Closed;
                            remove_session = true;
                            should_return_early = true;
                            should_notify_reverse = true;
                        }
                    }

                    if !should_return_early
                        && (state.lifecycle == TcpLifecycle::Closed
                            || state.lifecycle == TcpLifecycle::FinSent)
                    {
                        should_return_early = true;
                    }

                    if !should_return_early && !is_ack_only_or_window_update && !payload.is_empty()
                    {
                        let merged = collect_in_order_payload(
                            &mut state,
                            tcp_header.sequence_number(),
                            payload,
                        );
                        state.last_activity = Instant::now();
                        if merged.is_empty() {
                            merged_payload_empty = true;
                            should_return_early = true;
                        } else {
                            forward_payload = Some(merged);
                        }
                    }
                }

                if should_notify_reverse {
                    session.window_notify.notify_waiters();
                }

                if let Some((sequence_number, acknowledgment_number)) = send_fin {
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

                if remove_session {
                    self.tcp_sessions.remove(&flow_key);
                }

                if should_return_early {
                    if merged_payload_empty {
                        debug!(
                            "Buffered/dropped non-forwardable TCP segment {}:{} -> {}:{}",
                            ip_packet.src, source_port, ip_packet.dst, dest_port
                        );
                    }
                    return Ok(());
                }

                if is_ack_only_or_window_update {
                    return Ok(());
                }

                if let Some(forward_payload) = forward_payload {
                    if session.forward_tx.try_send(forward_payload).is_err() {
                        let (sequence_number, acknowledgment_number) = {
                            let state = session.state.lock().await;
                            (
                                state.server_next_seq.load(Ordering::Relaxed),
                                state.client_next_seq.load(Ordering::Relaxed),
                            )
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
                if !self.pending_connections.contains(&flow_key) {
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
        let is_direct_flow = if is_static_bypass {
            true // skip the async process-name lookup for static bypass IPs
        } else if !self.enable_user_space_process_exclusion {
            false
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
                if !self.try_mark_connect_pending(&flow_key).await {
                    return Ok(());
                }

                let tun_packet_tx = self.tun_packet_tx.clone();
                let tcp_sessions: Arc<DashMap<FlowKey, Arc<TcpSession>>> =
                    self.tcp_sessions.clone();
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

                    pending_connections.remove(&fk);

                    match connect_result {
                        Ok(Ok(stream)) => {
                            Self::admit_connected_stream(
                                fk.clone(),
                                client_isn,
                                stream,
                                mtu,
                                tun_packet_tx.clone(),
                                tcp_sessions.clone(),
                            )
                            .await;
                            debug!("Direct TCP proxy established for excluded flow {:?}", fk);
                        }
                        Ok(Err(err)) => {
                            warn!(
                                "Direct TCP connect failed for excluded flow {:?}: {}",
                                fk, err
                            );
                            Self::send_connect_failure_rst(&tun_packet_tx, &fk, client_isn).await;
                        }
                        Err(_) => {
                            warn!("Direct TCP connect timed out for excluded flow {:?}", fk);
                            Self::send_connect_failure_rst(&tun_packet_tx, &fk, client_isn).await;
                        }
                    }
                });

                debug!(
                    "{} TCP {}:{} -> {}:{}: direct-proxying via physical NIC",
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
        if let Some(session) = self
            .tcp_sessions
            .get(&flow_key)
            .map(|entry| entry.value().clone())
        {
            let resend_syn_ack = {
                let mut state = session.state.lock().await;
                state.last_activity = Instant::now();
                if state.lifecycle == TcpLifecycle::SynReceived {
                    Some((
                        state
                            .server_next_seq
                            .load(Ordering::Relaxed)
                            .wrapping_sub(1),
                        state.client_next_seq.load(Ordering::Relaxed),
                    ))
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
        if !self.try_mark_connect_pending(&flow_key).await {
            return Ok(());
        }

        let socks5_client = self.socks5_client.clone();
        let tun_packet_tx = self.tun_packet_tx.clone();
        let tcp_sessions: Arc<DashMap<FlowKey, Arc<TcpSession>>> = self.tcp_sessions.clone();
        let pending_connections = self.pending_connections.clone();
        let mtu = self.config.tun.mtu as usize;
        let client_isn = tcp_header.sequence_number();
        let fk = flow_key.clone();

        tokio::spawn(async move {
            let connect_result = timeout(TCP_CONNECT_TIMEOUT, socks5_client.connect(fk.dst)).await;

            pending_connections.remove(&fk);

            match connect_result {
                Ok(Ok(stream)) => {
                    Self::admit_connected_stream(
                        fk.clone(),
                        client_isn,
                        stream,
                        mtu,
                        tun_packet_tx.clone(),
                        tcp_sessions.clone(),
                    )
                    .await;
                }
                Ok(Err(err)) => {
                    warn!("SOCKS5 connect failed for {:?}: {}", fk, err);
                    Self::send_connect_failure_rst(&tun_packet_tx, &fk, client_isn).await;
                }
                Err(_) => {
                    warn!("SOCKS5 connect timed out for {:?}", fk);
                    Self::send_connect_failure_rst(&tun_packet_tx, &fk, client_isn).await;
                }
            }
        });

        Ok(())
    }

    async fn try_mark_connect_pending(&self, flow_key: &FlowKey) -> bool {
        self.pending_connections.insert(flow_key.clone())
    }

    async fn send_connect_failure_rst(
        tun_packet_tx: &mpsc::Sender<Vec<u8>>,
        flow_key: &FlowKey,
        client_isn: u32,
    ) {
        let _ = packet::packet_build::inject_tcp_control(
            tun_packet_tx,
            flow_key,
            0,
            client_isn.wrapping_add(1),
            false,
            false,
            true,
        )
        .await;
    }

    async fn admit_connected_stream(
        flow_key: FlowKey,
        client_isn: u32,
        stream: TcpStream,
        mtu: usize,
        tun_packet_tx: mpsc::Sender<Vec<u8>>,
        tcp_sessions: Arc<DashMap<FlowKey, Arc<TcpSession>>>,
    ) {
        let (reader, writer) = stream.into_split();
        let writer = Arc::new(Mutex::new(writer));
        let (forward_tx, forward_rx) = mpsc::channel::<Vec<u8>>(64);

        let session = Arc::new(TcpSession {
            state: Arc::new(Mutex::new(TcpFlowState {
                client_next_seq: AtomicU32::new(client_isn.wrapping_add(1)),
                server_next_seq: AtomicU32::new(1),
                server_acked_seq: AtomicU32::new(1),
                client_window: AtomicU16::new(65535),
                reorder_buffer: BTreeMap::new(),
                reorder_bytes: 0,
                lifecycle: TcpLifecycle::SynReceived,
                last_activity: Instant::now(),
            })),
            forward_tx,
            window_notify: Arc::new(tokio::sync::Notify::new()),
        });

        let syn_ack_seq = {
            let state = session.state.lock().await;
            let seq = state.server_next_seq.load(Ordering::Relaxed);
            state
                .server_next_seq
                .store(seq.wrapping_add(1), Ordering::Relaxed);
            seq
        };

        tcp_sessions.insert(flow_key.clone(), session.clone());

        Self::spawn_forward_writer_task(
            flow_key.clone(),
            forward_rx,
            writer,
            session.state.clone(),
            tcp_sessions.clone(),
            tun_packet_tx.clone(),
        );

        Self::spawn_reverse_tcp_task(
            flow_key.clone(),
            reader,
            session,
            tcp_sessions,
            tun_packet_tx.clone(),
            mtu,
        );

        let _ = packet::packet_build::inject_tcp_control(
            &tun_packet_tx,
            &flow_key,
            syn_ack_seq,
            client_isn.wrapping_add(1),
            true,
            false,
            false,
        )
        .await;
    }

    /// Spawn a task that drains the per-session forward channel and writes
    /// payload batches to the SOCKS5 TCP stream in order, then emits one ACK
    /// for the whole batch to the TUN-side client.
    fn spawn_forward_writer_task(
        flow_key: FlowKey,
        mut forward_rx: mpsc::Receiver<Vec<u8>>,
        writer: Arc<Mutex<OwnedWriteHalf>>,
        state: Arc<Mutex<TcpFlowState>>,
        sessions: Arc<DashMap<FlowKey, Arc<TcpSession>>>,
        tun_packet_tx: mpsc::Sender<Vec<u8>>,
    ) {
        tokio::spawn(async move {
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(TCP_ACK_MAX_BATCH_WRITES);

            loop {
                batch.clear();
                let Some(first_payload) = forward_rx.recv().await else {
                    break;
                };
                batch.push(first_payload);

                let batch_deadline = Instant::now() + TCP_ACK_COALESCE_DELAY;
                let mut channel_closed = false;

                while batch.len() < TCP_ACK_MAX_BATCH_WRITES {
                    match forward_rx.try_recv() {
                        Ok(payload) => batch.push(payload),
                        Err(TryRecvError::Empty) => {
                            let now = Instant::now();
                            if now >= batch_deadline {
                                break;
                            }

                            match timeout(batch_deadline - now, forward_rx.recv()).await {
                                Ok(Some(payload)) => batch.push(payload),
                                Ok(None) => {
                                    channel_closed = true;
                                    break;
                                }
                                Err(_) => break,
                            }
                        }
                        Err(TryRecvError::Disconnected) => {
                            channel_closed = true;
                            break;
                        }
                    }
                }

                let write_result = {
                    let mut w = writer.lock().await;
                    let mut write_error = None;
                    for payload in &batch {
                        if let Err(err) = w.write_all(payload).await {
                            write_error = Some(err);
                            break;
                        }
                    }
                    write_error
                };

                if let Some(err) = write_result {
                    let (sequence_number, acknowledgment_number) = {
                        let s = state.lock().await;
                        (
                            s.server_next_seq.load(Ordering::Relaxed),
                            s.client_next_seq.load(Ordering::Relaxed),
                        )
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

                // ACK all forwarded payloads in this coalesced batch.
                let (ack_seq, ack_ack) = {
                    let mut s = state.lock().await;
                    s.last_activity = Instant::now();
                    if s.lifecycle == TcpLifecycle::SynReceived {
                        s.lifecycle = TcpLifecycle::Established;
                    }
                    (
                        s.server_next_seq.load(Ordering::Relaxed),
                        s.client_next_seq.load(Ordering::Relaxed),
                    )
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

                if channel_closed {
                    break;
                }
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
                (IpAddr::V6(_), IpAddr::V6(_)) => IPV6_TCP_HEADER_OVERHEAD,
                _ => IPV4_TCP_HEADER_OVERHEAD,
            };
            let max_payload_per_packet = mtu
                .saturating_sub(header_overhead)
                .clamp(MIN_TCP_PAYLOAD, MAX_TCP_PAYLOAD);
            // Keep per-flow read buffer bounded near MTU scale to reduce memory under many flows.
            let read_buf_len = mtu.saturating_mul(2).clamp(READ_BUF_MIN, READ_BUF_MAX);
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
                        let notified = session.window_notify.notified();
                        let (terminated, can_send) = {
                            let state = session.state.lock().await;
                            if state.lifecycle == TcpLifecycle::Closed
                                || state.lifecycle == TcpLifecycle::FinSent
                            {
                                (true, false)
                            } else {
                                let in_flight =
                                    state.server_next_seq.load(Ordering::Relaxed).wrapping_sub(
                                        state.server_acked_seq.load(Ordering::Relaxed),
                                    ) as usize;
                                let wnd =
                                    usize::from(state.client_window.load(Ordering::Relaxed)).max(1);
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

                        notified.await;
                    }

                    if chunk_write_failed {
                        break;
                    }

                    let (sequence_number, acknowledgment_number) = {
                        let mut state = session.state.lock().await;
                        if state.lifecycle == TcpLifecycle::SynReceived {
                            state.lifecycle = TcpLifecycle::Established;
                        }
                        let seq = state.server_next_seq.load(Ordering::Relaxed);
                        let ack = state.client_next_seq.load(Ordering::Relaxed);
                        state
                            .server_next_seq
                            .store(seq.wrapping_add(chunk.len() as u32), Ordering::Relaxed);
                        state.last_activity = Instant::now();
                        (seq, ack)
                    };

                    let builder = match (flow_key.dst.ip(), flow_key.src.ip()) {
                        (IpAddr::V4(dst), IpAddr::V4(src)) => {
                            PacketBuilder::ipv4(dst.octets(), src.octets(), 64)
                                .tcp(
                                    flow_key.dst.port(),
                                    flow_key.src.port(),
                                    sequence_number,
                                    65535,
                                )
                                .ack(acknowledgment_number)
                                .psh()
                        }
                        (IpAddr::V6(dst), IpAddr::V6(src)) => {
                            PacketBuilder::ipv6(dst.octets(), src.octets(), 64)
                                .tcp(
                                    flow_key.dst.port(),
                                    flow_key.src.port(),
                                    sequence_number,
                                    65535,
                                )
                                .ack(acknowledgment_number)
                                .psh()
                        }
                        _ => break,
                    };

                    let mut packet = Vec::with_capacity(builder.size(chunk.len()));
                    if let Err(err) = builder.write(&mut packet, chunk) {
                        warn!(
                            "Failed to build reverse TCP packet for flow {:?}: {}",
                            flow_key, err
                        );
                        continue;
                    }

                    let write_result = tun_packet_tx.send(packet).await;

                    if let Err(err) = write_result {
                        warn!(
                            "Failed to write reverse TCP packet to TUN for flow {:?}: {}",
                            flow_key, err
                        );
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
                    let seq = state.server_next_seq.load(Ordering::Relaxed);
                    state
                        .server_next_seq
                        .store(seq.wrapping_add(1), Ordering::Relaxed);
                    state.lifecycle = TcpLifecycle::FinSent;
                    state.last_activity = Instant::now();
                    (true, seq, state.client_next_seq.load(Ordering::Relaxed))
                } else {
                    (false, 0, 0)
                }
            };

            if should_send_fin {
                let builder = match (flow_key.dst.ip(), flow_key.src.ip()) {
                    (IpAddr::V4(dst), IpAddr::V4(src)) => {
                        PacketBuilder::ipv4(dst.octets(), src.octets(), 64)
                            .tcp(
                                flow_key.dst.port(),
                                flow_key.src.port(),
                                sequence_number,
                                65535,
                            )
                            .ack(acknowledgment_number)
                            .fin()
                    }
                    (IpAddr::V6(dst), IpAddr::V6(src)) => {
                        PacketBuilder::ipv6(dst.octets(), src.octets(), 64)
                            .tcp(
                                flow_key.dst.port(),
                                flow_key.src.port(),
                                sequence_number,
                                65535,
                            )
                            .ack(acknowledgment_number)
                            .fin()
                    }
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
        let mut expired = Vec::with_capacity(snapshot.len().min(64));

        for (flow_key, session) in snapshot {
            let mut state = session.state.lock().await;
            let is_fin_wait_expired = state.lifecycle == TcpLifecycle::FinSent
                && now.duration_since(state.last_activity) >= TCP_FIN_WAIT_TIMEOUT;
            if state.lifecycle == TcpLifecycle::Closed
                || is_fin_wait_expired
                || now.duration_since(state.last_activity) >= TCP_SESSION_IDLE_TIMEOUT
            {
                state.lifecycle = TcpLifecycle::Closed;
                expired.push((flow_key, session.clone()));
            }
        }

        if expired.is_empty() {
            return;
        }

        for (flow_key, session) in expired {
            session.window_notify.notify_waiters();
            self.tcp_sessions.remove(&flow_key);
        }
    }
}
