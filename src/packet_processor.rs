use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::{collections::BTreeMap, collections::HashMap, collections::HashSet, hash::Hash};
use std::time::{Duration, Instant};

use anyhow::Result;
use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{sleep, timeout};

use etherparse::{
    Ipv4HeaderSlice, Ipv6HeaderSlice, PacketBuilder, TcpHeaderSlice, UdpHeader, UdpHeaderSlice,
};
use crate::config::Config;
use crate::dns_router::DnsRouter;
use crate::process_lookup::{self, ProcessLookupOptions, TransportProtocol};
use crate::route_manager;
use crate::socks5_client::{Socks5Client, Socks5UdpSession};

struct ParsedIpPacket {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    header_len: usize,
}

pub struct PacketProcessor {
    config: Config,
    socks5_client: Socks5Client,
    dns_router: Arc<DnsRouter>,
    process_lookup_options: ProcessLookupOptions,
    outbound_interface: Option<String>,
    tun_packet_tx: mpsc::Sender<Vec<u8>>,
    tcp_sessions: Arc<Mutex<HashMap<FlowKey, Arc<TcpSession>>>>,
    pending_connections: Arc<Mutex<HashSet<FlowKey>>>,
    udp_sessions: Arc<Mutex<HashMap<UdpFlowKey, UdpSessionEntry>>>,
    pending_udp_sessions: Arc<Mutex<HashSet<UdpFlowKey>>>,
    udp_timeout_backoff: Arc<Mutex<HashMap<UdpFlowKey, Instant>>>,
    process_name_cache: Arc<Mutex<HashMap<ProcessLookupKey, ProcessLookupEntry>>>,
    dynamic_bypass_ips: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    dns_task_limiter: Arc<Semaphore>,
    udp_task_limiter: Arc<Semaphore>,
}

#[derive(Clone, Debug, Eq)]
struct ProcessLookupKey {
    protocol: TransportProtocol,
    src: SocketAddr,
    dst: SocketAddr,
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

#[derive(Clone, Debug)]
struct ProcessLookupEntry {
    process_name: Option<String>,
    recorded_at: Instant,
}

struct TcpSession {
    state: Arc<Mutex<TcpFlowState>>,
    /// Channel used to pass forward payloads to the per-session writer task,
    /// keeping the main packet loop non-blocking.
    forward_tx: mpsc::Sender<Vec<u8>>,
}

#[derive(Clone, Debug, Eq)]
struct UdpFlowKey {
    src: SocketAddr,
    dst: SocketAddr,
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

#[derive(Clone)]
struct UdpSessionEntry {
    session: Arc<Mutex<Socks5UdpSession>>,
    last_activity: Instant,
}

#[derive(Debug)]
struct TcpFlowState {
    client_next_seq: u32,
    server_next_seq: u32,
    server_acked_seq: u32,
    client_window: u16,
    reorder_buffer: BTreeMap<u32, Vec<u8>>,
    reorder_bytes: usize,
    lifecycle: TcpLifecycle,
    last_activity: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpLifecycle {
    SynReceived,
    Established,
    FinSent,
    Closed,
}

#[derive(Clone, Debug, Eq)]
struct FlowKey {
    src: SocketAddr,
    dst: SocketAddr,
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

impl PacketProcessor {
    const TCP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
    const TCP_FIN_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
    const TCP_SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);
    const TCP_REORDER_BUFFER_LIMIT: usize = 64 * 1024;
    const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    const PROCESS_LOOKUP_CACHE_TTL: Duration = Duration::from_secs(5);
    const DYNAMIC_BYPASS_ROUTE_TTL: Duration = Duration::from_secs(300);
    const DYNAMIC_BYPASS_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
    const UDP_PROXY_TIMEOUT: Duration = Duration::from_millis(1200);
    const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
    const UDP_SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
    const UDP_TIMEOUT_BACKOFF: Duration = Duration::from_secs(30);
    const DNS_TASK_CONCURRENCY_LIMIT: usize = 32;
    const UDP_TASK_CONCURRENCY_LIMIT: usize = 64;
    const TUN_WRITE_QUEUE_CAPACITY: usize = 512;
    const TUN_WRITE_ENQUEUE_TIMEOUT: Duration = Duration::from_millis(5);
    const PROCESS_CACHE_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
    const PROCESS_CACHE_MAX_ENTRIES: usize = 1024;

    pub fn new(
        config: Config,
        tun_writer: Arc<tun_rs::AsyncDevice>,
        outbound_interface: Option<String>,
    ) -> Result<Self> {
        let socks5_client = Socks5Client::new(config.socks5.clone(), outbound_interface.clone());
        let dns_router = Arc::new(DnsRouter::new(config.dns.clone(), &config, outbound_interface.clone())?);
        let process_lookup_options = ProcessLookupOptions::from_config(&config);
        let (tun_packet_tx, mut tun_packet_rx) = mpsc::channel::<Vec<u8>>(Self::TUN_WRITE_QUEUE_CAPACITY);

        tokio::spawn(async move {
            while let Some(packet) = tun_packet_rx.recv().await {
                if let Err(err) = tun_writer.send(&packet).await {
                    warn!("Failed to write packet to TUN from writer queue: {}", err);
                }
            }
        });
        
        Ok(Self {
            config,
            socks5_client,
            dns_router,
            process_lookup_options,
            outbound_interface,
            tun_packet_tx,
            tcp_sessions: Arc::new(Mutex::new(HashMap::new())),
            pending_connections: Arc::new(Mutex::new(HashSet::new())),
            udp_sessions: Arc::new(Mutex::new(HashMap::new())),
            pending_udp_sessions: Arc::new(Mutex::new(HashSet::new())),
            udp_timeout_backoff: Arc::new(Mutex::new(HashMap::new())),
            process_name_cache: Arc::new(Mutex::new(HashMap::new())),
            dynamic_bypass_ips: Arc::new(Mutex::new(HashMap::new())),
            dns_task_limiter: Arc::new(Semaphore::new(Self::DNS_TASK_CONCURRENCY_LIMIT)),
            udp_task_limiter: Arc::new(Semaphore::new(Self::UDP_TASK_CONCURRENCY_LIMIT)),
        })
    }

    pub fn dynamic_bypass_ips_handle(&self) -> Arc<Mutex<HashMap<IpAddr, Instant>>> {
        self.dynamic_bypass_ips.clone()
    }
    
    pub async fn process_packets(&self, tun_reader: Arc<tun_rs::AsyncDevice>) -> Result<()> {
        info!("Starting packet processing");
        
        let mut buffer = vec![0; self.config.tun.mtu as usize];
        let mut last_cleanup_at = Instant::now();
        let mut last_dynamic_cleanup_at = Instant::now();
        let mut last_udp_session_cleanup_at = Instant::now();
        let mut last_process_cache_cleanup_at = Instant::now();
        
        loop {
            if last_cleanup_at.elapsed() >= Self::TCP_SESSION_CLEANUP_INTERVAL {
                self.cleanup_expired_tcp_sessions().await;
                last_cleanup_at = Instant::now();
            }
            if last_dynamic_cleanup_at.elapsed() >= Self::DYNAMIC_BYPASS_CLEANUP_INTERVAL {
                self.cleanup_expired_dynamic_bypass_routes().await;
                last_dynamic_cleanup_at = Instant::now();
            }
            if last_udp_session_cleanup_at.elapsed() >= Self::UDP_SESSION_CLEANUP_INTERVAL {
                self.cleanup_expired_udp_sessions().await;
                last_udp_session_cleanup_at = Instant::now();
            }
            if last_process_cache_cleanup_at.elapsed() >= Self::PROCESS_CACHE_CLEANUP_INTERVAL {
                self.cleanup_process_lookup_cache().await;
                last_process_cache_cleanup_at = Instant::now();
            }

            let bytes_read = tun_reader.recv(&mut buffer).await?;
            
            if bytes_read == 0 {
                continue;
            }
            
            let packet = &buffer[..bytes_read];
            
            if let Err(e) = self.process_packet(packet).await {
                error!("Error processing packet: {}", e);
            }
        }
    }
    
    async fn process_packet(&self, packet: &[u8]) -> Result<()> {
        // Parse IP header
        if packet.len() < 20 {
            return Err(anyhow::anyhow!("Packet too short"));
        }

        let ip_version = packet[0] >> 4;
        let parsed = match ip_version {
            4 => {
                let ip_header = Ipv4HeaderSlice::from_slice(packet)?;
                ParsedIpPacket {
                    src: IpAddr::V4(ip_header.source_addr()),
                    dst: IpAddr::V4(ip_header.destination_addr()),
                    protocol: ip_header.protocol().0,
                    header_len: (ip_header.ihl() as usize) * 4,
                }
            }
            6 => {
                if packet.len() < 40 {
                    return Err(anyhow::anyhow!("IPv6 packet too short"));
                }

                let ip_header = Ipv6HeaderSlice::from_slice(packet)?;
                ParsedIpPacket {
                    src: IpAddr::V6(ip_header.source_addr()),
                    dst: IpAddr::V6(ip_header.destination_addr()),
                    protocol: ip_header.next_header().0,
                    header_len: 40,
                }
            }
            _ => return Ok(()),
        };
        
        // Check if we should skip this IP
        let dest_ip = parsed.dst;
        if self.config.should_skip_ip(dest_ip) {
            debug!("Skipping packet to {}", dest_ip);
            return Ok(());
        }
        
        // Handle different protocols
        match parsed.protocol {
            6 => self.handle_tcp_packet(packet, &parsed).await,
            17 => self.handle_udp_packet(packet, &parsed).await,
            _ => {
                debug!("Unsupported protocol number: {}", parsed.protocol);
                Ok(())
            }
        }
    }
    
    async fn handle_tcp_packet(&self, packet: &[u8], ip_packet: &ParsedIpPacket) -> Result<()> {
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
            let session = {
                let table = self.tcp_sessions.lock().await;
                table.get(&flow_key).cloned()
            };

            if let Some(session) = session {
                let is_ack_only_or_window_update =
                    payload.is_empty() && !tcp_header.fin() && !tcp_header.rst();

                if tcp_header.rst() || tcp_header.fin() {
                    if tcp_header.fin() {
                        let (sequence_number, acknowledgment_number) = {
                            let mut state = session.state.lock().await;
                            if Self::seq_at_or_after(
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
                        self.inject_tcp_control_packet(
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
                        self.tcp_sessions.lock().await.remove(&flow_key);
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
                        if Self::seq_at_or_after(
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
                        self.tcp_sessions.lock().await.remove(&flow_key);
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
                        let merged = Self::collect_in_order_payload(
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
                        let _ = self
                            .inject_tcp_control_packet(
                                &flow_key,
                                sequence_number,
                                acknowledgment_number,
                                false,
                                false,
                                true,
                            )
                            .await;
                        self.tcp_sessions.lock().await.remove(&flow_key);
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
        // Process exclusion is only evaluated for new connection attempts (SYNs),
        // not for every data packet on established flows.
        if self
            .should_exclude_process_flow(TransportProtocol::Tcp, source_addr, target_addr)
            .await
        {
            // ── Preferred path: transparent direct proxy via physical NIC ──────
            // When an outbound interface is known, accept the SYN and proxy the
            // TCP connection directly to the destination via SO_BINDTODEVICE.
            // The TUN session is set up identically to the SOCKS5 path — no RST,
            // no reconnect, no connection interruption for the application.
            if let Some(iface) = self.outbound_interface.clone() {
                {
                    let mut pending = self.pending_connections.lock().await;
                    if pending.contains(&flow_key) {
                        return Ok(());
                    }
                    pending.insert(flow_key.clone());
                }

                let tun_packet_tx = self.tun_packet_tx.clone();
                let tcp_sessions = self.tcp_sessions.clone();
                let pending_connections = self.pending_connections.clone();
                let mtu = self.config.tun.mtu as usize;
                let client_isn = tcp_header.sequence_number();
                let fk = flow_key.clone();

                tokio::spawn(async move {
                    let connect_result = timeout(
                        PacketProcessor::TCP_CONNECT_TIMEOUT,
                        PacketProcessor::open_direct_tcp(fk.dst, iface),
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

                            {
                                let mut table = tcp_sessions.lock().await;
                                table.insert(fk.clone(), session.clone());
                            }

                            PacketProcessor::spawn_forward_writer_task(
                                fk.clone(),
                                forward_rx,
                                writer,
                                session.state.clone(),
                                tcp_sessions.clone(),
                                tun_packet_tx.clone(),
                            );

                            PacketProcessor::spawn_reverse_tcp_task(
                                fk.clone(),
                                reader,
                                session,
                                tcp_sessions,
                                tun_packet_tx.clone(),
                                mtu,
                            );

                            let _ = PacketProcessor::inject_tcp_control(
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
                            let _ = PacketProcessor::inject_tcp_control(
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
                            let _ = PacketProcessor::inject_tcp_control(
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
                    "Excluded process flow (TCP) {}:{} -> {}:{}: direct-proxying",
                    ip_packet.src, source_port, ip_packet.dst, dest_port
                );
                return Ok(());
            }

            // ── Fallback: route-based bypass (RST + reconnect) ────────────────
            // No outbound interface is configured; install a kernel /32 route so
            // the app's next reconnect goes via the physical NIC directly.
            // Defensively remove any ghost session.
            let had_session = {
                let mut table = self.tcp_sessions.lock().await;
                table.remove(&flow_key).is_some()
            };

            let mut should_reset = !self.config.tun.auto_route || had_session;

            if self.config.tun.auto_route {
                if let Err(err) = self.ensure_dynamic_bypass_for_ip(target_addr.ip()).await {
                    warn!(
                        "Failed to install dynamic bypass route for excluded flow {}:{} -> {}:{}: {}",
                        ip_packet.src, source_port, ip_packet.dst, dest_port, err
                    );
                    should_reset = true;
                }
            }

            if should_reset {
                let _ = self
                    .inject_tcp_control_packet(
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
        if let Some(session) = {
            let table = self.tcp_sessions.lock().await;
            table.get(&flow_key).cloned()
        } {
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
                self.inject_tcp_control_packet(
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
        let tcp_sessions = self.tcp_sessions.clone();
        let pending_connections = self.pending_connections.clone();
        let mtu = self.config.tun.mtu as usize;
        let client_isn = tcp_header.sequence_number();
        let fk = flow_key.clone();

        tokio::spawn(async move {
            let connect_result = timeout(
                PacketProcessor::TCP_CONNECT_TIMEOUT,
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

                    {
                        let mut table = tcp_sessions.lock().await;
                        table.insert(fk.clone(), session.clone());
                    }

                    PacketProcessor::spawn_forward_writer_task(
                        fk.clone(),
                        forward_rx,
                        writer,
                        session.state.clone(),
                        tcp_sessions.clone(),
                        tun_packet_tx.clone(),
                    );

                    PacketProcessor::spawn_reverse_tcp_task(
                        fk.clone(),
                        reader,
                        session,
                        tcp_sessions,
                        tun_packet_tx.clone(),
                        mtu,
                    );

                    let _ = PacketProcessor::inject_tcp_control(
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
                    let _ = PacketProcessor::inject_tcp_control(
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
                    let _ = PacketProcessor::inject_tcp_control(
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

    fn seq_at_or_after(candidate: u32, reference: u32) -> bool {
        (candidate.wrapping_sub(reference) as i32) >= 0
    }

    fn collect_in_order_payload(
        state: &mut TcpFlowState,
        seg_start: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let expected = state.client_next_seq;
        let seg_end = seg_start.wrapping_add(payload.len() as u32);

        if Self::seq_at_or_after(expected, seg_end) {
            // Fully duplicate/retransmitted bytes.
            return Vec::new();
        }

        let mut trimmed_start = 0usize;
        if Self::seq_at_or_after(expected, seg_start) {
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

            if state.reorder_bytes > Self::TCP_REORDER_BUFFER_LIMIT {
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
    
    async fn handle_udp_packet(&self, packet: &[u8], ip_packet: &ParsedIpPacket) -> Result<()> {
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

        let source_addr = SocketAddr::new(ip_packet.src, source_port);
        let target_addr = SocketAddr::new(ip_packet.dst, dest_port);

        if !Self::is_proxyable_udp_destination(target_addr.ip()) {
            debug!(
                "Skipping local-scope UDP flow {}:{} -> {}:{}",
                ip_packet.src,
                source_port,
                ip_packet.dst,
                dest_port
            );
            return Ok(());
        }

        if self
            .should_exclude_process_flow(TransportProtocol::Udp, source_addr, target_addr)
            .await
        {
            // ── Preferred path: direct UDP exchange via physical NIC ───────────
            // Relay the datagram through a socket bound to the physical interface
            // and inject the response back to TUN. The application never sees a
            // dropped packet, so no connection is interrupted.
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
                        PacketProcessor::UDP_PROXY_TIMEOUT,
                        PacketProcessor::direct_udp_exchange(target_addr, udp_payload, iface),
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
                            let _ = PacketProcessor::write_tun_packet_with(
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
                    "Excluded process flow (UDP) {}:{} -> {}:{}: direct forwarding",
                    ip_packet.src, source_port, ip_packet.dst, dest_port
                );
                return Ok(());
            }

            // ── Fallback: route-based bypass ───────────────────────────────────
            if self.config.tun.auto_route {
                if let Err(err) = self.ensure_dynamic_bypass_for_ip(target_addr.ip()).await {
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

                let dns_txid = PacketProcessor::dns_txid(&udp_payload);
                let response_payload = match dns_router.resolve(&udp_payload).await {
                    Ok(resp) => PacketProcessor::normalize_dns_response_for_query(&udp_payload, resp),
                    Err(err) => {
                        warn!(
                            "DNS forwarding failed for {}:{}: {}; returning spoofed SERVFAIL",
                            dst_ip,
                            dest_port,
                            err
                        );
                        PacketProcessor::build_dns_servfail_response(&udp_payload)
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
                if PacketProcessor::write_tun_packet_with(tun_packet_tx, response_packet)
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
                PacketProcessor::UDP_PROXY_TIMEOUT,
                PacketProcessor::proxy_udp_with_reused_session_shared(
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
                    PacketProcessor::clear_udp_backoff_shared(udp_timeout_backoff.clone(), &udp_flow_key)
                        .await;
                    resp
                }
                Ok(Err(err)) => {
                    PacketProcessor::mark_udp_flow_backoff_shared(
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
                    PacketProcessor::mark_udp_flow_backoff_shared(
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
            if PacketProcessor::write_tun_packet_with(tun_packet_tx, response_packet)
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

    fn is_proxyable_udp_destination(ip: IpAddr) -> bool {
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

    async fn proxy_udp_with_reused_session_shared(
        socks5_client: Socks5Client,
        udp_sessions: Arc<Mutex<HashMap<UdpFlowKey, UdpSessionEntry>>>,
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
            !pending.insert(flow_key.clone())
        };
        if is_already_pending {
            return Err(anyhow::anyhow!(
                "UDP ASSOCIATE session establishment already in progress for {} -> {}",
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
            let mut table = udp_sessions.lock().await;
            table.insert(
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
        udp_sessions: Arc<Mutex<HashMap<UdpFlowKey, UdpSessionEntry>>>,
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
                let mut table = udp_sessions.lock().await;
                if let Some(entry) = table.get_mut(flow_key) {
                    entry.last_activity = Instant::now();
                }
                Ok(resp)
            }
            Err(err) => {
                let mut table = udp_sessions.lock().await;
                table.remove(flow_key);
                Err(err)
            }
        }
    }

    async fn get_cached_udp_session_shared(
        udp_sessions: Arc<Mutex<HashMap<UdpFlowKey, UdpSessionEntry>>>,
        flow_key: &UdpFlowKey,
    ) -> Option<Arc<Mutex<Socks5UdpSession>>> {
        let mut table = udp_sessions.lock().await;
        if let Some(entry) = table.get_mut(flow_key) {
            entry.last_activity = Instant::now();
            return Some(entry.session.clone());
        }
        None
    }

    async fn remove_udp_session_shared(
        udp_sessions: Arc<Mutex<HashMap<UdpFlowKey, UdpSessionEntry>>>,
        flow_key: &UdpFlowKey,
    ) {
        let mut table = udp_sessions.lock().await;
        table.remove(flow_key);
    }

    async fn cleanup_expired_udp_sessions(&self) {
        let removed = {
            let mut table = self.udp_sessions.lock().await;
            let now = Instant::now();
            let before = table.len();
            table.retain(|_, entry| now.duration_since(entry.last_activity) < Self::UDP_SESSION_IDLE_TIMEOUT);
            before.saturating_sub(table.len())
        };

        if removed > 0 {
            debug!("Cleaned up {} idle UDP ASSOCIATE sessions", removed);
        }

        {
            let mut backoff = self.udp_timeout_backoff.lock().await;
            let now = Instant::now();
            backoff.retain(|_, until| *until > now);
        }
    }

    async fn cleanup_process_lookup_cache(&self) {
        let now = Instant::now();

        {
            let mut cache = self.process_name_cache.lock().await;
            cache.retain(|_, entry| now.duration_since(entry.recorded_at) <= Self::PROCESS_LOOKUP_CACHE_TTL);

            if cache.len() > Self::PROCESS_CACHE_MAX_ENTRIES {
                let overflow = cache.len() - Self::PROCESS_CACHE_MAX_ENTRIES;
                let mut entries = cache
                    .iter()
                    .map(|(key, entry)| (key.clone(), entry.recorded_at))
                    .collect::<Vec<_>>();

                entries.sort_by_key(|(_, recorded_at)| *recorded_at);

                for (key, _) in entries.into_iter().take(overflow) {
                    cache.remove(&key);
                }
            }
        }

    }

    async fn is_udp_flow_in_backoff(&self, flow_key: &UdpFlowKey) -> bool {
        let backoff = self.udp_timeout_backoff.lock().await;
        let now = Instant::now();
        backoff.get(flow_key).is_some_and(|until| *until > now)
    }

    async fn mark_udp_flow_backoff_shared(
        udp_timeout_backoff: Arc<Mutex<HashMap<UdpFlowKey, Instant>>>,
        flow_key: UdpFlowKey,
    ) {
        let mut backoff = udp_timeout_backoff.lock().await;
        backoff.insert(flow_key, Instant::now() + Self::UDP_TIMEOUT_BACKOFF);
    }

    async fn clear_udp_backoff_shared(
        udp_timeout_backoff: Arc<Mutex<HashMap<UdpFlowKey, Instant>>>,
        flow_key: &UdpFlowKey,
    ) {
        let mut backoff = udp_timeout_backoff.lock().await;
        backoff.remove(flow_key);
    }

    fn dns_txid(payload: &[u8]) -> Option<u16> {
        if payload.len() >= 2 {
            Some(u16::from_be_bytes([payload[0], payload[1]]))
        } else {
            None
        }
    }

    fn normalize_dns_response_for_query(query: &[u8], mut response: Vec<u8>) -> Vec<u8> {
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

    fn build_dns_servfail_response(query: &[u8]) -> Vec<u8> {
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

    async fn write_tun_packet_with(
        tun_packet_tx: mpsc::Sender<Vec<u8>>,
        packet: Vec<u8>,
    ) -> Result<()> {
        Self::enqueue_tun_packet_with_timeout(tun_packet_tx, packet).await
    }

    async fn enqueue_tun_packet_with_timeout(
        tun_packet_tx: mpsc::Sender<Vec<u8>>,
        packet: Vec<u8>,
    ) -> Result<()> {
        match timeout(Self::TUN_WRITE_ENQUEUE_TIMEOUT, tun_packet_tx.send(packet)).await {
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

    /// Check whether the flow belongs to an excluded process.
    ///
    /// Design mirrors mihomo's approach:
    /// - Cache hit → return immediately (hot path, no blocking).
    /// - Cache miss → perform a **synchronous** process lookup on a blocking
    ///   thread and await the result before returning.  This eliminates the
    ///   "first-packet-leaks-to-proxy" window that the previous async-lazy
    ///   design had: a SYN/first-datagram is held until the lookup finishes,
    ///   so the exclusion decision is always made before any connection is
    ///   established to the SOCKS5 proxy.
    async fn should_exclude_process_flow(
        &self,
        protocol: TransportProtocol,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> bool {
        if self.config.filtering.exclude_processes.is_empty() {
            return false;
        }

        let key = ProcessLookupKey { protocol, src, dst };

        // ── Fast path: valid cache entry ─────────────────────────────────────
        {
            let cache = self.process_name_cache.lock().await;
            if let Some(entry) = cache.get(&key) {
                if entry.recorded_at.elapsed() <= Self::PROCESS_LOOKUP_CACHE_TTL {
                    if let Some(ref name) = entry.process_name {
                        if self.config.is_excluded_process_name(name) {
                            debug!(
                                "Excluded process matched (cached): process={} protocol={:?} flow={} -> {}",
                                name, protocol, src, dst
                            );
                            return true;
                        }
                    }
                    return false;
                }
            }
        }

        // ── Slow path: synchronous blocking lookup ───────────────────────────
        // Run the platform-native query on a blocking thread and wait for it.
        // For TCP this is fine because the SYN itself has no RTT budget yet;
        // the extra ~0.5–2 ms for a netlink round-trip is imperceptible.
        let options = self.process_lookup_options.clone();
        let key_clone = key.clone();
        let lookup = tokio::task::spawn_blocking(move || {
            process_lookup::find_process_name_for_flow(
                &options,
                key_clone.protocol,
                key_clone.src,
                key_clone.dst,
            )
        })
        .await
        .ok()
        .flatten();

        // Write result into cache so subsequent packets for the same flow are fast.
        {
            let mut cache = self.process_name_cache.lock().await;
            cache.insert(
                key,
                ProcessLookupEntry {
                    process_name: lookup.clone(),
                    recorded_at: Instant::now(),
                },
            );
        }

        if let Some(ref name) = lookup {
            if self.config.is_excluded_process_name(name) {
                debug!(
                    "Excluded process matched: process={} protocol={:?} flow={} -> {}",
                    name, protocol, src, dst
                );
                return true;
            }
        }

        false
    }

    /// Connect directly to `dst` via the physical outbound interface, bypassing
    /// the TUN device. Uses `SO_BINDTODEVICE` on Linux so the socket is pinned
    /// to the physical NIC and never re-enters the TUN routing path.
    async fn open_direct_tcp(dst: SocketAddr, outbound_interface: String) -> Result<tokio::net::TcpStream> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            use tokio::net::TcpSocket;

            let socket = if dst.is_ipv6() {
                TcpSocket::new_v6()?
            } else {
                TcpSocket::new_v4()?
            };
            let fd = socket.as_raw_fd();
            let iface_c = std::ffi::CString::new(outbound_interface.as_str())
                .map_err(|_| anyhow::anyhow!("outbound interface name contains null byte"))?;
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    iface_c.as_ptr() as *const libc::c_void,
                    iface_c.to_bytes_with_nul().len() as libc::socklen_t,
                )
            };
            if ret == 0 {
                let stream = socket.connect(dst).await?;
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            debug!(
                "SO_BINDTODEVICE to '{}' failed ({}); direct TCP connect may re-enter TUN",
                outbound_interface,
                std::io::Error::last_os_error()
            );
        }
        let stream = tokio::net::TcpStream::connect(dst).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// Send a single UDP datagram directly to `dst` via the physical outbound
    /// interface and return the first response datagram. Uses `SO_BINDTODEVICE`
    /// on Linux to prevent the socket from re-entering the TUN device.
    async fn direct_udp_exchange(
        dst: SocketAddr,
        payload: Vec<u8>,
        outbound_interface: String,
    ) -> Result<Vec<u8>> {
        use tokio::net::UdpSocket;

        let bind_addr: SocketAddr = if dst.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(bind_addr).await?;

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            let iface_c = std::ffi::CString::new(outbound_interface.as_str())
                .map_err(|_| anyhow::anyhow!("outbound interface name contains null byte"))?;
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    iface_c.as_ptr() as *const libc::c_void,
                    iface_c.to_bytes_with_nul().len() as libc::socklen_t,
                )
            };
            if ret != 0 {
                debug!(
                    "SO_BINDTODEVICE to '{}' for direct UDP failed ({}); datagram may re-enter TUN",
                    outbound_interface,
                    std::io::Error::last_os_error()
                );
            }
        }

        socket.connect(dst).await?;
        socket.send(&payload).await?;
        let mut buf = vec![0u8; 65535];
        let n = socket.recv(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }

    async fn ensure_dynamic_bypass_for_ip(&self, ip: IpAddr) -> Result<()> {
        if !self.config.tun.auto_route || self.config.should_skip_ip(ip) {
            return Ok(());
        }

        {
            let mut dynamic = self.dynamic_bypass_ips.lock().await;
            if let Some(last_seen) = dynamic.get_mut(&ip) {
                // IP already tracked (route installed or pending): refresh TTL and return.
                *last_seen = Instant::now();
                return Ok(());
            }
            // Insert a placeholder *before* releasing the lock to prevent concurrent tasks
            // from racing into open_udp_session / apply_skip_ip_routes for the same IP
            // and causing duplicate route entries or Windows ephemeral-port exhaustion.
            dynamic.insert(ip, Instant::now());
        }

        let outbound_interface = self.outbound_interface.clone();
        let install_result = tokio::task::spawn_blocking(move || {
            route_manager::apply_skip_ip_routes(&[ip], outbound_interface.as_deref())
        })
        .await
        .map_err(|err| anyhow::anyhow!("dynamic bypass task join error: {}", err))?;

        if let Err(err) = install_result {
            // Route installation failed: remove the placeholder so the next packet can retry.
            let mut dynamic = self.dynamic_bypass_ips.lock().await;
            dynamic.remove(&ip);
            return Err(err);
        }

        info!("Installed dynamic bypass route for excluded process destination {}", ip);
        Ok(())
    }

    async fn cleanup_expired_dynamic_bypass_routes(&self) {
        if !self.config.tun.auto_route {
            return;
        }

        let expired_ips: Vec<IpAddr> = {
            let mut dynamic = self.dynamic_bypass_ips.lock().await;
            let now = Instant::now();
            let expired: Vec<IpAddr> = dynamic
                .iter()
                .filter_map(|(ip, inserted_at)| {
                    if now.duration_since(*inserted_at) >= Self::DYNAMIC_BYPASS_ROUTE_TTL {
                        Some(*ip)
                    } else {
                        None
                    }
                })
                .collect();

            for ip in &expired {
                dynamic.remove(ip);
            }
            expired
        };

        if expired_ips.is_empty() {
            return;
        }

        let expired_count = expired_ips.len();
        let cleanup_targets = expired_ips;
        let cleanup_result = tokio::task::spawn_blocking(move || {
            route_manager::cleanup_skip_ip_routes(&cleanup_targets)
        })
        .await;

        match cleanup_result {
            Ok(Ok(())) => {
                debug!("Cleaned up {} expired dynamic bypass routes", expired_count);
            }
            Ok(Err(err)) => {
                warn!("Failed to cleanup expired dynamic bypass routes: {}", err);
            }
            Err(err) => {
                warn!("Dynamic bypass cleanup task join error: {}", err);
            }
        }
    }

    async fn inject_tcp_control_packet(
        &self,
        flow_key: &FlowKey,
        sequence_number: u32,
        acknowledgment_number: u32,
        syn: bool,
        fin: bool,
        rst: bool,
    ) -> Result<()> {
        Self::inject_tcp_control(
            &self.tun_packet_tx, flow_key, sequence_number, acknowledgment_number, syn, fin, rst,
        ).await
    }

    async fn inject_tcp_control(
        tun_packet_tx: &mpsc::Sender<Vec<u8>>,
        flow_key: &FlowKey,
        sequence_number: u32,
        acknowledgment_number: u32,
        syn: bool,
        fin: bool,
        rst: bool,
    ) -> Result<()> {
        let mut builder = match (flow_key.dst.ip(), flow_key.src.ip()) {
            (IpAddr::V4(dst), IpAddr::V4(src)) => PacketBuilder::ipv4(dst.octets(), src.octets(), 64)
                .tcp(flow_key.dst.port(), flow_key.src.port(), sequence_number, 65535)
                .ack(acknowledgment_number),
            (IpAddr::V6(dst), IpAddr::V6(src)) => PacketBuilder::ipv6(dst.octets(), src.octets(), 64)
                .tcp(flow_key.dst.port(), flow_key.src.port(), sequence_number, 65535)
                .ack(acknowledgment_number),
            _ => return Ok(()),
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

        let mut packet = Vec::with_capacity(builder.size(0));
        builder.write(&mut packet, &[])?;
        Self::enqueue_tun_packet_with_timeout(tun_packet_tx.clone(), packet)
            .await
            .map_err(|err| anyhow::anyhow!(
                "failed to enqueue tcp control packet for TUN write: {}",
                err
            ))?;
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
        sessions: Arc<Mutex<HashMap<FlowKey, Arc<TcpSession>>>>,
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
                    let _ = PacketProcessor::inject_tcp_control(
                        &tun_packet_tx,
                        &flow_key,
                        sequence_number,
                        acknowledgment_number,
                        false,
                        false,
                        true,
                    )
                    .await;
                    sessions.lock().await.remove(&flow_key);
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
                let _ = PacketProcessor::inject_tcp_control(
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
        sessions: Arc<Mutex<HashMap<FlowKey, Arc<TcpSession>>>>,
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
                let mut table = sessions.lock().await;
                table.remove(&flow_key);
            }
        });
    }

    async fn cleanup_expired_tcp_sessions(&self) {
        let snapshot: Vec<(FlowKey, Arc<TcpSession>)> = {
            let table = self.tcp_sessions.lock().await;
            table
                .iter()
                .map(|(flow_key, session)| (flow_key.clone(), session.clone()))
                .collect()
        };

        let now = Instant::now();
        let mut expired = Vec::new();

        for (flow_key, session) in snapshot {
            let state = session.state.lock().await;
            let is_fin_wait_expired = state.lifecycle == TcpLifecycle::FinSent
                && now.duration_since(state.last_activity) >= Self::TCP_FIN_WAIT_TIMEOUT;
            if state.lifecycle == TcpLifecycle::Closed
                || is_fin_wait_expired
                || now.duration_since(state.last_activity) >= Self::TCP_SESSION_IDLE_TIMEOUT
            {
                expired.push(flow_key);
            }
        }

        if expired.is_empty() {
            return;
        }

        let mut table = self.tcp_sessions.lock().await;
        for flow_key in expired {
            table.remove(&flow_key);
        }
    }
}
