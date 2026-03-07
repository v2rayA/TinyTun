use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::{collections::BTreeMap, collections::HashMap, collections::HashSet, hash::Hash};
use std::time::{Duration, Instant};

use anyhow::Result;
use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

use etherparse::{
    Ipv4HeaderSlice, Ipv6HeaderSlice, PacketBuilder, TcpHeaderSlice, UdpHeader, UdpHeaderSlice,
};
use crate::config::Config;
use crate::socks5_client::Socks5Client;

struct ParsedIpPacket {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    header_len: usize,
}

pub struct PacketProcessor {
    config: Config,
    socks5_client: Socks5Client,
    tun_writer: Arc<Mutex<tun::DeviceWriter>>,
    tcp_sessions: Arc<Mutex<HashMap<FlowKey, Arc<TcpSession>>>>,
    pending_connections: Arc<Mutex<HashSet<FlowKey>>>,
}

struct TcpSession {
    writer: Arc<Mutex<OwnedWriteHalf>>,
    state: Arc<Mutex<TcpFlowState>>,
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
    const TCP_SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);
    const TCP_REORDER_BUFFER_LIMIT: usize = 256 * 1024;
    const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

    pub fn new(config: Config, tun_writer: Arc<Mutex<tun::DeviceWriter>>) -> Self {
        let socks5_client = Socks5Client::new(config.socks5.clone());
        
        Self {
            config,
            socks5_client,
            tun_writer,
            tcp_sessions: Arc::new(Mutex::new(HashMap::new())),
            pending_connections: Arc::new(Mutex::new(HashSet::new())),
        }
    }
    
    pub async fn process_packets(&self, tun_reader: Arc<Mutex<tun::DeviceReader>>) -> Result<()> {
        info!("Starting packet processing");
        
        let mut buffer = vec![0; self.config.tun.mtu as usize];
        let mut last_cleanup_at = Instant::now();
        
        loop {
            if last_cleanup_at.elapsed() >= Self::TCP_SESSION_CLEANUP_INTERVAL {
                self.cleanup_expired_tcp_sessions().await;
                last_cleanup_at = Instant::now();
            }

            let bytes_read = {
                let mut reader = tun_reader.lock().await;
                reader.read(&mut buffer).await?
            };
            
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
        let is_ack_only_or_window_update = payload.is_empty()
            && !tcp_header.syn()
            && !tcp_header.fin()
            && !tcp_header.rst();
        // Reuse existing SOCKS5 stream for the same flow when available.
        let session = if let Some(existing) = {
            let table = self.tcp_sessions.lock().await;
            table.get(&flow_key).cloned()
        } {
            let mut resend_syn_ack = None;
            {
                let mut state = existing.state.lock().await;
                state.last_activity = Instant::now();
                if state.lifecycle == TcpLifecycle::SynReceived && tcp_header.ack() {
                    state.lifecycle = TcpLifecycle::Established;
                }

                // Handle SYN retransmission during handshake by re-sending SYN-ACK.
                if state.lifecycle == TcpLifecycle::SynReceived && tcp_header.syn() && !tcp_header.ack() {
                    resend_syn_ack = Some((state.server_next_seq.wrapping_sub(1), state.client_next_seq));
                }
            }

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
                return Ok(());
            }

            existing
        } else {
            if tcp_header.syn() {
                // Spawn SOCKS5 connection in background so the packet loop is not blocked.
                let mut pending = self.pending_connections.lock().await;
                if pending.contains(&flow_key) {
                    return Ok(());
                }
                pending.insert(flow_key.clone());
                drop(pending);

                let socks5_client = self.socks5_client.clone();
                let tun_writer = self.tun_writer.clone();
                let tcp_sessions = self.tcp_sessions.clone();
                let pending_connections = self.pending_connections.clone();
                let mtu = self.config.tun.mtu as usize;
                let client_isn = tcp_header.sequence_number();
                let fk = flow_key.clone();

                tokio::spawn(async move {
                    let connect_result = timeout(
                        PacketProcessor::TCP_CONNECT_TIMEOUT,
                        socks5_client.connect(fk.dst),
                    ).await;

                    // Always remove from pending set.
                    {
                        let mut pending = pending_connections.lock().await;
                        pending.remove(&fk);
                    }

                    match connect_result {
                        Ok(Ok(stream)) => {
                            let (reader, writer) = stream.into_split();

                            let session = Arc::new(TcpSession {
                                writer: Arc::new(Mutex::new(writer)),
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
                            });

                            // Advance server_next_seq for the SYN before registering.
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

                            PacketProcessor::spawn_reverse_tcp_task(
                                fk.clone(),
                                reader,
                                session,
                                tcp_sessions,
                                tun_writer.clone(),
                                mtu,
                            );

                            let _ = PacketProcessor::inject_tcp_control(
                                &tun_writer, &fk,
                                syn_ack_seq, client_isn.wrapping_add(1),
                                true, false, false,
                            ).await;
                        }
                        Ok(Err(err)) => {
                            warn!("SOCKS5 connect failed for {:?}: {}", fk, err);
                            let _ = PacketProcessor::inject_tcp_control(
                                &tun_writer, &fk,
                                0, client_isn.wrapping_add(1),
                                false, false, true,
                            ).await;
                        }
                        Err(_) => {
                            warn!("SOCKS5 connect timed out for {:?}", fk);
                            let _ = PacketProcessor::inject_tcp_control(
                                &tun_writer, &fk,
                                0, client_isn.wrapping_add(1),
                                false, false, true,
                            ).await;
                        }
                    }
                });

                return Ok(());
            }

            // Non-SYN for unknown flow: silently drop if SOCKS5 connect is in progress.
            {
                let pending = self.pending_connections.lock().await;
                if pending.contains(&flow_key) {
                    return Ok(());
                }
            }
            debug!(
                "Dropping unknown non-SYN TCP packet {}:{} -> {}:{}",
                ip_packet.src,
                source_port,
                ip_packet.dst,
                dest_port
            );
            return Ok(());
        };

        if tcp_header.rst() || tcp_header.fin() {
            if tcp_header.fin() {
                let (sequence_number, acknowledgment_number) = {
                    let mut state = session.state.lock().await;
                    // FIN consumes one sequence number when it is at/after expected seq.
                    if Self::seq_at_or_after(tcp_header.sequence_number(), state.client_next_seq) {
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
                let mut table = self.tcp_sessions.lock().await;
                table.remove(&flow_key);
                return Ok(());
            }
        }

        if tcp_header.ack() {
            let should_close = {
                let mut state = session.state.lock().await;
                // Track peer ACK/window for reverse flow-control.
                state.client_window = tcp_header.window_size();
                if Self::seq_at_or_after(tcp_header.acknowledgment_number(), state.server_acked_seq) {
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
                let mut table = self.tcp_sessions.lock().await;
                table.remove(&flow_key);
                return Ok(());
            }
        }

        let lifecycle = {
            let state = session.state.lock().await;
            state.lifecycle
        };

        if lifecycle == TcpLifecycle::Closed || lifecycle == TcpLifecycle::FinSent {
            return Ok(());
        }

        if is_ack_only_or_window_update {
            // No payload to forward to SOCKS; treat as local TCP state maintenance only.
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
                    ip_packet.src,
                    source_port,
                    ip_packet.dst,
                    dest_port
                );
                return Ok(());
            }

            let write_result = {
                let mut writer = session.writer.lock().await;
                writer.write_all(&forward_payload).await
            };

            if let Err(err) = write_result {
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

                let mut table = self.tcp_sessions.lock().await;
                table.remove(&flow_key);
                warn!("TCP write failed for flow {:?}: {}", flow_key, err);
                return Ok(());
            }

            // Send ACK back to client to confirm receipt of forwarded data.
            let (ack_seq, ack_ack) = {
                let mut state = session.state.lock().await;
                state.last_activity = Instant::now();
                if state.lifecycle == TcpLifecycle::SynReceived {
                    state.lifecycle = TcpLifecycle::Established;
                }
                (state.server_next_seq, state.client_next_seq)
            };
            let _ = self.inject_tcp_control_packet(
                &flow_key, ack_seq, ack_ack, false, false, false,
            ).await;
        }

        debug!(
            "TCP flow active {}:{} -> {}:{}",
            ip_packet.src,
            source_port,
            ip_packet.dst,
            dest_port
        );
        
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
        
        if dest_port == self.config.dns.listen_port {
            let udp_payload = &udp_data[UdpHeader::LEN..];
            let response_payload = match self.forward_dns_query(udp_payload).await {
                Ok(resp) => resp,
                Err(err) => {
                    warn!("DNS forwarding failed for {}:{}: {}", ip_packet.dst, dest_port, err);
                    return Ok(());
                }
            };

            // Build IP+UDP response back to the original requester.
            let response_builder = match (ip_packet.dst, ip_packet.src) {
                (IpAddr::V4(dst), IpAddr::V4(src)) => {
                    PacketBuilder::ipv4(dst.octets(), src.octets(), 64)
                        .udp(dest_port, source_port)
                }
                (IpAddr::V6(dst), IpAddr::V6(src)) => {
                    PacketBuilder::ipv6(dst.octets(), src.octets(), 64)
                        .udp(dest_port, source_port)
                }
                _ => return Ok(()),
            };

            let mut response_packet = Vec::with_capacity(response_builder.size(response_payload.len()));
            response_builder.write(&mut response_packet, &response_payload)?;
            self.write_tun_packet(&response_packet).await?;

            debug!(
                "Forwarded DNS query for {}:{} and injected {} bytes back to TUN",
                ip_packet.dst,
                dest_port,
                response_packet.len()
            );

            return Ok(());
        }

        // Other UDP proxying is still pending full SOCKS5 UDP ASSOCIATE support.
        warn!(
            "UDP packet to port {} not proxied (only DNS UDP/{} is currently forwarded)",
            dest_port,
            self.config.dns.listen_port
        );
        
        Ok(())
    }

    async fn forward_dns_query(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let timeout_duration = Duration::from_millis(self.config.dns.timeout_ms);
        let servers = self.config.effective_dns_servers();
        let mut last_error: Option<anyhow::Error> = None;

        for server in servers {
            let result = match server.route {
                crate::config::DnsRoute::Direct => {
                    self.forward_dns_query_direct(payload, server.address, timeout_duration)
                        .await
                }
                crate::config::DnsRoute::Proxy => {
                    self.forward_dns_query_via_socks(payload, server.address, timeout_duration)
                        .await
                }
            };

            match result {
                Ok(response) => return Ok(response),
                Err(err) => {
                    warn!(
                        "DNS upstream {} via {:?} failed: {}",
                        server.address,
                        server.route,
                        err
                    );
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No DNS upstream server configured")))
    }

    async fn forward_dns_query_direct(
        &self,
        payload: &[u8],
        upstream: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<Vec<u8>> {
        let bind_addr = match upstream {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr).await?;
        timeout(timeout_duration, socket.send_to(payload, upstream)).await??;

        let mut response = vec![0u8; 4096];
        let (size, _) = timeout(timeout_duration, socket.recv_from(&mut response)).await??;
        response.truncate(size);
        Ok(response)
    }

    async fn forward_dns_query_via_socks(
        &self,
        payload: &[u8],
        upstream: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<Vec<u8>> {
        // Give the SOCKS5 handshake its own generous timeout so that a slow
        // proxy negotiation doesn't leave a half-open TCP connection (which
        // the server would log as "insufficient header > EOF").
        let handshake_timeout = timeout_duration.max(Duration::from_secs(10));

        let socks5_client = self.socks5_client.clone();
        let mut stream = timeout(handshake_timeout, socks5_client.connect(upstream)).await
            .map_err(|_| anyhow::anyhow!("SOCKS5 handshake timed out for DNS upstream {}", upstream))??;

        // DNS-over-TCP framing: two-byte big-endian payload length prefix.
        let mut framed_query = Vec::with_capacity(payload.len() + 2);
        framed_query.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        framed_query.extend_from_slice(payload);
        timeout(timeout_duration, stream.write_all(&framed_query)).await??;
        timeout(timeout_duration, stream.flush()).await??;

        let mut len_buf = [0u8; 2];
        timeout(timeout_duration, stream.read_exact(&mut len_buf)).await??;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        let mut response = vec![0u8; response_len];
        timeout(timeout_duration, stream.read_exact(&mut response)).await??;
        Ok(response)
    }

    async fn write_tun_packet(&self, packet: &[u8]) -> Result<()> {
        let mut writer = self.tun_writer.lock().await;
        writer.write_all(packet).await?;
        Ok(())
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
            &self.tun_writer, flow_key, sequence_number, acknowledgment_number, syn, fin, rst,
        ).await
    }

    async fn inject_tcp_control(
        tun_writer: &Arc<Mutex<tun::DeviceWriter>>,
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
        let mut writer = tun_writer.lock().await;
        writer.write_all(&packet).await?;
        Ok(())
    }

    fn spawn_reverse_tcp_task(
        flow_key: FlowKey,
        mut reader: OwnedReadHalf,
        session: Arc<TcpSession>,
        sessions: Arc<Mutex<HashMap<FlowKey, Arc<TcpSession>>>>,
        tun_writer: Arc<Mutex<tun::DeviceWriter>>,
        mtu: usize,
    ) {
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 8192];
            let header_overhead = match (flow_key.dst.ip(), flow_key.src.ip()) {
                (IpAddr::V6(_), IpAddr::V6(_)) => 60, // IPv6(40) + TCP(20)
                _ => 40, // IPv4(20) + TCP(20)
            };
            let max_payload_per_packet = mtu.saturating_sub(header_overhead).clamp(256, 1460);

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

                    let write_result = {
                        let mut writer = tun_writer.lock().await;
                        writer.write_all(&packet).await
                    };

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
                    let _ = {
                        let mut writer = tun_writer.lock().await;
                        writer.write_all(&fin_packet).await
                    };
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
            if state.lifecycle == TcpLifecycle::Closed
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
