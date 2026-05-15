use std::sync::Arc;

use anyhow::Result;
use log::{debug, error, info, warn};
use tokio::sync::mpsc;
use tokio::time::{interval, MissedTickBehavior};

use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};

use crate::config::Config;
use crate::dns_router::DnsRouter;
use crate::packet;
use crate::packet::shared::ParsedIpPacket;
use crate::packet::tcp::TcpHandler;
use crate::packet::udp::UdpHandler;
use crate::socks5_client::Socks5Client;

pub struct PacketProcessor {
    pub config: Arc<Config>,
    pub outbound_interface: Option<Arc<str>>,
    pub tcp_handler: TcpHandler,
    pub udp_handler: UdpHandler,
}

impl PacketProcessor {
    const TCP_SESSION_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
    const DYNAMIC_BYPASS_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
    const UDP_SESSION_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
    const PROCESS_CACHE_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
    const PROCESS_CACHE_MAX_ENTRIES: usize = 1024;
    const TUN_WRITE_QUEUE_CAPACITY: usize = 512;

    pub fn new(
        config: Config,
        tun_writer: Arc<tun_rs::AsyncDevice>,
        outbound_interface: Option<String>,
    ) -> Result<Self> {
        let config = Arc::new(config);
        let outbound_interface_arc = outbound_interface
            .as_deref()
            .map(Arc::<str>::from);
        let socks5_client = Arc::new(Socks5Client::new(config.socks5.clone(), outbound_interface.clone()));
        let dns_router = Arc::new(DnsRouter::new(config.dns.clone(), &config, outbound_interface.clone())?);
        let (tun_packet_tx, mut tun_packet_rx) = mpsc::channel::<Vec<u8>>(Self::TUN_WRITE_QUEUE_CAPACITY);

        tokio::spawn(async move {
            while let Some(packet) = tun_packet_rx.recv().await {
                if let Err(err) = tun_writer.send(&packet).await {
                    warn!("Failed to write packet to TUN from writer queue: {}", err);
                }
            }
        });

        let tcp_handler = TcpHandler::new(
            config.clone(),
            socks5_client.clone(),
            outbound_interface_arc.clone(),
            tun_packet_tx.clone(),
        );

        let udp_handler = UdpHandler::new(
            config.clone(),
            socks5_client.clone(),
            dns_router.clone(),
            outbound_interface_arc.clone(),
            tun_packet_tx.clone(),
        );

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

                    if let Err(e) = self.process_packet(packet).await {
                        error!("Error processing packet: {}", e);
                    }
                }
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
                    src: ip_header.source_addr().into(),
                    dst: ip_header.destination_addr().into(),
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
                    src: ip_header.source_addr().into(),
                    dst: ip_header.destination_addr().into(),
                    protocol: ip_header.next_header().0,
                    header_len: 40,
                }
            }
            _ => return Ok(()),
        };

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
            6 => self
                .tcp_handler
                .handle_tcp_packet(packet, &parsed, is_static_bypass)
                .await,
            17 => self
                .udp_handler
                .handle_udp_packet(packet, &parsed, is_static_bypass)
                .await,
            _ => {
                debug!("Unsupported protocol number: {}", parsed.protocol);
                Ok(())
            }
        }
    }
}
