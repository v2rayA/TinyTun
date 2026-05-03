use std::sync::Arc;

use anyhow::Result;
use log::{debug, error, info, warn};
use tokio::sync::mpsc;

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
    pub dns_router: Arc<DnsRouter>,
    pub socks5_client: Arc<Socks5Client>,
    pub outbound_interface: Option<String>,
    pub tun_packet_tx: mpsc::Sender<Vec<u8>>,
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
            dns_router.clone(),
            outbound_interface.clone(),
            tun_packet_tx.clone(),
        );

        let udp_handler = UdpHandler::new(
            config.clone(),
            socks5_client.clone(),
            dns_router.clone(),
            outbound_interface.clone(),
            tun_packet_tx.clone(),
        );

        Ok(Self {
            config,
            socks5_client,
            dns_router,
            outbound_interface,
            tun_packet_tx,
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
        let mut last_cleanup_at = std::time::Instant::now();
        let mut last_dynamic_cleanup_at = std::time::Instant::now();
        let mut last_udp_session_cleanup_at = std::time::Instant::now();
        let mut last_process_cache_cleanup_at = std::time::Instant::now();

        loop {
            if last_cleanup_at.elapsed() >= Self::TCP_SESSION_CLEANUP_INTERVAL {
                self.tcp_handler.cleanup_expired_tcp_sessions().await;
                last_cleanup_at = std::time::Instant::now();
            }
            if last_dynamic_cleanup_at.elapsed() >= Self::DYNAMIC_BYPASS_CLEANUP_INTERVAL {
                packet::route::cleanup_expired_dynamic_bypass_routes(
                    &self.tcp_handler.dynamic_bypass_ips,
                    &self.config,
                )
                .await;
                last_dynamic_cleanup_at = std::time::Instant::now();
            }
            if last_udp_session_cleanup_at.elapsed() >= Self::UDP_SESSION_CLEANUP_INTERVAL {
                self.udp_handler.cleanup_expired_udp_sessions().await;
                last_udp_session_cleanup_at = std::time::Instant::now();
            }
            if last_process_cache_cleanup_at.elapsed() >= Self::PROCESS_CACHE_CLEANUP_INTERVAL {
                packet::bypass::cleanup_process_lookup_cache(
                    &self.tcp_handler.process_name_cache,
                    Self::PROCESS_CACHE_MAX_ENTRIES,
                )
                .await;
                last_process_cache_cleanup_at = std::time::Instant::now();
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
        if self.config.should_skip_ip(dest_ip) {
            // When an outbound interface is configured, TCP/UDP packets for
            // statically-bypassed IPs are forwarded transparently through the
            // physical NIC inside the protocol handlers rather than silently
            // dropped.  Non-TCP/UDP traffic and the no-interface case still
            // drop immediately (rely on routing to have excluded those flows).
            let can_direct = self.outbound_interface.is_some()
                && (parsed.protocol == 6 || parsed.protocol == 17);
            if !can_direct {
                debug!("Skipping packet to {}", dest_ip);
                return Ok(());
            }
        }

        // Handle different protocols
        match parsed.protocol {
            6 => self.tcp_handler.handle_tcp_packet(packet, &parsed).await,
            17 => self.udp_handler.handle_udp_packet(packet, &parsed).await,
            _ => {
                debug!("Unsupported protocol number: {}", parsed.protocol);
                Ok(())
            }
        }
    }
}
