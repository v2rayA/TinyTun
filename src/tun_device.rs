use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use log::{info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use tun::{AbstractDevice, Configuration, DeviceReader, DeviceWriter};

pub struct TunDevice {
    reader: Arc<Mutex<DeviceReader>>,
    writer: Arc<Mutex<DeviceWriter>>,
    name: String,
}

impl TunDevice {
    pub async fn new(
        name: &str,
        ip: Ipv4Addr,
        netmask: Ipv4Addr,
        ipv6: Option<Ipv6Addr>,
        ipv6_prefix: u8,
    ) -> Result<Self> {
        info!("Creating TUN device: {}", name);
        
        let mut config = Configuration::default();
        config
            .tun_name(name)
            .address(ip)
            .netmask(netmask)
            .mtu(1500)
            .up();
        
        let device = tun::create_as_async(&config).map_err(|err| {
            #[cfg(windows)]
            {
                let msg = err.to_string();
                if msg.contains("Code 0x00000005") || msg.contains("拒绝访问") {
                    return anyhow::anyhow!(
                        "Failed to create Wintun adapter due to access denied. Run this process in an elevated Administrator shell. Original error: {}",
                        err
                    );
                }

                if msg.contains("LoadLibraryExW failed") || msg.contains("os error 126") {
                    return anyhow::anyhow!(
                        "Failed to load Wintun runtime. Ensure wintun.dll is next to tinytun.exe (or in PATH). Original error: {}",
                        err
                    );
                }
            }

            anyhow::anyhow!("Failed to create TUN device: {}", err)
        })?;
        let device_name = device.tun_name()?;
        
        info!("TUN device created: {}", device_name);
        
        // Set up the interface
        Self::setup_interface(&device_name, ip, netmask, ipv6, ipv6_prefix)?;
        
        let (writer, reader) = device.split()?;
        let reader = Arc::new(Mutex::new(reader));
        let writer = Arc::new(Mutex::new(writer));
        
        Ok(Self {
            reader,
            writer,
            name: device_name,
        })
    }
    
    fn setup_interface(
        _name: &str,
        _ip: Ipv4Addr,
        _netmask: Ipv4Addr,
        _ipv6: Option<Ipv6Addr>,
        _ipv6_prefix: u8,
    ) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            let name = _name;
            let ip = _ip;
            let netmask = _netmask;
            let ipv6 = _ipv6;
            let ipv6_prefix = _ipv6_prefix;
            
            // Bring interface up
            let output = Command::new("ip")
                .args(&["link", "set", "dev", name, "up"])
                .output()?;
            
            if !output.status.success() {
                warn!("Failed to bring up interface {}: {}", name, String::from_utf8_lossy(&output.stderr));
            }
            
            // Set IP address
            let ip_str = format!("{}/{}", ip, Self::netmask_to_prefix(netmask));
            let output = Command::new("ip")
                .args(&["addr", "add", &ip_str, "dev", name])
                .output()?;
            
            if !output.status.success() {
                warn!("Failed to set IP address for {}: {}", name, String::from_utf8_lossy(&output.stderr));
            }

            if let Some(v6) = ipv6 {
                let v6_str = format!("{}/{}", v6, ipv6_prefix);
                let output = Command::new("ip")
                    .args(["-6", "addr", "replace", &v6_str, "dev", name])
                    .output()?;

                if !output.status.success() {
                    warn!(
                        "Failed to set IPv6 address for {}: {}",
                        name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
        
        #[cfg(windows)]
        {
            use std::process::Command;
            let name = _name;
            let ipv6 = _ipv6;
            let ipv6_prefix = _ipv6_prefix;

            info!("TUN interface setup on Windows may require additional configuration");

            if let Some(v6) = ipv6 {
                let v6_str = format!("{}/{}", v6, ipv6_prefix);
                let output = Command::new("netsh")
                    .args([
                        "interface",
                        "ipv6",
                        "add",
                        "address",
                        &format!("interface={}", name),
                        &format!("address={}", v6_str),
                        "store=active",
                    ])
                    .output()?;

                if !output.status.success() {
                    warn!(
                        "Failed to set IPv6 address for {}: {}",
                        name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }

            // Always configure Google Public DNS on the TUN interface so the OS
            // routes DNS queries through the tunnel.
            let google_v4 = [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)];

            {
                let output = Command::new("netsh")
                    .args([
                        "interface",
                        "ipv4",
                        "set",
                        "dnsservers",
                        &format!("name={}", name),
                        "source=static",
                        &format!("address={}", google_v4[0]),
                        "validate=no",
                    ])
                    .output()?;

                if !output.status.success() {
                    warn!(
                        "Failed to set primary IPv4 DNS for {}: {}",
                        name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                } else {
                    let output = Command::new("netsh")
                        .args([
                            "interface",
                            "ipv4",
                            "add",
                            "dnsservers",
                            &format!("name={}", name),
                            &format!("address={}", google_v4[1]),
                            "index=2",
                            "validate=no",
                        ])
                        .output()?;

                    if !output.status.success() {
                        warn!(
                            "Failed to add IPv4 DNS {} for {}: {}",
                            google_v4[1],
                            name,
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                }
            }

            if ipv6.is_some() {
                let google_v6 = [
                    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
                    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
                ];

                let output = Command::new("netsh")
                    .args([
                        "interface",
                        "ipv6",
                        "set",
                        "dnsservers",
                        &format!("interface={}", name),
                        &format!("address={}", google_v6[0]),
                        "validate=no",
                    ])
                    .output()?;

                if !output.status.success() {
                    warn!(
                        "Failed to set primary IPv6 DNS for {}: {}",
                        name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                } else {
                    let output = Command::new("netsh")
                        .args([
                            "interface",
                            "ipv6",
                            "add",
                            "dnsservers",
                            &format!("interface={}", name),
                            &format!("address={}", google_v6[1]),
                            "index=2",
                            "validate=no",
                        ])
                        .output()?;

                    if !output.status.success() {
                        warn!(
                            "Failed to add IPv6 DNS {} for {}: {}",
                            google_v6[1],
                            name,
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                }
            }
        }
        
        Ok(())
    }
    
    fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
        let octets = netmask.octets();
        let mut prefix = 0;
        
        for octet in octets.iter() {
            let mut mask = *octet;
            while mask & 0x80 != 0 {
                prefix += 1;
                mask <<= 1;
            }
            if mask != 0 {
                break;
            }
        }
        
        prefix
    }
    
    pub fn get_reader(&self) -> Arc<Mutex<DeviceReader>> {
        self.reader.clone()
    }

    pub fn get_writer(&self) -> Arc<Mutex<DeviceWriter>> {
        self.writer.clone()
    }
    
    pub async fn write_packet(&self, packet: &[u8]) -> Result<usize> {
        let mut writer = self.writer.lock().await;
        writer.write_all(packet).await?;
        Ok(packet.len())
    }
    
    pub async fn read_packet(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut reader = self.reader.lock().await;
        let bytes_read = reader.read(buffer).await?;
        Ok(bytes_read)
    }
    
    pub async fn cleanup(&self) -> Result<()> {
        info!("Cleaning up TUN device: {}", self.name);
        
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            
            let output = Command::new("ip")
                .args(&["link", "delete", &self.name])
                .output()?;
            
            if !output.status.success() {
                warn!("Failed to delete TUN interface {}: {}", self.name, String::from_utf8_lossy(&output.stderr));
            }
        }
        
        Ok(())
    }
    
    pub fn name(&self) -> &str {
        &self.name
    }
}

// DNS server for handling DNS requests on the TUN interface
pub struct DnsServer {
    socket: UdpSocket,
    upstream_server: SocketAddr,
    timeout: Duration,
}

impl DnsServer {
    pub async fn new(listen_port: u16, upstream_server: SocketAddr, timeout_ms: u64) -> Result<Self> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", listen_port)).await?;
        info!("DNS server listening on port {}", listen_port);
        
        Ok(Self {
            socket,
            upstream_server,
            timeout: Duration::from_millis(timeout_ms),
        })
    }
    
    pub async fn handle_dns_request(&self, buffer: &[u8], client_addr: SocketAddr) -> Result<()> {
        // Forward DNS request to upstream server
        let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;
        upstream_socket.send_to(buffer, self.upstream_server).await?;
        
        // Wait for response
        let mut response_buffer = vec![0; 512];
        let (bytes_read, _) = tokio::time::timeout(
            self.timeout,
            upstream_socket.recv_from(&mut response_buffer)
        ).await??;
        
        // Send response back to client
        self.socket.send_to(&response_buffer[..bytes_read], client_addr).await?;
        
        Ok(())
    }
}