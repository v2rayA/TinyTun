use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Result;
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::config::Socks5Config;

pub struct Socks5UdpSession {
    // Keep the TCP control channel alive for this UDP ASSOCIATE session.
    _control: TcpStream,
    relay_addr: SocketAddr,
    udp_socket: UdpSocket,
}

#[derive(Clone)]
pub struct Socks5Client {
    config: Socks5Config,
}

impl Socks5Client {
    pub fn new(config: Socks5Config) -> Self {
        Self { config }
    }
}

impl Socks5Client {
    pub async fn connect(&self, target_addr: SocketAddr) -> Result<TcpStream> {
        debug!("Connecting to SOCKS5 proxy: {}", self.config.address);
        
        let mut stream = TcpStream::connect(&self.config.address).await?;
        stream.set_nodelay(true)?;
        
        // SOCKS5 handshake
        self.perform_handshake(&mut stream).await?;
        
        // Connect to target
        self.connect_to_target(&mut stream, target_addr).await?;
        
        Ok(stream)
    }

    pub async fn open_udp_session(&self, target_hint: SocketAddr) -> Result<Socks5UdpSession> {
        debug!(
            "Opening SOCKS5 UDP ASSOCIATE session for target family {}",
            target_hint
        );

        let mut control = TcpStream::connect(&self.config.address).await?;
        control.set_nodelay(true)?;
        self.perform_handshake(&mut control).await?;

        let relay_addr = self.udp_associate(&mut control).await?;
        // Bind by relay family (not destination family): an IPv4 relay can still
        // carry IPv6 destination datagrams inside SOCKS5 UDP framing.
        let bind_addr = if relay_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let udp_socket = UdpSocket::bind(bind_addr).await?;

        Ok(Socks5UdpSession {
            _control: control,
            relay_addr,
            udp_socket,
        })
    }
    
    async fn perform_handshake(&self, stream: &mut TcpStream) -> Result<()> {
        // SOCKS5 handshake: client greeting
        // Always offer NO AUTH; additionally offer USERNAME/PASSWORD if credentials are configured.
        let auth_methods: Vec<u8> = if self.config.username.is_some() && self.config.password.is_some() {
            vec![0x00, 0x02] // No auth + Username/password
        } else {
            vec![0x00] // No authentication only
        };
        
        let mut greeting = Vec::with_capacity(2 + auth_methods.len());
        greeting.push(0x05); // SOCKS5 version
        greeting.push(auth_methods.len() as u8);
        greeting.extend_from_slice(&auth_methods);
        
        stream.write_all(&greeting).await?;
        stream.flush().await?;
        
        // Read server response
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        
        if response[0] != 0x05 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 version in server response: 0x{:02x}", response[0]));
        }
        
        let auth_method = response[1];
        
        if auth_method == 0xFF {
            return Err(anyhow::anyhow!("SOCKS5 server rejected all offered authentication methods"));
        }
        
        // Authenticate if required
        if auth_method == 0x02 {
            self.authenticate(stream).await?;
        } else if auth_method != 0x00 {
            return Err(anyhow::anyhow!("Unsupported authentication method: 0x{:02x}", auth_method));
        }
        
        Ok(())
    }
    
    async fn authenticate(&self, stream: &mut TcpStream) -> Result<()> {
        let username = self.config.username.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Username required but not provided"))?;
        let password = self.config.password.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Password required but not provided"))?;
        
        let mut auth_request = vec![0x01, username.len() as u8];
        auth_request.extend_from_slice(username.as_bytes());
        auth_request.push(password.len() as u8);
        auth_request.extend_from_slice(password.as_bytes());
        
        stream.write_all(&auth_request).await?;
        stream.flush().await?;
        
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        
        if response[0] != 0x01 || response[1] != 0x00 {
            return Err(anyhow::anyhow!("SOCKS5 authentication failed"));
        }
        
        Ok(())
    }
    
    async fn connect_to_target(&self, stream: &mut TcpStream, target_addr: SocketAddr) -> Result<()> {
        // Build CONNECT request
        let (addr_type, addr_data) = match target_addr {
            SocketAddr::V4(v4) => (0x01, v4.ip().octets().to_vec()),
            SocketAddr::V6(v6) => (0x04, v6.ip().octets().to_vec()),
        };
        
        let port = target_addr.port();
        
        let mut request = vec![
            0x05, // SOCKS5 version
            0x01, // CONNECT command
            0x00, // Reserved
            addr_type,
        ];
        
        request.extend_from_slice(&addr_data);
        request.extend_from_slice(&port.to_be_bytes());
        
        stream.write_all(&request).await?;
        stream.flush().await?;
        
        // Read server response
        let mut response = vec![0u8; 4];
        stream.read_exact(&mut response).await?;
        
        if response[0] != 0x05 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 version in server response"));
        }
        
        if response[1] != 0x00 {
            return Err(anyhow::anyhow!("SOCKS5 connection failed with code: 0x{:02x}", response[1]));
        }
        
        // Read bound address and port (we don't need them for CONNECT)
        match response[3] {
            0x01 => {
                // IPv4 address
                let mut addr = [0u8; 6]; // 4 bytes IP + 2 bytes port
                stream.read_exact(&mut addr).await?;
            }
            0x03 => {
                // Domain name
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                
                let mut data = vec![0u8; len + 2]; // domain + port
                stream.read_exact(&mut data).await?;
            }
            0x04 => {
                // IPv6 address
                let mut addr = [0u8; 18]; // 16 bytes IP + 2 bytes port
                stream.read_exact(&mut addr).await?;
            }
            _ => return Err(anyhow::anyhow!("Invalid address type in SOCKS5 response")),
        }
        
        Ok(())
    }

    async fn udp_associate(&self, stream: &mut TcpStream) -> Result<SocketAddr> {
        let request = vec![
            0x05, // SOCKS5
            0x03, // UDP ASSOCIATE
            0x00, // Reserved
            0x01, // ATYP IPv4
            0x00,
            0x00,
            0x00,
            0x00, // 0.0.0.0
            0x00,
            0x00, // Port 0
        ];

        stream.write_all(&request).await?;
        stream.flush().await?;

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            return Err(anyhow::anyhow!(
                "Invalid SOCKS5 version in UDP ASSOCIATE response: 0x{:02x}",
                head[0]
            ));
        }
        if head[1] != 0x00 {
            return Err(anyhow::anyhow!(
                "SOCKS5 UDP ASSOCIATE failed with code: 0x{:02x}",
                head[1]
            ));
        }

        let bound = Self::read_bound_addr(stream, head[3]).await?;
        let peer_ip = stream.peer_addr()?.ip();
        let relay = match bound.ip() {
            IpAddr::V4(v4) if v4.is_unspecified() => SocketAddr::new(peer_ip, bound.port()),
            IpAddr::V6(v6) if v6.is_unspecified() => SocketAddr::new(peer_ip, bound.port()),
            _ => bound,
        };

        Ok(relay)
    }

    async fn read_bound_addr(stream: &mut TcpStream, atyp: u8) -> Result<SocketAddr> {
        let addr = match atyp {
            0x01 => {
                let mut raw = [0u8; 4];
                stream.read_exact(&mut raw).await?;
                IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
            }
            0x04 => {
                let mut raw = [0u8; 16];
                stream.read_exact(&mut raw).await?;
                IpAddr::V6(Ipv6Addr::from(raw))
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                stream.read_exact(&mut domain).await?;
                let text = String::from_utf8(domain)
                    .map_err(|_| anyhow::anyhow!("Invalid domain in SOCKS5 response"))?;
                let resolved = tokio::net::lookup_host((text.as_str(), 0))
                    .await?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Failed to resolve SOCKS5 relay domain"))?;
                resolved.ip()
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid address type in SOCKS5 response: 0x{:02x}",
                    atyp
                ));
            }
        };

        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        Ok(SocketAddr::new(addr, u16::from_be_bytes(port)))
    }

    fn build_udp_request(target_addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut request = vec![0x00, 0x00, 0x00]; // RSV(2), FRAG(1)
        match target_addr {
            SocketAddr::V4(v4) => {
                request.push(0x01);
                request.extend_from_slice(&v4.ip().octets());
                request.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                request.push(0x04);
                request.extend_from_slice(&v6.ip().octets());
                request.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
        request.extend_from_slice(payload);
        request
    }

    fn parse_udp_response(packet: &[u8]) -> Result<(SocketAddr, Vec<u8>)> {
        if packet.len() < 4 {
            return Err(anyhow::anyhow!("SOCKS5 UDP response too short"));
        }

        if packet[2] != 0x00 {
            return Err(anyhow::anyhow!(
                "SOCKS5 UDP fragmentation is not supported (FRAG={})",
                packet[2]
            ));
        }

        let atyp = packet[3];
        let mut pos = 4usize;
        let addr = match atyp {
            0x01 => {
                if packet.len() < pos + 4 {
                    return Err(anyhow::anyhow!("SOCKS5 UDP IPv4 header too short"));
                }
                let ip = Ipv4Addr::new(packet[pos], packet[pos + 1], packet[pos + 2], packet[pos + 3]);
                pos += 4;
                IpAddr::V4(ip)
            }
            0x04 => {
                if packet.len() < pos + 16 {
                    return Err(anyhow::anyhow!("SOCKS5 UDP IPv6 header too short"));
                }
                let mut raw = [0u8; 16];
                raw.copy_from_slice(&packet[pos..pos + 16]);
                pos += 16;
                IpAddr::V6(Ipv6Addr::from(raw))
            }
            0x03 => {
                if packet.len() < pos + 1 {
                    return Err(anyhow::anyhow!("SOCKS5 UDP domain header too short"));
                }
                let len = packet[pos] as usize;
                pos += 1;
                if packet.len() < pos + len {
                    return Err(anyhow::anyhow!("SOCKS5 UDP domain bytes too short"));
                }
                let domain = String::from_utf8(packet[pos..pos + len].to_vec())
                    .map_err(|_| anyhow::anyhow!("Invalid SOCKS5 UDP domain bytes"))?;
                pos += len;
                let resolved = std::net::ToSocketAddrs::to_socket_addrs(&(domain.as_str(), 0))?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Failed to resolve SOCKS5 UDP domain"))?;
                resolved.ip()
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid SOCKS5 UDP address type: 0x{:02x}",
                    atyp
                ));
            }
        };

        if packet.len() < pos + 2 {
            return Err(anyhow::anyhow!("SOCKS5 UDP port bytes missing"));
        }
        let port = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        pos += 2;

        let payload = packet[pos..].to_vec();
        Ok((SocketAddr::new(addr, port), payload))
    }
    
    pub async fn resolve_domain(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if !self.config.dns_over_socks5 {
            return Err(anyhow::anyhow!("DNS resolution over SOCKS5 is disabled"));
        }
        
        // Connect to DNS server through SOCKS5
        let dns_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let client = self.clone();
        let mut stream = client.connect(dns_addr).await?;
        
        // Simple DNS query (A record)
        let query = self.build_dns_query(domain, 1)?; // A record
        stream.write_all(&query).await?;
        
        // Read response
        let mut response = vec![0u8; 512];
        let bytes_read = stream.read(&mut response).await?;
        
        // Parse DNS response
        let ips = self.parse_dns_response(&response[..bytes_read])?;
        
        Ok(ips)
    }
    
    fn build_dns_query(&self, domain: &str, qtype: u16) -> Result<Vec<u8>> {
        let mut query = Vec::new();
        
        // DNS header (12 bytes)
        query.extend_from_slice(&[
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
        ]);
        
        // Question section
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0x00); // End of name
        
        query.extend_from_slice(&qtype.to_be_bytes()); // Type
        query.extend_from_slice(&[0x00, 0x01]); // Class: IN
        
        Ok(query)
    }
    
    fn parse_dns_response(&self, response: &[u8]) -> Result<Vec<IpAddr>> {
        if response.len() < 12 {
            return Err(anyhow::anyhow!("Invalid DNS response length"));
        }
        
        let mut ips = Vec::new();
        let mut pos = 12; // Skip header
        
        // Skip questions
        while pos < response.len() && response[pos] != 0x00 {
            pos += 1;
        }
        pos += 5; // Skip null byte and QTYPE/QCLASS
        
        // Parse answers
        while pos < response.len() {
            if response[pos] == 0xC0 {
                // Compressed name
                pos += 2;
            } else {
                // Skip name
                while pos < response.len() && response[pos] != 0x00 {
                    pos += 1;
                }
                pos += 1;
            }
            
            if pos + 10 > response.len() {
                break;
            }
            
            let qtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
            let qclass = u16::from_be_bytes([response[pos + 2], response[pos + 3]]);
            let _ttl = u32::from_be_bytes([response[pos + 4], response[pos + 5], response[pos + 6], response[pos + 7]]);
            let data_len = u16::from_be_bytes([response[pos + 8], response[pos + 9]]);
            
            pos += 10;
            
            if qtype == 1 && qclass == 1 { // A record
                if data_len == 4 && pos + 4 <= response.len() {
                    let ip = Ipv4Addr::new(response[pos], response[pos + 1], response[pos + 2], response[pos + 3]);
                    ips.push(IpAddr::V4(ip));
                }
            }
            
            pos += data_len as usize;
        }
        
        Ok(ips)
    }
}

impl Socks5UdpSession {
    pub async fn exchange(&mut self, target_addr: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
        let request = Socks5Client::build_udp_request(target_addr, payload);
        self.udp_socket.send_to(&request, self.relay_addr).await?;

        let mut recv_buf = vec![0u8; 8192];
        let (n, _) = self.udp_socket.recv_from(&mut recv_buf).await?;
        let (_, response_payload) = Socks5Client::parse_udp_response(&recv_buf[..n])?;
        Ok(response_payload)
    }
}