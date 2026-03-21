use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Result;
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::config::ProxyConfig;

pub struct Socks5UdpSession {
    // Keep the TCP control channel alive for this UDP ASSOCIATE session.
    _control: TcpStream,
    relay_addr: SocketAddr,
    udp_socket: UdpSocket,
}

#[derive(Clone)]
pub struct Socks5Client {
    config: ProxyConfig,
}

impl Socks5Client {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    /// Return a `socks5h://[user:pass@]host:port` URL for use with HTTP clients
    /// that support SOCKS5 proxies (e.g. `reqwest`).
    pub fn proxy_socks5h_url(&self) -> String {
        let addr = self.config.address;
        match (&self.config.username, &self.config.password) {
            (Some(u), Some(p)) => format!(
                "socks5h://{}:{}@{}",
                percent_encode(u),
                percent_encode(p),
                addr
            ),
            _ => format!("socks5h://{}", addr),
        }
    }

    pub fn name(&self) -> &str {
        &self.config.name
    }

    pub fn address(&self) -> SocketAddr {
        self.config.address
    }
}

/// Percent-encode a string for use in a URL userinfo component.
fn percent_encode(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                vec![c]
            } else {
                c.to_string()
                    .bytes()
                    .flat_map(|b| format!("%{:02X}", b).chars().collect::<Vec<_>>())
                    .collect()
            }
        })
        .collect()
}

impl Socks5Client {
    pub async fn connect(&self, target_addr: SocketAddr) -> Result<TcpStream> {
        debug!("Connecting to SOCKS5 proxy {}: target {}", self.config.address, target_addr);

        let mut stream = TcpStream::connect(&self.config.address).await?;
        stream.set_nodelay(true)?;

        self.perform_handshake(&mut stream).await?;
        self.connect_to_target(&mut stream, target_addr).await?;

        Ok(stream)
    }

    pub async fn open_udp_session(&self, target_hint: SocketAddr) -> Result<Socks5UdpSession> {
        debug!(
            "Opening SOCKS5 UDP ASSOCIATE session (proxy={}, target family={})",
            self.config.address,
            target_hint
        );

        let mut control = TcpStream::connect(&self.config.address).await?;
        control.set_nodelay(true)?;
        self.perform_handshake(&mut control).await?;

        let relay_addr = self.udp_associate(&mut control).await?;
        let bind_addr = if relay_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let udp_socket = UdpSocket::bind(bind_addr).await?;

        Ok(Socks5UdpSession {
            _control: control,
            relay_addr,
            udp_socket,
        })
    }

    /// Perform the SOCKS5 method-negotiation handshake.
    ///
    /// If the proxy selects username/password auth (method 0x02) the
    /// sub-negotiation is performed immediately inside this call.
    async fn perform_handshake(&self, stream: &mut TcpStream) -> Result<()> {
        let has_auth = self.config.username.is_some() && self.config.password.is_some();

        // Build and send greeting in a single write to minimise RTTs.
        let greeting = if has_auth {
            vec![0x05, 0x02, 0x00, 0x02] // VER, NAUTH=2, NO_AUTH, USER_PASS
        } else {
            vec![0x05, 0x01, 0x00] // VER, NAUTH=1, NO_AUTH
        };
        stream.write_all(&greeting).await?;
        drop(greeting); // free

        let mut method_resp = [0u8; 2];
        stream.read_exact(&mut method_resp).await
            .map_err(|e| anyhow::anyhow!("Failed to read SOCKS5 method selection: {}", e))?;

        if method_resp[0] != 0x05 {
            return Err(anyhow::anyhow!(
                "SOCKS5 server sent unexpected version byte 0x{:02x} (expected 0x05)",
                method_resp[0]
            ));
        }

        match method_resp[1] {
            0xFF => Err(anyhow::anyhow!(
                "SOCKS5 server rejected all offered authentication methods"
            )),
            0x02 => self.authenticate(stream).await,
            0x00 => Ok(()),
            other => Err(anyhow::anyhow!(
                "SOCKS5 server chose unsupported auth method 0x{:02x}",
                other
            )),
        }
    }

    /// Perform SOCKS5 username/password sub-negotiation (RFC 1929).
    async fn authenticate(&self, stream: &mut TcpStream) -> Result<()> {
        let username = self.config.username.as_deref()
            .ok_or_else(|| anyhow::anyhow!("Proxy selected username/password auth but no username configured"))?;
        let password = self.config.password.as_deref()
            .ok_or_else(|| anyhow::anyhow!("Proxy selected username/password auth but no password configured"))?;

        if username.len() > 255 || password.len() > 255 {
            return Err(anyhow::anyhow!("SOCKS5 username or password exceeds 255 bytes"));
        }

        // Build auth sub-negotiation request in one buffer.
        let mut req = Vec::with_capacity(3 + username.len() + password.len());
        req.push(0x01); // sub-negotiation version
        req.push(username.len() as u8);
        req.extend_from_slice(username.as_bytes());
        req.push(password.len() as u8);
        req.extend_from_slice(password.as_bytes());

        stream.write_all(&req).await?;

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await
            .map_err(|e| anyhow::anyhow!("Failed to read SOCKS5 auth response: {}", e))?;

        if resp[1] != 0x00 {
            return Err(anyhow::anyhow!(
                "SOCKS5 authentication failed (status=0x{:02x})",
                resp[1]
            ));
        }

        Ok(())
    }

    /// Send a SOCKS5 CONNECT request and read the server reply.
    async fn connect_to_target(&self, stream: &mut TcpStream, target_addr: SocketAddr) -> Result<()> {
        // Build the full CONNECT request in one buffer to avoid extra RTTs.
        let mut request = Vec::with_capacity(22);
        request.extend_from_slice(&[
            0x05, // VER
            0x01, // CMD = CONNECT
            0x00, // RSV
        ]);
        match target_addr {
            SocketAddr::V4(v4) => {
                request.push(0x01);
                request.extend_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                request.push(0x04);
                request.extend_from_slice(&v6.ip().octets());
            }
        }
        request.extend_from_slice(&target_addr.port().to_be_bytes());

        stream.write_all(&request).await?;

        // Read the fixed 4-byte reply header.
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await
            .map_err(|e| anyhow::anyhow!("Failed to read SOCKS5 CONNECT reply header: {}", e))?;

        if head[0] != 0x05 {
            return Err(anyhow::anyhow!(
                "SOCKS5 CONNECT reply has unexpected version byte 0x{:02x}",
                head[0]
            ));
        }

        if head[1] != 0x00 {
            // Still need to drain the bound-address field before returning,
            // otherwise the connection state machine is left in an inconsistent
            // state if the caller reuses the stream.
            let _ = Self::drain_bound_addr(stream, head[3]).await;
            return Err(anyhow::anyhow!(
                "SOCKS5 CONNECT to {} rejected (REP=0x{:02x}: {})",
                target_addr,
                head[1],
                socks5_rep_name(head[1])
            ));
        }

        // Drain the bound-address/port echo from the server reply.
        Self::drain_bound_addr(stream, head[3]).await?;

        Ok(())
    }

    /// Drain the BND.ADDR + BND.PORT fields from a SOCKS5 reply.
    ///
    /// Called after reading the 4-byte fixed header to leave the stream
    /// positioned at the start of the application data.
    async fn drain_bound_addr(stream: &mut TcpStream, atyp: u8) -> Result<()> {
        match atyp {
            0x01 => {
                let mut buf = [0u8; 6]; // 4-byte IPv4 + 2-byte port
                stream.read_exact(&mut buf).await
                    .map_err(|e| anyhow::anyhow!("Failed to read SOCKS5 bound IPv4 address: {}", e))?;
            }
            0x04 => {
                let mut buf = [0u8; 18]; // 16-byte IPv6 + 2-byte port
                stream.read_exact(&mut buf).await
                    .map_err(|e| anyhow::anyhow!("Failed to read SOCKS5 bound IPv6 address: {}", e))?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await
                    .map_err(|e| anyhow::anyhow!("Failed to read SOCKS5 bound domain length: {}", e))?;
                let mut buf = vec![0u8; len[0] as usize + 2]; // domain + 2-byte port
                stream.read_exact(&mut buf).await
                    .map_err(|e| anyhow::anyhow!("Failed to read SOCKS5 bound domain: {}", e))?;
            }
            other => {
                return Err(anyhow::anyhow!(
                    "SOCKS5 reply contains unknown ATYP 0x{:02x}",
                    other
                ));
            }
        }
        Ok(())
    }

    async fn udp_associate(&self, stream: &mut TcpStream) -> Result<SocketAddr> {
        // UDP ASSOCIATE: client sends 0.0.0.0:0 to indicate "any source".
        let request = [
            0x05, 0x03, 0x00, // VER, CMD=UDP ASSOCIATE, RSV
            0x01, 0x00, 0x00, 0x00, 0x00, // ATYP=IPv4, addr=0.0.0.0
            0x00, 0x00, // port=0
        ];

        stream.write_all(&request).await?;

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await
            .map_err(|e| anyhow::anyhow!("Failed to read SOCKS5 UDP ASSOCIATE reply header: {}", e))?;

        if head[0] != 0x05 {
            return Err(anyhow::anyhow!(
                "SOCKS5 UDP ASSOCIATE reply has unexpected version byte 0x{:02x}",
                head[0]
            ));
        }
        if head[1] != 0x00 {
            let _ = Self::drain_bound_addr(stream, head[3]).await;
            return Err(anyhow::anyhow!(
                "SOCKS5 UDP ASSOCIATE failed (REP=0x{:02x}: {})",
                head[1],
                socks5_rep_name(head[1])
            ));
        }

        let bound = Self::read_relay_addr(stream, head[3]).await?;
        let peer_ip = stream.peer_addr()?.ip();
        let relay = match bound.ip() {
            IpAddr::V4(v4) if v4.is_unspecified() => SocketAddr::new(peer_ip, bound.port()),
            IpAddr::V6(v6) if v6.is_unspecified() => SocketAddr::new(peer_ip, bound.port()),
            _ => bound,
        };

        Ok(relay)
    }

    async fn read_relay_addr(stream: &mut TcpStream, atyp: u8) -> Result<SocketAddr> {
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
                    .map_err(|_| anyhow::anyhow!("SOCKS5 relay address contained invalid UTF-8"))?;
                let resolved = tokio::net::lookup_host((text.as_str(), 0))
                    .await?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Failed to resolve SOCKS5 relay domain '{}'", text))?
                    .ip();
                resolved
            }
            other => {
                return Err(anyhow::anyhow!(
                    "SOCKS5 relay address has unknown ATYP 0x{:02x}",
                    other
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
            return Err(anyhow::anyhow!(
                "SOCKS5 UDP response too short ({} bytes, need at least 4)",
                packet.len()
            ));
        }

        if packet[2] != 0x00 {
            return Err(anyhow::anyhow!(
                "SOCKS5 UDP fragmentation not supported (FRAG={})",
                packet[2]
            ));
        }

        let atyp = packet[3];
        let mut pos = 4usize;
        let addr = match atyp {
            0x01 => {
                if packet.len() < pos + 4 {
                    return Err(anyhow::anyhow!("SOCKS5 UDP datagram truncated in IPv4 address field"));
                }
                let ip = Ipv4Addr::new(packet[pos], packet[pos + 1], packet[pos + 2], packet[pos + 3]);
                pos += 4;
                IpAddr::V4(ip)
            }
            0x04 => {
                if packet.len() < pos + 16 {
                    return Err(anyhow::anyhow!("SOCKS5 UDP datagram truncated in IPv6 address field"));
                }
                let mut raw = [0u8; 16];
                raw.copy_from_slice(&packet[pos..pos + 16]);
                pos += 16;
                IpAddr::V6(Ipv6Addr::from(raw))
            }
            0x03 => {
                if packet.len() < pos + 1 {
                    return Err(anyhow::anyhow!("SOCKS5 UDP datagram truncated in domain length field"));
                }
                let len = packet[pos] as usize;
                pos += 1;
                if packet.len() < pos + len {
                    return Err(anyhow::anyhow!("SOCKS5 UDP datagram truncated in domain field"));
                }
                let domain = String::from_utf8(packet[pos..pos + len].to_vec())
                    .map_err(|_| anyhow::anyhow!("SOCKS5 UDP datagram domain contained invalid UTF-8"))?;
                pos += len;
                std::net::ToSocketAddrs::to_socket_addrs(&(domain.as_str(), 0))?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Failed to resolve SOCKS5 UDP domain '{}'", domain))?
                    .ip()
            }
            other => {
                return Err(anyhow::anyhow!(
                    "SOCKS5 UDP datagram has unknown ATYP 0x{:02x}",
                    other
                ));
            }
        };

        if packet.len() < pos + 2 {
            return Err(anyhow::anyhow!("SOCKS5 UDP datagram truncated in port field"));
        }
        let port = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        pos += 2;

        Ok((SocketAddr::new(addr, port), packet[pos..].to_vec()))
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

/// Human-readable description for SOCKS5 reply codes (RFC 1928 §6).
fn socks5_rep_name(rep: u8) -> &'static str {
    match rep {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}
