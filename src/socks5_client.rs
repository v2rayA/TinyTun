use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::Mutex;

use crate::config::Socks5Config;

pub struct Socks5Client {
    config: Socks5Config,
    stream: Option<Arc<Mutex<TcpStream>>>,
}

impl Socks5Client {
    pub fn new(config: Socks5Config) -> Self {
        Self {
            config,
            stream: None,
        }
    }
}

impl Clone for Socks5Client {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            stream: None,
        }
    }
}

impl Socks5Client {
    pub async fn connect(&mut self, target_addr: SocketAddr) -> Result<TcpStream> {
        info!("Connecting to SOCKS5 proxy: {}", self.config.address);
        
        let mut stream = TcpStream::connect(&self.config.address).await?;
        
        // SOCKS5 handshake
        self.perform_handshake(&mut stream).await?;
        
        // Connect to target
        self.connect_to_target(&mut stream, target_addr).await?;
        
        Ok(stream)
    }
    
    async fn perform_handshake(&self, stream: &mut TcpStream) -> Result<()> {
        // SOCKS5 handshake: client greeting
        let auth_methods = if self.config.username.is_some() && self.config.password.is_some() {
            vec![0x02] // Username/password authentication
        } else {
            vec![0x00] // No authentication
        };
        
        let mut greeting = vec![0x05, auth_methods.len() as u8];
        greeting.extend_from_slice(&auth_methods);
        
        stream.write_all(&greeting).await?;
        
        // Read server response
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        
        if response[0] != 0x05 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 version in server response"));
        }
        
        let auth_method = response[1];
        
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
    
    pub async fn resolve_domain(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if !self.config.dns_over_socks5 {
            return Err(anyhow::anyhow!("DNS resolution over SOCKS5 is disabled"));
        }
        
        // Connect to DNS server through SOCKS5
        let dns_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let mut client = self.clone();
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
            let ttl = u32::from_be_bytes([response[pos + 4], response[pos + 5], response[pos + 6], response[pos + 7]]);
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