use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use log::{debug, info};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::config::DnsConfig;

pub struct DnsHandler {
    config: DnsConfig,
    upstream_socket: Arc<Mutex<UdpSocket>>,
    local_socket: UdpSocket,
}

impl DnsHandler {
    pub async fn new(config: DnsConfig) -> Result<Self> {
        let local_socket = UdpSocket::bind(format!("0.0.0.0:{}", config.listen_port)).await?;
        info!("DNS handler listening on port {}", config.listen_port);
        
        let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let upstream_socket = Arc::new(Mutex::new(upstream_socket));
        
        Ok(Self {
            config,
            upstream_socket,
            local_socket,
        })
    }
    
    pub async fn handle_request(&self, buffer: &[u8], client_addr: SocketAddr) -> Result<()> {
        debug!("DNS request from {}: {} bytes", client_addr, buffer.len());
        
        // Forward to upstream server
        let upstream_socket = self.upstream_socket.clone();
        let upstream_addr = self.config.groups.first()
            .and_then(|g| g.servers.first().copied())
            .ok_or_else(|| anyhow::anyhow!("No DNS server configured"))?;
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);
        
        let response = timeout(timeout_duration, async move {
            let socket = upstream_socket.lock().await;
            socket.send_to(buffer, upstream_addr).await?;
            
            let mut response_buffer = vec![0; 512];
            let (bytes_read, _) = socket.recv_from(&mut response_buffer).await?;
            
            Ok::<Vec<u8>, std::io::Error>(response_buffer[..bytes_read].to_vec())
        }).await??;
        
        // Send response back to client
        self.local_socket.send_to(&response, client_addr).await?;
        
        debug!("DNS response sent to {}", client_addr);
        
        Ok(())
    }
    
    pub async fn resolve_domain(&self, domain: &str, qtype: u16) -> Result<Vec<IpAddr>> {
        let query = self.build_dns_query(domain, qtype)?;
        
        let upstream_socket = self.upstream_socket.clone();
        let upstream_addr = self.config.groups.first()
            .and_then(|g| g.servers.first().copied())
            .ok_or_else(|| anyhow::anyhow!("No DNS server configured"))?;
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);
        
        let response = timeout(timeout_duration, async move {
            let socket = upstream_socket.lock().await;
            socket.send_to(&query, upstream_addr).await?;
            
            let mut response_buffer = vec![0; 512];
            let (bytes_read, _) = socket.recv_from(&mut response_buffer).await?;
            
            Ok::<Vec<u8>, std::io::Error>(response_buffer[..bytes_read].to_vec())
        }).await??;
        
        self.parse_dns_response(&response)
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
            
            match qtype {
                1 => { // A record
                    if qclass == 1 && data_len == 4 && pos + 4 <= response.len() {
                        let ip = Ipv4Addr::new(response[pos], response[pos + 1], response[pos + 2], response[pos + 3]);
                        ips.push(IpAddr::V4(ip));
                    }
                }
                28 => { // AAAA record
                    if qclass == 1 && data_len == 16 && pos + 16 <= response.len() {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&response[pos..pos + 16]);
                        let ip = Ipv6Addr::from(octets);
                        ips.push(IpAddr::V6(ip));
                    }
                }
                _ => {}
            }
            
            pos += data_len as usize;
        }
        
        Ok(ips)
    }
    
    pub fn local_address(&self) -> SocketAddr {
        self.local_socket.local_addr().unwrap_or_else(|_| {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), self.config.listen_port)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_dns_query_parsing() {
        // Simple test for DNS query parsing
        let handler = DnsHandler {
            config: DnsConfig {
                servers: vec![],
                listen_port: 5353,
                timeout_ms: 5000,
            },
            upstream_socket: Arc::new(Mutex::new(UdpSocket::bind("0.0.0.0:0").await.unwrap())),
            local_socket: UdpSocket::bind("0.0.0.0:0").await.unwrap(),
        };
        
        let query = handler.build_dns_query("example.com", 1).unwrap();
        assert_eq!(query.len(), 29); // 12-byte header + 13-byte qname + 4-byte qtype/class
        
        // Test that we can parse a minimal response (this would need actual DNS response data)
        // For now, just test that the function doesn't panic with empty data
        let result = handler.parse_dns_response(&[]);
        assert!(result.is_err());
    }
}