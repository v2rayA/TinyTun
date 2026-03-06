use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::fs;

use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6Mode {
    Auto,
    On,
    Off,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsRoute {
    Direct,
    Proxy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub tun: TunConfig,
    pub socks5: Socks5Config,
    pub dns: DnsConfig,
    pub filtering: FilteringConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TunConfig {
    pub name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub ipv6_mode: Ipv6Mode,
    pub ipv6: Ipv6Addr,
    pub ipv6_prefix: u8,
    pub auto_route: bool,
    pub mtu: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    pub address: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
    pub dns_over_socks5: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub upstream_server: SocketAddr,
    pub servers: Vec<DnsServerEntry>,
    pub listen_port: u16,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerEntry {
    pub address: SocketAddr,
    pub route: DnsRoute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilteringConfig {
    pub skip_ips: Vec<IpAddr>,
    pub skip_networks: Vec<String>, // CIDR notation
    pub block_ports: Vec<u16>,
    pub allow_ports: Vec<u16>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tun: TunConfig::default(),
            socks5: Socks5Config::default(),
            dns: DnsConfig::default(),
            filtering: FilteringConfig::default(),
        }
    }
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "tun0".to_string(),
            ip: Ipv4Addr::new(198, 18, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 255),
            ipv6_mode: Ipv6Mode::Auto,
            ipv6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            ipv6_prefix: 128,
            auto_route: false,
            mtu: 1500,
        }
    }
}

impl Default for Ipv6Mode {
    fn default() -> Self {
        Self::Auto
    }
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080),
            username: None,
            password: None,
            dns_over_socks5: true,
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstream_server: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            servers: vec![DnsServerEntry {
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                route: DnsRoute::Direct,
            }],
            listen_port: 53,
            timeout_ms: 5000,
        }
    }
}

impl Default for FilteringConfig {
    fn default() -> Self {
        Self {
            skip_ips: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), // localhost
                IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), // TUN interface
            ],
            skip_networks: vec![
                "192.168.0.0/16".to_string(),  // Private networks
                "172.16.0.0/12".to_string(),
                "10.0.0.0/8".to_string(),
                "127.0.0.0/8".to_string(),      // Localhost
                "169.254.0.0/16".to_string(),   // Link-local
            ],
            block_ports: vec![22, 23, 25, 110, 143], // Common blocked ports
            allow_ports: vec![80, 443, 53],           // Always allow HTTP, HTTPS, DNS
        }
    }
}

impl Config {
    pub fn effective_dns_servers(&self) -> Vec<DnsServerEntry> {
        if !self.dns.servers.is_empty() {
            return self.dns.servers.clone();
        }

        vec![DnsServerEntry {
            address: self.dns.upstream_server,
            route: DnsRoute::Direct,
        }]
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }
    
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
    
    /// Check if an IP address should be skipped (not proxied)
    pub fn should_skip_ip(&self, ip: IpAddr) -> bool {
        // Check exact IP matches
        if self.filtering.skip_ips.contains(&ip) {
            return true;
        }
        
        // Check network ranges
        for network_str in &self.filtering.skip_networks {
            if let Ok(network) = network_str.parse::<ipnetwork::IpNetwork>() {
                if network.contains(ip) {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Check if a port should be skipped
    pub fn should_skip_port(&self, port: u16) -> bool {
        // Always allow explicit allow ports
        if self.filtering.allow_ports.contains(&port) {
            return false;
        }
        
        // Block if in block list
        if self.filtering.block_ports.contains(&port) {
            return true;
        }
        
        false
    }
    
    /// Check if a connection should be proxied
    pub fn should_proxy(&self, ip: IpAddr, port: u16) -> bool {
        !self.should_skip_ip(ip) && !self.should_skip_port(port)
    }
}