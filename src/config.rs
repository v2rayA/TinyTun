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
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    pub tun: TunConfig,
    #[serde(default)]
    pub inbound: InboundConfig,
    pub socks5: Socks5Config,
    pub dns: DnsConfig,
    pub filtering: FilteringConfig,
    #[serde(default)]
    pub route: RouteConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InboundMode {
    Tun,
    LinuxEbpf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InboundConfig {
    pub mode: InboundMode,
    pub linux_ebpf: LinuxEbpfIngressConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LinuxEbpfIngressConfig {
    pub enabled: bool,
    pub interface: Option<String>,
    pub bpf_object: String,
    pub bpf_section: String,
    pub skip_map_path: String,
    pub skip_map_v6_path: String,
    pub mark: u32,
    pub table_id: u32,
    pub redirect_port: u16,
    pub redirect_tcp: bool,
    pub redirect_udp: bool,
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
    pub servers: Vec<DnsServerEntry>,
    pub listen_port: u16,
    pub timeout_ms: u64,
    #[serde(default)]
    pub hijack: DnsHijackConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsHijackConfig {
    pub enabled: bool,
    pub mark: u32,
    pub table_id: u32,
    pub capture_tcp: bool,
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
    #[serde(default)]
    pub exclude_processes: Vec<String>,
    #[serde(default)]
    pub process_lookup: ProcessLookupConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessLookupConfig {
    pub linux_backend: String,
    pub linux_ebpf_cache_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteConfig {
    pub auto_detect_interface: bool,
    pub default_interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    pub loglevel: LogLevel,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log: LogConfig::default(),
            tun: TunConfig::default(),
            inbound: InboundConfig::default(),
            socks5: Socks5Config::default(),
            dns: DnsConfig::default(),
            filtering: FilteringConfig::default(),
            route: RouteConfig::default(),
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
            servers: vec![DnsServerEntry {
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                route: DnsRoute::Direct,
            }],
            listen_port: 53,
            timeout_ms: 5000,
            hijack: DnsHijackConfig::default(),
        }
    }
}

impl Default for DnsHijackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mark: 0x1,
            table_id: 100,
            capture_tcp: true,
        }
    }
}

impl Default for FilteringConfig {
    fn default() -> Self {
        Self {
            skip_ips: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), // localhost
                IpAddr::V6(Ipv6Addr::LOCALHOST), // localhost v6
                IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), // TUN interface
            ],
            skip_networks: vec![
                "127.0.0.0/8".to_string(),      // Localhost
                "169.254.0.0/16".to_string(),   // Link-local
                "::1/128".to_string(),          // Localhost v6
                "fc00::/7".to_string(),         // Unique local addresses
                "fe80::/10".to_string(),        // Link-local v6
            ],
            block_ports: vec![22, 23, 25, 110, 143], // Common blocked ports
            allow_ports: vec![80, 443, 53],           // Always allow HTTP, HTTPS, DNS
            exclude_processes: Vec::new(),
            process_lookup: ProcessLookupConfig::default(),
        }
    }
}

impl Default for ProcessLookupConfig {
    fn default() -> Self {
        Self {
            linux_backend: "auto".to_string(),
            linux_ebpf_cache_path: Some("/run/tinytun-ebpf-flow-cache.json".to_string()),
        }
    }
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            auto_detect_interface: true,
            default_interface: None,
        }
    }
}

impl Config {
    pub fn effective_dns_servers(&self) -> Vec<DnsServerEntry> {
        self.dns.servers.clone()
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

    pub fn is_excluded_process_name(&self, process_name: &str) -> bool {
        let candidate = process_name.rsplit(['/', '\\']).next().unwrap_or(process_name);
        self.filtering.exclude_processes.iter().any(|excluded| {
            let excluded_name = excluded.rsplit(['/', '\\']).next().unwrap_or(excluded);
            excluded_name.eq_ignore_ascii_case(candidate)
        })
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Warning
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            loglevel: LogLevel::default(),
        }
    }
}

impl Default for InboundMode {
    fn default() -> Self {
        Self::Tun
    }
}

impl Default for InboundConfig {
    fn default() -> Self {
        Self {
            mode: InboundMode::Tun,
            linux_ebpf: LinuxEbpfIngressConfig::default(),
        }
    }
}

impl Default for LinuxEbpfIngressConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: None,
            bpf_object: "/etc/tinytun/tinytun_ingress.bpf.o".to_string(),
            bpf_section: "classifier/ingress".to_string(),
            skip_map_path: "/sys/fs/bpf/tinytun/skip_v4".to_string(),
            skip_map_v6_path: "/sys/fs/bpf/tinytun/skip_v6".to_string(),
            mark: 0x233,
            table_id: 233,
            redirect_port: 15080,
            redirect_tcp: true,
            redirect_udp: true,
        }
    }
}