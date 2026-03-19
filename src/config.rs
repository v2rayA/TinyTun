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

/// Transport used by a [`DnsGroup`] when forwarding queries to upstream servers.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsUpstream {
    /// Send directly via UDP (or plain TCP).
    #[default]
    Direct,
    /// Tunnel through the configured SOCKS5 proxy (DNS-over-TCP framing).
    Proxy,
}

/// Strategy controlling how a [`DnsGroup`] picks which server(s) to query.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsQueryStrategy {
    /// Send to **all** servers simultaneously; use the first successful response.
    Concurrent,
    /// Try each server top-to-bottom; advance to the next only on failure.
    #[default]
    Sequential,
    /// Shuffle the server list randomly, then try sequentially on that order.
    Random,
}

/// A named group of DNS upstream servers sharing a query strategy and transport.
///
/// Routing rules (in [`DnsRoutingConfig`]) reference groups by `name`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsGroup {
    /// Unique identifier referenced by routing rules (e.g. `"direct"`, `"proxy"`).
    pub name: String,
    /// Upstream DNS server addresses (host:port).
    pub servers: Vec<SocketAddr>,
    /// How to select which server(s) to query within this group.
    #[serde(default)]
    pub strategy: DnsQueryStrategy,
    /// Whether to query servers directly or via the SOCKS5 proxy.
    #[serde(default)]
    pub upstream: DnsUpstream,
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
    pub socks5: Socks5Config,
    pub dns: DnsConfig,
    pub filtering: FilteringConfig,
    #[serde(default)]
    pub route: RouteConfig,
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
    /// Named upstream groups.  At least one group is required.
    pub groups: Vec<DnsGroup>,
    pub listen_port: u16,
    pub timeout_ms: u64,
    #[serde(default)]
    pub hijack: DnsHijackConfig,
    #[serde(default)]
    pub routing: DnsRoutingConfig,
}

/// A DNS domain-matching rule.
///
/// When a rule matches:
/// - if `reject` is `true` — the query is answered with NXDOMAIN immediately;
/// - otherwise — the query is forwarded to the DNS group named by `group`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRoutingRule {
    pub matcher: DnsMatcher,
    /// Name of the [`DnsGroup`] to forward matching queries to.
    /// This field is ignored when `reject` is `true`.
    #[serde(default)]
    pub group: Option<String>,
    /// Return NXDOMAIN for matching domains (blocks the domain).
    /// Takes priority over `group`.
    #[serde(default)]
    pub reject: bool,
}

/// Matcher variants, serialised with a `"type"` tag and an optional `"value"`.
///
/// JSON examples:
/// ```json
/// {"type": "domain_suffix",  "value": "cn"}
/// {"type": "domain_keyword", "value": "google"}
/// {"type": "domain_full",    "value": "example.com"}
/// {"type": "domain_regex",   "value": "^ads?[0-9]*\\."}
/// {"type": "geosite",        "file": "/etc/v2ray/geosite.dat", "tag": "cn"}
/// {"type": "wildcard"}
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DnsMatcher {
    /// Exact domain match (e.g. `"example.com"` but not `"www.example.com"`).
    DomainFull { value: String },
    /// Suffix match — matches the domain itself and all its sub-domains.
    DomainSuffix { value: String },
    /// Sub-string match anywhere in the domain label.
    DomainKeyword { value: String },
    /// Full regex match against the FQDN (excluding the trailing dot).
    DomainRegex { value: String },
    /// Match against a v2ray geosite.dat category.
    ///
    /// `file` is the absolute path to the `geosite.dat` file.
    /// `tag`  is the category name (case-insensitive, e.g. `"cn"`,
    /// `"google"`, `"category-ads-all"`).
    Geosite { file: String, tag: String },
    /// Unconditionally matches every domain (catch-all / default).
    Wildcard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsRoutingConfig {
    /// Ordered list of routing rules; first match wins.
    pub rules: Vec<DnsRoutingRule>,
    /// Name of the [`DnsGroup`] to use when no rule matches.
    pub fallback_group: String,
    /// Enable TTL-aware LRU response cache.
    pub enable_cache: bool,
    /// Maximum number of cached DNS responses.
    pub cache_capacity: usize,
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
pub struct FilteringConfig {
    pub skip_ips: Vec<IpAddr>,
    pub skip_networks: Vec<String>, // CIDR notation
    pub block_ports: Vec<u16>,
    pub allow_ports: Vec<u16>,
    #[serde(default)]
    pub exclude_processes: Vec<String>,
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
            groups: vec![
                DnsGroup {
                    name: "direct".to_string(),
                    servers: vec![
                        "114.114.114.114:53".parse().unwrap(),
                        "223.5.5.5:53".parse().unwrap(),
                    ],
                    strategy: DnsQueryStrategy::Concurrent,
                    upstream: DnsUpstream::Direct,
                },
                DnsGroup {
                    name: "proxy".to_string(),
                    servers: vec![
                        "8.8.8.8:53".parse().unwrap(),
                        "1.1.1.1:53".parse().unwrap(),
                    ],
                    strategy: DnsQueryStrategy::Concurrent,
                    upstream: DnsUpstream::Proxy,
                },
            ],
            listen_port: 53,
            timeout_ms: 5000,
            hijack: DnsHijackConfig::default(),
            routing: DnsRoutingConfig::default(),
        }
    }
}

impl Default for DnsRoutingConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            fallback_group: "proxy".to_string(),
            enable_cache: true,
            cache_capacity: 4096,
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
