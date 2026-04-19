use std::collections::HashSet;
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

/// Encryption / transport protocol used to communicate with upstream DNS servers.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsProtocol {
    /// Plain DNS over UDP (RFC 1035, default port 53).
    #[default]
    Udp,
    /// Plain DNS over TCP (RFC 1035, default port 53).
    Tcp,
    /// DNS over TLS — RFC 7858 (default port 853).
    /// `servers` entries must be `"host:port"` strings.
    Dot,
    /// DNS over HTTPS — RFC 8484.
    /// `servers` entries must be HTTPS URLs, e.g. `"https://dns.google/dns-query"`.
    Doh,
    /// DNS over QUIC — RFC 9250 (default port 853).
    /// `servers` entries must be `"host:port"` strings.
    /// Note: QUIC is UDP-based and cannot be tunnelled through a TCP SOCKS5 proxy.
    Doq,
}

/// Transport used by a [`DnsGroup`] when forwarding queries to upstream servers.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(untagged)]
pub enum DnsUpstream {
    /// Send directly via UDP (or plain TCP).
    #[default]
    #[serde(rename = "direct")]
    Direct,
    /// Tunnel through a named SOCKS5 proxy.
    ///
    /// Use `"proxy"` to select the first configured proxy, or any name from
    /// the `proxies` list to select a specific one.
    Named(String),
}

impl DnsUpstream {
    /// Return the proxy name if this upstream uses a proxy, or `None` for direct.
    pub fn proxy_name(&self) -> Option<&str> {
        match self {
            DnsUpstream::Direct => None,
            DnsUpstream::Named(name) => Some(name.as_str()),
        }
    }

    /// Returns `true` when the upstream should be routed through a proxy.
    pub fn is_proxy(&self) -> bool {
        matches!(self, DnsUpstream::Named(_))
    }
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
    /// Upstream server addresses.
    ///
    /// - For `Udp`, `Tcp`, `Dot`, `Doq`: `"host:port"` strings
    ///   (e.g. `"8.8.8.8:853"` or `"dns.google:853"`).
    /// - For `Doh`: HTTPS endpoint URLs
    ///   (e.g. `"https://dns.google/dns-query"`).
    pub servers: Vec<String>,
    /// How to select which server(s) to query within this group.
    #[serde(default)]
    pub strategy: DnsQueryStrategy,
    /// Whether to query servers directly or via a SOCKS5 proxy.
    ///
    /// - `"direct"` — plain UDP/TCP, no proxy.
    /// - `"proxy"` — route through the default SOCKS5 proxy.
    /// - any other string — route through the named proxy from the `proxies` list.
    ///
    /// For `Doq`, this field is ignored (QUIC cannot traverse TCP SOCKS5).
    #[serde(default)]
    pub upstream: DnsUpstream,
    /// Encryption protocol used to communicate with each server.
    #[serde(default)]
    pub protocol: DnsProtocol,
    /// TLS server name (SNI) override for `Dot` and `Doq`.
    ///
    /// When omitted the hostname portion of the server address string is used
    /// as the SNI value.  Required when `servers` contains bare IP addresses
    /// and the server certificate does not cover that IP via a SAN.
    #[serde(default)]
    pub sni: Option<String>,
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

/// A named SOCKS5 proxy upstream.
///
/// The `name` field uniquely identifies the proxy and is referenced by
/// DNS group `upstream` values and traffic routing rules.
/// The first entry in `proxies` (or the `socks5` shorthand) acts as the
/// **default proxy** and can be referenced via the special name `"proxy"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Unique name used to reference this proxy.
    /// The default proxy should be named `"proxy"`.
    #[serde(default = "default_proxy_name")]
    pub name: String,
    /// SOCKS5 proxy address (`host:port`).
    pub address: SocketAddr,
    /// Optional SOCKS5 username.
    pub username: Option<String>,
    /// Optional SOCKS5 password.
    pub password: Option<String>,
}

fn default_proxy_name() -> String {
    "proxy".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    pub tun: TunConfig,
    /// Shorthand for the default proxy (equivalent to `proxies[0]` with
    /// name=`"proxy"`).  Kept for backward compatibility.
    pub socks5: ProxyConfig,
    /// Additional named proxies.  Entries here are merged with `socks5`.
    /// Names must be unique; `"proxy"` is reserved for the default proxy.
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,
    pub dns: DnsConfig,
    pub filtering: FilteringConfig,
    #[serde(default)]
    pub route: RouteConfig,
}

impl Config {
    /// Return every configured proxy in order (default first, then extras).
    pub fn all_proxies(&self) -> impl Iterator<Item = &ProxyConfig> {
        std::iter::once(&self.socks5).chain(self.proxies.iter())
    }
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
#[serde(default)]
pub struct FilteringConfig {
    pub skip_ips: Vec<IpAddr>,
    pub skip_networks: Vec<String>, // CIDR notation
    pub block_ports: Vec<u16>,
    pub allow_ports: Vec<u16>,
    #[serde(default)]
    pub exclude_processes: Vec<String>,
    // ── Runtime-only: built by `finalize()`, never serialised ────────────
    /// Fast O(1) lookup set for exact-IP matching; mirrors `skip_ips`.
    #[serde(skip)]
    pub(crate) skip_ips_set: HashSet<IpAddr>,
    /// Pre-parsed CIDR networks; mirrors `skip_networks` (no per-packet re-parsing).
    #[serde(skip)]
    pub(crate) skip_networks_parsed: Vec<ipnetwork::IpNetwork>,
}

impl FilteringConfig {
    /// Rebuild the runtime lookup structures from `skip_ips` and `skip_networks`.
    /// Call this once after construction and again after any `push` to those vecs.
    pub fn finalize(&mut self) {
        self.skip_ips_set = self.skip_ips.iter().copied().collect();
        self.skip_networks_parsed = self
            .skip_networks
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
    }
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
    pub hide_timestamp: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log: LogConfig::default(),
            tun: TunConfig::default(),
            socks5: ProxyConfig::default(),
            proxies: Vec::new(),
            dns: DnsConfig::default(),
            filtering: FilteringConfig::default(),
            route: RouteConfig::default(),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            name: "proxy".to_string(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080),
            username: None,
            password: None,
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

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            groups: vec![
                DnsGroup {
                    name: "direct".to_string(),
                    servers: vec![
                        "114.114.114.114:53".to_string(),
                        "223.5.5.5:53".to_string(),
                    ],
                    strategy: DnsQueryStrategy::Concurrent,
                    upstream: DnsUpstream::Direct,
                    protocol: DnsProtocol::Udp,
                    sni: None,
                },
                DnsGroup {
                    name: "proxy".to_string(),
                    servers: vec![
                        "8.8.8.8:53".to_string(),
                        "1.1.1.1:53".to_string(),
                    ],
                    strategy: DnsQueryStrategy::Concurrent,
                    upstream: DnsUpstream::Named("proxy".to_string()),
                    protocol: DnsProtocol::Udp,
                    sni: None,
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
        let mut cfg = Self {
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
            skip_ips_set: HashSet::new(),
            skip_networks_parsed: Vec::new(),
        };
        cfg.finalize();
        cfg
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
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("json");
        let mut config = match ext {
            "yaml" | "yml" => {
                let yaml_config: YamlConfig = serde_yaml::from_str(&content)?;
                yaml_config.into_config()?
            }
            _ => {
                let config: Config = serde_json::from_str(&content)?;
                config
            }
        };
        // Rebuild the runtime lookup structures (CIDR pre-parsing, IP HashSet).
        config.filtering.finalize();
        Ok(config)
    }

    /// Check if an IP address should be skipped (not proxied).
    ///
    /// Uses pre-built runtime structures (populated by `FilteringConfig::finalize`)
    /// for O(1) exact-IP lookup and zero per-call CIDR string parsing.
    pub fn should_skip_ip(&self, ip: IpAddr) -> bool {
        if self.filtering.skip_ips_set.contains(&ip) {
            return true;
        }
        self.filtering.skip_networks_parsed.iter().any(|n| n.contains(ip))
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
            hide_timestamp: false,
        }
    }
}

// ---------------------------------------------------------------------------
// YAML support — simplified rule syntax
// ---------------------------------------------------------------------------

/// YAML-specific representation of DNS routing config.
/// Rules are written as compact strings instead of nested objects.
///
/// Syntax:  `match(<condition>),<action>`
///
/// Conditions:
///   `geosite:<tag>`           — v2ray geosite category (uses `geosite_file`)
///   `geosite:<tag>:<file>`    — explicit geosite.dat path
///   `domain:<fqdn>`           — exact domain match
///   `suffix:<domain>`         — suffix (sub-domain) match
///   `keyword:<word>`          — substring keyword match
///   `regex:<pattern>`         — regex match
///   `*`                       — wildcard / catch-all
///
/// Actions:
///   `<group-name>`            — forward to named DNS group
///   `reject`                  — answer with NXDOMAIN
///
/// Examples:
///   `match(geosite:category-ads-all),reject`
///   `match(geosite:cn),direct`
///   `match(suffix:github.com),proxy`
///   `match(*),proxy`
#[derive(Debug, Clone, Serialize, Deserialize)]
struct YamlDnsRoutingConfig {
    /// Ordered routing rules in compact string form.
    #[serde(default)]
    pub rules: Vec<String>,
    /// Name of the fallback DNS group when no rule matches.
    #[serde(default = "default_fallback_group")]
    pub fallback_group: String,
    /// Default geosite.dat path used when a `geosite:tag` rule omits the file.
    #[serde(default)]
    pub geosite_file: Option<String>,
    #[serde(default = "default_true")]
    pub enable_cache: bool,
    #[serde(default = "default_cache_capacity")]
    pub cache_capacity: usize,
}

fn default_fallback_group() -> String { "proxy".to_string() }
fn default_true() -> bool { true }
fn default_cache_capacity() -> usize { 4096 }

impl Default for YamlDnsRoutingConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            fallback_group: default_fallback_group(),
            geosite_file: None,
            enable_cache: true,
            cache_capacity: default_cache_capacity(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct YamlDnsConfig {
    pub groups: Vec<DnsGroup>,
    #[serde(default = "default_dns_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub hijack: DnsHijackConfig,
    #[serde(default)]
    pub routing: YamlDnsRoutingConfig,
}

fn default_dns_listen_port() -> u16 { 53 }
fn default_dns_timeout_ms() -> u64 { 5000 }

/// Top-level YAML config.  Identical to [`Config`] except DNS routing rules
/// are in the compact string syntax.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct YamlConfig {
    #[serde(default)]
    pub log: LogConfig,
    pub tun: TunConfig,
    pub socks5: ProxyConfig,
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,
    pub dns: YamlDnsConfig,
    pub filtering: FilteringConfig,
    #[serde(default)]
    pub route: RouteConfig,
}

impl YamlConfig {
    fn into_config(self) -> Result<Config> {
        let geosite_file = self.dns.routing.geosite_file;
        let rules = self
            .dns
            .routing
            .rules
            .iter()
            .map(|s| parse_yaml_rule(s, geosite_file.as_deref()))
            .collect::<Result<Vec<_>>>()?;

        Ok(Config {
            log: self.log,
            tun: self.tun,
            socks5: self.socks5,
            proxies: self.proxies,
            dns: DnsConfig {
                groups: self.dns.groups,
                listen_port: self.dns.listen_port,
                timeout_ms: self.dns.timeout_ms,
                hijack: self.dns.hijack,
                routing: DnsRoutingConfig {
                    rules,
                    fallback_group: self.dns.routing.fallback_group,
                    enable_cache: self.dns.routing.enable_cache,
                    cache_capacity: self.dns.routing.cache_capacity,
                },
            },
            filtering: self.filtering,
            route: self.route,
        })
    }
}

/// Parse one compact rule string into a [`DnsRoutingRule`].
fn parse_yaml_rule(s: &str, default_geosite_file: Option<&str>) -> Result<DnsRoutingRule> {
    // Expected: `match(<condition>),<action>`
    let s = s.trim();
    let inner = s
        .strip_prefix("match(")
        .ok_or_else(|| anyhow::anyhow!("DNS rule must start with 'match(': {s}"))?;

    let close = inner
        .rfind(')') // find the matching closing paren
        .ok_or_else(|| anyhow::anyhow!("DNS rule missing closing ')': {s}"))?;

    let condition = &inner[..close];
    let rest = inner[close + 1..].trim();
    let action = rest
        .strip_prefix(',')
        .ok_or_else(|| anyhow::anyhow!("DNS rule missing ',<action>' after ')': {s}"))?
        .trim();

    let matcher = parse_condition(condition, default_geosite_file, s)?;

    let (group, reject) = if action.eq_ignore_ascii_case("reject") {
        (None, true)
    } else {
        (Some(action.to_string()), false)
    };

    Ok(DnsRoutingRule { matcher, group, reject })
}

fn parse_condition(
    cond: &str,
    default_geosite_file: Option<&str>,
    full_rule: &str,
) -> Result<DnsMatcher> {
    if cond == "*" {
        return Ok(DnsMatcher::Wildcard);
    }

    if let Some(rest) = cond.strip_prefix("geosite:") {
        // geosite:TAG  or  geosite:TAG:FILE
        let mut parts = rest.splitn(2, ':');
        let tag = parts.next().unwrap_or("").to_string();
        let file = parts
            .next()
            .map(|f| f.to_string())
            .or_else(|| default_geosite_file.map(|f| f.to_string()))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "geosite rule '{full_rule}' has no file path \
                     and no 'geosite_file' default is set"
                )
            })?;
        return Ok(DnsMatcher::Geosite { file, tag });
    }

    if let Some(value) = cond.strip_prefix("domain:") {
        return Ok(DnsMatcher::DomainFull { value: value.to_string() });
    }
    if let Some(value) = cond.strip_prefix("suffix:") {
        return Ok(DnsMatcher::DomainSuffix { value: value.to_string() });
    }
    if let Some(value) = cond.strip_prefix("keyword:") {
        return Ok(DnsMatcher::DomainKeyword { value: value.to_string() });
    }
    if let Some(value) = cond.strip_prefix("regex:") {
        return Ok(DnsMatcher::DomainRegex { value: value.to_string() });
    }

    Err(anyhow::anyhow!("Unknown condition '{cond}' in rule: {full_rule}"))
}

