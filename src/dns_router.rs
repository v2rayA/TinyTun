//! DNS routing engine.
//!
//! [`DnsRouter`] accepts a raw DNS wire-format query, applies domain-based
//! routing rules to select the appropriate upstream server(s), optionally
//! queries them in parallel, caches successful responses by their DNS TTL,
//! and returns a raw DNS wire-format response.
//!
//! Design is inspired by the DNS subsystem of [dae](https://github.com/daeuniverse/dae),
//! adapted for TinyTun's simpler architecture.

use std::net::SocketAddr;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use log::{debug, warn};
use lru::LruCache;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::config::{DnsConfig, DnsGroup, DnsMatcher, DnsQueryStrategy, DnsUpstream};
use crate::geosite::{DomainType, GeositeDb};
use crate::socks5_client::Socks5Client;

// ---------------------------------------------------------------------------
// Cache types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct CacheKey {
    domain: String,
    qtype: u16,
    qclass: u16,
}

struct CacheEntry {
    /// Raw DNS response bytes (TxID is *not* patched — callers must normalise).
    response: Vec<u8>,
    expires_at: Instant,
}

// ---------------------------------------------------------------------------
// Internal query metadata extracted from the wire-format question section
// ---------------------------------------------------------------------------

struct DnsQueryInfo {
    domain: String,
    qtype: u16,
    qclass: u16,
}

// ---------------------------------------------------------------------------
// Pre-compiled matchers, actions, and match outcomes
// ---------------------------------------------------------------------------

/// Compiled form of a [`crate::config::DnsMatcher`].
enum CompiledMatcher {
    DomainFull(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(regex::Regex),
    Wildcard,
    Geosite(Box<CompiledGeositeSet>),
}

/// Pre-compiled domain set built from one geosite category tag.
/// Uses typed buckets so the common cases (exact & suffix) are O(1).
struct CompiledGeositeSet {
    exact:    HashSet<String>,      // DomainType::Full
    suffixes: HashSet<String>,      // DomainType::Domain
    keywords: Vec<String>,          // DomainType::Plain
    regexes:  Vec<regex::Regex>,    // DomainType::Regex
}

/// Action taken when a routing rule matches.
enum CompiledAction {
    /// Forward to the named DNS group.
    Forward(String),
    /// Return NXDOMAIN immediately (block the domain).
    Reject,
}

struct CompiledRule {
    matcher: CompiledMatcher,
    action:  CompiledAction,
}

/// Outcome returned by [`DnsRouter::match_rule`].
enum MatchOutcome {
    Forward(String),
    Reject,
    NoMatch,
}

// ---------------------------------------------------------------------------
// DnsRouter
// ---------------------------------------------------------------------------

/// Shared, cloneable DNS routing engine.
///
/// Create once with [`DnsRouter::new`] and wrap in `Arc` before cloning into
/// async tasks.
pub struct DnsRouter {
    config: DnsConfig,
    socks5_client: Socks5Client,
    /// Pre-compiled routing rules (same order as `config.routing.rules`).
    rules: Vec<CompiledRule>,
    /// Fast lookup: group name → group config.
    groups: HashMap<String, DnsGroup>,
    cache: Arc<Mutex<LruCache<CacheKey, CacheEntry>>>,
}

impl DnsRouter {
    /// Build a new `DnsRouter` from the DNS section of the configuration.
    ///
    /// Returns an error if any `geosite` rule references a file that cannot
    /// be read or parsed.
    pub fn new(config: DnsConfig, socks5_client: Socks5Client) -> Result<Self> {
        let capacity = NonZeroUsize::new(config.routing.cache_capacity.max(1)).unwrap();
        let cache = LruCache::new(capacity);

        let groups: HashMap<String, DnsGroup> = config
            .groups
            .iter()
            .map(|g| (g.name.clone(), g.clone()))
            .collect();

        // Compile routing rules.  geosite.dat files are loaded once per
        // unique path and shared across rules that reference the same file.
        let mut geosite_cache: HashMap<String, Arc<GeositeDb>> = HashMap::new();
        let mut rules: Vec<CompiledRule> = Vec::new();

        for rule in &config.routing.rules {
            let matcher = match &rule.matcher {
                DnsMatcher::DomainFull { value } => {
                    CompiledMatcher::DomainFull(value.to_lowercase())
                }
                DnsMatcher::DomainSuffix { value } => {
                    CompiledMatcher::DomainSuffix(
                        value.trim_start_matches('.').to_lowercase(),
                    )
                }
                DnsMatcher::DomainKeyword { value } => {
                    CompiledMatcher::DomainKeyword(value.to_lowercase())
                }
                DnsMatcher::DomainRegex { value } => {
                    match regex::Regex::new(value) {
                        Ok(re) => CompiledMatcher::DomainRegex(re),
                        Err(err) => {
                            warn!("DNS routing: invalid regex '{}': {}", value, err);
                            continue;
                        }
                    }
                }
                DnsMatcher::Wildcard => CompiledMatcher::Wildcard,
                DnsMatcher::Geosite { file, tag } => {
                    // Load and cache the geosite.dat (once per unique file path).
                    let db = match geosite_cache.entry(file.clone()) {
                        std::collections::hash_map::Entry::Occupied(e) => {
                            e.get().clone()
                        }
                        std::collections::hash_map::Entry::Vacant(e) => {
                            let db = GeositeDb::load(file)?;
                            e.insert(Arc::new(db)).clone()
                        }
                    };
                    // Look up the requested tag.
                    let domains = match db.get_tag(tag) {
                        Some(d) => d,
                        None => {
                            warn!(
                                "DNS routing: geosite tag '{}' not found in '{}'",
                                tag, file
                            );
                            continue;
                        }
                    };
                    // Build per-type buckets for efficient matching.
                    let mut set = CompiledGeositeSet {
                        exact:    HashSet::new(),
                        suffixes: HashSet::new(),
                        keywords: Vec::new(),
                        regexes:  Vec::new(),
                    };
                    for d in domains {
                        match d.typ {
                            DomainType::Full   => { set.exact.insert(d.value.clone()); }
                            DomainType::Domain => { set.suffixes.insert(d.value.clone()); }
                            DomainType::Plain  => { set.keywords.push(d.value.clone()); }
                            DomainType::Regex  => {
                                match regex::Regex::new(&d.value) {
                                    Ok(re) => set.regexes.push(re),
                                    Err(e) => warn!(
                                        "geosite '{}@{}': invalid regex '{}': {}",
                                        file, tag, d.value, e
                                    ),
                                }
                            }
                        }
                    }
                    CompiledMatcher::Geosite(Box::new(set))
                }
            };

            let action = if rule.reject {
                CompiledAction::Reject
            } else if let Some(group) = &rule.group {
                CompiledAction::Forward(group.clone())
            } else {
                warn!("DNS routing rule has neither a group nor reject=true; skipping");
                continue;
            };

            rules.push(CompiledRule { matcher, action });
        }

        Ok(Self {
            config,
            socks5_client,
            rules,
            groups,
            cache: Arc::new(Mutex::new(cache)),
        })
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Resolve a raw DNS query.
    ///
    /// Steps:
    /// 1. Parse the questioned domain from the wire-format query.
    /// 2. Look up the TTL-aware response cache.
    /// 3. Match the domain against routing rules to select an upstream type.
    /// 4. Query the selected upstream(s) — in parallel if configured.
    /// 5. Cache the successful response.
    ///
    /// The returned bytes are raw DNS wire-format.  The transaction ID in the
    /// response intentionally matches the *upstream*'s reply (not the query),
    /// so callers should call `normalize_dns_response_for_query` if needed.
    pub async fn resolve(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let query_info = Self::parse_query_info(payload);

        // --- Cache lookup ---------------------------------------------------
        if self.config.routing.enable_cache {
            if let Some(ref info) = query_info {
                let key = CacheKey {
                    domain: info.domain.clone(),
                    qtype: info.qtype,
                    qclass: info.qclass,
                };
                if let Some(entry) = self.cache.lock().await.get(&key) {
                    if entry.expires_at > Instant::now() {
                        debug!(
                            "DNS cache hit for {} (qtype={})",
                            info.domain, info.qtype
                        );
                        return Ok(entry.response.clone());
                    }
                }
            }
        }

        // --- Route selection ------------------------------------------------
        let outcome = query_info
            .as_ref()
            .map(|info| self.match_rule(&info.domain))
            .unwrap_or(MatchOutcome::NoMatch);

        let group_name: String = match outcome {
            MatchOutcome::Reject => {
                debug!(
                    "DNS reject: {}",
                    query_info.as_ref().map(|i| i.domain.as_str()).unwrap_or("(unknown)")
                );
                let nxdomain = Self::build_nxdomain_response(payload);
                // Cache the NXDOMAIN with a 1-hour TTL so repeated queries
                // for blocked domains are served instantly from cache.
                if self.config.routing.enable_cache {
                    if let Some(ref info) = query_info {
                        let key = CacheKey {
                            domain: info.domain.clone(),
                            qtype: info.qtype,
                            qclass: info.qclass,
                        };
                        self.cache.lock().await.put(key, CacheEntry {
                            response: nxdomain.clone(),
                            expires_at: Instant::now() + Duration::from_secs(3600),
                        });
                    }
                }
                return Ok(nxdomain);
            }
            MatchOutcome::Forward(name) => name,
            MatchOutcome::NoMatch => self.config.routing.fallback_group.clone(),
        };

        let group = match self.groups.get(&group_name) {
            Some(g) => g,
            None => {
                warn!(
                    "DNS routing: group '{}' not found, falling back to first available",
                    group_name
                );
                match self.config.groups.first() {
                    Some(g) => g,
                    None => return Err(anyhow::anyhow!("No DNS groups configured")),
                }
            }
        };

        if group.servers.is_empty() {
            return Err(anyhow::anyhow!(
                "DNS group '{}' has no servers configured",
                group.name
            ));
        }

        // --- Upstream query -------------------------------------------------
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);

        let response = match group.strategy {
            DnsQueryStrategy::Concurrent => {
                self.query_concurrent(payload, group, timeout_duration).await?
            }
            DnsQueryStrategy::Sequential => {
                self.query_sequential(payload, group, timeout_duration).await?
            }
            DnsQueryStrategy::Random => {
                self.query_random(payload, group, timeout_duration).await?
            }
        };

        // --- Cache insert ---------------------------------------------------
        if self.config.routing.enable_cache {
            if let Some(ref info) = query_info {
                let ttl_secs = Self::extract_min_ttl(&response);
                if ttl_secs > 0 {
                    let key = CacheKey {
                        domain: info.domain.clone(),
                        qtype: info.qtype,
                        qclass: info.qclass,
                    };
                    let entry = CacheEntry {
                        response: response.clone(),
                        expires_at: Instant::now() + Duration::from_secs(u64::from(ttl_secs)),
                    };
                    self.cache.lock().await.put(key, entry);
                }
            }
        }

        Ok(response)
    }

    // -----------------------------------------------------------------------
    // Rule matching
    // -----------------------------------------------------------------------

    fn match_rule(&self, domain: &str) -> MatchOutcome {
        let domain_lc = domain.to_lowercase();
        let domain_lc = domain_lc.trim_end_matches('.');

        for rule in &self.rules {
            if Self::domain_matches(&rule.matcher, domain_lc) {
                return match &rule.action {
                    CompiledAction::Forward(name) => MatchOutcome::Forward(name.clone()),
                    CompiledAction::Reject => MatchOutcome::Reject,
                };
            }
        }

        MatchOutcome::NoMatch
    }

    fn domain_matches(matcher: &CompiledMatcher, domain: &str) -> bool {
        match matcher {
            CompiledMatcher::DomainFull(target) => domain == target.as_str(),
            CompiledMatcher::DomainSuffix(suffix) => {
                domain == suffix.as_str()
                    || domain.ends_with(&format!(".{}", suffix))
            }
            CompiledMatcher::DomainKeyword(keyword) => domain.contains(keyword.as_str()),
            CompiledMatcher::DomainRegex(re) => re.is_match(domain),
            CompiledMatcher::Wildcard => true,
            CompiledMatcher::Geosite(set) => Self::matches_geosite_set(set, domain),
        }
    }

    /// Match a domain against a pre-compiled geosite category set.
    ///
    /// - `Full` entries: O(1) hash lookup.
    /// - `Domain` (suffix) entries: O(labels) hash lookups, one per label.
    /// - `Plain` (keyword) entries: linear scan.
    /// - `Regex` entries: linear scan.
    fn matches_geosite_set(set: &CompiledGeositeSet, domain: &str) -> bool {
        // Exact match (DomainType::Full).
        if set.exact.contains(domain) {
            return true;
        }
        // Suffix match (DomainType::Domain): check the domain itself and every
        // parent component so that "example.com" matches "www.example.com".
        {
            let mut rest = domain;
            loop {
                if set.suffixes.contains(rest) {
                    return true;
                }
                match rest.find('.') {
                    Some(pos) => rest = &rest[pos + 1..],
                    None => break,
                }
            }
        }
        // Keyword match (DomainType::Plain).
        for kw in &set.keywords {
            if domain.contains(kw.as_str()) {
                return true;
            }
        }
        // Regex match (DomainType::Regex).
        for re in &set.regexes {
            if re.is_match(domain) {
                return true;
            }
        }
        false
    }

    /// Build a DNS NXDOMAIN (RCODE = 3) response for a blocked domain.
    fn build_nxdomain_response(query: &[u8]) -> Vec<u8> {
        let mut resp = Vec::with_capacity(query.len().max(12));
        let txid = if query.len() >= 2 {
            [query[0], query[1]]
        } else {
            [0, 0]
        };
        let qdcount = if query.len() >= 6 {
            u16::from_be_bytes([query[4], query[5]])
        } else {
            0
        };
        // QR=1, RD copied, RA=1, RCODE=3 (NXDOMAIN)
        let rd = if query.len() >= 3 { query[2] & 0x01 } else { 0 };
        resp.extend_from_slice(&txid);
        resp.push(0x80 | rd);   // flags hi: QR=1, RD copied
        resp.push(0x80 | 0x03); // flags lo: RA=1, RCODE=3 NXDOMAIN
        resp.extend_from_slice(&qdcount.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Echo the question section so clients can correlate the response.
        if qdcount > 0 && query.len() > 12 {
            resp.extend_from_slice(&query[12..]);
        }
        resp
    }

    // -----------------------------------------------------------------------
    // Strategy: Sequential — try top-to-bottom, advance on failure
    // -----------------------------------------------------------------------

    async fn query_sequential(
        &self,
        payload: &[u8],
        group: &DnsGroup,
        timeout_duration: Duration,
    ) -> Result<Vec<u8>> {
        let mut last_err: Option<anyhow::Error> = None;

        for &addr in &group.servers {
            match Self::query_server(&self.socks5_client, payload, addr, group.upstream, timeout_duration).await {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    warn!("DNS [{}] {} failed (sequential): {}", group.name, addr, err);
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("All servers in DNS group '{}' failed", group.name)))
    }

    // -----------------------------------------------------------------------
    // Strategy: Concurrent — all at once, first success wins
    // -----------------------------------------------------------------------

    async fn query_concurrent(
        &self,
        payload: &[u8],
        group: &DnsGroup,
        timeout_duration: Duration,
    ) -> Result<Vec<u8>> {
        use futures::FutureExt;

        let socks5_client = self.socks5_client.clone();
        let upstream = group.upstream;
        let payload = payload.to_vec();

        let futs: Vec<_> = group
            .servers
            .iter()
            .map(|&addr| {
                let sc = socks5_client.clone();
                let p = payload.clone();
                async move { Self::query_server(&sc, &p, addr, upstream, timeout_duration).await }
                    .boxed()
            })
            .collect();

        futures::future::select_ok(futs)
            .await
            .map(|(resp, _)| resp)
    }

    // -----------------------------------------------------------------------
    // Strategy: Random — shuffle server list, then try sequentially
    // -----------------------------------------------------------------------

    async fn query_random(
        &self,
        payload: &[u8],
        group: &DnsGroup,
        timeout_duration: Duration,
    ) -> Result<Vec<u8>> {
        let indices = Self::shuffled_indices(group.servers.len());
        let mut last_err: Option<anyhow::Error> = None;

        for idx in indices {
            let addr = group.servers[idx];
            match Self::query_server(&self.socks5_client, payload, addr, group.upstream, timeout_duration).await {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    warn!("DNS [{}] {} failed (random): {}", group.name, addr, err);
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("All servers in DNS group '{}' failed", group.name)))
    }

    /// Produce a randomly-shuffled index list of length `len`.
    ///
    /// Uses a Xorshift32 PRNG seeded from the current time sub-second
    /// nanoseconds so that no external randomness crate is required.
    fn shuffled_indices(len: usize) -> Vec<usize> {
        if len <= 1 {
            return (0..len).collect();
        }
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let mut rng: u32 = if seed == 0 { 0xA5A5_A5A5 } else { seed };
        let mut indices: Vec<usize> = (0..len).collect();
        for i in (1..len).rev() {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            let j = (rng as usize) % (i + 1);
            indices.swap(i, j);
        }
        indices
    }

    // -----------------------------------------------------------------------
    // Per-server dispatch
    // -----------------------------------------------------------------------

    async fn query_server(
        socks5_client: &Socks5Client,
        payload: &[u8],
        address: SocketAddr,
        upstream: DnsUpstream,
        timeout_duration: Duration,
    ) -> Result<Vec<u8>> {
        match upstream {
            DnsUpstream::Direct => Self::query_direct(payload, address, timeout_duration).await,
            DnsUpstream::Proxy => {
                Self::query_via_socks(socks5_client.clone(), payload, address, timeout_duration).await
            }
        }
    }

    // -----------------------------------------------------------------------
    // Direct UDP upstream
    // -----------------------------------------------------------------------

    async fn query_direct(
        payload: &[u8],
        upstream: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<Vec<u8>> {
        let bind_addr = match upstream {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr).await?;
        timeout(timeout_duration, socket.send_to(payload, upstream)).await??;

        let mut buf = vec![0u8; 4096];
        let (n, _) = timeout(timeout_duration, socket.recv_from(&mut buf)).await??;
        buf.truncate(n);
        Ok(buf)
    }

    // -----------------------------------------------------------------------
    // SOCKS5-proxied upstream (DNS-over-TCP framing)
    // -----------------------------------------------------------------------

    async fn query_via_socks(
        socks5_client: Socks5Client,
        payload: &[u8],
        upstream: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<Vec<u8>> {
        // Give the SOCKS5 handshake its own generous timeout so that a slow
        // proxy negotiation doesn't leave a half-open TCP connection.
        let handshake_timeout = timeout_duration.max(Duration::from_secs(10));

        let mut stream = timeout(handshake_timeout, socks5_client.connect(upstream))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "SOCKS5 handshake timed out for DNS upstream {}",
                    upstream
                )
            })??;

        // DNS-over-TCP framing: two-byte big-endian length prefix.
        let mut framed = Vec::with_capacity(payload.len() + 2);
        framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        framed.extend_from_slice(payload);
        timeout(timeout_duration, stream.write_all(&framed)).await??;
        timeout(timeout_duration, stream.flush()).await??;

        let mut len_buf = [0u8; 2];
        timeout(timeout_duration, stream.read_exact(&mut len_buf)).await??;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        let mut response = vec![0u8; response_len];
        timeout(timeout_duration, stream.read_exact(&mut response)).await??;
        Ok(response)
    }

    // -----------------------------------------------------------------------
    // DNS wire-format helpers
    // -----------------------------------------------------------------------

    /// Extract the queried domain name and record type from the first question
    /// of a DNS wire-format message.  Returns `None` on malformed input.
    fn parse_query_info(payload: &[u8]) -> Option<DnsQueryInfo> {
        if payload.len() < 12 {
            return None;
        }

        // QR=0 expected for a query, but we are lenient here.
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if qdcount == 0 {
            return None;
        }

        // Walk the QNAME labels starting right after the 12-byte fixed header.
        let mut pos = 12usize;
        let mut labels: Vec<&str> = Vec::new();

        loop {
            if pos >= payload.len() {
                return None;
            }
            let len = payload[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            // Pointer compression is not expected in a *query* question, but
            // guard against malformed packets anyway.
            if (payload[pos] & 0xC0) == 0xC0 {
                pos += 2;
                break;
            }
            if pos + 1 + len > payload.len() {
                return None;
            }
            let label = std::str::from_utf8(&payload[pos + 1..pos + 1 + len]).ok()?;
            labels.push(label);
            pos += 1 + len;
        }

        if pos + 4 > payload.len() {
            return None;
        }

        let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let qclass = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]);

        Some(DnsQueryInfo {
            domain: labels.join("."),
            qtype,
            qclass,
        })
    }

    /// Return the minimum TTL (in seconds) across all answer and authority
    /// records in a DNS wire-format response.  Returns `0` when there are no
    /// records or when the response is malformed.
    fn extract_min_ttl(response: &[u8]) -> u32 {
        Self::try_extract_min_ttl(response).unwrap_or(0)
    }

    fn try_extract_min_ttl(response: &[u8]) -> Option<u32> {
        if response.len() < 12 {
            return None;
        }

        let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
        let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
        let nscount = u16::from_be_bytes([response[8], response[9]]) as usize;

        if ancount + nscount == 0 {
            return Some(0);
        }

        let mut pos = 12usize;

        // Skip the question section.
        for _ in 0..qdcount {
            pos = Self::skip_name(response, pos)?;
            pos = pos.checked_add(4)?; // QTYPE + QCLASS
        }

        let total_rrs = ancount + nscount;
        let mut min_ttl = u32::MAX;

        for _ in 0..total_rrs {
            pos = Self::skip_name(response, pos)?;
            if pos + 10 > response.len() {
                break;
            }
            let ttl = u32::from_be_bytes([
                response[pos + 4],
                response[pos + 5],
                response[pos + 6],
                response[pos + 7],
            ]);
            let rdlen = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;

            if ttl < min_ttl {
                min_ttl = ttl;
            }

            pos = pos.checked_add(10 + rdlen)?;
        }

        Some(if min_ttl == u32::MAX { 0 } else { min_ttl })
    }

    /// Advance `pos` past a DNS name field (handling pointer compression) and
    /// return the position of the first byte *after* the name.
    fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
        loop {
            if pos >= data.len() {
                return None;
            }
            let byte = data[pos];
            if byte == 0 {
                return Some(pos + 1);
            } else if (byte & 0xC0) == 0xC0 {
                // Two-byte pointer; we consume it and stop following labels.
                return Some(pos + 2);
            } else if (byte & 0xC0) == 0x00 {
                let label_len = (byte & 0x3F) as usize;
                pos = pos.checked_add(1 + label_len)?;
            } else {
                // Unknown label type — treat as malformed.
                return None;
            }
        }
    }
}
