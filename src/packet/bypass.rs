use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

use crate::config::Config;
use crate::packet::shared::{ProcessLookupEntry, ProcessLookupKey};
use crate::process_lookup::{self, ProcessLookupOptions, TransportProtocol};

/// Duration after which a process lookup cache entry is considered stale.
const PROCESS_LOOKUP_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// Check whether the flow belongs to an excluded process.
///
/// Design mirrors mihomo's approach:
/// - Cache hit → return immediately (hot path, no blocking).
/// - Cache miss → perform a **synchronous** process lookup on a blocking
///   thread and await the result before returning.  This eliminates the
///   "first-packet-leaks-to-proxy" window that the previous async-lazy
///   design had: a SYN/first-datagram is held until the lookup finishes,
///   so the exclusion decision is always made before any connection is
///   established to the SOCKS5 proxy.
pub async fn should_exclude_process_flow(
    config: &Config,
    process_name_cache: &Arc<Mutex<HashMap<ProcessLookupKey, ProcessLookupEntry>>>,
    process_lookup_options: &ProcessLookupOptions,
    protocol: TransportProtocol,
    src: std::net::SocketAddr,
    dst: std::net::SocketAddr,
) -> bool {
    if config.filtering.exclude_processes.is_empty() {
        return false;
    }

    let key = ProcessLookupKey { protocol, src, dst };

    // ── Fast path: valid cache entry ─────────────────────────────────────
    {
        let cache = process_name_cache.lock().await;
        if let Some(entry) = cache.get(&key) {
            if entry.recorded_at.elapsed() <= PROCESS_LOOKUP_CACHE_TTL {
                if let Some(ref name) = entry.process_name {
                    if config.is_excluded_process_name(name) {
                        log::debug!(
                            "Excluded process matched (cached): process={} protocol={:?} flow={} -> {}",
                            name, protocol, src, dst
                        );
                        return true;
                    }
                }
                return false;
            }
        }
    }

    // ── Slow path: synchronous blocking lookup ───────────────────────────
    // Run the platform-native query on a blocking thread and wait for it.
    // For TCP this is fine because the SYN itself has no RTT budget yet;
    // the extra ~0.5–2 ms for a netlink round-trip is imperceptible.
    let options = process_lookup_options.clone();
    let key_clone = key.clone();
    let lookup = tokio::task::spawn_blocking(move || {
        process_lookup::find_process_name_for_flow(
            &options,
            key_clone.protocol,
            key_clone.src,
            key_clone.dst,
        )
    })
    .await
    .ok()
    .flatten();

    // Write result into cache so subsequent packets for the same flow are fast.
    {
        let mut cache = process_name_cache.lock().await;
        cache.insert(
            key,
            ProcessLookupEntry {
                process_name: lookup.clone(),
                recorded_at: Instant::now(),
            },
        );
    }

    if let Some(ref name) = lookup {
        if config.is_excluded_process_name(name) {
            log::debug!(
                "Excluded process matched: process={} protocol={:?} flow={} -> {}",
                name,
                protocol,
                src,
                dst
            );
            return true;
        }
    }

    false
}

/// Clean up expired entries from the process lookup cache.
pub async fn cleanup_process_lookup_cache(
    process_name_cache: &Arc<Mutex<HashMap<ProcessLookupKey, ProcessLookupEntry>>>,
    max_entries: usize,
) {
    let now = Instant::now();

    {
        let mut cache = process_name_cache.lock().await;
        cache.retain(|_, entry| now.duration_since(entry.recorded_at) <= PROCESS_LOOKUP_CACHE_TTL);

        if cache.len() > max_entries {
            let overflow = cache.len() - max_entries;
            let mut entries = cache
                .iter()
                .map(|(key, entry)| (key.clone(), entry.recorded_at))
                .collect::<Vec<_>>();

            entries.sort_by_key(|(_, recorded_at)| *recorded_at);

            for (key, _) in entries.into_iter().take(overflow) {
                cache.remove(&key);
            }
        }
    }
}
