use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use dashmap::DashMap;

use crate::config::Config;
use crate::route_manager;

/// Duration after which a dynamic bypass route expires.
const DYNAMIC_BYPASS_ROUTE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Ensure a dynamic bypass route is installed for the given IP.
///
/// This is called when an excluded-process flow is detected but no outbound
/// interface is configured for socket-level binding.  A /32 host route is
/// installed so the application's next reconnect goes via the physical NIC.
pub async fn ensure_dynamic_bypass_for_ip(
    dynamic_bypass_ips: &Arc<DashMap<IpAddr, Instant>>,
    config: &Config,
    outbound_interface: &Option<String>,
    ip: IpAddr,
) -> Result<()> {
    if !config.tun.auto_route || config.should_skip_ip(ip) {
        return Ok(());
    }

    {
        if let Some(mut last_seen) = dynamic_bypass_ips.get_mut(&ip) {
            // IP already tracked (route installed or pending): refresh TTL and return.
            *last_seen = Instant::now();
            return Ok(());
        }
        // Insert a placeholder *before* releasing the lock to prevent concurrent tasks
        // from racing into open_udp_session / apply_skip_ip_routes for the same IP
        // and causing duplicate route entries or Windows ephemeral-port exhaustion.
        dynamic_bypass_ips.insert(ip, Instant::now());
    }

    let outbound_interface = outbound_interface.clone();
    let install_result = tokio::task::spawn_blocking(move || {
        route_manager::apply_skip_ip_routes(&[ip], outbound_interface.as_deref())
    })
    .await
    .map_err(|err| anyhow::anyhow!("dynamic bypass task join error: {}", err))?;

    if let Err(err) = install_result {
        // Route installation failed: remove the placeholder so the next packet can retry.
        dynamic_bypass_ips.remove(&ip);
        return Err(err);
    }

    log::info!(
        "Installed dynamic bypass route for excluded process destination {}",
        ip
    );
    Ok(())
}

/// Clean up expired dynamic bypass routes.
pub async fn cleanup_expired_dynamic_bypass_routes(
    dynamic_bypass_ips: &Arc<DashMap<IpAddr, Instant>>,
    config: &Config,
) {
    if !config.tun.auto_route {
        return;
    }

    let now = Instant::now();
    let expired_ips: Vec<IpAddr> = dynamic_bypass_ips
        .iter()
        .filter_map(|entry| {
            let (ip, inserted_at) = entry.pair();
            if now.duration_since(*inserted_at) >= DYNAMIC_BYPASS_ROUTE_TTL {
                Some(*ip)
            } else {
                None
            }
        })
        .collect();

    for ip in &expired_ips {
        dynamic_bypass_ips.remove(ip);
    }

    if expired_ips.is_empty() {
        return;
    }

    let expired_count = expired_ips.len();
    let cleanup_targets = expired_ips;
    let cleanup_result = tokio::task::spawn_blocking(move || {
        route_manager::cleanup_skip_ip_routes(&cleanup_targets)
    })
    .await;

    match cleanup_result {
        Ok(Ok(())) => {
            log::debug!(
                "Cleaned up {} expired dynamic bypass routes",
                expired_count
            );
        }
        Ok(Err(err)) => {
            log::warn!("Failed to cleanup expired dynamic bypass routes: {}", err);
        }
        Err(err) => {
            log::warn!("Dynamic bypass cleanup task join error: {}", err);
        }
    }
}
