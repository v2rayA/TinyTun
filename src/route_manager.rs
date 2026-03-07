use ::route_manager::{Route as SysRoute, RouteManager as SysRouteManager};
use anyhow::{anyhow, Result};
use ipnetwork::IpNetwork;
use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "windows")]
use ipconfig::OperStatus;

pub fn resolve_route_interface(
    auto_detect_interface: bool,
    default_interface: Option<&str>,
) -> Result<Option<String>> {
    if auto_detect_interface {
        let route = find_default_route_v4(None)?
            .ok_or_else(|| anyhow!("failed to auto-detect a routable default interface"))?;
        let if_name = route
            .if_name()
            .cloned()
            .ok_or_else(|| anyhow!("default route does not expose interface name"))?;
        return Ok(Some(if_name));
    }

    if let Some(interface) = default_interface {
        let route = find_default_route_v4(Some(interface))?
            .ok_or_else(|| anyhow!("selected interface '{}' is not routable", interface))?;
        let if_name = route.if_name().cloned().unwrap_or_else(|| interface.to_string());
        return Ok(Some(if_name));
    }

    Ok(None)
}

pub fn is_interface_routable(interface: &str) -> Result<bool> {
    Ok(find_default_route_v4(Some(interface))?.is_some())
}

pub fn apply_auto_routes(interface: &str, ipv6_enabled: bool) -> Result<()> {
    let mut manager = new_route_manager()?;

    add_or_replace(
        &mut manager,
        &route_with_interface(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1, interface),
    )?;
    add_or_replace(
        &mut manager,
        &route_with_interface(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1, interface),
    )?;

    if ipv6_enabled {
        add_or_replace(
            &mut manager,
            &route_with_interface(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1, interface),
        )?;
        add_or_replace(
            &mut manager,
            &route_with_interface(
                "8000::".parse::<Ipv6Addr>()?.into(),
                1,
                interface,
            ),
        )?;
    }

    Ok(())
}

pub fn cleanup_auto_routes(interface: &str, ipv6_enabled: bool) -> Result<()> {
    let mut manager = new_route_manager()?;

    let v4_1 = route_with_interface(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1, interface);
    let v4_2 = route_with_interface(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1, interface);
    let _ = manager.delete(&v4_1);
    let _ = manager.delete(&v4_2);

    if ipv6_enabled {
        let v6_1 = route_with_interface(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1, interface);
        let v6_2 = route_with_interface("8000::".parse::<Ipv6Addr>()?.into(), 1, interface);
        let _ = manager.delete(&v6_1);
        let _ = manager.delete(&v6_2);
    }

    Ok(())
}

pub fn apply_skip_ip_routes(skip_ips: &[IpAddr], outbound_interface: Option<&str>) -> Result<()> {
    if skip_ips.is_empty() {
        return Ok(());
    }

    let targets = skip_ips
        .iter()
        .copied()
        .filter(|ip| match ip {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified(),
            IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
        })
        .collect::<Vec<_>>();

    let mut manager = new_route_manager()?;
    apply_skip_prefixes(
        &mut manager,
        targets.iter().map(|ip| (*ip, single_host_prefix(*ip))),
        outbound_interface,
    )
}

pub fn cleanup_skip_ip_routes(skip_ips: &[IpAddr]) -> Result<()> {
    if skip_ips.is_empty() {
        return Ok(());
    }

    let mut manager = new_route_manager()?;

    for ip in skip_ips {
        let valid = match ip {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified(),
            IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
        };
        if !valid {
            continue;
        }
        let route = SysRoute::new(*ip, single_host_prefix(*ip));
        let _ = manager.delete(&route);
    }

    Ok(())
}

pub fn apply_skip_network_routes(
    skip_networks: &[String],
    outbound_interface: Option<&str>,
) -> Result<()> {
    if skip_networks.is_empty() {
        return Ok(());
    }

    let mut prefixes = Vec::new();
    for net in skip_networks {
        if let Ok(parsed) = net.parse::<IpNetwork>() {
            match parsed {
                IpNetwork::V4(v4) => {
                    if !v4.contains(Ipv4Addr::LOCALHOST) {
                        prefixes.push((IpAddr::V4(v4.ip()), v4.prefix()));
                    }
                }
                IpNetwork::V6(v6) => {
                    if !v6.contains(Ipv6Addr::LOCALHOST) {
                        prefixes.push((IpAddr::V6(v6.ip()), v6.prefix()));
                    }
                }
            }
        }
    }

    if prefixes.is_empty() {
        return Ok(());
    }

    let mut manager = new_route_manager()?;
    apply_skip_prefixes(&mut manager, prefixes.into_iter(), outbound_interface)
}

pub fn cleanup_skip_network_routes(skip_networks: &[String]) -> Result<()> {
    if skip_networks.is_empty() {
        return Ok(());
    }

    let mut manager = new_route_manager()?;
    for net in skip_networks {
        if let Ok(parsed) = net.parse::<IpNetwork>() {
            let route = match parsed {
                IpNetwork::V4(v4) => {
                    if v4.contains(Ipv4Addr::LOCALHOST) {
                        continue;
                    }
                    SysRoute::new(IpAddr::V4(v4.ip()), v4.prefix())
                }
                IpNetwork::V6(v6) => {
                    if v6.contains(Ipv6Addr::LOCALHOST) {
                        continue;
                    }
                    SysRoute::new(IpAddr::V6(v6.ip()), v6.prefix())
                }
            };

            let _ = manager.delete(&route);
        }
    }

    Ok(())
}

fn apply_skip_prefixes<I>(
    manager: &mut SysRouteManager,
    prefixes: I,
    outbound_interface: Option<&str>,
) -> Result<()>
where
    I: IntoIterator<Item = (IpAddr, u8)>,
{
    let entries = prefixes.into_iter().collect::<Vec<_>>();

    let has_v4_targets = entries.iter().any(|(ip, _)| ip.is_ipv4());
    let has_v6_targets = entries.iter().any(|(ip, _)| ip.is_ipv6());

    let has_v4_default = find_default_route_v4(None)?.is_some();
    let has_v6_default = find_default_route_v6(None)?.is_some();

    let v4_base = select_default_with_fallback(true, outbound_interface)?;
    let v6_base = select_default_with_fallback(false, outbound_interface)?;

    if has_v4_targets && has_v4_default && v4_base.is_none() {
        return Err(anyhow!("no usable IPv4 default route found for bypass setup"));
    }
    if has_v6_targets && has_v6_default && v6_base.is_none() {
        return Err(anyhow!("no usable IPv6 default route found for bypass setup"));
    }

    for (ip, prefix) in entries {
        let base = if ip.is_ipv4() {
            v4_base.as_ref()
        } else {
            v6_base.as_ref()
        };

        let Some(base) = base else {
            continue;
        };

        let route = build_route_from_base(ip, prefix, base);
        add_or_replace(manager, &route)?;
    }

    Ok(())
}

fn select_default_with_fallback(is_v4: bool, outbound_interface: Option<&str>) -> Result<Option<SysRoute>> {
    if is_v4 {
        if let Some(route) = find_default_route_v4(outbound_interface)? {
            return Ok(Some(route));
        }
        if outbound_interface.is_some() {
            return find_default_route_v4(None);
        }
        return Ok(None);
    }

    if let Some(route) = find_default_route_v6(outbound_interface)? {
        return Ok(Some(route));
    }
    if outbound_interface.is_some() {
        return find_default_route_v6(None);
    }
    Ok(None)
}

fn find_default_route_v4(interface: Option<&str>) -> Result<Option<SysRoute>> {
    let mut manager = new_route_manager()?;
    let mut routes = manager.list()?;
    routes.retain(|r| r.destination().is_ipv4() && r.prefix() == 0);

    #[cfg(target_os = "windows")]
    filter_connected_windows_routes(&mut routes, true)?;

    if let Some(iface) = interface {
        routes.retain(|r| route_matches_interface(r, iface));
    }
    Ok(best_route(routes))
}

fn find_default_route_v6(interface: Option<&str>) -> Result<Option<SysRoute>> {
    let mut manager = new_route_manager()?;
    let mut routes = manager.list()?;
    routes.retain(|r| r.destination().is_ipv6() && r.prefix() == 0);

    #[cfg(target_os = "windows")]
    filter_connected_windows_routes(&mut routes, false)?;

    if let Some(iface) = interface {
        routes.retain(|r| route_matches_interface(r, iface));
    }
    Ok(best_route(routes))
}

fn route_matches_interface(route: &SysRoute, interface: &str) -> bool {
    route
        .if_name()
        .is_some_and(|name| name.eq_ignore_ascii_case(interface))
}

#[cfg(target_os = "windows")]
fn filter_connected_windows_routes(routes: &mut Vec<SysRoute>, is_v4: bool) -> Result<()> {
    let adapters = ipconfig::get_adapters()
        .map_err(|err| anyhow!("failed to query local adapters: {}", err))?;

    let connected = adapters
        .into_iter()
        .filter(|adapter| adapter.oper_status() == OperStatus::IfOperStatusUp)
        .filter(|adapter| {
            adapter
                .gateways()
                .iter()
                .any(|gateway| if is_v4 { gateway.is_ipv4() } else { gateway.is_ipv6() })
        })
        .map(|adapter| adapter.friendly_name().to_ascii_lowercase())
        .collect::<Vec<_>>();

    if connected.is_empty() {
        return Ok(());
    }

    let filtered = routes
        .iter()
        .filter(|route| {
            route.if_name().is_some_and(|name| {
                let lowered = name.to_ascii_lowercase();
                connected.iter().any(|candidate| candidate == &lowered)
            })
        })
        .cloned()
        .collect::<Vec<_>>();

    // Keep current behavior if adapter metadata cannot narrow candidates.
    if !filtered.is_empty() {
        *routes = filtered;
    }

    Ok(())
}

fn best_route(mut routes: Vec<SysRoute>) -> Option<SysRoute> {
    routes.sort_by(compare_routes);
    routes.into_iter().next()
}

fn compare_routes(a: &SysRoute, b: &SysRoute) -> Ordering {
    let am = route_metric(a);
    let bm = route_metric(b);
    match (am, bm) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn route_metric(route: &SysRoute) -> Option<u32> {
    route.metric()
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn route_metric(_route: &SysRoute) -> Option<u32> {
    None
}

fn build_route_from_base(destination: IpAddr, prefix: u8, base: &SysRoute) -> SysRoute {
    let mut route = SysRoute::new(destination, prefix);

    if let Some(gateway) = base.gateway() {
        route = route.with_gateway(gateway);
    }
    if let Some(if_index) = base.if_index() {
        route = route.with_if_index(if_index);
    }
    if let Some(if_name) = base.if_name().cloned() {
        route = route.with_if_name(if_name);
    }

    route
}

fn add_or_replace(manager: &mut SysRouteManager, route: &SysRoute) -> Result<()> {
    if manager.add(route).is_ok() {
        return Ok(());
    }

    let _ = manager.delete(route);
    manager
        .add(route)
        .map_err(|err| anyhow!("failed to add route {}: {}", route, err))
}

fn route_with_interface(destination: IpAddr, prefix: u8, interface: &str) -> SysRoute {
    SysRoute::new(destination, prefix).with_if_name(interface.to_string())
}

fn single_host_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv4() {
        32
    } else {
        128
    }
}

fn new_route_manager() -> Result<SysRouteManager> {
    SysRouteManager::new().map_err(|err| anyhow!("failed to create route manager: {}", err))
}
