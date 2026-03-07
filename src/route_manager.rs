use anyhow::{anyhow, Result};
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::process::Command;

pub fn resolve_route_interface(
    auto_detect_interface: bool,
    default_interface: Option<&str>,
) -> Result<Option<String>> {
    #[cfg(windows)]
    {
        if auto_detect_interface {
            let script = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
                $OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
                $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; \
                if ($r) { $r.InterfaceAlias }";
            let iface = run_checked_capture_stdout("powershell", &["-NoProfile", "-Command", script])?;
            let iface = iface.trim().to_string();
            if iface.is_empty() {
                return Err(anyhow!("failed to auto-detect a routable default interface"));
            }
            return Ok(Some(iface));
        }

        if let Some(interface) = default_interface {
            let escaped = ps_single_quote(interface);
            let script = format!(
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
                 $OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
                 $alias='{iface}'; \
                 $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceAlias $alias -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; \
                 if ($r) {{ $r.InterfaceAlias }} else {{ throw 'default route not found for selected interface' }};",
                iface = escaped
            );
            let iface = run_checked_capture_stdout("powershell", &["-NoProfile", "-Command", &script])?;
            let iface = iface.trim().to_string();
            if iface.is_empty() {
                return Err(anyhow!(
                    "selected interface '{}' is not routable",
                    interface
                ));
            }
            return Ok(Some(iface));
        }

        return Ok(None);
    }

    #[allow(unreachable_code)]
    Ok(None)
}

pub fn is_interface_routable(interface: &str) -> Result<bool> {
    #[cfg(windows)]
    {
        let escaped = ps_single_quote(interface);
        let script = format!(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
             $OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
             $alias='{iface}'; \
             $adapter = Get-NetAdapter -InterfaceAlias $alias -ErrorAction SilentlyContinue; \
             if (-not $adapter -or $adapter.Status -ne 'Up') {{ '0'; exit 0 }}; \
             $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceAlias $alias -ErrorAction SilentlyContinue | Select-Object -First 1; \
             if ($r) {{ '1' }} else {{ '0' }};",
            iface = escaped
        );
        let out = run_checked_capture_stdout("powershell", &["-NoProfile", "-Command", &script])?;
        return Ok(out.trim() == "1");
    }

    #[allow(unreachable_code)]
    Ok(true)
}

pub fn apply_auto_routes(interface: &str, ipv6_enabled: bool) -> Result<()> {
    #[cfg(windows)]
    {
        let mut script = format!(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8; $OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
             New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias '{iface}' -NextHop '0.0.0.0' -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null; \
             New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias '{iface}' -NextHop '0.0.0.0' -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;",
            iface = interface
        );

        if ipv6_enabled {
            script.push_str(&format!(
                " New-NetRoute -DestinationPrefix '::/1' -InterfaceAlias '{iface}' -NextHop '::' -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null; \
                  New-NetRoute -DestinationPrefix '8000::/1' -InterfaceAlias '{iface}' -NextHop '::' -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;",
                iface = interface
            ));
        }

        run_checked("powershell", &["-NoProfile", "-Command", &script])?;
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        run_checked("ip", &["route", "replace", "0.0.0.0/1", "dev", interface])?;
        run_checked("ip", &["route", "replace", "128.0.0.0/1", "dev", interface])?;

        if ipv6_enabled {
            run_checked("ip", &["-6", "route", "replace", "::/1", "dev", interface])?;
            run_checked("ip", &["-6", "route", "replace", "8000::/1", "dev", interface])?;
        }
        return Ok(());
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    {
        run_checked("route", &["-n", "add", "-net", "0.0.0.0/1", "-interface", interface])?;
        run_checked("route", &["-n", "add", "-net", "128.0.0.0/1", "-interface", interface])?;

        if ipv6_enabled {
            run_checked("route", &["-n", "add", "-inet6", "-net", "::/1", "-interface", interface])?;
            run_checked("route", &["-n", "add", "-inet6", "-net", "8000::/1", "-interface", interface])?;
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Ok(())
}

pub fn cleanup_auto_routes(interface: &str, ipv6_enabled: bool) -> Result<()> {
    #[cfg(windows)]
    {
        let mut script = format!(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8; $OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
             Remove-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias '{iface}' -Confirm:$false -ErrorAction SilentlyContinue; \
             Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias '{iface}' -Confirm:$false -ErrorAction SilentlyContinue;",
            iface = interface
        );

        if ipv6_enabled {
            script.push_str(&format!(
                " Remove-NetRoute -DestinationPrefix '::/1' -InterfaceAlias '{iface}' -Confirm:$false -ErrorAction SilentlyContinue; \
                  Remove-NetRoute -DestinationPrefix '8000::/1' -InterfaceAlias '{iface}' -Confirm:$false -ErrorAction SilentlyContinue;",
                iface = interface
            ));
        }

        run_checked("powershell", &["-NoProfile", "-Command", &script])?;
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        run_best_effort("ip", &["route", "del", "0.0.0.0/1", "dev", interface]);
        run_best_effort("ip", &["route", "del", "128.0.0.0/1", "dev", interface]);

        if ipv6_enabled {
            run_best_effort("ip", &["-6", "route", "del", "::/1", "dev", interface]);
            run_best_effort("ip", &["-6", "route", "del", "8000::/1", "dev", interface]);
        }
        return Ok(());
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    {
        run_best_effort("route", &["-n", "delete", "-net", "0.0.0.0/1", "-interface", interface]);
        run_best_effort("route", &["-n", "delete", "-net", "128.0.0.0/1", "-interface", interface]);

        if ipv6_enabled {
            run_best_effort("route", &["-n", "delete", "-inet6", "-net", "::/1", "-interface", interface]);
            run_best_effort("route", &["-n", "delete", "-inet6", "-net", "8000::/1", "-interface", interface]);
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Ok(())
}

pub fn apply_skip_ip_routes(skip_ips: &[IpAddr], outbound_interface: Option<&str>) -> Result<()> {
    if skip_ips.is_empty() {
        return Ok(());
    }

    #[cfg(windows)]
    {
        let ipv4_targets: Vec<String> = skip_ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4.to_string()),
                _ => None,
            })
            .collect();
        let ipv6_targets: Vec<String> = skip_ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(v6) if !v6.is_loopback() && !v6.is_unspecified() => Some(v6.to_string()),
                _ => None,
            })
            .collect();

        let v4_route_query = match outbound_interface {
            Some(interface) => format!(
                "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '{iface}' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1",
                iface = ps_single_quote(interface)
            ),
            None => "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1".to_string(),
        };
        let v6_route_query = match outbound_interface {
            Some(interface) => format!(
                "Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias '{iface}' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1",
                iface = ps_single_quote(interface)
            ),
            None => "Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1".to_string(),
        };

        let mut script = format!(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8; $OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
             $v4={v4_query}; \
             if (({need_v4}) -and -not $v4) {{ throw 'no usable IPv4 default route found for bypass setup' }}; \
             if ($v4) {{",
            v4_query = v4_route_query,
            need_v4 = if ipv4_targets.is_empty() { "$false" } else { "$true" }
        );

        for ip in &ipv4_targets {
            script.push_str(&format!(
                " New-NetRoute -DestinationPrefix '{ip}/32' -InterfaceIndex $v4.InterfaceIndex -NextHop $v4.NextHop -RouteMetric $v4.RouteMetric -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;",
                ip = ip
            ));
        }
        script.push_str(" }");

        script.push_str(&format!(
            " $v6={v6_query}; if (({need_v6}) -and -not $v6) {{ throw 'no usable IPv6 default route found for bypass setup' }}; if ($v6) {{",
            v6_query = v6_route_query,
            need_v6 = if ipv6_targets.is_empty() { "$false" } else { "$true" }
        ));
        for ip in &ipv6_targets {
            script.push_str(&format!(
                " New-NetRoute -DestinationPrefix '{ip}/128' -InterfaceIndex $v6.InterfaceIndex -NextHop $v6.NextHop -RouteMetric $v6.RouteMetric -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;",
                ip = ip
            ));
        }
        script.push_str(" }");

        run_checked("powershell", &["-NoProfile", "-Command", &script])?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    Ok(())
}

pub fn cleanup_skip_ip_routes(skip_ips: &[IpAddr]) -> Result<()> {
    if skip_ips.is_empty() {
        return Ok(());
    }

    #[cfg(windows)]
    {
        let mut script = String::from(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8; $OutputEncoding=[System.Text.UTF8Encoding]::UTF8;",
        );

        for ip in skip_ips {
            match ip {
                IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => {
                    script.push_str(&format!(
                        " Remove-NetRoute -DestinationPrefix '{ip}/32' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue;",
                        ip = v4
                    ));
                }
                IpAddr::V6(v6) if !v6.is_loopback() && !v6.is_unspecified() => {
                    script.push_str(&format!(
                        " Remove-NetRoute -DestinationPrefix '{ip}/128' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue;",
                        ip = v6
                    ));
                }
                _ => {}
            }
        }

        run_checked("powershell", &["-NoProfile", "-Command", &script])?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    Ok(())
}

pub fn apply_skip_network_routes(
    skip_networks: &[String],
    outbound_interface: Option<&str>,
) -> Result<()> {
    if skip_networks.is_empty() {
        return Ok(());
    }

    #[cfg(windows)]
    {
        let mut v4_prefixes = Vec::new();
        let mut v6_prefixes = Vec::new();

        for net in skip_networks {
            if let Ok(parsed) = net.parse::<IpNetwork>() {
                match parsed {
                    IpNetwork::V4(v4) => {
                        // Loopback keeps its local route and should not be forced to a gateway.
                        if !v4.contains(std::net::Ipv4Addr::LOCALHOST) {
                            v4_prefixes.push(v4.to_string());
                        }
                    }
                    IpNetwork::V6(v6) => {
                        // Localhost keeps its local route and should not be forced to a gateway.
                        if !v6.contains(std::net::Ipv6Addr::LOCALHOST) {
                            v6_prefixes.push(v6.to_string());
                        }
                    }
                }
            }
        }

        if v4_prefixes.is_empty() && v6_prefixes.is_empty() {
            return Ok(());
        }

        let v4_route_query = match outbound_interface {
            Some(interface) => format!(
                "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '{iface}' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1",
                iface = ps_single_quote(interface)
            ),
            None => "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1".to_string(),
        };
        let v6_route_query = match outbound_interface {
            Some(interface) => format!(
                "Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias '{iface}' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1",
                iface = ps_single_quote(interface)
            ),
            None => "Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1".to_string(),
        };

        let mut script = format!(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8; $OutputEncoding=[System.Text.UTF8Encoding]::UTF8; \
             $v4={v4_query}; \
             if (({need_v4}) -and -not $v4) {{ throw 'no usable IPv4 default route found for bypass setup' }}; \
             if ($v4) {{",
            v4_query = v4_route_query,
            need_v4 = if v4_prefixes.is_empty() { "$false" } else { "$true" }
        );

        for prefix in &v4_prefixes {
            script.push_str(&format!(
                " New-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex $v4.InterfaceIndex -NextHop $v4.NextHop -RouteMetric $v4.RouteMetric -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;",
                prefix = prefix
            ));
        }
        script.push_str(" }");

        script.push_str(&format!(
            " $v6={v6_query}; if (({need_v6}) -and -not $v6) {{ throw 'no usable IPv6 default route found for bypass setup' }}; if ($v6) {{",
            v6_query = v6_route_query,
            need_v6 = if v6_prefixes.is_empty() { "$false" } else { "$true" }
        ));
        for prefix in &v6_prefixes {
            script.push_str(&format!(
                " New-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex $v6.InterfaceIndex -NextHop $v6.NextHop -RouteMetric $v6.RouteMetric -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null;",
                prefix = prefix
            ));
        }
        script.push_str(" }");

        run_checked("powershell", &["-NoProfile", "-Command", &script])?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    Ok(())
}

pub fn cleanup_skip_network_routes(skip_networks: &[String]) -> Result<()> {
    if skip_networks.is_empty() {
        return Ok(());
    }

    #[cfg(windows)]
    {
        let mut script = String::from(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8; $OutputEncoding=[System.Text.UTF8Encoding]::UTF8;",
        );

        for net in skip_networks {
            if let Ok(parsed) = net.parse::<IpNetwork>() {
                match parsed {
                    IpNetwork::V4(v4) => {
                        if !v4.contains(std::net::Ipv4Addr::LOCALHOST) {
                            script.push_str(&format!(
                                " Remove-NetRoute -DestinationPrefix '{prefix}' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue;",
                                prefix = v4
                            ));
                        }
                    }
                    IpNetwork::V6(v6) => {
                        if !v6.contains(std::net::Ipv6Addr::LOCALHOST) {
                            script.push_str(&format!(
                                " Remove-NetRoute -DestinationPrefix '{prefix}' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue;",
                                prefix = v6
                            ));
                        }
                    }
                }
            }
        }

        run_checked("powershell", &["-NoProfile", "-Command", &script])?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    Ok(())
}

fn run_checked(cmd: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|err| anyhow!("failed to execute {}: {}", cmd, err))?;

    if output.status.success() {
        return Ok(());
    }

    Err(anyhow!(
        "command failed: {} {} => {}",
        cmd,
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn run_checked_capture_stdout(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|err| anyhow!("failed to execute {}: {}", cmd, err))?;

    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
    }

    Err(anyhow!(
        "command failed: {} {} => {}",
        cmd,
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn ps_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(not(windows))]
fn run_best_effort(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}
