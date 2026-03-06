use anyhow::{anyhow, Result};
use std::process::Command;

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

#[cfg(not(windows))]
fn run_best_effort(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}
