use anyhow::Result;

use crate::config::Config;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct DnsHijackState {
    pub table_id: u32,
    pub mark: u32,
    pub capture_tcp: bool,
}

#[cfg(target_os = "linux")]
pub fn apply_dns_hijack(config: &Config, tun_name: &str) -> Result<Option<DnsHijackState>> {
    use std::process::Command;

    if !config.dns.hijack.enabled {
        return Ok(None);
    }

    let table_id = config.dns.hijack.table_id;
    let mark = config.dns.hijack.mark;
    let capture_tcp = config.dns.hijack.capture_tcp;

    // Recreate chain each startup to keep state deterministic.
    let _ = Command::new("iptables")
        .args(["-t", "mangle", "-D", "OUTPUT", "-j", "TINYTUN_DNS_HIJACK"])
        .output();
    let _ = Command::new("iptables")
        .args(["-t", "mangle", "-F", "TINYTUN_DNS_HIJACK"])
        .output();
    let _ = Command::new("iptables")
        .args(["-t", "mangle", "-X", "TINYTUN_DNS_HIJACK"])
        .output();

    let chain_new = Command::new("iptables")
        .args(["-t", "mangle", "-N", "TINYTUN_DNS_HIJACK"])
        .output()?;
    if !chain_new.status.success() {
        return Err(anyhow::anyhow!(
            "failed to create iptables chain TINYTUN_DNS_HIJACK: {}",
            String::from_utf8_lossy(&chain_new.stderr)
        ));
    }

    // Avoid hijacking tinytun process traffic to prevent feedback loops.
    // SAFETY: `libc::geteuid()` is a simple FFI call with no arguments and no
    // side effects on Rust state. It always succeeds and returns the effective UID.
    let uid = unsafe { libc::geteuid() }.to_string();
    let owner_rule = Command::new("iptables")
        .args([
            "-t",
            "mangle",
            "-A",
            "TINYTUN_DNS_HIJACK",
            "-m",
            "owner",
            "--uid-owner",
            &uid,
            "-j",
            "RETURN",
        ])
        .output()?;
    if !owner_rule.status.success() {
        return Err(anyhow::anyhow!(
            "failed to append owner exclusion rule: {}",
            String::from_utf8_lossy(&owner_rule.stderr)
        ));
    }

    let mark_hex = format!("0x{mark:x}");
    let udp_mark_rule = Command::new("iptables")
        .args([
            "-t",
            "mangle",
            "-A",
            "TINYTUN_DNS_HIJACK",
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "MARK",
            "--set-mark",
            &mark_hex,
        ])
        .output()?;
    if !udp_mark_rule.status.success() {
        return Err(anyhow::anyhow!(
            "failed to append UDP/53 mark rule: {}",
            String::from_utf8_lossy(&udp_mark_rule.stderr)
        ));
    }

    if capture_tcp {
        let tcp_mark_rule = Command::new("iptables")
            .args([
                "-t",
                "mangle",
                "-A",
                "TINYTUN_DNS_HIJACK",
                "-p",
                "tcp",
                "--dport",
                "53",
                "-j",
                "MARK",
                "--set-mark",
                &mark_hex,
            ])
            .output()?;
        if !tcp_mark_rule.status.success() {
            return Err(anyhow::anyhow!(
                "failed to append TCP/53 mark rule: {}",
                String::from_utf8_lossy(&tcp_mark_rule.stderr)
            ));
        }
    }

    let output_hook = Command::new("iptables")
        .args(["-t", "mangle", "-A", "OUTPUT", "-j", "TINYTUN_DNS_HIJACK"])
        .output()?;
    if !output_hook.status.success() {
        return Err(anyhow::anyhow!(
            "failed to hook OUTPUT chain for dns hijack: {}",
            String::from_utf8_lossy(&output_hook.stderr)
        ));
    }

    let table_id_s = table_id.to_string();
    let _ = Command::new("ip")
        .args([
            "rule",
            "del",
            "fwmark",
            &mark_hex,
            "lookup",
            &table_id_s,
            "priority",
            "10000",
        ])
        .output();
    let _ = Command::new("ip")
        .args(["route", "flush", "table", &table_id_s])
        .output();

    let route_add = Command::new("ip")
        .args(["route", "add", "default", "dev", tun_name, "table", &table_id_s])
        .output()?;
    if !route_add.status.success() {
        return Err(anyhow::anyhow!(
            "failed to add dns hijack route table {} via {}: {}",
            table_id,
            tun_name,
            String::from_utf8_lossy(&route_add.stderr)
        ));
    }

    let rule_add = Command::new("ip")
        .args([
            "rule",
            "add",
            "fwmark",
            &mark_hex,
            "lookup",
            &table_id_s,
            "priority",
            "10000",
        ])
        .output()?;
    if !rule_add.status.success() {
        return Err(anyhow::anyhow!(
            "failed to add dns hijack policy rule: {}",
            String::from_utf8_lossy(&rule_add.stderr)
        ));
    }

    Ok(Some(DnsHijackState {
        table_id,
        mark,
        capture_tcp,
    }))
}

#[cfg(target_os = "linux")]
pub fn cleanup_dns_hijack(state: Option<&DnsHijackState>) -> Result<()> {
    use log::warn;
    use std::process::Command;

    let (table_id, mark, _capture_tcp) = if let Some(s) = state {
        (s.table_id, s.mark, s.capture_tcp)
    } else {
        // Best-effort fallback for default values.
        (100, 0x1, true)
    };

    let mark_hex = format!("0x{mark:x}");
    let table_id_s = table_id.to_string();

    // ── Continue-on-error cleanup ───────────────────────────────────────────
    // Each step is best-effort: if a rule or chain has already been removed
    // (e.g. by a previous crash or manual intervention), we log the error but
    // continue so that the remaining rules are still cleaned up.  This prevents
    // partial cleanup failures from leaving stale iptables rules on the system.
    let mut errors: Vec<String> = Vec::new();

    let _ = Command::new("ip")
        .args([
            "rule",
            "del",
            "fwmark",
            &mark_hex,
            "lookup",
            &table_id_s,
            "priority",
            "10000",
        ])
        .output();
    let _ = Command::new("ip")
        .args(["route", "flush", "table", &table_id_s])
        .output();

    let results: [(&str, &[&str]); 3] = [
        ("iptables -D OUTPUT", &["-t", "mangle", "-D", "OUTPUT", "-j", "TINYTUN_DNS_HIJACK"]),
        ("iptables -F chain",  &["-t", "mangle", "-F", "TINYTUN_DNS_HIJACK"]),
        ("iptables -X chain",  &["-t", "mangle", "-X", "TINYTUN_DNS_HIJACK"]),
    ];

    for (label, args) in &results {
        let output = Command::new("iptables").args(*args).output();
        match output {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                errors.push(format!("{} failed: {}", label, stderr.trim()));
            }
            Err(e) => {
                errors.push(format!("{} invocation failed: {}", label, e));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        warn!(
            "DNS hijack cleanup completed with {} non-fatal error(s): {}",
            errors.len(),
            errors.join("; ")
        );
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
#[cfg(target_os = "windows")]
pub fn apply_dns_hijack(config: &Config, tun_name: &str) -> Result<Option<DnsHijackState>> {
    use ipconfig::OperStatus;
    use windows::Win32::NetworkManagement::WindowsFirewall::{
        INetFwPolicy2, NetFwPolicy2, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK,
        NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };

    if !config.dns.hijack.enabled {
        return Ok(None);
    }

    // SAFETY: `CoInitializeEx` initializes COM for this thread; it must be paired with
    // `CoUninitialize` before the thread exits. `CoCreateInstance` creates a COM object;
    // the returned interface pointer is valid and checked via `ok()?`. `policy.Rules()`
    // returns a valid `INetFwRules` interface. All COM calls use the `windows-rs` safe
    // wrappers which handle reference counting.
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()?; }
    let policy: INetFwPolicy2 = unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)? };
    let rules = unsafe { policy.Rules()? };

    cleanup_windows_dns_hijack_rules(&rules)?;

    let adapters = ipconfig::get_adapters()
        .map_err(|err| anyhow::anyhow!("failed to enumerate adapters: {}", err))?;

    let mut tun_local_addresses = Vec::new();
    let mut block_scopes = Vec::new();

    for adapter in adapters {
        if adapter.oper_status() != OperStatus::IfOperStatusUp {
            continue;
        }

        let alias = adapter.friendly_name().trim().to_string();
        if alias.is_empty() {
            continue;
        }

        let local_ips: Vec<String> = adapter
            .ip_addresses()
            .iter()
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
            .map(std::string::ToString::to_string)
            .collect();

        if local_ips.is_empty() {
            continue;
        }

        if alias.eq_ignore_ascii_case(tun_name) {
            tun_local_addresses.extend(local_ips);
        } else {
            block_scopes.push((alias, local_ips));
        }
    }

    if !tun_local_addresses.is_empty() {
        add_windows_dns_rule(
            &rules,
            "TinyTun DNS Hijack Allow UDP",
            NET_FW_ACTION_ALLOW,
            NET_FW_IP_PROTOCOL_UDP.0,
            Some(&tun_local_addresses.join(",")),
        )?;

        if config.dns.hijack.capture_tcp {
            add_windows_dns_rule(
                &rules,
                "TinyTun DNS Hijack Allow TCP",
                NET_FW_ACTION_ALLOW,
                NET_FW_IP_PROTOCOL_TCP.0,
                Some(&tun_local_addresses.join(",")),
            )?;
        }
    }

    for (alias, ips) in block_scopes {
        let local_scope = ips.join(",");

        add_windows_dns_rule(
            &rules,
            &format!("TinyTun DNS Hijack Block UDP [{}]", alias),
            NET_FW_ACTION_BLOCK,
            NET_FW_IP_PROTOCOL_UDP.0,
            Some(&local_scope),
        )?;

        if config.dns.hijack.capture_tcp {
            add_windows_dns_rule(
                &rules,
                &format!("TinyTun DNS Hijack Block TCP [{}]", alias),
                NET_FW_ACTION_BLOCK,
                NET_FW_IP_PROTOCOL_TCP.0,
                Some(&local_scope),
            )?;
        }
    }

    // SAFETY: `CoUninitialize` matches the `CoInitializeEx` call above. Must be called
    // on the same thread. No COM calls are made after this point.
    unsafe {
        CoUninitialize();
    }

    Ok(Some(DnsHijackState {
        table_id: config.dns.hijack.table_id,
        mark: config.dns.hijack.mark,
        capture_tcp: config.dns.hijack.capture_tcp,
    }))
}

#[cfg(target_os = "windows")]
pub fn cleanup_dns_hijack(_state: Option<&DnsHijackState>) -> Result<()> {
    use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwPolicy2, INetFwRules, NetFwPolicy2};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };

    // SAFETY: Same COM initialization pattern as `apply_dns_hijack` on Windows.
    // `CoInitializeEx`/`CoUninitialize` are properly paired. COM interface pointers
    // are managed by `windows-rs` safe wrappers.
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()?; }
    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)?
    };
    let rules: INetFwRules = unsafe { policy.Rules()? };
    let result = cleanup_windows_dns_hijack_rules(&rules);
    // SAFETY: Paired `CoUninitialize` for the `CoInitializeEx` above.
    unsafe {
        CoUninitialize();
    }
    result
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn apply_dns_hijack(_config: &Config, _tun_name: &str) -> Result<Option<DnsHijackState>> {
    Ok(None)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn cleanup_dns_hijack(_state: Option<&DnsHijackState>) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn add_windows_dns_rule(
    rules: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules,
    name: &str,
    action: windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_ACTION,
    protocol: i32,
    local_addresses: Option<&str>,
) -> Result<()> {
    use windows::core::BSTR;
    use windows::Win32::Foundation::VARIANT_TRUE;
    use windows::Win32::NetworkManagement::WindowsFirewall::{
        INetFwRule, NetFwRule, NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_OUT,
    };
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

    // SAFETY: `CoCreateInstance` creates a COM `NetFwRule` object. The returned
    // `INetFwRule` interface pointer is valid. All subsequent `Set*` calls are
    // COM method invocations on a valid interface; `windows-rs` handles the
    // underlying vtable dispatch safely.
    let rule: INetFwRule = unsafe {
        CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?
    };

    unsafe {
        rule.SetName(&BSTR::from(name))?;
        rule.SetGrouping(&BSTR::from("TinyTun DNS Hijack"))?;
        rule.SetDescription(&BSTR::from("TinyTun managed DNS hijack rule"))?;
        rule.SetEnabled(VARIANT_TRUE)?;
        rule.SetDirection(NET_FW_RULE_DIR_OUT)?;
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0 as i32)?;
        rule.SetProtocol(protocol)?;
        rule.SetRemotePorts(&BSTR::from("53"))?;
    }
    if let Some(scope) = local_addresses {
        // SAFETY: `rule` is a valid `INetFwRule` interface. `SetLocalAddresses` is
        // a COM method call with a valid `BSTR` parameter.
        unsafe {
            rule.SetLocalAddresses(&BSTR::from(scope))?;
        }
    }
    // SAFETY: `rule` is a valid `INetFwRule` interface. `SetAction` is a COM method call.
    unsafe {
        rule.SetAction(action)?;
    }

    // SAFETY: Both `rules` and `rule` are valid COM interfaces. `Add` registers the rule.
    unsafe {
        rules.Add(&rule)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn cleanup_windows_dns_hijack_rules(
    rules: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules,
) -> Result<()> {
    // Known deterministic rule names created by this module.
    let static_names = [
        "TinyTun DNS Hijack Allow UDP",
        "TinyTun DNS Hijack Allow TCP",
    ];

    for name in static_names {
        // SAFETY: `rules` is a valid `INetFwRules` interface. `Remove` is a COM method call.
        // The `BSTR` is properly constructed from a Rust string slice.
        let _ = unsafe { rules.Remove(&windows::core::BSTR::from(name)) };
    }

    // Remove potential dynamic block rules from previous runs.
    // We cannot enumerate robustly here without IEnumVARIANT plumbing, so remove
    // common prefixes with a bounded set of aliases from current adapters.
    if let Ok(adapters) = ipconfig::get_adapters() {
        for adapter in adapters {
            let alias = adapter.friendly_name().trim();
            if alias.is_empty() {
                continue;
            }
            // SAFETY: Same pattern as static names above. `rules.Remove` is a COM method call
            // with a valid `BSTR` parameter. The `_ =` discards the `Result` as this is best-effort cleanup.
            let _ = unsafe { rules.Remove(&windows::core::BSTR::from(format!(
                "TinyTun DNS Hijack Block UDP [{}]",
                alias
            ))) };
            // SAFETY: Same as above for TCP variant.
            let _ = unsafe { rules.Remove(&windows::core::BSTR::from(format!(
                "TinyTun DNS Hijack Block TCP [{}]",
                alias
            ))) };
        }
    }

    Ok(())
}
