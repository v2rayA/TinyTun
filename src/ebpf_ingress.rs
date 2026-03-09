#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;

use anyhow::{anyhow, Result};
#[cfg(target_os = "linux")]
use ipnetwork::IpNetwork;
#[cfg(target_os = "linux")]
use log::info;

use crate::config::Config;

#[cfg(target_os = "linux")]
const CHAIN_NAME: &str = "TINYTUN_EBPF_INGRESS";
#[cfg(target_os = "linux")]
const PRIO: &str = "10020";
#[cfg(target_os = "linux")]
const FILTER_PRIO: &str = "1";
#[cfg(target_os = "linux")]
const FILTER_HANDLE_A: &str = "1";
#[cfg(target_os = "linux")]
const FILTER_HANDLE_B: &str = "2";
#[cfg(target_os = "linux")]
const CHAIN_SUFFIX_A: &str = "A";
#[cfg(target_os = "linux")]
const CHAIN_SUFFIX_B: &str = "B";

#[derive(Clone, Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct EbpfIngressState {
    pub interface: String,
    pub mark: u32,
    pub table_id: u32,
    pub redirect_port: u16,
}

#[cfg(target_os = "linux")]
pub fn apply_ebpf_ingress(config: &Config) -> Result<EbpfIngressState> {
    let ingress = &config.inbound.linux_ebpf;
    if !ingress.enabled {
        return Err(anyhow!("linux eBPF ingress mode requires inbound.linux_ebpf.enabled=true"));
    }

    let interface = if let Some(name) = ingress.interface.clone() {
        name
    } else {
        crate::route_manager::resolve_route_interface(
            config.route.auto_detect_interface,
            config.route.default_interface.as_deref(),
        )?
        .ok_or_else(|| anyhow!("failed to resolve outbound interface for eBPF ingress"))?
    };

    let state = EbpfIngressState {
        interface,
        mark: ingress.mark,
        table_id: ingress.table_id,
        redirect_port: ingress.redirect_port,
    };

    let apply_result = (|| -> Result<()> {
        if !Path::new(&ingress.bpf_object).exists() {
            return Err(anyhow!(
                "eBPF object file not found: {}",
                ingress.bpf_object
            ));
        }

        ensure_tool("tc")?;
        ensure_tool("ip")?;
        ensure_tool("iptables")?;
        ensure_tool("ip6tables")?;
        ensure_tool("bpftool")?;

        // Ensure clsact exists, then flip active tc handle to reduce reload disruption.
        let _ = Command::new("tc")
            .args(["qdisc", "add", "dev", state.interface.as_str(), "clsact"])
            .output();

        flip_tc_ingress_filter(
            state.interface.as_str(),
            ingress.bpf_object.as_str(),
            ingress.bpf_section.as_str(),
        )?;

        sync_skip_maps(
            &ingress.skip_map_path,
            &ingress.skip_map_v6_path,
            &config.filtering.skip_ips,
            &config.filtering.skip_networks,
        )?;

        let mark_hex = format!("0x{:x}", state.mark);
        let table_id_s = state.table_id.to_string();

        let _ = Command::new("ip")
            .args([
                "rule",
                "del",
                "fwmark",
                mark_hex.as_str(),
                "lookup",
                table_id_s.as_str(),
                "priority",
                PRIO,
            ])
            .output();
        let _ = Command::new("ip")
            .args([
                "-6",
                "rule",
                "del",
                "fwmark",
                mark_hex.as_str(),
                "lookup",
                table_id_s.as_str(),
                "priority",
                PRIO,
            ])
            .output();
        let _ = Command::new("ip")
            .args(["route", "flush", "table", table_id_s.as_str()])
            .output();
        let _ = Command::new("ip")
            .args(["-6", "route", "flush", "table", table_id_s.as_str()])
            .output();

        run_cmd(
            "ip",
            &[
                "route",
                "add",
                "local",
                "default",
                "dev",
                "lo",
                "table",
                table_id_s.as_str(),
            ],
            "install local policy route for eBPF ingress hijack",
        )?;

        run_cmd(
            "ip",
            &[
                "-6",
                "route",
                "add",
                "local",
                "default",
                "dev",
                "lo",
                "table",
                table_id_s.as_str(),
            ],
            "install IPv6 local policy route for eBPF ingress hijack",
        )?;

        run_cmd(
            "ip",
            &[
                "rule",
                "add",
                "fwmark",
                mark_hex.as_str(),
                "lookup",
                table_id_s.as_str(),
                "priority",
                PRIO,
            ],
            "install policy rule for eBPF ingress hijack",
        )?;

        run_cmd(
            "ip",
            &[
                "-6",
                "rule",
                "add",
                "fwmark",
                mark_hex.as_str(),
                "lookup",
                table_id_s.as_str(),
                "priority",
                PRIO,
            ],
            "install IPv6 policy rule for eBPF ingress hijack",
        )?;

        apply_nat_flip(
            "iptables",
            true,
            mark_hex.as_str(),
            state.redirect_port,
            ingress.redirect_tcp,
            ingress.redirect_udp,
            &config.filtering.skip_ips,
            &config.filtering.skip_networks,
        )?;

        apply_nat_flip(
            "ip6tables",
            false,
            mark_hex.as_str(),
            state.redirect_port,
            ingress.redirect_tcp,
            ingress.redirect_udp,
            &config.filtering.skip_ips,
            &config.filtering.skip_networks,
        )?;

        Ok(())
    })();

    if let Err(err) = apply_result {
        let _ = cleanup_ebpf_ingress(Some(&state));
        return Err(anyhow!("failed to apply eBPF ingress (rolled back): {}", err));
    }

    info!(
        "Linux eBPF ingress enabled on {} (mark=0x{:x}, table={}, redirect_port={})",
        state.interface, state.mark, state.table_id, state.redirect_port
    );

    Ok(state)
}

#[cfg(target_os = "linux")]
pub fn cleanup_ebpf_ingress(state: Option<&EbpfIngressState>) -> Result<()> {
    let (interface, mark, table_id) = if let Some(s) = state {
        (Some(s.interface.as_str()), s.mark, s.table_id)
    } else {
        (None, 0x233, 233)
    };

    let mark_hex = format!("0x{:x}", mark);
    let table_id_s = table_id.to_string();

    cleanup_nat_chains("iptables");
    cleanup_nat_chains("ip6tables");

    let _ = Command::new("ip")
        .args([
            "rule",
            "del",
            "fwmark",
            mark_hex.as_str(),
            "lookup",
            table_id_s.as_str(),
            "priority",
            PRIO,
        ])
        .output();
    let _ = Command::new("ip")
        .args([
            "-6",
            "rule",
            "del",
            "fwmark",
            mark_hex.as_str(),
            "lookup",
            table_id_s.as_str(),
            "priority",
            PRIO,
        ])
        .output();
    let _ = Command::new("ip")
        .args(["route", "flush", "table", table_id_s.as_str()])
        .output();
    let _ = Command::new("ip")
        .args(["-6", "route", "flush", "table", table_id_s.as_str()])
        .output();

    if let Some(iface) = interface {
        let _ = Command::new("tc")
            .args([
                "filter",
                "del",
                "dev",
                iface,
                "ingress",
                "prio",
                FILTER_PRIO,
                "handle",
                FILTER_HANDLE_A,
                "bpf",
            ])
            .output();
        let _ = Command::new("tc")
            .args([
                "filter",
                "del",
                "dev",
                iface,
                "ingress",
                "prio",
                FILTER_PRIO,
                "handle",
                FILTER_HANDLE_B,
                "bpf",
            ])
            .output();
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", iface, "clsact"])
            .output();
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn apply_ebpf_ingress(_config: &Config) -> Result<EbpfIngressState> {
    Err(anyhow!("linux eBPF ingress is only supported on Linux"))
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn cleanup_ebpf_ingress(_state: Option<&EbpfIngressState>) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_nat_chains(iptable_bin: &str) {
    for chain in [CHAIN_NAME, &format!("{}_{}", CHAIN_NAME, CHAIN_SUFFIX_A), &format!("{}_{}", CHAIN_NAME, CHAIN_SUFFIX_B)] {
        let _ = Command::new(iptable_bin)
            .args(["-t", "nat", "-D", "PREROUTING", "-j", chain])
            .output();
        let _ = Command::new(iptable_bin)
            .args(["-t", "nat", "-F", chain])
            .output();
        let _ = Command::new(iptable_bin)
            .args(["-t", "nat", "-X", chain])
            .output();
    }
}

#[cfg(target_os = "linux")]
fn flip_tc_ingress_filter(interface: &str, bpf_object: &str, bpf_section: &str) -> Result<()> {
    let active = detect_active_tc_handle(interface);
    let next_handle = if active.as_deref() == Some(FILTER_HANDLE_A) {
        FILTER_HANDLE_B
    } else {
        FILTER_HANDLE_A
    };

    run_cmd(
        "tc",
        &[
            "filter",
            "replace",
            "dev",
            interface,
            "ingress",
            "prio",
            FILTER_PRIO,
            "handle",
            next_handle,
            "bpf",
            "da",
            "obj",
            bpf_object,
            "sec",
            bpf_section,
        ],
        "attach flipped tc ingress bpf filter",
    )?;

    if let Some(old) = active {
        if old != next_handle {
            let _ = Command::new("tc")
                .args([
                    "filter",
                    "del",
                    "dev",
                    interface,
                    "ingress",
                    "prio",
                    FILTER_PRIO,
                    "handle",
                    old.as_str(),
                    "bpf",
                ])
                .output();
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn detect_active_tc_handle(interface: &str) -> Option<String> {
    let output = Command::new("tc")
        .args(["filter", "show", "dev", interface, "ingress"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let s = String::from_utf8_lossy(&output.stdout);
    if s.contains("handle 0x2") || s.contains("handle 2") {
        return Some(FILTER_HANDLE_B.to_string());
    }
    if s.contains("handle 0x1") || s.contains("handle 1") {
        return Some(FILTER_HANDLE_A.to_string());
    }
    None
}

#[cfg(target_os = "linux")]
fn apply_nat_flip(
    iptable_bin: &str,
    ipv4: bool,
    mark_hex: &str,
    redirect_port: u16,
    redirect_tcp: bool,
    redirect_udp: bool,
    skip_ips: &[IpAddr],
    skip_networks: &[String],
) -> Result<()> {
    ensure_root_chain(iptable_bin)?;

    let active_suffix = detect_active_chain_suffix(iptable_bin)?;
    let next_suffix = if active_suffix.as_deref() == Some(CHAIN_SUFFIX_A) {
        CHAIN_SUFFIX_B
    } else {
        CHAIN_SUFFIX_A
    };

    let next_chain = format!("{}_{}", CHAIN_NAME, next_suffix);
    recreate_named_chain(iptable_bin, &next_chain)?;
    add_skip_return_rules(iptable_bin, &next_chain, ipv4, skip_ips, skip_networks)?;

    if redirect_tcp {
        run_cmd(
            iptable_bin,
            &[
                "-t",
                "nat",
                "-A",
                &next_chain,
                "-p",
                "tcp",
                "-m",
                "mark",
                "--mark",
                mark_hex,
                "-j",
                "REDIRECT",
                "--to-ports",
                &redirect_port.to_string(),
            ],
            "add TCP redirect rule in flipped chain",
        )?;
    }

    if redirect_udp {
        run_cmd(
            iptable_bin,
            &[
                "-t",
                "nat",
                "-A",
                &next_chain,
                "-p",
                "udp",
                "-m",
                "mark",
                "--mark",
                mark_hex,
                "-j",
                "REDIRECT",
                "--to-ports",
                &redirect_port.to_string(),
            ],
            "add UDP redirect rule in flipped chain",
        )?;
    }

    run_cmd(
        iptable_bin,
        &["-t", "nat", "-F", CHAIN_NAME],
        "switch root chain to new flipped chain",
    )?;
    run_cmd(
        iptable_bin,
        &["-t", "nat", "-A", CHAIN_NAME, "-j", &next_chain],
        "switch root chain jump target",
    )?;

    if let Some(active) = active_suffix {
        let old_chain = format!("{}_{}", CHAIN_NAME, active);
        if old_chain != next_chain {
            let _ = Command::new(iptable_bin)
                .args(["-t", "nat", "-F", &old_chain])
                .output();
            let _ = Command::new(iptable_bin)
                .args(["-t", "nat", "-X", &old_chain])
                .output();
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_root_chain(iptable_bin: &str) -> Result<()> {
    let check = Command::new(iptable_bin)
        .args(["-t", "nat", "-L", CHAIN_NAME])
        .output();
    let exists = check.as_ref().map(|o| o.status.success()).unwrap_or(false);

    if !exists {
        run_cmd(
            iptable_bin,
            &["-t", "nat", "-N", CHAIN_NAME],
            "create root eBPF ingress NAT chain",
        )?;
    }

    let hook_exists = Command::new(iptable_bin)
        .args(["-t", "nat", "-C", "PREROUTING", "-j", CHAIN_NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !hook_exists {
        run_cmd(
            iptable_bin,
            &["-t", "nat", "-A", "PREROUTING", "-j", CHAIN_NAME],
            "hook root eBPF ingress chain into PREROUTING",
        )?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn detect_active_chain_suffix(iptable_bin: &str) -> Result<Option<String>> {
    let output = Command::new(iptable_bin)
        .args(["-t", "nat", "-S", CHAIN_NAME])
        .output()
        .map_err(|err| anyhow!("failed to inspect {} chain {}: {}", iptable_bin, CHAIN_NAME, err))?;

    if !output.status.success() {
        return Ok(None);
    }

    let content = String::from_utf8_lossy(&output.stdout);
    if content.contains(&format!("-j {}_{}", CHAIN_NAME, CHAIN_SUFFIX_A)) {
        return Ok(Some(CHAIN_SUFFIX_A.to_string()));
    }
    if content.contains(&format!("-j {}_{}", CHAIN_NAME, CHAIN_SUFFIX_B)) {
        return Ok(Some(CHAIN_SUFFIX_B.to_string()));
    }

    Ok(None)
}

#[cfg(target_os = "linux")]
fn recreate_named_chain(iptable_bin: &str, chain: &str) -> Result<()> {
    let _ = Command::new(iptable_bin)
        .args(["-t", "nat", "-F", chain])
        .output();
    let _ = Command::new(iptable_bin)
        .args(["-t", "nat", "-X", chain])
        .output();

    run_cmd(
        iptable_bin,
        &["-t", "nat", "-N", chain],
        "create flipped eBPF ingress NAT subchain",
    )
}

#[cfg(target_os = "linux")]
fn add_skip_return_rules(
    iptable_bin: &str,
    chain: &str,
    ipv4: bool,
    skip_ips: &[IpAddr],
    skip_networks: &[String],
) -> Result<()> {
    for ip in skip_ips {
        if ip.is_ipv4() != ipv4 {
            continue;
        }
        run_cmd(
            iptable_bin,
            &[
                "-t",
                "nat",
                "-A",
                chain,
                "-d",
                &ip.to_string(),
                "-j",
                "RETURN",
            ],
            "add eBPF skip-ip return rule",
        )?;
    }

    for network in skip_networks {
        let parsed = match network.parse::<IpNetwork>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if matches!(parsed, IpNetwork::V4(_)) != ipv4 {
            continue;
        }

        run_cmd(
            iptable_bin,
            &[
                "-t",
                "nat",
                "-A",
                chain,
                "-d",
                network,
                "-j",
                "RETURN",
            ],
            "add eBPF skip-network return rule",
        )?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn sync_skip_maps(
    map_v4_path: &str,
    map_v6_path: &str,
    skip_ips: &[IpAddr],
    skip_networks: &[String],
) -> Result<()> {
    let mut v4_keys = HashSet::new();
    let mut v6_keys = HashSet::new();

    for ip in skip_ips {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() || v4.is_unspecified() {
                    continue;
                }
                v4_keys.insert(lpm_key_hex(32, &v4.octets()));
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() {
                    continue;
                }
                v6_keys.insert(lpm_key_hex(128, &v6.octets()));
            }
        }
    }

    for network in skip_networks {
        let parsed = match network.parse::<IpNetwork>() {
            Ok(v) => v,
            Err(_) => continue,
        };

        match parsed {
            IpNetwork::V4(v4) => {
                v4_keys.insert(lpm_key_hex(v4.prefix() as u32, &v4.ip().octets()));
            }
            IpNetwork::V6(v6) => {
                v6_keys.insert(lpm_key_hex(v6.prefix() as u32, &v6.ip().octets()));
            }
        }
    }

    for key in v4_keys {
        run_cmd(
            "bpftool",
            &[
                "map",
                "update",
                "pinned",
                map_v4_path,
                "key",
                &key,
                "value",
                "hex",
                "01",
            ],
            "update eBPF skip map (IPv4)",
        )?;
    }

    for key in v6_keys {
        run_cmd(
            "bpftool",
            &[
                "map",
                "update",
                "pinned",
                map_v6_path,
                "key",
                &key,
                "value",
                "hex",
                "01",
            ],
            "update eBPF skip map (IPv6)",
        )?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn lpm_key_hex(prefix: u32, addr_bytes: &[u8]) -> String {
    let prefix_bytes = prefix.to_le_bytes();
    let mut parts = Vec::with_capacity(4 + addr_bytes.len());
    parts.extend(prefix_bytes.iter().map(|b| format!("{:02x}", b)));
    parts.extend(addr_bytes.iter().map(|b| format!("{:02x}", b)));
    format!("hex {}", parts.join(" "))
}

#[cfg(target_os = "linux")]
fn run_cmd(bin: &str, args: &[&str], context: &str) -> Result<()> {
    let output = Command::new(bin).args(args).output().map_err(|err| {
        anyhow!("failed to execute {} ({}): {}", bin, context, err)
    })?;

    if output.status.success() {
        return Ok(());
    }

    Err(anyhow!(
        "{} failed ({}): {}",
        bin,
        context,
        String::from_utf8_lossy(&output.stderr)
    ))
}

#[cfg(target_os = "linux")]
fn ensure_tool(bin: &str) -> Result<()> {
    let output = Command::new("sh")
        .args(["-c", &format!("command -v {}", bin)])
        .output()
        .map_err(|err| anyhow!("failed to detect tool {}: {}", bin, err))?;

    if output.status.success() {
        return Ok(());
    }

    Err(anyhow!("required command is missing: {}", bin))
}
