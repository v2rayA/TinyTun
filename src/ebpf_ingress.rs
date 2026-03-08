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

    // Ensure clsact exists, then attach ingress classifier from user-supplied object.
    let _ = Command::new("tc")
        .args(["qdisc", "add", "dev", interface.as_str(), "clsact"])
        .output();

    run_cmd(
        "tc",
        &[
            "filter",
            "replace",
            "dev",
            interface.as_str(),
            "ingress",
            "prio",
            "1",
            "handle",
            "1",
            "bpf",
            "da",
            "obj",
            ingress.bpf_object.as_str(),
            "sec",
            ingress.bpf_section.as_str(),
        ],
        "attach eBPF ingress classifier",
    )?;

    sync_skip_maps(
        &ingress.skip_map_path,
        &ingress.skip_map_v6_path,
        &config.filtering.skip_ips,
    )?;

    let mark_hex = format!("0x{:x}", ingress.mark);
    let table_id_s = ingress.table_id.to_string();

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

    recreate_chain("iptables")?;
    recreate_chain("ip6tables")?;
    add_skip_return_rules(
        "iptables",
        true,
        &config.filtering.skip_ips,
        &config.filtering.skip_networks,
    )?;
    add_skip_return_rules(
        "ip6tables",
        false,
        &config.filtering.skip_ips,
        &config.filtering.skip_networks,
    )?;

    if ingress.redirect_tcp {
        run_cmd(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                CHAIN_NAME,
                "-p",
                "tcp",
                "-m",
                "mark",
                "--mark",
                mark_hex.as_str(),
                "-j",
                "REDIRECT",
                "--to-ports",
                &ingress.redirect_port.to_string(),
            ],
            "add TCP redirect rule for eBPF ingress",
        )?;

        run_cmd(
            "ip6tables",
            &[
                "-t",
                "nat",
                "-A",
                CHAIN_NAME,
                "-p",
                "tcp",
                "-m",
                "mark",
                "--mark",
                mark_hex.as_str(),
                "-j",
                "REDIRECT",
                "--to-ports",
                &ingress.redirect_port.to_string(),
            ],
            "add IPv6 TCP redirect rule for eBPF ingress",
        )?;
    }

    if ingress.redirect_udp {
        run_cmd(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                CHAIN_NAME,
                "-p",
                "udp",
                "-m",
                "mark",
                "--mark",
                mark_hex.as_str(),
                "-j",
                "REDIRECT",
                "--to-ports",
                &ingress.redirect_port.to_string(),
            ],
            "add UDP redirect rule for eBPF ingress",
        )?;

        run_cmd(
            "ip6tables",
            &[
                "-t",
                "nat",
                "-A",
                CHAIN_NAME,
                "-p",
                "udp",
                "-m",
                "mark",
                "--mark",
                mark_hex.as_str(),
                "-j",
                "REDIRECT",
                "--to-ports",
                &ingress.redirect_port.to_string(),
            ],
            "add IPv6 UDP redirect rule for eBPF ingress",
        )?;
    }

    run_cmd(
        "iptables",
        &["-t", "nat", "-A", "PREROUTING", "-j", CHAIN_NAME],
        "hook eBPF ingress chain into PREROUTING",
    )?;

    run_cmd(
        "ip6tables",
        &["-t", "nat", "-A", "PREROUTING", "-j", CHAIN_NAME],
        "hook IPv6 eBPF ingress chain into PREROUTING",
    )?;

    info!(
        "Linux eBPF ingress enabled on {} (mark=0x{:x}, table={}, redirect_port={})",
        interface, ingress.mark, ingress.table_id, ingress.redirect_port
    );

    Ok(EbpfIngressState {
        interface,
        mark: ingress.mark,
        table_id: ingress.table_id,
        redirect_port: ingress.redirect_port,
    })
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

    let _ = Command::new("iptables")
        .args(["-t", "nat", "-D", "PREROUTING", "-j", CHAIN_NAME])
        .output();
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-F", CHAIN_NAME])
        .output();
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-X", CHAIN_NAME])
        .output();

    let _ = Command::new("ip6tables")
        .args(["-t", "nat", "-D", "PREROUTING", "-j", CHAIN_NAME])
        .output();
    let _ = Command::new("ip6tables")
        .args(["-t", "nat", "-F", CHAIN_NAME])
        .output();
    let _ = Command::new("ip6tables")
        .args(["-t", "nat", "-X", CHAIN_NAME])
        .output();

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
            .args(["filter", "del", "dev", iface, "ingress", "prio", "1", "handle", "1", "bpf"])
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
fn recreate_chain(iptable_bin: &str) -> Result<()> {
    let _ = Command::new(iptable_bin)
        .args(["-t", "nat", "-D", "PREROUTING", "-j", CHAIN_NAME])
        .output();
    let _ = Command::new(iptable_bin)
        .args(["-t", "nat", "-F", CHAIN_NAME])
        .output();
    let _ = Command::new(iptable_bin)
        .args(["-t", "nat", "-X", CHAIN_NAME])
        .output();

    run_cmd(
        iptable_bin,
        &["-t", "nat", "-N", CHAIN_NAME],
        "create eBPF ingress NAT chain",
    )
}

#[cfg(target_os = "linux")]
fn add_skip_return_rules(
    iptable_bin: &str,
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
                CHAIN_NAME,
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
                CHAIN_NAME,
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
fn sync_skip_maps(map_v4_path: &str, map_v6_path: &str, skip_ips: &[IpAddr]) -> Result<()> {
    for ip in skip_ips {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() || v4.is_unspecified() {
                    continue;
                }

                let octets = v4.octets();
                let key = format!(
                    "hex 20 00 00 00 {:02x} {:02x} {:02x} {:02x}",
                    octets[0], octets[1], octets[2], octets[3]
                );

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
                    "update eBPF skip-ip map (IPv4)",
                )?;
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() {
                    continue;
                }

                let octets = v6.octets();
                let key = format!(
                    "hex 80 00 00 00 {}",
                    octets
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                );

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
                    "update eBPF skip-ip map (IPv6)",
                )?;
            }
        }
    }

    Ok(())
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
