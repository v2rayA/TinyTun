use std::net::SocketAddr;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;

#[cfg(any(windows, target_os = "macos"))]
use std::process::Command;

use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo,
};

#[cfg(target_os = "linux")]
use serde::Deserialize;

#[cfg(target_os = "linux")]
use crate::config::ProcessLookupConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug)]
pub struct ProcessLookupOptions {
    #[cfg(target_os = "linux")]
    pub linux: ProcessLookupConfig,
}

impl ProcessLookupOptions {
    pub fn from_config(config: &crate::config::Config) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                linux: config.filtering.process_lookup.clone(),
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = config;
            Self {}
        }
    }
}

pub fn find_process_name_for_flow(
    options: &ProcessLookupOptions,
    protocol: TransportProtocol,
    src: SocketAddr,
    dst: SocketAddr,
) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        return find_process_name_for_flow_linux(options, protocol, src, dst);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        find_process_name_for_flow_netstat2(protocol, src, dst)
    }
}

#[cfg(target_os = "linux")]
fn find_process_name_for_flow_linux(
    options: &ProcessLookupOptions,
    protocol: TransportProtocol,
    src: SocketAddr,
    dst: SocketAddr,
) -> Option<String> {
    let backend = options.linux.linux_backend.to_ascii_lowercase();

    if backend == "ebpf" {
        return find_process_name_for_flow_linux_ebpf(options, protocol, src, dst);
    }

    if backend == "ss" {
        // Keep backward-compatible config value, but now use netstat2 instead of shelling out to ss.
        return find_process_name_for_flow_netstat2(protocol, src, dst);
    }

    // auto: prefer eBPF cache if present, then fallback to netstat2.
    find_process_name_for_flow_linux_ebpf(options, protocol, src, dst)
        .or_else(|| find_process_name_for_flow_netstat2(protocol, src, dst))
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
struct EbpfFlowRecord {
    protocol: String,
    src: String,
    dst: String,
    process_name: String,
}

#[cfg(target_os = "linux")]
fn find_process_name_for_flow_linux_ebpf(
    options: &ProcessLookupOptions,
    protocol: TransportProtocol,
    src: SocketAddr,
    dst: SocketAddr,
) -> Option<String> {
    let cache_path = options
        .linux
        .linux_ebpf_cache_path
        .as_deref()
        .unwrap_or("/run/tinytun-ebpf-flow-cache.json");

    let content = std::fs::read_to_string(cache_path).ok()?;
    let records: Vec<EbpfFlowRecord> = serde_json::from_str(&content).ok()?;

    let protocol_name = match protocol {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
    };

    let src_text = src.to_string();
    let dst_text = dst.to_string();

    for record in records {
        if record.protocol.eq_ignore_ascii_case(protocol_name)
            && record.src == src_text
            && record.dst == dst_text
        {
            let name = record.process_name.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }

    None
}

fn find_process_name_for_flow_netstat2(
    protocol: TransportProtocol,
    src: SocketAddr,
    dst: SocketAddr,
) -> Option<String> {
    let af_flags = if src.is_ipv4() && dst.is_ipv4() {
        AddressFamilyFlags::IPV4
    } else if src.is_ipv6() && dst.is_ipv6() {
        AddressFamilyFlags::IPV6
    } else {
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6
    };

    let proto_flags = match protocol {
        TransportProtocol::Tcp => ProtocolFlags::TCP,
        TransportProtocol::Udp => ProtocolFlags::UDP,
    };

    let sockets = get_sockets_info(af_flags, proto_flags).ok()?;

    for socket in sockets {
        let matched = match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                protocol == TransportProtocol::Tcp
                    && tcp.local_port == src.port()
                    && tcp.remote_port == dst.port()
                    && tcp.local_addr == src.ip()
                    && tcp.remote_addr == dst.ip()
            }
            ProtocolSocketInfo::Udp(udp) => {
                // UDP often has no stable remote endpoint in kernel tables,
                // so local tuple match is the reliable signal.
                protocol == TransportProtocol::Udp
                    && udp.local_port == src.port()
                    && udp.local_addr == src.ip()
            }
        };

        if !matched {
            continue;
        }

        if let Some(pid) = socket.associated_pids.first().copied() {
            if let Some(name) = process_name_from_pid(pid) {
                return Some(name);
            }
        }
    }

    None
}

fn process_name_from_pid(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(name) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        if let Ok(cmdline) = std::fs::read(format!("/proc/{}/cmdline", pid)) {
            if let Some(raw_first) = cmdline.split(|b| *b == 0).next() {
                if let Ok(text) = std::str::from_utf8(raw_first) {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        let basename = Path::new(trimmed)
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or(trimmed);
                        return Some(basename.to_string());
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let filter = format!("PID eq {}", pid);
        if let Some(output) = run_and_capture("tasklist", &["/FI", &filter, "/FO", "CSV", "/NH"]) {
            let first_line = output.lines().next().unwrap_or("").trim();
            if let Some(name) = parse_tasklist_image_name(first_line) {
                return Some(name);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(output) = run_and_capture("ps", &["-p", &pid.to_string(), "-o", "comm="]) {
            let trimmed = output.trim();
            if !trimmed.is_empty() {
                let basename = Path::new(trimmed)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(trimmed);
                return Some(basename.to_string());
            }
        }
    }

    None
}

#[cfg(any(windows, target_os = "macos"))]
fn run_and_capture(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

#[cfg(windows)]
fn parse_tasklist_image_name(line: &str) -> Option<String> {
    if line.is_empty() || line.starts_with("INFO:") {
        return None;
    }

    if let Some(rest) = line.strip_prefix('"') {
        let end = rest.find("\",")?;
        let name = rest[..end].trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
        return None;
    }

    let name = line.split(',').next().unwrap_or("").trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}
