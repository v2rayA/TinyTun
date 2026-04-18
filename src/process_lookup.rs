use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::net::IpAddr;

#[cfg(not(target_os = "freebsd"))]
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Default)]
pub struct ProcessLookupOptions {}

impl ProcessLookupOptions {
    pub fn from_config(config: &crate::config::Config) -> Self {
        let _ = config;
        Self {}
    }
}

pub fn find_process_name_for_flow(
    options: &ProcessLookupOptions,
    protocol: TransportProtocol,
    src: SocketAddr,
    dst: SocketAddr,
) -> Option<String> {
    let _ = options;
    let pid = find_pid_for_flow(protocol, src, dst)?;
    process_name_from_pid(pid)
}

/// Look up the PID owning the given network flow using platform-native APIs.
fn find_pid_for_flow(
    protocol: TransportProtocol,
    src: SocketAddr,
    dst: SocketAddr,
) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        return linux_find_pid(protocol, src, dst);
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        return bsd_find_pid(protocol, src, dst);
    }

    #[cfg(windows)]
    {
        return windows_find_pid(protocol, src, dst);
    }

    #[allow(unreachable_code)]
    None
}

// ──────────────────────────────────────────────────────────────────────────────
// Linux: parse /proc/net/tcp[6] and /proc/net/udp[6]
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn linux_find_pid(protocol: TransportProtocol, src: SocketAddr, dst: SocketAddr) -> Option<u32> {
    // Collect candidate inodes from the kernel socket table.
    let inode = match (protocol, src.is_ipv4()) {
        (TransportProtocol::Tcp, true) => linux_find_inode("/proc/net/tcp", src, Some(dst)),
        (TransportProtocol::Tcp, false) => linux_find_inode("/proc/net/tcp6", src, Some(dst)),
        (TransportProtocol::Udp, true) => linux_find_inode("/proc/net/udp", src, None),
        (TransportProtocol::Udp, false) => linux_find_inode("/proc/net/udp6", src, None),
    }?;

    linux_pid_from_inode(inode)
}

/// Parse /proc/net/tcp or /proc/net/udp and return the socket inode matching
/// the given local (and optionally remote) address.
///
/// Each data line has the format (whitespace-separated fields):
///   sl  local_address  rem_address  st  tx_queue:rx_queue  ...  inode
///   0   1              2            3   4                   ...  9
#[cfg(target_os = "linux")]
fn linux_find_inode(path: &str, src: SocketAddr, dst: Option<SocketAddr>) -> Option<u64> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let local = parse_linux_hex_addr(fields[1])?;
        if local != src {
            continue;
        }

        if let Some(d) = dst {
            let remote = parse_linux_hex_addr(fields[2])?;
            if remote != d {
                continue;
            }
        }

        let inode: u64 = fields[9].parse().ok()?;
        return Some(inode);
    }
    None
}

/// Parse a Linux hex-encoded address:port pair like "0100007F:1234" (little-endian IPv4)
/// or the 128-bit IPv6 variant.
#[cfg(target_os = "linux")]
fn parse_linux_hex_addr(s: &str) -> Option<SocketAddr> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    match addr_hex.len() {
        8 => {
            // IPv4 – 4 bytes little-endian
            let n = u32::from_str_radix(addr_hex, 16).ok()?;
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(n.swap_bytes())));
            Some(SocketAddr::new(ip, port))
        }
        32 => {
            // IPv6 – 4 × 4-byte words, each in host byte order
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&addr_hex[i * 8..(i + 1) * 8], 16).ok()?;
                let be = word.to_be_bytes();
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&be);
            }
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(bytes));
            Some(SocketAddr::new(ip, port))
        }
        _ => None,
    }
}

/// Walk /proc/<pid>/fd/ to find which process owns the given socket inode.
#[cfg(target_os = "linux")]
fn linux_pid_from_inode(inode: u64) -> Option<u32> {
    let target = format!("socket:[{}]", inode);
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{}/fd", pid);
        if let Ok(fds) = std::fs::read_dir(&fd_dir) {
            for fd in fds.flatten() {
                if let Ok(link) = std::fs::read_link(fd.path()) {
                    if link.to_string_lossy() == target {
                        return Some(pid);
                    }
                }
            }
        }
    }
    None
}

// ──────────────────────────────────────────────────────────────────────────────
// macOS / FreeBSD: parse `sockstat -l` output
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn bsd_find_pid(protocol: TransportProtocol, src: SocketAddr, dst: SocketAddr) -> Option<u32> {
    use std::process::Command;

    // sockstat is available on both macOS and FreeBSD.
    // Output columns: USER COMMAND PID FD PROTO LOCAL-ADDRESS FOREIGN-ADDRESS
    let proto_flag = match protocol {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
    };

    let output = Command::new("sockstat")
        .args(["-l", "-P", proto_flag])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let src_str = src.to_string();
    let dst_str = dst.to_string();

    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 {
            continue;
        }
        let pid_str = fields[2];
        let local = fields[5];
        let remote = fields[6];

        let local_matches = local == src_str || local.ends_with(&format!(":{}", src.port()));
        let remote_matches = match protocol {
            TransportProtocol::Tcp => remote == dst_str,
            // UDP remote endpoint may be "*.*" in the table
            TransportProtocol::Udp => {
                remote == dst_str || remote == "*.*" || remote.starts_with("*:")
            }
        };

        if local_matches && remote_matches {
            if let Ok(pid) = pid_str.parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

// ──────────────────────────────────────────────────────────────────────────────
// Windows: parse `netstat -ano` output
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(windows)]
fn windows_find_pid(protocol: TransportProtocol, src: SocketAddr, dst: SocketAddr) -> Option<u32> {
    use std::process::Command;

    let output = Command::new("netstat").args(["-ano"]).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let proto_prefix = match protocol {
        TransportProtocol::Tcp => "TCP",
        TransportProtocol::Udp => "UDP",
    };

    let src_str = src.to_string();
    let dst_str = dst.to_string();

    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with(proto_prefix) {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // TCP: Proto Local Foreign State PID  (5 fields)
        // UDP: Proto Local Foreign PID        (4 fields)
        let (local, remote, pid_field) = match (protocol, fields.len()) {
            (TransportProtocol::Tcp, 5) => (fields[1], fields[2], fields[4]),
            (TransportProtocol::Udp, 4) => (fields[1], fields[2], fields[3]),
            _ => continue,
        };

        if local != src_str {
            continue;
        }

        let remote_ok = match protocol {
            TransportProtocol::Tcp => remote == dst_str,
            TransportProtocol::Udp => remote == dst_str || remote == "*:*",
        };
        if !remote_ok {
            continue;
        }

        if let Ok(pid) = pid_field.parse::<u32>() {
            return Some(pid);
        }
    }
    None
}

// ──────────────────────────────────────────────────────────────────────────────
// Process name lookup
// On FreeBSD: sysctl(KERN_PROC_PID) via libc (no libkvm/libprocstat needed)
// Everywhere else: sysinfo
// ──────────────────────────────────────────────────────────────────────────────

/// FreeBSD: resolve process name from PID using sysctl(KERN_PROC_PID).
/// This only requires libc and works in Zig cross-compilation environments
/// where libkvm / libprocstat are unavailable.
#[cfg(target_os = "freebsd")]
fn process_name_from_pid(pid: u32) -> Option<String> {
    use libc::{c_int, kinfo_proc, sysctl, CTL_KERN, KERN_PROC, KERN_PROC_PID};
    use std::{ffi::CStr, mem};

    let name = unsafe {
        let mut mib: [c_int; 4] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid as c_int];
        let mut info: kinfo_proc = mem::zeroed();
        let mut len: libc::size_t = mem::size_of::<kinfo_proc>();

        let ret = sysctl(
            mib.as_mut_ptr(),
            4,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        );

        if ret != 0 || len == 0 {
            return None;
        }

        CStr::from_ptr(info.ki_comm.as_ptr())
            .to_string_lossy()
            .into_owned()
    };

    let name = name.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

/// All other platforms: resolve process name from PID via sysinfo.
#[cfg(not(target_os = "freebsd"))]
fn process_name_from_pid(pid: u32) -> Option<String> {
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing()),
    );
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[Pid::from_u32(pid)]),
        false,
        ProcessRefreshKind::nothing(),
    );
    let proc = sys.process(Pid::from_u32(pid))?;
    let name = proc.name().to_string_lossy();
    let name = name.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}
