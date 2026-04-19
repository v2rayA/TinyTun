use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

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
// Linux: NETLINK_INET_DIAG (same approach as mihomo)
//
// Phase 1: send an inet_diag_req_v2 to the kernel, which returns uid + inode
//          for the matching socket in a single round-trip.
// Phase 2: scan /proc/<pid>/fd/ for the process that owns that inode, filtering
//          by UID first to skip unrelated processes quickly.
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn linux_find_pid(protocol: TransportProtocol, src: SocketAddr, dst: SocketAddr) -> Option<u32> {
    use std::net::IpAddr;

    let ipproto: u8 = match protocol {
        TransportProtocol::Tcp => libc::IPPROTO_TCP as u8,
        TransportProtocol::Udp => libc::IPPROTO_UDP as u8,
    };

    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            netlink_find_pid(libc::AF_INET as u8, ipproto, &s.octets(), src.port(), &d.octets(), dst.port())
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            netlink_find_pid(libc::AF_INET6 as u8, ipproto, &s.octets(), src.port(), &d.octets(), dst.port())
        }
        // IPv4-mapped IPv6 → try both families
        (IpAddr::V6(s), IpAddr::V4(d)) => {
            if let Some(s4) = s.to_ipv4_mapped() {
                netlink_find_pid(libc::AF_INET as u8, ipproto, &s4.octets(), src.port(), &d.octets(), dst.port())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Send an NETLINK_INET_DIAG request and parse the response to obtain
/// (uid, inode) for the socket matching the given 5-tuple.
/// Then walk /proc to find the PID that owns that inode.
#[cfg(target_os = "linux")]
fn netlink_find_pid(
    family: u8,
    ipproto: u8,
    src_ip: &[u8],
    src_port: u16,
    dst_ip: &[u8],
    dst_port: u16,
) -> Option<u32> {
    // ── Build the netlink request ────────────────────────────────────────────
    // struct inet_diag_req_v2 layout (total 56 bytes, see linux/inet_diag.h):
    //   u8   sdiag_family
    //   u8   sdiag_protocol
    //   u8   idiag_ext
    //   u8   pad
    //   u32  idiag_states   (0xffffffff = all)
    //   struct inet_diag_sockid (48 bytes):
    //     be16 idiag_sport
    //     be16 idiag_dport
    //     u32  idiag_src[4]
    //     u32  idiag_dst[4]
    //     u32  idiag_if
    //     u32  idiag_cookie[2]
    const INET_DIAG_REQ_V2_LEN: usize = 56;
    const NLMSG_HDR_LEN: usize = 16; // struct nlmsghdr
    const TOTAL_LEN: usize = NLMSG_HDR_LEN + INET_DIAG_REQ_V2_LEN;
    const SOCK_DIAG_BY_FAMILY: u16 = 20; // SOCK_DIAG_BY_FAMILY

    let mut buf = [0u8; TOTAL_LEN];

    // nlmsghdr: len, type, flags, seq, pid
    let nlmsg_len = (TOTAL_LEN as u32).to_ne_bytes();
    buf[0..4].copy_from_slice(&nlmsg_len);
    buf[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    buf[6..8].copy_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
    // seq=1, pid=0

    // inet_diag_req_v2
    let req = &mut buf[NLMSG_HDR_LEN..];
    req[0] = family;
    req[1] = ipproto;
    // idiag_ext = 0, pad = 0
    req[4..8].copy_from_slice(&0xffffffffu32.to_ne_bytes()); // idiag_states

    // idiag_sockid starts at offset 8 within req
    let sid = &mut req[8..];
    sid[0..2].copy_from_slice(&src_port.to_be_bytes());
    sid[2..4].copy_from_slice(&dst_port.to_be_bytes());

    // src addr: always stored as 16 bytes (for IPv4, left-pad to 4 bytes, rest zero)
    let ip_len = src_ip.len().min(16);
    sid[4..4 + ip_len].copy_from_slice(&src_ip[..ip_len]);
    let ip_len = dst_ip.len().min(16);
    sid[20..20 + ip_len].copy_from_slice(&dst_ip[..ip_len]);
    // idiag_if = 0, idiag_cookie = INET_DIAG_NOCOOKIE

    // ── Open netlink socket and send ─────────────────────────────────────────
    let fd = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_INET_DIAG)
    };
    if fd < 0 {
        return None;
    }
    struct SocketGuard(libc::c_int);
    impl Drop for SocketGuard {
        fn drop(&mut self) { unsafe { libc::close(self.0); } }
    }
    let _guard = SocketGuard(fd);

    let sent = unsafe {
        libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0)
    };
    if sent < 0 {
        return None;
    }

    // ── Read response ────────────────────────────────────────────────────────
    // Response nlmsghdr + inet_diag_msg (minimum 72 bytes total)
    // struct inet_diag_msg layout (56 bytes):
    //   u8  idiag_family
    //   u8  idiag_state
    //   u8  idiag_timer
    //   u8  idiag_retrans
    //   struct inet_diag_sockid  (48 bytes, same as above)
    //   u32 idiag_expires
    //   u32 idiag_rqueue
    //   u32 idiag_wqueue
    //   u32 idiag_uid
    //   u32 idiag_inode
    const INET_DIAG_MSG_LEN: usize = 56;
    const RESP_BUF_LEN: usize = NLMSG_HDR_LEN + INET_DIAG_MSG_LEN;

    let mut resp = [0u8; 512];
    let rcvd = unsafe {
        libc::recv(fd, resp.as_mut_ptr() as *mut libc::c_void, resp.len(), 0)
    };
    if rcvd < RESP_BUF_LEN as isize {
        return None;
    }

    let msg = &resp[NLMSG_HDR_LEN..];
    // Check for NLMSG_ERROR (type 2)
    let nlmsg_type = u16::from_ne_bytes([resp[4], resp[5]]);
    if nlmsg_type == 2 {
        return None; // NLMSG_ERROR
    }

    let uid = u32::from_ne_bytes([msg[48], msg[49], msg[50], msg[51]]);
    let inode = u32::from_ne_bytes([msg[52], msg[53], msg[54], msg[55]]);

    if inode == 0 {
        return None;
    }

    linux_pid_from_inode(inode as u64, uid)
}

/// Walk /proc/<pid>/fd/ to find which process owns the given socket inode.
/// Pre-filters by UID to avoid stat-ing every FD of every process.
///
/// Results are cached in a module-level static for `INODE_PID_CACHE_TTL`.
/// Multiple connections from the same process hit the cache for the inode →
/// pid mapping, avoiding repeated /proc walks.
#[cfg(target_os = "linux")]
fn linux_pid_from_inode(inode: u64, uid: u32) -> Option<u32> {
    use std::sync::{Mutex, OnceLock};

    // (inode, uid) → (pid, recorded_at)
    static CACHE: OnceLock<Mutex<std::collections::HashMap<(u64, u32), (u32, Instant)>>> =
        OnceLock::new();
    const CACHE_TTL: Duration = Duration::from_secs(5);

    let cache = CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));

    // Fast path: check cache.
    if let Ok(guard) = cache.lock() {
        if let Some(&(pid, recorded_at)) = guard.get(&(inode, uid)) {
            if recorded_at.elapsed() < CACHE_TTL {
                // Verify the pid is still alive (cheap stat check).
                if std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                    return Some(pid);
                }
            }
        }
    }

    // Slow path: walk /proc.
    let pid = linux_pid_from_inode_slow(inode, uid)?;

    if let Ok(mut guard) = cache.lock() {
        guard.insert((inode, uid), (pid, Instant::now()));
    }

    Some(pid)
}

/// Inner slow-path: walks /proc to resolve inode → pid.
#[cfg(target_os = "linux")]
fn linux_pid_from_inode_slow(inode: u64, uid: u32) -> Option<u32> {
    let target = format!("socket:[{}]", inode);
    let proc_dir = std::fs::read_dir("/proc").ok()?;

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Quick UID pre-filter: check /proc/<pid>/status for Uid: line.
        // Skip processes whose real UID doesn't match to avoid unnecessary
        // fd enumeration (same optimisation as mihomo).
        if !linux_pid_uid_matches(pid, uid) {
            continue;
        }

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

/// Check whether /proc/<pid>/status shows the given UID as the real UID.
#[cfg(target_os = "linux")]
fn linux_pid_uid_matches(pid: u32, uid: u32) -> bool {
    let status = match std::fs::read_to_string(format!("/proc/{}/status", pid)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Format: "Uid:\tREAL\tEFFECTIVE\tSAVED\tFSUID"
            if let Some(real_uid_str) = rest.split_whitespace().next() {
                return real_uid_str.parse::<u32>().ok() == Some(uid);
            }
        }
    }
    false
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
// Windows: GetExtendedTcpTable / GetExtendedUdpTable (iphlpapi)
//
// Replaces the previous `netstat -ano` subprocess approach. Using the kernel
// API directly is O(1) per query and avoids spawning a child process for every
// process lookup, which was O(flows/second) subprocess launches under load.
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        p_tcp_table: *mut core::ffi::c_void,
        pdw_size: *mut u32,
        b_order: i32,
        dw_af: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;

    fn GetExtendedUdpTable(
        p_udp_table: *mut core::ffi::c_void,
        pdw_size: *mut u32,
        b_order: i32,
        dw_af: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;
}

#[cfg(windows)]
fn windows_find_pid(protocol: TransportProtocol, src: SocketAddr, _dst: SocketAddr) -> Option<u32> {
    use std::net::IpAddr;
    match (protocol, src.ip()) {
        (TransportProtocol::Tcp, IpAddr::V4(src_v4)) => {
            windows_tcp_pid_v4(src_v4, src.port(), _dst)
        }
        (TransportProtocol::Udp, IpAddr::V4(src_v4)) => {
            windows_udp_pid_v4(src_v4, src.port())
        }
        // IPv6 flows: fall back to none (IPv4 covers the primary TUN use-case).
        _ => None,
    }
}

/// Decode a Windows port field: ports are stored as big-endian u16 in
/// the low two bytes of a little-endian u32.
#[cfg(windows)]
#[inline]
fn win_port(dw: u32) -> u16 {
    u16::from_be(dw as u16)
}

/// Decode a Windows IPv4 address field (little-endian u32 → Ipv4Addr).
#[cfg(windows)]
#[inline]
fn win_ipv4(dw: u32) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::from(dw.swap_bytes())
}

#[cfg(windows)]
fn windows_tcp_pid_v4(
    src_ip: std::net::Ipv4Addr,
    src_port: u16,
    dst: SocketAddr,
) -> Option<u32> {
    // MIB_TCPROW_OWNER_PID layout (24 bytes):
    //   u32 dwState, u32 dwLocalAddr, u32 dwLocalPort,
    //   u32 dwRemoteAddr, u32 dwRemotePort, u32 dwOwningPid
    const ROW_SIZE: usize = 24;
    const AF_INET: u32 = 2;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    let mut size: u32 = 0;
    // First call to get required buffer size.
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if size == 0 {
        return None;
    }

    let mut buf: Vec<u8> = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    // 0 = ERROR_SUCCESS
    if ret != 0 && ret != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }
    if (buf.len() as u32) < size || buf.len() < 4 {
        return None;
    }

    let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let dst_v4 = match dst.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => return None,
    };

    for i in 0..num_entries {
        let offset = 4 + i * ROW_SIZE;
        if offset + ROW_SIZE > buf.len() {
            break;
        }
        let row = &buf[offset..offset + ROW_SIZE];
        let local_addr = win_ipv4(u32::from_ne_bytes([row[4], row[5], row[6], row[7]]));
        let local_port = win_port(u32::from_ne_bytes([row[8], row[9], row[10], row[11]]));
        let remote_addr = win_ipv4(u32::from_ne_bytes([row[12], row[13], row[14], row[15]]));
        let remote_port = win_port(u32::from_ne_bytes([row[16], row[17], row[18], row[19]]));
        let pid = u32::from_ne_bytes([row[20], row[21], row[22], row[23]]);

        if local_addr == src_ip
            && local_port == src_port
            && remote_addr == dst_v4
            && remote_port == dst.port()
        {
            return Some(pid);
        }
    }
    None
}

#[cfg(windows)]
fn windows_udp_pid_v4(src_ip: std::net::Ipv4Addr, src_port: u16) -> Option<u32> {
    // MIB_UDPROW_OWNER_PID layout (12 bytes):
    //   u32 dwLocalAddr, u32 dwLocalPort, u32 dwOwningPid
    const ROW_SIZE: usize = 12;
    const AF_INET: u32 = 2;
    const UDP_TABLE_OWNER_PID: u32 = 1;

    let mut size: u32 = 0;
    unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }
    if size == 0 {
        return None;
    }

    let mut buf: Vec<u8> = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if ret != 0 || buf.len() < 4 {
        return None;
    }

    let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    for i in 0..num_entries {
        let offset = 4 + i * ROW_SIZE;
        if offset + ROW_SIZE > buf.len() {
            break;
        }
        let row = &buf[offset..offset + ROW_SIZE];
        let local_addr = win_ipv4(u32::from_ne_bytes([row[0], row[1], row[2], row[3]]));
        let local_port = win_port(u32::from_ne_bytes([row[4], row[5], row[6], row[7]]));
        let pid = u32::from_ne_bytes([row[8], row[9], row[10], row[11]]);

        if local_addr == src_ip && local_port == src_port {
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

