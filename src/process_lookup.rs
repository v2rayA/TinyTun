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
    // SAFETY: `libc::socket()` is a FFI call that returns a raw file descriptor.
    // All arguments are valid constants; `SOCK_CLOEXEC` is safe and prevents fd leaks.
    // The return value is checked (< 0) to detect errors before any use.
    let fd = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_INET_DIAG)
    };
    if fd < 0 {
        return None;
    }
    struct SocketGuard(libc::c_int);
    impl Drop for SocketGuard {
        // SAFETY: `self.0` is a valid file descriptor from `libc::socket()` above.
        // `SocketGuard` is not `Clone`, ensuring `close()` is called exactly once.
        // No other code holds a reference to this fd at drop time.
        fn drop(&mut self) { unsafe { libc::close(self.0); } }
    }
    let _guard = SocketGuard(fd);

    // SAFETY: `fd` is a valid netlink socket. `buf.as_ptr()` points to a valid,
    // initialized buffer of `buf.len()` bytes. `libc::send()` only reads from the
    // buffer; no concurrent writes occur. Return value is checked for errors.
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
    // SAFETY: `fd` is a valid netlink socket. `resp.as_mut_ptr()` points to a valid,
    // properly aligned buffer of `resp.len()` bytes. `libc::recv()` writes into this
    // buffer; no other thread reads from `resp` concurrently. Return value is checked.
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
// ──────────────────────────────────────────────────────────────────────────────
// macOS / FreeBSD: parse `sockstat -l` output
// ──────────────────────────────────────────────────────────────────────────────

/// Match a `sockstat` address field against a `SocketAddr`.
///
/// `sockstat` uses `addr.port` notation (dot-separated) for both IPv4 and
/// IPv6: e.g. `192.168.1.1.80`, `2001:db8::1.80`.  Rust's `SocketAddr::to_string()`
/// uses `addr:port` for IPv4 and `[addr]:port` for IPv6.  Both forms are tried
/// so that the comparison is format-agnostic.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn sockstat_field_matches(field: &str, addr: SocketAddr) -> bool {
    use std::net::IpAddr;

    // Rust canonical form ("192.0.2.1:80" or "[::1]:80")
    if field == addr.to_string() {
        return true;
    }

    let port = addr.port();
    // sockstat dot form: "<raw_ip>.<port>"
    let dot_form = match addr.ip() {
        IpAddr::V4(v4) => format!("{}.{}", v4, port),
        IpAddr::V6(v6) => format!("{}.{}", v6, port),
    };
    if field == dot_form {
        return true;
    }

    // Bracketed IPv6 with colon: "[::1]:80" (some sockstat versions)
    // Already covered by the Rust canonical form check above, but kept for clarity.

    // Last resort: just match the trailing port separator regardless of IP.
    field.ends_with(&format!(":{}", port)) || field.ends_with(&format!(".{}", port))
}

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

    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 {
            continue;
        }
        let pid_str = fields[2];
        let local = fields[5];
        let remote = fields[6];

        if !sockstat_field_matches(local, src) {
            continue;
        }

        let remote_matches = match protocol {
            TransportProtocol::Tcp => sockstat_field_matches(remote, dst),
            // UDP remote endpoint may be "*.*" or "*:*" in the table
            TransportProtocol::Udp => {
                sockstat_field_matches(remote, dst)
                    || remote == "*.*"
                    || remote == "*:*"
                    || remote.starts_with("*:")
                    || remote.starts_with("*.")
            }
        };

        if remote_matches {
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
//
// Memory management uses RAII wrappers (HeapBuffer, ProcessHandle) to ensure
// that heap-allocated buffers and kernel handles are always freed, even on
// error paths.
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

// ── RAII wrapper for Windows heap-allocated memory ──────────────────────────
//
// `HeapBuffer` owns a block of memory allocated via `HeapAlloc`. The memory is
// automatically freed via `HeapFree` when the `HeapBuffer` is dropped, ensuring
// no leaks on error paths. This replaces the previous manual `HeapAlloc`/`HeapFree`
// pairs that were vulnerable to early-return leaks.

/// RAII wrapper for a Windows heap-allocated buffer.
///
/// The buffer is allocated with `HEAP_ZERO_MEMORY` and freed on drop.
/// This eliminates manual `HeapFree` calls and prevents memory leaks on
/// error return paths.
#[cfg(windows)]
struct HeapBuffer {
    ptr: *mut std::ffi::c_void,
    size: usize,
}

// SAFETY: `HeapBuffer` owns a heap allocation that is only accessed through
// `&self` or `&mut self` references. There is no shared mutable aliasing.
// `HeapAlloc`/`HeapFree` are thread-safe (the process heap is synchronized).
#[cfg(windows)]
unsafe impl Send for HeapBuffer {}
#[cfg(windows)]
unsafe impl Sync for HeapBuffer {}

#[cfg(windows)]
impl HeapBuffer {
    /// Allocate a zero-initialized heap buffer of the given size.
    ///
    /// Returns `None` if allocation fails (e.g., out of memory).
    fn allocate(size: usize) -> Option<Self> {
        // SAFETY: `GetProcessHeap()` returns the default process heap, which is always
        // available. `HeapAlloc` with `HEAP_ZERO_MEMORY` zero-initializes the buffer.
        // The returned pointer is checked for null to detect allocation failure.
        let ptr = unsafe {
            windows::Win32::System::Memory::HeapAlloc(
                windows::Win32::System::Memory::GetProcessHeap(),
                windows::Win32::System::Memory::HEAP_ZERO_MEMORY,
                size,
            )
        };
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr, size })
        }
    }

    /// Return a const pointer to the buffer.
    fn as_ptr(&self) -> *const std::ffi::c_void {
        self.ptr
    }

    /// Return a mutable pointer to the buffer.
    fn as_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        self.ptr
    }

    /// Return the allocated size in bytes.
    fn size(&self) -> usize {
        self.size
    }
}

#[cfg(windows)]
impl Drop for HeapBuffer {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was allocated by `HeapAlloc` on the process heap.
        // `HeapFree` is the correct deallocation function. `HEAP_NO_SERIALIZE` is safe
        // because no other thread is concurrently freeing this same pointer (each
        // `HeapBuffer` owns a unique allocation). The process heap remains valid for
        // the entire lifetime of the process.
        unsafe {
            windows::Win32::System::Memory::HeapFree(
                windows::Win32::System::Memory::GetProcessHeap(),
                windows::Win32::System::Memory::HEAP_NO_SERIALIZE,
                self.ptr,
            );
        }
    }
}

// ── RAII wrapper for a Windows kernel handle ────────────────────────────────
//
// `ProcessHandle` owns a `HANDLE` returned by `OpenProcess`. The handle is
// automatically closed via `CloseHandle` on drop, preventing handle leaks.

/// RAII wrapper for a Windows process handle (`HANDLE` from `OpenProcess`).
///
/// The handle is automatically closed via `CloseHandle` when the wrapper is
/// dropped, preventing handle leaks on error paths.
#[cfg(windows)]
struct ProcessHandle(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl ProcessHandle {
    /// Wrap an existing handle. The caller must ensure the handle is valid.
    ///
    /// # Safety
    ///
    /// `handle` must be a valid handle returned by `OpenProcess` (or similar),
    /// or `HANDLE::default()` (which represents an invalid handle). The handle
    /// must not be closed elsewhere while this `ProcessHandle` is alive.
    unsafe fn new(handle: windows::Win32::Foundation::HANDLE) -> Self {
        Self(handle)
    }

    /// Return a reference to the inner `HANDLE`.
    fn as_raw(&self) -> &windows::Win32::Foundation::HANDLE {
        &self.0
    }
}

#[cfg(windows)]
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid handle obtained from `OpenProcess` (or
        // `HANDLE::default()` if opening failed). `CloseHandle` is the correct
        // function to close it. Each `ProcessHandle` owns exactly one handle,
        // so no double-close can occur.
        if !self.0.is_invalid() {
            unsafe {
                windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
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
        (TransportProtocol::Tcp, IpAddr::V6(src_v6)) => {
            windows_tcp_pid_v6(src_v6, src.port(), _dst)
        }
        (TransportProtocol::Udp, IpAddr::V6(src_v6)) => {
            windows_udp_pid_v6(src_v6, src.port())
        }
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
    // SAFETY: `GetExtendedTcpTable` with `null_mut()` is the documented way to query
    // the required buffer size. `&mut size` is a valid pointer to a `u32`. The function
    // only writes to `size`; no data races occur as this is the only thread accessing it.
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

    // Allocate a heap buffer via the RAII wrapper. The buffer is automatically freed
    // when `HeapBuffer` is dropped, eliminating manual `HeapFree` calls on all paths.
    let mut buf = HeapBuffer::allocate(size as usize)?;

    // SAFETY: `buf.as_mut_ptr()` points to a valid, properly sized heap buffer of
    // `size` bytes, zero-initialized by `HeapBuffer::allocate`. `GetExtendedTcpTable`
    // writes into this buffer; no other thread reads from `buf` concurrently.
    // The return value is checked (0 = ERROR_SUCCESS) before using the data.
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
        return None; // HeapBuffer::drop 自动释放堆内存
    }

    // ── Bounds check: validate that `dwNumEntries` does not exceed the buffer ──
    // The MIB_TCPTABLE header is just `dwNumEntries` (u32 = 4 bytes).
    // Each entry is `ROW_SIZE` bytes. Compute the maximum number of entries
    // that fit in the allocated buffer and reject if the kernel reports more.
    let header_size = std::mem::size_of::<u32>();
    if buf.size() < header_size {
        return None;
    }
    let max_entries = buf.size().saturating_sub(header_size) / ROW_SIZE;
    // SAFETY: `buf.as_ptr()` points to a valid, zero-initialized heap buffer of
    // at least `header_size` bytes. Reading the first 4 bytes as `u32` is safe
    // because the buffer was allocated with at least `size` bytes (checked above).
    let num_entries = unsafe {
        let ptr = buf.as_ptr() as *const u32;
        std::ptr::read_unaligned(ptr)
    };
    if num_entries as usize > max_entries {
        return None; // 边界检查失败，防止越界读取
    }

    let dst_v4 = match dst.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => return None,
    };

    // SAFETY: `buf.as_ptr()` points to a valid heap buffer of `buf.size()` bytes.
    // The iteration is bounded by `num_entries` which was validated against
    // `max_entries` above, ensuring `offset + ROW_SIZE` never exceeds the buffer.
    for i in 0..num_entries as usize {
        let offset = header_size + i * ROW_SIZE;
        // SAFETY: `offset + ROW_SIZE <= buf.size()` is guaranteed by the bounds check above.
        let ptr = unsafe { (buf.as_ptr() as *const u8).add(offset) };
        // SAFETY: Each field read uses `read_unaligned` because the heap buffer
        // may not satisfy the alignment requirements of `u32`.
        let local_addr = unsafe {
            let dw = std::ptr::read_unaligned(ptr.add(4) as *const u32);
            win_ipv4(dw)
        };
        let local_port = unsafe {
            let dw = std::ptr::read_unaligned(ptr.add(8) as *const u32);
            win_port(dw)
        };
        let remote_addr = unsafe {
            let dw = std::ptr::read_unaligned(ptr.add(12) as *const u32);
            win_ipv4(dw)
        };
        let remote_port = unsafe {
            let dw = std::ptr::read_unaligned(ptr.add(16) as *const u32);
            win_port(dw)
        };
        let pid = unsafe {
            std::ptr::read_unaligned(ptr.add(20) as *const u32)
        };

        if local_addr == src_ip
            && local_port == src_port
            && remote_addr == dst_v4
            && remote_port == dst.port()
        {
            return Some(pid);
        }
    }
    None
    // HeapBuffer::drop 自动释放堆内存
}

#[cfg(windows)]
fn windows_udp_pid_v4(src_ip: std::net::Ipv4Addr, src_port: u16) -> Option<u32> {
    // MIB_UDPROW_OWNER_PID layout (12 bytes):
    //   u32 dwLocalAddr, u32 dwLocalPort, u32 dwOwningPid
    const ROW_SIZE: usize = 12;
    const AF_INET: u32 = 2;
    const UDP_TABLE_OWNER_PID: u32 = 1;

    let mut size: u32 = 0;
    // SAFETY: Same pattern as `GetExtendedTcpTable` — query buffer size with null pointer.
    // `&mut size` is a valid pointer. No concurrent access to `size`.
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

    // Allocate a heap buffer via the RAII wrapper. The buffer is automatically freed
    // when `HeapBuffer` is dropped, eliminating manual `HeapFree` calls on all paths.
    let mut buf = HeapBuffer::allocate(size as usize)?;

    // SAFETY: `buf.as_mut_ptr()` points to a valid buffer of `size` bytes.
    // `GetExtendedUdpTable` writes into this buffer; no concurrent reads.
    // Return value is checked (0 = success) and buffer bounds are validated.
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
    if ret != 0 {
        return None; // HeapBuffer::drop 自动释放堆内存
    }

    // ── Bounds check: validate that `dwNumEntries` does not exceed the buffer ──
    let header_size = std::mem::size_of::<u32>();
    if buf.size() < header_size {
        return None;
    }
    let max_entries = buf.size().saturating_sub(header_size) / ROW_SIZE;
    // SAFETY: `buf.as_ptr()` points to a valid, zero-initialized heap buffer of
    // at least `header_size` bytes. Reading the first 4 bytes as `u32` is safe.
    let num_entries = unsafe {
        let ptr = buf.as_ptr() as *const u32;
        std::ptr::read_unaligned(ptr)
    };
    if num_entries as usize > max_entries {
        return None; // 边界检查失败，防止越界读取
    }

    // SAFETY: `buf.as_ptr()` points to a valid heap buffer of `buf.size()` bytes.
    // The iteration is bounded by `num_entries` which was validated against
    // `max_entries` above, ensuring `offset + ROW_SIZE` never exceeds the buffer.
    for i in 0..num_entries as usize {
        let offset = header_size + i * ROW_SIZE;
        // SAFETY: `offset + ROW_SIZE <= buf.size()` is guaranteed by the bounds check above.
        let ptr = unsafe { (buf.as_ptr() as *const u8).add(offset) };
        // SAFETY: Each field read uses `read_unaligned` because the heap buffer
        // may not satisfy the alignment requirements of `u32`.
        let local_addr = unsafe {
            let dw = std::ptr::read_unaligned(ptr as *const u32);
            win_ipv4(dw)
        };
        let local_port = unsafe {
            let dw = std::ptr::read_unaligned(ptr.add(4) as *const u32);
            win_port(dw)
        };
        let pid = unsafe {
            std::ptr::read_unaligned(ptr.add(8) as *const u32)
        };

        if local_addr == src_ip && local_port == src_port {
            return Some(pid);
        }
    }
    None
    // HeapBuffer::drop 自动释放堆内存
}

/// Look up the PID for a TCP/IPv6 flow using GetExtendedTcpTable with AF_INET6.
///
/// MIB_TCP6ROW_OWNER_PID layout (56 bytes total):
///   ucLocalAddr[16]     – local IPv6 address (network byte order)
///   dwLocalScopeId  u32 – scope ID (ignored for matching)
///   dwLocalPort     u32 – big-endian port in low 2 bytes
///   ucRemoteAddr[16]    – remote IPv6 address (network byte order)
///   dwRemoteScopeId u32 – scope ID (ignored for matching)
///   dwRemotePort    u32 – big-endian port in low 2 bytes
///   dwState         u32 – connection state (ignored)
///   dwOwningPid     u32 – owning process ID
#[cfg(windows)]
fn windows_tcp_pid_v6(
    src_ip: std::net::Ipv6Addr,
    src_port: u16,
    dst: SocketAddr,
) -> Option<u32> {
    const ROW_SIZE: usize = 56;
    const AF_INET6: u32 = 23;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    let dst_v6 = match dst.ip() {
        std::net::IpAddr::V6(v6) => v6,
        _ => return None,
    };

    let mut size: u32 = 0;
    // SAFETY: Same two-call pattern as v4 variant. First call with null pointer queries
    // required buffer size. `&mut size` is a valid pointer. No concurrent access.
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if size == 0 {
        return None;
    }

    // Allocate a heap buffer via the RAII wrapper. The buffer is automatically freed
    // when `HeapBuffer` is dropped, eliminating manual `HeapFree` calls on all paths.
    let mut buf = HeapBuffer::allocate(size as usize)?;

    // SAFETY: `buf.as_mut_ptr()` points to a valid buffer of `size` bytes.
    // `GetExtendedTcpTable` writes into this buffer; no concurrent reads.
    // Return value is checked and buffer bounds are validated before iteration.
    let ret = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            0,
            AF_INET6,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if ret != 0 && ret != ERROR_INSUFFICIENT_BUFFER {
        return None; // HeapBuffer::drop 自动释放堆内存
    }

    // ── Bounds check: validate that `dwNumEntries` does not exceed the buffer ──
    let header_size = std::mem::size_of::<u32>();
    if buf.size() < header_size {
        return None;
    }
    let max_entries = buf.size().saturating_sub(header_size) / ROW_SIZE;
    // SAFETY: `buf.as_ptr()` points to a valid, zero-initialized heap buffer of
    // at least `header_size` bytes. Reading the first 4 bytes as `u32` is safe.
    let num_entries = unsafe {
        let ptr = buf.as_ptr() as *const u32;
        std::ptr::read_unaligned(ptr)
    };
    if num_entries as usize > max_entries {
        return None; // 边界检查失败，防止越界读取
    }

    let src_octets: [u8; 16] = src_ip.octets();
    let dst_octets: [u8; 16] = dst_v6.octets();

    // SAFETY: `buf.as_ptr()` points to a valid heap buffer of `buf.size()` bytes.
    // The iteration is bounded by `num_entries` which was validated against
    // `max_entries` above, ensuring `offset + ROW_SIZE` never exceeds the buffer.
    for i in 0..num_entries as usize {
        let offset = header_size + i * ROW_SIZE;
        // SAFETY: `offset + ROW_SIZE <= buf.size()` is guaranteed by the bounds check above.
        let ptr = unsafe { (buf.as_ptr() as *const u8).add(offset) };
        // offsets: local_addr[0..16], local_scope[16..20], local_port[20..24],
        //          remote_addr[24..40], remote_scope[40..44], remote_port[44..48],
        //          state[48..52], pid[52..56]
        // SAFETY: Each field read uses `read_unaligned` because the heap buffer
        // may not satisfy the alignment requirements of `u32`.
        let local_addr = unsafe { std::slice::from_raw_parts(ptr, 16) };
        let local_port = unsafe {
            let dw = std::ptr::read_unaligned(ptr.add(20) as *const u32);
            win_port(dw)
        };
        let remote_addr = unsafe { std::slice::from_raw_parts(ptr.add(24), 16) };
        let remote_port = unsafe {
            let dw = std::ptr::read_unaligned(ptr.add(44) as *const u32);
            win_port(dw)
        };
        let pid = unsafe {
            std::ptr::read_unaligned(ptr.add(52) as *const u32)
        };

        if local_addr == src_octets
            && local_port == src_port
            && remote_addr == dst_octets
            && remote_port == dst.port()
        {
            return Some(pid);
        }
    }
    None
    // HeapBuffer::drop 自动释放堆内存
}

/// Look up the PID for a UDP/IPv6 flow using GetExtendedUdpTable with AF_INET6.
///
/// MIB_UDP6ROW_OWNER_PID layout (28 bytes total):
///   ucLocalAddr[16]     – local IPv6 address (network byte order)
///   dwLocalScopeId  u32 – scope ID (ignored)
///   dwLocalPort     u32 – big-endian port in low 2 bytes
///   dwOwningPid     u32 – owning process ID
#[cfg(windows)]
fn windows_udp_pid_v6(src_ip: std::net::Ipv6Addr, src_port: u16) -> Option<u32> {
    const ROW_SIZE: usize = 28;
    const AF_INET6: u32 = 23;
    const UDP_TABLE_OWNER_PID: u32 = 1;

    let mut size: u32 = 0;
    // SAFETY: Same two-call pattern. First call queries buffer size with null pointer.
    // `&mut size` is a valid pointer; no concurrent access.
    unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }
    if size == 0 {
        return None;
    }

    // Allocate a heap buffer via the RAII wrapper. The buffer is automatically freed
    // when `HeapBuffer` is dropped, eliminating manual `HeapFree` calls on all paths.
    let mut buf = HeapBuffer::allocate(size as usize)?;

    // SAFETY: `buf.as_mut_ptr()` points to a valid buffer of `size` bytes.
    // `GetExtendedUdpTable` writes into this buffer; no concurrent reads.
    // Return value is checked and buffer bounds are validated before iteration.
    let ret = unsafe {
        GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            0,
            AF_INET6,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if ret != 0 {
        return None; // HeapBuffer::drop 自动释放堆内存
    }

    // ── Bounds check: validate that `dwNumEntries` does not exceed the buffer ──
    let header_size = std::mem::size_of::<u32>();
    if buf.size() < header_size {
        return None;
    }
    let max_entries = buf.size().saturating_sub(header_size) / ROW_SIZE;
    // SAFETY: `buf.as_ptr()` points to a valid, zero-initialized heap buffer of
    // at least `header_size` bytes. Reading the first 4 bytes as `u32` is safe.
    let num_entries = unsafe {
        let ptr = buf.as_ptr() as *const u32;
        std::ptr::read_unaligned(ptr)
    };
    if num_entries as usize > max_entries {
        return None; // 边界检查失败，防止越界读取
    }

    let src_octets: [u8; 16] = src_ip.octets();

    // SAFETY: `buf.as_ptr()` points to a valid heap buffer of `buf.size()` bytes.
    // The iteration is bounded by `num_entries` which was validated against
    // `max_entries` above, ensuring `offset + ROW_SIZE` never exceeds the buffer.
    for i in 0..num_entries as usize {
        let offset = header_size + i * ROW_SIZE;
        // SAFETY: `offset + ROW_SIZE <= buf.size()` is guaranteed by the bounds check above.
        let ptr = unsafe { (buf.as_ptr() as *const u8).add(offset) };
        // offsets: local_addr[0..16], local_scope[16..20], local_port[20..24], pid[24..28]
        // SAFETY: Each field read uses `read_unaligned` because the heap buffer
        // may not satisfy the alignment requirements of `u32`.
        let local_addr = unsafe { std::slice::from_raw_parts(ptr, 16) };
        let local_port = unsafe {
            let dw = std::ptr::read_unaligned(ptr.add(20) as *const u32);
            win_port(dw)
        };
        let pid = unsafe {
            std::ptr::read_unaligned(ptr.add(24) as *const u32)
        };

        if local_addr == src_octets && local_port == src_port {
            return Some(pid);
        }
    }
    None
    // HeapBuffer::drop 自动释放堆内存
}

// ──────────────────────────────────────────────────────────────────────────────
// Process name lookup
// On FreeBSD: sysctl(KERN_PROC_PID) via libc (no libkvm/libprocstat needed)
// On Windows: OpenProcess + QueryFullProcessImageNameW via the windows crate
// Everywhere else: sysinfo
// ──────────────────────────────────────────────────────────────────────────────

/// FreeBSD: resolve process name from PID using sysctl(KERN_PROC_PID).
/// This only requires libc and works in Zig cross-compilation environments
/// where libkvm / libprocstat are unavailable.
#[cfg(target_os = "freebsd")]
fn process_name_from_pid(pid: u32) -> Option<String> {
    use libc::{c_int, kinfo_proc, sysctl, CTL_KERN, KERN_PROC, KERN_PROC_PID};
    use std::{ffi::CStr, mem};

    // SAFETY: `sysctl` is a FFI call. `mib` is a properly initialized array of 4 `c_int` values.
    // `&mut info` is a valid, properly aligned pointer to a zero-initialized `kinfo_proc` struct.
    // `len` is set to the correct size of the struct. `sysctl` writes into `info`; no concurrent
    // access occurs. Return value is checked (0 = success) before using the data.
    // `info.ki_comm` is a fixed-size C char array; `CStr::from_ptr` is safe because the array
    // is guaranteed to be NUL-terminated by the kernel.
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

/// Windows: resolve process name from PID using `OpenProcess` +
/// `QueryFullProcessImageNameW`. The process handle is managed by the
/// `ProcessHandle` RAII wrapper, ensuring `CloseHandle` is always called.
#[cfg(windows)]
fn process_name_from_pid(pid: u32) -> Option<String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // SAFETY: `OpenProcess` is a FFI call with valid parameters.
    // `PROCESS_QUERY_LIMITED_INFORMATION` is the minimal access right needed for
    // `QueryFullProcessImageNameW`. The returned handle is wrapped in `ProcessHandle`
    // to ensure it is closed on all paths. A null handle (failure) is handled by
    // `ProcessHandle::drop` which checks `is_invalid()`.
    let handle = unsafe {
        ProcessHandle::new(OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        ))
    };
    if handle.as_raw().is_invalid() {
        return None;
    }

    // SAFETY: `handle` is a valid process handle (checked above).
    // `QueryFullProcessImageNameW` writes the process image path into `buf`.
    // The buffer size is passed as `&mut size` and updated by the function.
    // The return value is checked (nonzero = success) before using the data.
    let name = unsafe {
        let mut buf: [u16; 260] = [0u16; 260]; // MAX_PATH
        let mut size: u32 = buf.len() as u32;
        let ret = windows::Win32::System::ProcessStatus::QueryFullProcessImageNameW(
            *handle.as_raw(),
            windows::Win32::System::ProcessStatus::PROCESS_NAME_WIN32,
            &mut buf,
            &mut size,
        );
        if ret.as_bool() {
            let slice = &buf[..size as usize];
            OsString::from_wide(slice).to_string_lossy().into_owned()
        } else {
            return None;
        }
    };

    let name = name.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
    // ProcessHandle::drop 自动调用 CloseHandle
}

/// All other platforms (Linux, macOS): resolve process name from PID via sysinfo.
#[cfg(not(any(target_os = "freebsd", windows)))]
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

