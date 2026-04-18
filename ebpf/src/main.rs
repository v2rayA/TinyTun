//! TinyTun eBPF process-exclusion programs.
//!
//! Design mirrors dae (daeuniverse/dae):
//!
//! ## cgroup hooks  →  cookie_pid_map
//!
//! Six cgroup BPF programs fire at socket lifecycle events (create, connect,
//! sendmsg, …).  Each hook reads the current task's argv[0] basename (≤ 16
//! bytes, same as TASK_COMM_LEN) and stores it in an LRU hash map keyed by
//! the socket cookie:
//!
//!   cookie_pid_map : BPF_MAP_TYPE_LRU_HASH
//!     key  : u64  (socket cookie)
//!     value: [u8; 16]  (process name, NUL-padded)
//!
//! ## TC egress hook  →  per-packet routing
//!
//! A TC classifier attached to the WAN interface reads the socket cookie of
//! each outbound skb, looks up the pname in cookie_pid_map, then consults a
//! second map that the user-space loader populates with the list of excluded
//! process names:
//!
//!   exclude_procs_map : BPF_MAP_TYPE_HASH
//!     key  : [u8; 16]  (process name, NUL-padded)
//!     value: u8  (1 = excluded)
//!
//! If the pname is in exclude_procs_map the packet is returned with
//! TC_ACT_OK (pass through without TUN redirect).  Otherwise it falls through
//! to the normal TUN redirect path.
//!
//! The user-space loader in `src/ebpf_loader.rs` is responsible for:
//!   1. Loading this object file (embedded via `include_bytes!`).
//!   2. Attaching cgroup programs to the cgroupv2 root.
//!   3. Attaching the TC classifier to the WAN interface egress.
//!   4. Keeping exclude_procs_map in sync with config changes.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE},
    helpers::{
        bpf_get_current_task, bpf_get_socket_cookie, bpf_probe_read_kernel,
        bpf_probe_read_user_str_bytes,
    },
    macros::{cgroup_sock, cgroup_sock_addr, map, tc_classifier},
    maps::{LruHashMap, HashMap},
    programs::{SkBuff, SockContext, SockAddrContext},
};

// ── BPF Maps ─────────────────────────────────────────────────────────────────

/// Maps socket cookie → process name (basename of argv[0], max 16 bytes).
/// Populated by cgroup hooks at connect()/sendmsg() time so the mapping is
/// ready before the first packet hits the TC hook.
#[map]
static COOKIE_PNAME_MAP: LruHashMap<u64, [u8; 16]> =
    LruHashMap::with_max_entries(65536, 0);

/// Set of excluded process names.  Populated by user-space from the config.
/// Key = NUL-padded process name (16 bytes), value = 1u8.
#[map]
static EXCLUDE_PROCS_MAP: HashMap<[u8; 16], u8> =
    HashMap::with_max_entries(256, 0);

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read the argv[0] basename of the current task into `buf`.
/// Mirrors dae's `get_pid_pname` kernel helper.
#[inline(always)]
unsafe fn read_current_pname(buf: &mut [u8; 16]) {
    // task_struct → mm_struct → arg_start  (pointer to argv[0] string)
    let task = bpf_get_current_task() as *const aya_ebpf::bindings::task_struct;

    // Read task->mm
    let mm_ptr: *const aya_ebpf::bindings::mm_struct =
        match bpf_probe_read_kernel(&(*task).mm) {
            Ok(p) => p,
            Err(_) => return,
        };
    if mm_ptr.is_null() {
        return;
    }

    // Read mm->arg_start
    let arg_start: u64 = match bpf_probe_read_kernel(&(*mm_ptr).arg_start) {
        Ok(v) => v,
        Err(_) => return,
    };
    if arg_start == 0 {
        return;
    }

    // Read up to 64 bytes of argv[0] from user memory
    let mut argv0 = [0u8; 64];
    let _ = bpf_probe_read_user_str_bytes(arg_start as *const u8, &mut argv0);

    // Extract basename: find the last '/' and copy up to 16 bytes after it
    let mut start = 0usize;
    for i in 0..64usize {
        if argv0[i] == b'/' {
            start = i + 1;
        }
        if argv0[i] == 0 {
            break;
        }
    }
    let mut i = 0usize;
    while i < 16 {
        let c = argv0[start + i];
        if c == 0 || start + i >= 64 {
            break;
        }
        buf[i] = c;
        i += 1;
    }
    // remaining bytes stay zero (buf is already zeroed)
}

/// Insert or refresh the cookie → pname mapping for the current socket.
#[inline(always)]
unsafe fn update_cookie_pname(cookie: u64) {
    let mut pname = [0u8; 16];
    read_current_pname(&mut pname);
    if pname[0] == 0 {
        return; // could not determine process name, skip
    }
    let _ = COOKIE_PNAME_MAP.insert(&cookie, &pname, 0);
}

// ── cgroup/sock_create ────────────────────────────────────────────────────────

/// Record pname when a new socket is created.
#[cgroup_sock(sock_create)]
pub fn cg_sock_create(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut _) };
    unsafe { update_cookie_pname(cookie) };
    0
}

// ── cgroup/connect4 & connect6 ────────────────────────────────────────────────

/// Refresh pname at connect() so UDP sockets that are only sendmsg-ed also
/// get an up-to-date entry (the socket may have been created by a different
/// thread / exec context).
#[cgroup_sock_addr(connect4)]
pub fn cg_connect4(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut _) };
    unsafe { update_cookie_pname(cookie) };
    1 // SockAddr hooks must return 1 (allow)
}

#[cgroup_sock_addr(connect6)]
pub fn cg_connect6(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut _) };
    unsafe { update_cookie_pname(cookie) };
    1
}

// ── cgroup/sendmsg4 & sendmsg6 ────────────────────────────────────────────────

/// For UDP, sendmsg() is the point at which a datagram is associated with a
/// destination.  Refresh the mapping here as well.
#[cgroup_sock_addr(sendmsg4)]
pub fn cg_sendmsg4(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut _) };
    unsafe { update_cookie_pname(cookie) };
    1
}

#[cgroup_sock_addr(sendmsg6)]
pub fn cg_sendmsg6(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut _) };
    unsafe { update_cookie_pname(cookie) };
    1
}

// ── cgroup/sock_release ───────────────────────────────────────────────────────

/// Clean up the mapping when a socket is released to avoid cookie reuse
/// collisions in the LRU map.
#[cgroup_sock(post_bind4)]
pub fn cg_sock_release(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut _) };
    let _ = unsafe { COOKIE_PNAME_MAP.remove(&cookie) };
    0
}

// ── TC egress classifier ──────────────────────────────────────────────────────

/// Attached to the WAN interface's egress TC queue.
///
/// Decision logic:
///   1. Look up the skb's socket cookie in COOKIE_PNAME_MAP.
///   2. If the pname is found in EXCLUDE_PROCS_MAP → TC_ACT_OK (direct pass,
///      packet is NOT redirected into the TUN device).
///   3. Otherwise → TC_ACT_PIPE (continue to the next TC action, which is
///      the TUN redirect installed by the main tinytun setup).
///
/// This mirrors dae's `do_tproxy_wan_egress` routing decision: excluded
/// processes' packets never enter user space — zero overhead direct path.
#[tc_classifier]
pub fn tc_egress(ctx: SkBuff) -> i32 {
    // bpf_get_socket_cookie on an skb may return 0 for non-socket packets
    // (e.g. kernel-generated ICMP); pass those through untouched.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut _) };
    if cookie == 0 {
        return TC_ACT_PIPE as i32;
    }

    // Look up the process name for this socket.
    let pname = match unsafe { COOKIE_PNAME_MAP.get(&cookie) } {
        Some(p) => *p,
        None => return TC_ACT_PIPE as i32, // no mapping → proxy as normal
    };

    // Check whether this process is excluded.
    if unsafe { EXCLUDE_PROCS_MAP.get(&pname) }.is_some() {
        // Excluded: let the packet pass directly on the physical interface.
        // The kernel will route it via the normal routing table, bypassing
        // the TUN redirect rule.
        return TC_ACT_OK as i32;
    }

    TC_ACT_PIPE as i32
}

// ── panic handler (required for no_std) ──────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
