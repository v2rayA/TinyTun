//! eBPF TC (Traffic Control) egress program for tinytun.
//!
//! This program is attached to the **egress** hook of the TUN interface.
//! Packets arriving here are raw IPv4/IPv6 datagrams (no Ethernet header)
//! that the kernel is about to deliver to the user-space `read()` call on
//! the TUN file descriptor.
//!
//! The program enforces the following filtering policy (in order):
//!
//! 1. **Skip-IP list** (`SKIP_IPS_V4` / `SKIP_IPS_V6`): exact destination IP
//!    matches are dropped here.  These packets should never reach the TUN
//!    interface in the first place because the user-space route manager adds
//!    per-host bypass routes for them; this check is a safety net.
//! 2. **Skip-network list** (`SKIP_NETS_V4` / `SKIP_NETS_V6`): CIDR prefix
//!    matches — same rationale as above.
//! 3. **Allow-port override** (`ALLOW_PORTS`): if the destination port is in
//!    this set, the packet is unconditionally forwarded to user space (proxy),
//!    overriding any block-port rule.
//! 4. **Block-port list** (`BLOCK_PORTS`): the packet is dropped.
//! 5. **Default**: forward to user space for proxying.
//!
//! Intercepted packets are reported via the `EVENTS` perf-event array so that
//! user space can log/count them.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{HashMap, LpmTrie, PerfEventArray},
    maps::lpm_trie::Key,
    programs::TcContext,
};
use aya_log_ebpf::debug;
use tinytun_common::{action, proto, PacketEvent};

// ---------------------------------------------------------------------------
// BPF maps (populated by user-space via aya)
// ---------------------------------------------------------------------------

/// Exact IPv4 destination addresses to skip (network byte order).
#[map]
static SKIP_IPS_V4: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// IPv4 CIDR networks to skip.  Key data is the IPv4 address in network byte
/// order; `prefix_len` is the number of bits to match.
#[map]
static SKIP_NETS_V4: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

/// Exact IPv6 destination addresses to skip (16-byte big-endian array).
#[map]
static SKIP_IPS_V6: HashMap<[u8; 16], u8> = HashMap::with_max_entries(512, 0);

/// IPv6 CIDR networks to skip.  Key data is the 16-byte IPv6 address
/// in network byte order; `prefix_len` is the number of bits to match.
#[map]
static SKIP_NETS_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(512, 0);

/// Destination ports that are **always** proxied (override block-port rules).
/// Keyed by port number in host byte order.
#[map]
static ALLOW_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

/// Destination ports whose packets are **dropped** (unless in `ALLOW_PORTS`).
/// Keyed by port number in host byte order.
#[map]
static BLOCK_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

/// Perf-event ring buffer for reporting filtered packets to user space.
#[map]
static EVENTS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const IPPROTO_TCP: u8 = proto::TCP;
const IPPROTO_UDP: u8 = proto::UDP;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// TC egress classifier attached to the TUN interface.
///
/// Returns one of the `TC_ACT_*` constants.
#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(&ctx) {
        Ok(action) => action,
        // On any parse error, pass the packet through so we don't silently
        // break connectivity.
        Err(_) => TC_ACT_OK as i32,
    }
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

fn try_tc_egress(ctx: &TcContext) -> Result<i32, i32> {
    // TUN operates at L3 — packets start directly with the IP header.
    // Read the first byte to determine the IP version.
    let first_byte: u8 = ctx.load(0).map_err(|_| TC_ACT_OK as i32)?;
    let ip_version = first_byte >> 4;

    match ip_version {
        4 => handle_ipv4(ctx),
        6 => handle_ipv6(ctx),
        _ => Ok(TC_ACT_OK as i32),
    }
}

/// Process an IPv4 packet.
fn handle_ipv4(ctx: &TcContext) -> Result<i32, i32> {
    let act_ok = TC_ACT_OK as i32;
    let act_shot = TC_ACT_SHOT as i32;

    // IHL (Internet Header Length) is the lower nibble of byte 0, in 32-bit words.
    let ihl_byte: u8 = ctx.load(0).map_err(|_| act_ok)?;
    let ihl = ((ihl_byte & 0x0F) as usize) * 4;
    if ihl < 20 {
        // Malformed IP header — pass through.
        return Ok(act_ok);
    }

    // Protocol is at offset 9 in the IPv4 header.
    let protocol: u8 = ctx.load(9).map_err(|_| act_ok)?;

    // Destination IP is at offset 16, stored in network byte order (big-endian).
    let dst_ip_be: u32 = ctx.load(16).map_err(|_| act_ok)?;

    // --- 1. Skip-IP exact match ---
    if unsafe { SKIP_IPS_V4.get(&dst_ip_be).is_some() } {
        debug!(ctx, "ebpf: ipv4 skip-ip {:i} -> drop", u32::from_be(dst_ip_be));
        emit_event(ctx, dst_ip_be, 0, 0, protocol, action::SKIP);
        return Ok(act_shot);
    }

    // --- 2. Skip-network LPM match ---
    // Use prefix_len = 32 to perform a longest-prefix lookup.
    let lpm_key = Key::new(32, dst_ip_be);
    if SKIP_NETS_V4.get(&lpm_key).is_some() {
        debug!(ctx, "ebpf: ipv4 skip-net {:i} -> drop", u32::from_be(dst_ip_be));
        emit_event(ctx, dst_ip_be, 0, 0, protocol, action::SKIP);
        return Ok(act_shot);
    }

    // --- 3 & 4. Port-based filtering (TCP/UDP only) ---
    if protocol == IPPROTO_TCP || protocol == IPPROTO_UDP {
        // Destination port is the second 16-bit field of the transport header,
        // i.e. at offset `ihl + 2` from the start of the IP packet.
        let dst_port_be: u16 = ctx.load(ihl + 2).map_err(|_| act_ok)?;
        let dst_port = u16::from_be(dst_port_be);

        // Source port is the first 16-bit field.
        let src_port_be: u16 = ctx.load(ihl).map_err(|_| act_ok)?;
        let src_port = u16::from_be(src_port_be);

        // Allow-port overrides block-port.
        if unsafe { ALLOW_PORTS.get(&dst_port).is_some() } {
            debug!(ctx, "ebpf: ipv4 allow-port {} -> proxy", dst_port);
            emit_event(ctx, dst_ip_be, src_port, dst_port, protocol, action::PROXY);
            return Ok(act_ok);
        }

        // Block-port: drop the packet.
        if unsafe { BLOCK_PORTS.get(&dst_port).is_some() } {
            debug!(ctx, "ebpf: ipv4 block-port {} -> drop", dst_port);
            emit_event(ctx, dst_ip_be, src_port, dst_port, protocol, action::DROP);
            return Ok(act_shot);
        }

        // Default: proxy.
        emit_event(ctx, dst_ip_be, src_port, dst_port, protocol, action::PROXY);
    }

    Ok(act_ok)
}

/// Process an IPv6 packet.
fn handle_ipv6(ctx: &TcContext) -> Result<i32, i32> {
    let act_ok = TC_ACT_OK as i32;
    let act_shot = TC_ACT_SHOT as i32;

    // IPv6 fixed header is 40 bytes.
    // Next header (protocol) is at offset 6.
    let protocol: u8 = ctx.load(6).map_err(|_| act_ok)?;

    // Destination address is at offset 24 (16 bytes).
    let dst_addr: [u8; 16] = ctx.load(24).map_err(|_| act_ok)?;

    // --- 1. Skip-IP exact match ---
    if unsafe { SKIP_IPS_V6.get(&dst_addr).is_some() } {
        emit_event_v6(ctx, &dst_addr, 0, 0, protocol, action::SKIP);
        return Ok(act_shot);
    }

    // --- 2. Skip-network LPM match ---
    let lpm_key = Key::new(128, dst_addr);
    if SKIP_NETS_V6.get(&lpm_key).is_some() {
        emit_event_v6(ctx, &dst_addr, 0, 0, protocol, action::SKIP);
        return Ok(act_shot);
    }

    // --- 3 & 4. Port-based filtering (TCP/UDP only; skip IPv6 extension headers) ---
    if protocol == IPPROTO_TCP || protocol == IPPROTO_UDP {
        // Assumes no extension headers — transport header starts at offset 40.
        const IPV6_HDR_LEN: usize = 40;
        let dst_port_be: u16 = ctx.load(IPV6_HDR_LEN + 2).map_err(|_| act_ok)?;
        let dst_port = u16::from_be(dst_port_be);

        let src_port_be: u16 = ctx.load(IPV6_HDR_LEN).map_err(|_| act_ok)?;
        let src_port = u16::from_be(src_port_be);

        if unsafe { ALLOW_PORTS.get(&dst_port).is_some() } {
            emit_event_v6(ctx, &dst_addr, src_port, dst_port, protocol, action::PROXY);
            return Ok(act_ok);
        }

        if unsafe { BLOCK_PORTS.get(&dst_port).is_some() } {
            emit_event_v6(ctx, &dst_addr, src_port, dst_port, protocol, action::DROP);
            return Ok(act_shot);
        }
    }

    Ok(act_ok)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Emit an IPv4 packet event to the perf-event ring buffer.
#[inline(always)]
fn emit_event(
    ctx: &TcContext,
    dst_ip_be: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    action: u8,
) {
    let event = PacketEvent {
        src_ip: 0,
        dst_ip: dst_ip_be,
        src_port,
        dst_port,
        protocol,
        action,
        _pad: [0; 2],
    };
    EVENTS.output(ctx, &event, 0);
}

/// Emit an IPv6 packet event.  The destination address is truncated to the
/// first 4 bytes (upper 32 bits) so it fits in the `u32` field.
#[inline(always)]
fn emit_event_v6(
    ctx: &TcContext,
    dst_addr: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    action: u8,
) {
    let dst_prefix = u32::from_be_bytes([dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]]);
    let event = PacketEvent {
        src_ip: 0,
        dst_ip: dst_prefix,
        src_port,
        dst_port,
        protocol,
        action,
        _pad: [0; 2],
    };
    EVENTS.output(ctx, &event, 0);
}

// ---------------------------------------------------------------------------
// Panic handler (required for no_std)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // The BPF verifier does not allow infinite loops, but this is unreachable
    // in practice because the Rust eBPF target never generates real panics.
    unsafe { core::hint::unreachable_unchecked() }
}
