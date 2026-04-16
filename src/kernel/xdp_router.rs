#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::{xdp, map}, programs::XdpContext};
use aya_bpf::helpers::{bpf_ktime_get_ns, bpf_xdp_adjust_head};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map(name = "ROUTE_TABLE")]
static ROUTE_TABLE: aya_bpf::maps::LpmTrie<u32, u8> = aya_bpf::maps::LpmTrie::with_max_entries(1024, 0);

#[map(name = "TCP_SESSIONS")]
static TCP_SESSIONS: aya_bpf::maps::PerCpuHashMap<u64, TcpSession> = aya_bpf::maps::PerCpuHashMap::with_max_entries(65536, 0);

#[map(name = "UDP_SESSIONS")]
static UDP_SESSIONS: aya_bpf::maps::PerCpuHashMap<u64, UdpSession> = aya_bpf::maps::PerCpuHashMap::with_max_entries(65536, 0);

#[map(name = "PACKET_RING")]
static PACKET_RING: aya_bpf::maps::RingBuf = aya_bpf::maps::RingBuf::with_max_entries(1 << 20, 0);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TcpSession {
    pub src_port: u16,
    pub dst_port: u16,
    pub state: u8,
    pub last_seen: u64,
    pub flags: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UdpSession {
    pub src_port: u16,
    pub dst_port: u16,
    pub last_seen: u64,
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp(name = "tinytun_xdp")]
pub fn tinytun_xdp(ctx: XdpContext) -> u32 {
    match try_tinytun_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_tinytun_xdp(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => handle_ipv4(&ctx, eth_hdr),
        EtherType::Ipv6 => handle_ipv6(&ctx, eth_hdr),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn handle_ipv4(ctx: &XdpContext, eth_hdr: *const EthHdr) -> Result<u32, ()> {
    let ip_hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;

    let dst_addr = unsafe { u32::from_be((*ip_hdr).dst_addr) };
    let proto = unsafe { (*ip_hdr).proto };

    // Lookup routing decision
    let route = ROUTE_TABLE.get(&dst_addr);

    if let Some(route) = route {
        match route {
            0 => {
                // DIRECT: pass to kernel
                return Ok(xdp_action::XDP_PASS);
            },
            1 => {
                // PROXY: forward to userspace via ring buffer
                let start = ctx.data();
                let end = ctx.data_end();
                let len = end - start;

                if let Some(mut buf) = PACKET_RING.reserve::<[u8; 1500]>(0) {
                    unsafe {
                        core::ptr::copy_nonoverlapping(start as *const u8, buf.as_mut_ptr(), len);
                    }
                    buf.submit(len);
                    return Ok(xdp_action::XDP_DROP);
                }
            },
            2 => {
                // BLOCK: drop packet
                return Ok(xdp_action::XDP_DROP);
            },
            _ => {}
        }
    }

    match proto {
        IpProto::Tcp => handle_tcp(ctx, ip_hdr),
        IpProto::Udp => handle_udp(ctx, ip_hdr),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn handle_ipv6(ctx: &XdpContext, eth_hdr: *const EthHdr) -> Result<u32, ()> {
    let ip_hdr: *const Ipv6Hdr = ptr_at(ctx, EthHdr::LEN)?;
    Ok(xdp_action::XDP_PASS)
}

fn handle_tcp(ctx: &XdpContext, ip_hdr: *const Ipv4Hdr) -> Result<u32, ()> {
    let tcp_hdr: *const TcpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    let flow_key = unsafe {
        ((u32::from_be((*ip_hdr).src_addr) as u64) << 32) | u32::from_be((*ip_hdr).dst_addr) as u64
    };

    let now = unsafe { bpf_ktime_get_ns() };

    let session = TCP_SESSIONS.get(&flow_key);
    if session.is_none() {
        let new_session = TcpSession {
            src_port: unsafe { u16::from_be((*tcp_hdr).source) },
            dst_port: unsafe { u16::from_be((*tcp_hdr).dest) },
            state: 0,
            last_seen: now,
            flags: 0,
        };
        TCP_SESSIONS.insert(&flow_key, &new_session, 0).ok();
    }

    Ok(xdp_action::XDP_PASS)
}

fn handle_udp(ctx: &XdpContext, ip_hdr: *const Ipv4Hdr) -> Result<u32, ()> {
    let udp_hdr: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    let flow_key = unsafe {
        ((u32::from_be((*ip_hdr).src_addr) as u64) << 32) | u32::from_be((*ip_hdr).dst_addr) as u64
    };

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}