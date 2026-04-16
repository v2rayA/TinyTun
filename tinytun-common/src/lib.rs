//! Shared types between `tinytun` user-space and the `tinytun-ebpf` eBPF kernel program.
//!
//! This crate is `no_std` so it can be compiled for both the host (user space) and
//! `bpfel-unknown-none` (eBPF kernel space) targets.
#![no_std]

/// Action codes reported in [`PacketEvent`].
pub mod action {
    /// Packet passed through to user-space proxy.
    pub const PROXY: u8 = 1;
    /// Packet dropped (blocked port).
    pub const DROP: u8 = 2;
    /// Packet skipped (matched skip-IP / skip-network list, should not reach TUN).
    pub const SKIP: u8 = 3;
}

/// Protocol numbers carried in [`PacketEvent::protocol`].
pub mod proto {
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
}

/// Default firewall mark placed on packets that should be routed through the
/// TUN device in mark-based routing mode.
pub const DEFAULT_PROXY_MARK: u32 = 0x162;

/// Event emitted by the eBPF TC program to user space via `PerfEventArray`.
///
/// Both user-space and kernel-space structs must be `#[repr(C)]` with the
/// same layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PacketEvent {
    /// Source IPv4 address in **network byte order** (big-endian).
    pub src_ip: u32,
    /// Destination IPv4 address in **network byte order** (big-endian).
    pub dst_ip: u32,
    /// Source port in **host byte order**.
    pub src_port: u16,
    /// Destination port in **host byte order**.
    pub dst_port: u16,
    /// IP protocol number (see [`proto`]).
    pub protocol: u8,
    /// Action taken (see [`action`]).
    pub action: u8,
    /// Padding to align the struct to 4 bytes.
    pub _pad: [u8; 2],
}

// Safety: PacketEvent contains only plain-old-data types.
#[cfg(feature = "aya")]
unsafe impl aya::Pod for PacketEvent {}
