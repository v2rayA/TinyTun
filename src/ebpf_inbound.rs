//! eBPF-based inbound traffic filter for TinyTun (Linux only).
//!
//! This module loads the pre-compiled `tinytun-ebpf` eBPF object file,
//! populates the BPF maps from the user-supplied [`Config`], and attaches a
//! TC (Traffic Control) egress classifier to the TUN interface.
//!
//! The TC egress hook fires **before** a packet is delivered to the
//! user-space `read()` call on the TUN file descriptor.  The eBPF program
//! therefore filters packets at the kernel level:
//!
//! * **Skip-IP / skip-network** packets are dropped here (they should never
//!   reach the TUN interface anyway because the route-manager adds per-host
//!   bypass routes, but the eBPF acts as a safety net).
//! * **Block-port** packets are dropped.
//! * All other packets are passed to user space for proxying.
//!
//! # Lifecycle
//!
//! ```text
//! EbpfInbound::attach(&config, tun_name)
//!     → load eBPF object
//!     → populate maps from Config::filtering
//!     → qdisc_add_clsact(tun_name)
//!     → tc_prog.attach(tun_name, Egress)
//!     → spawn perf-event reader task
//!     → return EbpfInbound handle
//!
//! EbpfInbound::detach()   (called on shutdown)
//!     → stop perf-event task
//!     → TC link is automatically dropped (detached)
//! ```

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use anyhow::{Context, Result};
use aya::{
    maps::{
        lpm_trie::Key as LpmKey,
        perf::AsyncPerfEventArray,
        HashMap, LpmTrie,
    },
    programs::{
        tc::{self, TcAttachType},
        SchedClassifier,
    },
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use log::{debug, info, warn};
use tinytun_common::{action, PacketEvent};
use tokio::{sync::Notify, task::JoinHandle};

use crate::config::Config;

// ---------------------------------------------------------------------------
// Embedded eBPF object file
// ---------------------------------------------------------------------------

/// The compiled `tinytun-ebpf` ELF object, embedded at build time.
///
/// `aya::include_bytes_aligned!` ensures the byte slice is 32-byte aligned,
/// which is required by aya's ELF loader.
#[cfg(target_os = "linux")]
static TINYTUN_EBPF_BYTES: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tinytun-filter"));

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Handle to an active eBPF TC filter attached to a TUN interface.
///
/// Dropping this value detaches the TC program and stops the perf-event
/// reader task.
pub struct EbpfInbound {
    /// Shared shutdown signal for the perf-event reader task.
    shutdown: Arc<Notify>,
    /// Background task handle for the perf-event reader.
    reader_task: Option<JoinHandle<()>>,
    /// The loaded eBPF object.  Kept alive to maintain the TC link.
    _ebpf: Ebpf,
}

impl EbpfInbound {
    /// Load the eBPF program and attach it to the egress hook of `tun_name`.
    ///
    /// BPF maps are populated from `config.filtering`.  The SOCKS5 proxy
    /// addresses are automatically added to `SKIP_IPS_V4`/`SKIP_IPS_V6` to
    /// prevent routing loops.
    pub async fn attach(config: &Config, tun_name: &str) -> Result<Self> {
        let mut ebpf = Ebpf::load(TINYTUN_EBPF_BYTES)
            .context("failed to load tinytun-ebpf eBPF object")?;

        // Optionally attach the aya log backend for eBPF debug messages.
        if let Err(e) = EbpfLogger::init(&mut ebpf) {
            debug!("eBPF logger not available (kernel may be too old): {e}");
        }

        // --- Populate BPF maps ---
        populate_maps(&mut ebpf, config).context("failed to populate eBPF maps")?;

        // --- Attach TC egress classifier ---
        //
        // The `clsact` qdisc must be added first; if it already exists aya
        // returns `TcError::AlreadyAttached` which we silently ignore.
        match tc::qdisc_add_clsact(tun_name) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to add clsact qdisc to {tun_name}")
                });
            }
        }

        let prog: &mut SchedClassifier = ebpf
            .program_mut("tc_egress")
            .context("eBPF program 'tc_egress' not found")?
            .try_into()
            .context("'tc_egress' is not a SchedClassifier")?;

        prog.load().context("failed to load tc_egress program")?;

        prog.attach(tun_name, TcAttachType::Egress)
            .context("failed to attach tc_egress to TUN egress")?;

        info!(
            "eBPF TC egress filter attached to {}",
            tun_name
        );

        // --- Start perf-event reader task ---
        let shutdown = Arc::new(Notify::new());
        let reader_task = {
            let shutdown = Arc::clone(&shutdown);
            spawn_perf_reader(&mut ebpf, shutdown)?
        };

        Ok(Self {
            shutdown,
            reader_task: Some(reader_task),
            _ebpf: ebpf,
        })
    }

    /// Signal shutdown and wait for the perf-event reader to finish.
    pub async fn detach(mut self) {
        self.shutdown.notify_one();
        if let Some(handle) = self.reader_task.take() {
            let _ = handle.await;
        }
        // `self._ebpf` is dropped here, which releases the TC link fd and
        // automatically detaches the program from the qdisc.
        info!("eBPF TC filter detached");
    }
}

// ---------------------------------------------------------------------------
// Map population
// ---------------------------------------------------------------------------

/// Write the filtering configuration from `config` into the BPF maps.
fn populate_maps(ebpf: &mut Ebpf, config: &Config) -> Result<()> {
    // Build the set of IPs to skip: user-configured list + all proxy addresses.
    let mut skip_ipv4: Vec<Ipv4Addr> = Vec::new();
    let mut skip_ipv6: Vec<Ipv6Addr> = Vec::new();

    for ip in &config.filtering.skip_ips {
        match ip {
            IpAddr::V4(a) => skip_ipv4.push(*a),
            IpAddr::V6(a) => skip_ipv6.push(*a),
        }
    }

    // Auto-add all configured SOCKS5 proxy IPs to prevent loops.
    for proxy in config.all_proxies() {
        match proxy.address.ip() {
            IpAddr::V4(a) => {
                if !skip_ipv4.contains(&a) {
                    skip_ipv4.push(a);
                }
            }
            IpAddr::V6(a) => {
                if !skip_ipv6.contains(&a) {
                    skip_ipv6.push(a);
                }
            }
        }
    }

    // --- SKIP_IPS_V4 ---
    {
        let mut map: HashMap<_, u32, u8> = HashMap::try_from(
            ebpf.map_mut("SKIP_IPS_V4").context("SKIP_IPS_V4 map not found")?,
        )
        .context("SKIP_IPS_V4 map type mismatch")?;

        for addr in &skip_ipv4 {
            let key = u32::from(*addr).to_be();
            map.insert(key, 1u8, 0)
                .with_context(|| format!("SKIP_IPS_V4: insert {addr}"))?;
        }
    }

    // --- SKIP_IPS_V6 ---
    {
        let mut map: HashMap<_, [u8; 16], u8> = HashMap::try_from(
            ebpf.map_mut("SKIP_IPS_V6").context("SKIP_IPS_V6 map not found")?,
        )
        .context("SKIP_IPS_V6 map type mismatch")?;

        for addr in &skip_ipv6 {
            map.insert(addr.octets(), 1u8, 0)
                .with_context(|| format!("SKIP_IPS_V6: insert {addr}"))?;
        }
    }

    // --- SKIP_NETS_V4 ---
    {
        let mut map: LpmTrie<_, u32, u8> = LpmTrie::try_from(
            ebpf.map_mut("SKIP_NETS_V4").context("SKIP_NETS_V4 map not found")?,
        )
        .context("SKIP_NETS_V4 map type mismatch")?;

        for net_str in &config.filtering.skip_networks {
            if let Ok(net) = net_str.parse::<ipnetwork::IpNetwork>() {
                if let IpAddr::V4(addr) = net.network() {
                    // aya's LpmKey::new expects `u32` for the prefix length
                    // even though ipnetwork::IpNetwork::prefix() returns `u8`.
                    let key = LpmKey::new(net.prefix() as u32, u32::from(addr).to_be());
                    map.insert(&key, 1u8, 0)
                        .with_context(|| format!("SKIP_NETS_V4: insert {net_str}"))?;
                }
            } else {
                warn!("eBPF: could not parse skip_network '{}', skipping", net_str);
            }
        }
    }

    // --- SKIP_NETS_V6 ---
    {
        let mut map: LpmTrie<_, [u8; 16], u8> = LpmTrie::try_from(
            ebpf.map_mut("SKIP_NETS_V6").context("SKIP_NETS_V6 map not found")?,
        )
        .context("SKIP_NETS_V6 map type mismatch")?;

        for net_str in &config.filtering.skip_networks {
            if let Ok(net) = net_str.parse::<ipnetwork::IpNetwork>() {
                if let IpAddr::V6(addr) = net.network() {
                    // aya's LpmKey::new expects `u32` for the prefix length.
                    let key = LpmKey::new(net.prefix() as u32, addr.octets());
                    map.insert(&key, 1u8, 0)
                        .with_context(|| format!("SKIP_NETS_V6: insert {net_str}"))?;
                }
            }
        }
    }

    // --- ALLOW_PORTS ---
    {
        let mut map: HashMap<_, u16, u8> = HashMap::try_from(
            ebpf.map_mut("ALLOW_PORTS").context("ALLOW_PORTS map not found")?,
        )
        .context("ALLOW_PORTS map type mismatch")?;

        for &port in &config.filtering.allow_ports {
            map.insert(port, 1u8, 0)
                .with_context(|| format!("ALLOW_PORTS: insert {port}"))?;
        }
    }

    // --- BLOCK_PORTS ---
    {
        let mut map: HashMap<_, u16, u8> = HashMap::try_from(
            ebpf.map_mut("BLOCK_PORTS").context("BLOCK_PORTS map not found")?,
        )
        .context("BLOCK_PORTS map type mismatch")?;

        for &port in &config.filtering.block_ports {
            // Skip any port that is also in allow_ports (allow overrides block).
            if !config.filtering.allow_ports.contains(&port) {
                map.insert(port, 1u8, 0)
                    .with_context(|| format!("BLOCK_PORTS: insert {port}"))?;
            }
        }
    }

    info!(
        "eBPF maps populated: {} skip-IPs (v4), {} skip-IPs (v6), \
         {} skip-nets, {} allow-ports, {} block-ports",
        skip_ipv4.len(),
        skip_ipv6.len(),
        config.filtering.skip_networks.len(),
        config.filtering.allow_ports.len(),
        config.filtering.block_ports.len(),
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Perf-event reader
// ---------------------------------------------------------------------------

/// Spawn a background task that drains the `EVENTS` perf-event array and
/// logs each intercepted packet.
fn spawn_perf_reader(ebpf: &mut Ebpf, shutdown: Arc<Notify>) -> Result<JoinHandle<()>> {
    let cpus = online_cpus().map_err(|e| anyhow::anyhow!("online_cpus: {e:?}"))?;

    let mut perf_array: AsyncPerfEventArray<_> = AsyncPerfEventArray::try_from(
        ebpf.take_map("EVENTS").context("EVENTS map not found")?,
    )
    .context("EVENTS map type mismatch")?;

    let handle = tokio::spawn(async move {
        // Open one ring buffer per CPU.
        let mut cpu_bufs: Vec<_> = cpus
            .iter()
            .filter_map(|&cpu| {
                perf_array
                    .open(cpu, Some(256 * 1024))
                    .map_err(|e| warn!("eBPF: failed to open perf buf for CPU {cpu}: {e}"))
                    .ok()
            })
            .collect();

        if cpu_bufs.is_empty() {
            warn!("eBPF: no perf buffers opened; packet events will not be logged");
            return;
        }

        // Pre-allocate per-event BytesMut buffers large enough for PacketEvent.
        const BUF_COUNT: usize = 64;
        let event_size = std::mem::size_of::<PacketEvent>();
        let mut raw_bufs: Vec<BytesMut> = (0..BUF_COUNT)
            .map(|_| BytesMut::with_capacity(event_size + 256))
            .collect();

        loop {
            let mut any_data = false;
            for buf in cpu_bufs.iter_mut() {
                // Reset buffers before each read.
                for b in raw_bufs.iter_mut() {
                    b.clear();
                    // Reserve at least `event_size` bytes so the kernel can
                    // write into the uninitialised part.
                    if b.capacity() < event_size {
                        b.reserve(event_size);
                    }
                    // SAFETY: We immediately overwrite this memory via the
                    // kernel perf ring write; we only read it after verifying
                    // the read count.
                    unsafe { b.set_len(b.capacity()) };
                }

                match buf.read_events(&mut raw_bufs).await {
                    Ok(info) if info.read > 0 => {
                        any_data = true;
                        for raw in &raw_bufs[..info.read] {
                        if raw.len() >= event_size {
                                // SAFETY: Three conditions are met:
                                // 1. `raw.len() >= event_size` is verified above.
                                // 2. We pre-allocated `event_size + 256` bytes per
                                //    buffer and called `set_len(capacity)`, so the
                                //    kernel's perf ring write has already initialised
                                //    this memory before `read_events` returns.
                                // 3. `PacketEvent` is `#[repr(C)]` with only
                                //    plain-old-data fields; `read_unaligned` handles
                                //    any alignment requirements safely.
                                let ev = unsafe {
                                    (raw.as_ptr() as *const PacketEvent).read_unaligned()
                                };
                                log_event(&ev);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("eBPF perf read error: {e}");
                    }
                }
            }

            // Yield briefly when idle to avoid spinning.
            if !any_data {
                tokio::select! {
                    _ = shutdown.notified() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
                }
            }
        }
    });

    Ok(handle)
}

/// Log a single [`PacketEvent`] from the eBPF program.
fn log_event(ev: &PacketEvent) {
    let dst = Ipv4Addr::from(u32::from_be(ev.dst_ip));
    let proto = match ev.protocol {
        tinytun_common::proto::TCP => "TCP",
        tinytun_common::proto::UDP => "UDP",
        p => {
            debug!("eBPF event: protocol={p} dst={dst} → action={}", ev.action);
            return;
        }
    };
    let action_str = match ev.action {
        action::PROXY => "proxy",
        action::DROP => "drop",
        action::SKIP => "skip",
        _ => "?",
    };
    debug!(
        "eBPF: {proto} dst={}:{} → {action_str}",
        dst, ev.dst_port
    );
}
