// src/ebpf_mode.rs
//
// Linux eBPF transparent-proxy mode.
//
// Architecture
// ============
//
// 1. A compiled eBPF object (two programs: TC egress classifier +
//    sk_lookup) is embedded in the binary at build time.
//
// 2. At runtime the TC classifier is attached to the *egress* path of the
//    configured outbound network interface.  It inspects each outgoing
//    packet and – for any destination that is not in the skip-IP/network
//    lists – sets `skb->mark` to the configured fwmark value.
//
// 3. Two `ip` policy-routing rules are installed (NOT iptables):
//       ip rule  add fwmark <mark> lookup <table>
//       ip route add local default dev lo table <table>
//    Marked packets are therefore re-delivered to the loopback interface,
//    making them look like incoming connections.
//
// 4. The sk_lookup eBPF program is attached to the network namespace.  It
//    runs when the kernel cannot find a listening socket for an incoming
//    TCP connection.  If the packet arrived on loopback (i.e. it was
//    redirected there by step 3) *and* its destination is not in the skip
//    lists, the connection is redirected to TinyTun's own IP_TRANSPARENT
//    listening socket.
//
// 5. TinyTun's IP_TRANSPARENT socket accepts TCP connections whose
//    `getsockname()` returns the *original* destination (e.g. 8.8.8.8:443)
//    thanks to the `IP_TRANSPARENT` socket option.  TinyTun then opens a
//    SOCKS5 connection to that original destination and bridges the two
//    streams.
//
// This design eliminates the need for:
//   • a TUN/TAP device
//   • iptables / nftables (firewall) rules
//   • external bpftool for map management
//   • an external BPF object file on disk

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, Result};
use aya::maps::{lpm_trie::Key, LpmTrie, SockMap};
use aya::programs::{SchedClassifier, SkLookup, TcAttachType};
use aya::Ebpf;
use ipnetwork::IpNetwork;
use log::{info, warn};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::socks5_client::Socks5Client;

// The compiled eBPF object is embedded at build time.
static BPF_OBJECT: &[u8] = include_bytes!(env!("BPF_OBJECT_PATH"));

// Policy-routing priority used for our fwmark rule.
const PRIO: &str = "10020";

/// State kept alive for the duration of the eBPF mode.
pub struct EbpfModeState {
    /// Name of the network interface TC is attached to.
    pub interface: String,
    pub mark: u32,
    pub table_id: u32,
    pub redirect_port: u16,
    // Keep the Bpf handle alive so programs stay loaded.
    _bpf: Ebpf,
    // Keep the listening socket alive so the sockmap reference stays valid.
    _listener: std::net::TcpListener,
}

/// Entry point: set up eBPF, policy routing, transparent proxy listener,
/// then run the accept loop until a shutdown signal is received.
pub async fn run(config: Config) -> Result<()> {
    let state = setup(&config)?;

    info!(
        "Linux eBPF mode active on {} (mark=0x{:x}, table={}, port={})",
        state.interface, state.mark, state.table_id, state.redirect_port
    );

    // Spawn the accept/proxy loop.
    let socks5_config = config.socks5.clone();
    let skip_ips: Vec<IpAddr> = config.filtering.skip_ips.clone();
    let skip_networks: Vec<String> = config.filtering.skip_networks.clone();

    // Build a Tokio listener from the raw fd that is already in the sockmap.
    let raw_fd = state._listener.as_raw_fd();

    // Clone the raw fd into a non-owning duplicate so Tokio can own its copy
    // while `_listener` in `state` keeps the original alive (and the
    // sockmap reference valid).
    let dup_fd = unsafe { libc::dup(raw_fd) };
    if dup_fd < 0 {
        return Err(anyhow!(
            "dup() on transparent listener fd failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let dup_std_listener = unsafe {
        use std::os::unix::io::FromRawFd;
        std::net::TcpListener::from_raw_fd(dup_fd)
    };
    dup_std_listener.set_nonblocking(true)?;
    let tokio_listener = TcpListener::from_std(dup_std_listener)?;

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    let proxy_handle = {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            run_accept_loop(
                tokio_listener,
                socks5_config,
                skip_ips,
                skip_networks,
                shutdown_tx,
            )
            .await
        })
    };

    // Wait for Ctrl-C or an error from the accept loop.
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
        _ = shutdown_rx.recv() => {
            info!("Accept loop terminated, shutting down");
        }
    }

    proxy_handle.abort();
    cleanup_routing(&state);
    info!("Linux eBPF mode shut down");
    Ok(())
}

// ── Setup ──────────────────────────────────────────────────────────────────

fn setup(config: &Config) -> Result<EbpfModeState> {
    let ingress = &config.inbound.linux_ebpf;
    if !ingress.enabled {
        return Err(anyhow!(
            "linux eBPF mode requires inbound.linux_ebpf.enabled = true"
        ));
    }

    // Resolve interface name.
    let interface = if let Some(name) = ingress.interface.clone() {
        name
    } else {
        crate::route_manager::resolve_route_interface(
            config.route.auto_detect_interface,
            config.route.default_interface.as_deref(),
        )?
        .ok_or_else(|| anyhow!("failed to resolve outbound interface for eBPF mode"))?
    };

    // Create the IP_TRANSPARENT TCP listening socket *before* loading BPF
    // so we can store its fd in the sockmap.
    let listener_std = create_transparent_listener(ingress.redirect_port)?;

    // Load the embedded BPF object.
    let mut bpf = Ebpf::load(BPF_OBJECT).map_err(|e| anyhow!("failed to load BPF object: {}", e))?;

    // Populate CONFIG map: [0] = fwmark, [1] = lo ifindex.
    {
        let lo_ifindex = interface_index("lo")?;
        let mut cfg_map: aya::maps::Array<_, u32> = bpf
            .map_mut("CONFIG")
            .ok_or_else(|| anyhow!("BPF map CONFIG not found"))?
            .try_into()
            .map_err(|e| anyhow!("CONFIG map type error: {}", e))?;
        cfg_map
            .set(0, ingress.mark, 0)
            .map_err(|e| anyhow!("failed to set CONFIG[0]: {}", e))?;
        cfg_map
            .set(1, lo_ifindex, 0)
            .map_err(|e| anyhow!("failed to set CONFIG[1]: {}", e))?;
    }

    // Populate SKIP_V4 / SKIP_V6 LPM trie maps.
    populate_skip_maps(&mut bpf, &config.filtering.skip_ips, &config.filtering.skip_networks)?;

    // Store the listening socket in PROXY_SOCK map so sk_lookup can use it.
    {
        let mut sock_map: SockMap<_> = bpf
            .map_mut("PROXY_SOCK")
            .ok_or_else(|| anyhow!("BPF map PROXY_SOCK not found"))?
            .try_into()
            .map_err(|e| anyhow!("PROXY_SOCK map type error: {}", e))?;
        sock_map
            .set(0, &listener_std, 0)
            .map_err(|e| anyhow!("failed to store socket in PROXY_SOCK: {}", e))?;
    }

    // Attach TC egress classifier.
    // Ensure clsact qdisc exists on the interface.
    let _ = Command::new("tc")
        .args(["qdisc", "add", "dev", &interface, "clsact"])
        .output();
    {
        let tc: &mut SchedClassifier = bpf
            .program_mut("tinytun_tc_egress")
            .ok_or_else(|| anyhow!("BPF program tinytun_tc_egress not found"))?
            .try_into()
            .map_err(|e| anyhow!("TC program type error: {}", e))?;
        tc.load()
            .map_err(|e| anyhow!("failed to load TC program: {}", e))?;
        tc.attach(&interface, TcAttachType::Egress)
            .map_err(|e| anyhow!("failed to attach TC egress on {}: {}", interface, e))?;
    }

    // Attach sk_lookup program to the current network namespace.
    {
        use std::fs::File;
        let ns = File::open("/proc/self/ns/net")
            .map_err(|e| anyhow!("failed to open net namespace fd: {}", e))?;
        let sk_lookup: &mut SkLookup = bpf
            .program_mut("tinytun_sk_lookup")
            .ok_or_else(|| anyhow!("BPF program tinytun_sk_lookup not found"))?
            .try_into()
            .map_err(|e| anyhow!("sk_lookup program type error: {}", e))?;
        sk_lookup
            .load()
            .map_err(|e| anyhow!("failed to load sk_lookup program: {}", e))?;
        sk_lookup
            .attach(ns)
            .map_err(|e| anyhow!("failed to attach sk_lookup to netns: {}", e))?;
    }

    // Install policy-routing rules (no iptables).
    install_routing(ingress.mark, ingress.table_id)?;

    Ok(EbpfModeState {
        interface,
        mark: ingress.mark,
        table_id: ingress.table_id,
        redirect_port: ingress.redirect_port,
        _bpf: bpf,
        _listener: listener_std,
    })
}

// ── Transparent listener ───────────────────────────────────────────────────

/// Create a TCP socket with `IP_TRANSPARENT` bound to `0.0.0.0:port`.
/// The `IP_TRANSPARENT` option allows this socket to accept connections
/// whose destination IP is *not* locally assigned – after `sk_lookup`
/// redirects an incoming SYN, the accepted socket's local address will
/// equal the packet's original destination IP:port.
fn create_transparent_listener(port: u16) -> Result<std::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| anyhow!("socket(): {}", e))?;

    sock.set_reuse_address(true)
        .map_err(|e| anyhow!("SO_REUSEADDR: {}", e))?;

    // Enable IP_TRANSPARENT: lets us accept connections for foreign IPs.
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_TRANSPARENT,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(anyhow!(
            "setsockopt(IP_TRANSPARENT): {}",
            std::io::Error::last_os_error()
        ));
    }

    // Also set SO_REUSEPORT so we can restart without waiting.
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        warn!(
            "setsockopt(SO_REUSEPORT) failed (non-fatal): {}",
            std::io::Error::last_os_error()
        );
    }

    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    sock.bind(&addr.into())
        .map_err(|e| anyhow!("bind(0.0.0.0:{}): {}", port, e))?;
    sock.listen(1024)
        .map_err(|e| anyhow!("listen(): {}", e))?;

    let std_listener: std::net::TcpListener = sock.into();
    Ok(std_listener)
}

// ── BPF map helpers ────────────────────────────────────────────────────────

fn populate_skip_maps(
    bpf: &mut Ebpf,
    skip_ips: &[IpAddr],
    skip_networks: &[String],
) -> Result<()> {
    // Collect entries first so we can do two separate borrows of `bpf`.
    let mut v4_entries: Vec<(u32, [u8; 4])> = Vec::new();
    let mut v6_entries: Vec<(u32, [u8; 16])> = Vec::new();

    for ip in skip_ips {
        match ip {
            IpAddr::V4(v4) => v4_entries.push((32, v4.octets())),
            IpAddr::V6(v6) => v6_entries.push((128, v6.octets())),
        }
    }

    for network_str in skip_networks {
        let net = match network_str.parse::<IpNetwork>() {
            Ok(n) => n,
            Err(_) => {
                warn!("Ignoring unparseable skip_network: {}", network_str);
                continue;
            }
        };
        match net {
            IpNetwork::V4(v4net) => {
                v4_entries.push((v4net.prefix() as u32, v4net.ip().octets()));
            }
            IpNetwork::V6(v6net) => {
                v6_entries.push((v6net.prefix() as u32, v6net.ip().octets()));
            }
        }
    }

    // Insert IPv4 entries (borrow ends when the block ends).
    {
        let mut skip_v4: LpmTrie<_, [u8; 4], u8> = bpf
            .map_mut("SKIP_V4")
            .ok_or_else(|| anyhow!("BPF map SKIP_V4 not found"))?
            .try_into()
            .map_err(|e| anyhow!("SKIP_V4 map type error: {}", e))?;
        for (prefix, addr) in &v4_entries {
            skip_v4
                .insert(&Key::new(*prefix, *addr), 1u8, 0)
                .map_err(|e| anyhow!("SKIP_V4 insert: {}", e))?;
        }
    }

    // Insert IPv6 entries.
    {
        let mut skip_v6: LpmTrie<_, [u8; 16], u8> = bpf
            .map_mut("SKIP_V6")
            .ok_or_else(|| anyhow!("BPF map SKIP_V6 not found"))?
            .try_into()
            .map_err(|e| anyhow!("SKIP_V6 map type error: {}", e))?;
        for (prefix, addr) in &v6_entries {
            skip_v6
                .insert(&Key::new(*prefix, *addr), 1u8, 0)
                .map_err(|e| anyhow!("SKIP_V6 insert: {}", e))?;
        }
    }

    Ok(())
}

// ── Policy routing (no iptables) ──────────────────────────────────────────

fn install_routing(mark: u32, table_id: u32) -> Result<()> {
    let mark_hex = format!("0x{:x}", mark);
    let table_s = table_id.to_string();

    // Remove any stale rules/routes from a previous run.
    cleanup_routing_inner(mark, table_id);

    // ip route add local default dev lo table <table>
    run_cmd(
        "ip",
        &[
            "route", "add", "local", "default", "dev", "lo", "table", &table_s,
        ],
        "add local default route to loopback table",
    )?;

    run_cmd(
        "ip",
        &[
            "-6", "route", "add", "local", "default", "dev", "lo", "table", &table_s,
        ],
        "add IPv6 local default route to loopback table",
    )?;

    // ip rule add fwmark <mark> lookup <table>
    run_cmd(
        "ip",
        &[
            "rule", "add", "fwmark", &mark_hex, "lookup", &table_s, "priority", PRIO,
        ],
        "add IPv4 policy rule for proxy fwmark",
    )?;

    run_cmd(
        "ip",
        &[
            "-6",
            "rule",
            "add",
            "fwmark",
            &mark_hex,
            "lookup",
            &table_s,
            "priority",
            PRIO,
        ],
        "add IPv6 policy rule for proxy fwmark",
    )?;

    Ok(())
}

pub fn cleanup_routing(state: &EbpfModeState) {
    cleanup_routing_inner(state.mark, state.table_id);

    // Remove TC classifier.
    let _ = Command::new("tc")
        .args([
            "filter",
            "del",
            "dev",
            &state.interface,
            "egress",
        ])
        .output();
    let _ = Command::new("tc")
        .args(["qdisc", "del", "dev", &state.interface, "clsact"])
        .output();
}

fn cleanup_routing_inner(mark: u32, table_id: u32) {
    let mark_hex = format!("0x{:x}", mark);
    let table_s = table_id.to_string();

    let _ = Command::new("ip")
        .args([
            "rule", "del", "fwmark", &mark_hex, "lookup", &table_s, "priority", PRIO,
        ])
        .output();
    let _ = Command::new("ip")
        .args([
            "-6",
            "rule",
            "del",
            "fwmark",
            &mark_hex,
            "lookup",
            &table_s,
            "priority",
            PRIO,
        ])
        .output();
    let _ = Command::new("ip")
        .args(["route", "flush", "table", &table_s])
        .output();
    let _ = Command::new("ip")
        .args(["-6", "route", "flush", "table", &table_s])
        .output();
}

// ── Accept loop ────────────────────────────────────────────────────────────

async fn run_accept_loop(
    listener: TcpListener,
    socks5_config: crate::config::Socks5Config,
    skip_ips: Vec<IpAddr>,
    skip_networks: Vec<String>,
    _shutdown: mpsc::Sender<()>,
) {
    let socks5 = Socks5Client::new(socks5_config);
    loop {
        match listener.accept().await {
            Ok((stream, _remote)) => {
                // With IP_TRANSPARENT, `local_addr()` on the accepted socket
                // returns the *original* destination IP:port.
                let original_dst = match stream.local_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        warn!("Failed to get local_addr of accepted connection: {}", e);
                        continue;
                    }
                };

                // Secondary safety check: don't proxy skip-listed addresses.
                if should_skip(original_dst.ip(), &skip_ips, &skip_networks) {
                    continue;
                }

                let socks5 = socks5.clone();
                tokio::spawn(async move {
                    if let Err(e) = proxy_tcp(stream, original_dst, socks5).await {
                        log::debug!("TCP proxy error for {}: {}", original_dst, e);
                    }
                });
            }
            Err(e) => {
                warn!("Accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

async fn proxy_tcp(
    mut client: tokio::net::TcpStream,
    original_dst: SocketAddr,
    socks5: Socks5Client,
) -> Result<()> {
    let mut proxy = socks5.connect(original_dst).await?;

    // Bidirectional copy until either side closes.
    let (mut cr, mut cw) = client.split();
    let (mut pr, mut pw) = proxy.split();

    let c2p = tokio::io::copy(&mut cr, &mut pw);
    let p2c = tokio::io::copy(&mut pr, &mut cw);

    tokio::select! {
        res = c2p => {
            if let Err(e) = pw.shutdown().await {
                log::debug!("proxy write shutdown error for {}: {}", original_dst, e);
            }
            res?;
        }
        res = p2c => {
            if let Err(e) = cw.shutdown().await {
                log::debug!("client write shutdown error for {}: {}", original_dst, e);
            }
            res?;
        }
    }

    Ok(())
}

// ── Utilities ─────────────────────────────────────────────────────────────

fn should_skip(ip: IpAddr, skip_ips: &[IpAddr], skip_networks: &[String]) -> bool {
    if skip_ips.contains(&ip) {
        return true;
    }
    for net_str in skip_networks {
        if let Ok(net) = net_str.parse::<IpNetwork>() {
            if net.contains(ip) {
                return true;
            }
        }
    }
    false
}

/// Return the interface index for a named interface.
fn interface_index(name: &str) -> Result<u32> {
    let name_cstr = std::ffi::CString::new(name)
        .map_err(|_| anyhow!("invalid interface name: {}", name))?;
    let idx = unsafe { libc::if_nametoindex(name_cstr.as_ptr()) };
    if idx == 0 {
        Err(anyhow!(
            "interface {} not found: {}",
            name,
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(idx)
    }
}

fn run_cmd(bin: &str, args: &[&str], context: &str) -> Result<()> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| anyhow!("failed to execute {} ({}): {}", bin, context, e))?;
    if out.status.success() {
        return Ok(());
    }
    Err(anyhow!(
        "{} failed ({}): {}",
        bin,
        context,
        String::from_utf8_lossy(&out.stderr)
    ))
}
