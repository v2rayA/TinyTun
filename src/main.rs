mod config;
mod tun_device;
mod socks5_client;
mod dns_handler;
mod packet_processor;
mod error;
mod route_manager;

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use log::{error, info, warn};
use tokio::net::TcpStream;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use crate::config::{Config, DnsRoute, DnsServerEntry, Ipv6Mode};
use crate::tun_device::TunDevice;
use crate::packet_processor::PacketProcessor;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum CliIpv6Mode {
    Auto,
    On,
    Off,
}

impl From<CliIpv6Mode> for Ipv6Mode {
    fn from(value: CliIpv6Mode) -> Self {
        match value {
            CliIpv6Mode::Auto => Ipv6Mode::Auto,
            CliIpv6Mode::On => Ipv6Mode::On,
            CliIpv6Mode::Off => Ipv6Mode::Off,
        }
    }
}

#[derive(Parser)]
#[command(name = "tinytun")]
#[command(about = "A Rust-based tun2socks implementation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the tun2socks proxy
    Run {
        /// Configuration file path
        #[arg(short, long)]
        config: Option<String>,
        
        /// SOCKS5 proxy address
        #[arg(short, long)]
        socks5: Option<String>,
        
        /// DNS server address (repeatable)
        #[arg(long)]
        dns: Vec<String>,

        /// Route for each --dns entry: direct or proxy (repeatable)
        #[arg(long, value_enum)]
        dns_route: Vec<CliDnsRoute>,

        /// Local DNS capture/forward listen port (default from config or built-in default)
        #[arg(long)]
        dns_listen_port: Option<u16>,
        
        /// TUN device name
        #[arg(short, long)]
        interface: Option<String>,
        
        /// TUN device IP address
        #[arg(long)]
        ip: Option<Ipv4Addr>,
        
        /// TUN device netmask
        #[arg(short, long)]
        netmask: Option<Ipv4Addr>,

        /// IPv6 mode: auto enables IPv6 when system IPv6 is available
        #[arg(long, value_enum)]
        ipv6_mode: Option<CliIpv6Mode>,

        /// TUN device IPv6 address
        #[arg(long)]
        ipv6: Option<Ipv6Addr>,

        /// TUN device IPv6 prefix length
        #[arg(long)]
        ipv6_prefix: Option<u8>,

        /// Enable automatic route setup and cleanup
        #[arg(long, default_missing_value = "true", num_args = 0..=1)]
        auto_route: Option<bool>,
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    env_logger::init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Run {
            config,
            socks5,
            dns,
            dns_route,
            dns_listen_port,
            interface,
            ip,
            netmask,
            ipv6_mode,
            ipv6,
            ipv6_prefix,
            auto_route,
        } => {
            let config = load_config(
                config,
                socks5,
                dns,
                dns_route,
                dns_listen_port,
                interface,
                ip,
                netmask,
                ipv6_mode.map(|m| m.into()),
                ipv6,
                ipv6_prefix,
                auto_route,
            )?;
            run_proxy(config).await
        }
    }
}

async fn run_proxy(config: Config) -> Result<()> {
    info!("Starting TinyTun with configuration: {:?}", config);

    preflight_checks(&config).await?;

    let ipv6_enabled = resolve_ipv6_enabled(config.tun.ipv6_mode.clone());
    if ipv6_enabled {
        info!("IPv6 mode resolved to enabled");
    } else {
        info!("IPv6 mode resolved to disabled");
    }
    
    // Create TUN device
    let tun_device = TunDevice::new(
        &config.tun.name,
        config.tun.ip,
        config.tun.netmask,
        if ipv6_enabled { Some(config.tun.ipv6) } else { None },
        config.tun.ipv6_prefix,
    ).await?;
    
    info!("TUN device created: {}", config.tun.name);
    
    // Create packet processor
    let tun_writer = tun_device.get_writer();
    let processor = PacketProcessor::new(config.clone(), tun_writer);

    let mut auto_route_applied = false;
    if config.tun.auto_route {
        if let Err(err) = route_manager::apply_skip_ip_routes(tun_device.name(), &config.filtering.skip_ips) {
            warn!("Failed to apply skip_ip bypass routes: {}", err);
        }

        match route_manager::apply_auto_routes(tun_device.name(), ipv6_enabled) {
            Ok(()) => {
                auto_route_applied = true;
                info!("Automatic routing enabled for interface {}", tun_device.name());
            }
            Err(err) => {
                warn!("Failed to apply automatic routes: {}", err);
            }
        }
    }
    
    // Channel for graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    
    // Start packet processing
    let tun_reader = tun_device.get_reader();
    let processor_handle = tokio::spawn(async move {
        if let Err(e) = processor.process_packets(tun_reader).await {
            error!("Packet processing error: {}", e);
        }
    });
    
    // Handle shutdown signals
    let shutdown_signal = async {
        let _ = signal::ctrl_c().await;
        info!("Received shutdown signal");
    };
    
    tokio::select! {
        _ = shutdown_signal => {
            info!("Shutting down...");
        }
        _ = shutdown_rx.recv() => {
            info!("Shutdown requested");
        }
    }
    
    // Cleanup
    processor_handle.abort();

    if auto_route_applied {
        if let Err(err) = route_manager::cleanup_auto_routes(tun_device.name(), ipv6_enabled) {
            warn!("Failed to cleanup automatic routes: {}", err);
        }

        if let Err(err) = route_manager::cleanup_skip_ip_routes(&config.filtering.skip_ips) {
            warn!("Failed to cleanup skip_ip bypass routes: {}", err);
        }
    }

    tun_device.cleanup().await?;
    
    info!("TinyTun shutdown complete");
    Ok(())
}

fn load_config(
    config_path: Option<String>,
    socks5: Option<String>,
    dns: Vec<String>,
    dns_route: Vec<CliDnsRoute>,
    dns_listen_port: Option<u16>,
    interface: Option<String>,
    ip: Option<Ipv4Addr>,
    netmask: Option<Ipv4Addr>,
    ipv6_mode: Option<Ipv6Mode>,
    ipv6: Option<Ipv6Addr>,
    ipv6_prefix: Option<u8>,
    auto_route: Option<bool>,
) -> Result<Config> {
    let mut config = if let Some(path) = config_path {
        Config::from_file(&path)?
    } else {
        Config::default()
    };
    
    // Override with CLI arguments if provided
    if let Some(socks5_addr) = socks5 {
        config.socks5.address = socks5_addr.parse()?;
    }
    
    if !dns.is_empty() {
        let dns_servers = build_dns_servers_from_cli(&dns, &dns_route)?;
        config.dns.servers = dns_servers;
    }

    if let Some(port) = dns_listen_port {
        config.dns.listen_port = port;
    }
    
    if let Some(name) = interface {
        config.tun.name = name;
    }
    if let Some(v) = ip {
        config.tun.ip = v;
    }
    if let Some(v) = netmask {
        config.tun.netmask = v;
    }
    if let Some(v) = ipv6_mode {
        config.tun.ipv6_mode = v;
    }
    if let Some(v) = ipv6 {
        config.tun.ipv6 = v;
    }
    if let Some(v) = ipv6_prefix {
        config.tun.ipv6_prefix = v;
    }
    if let Some(v) = auto_route {
        config.tun.auto_route = v;
    }

    // Ensure the SOCKS5 proxy IP is never captured by the TUN device (prevents routing loops).
    let proxy_ip = config.socks5.address.ip();
    if !config.should_skip_ip(proxy_ip) {
        config.filtering.skip_ips.push(proxy_ip);
    }
    
    Ok(config)
}

fn build_dns_servers_from_cli(dns: &[String], dns_route: &[CliDnsRoute]) -> Result<Vec<DnsServerEntry>> {
    if dns.is_empty() {
        return Ok(Vec::new());
    }

    let routes: Vec<DnsRoute> = if dns_route.is_empty() {
        vec![DnsRoute::Direct; dns.len()]
    } else if dns_route.len() == 1 && dns.len() > 1 {
        vec![dns_route[0].into(); dns.len()]
    } else if dns_route.len() == dns.len() {
        dns_route.iter().copied().map(Into::into).collect()
    } else {
        return Err(anyhow::anyhow!(
            "--dns and --dns-route count mismatch: got {} dns servers and {} routes",
            dns.len(),
            dns_route.len()
        ));
    };

    let mut out = Vec::with_capacity(dns.len());
    for (idx, dns_addr) in dns.iter().enumerate() {
        out.push(DnsServerEntry {
            address: dns_addr.parse()?,
            route: routes[idx].clone(),
        });
    }

    Ok(out)
}

fn resolve_ipv6_enabled(mode: Ipv6Mode) -> bool {
    match mode {
        Ipv6Mode::On => true,
        Ipv6Mode::Off => false,
        Ipv6Mode::Auto => has_system_ipv6(),
    }
}

fn has_system_ipv6() -> bool {
    std::net::UdpSocket::bind("[::1]:0").is_ok()
}

async fn preflight_checks(config: &Config) -> Result<()> {
    #[cfg(windows)]
    {
        if !has_wintun_runtime() {
            return Err(anyhow::anyhow!(
                "wintun.dll was not found next to tinytun.exe or in PATH. Place wintun.dll in target/release (or target/debug) or add its directory to PATH."
            ));
        }

        if !is_likely_elevated() {
            return Err(anyhow::anyhow!(
                "Windows administrator privileges are required to create a Wintun adapter. Please run the terminal as Administrator and retry."
            ));
        }
    }

    let socks_addr = config.socks5.address;
    let connect_result = timeout(Duration::from_secs(3), TcpStream::connect(socks_addr)).await;
    match connect_result {
        Ok(Ok(_)) => {
            info!("SOCKS5 endpoint {} is reachable", socks_addr);
        }
        Ok(Err(err)) => {
            warn!(
                "SOCKS5 endpoint {} is not reachable yet: {}. Startup will continue, but packet forwarding may fail.",
                socks_addr, err
            );
        }
        Err(_) => {
            warn!(
                "SOCKS5 reachability probe to {} timed out after 3s. Startup will continue.",
                socks_addr
            );
        }
    }

    Ok(())
}

#[cfg(windows)]
fn is_likely_elevated() -> bool {
    // fltmc succeeds only in elevated shells on typical Windows setups.
    std::process::Command::new("fltmc")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn has_wintun_runtime() -> bool {
    use std::env;
    use std::path::PathBuf;

    if let Ok(exe_path) = env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            if exe_dir.join("wintun.dll").exists() {
                return true;
            }
        }
    }

    if let Ok(path_var) = env::var("PATH") {
        for dir in env::split_paths(&path_var) {
            let candidate: PathBuf = dir.join("wintun.dll");
            if candidate.exists() {
                return true;
            }
        }
    }

    false
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum CliDnsRoute {
    Direct,
    Proxy,
}

impl From<CliDnsRoute> for DnsRoute {
    fn from(value: CliDnsRoute) -> Self {
        match value {
            CliDnsRoute::Direct => DnsRoute::Direct,
            CliDnsRoute::Proxy => DnsRoute::Proxy,
        }
    }
}