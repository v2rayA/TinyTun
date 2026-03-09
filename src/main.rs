mod config;
mod tun_device;
mod socks5_client;
mod dns_handler;
mod packet_processor;
mod error;
mod route_manager;
mod process_lookup;
mod dns_hijack;
mod ebpf_ingress;
#[cfg(target_os = "linux")]
mod ebpf_mode;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use env_logger::Builder;
use log::{error, info, warn, LevelFilter};
use tokio::net::TcpStream;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Duration};

use crate::config::{Config, DnsRoute, DnsServerEntry, InboundMode, Ipv6Mode, LogLevel};
use crate::dns_hijack::DnsHijackState;
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

        /// Log level: debug, info, warning, error, none
        #[arg(long, value_enum)]
        loglevel: Option<CliLogLevel>,
        
        /// SOCKS5 proxy address
        #[arg(short, long)]
        socks5: Option<String>,

        /// SOCKS5 username
        #[arg(long)]
        socks5_username: Option<String>,

        /// SOCKS5 password
        #[arg(long)]
        socks5_password: Option<String>,

        /// Use SOCKS5 path for DNS where applicable
        #[arg(long, default_missing_value = "true", num_args = 0..=1)]
        socks5_dns_over_socks5: Option<bool>,
        
        /// DNS server address (repeatable)
        #[arg(long)]
        dns: Vec<String>,

        /// Route for each --dns entry: direct or proxy (repeatable)
        #[arg(long, value_enum)]
        dns_route: Vec<CliDnsRoute>,

        /// Local DNS capture/forward listen port (default from config or built-in default)
        #[arg(long)]
        dns_listen_port: Option<u16>,

        /// DNS upstream timeout in milliseconds
        #[arg(long)]
        dns_timeout_ms: Option<u64>,

        /// Enable DNS hijack
        #[arg(long, default_missing_value = "true", num_args = 0..=1)]
        dns_hijack_enabled: Option<bool>,

        /// DNS hijack firewall mark (Linux)
        #[arg(long)]
        dns_hijack_mark: Option<u32>,

        /// DNS hijack routing table id (Linux)
        #[arg(long)]
        dns_hijack_table_id: Option<u32>,

        /// Capture TCP/53 in DNS hijack
        #[arg(long, default_missing_value = "true", num_args = 0..=1)]
        dns_hijack_capture_tcp: Option<bool>,
        
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

        /// TUN MTU
        #[arg(long)]
        mtu: Option<u32>,

        /// Skip IPs from proxy handling (repeatable)
        #[arg(long = "skip-ip")]
        skip_ip: Vec<IpAddr>,

        /// Skip CIDR networks from proxy handling (repeatable)
        #[arg(long = "skip-network")]
        skip_network: Vec<String>,

        /// Block destination ports (repeatable)
        #[arg(long = "block-port")]
        block_port: Vec<u16>,

        /// Allow destination ports (repeatable)
        #[arg(long = "allow-port")]
        allow_port: Vec<u16>,

        /// Process names to exclude from proxy handling (repeatable)
        #[arg(long = "exclude-process")]
        exclude_process: Vec<String>,

        /// Linux process lookup backend: auto, ss, or ebpf
        #[arg(long)]
        linux_process_backend: Option<String>,

        /// Linux eBPF flow cache file path (used when backend is auto/ebpf)
        #[arg(long)]
        linux_ebpf_cache_path: Option<String>,

        /// Inbound traffic capture mode: tun or linux-ebpf
        #[arg(long, value_enum)]
        inbound_mode: Option<CliInboundMode>,

        /// Enable Linux eBPF ingress mode settings
        #[arg(long, default_missing_value = "true", num_args = 0..=1)]
        linux_ebpf_ingress_enabled: Option<bool>,

        /// Linux ingress interface for eBPF attach (auto when omitted)
        #[arg(long)]
        linux_ebpf_ingress_interface: Option<String>,

        /// Linux eBPF ingress fwmark value
        #[arg(long)]
        linux_ebpf_ingress_mark: Option<u32>,

        /// Linux eBPF ingress policy routing table id
        #[arg(long)]
        linux_ebpf_ingress_table_id: Option<u32>,

        /// Linux eBPF ingress redirect target port (internal transparent listener)
        #[arg(long)]
        linux_ebpf_ingress_redirect_port: Option<u16>,

        /// Redirect TCP in Linux eBPF mode
        #[arg(long, default_missing_value = "true", num_args = 0..=1)]
        linux_ebpf_ingress_redirect_tcp: Option<bool>,

        /// Redirect UDP in Linux eBPF mode
        #[arg(long, default_missing_value = "true", num_args = 0..=1)]
        linux_ebpf_ingress_redirect_udp: Option<bool>,

        /// Auto-detect outbound physical interface for bypass routes
        #[arg(long, default_missing_value = "true", num_args = 0..=1)]
        auto_detect_interface: Option<bool>,

        /// Manually specify outbound physical interface for bypass routes
        #[arg(long)]
        default_interface: Option<String>,
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Run {
            config,
            loglevel,
            socks5,
            socks5_username,
            socks5_password,
            socks5_dns_over_socks5,
            dns,
            dns_route,
            dns_listen_port,
            dns_timeout_ms,
            dns_hijack_enabled,
            dns_hijack_mark,
            dns_hijack_table_id,
            dns_hijack_capture_tcp,
            interface,
            ip,
            netmask,
            ipv6_mode,
            ipv6,
            ipv6_prefix,
            auto_route,
            mtu,
            skip_ip,
            skip_network,
            block_port,
            allow_port,
            exclude_process,
            linux_process_backend,
            linux_ebpf_cache_path,
            inbound_mode,
            linux_ebpf_ingress_enabled,
            linux_ebpf_ingress_interface,
            linux_ebpf_ingress_mark,
            linux_ebpf_ingress_table_id,
            linux_ebpf_ingress_redirect_port,
            linux_ebpf_ingress_redirect_tcp,
            linux_ebpf_ingress_redirect_udp,
            auto_detect_interface,
            default_interface,
        } => {
            let config = load_config(
                config,
                loglevel.map(Into::into),
                socks5,
                socks5_username,
                socks5_password,
                socks5_dns_over_socks5,
                dns,
                dns_route,
                dns_listen_port,
                dns_timeout_ms,
                dns_hijack_enabled,
                dns_hijack_mark,
                dns_hijack_table_id,
                dns_hijack_capture_tcp,
                interface,
                ip,
                netmask,
                ipv6_mode.map(|m| m.into()),
                ipv6,
                ipv6_prefix,
                auto_route,
                mtu,
                skip_ip,
                skip_network,
                block_port,
                allow_port,
                exclude_process,
                linux_process_backend,
                linux_ebpf_cache_path,
                inbound_mode.map(Into::into),
                linux_ebpf_ingress_enabled,
                linux_ebpf_ingress_interface,
                linux_ebpf_ingress_mark,
                linux_ebpf_ingress_table_id,
                linux_ebpf_ingress_redirect_port,
                linux_ebpf_ingress_redirect_tcp,
                linux_ebpf_ingress_redirect_udp,
                auto_detect_interface,
                default_interface,
            )?;
            init_logging(config.log.loglevel.clone());
            run_proxy(config).await
        }
    }
}

async fn run_proxy(config: Config) -> Result<()> {
    info!("Starting TinyTun with configuration: {:?}", config);

    preflight_checks(&config).await?;

    if matches!(config.inbound.mode, InboundMode::LinuxEbpf) {
        return run_linux_ebpf_mode(config).await;
    }

    let ipv6_enabled = resolve_ipv6_enabled(config.tun.ipv6_mode.clone());
    if ipv6_enabled {
        info!("IPv6 mode resolved to enabled");
    } else {
        info!("IPv6 mode resolved to disabled");
    }
    
    // Apply skip routes BEFORE creating TUN device to ensure specific IPs are routed to physical port
    let mut auto_route_applied = false;
    let mut skip_ip_routes_applied = false;
    let mut skip_network_routes_applied = false;
    let mut selected_outbound_interface: Option<String> = None;
    if config.tun.auto_route {
        selected_outbound_interface = route_manager::resolve_route_interface(
            config.route.auto_detect_interface,
            config.route.default_interface.as_deref(),
        )?;

        if let Some(interface) = &selected_outbound_interface {
            info!("Using outbound interface for bypass routes: {}", interface);
        }

        if let Err(err) = route_manager::apply_skip_ip_routes(
            &config.filtering.skip_ips,
            selected_outbound_interface.as_deref(),
        ) {
            return Err(anyhow!(
                "failed to apply skip_ip bypass routes while auto_route is enabled: {}",
                err
            ));
        }
        skip_ip_routes_applied = true;

        if let Err(err) = route_manager::apply_skip_network_routes(
            &config.filtering.skip_networks,
            selected_outbound_interface.as_deref(),
        ) {
            let _ = route_manager::cleanup_skip_ip_routes(&config.filtering.skip_ips);
            return Err(anyhow!(
                "failed to apply skip_network bypass routes while auto_route is enabled: {}",
                err
            ));
        }
        skip_network_routes_applied = true;
    }
    
    // Create TUN device
    let tun_device = match TunDevice::new(
        &config.tun.name,
        config.tun.ip,
        config.tun.netmask,
        if ipv6_enabled { Some(config.tun.ipv6) } else { None },
        config.tun.ipv6_prefix,
        config.tun.auto_route,
    ).await {
        Ok(device) => device,
        Err(err) => {
            if skip_network_routes_applied {
                let _ = route_manager::cleanup_skip_network_routes(&config.filtering.skip_networks);
            }
            if skip_ip_routes_applied {
                let _ = route_manager::cleanup_skip_ip_routes(&config.filtering.skip_ips);
            }
            return Err(err);
        }
    };
    
    info!("TUN device created: {}", config.tun.name);
    
    // Create packet processor
    let tun_writer = tun_device.get_writer();
    let processor = PacketProcessor::new(
        config.clone(),
        tun_writer,
        selected_outbound_interface.clone(),
    );
    let dynamic_bypass_ips_handle = processor.dynamic_bypass_ips_handle();

    // Apply automatic routes after TUN device is created
    if config.tun.auto_route {
        match route_manager::apply_auto_routes(tun_device.name(), ipv6_enabled) {
            Ok(()) => {
                auto_route_applied = true;
                info!("Automatic routing enabled for interface {}", tun_device.name());
            }
            Err(err) => {
                if skip_network_routes_applied {
                    let _ = route_manager::cleanup_skip_network_routes(&config.filtering.skip_networks);
                }
                if skip_ip_routes_applied {
                    let _ = route_manager::cleanup_skip_ip_routes(&config.filtering.skip_ips);
                }
                tun_device.cleanup().await?;
                return Err(anyhow!(
                    "failed to apply automatic routes while auto_route is enabled: {}",
                    err
                ));
            }
        }
    }

    let mut dns_hijack_state: Option<DnsHijackState> = None;
    if config.dns.hijack.enabled {
        match dns_hijack::apply_dns_hijack(&config, tun_device.name()) {
            Ok(state) => {
                dns_hijack_state = state;
                info!(
                    "DNS hijack enabled (mark=0x{:x}, table={})",
                    config.dns.hijack.mark,
                    config.dns.hijack.table_id
                );
            }
            Err(err) => {
                if auto_route_applied {
                    let _ = route_manager::cleanup_auto_routes(tun_device.name(), ipv6_enabled);
                }
                if skip_network_routes_applied {
                    let _ = route_manager::cleanup_skip_network_routes(&config.filtering.skip_networks);
                }
                if skip_ip_routes_applied {
                    let _ = route_manager::cleanup_skip_ip_routes(&config.filtering.skip_ips);
                }
                tun_device.cleanup().await?;
                return Err(anyhow!("failed to apply DNS hijack: {}", err));
            }
        }
    }
    
    // Channel for graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<String>(1);

    let mut interface_monitor_handle = None;
    if config.tun.auto_route {
        if let Some(interface_name) = selected_outbound_interface.clone() {
            let shutdown_tx = shutdown_tx.clone();
            let skip_ips = config.filtering.skip_ips.clone();
            let skip_networks = config.filtering.skip_networks.clone();
            let auto_detect_interface = config.route.auto_detect_interface;
            let dynamic_bypass_ips_handle = dynamic_bypass_ips_handle.clone();

            interface_monitor_handle = Some(tokio::spawn(async move {
                let mut active_interface = interface_name;

                loop {
                    sleep(Duration::from_secs(5)).await;

                    let active_for_check = active_interface.clone();
                    let routable = match tokio::task::spawn_blocking(move || {
                        route_manager::is_interface_routable(&active_for_check)
                    })
                    .await
                    {
                        Ok(Ok(v)) => v,
                        Ok(Err(err)) => {
                            warn!(
                                "Failed to check interface routability for {}: {}",
                                active_interface, err
                            );
                            continue;
                        }
                        Err(err) => {
                            warn!(
                                "Interface routability check task failed for {}: {}",
                                active_interface, err
                            );
                            continue;
                        }
                    };

                    if routable {
                        continue;
                    }

                    if auto_detect_interface {
                        match tokio::task::spawn_blocking(|| {
                            route_manager::resolve_route_interface(true, None)
                        })
                        .await
                        {
                            Ok(Ok(Some(new_interface))) => {
                                if new_interface == active_interface {
                                    continue;
                                }

                                warn!(
                                    "Outbound interface {} is gone, switching bypass routes to {}",
                                    active_interface, new_interface
                                );

                                let skip_networks_for_cleanup = skip_networks.clone();
                                let skip_ips_for_cleanup = skip_ips.clone();
                                let _ = tokio::task::spawn_blocking(move || {
                                    let _ = route_manager::cleanup_skip_network_routes(&skip_networks_for_cleanup);
                                    let _ = route_manager::cleanup_skip_ip_routes(&skip_ips_for_cleanup);
                                })
                                .await;

                                let skip_ips_for_apply = skip_ips.clone();
                                let skip_networks_for_apply = skip_networks.clone();
                                let apply_iface = new_interface.clone();
                                let apply_result = match tokio::task::spawn_blocking(move || {
                                    route_manager::apply_skip_ip_routes(
                                        &skip_ips_for_apply,
                                        Some(apply_iface.as_str()),
                                    )
                                    .and_then(|_| {
                                        route_manager::apply_skip_network_routes(
                                            &skip_networks_for_apply,
                                            Some(apply_iface.as_str()),
                                        )
                                    })
                                })
                                .await
                                {
                                    Ok(result) => result,
                                    Err(err) => {
                                        Err(anyhow!(
                                            "route switch apply task join error: {}",
                                            err
                                        ))
                                    }
                                };

                                let apply_result = if apply_result.is_ok() {
                                    let dynamic_targets: Vec<std::net::IpAddr> = {
                                        let guard = dynamic_bypass_ips_handle.lock().await;
                                        guard.keys().copied().collect()
                                    };

                                    if dynamic_targets.is_empty() {
                                        Ok(())
                                    } else {
                                        let dynamic_iface = new_interface.clone();
                                        match tokio::task::spawn_blocking(move || {
                                            route_manager::apply_skip_ip_routes(
                                                &dynamic_targets,
                                                Some(dynamic_iface.as_str()),
                                            )
                                        })
                                        .await
                                        {
                                            Ok(result) => result,
                                            Err(err) => Err(anyhow!(
                                                "dynamic bypass re-apply task join error: {}",
                                                err
                                            )),
                                        }
                                    }
                                } else {
                                    apply_result
                                };

                                match apply_result {
                                    Ok(()) => {
                                        active_interface = new_interface;
                                        info!(
                                            "Bypass routes re-applied on outbound interface {}",
                                            active_interface
                                        );
                                    }
                                    Err(err) => {
                                        let _ = shutdown_tx
                                            .send(format!(
                                                "failed to re-apply bypass routes after interface switch: {}",
                                                err
                                            ))
                                            .await;
                                        break;
                                    }
                                }
                            }
                            Ok(Ok(None)) => {
                                warn!(
                                    "Outbound interface {} is gone and no replacement is currently routable",
                                    active_interface
                                );
                            }
                            Ok(Err(err)) => {
                                warn!(
                                    "Failed to auto-detect replacement outbound interface: {}",
                                    err
                                );
                            }
                            Err(err) => {
                                warn!(
                                    "Auto-detect replacement interface task failed: {}",
                                    err
                                );
                            }
                        }
                    } else {
                        let _ = shutdown_tx
                            .send(format!(
                                "manually selected outbound interface '{}' is no longer routable",
                                active_interface
                            ))
                            .await;
                        break;
                    }
                }
            }));
        }
    }
    
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
    
    let mut shutdown_error: Option<String> = None;
    tokio::select! {
        _ = shutdown_signal => {
            info!("Shutting down...");
        }
        msg = shutdown_rx.recv() => {
            info!("Shutdown requested");
            shutdown_error = msg;
        }
    }
    
    // Cleanup
    processor_handle.abort();
    if let Some(handle) = interface_monitor_handle {
        handle.abort();
    }

    if auto_route_applied {
        if let Err(err) = route_manager::cleanup_auto_routes(tun_device.name(), ipv6_enabled) {
            warn!("Failed to cleanup automatic routes: {}", err);
        }
    }

    if config.dns.hijack.enabled {
        if let Err(err) = dns_hijack::cleanup_dns_hijack(dns_hijack_state.as_ref()) {
            warn!("Failed to cleanup DNS hijack rules: {}", err);
        }
    }

    if config.tun.auto_route {
        let dynamic_targets: Vec<std::net::IpAddr> = {
            let guard = dynamic_bypass_ips_handle.lock().await;
            guard.keys().copied().collect()
        };
        if !dynamic_targets.is_empty() {
            if let Err(err) = route_manager::cleanup_skip_ip_routes(&dynamic_targets) {
                warn!("Failed to cleanup dynamic bypass routes: {}", err);
            }
        }
    }

    if skip_ip_routes_applied {
        if let Err(err) = route_manager::cleanup_skip_ip_routes(&config.filtering.skip_ips) {
            warn!("Failed to cleanup skip_ip bypass routes: {}", err);
        }
    }

    if skip_network_routes_applied {
        if let Err(err) = route_manager::cleanup_skip_network_routes(&config.filtering.skip_networks) {
            warn!("Failed to cleanup skip_network bypass routes: {}", err);
        }
    }

    tun_device.cleanup().await?;

    if let Some(reason) = shutdown_error {
        return Err(anyhow!(reason));
    }
    
    info!("TinyTun shutdown complete");
    Ok(())
}

async fn run_linux_ebpf_mode(config: Config) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        return Err(anyhow!("inbound.mode=linux-ebpf is only supported on Linux"));
    }

    #[cfg(target_os = "linux")]
    {
        ebpf_mode::run(config).await
    }
}

fn load_config(
    config_path: Option<String>,
    loglevel: Option<LogLevel>,
    socks5: Option<String>,
    socks5_username: Option<String>,
    socks5_password: Option<String>,
    socks5_dns_over_socks5: Option<bool>,
    dns: Vec<String>,
    dns_route: Vec<CliDnsRoute>,
    dns_listen_port: Option<u16>,
    dns_timeout_ms: Option<u64>,
    dns_hijack_enabled: Option<bool>,
    dns_hijack_mark: Option<u32>,
    dns_hijack_table_id: Option<u32>,
    dns_hijack_capture_tcp: Option<bool>,
    interface: Option<String>,
    ip: Option<Ipv4Addr>,
    netmask: Option<Ipv4Addr>,
    ipv6_mode: Option<Ipv6Mode>,
    ipv6: Option<Ipv6Addr>,
    ipv6_prefix: Option<u8>,
    auto_route: Option<bool>,
    mtu: Option<u32>,
    skip_ip: Vec<IpAddr>,
    skip_network: Vec<String>,
    block_port: Vec<u16>,
    allow_port: Vec<u16>,
    linux_exclude_process: Vec<String>,
    linux_process_backend: Option<String>,
    linux_ebpf_cache_path: Option<String>,
    inbound_mode: Option<InboundMode>,
    linux_ebpf_ingress_enabled: Option<bool>,
    linux_ebpf_ingress_interface: Option<String>,
    linux_ebpf_ingress_mark: Option<u32>,
    linux_ebpf_ingress_table_id: Option<u32>,
    linux_ebpf_ingress_redirect_port: Option<u16>,
    linux_ebpf_ingress_redirect_tcp: Option<bool>,
    linux_ebpf_ingress_redirect_udp: Option<bool>,
    auto_detect_interface: Option<bool>,
    default_interface: Option<String>,
) -> Result<Config> {
    let default_interface_cli_provided = default_interface.is_some();

    let mut config = if let Some(path) = config_path {
        Config::from_file(&path)?
    } else {
        Config::default()
    };

    // Override with CLI arguments if provided
    if let Some(v) = loglevel {
        config.log.loglevel = v;
    }

    if let Some(socks5_addr) = socks5 {
        config.socks5.address = socks5_addr.parse()?;
    }
    if let Some(v) = socks5_username {
        config.socks5.username = Some(v);
    }
    if let Some(v) = socks5_password {
        config.socks5.password = Some(v);
    }
    if let Some(v) = socks5_dns_over_socks5 {
        config.socks5.dns_over_socks5 = v;
    }

    if !dns.is_empty() {
        let dns_servers = build_dns_servers_from_cli(&dns, &dns_route)?;
        config.dns.servers = dns_servers;
    }

    if let Some(port) = dns_listen_port {
        config.dns.listen_port = port;
    }
    if let Some(v) = dns_timeout_ms {
        config.dns.timeout_ms = v;
    }
    if let Some(v) = dns_hijack_enabled {
        config.dns.hijack.enabled = v;
    }
    if let Some(v) = dns_hijack_mark {
        config.dns.hijack.mark = v;
    }
    if let Some(v) = dns_hijack_table_id {
        config.dns.hijack.table_id = v;
    }
    if let Some(v) = dns_hijack_capture_tcp {
        config.dns.hijack.capture_tcp = v;
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
    if let Some(v) = mtu {
        config.tun.mtu = v;
    }
    if !skip_ip.is_empty() {
        config.filtering.skip_ips = skip_ip;
    }
    if !skip_network.is_empty() {
        config.filtering.skip_networks = skip_network;
    }
    if !block_port.is_empty() {
        config.filtering.block_ports = block_port;
    }
    if !allow_port.is_empty() {
        config.filtering.allow_ports = allow_port;
    }
    if !linux_exclude_process.is_empty() {
        config.filtering.exclude_processes = linux_exclude_process;
    }
    if let Some(v) = linux_process_backend {
        config.filtering.process_lookup.linux_backend = v;
    }
    if let Some(v) = linux_ebpf_cache_path {
        config.filtering.process_lookup.linux_ebpf_cache_path = Some(v);
    }
    if let Some(v) = inbound_mode {
        config.inbound.mode = v;
    }
    if let Some(v) = linux_ebpf_ingress_enabled {
        config.inbound.linux_ebpf.enabled = v;
    }
    if let Some(v) = linux_ebpf_ingress_interface {
        config.inbound.linux_ebpf.interface = Some(v);
    }
    if let Some(v) = linux_ebpf_ingress_mark {
        config.inbound.linux_ebpf.mark = v;
    }
    if let Some(v) = linux_ebpf_ingress_table_id {
        config.inbound.linux_ebpf.table_id = v;
    }
    if let Some(v) = linux_ebpf_ingress_redirect_port {
        config.inbound.linux_ebpf.redirect_port = v;
    }
    if let Some(v) = linux_ebpf_ingress_redirect_tcp {
        config.inbound.linux_ebpf.redirect_tcp = v;
    }
    if let Some(v) = linux_ebpf_ingress_redirect_udp {
        config.inbound.linux_ebpf.redirect_udp = v;
    }

    let backend = config
        .filtering
        .process_lookup
        .linux_backend
        .to_ascii_lowercase();
    if backend != "auto" && backend != "ss" && backend != "ebpf" {
        return Err(anyhow!(
            "invalid linux_process_backend '{}': expected one of auto|ss|ebpf",
            config.filtering.process_lookup.linux_backend
        ));
    }
    if let Some(v) = auto_detect_interface {
        config.route.auto_detect_interface = v;
    }
    if let Some(v) = default_interface {
        config.route.default_interface = Some(v);
    }

    // CLI ergonomics: if user manually sets --default-interface without explicitly
    // setting --auto-detect-interface, treat it as manual mode.
    if default_interface_cli_provided && auto_detect_interface.is_none() {
        config.route.auto_detect_interface = false;
    }

    if config.route.auto_detect_interface && config.route.default_interface.is_some() {
        return Err(anyhow!(
            "auto_detect_interface and default_interface cannot both be enabled; disable auto_detect_interface when default_interface is set"
        ));
    }

    // Ensure tunnel local addresses are never proxied.
    let tun_v4 = std::net::IpAddr::V4(config.tun.ip);
    if !config.should_skip_ip(tun_v4) {
        config.filtering.skip_ips.push(tun_v4);
    }
    let tun_v6 = std::net::IpAddr::V6(config.tun.ipv6);
    if !config.should_skip_ip(tun_v6) {
        config.filtering.skip_ips.push(tun_v6);
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

    if matches!(config.inbound.mode, InboundMode::LinuxEbpf) {
        return Ok(());
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

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum CliLogLevel {
    Debug,
    Info,
    Warning,
    Error,
    None,
}

impl From<CliLogLevel> for LogLevel {
    fn from(value: CliLogLevel) -> Self {
        match value {
            CliLogLevel::Debug => LogLevel::Debug,
            CliLogLevel::Info => LogLevel::Info,
            CliLogLevel::Warning => LogLevel::Warning,
            CliLogLevel::Error => LogLevel::Error,
            CliLogLevel::None => LogLevel::None,
        }
    }
}

fn init_logging(level: LogLevel) {
    let level_filter = match level {
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Warning => LevelFilter::Warn,
        LogLevel::Error => LevelFilter::Error,
        LogLevel::None => LevelFilter::Off,
    };

    let mut builder = Builder::new();
    builder.filter_level(level_filter);
    builder.format_timestamp_secs();
    builder.format(|buf, record| {
        use std::io::Write;

        let lvl = match record.level() {
            log::Level::Error => "Error",
            log::Level::Warn => "Warning",
            log::Level::Info => "Info",
            log::Level::Debug => "Debug",
            log::Level::Trace => "Debug",
        };

        writeln!(buf, "{} [{}] {}", buf.timestamp(), lvl, record.args())
    });

    let _ = builder.try_init();
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum CliInboundMode {
    Tun,
    #[value(name = "linux-ebpf")]
    LinuxEbpf,
}

impl From<CliInboundMode> for InboundMode {
    fn from(value: CliInboundMode) -> Self {
        match value {
            CliInboundMode::Tun => InboundMode::Tun,
            CliInboundMode::LinuxEbpf => InboundMode::LinuxEbpf,
        }
    }
}