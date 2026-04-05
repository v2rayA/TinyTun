use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::Result;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use tun::{AbstractDevice, Configuration, DeviceReader, DeviceWriter};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MacosDnsRestoreInfo {
    service: String,
    ipv4_servers: Vec<String>,
    ipv6_servers: Vec<String>,
}

pub struct TunDevice {
    reader: Arc<Mutex<DeviceReader>>,
    writer: Arc<Mutex<DeviceWriter>>,
    name: String,
    #[cfg(target_os = "macos")]
    macos_dns_restore: Option<MacosDnsRestoreInfo>,
}

impl TunDevice {
    pub async fn new(
        name: &str,
        ip: Ipv4Addr,
        netmask: Ipv4Addr,
        ipv6: Option<Ipv6Addr>,
        ipv6_prefix: u8,
        auto_route_enabled: bool,
        mtu: u32,
    ) -> Result<Self> {
        info!("Creating TUN device: {}", name);
        
        let mut config = Configuration::default();
        config
            .tun_name(name)
            .address(ip)
            .netmask(netmask)
            .mtu(mtu as u16)
            .up();

        #[cfg(windows)]
        if auto_route_enabled {
            // Lower interface metric so split routes on TUN win route selection deterministically.
            config.metric(6);
        }
        
        let device = tun::create_as_async(&config).map_err(|err| {
            #[cfg(windows)]
            {
                let msg = err.to_string();
                if msg.contains("Code 0x00000005") || msg.contains("拒绝访问") {
                    return anyhow::anyhow!(
                        "Failed to create Wintun adapter due to access denied. Run this process in an elevated Administrator shell. Original error: {}",
                        err
                    );
                }

                if msg.contains("LoadLibraryExW failed") || msg.contains("os error 126") {
                    return anyhow::anyhow!(
                        "Failed to load Wintun runtime. Ensure wintun.dll is next to tinytun.exe (or in PATH). Original error: {}",
                        err
                    );
                }
            }

            anyhow::anyhow!("Failed to create TUN device: {}", err)
        })?;
        let device_name = device.tun_name()?;
        
        info!("TUN device created: {}", device_name);

        #[cfg(target_os = "macos")]
        if let Err(err) = Self::try_restore_macos_dns_from_persisted_state() {
            warn!("Failed to restore stale macOS DNS state at startup: {}", err);
        }
        
        // Set up the interface
        let setup_state = Self::setup_interface(
            &device_name,
            ip,
            netmask,
            ipv6,
            ipv6_prefix,
            auto_route_enabled,
        )?;

        #[cfg(target_os = "macos")]
        let macos_dns_restore = setup_state;
        #[cfg(not(target_os = "macos"))]
        let _ = setup_state;
        
        let (writer, reader) = device.split()?;
        let reader = Arc::new(Mutex::new(reader));
        let writer = Arc::new(Mutex::new(writer));
        
        Ok(Self {
            reader,
            writer,
            name: device_name,
            #[cfg(target_os = "macos")]
            macos_dns_restore,
        })
    }
    
    fn setup_interface(
        _name: &str,
        _ip: Ipv4Addr,
        _netmask: Ipv4Addr,
        _ipv6: Option<Ipv6Addr>,
        _ipv6_prefix: u8,
        _auto_route_enabled: bool,
    ) -> Result<Option<MacosDnsRestoreInfo>> {
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            let name = _name;
            let ip = _ip;
            let netmask = _netmask;
            let ipv6 = _ipv6;
            let ipv6_prefix = _ipv6_prefix;
            
            // Bring interface up
            let output = Command::new("ip")
                .args(&["link", "set", "dev", name, "up"])
                .output()?;
            
            if !output.status.success() {
                warn!("Failed to bring up interface {}: {}", name, String::from_utf8_lossy(&output.stderr));
            }
            
            // Set IP address (replace is idempotent — handles the case where the
            // tun crate already assigned the address via ioctl)
            let ip_str = format!("{}/{}", ip, Self::netmask_to_prefix(netmask));
            let output = Command::new("ip")
                .args(&["addr", "replace", &ip_str, "dev", name])
                .output()?;
            
            if !output.status.success() {
                warn!("Failed to set IP address for {}: {}", name, String::from_utf8_lossy(&output.stderr));
            }

            if let Some(v6) = ipv6 {
                let v6_str = format!("{}/{}", v6, ipv6_prefix);
                let output = Command::new("ip")
                    .args(["-6", "addr", "replace", &v6_str, "dev", name])
                    .output()?;

                if !output.status.success() {
                    warn!(
                        "Failed to set IPv6 address for {}: {}",
                        name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
        
        #[cfg(windows)]
        {
            use std::process::Command;
            let name = _name;
            let ipv6 = _ipv6;
            let ipv6_prefix = _ipv6_prefix;
            let auto_route_enabled = _auto_route_enabled;

            info!("TUN interface setup on Windows may require additional configuration");

            if let Some(v6) = ipv6 {
                let v6_str = format!("{}/{}", v6, ipv6_prefix);
                let output = Command::new("netsh")
                    .args([
                        "interface",
                        "ipv6",
                        "add",
                        "address",
                        &format!("interface={}", name),
                        &format!("address={}", v6_str),
                        "store=active",
                    ])
                    .output()?;

                if !output.status.success() {
                    warn!(
                        "Failed to set IPv6 address for {}: {}",
                        name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }

            // Always configure Google Public DNS on the TUN interface so the OS
            // routes DNS queries through the tunnel.
            let google_v4 = [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)];

            {
                let output = Command::new("netsh")
                    .args([
                        "interface",
                        "ipv4",
                        "set",
                        "dnsservers",
                        &format!("name={}", name),
                        "source=static",
                        &format!("address={}", google_v4[0]),
                        "validate=no",
                    ])
                    .output()?;

                if !output.status.success() {
                    warn!(
                        "Failed to set primary IPv4 DNS for {}: {}",
                        name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                } else {
                    let output = Command::new("netsh")
                        .args([
                            "interface",
                            "ipv4",
                            "add",
                            "dnsservers",
                            &format!("name={}", name),
                            &format!("address={}", google_v4[1]),
                            "index=2",
                            "validate=no",
                        ])
                        .output()?;

                    if !output.status.success() {
                        warn!(
                            "Failed to add IPv4 DNS {} for {}: {}",
                            google_v4[1],
                            name,
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                }
            }

            if ipv6.is_some() {
                let google_v6 = [
                    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
                    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
                ];

                let output = Command::new("netsh")
                    .args([
                        "interface",
                        "ipv6",
                        "set",
                        "dnsservers",
                        &format!("interface={}", name),
                        &format!("address={}", google_v6[0]),
                        "validate=no",
                    ])
                    .output()?;

                if !output.status.success() {
                    warn!(
                        "Failed to set primary IPv6 DNS for {}: {}",
                        name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                } else {
                    let output = Command::new("netsh")
                        .args([
                            "interface",
                            "ipv6",
                            "add",
                            "dnsservers",
                            &format!("interface={}", name),
                            &format!("address={}", google_v6[1]),
                            "index=2",
                            "validate=no",
                        ])
                        .output()?;

                    if !output.status.success() {
                        warn!(
                            "Failed to add IPv6 DNS {} for {}: {}",
                            google_v6[1],
                            name,
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                }
            }

            if auto_route_enabled {
                let output = Command::new("netsh")
                    .args([
                        "interface",
                        "ipv4",
                        "set",
                        "interface",
                        &format!("name={}", name),
                        "metric=6",
                    ])
                    .output()?;

                if !output.status.success() {
                    warn!(
                        "Failed to set IPv4 interface metric=6 for {}: {}",
                        name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                } else {
                    info!("Set interface metric for {} (IPv4) to 6", name);
                }

                let output = Command::new("netsh")
                    .args([
                        "interface",
                        "ipv6",
                        "set",
                        "interface",
                        &format!("interface={}", name),
                        "metric=6",
                    ])
                    .output()?;

                if !output.status.success() {
                    warn!(
                        "Failed to set IPv6 interface metric=6 for {}: {}",
                        name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                } else {
                    info!("Set interface metric for {} (IPv6) to 6", name);
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;

            let name = _name;
            let ip = _ip;
            let netmask = _netmask;
            let ipv6 = _ipv6;
            let ipv6_prefix = _ipv6_prefix;

            // utun is point-to-point on macOS; set local+peer to the same address.
            // Delete first so a restart with the same address doesn't leave a stale
            // "Address already assigned" error (ifconfig doesn't have a 'replace').
            let _ = Command::new("ifconfig")
                .args([
                    name,
                    "inet",
                    &ip.to_string(),
                    &ip.to_string(),
                    "netmask",
                    &netmask.to_string(),
                    "-alias",
                ])
                .output();
            let output = Command::new("ifconfig")
                .args([
                    name,
                    "inet",
                    &ip.to_string(),
                    &ip.to_string(),
                    "netmask",
                    &netmask.to_string(),
                    "up",
                ])
                .output()?;

            if !output.status.success() {
                warn!(
                    "Failed to set IPv4 address for {}: {}",
                    name,
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            if let Some(v6) = ipv6 {
                // Remove the address first (ignore errors if not present) so that
                // restarting the daemon doesn't accumulate duplicate IPv6 aliases.
                let _ = Command::new("ifconfig")
                    .args([
                        name,
                        "inet6",
                        &v6.to_string(),
                        "prefixlen",
                        &ipv6_prefix.to_string(),
                        "-alias",
                    ])
                    .output();
                let output = Command::new("ifconfig")
                    .args([
                        name,
                        "inet6",
                        &v6.to_string(),
                        "prefixlen",
                        &ipv6_prefix.to_string(),
                        "alias",
                    ])
                    .output()?;

                if !output.status.success() {
                    warn!(
                        "Failed to set IPv6 address for {}: {}",
                        name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }

            let output = Command::new("ifconfig").args([name, "up"]).output()?;
            if !output.status.success() {
                warn!(
                    "Failed to bring up interface {}: {}",
                    name,
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            // Align with Windows behavior: set DNS on the active service so queries
            // are directed to public resolvers and then captured by TUN split routes.
            let google_v4 = [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)];
            let google_v6 = [
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
            ];

            let restore = match Self::capture_macos_dns_restore_info(
                if ipv6.is_some() { Some(google_v6) } else { None },
            ) {
                Ok(state) => Some(state),
                Err(err) => {
                    warn!("Failed to capture macOS DNS restore state: {}", err);
                    None
                }
            };

            if let Some(state) = &restore {
                if let Err(err) = Self::persist_macos_dns_restore_state(state) {
                    warn!("Failed to persist macOS DNS restore state: {}", err);
                }
            }

            if let Err(err) = Self::configure_macos_dns_servers(
                google_v4,
                if ipv6.is_some() { Some(google_v6) } else { None },
            ) {
                warn!("Failed to configure macOS DNS servers: {}", err);

                if let Some(state) = &restore {
                    if let Err(restore_err) = Self::restore_macos_dns_servers(state) {
                        warn!("Failed to rollback macOS DNS after setup failure: {}", restore_err);
                    }
                }

                if let Err(clear_err) = Self::clear_macos_dns_restore_state() {
                    warn!("Failed to clear persisted macOS DNS restore state: {}", clear_err);
                }
            }

            if restore.is_some() {
                return Ok(restore);
            }
        }

        Ok(None)
    }
    
    #[cfg(target_os = "macos")]
    fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
        let octets = netmask.octets();
        let mut prefix = 0;
        
        for octet in octets.iter() {
            let mut mask = *octet;
            while mask & 0x80 != 0 {
                prefix += 1;
                mask <<= 1;
            }
            if mask != 0 {
                break;
            }
        }
        
        prefix
    }

    #[cfg(target_os = "macos")]
    fn configure_macos_dns_servers(
        v4_servers: [Ipv4Addr; 2],
        v6_servers: Option<[Ipv6Addr; 2]>,
    ) -> Result<()> {
        use std::process::Command;

        let (service, default_device) = Self::resolve_active_macos_network_service()?;

        let set_v4 = Command::new("networksetup")
            .args([
                "-setdnsservers",
                &service,
                &v4_servers[0].to_string(),
                &v4_servers[1].to_string(),
            ])
            .output()?;
        if !set_v4.status.success() {
            return Err(anyhow::anyhow!(
                "failed setting IPv4 DNS on service '{}': {}",
                service,
                String::from_utf8_lossy(&set_v4.stderr)
            ));
        }

        if let Some(v6) = v6_servers {
            let set_v6 = Command::new("networksetup")
                .args([
                    "-setv6dnsservers",
                    &service,
                    &v6[0].to_string(),
                    &v6[1].to_string(),
                ])
                .output()?;
            if !set_v6.status.success() {
                return Err(anyhow::anyhow!(
                    "failed setting IPv6 DNS on service '{}': {}",
                    service,
                    String::from_utf8_lossy(&set_v6.stderr)
                ));
            }
        }

        info!(
            "Configured macOS DNS on service '{}' (default interface: {})",
            service,
            default_device
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn capture_macos_dns_restore_info(
        v6_servers: Option<[Ipv6Addr; 2]>,
    ) -> Result<MacosDnsRestoreInfo> {
        let (service, _) = Self::resolve_active_macos_network_service()?;

        let ipv4_servers = Self::read_macos_dns_servers(&service, false)?;
        let ipv6_servers = if v6_servers.is_some() {
            Self::read_macos_dns_servers(&service, true)?
        } else {
            Vec::new()
        };

        Ok(MacosDnsRestoreInfo {
            service,
            ipv4_servers,
            ipv6_servers,
        })
    }

    #[cfg(target_os = "macos")]
    fn resolve_active_macos_network_service() -> Result<(String, String)> {
        use std::process::Command;

        let default_route = Command::new("route")
            .args(["-n", "get", "default"])
            .output()?;
        if !default_route.status.success() {
            return Err(anyhow::anyhow!(
                "route get default failed: {}",
                String::from_utf8_lossy(&default_route.stderr)
            ));
        }

        let route_text = String::from_utf8_lossy(&default_route.stdout);
        let default_device = route_text
            .lines()
            .find_map(|line| line.trim().strip_prefix("interface: "))
            .map(str::trim)
            .ok_or_else(|| anyhow::anyhow!("could not determine default route interface"))?
            .to_string();

        // Prefer service-order output because it respects user-renamed service names.
        let service_order = Command::new("networksetup")
            .args(["-listnetworkserviceorder"])
            .output()?;
        if service_order.status.success() {
            let mut pending_service: Option<String> = None;
            for raw in String::from_utf8_lossy(&service_order.stdout).lines() {
                let line = raw.trim();

                if line.starts_with('(') {
                    if let Some(idx) = line.find(')') {
                        let service = line[idx + 1..].trim();
                        if !service.is_empty() && !service.starts_with('*') {
                            pending_service = Some(service.to_string());
                        } else {
                            pending_service = None;
                        }
                    }
                    continue;
                }

                if let Some(device_pos) = line.find("Device: ") {
                    let device_part = &line[device_pos + "Device: ".len()..];
                    let device = device_part
                        .trim_end_matches(')')
                        .trim()
                        .split(',')
                        .next()
                        .unwrap_or("")
                        .trim();

                    if device == default_device {
                        if let Some(service) = pending_service.take() {
                            return Ok((service, default_device));
                        }
                    }
                }
            }
        }

        // Fallback for older layouts.
        let hw_ports = Command::new("networksetup")
            .args(["-listallhardwareports"])
            .output()?;
        if !hw_ports.status.success() {
            return Err(anyhow::anyhow!(
                "networksetup service mapping failed: {}",
                String::from_utf8_lossy(&hw_ports.stderr)
            ));
        }

        let mut service_name: Option<String> = None;
        let mut pending_port: Option<String> = None;
        for raw in String::from_utf8_lossy(&hw_ports.stdout).lines() {
            let line = raw.trim();
            if let Some(port) = line.strip_prefix("Hardware Port: ") {
                pending_port = Some(port.trim().to_string());
                continue;
            }

            if let Some(device) = line.strip_prefix("Device: ") {
                if device.trim() == default_device {
                    service_name = pending_port.clone();
                    break;
                }
            }
        }

        let service = service_name.ok_or_else(|| {
            anyhow::anyhow!(
                "could not map default interface '{}' to a macOS network service",
                default_device
            )
        })?;
        Ok((service, default_device))
    }

    #[cfg(target_os = "macos")]
    fn read_macos_dns_servers(service: &str, ipv6: bool) -> Result<Vec<String>> {
        use std::process::Command;

        let mut cmd = Command::new("networksetup");
        if ipv6 {
            cmd.args(["-getv6dnsservers", service]);
        } else {
            cmd.args(["-getdnsservers", service]);
        }

        let out = cmd.output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "networksetup DNS read failed for service '{}': {}",
                service,
                String::from_utf8_lossy(&out.stderr)
            ));
        }

        let text = String::from_utf8_lossy(&out.stdout);
        let mut servers = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("There aren't any") {
                return Ok(Vec::new());
            }
            servers.push(trimmed.to_string());
        }

        Ok(servers)
    }

    #[cfg(target_os = "macos")]
    fn restore_macos_dns_servers(state: &MacosDnsRestoreInfo) -> Result<()> {
        use std::process::Command;

        let mut cmd_v4 = Command::new("networksetup");
        cmd_v4.args(["-setdnsservers", &state.service]);
        if state.ipv4_servers.is_empty() {
            cmd_v4.arg("Empty");
        } else {
            cmd_v4.args(state.ipv4_servers.iter().map(String::as_str));
        }
        let out_v4 = cmd_v4.output()?;
        if !out_v4.status.success() {
            return Err(anyhow::anyhow!(
                "failed restoring IPv4 DNS on service '{}': {}",
                state.service,
                String::from_utf8_lossy(&out_v4.stderr)
            ));
        }

        let mut cmd_v6 = Command::new("networksetup");
        cmd_v6.args(["-setv6dnsservers", &state.service]);
        if state.ipv6_servers.is_empty() {
            cmd_v6.arg("Empty");
        } else {
            cmd_v6.args(state.ipv6_servers.iter().map(String::as_str));
        }
        let out_v6 = cmd_v6.output()?;
        if !out_v6.status.success() {
            return Err(anyhow::anyhow!(
                "failed restoring IPv6 DNS on service '{}': {}",
                state.service,
                String::from_utf8_lossy(&out_v6.stderr)
            ));
        }

        info!("Restored macOS DNS on service '{}'", state.service);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn macos_dns_state_file_path() -> std::path::PathBuf {
        std::env::temp_dir().join("tinytun-macos-dns-restore.json")
    }

    #[cfg(target_os = "macos")]
    fn persist_macos_dns_restore_state(state: &MacosDnsRestoreInfo) -> Result<()> {
        let path = Self::macos_dns_state_file_path();
        let serialized = serde_json::to_vec(state)?;
        std::fs::write(&path, serialized)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn load_macos_dns_restore_state() -> Result<Option<MacosDnsRestoreInfo>> {
        let path = Self::macos_dns_state_file_path();
        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read(&path)?;
        let state: MacosDnsRestoreInfo = serde_json::from_slice(&data)?;
        Ok(Some(state))
    }

    #[cfg(target_os = "macos")]
    fn clear_macos_dns_restore_state() -> Result<()> {
        let path = Self::macos_dns_state_file_path();
        if !path.exists() {
            return Ok(());
        }

        std::fs::remove_file(path)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn try_restore_macos_dns_from_persisted_state() -> Result<()> {
        let Some(state) = Self::load_macos_dns_restore_state()? else {
            return Ok(());
        };

        if let Err(err) = Self::restore_macos_dns_servers(&state) {
            // Keep state file for retry on next startup if restore still fails.
            return Err(err);
        }

        Self::clear_macos_dns_restore_state()?;
        Ok(())
    }
    
    pub fn get_reader(&self) -> Arc<Mutex<DeviceReader>> {
        self.reader.clone()
    }

    pub fn get_writer(&self) -> Arc<Mutex<DeviceWriter>> {
        self.writer.clone()
    }
    
    pub async fn cleanup(&self) -> Result<()> {
        info!("Cleaning up TUN device: {}", self.name);
        
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            
            let output = Command::new("ip")
                .args(&["link", "delete", &self.name])
                .output()?;
            
            if !output.status.success() {
                warn!("Failed to delete TUN interface {}: {}", self.name, String::from_utf8_lossy(&output.stderr));
            }
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;

            if let Some(state) = &self.macos_dns_restore {
                if let Err(err) = Self::restore_macos_dns_servers(state) {
                    warn!("Failed to restore macOS DNS settings: {}", err);
                }
            }

            if let Err(err) = Self::clear_macos_dns_restore_state() {
                warn!("Failed to clear persisted macOS DNS restore state: {}", err);
            }

            // utun devices are usually released when handle closes; mark down best-effort.
            let output = Command::new("ifconfig")
                .args([&self.name, "down"])
                .output()?;

            if !output.status.success() {
                warn!(
                    "Failed to bring down TUN interface {}: {}",
                    self.name,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        
        Ok(())
    }
    
    pub fn name(&self) -> &str {
        &self.name
    }
}