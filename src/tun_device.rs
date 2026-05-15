use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::{Context, Result};
use tun_rs::{AsyncDevice, DeviceBuilder};

pub struct TunDevice {
    device: Option<Arc<AsyncDevice>>,
    name: String,
}

impl TunDevice {
    /// Create and configure a new TUN device
    pub async fn new(
        name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        ipv6_address: Option<Ipv6Addr>,
        ipv6_prefix: u8,
        _auto_route: bool,
        mtu: u32,
    ) -> Result<Self> {
        let builder = DeviceBuilder::new()
            .name(name)
            .ipv4(address, netmask, None)
            .mtu(mtu as u16);

        let builder = if let Some(ipv6) = ipv6_address {
            builder.ipv6(ipv6, ipv6_prefix)
        } else {
            builder
        };

        let device = builder
            .build_async()
            .with_context(|| format!("Failed to create TUN device '{}'", name))?;

        let device_name = device.name().unwrap_or_else(|_| name.to_string());

        Ok(Self {
            device: Some(Arc::new(device)),
            name: device_name,
        })
    }

    /// Get the name of the TUN interface
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get a shared handle to the TUN device for reading
    pub fn get_reader(&self) -> Arc<AsyncDevice> {
        self
            .device
            .as_ref()
            .expect("TUN reader requested after device cleanup")
            .clone()
    }

    /// Get a shared handle to the TUN device for writing
    pub fn get_writer(&self) -> Arc<AsyncDevice> {
        self
            .device
            .as_ref()
            .expect("TUN writer requested after device cleanup")
            .clone()
    }

    /// Cleanup and shutdown the TUN device
    pub async fn cleanup(&mut self) -> Result<()> {
        // Idempotent cleanup: release our local handle only once.
        if self.device.take().is_none() {
            return Ok(());
        }

        // Best-effort interface teardown on Unix-like systems.
        // Errors are ignored because the caller already performs route and
        // firewall cleanup; interface-down failures should not block shutdown.
        #[cfg(target_os = "linux")]
        {
            let _ = tokio::process::Command::new("ip")
                .args(["link", "set", "dev", self.name.as_str(), "down"])
                .status()
                .await;
        }

        #[cfg(target_os = "macos")]
        {
            let _ = tokio::process::Command::new("ifconfig")
                .args([self.name.as_str(), "down"])
                .status()
                .await;
        }

        Ok(())
    }
}