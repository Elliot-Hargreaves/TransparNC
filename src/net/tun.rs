//! TUN interface management for TransparNC.
//! This module handles the creation and configuration of virtual network interfaces.

use anyhow::Result;
use std::net::Ipv4Addr;
use tun::{Configuration, Device};

/// Configuration for a TUN interface.
pub struct TunConfig {
    /// The name of the interface.
    pub name: String,
    /// The IP address to assign to the interface.
    pub address: Ipv4Addr,
    /// The netmask to assign to the interface.
    pub netmask: Ipv4Addr,
    /// The MTU of the interface.
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "utun%d".to_string(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1420,
        }
    }
}

/// A wrapper around a TUN device.
pub struct TunDevice {
    #[allow(dead_code)]
    device: Device,
}

impl TunDevice {
    /// Creates a new TUN interface based on the provided configuration.
    ///
    /// # Arguments
    /// * `config` - The configuration for the TUN interface.
    ///
    /// # Errors
    /// Returns an error if the interface could not be created or configured.
    pub fn new(config: TunConfig) -> Result<Self> {
        let mut tun_config = Configuration::default();

        tun_config
            .tun_name(&config.name)
            .address(config.address)
            .netmask(config.netmask)
            .mtu(config.mtu)
            .up();

        let device = tun::create(&tun_config)
            .map_err(|e| anyhow::anyhow!("Failed to create TUN device: {}", e))?;

        Ok(Self { device })
    }
}
