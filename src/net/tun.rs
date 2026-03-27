//! TUN interface management for TransparNC.
//! This module handles the creation and configuration of virtual network interfaces.

use anyhow::{Result, anyhow};
use std::net::Ipv4Addr;
use tokio_tun::Tun;

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
    /// Returns a default configuration with:
    /// - Name: "utun%d" (automatically assigned by OS)
    /// - Address: 172.222.0.1
    /// - Netmask: 255.255.255.0
    /// - MTU: 1420 (WireGuard default)
    fn default() -> Self {
        Self {
            name: "utun%d".to_string(),
            address: Ipv4Addr::new(172, 222, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1420,
        }
    }
}

/// A wrapper around a asynchronous TUN device.
pub struct TunDevice {
    /// The underlying async TUN device.
    pub device: Tun,
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
        let device = Tun::builder()
            .name(&config.name)
            .address(config.address)
            .netmask(config.netmask)
            .mtu(config.mtu as i32)
            .up()
            .try_build()
            .map_err(|e| anyhow!("Failed to create TUN device: {}", e))?;

        Ok(Self { device })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();
        assert_eq!(config.address, Ipv4Addr::new(172, 222, 0, 1));
        assert_eq!(config.mtu, 1420);
    }

    #[test]
    #[ignore] // This test requires root permissions/CAP_NET_ADMIN to create a TUN device.
    fn test_create_tun() {
        let config = TunConfig::default();
        let device = TunDevice::new(config);
        assert!(
            device.is_ok(),
            "Failed to create TUN device: {:?}",
            device.err()
        );
    }
}
