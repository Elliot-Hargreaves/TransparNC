//! TUN interface management for TransparNC.
//! This module handles the creation and configuration of virtual network interfaces.

use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;
use std::io::{Read, Write};
use tun::{AbstractDevice, Configuration};

/// Configuration for a TUN interface.
pub struct TunConfig {
    /// The name of the interface.
    /// On Linux, it's something like "tun0".
    /// On macOS, it's something like "utun0".
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
    /// - Address: 10.0.0.1
    /// - Netmask: 255.255.255.0
    /// - MTU: 1420 (WireGuard default)
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
    /// The underlying OS TUN device.
    device: Box<dyn AbstractDevice + Send + Sync>,
}

impl TunDevice {
    /// Creates a new TUN interface based on the provided configuration.
    ///
    /// # Arguments
    /// * `config` - The configuration for the TUN interface.
    ///
    /// # Errors
    /// Returns an error if the interface could not be created or configured.
    /// This typically happens if the user lacks the necessary permissions (e.g., root on Linux).
    pub fn new(config: TunConfig) -> Result<Self> {
        let mut tun_config = Configuration::default();

        tun_config
            .tun_name(&config.name)
            .address(config.address)
            .netmask(config.netmask)
            .mtu(config.mtu)
            .up();

        // On Windows, you might need to specify the device path or use wintun.
        // The `tun` crate handles much of this, but we may need to refine this later.

        let device = tun::create(&tun_config)
            .map_err(|e| anyhow!("Failed to create TUN device: {}", e))?;

        Ok(Self {
            device: Box::new(device),
        })
    }

    /// Reads a packet from the TUN interface.
    ///
    /// # Arguments
    /// * `buf` - The buffer to read the packet into.
    ///
    /// # Returns
    /// The number of bytes read.
    ///
    /// # Errors
    /// Returns an error if the read operation fails.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.device
            .read(buf)
            .map_err(|e| anyhow!("Failed to read from TUN device: {}", e))
    }

    /// Writes a packet to the TUN interface.
    ///
    /// # Arguments
    /// * `buf` - The buffer containing the packet to write.
    ///
    /// # Returns
    /// The number of bytes written.
    ///
    /// # Errors
    /// Returns an error if the write operation fails.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.device
            .write(buf)
            .map_err(|e| anyhow!("Failed to write to TUN device: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();
        assert_eq!(config.address, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(config.mtu, 1420);
    }

    #[test]
    #[ignore] // This test requires root permissions/CAP_NET_ADMIN to create a TUN device.
    fn test_create_tun() {
        let config = TunConfig::default();
        let device = TunDevice::new(config);
        assert!(device.is_ok(), "Failed to create TUN device: {:?}", device.err());
    }
}
