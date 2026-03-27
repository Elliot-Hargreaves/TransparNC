//! WireGuard (boringtun) integration layer.
//! This module provides the key management and the core packet processing loop
//! for the WireGuard userspace implementation.

use anyhow::Result;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::rngs::OsRng;
use std::net::SocketAddr;

/// A pair of WireGuard keys.
pub struct KeyPair {
    /// The private key of the node.
    pub private: StaticSecret,
    /// The corresponding public key.
    pub public: PublicKey,
}

impl KeyPair {
    /// Generates a new random X25519 key pair.
    pub fn generate() -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);
        Self { private, public }
    }

    /// Creates a key pair from a private key.
    pub fn from_private(private: StaticSecret) -> Self {
        let public = PublicKey::from(&private);
        Self { private, public }
    }
}

/// A wrapper around `boringtun::noise::Tunn` for a single peer.
pub struct WireGuardPeer {
    /// The underlying boringtun tunnel.
    tunnel: Box<Tunn>,
    /// The remote endpoint of the peer.
    endpoint: Option<SocketAddr>,
    /// The public key of the peer.
    pub public_key: PublicKey,
}

impl WireGuardPeer {
    /// Creates a new WireGuard peer.
    ///
    /// # Arguments
    /// * `static_private` - The private key of the local node.
    /// * `peer_static_public` - The public key of the remote peer.
    /// * `preshared_key` - Optional pre-shared key for extra security.
    /// * `keepalive` - Optional keep-alive interval in seconds.
    /// * `index` - A unique index for the tunnel.
    /// * `endpoint` - The remote endpoint of the peer.
    pub fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Option<[u8; 32]>,
        keepalive: Option<u16>,
        index: u32,
        _endpoint: Option<SocketAddr>,
    ) -> Result<Self> {
        let tunnel = Tunn::new(
            static_private,
            peer_static_public,
            preshared_key,
            keepalive,
            index,
            None,
        );

        Ok(Self {
            tunnel: Box::new(tunnel),
            endpoint: _endpoint,
            public_key: peer_static_public,
        })
    }

    /// Processes an incoming packet from the TUN interface.
    ///
    /// Encapsulates the packet into a WireGuard packet to be sent over UDP.
    pub fn encapsulate<'a>(&mut self, packet: &[u8], out: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.encapsulate(packet, out)
    }

    /// Processes an incoming packet from the UDP socket.
    ///
    /// Decapsulates the WireGuard packet and returns the original IP packet.
    pub fn decapsulate<'a>(&mut self, packet: &[u8], out: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.decapsulate(None, packet, out)
    }

    /// Returns the remote endpoint of the peer.
    pub fn endpoint(&self) -> Option<SocketAddr> {
        self.endpoint
    }

    /// Returns the public key of the peer.
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Updates the remote endpoint of the peer.
    pub fn set_endpoint(&mut self, endpoint: SocketAddr) {
        self.endpoint = Some(endpoint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = KeyPair::generate();
        assert_ne!(keypair.private.to_bytes(), [0u8; 32]);
        // Simple check that public key is derived
        let expected_public = PublicKey::from(&keypair.private);
        assert_eq!(keypair.public.as_bytes(), expected_public.as_bytes());
    }

    #[test]
    fn test_peer_creation() {
        let local = KeyPair::generate();
        let remote = KeyPair::generate();
        let peer = WireGuardPeer::new(local.private, remote.public, None, None, 1, None);
        assert!(peer.is_ok());
    }
}
