//! NAT discovery and traversal for TransparNC.
//! This module provides tools to discover external endpoints and perform hole punching.

use async_trait::async_trait;
use std::net::SocketAddr;
use thiserror::Error;
use stun::message::{Message, BINDING_REQUEST, Getter};
use tokio::net::UdpSocket;
use std::time::Duration;

/// Errors related to NAT discovery.
#[derive(Debug, Error)]
pub enum NatError {
    #[error("STUN request timed out")]
    Timeout,
    #[error("Failed to parse STUN response")]
    ParseError,
    #[error("Network error during STUN: {0}")]
    NetworkError(String),
}

/// A trait for NAT discovery clients.
/// This allows for mocking in tests as per AGENTS.md.
#[async_trait]
pub trait StunClient: Send + Sync {
    /// Discovers the external IP and port for the local node using the provided socket.
    async fn discover_external_addr(&self, socket: &UdpSocket) -> Result<SocketAddr, NatError>;
}

/// Implementation of a real STUN client using the `stun` crate.
pub struct RealStunClient {
    stun_server: String,
}

impl RealStunClient {
    /// Creates a new STUN client with the given server address.
    pub fn new(stun_server: String) -> Self {
        Self { stun_server }
    }
}

#[async_trait]
impl StunClient for RealStunClient {
    async fn discover_external_addr(&self, socket: &UdpSocket) -> Result<SocketAddr, NatError> {
        println!("STUN: Connecting to {}", self.stun_server);
        
        let mut msg = Message::new();
        msg.set_type(BINDING_REQUEST);
        msg.new_transaction_id().map_err(|_| NatError::ParseError)?;
        msg.encode();

        // Try multiple times as UDP is unreliable
        for attempt in 1..=3 {
            println!("STUN: Sending request to {} (attempt {})...", self.stun_server, attempt);
            if let Err(e) = socket.send_to(msg.raw.as_slice(), &self.stun_server).await {
                println!("STUN: Send error: {}", e);
                if attempt == 3 {
                    return Err(NatError::NetworkError(e.to_string()));
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }

            let mut buf = [0u8; 1024];
            match tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
                Ok(Ok((n, addr))) => {
                    println!("STUN: Received {} bytes from {}", n, addr);

                    let mut response = Message::new();
                    response.raw = buf[..n].to_vec();
                    if let Err(e) = response.decode() {
                        println!("STUN: Decode error: {}", e);
                        continue; // Try next attempt
                    }

                    let mut addr = stun::xoraddr::XorMappedAddress::default();
                    if addr.get_from(&response).is_ok() {
                        let external_addr = SocketAddr::new(addr.ip, addr.port);
                        println!("STUN: Discovered XOR-Mapped Address: {}", external_addr);
                        return Ok(external_addr);
                    }

                    let mut addr = stun::addr::MappedAddress::default();
                    if addr.get_from(&response).is_ok() {
                        let external_addr = SocketAddr::new(addr.ip, addr.port);
                        println!("STUN: Discovered Mapped Address: {}", external_addr);
                        return Ok(external_addr);
                    }
                    println!("STUN: No address in response");
                }
                Ok(Err(e)) => {
                    println!("STUN: Recv error: {}", e);
                }
                Err(_) => {
                    println!("STUN: Attempt {} timed out", attempt);
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Err(NatError::Timeout)
    }
}

/// A mock STUN client for testing purposes.
pub struct MockStunClient {
    external_addr: SocketAddr,
}

impl MockStunClient {
    /// Creates a new mock STUN client that returns the given address.
    pub fn new(external_addr: SocketAddr) -> Self {
        Self { external_addr }
    }
}

#[async_trait]
impl StunClient for MockStunClient {
    async fn discover_external_addr(&self, _socket: &UdpSocket) -> Result<SocketAddr, NatError> {
        Ok(self.external_addr)
    }
}
