/// Networking implementation including TUN management and WireGuard integration.
pub mod tun;
pub mod wireguard;

use tokio::net::UdpSocket;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::net::tun::TunDevice;
use crate::net::wireguard::WireGuardPeer;
use boringtun::noise::TunnResult;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The main VPN engine that connects TUN interface with WireGuard peers.
pub struct VpnEngine {
    tun: TunDevice,
    peers: Arc<Mutex<Vec<WireGuardPeer>>>,
    udp: Arc<UdpSocket>,
}

impl VpnEngine {
    /// Creates a new VPN engine.
    pub async fn new(tun: TunDevice, local_port: u16) -> anyhow::Result<Self> {
        let udp = UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await?;
        Ok(Self {
            tun,
            peers: Arc::new(Mutex::new(Vec::new())),
            udp: Arc::new(udp),
        })
    }

    /// Adds a peer to the VPN engine.
    pub async fn add_peer(&self, peer: WireGuardPeer) {
        let mut peers = self.peers.lock().await;
        peers.push(peer);
    }

    /// Runs the main packet processing loop.
    pub async fn run(self) -> anyhow::Result<()> {
        let (mut tun_reader, mut tun_writer) = tokio::io::split(self.tun.device);
        let peers = self.peers.clone();
        let udp = self.udp.clone();

        // TUN -> UDP loop
        let tun_to_udp = {
            let peers = peers.clone();
            let udp = udp.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let mut out = [0u8; 2048];
                loop {
                    match tun_reader.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let mut peers = peers.lock().await;
                            // For simplicity, we send to the first peer with an endpoint.
                            // In a real P2P VPN, we'd look up the peer by destination IP.
                            if let Some(peer) = peers.iter_mut().find(|p| p.endpoint().is_some()) {
                                match peer.encapsulate(&buf[..n], &mut out) {
                                    TunnResult::WriteToNetwork(packet) => {
                                        if let Some(endpoint) = peer.endpoint() {
                                            let _ = udp.send_to(packet, endpoint).await;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        // UDP -> TUN loop
        let udp_to_tun = {
            let peers = peers.clone();
            let udp = udp.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let mut out = [0u8; 2048];
                loop {
                    match udp.recv_from(&mut buf).await {
                        Ok((n, addr)) => {
                            let mut peers = peers.lock().await;
                            // Find peer by endpoint or try all (simpler for now)
                            if let Some(peer) = peers.iter_mut().find(|p| p.endpoint() == Some(addr)) {
                                match peer.decapsulate(&buf[..n], &mut out) {
                                    TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                                        let _ = tun_writer.write_all(packet).await;
                                    }
                                    TunnResult::WriteToNetwork(packet) => {
                                        let _ = udp.send_to(packet, addr).await;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        let _ = tokio::try_join!(tun_to_udp, udp_to_tun);
        Ok(())
    }
}
