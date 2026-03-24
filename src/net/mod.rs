pub mod ice;
pub mod nat;
/// Networking implementation including TUN management and WireGuard integration.
pub mod tun;
pub mod wireguard;

use crate::net::nat::StunClient;
use crate::net::tun::TunDevice;
use crate::net::wireguard::WireGuardPeer;
use boringtun::noise::TunnResult;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// The main VPN engine that connects TUN interface with WireGuard peers.
pub struct VpnEngine {
    tun: TunDevice,
    peers: Arc<Mutex<Vec<WireGuardPeer>>>,
    udp: Arc<UdpSocket>,
    stun_client: Option<Box<dyn StunClient>>,
}

impl VpnEngine {
    /// Creates a new VPN engine.
    pub async fn new(
        tun: TunDevice,
        local_port: u16,
        stun_client: Option<Box<dyn StunClient>>,
    ) -> anyhow::Result<Self> {
        let udp = UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await?;
        Ok(Self {
            tun,
            peers: Arc::new(Mutex::new(Vec::new())),
            udp: Arc::new(udp),
            stun_client,
        })
    }

    /// Adds a peer to the VPN engine.
    pub async fn add_peer(&self, peer: WireGuardPeer) {
        let mut peers = self.peers.lock().await;
        peers.push(peer);
    }

    /// Runs the main packet processing loop.
    pub async fn run(self) -> anyhow::Result<()> {
        if let Some(stun) = &self.stun_client {
            match stun.discover_external_addr(&self.udp).await {
                Ok(addr) => println!("Discovered external address: {}", addr),
                Err(e) => eprintln!("NAT discovery failed: {}", e),
            }
        }

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
                                if let TunnResult::WriteToNetwork(packet) =
                                    peer.encapsulate(&buf[..n], &mut out)
                                {
                                    if let Some(endpoint) = peer.endpoint() {
                                        let _ = udp.send_to(packet, endpoint).await;
                                    }
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
                while let Ok((n, addr)) = udp.recv_from(&mut buf).await {
                    let mut peers = peers.lock().await;
                    // Find peer by endpoint or try all (simpler for now)
                    if let Some(peer) = peers.iter_mut().find(|p| p.endpoint() == Some(addr)) {
                        match peer.decapsulate(&buf[..n], &mut out) {
                            TunnResult::WriteToTunnelV4(packet, _)
                            | TunnResult::WriteToTunnelV6(packet, _) => {
                                let _ = tun_writer.write_all(packet).await;
                            }
                            TunnResult::WriteToNetwork(packet) => {
                                let _ = udp.send_to(packet, addr).await;
                            }
                            _ => {}
                        }
                    }
                }
            })
        };

        let _ = tokio::try_join!(tun_to_udp, udp_to_tun);
        Ok(())
    }
}
