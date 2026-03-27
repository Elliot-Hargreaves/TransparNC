pub mod ice;
pub mod nat;
pub mod peer;
/// Networking implementation including TUN management and WireGuard integration.
pub mod tun;
pub mod wireguard;

use crate::net::nat::StunClient;
use crate::net::peer::{PeerManager, PeerStore};
use crate::net::tun::TunDevice;
use crate::net::wireguard::WireGuardPeer;
use boringtun::noise::TunnResult;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Default interval between heartbeat checks in seconds.
const HEARTBEAT_INTERVAL_SECS: u64 = 15;

/// Duration after which a connected peer with no heartbeat becomes stale.
const STALE_TIMEOUT_SECS: u64 = 30;

/// Duration after which a stale peer is considered disconnected.
const DISCONNECT_TIMEOUT_SECS: u64 = 90;

/// The main VPN engine that connects TUN interface with WireGuard peers.
///
/// Manages TUN↔UDP packet forwarding, WireGuard encryption/decryption,
/// peer lifecycle tracking via `PeerManager`, and periodic heartbeat checks.
pub struct VpnEngine {
    /// The virtual network interface for reading/writing IP packets.
    tun: TunDevice,
    /// WireGuard tunnel instances for each peer (indexed by endpoint).
    wg_peers: Arc<Mutex<Vec<WireGuardPeer>>>,
    /// Tracks peer connection state, heartbeats, and lifecycle transitions.
    pub peer_manager: Arc<Mutex<PeerManager>>,
    /// The UDP socket used for sending/receiving encrypted WireGuard packets.
    pub udp: Arc<UdpSocket>,
    /// Optional STUN client for NAT discovery.
    stun_client: Option<Box<dyn StunClient>>,
}

impl VpnEngine {
    /// Creates a new VPN engine using an already bound UDP socket.
    pub fn with_socket(
        tun: TunDevice,
        udp: Arc<UdpSocket>,
        stun_client: Option<Box<dyn StunClient>>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            tun,
            wg_peers: Arc::new(Mutex::new(Vec::new())),
            peer_manager: Arc::new(Mutex::new(PeerManager::new())),
            udp,
            stun_client,
        })
    }

    /// Creates a new VPN engine.
    ///
    /// Binds a UDP socket on the given port and initialises an empty
    /// `PeerManager` for tracking peer lifecycle.
    pub async fn new(
        tun: TunDevice,
        local_port: u16,
        stun_client: Option<Box<dyn StunClient>>,
    ) -> anyhow::Result<Self> {
        let udp = UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await?;
        Ok(Self {
            tun,
            wg_peers: Arc::new(Mutex::new(Vec::new())),
            peer_manager: Arc::new(Mutex::new(PeerManager::new())),
            udp: Arc::new(udp),
            stun_client,
        })
    }

    /// Adds a WireGuard tunnel peer to the engine.
    pub async fn add_wg_peer(&self, peer: WireGuardPeer) {
        let mut peers = self.wg_peers.lock().await;
        peers.push(peer);
    }

    /// Returns a shared reference to the peer manager.
    ///
    /// Callers can lock the mutex to add/remove peers, update state,
    /// or query active connections.
    pub fn peer_manager(&self) -> Arc<Mutex<PeerManager>> {
        self.peer_manager.clone()
    }

    /// Returns a shared reference to the WireGuard peers list.
    pub fn wg_peers(&self) -> Arc<Mutex<Vec<WireGuardPeer>>> {
        self.wg_peers.clone()
    }

    /// Runs the main packet processing loop.
    pub async fn run(self) -> anyhow::Result<()> {
        let (mut tun_reader, mut tun_writer) = tokio::io::split(self.tun.device);
        let wg_peers = self.wg_peers.clone();
        let udp = self.udp.clone();
        let peer_manager = self.peer_manager.clone();

        // TUN -> UDP loop
        let tun_to_udp = {
            let wg_peers = wg_peers.clone();
            let udp = udp.clone();
            let peer_manager = peer_manager.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let mut out = [0u8; 2048];
                loop {
                    match tun_reader.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if n < 20 {
                                continue;
                            }
                            let dest_ip_bytes = [buf[16], buf[17], buf[18], buf[19]];
                            let dest_ip = format!("{}.{}.{}.{}", dest_ip_bytes[0], dest_ip_bytes[1], dest_ip_bytes[2], dest_ip_bytes[3]);
                            
                            // 192.168.22.N -> N
                            let target_index = dest_ip_bytes[3];
                            
                            let mut peers = wg_peers.lock().await;
                            let mgr = peer_manager.lock().await;
                            
                            // Find the peer info by virtual_index
                            let target_peer_id = mgr.all_peers().iter()
                                .find(|p| p.info.virtual_index == target_index)
                                .map(|p| p.peer_id);

                            if let Some(peer_id) = target_peer_id {
                                // Find the WG peer by matching public key (mapped via peer_id -> info -> public_key)
                                let peer_info = mgr.get_peer(&peer_id).map(|e| e.info.clone());
                                if let Some(info) = peer_info {
                                    if let Some(peer) = peers.iter_mut().find(|p| {
                                        hex::encode(p.public_key().as_bytes()) == info.public_key
                                    }) {
                                        match peer.encapsulate(&buf[..n], &mut out) {
                                            TunnResult::WriteToNetwork(packet) => {
                                                if let Some(endpoint) = peer.endpoint() {
                                                    match udp.send_to(packet, endpoint).await {
                                                        Ok(_) => {
                                                            eprintln!("[vpn] Sent {} encrypted bytes to {} ({})", packet.len(), dest_ip, endpoint);
                                                        }
                                                        Err(e) => {
                                                            eprintln!("[vpn] Failed to send UDP to {}: {}", endpoint, e);
                                                        }
                                                    }
                                                } else {
                                                    eprintln!("[vpn] No endpoint for peer {}", dest_ip);
                                                }
                                            }
                                            TunnResult::Err(e) => {
                                                eprintln!("[vpn] WG encapsulation error for {}: {:?}", dest_ip, e);
                                            }
                                            _ => {}
                                        }
                                    } else {
                                        // eprintln!("[vpn] No WG peer found for IP {}", dest_ip);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[vpn] TUN read error: {}", e);
                            break;
                        }
                    }
                }
            })
        };

        // UDP -> TUN loop
        let udp_to_tun = {
            let wg_peers = wg_peers.clone();
            let udp = udp.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let mut out = [0u8; 2048];
                while let Ok((n, addr)) = udp.recv_from(&mut buf).await {
                    let mut peers = wg_peers.lock().await;
                    // Find peer by endpoint
                    if let Some(peer) = peers.iter_mut().find(|p| p.endpoint() == Some(addr)) {
                        match peer.decapsulate(&buf[..n], &mut out) {
                            TunnResult::WriteToTunnelV4(packet, _)
                            | TunnResult::WriteToTunnelV6(packet, _) => {
                                if let Err(e) = tun_writer.write_all(packet).await {
                                    eprintln!("[vpn] TUN write error: {}", e);
                                } else {
                                    eprintln!("[vpn] Wrote {} bytes to TUN from {}", packet.len(), addr);
                                }
                            }
                            TunnResult::WriteToNetwork(packet) => {
                                let _ = udp.send_to(packet, addr).await;
                            }
                            TunnResult::Err(e) => {
                                eprintln!("[vpn] WG decapsulation error from {}: {:?}", addr, e);
                            }
                            _ => {}
                        }
                    } else {
                        // If endpoint not found, try all peers (one might be the correct one if endpoint changed)
                        // but only if we have few peers to avoid perf issues.
                        for peer in peers.iter_mut() {
                             match peer.decapsulate(&buf[..n], &mut out) {
                                TunnResult::WriteToTunnelV4(packet, _)
                                | TunnResult::WriteToTunnelV6(packet, _) => {
                                    if let Err(e) = tun_writer.write_all(packet).await {
                                        eprintln!("[vpn] TUN write error: {}", e);
                                    } else {
                                        eprintln!("[vpn] Wrote {} bytes to TUN from {} (new endpoint)", packet.len(), addr);
                                    }
                                    // Update endpoint if it matched
                                    peer.set_endpoint(addr);
                                    break;
                                }
                                TunnResult::WriteToNetwork(packet) => {
                                    let _ = udp.send_to(packet, addr).await;
                                    break;
                                }
                                _ => {}
                             }
                        }
                    }
                }
            })
        };

        // Heartbeat / keep-alive checker task
        let heartbeat_checker = {
            let peer_manager = peer_manager.clone();
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
                loop {
                    interval.tick().await;
                    let mut mgr = peer_manager.lock().await;
                    mgr.check_timeouts(
                        std::time::Duration::from_secs(STALE_TIMEOUT_SECS),
                        std::time::Duration::from_secs(DISCONNECT_TIMEOUT_SECS),
                    );
                }
            })
        };

        let _ = tokio::try_join!(tun_to_udp, udp_to_tun, heartbeat_checker);
        Ok(())
    }
}
