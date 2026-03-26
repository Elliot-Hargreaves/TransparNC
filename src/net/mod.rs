pub mod ice;
pub mod nat;
pub mod peer;
/// Networking implementation including TUN management and WireGuard integration.
pub mod tun;
pub mod wireguard;

use crate::net::nat::StunClient;
use crate::net::peer::PeerManager;
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
    peer_manager: Arc<Mutex<PeerManager>>,
    /// The UDP socket used for sending/receiving encrypted WireGuard packets.
    udp: Arc<UdpSocket>,
    /// Optional STUN client for NAT discovery.
    stun_client: Option<Box<dyn StunClient>>,
}

impl VpnEngine {
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

    /// Runs the main packet processing loop.
    ///
    /// Spawns three concurrent tasks:
    /// 1. TUN → UDP: reads IP packets from the TUN device, encrypts via
    ///    WireGuard, and sends over UDP.
    /// 2. UDP → TUN: receives encrypted packets from UDP, decrypts, and
    ///    writes to the TUN device.
    /// 3. Heartbeat checker: periodically inspects peer timestamps and
    ///    transitions stale/disconnected peers.
    pub async fn run(self) -> anyhow::Result<()> {
        if let Some(stun) = &self.stun_client {
            match stun.discover_external_addr(&self.udp).await {
                Ok(addr) => println!("Discovered external address: {}", addr),
                Err(e) => eprintln!("NAT discovery failed: {}", e),
            }
        }

        let (mut tun_reader, mut tun_writer) = tokio::io::split(self.tun.device);
        let wg_peers = self.wg_peers.clone();
        let udp = self.udp.clone();
        let peer_manager = self.peer_manager.clone();

        // TUN -> UDP loop
        let tun_to_udp = {
            let wg_peers = wg_peers.clone();
            let udp = udp.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let mut out = [0u8; 2048];
                loop {
                    match tun_reader.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let mut peers = wg_peers.lock().await;
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
            let wg_peers = wg_peers.clone();
            let udp = udp.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let mut out = [0u8; 2048];
                while let Ok((n, addr)) = udp.recv_from(&mut buf).await {
                    let mut peers = wg_peers.lock().await;
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
