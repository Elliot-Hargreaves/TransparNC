pub mod ice;
pub mod nat;
pub mod peer;
/// Networking implementation including TUN management and WireGuard integration.
pub mod tun;
pub mod wireguard;

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

/// Shared TUN I/O halves, split once and shared across all per-peer engines.
///
/// Splitting the TUN device once and wrapping each half in an `Arc<Mutex<…>>`
/// lets multiple `VpnEngine` instances (one per peer) read from and write to
/// the same virtual interface without re-splitting or unsafe sharing.
pub type SharedTunReader = Arc<Mutex<tokio::io::ReadHalf<tokio_tun::Tun>>>;
pub type SharedTunWriter = Arc<Mutex<tokio::io::WriteHalf<tokio_tun::Tun>>>;

/// Splits a `TunDevice` into a shared reader/writer pair suitable for use
/// across multiple `VpnEngine` instances.
pub fn split_tun(tun: TunDevice) -> (SharedTunReader, SharedTunWriter) {
    let (r, w) = tokio::io::split(tun.device);
    (Arc::new(Mutex::new(r)), Arc::new(Mutex::new(w)))
}

/// The main VPN engine that connects TUN interface with a single WireGuard peer.
///
/// Each peer connection gets its own `VpnEngine` instance with a dedicated UDP
/// socket (the one used for ICE hole-punching, now "upgraded" to the data plane).
/// All engines share the same TUN reader/writer pair so IP packets are correctly
/// routed regardless of which peer sent them.
pub struct VpnEngine {
    /// Shared TUN reader — used by the TUN→UDP forwarding loop.
    tun_reader: SharedTunReader,
    /// Shared TUN writer — used by the UDP→TUN forwarding loop.
    tun_writer: SharedTunWriter,
    /// The WireGuard tunnel for this specific peer.
    wg_peer: Arc<Mutex<WireGuardPeer>>,
    /// Tracks peer connection state, heartbeats, and lifecycle transitions.
    pub peer_manager: Arc<Mutex<PeerManager>>,
    /// The UDP socket that was used for ICE and is now the data-plane socket.
    pub udp: Arc<UdpSocket>,
    /// The virtual index of this peer (used to route TUN packets to the right engine).
    virtual_index: u8,
}

impl VpnEngine {
    /// Creates a new per-peer VPN engine.
    ///
    /// `tun_reader` and `tun_writer` are shared across all peer engines.
    /// `udp` is the socket that completed ICE hole-punching — it already has
    /// a working path to the remote peer and must not be rebound.
    /// `wg_peer` is the WireGuard tunnel pre-configured with the remote endpoint.
    /// `virtual_index` is the peer's assigned subnet index (e.g. 2 for 192.168.22.2).
    pub fn new(
        tun_reader: SharedTunReader,
        tun_writer: SharedTunWriter,
        udp: Arc<UdpSocket>,
        wg_peer: WireGuardPeer,
        peer_manager: Arc<Mutex<PeerManager>>,
        virtual_index: u8,
    ) -> Self {
        Self {
            tun_reader,
            tun_writer,
            wg_peer: Arc::new(Mutex::new(wg_peer)),
            peer_manager,
            udp,
            virtual_index,
        }
    }

    /// Runs the packet processing loops for this peer connection.
    ///
    /// Spawns two tasks:
    /// - TUN→UDP: reads IP packets destined for this peer's virtual IP,
    ///   WireGuard-encapsulates them, and sends them over the UDP socket.
    /// - UDP→TUN: receives encrypted packets from the peer, decapsulates them,
    ///   and writes the plaintext IP packets back to the TUN interface.
    pub async fn run(self) -> anyhow::Result<()> {
        let wg_peer = self.wg_peer.clone();
        let udp = self.udp.clone();
        let tun_reader = self.tun_reader.clone();
        let tun_writer = self.tun_writer.clone();
        let virtual_index = self.virtual_index;
        let peer_manager = self.peer_manager.clone();

        // TUN -> UDP loop: forward packets destined for this peer's virtual IP.
        let tun_to_udp = {
            let wg_peer = wg_peer.clone();
            let udp = udp.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let mut out = [0u8; 2048];
                loop {
                    let n = {
                        let mut reader = tun_reader.lock().await;
                        match reader.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!("[vpn] TUN read error: {}", e);
                                break;
                            }
                        }
                    };

                    if n < 20 {
                        continue;
                    }

                    // Only forward packets whose destination IP matches this peer's
                    // virtual index (192.168.22.<virtual_index>).
                    let dest_index = buf[19];
                    if dest_index != virtual_index {
                        continue;
                    }

                    let dest_ip = format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19]);
                    eprintln!("[vpn] Captured {} bytes from TUN. Dest IP: {}", n, dest_ip);

                    let mut peer = wg_peer.lock().await;
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
                }
            })
        };

        // UDP -> TUN loop: receive encrypted packets from this peer and write
        // decapsulated IP packets to the TUN interface.
        let udp_to_tun = {
            let wg_peer = wg_peer.clone();
            let udp = udp.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let mut out = [0u8; 2048];
                while let Ok((n, addr)) = udp.recv_from(&mut buf).await {
                    let mut peer = wg_peer.lock().await;
                    match peer.decapsulate(&buf[..n], &mut out) {
                        TunnResult::WriteToTunnelV4(packet, _)
                        | TunnResult::WriteToTunnelV6(packet, _) => {
                            let mut writer = tun_writer.lock().await;
                            if let Err(e) = writer.write_all(packet).await {
                                eprintln!("[vpn] TUN write error: {}", e);
                            } else {
                                eprintln!("[vpn] Wrote {} bytes to TUN from {}", packet.len(), addr);
                            }
                        }
                        TunnResult::WriteToNetwork(packet) => {
                            // WireGuard handshake response — send it back.
                            let _ = udp.send_to(packet, addr).await;
                        }
                        TunnResult::Err(e) => {
                            eprintln!("[vpn] WG decapsulation error from {}: {:?}", addr, e);
                        }
                        _ => {}
                    }
                }
            })
        };

        // Heartbeat / keep-alive checker task.
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
