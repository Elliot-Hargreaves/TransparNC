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
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};

/// Default interval between heartbeat checks in seconds.
const HEARTBEAT_INTERVAL_SECS: u64 = 15;

/// Duration after which a connected peer with no heartbeat becomes stale.
const STALE_TIMEOUT_SECS: u64 = 30;

/// Duration after which a stale peer is considered disconnected.
const DISCONNECT_TIMEOUT_SECS: u64 = 90;

/// Capacity of each per-peer TUN packet channel.
///
/// Sized to absorb a short burst of packets while the peer's forwarding loop
/// catches up, without consuming excessive memory.
const TUN_CHANNEL_CAPACITY: usize = 64;

/// Shared TUN writer — used by the UDP→TUN forwarding loop across all engines.
pub type SharedTunWriter = Arc<Mutex<tokio::io::WriteHalf<tokio_tun::Tun>>>;

/// A handle that allows new peer engines to register themselves with the
/// single TUN reader dispatcher task.
///
/// Each peer registers its virtual index and receives a dedicated channel
/// receiver. The dispatcher routes incoming TUN packets to the correct peer
/// based on the destination IP's last octet.
#[derive(Clone)]
pub struct TunDispatcherHandle {
    /// Sender side of the registration channel.
    register_tx: mpsc::Sender<(u8, mpsc::Sender<Vec<u8>>)>,
}

impl TunDispatcherHandle {
    /// Registers a peer with the given virtual index and returns a receiver
    /// that will yield TUN packets destined for that peer.
    pub async fn register(&self, virtual_index: u8) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(TUN_CHANNEL_CAPACITY);
        // Ignore send errors — they only occur if the dispatcher task has
        // already exited (e.g. TUN device closed), in which case the engine
        // will naturally receive nothing and shut down.
        let _ = self.register_tx.send((virtual_index, tx)).await;
        rx
    }
}

/// Splits a `TunDevice` and spawns a single dispatcher task that owns the
/// read half. Returns a `TunDispatcherHandle` for registering per-peer
/// channels and a `SharedTunWriter` for writing decapsulated packets back.
///
/// The dispatcher reads IP packets from the TUN interface and routes each one
/// to the registered peer whose virtual index matches the packet's destination
/// IP last octet (e.g. 192.168.22.3 → index 3). This eliminates the mutex
/// contention that arose from sharing a single `Arc<Mutex<ReadHalf<Tun>>>`
/// across all peer engines.
pub fn split_tun(tun: TunDevice) -> (TunDispatcherHandle, SharedTunWriter) {
    let (read_half, write_half) = tokio::io::split(tun.device);
    let writer = Arc::new(Mutex::new(write_half));

    // Registration channel: peers send (virtual_index, sender) to subscribe.
    let (register_tx, register_rx) = mpsc::channel::<(u8, mpsc::Sender<Vec<u8>>)>(32);

    tokio::spawn(run_tun_dispatcher(read_half, register_rx));

    let handle = TunDispatcherHandle { register_tx };
    (handle, writer)
}

/// The dispatcher task: owns the TUN read half and routes packets to peers.
///
/// Runs until the TUN device is closed or an unrecoverable read error occurs.
/// New peers can register at any time by sending on the registration channel.
async fn run_tun_dispatcher(
    mut reader: tokio::io::ReadHalf<tokio_tun::Tun>,
    mut register_rx: mpsc::Receiver<(u8, mpsc::Sender<Vec<u8>>)>,
) {
    let mut peers: HashMap<u8, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buf = [0u8; 2048];

    loop {
        tokio::select! {
            // Accept new peer registrations without blocking packet forwarding.
            reg = register_rx.recv() => {
                // Registration channel closed — no more peers will register,
                // but we keep running to drain remaining packets.
                if let Some((index, tx)) = reg {
                    log::debug!("[tun-dispatcher] Registered peer with virtual index {}", index);
                    peers.insert(index, tx);
                }
            }
            // Read the next IP packet from the TUN interface.
            result = reader.read(&mut buf) => {
                match result {
                    Ok(0) | Err(_) => {
                        log::warn!("[tun-dispatcher] TUN read returned 0 or error — shutting down dispatcher");
                        break;
                    }
                    Ok(n) if n < 20 => {
                        // Too short to be a valid IPv4 packet; skip silently.
                    }
                    Ok(n) => {
                        // Route by destination IP last octet (192.168.22.<index>).
                        let dest_index = buf[19];
                        if let Some(tx) = peers.get(&dest_index) {
                            let packet = buf[..n].to_vec();
                            if tx.send(packet).await.is_err() {
                                // Peer engine has exited; remove the stale entry.
                                log::debug!("[tun-dispatcher] Peer {} channel closed, removing", dest_index);
                                peers.remove(&dest_index);
                            }
                        } else {
                            log::debug!("[tun-dispatcher] No peer registered for dest index {}", dest_index);
                        }
                    }
                }
            }
        }
    }
}

/// The main VPN engine that connects TUN interface with a single WireGuard peer.
///
/// Each peer connection gets its own `VpnEngine` instance with a dedicated UDP
/// socket (the one used for ICE hole-punching, now "upgraded" to the data plane).
/// Packets from the TUN interface arrive via a dedicated `mpsc` channel fed by
/// the single `TunDispatcher` task, eliminating mutex contention across peers.
pub struct VpnEngine {
    /// Per-peer channel receiver for TUN packets destined for this peer.
    tun_rx: mpsc::Receiver<Vec<u8>>,
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
    /// `tun_rx` is the per-peer channel receiver from the `TunDispatcher`.
    /// `tun_writer` is shared across all peer engines for writing decapsulated packets.
    /// `udp` is the socket that completed ICE hole-punching — it already has
    /// a working path to the remote peer and must not be rebound.
    /// `wg_peer` is the WireGuard tunnel pre-configured with the remote endpoint.
    /// `virtual_index` is the peer's assigned subnet index (e.g. 2 for 192.168.22.2).
    pub fn new(
        tun_rx: mpsc::Receiver<Vec<u8>>,
        tun_writer: SharedTunWriter,
        udp: Arc<UdpSocket>,
        wg_peer: WireGuardPeer,
        peer_manager: Arc<Mutex<PeerManager>>,
        virtual_index: u8,
    ) -> Self {
        Self {
            tun_rx,
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
    /// - TUN→UDP: receives IP packets from the per-peer channel (fed by the
    ///   TUN dispatcher), WireGuard-encapsulates them, and sends them over UDP.
    /// - UDP→TUN: receives encrypted packets from the peer, decapsulates them,
    ///   and writes the plaintext IP packets back to the TUN interface.
    ///
    /// The `shutdown_rx` oneshot receiver allows the caller to cancel this engine
    /// (e.g. when the remote peer leaves the network), preventing stale WireGuard
    /// handshake attempts to a gone endpoint.
    pub async fn run(self, shutdown_rx: tokio::sync::oneshot::Receiver<()>) -> anyhow::Result<()> {
        let wg_peer = self.wg_peer.clone();
        let udp = self.udp.clone();
        let mut tun_rx = self.tun_rx;
        let tun_writer = self.tun_writer.clone();
        let virtual_index = self.virtual_index;
        let peer_manager = self.peer_manager.clone();

        // TUN -> UDP loop: forward packets received from the dispatcher channel.
        let tun_to_udp = {
            let wg_peer = wg_peer.clone();
            let udp = udp.clone();
            tokio::spawn(async move {
                let mut out = [0u8; 2048];
                while let Some(buf) = tun_rx.recv().await {
                    let n = buf.len();
                    if n < 20 {
                        continue;
                    }

                    let dest_ip = format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19]);
                    log::debug!(
                        "[vpn] Captured {} bytes from TUN. Dest IP: {} (index {})",
                        n,
                        dest_ip,
                        virtual_index
                    );

                    let mut peer = wg_peer.lock().await;
                    match peer.encapsulate(&buf[..n], &mut out) {
                        TunnResult::WriteToNetwork(packet) => {
                            if let Some(endpoint) = peer.endpoint() {
                                match udp.send_to(packet, endpoint).await {
                                    Ok(_) => {
                                        log::debug!(
                                            "[vpn] Sent {} encrypted bytes to {} ({})",
                                            packet.len(),
                                            dest_ip,
                                            endpoint
                                        );
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "[vpn] Failed to send UDP to {}: {}",
                                            endpoint,
                                            e
                                        );
                                    }
                                }
                            } else {
                                log::warn!("[vpn] No endpoint for peer {}", dest_ip);
                            }
                        }
                        TunnResult::Err(e) => {
                            log::warn!("[vpn] WG encapsulation error for {}: {:?}", dest_ip, e);
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
                                log::warn!("[vpn] TUN write error: {}", e);
                            } else {
                                log::debug!(
                                    "[vpn] Wrote {} bytes to TUN from {}",
                                    packet.len(),
                                    addr
                                );
                            }
                        }
                        TunnResult::WriteToNetwork(packet) => {
                            // WireGuard handshake response — send it back.
                            let _ = udp.send_to(packet, addr).await;
                        }
                        TunnResult::Err(e) => {
                            log::warn!("[vpn] WG decapsulation error from {}: {:?}", addr, e);
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

        // Wait for any loop to finish, or for an explicit shutdown signal.
        // The shutdown path is taken when the remote peer leaves the network so
        // we stop sending WireGuard handshakes to a now-gone endpoint.
        tokio::select! {
            _ = tun_to_udp => {}
            _ = udp_to_tun => {}
            _ = heartbeat_checker => {}
            _ = shutdown_rx => {
                log::info!("[vpn] Shutdown signal received for peer index {}", virtual_index);
            }
        }
        Ok(())
    }
}
