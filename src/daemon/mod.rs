//! Daemon mode entry point and IPC server.
//!
//! When the binary is launched with `--daemon`, this module takes over.
//! It listens on a Unix domain socket for commands from the GUI process,
//! manages TUN device lifecycle, and reports status back over IPC.

use crate::common::ipc::{
    ConnectionStatus, DaemonCommand, DaemonEvent, IpcPeerInfo, read_message, write_message,
};
use crate::common::messages::{
    CandidateExchange, NetworkId, PeerId, PeerInfo, SignalingMessage,
};
use crate::net::ice::{Candidate, ConnectivityState, gather_candidates};
use crate::net::peer::{PeerConnectionState, PeerManager, PeerStore};
use crate::net::tun::{TunConfig, TunDevice};
use crate::net::wireguard::{KeyPair, WireGuardPeer};
use futures_util::{SinkExt, StreamExt};
use std::path::Path;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, broadcast};
use tokio_tungstenite::tungstenite;
use uuid::Uuid;

/// Shared daemon state protected by a mutex.
///
/// Holds the current connection status and peer list so that any newly
/// connected GUI client can immediately receive a snapshot.
struct DaemonState {
    /// High-level connection status.
    status: ConnectionStatus,
    /// Currently known peers.
    peers: Vec<IpcPeerInfo>,
    /// The active TUN interface for the connection.
    tun: Option<TunDevice>,
    /// Handle to the VPN engine's peer manager (for querying/updating states).
    engine_peer_manager: Option<Arc<Mutex<PeerManager>>>,
    /// Handle to the VPN engine's WireGuard peers list for adding endpoints.
    engine_wg_peers: Option<Arc<Mutex<Vec<crate::net::wireguard::WireGuardPeer>>>>,
}

impl DaemonState {
    /// Creates a new daemon state in the disconnected state.
    fn new() -> Self {
        Self {
            status: ConnectionStatus::Disconnected,
            peers: Vec::new(),
            tun: None,
            engine_peer_manager: None,
            engine_wg_peers: None,
        }
    }
}

/// Runs the daemon, listening for GUI connections on the given socket path.
///
/// The daemon will remove any stale socket file, bind a new `UnixListener`,
/// and accept GUI clients in a loop. A broadcast channel is used to fan-out
/// events to all connected clients. The daemon shuts down when it receives
/// a `Shutdown` command.
pub async fn run(socket_path: &str) -> anyhow::Result<()> {
    // Clean up stale socket from a previous run.
    if Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    eprintln!("[daemon] Listening on {}", socket_path);

    // Make the socket world-accessible so the unprivileged GUI can connect.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o777))?;
    }

    let state = Arc::new(Mutex::new(DaemonState::new()));
    // Broadcast channel for pushing events to all connected GUI clients.
    let (event_tx, _) = broadcast::channel::<DaemonEvent>(64);
    // Shutdown signal — when fired, the accept loop and all handlers exit.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, _addr) = accept_result?;
                let state = state.clone();
                let event_tx = event_tx.clone();
                let event_rx = event_tx.subscribe();
                let shutdown_tx = shutdown_tx.clone();
                tokio::spawn(handle_client(stream, state, event_tx, event_rx, shutdown_tx));
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }

    // Cleanup the socket file on exit.
    let _ = std::fs::remove_file(socket_path);
    eprintln!("[daemon] Shut down cleanly.");
    Ok(())
}

/// Handles a single GUI client connection.
///
/// Sends the current state snapshot immediately, then enters a loop reading
/// commands and forwarding broadcast events back to the client.
async fn handle_client(
    stream: UnixStream,
    state: Arc<Mutex<DaemonState>>,
    event_tx: broadcast::Sender<DaemonEvent>,
    mut event_rx: broadcast::Receiver<DaemonEvent>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) {
    let (mut reader, mut writer) = stream.into_split();

    // Send the current state snapshot so a reconnecting GUI is up-to-date.
    {
        let st = state.lock().await;
        let _ = write_message(
            &mut writer,
            &DaemonEvent::StatusUpdate {
                status: st.status.clone(),
            },
        )
        .await;
        if !st.peers.is_empty() {
            let _ = write_message(
                &mut writer,
                &DaemonEvent::PeerUpdate {
                    peers: st.peers.clone(),
                },
            )
            .await;
        }
    }

    loop {
        tokio::select! {
            // Forward broadcast events from the daemon to this client.
            Ok(event) = event_rx.recv() => {
                if write_message(&mut writer, &event).await.is_err() {
                    break;
                }
            }
            // Read commands from the GUI client.
            cmd_result = read_message::<DaemonCommand>(&mut reader) => {
                match cmd_result {
                    Ok(Some(cmd)) => {
                        handle_command(cmd, &state, &event_tx, &shutdown_tx, &mut writer).await;
                    }
                    // Client disconnected or protocol error — stop this handler.
                    _ => break,
                }
            }
        }
    }
}

/// Processes a single command from a GUI client.
///
/// Mutates shared daemon state and broadcasts resulting events to all
/// connected clients.
async fn handle_command(
    cmd: DaemonCommand,
    state: &Arc<Mutex<DaemonState>>,
    event_tx: &broadcast::Sender<DaemonEvent>,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
) {
    match cmd {
        DaemonCommand::GetStatus => {
            let st = state.lock().await;
            let _ = write_message(
                writer,
                &DaemonEvent::StatusUpdate {
                    status: st.status.clone(),
                },
            )
            .await;
        }
        DaemonCommand::Connect { network_id } => {
            eprintln!("[daemon] Connect requested for network: {}", network_id);
            let mut st = state.lock().await;
            st.status = ConnectionStatus::Connecting;
            let _ = event_tx.send(DaemonEvent::StatusUpdate {
                status: st.status.clone(),
            });
            // TODO: actually create TUN and start WireGuard here.
            // For now, simulate a successful connection.
            st.status = ConnectionStatus::Connected {
                virtual_ip: "192.168.22.1".to_string(),
            };
            let _ = event_tx.send(DaemonEvent::StatusUpdate {
                status: st.status.clone(),
            });
        }
        DaemonCommand::Disconnect => {
            eprintln!("[daemon] Disconnect requested.");
            let mut st = state.lock().await;
            st.status = ConnectionStatus::Disconnected;
            st.peers.clear();
            let _ = event_tx.send(DaemonEvent::StatusUpdate {
                status: st.status.clone(),
            });
        }
        DaemonCommand::Shutdown => {
            eprintln!("[daemon] Shutdown requested — tearing down TUN devices.");
            // TODO: actually tear down TUN devices here.
            let _ = write_message(writer, &DaemonEvent::ShuttingDown).await;
            let _ = event_tx.send(DaemonEvent::ShuttingDown);
            // Signal the accept loop to exit.
            let _ = shutdown_tx.send(true);
        }
        DaemonCommand::JoinNetwork {
            network_id,
            signaling_server,
        } => {
            eprintln!(
                "[daemon] Join network '{}' via signaling server '{}'",
                network_id, signaling_server
            );
            let mut st = state.lock().await;
            st.status = ConnectionStatus::Connecting;
            let _ = event_tx.send(DaemonEvent::StatusUpdate {
                status: st.status.clone(),
            });
            drop(st);

            // Parse the network_id as a UUID; if it fails, derive one
            // deterministically from the name so arbitrary strings still work.
            let net_uuid =
                Uuid::parse_str(&network_id).unwrap_or_else(|_| name_to_uuid(&network_id));

            let state = state.clone();
            let event_tx = event_tx.clone();
            tokio::spawn(async move {
                connect_to_signaling(&signaling_server, NetworkId(net_uuid), &state, &event_tx)
                    .await;
            });
        }
        DaemonCommand::CreateNetwork {
            network_name,
            signaling_server,
        } => {
            eprintln!(
                "[daemon] Create network '{}' via signaling server '{}'",
                network_name, signaling_server
            );
            let mut st = state.lock().await;
            st.status = ConnectionStatus::Connecting;
            let _ = event_tx.send(DaemonEvent::StatusUpdate {
                status: st.status.clone(),
            });
            drop(st);

            // Generate a deterministic network UUID from the chosen name so
            // that other peers can join using the same name string.
            let net_uuid = name_to_uuid(&network_name);
            eprintln!(
                "[daemon] Network '{}' mapped to UUID {}",
                network_name, net_uuid
            );

            let state = state.clone();
            let event_tx = event_tx.clone();
            tokio::spawn(async move {
                connect_to_signaling(&signaling_server, NetworkId(net_uuid), &state, &event_tx)
                    .await;
            });
        }
    }
}

/// Derives a deterministic UUID from an arbitrary network name string.
///
/// Uses a simple hash-based approach to produce a reproducible UUID so that
/// two peers using the same human-readable name will arrive at the same
/// network identifier.
fn name_to_uuid(name: &str) -> Uuid {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // Include a fixed namespace prefix to avoid collisions with random UUIDs.
    "transparnc-network:".hash(&mut hasher);
    name.hash(&mut hasher);
    let hash = hasher.finish();
    // Build a UUID from the 64-bit hash, zero-filling the upper half.
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&hash.to_be_bytes());
    bytes[8..16].copy_from_slice(&hash.to_le_bytes());
    Uuid::from_bytes(bytes)
}

/// Connects to the signaling server over WebSocket, sends a `Join` message,
/// and listens for responses. Updates daemon state and broadcasts events to
/// GUI clients as peers are discovered.
async fn connect_to_signaling(
    signaling_server: &str,
    network_id: NetworkId,
    state: &Arc<Mutex<DaemonState>>,
    event_tx: &broadcast::Sender<DaemonEvent>,
) {
    let url = format!("ws://{}/ws", signaling_server);
    eprintln!("[daemon] Connecting to signaling server at {}", url);

    let ws_stream = match tokio_tungstenite::connect_async(&url).await {
        Ok((stream, _response)) => {
            eprintln!("[daemon] WebSocket connection established to {}", url);
            stream
        }
        Err(e) => {
            eprintln!("[daemon] Failed to connect to signaling server: {}", e);
            let mut st = state.lock().await;
            st.status = ConnectionStatus::Disconnected;
            let _ = event_tx.send(DaemonEvent::StatusUpdate {
                status: st.status.clone(),
            });
            let _ = event_tx.send(DaemonEvent::Error {
                message: format!("Failed to connect to signaling server: {}", e),
            });
            return;
        }
    };

    let (mut ws_writer, mut ws_reader) = ws_stream.split();

    // Generate real X25519 keys for this session.
    let keypair = KeyPair::generate();
    let static_private = keypair.private.clone();
    let public_key = hex::encode(keypair.public.as_bytes());

    // Local port for UDP/ICE (hardcoded for now, should be dynamic)
    let local_port = 51820;
    let udp = match tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await {
        Ok(u) => Arc::new(u),
        Err(e) => {
            eprintln!("[daemon] Failed to bind UDP socket on {}: {}", local_port, e);
            return;
        }
    };

    // Trace local candidates
    let local_candidates = crate::net::ice::gather_host_candidates(local_port);
    for candidate in &local_candidates {
        eprintln!(
            "[daemon] Gathered local ICE candidate: {:?} ({})",
            candidate.candidate_type, candidate.addr
        );
    }

    // Prepare signaling message to exchange candidates
    let exchange = CandidateExchange {
        candidates: local_candidates.clone(),
    };
    let exchange_json = serde_json::to_string(&exchange).unwrap();

    // Generate a unique peer ID.
    let peer_id = PeerId(Uuid::new_v4());

    let join_msg = SignalingMessage::Join {
        network_id,
        peer_id,
        public_key,
    };
    let join_json = serde_json::to_string(&join_msg).expect("failed to serialize Join message");
    eprintln!("[daemon] Sending Join message: {}", join_json);

    if let Err(e) = ws_writer
        .send(tungstenite::Message::Text(join_json.into()))
        .await
    {
        eprintln!("[daemon] Failed to send Join message: {}", e);
        let mut st = state.lock().await;
        st.status = ConnectionStatus::Disconnected;
        let _ = event_tx.send(DaemonEvent::StatusUpdate {
            status: st.status.clone(),
        });
        return;
    }

    // Listen for signaling messages from the server.
    while let Some(msg_result) = ws_reader.next().await {
        match msg_result {
            Ok(tungstenite::Message::Text(text)) => {
                eprintln!("[daemon] Received from signaling server: {}", text);
                match serde_json::from_str::<SignalingMessage>(&text) {
                    Ok(SignalingMessage::Joined {
                        peers,
                        assigned_index,
                    }) => {
                        eprintln!(
                            "[daemon] Joined network successfully, {} existing peer(s). Assigned index: {}",
                            peers.len(),
                            assigned_index
                        );

                        // Use the hardcoded 192.168.22.N IP.
                        let ip_str = format!("192.168.22.{}", assigned_index);
                        let ip = ip_str.parse::<std::net::Ipv4Addr>().unwrap();

                        let config = TunConfig {
                            name: "transparnc0".to_string(),
                            address: ip,
                            netmask: "255.255.255.0".parse().unwrap(),
                            mtu: 1420,
                        };

                        let (assigned_ip, tun_device) = match TunDevice::new(config) {
                            Ok(tun) => {
                                eprintln!(
                                    "[daemon] Successfully created TUN device with IP {}",
                                    ip_str
                                );
                                (Some(ip_str), Some(tun))
                            }
                            Err(e) => {
                                eprintln!(
                                    "[daemon] Failed to create TUN device with IP {}: {}",
                                    ip_str, e
                                );
                                (None, None)
                            }
                        };

                        if let (Some(ip), Some(tun)) = (assigned_ip, tun_device) {
                            let ipc_peers: Vec<IpcPeerInfo> = peers
                                .iter()
                                .map(|p| IpcPeerInfo {
                                    name: p.peer_id.0.to_string(),
                                    virtual_ip: format!("192.168.22.{}", p.virtual_index),
                                    connected: false,
                                })
                                .collect();

                            // Instantiate VpnEngine.
                            let engine = match crate::net::VpnEngine::with_socket(tun, udp.clone(), None) {
                                Ok(e) => e,
                                Err(e) => {
                                    eprintln!("[daemon] Failed to create VpnEngine: {}", e);
                                    return;
                                }
                            };

                            let mut st = state.lock().await;
                            st.status = ConnectionStatus::Connected { virtual_ip: ip };
                            st.peers = ipc_peers.clone();
                            st.tun = None; // VpnEngine took ownership of the TUN device.
                            st.engine_peer_manager = Some(engine.peer_manager());
                            st.engine_wg_peers = Some(engine.wg_peers());
                            let _ = event_tx.send(DaemonEvent::StatusUpdate {
                                status: st.status.clone(),
                            });
                            let _ = event_tx.send(DaemonEvent::PeerUpdate { peers: ipc_peers });

                            // Add initial peers to VpnEngine and start signaling them.
                            for p in &peers {
                                let peer_id_remote = p.peer_id;
                                let peer_info = p.clone();
                                let peer_manager = engine.peer_manager();
                                let mut mgr = peer_manager.lock().await;
                                let _ = mgr.add_peer(peer_info.clone());

                                // Send our ICE candidates to the newly discovered peer.
                                let signal = SignalingMessage::Signal {
                                    to: peer_id_remote,
                                    from: peer_id,
                                    data: exchange_json.clone(),
                                };
                                if let Ok(json) = serde_json::to_string(&signal) {
                                    let _ = ws_writer
                                        .send(tungstenite::Message::Text(json.into()))
                                        .await;
                                }
                            }

                            // Run VPN Engine in the background (move ownership).
                            tokio::spawn(async move {
                                if let Err(e) = engine.run().await {
                                    eprintln!("[daemon] VpnEngine exited with error: {}", e);
                                }
                            });
                        } else {
                            eprintln!(
                                "[daemon] Could not find an available subnet for IP index {}",
                                assigned_index
                            );
                            let mut st = state.lock().await;
                            st.status = ConnectionStatus::Disconnected;
                            let _ = event_tx.send(DaemonEvent::StatusUpdate {
                                status: st.status.clone(),
                            });
                            let _ = event_tx.send(DaemonEvent::Error {
                                message: "Failed to allocate a local virtual IP".to_string(),
                            });
                            return;
                        }
                    }
                    Ok(SignalingMessage::PeerJoined { peer }) => {
                        eprintln!(
                            "[daemon] New peer joined: {:?} with index {}",
                            peer.peer_id, peer.virtual_index
                        );

                        // If we are connected, send our candidates to the newcomer.
                        let is_connected = {
                            let st = state.lock().await;
                            matches!(st.status, ConnectionStatus::Connected { .. })
                        };

                        if is_connected {
                            // Also add the peer to our peer manager if it's not already there.
                            let peer_manager = {
                                let st = state.lock().await;
                                st.engine_peer_manager.clone()
                            };

                            if let Some(peer_manager) = peer_manager {
                                let mut mgr = peer_manager.lock().await;
                                if mgr.get_peer(&peer.peer_id).is_none() {
                                    let _ = mgr.add_peer(peer.clone());
                                }
                            }

                            let signal = SignalingMessage::Signal {
                                to: peer.peer_id,
                                from: peer_id,
                                data: exchange_json.clone(),
                            };
                            if let Ok(json) = serde_json::to_string(&signal) {
                                let _ = ws_writer
                                    .send(tungstenite::Message::Text(json.into()))
                                    .await;
                            }
                        }

                        let mut st = state.lock().await;
                        st.peers.push(IpcPeerInfo {
                            name: peer.peer_id.0.to_string(),
                            virtual_ip: format!("192.168.22.{}", peer.virtual_index),
                            connected: false,
                        });
                        let _ = event_tx.send(DaemonEvent::PeerUpdate {
                            peers: st.peers.clone(),
                        });
                    }
                    Ok(SignalingMessage::PeerLeft { peer_id }) => {
                        eprintln!("[daemon] Peer left: {:?}", peer_id);
                        let mut st = state.lock().await;
                        st.peers.retain(|p| p.name != peer_id.0.to_string());
                        let _ = event_tx.send(DaemonEvent::PeerUpdate {
                            peers: st.peers.clone(),
                        });
                    }
                    Ok(SignalingMessage::Signal { from, data, .. }) => {
                        eprintln!(
                            "[daemon] Received signal from peer {:?}: length={}",
                            from,
                            data.len()
                        );
                        if let Ok(exchange) = serde_json::from_str::<CandidateExchange>(&data) {
                            eprintln!(
                                "[daemon] Received {} remote ICE candidates from {:?}",
                                exchange.candidates.len(),
                                from
                            );

                            // Start hole punching and WireGuard session in the background.
                            let udp_clone = udp.clone();
                            let from_peer_id = from;
                            let remote_candidates = exchange.candidates;
                            let state_clone = state.clone();
                            let static_private_clone = static_private.clone();

                            tokio::spawn(async move {
                                let (conn_state, result) = crate::net::ice::establish_connectivity(
                                    &udp_clone,
                                    None, // STUN handled by VpnEngine/manually if needed
                                    remote_candidates,
                                )
                                .await;

                                if let Ok(selected_pair) = result {
                                    eprintln!(
                                        "[daemon] ICE connection established with {:?} via {:?}",
                                        from_peer_id, selected_pair.remote.addr
                                    );

                                    // Create WireGuard peer and add to VpnEngine.
                                    let (peer_manager, wg_peers) = {
                                        let st = state_clone.lock().await;
                                        (st.engine_peer_manager.clone(), st.engine_wg_peers.clone())
                                    };

                                    if let (Some(peer_manager), Some(wg_peers)) = (peer_manager, wg_peers) {
                                        let peer_info = {
                                            let mgr = peer_manager.lock().await;
                                            mgr.get_peer(&from_peer_id).map(|e| e.info.clone())
                                        };

                                        if let Some(info) = peer_info {
                                            if let Ok(peer_pub_bytes) = hex::decode(&info.public_key) {
                                                if peer_pub_bytes.len() == 32 {
                                                    let mut bytes = [0u8; 32];
                                                    bytes.copy_from_slice(&peer_pub_bytes);
                                                    let peer_static_public =
                                                        boringtun::x25519::PublicKey::from(bytes);

                                                    let wg_peer = WireGuardPeer::new(
                                                        static_private_clone,
                                                        peer_static_public,
                                                        None,
                                                        Some(25),
                                                        0, // index
                                                        Some(selected_pair.remote.addr),
                                                    );

                                                    if let Ok(peer) = wg_peer {
                                                        let mut peers = wg_peers.lock().await;
                                                        peers.push(peer);
                                                        let mut mgr = peer_manager.lock().await;
                                                        let _ = mgr.update_state(
                                                            &from_peer_id,
                                                            PeerConnectionState::Connected,
                                                        );
                                                        eprintln!(
                                                            "[daemon] WireGuard peer added for {:?}",
                                                            from_peer_id
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    eprintln!(
                                        "[daemon] ICE connection failed for peer {:?}: {:?}",
                                        from_peer_id, conn_state
                                    );
                                }
                            });
                        } else {
                            eprintln!("[daemon] Failed to parse Signal data as CandidateExchange");
                        }
                    }
                    Ok(other) => {
                        eprintln!("[daemon] Unhandled signaling message: {:?}", other);
                    }
                    Err(e) => {
                        eprintln!("[daemon] Failed to parse signaling message: {}", e);
                    }
                }
            }
            Ok(tungstenite::Message::Close(_)) => {
                eprintln!("[daemon] Signaling server closed the connection");
                break;
            }
            Err(e) => {
                eprintln!("[daemon] WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    // Connection lost — update state.
    eprintln!("[daemon] Disconnected from signaling server");
    let mut st = state.lock().await;
    st.status = ConnectionStatus::Disconnected;
    st.peers.clear();
    let _ = event_tx.send(DaemonEvent::StatusUpdate {
        status: st.status.clone(),
    });
}
