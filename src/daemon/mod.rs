//! Daemon mode entry point and IPC server.
//!
//! When the binary is launched with `--daemon`, this module takes over.
//! It listens on a Unix domain socket for commands from the GUI process,
//! manages TUN device lifecycle, and reports status back over IPC.

use crate::common::ipc::{
    ConnectionStatus, DaemonCommand, DaemonEvent, IpcPeerInfo, read_message, write_message,
};
use crate::common::messages::{
    CandidateExchange, NetworkId, PeerId, SignalingMessage,
};
use crate::net::ice::Candidate;
use crate::net::nat::RealStunClient;
use crate::net::peer::{PeerConnectionState, PeerManager, PeerStore};
use crate::net::tun::{TunConfig, TunDevice};
use crate::net::wireguard::{KeyPair, WireGuardPeer};
use crate::net::{SharedTunReader, SharedTunWriter, split_tun};
use futures_util::{SinkExt, StreamExt};
use std::path::Path;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream, UdpSocket};
use tokio::sync::{Mutex, broadcast, mpsc};
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
    /// Shared TUN reader — handed to each per-peer VpnEngine.
    tun_reader: Option<SharedTunReader>,
    /// Shared TUN writer — handed to each per-peer VpnEngine.
    tun_writer: Option<SharedTunWriter>,
    /// Shared peer manager across all per-peer engines.
    peer_manager: Option<Arc<Mutex<PeerManager>>>,
}

impl DaemonState {
    /// Creates a new daemon state in the disconnected state.
    fn new() -> Self {
        Self {
            status: ConnectionStatus::Disconnected,
            peers: Vec::new(),
            tun_reader: None,
            tun_writer: None,
            peer_manager: None,
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

/// Runs the networking stack in the foreground without a GUI or IPC socket.
///
/// Intended for headless/CLI testing environments. Joins the given network
/// via the signaling server and blocks until the user sends SIGINT (Ctrl-C).
/// The codepath through `connect_to_signaling` is identical to what the daemon
/// executes when it receives a `JoinNetwork` command from the GUI.
pub async fn run_headless(network: &str, signaling_server: &str) -> anyhow::Result<()> {
    eprintln!("[headless] Joining network '{}' via '{}'", network, signaling_server);

    let net_uuid = Uuid::parse_str(network).unwrap_or_else(|_| name_to_uuid(network));
    eprintln!("[headless] Resolved network UUID: {}", net_uuid);

    let state = Arc::new(Mutex::new(DaemonState::new()));
    let (event_tx, mut event_rx) = broadcast::channel::<DaemonEvent>(64);

    // Mark as connecting before handing off to the signaling task.
    {
        let mut st = state.lock().await;
        st.status = ConnectionStatus::Connecting;
    }

    // Spawn the same signaling/connection task the daemon uses when it receives
    // a JoinNetwork command from the GUI.
    let state_clone = state.clone();
    let event_tx_clone = event_tx.clone();
    let signaling_server = signaling_server.to_string();
    tokio::spawn(async move {
        connect_to_signaling(&signaling_server, NetworkId(net_uuid), &state_clone, &event_tx_clone).await;
    });

    // Print events to stderr so the operator can observe what's happening,
    // and block until Ctrl-C is received.
    loop {
        tokio::select! {
            Ok(event) = event_rx.recv() => {
                eprintln!("[headless] Event: {:?}", event);
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[headless] Shutting down.");
                break;
            }
        }
    }

    Ok(())
}

/// Deterministically maps a human-readable network name to a UUID.
fn name_to_uuid(name: &str) -> Uuid {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    "transparnc-network:".hash(&mut hasher);
    name.hash(&mut hasher);
    let hash = hasher.finish();
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&hash.to_be_bytes());
    bytes[8..16].copy_from_slice(&hash.to_le_bytes());
    Uuid::from_bytes(bytes)
}

/// Gathers ICE candidates (host + STUN) for a given UDP socket.
///
/// Returns the candidate list and the JSON-serialised `CandidateExchange`
/// ready to be forwarded to a remote peer via the signaling server.
async fn gather_candidates_for_socket(
    socket: &UdpSocket,
    stun_server: &str,
) -> (Vec<Candidate>, String) {
    let stun_client = RealStunClient::new(stun_server.to_string());
    let candidates = match crate::net::ice::gather_candidates(Some(&stun_client), socket).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[daemon] Candidate gathering failed: {}", e);
            let port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
            crate::net::ice::gather_host_candidates(port)
        }
    };
    for c in &candidates {
        eprintln!("[daemon] Gathered local candidate: {:?} ({})", c.candidate_type, c.addr);
    }
    let exchange = CandidateExchange { candidates: candidates.clone() };
    let json = serde_json::to_string(&exchange).unwrap_or_default();
    (candidates, json)
}

/// Connects to the signaling server, joins the network, and manages the
/// peer-to-peer connection lifecycle.
///
/// Each peer connection uses its own ephemeral UDP socket so that ICE
/// hole-punching and the WireGuard data plane never share a socket — this
/// eliminates the race condition where the VpnEngine's receive loop would
/// consume ICE ACK packets before the connectivity check could see them.
async fn connect_to_signaling(
    signaling_server: &str,
    network_id: NetworkId,
    state: &Arc<Mutex<DaemonState>>,
    event_tx: &broadcast::Sender<DaemonEvent>,
) {
    let url = format!("ws://{}/ws", signaling_server);
    eprintln!("[daemon] Connecting to signaling server at {}", url);

    let ws_stream = match tokio_tungstenite::connect_async(&url).await {
        Ok((stream, _)) => {
            eprintln!("[daemon] WebSocket connection established to {}", url);
            stream
        }
        Err(e) => {
            eprintln!("[daemon] Failed to connect to signaling server: {}", e);
            let mut st = state.lock().await;
            st.status = ConnectionStatus::Disconnected;
            let _ = event_tx.send(DaemonEvent::StatusUpdate { status: st.status.clone() });
            let _ = event_tx.send(DaemonEvent::Error { message: format!("Failed to connect: {}", e) });
            return;
        }
    };

    let (mut ws_writer, mut ws_reader) = ws_stream.split();
    let keypair = KeyPair::generate();
    let static_private = keypair.private.clone();
    let public_key = hex::encode(keypair.public.as_bytes());
    let stun_server = "stun.l.google.com:19302".to_string();

    // Send an empty candidate list as the trigger signal. Its only purpose
    // is to prompt the remote peer to start its ICE flow toward us. The
    // remote peer will respond with its real STUN-discovered candidates,
    // which will trigger our own ICE run. Sending port-0 placeholder
    // candidates here would cause the remote peer to probe invalid addresses.
    let init_exchange_json = {
        let exchange = CandidateExchange { candidates: vec![] };
        serde_json::to_string(&exchange).unwrap_or_default()
    };

    let peer_id = PeerId(Uuid::new_v4());
    let join_msg = SignalingMessage::Join { network_id, peer_id, public_key };
    let join_json = serde_json::to_string(&join_msg).unwrap();
    eprintln!("[daemon] Sending Join: {}", join_json);

    if let Err(e) = ws_writer.send(tungstenite::Message::Text(join_json.into())).await {
        eprintln!("[daemon] Failed to send Join: {}", e);
        let mut st = state.lock().await;
        st.status = ConnectionStatus::Disconnected;
        let _ = event_tx.send(DaemonEvent::StatusUpdate { status: st.status.clone() });
        return;
    }

    // Channel used by per-peer ICE tasks to send their per-peer candidate JSON
    // back to the signaling loop so it can forward it to the remote peer.
    let (peer_signal_tx, mut peer_signal_rx) = mpsc::channel::<(PeerId, String)>(16);

    loop {
        tokio::select! {
            // Forward per-peer candidate updates back through the signaling server.
            Some((to_peer, candidates_json)) = peer_signal_rx.recv() => {
                let signal = SignalingMessage::Signal {
                    to: to_peer,
                    from: peer_id,
                    data: candidates_json,
                };
                if let Ok(json) = serde_json::to_string(&signal) {
                    let _ = ws_writer.send(tungstenite::Message::Text(json.into())).await;
                }
            }
            msg_result = ws_reader.next() => {
                let msg = match msg_result {
                    Some(Ok(m)) => m,
                    _ => break,
                };
                match msg {
                    tungstenite::Message::Text(text) => {
                        eprintln!("[daemon] Received signal: {}", text);
                        if let Ok(sig_msg) = serde_json::from_str::<SignalingMessage>(&text) {
                            match sig_msg {
                                SignalingMessage::Joined { peers, assigned_index } => {
                                    eprintln!("[daemon] Joined network. Index: {}", assigned_index);
                                    let ip_str = format!("192.168.22.{}", assigned_index);
                                    let ip = ip_str.parse::<std::net::Ipv4Addr>().unwrap();
                                    let config = TunConfig {
                                        name: "transparnc0".to_string(),
                                        address: ip,
                                        netmask: "255.255.255.0".parse().unwrap(),
                                        mtu: 1420,
                                    };
                                    match TunDevice::new(config) {
                                        Ok(tun) => {
                                            eprintln!("[daemon] Successfully created TUN device with IP {}", ip_str);
                                            let (tun_reader, tun_writer) = split_tun(tun);
                                            let peer_manager = Arc::new(Mutex::new(PeerManager::new()));
                                            let ipc_peers: Vec<IpcPeerInfo> = peers.iter().map(|p| IpcPeerInfo {
                                                name: p.peer_id.0.to_string(),
                                                virtual_ip: format!("192.168.22.{}", p.virtual_index),
                                                connected: false,
                                            }).collect();
                                            {
                                                let mut st = state.lock().await;
                                                st.status = ConnectionStatus::Connected { virtual_ip: ip_str };
                                                st.peers = ipc_peers.clone();
                                                st.tun_reader = Some(tun_reader);
                                                st.tun_writer = Some(tun_writer);
                                                st.peer_manager = Some(peer_manager.clone());
                                                let _ = event_tx.send(DaemonEvent::StatusUpdate { status: st.status.clone() });
                                                let _ = event_tx.send(DaemonEvent::PeerUpdate { peers: ipc_peers });
                                            }
                                            // For each existing peer, initiate the per-peer ICE flow.
                                            for p in &peers {
                                                {
                                                    let mut mgr = peer_manager.lock().await;
                                                    let _ = mgr.add_peer(p.clone());
                                                }
                                                // Send our initial candidates so the existing peer
                                                // knows to start its own ICE flow toward us.
                                                let signal = SignalingMessage::Signal {
                                                    to: p.peer_id,
                                                    from: peer_id,
                                                    data: init_exchange_json.clone(),
                                                };
                                                if let Ok(json) = serde_json::to_string(&signal) {
                                                    let _ = ws_writer.send(tungstenite::Message::Text(json.into())).await;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("[daemon] Failed to create TUN device: {}", e);
                                        }
                                    }
                                }
                                SignalingMessage::PeerJoined { peer: p } => {
                                    eprintln!("[daemon] New peer: {:?}", p.peer_id);
                                    let (pm, connected) = {
                                        let st = state.lock().await;
                                        (st.peer_manager.clone(), matches!(st.status, ConnectionStatus::Connected { .. }))
                                    };
                                    if connected {
                                        if let Some(pm) = pm {
                                            let mut mgr = pm.lock().await;
                                            if mgr.get_peer(&p.peer_id).is_none() {
                                                let _ = mgr.add_peer(p.clone());
                                            }
                                        }
                                        // Send our initial candidates to trigger the ICE flow.
                                        let signal = SignalingMessage::Signal {
                                            to: p.peer_id,
                                            from: peer_id,
                                            data: init_exchange_json.clone(),
                                        };
                                        if let Ok(json) = serde_json::to_string(&signal) {
                                            let _ = ws_writer.send(tungstenite::Message::Text(json.into())).await;
                                        }
                                    }
                                    let mut st = state.lock().await;
                                    st.peers.push(IpcPeerInfo {
                                        name: p.peer_id.0.to_string(),
                                        virtual_ip: format!("192.168.22.{}", p.virtual_index),
                                        connected: false,
                                    });
                                    let _ = event_tx.send(DaemonEvent::PeerUpdate { peers: st.peers.clone() });
                                }
                                SignalingMessage::PeerLeft { peer_id: p_id } => {
                                    eprintln!("[daemon] Peer left: {:?}", p_id);
                                    let mut st = state.lock().await;
                                    st.peers.retain(|p| p.name != p_id.0.to_string());
                                    let _ = event_tx.send(DaemonEvent::PeerUpdate { peers: st.peers.clone() });
                                }
                                SignalingMessage::Signal { from, data, .. } => {
                                    eprintln!("[daemon] Signal from {:?}", from);
                                    if let Ok(ex) = serde_json::from_str::<CandidateExchange>(&data) {
                                        if ex.candidates.is_empty() {
                                            // Trigger signal — the remote peer is telling us to
                                            // start our ICE flow. Bind the data-plane socket now,
                                            // do STUN once, send our candidates back, and store
                                            // the socket + candidates in PeerEntry.ice_state so
                                            // the real ICE run can reuse them without a second
                                            // STUN request. The peer stays in `Discovered` so
                                            // the real signal passes the guard below.
                                            let st_c = state.clone();
                                            let stun_server_c = stun_server.clone();
                                            let peer_signal_tx_c = peer_signal_tx.clone();
                                            tokio::spawn(async move {
                                                let ice_socket = match UdpSocket::bind("0.0.0.0:0").await {
                                                    Ok(s) => Arc::new(s),
                                                    Err(e) => {
                                                        eprintln!("[daemon] Failed to bind trigger socket for {:?}: {}", from, e);
                                                        return;
                                                    }
                                                };
                                                let (local_candidates, candidates_json) =
                                                    gather_candidates_for_socket(&ice_socket, &stun_server_c).await;
                                                eprintln!(
                                                    "[daemon] Trigger signal from {:?}: sending candidates (port {}), awaiting real candidates to start ICE.",
                                                    from,
                                                    ice_socket.local_addr().map(|a| a.port()).unwrap_or(0)
                                                );
                                                let _ = peer_signal_tx_c.send((from, candidates_json)).await;
                                                // Store the socket and candidates so the real ICE
                                                // path can take them without rebinding or re-STUNing.
                                                let st = st_c.lock().await;
                                                if let Some(pm) = &st.peer_manager {
                                                    let mut mgr = pm.lock().await;
                                                    if let Some(entry) = mgr.get_peer_mut(&from) {
                                                        entry.ice_state = Some((ice_socket, local_candidates));
                                                    }
                                                }
                                            });
                                        } else {
                                            // Real signal with actual candidates. Only proceed if
                                            // the peer is in `Discovered` state, atomically
                                            // transitioning to `Negotiating` to prevent a
                                            // ping-pong loop. Take the stored ice_state (socket +
                                            // candidates from the trigger phase) so we don't need
                                            // a second STUN request.
                                            let (should_handle, stored_ice_state) = {
                                                let st = state.lock().await;
                                                if let Some(pm) = &st.peer_manager {
                                                    let mut mgr = pm.lock().await;
                                                    if let Some(entry) = mgr.get_peer_mut(&from) {
                                                        if entry.state == PeerConnectionState::Discovered {
                                                            let ice_state = entry.ice_state.take();
                                                            let _ = mgr.update_state(&from, PeerConnectionState::Negotiating);
                                                            (true, ice_state)
                                                        } else {
                                                            eprintln!(
                                                                "[daemon] Ignoring duplicate Signal from {:?} (state: {})",
                                                                from, entry.state
                                                            );
                                                            (false, None)
                                                        }
                                                    } else {
                                                        (false, None)
                                                    }
                                                } else {
                                                    (false, None)
                                                }
                                            };

                                            if should_handle {
                                                let st_c = state.clone();
                                                let priv_c = static_private.clone();
                                                let stun_server_c = stun_server.clone();
                                                let peer_signal_tx_c = peer_signal_tx.clone();
                                                let event_tx_c = event_tx.clone();
                                                tokio::spawn(async move {
                                                    handle_peer_signal(
                                                        from,
                                                        ex.candidates,
                                                        stored_ice_state,
                                                        priv_c,
                                                        stun_server_c,
                                                        st_c,
                                                        peer_signal_tx_c,
                                                        event_tx_c,
                                                    ).await;
                                                });
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    tungstenite::Message::Close(_) => break,
                    tungstenite::Message::Ping(_) => {
                        let _ = ws_writer.send(tungstenite::Message::Pong(tungstenite::Bytes::new())).await;
                    }
                    _ => {}
                }
            }
        }
    }
    eprintln!("[daemon] Disconnected from signaling server");
    let mut st = state.lock().await;
    st.status = ConnectionStatus::Disconnected;
    st.peers.clear();
    let _ = event_tx.send(DaemonEvent::StatusUpdate { status: st.status.clone() });
}

/// Handles the per-peer ICE flow triggered by a real (non-empty) `Signal` message.
///
/// This function:
/// 1. Reuses the socket and local candidates stored in `existing_ice_state` from
///    the trigger-signal phase (no second STUN). If `None` (initiating side that
///    never received a trigger), binds a fresh socket and runs STUN.
/// 2. Sends local candidates to the remote peer if not already sent.
/// 3. Runs ICE connectivity checks on that socket.
/// 4. On success, creates a `WireGuardPeer` with the confirmed remote endpoint
///    and starts a per-peer `VpnEngine` that "upgrades" the ICE socket into the
///    WireGuard data-plane socket.
async fn handle_peer_signal(
    from: PeerId,
    remote_candidates: Vec<Candidate>,
    existing_ice_state: Option<(Arc<UdpSocket>, Vec<Candidate>)>,
    static_private: boringtun::x25519::StaticSecret,
    stun_server: String,
    state: Arc<Mutex<DaemonState>>,
    peer_signal_tx: mpsc::Sender<(PeerId, String)>,
    event_tx: broadcast::Sender<DaemonEvent>,
) {
    // 1. Reuse the socket and candidates from the trigger phase if available,
    //    avoiding a second STUN request on a different ephemeral port.
    //    If not available (initiating side), bind a fresh socket and run STUN.
    let (ice_socket, local_candidates) = match existing_ice_state {
        Some((sock, candidates)) => {
            eprintln!(
                "[daemon] Reusing trigger-phase socket (port {}) for ICE with {:?}",
                sock.local_addr().map(|a| a.port()).unwrap_or(0),
                from
            );
            (sock, candidates)
        }
        None => {
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    eprintln!("[daemon] Failed to bind per-peer socket for {:?}: {}", from, e);
                    return;
                }
            };
            let (candidates, candidates_json) =
                gather_candidates_for_socket(&sock, &stun_server).await;
            eprintln!(
                "[daemon] Sending per-peer candidates to {:?} (socket port {})",
                from,
                sock.local_addr().map(|a| a.port()).unwrap_or(0)
            );
            let _ = peer_signal_tx.send((from, candidates_json)).await;
            (sock, candidates)
        }
    };

    // 2. Run ICE on the socket whose port was already advertised to the remote peer.
    //    remote_candidates are real (non-zero port) at this point.
    eprintln!("[daemon] Starting ICE connectivity check with {:?}", from);
    for c in &remote_candidates {
        eprintln!("[daemon]   Remote candidate: {:?} @ {}", c.candidate_type, c.addr);
    }

    let (conn_state, result) = crate::net::ice::establish_connectivity_with_local(
        &ice_socket,
        local_candidates,
        remote_candidates,
    ).await;

    match result {
        Ok(selected) => {
            eprintln!("[daemon] ICE success with {:?}: selected {}", from, selected.remote.addr);

            // 5. Look up the peer's public key and virtual index, then create
            //    a WireGuard tunnel and start a per-peer VpnEngine.
            let (tun_reader, tun_writer, pm, virtual_index, peer_public_key) = {
                let st = state.lock().await;
                let pm = st.peer_manager.clone();
                let tun_reader = st.tun_reader.clone();
                let tun_writer = st.tun_writer.clone();
                let (vi, pk) = if let Some(ref pm) = pm {
                    let mgr = pm.lock().await;
                    if let Some(entry) = mgr.get_peer(&from) {
                        (entry.info.virtual_index, entry.info.public_key.clone())
                    } else {
                        (0, String::new())
                    }
                } else {
                    (0, String::new())
                };
                (tun_reader, tun_writer, pm, vi, pk)
            };

            let (tun_reader, tun_writer) = match (tun_reader, tun_writer) {
                (Some(r), Some(w)) => (r, w),
                _ => {
                    eprintln!("[daemon] TUN not ready for peer {:?}", from);
                    return;
                }
            };

            let pm = match pm {
                Some(p) => p,
                None => {
                    eprintln!("[daemon] Peer manager not ready for {:?}", from);
                    return;
                }
            };

            if peer_public_key.is_empty() || virtual_index == 0 {
                eprintln!("[daemon] Missing peer info for {:?}", from);
                return;
            }

            let key_bytes = match hex::decode(&peer_public_key) {
                Ok(b) if b.len() == 32 => b,
                _ => {
                    eprintln!("[daemon] Invalid public key for {:?}", from);
                    return;
                }
            };
            let mut b = [0u8; 32];
            b.copy_from_slice(&key_bytes);
            let remote_pub = boringtun::x25519::PublicKey::from(b);

            let wg_peer = match WireGuardPeer::new(
                static_private,
                remote_pub,
                None,
                Some(25),
                0,
                Some(selected.remote.addr),
            ) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[daemon] Failed to create WireGuard peer for {:?}: {:?}", from, e);
                    return;
                }
            };

            let _ = pm.lock().await.update_state(&from, PeerConnectionState::Connected);

            // Update the IPC peer list to mark this peer as connected.
            {
                let mut st = state.lock().await;
                for p in st.peers.iter_mut() {
                    if p.name == from.0.to_string() {
                        p.connected = true;
                    }
                }
                let _ = event_tx.send(DaemonEvent::PeerUpdate { peers: st.peers.clone() });
            }

            // Start the per-peer VpnEngine — the ICE socket is now the data-plane socket.
            let engine = crate::net::VpnEngine::new(
                tun_reader,
                tun_writer,
                ice_socket,
                wg_peer,
                pm,
                virtual_index,
            );
            tokio::spawn(async move {
                if let Err(e) = engine.run().await {
                    eprintln!("[daemon] VpnEngine error for {:?}: {}", from, e);
                }
            });
        }
        Err(e) => {
            eprintln!("[daemon] ICE failed for {:?}: {:?} ({:?})", from, conn_state, e);
        }
    }
}
