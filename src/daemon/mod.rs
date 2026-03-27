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
use crate::net::ice::CandidateType;
use crate::net::nat::RealStunClient;
use crate::net::peer::{PeerConnectionState, PeerManager, PeerStore};
use crate::net::tun::{TunConfig, TunDevice};
use crate::net::wireguard::{KeyPair, WireGuardPeer};
use futures_util::{SinkExt, StreamExt};
use std::path::Path;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
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
    let local_port = 51820;
    let udp = match tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await {
        Ok(u) => Arc::new(u),
        Err(e) => {
            eprintln!("[daemon] Failed to bind UDP socket: {}", e);
            return;
        }
    };

    let stun_server = "stun.l.google.com:19302".to_string();
    let stun_client = RealStunClient::new(stun_server.clone());
    let mut local_candidates = match crate::net::ice::gather_candidates(Some(&stun_client), &udp).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[daemon] Initial gathering failed: {}", e);
            crate::net::ice::gather_host_candidates(local_port)
        }
    };

    let mut exchange = CandidateExchange { candidates: local_candidates.clone() };
    let mut exchange_json = serde_json::to_string(&exchange).unwrap();
    let has_stun = local_candidates.iter().any(|c| matches!(c.candidate_type, CandidateType::ServerReflexive));
    let (exchange_update_tx, mut exchange_update_rx) = mpsc::channel::<String>(1);

    if !has_stun {
        eprintln!("[daemon] STUN not yet gathered. Starting background refresh.");
        let udp_clone = udp.clone();
        let stun_server_clone = stun_server.clone();
        tokio::spawn(async move {
            let stun_client = RealStunClient::new(stun_server_clone);
            match tokio::time::timeout(std::time::Duration::from_secs(5), crate::net::ice::gather_candidates(Some(&stun_client), &udp_clone)).await {
                Ok(Ok(new_candidates)) => {
                    if new_candidates.iter().any(|c| matches!(c.candidate_type, CandidateType::ServerReflexive)) {
                        let new_json = serde_json::to_string(&CandidateExchange { candidates: new_candidates }).unwrap();
                        let _ = exchange_update_tx.send(new_json).await;
                    }
                }
                _ => eprintln!("[daemon] Background STUN failed or timed out."),
            }
        });
    }

    for c in &local_candidates {
        eprintln!("[daemon] Gathered local candidate: {:?} ({})", c.candidate_type, c.addr);
    }

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

    loop {
        tokio::select! {
            Some(new_json) = exchange_update_rx.recv() => {
                eprintln!("[daemon] STUN gathered. Updating exchange and re-signaling.");
                exchange_json = new_json.clone();
                if let Ok(new_ex) = serde_json::from_str::<CandidateExchange>(&new_json) {
                    local_candidates = new_ex.candidates.clone();
                    exchange.candidates = new_ex.candidates;
                }
                let peers_to_signal = {
                    let st = state.lock().await;
                    if matches!(st.status, ConnectionStatus::Connected { .. }) {
                        st.peers.clone()
                    } else {
                        vec![]
                    }
                };
                for p_info in peers_to_signal {
                    if let Ok(p_id) = p_info.name.parse::<Uuid>() {
                        let signal = SignalingMessage::Signal { to: PeerId(p_id), from: peer_id, data: exchange_json.clone() };
                        if let Ok(json) = serde_json::to_string(&signal) {
                            let _ = ws_writer.send(tungstenite::Message::Text(json.into())).await;
                        }
                    }
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
                                    let config = TunConfig { name: "transparnc0".to_string(), address: ip, netmask: "255.255.255.0".parse().unwrap(), mtu: 1420 };
                                    if let Ok(tun) = TunDevice::new(config) {
                                        let ipc_peers: Vec<IpcPeerInfo> = peers.iter().map(|p| IpcPeerInfo { name: p.peer_id.0.to_string(), virtual_ip: format!("192.168.22.{}", p.virtual_index), connected: false }).collect();
                                        let stun_for_engine = stun_server.clone();
                                                                                let engine = match crate::net::VpnEngine::with_socket(tun, udp.clone(), Some(Box::new(RealStunClient::new(stun_for_engine)))) {
                                            Ok(e) => e,
                                            Err(e) => { eprintln!("[daemon] Failed engine: {}", e); return; }
                                        };
                                        {
                                            let mut st = state.lock().await;
                                            st.status = ConnectionStatus::Connected { virtual_ip: ip_str };
                                            st.peers = ipc_peers.clone();
                                            st.engine_peer_manager = Some(engine.peer_manager());
                                            st.engine_wg_peers = Some(engine.wg_peers());
                                            let _ = event_tx.send(DaemonEvent::StatusUpdate { status: st.status.clone() });
                                            let _ = event_tx.send(DaemonEvent::PeerUpdate { peers: ipc_peers });
                                        }
                                        for p in &peers {
                                            let pm = engine.peer_manager();
                                            let mut mgr = pm.lock().await;
                                            let _ = mgr.add_peer(p.clone());
                                            let signal = SignalingMessage::Signal { to: p.peer_id, from: peer_id, data: exchange_json.clone() };
                                            if let Ok(json) = serde_json::to_string(&signal) { let _ = ws_writer.send(tungstenite::Message::Text(json.into())).await; }
                                        }
                                        tokio::spawn(async move { if let Err(e) = engine.run().await { eprintln!("[daemon] Engine error: {}", e); } });
                                    }
                                }
                                SignalingMessage::PeerJoined { peer: p } => {
                                    eprintln!("[daemon] New peer: {:?}", p.peer_id);
                                    let (pm, connected) = {
                                        let st = state.lock().await;
                                        (st.engine_peer_manager.clone(), matches!(st.status, ConnectionStatus::Connected { .. }))
                                    };
                                    if connected {
                                        if let Some(pm) = pm {
                                            let mut mgr = pm.lock().await;
                                            if mgr.get_peer(&p.peer_id).is_none() { let _ = mgr.add_peer(p.clone()); }
                                        }
                                        let signal = SignalingMessage::Signal { to: p.peer_id, from: peer_id, data: exchange_json.clone() };
                                        if let Ok(json) = serde_json::to_string(&signal) { let _ = ws_writer.send(tungstenite::Message::Text(json.into())).await; }
                                    }
                                    let mut st = state.lock().await;
                                    st.peers.push(IpcPeerInfo { name: p.peer_id.0.to_string(), virtual_ip: format!("192.168.22.{}", p.virtual_index), connected: false });
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
                                        let st_c = state.clone();
                                        let priv_c = static_private.clone();
                                        let local_c = local_candidates.clone();
                                        tokio::spawn(async move {
                                            // Use a dedicated ephemeral socket for ICE probing so
                                            // the VpnEngine's udp_to_tun loop cannot consume the
                                            // ACK packets before the connectivity check sees them.
                                            let (conn_state, result) = crate::net::ice::establish_connectivity_own_socket(local_c, ex.candidates).await;
                                            if let Ok(selected) = result {
                                                eprintln!("[daemon] ICE success with {:?}", from);
                                                let (pm, wp) = { let st = st_c.lock().await; (st.engine_peer_manager.clone(), st.engine_wg_peers.clone()) };
                                                if let (Some(pm), Some(wp)) = (pm, wp) {
                                                    let info = { let mgr = pm.lock().await; mgr.get_peer(&from).map(|e| e.info.clone()) };
                                                    if let Some(info) = info {
                                                        if let Ok(bytes) = hex::decode(&info.public_key) {
                                                            if bytes.len() == 32 {
                                                                let mut b = [0u8; 32]; b.copy_from_slice(&bytes);
                                                                if let Ok(peer) = WireGuardPeer::new(priv_c, boringtun::x25519::PublicKey::from(b), None, Some(25), 0, Some(selected.remote.addr)) {
                                                                    wp.lock().await.push(peer);
                                                                    let _ = pm.lock().await.update_state(&from, PeerConnectionState::Connected);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            } else { eprintln!("[daemon] ICE failed for {:?}: {:?}", from, conn_state); }
                                        });
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    tungstenite::Message::Close(_) => break,
                    tungstenite::Message::Ping(_) => { let _ = ws_writer.send(tungstenite::Message::Pong(tungstenite::Bytes::new())).await; }
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
