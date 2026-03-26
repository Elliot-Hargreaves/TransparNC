//! Daemon mode entry point and IPC server.
//!
//! When the binary is launched with `--daemon`, this module takes over.
//! It listens on a Unix domain socket for commands from the GUI process,
//! manages TUN device lifecycle, and reports status back over IPC.

use crate::common::ipc::{
    ConnectionStatus, DaemonCommand, DaemonEvent, IpcPeerInfo, read_message, write_message,
};
use crate::common::messages::{NetworkId, PeerId, SignalingMessage};
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
}

impl DaemonState {
    /// Creates a new daemon state in the disconnected state.
    fn new() -> Self {
        Self {
            status: ConnectionStatus::Disconnected,
            peers: Vec::new(),
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
                virtual_ip: "10.0.0.1".to_string(),
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

    // Generate a unique peer ID and a placeholder public key for this session.
    let peer_id = PeerId(Uuid::new_v4());
    let public_key = "placeholder-public-key".to_string();

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
                    Ok(SignalingMessage::Joined { peers }) => {
                        eprintln!(
                            "[daemon] Joined network successfully, {} existing peer(s)",
                            peers.len()
                        );
                        let ipc_peers: Vec<IpcPeerInfo> = peers
                            .iter()
                            .map(|p| IpcPeerInfo {
                                name: p.peer_id.0.to_string(),
                                virtual_ip: "pending".to_string(),
                                connected: false,
                            })
                            .collect();
                        let mut st = state.lock().await;
                        st.status = ConnectionStatus::Connected {
                            virtual_ip: "10.0.0.x".to_string(),
                        };
                        st.peers = ipc_peers.clone();
                        let _ = event_tx.send(DaemonEvent::StatusUpdate {
                            status: st.status.clone(),
                        });
                        let _ = event_tx.send(DaemonEvent::PeerUpdate { peers: ipc_peers });
                    }
                    Ok(SignalingMessage::PeerJoined { peer }) => {
                        eprintln!("[daemon] New peer joined: {:?}", peer.peer_id);
                        let mut st = state.lock().await;
                        st.peers.push(IpcPeerInfo {
                            name: peer.peer_id.0.to_string(),
                            virtual_ip: "pending".to_string(),
                            connected: false,
                        });
                        let _ = event_tx.send(DaemonEvent::PeerUpdate {
                            peers: st.peers.clone(),
                        });
                    }
                    Ok(SignalingMessage::Signal { from, data, .. }) => {
                        eprintln!(
                            "[daemon] Received signal from {:?}: {}",
                            from,
                            &data[..data.len().min(80)]
                        );
                        // TODO: handle ICE candidate exchange.
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
