//! Daemon mode entry point and IPC server.
//!
//! When the binary is launched with `--daemon`, this module takes over.
//! It listens on a Unix domain socket for commands from the GUI process,
//! manages TUN device lifecycle, and reports status back over IPC.

use crate::common::ipc::{
    ConnectionStatus, DaemonCommand, DaemonEvent, IpcPeerInfo, read_message, write_message,
};
use std::path::Path;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, broadcast};

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
            // TODO: connect to signaling server and join the network.
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
            // TODO: connect to signaling server and create the network.
        }
    }
}
