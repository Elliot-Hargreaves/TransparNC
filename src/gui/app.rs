//! Iced application root for the TransparNC GUI.
//!
//! Implements the Elm-style architecture (state, message, update, view) with
//! a dark theme. On startup the GUI attempts to connect to an already-running
//! daemon; if none is found it prompts the user before launching one via
//! `pkexec`.

use crate::common::ipc::{
    ConnectionStatus, DaemonCommand, DaemonEvent, IpcPeerInfo, read_message, write_message,
};
use iced::widget::{Space, button, center, column, container, row, scrollable, text};
use iced::{Element, Fill, Task, Theme};
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::Mutex;

// ── Application state ──────────────────────────────────────────────────────

/// Top-level GUI state.
pub struct App {
    /// Current phase of the GUI lifecycle.
    phase: Phase,
    /// Connection status reported by the daemon.
    connection_status: ConnectionStatus,
    /// Peer list reported by the daemon.
    peers: Vec<IpcPeerInfo>,
    /// Path to the IPC socket.
    socket_path: String,
    /// Shared writer half — set once connected to the daemon.
    writer: Option<Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>>,
    /// Human-readable log / status line shown at the bottom.
    status_line: String,
}

/// Lifecycle phases of the GUI.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// Checking whether a daemon is already running.
    CheckingDaemon,
    /// No daemon found — asking the user for permission to start one.
    PromptStartDaemon,
    /// Daemon is being launched via `pkexec`.
    StartingDaemon,
    /// Connected to the daemon and operational.
    Connected,
    /// The daemon has shut down (or we lost the connection).
    Disconnected,
}

// ── Messages ───────────────────────────────────────────────────────────────

/// All messages the GUI can receive.
#[derive(Debug, Clone)]
pub enum Message {
    /// Result of the initial daemon connectivity check.
    DaemonCheckResult(bool),
    /// User confirmed they want to start the daemon.
    UserAcceptedDaemonStart,
    /// The daemon process was spawned (or failed).
    DaemonSpawnResult(Result<(), String>),
    /// Successfully connected to the daemon — carries the writer handle.
    DaemonConnected(Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>),
    /// Failed to connect to the daemon.
    DaemonConnectFailed(String),
    /// An IPC event arrived from the daemon.
    DaemonEvent(DaemonEvent),
    /// The IPC connection was lost.
    DaemonConnectionLost,
    /// User pressed the "Shutdown Daemon" button.
    ShutdownDaemon,
    /// A command was sent (or failed) — used to surface errors.
    CommandSent(Result<(), String>),
}

// ── Construction ───────────────────────────────────────────────────────────

impl App {
    /// Creates the initial application state and fires the daemon check task.
    pub fn new(socket_path: String) -> (Self, Task<Message>) {
        let app = Self {
            phase: Phase::CheckingDaemon,
            connection_status: ConnectionStatus::Disconnected,
            peers: Vec::new(),
            socket_path: socket_path.clone(),
            writer: None,
            status_line: "Checking for running daemon…".into(),
        };
        let task = Task::perform(check_daemon(socket_path), Message::DaemonCheckResult);
        (app, task)
    }
}

// ── Update ─────────────────────────────────────────────────────────────────

impl App {
    /// Processes a single message and returns any follow-up tasks.
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::DaemonCheckResult(running) => {
                if running {
                    self.status_line = "Daemon found — connecting…".into();
                    self.phase = Phase::Connected;
                    return start_ipc_connection(self.socket_path.clone());
                }
                self.phase = Phase::PromptStartDaemon;
                self.status_line =
                    "No daemon detected. Press OK to start one (requires elevated privileges)."
                        .into();
                Task::none()
            }

            Message::UserAcceptedDaemonStart => {
                self.phase = Phase::StartingDaemon;
                self.status_line = "Launching daemon via pkexec…".into();
                let socket = self.socket_path.clone();
                Task::perform(spawn_daemon(socket), |r| {
                    Message::DaemonSpawnResult(r.map_err(|e| e.to_string()))
                })
            }

            Message::DaemonSpawnResult(Ok(())) => {
                self.status_line = "Daemon started — connecting…".into();
                self.phase = Phase::Connected;
                start_ipc_connection(self.socket_path.clone())
            }

            Message::DaemonSpawnResult(Err(e)) => {
                self.status_line = format!("Failed to start daemon: {}", e);
                self.phase = Phase::PromptStartDaemon;
                Task::none()
            }

            Message::DaemonConnected(writer) => {
                self.writer = Some(writer);
                self.status_line = "Connected to daemon.".into();
                self.phase = Phase::Connected;
                Task::none()
            }

            Message::DaemonConnectFailed(e) => {
                self.status_line = format!("Connection failed: {}", e);
                self.phase = Phase::Disconnected;
                Task::none()
            }

            Message::DaemonEvent(event) => {
                self.apply_daemon_event(event);
                Task::none()
            }

            Message::DaemonConnectionLost => {
                self.phase = Phase::Disconnected;
                self.writer = None;
                self.status_line = "Lost connection to daemon.".into();
                Task::none()
            }

            Message::ShutdownDaemon => {
                self.status_line = "Sending shutdown command…".into();
                if let Some(writer) = self.writer.clone() {
                    // `write_message` requires a Tokio runtime, so we spawn a
                    // blocking task that creates one for the single write.
                    Task::perform(
                        async move {
                            tokio::runtime::Runtime::new()
                                .map_err(|e| e.to_string())
                                .and_then(|rt| {
                                    rt.block_on(async {
                                        let mut w = writer.lock().await;
                                        write_message(&mut w, &DaemonCommand::Shutdown)
                                            .await
                                            .map_err(|e| e.to_string())
                                    })
                                })
                        },
                        Message::CommandSent,
                    )
                } else {
                    Task::none()
                }
            }

            Message::CommandSent(Ok(())) => Task::none(),
            Message::CommandSent(Err(e)) => {
                self.status_line = format!("Command error: {}", e);
                Task::none()
            }
        }
    }

    /// Applies a daemon event to the local GUI state.
    fn apply_daemon_event(&mut self, event: DaemonEvent) {
        match event {
            DaemonEvent::StatusUpdate { status } => {
                self.status_line = format!("Status: {:?}", status);
                self.connection_status = status;
            }
            DaemonEvent::PeerUpdate { peers } => {
                self.peers = peers;
            }
            DaemonEvent::Error { message } => {
                self.status_line = format!("Daemon error: {}", message);
            }
            DaemonEvent::ShuttingDown => {
                self.phase = Phase::Disconnected;
                self.writer = None;
                self.status_line = "Daemon has shut down.".into();
            }
        }
    }
}

// ── View ───────────────────────────────────────────────────────────────────

impl App {
    /// Renders the current GUI state.
    pub fn view(&self) -> Element<'_, Message> {
        let content: Element<'_, Message> = match &self.phase {
            Phase::CheckingDaemon => center(text("Checking for daemon…").size(20)).into(),

            Phase::PromptStartDaemon => {
                let prompt = column![
                    text("TransparNC Daemon").size(28),
                    Space::new().height(10),
                    text(
                        "The background daemon is not running.\n\
                         Starting it will require elevated privileges (pkexec)."
                    )
                    .size(16),
                    Space::new().height(20),
                    button(text("OK — Start Daemon")).on_press(Message::UserAcceptedDaemonStart),
                ]
                .align_x(iced::Alignment::Center);
                center(prompt).into()
            }

            Phase::StartingDaemon => center(text("Starting daemon…").size(20)).into(),

            Phase::Connected | Phase::Disconnected => self.main_view(),
        };

        let status_bar = container(text(&self.status_line).size(13))
            .padding(6)
            .width(Fill);

        column![content, status_bar].height(Fill).into()
    }

    /// The main operational view shown once connected to the daemon.
    fn main_view(&self) -> Element<'_, Message> {
        let status_text = match &self.connection_status {
            ConnectionStatus::Disconnected => "Disconnected".to_string(),
            ConnectionStatus::Connecting => "Connecting…".to_string(),
            ConnectionStatus::Connected { virtual_ip } => {
                format!("Connected — {}", virtual_ip)
            }
        };

        let header = row![
            text("TransparNC").size(24),
            Space::new().width(Fill),
            text(status_text.clone()).size(16),
        ]
        .padding(10);

        let peer_list: Element<'_, Message> = if self.peers.is_empty() {
            center(text("No peers connected.").size(14)).into()
        } else {
            let items = self
                .peers
                .iter()
                .fold(column![].spacing(4).padding(8), |col, peer| {
                    let indicator = if peer.connected { "●" } else { "○" };
                    col.push(
                        row![
                            text(indicator).size(14),
                            Space::new().width(8),
                            text(&peer.name).size(14),
                            Space::new().width(Fill),
                            text(&peer.virtual_ip).size(14),
                        ]
                        .padding(4),
                    )
                });
            scrollable(items).height(Fill).into()
        };

        let controls = row![
            Space::new().width(Fill),
            button(text("Shutdown Daemon"))
                .on_press(Message::ShutdownDaemon)
                .style(button::danger),
        ]
        .padding(10);

        column![header, peer_list, controls].height(Fill).into()
    }

    /// Returns the dark theme.
    pub fn theme(&self) -> Theme {
        Theme::Dark
    }
}

// ── Async helpers ──────────────────────────────────────────────────────────

/// Checks whether a daemon is already listening on the socket.
///
/// Uses a blocking `std::os::unix::net::UnixStream` because this future may
/// be polled outside a Tokio runtime (Iced's own executor).
async fn check_daemon(socket_path: String) -> bool {
    std::os::unix::net::UnixStream::connect(&socket_path).is_ok()
}

/// Spawns the current binary in daemon mode via `pkexec`.
async fn spawn_daemon(socket_path: String) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let child = std::process::Command::new("pkexec")
        .arg(&exe)
        .arg("--daemon")
        .arg("--socket")
        .arg(&socket_path)
        .spawn()?;

    // Detach — we don't wait for the daemon to exit.
    std::mem::forget(child);

    // Give the daemon a moment to bind the socket.
    std::thread::sleep(std::time::Duration::from_millis(500));
    Ok(())
}

/// Connects to the daemon socket, sends back a `DaemonConnected` message
/// with the writer half, then continuously reads events and emits
/// `DaemonEvent` messages until the connection drops.
///
/// Uses `Task::run` to produce a stream of messages from a single long-lived
/// async operation.
fn start_ipc_connection(socket_path: String) -> Task<Message> {
    Task::stream(iced::stream::channel(
        32,
        move |mut sender: iced::futures::channel::mpsc::Sender<Message>| async move {
            // Iced's executor is not Tokio, so we spin up a dedicated Tokio
            // runtime for the IPC connection which requires `tokio::net`.
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = sender.try_send(Message::DaemonConnectFailed(format!(
                        "Failed to create Tokio runtime: {}",
                        e
                    )));
                    std::future::pending::<()>().await;
                    return;
                }
            };

            // Run the entire IPC loop inside the Tokio runtime on a
            // background thread, forwarding messages back via the sender.
            let _ = rt
                .spawn(async move {
                    // Retry connecting — the daemon may still be starting up.
                    let stream = {
                        let mut result = None;
                        for _ in 0..20 {
                            match UnixStream::connect(&socket_path).await {
                                Ok(s) => {
                                    result = Some(s);
                                    break;
                                }
                                Err(_) => {
                                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                                }
                            }
                        }
                        result
                    };

                    let Some(stream) = stream else {
                        let _ = sender.try_send(Message::DaemonConnectFailed(
                            "Could not connect to daemon socket".into(),
                        ));
                        return;
                    };

                    let (mut reader, writer) = stream.into_split();
                    let writer = Arc::new(Mutex::new(writer));

                    // Hand the writer to the App so it can send commands.
                    let _ = sender.try_send(Message::DaemonConnected(writer));

                    // Read events from the daemon in a loop.
                    loop {
                        match read_message::<DaemonEvent>(&mut reader).await {
                            Ok(Some(event)) => {
                                if sender.try_send(Message::DaemonEvent(event)).is_err() {
                                    break;
                                }
                            }
                            Ok(None) | Err(_) => {
                                let _ = sender.try_send(Message::DaemonConnectionLost);
                                break;
                            }
                        }
                    }
                })
                .await;

            // Keep alive so the stream object isn't dropped.
            std::future::pending::<()>().await;
        },
    ))
}

/// Entry point called from `main.rs` to launch the Iced GUI.
pub fn run(socket_path: &str) -> iced::Result {
    let socket = socket_path.to_owned();
    iced::application(move || App::new(socket.clone()), App::update, App::view)
        .title("TransparNC")
        .theme(App::theme)
        .window_size((600.0, 450.0))
        .run()
}
