//! Iced application root for the TransparNC GUI.
//!
//! Implements the Elm-style architecture (state, message, update, view) with
//! a dark theme. On startup the GUI attempts to connect to an already-running
//! daemon; if none is found it prompts the user before launching one via
//! `pkexec`.

use crate::common::ipc::{
    ConnectionStatus, DaemonCommand, DaemonEvent, IpcPeerInfo, read_message, write_message,
};
use iced::widget::{
    Space, button, center, checkbox, column, container, row, scrollable, text, text_input,
};
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
    /// State for the network dialog (join or create).
    network_dialog: Option<NetworkDialog>,
}

/// Default signaling server FQDN.
const DEFAULT_SIGNALING_HOST: &str = "coffy.dev";

/// Default signaling server port.
const DEFAULT_SIGNALING_PORT: u16 = 8080;

/// Tracks which kind of network dialog is open and its input fields.
#[derive(Debug, Clone)]
struct NetworkDialog {
    /// Whether the user is joining or creating a network.
    kind: NetworkDialogKind,
    /// The network identifier (for join) or desired name (for create).
    network_input: String,
    /// Signaling server FQDN (without port).
    signaling_host: String,
    /// Signaling server port.
    signaling_port: String,
    /// When true the default server (`coffy.dev:8080`) is used and the
    /// host/port fields are not editable.
    use_default_server: bool,
}

/// Distinguishes between the two network dialog modes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NetworkDialogKind {
    /// The user wants to join an existing network.
    Join,
    /// The user wants to create a new network.
    Create,
}

impl NetworkDialog {
    /// Creates a new dialog with defaults pre-filled.
    fn new(kind: NetworkDialogKind) -> Self {
        Self {
            kind,
            network_input: String::new(),
            signaling_host: DEFAULT_SIGNALING_HOST.to_string(),
            signaling_port: DEFAULT_SIGNALING_PORT.to_string(),
            use_default_server: true,
        }
    }

    /// Returns the `host:port` signaling server address.
    fn signaling_address(&self) -> String {
        format!(
            "{}:{}",
            self.signaling_host.trim(),
            self.signaling_port.trim()
        )
    }
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
    /// User opened the "Join Network" dialog.
    OpenJoinDialog,
    /// User opened the "Create Network" dialog.
    OpenCreateDialog,
    /// User closed the network dialog without submitting.
    CloseNetworkDialog,
    /// The network name/ID input field changed.
    NetworkInputChanged(String),
    /// The signaling server host input field changed.
    SignalingHostChanged(String),
    /// The signaling server port input field changed.
    SignalingPortChanged(String),
    /// The "use default server" checkbox was toggled.
    UseDefaultServerToggled(bool),
    /// User submitted the network dialog (join or create).
    SubmitNetworkDialog,
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
            network_dialog: None,
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
                self.status_line = "Daemon started — connecting (retrying every 1s)…".into();
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
                self.status_line = format!("Connection failed: {} — retrying…", e);
                // Keep retrying instead of giving up, so the user has time to
                // enter their password when the daemon is started via pkexec.
                start_ipc_connection(self.socket_path.clone())
            }

            Message::DaemonEvent(event) => {
                self.apply_daemon_event(event);
                Task::none()
            }

            Message::DaemonConnectionLost => {
                self.phase = Phase::PromptStartDaemon;
                self.writer = None;
                self.connection_status = ConnectionStatus::Disconnected;
                self.peers.clear();
                self.network_dialog = None;
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

            Message::OpenJoinDialog => {
                self.network_dialog = Some(NetworkDialog::new(NetworkDialogKind::Join));
                Task::none()
            }

            Message::OpenCreateDialog => {
                self.network_dialog = Some(NetworkDialog::new(NetworkDialogKind::Create));
                Task::none()
            }

            Message::CloseNetworkDialog => {
                self.network_dialog = None;
                Task::none()
            }

            Message::NetworkInputChanged(value) => {
                if let Some(dialog) = &mut self.network_dialog {
                    dialog.network_input = value;
                }
                Task::none()
            }

            Message::SignalingHostChanged(value) => {
                if let Some(dialog) = &mut self.network_dialog {
                    dialog.signaling_host = value;
                }
                Task::none()
            }

            Message::SignalingPortChanged(value) => {
                if let Some(dialog) = &mut self.network_dialog {
                    dialog.signaling_port = value;
                }
                Task::none()
            }

            Message::UseDefaultServerToggled(checked) => {
                if let Some(dialog) = &mut self.network_dialog {
                    dialog.use_default_server = checked;
                    if checked {
                        dialog.signaling_host = DEFAULT_SIGNALING_HOST.to_string();
                        dialog.signaling_port = DEFAULT_SIGNALING_PORT.to_string();
                    }
                }
                Task::none()
            }

            Message::SubmitNetworkDialog => self.submit_network_dialog(),
        }
    }

    /// Builds the signaling server address from the current dialog state and
    /// sends the appropriate `DaemonCommand` to the daemon.
    fn submit_network_dialog(&mut self) -> Task<Message> {
        let dialog = match self.network_dialog.take() {
            Some(d) => d,
            None => return Task::none(),
        };

        if dialog.network_input.trim().is_empty() {
            self.status_line = "Please enter a network name / ID.".into();
            self.network_dialog = Some(dialog);
            return Task::none();
        }

        let signaling_server = dialog.signaling_address();

        let command = match dialog.kind {
            NetworkDialogKind::Join => DaemonCommand::JoinNetwork {
                network_id: dialog.network_input.trim().to_string(),
                signaling_server,
            },
            NetworkDialogKind::Create => DaemonCommand::CreateNetwork {
                network_name: dialog.network_input.trim().to_string(),
                signaling_server,
            },
        };

        self.status_line = format!("Sending {:?}…", command);

        if let Some(writer) = self.writer.clone() {
            Task::perform(
                async move {
                    let mut w = writer.lock().await;
                    write_message(&mut w, &command)
                        .await
                        .map_err(|e| e.to_string())
                },
                Message::CommandSent,
            )
        } else {
            self.status_line = "Not connected to daemon.".into();
            Task::none()
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
                self.phase = Phase::PromptStartDaemon;
                self.writer = None;
                self.connection_status = ConnectionStatus::Disconnected;
                self.peers.clear();
                self.network_dialog = None;
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
                    button(text("OK — Start Daemon"))
                        .on_press(Message::UserAcceptedDaemonStart)
                        .style(button::secondary),
                ]
                .align_x(iced::Alignment::Center);
                center(prompt).into()
            }

            Phase::StartingDaemon => center(text("Starting daemon…").size(20)).into(),

            Phase::Connected => self.main_view(),
        };

        let status_bar = container(text(&self.status_line).size(13))
            .padding(6)
            .width(Fill);

        column![content, status_bar].height(Fill).into()
    }

    /// The main operational view shown once connected to the daemon.
    ///
    /// When a network dialog is open it is rendered in place of the peer list
    /// so the user can fill in the signaling server details.
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

        // Either show the network dialog or the normal peer list.
        let body: Element<'_, Message> = if let Some(dialog) = &self.network_dialog {
            self.network_dialog_view(dialog)
        } else {
            self.peer_list_view()
        };

        let controls = if self.network_dialog.is_some() {
            // While a dialog is open the bottom bar only shows Cancel.
            row![
                Space::new().width(Fill),
                button(text("Cancel").size(14))
                    .padding(6)
                    .on_press(Message::CloseNetworkDialog)
                    .style(button::secondary),
            ]
            .padding(10)
        } else {
            row![
                button(text("Join Network").size(14))
                    .padding(6)
                    .on_press(Message::OpenJoinDialog)
                    .style(button::secondary),
                Space::new().width(8),
                button(text("Create Network").size(14))
                    .padding(6)
                    .on_press(Message::OpenCreateDialog)
                    .style(button::secondary),
                Space::new().width(Fill),
                button(text("Shutdown Daemon").size(14))
                    .padding(6)
                    .on_press(Message::ShutdownDaemon)
                    .style(|theme: &Theme, status| {
                        let palette = theme.palette();
                        let mut style = button::secondary(theme, status);
                        match status {
                            button::Status::Active | button::Status::Pressed => {
                                style.border.color = palette.danger;
                                style.border.width = 1.0;
                                style.background = None;
                                style.text_color = palette.danger;
                            }
                            button::Status::Hovered => {
                                style.background = Some(palette.danger.into());
                                style.text_color = palette.background.into();
                            }
                            _ => {}
                        }
                        style
                    }),
            ]
            .padding(10)
        };

        column![header, body, controls].height(Fill).into()
    }

    /// Renders the peer list (default body when no dialog is open).
    fn peer_list_view(&self) -> Element<'_, Message> {
        let content: Element<'_, Message> = if self.peers.is_empty() {
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

        container(
            container(content)
                .height(Fill)
                .width(Fill)
                .padding(8)
                .style(|theme: &Theme| {
                    let palette = theme.palette();
                    let mut background = palette.background;
                    background.r *= 0.8;
                    background.g *= 0.8;
                    background.b *= 0.8;

                    container::Style {
                        background: Some(background.into()),
                        border: iced::Border {
                            radius: 10.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    }
                }),
        )
        .padding(10)
        .height(Fill)
        .width(Fill)
        .into()
    }

    /// Renders the join / create network dialog form.
    fn network_dialog_view(&self, dialog: &NetworkDialog) -> Element<'_, Message> {
        let title = match dialog.kind {
            NetworkDialogKind::Join => "Join Network",
            NetworkDialogKind::Create => "Create Network",
        };

        let network_label = match dialog.kind {
            NetworkDialogKind::Join => "Network ID",
            NetworkDialogKind::Create => "Network Name",
        };

        let network_field = text_input(network_label, &dialog.network_input)
            .on_input(Message::NetworkInputChanged)
            .padding(8);

        let use_default = checkbox(dialog.use_default_server)
            .label(format!(
                "Use default server ({}:{})",
                DEFAULT_SIGNALING_HOST, DEFAULT_SIGNALING_PORT
            ))
            .on_toggle(Message::UseDefaultServerToggled)
            .style(checkbox::secondary);

        let mut form = column![
            text(title).size(22),
            Space::new().height(12),
            text(network_label).size(14),
            network_field,
            Space::new().height(12),
            use_default,
        ]
        .spacing(4)
        .padding(16);

        // Only show host/port fields when the user opts out of the default.
        if !dialog.use_default_server {
            let host_field = text_input("Signaling server FQDN", &dialog.signaling_host)
                .on_input(Message::SignalingHostChanged)
                .padding(8);

            let port_field = text_input("Port", &dialog.signaling_port)
                .on_input(Message::SignalingPortChanged)
                .padding(8);

            form = form
                .push(Space::new().height(8))
                .push(text("Signaling Server").size(14))
                .push(row![
                    host_field,
                    Space::new().width(8),
                    container(port_field).width(100),
                ]);
        }

        let submit_label = match dialog.kind {
            NetworkDialogKind::Join => "Join",
            NetworkDialogKind::Create => "Create",
        };

        form = form.push(Space::new().height(16)).push(row![
            Space::new().width(Fill),
            button(text(submit_label))
                .on_press(Message::SubmitNetworkDialog)
                .style(button::secondary),
        ]);

        container(form).width(Fill).height(Fill).padding(8).into()
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
                    // Retry connecting indefinitely with a 1-second interval so
                    // the user has time to enter their password when the daemon
                    // is launched via pkexec with elevated privileges.
                    let stream = loop {
                        match UnixStream::connect(&socket_path).await {
                            Ok(s) => break s,
                            Err(_) => {
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        }
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
        .window_size((470.0, 450.0))
        .resizable(false)
        .run()
}
