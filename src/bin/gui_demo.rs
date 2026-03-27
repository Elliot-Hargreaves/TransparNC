//! Demo program for the TransparNC GUI.
//!
//! This binary provides a non-functional preview of the GUI with mock data.
//! It does not require a running daemon or elevated privileges.

use iced::widget::{
    Space, button, center, checkbox, column, container, row, scrollable, text, text_input,
};
use iced::{Element, Fill, Task, Theme};

// Re-using common types for consistency in the demo
use transpar_nc::common::ipc::{ConnectionStatus, IpcPeerInfo};

/// Top-level GUI state for the demo.
struct DemoApp {
    phase: Phase,
    connection_status: ConnectionStatus,
    peers: Vec<IpcPeerInfo>,
    status_line: String,
    network_dialog: Option<NetworkDialog>,
}

#[derive(Debug, Clone)]
struct NetworkDialog {
    kind: NetworkDialogKind,
    network_input: String,
    signaling_host: String,
    signaling_port: String,
    use_default_server: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NetworkDialogKind {
    Join,
    Create,
}

const DEFAULT_SIGNALING_HOST: &str = "coffy.dev";
const DEFAULT_SIGNALING_PORT: u16 = 8080;

impl NetworkDialog {
    fn new(kind: NetworkDialogKind) -> Self {
        Self {
            kind,
            network_input: String::new(),
            signaling_host: DEFAULT_SIGNALING_HOST.to_string(),
            signaling_port: DEFAULT_SIGNALING_PORT.to_string(),
            use_default_server: true,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    CheckingDaemon,
    PromptStartDaemon,
    StartingDaemon,
    Connected,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum Message {
    UserAcceptedDaemonStart,
    OpenJoinDialog,
    OpenCreateDialog,
    CloseNetworkDialog,
    NetworkInputChanged(String),
    SignalingHostChanged(String),
    SignalingPortChanged(String),
    UseDefaultServerToggled(bool),
    SubmitNetworkDialog,
    ShutdownDaemon,
    ResetDemo,
}

impl DemoApp {
    fn new() -> (Self, Task<Message>) {
        (
            Self {
                phase: Phase::PromptStartDaemon,
                connection_status: ConnectionStatus::Disconnected,
                peers: Vec::new(),
                status_line: "Welcome to the TransparNC GUI Demo!".into(),
                network_dialog: None,
            },
            Task::none(),
        )
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::UserAcceptedDaemonStart => {
                self.phase = Phase::Connected;
                self.status_line = "Demo: Connected to virtual daemon.".into();
                self.connection_status = ConnectionStatus::Connected {
                    virtual_ip: "192.168.22.1".to_string(),
                };
                self.peers = vec![
                    IpcPeerInfo {
                        name: "Alice's Laptop".to_string(),
                        virtual_ip: "192.168.22.2".to_string(),
                        connected: true,
                    },
                    IpcPeerInfo {
                        name: "Home Server".to_string(),
                        virtual_ip: "192.168.22.5".to_string(),
                        connected: true,
                    },
                    IpcPeerInfo {
                        name: "Bob's Phone".to_string(),
                        virtual_ip: "192.168.22.10".to_string(),
                        connected: false,
                    },
                    IpcPeerInfo {
                        name: "Work Station".to_string(),
                        virtual_ip: "192.168.22.11".to_string(),
                        connected: true,
                    },
                    IpcPeerInfo {
                        name: "Gaming Rig".to_string(),
                        virtual_ip: "192.168.22.15".to_string(),
                        connected: true,
                    },
                    IpcPeerInfo {
                        name: "Smart Fridge".to_string(),
                        virtual_ip: "192.168.22.20".to_string(),
                        connected: false,
                    },
                    IpcPeerInfo {
                        name: "Backup Server".to_string(),
                        virtual_ip: "192.168.22.30".to_string(),
                        connected: true,
                    },
                    IpcPeerInfo {
                        name: "Raspberry Pi".to_string(),
                        virtual_ip: "192.168.22.40".to_string(),
                        connected: true,
                    },
                    IpcPeerInfo {
                        name: "IoT Sensor A".to_string(),
                        virtual_ip: "192.168.22.101".to_string(),
                        connected: true,
                    },
                    IpcPeerInfo {
                        name: "IoT Sensor B".to_string(),
                        virtual_ip: "192.168.22.102".to_string(),
                        connected: false,
                    },
                ];
            }
            Message::OpenJoinDialog => {
                self.network_dialog = Some(NetworkDialog::new(NetworkDialogKind::Join));
            }
            Message::OpenCreateDialog => {
                self.network_dialog = Some(NetworkDialog::new(NetworkDialogKind::Create));
            }
            Message::CloseNetworkDialog => {
                self.network_dialog = None;
            }
            Message::NetworkInputChanged(val) => {
                if let Some(dialog) = &mut self.network_dialog {
                    dialog.network_input = val;
                }
            }
            Message::SignalingHostChanged(val) => {
                if let Some(dialog) = &mut self.network_dialog {
                    dialog.signaling_host = val;
                }
            }
            Message::SignalingPortChanged(val) => {
                if let Some(dialog) = &mut self.network_dialog {
                    dialog.signaling_port = val;
                }
            }
            Message::UseDefaultServerToggled(val) => {
                if let Some(dialog) = &mut self.network_dialog {
                    dialog.use_default_server = val;
                }
            }
            Message::SubmitNetworkDialog => {
                let name = self.network_dialog.as_ref().map(|d| d.network_input.clone()).unwrap_or_default();
                self.status_line = format!("Demo: Mock submitted network '{}'", name);
                self.network_dialog = None;
            }
            Message::ShutdownDaemon => {
                self.phase = Phase::PromptStartDaemon;
                self.status_line = "Demo: Daemon shut down (resetting demo).".into();
                self.peers.clear();
                self.connection_status = ConnectionStatus::Disconnected;
            }
            Message::ResetDemo => {
                *self = Self::new().0;
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let content: Element<'_, Message> = match &self.phase {
            Phase::CheckingDaemon => center(text("Checking for daemon…").size(20)).into(),
            Phase::PromptStartDaemon => {
                let prompt = column![
                    text("TransparNC Daemon (Demo Mode)").size(28),
                    Space::new().height(10),
                    text(
                        "The background daemon is not running.\n\
                         (This is a demo, clicking OK will simulate connection.)"
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

    fn main_view(&self) -> Element<'_, Message> {
        let status_text = match &self.connection_status {
            ConnectionStatus::Disconnected => "Disconnected".to_string(),
            ConnectionStatus::Connecting => "Connecting…".to_string(),
            ConnectionStatus::Connected { virtual_ip } => {
                format!("Connected — {}", virtual_ip)
            }
        };

        let header = row![
            text("TransparNC Demo").size(24),
            Space::new().width(Fill),
            text(status_text).size(16),
        ]
        .padding(10);

        let body: Element<'_, Message> = if let Some(dialog) = &self.network_dialog {
            self.network_dialog_view(dialog)
        } else {
            self.peer_list_view()
        };

        let controls = if self.network_dialog.is_some() {
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

        container(container(content)
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
            }))
            .padding(10)
            .height(Fill)
            .width(Fill)
            .into()
    }

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

    fn theme(&self) -> Theme {
        Theme::Dark
    }
}

pub fn main() -> iced::Result {
    iced::application(DemoApp::new, DemoApp::update, DemoApp::view)
        .title("TransparNC Demo")
        .theme(DemoApp::theme)
        .window_size((470.0, 450.0))
        .resizable(false)
        .run()
}
