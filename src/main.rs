//! Main entry point for TransparNC.
//!
//! Dispatches between GUI mode (default), daemon mode (`--daemon`), and
//! headless mode (`--network`). The daemon runs with elevated privileges and
//! manages TUN devices and WireGuard tunnels. The GUI runs as a normal user
//! and communicates with the daemon over a Unix domain socket. Headless mode
//! runs the full networking stack in the foreground without a GUI, which is
//! useful for testing in headless environments.

use clap::Parser;

shadow_rs::shadow!(build);

/// TransparNC — Peer-to-peer VPN.
#[derive(Parser, Debug)]
#[command(
    name = "transparnc",
    version = &*Box::leak(
        format!(
            "{} ({}, {})",
            env!("CARGO_PKG_VERSION"),
            if build::SHORT_COMMIT.is_empty() {
                "no-git"
            } else {
                &build::SHORT_COMMIT[..build::SHORT_COMMIT.len().min(7)]
            },
            build::BUILD_TIME_2822
        )
        .into_boxed_str()
    ),
    about
)]
struct Cli {
    /// Run in daemon mode (privileged — handles TUN/WireGuard).
    #[arg(long)]
    daemon: bool,

    /// Network name or UUID to join. When provided, the app runs in headless
    /// mode: the full networking stack starts in the foreground with no GUI.
    #[arg(long)]
    network: Option<String>,

    /// Signaling server WebSocket URL (used in headless mode).
    #[arg(long, default_value = "coffy.dev:8080")]
    signaling_server: String,

    /// Path to the IPC Unix domain socket (used in daemon/GUI mode).
    #[arg(long, default_value = "/tmp/transparnc.sock")]
    socket: String,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    if let Some(network) = cli.network {
        // Headless mode: --network was supplied, so run the networking stack
        // in the foreground without a GUI or IPC socket.
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(transpar_nc::daemon::run_headless(
                &network,
                &cli.signaling_server,
            ))
    } else if cli.daemon {
        // Daemon mode needs a tokio runtime for async networking.
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(transpar_nc::daemon::run(&cli.socket))
    } else {
        // GUI mode — Iced manages its own event loop.
        transpar_nc::gui::app::run(&cli.socket).map_err(|e| anyhow::anyhow!("{}", e))
    }
}
