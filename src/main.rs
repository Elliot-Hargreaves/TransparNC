//! Main entry point for TransparNC.
//!
//! Dispatches between GUI mode (default) and daemon mode (`--daemon`).
//! The daemon runs with elevated privileges and manages TUN devices and
//! WireGuard tunnels. The GUI runs as a normal user and communicates
//! with the daemon over a Unix domain socket.

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

    /// Path to the IPC Unix domain socket.
    #[arg(long, default_value = "/tmp/transparnc.sock")]
    socket: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.daemon {
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
