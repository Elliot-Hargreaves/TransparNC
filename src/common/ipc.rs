//! IPC message types shared between the daemon and GUI processes.
//!
//! Communication uses a length-prefixed JSON wire format over a Unix domain
//! socket: each message is preceded by a 4-byte big-endian length header
//! followed by the JSON payload.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

/// Commands sent from the GUI to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonCommand {
    /// Request the daemon's current status.
    GetStatus,
    /// Connect to a network with the given identifier.
    Connect {
        /// Human-readable or UUID network identifier.
        network_id: String,
    },
    /// Disconnect from the current network.
    Disconnect,
    /// Tear down TUN devices and shut the daemon down gracefully.
    Shutdown,
}

/// Events sent from the daemon to the GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonEvent {
    /// Current connection status snapshot.
    StatusUpdate {
        /// The daemon's connection state.
        status: ConnectionStatus,
    },
    /// Information about connected peers has changed.
    PeerUpdate {
        /// Full list of currently known peers.
        peers: Vec<IpcPeerInfo>,
    },
    /// An error occurred inside the daemon.
    Error {
        /// Human-readable error description.
        message: String,
    },
    /// Acknowledgement that the daemon is shutting down.
    ShuttingDown,
}

/// Represents the daemon's high-level connection state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectionStatus {
    /// No active network connection.
    Disconnected,
    /// Currently establishing a connection.
    Connecting,
    /// Connected to a virtual network.
    Connected {
        /// The virtual IP assigned on the TUN interface.
        virtual_ip: String,
    },
}

/// Peer information exposed over IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcPeerInfo {
    /// Display name of the peer.
    pub name: String,
    /// Virtual IP address of the peer.
    pub virtual_ip: String,
    /// Whether the peer is currently reachable.
    pub connected: bool,
}

/// Writes a length-prefixed JSON message to the given writer.
///
/// The wire format is `[4-byte big-endian length][JSON payload]`.
pub async fn write_message<T: Serialize>(
    writer: &mut OwnedWriteHalf,
    msg: &T,
) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(msg)?;
    let len = (payload.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&payload).await?;
    Ok(())
}

/// Reads a length-prefixed JSON message from the given reader.
///
/// Returns `None` if the connection was closed cleanly (zero-length read).
pub async fn read_message<T: for<'de> Deserialize<'de>>(
    reader: &mut OwnedReadHalf,
) -> anyhow::Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    let msg = serde_json::from_slice(&payload)?;
    Ok(Some(msg))
}
