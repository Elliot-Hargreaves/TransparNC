//! Signaling messages for peer discovery and NAT traversal.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a virtual network room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkId(pub Uuid);

/// Unique identifier for a peer in the signaling system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub Uuid);

/// Messages sent between the client and the signaling server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalingMessage {
    /// Peer joins a specific network.
    Join {
        network_id: NetworkId,
        peer_id: PeerId,
        public_key: String,
    },
    /// Server acknowledges join and sends current peer list.
    Joined {
        peers: Vec<PeerInfo>,
    },
    /// Sent to a specific peer to initiate connection (SDP/ICE candidate exchange).
    Signal {
        to: PeerId,
        from: PeerId,
        data: String,
    },
    /// Periodic heartbeat to keep the signaling session alive.
    Heartbeat {
        peer_id: PeerId,
    },
}

/// Basic information about a peer in a network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub public_key: String,
}
