//! Core VPN state types and transitions.

use crate::common::messages::{NetworkId, PeerId, PeerInfo};

/// Core VPN state types and transitions.
#[derive(Debug, Clone)]
pub(crate) enum CoreState {
    /// Initial state before any network setup.
    Init,
    /// Connecting to the signaling server.
    ConnectingToSignaling,
    /// Joined a virtual network, waiting for peers or signaling.
    InNetwork {
        network_id: NetworkId,
        peer_id: PeerId,
        peers: Vec<PeerInfo>,
    },
    /// Establishing a direct P2P connection with a peer.
    Handshaking {
        target_peer: PeerId,
    },
    /// Connected and routing traffic.
    Connected,
}
