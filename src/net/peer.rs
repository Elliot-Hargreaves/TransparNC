//! Peer management module for tracking active peers and their connection status.
//!
//! Provides a state-machine based approach to peer lifecycle management,
//! a `PeerStore` trait for testability, and a concrete `PeerManager`
//! implementation with heartbeat/keep-alive support.

use crate::common::messages::{PeerId, PeerInfo};
use std::collections::HashMap;
use thiserror::Error;
use tokio::time::Instant;

/// Errors that can occur during peer management operations.
#[derive(Debug, Error)]
pub enum PeerError {
    /// Attempted to operate on a peer that does not exist.
    #[error("peer {0:?} not found")]
    NotFound(PeerId),

    /// Attempted to add a peer that already exists.
    #[error("peer {0:?} already exists")]
    AlreadyExists(PeerId),

    /// Attempted an invalid state transition.
    #[error("invalid state transition from {from} to {to} for peer {peer_id:?}")]
    InvalidTransition {
        /// The peer whose transition was rejected.
        peer_id: PeerId,
        /// The current state name.
        from: &'static str,
        /// The requested target state name.
        to: &'static str,
    },
}

/// Connection status of a single peer.
///
/// Models the lifecycle of a peer connection as a state machine.
/// Valid transitions:
/// - `Discovered` → `Negotiating`
/// - `Negotiating` → `Connected`
/// - `Connected` → `Stale` (missed heartbeats)
/// - `Stale` → `Connected` (heartbeat received)
/// - `Stale` → `Disconnected` (timeout)
/// - Any state → `Disconnected` (explicit disconnect)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerConnectionState {
    /// Peer discovered via signaling but not yet connected.
    Discovered,
    /// ICE/candidate exchange in progress.
    Negotiating,
    /// WireGuard tunnel established and traffic flowing.
    Connected,
    /// Peer has gone stale (missed heartbeats).
    Stale,
    /// Peer explicitly disconnected or timed out.
    Disconnected,
}

impl std::fmt::Display for PeerConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovered => write!(f, "Discovered"),
            Self::Negotiating => write!(f, "Negotiating"),
            Self::Connected => write!(f, "Connected"),
            Self::Stale => write!(f, "Stale"),
            Self::Disconnected => write!(f, "Disconnected"),
        }
    }
}

impl PeerConnectionState {
    /// Returns the string name of this state variant, used in error messages.
    fn name(&self) -> &'static str {
        match self {
            Self::Discovered => "Discovered",
            Self::Negotiating => "Negotiating",
            Self::Connected => "Connected",
            Self::Stale => "Stale",
            Self::Disconnected => "Disconnected",
        }
    }

    /// Checks whether transitioning from `self` to `target` is valid.
    ///
    /// Any state may transition to `Disconnected` (explicit teardown).
    /// Otherwise only the transitions documented on the enum are allowed.
    pub fn can_transition_to(&self, target: &PeerConnectionState) -> bool {
        if *target == PeerConnectionState::Disconnected {
            return true;
        }
        matches!(
            (self, target),
            (Self::Discovered, Self::Negotiating)
                | (Self::Negotiating, Self::Connected)
                | (Self::Connected, Self::Stale)
                | (Self::Stale, Self::Connected)
        )
    }
}

/// A single peer entry combining identity, metadata, and connection state.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// The unique identifier of this peer.
    pub peer_id: PeerId,
    /// Signaling-level metadata (public key, etc.).
    pub info: PeerInfo,
    /// Current connection state.
    pub state: PeerConnectionState,
    /// Timestamp of the last received heartbeat or data packet.
    /// `None` if the peer has never been in the `Connected` state.
    pub last_heartbeat: Option<Instant>,
}

impl PeerEntry {
    /// Creates a new peer entry in the `Discovered` state.
    pub fn new(info: PeerInfo) -> Self {
        Self {
            peer_id: info.peer_id,
            info,
            state: PeerConnectionState::Discovered,
            last_heartbeat: None,
        }
    }
}

/// Trait defining the interface for peer storage and management.
///
/// Enables mocking in unit tests and decouples the storage backend
/// from the networking logic.
pub trait PeerStore {
    /// Adds a new peer. Returns an error if the peer already exists.
    fn add_peer(&mut self, info: PeerInfo) -> Result<(), PeerError>;

    /// Removes a peer by ID. Returns an error if the peer does not exist.
    fn remove_peer(&mut self, peer_id: &PeerId) -> Result<(), PeerError>;

    /// Returns a reference to a peer entry, or `None` if not found.
    fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerEntry>;

    /// Returns a mutable reference to a peer entry, or `None` if not found.
    fn get_peer_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerEntry>;

    /// Transitions a peer to a new state, enforcing valid transitions.
    fn update_state(
        &mut self,
        peer_id: &PeerId,
        new_state: PeerConnectionState,
    ) -> Result<(), PeerError>;

    /// Returns all peers currently in the `Connected` state.
    fn active_peers(&self) -> Vec<&PeerEntry>;

    /// Returns the total number of tracked peers.
    fn peer_count(&self) -> usize;

    /// Returns all tracked peers regardless of state.
    fn all_peers(&self) -> Vec<&PeerEntry>;
}

/// In-memory peer manager backed by a `HashMap`.
///
/// This is the primary implementation of `PeerStore` used at runtime.
/// It enforces state-machine transitions and tracks heartbeat timestamps.
#[derive(Debug)]
pub struct PeerManager {
    /// Map from peer ID to peer entry for O(1) lookups.
    peers: HashMap<PeerId, PeerEntry>,
}

impl PeerManager {
    /// Creates a new empty peer manager.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Records a heartbeat for the given peer, updating `last_heartbeat`
    /// and transitioning from `Stale` back to `Connected` if applicable.
    ///
    /// Returns an error if the peer is not found.
    pub fn record_heartbeat(&mut self, peer_id: &PeerId) -> Result<(), PeerError> {
        let entry = self
            .peers
            .get_mut(peer_id)
            .ok_or(PeerError::NotFound(*peer_id))?;

        entry.last_heartbeat = Some(Instant::now());

        // A stale peer that sends a heartbeat is alive again.
        if entry.state == PeerConnectionState::Stale {
            entry.state = PeerConnectionState::Connected;
        }

        Ok(())
    }

    /// Checks all connected/stale peers against the given thresholds and
    /// transitions them accordingly.
    ///
    /// - A `Connected` peer whose `last_heartbeat` is older than `stale_after`
    ///   transitions to `Stale`.
    /// - A `Stale` peer whose `last_heartbeat` is older than `disconnect_after`
    ///   transitions to `Disconnected`.
    pub fn check_timeouts(
        &mut self,
        stale_after: std::time::Duration,
        disconnect_after: std::time::Duration,
    ) {
        let now = Instant::now();
        for entry in self.peers.values_mut() {
            let Some(last) = entry.last_heartbeat else {
                continue;
            };
            let elapsed = now.duration_since(last);

            match entry.state {
                PeerConnectionState::Connected if elapsed >= stale_after => {
                    entry.state = PeerConnectionState::Stale;
                }
                PeerConnectionState::Stale if elapsed >= disconnect_after => {
                    entry.state = PeerConnectionState::Disconnected;
                }
                _ => {}
            }
        }
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerStore for PeerManager {
    fn add_peer(&mut self, info: PeerInfo) -> Result<(), PeerError> {
        let peer_id = info.peer_id;
        if self.peers.contains_key(&peer_id) {
            return Err(PeerError::AlreadyExists(peer_id));
        }
        self.peers.insert(peer_id, PeerEntry::new(info));
        Ok(())
    }

    fn remove_peer(&mut self, peer_id: &PeerId) -> Result<(), PeerError> {
        self.peers
            .remove(peer_id)
            .map(|_| ())
            .ok_or(PeerError::NotFound(*peer_id))
    }

    fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerEntry> {
        self.peers.get(peer_id)
    }

    fn get_peer_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerEntry> {
        self.peers.get_mut(peer_id)
    }

    fn update_state(
        &mut self,
        peer_id: &PeerId,
        new_state: PeerConnectionState,
    ) -> Result<(), PeerError> {
        let entry = self
            .peers
            .get_mut(peer_id)
            .ok_or(PeerError::NotFound(*peer_id))?;

        if !entry.state.can_transition_to(&new_state) {
            return Err(PeerError::InvalidTransition {
                peer_id: *peer_id,
                from: entry.state.name(),
                to: new_state.name(),
            });
        }

        // When transitioning to Connected, initialize the heartbeat timestamp.
        if new_state == PeerConnectionState::Connected && entry.last_heartbeat.is_none() {
            entry.last_heartbeat = Some(Instant::now());
        }

        entry.state = new_state;
        Ok(())
    }

    fn active_peers(&self) -> Vec<&PeerEntry> {
        self.peers
            .values()
            .filter(|e| e.state == PeerConnectionState::Connected)
            .collect()
    }

    fn peer_count(&self) -> usize {
        self.peers.len()
    }

    fn all_peers(&self) -> Vec<&PeerEntry> {
        self.peers.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::messages::{PeerId, PeerInfo};
    use uuid::Uuid;

    /// Helper to create a `PeerInfo` with a random ID.
    fn make_peer_info() -> PeerInfo {
        PeerInfo {
            peer_id: PeerId(Uuid::new_v4()),
            public_key: "test-pubkey".to_string(),
            virtual_ip: "172.16.0.1".to_string(),
        }
    }

    // ── State transition tests ──────────────────────────────────────────

    #[test]
    fn peer_starts_in_discovered_state() {
        let info = make_peer_info();
        let entry = PeerEntry::new(info);
        assert_eq!(entry.state, PeerConnectionState::Discovered);
        assert!(entry.last_heartbeat.is_none());
    }

    #[test]
    fn peer_transitions_discovered_to_negotiating() {
        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        assert!(
            mgr.update_state(&info.peer_id, PeerConnectionState::Negotiating)
                .is_ok()
        );
        assert_eq!(
            mgr.get_peer(&info.peer_id).unwrap().state,
            PeerConnectionState::Negotiating
        );
    }

    #[test]
    fn peer_transitions_negotiating_to_connected() {
        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Negotiating)
            .unwrap();
        assert!(
            mgr.update_state(&info.peer_id, PeerConnectionState::Connected)
                .is_ok()
        );
        let entry = mgr.get_peer(&info.peer_id).unwrap();
        assert_eq!(entry.state, PeerConnectionState::Connected);
        assert!(entry.last_heartbeat.is_some());
    }

    #[test]
    fn peer_transitions_connected_to_stale() {
        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Negotiating)
            .unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Connected)
            .unwrap();
        assert!(
            mgr.update_state(&info.peer_id, PeerConnectionState::Stale)
                .is_ok()
        );
        assert_eq!(
            mgr.get_peer(&info.peer_id).unwrap().state,
            PeerConnectionState::Stale
        );
    }

    #[test]
    fn peer_transitions_stale_to_disconnected() {
        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Negotiating)
            .unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Connected)
            .unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Stale)
            .unwrap();
        assert!(
            mgr.update_state(&info.peer_id, PeerConnectionState::Disconnected)
                .is_ok()
        );
        assert_eq!(
            mgr.get_peer(&info.peer_id).unwrap().state,
            PeerConnectionState::Disconnected
        );
    }

    #[test]
    fn peer_transitions_stale_back_to_connected() {
        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Negotiating)
            .unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Connected)
            .unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Stale)
            .unwrap();
        assert!(
            mgr.update_state(&info.peer_id, PeerConnectionState::Connected)
                .is_ok()
        );
        assert_eq!(
            mgr.get_peer(&info.peer_id).unwrap().state,
            PeerConnectionState::Connected
        );
    }

    #[test]
    fn invalid_transition_discovered_to_connected_rejected() {
        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        let result = mgr.update_state(&info.peer_id, PeerConnectionState::Connected);
        assert!(result.is_err());
    }

    #[test]
    fn any_state_can_transition_to_disconnected() {
        // Discovered → Disconnected
        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        assert!(
            mgr.update_state(&info.peer_id, PeerConnectionState::Disconnected)
                .is_ok()
        );
    }

    // ── PeerManager CRUD tests ──────────────────────────────────────────

    #[test]
    fn add_peer_increases_count() {
        let mut mgr = PeerManager::new();
        assert_eq!(mgr.peer_count(), 0);
        mgr.add_peer(make_peer_info()).unwrap();
        assert_eq!(mgr.peer_count(), 1);
    }

    #[test]
    fn remove_peer_decreases_count() {
        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        assert_eq!(mgr.peer_count(), 1);
        mgr.remove_peer(&info.peer_id).unwrap();
        assert_eq!(mgr.peer_count(), 0);
    }

    #[test]
    fn add_duplicate_peer_is_rejected() {
        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        let result = mgr.add_peer(info);
        assert!(result.is_err());
    }

    #[test]
    fn get_peer_returns_correct_entry() {
        let info = make_peer_info();
        let id = info.peer_id;
        let mut mgr = PeerManager::new();
        mgr.add_peer(info).unwrap();
        let entry = mgr.get_peer(&id).unwrap();
        assert_eq!(entry.peer_id, id);
        assert_eq!(entry.info.public_key, "test-pubkey");
    }

    #[test]
    fn update_state_changes_peer_connection_state() {
        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Negotiating)
            .unwrap();
        assert_eq!(
            mgr.get_peer(&info.peer_id).unwrap().state,
            PeerConnectionState::Negotiating
        );
    }

    #[test]
    fn active_peers_only_returns_connected_peers() {
        let mut mgr = PeerManager::new();

        let info1 = make_peer_info();
        let info2 = make_peer_info();
        let info3 = make_peer_info();

        mgr.add_peer(info1.clone()).unwrap();
        mgr.add_peer(info2.clone()).unwrap();
        mgr.add_peer(info3.clone()).unwrap();

        // Move info1 to Connected
        mgr.update_state(&info1.peer_id, PeerConnectionState::Negotiating)
            .unwrap();
        mgr.update_state(&info1.peer_id, PeerConnectionState::Connected)
            .unwrap();

        // info2 stays Discovered, info3 goes to Negotiating
        mgr.update_state(&info3.peer_id, PeerConnectionState::Negotiating)
            .unwrap();

        let active = mgr.active_peers();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].peer_id, info1.peer_id);
    }

    #[test]
    fn removing_nonexistent_peer_returns_error() {
        let mut mgr = PeerManager::new();
        let fake_id = PeerId(Uuid::new_v4());
        let result = mgr.remove_peer(&fake_id);
        assert!(result.is_err());
    }

    // ── Heartbeat / keep-alive tests ────────────────────────────────────

    #[tokio::test]
    async fn heartbeat_updates_last_heartbeat_timestamp() {
        tokio::time::pause();

        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Negotiating)
            .unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Connected)
            .unwrap();

        let first = mgr.get_peer(&info.peer_id).unwrap().last_heartbeat.unwrap();

        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        mgr.record_heartbeat(&info.peer_id).unwrap();

        let second = mgr.get_peer(&info.peer_id).unwrap().last_heartbeat.unwrap();
        assert!(second > first);
    }

    #[tokio::test]
    async fn peer_marked_stale_after_missed_heartbeats() {
        tokio::time::pause();

        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Negotiating)
            .unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Connected)
            .unwrap();

        // Advance past the stale threshold
        tokio::time::advance(std::time::Duration::from_secs(20)).await;

        mgr.check_timeouts(
            std::time::Duration::from_secs(15),
            std::time::Duration::from_secs(60),
        );

        assert_eq!(
            mgr.get_peer(&info.peer_id).unwrap().state,
            PeerConnectionState::Stale
        );
    }

    #[tokio::test]
    async fn peer_marked_disconnected_after_prolonged_staleness() {
        tokio::time::pause();

        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Negotiating)
            .unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Connected)
            .unwrap();

        // First pass: become stale
        tokio::time::advance(std::time::Duration::from_secs(20)).await;
        mgr.check_timeouts(
            std::time::Duration::from_secs(15),
            std::time::Duration::from_secs(60),
        );
        assert_eq!(
            mgr.get_peer(&info.peer_id).unwrap().state,
            PeerConnectionState::Stale
        );

        // Second pass: become disconnected
        tokio::time::advance(std::time::Duration::from_secs(45)).await;
        mgr.check_timeouts(
            std::time::Duration::from_secs(15),
            std::time::Duration::from_secs(60),
        );
        assert_eq!(
            mgr.get_peer(&info.peer_id).unwrap().state,
            PeerConnectionState::Disconnected
        );
    }

    #[tokio::test]
    async fn heartbeat_resets_stale_peer_to_connected() {
        tokio::time::pause();

        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Negotiating)
            .unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Connected)
            .unwrap();

        // Become stale
        tokio::time::advance(std::time::Duration::from_secs(20)).await;
        mgr.check_timeouts(
            std::time::Duration::from_secs(15),
            std::time::Duration::from_secs(60),
        );
        assert_eq!(
            mgr.get_peer(&info.peer_id).unwrap().state,
            PeerConnectionState::Stale
        );

        // Heartbeat brings it back
        mgr.record_heartbeat(&info.peer_id).unwrap();
        assert_eq!(
            mgr.get_peer(&info.peer_id).unwrap().state,
            PeerConnectionState::Connected
        );
    }

    #[tokio::test]
    async fn unknown_peer_heartbeat_is_ignored() {
        let mut mgr = PeerManager::new();
        let fake_id = PeerId(Uuid::new_v4());
        let result = mgr.record_heartbeat(&fake_id);
        assert!(result.is_err());
    }

    // ── CoreState integration tests ─────────────────────────────────────

    #[test]
    fn all_peers_returns_every_tracked_peer() {
        let mut mgr = PeerManager::new();
        mgr.add_peer(make_peer_info()).unwrap();
        mgr.add_peer(make_peer_info()).unwrap();
        mgr.add_peer(make_peer_info()).unwrap();
        assert_eq!(mgr.all_peers().len(), 3);
    }

    #[test]
    fn peer_manager_reflects_disconnected_peers() {
        let info = make_peer_info();
        let mut mgr = PeerManager::new();
        mgr.add_peer(info.clone()).unwrap();
        mgr.update_state(&info.peer_id, PeerConnectionState::Disconnected)
            .unwrap();

        assert!(mgr.active_peers().is_empty());
        assert_eq!(
            mgr.get_peer(&info.peer_id).unwrap().state,
            PeerConnectionState::Disconnected
        );
    }

    // ── SignalingMessage::Heartbeat serialization test ───────────────────

    #[test]
    fn heartbeat_message_serialization_roundtrip() {
        use crate::common::messages::SignalingMessage;

        let peer_id = PeerId(Uuid::new_v4());
        let msg = SignalingMessage::Heartbeat { peer_id };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: SignalingMessage = serde_json::from_str(&json).unwrap();

        match deserialized {
            SignalingMessage::Heartbeat { peer_id: id } => assert_eq!(id, peer_id),
            _ => panic!("expected Heartbeat variant"),
        }
    }
}
