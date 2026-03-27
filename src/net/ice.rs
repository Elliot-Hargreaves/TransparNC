//! ICE-like candidate gathering and connectivity checking for NAT traversal.
//!
//! This module implements a simplified ICE (Interactive Connectivity Establishment)
//! mechanism. Peers gather local (host) and STUN-discovered (server-reflexive)
//! candidates, exchange them via the signaling channel, then perform simultaneous
//! UDP hole-punch probes to find a working bidirectional path.

use crate::net::nat::{NatError, StunClient};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes prefixed to hole-punch probe packets so they can be
/// distinguished from WireGuard traffic on the same UDP socket.
const PROBE_MAGIC: &[u8; 4] = b"TPNC";

/// Default number of probe rounds before giving up on a candidate pair.
const DEFAULT_MAX_PROBE_ATTEMPTS: u32 = 10;

/// Default time to wait for an ack after sending a probe.
const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(1000);

/// Default delay between successive probe rounds.
const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_millis(200);

/// Configuration for ICE connectivity probe behaviour.
///
/// Allows callers to override the default probe budget — useful for lossy
/// network conditions where more attempts or longer timeouts are needed.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// Maximum number of probe rounds before declaring failure.
    pub max_attempts: u32,
    /// Per-round timeout waiting for an ack.
    pub timeout: Duration,
    /// Delay between successive probe rounds.
    pub interval: Duration,
}

impl Default for ProbeConfig {
    /// Returns the default probe configuration used for normal network conditions.
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_PROBE_ATTEMPTS,
            timeout: DEFAULT_PROBE_TIMEOUT,
            interval: DEFAULT_PROBE_INTERVAL,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during ICE candidate gathering or connectivity checks.
#[derive(Debug, Error)]
pub enum IceError {
    /// STUN discovery failed during candidate gathering.
    #[error("STUN discovery failed: {0}")]
    StunFailed(#[from] NatError),

    /// No working candidate pair could be found.
    #[error("All connectivity checks failed — no working candidate pair")]
    AllChecksFailed,

    /// A network I/O error occurred during probing.
    #[error("Network error during connectivity check: {0}")]
    NetworkError(String),

    /// Candidate gathering produced zero candidates.
    #[error("No candidates were gathered")]
    NoCandidates,
}

// ---------------------------------------------------------------------------
// Candidate types
// ---------------------------------------------------------------------------

/// The type/origin of a connectivity candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CandidateType {
    /// A local interface address — highest priority.
    Host,
    /// An address discovered via STUN (external/reflexive) — lower priority.
    ServerReflexive,
}

/// A single connectivity candidate representing a possible network path endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Candidate {
    /// The socket address (IP + port) for this candidate.
    pub addr: SocketAddr,
    /// How this candidate was discovered.
    pub candidate_type: CandidateType,
    /// Numeric priority — higher is better. Host candidates are preferred
    /// over server-reflexive ones because they avoid an extra NAT hop.
    pub priority: u32,
}

impl Candidate {
    /// Creates a new candidate with an automatically assigned priority based on type.
    pub fn new(addr: SocketAddr, candidate_type: CandidateType) -> Self {
        let priority = match candidate_type {
            CandidateType::Host => 200,
            CandidateType::ServerReflexive => 100,
        };
        Self {
            addr,
            candidate_type,
            priority,
        }
    }
}

// ---------------------------------------------------------------------------
// Candidate pair
// ---------------------------------------------------------------------------

/// A pairing of a local candidate with a remote candidate, representing a
/// potential bidirectional path between two peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePair {
    /// Our local candidate.
    pub local: Candidate,
    /// The remote peer's candidate.
    pub remote: Candidate,
    /// Combined priority used to order connectivity checks. Computed as the
    /// sum of both candidates' individual priorities so that host↔host pairs
    /// are tried first.
    pub priority: u32,
}

impl CandidatePair {
    /// Builds a new candidate pair and computes its combined priority.
    pub fn new(local: Candidate, remote: Candidate) -> Self {
        let priority = local.priority + remote.priority;
        Self {
            local,
            remote,
            priority,
        }
    }
}

// ---------------------------------------------------------------------------
// Connectivity state machine
// ---------------------------------------------------------------------------

/// Models the lifecycle of the ICE-like connectivity establishment process.
/// Using an enum prevents invalid state combinations (AGENTS.md §2).
#[derive(Debug)]
pub enum ConnectivityState {
    /// Currently gathering local and STUN candidates.
    Gathering,
    /// Candidates have been gathered and exchanged; connectivity checks are
    /// running against the supplied candidate pairs.
    Checking {
        /// Candidate pairs ordered by descending priority.
        pairs: Vec<CandidatePair>,
    },
    /// A working bidirectional path has been found.
    Connected {
        /// The pair that succeeded.
        selected_pair: CandidatePair,
    },
    /// All checks exhausted without finding a working path.
    Failed,
}

// ---------------------------------------------------------------------------
// Candidate gathering
// ---------------------------------------------------------------------------

/// Gathers local host candidates by enumerating non-loopback network interfaces.
///
/// Each interface address is paired with the given `port` (typically the port
/// of the UDP socket already bound for WireGuard traffic) to form a host
/// candidate.
pub fn gather_host_candidates(port: u16) -> Vec<Candidate> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .map(|iface| {
            let addr = SocketAddr::new(iface.ip(), port);
            Candidate::new(addr, CandidateType::Host)
        })
        .collect()
}

/// Gathers a server-reflexive candidate by performing a STUN binding request
/// through the provided socket.
pub async fn gather_srflx_candidate(
    stun_client: &dyn StunClient,
    socket: &UdpSocket,
) -> Result<Candidate, IceError> {
    let external = stun_client.discover_external_addr(socket).await?;
    Ok(Candidate::new(external, CandidateType::ServerReflexive))
}

/// Convenience wrapper that gathers all available candidates (host + STUN).
///
/// If STUN discovery fails the error is logged but host candidates are still
/// returned — connectivity may still succeed over a LAN.
pub async fn gather_candidates(
    stun_client: Option<&dyn StunClient>,
    socket: &UdpSocket,
) -> Result<Vec<Candidate>, IceError> {
    let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);

    let mut candidates = gather_host_candidates(local_port);

    if let Some(stun) = stun_client {
        match gather_srflx_candidate(stun, socket).await {
            Ok(c) => candidates.push(c),
            Err(e) => {
                // Log but don't fail — host candidates may still work on a LAN.
                eprintln!("ICE: STUN candidate gathering failed: {e}");
            }
        }
    }

    if candidates.is_empty() {
        return Err(IceError::NoCandidates);
    }

    // Sort descending by priority so higher-priority candidates come first.
    candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
    Ok(candidates)
}

// ---------------------------------------------------------------------------
// Candidate pair formation
// ---------------------------------------------------------------------------

/// Forms candidate pairs from local and remote candidate lists, sorted by
/// descending combined priority (host↔host first).
pub fn form_candidate_pairs(
    local_candidates: &[Candidate],
    remote_candidates: &[Candidate],
) -> Vec<CandidatePair> {
    let mut pairs: Vec<CandidatePair> = local_candidates
        .iter()
        .flat_map(|l| {
            remote_candidates.iter().filter_map(move |r| {
                // Only pair candidates of the same address family (IPv4↔IPv4, IPv6↔IPv6).
                if matches!(
                    (&l.addr.ip(), &r.addr.ip()),
                    (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
                ) {
                    Some(CandidatePair::new(l.clone(), r.clone()))
                } else {
                    None
                }
            })
        })
        .collect();

    pairs.sort_by(|a, b| b.priority.cmp(&a.priority));
    pairs
}

// ---------------------------------------------------------------------------
// Hole-punch probing
// ---------------------------------------------------------------------------

/// Builds a probe packet: `TPNC` magic + 1-byte flags.
/// Flag 0x00 = initial probe, 0x01 = ack.
fn build_probe(ack: bool) -> Vec<u8> {
    let mut pkt = PROBE_MAGIC.to_vec();
    pkt.push(if ack { 0x01 } else { 0x00 });
    pkt
}

/// Returns `true` if `data` looks like a valid probe or ack packet.
fn is_probe(data: &[u8]) -> bool {
    data.len() == 5 && data.starts_with(PROBE_MAGIC)
}

/// Returns `true` if the packet is a probe *ack*.
fn is_ack(data: &[u8]) -> bool {
    is_probe(data) && data[4] == 0x01
}

/// Runs connectivity checks over the given candidate pairs using the provided
/// UDP socket. Returns the first pair that achieves a bidirectional exchange
/// (probe → ack in both directions).
///
/// The caller is expected to drive this from a tokio task. The function sends
/// probes to each remote candidate and listens for acks. The first pair to
/// complete a round-trip wins.
pub async fn check_connectivity(
    socket: &UdpSocket,
    pairs: &[CandidatePair],
) -> Result<CandidatePair, IceError> {
    check_connectivity_with_config(socket, pairs, &ProbeConfig::default()).await
}

/// Like [`check_connectivity`] but accepts a custom [`ProbeConfig`] to
/// override the default probe budget. This is useful for tests that run
/// under simulated packet loss and need a larger retry budget.
pub async fn check_connectivity_with_config(
    socket: &UdpSocket,
    pairs: &[CandidatePair],
    config: &ProbeConfig,
) -> Result<CandidatePair, IceError> {
    if pairs.is_empty() {
        return Err(IceError::AllChecksFailed);
    }

    let probe_pkt = build_probe(false);
    let ack_pkt = build_probe(true);
    let mut buf = [0u8; 64];

    for round in 0..config.max_attempts {
        let deadline = tokio::time::Instant::now() + config.timeout;

        // Collect remote addresses so we can index into them without borrowing `pairs`.
        let remote_addrs: Vec<std::net::SocketAddr> = pairs.iter().map(|p| p.remote.addr).collect();
        let mut send_idx = 0usize;

        // Interleave sends and receives so the receive path is active before the
        // first probe hits the wire. This ensures an inbound probe from the remote
        // peer is never silently dropped while we are still in the send phase.
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            if send_idx < remote_addrs.len() {
                // Race a send against a receive so we never block on one while the
                // other is ready.
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        if let Ok((n, src)) = result {
                            let data = &buf[..n];
                            if is_probe(data) && !is_ack(data) {
                                let _ = socket.send_to(&ack_pkt, src).await;
                            }
                            if is_ack(data)
                                && let Some(pair) = pairs.iter().find(|p| p.remote.addr == src)
                            {
                                eprintln!(
                                    "[ice] Connectivity check succeeded: {} <-> {}",
                                    pair.local.addr, pair.remote.addr
                                );
                                return Ok(pair.clone());
                            }
                        }
                    }
                    result = socket.send_to(&probe_pkt, remote_addrs[send_idx]) => {
                        if let Err(e) = result {
                            eprintln!("[ice] Probe send to {} failed: {e}", remote_addrs[send_idx]);
                        } else {
                             eprintln!("[ice] Sent probe to {}", remote_addrs[send_idx]);
                        }
                        send_idx += 1;
                    }
                }
            } else {
                // All probes sent — pure receive loop until the round deadline.
                match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
                    Ok(Ok((n, src))) => {
                        let data = &buf[..n];
                        if is_probe(data) && !is_ack(data) {
                            let _ = socket.send_to(&ack_pkt, src).await;
                        }
                        if is_ack(data)
                            && let Some(pair) = pairs.iter().find(|p| p.remote.addr == src)
                        {
                            eprintln!(
                                "[ice] Connectivity check succeeded: {} <-> {}",
                                pair.local.addr, pair.remote.addr
                            );
                            return Ok(pair.clone());
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!("[ice] Recv error during check: {e}");
                    }
                    Err(_) => {
                        // Round deadline elapsed — move to next round.
                        break;
                    }
                }
            }
        }

        if round < config.max_attempts - 1 {
            tokio::time::sleep(config.interval).await;
        }
    }

    Err(IceError::AllChecksFailed)
}

// ---------------------------------------------------------------------------
// High-level orchestrator
// ---------------------------------------------------------------------------

/// Orchestrates the full ICE-like flow: gather → exchange → check → connect.
///
/// This drives the [`ConnectivityState`] machine from `Gathering` through to
/// `Connected` or `Failed`. The caller supplies remote candidates (obtained
/// via the signaling channel) and an optional STUN client.
pub async fn establish_connectivity(
    socket: &UdpSocket,
    stun_client: Option<&dyn StunClient>,
    remote_candidates: Vec<Candidate>,
) -> (ConnectivityState, Result<CandidatePair, IceError>) {
    // --- Gathering ---
    let local_candidates = match gather_candidates(stun_client, socket).await {
        Ok(c) => c,
        Err(e) => return (ConnectivityState::Failed, Err(e)),
    };

    // --- Checking ---
    let pairs = form_candidate_pairs(&local_candidates, &remote_candidates);
    if pairs.is_empty() {
        return (ConnectivityState::Failed, Err(IceError::AllChecksFailed));
    }

    let _state = ConnectivityState::Checking {
        pairs: pairs.clone(),
    };

    match check_connectivity(socket, &pairs).await {
        Ok(selected) => (
            ConnectivityState::Connected {
                selected_pair: selected.clone(),
            },
            Ok(selected),
        ),
        Err(e) => (ConnectivityState::Failed, Err(e)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::nat::MockStunClient;

    /// Verifies that host candidate gathering produces at least one candidate
    /// on any machine with a non-loopback interface.
    #[test]
    fn test_gather_host_candidates() {
        let candidates = gather_host_candidates(12345);
        // Most machines have at least one non-loopback interface.
        assert!(
            !candidates.is_empty(),
            "Expected at least one host candidate"
        );
        for c in &candidates {
            assert_eq!(c.candidate_type, CandidateType::Host);
            assert_eq!(c.addr.port(), 12345);
            assert!(!c.addr.ip().is_loopback());
        }
    }

    /// Verifies STUN candidate gathering via the mock client.
    #[tokio::test]
    async fn test_gather_srflx_candidate_mock() {
        let external: SocketAddr = "203.0.113.5:34567".parse().unwrap();
        let mock = MockStunClient::new(external);
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

        let candidate = gather_srflx_candidate(&mock, &socket).await.unwrap();
        assert_eq!(candidate.addr, external);
        assert_eq!(candidate.candidate_type, CandidateType::ServerReflexive);
    }

    /// Full gather_candidates with a mock STUN client should return host + srflx.
    #[tokio::test]
    async fn test_gather_candidates_with_mock_stun() {
        let external: SocketAddr = "203.0.113.5:34567".parse().unwrap();
        let mock = MockStunClient::new(external);
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

        let candidates = gather_candidates(Some(&mock), &socket).await.unwrap();
        assert!(candidates.len() >= 2, "Expected host + srflx candidates");

        let has_srflx = candidates
            .iter()
            .any(|c| c.candidate_type == CandidateType::ServerReflexive);
        assert!(has_srflx, "Expected a server-reflexive candidate");

        // Should be sorted descending by priority (host first).
        for w in candidates.windows(2) {
            assert!(w[0].priority >= w[1].priority);
        }
    }

    /// Candidate pair formation only pairs same address-family candidates.
    #[test]
    fn test_form_candidate_pairs_same_family() {
        let local = vec![
            Candidate::new("192.168.1.5:5000".parse().unwrap(), CandidateType::Host),
            Candidate::new("[::1]:5000".parse().unwrap(), CandidateType::Host),
        ];
        let remote = vec![Candidate::new(
            "192.168.22.1:6000".parse().unwrap(),
            CandidateType::Host,
        )];

        let pairs = form_candidate_pairs(&local, &remote);
        // Only the IPv4 local should pair with the IPv4 remote.
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            pairs[0].local.addr,
            "192.168.1.5:5000".parse::<SocketAddr>().unwrap()
        );
    }

    /// Pairs should be sorted by descending combined priority.
    #[test]
    fn test_candidate_pair_priority_ordering() {
        let local = vec![
            Candidate::new("192.168.1.5:5000".parse().unwrap(), CandidateType::Host),
            Candidate::new(
                "203.0.113.5:5000".parse().unwrap(),
                CandidateType::ServerReflexive,
            ),
        ];
        let remote = vec![Candidate::new(
            "192.168.22.1:6000".parse().unwrap(),
            CandidateType::Host,
        )];

        let pairs = form_candidate_pairs(&local, &remote);
        assert_eq!(pairs.len(), 2);
        // Host↔Host (200+200=400) should come before SrFlx↔Host (100+200=300).
        assert!(pairs[0].priority > pairs[1].priority);
    }

    /// Probe/ack packet construction and parsing round-trips correctly.
    #[test]
    fn test_probe_ack_packets() {
        let probe = build_probe(false);
        assert!(is_probe(&probe));
        assert!(!is_ack(&probe));

        let ack = build_probe(true);
        assert!(is_probe(&ack));
        assert!(is_ack(&ack));

        // Random data should not be detected as a probe.
        assert!(!is_probe(&[0x00, 0x01, 0x02]));
        assert!(!is_probe(&[0x00; 5]));
    }

    /// End-to-end hole-punch test on loopback: two sockets exchange probes
    /// and one side should successfully receive an ack.
    #[tokio::test]
    async fn test_hole_punch_loopback() {
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let candidate_a = Candidate::new(addr_a, CandidateType::Host);
        let candidate_b = Candidate::new(addr_b, CandidateType::Host);

        // Peer A checks connectivity to B.
        let pairs_a = vec![CandidatePair::new(candidate_a.clone(), candidate_b.clone())];
        // Peer B checks connectivity to A.
        let pairs_b = vec![CandidatePair::new(candidate_b.clone(), candidate_a.clone())];

        let (result_a, result_b) = tokio::join!(
            check_connectivity(&sock_a, &pairs_a),
            check_connectivity(&sock_b, &pairs_b),
        );

        // At least one side should succeed (both should on loopback).
        assert!(
            result_a.is_ok() || result_b.is_ok(),
            "Expected at least one side to complete the hole-punch handshake"
        );
    }

    /// Serialization round-trip for candidates (used in signaling exchange).
    #[test]
    fn test_candidate_serde_roundtrip() {
        let candidate = Candidate::new("192.168.1.5:51820".parse().unwrap(), CandidateType::Host);
        let json = serde_json::to_string(&candidate).unwrap();
        let deserialized: Candidate = serde_json::from_str(&json).unwrap();
        assert_eq!(candidate, deserialized);
    }

    /// Connectivity check returns `AllChecksFailed` when the remote peer is
    /// unreachable (non-routable address). Validates timeout and retry logic.
    #[tokio::test]
    async fn test_check_connectivity_unreachable() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();

        // RFC 5737 TEST-NET-1 — guaranteed non-routable, packets will be dropped.
        let unreachable: SocketAddr = "192.0.2.1:9999".parse().unwrap();

        let pairs = vec![CandidatePair::new(
            Candidate::new(local_addr, CandidateType::Host),
            Candidate::new(unreachable, CandidateType::ServerReflexive),
        )];

        let result = check_connectivity(&socket, &pairs).await;
        assert!(
            result.is_err(),
            "Expected AllChecksFailed for unreachable peer"
        );
        assert!(
            matches!(result.unwrap_err(), IceError::AllChecksFailed),
            "Error variant should be AllChecksFailed"
        );
    }

    /// `establish_connectivity` transitions through the state machine and
    /// reaches `Connected` on loopback with a mock STUN client.
    #[tokio::test]
    async fn test_establish_connectivity_loopback() {
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        // Remote candidates as peer B would advertise.
        let remote_for_a = vec![Candidate::new(addr_b, CandidateType::Host)];
        let remote_for_b = vec![Candidate::new(addr_a, CandidateType::Host)];

        // Run both sides concurrently — no STUN needed for loopback.
        let (result_a, result_b) = tokio::join!(
            establish_connectivity(&sock_a, None, remote_for_a),
            establish_connectivity(&sock_b, None, remote_for_b),
        );

        // At least one side should reach Connected.
        let a_connected = matches!(result_a.0, ConnectivityState::Connected { .. });
        let b_connected = matches!(result_b.0, ConnectivityState::Connected { .. });
        assert!(
            a_connected || b_connected,
            "Expected at least one side to reach Connected state"
        );

        // The successful side should return Ok with the winning pair.
        if a_connected {
            assert!(result_a.1.is_ok());
            let pair = result_a.1.unwrap();
            assert_eq!(pair.remote.addr, addr_b);
        }
        if b_connected {
            assert!(result_b.1.is_ok());
            let pair = result_b.1.unwrap();
            assert_eq!(pair.remote.addr, addr_a);
        }
    }

    /// `establish_connectivity` reaches `Failed` when remote candidates point
    /// at unreachable addresses.
    #[tokio::test]
    async fn test_establish_connectivity_fails_unreachable() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let remote = vec![Candidate::new(
            "192.0.2.1:9999".parse().unwrap(),
            CandidateType::Host,
        )];

        let (state, result) = establish_connectivity(&socket, None, remote).await;
        assert!(
            matches!(state, ConnectivityState::Failed),
            "Expected Failed state for unreachable remote"
        );
        assert!(result.is_err());
    }

    /// `form_candidate_pairs` with empty candidate lists returns no pairs,
    /// and `check_connectivity` with empty pairs returns an error.
    #[tokio::test]
    async fn test_empty_candidates() {
        let pairs = form_candidate_pairs(&[], &[]);
        assert!(pairs.is_empty());

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = check_connectivity(&socket, &pairs).await;
        assert!(matches!(result.unwrap_err(), IceError::AllChecksFailed));
    }

    /// Simulates packet loss by inserting a UDP proxy between two peers that
    /// drops every N-th packet. Verifies that the retry logic in
    /// `check_connectivity_with_config` still succeeds despite the loss.
    #[tokio::test]
    async fn test_check_connectivity_simulated_loss() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        // Peer sockets — they talk through the proxy, not directly.
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        // Proxy socket sits between the two peers.
        let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        // Drop every 3rd packet (~33% loss) — enough to exercise retries but
        // statistically very likely to succeed within 15 rounds.
        let counter = Arc::new(AtomicU64::new(0));
        let drop_every_n: u64 = 3;

        let proxy = Arc::new(proxy);
        let proxy_clone = Arc::clone(&proxy);
        let counter_clone = Arc::clone(&counter);

        // Proxy task: forward packets between A and B, dropping every N-th.
        let proxy_handle = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            // Track which side sent the first packet so we can route correctly.
            let mut known_a: Option<SocketAddr> = None;
            let mut known_b: Option<SocketAddr> = None;
            loop {
                let (n, src) = match proxy_clone.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };

                // Identify sender by matching the port.
                if src.port() == addr_a.port() {
                    known_a = Some(src);
                } else if src.port() == addr_b.port() {
                    known_b = Some(src);
                }

                let seq = counter_clone.fetch_add(1, Ordering::Relaxed);
                if seq % drop_every_n == 0 {
                    // Drop this packet.
                    continue;
                }

                // Forward to the other side.
                let dest = if src.port() == addr_a.port() {
                    known_b.unwrap_or(addr_b)
                } else {
                    known_a.unwrap_or(addr_a)
                };
                let _ = proxy_clone.send_to(&buf[..n], dest).await;
            }
        });

        // Each peer thinks the proxy is the remote peer.
        let candidate_a = Candidate::new(addr_a, CandidateType::Host);
        let proxy_as_b = Candidate::new(proxy_addr, CandidateType::Host);
        let candidate_b = Candidate::new(addr_b, CandidateType::Host);
        let proxy_as_a = Candidate::new(proxy_addr, CandidateType::Host);

        let pairs_a = vec![CandidatePair::new(candidate_a, proxy_as_b)];
        let pairs_b = vec![CandidatePair::new(candidate_b, proxy_as_a)];

        // Use a generous probe budget to tolerate the simulated loss.
        let config = ProbeConfig {
            max_attempts: 15,
            timeout: Duration::from_millis(500),
            interval: Duration::from_millis(100),
        };

        let (result_a, result_b) = tokio::join!(
            check_connectivity_with_config(&sock_a, &pairs_a, &config),
            check_connectivity_with_config(&sock_b, &pairs_b, &config),
        );

        // At least one side should succeed despite the packet loss.
        assert!(
            result_a.is_ok() || result_b.is_ok(),
            "Expected at least one side to succeed despite ~33% simulated packet loss. \
             A: {result_a:?}, B: {result_b:?}"
        );

        proxy_handle.abort();
    }
}
