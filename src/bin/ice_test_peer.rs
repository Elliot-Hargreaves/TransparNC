//! Standalone ICE test peer binary for container-based integration tests.
//!
//! This binary performs ICE candidate gathering, exchanges candidates with a
//! remote peer via the signaling server, and attempts hole-punch connectivity.
//! It is designed to be run inside Docker containers with various NAT topologies.

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use transpar_nc::common::messages::{CandidateExchange, NetworkId, PeerId, SignalingMessage};
use transpar_nc::net::ice::{
    Candidate, CandidateType, check_connectivity, establish_connectivity, form_candidate_pairs,
    gather_candidates,
};
use transpar_nc::net::nat::{RealStunClient, StunClient};
use uuid::Uuid;

/// CLI arguments for the ICE test peer.
#[derive(Parser)]
#[command(about = "ICE test peer for container integration tests")]
struct Cli {
    /// UDP port to bind for hole-punch probes.
    #[arg(long, default_value_t = 51820)]
    local_port: u16,

    /// STUN server address (ip:port).
    #[arg(long)]
    stun_server: Option<String>,

    /// Signaling server WebSocket URL (e.g., ws://172.30.0.100:8080/ws).
    #[arg(long)]
    signaling_url: Option<String>,

    /// Network ID to join on the signaling server.
    #[arg(long, default_value = "00000000-0000-0000-0000-000000000001")]
    network_id: String,

    /// Manually specified remote candidates (comma-separated ip:port list).
    /// Used when signaling is not available.
    #[arg(long, value_delimiter = ',')]
    remote_candidates: Vec<SocketAddr>,

    /// If set, run the full establish_connectivity orchestrator instead of
    /// manual gather + check.
    #[arg(long, default_value_t = false)]
    use_orchestrator: bool,

    /// If set, also attempt a WireGuard tunnel after hole-punch succeeds.
    #[arg(long, default_value_t = false)]
    wireguard: bool,

    /// Virtual TUN IP for WireGuard mode.
    #[arg(long, default_value = "10.0.0.1")]
    tun_ip: String,

    /// Remote peer's WireGuard public key (hex) for WireGuard mode.
    #[arg(long)]
    peer_wg_key: Option<String>,

    /// Our WireGuard private key (hex) for WireGuard mode.
    #[arg(long)]
    wg_private_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("ICE_TEST: Binding UDP socket on 0.0.0.0:{}", cli.local_port);
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", cli.local_port)).await?;
    let local_addr = socket.local_addr()?;
    println!("ICE_TEST: Bound to {local_addr}");

    // --- Candidate Gathering ---
    let stun_client: Option<Box<dyn StunClient>> = cli
        .stun_server
        .map(|s| Box::new(RealStunClient::new(s)) as Box<dyn StunClient>);

    let stun_ref = stun_client.as_deref();

    println!("ICE_TEST: Gathering candidates...");
    let local_candidates = gather_candidates(stun_ref, &socket).await?;
    println!("ICE_TEST: Gathered {} candidates:", local_candidates.len());
    for c in &local_candidates {
        println!("  {:?} {}", c.candidate_type, c.addr);
    }

    // --- Get remote candidates ---
    let remote_candidates = if !cli.remote_candidates.is_empty() {
        // Manual mode: remote candidates provided via CLI.
        cli.remote_candidates
            .iter()
            .map(|addr| Candidate::new(*addr, CandidateType::Host))
            .collect::<Vec<_>>()
    } else if let Some(ref signaling_url) = cli.signaling_url {
        // Signaling mode: exchange candidates via WebSocket.
        println!("ICE_TEST: Connecting to signaling server at {signaling_url}");
        exchange_candidates_via_signaling(signaling_url, &cli.network_id, &local_candidates).await?
    } else {
        println!("ICE_TEST: ERROR — no remote candidates and no signaling URL provided");
        std::process::exit(1);
    };

    println!(
        "ICE_TEST: Received {} remote candidates:",
        remote_candidates.len()
    );
    for c in &remote_candidates {
        println!("  {:?} {}", c.candidate_type, c.addr);
    }

    // --- Connectivity Check ---
    if cli.use_orchestrator {
        println!("ICE_TEST: Running establish_connectivity orchestrator...");
        let (state, result) =
            establish_connectivity(&socket, stun_ref, remote_candidates.clone()).await;
        println!("ICE_TEST: State: {state:?}");
        match result {
            Ok(pair) => {
                println!(
                    "ICE_TEST: SUCCESS — connected via {} <-> {}",
                    pair.local.addr, pair.remote.addr
                );
            }
            Err(e) => {
                println!("ICE_TEST: FAILED — {e}");
                std::process::exit(1);
            }
        }
    } else {
        println!("ICE_TEST: Forming candidate pairs...");
        let pairs = form_candidate_pairs(&local_candidates, &remote_candidates);
        println!("ICE_TEST: Formed {} pairs", pairs.len());
        for (i, p) in pairs.iter().enumerate() {
            println!(
                "  [{i}] {} <-> {} (priority {})",
                p.local.addr, p.remote.addr, p.priority
            );
        }

        println!("ICE_TEST: Running connectivity checks...");
        match check_connectivity(&socket, &pairs).await {
            Ok(pair) => {
                println!(
                    "ICE_TEST: SUCCESS — connected via {} <-> {}",
                    pair.local.addr, pair.remote.addr
                );
            }
            Err(e) => {
                println!("ICE_TEST: FAILED — {e}");
                std::process::exit(1);
            }
        }
    }

    // --- Optional WireGuard tunnel verification ---
    if cli.wireguard {
        println!("ICE_TEST: WireGuard mode requested — setting up tunnel...");
        // WireGuard tunnel setup is handled by the full pipeline test script
        // which configures TUN + boringtun after hole-punch succeeds.
        println!("ICE_TEST: WireGuard tunnel setup deferred to test script.");
    }

    println!("ICE_TEST: Done.");
    Ok(())
}

/// Exchanges ICE candidates with a remote peer via the signaling server.
///
/// Joins the specified network, waits for a peer, sends our candidates via
/// a `Signal` message, and waits to receive the remote peer's candidates.
async fn exchange_candidates_via_signaling(
    signaling_url: &str,
    network_id_str: &str,
    local_candidates: &[Candidate],
) -> Result<Vec<Candidate>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::connect_async;

    let network_id = NetworkId(Uuid::parse_str(network_id_str)?);
    let peer_id = PeerId(Uuid::new_v4());

    let (mut ws, _) = connect_async(signaling_url).await?;
    println!("ICE_TEST: Connected to signaling server as {}", peer_id.0);

    // Join the network.
    let join_msg = SignalingMessage::Join {
        network_id,
        peer_id,
        public_key: "test-key".to_string(),
    };
    let join_json = serde_json::to_string(&join_msg)?;
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        join_json.into(),
    ))
    .await?;

    // Wait for Joined response and any peer signals.
    let mut has_sent_to_peer = false;

    // Send our candidates to any peer that's already in the network, or wait
    // for one to join.
    let timeout = tokio::time::Duration::from_secs(30);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("Timed out waiting for remote peer candidates");
        }

        let msg = match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(msg))) => msg,
            Ok(Some(Err(e))) => anyhow::bail!("WebSocket error: {e}"),
            Ok(None) => anyhow::bail!("WebSocket closed"),
            Err(_) => anyhow::bail!("Timed out waiting for signaling message"),
        };

        if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
            let sig_msg: SignalingMessage = serde_json::from_str(&text)?;
            match sig_msg {
                SignalingMessage::Joined { peers } => {
                    println!("ICE_TEST: Joined network, {} existing peers", peers.len());
                    // Send our candidates to each existing peer.
                    for peer in &peers {
                        has_sent_to_peer = true;
                        let exchange = CandidateExchange {
                            candidates: local_candidates.to_vec(),
                        };
                        let signal = SignalingMessage::Signal {
                            to: peer.peer_id,
                            from: peer_id,
                            data: serde_json::to_string(&exchange)?,
                        };
                        let json = serde_json::to_string(&signal)?;
                        ws.send(tokio_tungstenite::tungstenite::Message::Text(json.into()))
                            .await?;
                        println!("ICE_TEST: Sent candidates to peer {}", peer.peer_id.0);
                    }
                }
                SignalingMessage::Signal { from, data, .. } => {
                    println!("ICE_TEST: Received signal from {}", from.0);
                    let exchange: CandidateExchange = serde_json::from_str(&data)?;
                    let remote_candidates = exchange.candidates;

                    // If we haven't sent our candidates to this peer yet, do so now.
                    if !has_sent_to_peer {
                        let our_exchange = CandidateExchange {
                            candidates: local_candidates.to_vec(),
                        };
                        let signal = SignalingMessage::Signal {
                            to: from,
                            from: peer_id,
                            data: serde_json::to_string(&our_exchange)?,
                        };
                        let json = serde_json::to_string(&signal)?;
                        ws.send(tokio_tungstenite::tungstenite::Message::Text(json.into()))
                            .await?;
                        println!("ICE_TEST: Sent candidates to peer {}", from.0);
                    }

                    // Close WebSocket gracefully.
                    let _ = ws.close(None).await;

                    return Ok(remote_candidates);
                }
                _ => {}
            }
        }
    }
}
