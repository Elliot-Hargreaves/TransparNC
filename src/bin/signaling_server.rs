//! Signaling server for TransparNC.
//!
//! This server coordinates peer discovery and NAT traversal by managing "rooms" (networks)
//! and relaying signaling messages between peers. It uses Redis for session persistence
//! and allocates Docker-style virtual IPs (172.X.0.N/24) to each peer.

use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use redis::AsyncCommands;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use transpar_nc::common::messages::{NetworkId, PeerId, PeerInfo, SignalingMessage};

/// Shared state for the signaling server.
struct ServerState {
    /// Redis client for persistent peer storage.
    redis: redis::Client,
    /// Active WebSocket connections for real-time relaying.
    /// Mapping: PeerId -> sender for their WebSocket.
    active_peers: RwLock<HashMap<PeerId, tokio::sync::mpsc::UnboundedSender<Message>>>,
    /// Tracks which peer belongs to which network for disconnect cleanup.
    peer_networks: RwLock<HashMap<PeerId, NetworkId>>,
    /// Tracks assigned client indices per network. Each slot is `Some(peer_id)` when
    /// occupied or `None` when recycled after a disconnect.
    network_allocations: RwLock<HashMap<NetworkId, Vec<Option<PeerId>>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration from environment
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let addr: SocketAddr = listen_addr.parse()?;

    println!("Starting signaling server on {}", addr);
    println!("Connecting to Redis at {}", redis_url);

    let redis_client = redis::Client::open(redis_url)?;
    let state = Arc::new(ServerState {
        redis: redis_client,
        active_peers: RwLock::new(HashMap::new()),
        peer_networks: RwLock::new(HashMap::new()),
        network_allocations: RwLock::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Upgrades HTTP requests to WebSockets.
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ServerState>>,
) -> impl IntoResponse {
    println!("[signaling] New WebSocket connection request");
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

/// Allocates a client index within a network, recycling gaps left by
/// disconnected peers. Returns a 1-based index.
async fn allocate_client_index(
    state: &ServerState,
    network_id: NetworkId,
    peer_id: PeerId,
) -> usize {
    let mut allocs = state.network_allocations.write().await;
    let slots = allocs.entry(network_id).or_default();
    // Find first empty slot to recycle.
    if let Some(i) = slots.iter().position(|s| s.is_none()) {
        slots[i] = Some(peer_id);
        i + 1
    } else {
        slots.push(Some(peer_id));
        slots.len()
    }
}

/// Handles an individual WebSocket connection.
async fn handle_socket(socket: WebSocket, state: Arc<ServerState>) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // Task to forward messages from the channel to the WebSocket sender.
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    let mut current_peer_id: Option<PeerId> = None;
    println!("[signaling] WebSocket connection established");

    while let Some(Ok(msg)) = receiver.next().await {
        let sig_msg = if let Message::Text(ref text) = msg {
            serde_json::from_str::<SignalingMessage>(text).ok()
        } else {
            None
        };
        if let Some(sig_msg) = sig_msg {
            println!(
                "[signaling] Received message: {:?}",
                std::mem::discriminant(&sig_msg)
            );
            match sig_msg {
                SignalingMessage::Join {
                    network_id,
                    peer_id,
                    public_key,
                } => {
                    println!(
                        "[signaling] Peer {:?} joining network {:?}",
                        peer_id, network_id
                    );
                    current_peer_id = Some(peer_id);

                    // Track which network this peer belongs to for cleanup.
                    state
                        .peer_networks
                        .write()
                        .await
                        .insert(peer_id, network_id);

                    // Register peer in active connections.
                    state.active_peers.write().await.insert(peer_id, tx.clone());

                    // Allocate a virtual IP index for this peer.
                    let client_index =
                        allocate_client_index(&state, network_id, peer_id).await as u8;
                    println!(
                        "[signaling] Assigned index {} to peer {:?}",
                        client_index, peer_id
                    );

                    let peer_info = PeerInfo {
                        peer_id,
                        public_key,
                        virtual_index: client_index,
                    };

                    // Persist peer in Redis (with TTL).
                    if let Ok(mut conn) = state.redis.get_multiplexed_async_connection().await {
                        let key = format!("net:{}:peers", network_id.0);

                        // Fetch existing peers *before* inserting the newcomer.
                        let existing_peers: Vec<PeerInfo> = if let Ok(peers_map) = conn
                            .hgetall::<String, HashMap<String, String>>(key.clone())
                            .await
                        {
                            peers_map
                                .values()
                                .filter_map(|s| serde_json::from_str(s).ok())
                                .collect()
                        } else {
                            vec![]
                        };

                        let _: () = conn
                            .hset(
                                key.clone(),
                                peer_id.0.to_string(),
                                serde_json::to_string(&peer_info).unwrap(),
                            )
                            .await
                            .unwrap_or(());
                        let _: () = conn.expire(key.clone(), 3600).await.unwrap_or(());

                        // Notify the newcomer of all peers that were already present.
                        let _ = tx.send(Message::Text(
                            serde_json::to_string(&SignalingMessage::Joined {
                                peers: existing_peers.clone(),
                                assigned_index: client_index,
                            })
                            .unwrap()
                            .into(),
                        ));

                        // Notify every existing active peer that a new peer has joined.
                        let active = state.active_peers.read().await;
                        let notification = serde_json::to_string(&SignalingMessage::PeerJoined {
                            peer: peer_info,
                        })
                        .unwrap();
                        for existing in &existing_peers {
                            if let Some(existing_tx) = active.get(&existing.peer_id) {
                                let _ =
                                    existing_tx.send(Message::Text(notification.clone().into()));
                            }
                        }
                    }
                }
                SignalingMessage::Signal { to, from, data } => {
                    println!("[signaling] Relaying signal from {:?} to {:?}", from, to);
                    let peers = state.active_peers.read().await;
                    if let Some(target_tx) = peers.get(&to) {
                        let relay = SignalingMessage::Signal { to, from, data };
                        let _ = target_tx
                            .send(Message::Text(serde_json::to_string(&relay).unwrap().into()));
                    }
                }
                SignalingMessage::Heartbeat { peer_id } => {
                    println!("[signaling] Heartbeat from {:?}", peer_id);
                }
                _ => {}
            }
        }
    }

    // Cleanup on disconnect — recycle IP and notify remaining peers.
    if let Some(peer_id) = current_peer_id {
        println!("[signaling] Peer {:?} disconnected", peer_id);
        state.active_peers.write().await.remove(&peer_id);

        // Determine which network this peer was in.
        let network_id = state.peer_networks.write().await.remove(&peer_id);

        // Recycle the client index so the next joiner can reuse it.
        {
            let mut allocs = state.network_allocations.write().await;
            if let Some(net_id) = network_id
                && let Some(slots) = allocs.get_mut(&net_id)
            {
                for slot in slots.iter_mut() {
                    if *slot == Some(peer_id) {
                        *slot = None;
                    }
                }
            }
        }

        // Remove from Redis.
        if let Some(net_id) = network_id {
            if let Ok(mut conn) = state.redis.get_multiplexed_async_connection().await {
                let key = format!("net:{}:peers", net_id.0);
                let _: () = conn.hdel(key, peer_id.0.to_string()).await.unwrap_or(());
            }

            // Notify remaining peers about the departure.
            let active = state.active_peers.read().await;
            let notification =
                serde_json::to_string(&SignalingMessage::PeerLeft { peer_id }).unwrap();
            let peer_networks = state.peer_networks.read().await;
            for (other_id, other_tx) in active.iter() {
                // Only notify peers in the same network.
                if peer_networks.get(other_id) == Some(&net_id) {
                    let _ = other_tx.send(Message::Text(notification.clone().into()));
                }
            }
        }
    } else {
        println!("[signaling] Anonymous WebSocket connection closed");
    }
    send_task.abort();
}
