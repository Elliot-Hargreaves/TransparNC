//! Signaling server for TransparNC.
//!
//! This server coordinates peer discovery and NAT traversal by managing "rooms" (networks)
//! and relaying signaling messages between peers. It uses Redis for session persistence.

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
use transpar_nc::common::messages::{PeerId, PeerInfo, SignalingMessage};

/// Shared state for the signaling server.
struct ServerState {
    /// Redis client for persistent peer storage.
    redis: redis::Client,
    /// Active WebSocket connections for real-time relaying.
    /// Mapping: PeerId -> sender for their WebSocket.
    active_peers: RwLock<HashMap<PeerId, tokio::sync::mpsc::UnboundedSender<Message>>>,
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
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

/// Handles an individual WebSocket connection.
async fn handle_socket(socket: WebSocket, state: Arc<ServerState>) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // Task to forward messages from the channel to the WebSocket sender
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    let mut current_peer_id: Option<PeerId> = None;

    while let Some(Ok(msg)) = receiver.next().await {
        let sig_msg = if let Message::Text(ref text) = msg {
            serde_json::from_str::<SignalingMessage>(text).ok()
        } else {
            None
        };
        if let Some(sig_msg) = sig_msg {
            match sig_msg {
                SignalingMessage::Join {
                    network_id,
                    peer_id,
                    public_key,
                } => {
                    current_peer_id = Some(peer_id);

                    // Register peer in state
                    state.active_peers.write().await.insert(peer_id, tx.clone());

                    // Persist peer in Redis (with TTL)
                    if let Ok(mut conn) = state.redis.get_multiplexed_async_connection().await {
                        let key = format!("net:{}:peers", network_id.0);
                        let peer_info = PeerInfo {
                            peer_id,
                            public_key,
                        };

                        // Fetch existing peers *before* inserting the newcomer so we can
                        // notify them about the new arrival and send the newcomer the
                        // existing list separately.
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
                        let _: () = conn.expire(key.clone(), 3600).await.unwrap_or(()); // 1 hour TTL

                        // Notify the newcomer of all peers that were already present.
                        let _ = tx.send(Message::Text(
                            serde_json::to_string(&SignalingMessage::Joined {
                                peers: existing_peers.clone(),
                            })
                            .unwrap()
                            .into(),
                        ));

                        // Notify every existing active peer that a new peer has joined so
                        // they can proactively initiate candidate exchange.
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
                    // Relay signal to target peer
                    let peers = state.active_peers.read().await;
                    if let Some(target_tx) = peers.get(&to) {
                        let relay = SignalingMessage::Signal { to, from, data };
                        let _ = target_tx
                            .send(Message::Text(serde_json::to_string(&relay).unwrap().into()));
                    }
                }
                SignalingMessage::Heartbeat { peer_id } => {
                    // Extend TTL in Redis could be done here if we tracked network_id
                    println!("Heartbeat from {:?}", peer_id);
                }
                _ => {}
            }
        }
    }

    // Cleanup on disconnect
    if let Some(peer_id) = current_peer_id {
        state.active_peers.write().await.remove(&peer_id);
    }
    send_task.abort();
}
