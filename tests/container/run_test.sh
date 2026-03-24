#!/bin/bash
set -e

# Container-Based Testing Orchestration Script

echo "--- 1. Building the transpar_nc binary for Linux ---"
cargo build --release

echo "--- 2. Building Docker images ---"
docker compose -f docker-compose.test.yml build

echo "--- 3. Starting nodes to generate keys ---"
# We'll run a temporary container to generate keys for both peers
PEER1_KEYS=$(docker run --rm --entrypoint transpar_nc transpar-nc-peer1 generate-keys)
PEER2_KEYS=$(docker run --rm --entrypoint transpar_nc transpar-nc-peer2 generate-keys)

PEER1_PUB=$(echo "$PEER1_KEYS" | grep "Public Key:" | cut -d' ' -f3)
PEER1_PRIV=$(echo "$PEER1_KEYS" | grep "Private Key:" | cut -d' ' -f3)
PEER2_PUB=$(echo "$PEER2_KEYS" | grep "Public Key:" | cut -d' ' -f3)
PEER2_PRIV=$(echo "$PEER2_KEYS" | grep "Private Key:" | cut -d' ' -f3)

echo "Peer 1 Public Key: $PEER1_PUB"
echo "Peer 2 Public Key: $PEER2_PUB"

echo "--- 4. Starting nodes with full configuration ---"
# Remove any leftover named containers from a previous run to avoid conflicts.
docker rm -f peer1 peer2 2>/dev/null || true
# Peer 1 config: local-port 51820, tun-ip 10.0.0.1, peer is Peer 2 at 172.20.0.3:51820
docker compose -f docker-compose.test.yml run -d --name peer1 peer1 \
    --local-port 51820 --tun-ip 10.0.0.1 \
    --private-key "$PEER1_PRIV" \
    --peer-key "$PEER2_PUB" --peer-endpoint "172.20.0.3:51820"

# Peer 2 config: local-port 51820, tun-ip 10.0.0.2, peer is Peer 1 at 172.20.0.2:51820
docker compose -f docker-compose.test.yml run -d --name peer2 peer2 \
    --local-port 51820 --tun-ip 10.0.0.2 \
    --private-key "$PEER2_PRIV" \
    --peer-key "$PEER1_PUB" --peer-endpoint "172.20.0.2:51820"

echo "Waiting for nodes to initialize..."
sleep 5

echo "--- 5. Verification Phase: Ping Test ---"
echo "Pinging peer2 (10.0.0.2) from peer1..."
if docker exec peer1 ping -c 4 10.0.0.2; then
    echo "SUCCESS: Ping test passed!"
    RESULT=0
else
    echo "FAILURE: Ping test failed!"
    RESULT=1
fi

echo "--- 6. Cleanup Phase ---"
docker stop peer1 peer2 || true
docker rm peer1 peer2 || true
docker compose -f docker-compose.test.yml down

exit $RESULT
