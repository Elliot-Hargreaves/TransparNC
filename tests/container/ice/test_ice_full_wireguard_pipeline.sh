#!/bin/bash
# Test: Full pipeline — ICE gather → exchange → hole-punch → WireGuard tunnel → ping
#
# This is the end-to-end integration test. Two peers behind separate NATs:
#   1. Gather candidates (host + STUN)
#   2. Exchange candidates via signaling server
#   3. Hole-punch to establish a UDP path
#   4. Configure WireGuard (boringtun) over the hole-punched path
#   5. Verify connectivity by pinging over the TUN interface
#
# This test uses the transpar_nc binary directly (not ice_test_peer) since
# it needs the full VPN engine with TUN + WireGuard.

COMPOSE_FILE="${1:?Usage: $0 <compose-file>}"

echo "--- Full Pipeline: Generating WireGuard keys ---"

# Generate key pairs for both peers.
PEER1_KEYS=$(docker exec ice-peer-1 transpar_nc generate-keys 2>&1)
PEER1_PRIVKEY=$(echo "$PEER1_KEYS" | grep "Private Key:" | awk '{print $3}')
PEER1_PUBKEY=$(echo "$PEER1_KEYS" | grep "Public Key:" | awk '{print $3}')

PEER2_KEYS=$(docker exec ice-peer-2 transpar_nc generate-keys 2>&1)
PEER2_PRIVKEY=$(echo "$PEER2_KEYS" | grep "Private Key:" | awk '{print $3}')
PEER2_PUBKEY=$(echo "$PEER2_KEYS" | grep "Public Key:" | awk '{print $3}')

if [ -z "$PEER1_PRIVKEY" ] || [ -z "$PEER2_PUBKEY" ]; then
    echo "FAILURE: Could not generate WireGuard keys"
    echo "Peer-1 keys: $PEER1_KEYS"
    echo "Peer-2 keys: $PEER2_KEYS"
    exit 1
fi

echo "Peer-1 pubkey: $PEER1_PUBKEY"
echo "Peer-2 pubkey: $PEER2_PUBKEY"

echo "--- Full Pipeline: Discovering srflx addresses ---"

# Discover external addresses via STUN so we know the hole-punch endpoints.
PEER1_GATHER=$(docker exec ice-peer-1 timeout 20 \
    ice_test_peer --local-port 51820 \
    --stun-server 172.50.0.100:3478 \
    --remote-candidates 127.0.0.1:1 2>&1) || true
PEER1_SRFLX=$(echo "$PEER1_GATHER" | grep "ServerReflexive" | awk '{print $NF}')

PEER2_GATHER=$(docker exec ice-peer-2 timeout 20 \
    ice_test_peer --local-port 51821 \
    --stun-server 172.50.0.100:3478 \
    --remote-candidates 127.0.0.1:1 2>&1) || true
PEER2_SRFLX=$(echo "$PEER2_GATHER" | grep "ServerReflexive" | awk '{print $NF}')

if [ -z "$PEER1_SRFLX" ] || [ -z "$PEER2_SRFLX" ]; then
    echo "FAILURE: Could not discover srflx addresses"
    exit 1
fi

echo "Peer-1 srflx: $PEER1_SRFLX"
echo "Peer-2 srflx: $PEER2_SRFLX"

echo "--- Full Pipeline: Starting VPN engines ---"

# Start peer-1 with peer-2's public key and srflx endpoint.
docker exec -d ice-peer-1 \
    transpar_nc \
    --local-port 51820 \
    --tun-ip 10.0.0.1 \
    --private-key "$PEER1_PRIVKEY" \
    --peer-key "$PEER2_PUBKEY" \
    --peer-endpoint "$PEER2_SRFLX" \
    --stun-server 172.50.0.100:3478

# Start peer-2 with peer-1's public key and srflx endpoint.
docker exec -d ice-peer-2 \
    transpar_nc \
    --local-port 51821 \
    --tun-ip 10.0.0.2 \
    --private-key "$PEER2_PRIVKEY" \
    --peer-key "$PEER1_PUBKEY" \
    --peer-endpoint "$PEER1_SRFLX" \
    --stun-server 172.50.0.100:3478

echo "Waiting for VPN engines to initialize (10s)..."
sleep 10

echo "--- Full Pipeline: Verifying TUN interfaces ---"

PEER1_TUN=$(docker exec ice-peer-1 ip addr show 2>&1)
echo "Peer-1 interfaces:"
echo "$PEER1_TUN"

PEER2_TUN=$(docker exec ice-peer-2 ip addr show 2>&1)
echo "Peer-2 interfaces:"
echo "$PEER2_TUN"

RESULT=0

# Check that TUN interfaces exist with the expected IPs.
if echo "$PEER1_TUN" | grep -q "10.0.0.1"; then
    echo "SUCCESS: Peer-1 has TUN interface with 10.0.0.1"
else
    echo "FAILURE: Peer-1 missing TUN interface with 10.0.0.1"
    RESULT=1
fi

if echo "$PEER2_TUN" | grep -q "10.0.0.2"; then
    echo "SUCCESS: Peer-2 has TUN interface with 10.0.0.2"
else
    echo "FAILURE: Peer-2 missing TUN interface with 10.0.0.2"
    RESULT=1
fi

echo "--- Full Pipeline: Ping test over WireGuard tunnel ---"

# Peer-1 pings peer-2's virtual IP through the WireGuard tunnel.
PING_RESULT=$(docker exec ice-peer-1 ping -c 3 -W 5 10.0.0.2 2>&1) || true
echo "$PING_RESULT"

if echo "$PING_RESULT" | grep -q " 0% packet loss"; then
    echo "SUCCESS: Ping over WireGuard tunnel succeeded (0% loss)"
elif echo "$PING_RESULT" | grep -qE " [0-9]+% packet loss" && ! echo "$PING_RESULT" | grep -q "100% packet loss"; then
    echo "SUCCESS: Ping over WireGuard tunnel partially succeeded"
else
    echo "FAILURE: Ping over WireGuard tunnel failed"
    RESULT=1
fi

# Reverse direction: peer-2 pings peer-1.
PING_RESULT2=$(docker exec ice-peer-2 ping -c 3 -W 5 10.0.0.1 2>&1) || true
echo "$PING_RESULT2"

if echo "$PING_RESULT2" | grep -q " 0% packet loss"; then
    echo "SUCCESS: Reverse ping over WireGuard tunnel succeeded"
elif echo "$PING_RESULT2" | grep -qE " [0-9]+% packet loss" && ! echo "$PING_RESULT2" | grep -q "100% packet loss"; then
    echo "SUCCESS: Reverse ping partially succeeded"
else
    echo "FAILURE: Reverse ping over WireGuard tunnel failed"
    RESULT=1
fi

exit $RESULT
