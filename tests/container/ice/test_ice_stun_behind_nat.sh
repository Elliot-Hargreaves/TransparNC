#!/bin/bash
# Test: Real STUN candidate gathering behind NAT
#
# Verifies that a peer behind a NAT router can use a real STUN server
# (coturn) to discover its server-reflexive address, and that the
# discovered address is the NAT gateway's public IP (not the private IP).
#
# Expected: peer-1 discovers 172.50.0.10:* (nat-router-1's public IP)
#           peer-2 discovers 172.50.0.20:* (nat-router-2's public IP)

COMPOSE_FILE="${1:?Usage: $0 <compose-file>}"

echo "--- STUN behind NAT: Running candidate gathering on peer-1 ---"
PEER1_OUTPUT=$(docker exec ice-peer-1 timeout 20 \
    ice_test_peer --local-port 51820 \
    --stun-server 172.50.0.100:3478 \
    --remote-candidates 127.0.0.1:1 2>&1) || true
echo "$PEER1_OUTPUT"

echo "--- STUN behind NAT: Running candidate gathering on peer-2 ---"
PEER2_OUTPUT=$(docker exec ice-peer-2 timeout 20 \
    ice_test_peer --local-port 51821 \
    --stun-server 172.50.0.100:3478 \
    --remote-candidates 127.0.0.1:1 2>&1) || true
echo "$PEER2_OUTPUT"

# Verify peer-1 discovered a server-reflexive candidate with the NAT gateway IP.
RESULT=0

if echo "$PEER1_OUTPUT" | grep -q "ServerReflexive 172.50.0.10:"; then
    echo "SUCCESS: Peer-1 discovered srflx candidate via NAT-1 gateway (172.50.0.10)"
else
    echo "FAILURE: Peer-1 did not discover expected srflx candidate (172.50.0.10:*)"
    RESULT=1
fi

if echo "$PEER2_OUTPUT" | grep -q "ServerReflexive 172.50.0.20:"; then
    echo "SUCCESS: Peer-2 discovered srflx candidate via NAT-2 gateway (172.50.0.20)"
else
    echo "FAILURE: Peer-2 did not discover expected srflx candidate (172.50.0.20:*)"
    RESULT=1
fi

# Both peers should also have host candidates (their private IPs).
if echo "$PEER1_OUTPUT" | grep -q "Host 172.60.0.10:"; then
    echo "SUCCESS: Peer-1 has host candidate with private IP (172.60.0.10)"
else
    echo "FAILURE: Peer-1 missing host candidate for 172.60.0.10"
    RESULT=1
fi

if echo "$PEER2_OUTPUT" | grep -q "Host 172.70.0.10:"; then
    echo "SUCCESS: Peer-2 has host candidate with private IP (172.70.0.10)"
else
    echo "FAILURE: Peer-2 missing host candidate for 172.70.0.10"
    RESULT=1
fi

exit $RESULT
