#!/bin/bash
# Test: Hole punching through actual NAT
#
# Two peers behind separate NAT routers discover their srflx addresses
# via STUN, then attempt hole-punch connectivity using each other's
# server-reflexive candidates. Both peers run ice_test_peer concurrently
# in a single process invocation (gather + check in one process) so the
# NAT conntrack state created during STUN discovery is still alive when
# the hole-punch probes are sent.
COMPOSE_FILE="${1:?Usage: $0 <compose-file>}"

echo "--- Hole Punch NAT: Gathering STUN candidates for both peers ---"

# Use --gather-only so each peer discovers its srflx address without
# closing the socket mid-test. The NAT mapping is created here and must
# remain alive for the hole-punch phase, which is why gather and check
# must happen in the same process (see Gap 2 in ICE_IMPLEMENTATION_GAPS.md).
PEER1_GATHER=$(docker exec ice-peer-1 timeout 20 \
    ice_test_peer --local-port 51820 \
    --stun-server 172.50.0.100:3478 \
    --gather-only 2>&1)
echo "Peer-1 gather output:"
echo "$PEER1_GATHER"

PEER2_GATHER=$(docker exec ice-peer-2 timeout 20 \
    ice_test_peer --local-port 51821 \
    --stun-server 172.50.0.100:3478 \
    --gather-only 2>&1)
echo "Peer-2 gather output:"
echo "$PEER2_GATHER"

# Extract the srflx addresses.
PEER1_SRFLX=$(echo "$PEER1_GATHER" | grep "ServerReflexive" | awk '{print $NF}')
PEER2_SRFLX=$(echo "$PEER2_GATHER" | grep "ServerReflexive" | awk '{print $NF}')

if [ -z "$PEER1_SRFLX" ] || [ -z "$PEER2_SRFLX" ]; then
    echo "FAILURE: Could not extract srflx addresses"
    echo "  Peer-1 srflx: '$PEER1_SRFLX'"
    echo "  Peer-2 srflx: '$PEER2_SRFLX'"
    exit 1
fi

echo "Peer-1 srflx: $PEER1_SRFLX"
echo "Peer-2 srflx: $PEER2_SRFLX"

echo "--- Hole Punch NAT: Running concurrent hole-punch ---"

# Launch both peers concurrently in a single process each. Each peer
# gathers candidates (re-using the same local port to hit the same NAT
# mapping) and immediately runs connectivity checks against the other
# peer's srflx address. Simultaneous probes ensure both NAT routers
# create conntrack entries before either probe arrives.
docker exec ice-peer-1 timeout 30 \
    ice_test_peer --local-port 51820 \
    --stun-server 172.50.0.100:3478 \
    --remote-candidates "$PEER2_SRFLX" 2>&1 &
PID1=$!

docker exec ice-peer-2 timeout 30 \
    ice_test_peer --local-port 51821 \
    --stun-server 172.50.0.100:3478 \
    --remote-candidates "$PEER1_SRFLX" 2>&1 &
PID2=$!

# Wait for both and capture exit codes.
wait $PID1
EXIT1=$?
wait $PID2
EXIT2=$?

echo "Peer-1 exit: $EXIT1, Peer-2 exit: $EXIT2"

# At least one side should succeed (both should with full-cone NAT).
if [ $EXIT1 -eq 0 ] || [ $EXIT2 -eq 0 ]; then
    echo "SUCCESS: Hole punch through NAT succeeded"
    exit 0
else
    echo "FAILURE: Neither peer completed the hole-punch handshake"
    exit 1
fi
