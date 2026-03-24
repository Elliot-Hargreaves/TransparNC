#!/bin/bash
# Test: Cross-subnet candidate pair fallback
#
# Verifies that when two peers are on different private subnets, host↔host
# candidate pairs (private IPs) fail and the connectivity check correctly
# falls back to server-reflexive pairs (which succeed via hole-punch).
#
# We give peer-1 only peer-2's *private* IP as a remote candidate (which is
# unreachable across subnets) and verify it fails. Then we give it peer-2's
# srflx address and verify it succeeds — demonstrating the fallback logic.

COMPOSE_FILE="${1:?Usage: $0 <compose-file>}"

echo "--- Cross-Subnet Fallback: Step 1 — host-only should fail ---"

# Peer-1 tries to reach peer-2's private IP directly (unreachable across NATs).
FAIL_OUTPUT=$(docker exec ice-peer-1 timeout 20 \
    ice_test_peer --local-port 51820 \
    --remote-candidates "172.70.0.10:51821" 2>&1) || true
echo "$FAIL_OUTPUT"

if echo "$FAIL_OUTPUT" | grep -q "FAILED"; then
    echo "SUCCESS: Host-to-host across subnets correctly failed"
else
    echo "FAILURE: Expected host-to-host across subnets to fail"
    exit 1
fi

echo "--- Cross-Subnet Fallback: Step 2 — gather srflx for peer-2 ---"

PEER2_GATHER=$(docker exec ice-peer-2 timeout 20 \
    ice_test_peer --local-port 51821 \
    --stun-server 172.50.0.100:3478 \
    --remote-candidates 127.0.0.1:1 2>&1) || true
echo "$PEER2_GATHER"

PEER2_SRFLX=$(echo "$PEER2_GATHER" | grep "ServerReflexive" | awk '{print $NF}')

if [ -z "$PEER2_SRFLX" ]; then
    echo "FAILURE: Could not get peer-2 srflx address"
    exit 1
fi

echo "Peer-2 srflx: $PEER2_SRFLX"

echo "--- Cross-Subnet Fallback: Step 3 — srflx pair should succeed ---"

# Now give peer-1 both the unreachable private IP AND the srflx address.
# The connectivity check should fail on the private IP pair (higher priority)
# and succeed on the srflx pair (lower priority but reachable).
docker exec ice-peer-1 timeout 30 \
    ice_test_peer --local-port 51820 \
    --stun-server 172.50.0.100:3478 \
    --remote-candidates "172.70.0.10:51821,$PEER2_SRFLX" 2>&1 &
PID1=$!

# Peer-2 also needs to probe back for hole-punch to work.
PEER1_GATHER=$(docker exec ice-peer-1 timeout 20 \
    ice_test_peer --local-port 51822 \
    --stun-server 172.50.0.100:3478 \
    --remote-candidates 127.0.0.1:1 2>&1) || true
PEER1_SRFLX=$(echo "$PEER1_GATHER" | grep "ServerReflexive" | awk '{print $NF}')

docker exec ice-peer-2 timeout 30 \
    ice_test_peer --local-port 51821 \
    --stun-server 172.50.0.100:3478 \
    --remote-candidates "172.60.0.10:51820,$PEER1_SRFLX" 2>&1 &
PID2=$!

wait $PID1
EXIT1=$?
wait $PID2
EXIT2=$?

echo "Peer-1 exit: $EXIT1, Peer-2 exit: $EXIT2"

if [ $EXIT1 -eq 0 ] || [ $EXIT2 -eq 0 ]; then
    echo "SUCCESS: Fallback from host to srflx pair succeeded"
    exit 0
else
    echo "FAILURE: Fallback to srflx pair did not succeed"
    exit 1
fi
