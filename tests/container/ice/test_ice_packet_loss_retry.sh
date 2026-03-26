#!/bin/bash
# Test: Timeout and retry behavior under packet loss (tc netem)
#
# Uses Linux traffic control (tc netem) to add packet loss on the NAT
# routers, then verifies that the ICE probe retry logic handles it
# correctly:
#   1. With moderate loss (20%), hole-punch should still succeed (retries).
#   2. With extreme loss (100%), hole-punch should fail gracefully.

COMPOSE_FILE="${1:?Usage: $0 <compose-file>}"

# First, gather srflx addresses before adding packet loss.
echo "--- Packet Loss: Gathering srflx addresses (clean network) ---"

PEER1_GATHER=$(docker exec ice-peer-1 timeout 20 \
    ice_test_peer --local-port 51830 \
    --stun-server 172.50.0.100:3478 \
    --gather-only 2>&1)
PEER1_SRFLX=$(echo "$PEER1_GATHER" | grep "ServerReflexive" | awk '{print $NF}')
PEER2_GATHER=$(docker exec ice-peer-2 timeout 20 \
    ice_test_peer --local-port 51831 \
    --stun-server 172.50.0.100:3478 \
    --gather-only 2>&1)
PEER2_SRFLX=$(echo "$PEER2_GATHER" | grep "ServerReflexive" | awk '{print $NF}')

if [ -z "$PEER1_SRFLX" ] || [ -z "$PEER2_SRFLX" ]; then
    echo "FAILURE: Could not gather srflx addresses"
    exit 1
fi

echo "Peer-1 srflx: $PEER1_SRFLX"
echo "Peer-2 srflx: $PEER2_SRFLX"

# --- Test with 30% packet loss: should succeed via retries ---

echo "--- Packet Loss: Adding 20% loss on NAT router 1 only ---"

# Apply loss on one NAT router only — 20% one-way loss is sufficient to
# exercise the retry logic without making round-trips statistically unlikely.
# With 10 probe rounds, the probability of all rounds failing is (0.2^2)^10 < 0.01%.
docker exec ice-nat-router-1 sh -c "
    apk add --no-cache iproute2 2>/dev/null
    PUBLIC_IF=\$(ip -o -4 addr show | awk '/172\.50/{print \$2}' | head -1)
    tc qdisc add dev \$PUBLIC_IF root netem loss 20%
    echo 'NAT-1: 20% loss applied on '\$PUBLIC_IF
" 2>&1

echo "--- Packet Loss: Running hole-punch with 20% loss ---"

docker exec ice-peer-1 timeout 45 \
    ice_test_peer --local-port 51830 \
    --stun-server 172.50.0.100:3478 \
    --max-probe-attempts 20 --probe-timeout-ms 1500 \
    --remote-candidates "$PEER2_SRFLX" 2>&1 &
PID1=$!

docker exec ice-peer-2 timeout 45 \
    ice_test_peer --local-port 51831 \
    --stun-server 172.50.0.100:3478 \
    --max-probe-attempts 20 --probe-timeout-ms 1500 \
    --remote-candidates "$PEER1_SRFLX" 2>&1 &
PID2=$!

wait $PID1
EXIT1=$?
wait $PID2
EXIT2=$?

echo "20% loss — Peer-1 exit: $EXIT1, Peer-2 exit: $EXIT2"

RESULT=0
if [ $EXIT1 -eq 0 ] || [ $EXIT2 -eq 0 ]; then
    echo "SUCCESS: Hole-punch succeeded despite 20% packet loss (retries worked)"
else
    echo "FAILURE: Hole-punch failed with 20% loss — retry logic may be insufficient"
    RESULT=1
fi

# --- Test with 100% packet loss: should fail gracefully ---

echo "--- Packet Loss: Increasing to 100% loss ---"

docker exec ice-nat-router-1 sh -c "
    PUBLIC_IF=\$(ip -o -4 addr show | awk '/172\.50/{print \$2}' | head -1)
    tc qdisc change dev \$PUBLIC_IF root netem loss 100%
    echo 'NAT-1: 100% loss applied'
" 2>&1

echo "--- Packet Loss: Running hole-punch with 100% loss (should fail) ---"

docker exec ice-peer-1 timeout 30 \
    ice_test_peer --local-port 51832 \
    --remote-candidates "$PEER2_SRFLX" 2>&1 &
PID1=$!

docker exec ice-peer-2 timeout 30 \
    ice_test_peer --local-port 51833 \
    --remote-candidates "$PEER1_SRFLX" 2>&1 &
PID2=$!

wait $PID1
EXIT1=$?
wait $PID2
EXIT2=$?

echo "100% loss — Peer-1 exit: $EXIT1, Peer-2 exit: $EXIT2"

if [ $EXIT1 -ne 0 ] && [ $EXIT2 -ne 0 ]; then
    echo "SUCCESS: Both peers correctly failed with 100% packet loss"
else
    echo "FAILURE: Expected both peers to fail with 100% loss"
    RESULT=1
fi

# --- Cleanup: remove netem rules ---

echo "--- Packet Loss: Removing tc netem rules ---"

docker exec ice-nat-router-1 sh -c "
    PUBLIC_IF=\$(ip -o -4 addr show | awk '/172\.50/{print \$2}' | head -1)
    tc qdisc del dev \$PUBLIC_IF root 2>/dev/null || true
" 2>&1

exit $RESULT
