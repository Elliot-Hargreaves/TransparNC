#!/bin/bash
# Test: Candidate exchange via signaling server
#
# Two peers behind separate NATs connect to the signaling server,
# exchange ICE candidates via Signal messages, and then perform
# hole-punch connectivity checks. This tests the full signaling-based
# candidate exchange flow end-to-end.

COMPOSE_FILE="${1:?Usage: $0 <compose-file>}"

NETWORK_ID="00000000-0000-0000-0000-000000000001"
SIGNALING_URL="ws://172.50.0.101:8080/ws"

echo "--- Candidate Exchange: Running both peers with signaling ---"

# Both peers use the signaling server to exchange candidates automatically.
# They run concurrently — one joins first, the other joins and triggers
# the candidate exchange.
docker exec ice-peer-1 timeout 45 \
    ice_test_peer --local-port 51820 \
    --stun-server 172.50.0.100:3478 \
    --signaling-url "$SIGNALING_URL" \
    --network-id "$NETWORK_ID" 2>&1 &
PID1=$!

# Small delay so peer-1 joins first and is listed when peer-2 joins.
sleep 2

docker exec ice-peer-2 timeout 45 \
    ice_test_peer --local-port 51821 \
    --stun-server 172.50.0.100:3478 \
    --signaling-url "$SIGNALING_URL" \
    --network-id "$NETWORK_ID" 2>&1 &
PID2=$!

# Capture outputs.
wait $PID1
EXIT1=$?
wait $PID2
EXIT2=$?

echo "Peer-1 exit: $EXIT1, Peer-2 exit: $EXIT2"

if [ $EXIT1 -eq 0 ] || [ $EXIT2 -eq 0 ]; then
    echo "SUCCESS: Candidate exchange via signaling + hole-punch succeeded"
    exit 0
else
    echo "FAILURE: Neither peer succeeded after signaling-based candidate exchange"
    exit 1
fi
