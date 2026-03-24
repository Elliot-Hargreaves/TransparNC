#!/bin/bash
set -e

# NAT Discovery Verification Script
# Verifies that peers can discover their external addresses via STUN
# in a simulated NAT environment using Docker containers.

RESULT=0

echo "--- 1. Building the transpar_nc binary for Linux ---"
cargo build --release

echo "--- 2. Building Docker images ---"
docker compose -f docker-compose.nat-test.yml build

echo "--- 3. Starting the NAT environment ---"
docker compose -f docker-compose.nat-test.yml down || true
docker compose -f docker-compose.nat-test.yml up -d

# peer-behind-nat has a 10s startup delay for NAT gateway readiness,
# plus up to 9s for STUN retries. 30s is sufficient.
echo "Waiting for services to initialize and STUN discovery to complete..."
sleep 30

echo "--- 4. Diagnostics ---"
echo "Network state for peer-behind-nat:"
docker exec peer-behind-nat ip addr
docker exec peer-behind-nat ip route

echo "Network state for nat-gateway:"
docker exec nat-gateway ip addr
docker exec nat-gateway iptables -t nat -L -v

echo "--- 5. Verification: Checking NAT discovery ---"
LOGS_BEHIND=$(docker compose -f docker-compose.nat-test.yml logs peer-behind-nat)
echo "$LOGS_BEHIND"

if echo "$LOGS_BEHIND" | grep -q "Discovered external address: 172.30.0.2:"; then
    echo "SUCCESS: Peer behind NAT discovered its gateway address!"
else
    echo "FAILURE: Peer behind NAT failed to discover its gateway address."
    RESULT=1
fi

LOGS_PUBLIC=$(docker compose -f docker-compose.nat-test.yml logs peer-public)
echo "$LOGS_PUBLIC"

if echo "$LOGS_PUBLIC" | grep -q "Discovered external address: 172.30.0.3:"; then
    echo "SUCCESS: Public peer discovered its own address!"
else
    echo "FAILURE: Public peer failed to discover its own address."
    RESULT=1
fi

echo "--- 6. Cleanup ---"
docker compose -f docker-compose.nat-test.yml down

exit $RESULT
