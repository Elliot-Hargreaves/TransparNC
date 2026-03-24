#!/bin/bash
set -e

# ICE Integration Test Suite
# Runs all ICE container-based tests against the dual-NAT topology.
#
# Prerequisites:
#   - Docker and docker compose installed
#   - cargo build --release completed (builds transpar_nc + ice_test_peer)
#
# Usage: ./tests/container/run_ice_tests.sh [test_name]
#   If test_name is provided, only that test is run.
#   Otherwise all tests are run sequentially.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.ice-test.yml"
RESULT=0

# List of all ICE test scripts (order matters — simpler tests first).
ALL_TESTS=(
    "test_ice_stun_behind_nat"
    "test_ice_hole_punch_nat"
    "test_ice_candidate_exchange_signaling"
    "test_ice_cross_subnet_fallback"
    "test_ice_packet_loss_retry"
    "test_ice_full_wireguard_pipeline"
)

# --- Helper functions ---

log() {
    echo ""
    echo "============================================================"
    echo "  $1"
    echo "============================================================"
}

## Bring up the shared infrastructure (NAT routers, STUN, signaling).
infra_up() {
    log "Building binaries"
    cd "$PROJECT_DIR"
    cargo build --release

    log "Building Docker images"
    docker compose -f "$COMPOSE_FILE" build

    log "Starting infrastructure"
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" up -d

    echo "Waiting for NAT routers and services to initialize (15s)..."
    sleep 15
}

## Tear down all containers.
infra_down() {
    log "Cleaning up"
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
}

## Run a single test by name.
run_test() {
    local test_name="$1"
    local test_script="$SCRIPT_DIR/ice/${test_name}.sh"

    if [ ! -f "$test_script" ]; then
        echo "ERROR: Test script not found: $test_script"
        return 1
    fi

    log "Running: $test_name"
    if bash "$test_script" "$COMPOSE_FILE"; then
        echo "PASS: $test_name"
        return 0
    else
        echo "FAIL: $test_name"
        return 1
    fi
}

# --- Main ---

trap infra_down EXIT

infra_up

if [ -n "$1" ]; then
    # Run a single named test.
    run_test "$1" || RESULT=1
else
    # Run all tests.
    for test in "${ALL_TESTS[@]}"; do
        if ! run_test "$test"; then
            RESULT=1
            # Continue running remaining tests to get full results.
        fi
    done
fi

echo ""
if [ $RESULT -eq 0 ]; then
    log "ALL ICE TESTS PASSED"
else
    log "SOME ICE TESTS FAILED"
fi

exit $RESULT
