# Container-Based Testing Implementation Plan

This plan outlines the steps to implement automated end-to-end "ping tests" between two virtual nodes using Docker containers. This is the final part of Phase 1 of the main `IMPLEMENTATION_PLAN.md`.

## 1. CLI Enhancement (`src/main.rs`)
To allow nodes to be configured dynamically within containers, we need a CLI interface.

- [ ] Add `clap` or use simple `std::env::args()` to parse:
    - `--local-port`: The UDP port for physical communication.
    - `--tun-ip`: The virtual IP for the TUN interface.
    - `--peer-key`: The public key of the remote peer.
    - `--peer-endpoint`: The physical IP:Port of the remote peer.
- [ ] Implement a command to generate and print a public key for setup.

## 2. Docker Infrastructure
Docker containers will provide isolated network namespaces with the necessary privileges.

- [ ] **Dockerfile**: Base image (e.g., Ubuntu/Alpine) with:
    - `iproute2` and `iputils-ping` installed.
    - The compiled `transpar_nc` binary.
- [ ] **Docker Compose (`docker-compose.test.yml`)**:
    - Define `peer1` and `peer2`.
    - Grant `CAP_NET_ADMIN` and mount `/dev/net/tun`.
    - Set up a shared bridge network for the "physical" UDP traffic.

## 3. Test Orchestration (`tests/container/run_test.sh`)
A script to automate the entire test lifecycle.

- [ ] **Setup Phase**:
    - Build the `transpar_nc` binary for the Linux target.
    - Build the Docker image.
    - Start containers in the background.
- [ ] **Configuration Phase**:
    - Extract public keys from both peers.
    - Restart or signal peers with each other's configuration.
- [ ] **Verification Phase**:
    - Execute `ping -c 4 10.0.0.2` from `peer1` (targeting `peer2`'s virtual IP).
    - Parse output for success/failure.
- [ ] **Cleanup Phase**:
    - Stop and remove containers and networks.

## 4. CI/CD Integration
- [ ] Add a "Container Integration Test" job to `.github/workflows/build.yml`.
- [ ] Ensure the runner has Docker and necessary permissions (GitHub Actions default runners do).

## 5. Success Criteria
- [ ] `peer1` can successfully ping `peer2` over the WireGuard-secured TUN interface.
- [ ] The test runs entirely automated without manual intervention.
- [ ] Code meets all standards defined in `AGENTS.md`.
