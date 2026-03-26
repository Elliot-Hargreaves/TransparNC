# TransparNC Implementation Plan

This document outlines the roadmap and checklist for developing TransparNC, a cross-platform P2P VPN similar to Hamachi, built with Rust and Iced.

## Phase 1: Core Networking & Virtualized Testing
Focus on the low-level networking and establishing the automated testing infrastructure from the beginning.

- [x] **Project Initialization & Testing Infrastructure**
    - [x] Update `Cargo.toml` with necessary dependencies (`boringtun`, `tokio`, `tun`, `serde`, `thiserror`).
    - [x] Define the project module structure (e.g., `core`, `net`, `gui`, `common`).
    - [x] Set up a basic GitHub Actions workflow for cross-platform builds (`linux`, `windows`, `macos`).
- [x] **Virtual Interface (TUN) Management & Initial Tests**
    - [x] Implement cross-platform TUN interface creation using the `tun` or `tokio-tun` crate.
    - [x] Handle platform-specific configuration (IP assignment, MTU) for Linux, Windows, and macOS.
    - [x] **Test:** Create a script using Docker or Network Namespaces (Linux) to verify TUN creation and basic packet flow.
- [x] **WireGuard Integration & Connectivity Tests**
    - [x] Integrate `boringtun` for userspace WireGuard implementation.
    - [x] Implement packet processing loop (reading from TUN -> encrypting -> sending to UDP, and vice versa).
    - [x] Key generation and management (Public/Private keys).
    - [ ] **Test:** Automate "ping tests" between two virtual interfaces in a simulated network.

## Phase 2: NAT Traversal & Signaling
The "magic" that allows peers to connect behind firewalls.

- [x] **Signaling System**
    - [x] Implement a basic signaling server using `axum` and WebSockets.
    - [x] Define exchange protocol for peer metadata (public keys, endpoints) in `src/common/messages.rs`.
    - [x] Integrate Redis for session persistence and state sharing.
- [x] **NAT Discovery (STUN/TURN)**
    - [x] Integrate a STUN client to discover external IP/Port.
    - [x] Implement ICE-like candidate gathering and hole punching.
- [x] **Peer Management**
    - [x] Maintain a list of active peers and their connection status.
    - [x] Implement heartbeat/keep-alive mechanism to maintain NAT mappings.
- [x] **Integration Tests**
    - [x] Verify NAT traversal logic in specialized CI environments (if possible) or through manual multi-machine tests.

## Phase 3: GUI Development (Iced)
Creating the user-facing application using the Iced framework.

- [ ] **Basic UI Layout**
    - [x] Main window with network status (Online/Offline).
    - [x] Peer list displaying names, virtual IPs, and connectivity status.
    - [ ] "Join Network" and "Create Network" dialogs.
- [x] **Integration with Core (Tasks/Subscriptions)**
    - [x] Use Iced `Subscription` to listen for network events from the VPN core.
    - [x] Use Iced `Task` to trigger actions like "Connect" or "Disconnect" asynchronously.
- [x] **State Management**
    - [x] Implement the Elm architecture (`Message`, `State`, `Update`, `View`) to handle application flow.
- [ ] **Theming & UX**
    - [x] Apply a clean, modern aesthetic to the UI.
    - [ ] System tray integration (if supported/required).

## Phase 4: Relay Server (Optional, Self-Hosted)
An optional relay (TURN-like) server for peers that cannot establish direct connections (e.g., symmetric NAT ↔ symmetric NAT). This is a separate service from the signaling server to avoid turning the signaling host into an open proxy.

- [ ] **Relay Server Binary (`transparnc-relay`)**
    - [ ] Implement a standalone relay server binary that forwards encrypted UDP traffic between peers.
    - [ ] Authentication via relay tokens to prevent unauthorized use.
    - [ ] Rate limiting and connection caps to bound resource usage.
- [ ] **Relay Candidate Support in Client**
    - [ ] Add a `Relay` variant to the `Candidate` enum, gated behind configuration (no relay candidates produced if no relay server is configured).
    - [ ] Relay candidates should have the lowest priority in connectivity checks — used only as a last resort when hole punching fails.
    - [ ] Signaling server URL and relay server URL must be completely independent configuration fields.
- [ ] **Relay Integration Tests**
    - [ ] Container-based tests with a relay server verifying fallback connectivity when direct paths are blocked.
    - [ ] Verify that relay is never used when direct connectivity succeeds.

## Phase 5: Distribution & Packaging
Preparing the app for end-users.

- [ ] **Packaging**
    - [ ] Linux: `.deb`, `.rpm`, or AppImage.
    - [ ] Windows: `.msi` or `.exe` installer (handling driver installation for TUN if needed).
    - [ ] macOS: `.dmg` or `.app` bundle.
- [ ] **Documentation & Final Validation**
    - [ ] User guide and technical documentation.
    - [ ] Finalize `README.md`.
    - [ ] Perform a full end-to-end regression test across all target platforms.
