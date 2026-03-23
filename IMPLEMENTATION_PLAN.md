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
- [ ] **WireGuard Integration & Connectivity Tests**
    - [ ] Integrate `boringtun` for userspace WireGuard implementation.
    - [ ] Implement packet processing loop (reading from TUN -> encrypting -> sending to UDP, and vice versa).
    - [ ] Key generation and management (Public/Private keys).
    - [ ] **Test:** Automate "ping tests" between two virtual interfaces in a simulated network.

## Phase 2: NAT Traversal & Signaling
The "magic" that allows peers to connect behind firewalls.

- [ ] **Signaling System**
    - [ ] Implement a basic signaling server or use an existing DHT/WebRTC signaling approach.
    - [ ] Define exchange protocol for peer metadata (public keys, endpoints).
- [ ] **NAT Discovery (STUN/TURN)**
    - [ ] Integrate a STUN client to discover external IP/Port.
    - [ ] Implement ICE-like candidate gathering and hole punching.
- [ ] **Peer Management**
    - [ ] Maintain a list of active peers and their connection status.
    - [ ] Implement heartbeat/keep-alive mechanism to maintain NAT mappings.
- [ ] **Integration Tests**
    - [ ] Verify NAT traversal logic in specialized CI environments (if possible) or through manual multi-machine tests.

## Phase 3: GUI Development (Iced)
Creating the user-facing application using the Iced framework.

- [ ] **Basic UI Layout**
    - [ ] Main window with network status (Online/Offline).
    - [ ] Peer list displaying names, virtual IPs, and connectivity status.
    - [ ] "Join Network" and "Create Network" dialogs.
- [ ] **Integration with Core (Tasks/Subscriptions)**
    - [ ] Use Iced `Subscription` to listen for network events from the VPN core.
    - [ ] Use Iced `Task` to trigger actions like "Connect" or "Disconnect" asynchronously.
- [ ] **State Management**
    - [ ] Implement the Elm architecture (`Message`, `State`, `Update`, `View`) to handle application flow.
- [ ] **Theming & UX**
    - [ ] Apply a clean, modern aesthetic to the UI.
    - [ ] System tray integration (if supported/required).

## Phase 4: Distribution & Packaging
Preparing the app for end-users.

- [ ] **Packaging**
    - [ ] Linux: `.deb`, `.rpm`, or AppImage.
    - [ ] Windows: `.msi` or `.exe` installer (handling driver installation for TUN if needed).
    - [ ] macOS: `.dmg` or `.app` bundle.
- [ ] **Documentation & Final Validation**
    - [ ] User guide and technical documentation.
    - [ ] Finalize `README.md`.
    - [ ] Perform a full end-to-end regression test across all target platforms.
