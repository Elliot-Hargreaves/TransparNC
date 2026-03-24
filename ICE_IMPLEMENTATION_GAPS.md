# ICE Implementation Gaps

This document summarises the six known gaps in the current ICE implementation that
cause the container-based ICE integration tests to fail with
`"All connectivity checks failed — no working candidate pair"`.

Gaps 1–3 are the root causes of the connectivity failure. Gaps 4–6 are secondary
correctness and design issues that will cause failures in the signaling and more
complex tests even after gaps 1–3 are fixed.

---

## Gap 1 — NAT Routers Have No Inbound Forwarding (Most Critical)

**Location:** `docker-compose.ice-test.yml`

The NAT routers are configured with only an outbound masquerade rule:

```sh
iptables -t nat -A POSTROUTING -o $PUBLIC_IF -j MASQUERADE
```

This handles outbound traffic (peer → public network) but **not inbound
hole-punch packets**. For hole-punching to work, when peer-1 sends a UDP packet
to peer-2's server-reflexive address (`172.50.0.20:51821`), nat-router-2 must
forward that packet to peer-2 (`172.70.0.10:51821`).

Linux conntrack *does* create a reverse mapping automatically — but only if
peer-2 has already sent an outbound packet to peer-1's server-reflexive address
first, creating the conntrack entry. This requires **truly simultaneous** sends
from both sides. The current test runs the gather phase sequentially (peer-1
first, then peer-2 in a separate `docker exec`), so no conntrack state exists
when the hole-punch phase begins.

---

## Gap 2 — Gather Phase and Hole-Punch Phase Use Separate Processes

**Location:** `tests/container/ice/test_ice_hole_punch_nat.sh`

The test runs two separate `docker exec ice_test_peer` invocations per peer:
one to gather candidates, one to hole-punch. Each invocation creates a **new
UDP socket**. Even though `--local-port 51820` is reused, the NAT conntrack
mapping from the gather phase is gone by the time the hole-punch phase starts
(the socket was closed when the first process exited).

The fix is to gather candidates and perform connectivity checks in a **single
process invocation** — which is what the `--use-orchestrator` flag is designed
for, but the hole-punch test does not use it.

---

## Gap 3 — `check_connectivity` Sends Then Listens, Not Concurrently

**Location:** `src/net/ice.rs`, `check_connectivity()`

```rust
// Send probes to all pairs...
for pair in pairs {
    socket.send_to(&probe_pkt, pair.remote.addr).await;
}
// Then listen for acks...
loop {
    match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await { ... }
}
```

The function sends all probes first, then enters a receive loop. If the remote
peer's probe arrives *before* the local peer has sent its own probe (which
creates the NAT mapping), the inbound packet is silently dropped by the NAT
router. The receive loop needs to run **concurrently** with sending — using
`tokio::select!` or a spawned task — so that incoming probes are handled even
during the send phase.

---

## Gap 4 — Missing `PeerJoined` Variant in the Signaling Protocol

**Location:** `src/common/messages.rs`

The `SignalingMessage` enum only has:

```rust
pub enum SignalingMessage {
    Join { ... },
    Joined { peers: Vec<PeerInfo> },  // only existing peers at join time
    Signal { to, from, data },
    Heartbeat { peer_id },
}
```

There is **no `PeerJoined` notification**. When peer-1 joins first, it receives
`Joined { peers: [] }` — nobody to send candidates to. When peer-2 joins later,
the server has no way to notify peer-1. The signaling exchange in
`ice_test_peer.rs` only works because peer-2 sends candidates to peer-1
(peer-1 was in peer-2's `Joined` list), and peer-1 responds reactively. This
is fragile: peer-1 never proactively initiates, and if peer-2 times out before
peer-1 responds, the exchange fails.

The fix requires adding a `PeerJoined { peer: PeerInfo }` variant so the server
can push new-peer notifications to existing members.

---

## Gap 5 — Remote Candidates Always Typed as `Host` in the Binary

**Location:** `src/bin/ice_test_peer.rs`, line 94

```rust
cli.remote_candidates
    .iter()
    .map(|addr| Candidate::new(*addr, CandidateType::Host))  // always Host
    .collect::<Vec<_>>()
```

When the hole-punch test passes server-reflexive addresses (e.g.,
`172.50.0.10:51820`) via `--remote-candidates`, they are typed as `Host`
candidates. This gives them priority 200 instead of 100, so they are tried
before any actual host candidates — but more importantly it means
`form_candidate_pairs` may pair them incorrectly. This is a semantic bug that
also makes debugging harder (logs show `Host` for what is actually a
server-reflexive address).

---

## Gap 6 — No `--gather-only` Mode

**Location:** `src/bin/ice_test_peer.rs` and
`tests/container/ice/test_ice_stun_behind_nat.sh`

`test_ice_stun_behind_nat.sh` passes `--remote-candidates 127.0.0.1:1` as a
dummy address just to satisfy the CLI requirement, then uses `|| true` to
swallow the inevitable connectivity failure:

```sh
PEER1_OUTPUT=$(docker exec ice-peer-1 timeout 20 \
    ice_test_peer --local-port 51820 \
    --stun-server 172.50.0.100:3478 \
    --remote-candidates 127.0.0.1:1 2>&1) || true
```

The binary wastes 5 × 500 ms = 2.5 seconds probing an unreachable address. A
`--gather-only` flag would skip the connectivity check phase entirely, making
the STUN test cleaner and faster.

---

## Summary

| # | Gap | Location | Impact |
|---|-----|----------|--------|
| 1 | NAT routers have no inbound forwarding / conntrack state | `docker-compose.ice-test.yml` | All hole-punch tests fail |
| 2 | Gather and hole-punch run in separate processes (NAT state lost) | `test_ice_hole_punch_nat.sh` | Hole-punch test fails |
| 3 | `check_connectivity` sends then listens, not concurrently | `src/net/ice.rs` | Probes dropped before NAT mapping exists |
| 4 | No `PeerJoined` signaling message | `src/common/messages.rs` | Signaling exchange test fails |
| 5 | Remote candidates always typed as `Host` | `src/bin/ice_test_peer.rs` | Wrong priority ordering, misleading logs |
| 6 | No `--gather-only` mode | `src/bin/ice_test_peer.rs` | STUN test uses `\|\| true` hack, wastes 2.5 s |
