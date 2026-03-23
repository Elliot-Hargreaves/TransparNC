# AGENTS.md

This document defines the core development rules and coding standards for the TransparNC project. All contributions and automated agents must adhere to these guidelines.

## 1. Documentation & Comments
- **Doc-Comments Mandatory:** Every public and private function, struct, enum, and trait must have a triple-slash (`///`) or double-slash with bang (`//!`) doc-comment explaining its purpose and any invariants.
- **Explain "Why", Not "What":** Comments should prioritize explaining the *reasoning* behind the code rather than describing what the code does. Code should be self-documenting through clear naming and structure.
- **Complexity Exception:** If a piece of code is inherently complex (e.g., low-level networking, custom encryption logic), comments explaining the "what" are permitted to aid understanding.

## 2. Rust Idioms & State Management
- **State as Enums:** Leverage Rust's `enum` type to represent mutually exclusive states. Prefer enums over multiple `Option<T>` fields to prevent invalid states (e.g., `State::Connecting`, `State::Connected(ConnectionInfo)`).
- **Traits for Interfaces:** Use traits to define clean interfaces between modules (e.g., networking, signaling). This enables easier mocking for unit testing and promotes modularity.
- **Avoid "Stray" Functions:** Most functions should be associated with a `struct` or `enum` via `impl` blocks to maintain logical grouping and organization.

## 3. Project Structure & Modularity
- **Modular Design:** Keep the codebase modular. Aim for a clear hierarchy (e.g., `core`, `net`, `gui`, `common`).
- **File Size Limit:** Keep source files below 800 lines. If a file exceeds this or grows too complex, split it into submodules.
- **Crate Boundaries:** Use `pub(crate)` for items that should be visible within the crate but not to external users.

## 4. Error Handling
- **Structured Errors:** Use the `thiserror` crate for defining custom error types in libraries and `anyhow` for application-level error handling.
- **Propagate Errors:** Prefer returning `Result<T, E>` over `panic!` or `unwrap()`. Handle errors as close to the source as possible or propagate them to a centralized handler.

## 5. Async & Concurrency
- **Tokio Runtime:** Since this is a networking-heavy project, use `tokio` for asynchronous operations.
- **Avoid Blocking Calls:** Ensure that long-running or blocking operations are moved to a separate thread pool or handled using `spawn_blocking` to avoid stalling the async executor.

## 6. Definition of Done (Quality Assurance)
A task is only considered "Completed" when:
- **Builds cleanly:** `cargo build` produces no errors or warnings.
- **Clippy Approved:** `cargo clippy` passes with no warnings (use `#[deny(warnings)]` where appropriate).
- **Tests Pass:** All tests under `cargo test` pass successfully.
- **Formatted:** Code is formatted according to `cargo fmt`.
- **Verified:** Documentation matches the implementation.

## 7. Dependency Management
- **Minimal Dependencies:** Only add dependencies that are strictly necessary.
- **Security First:** Prioritize well-maintained and audited crates, especially for networking and cryptography (e.g., `boringtun`).
