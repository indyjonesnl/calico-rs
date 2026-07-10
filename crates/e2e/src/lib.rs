//! `e2e` is a dev-only, test-only crate: it exists to host the US1 end-to-end
//! conformance tests under `tests/` (T032/T033/T034), which need a real,
//! multi-node cluster with calico-rs deployed as the CNI. The workspace root
//! is virtual (no root package), so those tests live here rather than in a
//! top-level `tests/`.
//!
//! The lib target is intentionally empty: all real dependencies (`kube`,
//! `k8s-openapi`, `datastore`, `apis`, `ipam`) are declared as `[dev-dependencies]`
//! so `cargo build --workspace` never needs to compile them — only
//! `cargo test -p e2e` does. Shared test support lives in
//! `tests/common/mod.rs` and is pulled in per test file via `mod common;`
//! (the standard Rust integration-test pattern for shared helpers).
//!
//! See `tests/common/mod.rs` for how to bring up the environment these tests
//! exercise, and the gating rules that make them self-skip otherwise.
