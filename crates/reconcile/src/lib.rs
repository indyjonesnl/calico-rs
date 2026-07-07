//! `reconcile` — the desired-vs-dataplane reconciliation primitives at the core
//! of Calico-rs.
//!
//! Every dataplane subsystem (nftables sets, routes, eBPF maps) programs the
//! kernel by expressing a *desired* state and diffing it against the last
//! *programmed* (dataplane) state, then applying only the delta. This crate
//! ports the upstream `deltatracker` + `cachingmap` pattern
//! (`felix/deltatracker`, `felix/cachingmap`) idiomatically to Rust.
//!
//! - [`DeltaTracker`] — keyed desired/dataplane views → pending updates/deletions.
//! - [`SetDeltaTracker`] — the set (membership-only) specialization.
//! - [`CachingMap`] — a [`DeltaTracker`] wired to a [`DataplaneMap`] backend so
//!   reconciliation is diff-based rather than a full rewrite.
//!
//! See `specs/001-calico-rs-rust-rewrite/contracts/datastore-backend.md`.

mod caching_map;
mod delta_tracker;
mod set_delta_tracker;

pub use caching_map::{CachingMap, DataplaneMap};
pub use delta_tracker::DeltaTracker;
pub use set_delta_tracker::SetDeltaTracker;
