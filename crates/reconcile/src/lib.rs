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
//! This crate also hosts cross-cutting infra every binary needs:
//! - [`init_tracing`] — idempotent structured-logging init (`observability`).
//! - [`Metrics`], [`Readiness`], [`serve`] — a hand-rolled health/readiness +
//!   Prometheus metrics HTTP helper (`health`), with no HTTP framework
//!   dependency. Binaries wire these into their startup in a later task.
//!
//! See `specs/001-calico-rs-rust-rewrite/contracts/datastore-backend.md`.

mod caching_map;
mod delta_tracker;
mod health;
mod observability;
mod set_delta_tracker;

pub use caching_map::{CachingMap, DataplaneMap};
pub use delta_tracker::DeltaTracker;
pub use health::{handle_request, serve, HealthServer, HttpResponse, Metrics, Readiness};
pub use observability::{build_env_filter, init_tracing, init_tracing_with};
pub use set_delta_tracker::SetDeltaTracker;
