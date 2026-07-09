//! `datastore` — the storage spine of Calico-rs.
//!
//! Every component reads and writes cluster state through this layer. The full
//! design (see `contracts/datastore-backend.md`) is a typed-key `Backend` over
//! `KVPair` with list/watch and a Kubernetes (KDD) implementation plus a
//! watcher-syncer. That is built incrementally.
//!
//! Implemented so far: the **compare-and-swap core** ([`CasStore`]) and an
//! in-memory backend ([`MemStore`]) used to build and test the CAS-dependent
//! logic (e.g. IPAM's two-phase affinity claim) without a live cluster. CAS on
//! a monotonic revision is the invariant the whole datastore is built around.

mod backend;
mod cas;
mod kdd;
mod mem;
mod model;
mod syncer;

pub use backend::{
    key_to_target, Backend, DsError, KVPairList, ListOptions, MemBackend, WatchEvent,
};
pub use cas::{CasError, CasStore, Revision, Versioned};
pub use kdd::{
    hash_hostname_for_label, hostname_hash_label, KddBackend, KddValue, LABEL_HOSTNAME_HASH,
};
pub use mem::MemStore;
pub use model::{cidr_to_token, KVPair, Key, ResourceKind};
pub use syncer::{SyncStatus, SyncerEvent, UpdateType};
