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
pub mod conversion;
mod kdd;
mod mem;
mod model;
mod syncer;
mod syncers;
pub mod updateprocessors;
mod watchersyncer;

pub use backend::{
    key_to_target, Backend, DsError, KVPairList, ListOptions, MemBackend, WatchEvent,
};
pub use cas::{CasError, CasStore, Revision, Versioned};
pub use conversion::{
    namespace_object_to_profile, namespace_to_profile, node_to_calico_node,
    pod_to_workload_endpoint, profile_name, service_account_profile_name,
    service_account_to_profile, veth_name_for_workload, workload_endpoint_name,
    WorkloadEndpointConversion,
};
pub use kdd::{
    hash_hostname_for_label, hostname_hash_label, KddBackend, KddValue, LABEL_HOSTNAME_HASH,
};
pub use mem::MemStore;
pub use model::{cidr_to_token, KVPair, Key, ResourceKind};
pub use syncer::{SyncStatus, SyncerEvent, UpdateType};
pub use syncers::{
    bgp_syncer_kinds, felix_syncer_kinds, node_status_syncer_kinds, run_syncer,
    tunnel_ip_syncer_kinds, SyncerV1Event,
};
pub use updateprocessors::{
    augment_policy_selector, process, process_felix_configuration, process_ip_pool,
    process_keys, process_network_policy, process_workload_endpoint, ConfigV1, EndpointPortV1,
    IpPoolV1, IpPoolV1Key, PolicyKind, PolicyV1, PolicyV1Key, ProcessError, RuleV1, V1KVPair,
    V1Key, V1Value, WorkloadEndpointV1, WorkloadEndpointV1Key, LABEL_NAMESPACE,
    LABEL_SERVICE_ACCOUNT,
};
pub use watchersyncer::watch_many;
