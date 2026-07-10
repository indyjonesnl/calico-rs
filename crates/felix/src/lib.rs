//! `felix` — the per-node dataplane agent of Calico-rs (library surface).
//!
//! Binaries (`felix`, self-tests) build on these modules:
//! - [`config`] — typed FelixConfiguration + restart/live classification
//! - [`nftables`] — backend-neutral rule/chain model + drift-hash
//! - [`nft`] — concrete nftables rendering + programming (`nft -f -`)

pub mod config;
pub mod dataplane;
pub mod endpoint_manager;
pub mod ipset_manager;
pub mod nat;
pub mod nft;
pub mod nftables;
pub mod policy_render;
pub mod reconcile;
pub mod route_manager;
pub mod vxlan;
pub mod vxlan_reconcile;
