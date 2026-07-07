//! `apis` — Calico-rs resource model (`projectcalico.org/v3`).
//!
//! These are the user-facing, serializable resource types. Field names and enum
//! values match upstream Calico's JSON/YAML wire form (constitution Principle I:
//! the resource model is a compatibility surface — existing manifests must apply
//! unchanged). Kubernetes CRD derivation (`kube::CustomResource`) and the v3↔v1
//! backend-model conversion layer are added on top (tasks T013, T020).
//!
//! Implemented kinds (P1/P2-central subset): IPPool, WorkloadEndpoint,
//! NetworkPolicy, GlobalNetworkPolicy, Tier, Profile, ClusterInformation. The
//! remaining kinds (HostEndpoint, NetworkSet, BGP*, FelixConfiguration, …) follow
//! the same pattern.

mod bgp;
mod common;
mod config;
pub mod crd;
mod ipam;
mod networking;
mod policy;

pub use bgp::{BGPConfiguration, BGPPeer, BgpConfigurationSpec, BgpPeerSpec};
pub use common::Metadata;
pub use config::{
    ClusterInformation, ClusterInformationSpec, FelixConfiguration, FelixConfigurationSpec,
};
pub use ipam::{
    AllocationAttributeSpec, BlockAffinity, BlockAffinitySpec, IPAMBlock, IPAMConfiguration,
    IPAMHandle, IpamBlockSpec, IpamConfigurationSpec, IpamHandleSpec,
};
pub use networking::{
    AllowedUse, AssignmentMode, EncapMode, GlobalNetworkSet, GlobalNetworkSetSpec, HostEndpoint,
    HostEndpointSpec, IPPool, IpPoolSpec, NetworkSet, NetworkSetSpec, WorkloadEndpointSpec,
    WorkloadPort,
};
pub use policy::{
    Action, EntityRule, GlobalNetworkPolicy, GlobalNetworkPolicySpec, NetworkPolicy,
    NetworkPolicySpec, PolicyType, Profile, ProfileSpec, Protocol, Rule, Tier, TierSpec,
};
