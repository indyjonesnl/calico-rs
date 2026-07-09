//! `apis` — Calico-rs resource model (`projectcalico.org/v3`).
//!
//! These are the user-facing, serializable resource types. Field names and enum
//! values match upstream Calico's JSON/YAML wire form (constitution Principle I:
//! the resource model is a compatibility surface — existing manifests must apply
//! unchanged). Kubernetes CRD derivation (`kube::CustomResource`) and the v3↔v1
//! backend-model conversion layer are added on top (tasks T013, T020).
//!
//! Implemented kinds: IPPool, WorkloadEndpoint, HostEndpoint, NetworkPolicy,
//! GlobalNetworkPolicy, StagedNetworkPolicy, StagedGlobalNetworkPolicy,
//! StagedKubernetesNetworkPolicy, Tier, Profile, NetworkSet, GlobalNetworkSet,
//! ClusterInformation, FelixConfiguration, BGPConfiguration, BGPPeer,
//! BGPFilter, KubeControllersConfiguration, CalicoNodeStatus, and the IPAM
//! kinds — this is the full P1/P2 resource model (T010, T013).

mod bgp;
mod common;
mod config;
pub mod crd;
mod ipam;
mod networking;
mod node;
mod policy;

pub use bgp::{
    BGPConfiguration, BGPFilter, BGPPeer, BgpConfigurationSpec, BgpFilterAction,
    BgpFilterMatchOperator, BgpFilterPrefixLength, BgpFilterRuleV4, BgpFilterRuleV6, BgpFilterSpec,
    BgpPeerSpec,
};
pub use common::Metadata;
pub use config::{
    CalicoNodeStatus, CalicoNodeStatusSpec, ClusterInformation, ClusterInformationSpec,
    ControllersConfig, FelixConfiguration, FelixConfigurationSpec, KubeControllersConfiguration,
    KubeControllersConfigurationSpec, NodeControllerConfig, NodeStatusClassType,
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
pub use node::{Node, NodeBgpSpec, NodeSpec, OrchRef};
pub use policy::{
    Action, EntityRule, GlobalNetworkPolicy, GlobalNetworkPolicySpec, NetworkPolicy,
    NetworkPolicySpec, PolicyType, Profile, ProfileSpec, Protocol, Rule, StagedAction,
    StagedGlobalNetworkPolicy, StagedGlobalNetworkPolicySpec, StagedKubernetesNetworkPolicy,
    StagedKubernetesNetworkPolicySpec, StagedNetworkPolicy, StagedNetworkPolicySpec, Tier,
    TierSpec,
};
