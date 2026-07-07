//! IPAM resource specs (the v3 storage forms): IPAMBlock, BlockAffinity,
//! IPAMHandle, IPAMConfiguration.
//!
//! These are the *serializable CRD* representations that the datastore persists.
//! The `ipam` crate holds the corresponding runtime types + allocation logic;
//! these specs are what a KDD-backed IPAM reads/writes. Field names match
//! upstream Calico's stored form.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Ownership metadata for one allocation within a block.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AllocationAttributeSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secondary: BTreeMap<String, String>,
}

/// Spec for the `IPAMBlock` resource — a contiguous pool slice (the CAS unit).
#[derive(CustomResource, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "IPAMBlock",
    plural = "ipamblocks",
    singular = "ipamblock"
)]
#[serde(rename_all = "camelCase")]
pub struct IpamBlockSpec {
    pub cidr: String,
    /// `"host:<name>"` / `"virtual:<name>"`; absent when unaffine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity: Option<String>,
    /// `allocations[ordinal]` = index into `attributes`, or null if free.
    pub allocations: Vec<Option<i64>>,
    /// FIFO free-list of ordinals.
    pub unallocated: Vec<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<AllocationAttributeSpec>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub sequence_number: u64,
    /// Per-ordinal (as string) block sequence number recorded at allocation
    /// time — the persisted half of the ABA release guard.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sequence_number_for_allocation: BTreeMap<String, u64>,
}

/// Spec for the `BlockAffinity` resource — a per-host claim on a block.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "BlockAffinity",
    plural = "blockaffinities",
    singular = "blockaffinity"
)]
#[serde(rename_all = "camelCase")]
pub struct BlockAffinitySpec {
    pub node: String,
    pub cidr: String,
    /// `pending` / `confirmed` / `pendingDeletion`.
    pub state: String,
    #[serde(default)]
    pub deleted: bool,
}

/// Spec for the `IPAMHandle` resource — the by-handle allocation index.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "IPAMHandle",
    plural = "ipamhandles",
    singular = "ipamhandle"
)]
#[serde(rename_all = "camelCase")]
pub struct IpamHandleSpec {
    pub handle_id: String,
    /// block CIDR -> count allocated under this handle.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub block: BTreeMap<String, i64>,
    #[serde(default)]
    pub deleted: bool,
}

/// Spec for the singleton `IPAMConfiguration` resource.
#[derive(CustomResource, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "IPAMConfiguration",
    plural = "ipamconfigurations",
    singular = "ipamconfiguration"
)]
#[serde(rename_all = "camelCase")]
pub struct IpamConfigurationSpec {
    pub strict_affinity: bool,
    pub auto_allocate_blocks: bool,
    #[serde(default)]
    pub max_blocks_per_host: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipamblock_spec_roundtrips() {
        let spec = IpamBlockSpec {
            cidr: "10.0.0.0/26".into(),
            affinity: Some("host:node-1".into()),
            allocations: vec![Some(0), None, None],
            unallocated: vec![1, 2],
            attributes: vec![AllocationAttributeSpec {
                handle_id: Some("net.pod-a".into()),
                ..Default::default()
            }],
            deleted: false,
            sequence_number: 3,
            sequence_number_for_allocation: BTreeMap::from([("0".to_string(), 3u64)]),
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"sequenceNumber\":3"));
        assert!(json.contains("\"sequenceNumberForAllocation\""));
        let round: IpamBlockSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(round, spec);
    }
}
