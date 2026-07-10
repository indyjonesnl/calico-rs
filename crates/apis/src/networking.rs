//! Networking resource specs: IPPool and WorkloadEndpoint.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Encapsulation mode shared by `ipipMode` and `vxlanMode`. Wire values match
/// upstream: `Never` / `Always` / `CrossSubnet`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EncapMode {
    #[default]
    Never,
    Always,
    CrossSubnet,
}

/// What an IP pool may be used for. Wire values: `Workload` / `Tunnel` / `LoadBalancer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum AllowedUse {
    Workload,
    Tunnel,
    LoadBalancer,
}

/// Whether addresses are auto-assigned or only assigned manually.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum AssignmentMode {
    #[default]
    Automatic,
    Manual,
}

/// Spec for the `IPPool` resource — an allocatable address range. Deriving
/// [`CustomResource`] generates the cluster-scoped `IPPool` root type (with
/// metadata/status) and `IPPool::crd()` for CRD manifest generation.
#[derive(CustomResource, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "IPPool",
    plural = "ippools",
    singular = "ippool"
)]
#[serde(rename_all = "camelCase")]
pub struct IpPoolSpec {
    pub cidr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_size: Option<u8>,
    #[serde(default)]
    pub ipip_mode: EncapMode,
    #[serde(rename = "vxlanMode", default)]
    pub vxlan_mode: EncapMode,
    #[serde(default)]
    pub nat_outgoing: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(rename = "disableBGPExport", default)]
    pub disable_bgp_export: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_uses: Vec<AllowedUse>,
    #[serde(default)]
    pub assignment_mode: AssignmentMode,
}

impl Default for IpPoolSpec {
    fn default() -> Self {
        Self {
            cidr: String::new(),
            block_size: None,
            ipip_mode: EncapMode::Never,
            vxlan_mode: EncapMode::Never,
            nat_outgoing: false,
            disabled: false,
            disable_bgp_export: false,
            node_selector: None,
            namespace_selector: None,
            allowed_uses: Vec::new(),
            assignment_mode: AssignmentMode::Automatic,
        }
    }
}

/// A named port exposed by a workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WorkloadPort {
    pub name: String,
    pub port: u16,
    pub protocol: String,
}

/// Spec for the namespaced `WorkloadEndpoint` resource — a pod's network presence.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "WorkloadEndpoint",
    plural = "workloadendpoints",
    singular = "workloadendpoint",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadEndpointSpec {
    pub node: String,
    pub orchestrator: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub workload: String,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pod: String,
    #[serde(
        rename = "containerID",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub container_id: String,
    pub interface_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipnetworks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<WorkloadPort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_spoofed_source_prefixes: Vec<String>,
}

/// Spec for the cluster-scoped `HostEndpoint` resource — a host interface that
/// can itself be subject to policy.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "HostEndpoint",
    plural = "hostendpoints",
    singular = "hostendpoint"
)]
#[serde(rename_all = "camelCase")]
pub struct HostEndpointSpec {
    pub node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
}

/// Spec for the namespaced `NetworkSet` resource — a labeled set of CIDRs
/// referenced by policy selectors.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "NetworkSet",
    plural = "networksets",
    singular = "networkset",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSetSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nets: Vec<String>,
}

/// Spec for the cluster-scoped `GlobalNetworkSet` resource.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "GlobalNetworkSet",
    plural = "globalnetworksets",
    singular = "globalnetworkset"
)]
#[serde(rename_all = "camelCase")]
pub struct GlobalNetworkSetSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nets: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ippool_wire_names_and_enum_values() {
        let spec = IpPoolSpec {
            cidr: "192.168.0.0/16".into(),
            block_size: Some(26),
            vxlan_mode: EncapMode::CrossSubnet,
            nat_outgoing: true,
            disable_bgp_export: true,
            allowed_uses: vec![AllowedUse::Workload, AllowedUse::Tunnel],
            ..Default::default()
        };
        let json = serde_json::to_string(&spec).unwrap();
        // Field name casing + enum spellings must match upstream Calico.
        assert!(json.contains("\"blockSize\":26"));
        assert!(json.contains("\"vxlanMode\":\"CrossSubnet\""));
        assert!(json.contains("\"natOutgoing\":true"));
        assert!(json.contains("\"disableBGPExport\":true"));
        assert!(json.contains("\"allowedUses\":[\"Workload\",\"Tunnel\"]"));
        // ipipMode defaults to Never and is always emitted.
        assert!(json.contains("\"ipipMode\":\"Never\""));

        let round: IpPoolSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(round, spec);
    }

    #[test]
    fn ippool_deserializes_minimal_manifest() {
        // A minimal upstream-style pool spec.
        let doc = r#"{"cidr":"10.0.0.0/16","natOutgoing":true}"#;
        let spec: IpPoolSpec = serde_json::from_str(doc).unwrap();
        assert_eq!(spec.cidr, "10.0.0.0/16");
        assert!(spec.nat_outgoing);
        assert_eq!(spec.vxlan_mode, EncapMode::Never);
        assert_eq!(spec.assignment_mode, AssignmentMode::Automatic);
    }

    #[test]
    fn workload_endpoint_container_id_casing() {
        let wep = WorkloadEndpointSpec {
            node: "node-1".into(),
            orchestrator: "k8s".into(),
            endpoint: "eth0".into(),
            container_id: "abc123".into(),
            interface_name: "cali123".into(),
            ipnetworks: vec!["10.0.0.5/32".into()],
            ..Default::default()
        };
        let json = serde_json::to_string(&wep).unwrap();
        assert!(json.contains("\"containerID\":\"abc123\""));
        assert!(json.contains("\"interfaceName\":\"cali123\""));
        let round: WorkloadEndpointSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(round, wep);
    }
}
