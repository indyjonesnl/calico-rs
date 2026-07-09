//! The Calico `Node` resource — a minimal projection of an orchestrator node's
//! Calico-relevant networking state (BGP addresses, tunnel addresses, orch refs).
//!
//! Wire field names match upstream Calico `NodeSpec`
//! (`libcalico-go/lib/apis/.../node.go`): `bgp`, `ipv4VXLANTunnelAddr`,
//! `ipv6VXLANTunnelAddr`, `orchRefs`, and within BGP `ipv4Address`,
//! `ipv6Address`, `asNumber`, `ipv4IPIPTunnelAddr`. Only a representative subset
//! of upstream's fields is modelled (T018).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// BGP configuration for a node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeBgpSpec {
    /// IPv4 address (and optional network) of this node. `ipv4Address`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_address: Option<String>,
    /// IPv6 address (and optional network) of this node. `ipv6Address`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_address: Option<String>,
    /// AS number of this node; falls back to the global default when unset.
    #[serde(rename = "asNumber", default, skip_serializing_if = "Option::is_none")]
    pub as_number: Option<u32>,
    /// IPv4 address of the IP-in-IP tunnel. `ipv4IPIPTunnelAddr`.
    #[serde(
        rename = "ipv4IPIPTunnelAddr",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ipv4_ipip_tunnel_addr: Option<String>,
}

/// A reference back to the orchestrator's node identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrchRef {
    /// Name of this node according to the orchestrator. `nodeName`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// The orchestrator using this node (e.g. `k8s`).
    pub orchestrator: String,
}

/// Spec for the cluster-scoped Calico `Node` resource. Deriving
/// [`CustomResource`] generates the `nodes.crd.projectcalico.org` root type.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "Node",
    plural = "nodes",
    singular = "node"
)]
#[serde(rename_all = "camelCase")]
pub struct NodeSpec {
    /// BGP configuration for this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bgp: Option<NodeBgpSpec>,
    /// IPv4 address of the VXLAN tunnel. `ipv4VXLANTunnelAddr`.
    #[serde(
        rename = "ipv4VXLANTunnelAddr",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ipv4_vxlan_tunnel_addr: Option<String>,
    /// IPv6 address of the VXLAN tunnel. `ipv6VXLANTunnelAddr`.
    #[serde(
        rename = "ipv6VXLANTunnelAddr",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ipv6_vxlan_tunnel_addr: Option<String>,
    /// Orchestrator references for this node. `orchRefs`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orch_refs: Vec<OrchRef>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_spec_wire_field_names_round_trip() {
        let spec = NodeSpec {
            bgp: Some(NodeBgpSpec {
                ipv4_address: Some("10.0.0.1/24".into()),
                ipv6_address: Some("fd00::1/64".into()),
                as_number: Some(64512),
                ipv4_ipip_tunnel_addr: Some("10.244.0.1".into()),
            }),
            ipv4_vxlan_tunnel_addr: Some("10.244.0.2".into()),
            ipv6_vxlan_tunnel_addr: Some("fd00::2".into()),
            orch_refs: vec![OrchRef {
                node_name: Some("nodeA".into()),
                orchestrator: "k8s".into(),
            }],
        };
        let json = serde_json::to_string(&spec).unwrap();
        // Exact upstream casing must be preserved.
        assert!(json.contains("\"ipv4Address\":\"10.0.0.1/24\""), "{json}");
        assert!(json.contains("\"ipv6Address\":\"fd00::1/64\""), "{json}");
        assert!(json.contains("\"asNumber\":64512"), "{json}");
        assert!(
            json.contains("\"ipv4IPIPTunnelAddr\":\"10.244.0.1\""),
            "{json}"
        );
        assert!(
            json.contains("\"ipv4VXLANTunnelAddr\":\"10.244.0.2\""),
            "{json}"
        );
        assert!(
            json.contains("\"ipv6VXLANTunnelAddr\":\"fd00::2\""),
            "{json}"
        );
        assert!(json.contains("\"orchRefs\":[{"), "{json}");
        assert!(json.contains("\"nodeName\":\"nodeA\""), "{json}");
        assert!(json.contains("\"orchestrator\":\"k8s\""), "{json}");

        let round: NodeSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(round, spec);
    }

    #[test]
    fn node_spec_minimal_omits_empty() {
        let spec = NodeSpec::default();
        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(json, "{}");
    }
}
