//! BGP resource specs: BGPConfiguration and BGPPeer (representative subsets).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Spec for the singleton `BGPConfiguration` resource.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "BGPConfiguration",
    plural = "bgpconfigurations",
    singular = "bgpconfiguration"
)]
#[serde(rename_all = "camelCase")]
pub struct BgpConfigurationSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_severity_screen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_to_node_mesh_enabled: Option<bool>,
    #[serde(rename = "asNumber", default, skip_serializing_if = "Option::is_none")]
    pub as_number: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
}

/// Spec for the cluster-scoped `BGPPeer` resource.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "BGPPeer",
    plural = "bgppeers",
    singular = "bgppeer"
)]
#[serde(rename_all = "camelCase")]
pub struct BgpPeerSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(rename = "peerIP", default, skip_serializing_if = "Option::is_none")]
    pub peer_ip: Option<String>,
    #[serde(rename = "asNumber", default, skip_serializing_if = "Option::is_none")]
    pub as_number: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_selector: Option<String>,
}

/// How a BGP filter rule's `cidr` match is applied. Wire values match
/// upstream: `Equal` / `NotEqual` / `In` / `NotIn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum BgpFilterMatchOperator {
    Equal,
    NotEqual,
    In,
    NotIn,
}

/// Terminal action for a BGP filter rule. Wire values match upstream:
/// `Accept` / `Reject`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum BgpFilterAction {
    Accept,
    Reject,
}

/// Restricts the range of prefix lengths a `cidr` match applies to. Shared
/// shape between the V4 and V6 rule variants (upstream models these as two
/// distinct but structurally identical types).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BgpFilterPrefixLength {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i32>,
}

/// A single IPv4 BGP filter rule (representative subset of upstream's
/// `BGPFilterRuleV4`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BgpFilterRuleV4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_operator: Option<BgpFilterMatchOperator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_length: Option<BgpFilterPrefixLength>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    pub action: BgpFilterAction,
}

/// A single IPv6 BGP filter rule (representative subset of upstream's
/// `BGPFilterRuleV6`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BgpFilterRuleV6 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_operator: Option<BgpFilterMatchOperator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_length: Option<BgpFilterPrefixLength>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    pub action: BgpFilterAction,
}

/// Spec for the cluster-scoped `BGPFilter` resource — ordered import/export
/// route filter rules applied to BGP peerings.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "BGPFilter",
    plural = "bgpfilters",
    singular = "bgpfilter"
)]
#[serde(rename_all = "camelCase")]
pub struct BgpFilterSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub export_v4: Vec<BgpFilterRuleV4>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub import_v4: Vec<BgpFilterRuleV4>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub export_v6: Vec<BgpFilterRuleV6>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub import_v6: Vec<BgpFilterRuleV6>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bgppeer_wire_names() {
        let p = BgpPeerSpec {
            peer_ip: Some("10.0.0.1".into()),
            as_number: Some(64512),
            ..Default::default()
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"peerIP\":\"10.0.0.1\""));
        assert!(json.contains("\"asNumber\":64512"));
        assert_eq!(serde_json::from_str::<BgpPeerSpec>(&json).unwrap(), p);
    }

    #[test]
    fn bgpfilter_rule_wire_names_and_enum_values() {
        let spec = BgpFilterSpec {
            import_v4: vec![BgpFilterRuleV4 {
                cidr: Some("10.0.0.0/8".into()),
                match_operator: Some(BgpFilterMatchOperator::In),
                action: BgpFilterAction::Accept,
                interface: Some("eth0".into()),
                source: Some("RemotePeers".into()),
                prefix_length: Some(BgpFilterPrefixLength {
                    min: Some(16),
                    max: Some(24),
                }),
            }],
            export_v6: vec![BgpFilterRuleV6 {
                cidr: Some("fd00::/8".into()),
                match_operator: Some(BgpFilterMatchOperator::NotIn),
                prefix_length: None,
                source: None,
                interface: None,
                action: BgpFilterAction::Reject,
            }],
            ..Default::default()
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"importV4\""));
        assert!(json.contains("\"exportV6\""));
        assert!(json.contains("\"matchOperator\":\"In\""));
        assert!(json.contains("\"action\":\"Accept\""));
        assert!(json.contains("\"prefixLength\":{\"min\":16,\"max\":24}"));
        let round: BgpFilterSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(round, spec);
    }

    #[test]
    fn bgpfilter_rule_minimal_omits_optionals() {
        let rule = BgpFilterRuleV4 {
            cidr: None,
            match_operator: None,
            prefix_length: None,
            source: None,
            interface: None,
            action: BgpFilterAction::Reject,
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert_eq!(json, r#"{"action":"Reject"}"#);
    }
}
