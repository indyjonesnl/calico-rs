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
}
