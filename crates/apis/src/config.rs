//! Cluster configuration resource specs (subset).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Spec for the singleton `ClusterInformation` resource. `datastoreReady` is the
/// readiness gate the CNI plugin checks before wiring any pod.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "ClusterInformation",
    plural = "clusterinformations",
    singular = "clusterinformation"
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInformationSpec {
    #[serde(
        rename = "clusterGUID",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub cluster_guid: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cluster_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub calico_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datastore_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub variant: String,
}

/// Spec for the `FelixConfiguration` resource (representative subset of the many
/// Felix parameters; extended as the dataplane grows).
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "FelixConfiguration",
    plural = "felixconfigurations",
    singular = "felixconfiguration"
)]
#[serde(rename_all = "camelCase")]
pub struct FelixConfigurationSpec {
    #[serde(
        rename = "bpfEnabled",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub bpf_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_severity_screen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_endpoint_to_host_action: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datastore_ready_gate_roundtrips() {
        let ci = ClusterInformationSpec {
            cluster_guid: "abcd".into(),
            datastore_ready: Some(true),
            ..Default::default()
        };
        let json = serde_json::to_string(&ci).unwrap();
        assert!(json.contains("\"clusterGUID\":\"abcd\""));
        assert!(json.contains("\"datastoreReady\":true"));
        let round: ClusterInformationSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(round, ci);
    }

    #[test]
    fn absent_datastore_ready_is_none() {
        let ci: ClusterInformationSpec = serde_json::from_str("{}").unwrap();
        assert_eq!(ci.datastore_ready, None);
    }
}
