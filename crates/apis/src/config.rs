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

/// Configuration for the node controller (representative subset of
/// upstream's `NodeControllerConfig`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeControllerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciler_period: Option<String>,
}

/// Enables and configures individual kube-controllers (representative
/// subset of upstream's `ControllersConfig`; only the node controller is
/// modeled today, extended as the controllers grow).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ControllersConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeControllerConfig>,
}

/// Spec for the singleton `KubeControllersConfiguration` resource
/// (representative subset of the kube-controllers configuration).
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "KubeControllersConfiguration",
    plural = "kubecontrollersconfigurations",
    singular = "kubecontrollersconfiguration"
)]
#[serde(rename_all = "camelCase")]
pub struct KubeControllersConfigurationSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_severity_screen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_checks: Option<String>,
    #[serde(default)]
    pub controllers: ControllersConfig,
}

/// The types of information a `CalicoNodeStatus` monitors. Wire values
/// match upstream: `Agent` / `BGP` / `Routes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum NodeStatusClassType {
    Agent,
    #[allow(clippy::upper_case_acronyms)]
    BGP,
    Routes,
}

/// Spec for the cluster-scoped `CalicoNodeStatus` resource — requests
/// on-demand status reporting for a single Calico node.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "CalicoNodeStatus",
    plural = "caliconodestatuses",
    singular = "caliconodestatus"
)]
#[serde(rename_all = "camelCase")]
pub struct CalicoNodeStatusSpec {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub classes: Vec<NodeStatusClassType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_period_seconds: Option<u32>,
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

    #[test]
    fn kube_controllers_configuration_wire_names() {
        let spec = KubeControllersConfigurationSpec {
            log_severity_screen: Some("Debug".into()),
            health_checks: Some("Enabled".into()),
            controllers: ControllersConfig {
                node: Some(NodeControllerConfig {
                    reconciler_period: Some("5m".into()),
                }),
            },
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"logSeverityScreen\":\"Debug\""));
        assert!(json.contains("\"healthChecks\":\"Enabled\""));
        assert!(json.contains("\"controllers\":{\"node\":{\"reconcilerPeriod\":\"5m\"}}"));
        let round: KubeControllersConfigurationSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(round, spec);
    }

    #[test]
    fn kube_controllers_configuration_defaults_are_minimal() {
        let spec: KubeControllersConfigurationSpec = serde_json::from_str("{}").unwrap();
        assert_eq!(spec.log_severity_screen, None);
        assert_eq!(spec.controllers, ControllersConfig::default());
    }

    #[test]
    fn calico_node_status_wire_names_and_classes() {
        let spec = CalicoNodeStatusSpec {
            node: "node-1".into(),
            classes: vec![NodeStatusClassType::Agent, NodeStatusClassType::BGP],
            update_period_seconds: Some(10),
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"node\":\"node-1\""));
        assert!(json.contains("\"classes\":[\"Agent\",\"BGP\"]"));
        assert!(json.contains("\"updatePeriodSeconds\":10"));
        let round: CalicoNodeStatusSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(round, spec);
    }
}
