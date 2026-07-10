//! `cni` — Calico-rs CNI plugin.
//!
//! The netlink/netns execution (veth creation, address/route programming) needs
//! host capabilities and lives in the binary. This library holds the pure,
//! testable core: CNI network-config parsing, workload-endpoint identity, and
//! the deterministic host-side interface name — the pieces that must match
//! upstream Calico exactly for interop (constitution Principle I).

use serde::Deserialize;
use sha1::{Digest, Sha1};

pub mod result;
pub mod sysctl;
pub mod wep;

#[cfg(target_os = "linux")]
pub mod lock;

#[cfg(target_os = "linux")]
pub mod dataplane;
#[cfg(target_os = "linux")]
pub mod orchestrate;

/// Default host interface prefix.
pub const DEFAULT_INTERFACE_PREFIX: &str = "cali";

/// Compute the deterministic host-side veth name for a workload, matching
/// upstream `VethNameForWorkload`: `<prefix><first 11 hex chars of
/// sha1("namespace.podname")>`. `prefix` defaults to `cali` when empty; if it
/// contains a comma-separated list, the first entry is used.
pub fn veth_name_for_workload(namespace: &str, pod: &str, prefix: &str) -> String {
    let prefix = match prefix.split(',').next() {
        Some(p) if !p.is_empty() => p,
        _ => DEFAULT_INTERFACE_PREFIX,
    };
    let mut h = Sha1::new();
    h.update(format!("{namespace}.{pod}").as_bytes());
    let hex = hex::encode(h.finalize());
    format!("{prefix}{}", &hex[..11])
}

/// The IPAM section of the CNI network config.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct IpamConf {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub subnet: Option<String>,
    #[serde(default)]
    pub assign_ipv4: Option<String>,
    #[serde(default)]
    pub assign_ipv6: Option<String>,
}

/// The policy section.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct PolicyConf {
    #[serde(rename = "type", default)]
    pub kind: String,
}

/// The `kubernetes` section: how the plugin reaches the API server. On a node,
/// calico-node writes a kubeconfig here (the plugin runs standalone under
/// kubelet, so it cannot use in-cluster service-account env).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct KubernetesConf {
    #[serde(default)]
    pub kubeconfig: Option<String>,
    #[serde(rename = "k8s_api_root", default)]
    pub k8s_api_root: Option<String>,
}

/// A subset of the Calico CNI network config (`types.NetConf`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct NetConf {
    #[serde(rename = "cniVersion", default)]
    pub cni_version: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub ipam: IpamConf,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub nodename: Option<String>,
    #[serde(default)]
    pub datastore_type: Option<String>,
    #[serde(default)]
    pub policy: PolicyConf,
    #[serde(default)]
    pub kubernetes: KubernetesConf,
    #[serde(rename = "log_level", default)]
    pub log_level: Option<String>,
}

impl NetConf {
    /// Parse a CNI network config from JSON (as delivered on stdin by kubelet).
    pub fn parse(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("invalid CNI netconf: {e}"))
    }

    /// Whether Calico IPAM is in use.
    pub fn uses_calico_ipam(&self) -> bool {
        self.ipam.kind == "calico-ipam"
    }
}

/// Identity of a workload endpoint, parsed from CNI args.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WepIdentifiers {
    pub namespace: String,
    pub pod: String,
    pub container_id: String,
    pub node: String,
    pub orchestrator: String,
    pub endpoint: String,
}

/// Parse `CNI_ARGS` (`KEY=VALUE;KEY=VALUE`) into a map-lite lookup, extracting the
/// Kubernetes pod identifiers, and assemble the workload endpoint identity.
pub fn identifiers_from_cni_args(cni_args: &str, container_id: &str, node: &str) -> WepIdentifiers {
    let mut namespace = String::new();
    let mut pod = String::new();
    for kv in cni_args.split(';') {
        if let Some((k, v)) = kv.split_once('=') {
            match k.trim() {
                "K8S_POD_NAMESPACE" => namespace = v.trim().to_string(),
                "K8S_POD_NAME" => pod = v.trim().to_string(),
                _ => {}
            }
        }
    }
    WepIdentifiers {
        namespace,
        pod,
        container_id: container_id.to_string(),
        node: node.to_string(),
        orchestrator: "k8s".to_string(),
        endpoint: "eth0".to_string(),
    }
}

impl WepIdentifiers {
    /// The WorkloadEndpoint resource name: `<node>-<orch>-<sanitized-pod>-<endpoint>`
    /// (mirrors upstream naming; dots in the pod name become dashes).
    pub fn workload_endpoint_name(&self) -> String {
        let pod = self.pod.replace('.', "-");
        format!(
            "{}-{}-{}-{}",
            self.node, self.orchestrator, pod, self.endpoint
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veth_name_matches_upstream_vectors() {
        // Reference values computed from sha1("<ns>.<pod>")[:11].
        assert_eq!(
            veth_name_for_workload("default", "nginx", ""),
            "calic440f455693"
        );
        assert_eq!(
            veth_name_for_workload("kube-system", "coredns-abc", ""),
            "cali3d5d6ab04b5"
        );
        assert_eq!(
            veth_name_for_workload("prod", "my-app-7d9f", "cali"),
            "cali163e8e8fd7c"
        );
    }

    #[test]
    fn veth_name_honors_custom_prefix_and_comma_list() {
        // Same hash, different prefix; comma list uses the first entry.
        let a = veth_name_for_workload("default", "nginx", "tap");
        assert!(a.starts_with("tap"));
        assert_eq!(&a[3..], "c440f455693");
        let b = veth_name_for_workload("default", "nginx", "tap,cali");
        assert_eq!(b, a);
    }

    #[test]
    fn veth_name_is_ifname_length_safe() {
        // Linux IFNAMSIZ is 16 (15 usable) — cali + 11 hex = 15.
        let n = veth_name_for_workload("some-namespace", "some-very-long-pod-name", "cali");
        assert_eq!(n.len(), 15);
    }

    #[test]
    fn parse_netconf() {
        let doc = r#"{
            "cniVersion": "0.3.1",
            "name": "k8s-pod-network",
            "type": "calico",
            "mtu": 1440,
            "ipam": { "type": "calico-ipam" },
            "policy": { "type": "k8s" },
            "datastore_type": "kubernetes",
            "log_level": "info"
        }"#;
        let nc = NetConf::parse(doc).unwrap();
        assert_eq!(nc.name, "k8s-pod-network");
        assert_eq!(nc.kind, "calico");
        assert_eq!(nc.mtu, Some(1440));
        assert!(nc.uses_calico_ipam());
        assert_eq!(nc.policy.kind, "k8s");
    }

    #[test]
    fn parse_netconf_rejects_garbage() {
        assert!(NetConf::parse("{ not json").is_err());
    }

    #[test]
    fn identifiers_and_wep_name() {
        let ids = identifiers_from_cni_args(
            "IgnoreUnknown=1;K8S_POD_NAMESPACE=prod;K8S_POD_NAME=web.0;K8S_POD_INFRA_CONTAINER_ID=abc",
            "container123",
            "node-1",
        );
        assert_eq!(ids.namespace, "prod");
        assert_eq!(ids.pod, "web.0");
        assert_eq!(ids.orchestrator, "k8s");
        // Dots in the pod name are sanitized to dashes in the WEP name.
        assert_eq!(ids.workload_endpoint_name(), "node-1-k8s-web-0-eth0");
    }
}
