//! Pure KDD projections: Kubernetes core objects → Calico backend resources.
//!
//! Upstream Calico projects core Kubernetes objects into Calico resources on read
//! (`libcalico-go/lib/backend/k8s/conversion/`). This module reproduces the
//! upstream **invariants** — WorkloadEndpoint names, the Calico-injected
//! label/annotation keys, and profile names — as pure, I/O-free functions that
//! feed felix/cni (WEP), controllers (Profile), and bgp/node (Node).
//!
//! All keys/formats are taken from upstream:
//! - `conversion/constants.go` — profile-name and label prefixes.
//! - `api/pkg/apis/projectcalico/v3/constants.go` — the `projectcalico.org/*`
//!   WEP label keys and `k8s` orchestrator string.
//! - `conversion/workload_endpoint_default.go` — Pod→WEP field mapping + the
//!   `VethNameForWorkload` algorithm.
//! - `conversion/conversion.go` — the `IsReadyCalicoPod` skip logic.
//! - `names/workloadendpoint.go` — `CalculateWorkloadEndpointName`.
//! - `backend/k8s/resources/resources.go` — the `projectcalico.org/metadata`
//!   annotation used to round-trip resource metadata through CRD storage.

pub mod policy;
pub use policy::k8s_network_policy_to_calico;

use std::collections::BTreeMap;

use apis::{NodeBgpSpec, NodeSpec, OrchRef, ProfileSpec, WorkloadEndpointSpec};
use k8s_openapi::api::core::v1::{Namespace, Node as K8sNode, Pod, ServiceAccount};
use kube::ResourceExt;
use sha1::{Digest, Sha1};

// ---- upstream key/prefix constants ---------------------------------------

/// Profile-name prefix for a namespace-derived profile (`constants.go`).
pub const NAMESPACE_PROFILE_PREFIX: &str = "kns.";
/// Label prefix for namespace labels exposed to policy (`constants.go`).
pub const NAMESPACE_LABEL_PREFIX: &str = "pcns.";
/// Profile-name prefix for a service-account-derived profile (`constants.go`).
pub const SERVICE_ACCOUNT_PROFILE_PREFIX: &str = "ksa.";
/// Label prefix for service-account labels exposed to policy (`constants.go`).
pub const SERVICE_ACCOUNT_LABEL_PREFIX: &str = "pcsa.";

/// Calico-injected WEP label: pod namespace (`v3/constants.go` `LabelNamespace`).
pub const LABEL_NAMESPACE: &str = "projectcalico.org/namespace";
/// Calico-injected WEP label: orchestrator (`v3/constants.go` `LabelOrchestrator`).
pub const LABEL_ORCHESTRATOR: &str = "projectcalico.org/orchestrator";
/// Calico-injected WEP label: service account (`v3/constants.go` `LabelServiceAccount`).
pub const LABEL_SERVICE_ACCOUNT: &str = "projectcalico.org/serviceaccount";
/// The Kubernetes orchestrator identifier (`v3/constants.go` `OrchestratorKubernetes`).
pub const ORCHESTRATOR_K8S: &str = "k8s";
/// The default WEP endpoint segment (`workload_endpoint_default.go`).
pub const DEFAULT_ENDPOINT: &str = "eth0";

/// Metadata round-trip annotation key (`resources.go` `metadataAnnotation`).
pub const METADATA_ANNOTATION: &str = "projectcalico.org/metadata";
/// Multus network-status annotation copied through by upstream WEP conversion.
pub const NETWORK_STATUS_ANNOTATION: &str = "k8s.v1.cni.cncf.io/network-status";

// ---- WorkloadEndpoint name -----------------------------------------------

/// Escape a WEP name segment: a single dash becomes a double dash, matching
/// upstream `escapeDashes`. (Upstream also rejects segments starting/ending with
/// a dash; that validation is out of scope for this pure name calc.)
fn escape_segment(segment: &str) -> String {
    segment.replace('-', "--")
}

/// Reproduce upstream `CalculateWorkloadEndpointName` for the `k8s`
/// orchestrator: join `[node, "k8s", pod, endpoint]` with `-`, with each
/// segment's `-` escaped to `--`. `endpoint` defaults to `eth0` when empty.
pub fn workload_endpoint_name(node: &str, pod: &str, endpoint: &str) -> String {
    let endpoint = if endpoint.is_empty() {
        DEFAULT_ENDPOINT
    } else {
        endpoint
    };
    [node, ORCHESTRATOR_K8S, pod, endpoint]
        .iter()
        .map(|s| escape_segment(s))
        .collect::<Vec<_>>()
        .join("-")
}

// ---- veth name (replicated from cni, cross-checked in tests) --------------

/// Deterministic host-side veth name for a workload, matching upstream
/// `VethNameForWorkload`: `cali` + first 11 hex chars of `sha1("<ns>.<pod>")`.
///
/// This replicates only the **default-prefix** (`cali`) path of
/// `cni::veth_name_for_workload`, which additionally takes a `prefix` param
/// (empty → `cali`, comma-list → first entry) sourced from
/// `FelixConfigurationSpec.interface_prefix`. Datastore cannot depend on `cni`
/// (which already depends on `datastore`, so a dep would form a cycle), so the
/// default-prefix algorithm is duplicated here and pinned to the same
/// reference vectors by [`tests::veth_name_matches_cni_reference_vectors`].
/// A cluster configured with a non-default `interfacePrefix` will diverge from
/// this function's output — the P3 felix/cni consumer of this projection must
/// thread the configured prefix through (e.g. by adding a `prefix` parameter
/// here) rather than relying on this hardcoded `cali` default.
pub fn veth_name_for_workload(namespace: &str, pod: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("{namespace}.{pod}").as_bytes());
    let hex = hex::encode(hasher.finalize());
    format!("cali{}", &hex[..11])
}

// ---- Pod → WorkloadEndpoint ----------------------------------------------

/// The result of projecting a Pod into a Calico WorkloadEndpoint: the resource
/// name plus its spec, labels, and annotations (kept separate because they land
/// in the WEP `ObjectMeta`, not the spec).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadEndpointConversion {
    /// The computed WEP resource name (`<node>-k8s-<pod>-<endpoint>`).
    pub name: String,
    /// The WEP spec.
    pub spec: WorkloadEndpointSpec,
    /// WEP labels (pod labels + Calico-injected label keys).
    pub labels: BTreeMap<String, String>,
    /// WEP annotations (`projectcalico.org/metadata` + copied network-status).
    pub annotations: BTreeMap<String, String>,
}

/// Service-account-derived profile name (`serviceAccountNameToProfileName`):
/// `ksa.<namespace>.<sa>`, with an empty namespace defaulting to `default`.
pub fn service_account_profile_name(namespace: &str, service_account: &str) -> String {
    let namespace = if namespace.is_empty() {
        "default"
    } else {
        namespace
    };
    format!("{SERVICE_ACCOUNT_PROFILE_PREFIX}{namespace}.{service_account}")
}

/// Collect the pod's IP addresses as CIDRs (`/32` for IPv4, `/128` for IPv6),
/// preferring the plural `status.podIPs`, falling back to the singular
/// `status.podIP`. Matches upstream `getPodIPs` for the status-populated cases.
fn pod_ip_networks(pod: &Pod) -> Vec<String> {
    let to_cidr = |ip: &str| -> String {
        if ip.contains(':') {
            format!("{ip}/128")
        } else {
            format!("{ip}/32")
        }
    };
    let status = match pod.status.as_ref() {
        Some(s) => s,
        None => return Vec::new(),
    };
    if let Some(ips) = status.pod_ips.as_ref() {
        if !ips.is_empty() {
            return ips.iter().map(|p| to_cidr(&p.ip)).collect();
        }
    }
    if let Some(ip) = status.pod_ip.as_ref() {
        if !ip.is_empty() {
            return vec![to_cidr(ip)];
        }
    }
    Vec::new()
}

/// Serialized shape stored under `projectcalico.org/metadata`: upstream marshals
/// the resource's `ObjectMeta` (with name/namespace/uid/resourceVersion cleared)
/// so metadata round-trips through CRD storage. `creationTimestamp` is always
/// emitted (as `null`) by `metav1.ObjectMeta`.
#[derive(serde::Serialize)]
struct WepMetadataAnnotation {
    #[serde(rename = "generateName", skip_serializing_if = "String::is_empty")]
    generate_name: String,
    #[serde(rename = "creationTimestamp")]
    creation_timestamp: Option<()>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    labels: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

/// Project a Pod into a Calico WorkloadEndpoint, or `None` if the pod is not
/// ready for Calico networking. This mirrors upstream `IsReadyCalicoPod`: skip
/// host-networked pods, unscheduled pods (no `spec.nodeName`), and pods without
/// an IP address (`status.podIP`/`podIPs`).
pub fn pod_to_workload_endpoint(pod: &Pod) -> Option<WorkloadEndpointConversion> {
    let spec = pod.spec.as_ref()?;

    // Skip host-networked pods — they share the host's network namespace.
    if spec.host_network.unwrap_or(false) {
        return None;
    }
    // Skip unscheduled pods (no node assigned yet).
    let node = spec.node_name.clone().filter(|n| !n.is_empty())?;

    // Skip pods without an IP — not yet networked.
    let ipnetworks = pod_ip_networks(pod);
    if ipnetworks.is_empty() {
        return None;
    }

    let pod_name = pod.name_any();
    let namespace = pod.namespace().unwrap_or_default();
    let name = workload_endpoint_name(&node, &pod_name, DEFAULT_ENDPOINT);

    // Service account: upstream reads spec.serviceAccountName (K8s defaults it to
    // "default" on admission). Add the SA profile only when a name is present.
    let service_account = spec.service_account_name.clone().filter(|s| !s.is_empty());

    let mut profiles = vec![format!("{NAMESPACE_PROFILE_PREFIX}{namespace}")];
    if let Some(sa) = service_account.as_deref() {
        profiles.push(service_account_profile_name(&namespace, sa));
    }

    // Labels: pod labels plus the Calico-injected keys.
    let mut labels: BTreeMap<String, String> = pod.labels().clone();
    labels.insert(LABEL_NAMESPACE.to_string(), namespace.clone());
    labels.insert(LABEL_ORCHESTRATOR.to_string(), ORCHESTRATOR_K8S.to_string());
    if let Some(sa) = service_account.as_deref() {
        // Upstream only adds the label for SA names < 63 chars (backwards compat).
        if sa.len() < 63 {
            labels.insert(LABEL_SERVICE_ACCOUNT.to_string(), sa.to_string());
        }
    }

    let interface_name = veth_name_for_workload(&namespace, &pod_name);

    let wep_spec = WorkloadEndpointSpec {
        node: node.clone(),
        orchestrator: ORCHESTRATOR_K8S.to_string(),
        workload: String::new(),
        endpoint: DEFAULT_ENDPOINT.to_string(),
        pod: pod_name.clone(),
        container_id: String::new(),
        interface_name,
        mac: None,
        ipnetworks,
        profiles,
        ports: Vec::new(),
        service_account_name: service_account.clone(),
        allow_spoofed_source_prefixes: Vec::new(),
    };

    // Annotations: copy the multus network-status annotation through (upstream
    // WEP conversion), then add the metadata round-trip annotation.
    let mut annotations: BTreeMap<String, String> = BTreeMap::new();
    if let Some(ns) = pod
        .annotations()
        .get(NETWORK_STATUS_ANNOTATION)
        .filter(|v| !v.is_empty())
    {
        annotations.insert(NETWORK_STATUS_ANNOTATION.to_string(), ns.clone());
    }
    let metadata = WepMetadataAnnotation {
        generate_name: pod.metadata.generate_name.clone().unwrap_or_default(),
        creation_timestamp: None,
        labels: labels.clone(),
        annotations: annotations.clone(),
    };
    if let Ok(json) = serde_json::to_string(&metadata) {
        annotations.insert(METADATA_ANNOTATION.to_string(), json);
    }

    Some(WorkloadEndpointConversion {
        name,
        spec: wep_spec,
        labels,
        annotations,
    })
}

// ---- Namespace → Profile (canonical) -------------------------------------

/// Profile name for a namespace, matching upstream (`kns.<namespace>`).
pub fn profile_name(namespace: &str) -> String {
    format!("{NAMESPACE_PROFILE_PREFIX}{namespace}")
}

/// Pure mapping: a namespace name + its labels → the Profile it should produce.
/// Namespace labels are exposed to policy under the `pcns.` prefix; the profile
/// applies a default allow posture. This is the canonical implementation shared
/// by `controllers` (whose wire output is cluster-verified).
pub fn namespace_to_profile(
    namespace: &str,
    labels: &BTreeMap<String, String>,
) -> (String, ProfileSpec) {
    use apis::{Action, Rule};
    let labels_to_apply = labels
        .iter()
        .map(|(k, v)| (format!("{NAMESPACE_LABEL_PREFIX}{k}"), v.clone()))
        .collect();
    let allow = || Rule {
        action: Action::Allow,
        protocol: None,
        source: Default::default(),
        destination: Default::default(),
    };
    let spec = ProfileSpec {
        ingress: vec![allow()],
        egress: vec![allow()],
        labels_to_apply,
    };
    (profile_name(namespace), spec)
}

/// Convenience wrapper: project a Kubernetes [`Namespace`] to its Profile.
pub fn namespace_object_to_profile(ns: &Namespace) -> (String, ProfileSpec) {
    namespace_to_profile(&ns.name_any(), ns.labels())
}

// ---- ServiceAccount → Profile --------------------------------------------

/// Project a Kubernetes ServiceAccount to a Calico Profile named
/// `ksa.<namespace>.<sa>`. SA labels are exposed under the `pcsa.` prefix; the
/// profile carries a default allow posture consistent with the namespace
/// projection.
pub fn service_account_to_profile(namespace: &str, sa: &ServiceAccount) -> (String, ProfileSpec) {
    use apis::{Action, Rule};
    let name = service_account_profile_name(namespace, &sa.name_any());
    let labels_to_apply = sa
        .labels()
        .iter()
        .map(|(k, v)| (format!("{SERVICE_ACCOUNT_LABEL_PREFIX}{k}"), v.clone()))
        .collect();
    let allow = || Rule {
        action: Action::Allow,
        protocol: None,
        source: Default::default(),
        destination: Default::default(),
    };
    let spec = ProfileSpec {
        ingress: vec![allow()],
        egress: vec![allow()],
        labels_to_apply,
    };
    (name, spec)
}

// ---- Node → Calico Node ---------------------------------------------------

/// The first `InternalIP` address of a Kubernetes Node, if any.
fn node_internal_ip(node: &K8sNode) -> Option<String> {
    node.status
        .as_ref()?
        .addresses
        .as_ref()?
        .iter()
        .find(|a| a.type_ == "InternalIP")
        .map(|a| a.address.clone())
}

/// Project a Kubernetes Node into a minimal Calico Node: name = node name;
/// a single `orchRef` (`nodeName` = node name, `orchestrator` = `k8s`); and, if
/// the Node advertises an `InternalIP`, that address as the BGP IPv4 address.
pub fn node_to_calico_node(node: &K8sNode) -> (String, NodeSpec) {
    let name = node.name_any();
    let bgp = node_internal_ip(node).map(|ip| NodeBgpSpec {
        ipv4_address: Some(ip),
        ..Default::default()
    });
    let spec = NodeSpec {
        bgp,
        ipv4_vxlan_tunnel_addr: None,
        ipv6_vxlan_tunnel_addr: None,
        orch_refs: vec![OrchRef {
            node_name: Some(name.clone()),
            orchestrator: ORCHESTRATOR_K8S.to_string(),
        }],
    };
    (name, spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        Node as K8sNode, NodeAddress, NodeStatus, Pod, PodSpec, PodStatus, ServiceAccount,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    // ---- WEP name golden vectors (upstream conversion_test.go) ----

    #[test]
    fn wep_name_golden_simple() {
        assert_eq!(
            workload_endpoint_name("nodeA", "podA", "eth0"),
            "nodeA-k8s-podA-eth0"
        );
    }

    #[test]
    fn wep_name_golden_escaped_dash() {
        // A dash in the pod name is escaped to a double dash.
        assert_eq!(
            workload_endpoint_name("node", "pod-name", "eth0"),
            "node-k8s-pod--name-eth0"
        );
    }

    #[test]
    fn wep_name_escapes_all_segments_and_defaults_endpoint() {
        assert_eq!(
            workload_endpoint_name("node-1", "my-pod", ""),
            "node--1-k8s-my--pod-eth0"
        );
    }

    // ---- veth name cross-check against cni's reference vectors ----

    #[test]
    fn veth_name_matches_cni_reference_vectors() {
        // Pins only the default-prefix ("cali") vectors: must stay byte-identical
        // to cni::veth_name_for_workload's default-prefix pinned vectors. A
        // non-default `interfacePrefix` is out of scope for this replica (see
        // the doc comment on veth_name_for_workload above).
        assert_eq!(
            veth_name_for_workload("default", "nginx"),
            "calic440f455693"
        );
        assert_eq!(
            veth_name_for_workload("kube-system", "coredns-abc"),
            "cali3d5d6ab04b5"
        );
        assert_eq!(
            veth_name_for_workload("prod", "my-app-7d9f"),
            "cali163e8e8fd7c"
        );
    }

    // ---- Pod → WEP ----

    fn ready_pod() -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some("podA".into()),
                namespace: Some("default".into()),
                labels: Some(std::collections::BTreeMap::from([
                    ("labelA".to_string(), "valueA".to_string()),
                    ("labelB".to_string(), "valueB".to_string()),
                ])),
                ..Default::default()
            },
            spec: Some(PodSpec {
                node_name: Some("nodeA".into()),
                service_account_name: Some("sa1".into()),
                ..Default::default()
            }),
            status: Some(PodStatus {
                pod_ip: Some("192.168.0.1".into()),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn pod_to_wep_normal_pod() {
        let c = pod_to_workload_endpoint(&ready_pod()).expect("ready pod converts");
        assert_eq!(c.name, "nodeA-k8s-podA-eth0");
        assert_eq!(c.spec.node, "nodeA");
        assert_eq!(c.spec.pod, "podA");
        assert_eq!(c.spec.orchestrator, "k8s");
        assert_eq!(c.spec.endpoint, "eth0");
        assert_eq!(c.spec.ipnetworks, vec!["192.168.0.1/32".to_string()]);
        assert_eq!(
            c.spec.profiles,
            vec!["kns.default".to_string(), "ksa.default.sa1".to_string()]
        );
        assert_eq!(c.spec.service_account_name.as_deref(), Some("sa1"));
        assert_eq!(
            c.spec.interface_name,
            veth_name_for_workload("default", "podA")
        );
        // Injected labels present alongside the pod labels.
        assert_eq!(c.labels.get("labelA").unwrap(), "valueA");
        assert_eq!(c.labels.get(LABEL_NAMESPACE).unwrap(), "default");
        assert_eq!(c.labels.get(LABEL_ORCHESTRATOR).unwrap(), "k8s");
        assert_eq!(c.labels.get(LABEL_SERVICE_ACCOUNT).unwrap(), "sa1");
        // Metadata annotation round-trips the WEP labels under the upstream key.
        let meta = c
            .annotations
            .get(METADATA_ANNOTATION)
            .expect("metadata annotation");
        assert!(
            meta.contains("\"projectcalico.org/namespace\":\"default\""),
            "{meta}"
        );
        assert!(meta.contains("\"creationTimestamp\":null"), "{meta}");
    }

    #[test]
    fn pod_to_wep_ipv6_uses_128_mask() {
        let mut pod = ready_pod();
        pod.status.as_mut().unwrap().pod_ip = Some("fd00::5".into());
        let c = pod_to_workload_endpoint(&pod).unwrap();
        assert_eq!(c.spec.ipnetworks, vec!["fd00::5/128".to_string()]);
    }

    #[test]
    fn pod_without_service_account_omits_sa_profile_and_label() {
        let mut pod = ready_pod();
        pod.spec.as_mut().unwrap().service_account_name = None;
        let c = pod_to_workload_endpoint(&pod).unwrap();
        assert_eq!(c.spec.profiles, vec!["kns.default".to_string()]);
        assert!(!c.labels.contains_key(LABEL_SERVICE_ACCOUNT));
        assert!(c.spec.service_account_name.is_none());
    }

    #[test]
    fn host_networked_pod_is_skipped() {
        let mut pod = ready_pod();
        pod.spec.as_mut().unwrap().host_network = Some(true);
        assert!(pod_to_workload_endpoint(&pod).is_none());
    }

    #[test]
    fn unscheduled_pod_is_skipped() {
        let mut pod = ready_pod();
        pod.spec.as_mut().unwrap().node_name = None;
        assert!(pod_to_workload_endpoint(&pod).is_none());
    }

    #[test]
    fn pod_without_ip_is_skipped() {
        let mut pod = ready_pod();
        pod.status.as_mut().unwrap().pod_ip = None;
        assert!(pod_to_workload_endpoint(&pod).is_none());
    }

    // ---- Namespace → Profile (behavior ported from controllers) ----

    #[test]
    fn namespace_maps_labels_to_pcns_prefix_and_allow_posture() {
        use apis::Action;
        let labels = BTreeMap::from([
            ("team".to_string(), "payments".to_string()),
            ("env".to_string(), "prod".to_string()),
        ]);
        let (name, spec) = namespace_to_profile("payments-ns", &labels);
        assert_eq!(name, "kns.payments-ns");
        assert_eq!(spec.labels_to_apply.get("pcns.team").unwrap(), "payments");
        assert_eq!(spec.labels_to_apply.get("pcns.env").unwrap(), "prod");
        assert_eq!(spec.ingress.len(), 1);
        assert_eq!(spec.ingress[0].action, Action::Allow);
        assert_eq!(spec.egress[0].action, Action::Allow);
    }

    #[test]
    fn namespace_empty_labels_yield_empty_labels_to_apply() {
        let (_, spec) = namespace_to_profile("kube-system", &BTreeMap::new());
        assert!(spec.labels_to_apply.is_empty());
    }

    // ---- ServiceAccount → Profile ----

    #[test]
    fn service_account_to_profile_name_and_pcsa_labels() {
        use apis::Action;
        let sa = ServiceAccount {
            metadata: ObjectMeta {
                name: Some("builder".into()),
                namespace: Some("ci".into()),
                labels: Some(std::collections::BTreeMap::from([(
                    "role".to_string(),
                    "build".to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };
        let (name, spec) = service_account_to_profile("ci", &sa);
        assert_eq!(name, "ksa.ci.builder");
        assert_eq!(spec.labels_to_apply.get("pcsa.role").unwrap(), "build");
        assert_eq!(spec.ingress[0].action, Action::Allow);
        assert_eq!(spec.egress[0].action, Action::Allow);
    }

    #[test]
    fn service_account_profile_name_defaults_empty_namespace() {
        assert_eq!(
            service_account_profile_name("", "default"),
            "ksa.default.default"
        );
    }

    // ---- Node → Calico Node ----

    #[test]
    fn node_internal_ip_becomes_bgp_ipv4_and_orch_ref() {
        let node = K8sNode {
            metadata: ObjectMeta {
                name: Some("nodeA".into()),
                ..Default::default()
            },
            status: Some(NodeStatus {
                addresses: Some(vec![
                    NodeAddress {
                        type_: "Hostname".into(),
                        address: "nodeA".into(),
                    },
                    NodeAddress {
                        type_: "InternalIP".into(),
                        address: "10.0.0.5".into(),
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let (name, spec) = node_to_calico_node(&node);
        assert_eq!(name, "nodeA");
        assert_eq!(spec.bgp.unwrap().ipv4_address.unwrap(), "10.0.0.5");
        assert_eq!(spec.orch_refs.len(), 1);
        assert_eq!(spec.orch_refs[0].node_name.as_deref(), Some("nodeA"));
        assert_eq!(spec.orch_refs[0].orchestrator, "k8s");
    }

    #[test]
    fn node_without_internal_ip_has_no_bgp() {
        let node = K8sNode {
            metadata: ObjectMeta {
                name: Some("nodeB".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (name, spec) = node_to_calico_node(&node);
        assert_eq!(name, "nodeB");
        assert!(spec.bgp.is_none());
        assert_eq!(spec.orch_refs[0].orchestrator, "k8s");
    }
}
