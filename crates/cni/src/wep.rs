//! WorkloadEndpoint construction + datastore write/delete for CNI ADD/DEL, and
//! the idempotent IP allocate-or-reuse step.
//!
//! The spec builder is pure (unit-tested without a cluster); the read/modify/write
//! against the datastore is factored out so the plugin binary and the integration
//! test drive the identical code path.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use apis::WorkloadEndpointSpec;
use datastore::conversion::{
    LABEL_NAMESPACE, LABEL_ORCHESTRATOR, LABEL_SERVICE_ACCOUNT, ORCHESTRATOR_K8S,
};
use datastore::{KddBackend, ResourceKind};
use ipam::{Cidr, KddIpam};

use crate::WepIdentifiers;

/// Build the CNI-owned WEP `metadata.labels` for a pod (pure).
///
/// Replicates the label half of datastore `pod_to_workload_endpoint` (T018)
/// using the shared datastore constants. It is *replicated* rather than reused
/// because that projection needs a fully-networked pod (`status.podIP`,
/// `spec.nodeName`) and returns `None` for a pod being wired — but in the CNI
/// ADD path the CNI is what assigns the IP, so the pod has no IP yet.
///
/// The result is the pod's own labels plus the Calico-injected keys:
/// `projectcalico.org/namespace` (the pod namespace), `.../orchestrator` (`k8s`),
/// and `.../serviceaccount` (the pod's SA when present, matching upstream's
/// `< 63` char guard). These labels are what namespace-scoped NetworkPolicies
/// select on, so a WEP without them matches no policy.
pub fn build_wep_labels(
    pod_labels: &BTreeMap<String, String>,
    namespace: &str,
    service_account: Option<&str>,
) -> BTreeMap<String, String> {
    let mut labels = pod_labels.clone();
    labels.insert(LABEL_NAMESPACE.to_string(), namespace.to_string());
    labels.insert(LABEL_ORCHESTRATOR.to_string(), ORCHESTRATOR_K8S.to_string());
    if let Some(sa) = service_account {
        // Upstream only stamps the SA label for names < 63 chars (compat).
        if !sa.is_empty() && sa.len() < 63 {
            labels.insert(LABEL_SERVICE_ACCOUNT.to_string(), sa.to_string());
        }
    }
    labels
}

/// Build the CNI-owned [`WorkloadEndpointSpec`] for a pod (pure).
///
/// Sets only the fields the CNI plugin owns — `node`, `orchestrator`, `pod`,
/// `endpoint`, `containerID`, `interfaceName` (the host-side `cali…` veth),
/// `ipnetworks` (`<pod_ip>/32`) and the namespace profile (`kns.<namespace>`).
/// Everything else is left at its default so a merge-patch of the serialized
/// spec never clobbers labels or controller-owned fields on an existing WEP.
pub fn build_wep_spec(
    ids: &WepIdentifiers,
    pod_ip: Ipv4Addr,
    host_veth: &str,
    node: &str,
) -> WorkloadEndpointSpec {
    WorkloadEndpointSpec {
        node: node.to_string(),
        orchestrator: ids.orchestrator.clone(),
        endpoint: ids.endpoint.clone(),
        pod: ids.pod.clone(),
        container_id: ids.container_id.clone(),
        interface_name: host_veth.to_string(),
        ipnetworks: vec![format!("{pod_ip}/32")],
        profiles: vec![format!("kns.{}", ids.namespace)],
        ..Default::default()
    }
}

/// The IPAM handle id for a CNI invocation, matching upstream `GetHandleID`:
/// `"<network-name>.<container-id>"`. Upstream uses exactly this one form (no
/// legacy alternative for the Kubernetes datastore), so DEL releases the same id.
pub fn handle_id(network_name: &str, container_id: &str) -> String {
    format!("{network_name}.{container_id}")
}

/// Idempotently obtain the pod's IPv4 address: reuse the address already owned by
/// `handle_id` if one exists (a repeated ADD for the same container), otherwise
/// allocate a fresh one from the pool. Reusing avoids leaking a second address on
/// a kubelet re-ADD and guarantees the same result each time.
pub async fn allocate_or_reuse(
    ipam: &KddIpam,
    node: &str,
    pool_cidr: Cidr,
    block_size: u8,
    handle_id: &str,
    secondary: &BTreeMap<String, String>,
) -> Result<Ipv4Addr, String> {
    let existing = ipam
        .ips_by_handle(handle_id)
        .await
        .map_err(|e| e.to_string())?;
    let ip = match existing.into_iter().next() {
        Some(ip) => ip,
        None => ipam
            .auto_assign_from_pool_with_attrs(node, pool_cidr, block_size, handle_id, secondary, 1)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .next()
            .ok_or("no address available in pool")?,
    };
    match ip {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err("IPv6 CNI not yet supported".to_string()),
    }
}

/// Build the JSON merge-patch body carrying the CNI-owned `metadata.labels` and
/// `spec` (pure). RFC 7386 merges maps recursively, so applying this SETS the
/// CNI-owned label keys and spec fields without clobbering controller-added
/// labels or controller-owned spec fields — [`build_wep_spec`] populates only
/// CNI-owned fields and skips empty optionals.
pub fn wep_patch_body(
    spec_val: &serde_json::Value,
    labels: &BTreeMap<String, String>,
) -> serde_json::Value {
    serde_json::json!({
        "metadata": { "labels": labels },
        "spec": spec_val,
    })
}

/// Create-or-patch the namespaced `WorkloadEndpoint` CR, writing the CNI-owned
/// spec fields **and** `metadata.labels`.
///
/// The labels (`projectcalico.org/namespace` etc.) are load-bearing: policies
/// are namespace-scoped at runtime, so a WEP without them matches no policy and
/// enforcement silently never applies.
///
/// On first ADD the CR is created (spec only — the datastore create carries just
/// the spec), then a merge patch stamps the labels and re-asserts the spec. If
/// the CR already exists (idempotent re-ADD, or a controller pre-created it) the
/// same merge patch is applied. Because the patch is an RFC 7386 merge of only
/// CNI-owned fields, it leaves controller-added labels and controller-owned spec
/// fields (`ports`, `serviceAccountName`, …) untouched.
pub async fn write_wep(
    backend: &KddBackend,
    namespace: &str,
    name: &str,
    spec: &WorkloadEndpointSpec,
    labels: &BTreeMap<String, String>,
) -> Result<(), String> {
    let spec_val = serde_json::to_value(spec).map_err(|e| e.to_string())?;
    let exists = backend
        .get(ResourceKind::WorkloadEndpoint, Some(namespace), name)
        .await
        .map_err(|e| e.to_string())?
        .is_some();

    // Create the CR if it is absent (tolerating a lost create race), then always
    // apply the label+spec merge patch so the CNI-owned labels are stamped on
    // both the fresh-create and idempotent-re-ADD paths.
    if !exists {
        match backend
            .create(
                ResourceKind::WorkloadEndpoint,
                Some(namespace),
                name,
                spec_val.clone(),
            )
            .await
        {
            Ok(_) => {}
            Err(datastore::CasError::AlreadyExists) => {}
            Err(e) => return Err(e.to_string()),
        }
    }

    backend
        .merge_patch(
            ResourceKind::WorkloadEndpoint,
            Some(namespace),
            name,
            wep_patch_body(&spec_val, labels),
            None,
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Delete the namespaced `WorkloadEndpoint` CR (CNI DEL). Best-effort and
/// idempotent: a missing WEP is treated as success so DEL never fails because
/// cleanup already happened.
pub async fn delete_wep(backend: &KddBackend, namespace: &str, name: &str) -> Result<(), String> {
    match backend
        .get(ResourceKind::WorkloadEndpoint, Some(namespace), name)
        .await
    {
        Ok(Some(kv)) => {
            match backend
                .delete(
                    ResourceKind::WorkloadEndpoint,
                    Some(namespace),
                    name,
                    &kv.raw_revision,
                )
                .await
            {
                Ok(()) | Err(datastore::CasError::NotFound) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        Ok(None) => Ok(()),
        Err(datastore::CasError::NotFound) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers_from_cni_args;

    fn ids() -> WepIdentifiers {
        identifiers_from_cni_args(
            "IgnoreUnknown=1;K8S_POD_NAMESPACE=prod;K8S_POD_NAME=web.0",
            "container-abc",
            "node-1",
        )
    }

    #[test]
    fn build_wep_spec_sets_cni_owned_fields() {
        let spec = build_wep_spec(
            &ids(),
            Ipv4Addr::new(10, 0, 5, 7),
            "cali163e8e8fd7c",
            "node-1",
        );
        assert_eq!(spec.node, "node-1");
        assert_eq!(spec.orchestrator, "k8s");
        assert_eq!(spec.endpoint, "eth0");
        assert_eq!(spec.pod, "web.0");
        assert_eq!(spec.container_id, "container-abc");
        assert_eq!(spec.interface_name, "cali163e8e8fd7c");
        assert_eq!(spec.ipnetworks, vec!["10.0.5.7/32".to_string()]);
        assert_eq!(spec.profiles, vec!["kns.prod".to_string()]);
        // No non-CNI fields are populated (so a merge patch cannot clobber them).
        assert!(spec.workload.is_empty());
        assert!(spec.ports.is_empty());
        assert!(spec.service_account_name.is_none());
        assert!(spec.mac.is_none());
    }

    #[test]
    fn build_wep_spec_serialization_omits_empty_optional_fields() {
        // The merge-patch relies on empty optionals being skipped so they do not
        // overwrite controller-owned data on an existing WEP.
        let spec = build_wep_spec(&ids(), Ipv4Addr::new(10, 0, 0, 1), "cali123", "n");
        let v = serde_json::to_value(&spec).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("workload"));
        assert!(!obj.contains_key("ports"));
        assert!(!obj.contains_key("serviceAccountName"));
        assert!(!obj.contains_key("mac"));
        // ...but the CNI-owned fields are present with upstream casing.
        assert_eq!(obj["interfaceName"], "cali123");
        assert_eq!(obj["ipnetworks"][0], "10.0.0.1/32");
        assert_eq!(obj["profiles"][0], "kns.prod");
    }

    #[test]
    fn wep_name_and_handle_id_forms() {
        assert_eq!(ids().workload_endpoint_name(), "node-1-k8s-web-0-eth0");
        assert_eq!(
            handle_id("k8s-pod-network", "container-abc"),
            "k8s-pod-network.container-abc"
        );
    }

    #[test]
    fn build_wep_labels_includes_pod_and_calico_labels() {
        let pod_labels = BTreeMap::from([("app".to_string(), "web".to_string())]);
        let labels = build_wep_labels(&pod_labels, "nettest", Some("sa1"));
        assert_eq!(labels.get("app").unwrap(), "web");
        assert_eq!(
            labels.get("projectcalico.org/namespace").unwrap(),
            "nettest"
        );
        assert_eq!(labels.get("projectcalico.org/orchestrator").unwrap(), "k8s");
        assert_eq!(
            labels.get("projectcalico.org/serviceaccount").unwrap(),
            "sa1"
        );
    }

    #[test]
    fn build_wep_labels_omits_service_account_when_absent() {
        let labels = build_wep_labels(&BTreeMap::new(), "nettest", None);
        assert!(!labels.contains_key("projectcalico.org/serviceaccount"));
        // Namespace + orchestrator are always injected, even with no pod labels.
        assert_eq!(
            labels.get("projectcalico.org/namespace").unwrap(),
            "nettest"
        );
        assert_eq!(labels.get("projectcalico.org/orchestrator").unwrap(), "k8s");
    }

    #[test]
    fn build_wep_labels_omits_service_account_label_when_name_too_long() {
        // Upstream only stamps the SA label for names < 63 chars (compat).
        let long_sa = "a".repeat(63);
        let labels = build_wep_labels(&BTreeMap::new(), "nettest", Some(&long_sa));
        assert!(!labels.contains_key("projectcalico.org/serviceaccount"));
    }

    #[test]
    fn wep_patch_body_includes_metadata_labels_and_spec() {
        let spec = build_wep_spec(&ids(), Ipv4Addr::new(10, 0, 5, 7), "cali123", "node-1");
        let spec_val = serde_json::to_value(&spec).unwrap();
        let labels = build_wep_labels(
            &BTreeMap::from([("app".to_string(), "web".to_string())]),
            "prod",
            Some("sa1"),
        );
        let patch = wep_patch_body(&spec_val, &labels);
        // metadata.labels carries the CNI-owned labels (RFC7386 merge → no-clobber).
        assert_eq!(patch["metadata"]["labels"]["app"], "web");
        assert_eq!(
            patch["metadata"]["labels"]["projectcalico.org/namespace"],
            "prod"
        );
        assert_eq!(
            patch["metadata"]["labels"]["projectcalico.org/orchestrator"],
            "k8s"
        );
        // spec is still carried in the same patch.
        assert_eq!(patch["spec"]["profiles"][0], "kns.prod");
        assert_eq!(patch["spec"]["interfaceName"], "cali123");
    }
}
