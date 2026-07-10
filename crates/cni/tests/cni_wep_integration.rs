//! Cluster-backed CNI ADD/DEL datastore-semantics integration test.
//!
//! Drives the exact datastore-visible steps of a CNI ADD/DEL against the live
//! `calico-rs-k0s` cluster (the netns/veth wiring is covered by the rootless-netns
//! selftests, so it is not repeated here):
//!
//!   ADD  = `wep::allocate_or_reuse` (idempotent IP) + `wep::write_wep`
//!   DEL  = `KddIpam::release_by_handle` + `wep::delete_wep`
//!
//! It proves idempotency (a repeated ADD returns the SAME address, leaks nothing —
//! the block free count is unchanged — and yields exactly one WorkloadEndpoint CR)
//! and that DEL releases the IP and deletes the WEP. Skips gracefully without a
//! cluster / without the CRDs applied.

use std::collections::BTreeMap;

use cni::identifiers_from_cni_args;
use datastore::{KddBackend, ResourceKind};
use ipam::{Cidr, KddIpam};

fn kubeconfig_path() -> Option<String> {
    if let Ok(p) = std::env::var("KUBECONFIG") {
        if std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    let repo = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.cluster/calico-rs-k0s.kubeconfig"
    );
    std::path::Path::new(repo)
        .exists()
        .then(|| repo.to_string())
}

#[tokio::test]
async fn cni_add_is_idempotent_and_del_cleans_up() {
    let Some(path) = kubeconfig_path() else {
        eprintln!("SKIP: no kubeconfig");
        return;
    };
    let backend = match KddBackend::from_kubeconfig_file(&path).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: no cluster ({e})");
            return;
        }
    };
    if backend.list(ResourceKind::IpamBlock, None).await.is_err() {
        eprintln!("SKIP: IPAM CRDs not applied");
        return;
    }
    let namespace = "default";
    if backend
        .list(ResourceKind::WorkloadEndpoint, Some(namespace))
        .await
        .is_err()
    {
        eprintln!("SKIP: WorkloadEndpoint CRD not applied");
        return;
    }

    let node = "calico-rs-k0s-controller";
    let pool = Cidr::parse("10.211.0.0/26").unwrap();
    let block_size = 26u8;
    let block_name = "10-211-0-0-26";
    let aff_name = format!("{node}-10-211-0-0-26");
    let container_id = "cni-wep-it-container";
    let handle = cni::wep::handle_id("k8s-pod-network", container_id);
    let ids = identifiers_from_cni_args(
        "K8S_POD_NAMESPACE=default;K8S_POD_NAME=cni-wep-it-pod",
        container_id,
        node,
    );
    let wep_name = ids.workload_endpoint_name();
    let host_veth = cni::veth_name_for_workload(&ids.namespace, &ids.pod, "cali");
    let secondary = BTreeMap::from([
        ("namespace".to_string(), ids.namespace.clone()),
        ("pod".to_string(), ids.pod.clone()),
        ("node".to_string(), node.to_string()),
    ]);

    let ipam = KddIpam::new(backend.clone());

    // Clean slate (best-effort).
    let _ = ipam.release_by_handle(&handle).await;
    let _ = cni::wep::delete_wep(&backend, namespace, &wep_name).await;
    for (kind, ns, name) in [
        (ResourceKind::IpamBlock, None, block_name.to_string()),
        (ResourceKind::BlockAffinity, None, aff_name.clone()),
        (
            ResourceKind::WorkloadEndpoint,
            Some(namespace),
            wep_name.clone(),
        ),
    ] {
        if let Ok(Some(kv)) = backend.get(kind, ns, &name).await {
            let _ = backend.delete(kind, ns, &name, &kv.raw_revision).await;
        }
    }

    // --- ADD #1: allocate + write WEP ---
    let ip1 = cni::wep::allocate_or_reuse(&ipam, node, pool, block_size, &handle, &secondary)
        .await
        .expect("first ADD allocation");
    let pod_labels = BTreeMap::from([("app".to_string(), "web".to_string())]);
    let labels = cni::wep::build_wep_labels(&pod_labels, &ids.namespace, Some("sa1"));
    let spec1 = cni::wep::build_wep_spec(&ids, ip1, &host_veth, node);
    cni::wep::write_wep(&backend, namespace, &wep_name, &spec1, &labels)
        .await
        .expect("first WEP write");

    let free_after_first = ipam.block_free_count(pool).await.unwrap();

    // WEP CR exists with the right IP + interface.
    let wep = backend
        .get(ResourceKind::WorkloadEndpoint, Some(namespace), &wep_name)
        .await
        .unwrap()
        .expect("WEP CR after ADD");
    assert_eq!(wep.spec["ipnetworks"][0], format!("{ip1}/32"));
    assert_eq!(wep.spec["interfaceName"], host_veth);
    assert_eq!(wep.spec["profiles"][0], "kns.default");
    assert_eq!(wep.spec["orchestrator"], "k8s");
    // metadata.labels are stamped — without these, namespace-scoped policies
    // match no endpoint and enforcement silently never applies.
    assert_eq!(wep.labels["projectcalico.org/namespace"], "default");
    assert_eq!(wep.labels["projectcalico.org/orchestrator"], "k8s");
    assert_eq!(wep.labels["projectcalico.org/serviceaccount"], "sa1");
    assert_eq!(wep.labels["app"], "web");

    // Simulate controller-owned mutations the CNI plugin must not clobber: a spec
    // field and a metadata label the CNI does not own.
    backend
        .merge_patch(
            ResourceKind::WorkloadEndpoint,
            Some(namespace),
            &wep_name,
            serde_json::json!({
                "metadata": { "labels": { "controller-owned": "keep" } },
                "spec": { "serviceAccountName": "sa-preserve" },
            }),
            None,
        )
        .await
        .expect("controller merge patch");

    // --- ADD #2 (idempotent re-ADD): same handle → same IP, no leak ---
    let ip2 = cni::wep::allocate_or_reuse(&ipam, node, pool, block_size, &handle, &secondary)
        .await
        .expect("second ADD allocation");
    assert_eq!(ip1, ip2, "re-ADD must return the same address");
    let spec2 = cni::wep::build_wep_spec(&ids, ip2, &host_veth, node);
    cni::wep::write_wep(&backend, namespace, &wep_name, &spec2, &labels)
        .await
        .expect("second WEP write");

    // No leak: the block free count is unchanged by the second ADD.
    assert_eq!(
        ipam.block_free_count(pool).await.unwrap(),
        free_after_first,
        "second ADD must not consume another address"
    );

    // Exactly one WorkloadEndpoint CR for this pod.
    let weps = backend
        .list(ResourceKind::WorkloadEndpoint, Some(namespace))
        .await
        .unwrap();
    assert_eq!(
        weps.iter().filter(|w| w.name == wep_name).count(),
        1,
        "exactly one WEP CR must exist"
    );

    // The CNI merge patch preserved the controller-owned field.
    let wep2 = backend
        .get(ResourceKind::WorkloadEndpoint, Some(namespace), &wep_name)
        .await
        .unwrap()
        .expect("WEP CR after re-ADD");
    assert_eq!(
        wep2.spec["serviceAccountName"], "sa-preserve",
        "re-ADD must not clobber controller-owned fields"
    );
    assert_eq!(
        wep2.labels["controller-owned"], "keep",
        "re-ADD merge patch must not clobber controller-added labels"
    );
    // CNI-owned labels are still present after the re-ADD.
    assert_eq!(wep2.labels["projectcalico.org/namespace"], "default");

    // --- DEL: release IP + delete WEP ---
    let freed = ipam.release_by_handle(&handle).await.expect("release");
    assert_eq!(freed, vec![std::net::IpAddr::V4(ip1)]);
    assert_eq!(
        ipam.block_free_count(pool).await.unwrap(),
        pool.capacity().unwrap(),
        "DEL must return the address to the block"
    );
    cni::wep::delete_wep(&backend, namespace, &wep_name)
        .await
        .expect("delete WEP");
    assert!(
        backend
            .get(ResourceKind::WorkloadEndpoint, Some(namespace), &wep_name)
            .await
            .unwrap()
            .is_none(),
        "WEP CR must be gone after DEL"
    );

    // DEL is idempotent: a second DEL is a no-op, not an error.
    assert!(ipam
        .release_by_handle(&handle)
        .await
        .expect("second release")
        .is_empty());
    cni::wep::delete_wep(&backend, namespace, &wep_name)
        .await
        .expect("second delete WEP");

    // Cleanup residual IPAM CRs.
    for (kind, name) in [
        (ResourceKind::IpamBlock, block_name.to_string()),
        (ResourceKind::BlockAffinity, aff_name.clone()),
    ] {
        if let Ok(Some(kv)) = backend.get(kind, None, &name).await {
            let _ = backend.delete(kind, None, &name, &kv.raw_revision).await;
        }
    }
}
