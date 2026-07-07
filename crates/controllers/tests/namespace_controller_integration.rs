//! Integration test for the namespace→Profile controller against the live
//! `calico-rs-k0s` cluster. Skips without a cluster. Requires the Profile CRD
//! applied (`cargo run -p apis --bin gen-crds | kubectl apply -f -`).

use datastore::{KddBackend, ResourceKind};
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{DeleteParams, PostParams};
use kube::Api;

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
async fn namespace_reconciles_to_profile() {
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
    if backend.list(ResourceKind::Profile, None).await.is_err() {
        eprintln!("SKIP: Profile CRD not applied");
        return;
    }
    let client = backend.client();

    let ns_name = "it-ctrl-ns";
    let profile = format!("kns.{ns_name}");
    let ns_api: Api<Namespace> = Api::all(client.clone());

    // Clean slate.
    let _ = ns_api.delete(ns_name, &DeleteParams::default()).await;
    if let Ok(Some(p)) = backend.get(ResourceKind::Profile, None, &profile).await {
        let _ = backend
            .delete(ResourceKind::Profile, None, &profile, &p.raw_revision)
            .await;
    }

    // Create a namespace with a label.
    let ns: Namespace = serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": { "name": ns_name, "labels": { "team": "payments" } }
    }))
    .unwrap();
    ns_api
        .create(&PostParams::default(), &ns)
        .await
        .expect("create namespace");

    // Run one reconcile pass.
    let n = controllers::reconcile_once(client.clone())
        .await
        .expect("reconcile");
    assert!(n >= 1);

    // The Profile CR should now exist with the pcns-prefixed label + allow rules.
    let p = backend
        .get(ResourceKind::Profile, None, &profile)
        .await
        .unwrap()
        .expect("profile created by reconcile");
    assert_eq!(p.spec["labelsToApply"]["pcns.team"], "payments");
    assert_eq!(p.spec["ingress"][0]["action"], "Allow");

    // Reconcile is idempotent (second pass updates in place, no error).
    controllers::reconcile_once(client.clone())
        .await
        .expect("reconcile again");

    // Cleanup.
    let _ = ns_api.delete(ns_name, &DeleteParams::default()).await;
    if let Ok(Some(p)) = backend.get(ResourceKind::Profile, None, &profile).await {
        let _ = backend
            .delete(ResourceKind::Profile, None, &profile, &p.raw_revision)
            .await;
    }
}

#[tokio::test]
async fn ipam_gc_reclaims_orphaned_node_affinities() {
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
    if backend
        .list(ResourceKind::BlockAffinity, None)
        .await
        .is_err()
    {
        eprintln!("SKIP: IPAM CRDs not applied");
        return;
    }
    let client = backend.client();

    let ghost = "ghost-node-gc";
    let aff_name = format!("{ghost}-10-77-0-0-26");
    let block_name = "10-77-0-0-26";

    // Seed a BlockAffinity + IPAMBlock for a node that does not exist.
    let _ = backend
        .create(
            ResourceKind::BlockAffinity,
            None,
            &aff_name,
            serde_json::json!({ "node": ghost, "cidr": "10.77.0.0/26", "state": "confirmed" }),
        )
        .await;
    let _ = backend
        .create(
            ResourceKind::IpamBlock,
            None,
            block_name,
            serde_json::json!({
                "cidr": "10.77.0.0/26",
                "affinity": format!("host:{ghost}"),
                "allocations": [null, null],
                "unallocated": [0, 1]
            }),
        )
        .await;

    // Sanity: they exist before GC.
    assert!(backend
        .get(ResourceKind::BlockAffinity, None, &aff_name)
        .await
        .unwrap()
        .is_some());

    let gc = controllers::gc_orphaned_affinities(client)
        .await
        .expect("gc");
    assert!(gc >= 1, "expected at least the ghost affinity to be GC'd");

    // Orphaned affinity + block are gone.
    assert!(backend
        .get(ResourceKind::BlockAffinity, None, &aff_name)
        .await
        .unwrap()
        .is_none());
    assert!(backend
        .get(ResourceKind::IpamBlock, None, block_name)
        .await
        .unwrap()
        .is_none());
}
