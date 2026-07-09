//! Integration test for the KDD backend against the local `calico-rs-k0s`
//! cluster. Skips gracefully when no cluster kubeconfig is available, so the
//! normal `cargo test` run stays green without a cluster.
//!
//! To exercise it: `scripts/k0s-cluster.sh up` (which also applies the IPPool
//! CRD used here), then `cargo test -p datastore --test kdd_integration`.

use std::collections::BTreeMap;
use std::time::Duration;

use datastore::{
    hostname_hash_label, CasError, KddBackend, ResourceKind, SyncStatus, SyncerEvent, UpdateType,
};
use futures::StreamExt;
use serde_json::json;

/// Locate a usable kubeconfig: `$KUBECONFIG` if set, else the repo dev-cluster
/// file. Returns `None` (→ skip) if neither exists.
fn kubeconfig_path() -> Option<String> {
    if let Ok(p) = std::env::var("KUBECONFIG") {
        if std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    // crates/datastore -> repo root
    let repo = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.cluster/calico-rs-k0s.kubeconfig"
    );
    std::path::Path::new(repo)
        .exists()
        .then(|| repo.to_string())
}

macro_rules! skip_if_no_cluster {
    ($backend:expr) => {
        match $backend {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "SKIP: no reachable calico-rs-k0s cluster ({e}); run scripts/k0s-cluster.sh up"
                );
                return;
            }
        }
    };
}

#[tokio::test]
async fn kdd_ippool_crud_and_cas() {
    let Some(path) = kubeconfig_path() else {
        eprintln!("SKIP: no kubeconfig (KUBECONFIG unset and .cluster/ absent)");
        return;
    };
    let backend = skip_if_no_cluster!(KddBackend::from_kubeconfig_file(&path).await);

    let kind = ResourceKind::IpPool;
    let name = "it-kdd-test-pool";

    // Verify the CRD is reachable; skip if the cluster isn't ready / CRD absent.
    if let Err(e) = backend.list(kind, None).await {
        eprintln!("SKIP: IPPool CRD not reachable ({e})");
        return;
    }

    // Clean slate: delete a leftover from a prior run (ignore absence).
    if let Ok(Some(existing)) = backend.get(kind, None, name).await {
        let _ = backend
            .delete(kind, None, name, &existing.raw_revision)
            .await;
    }

    // --- create ---
    let created = backend
        .create(
            kind,
            None,
            name,
            json!({ "cidr": "10.244.0.0/16", "blockSize": 26, "natOutgoing": true }),
        )
        .await
        .expect("create IPPool");
    assert_eq!(created.spec["cidr"], "10.244.0.0/16");
    assert!(!created.raw_revision.is_empty());

    // --- get ---
    let got = backend
        .get(kind, None, name)
        .await
        .expect("get IPPool")
        .expect("IPPool present");
    assert_eq!(got.spec["blockSize"], 26);
    assert_eq!(got.raw_revision, created.raw_revision);

    // --- update with a STALE revision → Conflict (CAS) ---
    let stale = format!("{}", got.revision.saturating_sub(1).max(1));
    let conflict = backend
        .update(kind, None, name, json!({ "cidr": "10.244.0.0/16" }), &stale)
        .await;
    assert!(
        matches!(conflict, Err(CasError::Conflict { .. })),
        "stale-revision update should conflict, got {conflict:?}"
    );

    // --- update with the CURRENT revision → succeeds and bumps revision ---
    let updated = backend
        .update(
            kind,
            None,
            name,
            json!({ "cidr": "10.244.0.0/16", "blockSize": 26, "natOutgoing": false }),
            &got.raw_revision,
        )
        .await
        .expect("CAS update with current revision");
    assert_eq!(updated.spec["natOutgoing"], false);
    assert_ne!(updated.raw_revision, got.raw_revision);

    // --- delete ---
    backend
        .delete(kind, None, name, &updated.raw_revision)
        .await
        .expect("delete IPPool");
    assert!(backend.get(kind, None, name).await.unwrap().is_none());
}

#[tokio::test]
async fn kdd_watch_reaches_insync_and_sees_new_object() {
    let Some(path) = kubeconfig_path() else {
        eprintln!("SKIP: no kubeconfig");
        return;
    };
    let backend = skip_if_no_cluster!(KddBackend::from_kubeconfig_file(&path).await);
    let kind = ResourceKind::IpPool;
    let name = "it-kdd-watch-pool";

    if let Err(e) = backend.list(kind, None).await {
        eprintln!("SKIP: IPPool CRD not reachable ({e})");
        return;
    }
    // Clean any leftover so its creation below is a fresh event.
    if let Ok(Some(existing)) = backend.get(kind, None, name).await {
        let _ = backend
            .delete(kind, None, name, &existing.raw_revision)
            .await;
    }

    let stream = backend.watch(kind, None);
    futures::pin_mut!(stream);

    // Drain the initial snapshot until InSync (bounded).
    let mut reached_insync = false;
    for _ in 0..200 {
        match tokio::time::timeout(Duration::from_secs(10), stream.next()).await {
            Ok(Some(Ok(SyncerEvent::Status(SyncStatus::InSync)))) => {
                reached_insync = true;
                break;
            }
            Ok(Some(_)) => continue, // snapshot updates / resync status
            Ok(None) => break,
            Err(_) => break, // timeout
        }
    }
    assert!(reached_insync, "watcher did not reach InSync");

    // Create a new pool; expect a live update for it on the stream.
    backend
        .create(kind, None, name, json!({ "cidr": "10.99.0.0/16" }))
        .await
        .expect("create pool");

    let mut saw_our_pool = false;
    for _ in 0..200 {
        match tokio::time::timeout(Duration::from_secs(10), stream.next()).await {
            Ok(Some(Ok(SyncerEvent::Update {
                key, update_type, ..
            }))) => {
                if matches!(update_type, UpdateType::New | UpdateType::Updated)
                    && key.path().ends_with(name)
                {
                    saw_our_pool = true;
                    break;
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => break,
        }
    }
    // Cleanup regardless of assertion outcome.
    if let Ok(Some(existing)) = backend.get(kind, None, name).await {
        let _ = backend
            .delete(kind, None, name, &existing.raw_revision)
            .await;
    }
    assert!(saw_our_pool, "watcher did not observe the created pool");
}

#[tokio::test]
async fn kdd_networkpolicy_namespaced_crud() {
    let Some(path) = kubeconfig_path() else {
        eprintln!("SKIP: no kubeconfig");
        return;
    };
    let backend = skip_if_no_cluster!(KddBackend::from_kubeconfig_file(&path).await);
    let kind = ResourceKind::NetworkPolicy;
    let ns = Some("default");
    let name = "it-kdd-np";

    if let Err(e) = backend.list(kind, ns).await {
        eprintln!("SKIP: NetworkPolicy CRD not reachable ({e})");
        return;
    }
    if let Ok(Some(existing)) = backend.get(kind, ns, name).await {
        let _ = backend.delete(kind, ns, name, &existing.raw_revision).await;
    }

    // Create a namespaced policy; exercises the int-or-string `protocol` schema.
    let created = backend
        .create(
            kind,
            ns,
            name,
            json!({
                "selector": "all()",
                "types": ["Ingress"],
                "ingress": [{
                    "action": "Allow",
                    "protocol": "TCP",
                    "destination": { "ports": [443] }
                }]
            }),
        )
        .await
        .expect("create NetworkPolicy");
    assert_eq!(created.spec["selector"], "all()");

    let got = backend
        .get(kind, ns, name)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(got.spec["ingress"][0]["action"], "Allow");
    assert_eq!(got.spec["ingress"][0]["protocol"], "TCP");

    backend
        .delete(kind, ns, name, &got.raw_revision)
        .await
        .expect("delete");
    assert!(backend.get(kind, ns, name).await.unwrap().is_none());
}

#[tokio::test]
async fn kdd_ipamblock_roundtrip_with_nullable_allocations() {
    let Some(path) = kubeconfig_path() else {
        eprintln!("SKIP: no kubeconfig");
        return;
    };
    let backend = skip_if_no_cluster!(KddBackend::from_kubeconfig_file(&path).await);
    let kind = ResourceKind::IpamBlock;
    // k8s resource name: the CIDR tokenized (as IPAM does).
    let name = "10-0-0-0-26";

    if let Err(e) = backend.list(kind, None).await {
        eprintln!("SKIP: IPAMBlock CRD not reachable ({e})");
        return;
    }
    if let Ok(Some(existing)) = backend.get(kind, None, name).await {
        let _ = backend
            .delete(kind, None, name, &existing.raw_revision)
            .await;
    }

    // Persist a block whose `allocations` array contains nulls (free ordinals) —
    // validates the derived IPAMBlock schema accepts the upstream storage shape.
    let created = backend
        .create(
            kind,
            None,
            name,
            json!({
                "cidr": "10.0.0.0/26",
                "affinity": "host:calico-rs-k0s-controller",
                "allocations": [0, null, null],
                "unallocated": [1, 2],
                "attributes": [{ "handleId": "net.pod-a" }],
                "sequenceNumber": 1
            }),
        )
        .await
        .expect("create IPAMBlock");
    assert_eq!(created.spec["allocations"][0], 0);
    assert!(created.spec["allocations"][1].is_null());

    let got = backend.get(kind, None, name).await.unwrap().unwrap();
    assert_eq!(got.spec["affinity"], "host:calico-rs-k0s-controller");
    assert_eq!(got.spec["attributes"][0]["handleId"], "net.pod-a");

    backend
        .delete(kind, None, name, &got.raw_revision)
        .await
        .expect("delete IPAMBlock");
}

#[tokio::test]
async fn kdd_blockaffinity_list_by_host_and_soft_then_hard_delete() {
    let Some(path) = kubeconfig_path() else {
        eprintln!("SKIP: no kubeconfig (KUBECONFIG unset and .cluster/ absent)");
        return;
    };
    let backend = skip_if_no_cluster!(KddBackend::from_kubeconfig_file(&path).await);
    let kind = ResourceKind::BlockAffinity;
    let host = "it-kdd-hostnamehash-host";
    let name = "it-kdd-hostnamehash-host-10-99-0-0-26";

    if let Err(e) = backend.list(kind, None).await {
        eprintln!("SKIP: BlockAffinity CRD not reachable ({e})");
        return;
    }

    // Clean slate: delete a leftover from a prior run (ignore absence).
    if let Ok(Some(existing)) = backend.get(kind, None, name).await {
        let _ = backend
            .delete(kind, None, name, &existing.raw_revision)
            .await;
    }

    // --- create with the hostname-hash label so list_by_host finds it ---
    let created = backend
        .create(
            kind,
            None,
            name,
            json!({ "node": host, "cidr": "10.99.0.0/26", "state": "confirmed" }),
        )
        .await
        .expect("create BlockAffinity");

    let (label, value) = hostname_hash_label(host);
    let mut labels = BTreeMap::new();
    labels.insert(label, value);
    backend
        .merge_patch(
            kind,
            None,
            name,
            json!({ "metadata": { "labels": labels } }),
            Some(&created.raw_revision),
        )
        .await
        .expect("stamp hostname-hash label");

    // --- list_by_host finds it ---
    let found = backend
        .list_by_host(kind, host)
        .await
        .expect("list_by_host");
    assert!(
        found.iter().any(|v| v.name == name),
        "list_by_host({host}) should find {name}, got {found:?}"
    );

    // --- soft_then_hard_delete removes it ---
    backend
        .soft_then_hard_delete(kind, None, name)
        .await
        .expect("soft_then_hard_delete");
    assert!(backend.get(kind, None, name).await.unwrap().is_none());

    // --- a second delete is a no-op (idempotent) ---
    backend
        .soft_then_hard_delete(kind, None, name)
        .await
        .expect("second soft_then_hard_delete should be idempotent");
}
