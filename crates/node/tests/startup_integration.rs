//! Integration test for `startup` (T047) against the local `calico-rs-k0s`
//! cluster. Skips gracefully when no cluster kubeconfig is reachable, so the
//! normal `cargo test` run stays green without a cluster (mirrors
//! `crates/datastore/tests/kdd_integration.rs`'s self-skip pattern).
//!
//! To exercise it: `scripts/k0s-cluster.sh up`, then
//! `cargo test -p node --test startup_integration`.
//!
//! `node` is a binary-only crate (no `lib.rs`), so this test pulls in
//! `src/startup.rs` directly via `#[path]` rather than `use node::...` — its
//! `apis`/`datastore` imports resolve fine since those are `node`'s regular
//! (non-dev) dependencies, which integration test binaries also link against.
#[path = "../src/startup.rs"]
mod startup;

use datastore::{KddBackend, ResourceKind};

/// Locate a usable kubeconfig: `$KUBECONFIG` if set, else the repo dev-cluster
/// file. Returns `None` (→ skip) if neither exists.
fn kubeconfig_path() -> Option<String> {
    if let Ok(p) = std::env::var("KUBECONFIG") {
        if std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    // crates/node -> repo root
    let repo = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.cluster/calico-rs-k0s.kubeconfig"
    );
    std::path::Path::new(repo)
        .exists()
        .then(|| repo.to_string())
}

#[tokio::test]
async fn startup_is_idempotent_against_live_cluster() {
    let Some(path) = kubeconfig_path() else {
        eprintln!("SKIP: no kubeconfig (KUBECONFIG unset and .cluster/ absent)");
        return;
    };
    let backend = match KddBackend::from_kubeconfig_file(&path).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "SKIP: no reachable calico-rs-k0s cluster ({e}); run scripts/k0s-cluster.sh up"
            );
            return;
        }
    };

    // Verify all three CRDs this test touches are reachable; skip otherwise.
    for kind in [
        ResourceKind::IpPool,
        ResourceKind::ClusterInformation,
        ResourceKind::Node,
    ] {
        if let Err(e) = backend.list(kind, None).await {
            eprintln!("SKIP: {kind:?} CRD not reachable ({e})");
            return;
        }
    }

    // A test-scoped name so we never touch a real cluster Node's CR.
    let nodename = "it-startup-idempotent-node";
    // Best-effort clean slate for the Node CR from a prior aborted run (the
    // shared ClusterInformation/default and default IPPool are left alone —
    // they're the real singleton cluster baseline, not test-scoped).
    if let Ok(Some(existing)) = backend.get(ResourceKind::Node, None, nodename).await {
        let _ = backend
            .delete(ResourceKind::Node, None, nodename, &existing.raw_revision)
            .await;
    }

    // --- first run ---
    startup::startup(&backend, nodename)
        .await
        .expect("first startup should succeed");

    let ci_first = backend
        .get(ResourceKind::ClusterInformation, None, "default")
        .await
        .expect("get ClusterInformation")
        .expect("ClusterInformation/default should exist after startup");
    assert_eq!(
        ci_first.spec["datastoreReady"], true,
        "datastore_ready must be true after startup, got {:?}",
        ci_first.spec
    );
    let guid_first = ci_first.spec["clusterGUID"].clone();
    assert!(
        guid_first.as_str().is_some_and(|g| !g.is_empty()),
        "clusterGUID should be set, got {:?}",
        guid_first
    );

    let pools_first = backend
        .list(ResourceKind::IpPool, None)
        .await
        .expect("list IPPool");
    assert!(
        !pools_first.is_empty(),
        "at least one IPPool should exist after startup"
    );

    let node_first = backend
        .get(ResourceKind::Node, None, nodename)
        .await
        .expect("get Node")
        .expect("Node CR should exist after startup");

    // --- second run: must be a no-op (idempotent) ---
    startup::startup(&backend, nodename)
        .await
        .expect("second startup should succeed");

    let ci_second = backend
        .get(ResourceKind::ClusterInformation, None, "default")
        .await
        .expect("get ClusterInformation")
        .expect("ClusterInformation/default should still exist");
    assert_eq!(
        ci_second.spec["datastoreReady"], true,
        "datastore_ready must still be true"
    );
    assert_eq!(
        ci_second.spec["clusterGUID"], guid_first,
        "clusterGUID must never change once set"
    );

    let pools_second = backend
        .list(ResourceKind::IpPool, None)
        .await
        .expect("list IPPool");
    assert_eq!(
        pools_second.len(),
        pools_first.len(),
        "second startup must not create a duplicate IPPool"
    );

    let node_second = backend
        .get(ResourceKind::Node, None, nodename)
        .await
        .expect("get Node")
        .expect("Node CR should still exist");
    assert_eq!(
        node_second.raw_revision, node_first.raw_revision,
        "second startup must not touch the existing Node CR"
    );

    // Cleanup: only the test-scoped Node CR.
    let _ = backend
        .delete(
            ResourceKind::Node,
            None,
            nodename,
            &node_second.raw_revision,
        )
        .await;
}
