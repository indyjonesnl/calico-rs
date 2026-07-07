//! Integration test for the felix reconcile *build* step against the live
//! `calico-rs-k0s` cluster: create a NetworkPolicy CR, then verify the rendered
//! nft table reflects it. (The apply step is proven separately by
//! `felix-policy-selftest` in a netns; here we validate list→render from real
//! datastore state.) Skips without a cluster.

use datastore::{KddBackend, ResourceKind};
use felix::reconcile::build_ingress_policy_table;

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
async fn reconcile_builds_nft_from_datastore_policies() {
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
        .list(ResourceKind::NetworkPolicy, Some("default"))
        .await
        .is_err()
    {
        eprintln!("SKIP: NetworkPolicy CRD not reachable");
        return;
    }

    let name = "it-felix-reconcile-np";
    if let Ok(Some(kv)) = backend
        .get(ResourceKind::NetworkPolicy, Some("default"), name)
        .await
    {
        let _ = backend
            .delete(
                ResourceKind::NetworkPolicy,
                Some("default"),
                name,
                &kv.raw_revision,
            )
            .await;
    }

    backend
        .create(
            ResourceKind::NetworkPolicy,
            Some("default"),
            name,
            serde_json::json!({
                "selector": "app == 'db'",
                "types": ["Ingress"],
                "ingress": [{
                    "action": "Allow",
                    "protocol": "TCP",
                    "source": { "nets": ["10.0.0.0/24"] },
                    "destination": { "ports": [5432] }
                }]
            }),
        )
        .await
        .expect("create NetworkPolicy");

    let table = build_ingress_policy_table(&backend, "default", "calico")
        .await
        .expect("build table");
    let doc = table.render();

    assert!(
        doc.contains(&format!("chain cali-pi-{name}")),
        "missing policy chain:\n{doc}"
    );
    assert!(
        doc.contains("ip saddr 10.0.0.0/24"),
        "missing rendered rule:\n{doc}"
    );
    assert!(doc.contains("th dport 5432"), "missing port match:\n{doc}");

    if let Ok(Some(kv)) = backend
        .get(ResourceKind::NetworkPolicy, Some("default"), name)
        .await
    {
        let _ = backend
            .delete(
                ResourceKind::NetworkPolicy,
                Some("default"),
                name,
                &kv.raw_revision,
            )
            .await;
    }
}
