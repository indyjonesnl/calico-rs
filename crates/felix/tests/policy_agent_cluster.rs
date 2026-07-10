//! Self-skipping smoke test for the felix **policy agent** end-to-end wiring
//! (`felix::policy_agent::run_policy_dataplane`).
//!
//! When a `calico-rs-k0s` cluster is reachable it creates a `NetworkPolicy` and
//! a `WorkloadEndpoint`, runs the agent for a few seconds, and asserts the loop
//! stays alive (does not panic / return an error) while watching and ingesting
//! them. It does NOT assert on the kernel: programming the real `inet calico`
//! table needs node privileges (the agent runs in the privileged DaemonSet), so
//! off-node the apply rounds fail-and-retry rather than crash — which this test
//! tolerates.
//!
//! Limitation: `KddBackend::create` sets only the resource `spec`, not
//! `metadata.labels`, so the created WEP carries no labels and the policy will
//! not actually go *active* here — this is a "the pipeline runs without
//! crashing" smoke test, not an enforcement assertion (the enforcement path is
//! covered by the calc/sequencer unit tests and the e2e harness).
//!
//! Skips gracefully when no cluster kubeconfig is available, so the normal
//! `cargo test` run stays green without a cluster. To exercise it:
//! `scripts/k0s-cluster.sh up`, then
//! `cargo test -p felix --test policy_agent_cluster`.

use std::time::Duration;

use datastore::{KddBackend, ResourceKind};
use serde_json::json;

/// Locate a usable kubeconfig: `$KUBECONFIG` if set, else the repo dev-cluster
/// file. Returns `None` (→ skip) if neither exists.
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

/// Delete a resource if it exists (ignoring errors) — used for pre/post cleanup.
async fn cleanup(backend: &KddBackend, kind: ResourceKind, name: &str) {
    if let Ok(Some(existing)) = backend.get(kind, Some("default"), name).await {
        let _ = backend
            .delete(kind, Some("default"), name, &existing.raw_revision)
            .await;
    }
}

#[tokio::test]
async fn policy_agent_ingests_policy_and_endpoint_without_crashing() {
    let Some(path) = kubeconfig_path() else {
        eprintln!("SKIP: no kubeconfig (KUBECONFIG unset and .cluster/ absent)");
        return;
    };
    let backend = match KddBackend::from_kubeconfig_file(&path).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: no reachable calico-rs-k0s cluster ({e})");
            return;
        }
    };

    // Verify the policy CRDs are reachable; skip if the cluster isn't ready.
    if let Err(e) = backend
        .list(ResourceKind::NetworkPolicy, Some("default"))
        .await
    {
        eprintln!("SKIP: NetworkPolicy CRD not reachable ({e})");
        return;
    }

    let np_name = "it-policy-agent-np";
    let wep_name = "it-policy-agent-wep";
    let node = "it-policy-agent-node";

    cleanup(&backend, ResourceKind::NetworkPolicy, np_name).await;
    cleanup(&backend, ResourceKind::WorkloadEndpoint, wep_name).await;

    // Create a label-selector NetworkPolicy and a WorkloadEndpoint on our
    // synthetic node so the agent has real resources to watch + ingest.
    let _ = backend
        .create(
            ResourceKind::NetworkPolicy,
            Some("default"),
            np_name,
            json!({
                "selector": "role == 'db'",
                "types": ["Ingress"],
                "ingress": [{"action": "Allow", "source": {"selector": "role == 'web'"}}]
            }),
        )
        .await;
    let _ = backend
        .create(
            ResourceKind::WorkloadEndpoint,
            Some("default"),
            wep_name,
            json!({
                "node": node,
                "orchestrator": "k8s",
                "endpoint": "eth0",
                "interfaceName": "caliITTEST",
                "ipnetworks": ["10.244.99.9"]
            }),
        )
        .await;

    // Run the agent briefly. It never returns on its own (infinite watch), so a
    // timeout elapsing == "ran without crashing", which is the smoke assertion.
    // If it DOES return early, it must be Ok.
    let agent = felix::policy_agent::run_policy_dataplane(backend.clone(), node.to_string());
    match tokio::time::timeout(Duration::from_secs(4), agent).await {
        Ok(res) => res.expect("policy agent returned an error"),
        Err(_elapsed) => { /* still running after the window: success */ }
    }

    cleanup(&backend, ResourceKind::NetworkPolicy, np_name).await;
    cleanup(&backend, ResourceKind::WorkloadEndpoint, wep_name).await;
}
