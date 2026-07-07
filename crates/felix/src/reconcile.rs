//! The felix reconcile loop: read policy from the datastore, render it to
//! nftables, and program the dataplane. The two halves are proven independently
//! (datastore list/watch against the cluster; nft programming in a netns); this
//! wires them.

use datastore::{KddBackend, ResourceKind};

use crate::nft::NftTable;
use crate::policy_render::render_ingress_policies;

/// Build the nft table for a namespace's ingress NetworkPolicies by listing them
/// from the datastore and rendering. (The list step is exercised against a live
/// cluster; the resulting table is applied by [`reconcile_once`].)
pub async fn build_ingress_policy_table(
    backend: &KddBackend,
    namespace: &str,
    table: &str,
) -> Result<NftTable, String> {
    let items = backend
        .list(ResourceKind::NetworkPolicy, Some(namespace))
        .await
        .map_err(|e| e.to_string())?;
    let mut policies = Vec::with_capacity(items.len());
    for kv in items {
        let spec =
            serde_json::from_value(kv.spec).map_err(|e| format!("bad NetworkPolicy spec: {e}"))?;
        policies.push((kv.name, spec));
    }
    Ok(render_ingress_policies("inet", table, &policies))
}

/// One reconcile pass: build the desired nft table from the datastore and apply
/// it. (Applying requires dataplane privileges — felix runs as a privileged
/// DaemonSet on the node.)
pub async fn reconcile_once(backend: &KddBackend, namespace: &str) -> Result<(), String> {
    let table = build_ingress_policy_table(backend, namespace, "calico").await?;
    table.apply()
}

/// Run the reconcile loop, polling on `interval`. (A production build reconciles
/// on `KddBackend::watch` events; polling is the simple first cut.)
pub async fn run(backend: KddBackend, namespace: String, interval: std::time::Duration) {
    loop {
        if let Err(e) = reconcile_once(&backend, &namespace).await {
            eprintln!("felix reconcile failed: {e}");
        }
        tokio::time::sleep(interval).await;
    }
}
