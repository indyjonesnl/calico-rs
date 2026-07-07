//! `controllers` — Calico-rs cluster-wide reconcilers (kube-controllers).
//!
//! Implemented: the **namespace → Profile** controller (task T100). Each
//! Kubernetes Namespace is mirrored to a Calico `Profile` named `kns.<namespace>`
//! whose `labelsToApply` are the namespace's labels prefixed `pcns.`, with a
//! default allow posture — matching upstream `kube-controllers`'
//! `namespace_controller`.
//!
//! The reconcile logic is factored into a pure [`namespace_to_profile`] mapping
//! (unit-tested) and an async [`reconcile_once`] pass over the datastore
//! (integration-tested against a real cluster). [`run`] wires them into a
//! long-running `kube::runtime` controller.

use std::collections::BTreeMap;
use std::sync::Arc;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use apis::{Action, ProfileSpec, Rule};
use datastore::{cidr_to_token, KddBackend, ResourceKind};
use futures::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Node};
use kube::runtime::controller::Action as CtrlAction;
use kube::runtime::{watcher, Controller};
use kube::{Api, Client, ResourceExt};

/// Profile name for a namespace, matching upstream (`kns.<namespace>`).
pub fn profile_name(namespace: &str) -> String {
    format!("kns.{namespace}")
}

/// Pure mapping: a namespace name + its labels → the Profile it should produce.
/// Namespace labels are exposed to policy under the `pcns.` prefix; the profile
/// applies a default allow posture.
pub fn namespace_to_profile(
    namespace: &str,
    labels: &BTreeMap<String, String>,
) -> (String, ProfileSpec) {
    let labels_to_apply = labels
        .iter()
        .map(|(k, v)| (format!("pcns.{k}"), v.clone()))
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

/// Upsert the Profile for one namespace into the datastore (create or CAS-update).
async fn upsert_profile(
    backend: &KddBackend,
    namespace: &str,
    labels: &BTreeMap<String, String>,
) -> Result<()> {
    let (name, spec) = namespace_to_profile(namespace, labels);
    let value = serde_json::to_value(&spec)?;
    match backend
        .get(ResourceKind::Profile, None, &name)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
    {
        Some(existing) => {
            backend
                .update(
                    ResourceKind::Profile,
                    None,
                    &name,
                    value,
                    &existing.raw_revision,
                )
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        None => {
            backend
                .create(ResourceKind::Profile, None, &name, value)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
    }
    Ok(())
}

/// One reconcile pass: mirror every Namespace to its Profile. Returns the number
/// of namespaces reconciled.
pub async fn reconcile_once(client: Client) -> Result<usize> {
    let backend = KddBackend::new(client.clone());
    let namespaces: Api<Namespace> = Api::all(client);
    let list = namespaces
        .list(&Default::default())
        .await
        .context("listing namespaces")?;
    let mut n = 0;
    for ns in list {
        let name = ns.name_any();
        let labels = ns.labels().clone();
        upsert_profile(&backend, &name, &labels).await?;
        n += 1;
    }
    Ok(n)
}

// ---- IPAM garbage collection ---------------------------------------------

/// Release IPAM state belonging to nodes that no longer exist: for each
/// `BlockAffinity` whose `node` is not among the live Kubernetes Nodes, delete
/// the affine `IPAMBlock` (reclaiming its addresses) and the affinity record.
/// Returns the number of affinities garbage-collected. (Task T098 — the core of
/// upstream `kube-controllers`' IPAM GC; prevents address leaks, spec SC-002.)
pub async fn gc_orphaned_affinities(client: Client) -> Result<usize> {
    let backend = KddBackend::new(client.clone());

    // Set of live node names.
    let nodes: Api<Node> = Api::all(client);
    let live: BTreeSet<String> = nodes
        .list(&Default::default())
        .await
        .context("listing nodes")?
        .into_iter()
        .map(|n| n.name_any())
        .collect();

    let affinities = backend
        .list(ResourceKind::BlockAffinity, None)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("listing block affinities")?;

    let mut gc = 0;
    for aff in affinities {
        let node = aff.spec.get("node").and_then(|v| v.as_str()).unwrap_or("");
        if live.contains(node) {
            continue;
        }
        // Orphaned: reclaim the affine block, then drop the affinity record.
        if let Some(cidr) = aff.spec.get("cidr").and_then(|v| v.as_str()) {
            let block_name = cidr_to_token(cidr);
            if let Ok(Some(blk)) = backend
                .get(ResourceKind::IpamBlock, None, &block_name)
                .await
            {
                let _ = backend
                    .delete(
                        ResourceKind::IpamBlock,
                        None,
                        &block_name,
                        &blk.raw_revision,
                    )
                    .await;
            }
        }
        backend
            .delete(
                ResourceKind::BlockAffinity,
                None,
                &aff.name,
                &aff.raw_revision,
            )
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        gc += 1;
    }
    Ok(gc)
}

/// Release IPAM allocations whose owning pod no longer exists. Each allocation
/// records its pod's `namespace`/`pod` in the block attribute's `secondary` map
/// (written by the CNI plugin). This lists live pods, then for every block
/// attribute referencing a pod that is gone, releases that handle's addresses
/// via [`ipam::KddIpam::release_by_handle`]. Returns the number of handles
/// reclaimed. Complements [`gc_orphaned_affinities`] (whole-node GC): this
/// catches the per-pod leak when a pod is force-deleted or its node crashes
/// before the CNI DEL runs. (spec SC-002 — no address leaks.)
pub async fn gc_orphaned_allocations(client: Client) -> Result<usize> {
    use k8s_openapi::api::core::v1::Pod;

    let backend = KddBackend::new(client.clone());

    // Live pods, keyed "<namespace>/<name>".
    let pods: Api<Pod> = Api::all(client.clone());
    let live: BTreeSet<String> = pods
        .list(&Default::default())
        .await
        .context("listing pods")?
        .into_iter()
        .map(|p| format!("{}/{}", p.namespace().unwrap_or_default(), p.name_any()))
        .collect();

    let blocks = backend
        .list(ResourceKind::IpamBlock, None)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("listing IPAM blocks")?;

    // Collect the distinct orphaned handle ids across all blocks. Iterate the
    // live `allocations` (each entry indexes into `attributes`), not the raw
    // `attributes` array — the array may retain unreferenced entries, and
    // scanning it would re-flag already-freed handles every cycle.
    let mut orphaned: BTreeSet<String> = BTreeSet::new();
    for blk in &blocks {
        let attrs = blk
            .spec
            .get("attributes")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let allocations = blk
            .spec
            .get("allocations")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for slot in &allocations {
            let Some(idx) = slot.as_u64() else { continue }; // null = free
            let Some(attr) = attrs.get(idx as usize) else {
                continue;
            };
            let secondary = attr.get("secondary");
            let ns = secondary
                .and_then(|s| s.get("namespace"))
                .and_then(|v| v.as_str());
            let pod = secondary
                .and_then(|s| s.get("pod"))
                .and_then(|v| v.as_str());
            let handle = attr.get("handleId").and_then(|v| v.as_str());
            // Only GC allocations we can attribute to a specific pod. Legacy
            // allocations without identity are left for whole-node GC / manual
            // reclaim, to avoid releasing an address we cannot prove is dead.
            let (Some(ns), Some(pod), Some(handle)) = (ns, pod, handle) else {
                continue;
            };
            if !live.contains(&format!("{ns}/{pod}")) {
                orphaned.insert(handle.to_string());
            }
        }
    }

    let ipam = ipam::KddIpam::new(KddBackend::new(client));
    let mut gc = 0;
    for handle in orphaned {
        ipam.release_by_handle(&handle)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
            .with_context(|| format!("releasing orphaned handle {handle}"))?;
        gc += 1;
    }
    Ok(gc)
}

// ---- long-running controller ---------------------------------------------

struct Ctx {
    backend: KddBackend,
}

async fn reconcile(ns: Arc<Namespace>, ctx: Arc<Ctx>) -> Result<CtrlAction, ReconcileError> {
    upsert_profile(&ctx.backend, &ns.name_any(), ns.labels())
        .await
        .map_err(|e| ReconcileError(e.to_string()))?;
    Ok(CtrlAction::await_change())
}

#[derive(Debug)]
struct ReconcileError(String);
impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "reconcile error: {}", self.0)
    }
}
impl std::error::Error for ReconcileError {}

fn error_policy(_ns: Arc<Namespace>, _err: &ReconcileError, _ctx: Arc<Ctx>) -> CtrlAction {
    CtrlAction::requeue(std::time::Duration::from_secs(5))
}

/// Run the namespace→Profile controller until the process is stopped.
pub async fn run(client: Client) -> Result<()> {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let ctx = Arc::new(Ctx {
        backend: KddBackend::new(client),
    });
    Controller::new(namespaces, watcher::Config::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::warn!("namespace controller reconcile failed: {e}");
            }
        })
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_labels_to_pcns_prefix_and_allow_posture() {
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
    fn empty_labels_yield_empty_labels_to_apply() {
        let (_, spec) = namespace_to_profile("kube-system", &BTreeMap::new());
        assert!(spec.labels_to_apply.is_empty());
    }
}
