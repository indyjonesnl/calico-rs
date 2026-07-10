//! The felix **policy agent**: the runtime wiring that makes US2 label policy
//! run end-to-end on a node.
//!
//! It assembles the pieces the earlier tasks built into one event-driven loop:
//!
//! ```text
//! datastore watch_many ─► adapter ─► CalcGraph ─► EventSequencer
//!                                                      │ flush_into
//!                                                      ▼
//!                                            collecting Vec sink
//!                                                      │ tx.send (in order)
//!                                                      ▼
//!                                      mpsc ─► dataplane::run(InternalDataplane)
//!                                                 └─ PolicyTableManager
//!                                                    (one atomic full-table render:
//!                                                     sets + chains, self-healing)
//! ```
//!
//! # Adapter (`syncer_update_to_resource`)
//!
//! Pure, datastore-free translation of one [`datastore::SyncerEvent::Update`]
//! into the calc graph's typed [`calc::ResourceUpdate`]. Per kind:
//!
//! - `NetworkPolicy` / `GlobalNetworkPolicy` → `Policy`. Both are
//!   **namespace-scoped** here (via `calc::scope_network_policy` /
//!   `calc::scope_global_network_policy`): a namespaced `NetworkPolicy` is
//!   confined to its namespace and its rule peers scoped, and a GNP's
//!   `namespaceSelector` (spec-level and per-rule) is `pcns.`-prefixed. GNP
//!   fields are mapped onto a [`apis::NetworkPolicySpec`]; the GNP-only
//!   `applyOnForward`, `doNotTrack`, `preDNAT` are dropped — see gaps.
//! - `Profile` → `Profile`.
//! - `WorkloadEndpoint` → `WorkloadEndpoint`, with the calc **endpoint id set to
//!   `spec.interfaceName`** (see the id==iface note below) and `ipnetworks`
//!   normalized to CIDR form so they match ip-set member encodings.
//! - `NetworkSet` → `NetworkSet`.
//! - `Tier` → `Tier`.
//! - anything else, or a spec that fails to deserialize → `None`.
//!
//! ## endpoint id == interface name (documented simplification)
//!
//! The [`crate::policy_table`] renderer keys an endpoint's dispatch chains by the
//! proto `WorkloadEndpoint.name`, which it uses verbatim as the nft
//! `iifname`/`oifname`. The event sequencer copies the calc endpoint id into that
//! `name`. So for the chains to actually hook the pod's host veth, the calc
//! endpoint identity MUST be the interface name — hence `id = spec.interfaceName`
//! here (not the resource name). This collapses the orchestrator/workload/endpoint
//! triple into the interface; a fuller identity is a follow-up.
//!
//! # Known gaps (surfaced, not silently ignored)
//!
//! - **Endpoint identity**: policy/endpoint ids are the bare resource `name`
//!   (the namespace is used for policy selector scoping but is not part of the
//!   calc id). Cross-namespace policy over-application is nonetheless prevented
//!   by the selector scoping above (tracker T059, closed): a namespaced
//!   `NetworkPolicy`'s selector carries `projectcalico.org/namespace == '<ns>'`,
//!   so it cannot match a WEP in another namespace even though the agent watches
//!   *all* namespaces (namespace = `None`).
//! - **GNP lossiness**: the GNP-only `applyOnForward`/`doNotTrack`/`preDNAT`
//!   fields are dropped in the mapping (the `namespaceSelector` is now folded,
//!   not dropped).
//! - **Privilege**: [`run_policy_dataplane`] programs real nftables via
//!   `PolicyTableManager::with_nft`; that only succeeds in the privileged node
//!   DaemonSet (or a netns with `nft`). Off-node the loop runs but the apply rounds
//!   fail and retry.

use std::collections::BTreeMap;

use apis::{GlobalNetworkPolicySpec, NetworkPolicySpec, NetworkSetSpec, ProfileSpec, TierSpec};
use calc::{CalcGraph, EventSequencer, ResourceUpdate};
use datastore::{watch_many, KddBackend, Key, ResourceKind, SyncStatus, SyncerEvent, UpdateType};
use futures::StreamExt;
use proto::{DataplaneSink, ToDataplane};
use tokio::sync::mpsc;

use crate::dataplane::{self, InternalDataplane};
use crate::policy_table::PolicyTableManager;

/// Bound on the buffered `ToDataplane` messages between the flush and the
/// dataplane apply loop.
const CHANNEL_CAPACITY: usize = 1024;

/// Translate one datastore `Update` into a calc [`ResourceUpdate`], or `None` if
/// the kind is not policy-relevant or the spec does not deserialize.
///
/// `namespace` is the resource's namespace (`Some` for a namespaced
/// `NetworkPolicy`, `None` for cluster-scoped kinds). `labels` are the
/// resource's own `metadata.labels` (what selectors match). `is_delete` maps to
/// the update's `remove` flag.
///
/// Namespaced `NetworkPolicy`s and `GlobalNetworkPolicy`s are namespace-scoped
/// here (via [`calc::scope_network_policy`] / [`calc::scope_global_network_policy`])
/// before the calc graph sees them — see the module-level scoping note.
pub fn syncer_update_to_resource(
    kind: ResourceKind,
    name: &str,
    namespace: Option<&str>,
    spec: serde_json::Value,
    labels: BTreeMap<String, String>,
    is_delete: bool,
) -> Option<ResourceUpdate> {
    match kind {
        ResourceKind::NetworkPolicy => {
            let spec: NetworkPolicySpec = deserialize(name, spec)?;
            // Confine a namespaced NetworkPolicy to its namespace so it cannot
            // match identically-labelled endpoints elsewhere (tracker T059).
            let spec = match namespace.filter(|ns| !ns.is_empty()) {
                Some(ns) => calc::scope_network_policy(&spec, ns),
                None => spec,
            };
            Some(ResourceUpdate::Policy {
                id: name.to_string(),
                spec,
                remove: is_delete,
            })
        }
        ResourceKind::GlobalNetworkPolicy => {
            let gnp: GlobalNetworkPolicySpec = deserialize(name, spec)?;
            // A GNP is cluster-scoped (no own-namespace confinement), but its
            // namespaceSelector (spec-level and per-rule) is pcns.-prefixed.
            let namespace_selector = gnp.namespace_selector.clone();
            let spec =
                calc::scope_global_network_policy(&gnp_to_network_policy(gnp), &namespace_selector);
            Some(ResourceUpdate::Policy {
                id: name.to_string(),
                spec,
                remove: is_delete,
            })
        }
        ResourceKind::Profile => {
            let spec: ProfileSpec = deserialize(name, spec)?;
            Some(ResourceUpdate::Profile {
                id: name.to_string(),
                spec,
                remove: is_delete,
            })
        }
        ResourceKind::WorkloadEndpoint => {
            let spec: apis::WorkloadEndpointSpec = deserialize(name, spec)?;
            Some(ResourceUpdate::WorkloadEndpoint {
                // The calc endpoint identity MUST be the interface name so the
                // endpoint manager's iifname/oifname hooks the right pod veth.
                id: spec.interface_name,
                node: spec.node,
                labels,
                profiles: spec.profiles,
                ipnets: spec.ipnetworks.iter().map(|n| normalize_cidr(n)).collect(),
                remove: is_delete,
            })
        }
        ResourceKind::NetworkSet => {
            let spec: NetworkSetSpec = deserialize(name, spec)?;
            Some(ResourceUpdate::NetworkSet {
                id: name.to_string(),
                labels,
                nets: spec.nets,
                remove: is_delete,
            })
        }
        ResourceKind::Tier => {
            let spec: TierSpec = deserialize(name, spec)?;
            Some(ResourceUpdate::Tier {
                name: name.to_string(),
                order: spec.order,
                remove: is_delete,
            })
        }
        // Not policy-relevant to the calc graph.
        _ => None,
    }
}

/// Deserialize a resource spec, logging (at debug) and returning `None` on
/// failure so one malformed resource never stalls the whole watch loop.
fn deserialize<T: serde::de::DeserializeOwned>(name: &str, spec: serde_json::Value) -> Option<T> {
    match serde_json::from_value(spec) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::debug!(resource = %name, error = %e, "policy agent: spec did not deserialize; ignoring");
            None
        }
    }
}

/// Normalize a WEP member address to CIDR form so it matches ip-set member
/// encodings: a bare IP becomes `/32` (v4) or `/128` (v6); an existing CIDR is
/// left as-is.
fn normalize_cidr(addr: &str) -> String {
    if addr.contains('/') {
        addr.to_string()
    } else if addr.contains(':') {
        format!("{addr}/128")
    } else {
        format!("{addr}/32")
    }
}

/// Map the overlapping fields of a [`GlobalNetworkPolicySpec`] onto a
/// [`NetworkPolicySpec`] (the only spec the calc graph consumes). The GNP-only
/// `applyOnForward`, `doNotTrack`, `preDNAT` are dropped — see the module's
/// known-gaps note. The `namespaceSelector` is folded separately by the caller
/// via [`calc::scope_global_network_policy`], not here.
fn gnp_to_network_policy(gnp: GlobalNetworkPolicySpec) -> NetworkPolicySpec {
    NetworkPolicySpec {
        tier: gnp.tier,
        order: gnp.order,
        selector: gnp.selector,
        types: gnp.types,
        ingress: gnp.ingress,
        egress: gnp.egress,
    }
}

/// A synchronous [`DataplaneSink`] that just collects messages in order, so the
/// sequencer's `flush_into` output can be forwarded to the async channel in the
/// exact order it was produced (mirrors proto's recording-sink pattern).
#[derive(Default)]
struct CollectingSink {
    msgs: Vec<ToDataplane>,
}

impl DataplaneSink for CollectingSink {
    type Error = std::convert::Infallible;
    fn apply(&mut self, msg: ToDataplane) -> Result<(), Self::Error> {
        self.msgs.push(msg);
        Ok(())
    }
}

/// Flush the sequencer into a collecting sink, then forward every message to the
/// dataplane channel **in order**. Errors only if the channel is closed (the
/// dataplane loop has exited).
async fn flush_to_channel(
    seq: &mut EventSequencer,
    tx: &mpsc::Sender<ToDataplane>,
) -> Result<(), String> {
    let mut sink = CollectingSink::default();
    // Infallible sink: flush cannot fail.
    let Ok(()) = seq.flush_into(&mut sink);
    for msg in sink.msgs {
        tx.send(msg)
            .await
            .map_err(|_| "dataplane apply loop closed the channel".to_string())?;
    }
    Ok(())
}

/// Run the policy dataplane for `local_node`: build the nft-backed managers, then
/// concurrently (via `join!`, since the managers are `?Send`) run the dataplane
/// apply loop and a watch loop over all policy-relevant kinds across all
/// namespaces, driving `datastore → adapter → CalcGraph → EventSequencer →
/// dataplane` for every event. Returns when the watch stream ends.
pub async fn run_policy_dataplane(backend: KddBackend, local_node: String) -> Result<(), String> {
    // ONE table-owning manager renders the ENTIRE `inet calico` table (named sets
    // + policy/profile/dispatch chains + the forward base chain) and applies it as
    // a single atomic, self-healing `nft -f -` document each reconcile. This
    // replaces the earlier two-manager delta design (IpSetManager + EndpointManager)
    // whose separate transactions poisoned each other on restart/churn.
    let mut idp = InternalDataplane::new();
    idp.add_manager(Box::new(PolicyTableManager::with_nft()));

    let (tx, rx) = mpsc::channel::<ToDataplane>(CHANNEL_CAPACITY);

    // The dataplane apply loop owns the managers and drains the channel. It is
    // driven concurrently with the watch loop on THIS task (the managers are
    // `?Send`, so it cannot be `tokio::spawn`ed) via `join!`.
    let dataplane_loop = dataplane::run(idp, rx, None);

    let watch_loop = async move {
        let mut graph = CalcGraph::new(&local_node);
        let mut seq = EventSequencer::new();

        let kinds = policy_kinds();
        let stream = watch_many(&backend, &kinds);
        futures::pin_mut!(stream);

        while let Some(item) = stream.next().await {
            match item {
                Ok(SyncerEvent::Status(SyncStatus::InSync)) => {
                    seq.mark_in_sync();
                    if let Err(e) = flush_to_channel(&mut seq, &tx).await {
                        tracing::warn!(error = %e, "policy agent: flush after InSync failed");
                        break;
                    }
                }
                Ok(SyncerEvent::Status(_)) => {}
                Ok(SyncerEvent::Update {
                    key,
                    spec,
                    labels,
                    update_type,
                    ..
                }) => {
                    let Key::Resource {
                        kind,
                        name,
                        namespace,
                    } = key
                    else {
                        continue;
                    };
                    let is_delete = matches!(update_type, UpdateType::Deleted);
                    let Some(ru) = syncer_update_to_resource(
                        kind,
                        &name,
                        namespace.as_deref(),
                        spec,
                        labels,
                        is_delete,
                    ) else {
                        continue;
                    };
                    match graph.on_update(ru) {
                        Ok(deltas) => {
                            seq.ingest(&deltas, &graph);
                            if let Err(e) = flush_to_channel(&mut seq, &tx).await {
                                tracing::warn!(error = %e, "policy agent: flush failed");
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, resource = %name, "policy agent: selector parse error; skipping resource");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "policy agent: watch error; continuing");
                }
            }
        }
        // Dropping `tx` here signals the dataplane loop to exit.
    };

    tokio::join!(dataplane_loop, watch_loop);
    Ok(())
}

/// The `(kind, namespace)` set the agent watches — every policy-relevant kind,
/// across all namespaces (`None`).
fn policy_kinds() -> [(ResourceKind, Option<String>); 6] {
    [
        (ResourceKind::NetworkPolicy, None),
        (ResourceKind::GlobalNetworkPolicy, None),
        (ResourceKind::Profile, None),
        (ResourceKind::WorkloadEndpoint, None),
        (ResourceKind::NetworkSet, None),
        (ResourceKind::Tier, None),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ---- adapter: per-kind mapping ---------------------------------------

    #[test]
    fn network_policy_maps_to_policy() {
        let spec = json!({
            "tier": "sec",
            "order": 10.0,
            "selector": "role == 'db'",
            "types": ["Ingress"],
            "ingress": [{"action":"Allow","source":{"selector":"role == 'web'"}}]
        });
        let ru = syncer_update_to_resource(
            ResourceKind::NetworkPolicy,
            "np1",
            None,
            spec,
            labels(&[]),
            false,
        )
        .expect("policy");
        match ru {
            ResourceUpdate::Policy { id, spec, remove } => {
                assert_eq!(id, "np1");
                assert_eq!(spec.tier.as_deref(), Some("sec"));
                assert_eq!(spec.selector, "role == 'db'");
                assert!(!remove);
            }
            other => panic!("expected Policy, got {other:?}"),
        }
    }

    #[test]
    fn delete_event_sets_remove_true() {
        let spec = json!({"selector":"all()"});
        let ru = syncer_update_to_resource(
            ResourceKind::NetworkPolicy,
            "np1",
            None,
            spec,
            labels(&[]),
            true,
        )
        .expect("policy");
        assert!(matches!(ru, ResourceUpdate::Policy { remove: true, .. }));
    }

    #[test]
    fn profile_maps_to_profile() {
        let spec = json!({"labelsToApply": {"stage":"frontend"}});
        let ru = syncer_update_to_resource(
            ResourceKind::Profile,
            "kns.default",
            None,
            spec,
            labels(&[]),
            false,
        )
        .expect("profile");
        match ru {
            ResourceUpdate::Profile { id, spec, remove } => {
                assert_eq!(id, "kns.default");
                assert_eq!(
                    spec.labels_to_apply.get("stage").map(String::as_str),
                    Some("frontend")
                );
                assert!(!remove);
            }
            other => panic!("expected Profile, got {other:?}"),
        }
    }

    #[test]
    fn workload_endpoint_id_is_interface_name_with_cidr_normalized_nets_and_event_labels() {
        let spec = json!({
            "node": "node-a",
            "orchestrator": "k8s",
            "endpoint": "eth0",
            "interfaceName": "cali123",
            "profiles": ["kns.default"],
            "ipnetworks": ["10.0.0.5", "10.0.0.0/24", "fe80::1"]
        });
        let ru = syncer_update_to_resource(
            ResourceKind::WorkloadEndpoint,
            "node-a-k8s-pod-eth0",
            None,
            spec,
            labels(&[("role", "db")]),
            false,
        )
        .expect("wep");
        match ru {
            ResourceUpdate::WorkloadEndpoint {
                id,
                node,
                labels: lbls,
                profiles,
                ipnets,
                remove,
            } => {
                assert_eq!(id, "cali123", "id must be the interface name");
                assert_eq!(node, "node-a");
                assert_eq!(lbls.get("role").map(String::as_str), Some("db"));
                assert_eq!(profiles, vec!["kns.default".to_string()]);
                assert_eq!(
                    ipnets,
                    vec![
                        "10.0.0.5/32".to_string(),
                        "10.0.0.0/24".to_string(),
                        "fe80::1/128".to_string()
                    ]
                );
                assert!(!remove);
            }
            other => panic!("expected WorkloadEndpoint, got {other:?}"),
        }
    }

    #[test]
    fn network_set_maps_with_labels_and_nets() {
        let spec = json!({"nets": ["192.168.0.0/16"]});
        let ru = syncer_update_to_resource(
            ResourceKind::NetworkSet,
            "corpnet",
            None,
            spec,
            labels(&[("env", "corp")]),
            false,
        )
        .expect("networkset");
        match ru {
            ResourceUpdate::NetworkSet {
                id,
                labels: lbls,
                nets,
                remove,
            } => {
                assert_eq!(id, "corpnet");
                assert_eq!(lbls.get("env").map(String::as_str), Some("corp"));
                assert_eq!(nets, vec!["192.168.0.0/16".to_string()]);
                assert!(!remove);
            }
            other => panic!("expected NetworkSet, got {other:?}"),
        }
    }

    #[test]
    fn tier_maps_order() {
        let spec = json!({"order": 100.0});
        let ru = syncer_update_to_resource(
            ResourceKind::Tier,
            "default",
            None,
            spec,
            labels(&[]),
            false,
        )
        .expect("tier");
        match ru {
            ResourceUpdate::Tier {
                name,
                order,
                remove,
            } => {
                assert_eq!(name, "default");
                assert_eq!(order, Some(100.0));
                assert!(!remove);
            }
            other => panic!("expected Tier, got {other:?}"),
        }
    }

    #[test]
    fn namespaced_network_policy_is_scoped_to_its_namespace() {
        // A namespaced NetworkPolicy must be confined to its namespace and its
        // rule peers scoped (tracker T059), so it cannot over-apply to an
        // identically-labelled endpoint in another namespace.
        let spec = json!({
            "selector": "role == 'db'",
            "types": ["Ingress"],
            "ingress": [{"action":"Allow","source":{"selector":"role == 'web'"}}]
        });
        let ru = syncer_update_to_resource(
            ResourceKind::NetworkPolicy,
            "np1",
            Some("prod"),
            spec,
            labels(&[]),
            false,
        )
        .expect("policy");
        match ru {
            ResourceUpdate::Policy { id, spec, .. } => {
                assert_eq!(id, "np1");
                // Applies-to selector confined to the namespace.
                assert_eq!(
                    spec.selector,
                    "(role == 'db') && projectcalico.org/namespace == 'prod'"
                );
                // Rule peer selector confined to the namespace (ns-first).
                assert_eq!(
                    spec.ingress[0].source.selector.as_deref(),
                    Some("(projectcalico.org/namespace == 'prod') && (role == 'web')")
                );
            }
            other => panic!("expected Policy, got {other:?}"),
        }
    }

    #[test]
    fn global_network_policy_namespace_selector_is_pcns_prefixed_not_own_ns_confined() {
        // A GNP is cluster-scoped: NOT own-namespace-confined, but its
        // spec-level namespaceSelector is pcns.-prefixed into the applies-to
        // selector, and rule namespaceSelectors are pcns.-prefixed.
        let spec = json!({
            "selector": "all()",
            "namespaceSelector": "team == 'x'",
            "types": ["Ingress"],
            "ingress": [{"action":"Allow","source":{"namespaceSelector":"env == 'prod'"}}]
        });
        let ru = syncer_update_to_resource(
            ResourceKind::GlobalNetworkPolicy,
            "gnp1",
            None,
            spec,
            labels(&[]),
            false,
        )
        .expect("gnp");
        match ru {
            ResourceUpdate::Policy { spec, .. } => {
                // No own-namespace confinement; namespaceSelector pcns.-prefixed
                // and appended. Upstream translates the resulting `all()` (the
                // GNP's own selector) to `has(projectcalico.org/namespace)` when
                // a namespaceSelector is present (globalnetworkpolicyprocessor).
                assert_eq!(
                    spec.selector,
                    "(has(projectcalico.org/namespace)) && pcns.team == \"x\""
                );
                assert_eq!(
                    spec.ingress[0].source.selector.as_deref(),
                    Some("pcns.env == \"prod\"")
                );
            }
            other => panic!("expected Policy from GNP, got {other:?}"),
        }
    }

    #[test]
    fn global_network_policy_maps_to_policy() {
        let spec = json!({
            "tier": "default",
            "order": 5.0,
            "selector": "all()",
            "namespaceSelector": "team == 'x'",
            "types": ["Egress"],
            "egress": [{"action":"Deny"}],
            "preDNAT": true
        });
        let ru = syncer_update_to_resource(
            ResourceKind::GlobalNetworkPolicy,
            "gnp1",
            None,
            spec,
            labels(&[]),
            false,
        )
        .expect("gnp");
        match ru {
            ResourceUpdate::Policy { id, spec, remove } => {
                assert_eq!(id, "gnp1");
                // GNP with a spec-level namespaceSelector: selector is
                // pcns.-prefixed and appended (not own-namespace-confined); the
                // GNP's own `all()` is translated to has(namespace) upstream.
                assert_eq!(
                    spec.selector,
                    "(has(projectcalico.org/namespace)) && pcns.team == \"x\""
                );
                assert_eq!(spec.tier.as_deref(), Some("default"));
                assert_eq!(spec.egress.len(), 1);
                assert!(!remove);
            }
            other => panic!("expected Policy from GNP, got {other:?}"),
        }
    }

    #[test]
    fn undeserializable_spec_returns_none() {
        // `types` must be an array of enum strings; a number fails to deserialize.
        let spec = json!({"selector":"all()","types": 42});
        assert!(syncer_update_to_resource(
            ResourceKind::NetworkPolicy,
            "np1",
            None,
            spec,
            labels(&[]),
            false
        )
        .is_none());
    }

    #[test]
    fn unknown_kind_returns_none() {
        let spec = json!({"cidr":"10.0.0.0/16"});
        assert!(syncer_update_to_resource(
            ResourceKind::IpPool,
            "p",
            None,
            spec,
            labels(&[]),
            false
        )
        .is_none());
    }

    // ---- end-to-end: adapter → graph → sequencer → collecting flush ------

    fn feed(
        graph: &mut CalcGraph,
        seq: &mut EventSequencer,
        kind: ResourceKind,
        name: &str,
        spec: serde_json::Value,
        lbls: &[(&str, &str)],
    ) {
        let ru = syncer_update_to_resource(kind, name, None, spec, labels(lbls), false)
            .expect("adapter produced a ResourceUpdate");
        let deltas = graph.on_update(ru).expect("graph update");
        seq.ingest(&deltas, graph);
    }

    /// Driving the graph through the ADAPTER and flushing via the collecting
    /// sink + channel yields the dependency-safe order the sequencer produced:
    /// IpSetUpdate → ActivePolicyUpdate → WorkloadEndpointUpdate(db) → InSync.
    #[tokio::test]
    async fn collecting_flush_preserves_event_sequencer_order_end_to_end() {
        let mut graph = CalcGraph::new("node-a");
        let mut seq = EventSequencer::new();

        feed(
            &mut graph,
            &mut seq,
            ResourceKind::Tier,
            "default",
            json!({"order":100.0}),
            &[],
        );
        feed(
            &mut graph,
            &mut seq,
            ResourceKind::NetworkPolicy,
            "np1",
            json!({
                "selector":"role == 'db'",
                "types":["Ingress"],
                "ingress":[{"action":"Allow","source":{"selector":"role == 'web'"}}]
            }),
            &[],
        );
        feed(
            &mut graph,
            &mut seq,
            ResourceKind::WorkloadEndpoint,
            "db-wep",
            json!({"node":"node-a","orchestrator":"k8s","endpoint":"eth0","interfaceName":"calidb","ipnetworks":["10.0.0.9"]}),
            &[("role", "db")],
        );
        feed(
            &mut graph,
            &mut seq,
            ResourceKind::WorkloadEndpoint,
            "web-wep",
            json!({"node":"node-a","orchestrator":"k8s","endpoint":"eth0","interfaceName":"caliweb","ipnetworks":["10.0.0.5"]}),
            &[("role", "web")],
        );
        seq.mark_in_sync();

        let (tx, mut rx) = mpsc::channel::<ToDataplane>(CHANNEL_CAPACITY);
        flush_to_channel(&mut seq, &tx).await.expect("flush");
        drop(tx);

        let mut seen = Vec::new();
        while let Some(msg) = rx.recv().await {
            seen.push(msg);
        }

        let pos = |pred: &dyn Fn(&ToDataplane) -> bool| seen.iter().position(pred);
        let ip = pos(&|m| matches!(m, ToDataplane::IpSetUpdate(_))).expect("IpSetUpdate");
        let pol =
            pos(&|m| matches!(m, ToDataplane::ActivePolicyUpdate { id, .. } if id.name == "np1"))
                .expect("ActivePolicyUpdate np1");
        let db = pos(&|m| matches!(m, ToDataplane::WorkloadEndpointUpdate { endpoint, .. } if endpoint.name == "calidb"))
            .expect("WorkloadEndpointUpdate calidb");
        let insync = pos(&|m| matches!(m, ToDataplane::InSync)).expect("InSync");

        assert!(ip < pol, "IP set precedes policy");
        assert!(pol < db, "policy precedes endpoint");
        assert!(db < insync, "endpoint precedes InSync");
        assert!(
            matches!(seen.last(), Some(ToDataplane::InSync)),
            "InSync is last"
        );

        // The db endpoint's dispatch is keyed by the interface name and lists np1.
        if let ToDataplane::WorkloadEndpointUpdate { endpoint, .. } = &seen[db] {
            assert_eq!(endpoint.name, "calidb");
            assert_eq!(endpoint.tiers[0].ingress_policies, vec!["np1".to_string()]);
            // CIDR-normalized by the adapter.
            assert_eq!(endpoint.ipv4_nets, vec!["10.0.0.9/32".to_string()]);
        }
    }
}
