//! Purpose-built syncers (felix, bgp, tunnel-ip, node-status).
//!
//! Upstream Calico defines one syncer per consumer
//! (`libcalico-go/lib/backend/syncersv1/{felixsyncer,bgpsyncer,tunnelipsyncer,
//! nodestatussyncer}`). Each SELECTS the resource kinds its consumer needs, runs
//! one list-then-watch per kind, pushes every v3 update through the matching v1
//! **update processor**, and delivers ordered v1 updates plus a single combined
//! sync status. This module composes the two lower layers rather than
//! reimplementing them:
//!
//! * [`watch_many`](crate::watch_many) (`watchersyncer`) — the merged multi-kind
//!   [`SyncerEvent`] stream with one combined [`SyncStatus`] state machine.
//! * [`process`](crate::updateprocessors::process) /
//!   [`process_keys`](crate::updateprocessors::process_keys)
//!   (`updateprocessors`) — the pure v3→v1 backend-model conversion.
//!
//! The consumer-facing output is [`SyncerV1Event`]. [`run_syncer`] wires
//! `watch_many` into the pure per-event transform [`to_v1_events`]; that
//! transform is what the unit tests drive over synthetic `SyncerEvent` streams,
//! no cluster required.
//!
//! ## Kind selection vs upstream
//!
//! Each `*_syncer_kinds()` function reproduces the subset of its upstream
//! syncer's resource list that our [`ResourceKind`] models. Kinds upstream
//! watches that we do not model yet are OMITTED (documented per function). A
//! selected kind that has no v1 processor yet (T020 only implements four) is
//! still watched, but its updates are **skipped** by the transform — see
//! [`to_v1_events`] — so a not-yet-modeled kind never kills the stream.

use futures::stream;
use futures::{Stream, TryStreamExt};

use crate::cas::CasError;
use crate::kdd::KddBackend;
use crate::model::{Key, ResourceKind};
use crate::syncer::{SyncStatus, SyncerEvent, UpdateType};
use crate::updateprocessors::{process, process_keys, V1KVPair, V1Key};

/// A v1 event delivered to a syncer's consumer (felix, bgp/confd, …). The v3→v1
/// analogue of [`SyncerEvent`]: status transitions pass through unchanged, and
/// each data update carries the *converted* v1 backend-model pair(s).
#[derive(Debug, Clone, PartialEq)]
pub enum SyncerV1Event {
    /// A combined sync-status transition, passed straight through from
    /// [`watch_many`](crate::watch_many).
    Status(SyncStatus),
    /// A v1 key/value pair to apply. `update_type` is [`UpdateType::New`] during
    /// the initial snapshot or [`UpdateType::Updated`] for a live change. A
    /// single v3 resource may yield several of these (a `FelixConfiguration`
    /// flattens into many config pairs). The pair is boxed: it is by far the
    /// largest variant (a `PolicyV1` carries several `Vec`s/`String`s), so
    /// boxing keeps `SyncerV1Event` small for the common `Status`/`Delete` path.
    Update {
        kv: Box<V1KVPair>,
        update_type: UpdateType,
    },
    /// A v1 key to delete. Derived from the v3 delete event's key + last-known
    /// spec via [`process_keys`]; one v3 delete may remove several v1 keys.
    Delete { key: V1Key },
}

// ===========================================================================
// per-syncer kind selection
// ===========================================================================

/// Resource kinds the **felix** syncer watches, matching upstream
/// `felixsyncer` intersected with what we model.
///
/// OMITTED (upstream watches, we do not model / have no `ResourceKind` for):
/// `ClusterInformation` (modeled kind but out of this task's felix set),
/// `BGPConfiguration`/`BGPPeer` (felix's BGP-agnostic view — modeled but not in
/// scope here), the `Staged*` policy kinds, `LiveMigration`, the Calico-IPAM
/// `Block` list, and the KDD-mode native Kubernetes kinds (`KubernetesNetwork
/// Policy`, `KubernetesClusterNetworkPolicy`, `KubernetesEndpointSlice`,
/// `KubernetesService`).
pub fn felix_syncer_kinds() -> Vec<(ResourceKind, Option<String>)> {
    [
        ResourceKind::NetworkPolicy,
        ResourceKind::GlobalNetworkPolicy,
        ResourceKind::Profile,
        ResourceKind::WorkloadEndpoint,
        ResourceKind::HostEndpoint,
        ResourceKind::IpPool,
        ResourceKind::FelixConfiguration,
        ResourceKind::Node,
        ResourceKind::NetworkSet,
        ResourceKind::GlobalNetworkSet,
        ResourceKind::Tier,
    ]
    .into_iter()
    .map(|k| (k, None))
    .collect()
}

/// Resource kinds the **bgp** syncer watches, matching upstream `bgpsyncer`
/// intersected with what we model.
///
/// OMITTED: `BGPFilter` (no `ResourceKind`) and the per-host `BlockAffinity`
/// list (upstream feeds confd block affinities; not modeled as a plain watched
/// kind here).
pub fn bgp_syncer_kinds() -> Vec<(ResourceKind, Option<String>)> {
    [
        ResourceKind::BgpConfiguration,
        ResourceKind::BgpPeer,
        ResourceKind::Node,
        ResourceKind::IpPool,
    ]
    .into_iter()
    .map(|k| (k, None))
    .collect()
}

/// Resource kinds the **tunnel-ip** syncer watches (tunnel-address allocation
/// inputs), matching upstream `tunnelipsyncer`: `Node` + `IPPool`. No upstream
/// kinds omitted.
pub fn tunnel_ip_syncer_kinds() -> Vec<(ResourceKind, Option<String>)> {
    [ResourceKind::Node, ResourceKind::IpPool]
        .into_iter()
        .map(|k| (k, None))
        .collect()
}

/// Resource kinds the **node-status** syncer watches.
///
/// Upstream `nodestatussyncer` watches only `CalicoNodeStatus`, which we do not
/// model (no `ResourceKind`); it is OMITTED. We watch `Node` as the closest
/// modeled input for node-status consumers.
pub fn node_status_syncer_kinds() -> Vec<(ResourceKind, Option<String>)> {
    vec![(ResourceKind::Node, None)]
}

// ===========================================================================
// the pure transform + the run function
// ===========================================================================

/// Convert one [`SyncerEvent`] into zero-or-more [`SyncerV1Event`]s. Pure and
/// per-event — the whole point of the composition, and what the unit tests
/// drive over synthetic streams. Semantics:
///
/// * `Status(..)` passes straight through.
/// * `Update{New|Updated}` runs [`process`]; each resulting v1 pair becomes a
///   [`SyncerV1Event::Update`] (many for a flattened `FelixConfiguration`, none
///   for a filtered-out `WorkloadEndpoint`).
/// * `Update{Deleted}` runs [`process_keys`] over the last-known spec; each v1
///   key becomes a [`SyncerV1Event::Delete`].
/// * A kind with **no v1 processor** (or a spec that fails to deserialize)
///   yields nothing — it is SKIPPED, never an error, so one unprocessable kind
///   cannot kill the syncer. Currently pass-through-skipped felix kinds:
///   `GlobalNetworkPolicy`, `Profile`, `HostEndpoint`, `Node`, `NetworkSet`,
///   `GlobalNetworkSet`, `Tier` (and, for the other syncers, `BGPConfiguration`,
///   `BGPPeer`, `Node`) — all pending their T020 processors.
fn to_v1_events(ev: SyncerEvent) -> Vec<SyncerV1Event> {
    let (key, spec, update_type) = match ev {
        SyncerEvent::Status(s) => return vec![SyncerV1Event::Status(s)],
        SyncerEvent::Update {
            key,
            spec,
            update_type,
            ..
        } => (key, spec, update_type),
    };

    // Only v3 resource keys have a v1 processor; anything else is skipped.
    let kind = match &key {
        Key::Resource { kind, .. } => *kind,
        _ => return Vec::new(),
    };

    match update_type {
        UpdateType::New | UpdateType::Updated => match process(kind, &key, &spec) {
            Ok(kvs) => kvs
                .into_iter()
                .map(|kv| SyncerV1Event::Update {
                    kv: Box::new(kv),
                    update_type,
                })
                .collect(),
            // Processor-less kind / undeserializable spec: skip (see docs).
            Err(_) => Vec::new(),
        },
        UpdateType::Deleted => match process_keys(kind, &key, &spec) {
            Ok(keys) => keys
                .into_iter()
                .map(|key| SyncerV1Event::Delete { key })
                .collect(),
            Err(_) => Vec::new(),
        },
    }
}

/// Run the pure v3→v1 transform over an input [`SyncerEvent`] stream. Generic
/// over the stream so tests can drive it with `futures::stream::iter`. Watch
/// errors (`Err(CasError)`) propagate through unchanged; each `Ok` event
/// fans out into its zero-or-more [`SyncerV1Event`]s.
fn to_v1_stream<S>(input: S) -> impl Stream<Item = Result<SyncerV1Event, CasError>>
where
    S: Stream<Item = Result<SyncerEvent, CasError>>,
{
    input
        .map_ok(|ev| stream::iter(to_v1_events(ev).into_iter().map(Ok)))
        .try_flatten()
}

/// Run a purpose-built syncer: watch `kinds` with a single combined sync status
/// ([`watch_many`](crate::watch_many)) and deliver the converted v1 events. Pair
/// with one of the `*_syncer_kinds()` selectors, e.g.
/// `run_syncer(&backend, &felix_syncer_kinds())`.
pub fn run_syncer(
    backend: &KddBackend,
    kinds: &[(ResourceKind, Option<String>)],
) -> impl Stream<Item = Result<SyncerV1Event, CasError>> + 'static {
    to_v1_stream(crate::watchersyncer::watch_many(backend, kinds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::updateprocessors::{PolicyKind, PolicyV1Key, V1Value};
    use futures::StreamExt;
    use serde_json::json;

    fn resource_key(kind: ResourceKind, namespace: Option<&str>, name: &str) -> Key {
        Key::Resource {
            kind,
            namespace: namespace.map(str::to_string),
            name: name.to_string(),
        }
    }

    fn update_event(
        kind: ResourceKind,
        namespace: Option<&str>,
        name: &str,
        spec: serde_json::Value,
        update_type: UpdateType,
    ) -> SyncerEvent {
        SyncerEvent::Update {
            key: resource_key(kind, namespace, name),
            spec,
            revision: 1,
            update_type,
        }
    }

    // ---- status pass-through ----

    #[test]
    fn status_events_pass_through_unchanged() {
        for s in [
            SyncStatus::WaitForDatastore,
            SyncStatus::ResyncInProgress,
            SyncStatus::InSync,
        ] {
            assert_eq!(
                to_v1_events(SyncerEvent::Status(s)),
                vec![SyncerV1Event::Status(s)]
            );
        }
    }

    // ---- NetworkPolicy New → one v1 Update (augmented selector + default tier) ----

    #[test]
    fn network_policy_new_becomes_one_v1_update() {
        let ev = update_event(
            ResourceKind::NetworkPolicy,
            Some("ns1"),
            "p",
            json!({ "selector": "a == 'b'" }),
            UpdateType::New,
        );
        let out = to_v1_events(ev);
        assert_eq!(out.len(), 1);
        match &out[0] {
            SyncerV1Event::Update { kv, update_type } => {
                assert_eq!(*update_type, UpdateType::New);
                match &kv.value {
                    V1Value::Policy(p) => {
                        // Augmented selector + defaulted tier from the processor.
                        assert_eq!(
                            p.selector,
                            "(a == 'b') && projectcalico.org/namespace == 'ns1'"
                        );
                        assert_eq!(p.tier, "default");
                    }
                    other => panic!("expected policy value, got {other:?}"),
                }
                assert_eq!(
                    kv.key,
                    V1Key::Policy(PolicyV1Key {
                        tier: "default".into(),
                        name: "p".into(),
                        namespace: Some("ns1".into()),
                        kind: PolicyKind::NetworkPolicy,
                    })
                );
            }
            other => panic!("expected update, got {other:?}"),
        }
    }

    // ---- FelixConfiguration New with N set fields → N v1 Updates ----

    #[test]
    fn felix_configuration_new_fans_out_to_one_update_per_set_field() {
        let ev = update_event(
            ResourceKind::FelixConfiguration,
            None,
            "default",
            json!({ "bpfEnabled": true, "logSeverityScreen": "Debug" }),
            UpdateType::New,
        );
        let out = to_v1_events(ev);
        assert_eq!(out.len(), 2, "two set fields -> two v1 updates");
        assert!(out.iter().all(|e| matches!(
            e,
            SyncerV1Event::Update {
                update_type: UpdateType::New,
                ..
            }
        )));
        let keys: Vec<&V1Key> = out
            .iter()
            .map(|e| match e {
                SyncerV1Event::Update { kv, .. } => &kv.key,
                other => panic!("expected update, got {other:?}"),
            })
            .collect();
        assert!(keys.contains(&&V1Key::Config {
            host: None,
            name: "BPFEnabled".into(),
        }));
        assert!(keys.contains(&&V1Key::Config {
            host: None,
            name: "LogSeverityScreen".into(),
        }));
    }

    // ---- NetworkPolicy Deleted → one v1 Delete with the right v1 key ----

    #[test]
    fn network_policy_delete_becomes_one_v1_delete_with_correct_key() {
        // Delete carries the last-known spec (our watcher provides it); the tier
        // must come from that spec so the delete key matches the update key.
        let ev = update_event(
            ResourceKind::NetworkPolicy,
            Some("ns1"),
            "p",
            json!({ "tier": "security", "selector": "a == 'b'" }),
            UpdateType::Deleted,
        );
        let out = to_v1_events(ev);
        assert_eq!(
            out,
            vec![SyncerV1Event::Delete {
                key: V1Key::Policy(PolicyV1Key {
                    tier: "security".into(),
                    name: "p".into(),
                    namespace: Some("ns1".into()),
                    kind: PolicyKind::NetworkPolicy,
                }),
            }]
        );
    }

    #[test]
    fn felix_configuration_delete_removes_every_config_key_it_produced() {
        let ev = update_event(
            ResourceKind::FelixConfiguration,
            None,
            "default",
            json!({ "bpfEnabled": true, "logSeverityScreen": "Debug" }),
            UpdateType::Deleted,
        );
        let out = to_v1_events(ev);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|e| matches!(e, SyncerV1Event::Delete { .. })));
    }

    // ---- processor-less kind → skipped, not an error ----

    #[test]
    fn processorless_kind_is_skipped_not_errored() {
        // Tier has no v1 processor yet; a New/Updated/Deleted all yield nothing.
        for ut in [UpdateType::New, UpdateType::Updated, UpdateType::Deleted] {
            let ev = update_event(ResourceKind::Tier, None, "default", json!({}), ut);
            assert!(
                to_v1_events(ev).is_empty(),
                "processor-less kind must be skipped for {ut:?}"
            );
        }
    }

    #[test]
    fn undeserializable_spec_is_skipped_not_errored() {
        // A supported kind with a spec that cannot deserialize is skipped too.
        let ev = update_event(
            ResourceKind::IpPool,
            None,
            "p",
            json!({ "cidr": 12345 }), // cidr must be a string
            UpdateType::New,
        );
        assert!(to_v1_events(ev).is_empty());
    }

    // ---- stream-level composition over a synthetic input ----

    async fn run_stream(events: Vec<Result<SyncerEvent, CasError>>) -> Vec<Result<SyncerV1Event, CasError>> {
        to_v1_stream(stream::iter(events)).collect().await
    }

    #[tokio::test]
    async fn stream_transforms_status_updates_and_skips_and_propagates_errors() {
        let events = vec![
            Ok(SyncerEvent::Status(SyncStatus::ResyncInProgress)),
            Ok(update_event(
                ResourceKind::NetworkPolicy,
                Some("ns1"),
                "p",
                json!({ "selector": "a == 'b'" }),
                UpdateType::New,
            )),
            // Skipped: no processor for Tier — must not appear, must not error.
            Ok(update_event(ResourceKind::Tier, None, "t", json!({}), UpdateType::New)),
            Ok(SyncerEvent::Status(SyncStatus::InSync)),
            Err(CasError::Backend("boom".into())),
        ];
        let out = run_stream(events).await;

        assert_eq!(out.len(), 4, "5 inputs: 1 skipped, 1 error passed through");
        assert_eq!(
            out[0].as_ref().unwrap(),
            &SyncerV1Event::Status(SyncStatus::ResyncInProgress)
        );
        assert!(matches!(
            out[1].as_ref().unwrap(),
            SyncerV1Event::Update {
                update_type: UpdateType::New,
                ..
            }
        ));
        assert_eq!(
            out[2].as_ref().unwrap(),
            &SyncerV1Event::Status(SyncStatus::InSync)
        );
        assert!(matches!(out[3], Err(CasError::Backend(_))));
    }

    // ---- kind-set functions ----

    #[test]
    fn syncer_kind_sets_match_expected() {
        let felix: Vec<ResourceKind> = felix_syncer_kinds().into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            felix,
            vec![
                ResourceKind::NetworkPolicy,
                ResourceKind::GlobalNetworkPolicy,
                ResourceKind::Profile,
                ResourceKind::WorkloadEndpoint,
                ResourceKind::HostEndpoint,
                ResourceKind::IpPool,
                ResourceKind::FelixConfiguration,
                ResourceKind::Node,
                ResourceKind::NetworkSet,
                ResourceKind::GlobalNetworkSet,
                ResourceKind::Tier,
            ]
        );
        assert!(felix_syncer_kinds().iter().all(|(_, ns)| ns.is_none()));

        let bgp: Vec<ResourceKind> = bgp_syncer_kinds().into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            bgp,
            vec![
                ResourceKind::BgpConfiguration,
                ResourceKind::BgpPeer,
                ResourceKind::Node,
                ResourceKind::IpPool,
            ]
        );

        let tunnel: Vec<ResourceKind> =
            tunnel_ip_syncer_kinds().into_iter().map(|(k, _)| k).collect();
        assert_eq!(tunnel, vec![ResourceKind::Node, ResourceKind::IpPool]);

        let node_status: Vec<ResourceKind> = node_status_syncer_kinds()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(node_status, vec![ResourceKind::Node]);
    }
}
