//! Watch + watcher-syncer: turns the Kubernetes list-then-watch stream into an
//! ordered sequence of typed [`SyncerEvent`]s with a sync-status state machine.
//!
//! Built on `kube::runtime::watcher`, which does the list-then-watch and
//! automatic re-list on desync. We map its events onto Calico's syncer model
//! (`libcalico-go` watchersyncer): a resync produces `ResyncInProgress`, the
//! initial list snapshot, then `InSync`; subsequent changes are incremental
//! `Apply`/`Delete` updates.

use std::collections::{BTreeMap, HashMap, HashSet};

use futures::{Stream, StreamExt, TryStreamExt};
use kube::api::DynamicObject;
use kube::runtime::watcher::{self, watcher};

use crate::cas::{CasError, Revision};
use crate::kdd::KddBackend;
use crate::model::{Key, ResourceKind};

/// Overall synchronization status of a syncer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStatus {
    /// Not yet connected to the datastore.
    WaitForDatastore,
    /// A (re)sync is in progress; the snapshot is not yet complete.
    ResyncInProgress,
    /// The initial snapshot has been delivered; subsequent events are live.
    InSync,
}

/// The nature of an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateType {
    /// A newly-seen key (including during the initial snapshot).
    New,
    /// An update to a key already seen.
    Updated,
    /// A key was deleted.
    Deleted,
}

/// One event emitted by a syncer stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncerEvent {
    /// A sync-status transition.
    Status(SyncStatus),
    /// A key/value update.
    Update {
        key: Key,
        spec: serde_json::Value,
        revision: Revision,
        update_type: UpdateType,
        /// The resource's own `metadata.labels` (empty map if absent). This is
        /// the WorkloadEndpoint/NetworkSet/etc.'s own label set that policy
        /// selectors match against — needed by the felix calc graph
        /// (`ResourceUpdate`), but otherwise inert: the v1-model purpose-built
        /// syncers (`syncers::to_v1_events`) do not read it.
        labels: BTreeMap<String, String>,
    },
}

impl KddBackend {
    /// Watch a resource kind, yielding a stream of [`SyncerEvent`]s. The stream
    /// begins with `Status(ResyncInProgress)`, delivers the initial snapshot as
    /// `New` updates, emits `Status(InSync)` once the snapshot is complete, and
    /// then streams live `Updated`/`Deleted` events. It re-lists (and repeats the
    /// cycle) automatically on watch desync.
    pub fn watch(
        &self,
        kind: ResourceKind,
        namespace: Option<&str>,
    ) -> impl Stream<Item = Result<SyncerEvent, CasError>> {
        let api = self.dynamic_api(kind, namespace);
        // `scan` threads per-kind [`WatchState`] through the watcher stream so a
        // re-list (a fresh Init..InitDone after a desync) can synthesize deletes
        // for keys that vanished while disconnected — the state persists across
        // re-lists because the underlying `watcher` is one continuous stream.
        watcher(api, watcher::Config::default())
            .scan(WatchState::default(), move |state, res| {
                let out = match res {
                    Ok(ev) => Ok(state.on_event(kind, ev)),
                    Err(e) => Err(CasError::Backend(e.to_string())),
                };
                futures::future::ready(Some(out))
            })
            .map_ok(|evs| futures::stream::iter(evs.into_iter().map(Ok::<_, CasError>)))
            .try_flatten()
    }
}

/// The last content delivered downstream for a key, retained so a *synthetic*
/// delete (emitted at InitDone for a key that vanished during a re-list) can carry
/// a faithful object — just as a live `watcher::Event::Delete(obj)` carries the
/// deleted object. Downstream (`syncers::process_keys`, the felix adapter) reads
/// the spec even on a delete, so an empty spec would be silently dropped.
#[derive(Clone)]
struct KnownObj {
    spec: serde_json::Value,
    revision: Revision,
    labels: BTreeMap<String, String>,
}

/// Per-kind watch state that maps `kube::runtime::watcher` events onto
/// [`SyncerEvent`]s while honoring the reflector **reset contract**.
///
/// `kube`'s `watcher` re-lists on desync, replaying `Init` → `InitApply`* →
/// `InitDone`; it does NOT emit deletes for objects that disappeared while the
/// watch was disconnected (that reconciliation is the consumer's job). Without it,
/// a resource deleted during a blip lingers downstream forever (stale policy
/// chains, endpoints, etc.). This state tracks the known key set and, at each
/// `InitDone`, emits a synthetic `Deleted` for every previously-known key absent
/// from the just-completed list.
#[derive(Default)]
struct WatchState {
    /// Keys currently believed present downstream, with last-delivered content.
    known: HashMap<Key, KnownObj>,
    /// Keys seen so far in the in-progress `Init`..`InitDone` (re)list cycle.
    seen_this_sync: HashSet<Key>,
}

impl WatchState {
    fn on_event(
        &mut self,
        kind: ResourceKind,
        ev: watcher::Event<DynamicObject>,
    ) -> Vec<SyncerEvent> {
        match ev {
            // Start of a fresh list-then-watch cycle: begin tracking which keys the
            // new list contains (do NOT drop `known` yet — it is the baseline the
            // InitDone diff removes vanished keys from).
            watcher::Event::Init => {
                self.seen_this_sync.clear();
                vec![SyncerEvent::Status(SyncStatus::ResyncInProgress)]
            }
            // One object from the (re)list snapshot.
            watcher::Event::InitApply(obj) => {
                let ev = update(kind, obj, UpdateType::New);
                if let SyncerEvent::Update { key, .. } = &ev {
                    self.seen_this_sync.insert(key.clone());
                }
                self.remember(&ev);
                vec![ev]
            }
            // Snapshot complete: emit a synthetic delete for every known key the new
            // list did NOT contain (it vanished during the disconnect), then InSync.
            watcher::Event::InitDone => {
                let mut stale: Vec<Key> = self
                    .known
                    .keys()
                    .filter(|k| !self.seen_this_sync.contains(*k))
                    .cloned()
                    .collect();
                // HashMap iteration is unordered; sort for deterministic output.
                stale.sort_by(|a, b| key_name(a).cmp(key_name(b)));
                let mut out = Vec::with_capacity(stale.len() + 1);
                for key in stale {
                    if let Some(obj) = self.known.remove(&key) {
                        out.push(SyncerEvent::Update {
                            key,
                            spec: obj.spec,
                            revision: obj.revision,
                            update_type: UpdateType::Deleted,
                            labels: obj.labels,
                        });
                    }
                }
                out.push(SyncerEvent::Status(SyncStatus::InSync));
                out
            }
            // A live add/modify.
            watcher::Event::Apply(obj) => {
                let ev = update(kind, obj, UpdateType::Updated);
                self.remember(&ev);
                vec![ev]
            }
            // A live delete.
            watcher::Event::Delete(obj) => {
                let ev = update(kind, obj, UpdateType::Deleted);
                if let SyncerEvent::Update { key, .. } = &ev {
                    self.known.remove(key);
                }
                vec![ev]
            }
        }
    }

    /// Record the last-delivered content for an upsert (New/Updated) so a later
    /// synthetic delete can carry a faithful object.
    fn remember(&mut self, ev: &SyncerEvent) {
        if let SyncerEvent::Update {
            key,
            spec,
            revision,
            labels,
            update_type,
        } = ev
        {
            if !matches!(update_type, UpdateType::Deleted) {
                self.known.insert(
                    key.clone(),
                    KnownObj {
                        spec: spec.clone(),
                        revision: *revision,
                        labels: labels.clone(),
                    },
                );
            }
        }
    }
}

/// The resource name of a [`Key`] (for deterministic delete ordering); empty for
/// non-resource keys, which this syncer never produces.
fn key_name(key: &Key) -> &str {
    match key {
        Key::Resource { name, .. } => name.as_str(),
        _ => "",
    }
}

fn update(kind: ResourceKind, obj: DynamicObject, update_type: UpdateType) -> SyncerEvent {
    let name = obj.metadata.name.clone().unwrap_or_default();
    let namespace = obj.metadata.namespace.clone();
    let revision = obj
        .metadata
        .resource_version
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let spec = obj
        .data
        .get("spec")
        .cloned()
        .unwrap_or(serde_json::Value::Object(Default::default()));
    let labels = obj.metadata.labels.clone().unwrap_or_default();
    SyncerEvent::Update {
        key: Key::Resource {
            kind,
            namespace,
            name,
        },
        spec,
        revision,
        update_type,
        labels,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::{ObjectMeta, TypeMeta};

    fn dynamic_object(labels: Option<BTreeMap<String, String>>) -> DynamicObject {
        DynamicObject {
            types: Some(TypeMeta {
                api_version: "projectcalico.org/v3".to_string(),
                kind: "WorkloadEndpoint".to_string(),
            }),
            metadata: ObjectMeta {
                name: Some("wep1".to_string()),
                namespace: Some("ns1".to_string()),
                resource_version: Some("42".to_string()),
                labels,
                ..Default::default()
            },
            data: serde_json::json!({ "spec": { "interfaceName": "cali123" } }),
        }
    }

    #[test]
    fn update_surfaces_metadata_labels() {
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "web".to_string());
        let obj = dynamic_object(Some(labels.clone()));

        let ev = update(ResourceKind::WorkloadEndpoint, obj, UpdateType::New);

        match ev {
            SyncerEvent::Update {
                labels: got_labels, ..
            } => assert_eq!(got_labels, labels),
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn update_defaults_labels_to_empty_map_when_absent() {
        let obj = dynamic_object(None);

        let ev = update(ResourceKind::WorkloadEndpoint, obj, UpdateType::New);

        match ev {
            SyncerEvent::Update {
                labels: got_labels, ..
            } => assert!(got_labels.is_empty()),
            other => panic!("expected Update, got {other:?}"),
        }
    }

    // ---- WatchState: reflector reset semantics ---------------------------

    const WEP: ResourceKind = ResourceKind::WorkloadEndpoint;

    fn obj_named(name: &str, rv: &str, iface: &str) -> DynamicObject {
        DynamicObject {
            types: Some(TypeMeta {
                api_version: "projectcalico.org/v3".to_string(),
                kind: "WorkloadEndpoint".to_string(),
            }),
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("nettest".to_string()),
                resource_version: Some(rv.to_string()),
                ..Default::default()
            },
            data: serde_json::json!({ "spec": { "interfaceName": iface } }),
        }
    }

    /// The `(name, update_type)` of each `Update` event (drops Status events).
    fn updates(evs: &[SyncerEvent]) -> Vec<(String, UpdateType)> {
        evs.iter()
            .filter_map(|e| match e {
                SyncerEvent::Update {
                    key: Key::Resource { name, .. },
                    update_type,
                    ..
                } => Some((name.clone(), *update_type)),
                _ => None,
            })
            .collect()
    }

    fn deleted_names(evs: &[SyncerEvent]) -> Vec<String> {
        updates(evs)
            .into_iter()
            .filter(|(_, t)| *t == UpdateType::Deleted)
            .map(|(n, _)| n)
            .collect()
    }

    #[test]
    fn initial_sync_delivers_snapshot_then_insync_with_no_deletes() {
        let mut st = WatchState::default();
        assert_eq!(
            st.on_event(WEP, watcher::Event::Init),
            vec![SyncerEvent::Status(SyncStatus::ResyncInProgress)]
        );
        let a = st.on_event(WEP, watcher::Event::InitApply(obj_named("a", "1", "calia")));
        let b = st.on_event(WEP, watcher::Event::InitApply(obj_named("b", "1", "calib")));
        let done = st.on_event(WEP, watcher::Event::InitDone);

        assert_eq!(updates(&a), vec![("a".to_string(), UpdateType::New)]);
        assert_eq!(updates(&b), vec![("b".to_string(), UpdateType::New)]);
        assert!(
            deleted_names(&done).is_empty(),
            "first sync must not synthesize deletes"
        );
        assert_eq!(done.last(), Some(&SyncerEvent::Status(SyncStatus::InSync)));
    }

    #[test]
    fn relist_emits_synthetic_delete_for_vanished_key() {
        let mut st = WatchState::default();
        st.on_event(WEP, watcher::Event::Init);
        st.on_event(WEP, watcher::Event::InitApply(obj_named("a", "1", "calia")));
        st.on_event(WEP, watcher::Event::InitApply(obj_named("b", "1", "calib")));
        st.on_event(WEP, watcher::Event::InitDone);

        // Watch desyncs; the re-list omits `b` (deleted while disconnected).
        st.on_event(WEP, watcher::Event::Init);
        let a2 = st.on_event(WEP, watcher::Event::InitApply(obj_named("a", "2", "calia")));
        let done = st.on_event(WEP, watcher::Event::InitDone);

        assert_eq!(updates(&a2), vec![("a".to_string(), UpdateType::New)]);
        assert_eq!(
            deleted_names(&done),
            vec!["b".to_string()],
            "the vanished key must be delivered as a delete at InitDone"
        );
        assert_eq!(done.last(), Some(&SyncerEvent::Status(SyncStatus::InSync)));
    }

    #[test]
    fn synthetic_delete_carries_last_known_spec_and_labels() {
        let mut st = WatchState::default();
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "web".to_string());
        let mut b = obj_named("b", "5", "calib");
        b.metadata.labels = Some(labels);

        st.on_event(WEP, watcher::Event::Init);
        st.on_event(WEP, watcher::Event::InitApply(b));
        st.on_event(WEP, watcher::Event::InitDone);

        // Re-list without `b`.
        st.on_event(WEP, watcher::Event::Init);
        let done = st.on_event(WEP, watcher::Event::InitDone);

        let (spec, del_labels) = done
            .iter()
            .find_map(|e| match e {
                SyncerEvent::Update {
                    key: Key::Resource { name, .. },
                    spec,
                    labels,
                    update_type: UpdateType::Deleted,
                    ..
                } if name == "b" => Some((spec.clone(), labels.clone())),
                _ => None,
            })
            .expect("synthetic delete for b");
        // Downstream deserializes the spec even on a delete, so it must be faithful.
        assert_eq!(spec["interfaceName"], "calib");
        assert_eq!(del_labels.get("app").map(String::as_str), Some("web"));
    }

    #[test]
    fn live_delete_then_relist_does_not_double_delete() {
        let mut st = WatchState::default();
        st.on_event(WEP, watcher::Event::Init);
        st.on_event(WEP, watcher::Event::InitApply(obj_named("a", "1", "calia")));
        st.on_event(WEP, watcher::Event::InitApply(obj_named("b", "1", "calib")));
        st.on_event(WEP, watcher::Event::InitDone);

        let d = st.on_event(WEP, watcher::Event::Delete(obj_named("b", "3", "calib")));
        assert_eq!(deleted_names(&d), vec!["b".to_string()]);

        // Re-list with only `a`: `b` is already gone, so no second delete.
        st.on_event(WEP, watcher::Event::Init);
        st.on_event(WEP, watcher::Event::InitApply(obj_named("a", "4", "calia")));
        let done = st.on_event(WEP, watcher::Event::InitDone);
        assert!(
            deleted_names(&done).is_empty(),
            "an already-deleted key must not be re-deleted on re-list"
        );
    }

    #[test]
    fn relist_with_all_keys_present_emits_no_deletes() {
        let mut st = WatchState::default();
        st.on_event(WEP, watcher::Event::Init);
        st.on_event(WEP, watcher::Event::InitApply(obj_named("a", "1", "calia")));
        st.on_event(WEP, watcher::Event::InitApply(obj_named("b", "1", "calib")));
        st.on_event(WEP, watcher::Event::InitDone);

        st.on_event(WEP, watcher::Event::Init);
        st.on_event(WEP, watcher::Event::InitApply(obj_named("a", "2", "calia")));
        st.on_event(WEP, watcher::Event::InitApply(obj_named("b", "2", "calib")));
        let done = st.on_event(WEP, watcher::Event::InitDone);
        assert!(
            deleted_names(&done).is_empty(),
            "keys still present on re-list must survive"
        );
    }
}
