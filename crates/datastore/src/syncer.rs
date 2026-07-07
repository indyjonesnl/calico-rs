//! Watch + watcher-syncer: turns the Kubernetes list-then-watch stream into an
//! ordered sequence of typed [`SyncerEvent`]s with a sync-status state machine.
//!
//! Built on `kube::runtime::watcher`, which does the list-then-watch and
//! automatic re-list on desync. We map its events onto Calico's syncer model
//! (`libcalico-go` watchersyncer): a resync produces `ResyncInProgress`, the
//! initial list snapshot, then `InSync`; subsequent changes are incremental
//! `Apply`/`Delete` updates.

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
        watcher(api, watcher::Config::default())
            .map(move |res| match res {
                Ok(ev) => Ok(events_for(kind, ev)),
                Err(e) => Err(CasError::Backend(e.to_string())),
            })
            .map_ok(|evs| futures::stream::iter(evs.into_iter().map(Ok::<_, CasError>)))
            .try_flatten()
    }
}

fn events_for(kind: ResourceKind, ev: watcher::Event<DynamicObject>) -> Vec<SyncerEvent> {
    match ev {
        // Start of a fresh list-then-watch cycle.
        watcher::Event::Init => vec![SyncerEvent::Status(SyncStatus::ResyncInProgress)],
        // One object from the initial snapshot.
        watcher::Event::InitApply(obj) => vec![update(kind, obj, UpdateType::New)],
        // Initial snapshot complete.
        watcher::Event::InitDone => vec![SyncerEvent::Status(SyncStatus::InSync)],
        // A live add/modify.
        watcher::Event::Apply(obj) => vec![update(kind, obj, UpdateType::Updated)],
        // A live delete.
        watcher::Event::Delete(obj) => vec![update(kind, obj, UpdateType::Deleted)],
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
    SyncerEvent::Update {
        key: Key::Resource {
            kind,
            namespace,
            name,
        },
        spec,
        revision,
        update_type,
    }
}
