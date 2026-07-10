//! Multi-kind watcher-syncer: watch several resource kinds at once and merge
//! them into ONE ordered [`SyncerEvent`] stream with a single COMBINED
//! sync-status state machine — the `libcalico-go` watchersyncer invariant that
//! downstream consumers (update processors, purpose-built syncers, typha, felix)
//! depend on.
//!
//! Built on the per-kind [`KddBackend::watch`] in [`crate::syncer`]. Each kind's
//! watch already emits `Status(ResyncInProgress)` → snapshot as `New` updates →
//! `Status(InSync)` → live `Updated`/`Deleted`, re-listing on desync. This layer
//! tags each kind's events with a kind index, merges the streams, and runs
//! [`Combined`] to collapse the per-kind statuses into one combined status:
//!
//! - Exactly one `Status(ResyncInProgress)` at the start (before the first
//!   snapshot item), never one per kind.
//! - Every kind's snapshot items pass through as `Update{..New}`; the per-kind
//!   `ResyncInProgress`/`InSync` transitions are consumed/suppressed.
//! - Exactly one `Status(InSync)`, emitted only once EVERY watched kind has
//!   reached its first `InSync` (its initial snapshot is complete).
//! - After combined `InSync`, live `Updated`/`Deleted` from all kinds pass
//!   through as they arrive.
//! - A kind that desyncs and re-lists after combined `InSync` re-applies its
//!   snapshot as ordinary updates; the combined status does NOT drop back to
//!   `ResyncInProgress` (matching upstream — once in-sync, always in-sync) and
//!   the re-list's per-kind status churn is suppressed.
//! - An empty kinds set is vacuously in sync: `ResyncInProgress` then `InSync`.

use futures::stream::{self, BoxStream};
use futures::{Stream, StreamExt, TryStreamExt};

use crate::cas::CasError;
use crate::kdd::KddBackend;
use crate::model::ResourceKind;
use crate::syncer::{SyncStatus, SyncerEvent};

/// Watch a set of `(kind, namespace)` pairs and return a single merged stream
/// with one combined sync-status state machine (see the module docs). Pure
/// orchestration over the per-kind [`KddBackend::watch`]; it does not duplicate
/// the event-mapping logic.
pub fn watch_many(
    backend: &KddBackend,
    kinds: &[(ResourceKind, Option<String>)],
) -> impl Stream<Item = Result<SyncerEvent, CasError>> + 'static {
    // Tag each per-kind stream with its index and box it (SelectAll needs Unpin
    // streams; the boxed streams are 'static because the underlying watch owns a
    // cloned client).
    let streams: Vec<BoxStream<'static, Result<(usize, SyncerEvent), CasError>>> = kinds
        .iter()
        .enumerate()
        .map(|(idx, (kind, namespace))| {
            backend
                .watch(*kind, namespace.as_deref())
                .map(move |res| res.map(move |ev| (idx, ev)))
                .boxed()
        })
        .collect();
    let merged = stream::select_all(streams);
    combine(kinds.len(), merged)
}

/// The combined sync-status state machine, factored out of the stream plumbing
/// so it can be unit-tested over synthetic per-kind event streams without a
/// cluster. `per_kind_insync[i]` latches once kind `i` first reaches `InSync`;
/// `combined_insync` latches once every kind has.
struct Combined {
    per_kind_insync: Vec<bool>,
    combined_insync: bool,
}

impl Combined {
    fn new(num_kinds: usize) -> Self {
        Self {
            per_kind_insync: vec![false; num_kinds],
            combined_insync: false,
        }
    }

    /// Events to emit before consuming any input: the single leading
    /// `ResyncInProgress`, plus an immediate `InSync` when there are no kinds
    /// (vacuously in sync).
    fn start(&mut self) -> Vec<SyncerEvent> {
        let mut out = vec![SyncerEvent::Status(SyncStatus::ResyncInProgress)];
        if self.per_kind_insync.is_empty() {
            self.combined_insync = true;
            out.push(SyncerEvent::Status(SyncStatus::InSync));
        }
        out
    }

    /// Handle one tagged per-kind event, returning the events to surface (empty
    /// ⇒ suppressed).
    fn on(&mut self, idx: usize, ev: SyncerEvent) -> Vec<SyncerEvent> {
        match ev {
            // Per-kind resync markers never surface: the combined resync was
            // already emitted by `start`, and a post-InSync re-list must not
            // reset the combined status.
            SyncerEvent::Status(SyncStatus::ResyncInProgress)
            | SyncerEvent::Status(SyncStatus::WaitForDatastore) => Vec::new(),
            SyncerEvent::Status(SyncStatus::InSync) => {
                self.per_kind_insync[idx] = true;
                // Emit the combined InSync exactly once, when the last kind
                // completes its initial snapshot. Later per-kind InSyncs (from
                // re-lists) are suppressed.
                if !self.combined_insync && self.per_kind_insync.iter().all(|&b| b) {
                    self.combined_insync = true;
                    vec![SyncerEvent::Status(SyncStatus::InSync)]
                } else {
                    Vec::new()
                }
            }
            // Data updates (snapshot `New`s and live `Updated`/`Deleted`) always
            // pass through in arrival order.
            update @ SyncerEvent::Update { .. } => vec![update],
        }
    }
}

/// Run [`Combined`] over a merged, kind-tagged input stream, producing the
/// combined [`SyncerEvent`] stream. Generic over the input stream so tests can
/// drive it with synthetic `futures::stream::iter` inputs.
fn combine<S>(num_kinds: usize, input: S) -> impl Stream<Item = Result<SyncerEvent, CasError>>
where
    S: Stream<Item = Result<(usize, SyncerEvent), CasError>>,
{
    let mut machine = Combined::new(num_kinds);
    let prologue = stream::iter(machine.start().into_iter().map(Ok));
    let body = input
        .map_ok(move |(idx, ev)| stream::iter(machine.on(idx, ev).into_iter().map(Ok)))
        .try_flatten();
    prologue.chain(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Key;
    use futures::StreamExt;
    use serde_json::json;

    use crate::syncer::UpdateType;

    fn status(s: SyncStatus) -> SyncerEvent {
        SyncerEvent::Status(s)
    }

    fn upd(name: &str, ut: UpdateType) -> SyncerEvent {
        SyncerEvent::Update {
            key: Key::Resource {
                kind: ResourceKind::IpPool,
                namespace: None,
                name: name.to_string(),
            },
            spec: json!({}),
            revision: 1,
            update_type: ut,
            labels: Default::default(),
        }
    }

    /// Drive `combine` over a synthetic tagged input and collect the output.
    async fn run(num_kinds: usize, events: Vec<(usize, SyncerEvent)>) -> Vec<SyncerEvent> {
        let input = stream::iter(events.into_iter().map(Ok::<_, CasError>));
        combine(num_kinds, input)
            .map(|r| r.expect("combine yields no errors on Ok inputs"))
            .collect()
            .await
    }

    fn count_status(out: &[SyncerEvent], s: SyncStatus) -> usize {
        out.iter().filter(|e| **e == SyncerEvent::Status(s)).count()
    }

    fn index_of(out: &[SyncerEvent], e: &SyncerEvent) -> usize {
        out.iter().position(|x| x == e).expect("event present")
    }

    #[tokio::test]
    async fn two_kinds_combined_status_and_ordering() {
        use SyncStatus::*;
        use UpdateType::*;
        let out = run(
            2,
            vec![
                (0, status(ResyncInProgress)), // per-kind resync: suppressed
                (0, upd("a1", New)),           // kind 0 snapshot
                (1, status(ResyncInProgress)), // per-kind resync: suppressed
                (1, upd("b1", New)),           // kind 1 snapshot
                (0, status(InSync)),           // only kind 0 in-sync: no combined InSync yet
                (0, upd("a2", New)),           // late snapshot item from kind 0
                (1, status(InSync)),           // both in-sync now: combined InSync
                (0, upd("a1", Updated)),       // live update after InSync
                (1, upd("b1", Deleted)),       // live delete after InSync
            ],
        )
        .await;

        // Exactly one combined ResyncInProgress (leading) and one InSync.
        assert_eq!(count_status(&out, ResyncInProgress), 1);
        assert_eq!(count_status(&out, InSync), 1);
        // ResyncInProgress is first.
        assert_eq!(out[0], status(ResyncInProgress));

        // All four snapshot News appear and precede the combined InSync.
        let insync_at = index_of(&out, &status(InSync));
        for name in ["a1", "b1", "a2"] {
            let at = index_of(&out, &upd(name, New));
            assert!(
                at < insync_at,
                "snapshot New {name} must precede combined InSync"
            );
        }
        // Live updates follow the combined InSync.
        assert!(index_of(&out, &upd("a1", Updated)) > insync_at);
        assert!(index_of(&out, &upd("b1", Deleted)) > insync_at);

        // Full expected sequence (per-kind statuses fully suppressed).
        assert_eq!(
            out,
            vec![
                status(ResyncInProgress),
                upd("a1", New),
                upd("b1", New),
                upd("a2", New),
                status(InSync),
                upd("a1", Updated),
                upd("b1", Deleted),
            ]
        );
    }

    #[tokio::test]
    async fn combined_insync_waits_for_every_kind() {
        use SyncStatus::*;
        use UpdateType::*;
        // Kind 0 reaches InSync long before kind 1; no combined InSync until both.
        let out = run(
            2,
            vec![
                (0, upd("a", New)),
                (0, status(InSync)),
                (1, upd("b", New)),
                (1, status(InSync)),
            ],
        )
        .await;
        assert_eq!(
            out,
            vec![
                status(ResyncInProgress),
                upd("a", New),
                upd("b", New),
                status(InSync),
            ]
        );
    }

    #[tokio::test]
    async fn post_insync_relist_does_not_reset_combined_status() {
        use SyncStatus::*;
        use UpdateType::*;
        let out = run(
            1,
            vec![
                (0, upd("a", New)),
                (0, status(InSync)),    // combined InSync
                (0, upd("a", Updated)), // live
                // --- kind 0 watch desyncs and re-lists ---
                (0, status(ResyncInProgress)), // suppressed: must NOT reset combined
                (0, upd("a", New)),            // re-listed snapshot, surfaced as an update
                (0, status(InSync)),           // suppressed: no second combined InSync
                (0, upd("a", Updated)),        // live again
            ],
        )
        .await;

        // Combined status transitions happen exactly once each and never revert.
        assert_eq!(count_status(&out, ResyncInProgress), 1);
        assert_eq!(count_status(&out, InSync), 1);
        // The re-list's snapshot item is still delivered (as data), after InSync.
        let insync_at = index_of(&out, &status(InSync));
        let relist_items: Vec<usize> = out
            .iter()
            .enumerate()
            .filter(|(_, e)| **e == upd("a", New))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            relist_items.len(),
            2,
            "both the initial and re-list New surface"
        );
        assert!(
            relist_items[1] > insync_at,
            "re-list New arrives after combined InSync"
        );

        assert_eq!(
            out,
            vec![
                status(ResyncInProgress),
                upd("a", New),
                status(InSync),
                upd("a", Updated),
                upd("a", New),
                upd("a", Updated),
            ]
        );
    }

    #[tokio::test]
    async fn empty_kinds_is_vacuously_in_sync() {
        use SyncStatus::*;
        let out = run(0, vec![]).await;
        assert_eq!(out, vec![status(ResyncInProgress), status(InSync)]);
    }
}
