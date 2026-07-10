//! The felix [`IpSetManager`]: materializes calc-graph IP sets as nftables
//! **named sets** (the ipset equivalent), applying only the *delta* between
//! desired and last-programmed membership.
//!
//! Modelled on upstream `felix/dataplane/linux/ipsets`. The calc graph emits
//! [`proto::ToDataplane::IpSetUpdate`] (full membership), [`IpSetDeltaUpdate`]
//! (incremental add/remove), and [`ToDataplane::IpSetRemove`]. Each IP set gets a
//! [`reconcile::SetDeltaTracker`] of its members (desired vs. programmed);
//! [`Manager::complete_deferred_work`] computes the pending adds/removes and
//! programs *only those* into the kernel via `nft add/delete element`, then marks
//! the tracker in sync so the next round's diff is minimal. Re-running with no
//! change programs nothing.
//!
//! ## Table & naming — coordination with the policy/endpoint manager (T058)
//!
//! The named sets live in the shared policy table [`TABLE_FAMILY`] `inet` /
//! [`TABLE_NAME`] `calico` — the same table the endpoint policy chains
//! (`cali-input`, `cali-pi-*`) are rendered into (see `policy_render`), so a rule
//! can reference a set with `ip saddr @<name>`. The set name is derived *only*
//! from the IP-set id via [`set_name_for`] (a deterministic, nft-safe token), so
//! the endpoint manager computes the identical name from the same id.
//!
//! Programming is **incremental** (`add set` / `add element` / `delete element` /
//! `delete set`) and never flushes the table, so the sets coexist with whatever
//! the policy renderer puts in the same table. (Coordination note for T058: if the
//! policy path programs its chains with a table-flushing declarative `apply`, it
//! must re-declare the sets in the same document, or move to incremental
//! programming — otherwise a flush would drop these sets. This manager itself
//! never flushes.)
//!
//! ## IpSetKind → nft set type
//!
//! - [`IpSetKind::Ip`]   → `type ipv4_addr` — bare addresses (`hash:ip`).
//! - [`IpSetKind::Net`]  → `type ipv4_addr; flags interval` — CIDRs (`hash:net`).
//! - [`IpSetKind::IpAndPort`] → `type ipv4_addr . inet_service` — the concatenated
//!   named-port encoding (`hash:ip,port`). **Minimal / deferred**: the set is
//!   declared with the concatenated type and members are programmed verbatim
//!   (the calc graph is expected to emit `ADDR . PORT` element syntax); no member
//!   re-encoding is done here yet.
//!
//! IPv4 first: the type prefix is `ipv4_addr`. IPv6 support (an `ipv6_addr` set
//! under a distinct name) is deferred — documented as a follow-up.
//!
//! `on_update` only mutates in-memory desired state (cheap, no I/O); all kernel
//! work happens in the async `complete_deferred_work`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use proto::{IpSetDeltaUpdate, IpSetId, IpSetKind, IpSetUpdate, ToDataplane};
use reconcile::SetDeltaTracker;
use sha2::{Digest, Sha256};

use crate::dataplane::{DataplaneError, Manager};

/// Family of the nft table the named sets live in (shared with the policy chains).
pub const TABLE_FAMILY: &str = "inet";
/// Name of the nft table the named sets live in (shared with the policy chains).
pub const TABLE_NAME: &str = "calico";

/// Derive the deterministic, nft-safe named-set name for an IP-set id.
///
/// The endpoint/policy manager (T058) references sets by this exact mapping, so it
/// must depend only on the id (never on kind or membership). The token is the
/// URL-safe base64 (no padding) of the first 12 bytes of SHA-256(id) — 16 chars,
/// 96 bits, collision-resistant — behind a `cali40` prefix (echoing upstream's
/// IPv4-set naming). base64url uses only `[A-Za-z0-9_-]`, all valid in nft
/// identifiers.
pub fn set_name_for(ip_set_id: &str) -> String {
    let digest = Sha256::digest(ip_set_id.as_bytes());
    let token = URL_SAFE_NO_PAD.encode(&digest[..12]);
    format!("cali40{token}")
}

/// The nft `type ...` (and optional `flags`) declaration for an [`IpSetKind`].
fn set_type_decl(kind: IpSetKind) -> &'static str {
    match kind {
        IpSetKind::Ip => "type ipv4_addr",
        IpSetKind::Net => "type ipv4_addr; flags interval",
        IpSetKind::IpAndPort => "type ipv4_addr . inet_service",
    }
}

/// The nft side of named-set programming, factored out so the delta logic is
/// unit-testable with a spy. The production impl is [`NftSetProgrammer`].
#[async_trait::async_trait(?Send)]
pub trait SetProgrammer {
    /// Feed a full `nft -f -` document (a batch of `add/delete` commands) to the
    /// kernel. Atomic: nft applies the whole document or none of it.
    async fn apply_document(&self, doc: &str) -> Result<(), String>;
}

/// Per-set desired-vs-programmed membership plus its kind.
struct SetState {
    kind: IpSetKind,
    tracker: SetDeltaTracker<String>,
    /// Whether this set has ever been successfully created in the kernel (an
    /// `add set` was actually applied for it). A set that only ever existed in
    /// memory (e.g. created and removed again before the first
    /// `complete_deferred_work`) must never be targeted by a kernel `delete
    /// set` — nft would error deleting a set it never had, failing the whole
    /// atomic batch and stalling the reconcile loop (T057 review finding 1).
    programmed: bool,
}

impl SetState {
    fn new(kind: IpSetKind) -> Self {
        Self {
            kind,
            tracker: SetDeltaTracker::new(),
            programmed: false,
        }
    }
}

/// Reconciles the kernel's nftables named sets to the calc graph's desired IP
/// sets, applying only the delta. Generic over [`SetProgrammer`] so tests inject a
/// spy; production uses [`IpSetManager::with_nft`].
pub struct IpSetManager<P: SetProgrammer> {
    /// Desired sets keyed by IP-set id (BTree ⇒ deterministic programming order).
    sets: BTreeMap<IpSetId, SetState>,
    /// Sets removed from `sets` that still need a kernel `delete set` — i.e.
    /// they were [`SetState::programmed`] at the time of removal. The whole
    /// state (not just the id) is retained so that a subsequent `IpSetUpdate`/
    /// `IpSetDeltaUpdate` for the same id before the delete is applied can
    /// resurrect it *with its programmed dataplane membership intact*, so the
    /// delta correctly deletes any members no longer desired (T057 review
    /// finding 2) instead of starting from a fresh, empty dataplane view.
    ///
    /// Invariant: every entry here has `programmed == true` — a set that was
    /// never programmed is dropped outright on removal (no entry, no kernel
    /// op; see finding 1).
    removed: BTreeMap<IpSetId, SetState>,
    programmer: P,
}

impl<P: SetProgrammer> IpSetManager<P> {
    /// Build a manager over an explicit programmer (used in tests).
    pub fn new(programmer: P) -> Self {
        Self {
            sets: BTreeMap::new(),
            removed: BTreeMap::new(),
            programmer,
        }
    }

    /// Number of desired sets currently tracked (test/introspection helper).
    pub fn desired_len(&self) -> usize {
        self.sets.len()
    }

    /// Total pending element ops (additions + removals across all sets) plus sets
    /// awaiting deletion — zero once fully reconciled.
    pub fn pending_count(&self) -> usize {
        let elems: usize = self
            .sets
            .values()
            .map(|s| s.tracker.pending_addition_count() + s.tracker.pending_removal_count())
            .sum();
        elems + self.removed.len()
    }

    /// Pending additions for one set's programmed name (test helper); `None` if the
    /// id is unknown.
    pub fn pending_additions(&self, id: &str) -> Option<usize> {
        self.sets
            .get(id)
            .map(|s| s.tracker.pending_addition_count())
    }

    /// Pending removals for one set (test helper).
    pub fn pending_removals(&self, id: &str) -> Option<usize> {
        self.sets.get(id).map(|s| s.tracker.pending_removal_count())
    }

    /// Build the batched nft document for the current delta, or `None` if there is
    /// nothing to program. Does not mutate tracker state. Also returns the ids
    /// that got an `add set` line this round (i.e. that are about to be
    /// programmed into the kernel for the first time or re-touched), so the
    /// caller can mark them [`SetState::programmed`] once the apply succeeds.
    fn render_delta_doc(&self) -> Option<(String, Vec<IpSetId>)> {
        // A desired set that has never been created in the kernel needs an
        // `add set` even with ZERO members and no member deltas (Bug 1): the set
        // CONTAINER must exist so a policy chain's `ip saddr @<set>` reference
        // resolves. `pending_count` only tracks element/removal ops, so consult
        // the un-created desired sets separately or an empty-but-referenced set
        // would never be programmed.
        let uncreated = self.sets.values().filter(|s| !s.programmed).count();
        if self.pending_count() == 0 && uncreated == 0 {
            return None;
        }
        let mut doc = String::new();
        // Ensure the shared table exists (`add` is idempotent — no flush).
        doc.push_str(&format!("add table {TABLE_FAMILY} {TABLE_NAME}\n"));

        let mut touched = Vec::new();
        for (id, state) in &self.sets {
            let adds: Vec<&String> = state.tracker.iter_pending_additions().collect();
            let dels: Vec<&String> = state.tracker.iter_pending_removals().collect();
            // Emit the set container when it has member deltas OR has never been
            // created yet (the empty-but-desired case). An already-created set
            // with no deltas is skipped, keeping re-apply idempotent.
            if adds.is_empty() && dels.is_empty() && state.programmed {
                continue;
            }
            touched.push(id.clone());
            let name = set_name_for(id);
            // `add set` is idempotent: creates the set if absent, no-op if present.
            doc.push_str(&format!(
                "add set {TABLE_FAMILY} {TABLE_NAME} {name} {{ {}; }}\n",
                set_type_decl(state.kind)
            ));
            if !adds.is_empty() {
                let elems = join_elements(&adds);
                doc.push_str(&format!(
                    "add element {TABLE_FAMILY} {TABLE_NAME} {name} {{ {elems} }}\n"
                ));
            }
            if !dels.is_empty() {
                let elems = join_elements(&dels);
                doc.push_str(&format!(
                    "delete element {TABLE_FAMILY} {TABLE_NAME} {name} {{ {elems} }}\n"
                ));
            }
        }

        // Only sets that were actually programmed into the kernel are eligible
        // to land here (see the `removed` field invariant) — a set dropped
        // before it was ever created must never get a kernel `delete set`.
        for id in self.removed.keys() {
            let name = set_name_for(id);
            doc.push_str(&format!("delete set {TABLE_FAMILY} {TABLE_NAME} {name}\n"));
        }
        Some((doc, touched))
    }
}

/// Join set elements into an nft `{ a, b, c }` body.
fn join_elements(elems: &[&String]) -> String {
    elems
        .iter()
        .map(|e| e.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

impl IpSetManager<NftSetProgrammer> {
    /// Build a production manager that programs the kernel via `nft -f -`.
    pub fn with_nft() -> Self {
        Self::new(NftSetProgrammer)
    }
}

#[async_trait::async_trait(?Send)]
impl<P: SetProgrammer> Manager for IpSetManager<P> {
    fn on_update(&mut self, msg: &ToDataplane) {
        match msg {
            ToDataplane::IpSetUpdate(IpSetUpdate { id, kind, members }) => {
                // A (re)definition cancels any pending removal. If the removed
                // set was still awaiting its kernel `delete set`, resurrect its
                // SetState (tracker and all) rather than starting fresh, so its
                // programmed dataplane membership isn't forgotten — otherwise a
                // later delta would fail to clean up members that are still
                // programmed in the kernel but no longer desired.
                if let Some(resurrected) = self.removed.remove(id) {
                    self.sets.insert(id.clone(), resurrected);
                }
                let state = self
                    .sets
                    .entry(id.clone())
                    .or_insert_with(|| SetState::new(*kind));
                state.kind = *kind;
                state.tracker.replace_desired(members.iter().cloned());
            }
            ToDataplane::IpSetDeltaUpdate(IpSetDeltaUpdate {
                id,
                added_members,
                removed_members,
            }) => {
                if let Some(resurrected) = self.removed.remove(id) {
                    self.sets.insert(id.clone(), resurrected);
                }
                // A delta before the full definition is unexpected; default the
                // kind to `Ip` so we don't drop the update.
                let state = self
                    .sets
                    .entry(id.clone())
                    .or_insert_with(|| SetState::new(IpSetKind::Ip));
                for m in added_members {
                    state.tracker.add_desired(m.clone());
                }
                for m in removed_members {
                    state.tracker.remove_desired(m);
                }
            }
            // Drop desired state. A set that was never programmed into the
            // kernel is simply dropped — there is nothing to delete, and
            // emitting a kernel `delete set` for it would make nft error on a
            // set that never existed, failing the whole atomic batch and
            // stalling the reconcile loop. Only a set that WAS programmed is
            // retained (in `removed`) so its kernel counterpart gets deleted.
            ToDataplane::IpSetRemove(id) => {
                if let Some(state) = self.sets.remove(id) {
                    if state.programmed {
                        self.removed.insert(id.clone(), state);
                    }
                }
            }
            _ => {}
        }
    }

    async fn complete_deferred_work(&mut self) -> Result<(), DataplaneError> {
        let Some((doc, touched)) = self.render_delta_doc() else {
            return Ok(()); // Fully in sync — program nothing (idempotent).
        };

        // Single atomic apply. On failure, return Err *without* committing the
        // trackers so the framework retries with state intact.
        self.programmer
            .apply_document(&doc)
            .await
            .map_err(DataplaneError::new)?;

        // Commit: mark every set actually touched this round (i.e. that got an
        // `add set` line) as programmed, so a later removal knows a kernel
        // `delete set` is required.
        for id in &touched {
            if let Some(state) = self.sets.get_mut(id) {
                state.programmed = true;
            }
        }
        // dataplane == desired for every set; drop the now-deleted sets.
        for state in self.sets.values_mut() {
            state.tracker.mark_in_sync();
        }
        self.removed.clear();
        Ok(())
    }
}

/// `nft`-backed [`SetProgrammer`] that feeds the batched document to `nft -f -`
/// via [`crate::nft::apply_ruleset`], off the async executor.
pub struct NftSetProgrammer;

#[async_trait::async_trait(?Send)]
impl SetProgrammer for NftSetProgrammer {
    async fn apply_document(&self, doc: &str) -> Result<(), String> {
        let doc = doc.to_owned();
        tokio::task::spawn_blocking(move || crate::nft::apply_ruleset(&doc))
            .await
            .map_err(|e| format!("nft apply task join: {e}"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A spy programmer recording every applied nft document so tests can assert
    /// exactly which ops the delta produced. Cloneable (shared inner). A `fail`
    /// toggle drives the retry test.
    #[derive(Clone, Default)]
    struct SpyProgrammer {
        inner: Rc<SpyInner>,
    }

    #[derive(Default)]
    struct SpyInner {
        docs: RefCell<Vec<String>>,
        fail: RefCell<bool>,
    }

    impl SpyProgrammer {
        fn docs(&self) -> Vec<String> {
            self.inner.docs.borrow().clone()
        }
        fn last(&self) -> String {
            self.inner.docs.borrow().last().cloned().unwrap_or_default()
        }
        fn clear(&self) {
            self.inner.docs.borrow_mut().clear();
        }
        fn set_fail(&self, v: bool) {
            *self.inner.fail.borrow_mut() = v;
        }
    }

    #[async_trait::async_trait(?Send)]
    impl SetProgrammer for SpyProgrammer {
        async fn apply_document(&self, doc: &str) -> Result<(), String> {
            if *self.inner.fail.borrow() {
                return Err("spy: injected failure".into());
            }
            self.inner.docs.borrow_mut().push(doc.to_owned());
            Ok(())
        }
    }

    fn update(id: &str, kind: IpSetKind, members: &[&str]) -> ToDataplane {
        ToDataplane::IpSetUpdate(IpSetUpdate {
            id: id.into(),
            kind,
            members: members.iter().map(|s| (*s).to_string()).collect(),
        })
    }
    fn delta(id: &str, added: &[&str], removed: &[&str]) -> ToDataplane {
        ToDataplane::IpSetDeltaUpdate(IpSetDeltaUpdate {
            id: id.into(),
            added_members: added.iter().map(|s| (*s).to_string()).collect(),
            removed_members: removed.iter().map(|s| (*s).to_string()).collect(),
        })
    }

    #[test]
    fn set_name_is_deterministic_nft_safe_and_id_only() {
        let a = set_name_for("s:selector-foo");
        assert_eq!(a, set_name_for("s:selector-foo"), "deterministic");
        assert_ne!(a, set_name_for("s:selector-bar"), "distinct ids differ");
        assert!(a.starts_with("cali40"));
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "nft-safe identifier: {a}"
        );
    }

    #[tokio::test]
    async fn full_update_programs_add_set_and_elements_once() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());

        mgr.on_update(&update("s1", IpSetKind::Ip, &["10.0.0.1", "10.0.0.2"]));
        assert_eq!(mgr.pending_additions("s1"), Some(2));
        assert!(spy.docs().is_empty(), "on_update must not touch the kernel");

        mgr.complete_deferred_work().await.unwrap();
        let doc = spy.last();
        let name = set_name_for("s1");
        assert!(doc.contains(&format!("add table {TABLE_FAMILY} {TABLE_NAME}")));
        assert!(doc.contains(&format!("add set {TABLE_FAMILY} {TABLE_NAME} {name}")));
        assert!(doc.contains("type ipv4_addr"));
        assert!(doc.contains("10.0.0.1"));
        assert!(doc.contains("10.0.0.2"));
        assert_eq!(mgr.pending_count(), 0, "reconciled after apply");
    }

    /// Bug 1 regression: a DESIRED set with ZERO members (e.g. an isolation/deny
    /// rule whose source selector currently matches nothing) must still have its
    /// set CONTAINER created in the kernel (`add set …`) on first program — even
    /// with no members and no member deltas. Otherwise a policy chain's
    /// `ip saddr @<set>` reference targets a non-existent set and nft fails
    /// ("No such file or directory"), stalling the endpoint apply forever.
    #[tokio::test]
    async fn empty_desired_set_is_still_created_on_first_program() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());

        // Zero members, yet the set is desired.
        mgr.on_update(&update("empty1", IpSetKind::Ip, &[]));
        mgr.complete_deferred_work().await.unwrap();

        let doc = spy.last();
        let name = set_name_for("empty1");
        assert!(
            doc.contains(&format!("add set {TABLE_FAMILY} {TABLE_NAME} {name}")),
            "empty-but-desired set must still emit `add set` (the container), doc: {doc:?}"
        );
        assert!(doc.contains("type ipv4_addr"), "type decl present: {doc:?}");

        // Idempotence: once created, a re-reconcile with no change is a no-op —
        // no needless re-`add set`.
        spy.clear();
        mgr.complete_deferred_work().await.unwrap();
        assert!(
            spy.docs().is_empty(),
            "already-created empty set must not be reprogrammed"
        );
    }

    #[tokio::test]
    async fn apply_twice_second_delta_is_empty() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());

        mgr.on_update(&update("s1", IpSetKind::Ip, &["10.0.0.1"]));
        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.docs().len(), 1);

        // Re-apply with no desired change: empty delta ⇒ NO nft document at all.
        spy.clear();
        mgr.complete_deferred_work().await.unwrap();
        assert!(
            spy.docs().is_empty(),
            "idempotent re-apply must program nothing"
        );
    }

    #[tokio::test]
    async fn add_then_remove_same_member_nets_nothing() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());

        // Establish an empty set first so its programmed state is known.
        mgr.on_update(&update("s1", IpSetKind::Ip, &[]));
        mgr.complete_deferred_work().await.unwrap();
        spy.clear();

        // Add then remove the SAME member before any apply: net desired change = 0.
        mgr.on_update(&delta("s1", &["10.0.0.9"], &[]));
        mgr.on_update(&delta("s1", &[], &["10.0.0.9"]));
        assert_eq!(mgr.pending_count(), 0, "add+remove cancels: empty delta");

        mgr.complete_deferred_work().await.unwrap();
        assert!(spy.docs().is_empty(), "no-op nets no nft ops");
    }

    #[tokio::test]
    async fn delta_programs_only_the_diff() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());

        mgr.on_update(&update("s1", IpSetKind::Ip, &["10.0.0.1", "10.0.0.2"]));
        mgr.complete_deferred_work().await.unwrap();
        spy.clear();

        // Add .3, remove .1 — the programmed .2 must NOT be re-added.
        mgr.on_update(&delta("s1", &["10.0.0.3"], &["10.0.0.1"]));
        assert_eq!(mgr.pending_additions("s1"), Some(1));
        assert_eq!(mgr.pending_removals("s1"), Some(1));

        mgr.complete_deferred_work().await.unwrap();
        let doc = spy.last();
        let name = set_name_for("s1");
        assert!(doc.contains(&format!(
            "add element {TABLE_FAMILY} {TABLE_NAME} {name} {{ 10.0.0.3 }}"
        )));
        assert!(doc.contains(&format!(
            "delete element {TABLE_FAMILY} {TABLE_NAME} {name} {{ 10.0.0.1 }}"
        )));
        assert!(
            !doc.contains("10.0.0.2"),
            "in-sync member must not be reprogrammed"
        );
        assert_eq!(mgr.pending_count(), 0);
    }

    #[tokio::test]
    async fn remove_set_programs_delete_set_and_drops_tracker() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());

        mgr.on_update(&update("s1", IpSetKind::Ip, &["10.0.0.1"]));
        mgr.complete_deferred_work().await.unwrap();
        spy.clear();

        mgr.on_update(&ToDataplane::IpSetRemove("s1".into()));
        assert_eq!(mgr.desired_len(), 0, "desired state dropped");
        assert_eq!(mgr.pending_count(), 1, "one set deletion pending");

        mgr.complete_deferred_work().await.unwrap();
        let name = set_name_for("s1");
        assert!(spy
            .last()
            .contains(&format!("delete set {TABLE_FAMILY} {TABLE_NAME} {name}")));
        assert_eq!(mgr.pending_count(), 0);
    }

    /// T057 review finding 1: a set that is created and removed again before it
    /// was ever programmed into the kernel must be dropped silently — no kernel
    /// `delete set` may be emitted (nft would error deleting a set it never
    /// created, failing the whole atomic batch and stalling the reconcile loop
    /// forever).
    #[tokio::test]
    async fn remove_before_first_apply_drops_silently_no_delete_set() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());

        // IpSetUpdate then IpSetRemove for the same id, both before any
        // complete_deferred_work — the set never touched the kernel.
        mgr.on_update(&update("s1", IpSetKind::Ip, &["10.0.0.1"]));
        mgr.on_update(&ToDataplane::IpSetRemove("s1".into()));

        assert_eq!(mgr.desired_len(), 0, "set gone from memory");
        assert_eq!(
            mgr.pending_count(),
            0,
            "a never-programmed set needs no kernel op at all"
        );

        mgr.complete_deferred_work().await.unwrap();
        assert!(
            spy.docs().iter().all(|d| !d.contains("delete set")),
            "no delete set for a set that was never created in the kernel"
        );
        assert!(spy.docs().is_empty(), "nothing to program at all");
    }

    /// T057 review finding 2: removing a *programmed* set and immediately
    /// re-adding it (with a smaller membership) before the next apply must not
    /// lose the kernel's previously-programmed membership — the delta must
    /// still delete the now-stale members instead of leaving them behind.
    #[tokio::test]
    async fn remove_then_readd_before_apply_deletes_stale_members() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());

        // Program s1 with two members so it is actually created in the kernel.
        mgr.on_update(&update("s1", IpSetKind::Ip, &["10.0.0.1", "10.0.0.2"]));
        mgr.complete_deferred_work().await.unwrap();
        spy.clear();

        // Remove, then immediately re-add with a smaller membership — both
        // before the next complete_deferred_work.
        mgr.on_update(&ToDataplane::IpSetRemove("s1".into()));
        mgr.on_update(&update("s1", IpSetKind::Ip, &["10.0.0.1"]));

        // The resurrected tracker must retain its programmed dataplane
        // knowledge: .1 is already there (no re-add needed), .2 is stale and
        // must be scheduled for deletion.
        assert_eq!(mgr.pending_additions("s1"), Some(0));
        assert_eq!(
            mgr.pending_removals("s1"),
            Some(1),
            ".2 must be deleted as stale"
        );

        mgr.complete_deferred_work().await.unwrap();
        let doc = spy.last();
        let name = set_name_for("s1");
        assert!(
            doc.contains(&format!(
                "delete element {TABLE_FAMILY} {TABLE_NAME} {name} {{ 10.0.0.2 }}"
            )),
            "stale member .2 must be deleted, doc: {doc}"
        );
        assert!(
            !doc.contains("delete set"),
            "the resurrected set must not be dropped from the kernel, doc: {doc}"
        );
        assert_eq!(mgr.pending_count(), 0);
    }

    #[tokio::test]
    async fn net_kind_declares_interval_flag() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());

        mgr.on_update(&update("net1", IpSetKind::Net, &["10.0.0.0/24"]));
        mgr.complete_deferred_work().await.unwrap();
        let doc = spy.last();
        assert!(doc.contains("type ipv4_addr; flags interval"));
        assert!(doc.contains("10.0.0.0/24"));
    }

    #[tokio::test]
    async fn ip_and_port_declares_concatenated_type() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());

        mgr.on_update(&update("p1", IpSetKind::IpAndPort, &["10.0.0.1 . 80"]));
        mgr.complete_deferred_work().await.unwrap();
        assert!(spy.last().contains("type ipv4_addr . inet_service"));
    }

    #[tokio::test]
    async fn full_update_replaces_membership() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());

        mgr.on_update(&update("s1", IpSetKind::Ip, &["10.0.0.1", "10.0.0.2"]));
        mgr.complete_deferred_work().await.unwrap();
        spy.clear();

        // Full replace: keep .2, drop .1, add .3.
        mgr.on_update(&update("s1", IpSetKind::Ip, &["10.0.0.2", "10.0.0.3"]));
        assert_eq!(mgr.pending_additions("s1"), Some(1)); // .3
        assert_eq!(mgr.pending_removals("s1"), Some(1)); // .1
        mgr.complete_deferred_work().await.unwrap();
        let doc = spy.last();
        assert!(doc.contains("10.0.0.3"));
        assert!(doc.contains("delete element"));
    }

    #[tokio::test]
    async fn failed_apply_retains_state_for_retry() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());

        mgr.on_update(&update("s1", IpSetKind::Ip, &["10.0.0.1"]));
        spy.set_fail(true);
        assert!(mgr.complete_deferred_work().await.is_err());
        assert_eq!(mgr.pending_count(), 1, "state retained after failure");

        spy.set_fail(false);
        mgr.complete_deferred_work().await.unwrap();
        assert!(spy.last().contains("10.0.0.1"));
        assert_eq!(mgr.pending_count(), 0);
    }

    #[tokio::test]
    async fn non_ipset_messages_are_ignored() {
        let spy = SpyProgrammer::default();
        let mut mgr = IpSetManager::new(spy.clone());
        mgr.on_update(&ToDataplane::InSync);
        assert_eq!(mgr.desired_len(), 0);
        mgr.complete_deferred_work().await.unwrap();
        assert!(spy.docs().is_empty());
    }
}
