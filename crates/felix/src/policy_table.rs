//! The felix [`PolicyTableManager`]: the single dataplane manager that OWNS the
//! entire `inet calico` nftables table and, on each reconcile, renders the
//! COMPLETE desired state (named sets + policy/profile chains + per-endpoint
//! dispatch chains + the `cali-forward` base hook) and applies it as ONE atomic,
//! self-healing `nft -f -` document.
//!
//! ## Why one full-render manager (the root-cause fix)
//!
//! The dataplane previously ran *two* separate [`crate::dataplane::Manager`]s — an
//! IP-set manager and an endpoint/chain manager — each applying incremental
//! `add/delete` deltas in its OWN `nft -f` transaction, tracking only what it had
//! itself programmed. That design was fragile:
//!
//! - On agent restart the in-memory view is empty but the kernel still holds the
//!   prior sets/chains. A stale/busy `delete set|chain` then FAILS and poisons the
//!   whole transaction, so *nothing* programs (empty table ⇒ all traffic dropped).
//! - Cross-manager ordering: a chain referenced `@<set>` the other manager had not
//!   yet committed → `No such file`.
//! - Deleting a chain still referenced → `Device or resource busy`.
//!
//! This manager fixes the class at its root. Each reconcile renders the whole
//! table and applies a single atomic document:
//!
//! ```text
//! add table inet calico          # create if absent (idempotent)
//! delete table inet calico       # now exists ⇒ never fails; removes ALL prior objects
//! add table inet calico          # a fresh, empty table
//! add set …  / add element …     # every desired set, declared FIRST
//! add chain …                    # every desired chain (all before any rule)
//! add rule …                     # every desired chain's rules (jumps/@set now resolve)
//! ```
//!
//! The `add table; delete table; add table` create-then-replace preamble wholesale
//! removes ALL prior contents — chains AND sets — so the output depends ONLY on the
//! desired state (idempotent, restart-safe, self-healing). The single table-level
//! `delete` is safe by construction (it is preceded by `add table`, so it never
//! references a missing table, even right after a restart); there are **no
//! per-object `delete set`/`delete chain` statements** that could reference a
//! stale/busy object and poison the transaction. Sets are declared before the
//! chains that reference them, so the old cross-manager ordering race is gone (one
//! document, one atomic transaction).
//!
//! (A plain `flush table` was considered but is INSUFFICIENT: it only empties each
//! chain's rules and leaves the stale chain/set objects in place — verified against
//! real `nft` — so it does not self-heal a changed topology. Hence the
//! create-then-replace.) The `cali-forward` base chain is re-declared every render
//! (its hook/priority are stable).
//!
//! ## Skip-if-unchanged
//!
//! Rendering identical desired state yields a byte-identical document. The manager
//! caches the last successfully-applied document and, when the freshly-rendered
//! document is byte-identical, programs NOTHING — so a steady state is not
//! re-flushed on every 100 ms tick. A failed apply does NOT update the cache, so
//! the framework's retry re-attempts the same document.
//!
//! `on_update` only mutates in-memory desired state (cheap, no I/O); all kernel
//! work happens in the async `complete_deferred_work`.

use std::collections::{BTreeMap, BTreeSet};

use proto::{
    IpSetDeltaUpdate, IpSetId, IpSetKind, IpSetUpdate, Policy, PolicyId, ToDataplane,
    WorkloadEndpoint, WorkloadEndpointId,
};

use crate::dataplane::{DataplaneError, Manager};
use crate::endpoint_manager::build_desired_chains;
use crate::ipset_manager::{render_set, TABLE_FAMILY, TABLE_NAME};

/// Per-set desired state: its kind plus its desired membership. A `BTreeSet` keeps
/// members ordered + de-duplicated so re-rendering identical state is byte-stable.
struct DesiredSet {
    kind: IpSetKind,
    members: BTreeSet<String>,
}

/// The nft side of table programming, factored out so the render/skip logic is
/// unit-testable with a spy. The production impl is [`NftTableApplier`].
#[async_trait::async_trait(?Send)]
pub trait TableApplier {
    /// Feed the full-table `nft -f -` document to the kernel. Atomic: nft applies
    /// the whole document or none of it.
    async fn apply_document(&self, doc: &str) -> Result<(), String>;
}

/// Reconciles the kernel's entire `inet calico` table to the calc graph's desired
/// state via one atomic full render. Generic over [`TableApplier`] so tests inject
/// a spy; production uses [`PolicyTableManager::with_nft`].
pub struct PolicyTableManager<A: TableApplier> {
    /// Desired IP sets keyed by id (BTree ⇒ deterministic render order).
    sets: BTreeMap<IpSetId, DesiredSet>,
    /// Desired policies by id (source of the per-policy chains' rules).
    policies: BTreeMap<PolicyId, Policy>,
    /// Desired profiles by id (source of the per-profile chains; supply Calico's
    /// open-by-default via the `kns.<ns>` allow profile).
    profiles: BTreeMap<String, Policy>,
    /// Desired local workload endpoints by id (source of the dispatch chains).
    endpoints: BTreeMap<WorkloadEndpointId, WorkloadEndpoint>,
    /// The last document successfully applied — the skip-if-unchanged guard.
    last_doc: Option<String>,
    /// Whether the last `complete_deferred_work` already logged the
    /// empty-desired-state info line — reset once desired state becomes
    /// non-empty, so the transition logs exactly once each way.
    logged_empty_desired_state: bool,
    applier: A,
}

impl<A: TableApplier> PolicyTableManager<A> {
    /// Build a manager over an explicit applier (used in tests).
    pub fn new(applier: A) -> Self {
        Self {
            sets: BTreeMap::new(),
            policies: BTreeMap::new(),
            profiles: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            last_doc: None,
            logged_empty_desired_state: false,
            applier,
        }
    }

    /// Number of desired sets tracked (test/introspection helper).
    pub fn set_count(&self) -> usize {
        self.sets.len()
    }

    /// Number of desired policies tracked (test/introspection helper).
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Number of desired endpoints tracked (test/introspection helper).
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Render the COMPLETE `inet calico` table as one atomic, self-healing
    /// `nft -f -` document from the current desired state. Pure: depends only on
    /// the desired maps and mutates nothing. Emits no per-object `delete`
    /// statements (only the safe table-level create-then-replace preamble).
    pub fn render(&self) -> String {
        let mut doc = String::new();
        // Create-then-replace idiom: `add table` (create if absent — idempotent),
        // then `delete table` (now guaranteed to exist, so it never fails, even
        // right after an agent restart), then `add table` again (a FRESH, empty
        // table). This wholesale-removes ALL prior contents — chains AND sets —
        // before rebuilding. `flush table` alone only empties chains' RULES and
        // leaves the (now-stale) chain/set objects behind, so it is NOT sufficient
        // for self-heal. The only `delete` here is this table-level replace, which
        // is safe by construction (preceded by `add table`) — there are NO
        // per-object `delete set`/`delete chain` statements that could reference
        // stale/busy objects and poison the transaction.
        doc.push_str(&format!("add table {TABLE_FAMILY} {TABLE_NAME}\n"));
        doc.push_str(&format!("delete table {TABLE_FAMILY} {TABLE_NAME}\n"));
        doc.push_str(&format!("add table {TABLE_FAMILY} {TABLE_NAME}\n"));

        // Sets FIRST: a chain's `ip saddr @<set>` reference must resolve, so every
        // named set (even an empty one) is declared before any rule.
        for (id, set) in &self.sets {
            render_set(
                &mut doc,
                id,
                set.kind,
                set.members.iter().map(String::as_str),
            );
        }

        let chains = build_desired_chains(&self.policies, &self.profiles, &self.endpoints);

        // Every `add chain` before any `add rule`, so jump/goto targets exist when
        // their referencing rule is added (single-transaction ordering).
        for (name, chain) in &chains {
            match chain.base_decl() {
                Some(decl) => doc.push_str(&format!(
                    "add chain {TABLE_FAMILY} {TABLE_NAME} {name} {{ {decl} }}\n"
                )),
                None => doc.push_str(&format!("add chain {TABLE_FAMILY} {TABLE_NAME} {name}\n")),
            }
        }
        for (name, chain) in &chains {
            for rule in &chain.rules {
                doc.push_str(&format!(
                    "add rule {TABLE_FAMILY} {TABLE_NAME} {name} {}\n",
                    rule.render()
                ));
            }
        }
        doc
    }
}

impl PolicyTableManager<NftTableApplier> {
    /// Build a production manager that programs the kernel via `nft -f -`.
    pub fn with_nft() -> Self {
        Self::new(NftTableApplier)
    }
}

#[async_trait::async_trait(?Send)]
impl<A: TableApplier> Manager for PolicyTableManager<A> {
    fn on_update(&mut self, msg: &ToDataplane) {
        match msg {
            ToDataplane::IpSetUpdate(IpSetUpdate { id, kind, members }) => {
                self.sets.insert(
                    id.clone(),
                    DesiredSet {
                        kind: *kind,
                        members: members.iter().cloned().collect(),
                    },
                );
            }
            ToDataplane::IpSetDeltaUpdate(IpSetDeltaUpdate {
                id,
                added_members,
                removed_members,
            }) => {
                // A delta before the full definition is unexpected; default the
                // kind to `Ip` so we don't drop the update.
                let set = self.sets.entry(id.clone()).or_insert_with(|| DesiredSet {
                    kind: IpSetKind::Ip,
                    members: BTreeSet::new(),
                });
                for m in added_members {
                    set.members.insert(m.clone());
                }
                for m in removed_members {
                    set.members.remove(m);
                }
            }
            ToDataplane::IpSetRemove(id) => {
                self.sets.remove(id);
            }
            ToDataplane::ActivePolicyUpdate { id, policy } => {
                self.policies.insert(id.clone(), policy.clone());
            }
            ToDataplane::ActivePolicyRemove(id) => {
                self.policies.remove(id);
            }
            ToDataplane::ActiveProfileUpdate { id, profile } => {
                self.profiles.insert(id.clone(), profile.clone());
            }
            ToDataplane::ActiveProfileRemove(id) => {
                self.profiles.remove(id);
            }
            ToDataplane::WorkloadEndpointUpdate { id, endpoint } => {
                self.endpoints.insert(id.clone(), endpoint.clone());
            }
            ToDataplane::WorkloadEndpointRemove(id) => {
                self.endpoints.remove(id);
            }
            _ => {}
        }
    }

    async fn complete_deferred_work(&mut self) -> Result<(), DataplaneError> {
        let doc = self.render();

        // Distinguish "the watch delivered nothing" from "apply failed": log once
        // on the transition INTO an empty desired state (and reset the guard once
        // state arrives), so an empty `inet calico` table is immediately
        // explainable from the logs.
        let desired_is_empty = self.sets.is_empty()
            && self.policies.is_empty()
            && self.profiles.is_empty()
            && self.endpoints.is_empty();
        if desired_is_empty {
            if !self.logged_empty_desired_state {
                tracing::info!("policy table: desired state is empty (no local endpoints)");
                self.logged_empty_desired_state = true;
            }
        } else {
            self.logged_empty_desired_state = false;
        }

        // Recompute the same pure chain set `render()` derived internally, purely
        // to summarize what is about to be applied (or was skipped) at debug —
        // does not affect the rendered document or the apply outcome.
        let chains = build_desired_chains(&self.policies, &self.profiles, &self.endpoints);
        let (policy_chains, profile_chains, dispatch_chains) = count_chain_kinds(chains.keys());

        // Skip-if-unchanged: a byte-identical render means the kernel already
        // matches desired — do NOT re-flush the table every tick.
        if self.last_doc.as_deref() == Some(doc.as_str()) {
            tracing::debug!(
                sets = self.sets.len(),
                policy_chains,
                profile_chains,
                dispatch_chains,
                "policy table: desired state unchanged since last apply; skipping"
            );
            return Ok(());
        }

        tracing::debug!(
            sets = self.sets.len(),
            policy_chains,
            profile_chains,
            dispatch_chains,
            "policy table: applying rendered document"
        );

        // Single atomic apply. On failure, return Err *without* caching the
        // document so the framework retries the same render with state intact.
        if let Err(e) = self.applier.apply_document(&doc).await {
            // The felix::dataplane apply loop already WARNs the manager index +
            // error; additionally surface the exact failing nft input at debug so
            // it can be inspected without reproducing the render by hand.
            let preview: String = doc.lines().take(40).collect::<Vec<_>>().join("\n");
            tracing::debug!(
                nft_document = %preview,
                "policy table: apply failed; rendered nft document (first 40 lines)"
            );
            return Err(DataplaneError::new(e));
        }

        self.last_doc = Some(doc);
        Ok(())
    }
}

/// Bucket rendered chain names into (policy, profile, dispatch) counts for the
/// debug apply summary. Pure string-prefix classification derived from the
/// deterministic names [`crate::endpoint_manager::build_desired_chains`] assigns;
/// purely for observability, no effect on what is rendered or applied. Chains
/// that match neither prefix (currently only the `cali-forward` base chain) are
/// not tallied.
fn count_chain_kinds<'a>(names: impl Iterator<Item = &'a String>) -> (usize, usize, usize) {
    let mut policy = 0;
    let mut profile = 0;
    let mut dispatch = 0;
    for name in names {
        if name.starts_with("cali-pi-") || name.starts_with("cali-po-") {
            policy += 1;
        } else if name.starts_with("cali-pri-") || name.starts_with("cali-pro-") {
            profile += 1;
        } else if name.starts_with("cali-tw-") || name.starts_with("cali-fw-") {
            dispatch += 1;
        }
    }
    (policy, profile, dispatch)
}

/// `nft`-backed [`TableApplier`] that feeds the full-table document to `nft -f -`
/// via [`crate::nft::apply_ruleset`], off the async executor.
pub struct NftTableApplier;

#[async_trait::async_trait(?Send)]
impl TableApplier for NftTableApplier {
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

    use crate::ipset_manager::set_name_for;
    use proto::{PolicyRule, RuleAction, TierInfo};

    /// A spy applier recording every applied nft document.
    #[derive(Clone, Default)]
    struct SpyApplier {
        docs: Rc<RefCell<Vec<String>>>,
        fail: Rc<RefCell<bool>>,
    }
    impl SpyApplier {
        fn last(&self) -> String {
            self.docs.borrow().last().cloned().unwrap_or_default()
        }
        fn count(&self) -> usize {
            self.docs.borrow().len()
        }
        fn clear(&self) {
            self.docs.borrow_mut().clear();
        }
        fn set_fail(&self, v: bool) {
            *self.fail.borrow_mut() = v;
        }
    }
    #[async_trait::async_trait(?Send)]
    impl TableApplier for SpyApplier {
        async fn apply_document(&self, doc: &str) -> Result<(), String> {
            if *self.fail.borrow() {
                return Err("spy: injected failure".into());
            }
            self.docs.borrow_mut().push(doc.to_owned());
            Ok(())
        }
    }

    // ---- builders --------------------------------------------------------

    fn ipset(id: &str, kind: IpSetKind, members: &[&str]) -> ToDataplane {
        ToDataplane::IpSetUpdate(IpSetUpdate {
            id: id.into(),
            kind,
            members: members.iter().map(|s| s.to_string()).collect(),
        })
    }
    fn allow_from_set(set_id: &str) -> Policy {
        Policy {
            inbound_rules: vec![PolicyRule {
                action_field: Some(RuleAction::Allow),
                src_ip_set_ids: vec![set_id.into()],
                ..Default::default()
            }],
            outbound_rules: vec![],
        }
    }
    fn allow_all_profile() -> Policy {
        Policy {
            inbound_rules: vec![PolicyRule::action(RuleAction::Allow)],
            outbound_rules: vec![PolicyRule::action(RuleAction::Allow)],
        }
    }
    fn pol_update(tier: &str, name: &str, policy: Policy) -> ToDataplane {
        ToDataplane::ActivePolicyUpdate {
            id: PolicyId {
                tier: tier.into(),
                name: name.into(),
            },
            policy,
        }
    }
    fn prof_update(id: &str, profile: Policy) -> ToDataplane {
        ToDataplane::ActiveProfileUpdate {
            id: id.into(),
            profile,
        }
    }
    fn wep_update(iface: &str, ep: WorkloadEndpoint) -> ToDataplane {
        ToDataplane::WorkloadEndpointUpdate {
            id: WorkloadEndpointId {
                orchestrator: "k8s".into(),
                workload: "ns/pod".into(),
                endpoint: iface.into(),
            },
            endpoint: ep,
        }
    }
    fn endpoint_with_ingress(iface: &str, tier: &str, policies: &[&str]) -> WorkloadEndpoint {
        WorkloadEndpoint {
            name: iface.into(),
            tiers: vec![TierInfo {
                name: tier.into(),
                ingress_policies: policies.iter().map(|s| s.to_string()).collect(),
                egress_policies: vec![],
            }],
            ..Default::default()
        }
    }
    fn endpoint_with_profiles(iface: &str, profiles: &[&str]) -> WorkloadEndpoint {
        WorkloadEndpoint {
            name: iface.into(),
            profile_ids: profiles.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    // ---- full render ------------------------------------------------------

    /// A policy + endpoint + ip-set (including an EMPTY set) renders one atomic
    /// document in dependency order (table → flush → sets → chains → rules) with
    /// NO delete statements, the `@set` policy match, the policy-jump→drop dispatch
    /// (no profile when a policy selects), and the forward base chain.
    #[tokio::test]
    async fn full_render_is_atomic_ordered_and_delete_free() {
        let spy = SpyApplier::default();
        let mut mgr = PolicyTableManager::new(spy.clone());

        mgr.on_update(&ipset("s:web", IpSetKind::Ip, &["10.0.0.5"]));
        mgr.on_update(&ipset("s:empty", IpSetKind::Ip, &[])); // empty-but-desired
        mgr.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
        mgr.on_update(&wep_update(
            "cali123",
            endpoint_with_ingress("cali123", "default", &["allow-web"]),
        ));
        assert!(spy.count() == 0, "on_update must not touch the kernel");

        mgr.complete_deferred_work().await.unwrap();
        let doc = spy.last();

        // Create-then-replace preamble: add, delete (safe — table now exists), add.
        assert!(doc.contains("add table inet calico"));
        assert!(doc.contains("delete table inet calico"));
        let add1 = doc.find("add table inet calico").unwrap();
        let del = doc.find("delete table inet calico").unwrap();
        assert!(
            add1 < del,
            "the table-level delete must be PRECEDED by add (restart-safe): {doc}"
        );

        // Both sets declared (the empty one too) with their containers.
        let web = set_name_for("s:web");
        let empty = set_name_for("s:empty");
        assert!(doc.contains(&format!("add set inet calico {web} {{ type ipv4_addr; }}")));
        assert!(doc.contains(&format!("add element inet calico {web} {{ 10.0.0.5 }}")));
        assert!(
            doc.contains(&format!(
                "add set inet calico {empty} {{ type ipv4_addr; }}"
            )),
            "empty-but-referenced set must still be declared: {doc}"
        );

        // Policy chain with the resolved @set match. ALLOW is NON-terminal: it sets
        // the accept mark and returns (so the other direction still evaluates), and
        // does NOT render a terminal `accept`.
        assert!(doc.contains("add chain inet calico cali-pi-default-allow-web"));
        assert!(doc.contains(&format!(
            "add rule inet calico cali-pi-default-allow-web ip saddr @{web} meta mark set meta mark or 0x01000000 return"
        )));
        assert!(
            !doc.contains(&format!(
                "add rule inet calico cali-pi-default-allow-web ip saddr @{web} accept"
            )),
            "ALLOW must not render a terminal accept: {doc}"
        );

        // Dispatch chain: clear accept mark on entry, jump the policy, return if the
        // policy allowed, then default deny. NO profile jump (policy selected).
        let tw = "cali-tw-cali123";
        assert!(doc.contains(&format!(
            "add rule inet calico {tw} meta mark set meta mark and 0xfeffffff"
        )));
        assert!(doc.contains(&format!(
            "add rule inet calico {tw} jump cali-pi-default-allow-web"
        )));
        assert!(doc.contains(&format!(
            "add rule inet calico {tw} meta mark & 0x01000000 == 0x01000000 return"
        )));
        assert!(doc.contains(&format!(
            "add rule inet calico {tw} drop comment \"default deny (ingress)\""
        )));

        // Forward base hook chain steers to-pod traffic to the dispatch chain.
        assert!(doc.contains(
            "add chain inet calico cali-forward { type filter hook forward priority 0; policy accept; }"
        ));
        assert!(doc.contains(&format!(
            "add rule inet calico cali-forward oifname \"cali123\" jump {tw}"
        )));

        // NO per-object delete statements — the only delete is the table-level
        // create-then-replace, which cannot poison the transaction.
        assert!(
            !doc.contains("delete set") && !doc.contains("delete chain"),
            "the full render must contain no per-object delete statements: {doc}"
        );

        // Dependency order: (2nd) add table < first set < first add chain < first
        // add rule. The rebuild happens after the delete-table replace.
        let rebuild = doc.rfind("add table inet calico").unwrap();
        let first_set = doc.find("add set").unwrap();
        let first_chain = doc.find("add chain").unwrap();
        let last_chain = doc.rfind("add chain").unwrap();
        let first_rule = doc.find("add rule").unwrap();
        assert!(rebuild < first_set, "table rebuilt before sets");
        assert!(first_set < first_chain, "sets declared before chains");
        assert!(
            last_chain < first_rule,
            "every add chain precedes every add rule"
        );
    }

    // ---- idempotence + skip-if-unchanged ---------------------------------

    #[tokio::test]
    async fn identical_desired_state_renders_identical_document() {
        let a = {
            let mut m = PolicyTableManager::new(SpyApplier::default());
            m.on_update(&ipset("s:web", IpSetKind::Ip, &["10.0.0.5"]));
            m.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
            m.on_update(&wep_update(
                "cali123",
                endpoint_with_ingress("cali123", "default", &["allow-web"]),
            ));
            m.render()
        };
        let b = {
            let mut m = PolicyTableManager::new(SpyApplier::default());
            // Same desired state, absorbed in a DIFFERENT order.
            m.on_update(&wep_update(
                "cali123",
                endpoint_with_ingress("cali123", "default", &["allow-web"]),
            ));
            m.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
            m.on_update(&ipset("s:web", IpSetKind::Ip, &["10.0.0.5"]));
            m.render()
        };
        assert_eq!(
            a, b,
            "render depends only on desired state, not arrival order"
        );
    }

    #[tokio::test]
    async fn skip_if_unchanged_does_not_reflush_steady_state() {
        let spy = SpyApplier::default();
        let mut mgr = PolicyTableManager::new(spy.clone());
        mgr.on_update(&ipset("s:web", IpSetKind::Ip, &["10.0.0.5"]));
        mgr.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));

        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.count(), 1, "first reconcile programs the table once");

        // No desired change → identical render → program NOTHING.
        mgr.complete_deferred_work().await.unwrap();
        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.count(), 1, "steady state is not re-flushed every tick");
    }

    #[tokio::test]
    async fn a_change_reapplies_the_full_document() {
        let spy = SpyApplier::default();
        let mut mgr = PolicyTableManager::new(spy.clone());
        mgr.on_update(&ipset("s:web", IpSetKind::Ip, &["10.0.0.5"]));
        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.count(), 1);

        // A membership change ⇒ a different document ⇒ re-apply.
        mgr.on_update(&ipset("s:web", IpSetKind::Ip, &["10.0.0.5", "10.0.0.6"]));
        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.count(), 2, "a changed render re-applies");
        assert!(spy.last().contains("10.0.0.6"));
    }

    // ---- self-heal / restart safety (pure) -------------------------------

    /// Applying from an arbitrary prior state is just a fresh full render: a
    /// manager that churned through unrelated state and then converged on a target
    /// renders the SAME document as a fresh manager fed only the target — there is
    /// no delta to get wrong, and the removed objects leave no trace (flush).
    #[tokio::test]
    async fn render_is_self_healing_independent_of_history() {
        // Manager that saw a bunch of now-removed state, then converged on target.
        let mut churned = PolicyTableManager::new(SpyApplier::default());
        churned.on_update(&ipset("s:old", IpSetKind::Ip, &["1.1.1.1"]));
        churned.on_update(&pol_update("default", "stale", allow_from_set("s:old")));
        churned.on_update(&wep_update(
            "caliOLD",
            endpoint_with_ingress("caliOLD", "default", &["stale"]),
        ));
        // ... all removed ...
        churned.on_update(&ToDataplane::IpSetRemove("s:old".into()));
        churned.on_update(&ToDataplane::ActivePolicyRemove(PolicyId {
            tier: "default".into(),
            name: "stale".into(),
        }));
        churned.on_update(&ToDataplane::WorkloadEndpointRemove(WorkloadEndpointId {
            orchestrator: "k8s".into(),
            workload: "ns/pod".into(),
            endpoint: "caliOLD".into(),
        }));
        // ... converge on the target.
        churned.on_update(&ipset("s:web", IpSetKind::Ip, &["10.0.0.5"]));
        churned.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
        churned.on_update(&wep_update(
            "cali123",
            endpoint_with_ingress("cali123", "default", &["allow-web"]),
        ));

        // Fresh manager fed ONLY the target.
        let mut fresh = PolicyTableManager::new(SpyApplier::default());
        fresh.on_update(&ipset("s:web", IpSetKind::Ip, &["10.0.0.5"]));
        fresh.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
        fresh.on_update(&wep_update(
            "cali123",
            endpoint_with_ingress("cali123", "default", &["allow-web"]),
        ));

        let churned_doc = churned.render();
        let fresh_doc = fresh.render();
        assert_eq!(
            churned_doc, fresh_doc,
            "render depends only on desired state, not history"
        );
        // And the removed objects leave no trace at all.
        assert!(!churned_doc.contains(&set_name_for("s:old")));
        assert!(!churned_doc.contains("stale"));
        assert!(!churned_doc.contains("caliOLD"));
    }

    // ---- GG (profile-only-when-no-policy) semantics ----------------------

    #[tokio::test]
    async fn open_by_default_profile_is_jumped_when_no_policy_selects() {
        let spy = SpyApplier::default();
        let mut mgr = PolicyTableManager::new(spy.clone());
        mgr.on_update(&prof_update("kns.nettest", allow_all_profile()));
        mgr.on_update(&wep_update(
            "cali123",
            endpoint_with_profiles("cali123", &["kns.nettest"]),
        ));
        mgr.complete_deferred_work().await.unwrap();
        let doc = spy.last();

        // Ingress profile chain: open-by-default ALLOW sets the accept mark + returns
        // (non-terminal), NOT a terminal accept.
        assert!(doc.contains("add chain inet calico cali-pri-kns.nettest"));
        assert!(doc.contains(
            "add rule inet calico cali-pri-kns.nettest meta mark set meta mark or 0x01000000 return"
        ));
        assert!(
            !doc.contains("add rule inet calico cali-pri-kns.nettest accept"),
            "profile ALLOW must not render a terminal accept: {doc}"
        );

        // The dispatch chain jumps the profile chain BEFORE its drop, with a
        // return-if-accepted in between.
        let tw = "cali-tw-cali123";
        let jump = doc
            .find(&format!(
                "add rule inet calico {tw} jump cali-pri-kns.nettest"
            ))
            .expect("dispatch jumps to ingress profile chain");
        let ret = doc
            .find(&format!(
                "add rule inet calico {tw} meta mark & 0x01000000 == 0x01000000 return"
            ))
            .expect("return-if-accepted after the profile jump");
        let drop = doc
            .find(&format!(
                "add rule inet calico {tw} drop comment \"default deny (ingress)\""
            ))
            .expect("dispatch still has final default deny");
        assert!(jump < ret, "return-if-accepted follows the profile jump");
        assert!(ret < drop, "default deny is last");
    }

    /// The `cali-forward` base chain jumps BOTH direction chains for a local
    /// endpoint (egress on `iifname`, ingress on `oifname`) and relies on its
    /// fall-through `policy accept` — no per-endpoint terminal accept. This is the
    /// structural guarantee that both directions are evaluated for a forwarded packet.
    #[tokio::test]
    async fn forward_chain_jumps_both_directions_and_falls_through() {
        let spy = SpyApplier::default();
        let mut mgr = PolicyTableManager::new(spy.clone());
        mgr.on_update(&prof_update("kns.nettest", allow_all_profile()));
        mgr.on_update(&wep_update(
            "cali123",
            endpoint_with_profiles("cali123", &["kns.nettest"]),
        ));
        mgr.complete_deferred_work().await.unwrap();
        let doc = spy.last();

        // Base chain declared with the fall-through accept policy.
        assert!(doc.contains(
            "add chain inet calico cali-forward { type filter hook forward priority 0; policy accept; }"
        ));
        // Egress (from the pod) on iifname, ingress (to the pod) on oifname.
        assert!(doc.contains(
            "add rule inet calico cali-forward iifname \"cali123\" jump cali-fw-cali123"
        ));
        assert!(doc.contains(
            "add rule inet calico cali-forward oifname \"cali123\" jump cali-tw-cali123"
        ));
        // The base chain itself never issues a terminal accept — acceptance is only
        // the fall-through after BOTH direction chains returned.
        assert!(
            !doc.contains("add rule inet calico cali-forward accept"),
            "cali-forward must accept only via fall-through, not a terminal rule: {doc}"
        );
    }

    #[tokio::test]
    async fn policy_selected_endpoint_does_not_fall_through_to_profile() {
        // Isolation: an endpoint selected by a policy in a direction ends at the
        // end-of-policy default-deny; profiles are NOT consulted (GG semantic).
        let spy = SpyApplier::default();
        let mut mgr = PolicyTableManager::new(spy.clone());
        mgr.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
        mgr.on_update(&prof_update("kns.nettest", allow_all_profile()));
        let mut ep = endpoint_with_ingress("cali123", "default", &["allow-web"]);
        ep.profile_ids = vec!["kns.nettest".into()];
        mgr.on_update(&wep_update("cali123", ep));
        mgr.complete_deferred_work().await.unwrap();

        let doc = spy.last();
        let tw = "cali-tw-cali123";
        assert!(
            doc.contains(&format!(
                "add rule inet calico {tw} jump cali-pi-default-allow-web"
            )),
            "ingress jumps the selecting policy: {doc}"
        );
        assert!(
            !doc.contains(&format!(
                "add rule inet calico {tw} jump cali-pri-kns.nettest"
            )),
            "policy-selected ingress must NOT fall through to the profile: {doc}"
        );
        assert!(doc.contains(&format!(
            "add rule inet calico {tw} drop comment \"default deny (ingress)\""
        )));
    }

    #[tokio::test]
    async fn profile_fallback_is_per_direction() {
        // Ingress policy but no egress policy: ingress = policy + drop (no profile);
        // egress falls back to the profile chain + drop.
        let spy = SpyApplier::default();
        let mut mgr = PolicyTableManager::new(spy.clone());
        mgr.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
        mgr.on_update(&prof_update("kns.nettest", allow_all_profile()));
        let mut ep = endpoint_with_ingress("cali123", "default", &["allow-web"]);
        ep.profile_ids = vec!["kns.nettest".into()];
        mgr.on_update(&wep_update("cali123", ep));
        mgr.complete_deferred_work().await.unwrap();

        let doc = spy.last();
        let tw = "cali-tw-cali123"; // ingress
        let fw = "cali-fw-cali123"; // egress
        assert!(doc.contains(&format!(
            "add rule inet calico {tw} jump cali-pi-default-allow-web"
        )));
        assert!(
            !doc.contains(&format!(
                "add rule inet calico {tw} jump cali-pri-kns.nettest"
            )),
            "ingress is policy-governed → no profile fallback: {doc}"
        );
        let prof = doc
            .find(&format!(
                "add rule inet calico {fw} jump cali-pro-kns.nettest"
            ))
            .expect("egress falls back to the profile chain");
        let drop = doc
            .find(&format!(
                "add rule inet calico {fw} drop comment \"default deny (egress)\""
            ))
            .expect("egress default deny");
        assert!(prof < drop, "egress profile jump precedes its default deny");
    }

    // ---- apply loop behaviour --------------------------------------------

    #[tokio::test]
    async fn failed_apply_does_not_cache_and_retries_same_document() {
        let spy = SpyApplier::default();
        let mut mgr = PolicyTableManager::new(spy.clone());
        mgr.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));

        spy.set_fail(true);
        assert!(mgr.complete_deferred_work().await.is_err());

        spy.set_fail(false);
        spy.clear();
        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(
            spy.count(),
            1,
            "retry re-applies (cache not poisoned by failure)"
        );
        assert!(spy.last().contains("cali-pi-default-allow-web"));
    }

    #[tokio::test]
    async fn empty_desired_state_still_programs_the_bare_table() {
        // Even with nothing desired, the manager owns the table: it renders the
        // create-or-clear preamble so a restart with stale kernel state is healed.
        let spy = SpyApplier::default();
        let mut mgr = PolicyTableManager::new(spy.clone());
        mgr.complete_deferred_work().await.unwrap();
        let doc = spy.last();
        assert!(doc.contains("add table inet calico"));
        assert!(doc.contains("delete table inet calico"));
        assert!(!doc.contains("delete set") && !doc.contains("delete chain"));
    }

    #[tokio::test]
    async fn non_policy_messages_are_ignored() {
        let spy = SpyApplier::default();
        let mut mgr = PolicyTableManager::new(spy.clone());
        mgr.on_update(&ToDataplane::RouteRemove("10.0.0.0/24".into()));
        assert_eq!(mgr.set_count(), 0);
        assert_eq!(mgr.policy_count(), 0);
        assert_eq!(mgr.endpoint_count(), 0);
    }
}
