//! Event sequencer: buffer + coalesce [`CalcGraph`] deltas, then flush them to a
//! [`DataplaneSink`] in **dependency-safe order** (T054), doing the calc→proto
//! conversion of resolved rules / endpoints along the way (T055).
//!
//! This is the Rust counterpart of upstream Felix's
//! `felix/calc/event_sequencer.go`. The calc graph emits deltas as an unordered
//! bundle per update ([`GraphDeltas`]); the dataplane, however, applies
//! [`proto::ToDataplane`] messages strictly in arrival order, so a policy that
//! references an IP set must never reach the dataplane before that IP set is
//! defined, and an IP set must never be removed while a policy still references
//! it. The sequencer enforces exactly that.
//!
//! # Emit ordering (the correctness contract)
//!
//! Mirrors upstream `EventSequencer.Flush` (adds in dependency order, then
//! removals in reverse):
//!
//! 1. `IpSetUpdate` — IP sets that became active, full membership.
//! 2. `IpSetDeltaUpdate` — incremental membership on already-active IP sets.
//! 3. `ActivePolicyUpdate` — policies that became (or stayed, on a rules change)
//!    active, rules converted to `proto::PolicyRule`.
//! 4. `ActiveProfileUpdate` — likewise for profiles.
//! 5. `WorkloadEndpointUpdate` — endpoints whose tier order changed.
//! 6. `WorkloadEndpointRemove` — endpoints that left.
//! 7. `ActiveProfileRemove`.
//! 8. `ActivePolicyRemove`.
//! 9. `IpSetRemove` — IP sets with no remaining referrers (LAST).
//! 10. `InSync` — emitted **once**, after the initial burst, when
//!     [`EventSequencer::mark_in_sync`] has been called.
//!
//! # Coalescing (within a flush)
//!
//! - Multiple member deltas to one IP set collapse to a single
//!   `IpSetDeltaUpdate` (an add then remove of the same member cancels).
//! - Multiple updates to the same policy / profile / endpoint collapse (last
//!   state wins).
//! - An IP set added then removed before it was ever flushed cancels entirely
//!   (a `sent_ip_sets` set, like upstream's `sentIPSets`, gates removals so a
//!   remove is only emitted for something the dataplane actually saw).
//!
//! # calc→proto conversion
//!
//! - [`ResolvedPolicy`] → `proto::Policy`: each [`ResolvedRule`] maps to a
//!   `proto::PolicyRule` — `action` → `RuleAction`, peer selector ids →
//!   `src/dst_ip_set_ids`, CIDRs → `src/dst_nets`, ports → `dst_ports`. (Calc's
//!   resolved rule carries no `src_ports`/`rule_id`, so those stay empty/None.)
//! - [`EndpointPolicyOrder`] → `proto::WorkloadEndpoint`: `endpoint_id` → `name`,
//!   tiers passthrough; `profile_ids` and `ipv4_nets`/`ipv6_nets` from the
//!   graph's local-endpoint detail (nets split on `':'` → v6 else v4).
//! - IP-set `kind`: inferred from member form — `Net` iff every member is a CIDR
//!   (`contains('/')`), else `Ip` (the common pod-IP case; a mixed set is `Ip`).

use std::collections::{BTreeMap, BTreeSet};

use proto::{
    DataplaneSink, IpSetDeltaUpdate, IpSetId, IpSetKind, IpSetUpdate, Policy, PolicyId, PolicyRule,
    RuleAction, TierInfo, ToDataplane, WorkloadEndpoint, WorkloadEndpointId,
};

use crate::active_rules::Transition;
use crate::active_rules::{ResolvedPolicy, ResolvedRule};
use crate::graph::{CalcGraph, GraphDeltas};
use crate::labelindex::MemberChange;
use crate::policy_resolver::TierPolicies;

/// Buffers and coalesces [`GraphDeltas`], flushing an ordered, dependency-safe
/// stream of [`proto::ToDataplane`] messages.
#[derive(Debug, Default)]
pub struct EventSequencer {
    // ---- pending adds (dependency order) --------------------------------
    /// IP-set id → full membership snapshot (refreshed each ingest).
    pending_added_ip_sets: BTreeMap<IpSetId, Vec<String>>,
    /// IP-set id → (added members, removed members) for already-active sets.
    pending_ip_set_deltas: BTreeMap<IpSetId, (BTreeSet<String>, BTreeSet<String>)>,
    /// calc policy id → (proto id, converted policy). Last state wins.
    pending_policy_updates: BTreeMap<String, (PolicyId, Policy)>,
    /// profile id → converted rules. Last state wins.
    pending_profile_updates: BTreeMap<String, Policy>,
    /// endpoint id → converted endpoint. Last state wins.
    pending_endpoint_updates: BTreeMap<String, WorkloadEndpoint>,
    // ---- pending removes (reverse dependency order) ---------------------
    pending_endpoint_removes: BTreeSet<String>,
    pending_profile_removes: BTreeSet<String>,
    /// calc policy id → proto id (kept so a remove needs no live graph lookup).
    pending_policy_removes: BTreeMap<String, PolicyId>,
    pending_removed_ip_sets: BTreeSet<IpSetId>,
    // ---- in-sync barrier -------------------------------------------------
    in_sync_pending: bool,
    in_sync_sent: bool,
    // ---- what the dataplane has actually seen ----------------------------
    sent_ip_sets: BTreeSet<IpSetId>,
    sent_policies: BTreeMap<String, PolicyId>,
    sent_profiles: BTreeSet<String>,
    sent_endpoints: BTreeSet<String>,
}

impl EventSequencer {
    /// Create an empty sequencer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Buffer one batch of graph deltas, coalescing into the pending state. The
    /// graph is read for full IP-set membership, resolved rules, policy tiers
    /// and local-endpoint detail.
    pub fn ingest(&mut self, deltas: &GraphDeltas, graph: &CalcGraph) {
        // 1. IP sets that became active: snapshot full membership; cancel any
        //    pending removal/deltas for the same id.
        for id in &deltas.ip_sets_added {
            self.pending_removed_ip_sets.remove(id);
            self.pending_ip_set_deltas.remove(id);
            let members = graph.ip_set_members(id).into_iter().collect();
            self.pending_added_ip_sets.insert(id.clone(), members);
        }
        // 2. IP sets that became inactive.
        for id in &deltas.ip_sets_removed {
            self.pending_added_ip_sets.remove(id);
            self.pending_ip_set_deltas.remove(id);
            // Only a set the dataplane has seen needs an explicit remove;
            // an added-then-removed-before-flush set cancels entirely.
            if self.sent_ip_sets.contains(id) {
                self.pending_removed_ip_sets.insert(id.clone());
            }
        }
        // 3. Member deltas: skip freshly-added (covered by the snapshot) and
        //    being-removed sets; coalesce the rest with add/remove cancellation.
        for d in &deltas.ip_set_member_deltas {
            if self.pending_added_ip_sets.contains_key(&d.ip_set_id)
                || self.pending_removed_ip_sets.contains(&d.ip_set_id)
            {
                continue;
            }
            let entry = self
                .pending_ip_set_deltas
                .entry(d.ip_set_id.clone())
                .or_default();
            match d.change {
                MemberChange::Added => {
                    if !entry.1.remove(&d.member) {
                        entry.0.insert(d.member.clone());
                    }
                }
                MemberChange::Removed => {
                    if !entry.0.remove(&d.member) {
                        entry.1.insert(d.member.clone());
                    }
                }
            }
        }
        // 3b. Refresh snapshots of still-added sets: membership can change via a
        //     later delta in the same batch (whose set is already active, so it
        //     is not re-listed in `ip_sets_added`).
        let added_ids: Vec<IpSetId> = self.pending_added_ip_sets.keys().cloned().collect();
        for id in added_ids {
            let members = graph.ip_set_members(&id).into_iter().collect();
            self.pending_added_ip_sets.insert(id, members);
        }
        // 4. Policy / profile active-set transitions.
        for t in &deltas.policy_transitions {
            match t {
                Transition::PolicyActive(id) => {
                    let pid = PolicyId {
                        tier: graph.policy_tier(id).unwrap_or("default").to_string(),
                        name: id.clone(),
                    };
                    let policy = graph
                        .resolved_policy(id)
                        .map(convert_policy)
                        .unwrap_or_default();
                    self.pending_policy_removes.remove(id);
                    self.pending_policy_updates
                        .insert(id.clone(), (pid, policy));
                }
                Transition::PolicyInactive(id) => {
                    self.pending_policy_updates.remove(id);
                    if let Some(pid) = self.sent_policies.get(id).cloned() {
                        self.pending_policy_removes.insert(id.clone(), pid);
                    }
                }
                Transition::ProfileActive(id) => {
                    let profile = graph
                        .resolved_profile(id)
                        .map(convert_policy)
                        .unwrap_or_default();
                    self.pending_profile_removes.remove(id);
                    self.pending_profile_updates.insert(id.clone(), profile);
                }
                Transition::ProfileInactive(id) => {
                    self.pending_profile_updates.remove(id);
                    if self.sent_profiles.contains(id) {
                        self.pending_profile_removes.insert(id.clone());
                    }
                }
            }
        }
        // 5. Endpoint orders → update (still local) or remove (gone).
        for order in &deltas.endpoint_orders {
            let id = &order.endpoint_id;
            if graph.is_local_endpoint(id) {
                let (profiles, ipnets) = graph.local_endpoint_detail(id).unwrap_or_default();
                let (ipv4_nets, ipv6_nets) = split_nets(&ipnets);
                let endpoint = WorkloadEndpoint {
                    name: id.clone(),
                    mac: None,
                    profile_ids: profiles,
                    tiers: order.tiers.iter().map(convert_tier).collect(),
                    ipv4_nets,
                    ipv6_nets,
                };
                self.pending_endpoint_removes.remove(id);
                self.pending_endpoint_updates.insert(id.clone(), endpoint);
            } else {
                self.pending_endpoint_updates.remove(id);
                if self.sent_endpoints.contains(id) {
                    self.pending_endpoint_removes.insert(id.clone());
                }
            }
        }
    }

    /// Mark that the initial datastore sync has completed: the next flush ends
    /// with a single [`proto::ToDataplane::InSync`]. Idempotent — `InSync` is
    /// only ever emitted once.
    pub fn mark_in_sync(&mut self) {
        self.in_sync_pending = true;
    }

    /// Emit the buffered batch to `sink` in dependency-safe order, then clear
    /// the buffers. Adds flow IP sets → policies → profiles → endpoints;
    /// removes flow in reverse; `InSync` closes the initial burst.
    pub fn flush_into<S: DataplaneSink>(&mut self, sink: &mut S) -> Result<(), S::Error> {
        // --- Adds, in dependency order: IP sets → policies → profiles → eps ---
        for (id, members) in std::mem::take(&mut self.pending_added_ip_sets) {
            let kind = infer_kind(&members);
            self.sent_ip_sets.insert(id.clone());
            sink.apply(ToDataplane::IpSetUpdate(IpSetUpdate { id, kind, members }))?;
        }
        for (id, (added, removed)) in std::mem::take(&mut self.pending_ip_set_deltas) {
            if added.is_empty() && removed.is_empty() {
                continue; // fully cancelled out
            }
            sink.apply(ToDataplane::IpSetDeltaUpdate(IpSetDeltaUpdate {
                id,
                added_members: added.into_iter().collect(),
                removed_members: removed.into_iter().collect(),
            }))?;
        }
        for (flat, (pid, policy)) in std::mem::take(&mut self.pending_policy_updates) {
            self.sent_policies.insert(flat, pid.clone());
            sink.apply(ToDataplane::ActivePolicyUpdate { id: pid, policy })?;
        }
        for (id, profile) in std::mem::take(&mut self.pending_profile_updates) {
            self.sent_profiles.insert(id.clone());
            sink.apply(ToDataplane::ActiveProfileUpdate { id, profile })?;
        }
        for (id, endpoint) in std::mem::take(&mut self.pending_endpoint_updates) {
            self.sent_endpoints.insert(id.clone());
            sink.apply(ToDataplane::WorkloadEndpointUpdate {
                id: workload_endpoint_id(&id),
                endpoint,
            })?;
        }
        // --- Removes, in reverse dependency order: eps → profiles → pol → IP ---
        for id in std::mem::take(&mut self.pending_endpoint_removes) {
            self.sent_endpoints.remove(&id);
            sink.apply(ToDataplane::WorkloadEndpointRemove(workload_endpoint_id(
                &id,
            )))?;
        }
        for id in std::mem::take(&mut self.pending_profile_removes) {
            self.sent_profiles.remove(&id);
            sink.apply(ToDataplane::ActiveProfileRemove(id))?;
        }
        for (flat, pid) in std::mem::take(&mut self.pending_policy_removes) {
            self.sent_policies.remove(&flat);
            sink.apply(ToDataplane::ActivePolicyRemove(pid))?;
        }
        for id in std::mem::take(&mut self.pending_removed_ip_sets) {
            self.sent_ip_sets.remove(&id);
            sink.apply(ToDataplane::IpSetRemove(id))?;
        }
        // --- InSync barrier: once, after the initial burst is flushed. ---
        if self.in_sync_pending && !self.in_sync_sent {
            self.in_sync_sent = true;
            self.in_sync_pending = false;
            sink.apply(ToDataplane::InSync)?;
        }
        Ok(())
    }
}

// ---- calc→proto conversion helpers ---------------------------------------

/// Convert a resolved policy/profile's rules into the wire [`Policy`].
fn convert_policy(rp: &ResolvedPolicy) -> Policy {
    Policy {
        inbound_rules: rp.inbound.iter().map(convert_rule).collect(),
        outbound_rules: rp.outbound.iter().map(convert_rule).collect(),
    }
}

/// Convert one resolved rule into a wire [`PolicyRule`].
fn convert_rule(r: &ResolvedRule) -> PolicyRule {
    PolicyRule {
        action_field: Some(convert_action(r.action)),
        protocol: r.protocol.clone(),
        src_nets: r.src_nets.clone(),
        dst_nets: r.dst_nets.clone(),
        src_ports: Vec::new(),
        dst_ports: r.dst_ports.clone(),
        src_ip_set_ids: r.src_ip_set_ids.clone(),
        dst_ip_set_ids: r.dst_ip_set_ids.clone(),
        rule_id: None,
    }
}

/// Map the v3 rule action onto the computed [`RuleAction`].
fn convert_action(a: apis::Action) -> RuleAction {
    match a {
        apis::Action::Allow => RuleAction::Allow,
        apis::Action::Deny => RuleAction::Deny,
        apis::Action::Log => RuleAction::Log,
        apis::Action::Pass => RuleAction::Pass,
    }
}

/// Convert a resolved tier order into a wire [`TierInfo`].
fn convert_tier(t: &TierPolicies) -> TierInfo {
    TierInfo {
        name: t.name.clone(),
        ingress_policies: t.ingress_policies.clone(),
        egress_policies: t.egress_policies.clone(),
    }
}

/// Split member IP/CIDR strings into (ipv4, ipv6) by the presence of `':'`.
fn split_nets(nets: &[String]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for n in nets {
        if n.contains(':') {
            v6.push(n.clone());
        } else {
            v4.push(n.clone());
        }
    }
    (v4, v6)
}

/// Infer an IP set's kind from its members: `Net` iff every member is a CIDR
/// (`contains('/')`), else `Ip` (also the empty-set default).
fn infer_kind(members: &[String]) -> IpSetKind {
    if !members.is_empty() && members.iter().all(|m| m.contains('/')) {
        IpSetKind::Net
    } else {
        IpSetKind::Ip
    }
}

/// Build a [`WorkloadEndpointId`] from a flat calc endpoint id: split on `'/'`
/// into `orchestrator/workload/endpoint`; a non-triplet id becomes the
/// `workload` component with the others empty.
fn workload_endpoint_id(id: &str) -> WorkloadEndpointId {
    let parts: Vec<&str> = id.splitn(3, '/').collect();
    if let [orchestrator, workload, endpoint] = parts.as_slice() {
        WorkloadEndpointId {
            orchestrator: (*orchestrator).to_string(),
            workload: (*workload).to_string(),
            endpoint: (*endpoint).to_string(),
        }
    } else {
        WorkloadEndpointId {
            orchestrator: String::new(),
            workload: id.to_string(),
            endpoint: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_rules::ip_set_id;
    use crate::graph::ResourceUpdate;
    use crate::selector::Selector;
    use apis::{NetworkPolicySpec, ProfileSpec};
    use std::collections::BTreeMap;

    /// Records applied messages in arrival order (the dataplane-manager pattern).
    #[derive(Default)]
    struct RecordingSink {
        seen: Vec<ToDataplane>,
    }
    impl DataplaneSink for RecordingSink {
        type Error = std::convert::Infallible;
        fn apply(&mut self, msg: ToDataplane) -> Result<(), Self::Error> {
            self.seen.push(msg);
            Ok(())
        }
    }
    impl RecordingSink {
        /// First index of a message matching `pred`, or `None`.
        fn pos(&self, pred: impl Fn(&ToDataplane) -> bool) -> Option<usize> {
            self.seen.iter().position(pred)
        }
    }

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn np(json: &str) -> NetworkPolicySpec {
        serde_json::from_str(json).unwrap()
    }

    fn policy(id: &str, spec: NetworkPolicySpec) -> ResourceUpdate {
        ResourceUpdate::Policy {
            id: id.into(),
            spec,
            remove: false,
        }
    }

    fn wep(id: &str, node: &str, lbls: &[(&str, &str)], ipnets: &[&str]) -> ResourceUpdate {
        ResourceUpdate::WorkloadEndpoint {
            id: id.into(),
            node: node.into(),
            labels: labels(lbls),
            profiles: vec![],
            ipnets: ipnets.iter().map(|s| s.to_string()).collect(),
            remove: false,
        }
    }

    fn remove_wep(id: &str) -> ResourceUpdate {
        ResourceUpdate::WorkloadEndpoint {
            id: id.into(),
            node: "node-a".into(),
            labels: BTreeMap::new(),
            profiles: vec![],
            ipnets: vec![],
            remove: true,
        }
    }

    fn tier(name: &str, order: Option<f64>) -> ResourceUpdate {
        ResourceUpdate::Tier {
            name: name.into(),
            order,
            remove: false,
        }
    }

    fn peer_id(sel: &str) -> String {
        ip_set_id(&Selector::parse(sel).unwrap())
    }

    const DB_FROM_WEB: &str = r#"{"selector":"role == 'db'","types":["Ingress"],
        "ingress":[{"action":"Allow","source":{"selector":"role == 'web'"}}]}"#;

    /// A batch that adds an IP set + a referencing policy + an endpoint must emit
    /// IpSetUpdate BEFORE ActivePolicyUpdate BEFORE WorkloadEndpointUpdate.
    #[test]
    fn adds_flow_ip_set_then_policy_then_endpoint() {
        let mut g = CalcGraph::new("node-a");
        let mut seq = EventSequencer::new();
        seq.ingest(&g.on_update(tier("default", Some(100.0))).unwrap(), &g);
        seq.ingest(&g.on_update(policy("np1", np(DB_FROM_WEB))).unwrap(), &g);
        seq.ingest(
            &g.on_update(wep("db", "node-a", &[("role", "db")], &["10.0.0.9"]))
                .unwrap(),
            &g,
        );
        seq.ingest(
            &g.on_update(wep("web", "node-a", &[("role", "web")], &["10.0.0.5"]))
                .unwrap(),
            &g,
        );

        let mut sink = RecordingSink::default();
        seq.flush_into(&mut sink).unwrap();

        let ip = sink
            .pos(|m| matches!(m, ToDataplane::IpSetUpdate(_)))
            .expect("IpSetUpdate");
        let pol = sink
            .pos(|m| matches!(m, ToDataplane::ActivePolicyUpdate { .. }))
            .expect("ActivePolicyUpdate");
        let ep = sink
            .pos(|m| matches!(m, ToDataplane::WorkloadEndpointUpdate { .. }))
            .expect("WorkloadEndpointUpdate");
        assert!(ip < pol, "IP set must precede policy");
        assert!(pol < ep, "policy must precede endpoint");
    }

    /// Removals flow in reverse: IpSetRemove must come AFTER the
    /// ActivePolicyRemove that referenced it.
    #[test]
    fn removes_flow_endpoint_then_policy_then_ip_set() {
        let mut g = CalcGraph::new("node-a");
        let mut seq = EventSequencer::new();
        seq.ingest(&g.on_update(tier("default", Some(100.0))).unwrap(), &g);
        seq.ingest(&g.on_update(policy("np1", np(DB_FROM_WEB))).unwrap(), &g);
        seq.ingest(
            &g.on_update(wep("db", "node-a", &[("role", "db")], &["10.0.0.9"]))
                .unwrap(),
            &g,
        );
        seq.ingest(
            &g.on_update(wep("web", "node-a", &[("role", "web")], &["10.0.0.5"]))
                .unwrap(),
            &g,
        );
        // Flush the adds so the removes have something to reference.
        let mut sink = RecordingSink::default();
        seq.flush_into(&mut sink).unwrap();

        // Remove the applies-to endpoint: policy deactivates, IP set unregisters.
        seq.ingest(&g.on_update(remove_wep("db")).unwrap(), &g);
        let mut sink = RecordingSink::default();
        seq.flush_into(&mut sink).unwrap();

        let ep = sink
            .pos(|m| matches!(m, ToDataplane::WorkloadEndpointRemove(_)))
            .expect("WorkloadEndpointRemove");
        let pol = sink
            .pos(|m| matches!(m, ToDataplane::ActivePolicyRemove(_)))
            .expect("ActivePolicyRemove");
        let ip = sink
            .pos(|m| matches!(m, ToDataplane::IpSetRemove(_)))
            .expect("IpSetRemove");
        assert!(ep < pol, "endpoint remove must precede policy remove");
        assert!(pol < ip, "policy remove must precede IP set remove");
    }

    /// Two member deltas to one already-active IP set collapse to one
    /// IpSetDeltaUpdate carrying the net set.
    #[test]
    fn member_deltas_coalesce_into_one_delta_update() {
        let mut g = CalcGraph::new("node-a");
        let mut seq = EventSequencer::new();
        seq.ingest(&g.on_update(policy("np1", np(DB_FROM_WEB))).unwrap(), &g);
        seq.ingest(
            &g.on_update(wep("db", "node-a", &[("role", "db")], &["10.0.0.9"]))
                .unwrap(),
            &g,
        );
        // First flush activates the peer IP set (empty) as an initial update.
        let mut sink = RecordingSink::default();
        seq.flush_into(&mut sink).unwrap();

        // Two web endpoints in the SAME batch → two member adds on the now
        // already-active peer set.
        seq.ingest(
            &g.on_update(wep("web1", "node-a", &[("role", "web")], &["10.0.0.5"]))
                .unwrap(),
            &g,
        );
        seq.ingest(
            &g.on_update(wep("web2", "node-a", &[("role", "web")], &["10.0.0.6"]))
                .unwrap(),
            &g,
        );
        let mut sink = RecordingSink::default();
        seq.flush_into(&mut sink).unwrap();

        let deltas: Vec<&IpSetDeltaUpdate> = sink
            .seen
            .iter()
            .filter_map(|m| match m {
                ToDataplane::IpSetDeltaUpdate(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(deltas.len(), 1, "the two adds must collapse to one delta");
        assert_eq!(deltas[0].id, peer_id("role == 'web'"));
        assert_eq!(
            deltas[0].added_members,
            vec!["10.0.0.5".to_string(), "10.0.0.6".to_string()]
        );
        assert!(deltas[0].removed_members.is_empty());
    }

    /// Two policy updates in one batch collapse to a single ActivePolicyUpdate
    /// (last state wins).
    #[test]
    fn policy_updates_coalesce() {
        let mut g = CalcGraph::new("node-a");
        let mut seq = EventSequencer::new();
        seq.ingest(&g.on_update(policy("np1", np(DB_FROM_WEB))).unwrap(), &g);
        // Activate it.
        seq.ingest(
            &g.on_update(wep("db", "node-a", &[("role", "db")], &["10.0.0.9"]))
                .unwrap(),
            &g,
        );
        // Change the rules while it stays active → re-emitted PolicyActive.
        let changed = np(r#"{"selector":"role == 'db'","types":["Ingress"],
            "ingress":[{"action":"Deny","source":{"selector":"role == 'app'"}}]}"#);
        seq.ingest(&g.on_update(policy("np1", changed)).unwrap(), &g);

        let mut sink = RecordingSink::default();
        seq.flush_into(&mut sink).unwrap();

        let updates: Vec<_> = sink
            .seen
            .iter()
            .filter(|m| matches!(m, ToDataplane::ActivePolicyUpdate { .. }))
            .collect();
        assert_eq!(updates.len(), 1, "coalesced to a single policy update");
        // Last state wins: the Deny/app rule, not the Allow/web one.
        if let ToDataplane::ActivePolicyUpdate { policy, .. } = updates[0] {
            assert_eq!(policy.inbound_rules[0].action_field, Some(RuleAction::Deny));
            assert_eq!(
                policy.inbound_rules[0].src_ip_set_ids,
                vec![peer_id("role == 'app'")]
            );
        } else {
            unreachable!()
        }
    }

    /// A selector-peer rule converts to a PolicyRule with the right ip-set id +
    /// action; CIDR/port matches pass through.
    #[test]
    fn resolved_rule_converts_to_policy_rule() {
        let mut g = CalcGraph::new("node-a");
        let mut seq = EventSequencer::new();
        let spec = np(r#"{"selector":"role == 'db'","types":["Ingress"],
            "ingress":[{"action":"Allow","protocol":"TCP",
                "source":{"selector":"role == 'web'","nets":["192.168.0.0/16"]},
                "destination":{"ports":[443]}}]}"#);
        seq.ingest(&g.on_update(policy("np1", spec)).unwrap(), &g);
        seq.ingest(
            &g.on_update(wep("db", "node-a", &[("role", "db")], &["10.0.0.9"]))
                .unwrap(),
            &g,
        );

        let mut sink = RecordingSink::default();
        seq.flush_into(&mut sink).unwrap();

        let policy = sink
            .seen
            .iter()
            .find_map(|m| match m {
                ToDataplane::ActivePolicyUpdate { policy, .. } => Some(policy),
                _ => None,
            })
            .expect("policy update");
        let r = &policy.inbound_rules[0];
        assert_eq!(r.action_field, Some(RuleAction::Allow));
        assert_eq!(r.protocol.as_deref(), Some("TCP"));
        assert_eq!(r.src_ip_set_ids, vec![peer_id("role == 'web'")]);
        assert_eq!(r.src_nets, vec!["192.168.0.0/16".to_string()]);
        assert_eq!(r.dst_ports, vec![443]);
    }

    /// A pure-CIDR IP set is `Net`; a pod-IP set is `Ip`.
    #[test]
    fn ip_set_kind_inference() {
        assert_eq!(infer_kind(&["10.0.0.1".to_string()]), IpSetKind::Ip);
        assert_eq!(infer_kind(&["192.168.0.0/16".to_string()]), IpSetKind::Net);
        assert_eq!(infer_kind(&[]), IpSetKind::Ip);
        // Mixed → Ip.
        assert_eq!(
            infer_kind(&["10.0.0.1".to_string(), "192.168.0.0/16".to_string()]),
            IpSetKind::Ip
        );
    }

    /// InSync is emitted once, at the end of the flush after `mark_in_sync`, and
    /// never again.
    #[test]
    fn in_sync_emitted_once() {
        let mut g = CalcGraph::new("node-a");
        let mut seq = EventSequencer::new();
        seq.ingest(&g.on_update(policy("np1", np(DB_FROM_WEB))).unwrap(), &g);
        seq.ingest(
            &g.on_update(wep("db", "node-a", &[("role", "db")], &["10.0.0.9"]))
                .unwrap(),
            &g,
        );
        seq.mark_in_sync();

        let mut sink = RecordingSink::default();
        seq.flush_into(&mut sink).unwrap();
        // InSync is the LAST message.
        assert!(matches!(sink.seen.last(), Some(ToDataplane::InSync)));
        assert_eq!(
            sink.seen
                .iter()
                .filter(|m| matches!(m, ToDataplane::InSync))
                .count(),
            1
        );

        // A subsequent flush does not repeat it.
        seq.ingest(
            &g.on_update(wep("web", "node-a", &[("role", "web")], &["10.0.0.5"]))
                .unwrap(),
            &g,
        );
        let mut sink2 = RecordingSink::default();
        seq.flush_into(&mut sink2).unwrap();
        assert!(!sink2.seen.iter().any(|m| matches!(m, ToDataplane::InSync)));
    }

    /// End-to-end: drive a CalcGraph (policy + local db endpoint + web peer),
    /// ingest, flush, and assert the full ordered ToDataplane sequence.
    #[test]
    fn end_to_end_ordered_sequence() {
        let mut g = CalcGraph::new("node-a");
        let mut seq = EventSequencer::new();
        seq.ingest(&g.on_update(tier("default", Some(100.0))).unwrap(), &g);
        seq.ingest(&g.on_update(policy("np1", np(DB_FROM_WEB))).unwrap(), &g);
        seq.ingest(
            &g.on_update(wep("db", "node-a", &[("role", "db")], &["10.0.0.9"]))
                .unwrap(),
            &g,
        );
        seq.ingest(
            &g.on_update(wep("web", "node-a", &[("role", "web")], &["10.0.0.5"]))
                .unwrap(),
            &g,
        );
        seq.mark_in_sync();

        let mut sink = RecordingSink::default();
        seq.flush_into(&mut sink).unwrap();

        let peer = peer_id("role == 'web'");
        // Expect: IpSetUpdate(peer, [web ip]), ActivePolicyUpdate(np1),
        // WorkloadEndpointUpdate(db), WorkloadEndpointUpdate(web), InSync.
        // (db and web are both local endpoints; web has no policy but is still
        //  surfaced as an endpoint.)
        let ip_pos = sink
            .pos(|m| matches!(m, ToDataplane::IpSetUpdate(u) if u.id == peer))
            .unwrap();
        let pol_pos = sink
            .pos(|m| matches!(m, ToDataplane::ActivePolicyUpdate { id, .. } if id.name == "np1"))
            .unwrap();
        let db_pos = sink
            .pos(|m| matches!(m, ToDataplane::WorkloadEndpointUpdate { endpoint, .. } if endpoint.name == "db"))
            .unwrap();
        let insync_pos = sink.pos(|m| matches!(m, ToDataplane::InSync)).unwrap();

        assert!(ip_pos < pol_pos && pol_pos < db_pos && db_pos < insync_pos);

        // The IP set holds the web IP and is kind Ip.
        if let ToDataplane::IpSetUpdate(u) = &sink.seen[ip_pos] {
            assert_eq!(u.members, vec!["10.0.0.5".to_string()]);
            assert_eq!(u.kind, IpSetKind::Ip);
        }
        // The policy's inbound rule references the peer IP set.
        if let ToDataplane::ActivePolicyUpdate { policy, .. } = &sink.seen[pol_pos] {
            assert_eq!(policy.inbound_rules[0].src_ip_set_ids, vec![peer.clone()]);
        }
        // The db endpoint's tier lists np1 on ingress.
        if let ToDataplane::WorkloadEndpointUpdate { endpoint, .. } = &sink.seen[db_pos] {
            assert_eq!(endpoint.tiers[0].name, "default");
            assert_eq!(endpoint.tiers[0].ingress_policies, vec!["np1".to_string()]);
            assert_eq!(endpoint.ipv4_nets, vec!["10.0.0.9".to_string()]);
        }
    }

    /// A profile referenced by a local endpoint surfaces as an
    /// ActiveProfileUpdate.
    #[test]
    fn profile_surfaces_as_active_profile_update() {
        let mut g = CalcGraph::new("node-a");
        let mut seq = EventSequencer::new();
        // Profile with a rule referencing a peer selector.
        let prof: ProfileSpec = serde_json::from_str(
            r#"{"ingress":[{"action":"Allow","source":{"selector":"role == 'web'"}}]}"#,
        )
        .unwrap();
        seq.ingest(
            &g.on_update(ResourceUpdate::Profile {
                id: "prof1".into(),
                spec: prof,
                remove: false,
            })
            .unwrap(),
            &g,
        );
        // A local endpoint referencing the profile activates it.
        seq.ingest(
            &g.on_update(ResourceUpdate::WorkloadEndpoint {
                id: "ep".into(),
                node: "node-a".into(),
                labels: BTreeMap::new(),
                profiles: vec!["prof1".into()],
                ipnets: vec!["10.0.0.1".into()],
                remove: false,
            })
            .unwrap(),
            &g,
        );

        let mut sink = RecordingSink::default();
        seq.flush_into(&mut sink).unwrap();

        let profile = sink.seen.iter().find_map(|m| match m {
            ToDataplane::ActiveProfileUpdate { id, profile } if id == "prof1" => Some(profile),
            _ => None,
        });
        let profile = profile.expect("ActiveProfileUpdate for prof1");
        assert_eq!(
            profile.inbound_rules[0].src_ip_set_ids,
            vec![peer_id("role == 'web'")]
        );
    }
}
