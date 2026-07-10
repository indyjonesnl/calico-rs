//! Calc-graph root dispatcher (`CalcGraph`).
//!
//! This is the Rust counterpart of upstream Felix's `felix/calc/calc_graph.go`:
//! the top-level object that receives datastore updates and **fans them out** to
//! the calculation components by resource type. It is the wiring, not the
//! algorithms — every non-trivial computation lives in one of the components it
//! composes:
//!
//! - [`ActiveRulesCalculator`] — which policies/profiles are active on the local
//!   node (drives IP-set registration via the transitions it emits).
//! - [`RuleScanner`] — ref-counted rule-selector → IP-set registration. It
//!   **owns the one [`MembershipIndex`]** the whole graph shares (see below).
//! - [`PolicyResolver`] — per-endpoint ordered tiers/policies.
//! - [`from_resources`](crate::from_resources) — v3 spec → selector/eval.
//!
//! # The single coherent membership index (the crux)
//!
//! IP-set membership needs ONE index in which two things meet:
//!
//! 1. rule peer **selectors** are registered (by the [`RuleScanner`] as policies
//!    go active), and
//! 2. every endpoint / network set is present as an **item** (its labels,
//!    inherited profile labels, and member IPs) so those selectors resolve to
//!    real members.
//!
//! The [`RuleScanner`] already owns a [`MembershipIndex`] and exposes both sides
//! of that contract: [`RuleScanner::on_policy_active`] registers selectors into
//! it, while [`RuleScanner::update_endpoint`] / [`RuleScanner::update_namespace`]
//! populate it with items and parent (profile) labels. The graph therefore holds
//! **no index of its own** — it routes item/parent population through the
//! scanner's methods, so selectors and members land in the same index and member
//! [`Delta`]s come back from every mutation. No change to the T052 scanner was
//! needed for this.
//!
//! # Local vs. remote endpoints
//!
//! - **Every** endpoint (local and remote) is fed to the shared index as an item,
//!   because an IP set can legitimately contain the IPs of pods on other nodes.
//! - Only **local** endpoints (`node == local_node`) additionally drive the
//!   [`ActiveRulesCalculator`] (which policies are enforced here) and the
//!   [`PolicyResolver`] (this node's policy chains). Remote endpoints never make
//!   a policy active or acquire a resolved policy order.
//!
//! # Effective labels
//!
//! The shared index performs profile-label inheritance internally for IP-set
//! membership. The [`ActiveRulesCalculator`] and [`PolicyResolver`], however,
//! match against an endpoint's **effective** labels (own merged with inherited
//! profile `labelsToApply`), so the graph computes those before feeding local
//! endpoints to them — using the same precedence as the index (own labels win,
//! earlier profiles win over later). When a profile's `labelsToApply` change, the
//! graph re-drives the local endpoints that reference it.
//!
//! # Scope
//!
//! Input is the typed [`ResourceUpdate`] enum, so the graph is unit-testable
//! without a live datastore; the datastore→enum adapter is T055. `GlobalNetwork
//! Policy`/`GlobalNetworkSet`/`HostEndpoint`/`Node` are out of scope here and
//! map through the same component methods at the adapter boundary when added.
//! Resource ids are assumed unique across types (the adapter namespaces them).

use std::collections::{BTreeMap, BTreeSet};

use apis::{NetworkPolicySpec, ProfileSpec};

use crate::active_rules::{ActiveRulesCalculator, ResolvedPolicy, RuleScanner, Transition};
use crate::from_resources::network_policy_to_eval;
use crate::labelindex::{Delta, IpSetId, Member};
use crate::policy_resolver::{EndpointPolicyOrder, PolicyResolver};
use crate::selector::SelectorError;

/// Local (workload) endpoint identifier.
pub type EndpointId = String;
/// Policy identifier.
pub type PolicyId = String;
/// Profile identifier.
pub type ProfileId = String;
/// Kubernetes node name.
pub type NodeName = String;

/// The tier a policy is assigned to when its spec names none.
const DEFAULT_TIER: &str = "default";

/// A typed datastore update the graph fans out. Built from a `SyncerV1Event` /
/// v3 spec at the datastore boundary (T055); kept datastore-free so the graph is
/// unit-testable.
#[derive(Debug, Clone)]
pub enum ResourceUpdate {
    /// A `NetworkPolicy` (add/update when `remove` is false, delete otherwise).
    Policy {
        id: PolicyId,
        spec: NetworkPolicySpec,
        remove: bool,
    },
    /// A `Profile`: its rules feed the active-rules calculator and its
    /// `labelsToApply` register as an index parent for inheritance.
    Profile {
        id: ProfileId,
        spec: ProfileSpec,
        remove: bool,
    },
    /// A `WorkloadEndpoint`. `node` decides local vs. remote; `labels` are the
    /// endpoint's OWN labels, `profiles` its profile ids (index parents +
    /// inheritance source), `ipnets` its member IPs/CIDRs.
    WorkloadEndpoint {
        id: EndpointId,
        node: NodeName,
        labels: BTreeMap<String, String>,
        profiles: Vec<ProfileId>,
        ipnets: Vec<String>,
        remove: bool,
    },
    /// A `NetworkSet`: an index item only (a selector target), never enforced.
    NetworkSet {
        id: String,
        labels: BTreeMap<String, String>,
        nets: Vec<String>,
        remove: bool,
    },
    /// A `Tier` and its order, driving policy-chain ordering in the resolver.
    Tier {
        name: String,
        order: Option<f64>,
        remove: bool,
    },
}

/// The aggregate deltas one [`CalcGraph::on_update`] produced across the
/// components, for a caller (T055 callbacks) to translate to the wire protocol.
#[derive(Debug, Clone, Default)]
pub struct GraphDeltas {
    /// IP-set membership changes surfaced by the shared index.
    pub ip_set_member_deltas: Vec<Delta>,
    /// IP-set ids that became active (`0 -> 1` referrers) this update.
    pub ip_sets_added: Vec<IpSetId>,
    /// IP-set ids that became inactive (`1 -> 0` referrers) this update.
    pub ip_sets_removed: Vec<IpSetId>,
    /// Policy/profile active-set transitions this update.
    pub policy_transitions: Vec<Transition>,
    /// Recomputed per-endpoint policy orders (one per affected local endpoint).
    pub endpoint_orders: Vec<EndpointPolicyOrder>,
}

impl GraphDeltas {
    fn absorb_scan(&mut self, scan: crate::active_rules::ScanResult) {
        self.ip_set_member_deltas.extend(scan.deltas);
        self.ip_sets_added.extend(scan.newly_active);
        self.ip_sets_removed.extend(scan.newly_inactive);
    }
}

/// A local endpoint's inputs needed to recompute its effective labels when a
/// referenced profile's labels change.
#[derive(Debug, Clone)]
struct LocalEndpoint {
    own_labels: BTreeMap<String, String>,
    profiles: Vec<ProfileId>,
}

/// The calc-graph root: owns the calculation components and routes
/// [`ResourceUpdate`]s to them, keeping one coherent membership index.
#[derive(Debug)]
pub struct CalcGraph {
    local_node: NodeName,
    arc: ActiveRulesCalculator,
    /// Owns the single shared [`MembershipIndex`].
    scanner: RuleScanner,
    resolver: PolicyResolver,
    /// Local endpoints only (id → own labels + profile ids), so a profile-label
    /// change can re-drive the endpoints that inherit from it.
    local_endpoints: BTreeMap<EndpointId, LocalEndpoint>,
    /// Profile `labelsToApply`, for computing effective labels for the ARC and
    /// resolver (the index does its own inheritance separately).
    profile_labels: BTreeMap<ProfileId, BTreeMap<String, String>>,
    /// Latest resolved rules per active policy (a getter surface for callbacks).
    resolved_policies: BTreeMap<PolicyId, ResolvedPolicy>,
    /// Latest resolved rules per active profile.
    resolved_profiles: BTreeMap<ProfileId, ResolvedPolicy>,
}

impl CalcGraph {
    /// Create an empty graph for the given local node name.
    pub fn new(local_node: impl Into<NodeName>) -> Self {
        Self {
            local_node: local_node.into(),
            arc: ActiveRulesCalculator::new(),
            scanner: RuleScanner::new(),
            resolver: PolicyResolver::new(),
            local_endpoints: BTreeMap::new(),
            profile_labels: BTreeMap::new(),
            resolved_policies: BTreeMap::new(),
            resolved_profiles: BTreeMap::new(),
        }
    }

    /// The local node name this graph enforces policy for.
    pub fn local_node(&self) -> &str {
        &self.local_node
    }

    /// Route one datastore update to the components. Fails only if a selector in
    /// a policy/profile spec does not parse.
    pub fn on_update(&mut self, update: ResourceUpdate) -> Result<GraphDeltas, SelectorError> {
        let mut deltas = GraphDeltas::default();
        match update {
            ResourceUpdate::Policy { id, spec, remove } => {
                self.on_policy(id, spec, remove, &mut deltas)?;
            }
            ResourceUpdate::Profile { id, spec, remove } => {
                self.on_profile(id, spec, remove, &mut deltas)?;
            }
            ResourceUpdate::WorkloadEndpoint {
                id,
                node,
                labels,
                profiles,
                ipnets,
                remove,
            } => {
                self.on_workload_endpoint(id, node, labels, profiles, ipnets, remove, &mut deltas);
            }
            ResourceUpdate::NetworkSet {
                id,
                labels,
                nets,
                remove,
            } => {
                self.on_network_set(id, labels, nets, remove, &mut deltas);
            }
            ResourceUpdate::Tier {
                name,
                order,
                remove,
            } => {
                let orders = if remove {
                    self.resolver.on_tier_remove(&name)
                } else {
                    self.resolver.on_tier_update(&name, order)
                };
                deltas.endpoint_orders.extend(orders);
            }
        }
        Ok(deltas)
    }

    // ---- getters (aggregate state for T055 callbacks) --------------------

    /// Current members of an IP set.
    pub fn ip_set_members(&self, ip_set_id: &str) -> BTreeSet<Member> {
        self.scanner.members(ip_set_id)
    }

    /// Whether a policy is currently active on the local node.
    pub fn is_policy_active(&self, id: &str) -> bool {
        self.arc.is_policy_active(id)
    }

    /// Whether a profile is currently active on the local node.
    pub fn is_profile_active(&self, id: &str) -> bool {
        self.arc.is_profile_active(id)
    }

    /// Whether an IP set is currently registered (has an active referrer).
    pub fn is_ip_set_active(&self, ip_set_id: &str) -> bool {
        self.scanner.is_ip_set_active(ip_set_id)
    }

    /// A local endpoint's current ordered tier/policy list.
    pub fn endpoint_order(&self, endpoint_id: &str) -> EndpointPolicyOrder {
        self.resolver.resolve(endpoint_id)
    }

    /// The resolved (IP-set-id-carrying) rules of an active policy.
    pub fn resolved_policy(&self, id: &str) -> Option<&ResolvedPolicy> {
        self.resolved_policies.get(id)
    }

    /// The resolved rules of an active profile.
    pub fn resolved_profile(&self, id: &str) -> Option<&ResolvedPolicy> {
        self.resolved_profiles.get(id)
    }

    // ---- fan-out routing -------------------------------------------------

    fn on_policy(
        &mut self,
        id: PolicyId,
        spec: NetworkPolicySpec,
        remove: bool,
        deltas: &mut GraphDeltas,
    ) -> Result<(), SelectorError> {
        if remove {
            let transitions = self.arc.on_policy_remove(&id);
            self.apply_transitions(transitions, deltas);
            deltas
                .endpoint_orders
                .extend(self.resolver.on_policy_remove(&id));
            return Ok(());
        }
        // Active-rules side: drives which policies are active + their IP sets.
        let transitions = self.arc.on_policy_update(&id, &spec)?;
        self.apply_transitions(transitions, deltas);
        // Resolver side: drives per-endpoint policy order. Reuse from_resources
        // to parse the applies-to selector + direction rather than duplicating.
        let eval = network_policy_to_eval(&spec)?;
        let tier = spec.tier.as_deref().unwrap_or(DEFAULT_TIER);
        deltas
            .endpoint_orders
            .extend(self.resolver.on_policy_update(
                &id,
                tier,
                spec.order,
                eval.selector,
                eval.applies_ingress,
                eval.applies_egress,
            ));
        Ok(())
    }

    fn on_profile(
        &mut self,
        id: ProfileId,
        spec: ProfileSpec,
        remove: bool,
        deltas: &mut GraphDeltas,
    ) -> Result<(), SelectorError> {
        if remove {
            let transitions = self.arc.on_profile_remove(&id);
            self.apply_transitions(transitions, deltas);
            deltas
                .ip_set_member_deltas
                .extend(self.scanner.remove_namespace(&id));
            self.profile_labels.remove(&id);
            self.redrive_profile_endpoints(&id, deltas);
            return Ok(());
        }
        let transitions = self.arc.on_profile_update(&id, &spec)?;
        self.apply_transitions(transitions, deltas);
        // Register labelsToApply as an index parent so endpoints referencing the
        // profile inherit them for IP-set membership.
        deltas.ip_set_member_deltas.extend(
            self.scanner
                .update_namespace(&id, spec.labels_to_apply.clone()),
        );
        self.profile_labels.insert(id.clone(), spec.labels_to_apply);
        // Local endpoints that inherit from this profile need their effective
        // labels (and thus active-set/order) recomputed.
        self.redrive_profile_endpoints(&id, deltas);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn on_workload_endpoint(
        &mut self,
        id: EndpointId,
        node: NodeName,
        labels: BTreeMap<String, String>,
        profiles: Vec<ProfileId>,
        ipnets: Vec<String>,
        remove: bool,
        deltas: &mut GraphDeltas,
    ) {
        if remove {
            deltas
                .ip_set_member_deltas
                .extend(self.scanner.remove_endpoint(&id));
            self.remove_local_endpoint(&id, deltas);
            return;
        }
        // Every endpoint — local or remote — is an item in the shared index:
        // IP sets can include pods on other nodes.
        let members: BTreeSet<Member> = ipnets.into_iter().collect();
        deltas
            .ip_set_member_deltas
            .extend(
                self.scanner
                    .update_endpoint(&id, labels.clone(), profiles.clone(), members),
            );

        if node == self.local_node {
            let eff = self.effective_labels(&labels, &profiles);
            let transitions = self
                .arc
                .on_endpoint_update(&id, eff.clone(), profiles.clone());
            self.apply_transitions(transitions, deltas);
            deltas
                .endpoint_orders
                .push(self.resolver.on_endpoint_update(&id, eff));
            self.local_endpoints.insert(
                id,
                LocalEndpoint {
                    own_labels: labels,
                    profiles,
                },
            );
        } else {
            // A previously-local endpoint that moved to another node stops being
            // enforced here (but remains an index item, updated above).
            self.remove_local_endpoint(&id, deltas);
        }
    }

    fn on_network_set(
        &mut self,
        id: String,
        labels: BTreeMap<String, String>,
        nets: Vec<String>,
        remove: bool,
        deltas: &mut GraphDeltas,
    ) {
        // A network set is a selector target only: an index item, no policy or
        // resolver involvement.
        if remove {
            deltas
                .ip_set_member_deltas
                .extend(self.scanner.remove_endpoint(&id));
        } else {
            let members: BTreeSet<Member> = nets.into_iter().collect();
            deltas
                .ip_set_member_deltas
                .extend(self.scanner.update_endpoint(&id, labels, vec![], members));
        }
    }

    // ---- helpers ---------------------------------------------------------

    /// Drive the [`RuleScanner`] off active-set transitions, keeping the resolved
    /// rule cache in step and accumulating IP-set deltas.
    fn apply_transitions(&mut self, transitions: Vec<Transition>, deltas: &mut GraphDeltas) {
        for t in transitions {
            match &t {
                Transition::PolicyActive(id) => {
                    if let Some(rules) = self.arc.policy_rules(id).cloned() {
                        let scan = self.scanner.on_policy_active(id.clone(), &rules);
                        if let Some(resolved) = scan.resolved.clone() {
                            self.resolved_policies.insert(id.clone(), resolved);
                        }
                        deltas.absorb_scan(scan);
                    }
                }
                Transition::PolicyInactive(id) => {
                    let scan = self.scanner.on_policy_inactive(id.clone());
                    self.resolved_policies.remove(id);
                    deltas.absorb_scan(scan);
                }
                Transition::ProfileActive(id) => {
                    if let Some(rules) = self.arc.profile_rules(id).cloned() {
                        let scan = self.scanner.on_profile_active(id.clone(), &rules);
                        if let Some(resolved) = scan.resolved.clone() {
                            self.resolved_profiles.insert(id.clone(), resolved);
                        }
                        deltas.absorb_scan(scan);
                    }
                }
                Transition::ProfileInactive(id) => {
                    let scan = self.scanner.on_profile_inactive(id.clone());
                    self.resolved_profiles.remove(id);
                    deltas.absorb_scan(scan);
                }
            }
            deltas.policy_transitions.push(t);
        }
    }

    /// Effective labels: profile `labelsToApply` (earlier profile wins) overridden
    /// by the endpoint's own labels. Mirrors the index's inheritance precedence.
    fn effective_labels(
        &self,
        own: &BTreeMap<String, String>,
        profiles: &[ProfileId],
    ) -> BTreeMap<String, String> {
        let mut merged = BTreeMap::new();
        // Insert profiles last-to-first so earlier profiles overwrite later ones.
        for pid in profiles.iter().rev() {
            if let Some(l) = self.profile_labels.get(pid) {
                for (k, v) in l {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }
        for (k, v) in own {
            merged.insert(k.clone(), v.clone());
        }
        merged
    }

    /// Recompute the active-set / order of every local endpoint referencing the
    /// given profile (its `labelsToApply` — and thus their effective labels —
    /// just changed).
    fn redrive_profile_endpoints(&mut self, profile_id: &str, deltas: &mut GraphDeltas) {
        let affected: Vec<EndpointId> = self
            .local_endpoints
            .iter()
            .filter(|(_, ep)| ep.profiles.iter().any(|p| p == profile_id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in affected {
            let ep = self.local_endpoints[&id].clone();
            let eff = self.effective_labels(&ep.own_labels, &ep.profiles);
            let transitions = self
                .arc
                .on_endpoint_update(&id, eff.clone(), ep.profiles.clone());
            self.apply_transitions(transitions, deltas);
            deltas
                .endpoint_orders
                .push(self.resolver.on_endpoint_update(&id, eff));
        }
    }

    /// Drop a local endpoint from the ARC and resolver if it was tracked as
    /// local (a no-op for remote/unknown ids). Does NOT touch the index item.
    fn remove_local_endpoint(&mut self, id: &str, deltas: &mut GraphDeltas) {
        if self.local_endpoints.remove(id).is_some() {
            let transitions = self.arc.on_endpoint_remove(id);
            self.apply_transitions(transitions, deltas);
            deltas
                .endpoint_orders
                .push(self.resolver.on_endpoint_remove(id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_rules::ip_set_id;
    use crate::selector::Selector;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn np(json: &str) -> NetworkPolicySpec {
        serde_json::from_str(json).unwrap()
    }

    fn peer_id(sel: &str) -> String {
        ip_set_id(&Selector::parse(sel).unwrap())
    }

    fn policy(id: &str, spec: NetworkPolicySpec) -> ResourceUpdate {
        ResourceUpdate::Policy {
            id: id.into(),
            spec,
            remove: false,
        }
    }

    fn wep(
        id: &str,
        node: &str,
        lbls: &[(&str, &str)],
        profiles: &[&str],
        ipnets: &[&str],
    ) -> ResourceUpdate {
        ResourceUpdate::WorkloadEndpoint {
            id: id.into(),
            node: node.into(),
            labels: labels(lbls),
            profiles: profiles.iter().map(|s| s.to_string()).collect(),
            ipnets: ipnets.iter().map(|s| s.to_string()).collect(),
            remove: false,
        }
    }

    fn remove_wep(id: &str, node: &str) -> ResourceUpdate {
        ResourceUpdate::WorkloadEndpoint {
            id: id.into(),
            node: node.into(),
            labels: BTreeMap::new(),
            profiles: vec![],
            ipnets: vec![],
            remove: true,
        }
    }

    fn profile_labels(id: &str, lbls: &[(&str, &str)]) -> ResourceUpdate {
        ResourceUpdate::Profile {
            id: id.into(),
            spec: ProfileSpec {
                labels_to_apply: labels(lbls),
                ..Default::default()
            },
            remove: false,
        }
    }

    fn tier(name: &str, order: Option<f64>) -> ResourceUpdate {
        ResourceUpdate::Tier {
            name: name.into(),
            order,
            remove: false,
        }
    }

    const DB_FROM_WEB: &str = r#"{"selector":"role == 'db'","types":["Ingress"],
        "ingress":[{"action":"Allow","source":{"selector":"role == 'web'"}}]}"#;

    /// End-to-end: a policy + a local db endpoint + a web endpoint yields an
    /// active policy, a peer IP set holding the web IP, and a resolved order.
    #[test]
    fn end_to_end_active_policy_peer_ipset_and_order() {
        let mut g = CalcGraph::new("node-a");
        g.on_update(tier("default", Some(100.0))).unwrap();
        g.on_update(policy("np1", np(DB_FROM_WEB))).unwrap();
        g.on_update(wep("db", "node-a", &[("role", "db")], &[], &["10.0.0.9"]))
            .unwrap();
        g.on_update(wep("web", "node-a", &[("role", "web")], &[], &["10.0.0.5"]))
            .unwrap();

        // Policy active on this node.
        assert!(g.is_policy_active("np1"));

        // Peer selector role=='web' is materialised and holds the web IP.
        let peer = peer_id("role == 'web'");
        assert!(g.is_ip_set_active(&peer));
        assert_eq!(g.ip_set_members(&peer), set(&["10.0.0.5"]));

        // The db endpoint's resolved order includes np1 on ingress.
        let order = g.endpoint_order("db");
        assert_eq!(order.tiers.len(), 1);
        assert_eq!(order.tiers[0].name, "default");
        assert_eq!(order.tiers[0].ingress_policies, vec!["np1"]);
        assert!(order.tiers[0].egress_policies.is_empty());

        // The resolved rule carries the peer IP-set id on the source side.
        let resolved = g.resolved_policy("np1").unwrap();
        assert_eq!(resolved.inbound[0].src_ip_set_ids, vec![peer]);
    }

    /// Relabelling the web endpoint away from role=web evicts its IP.
    #[test]
    fn relabel_peer_endpoint_leaves_ipset() {
        let mut g = CalcGraph::new("node-a");
        g.on_update(policy("np1", np(DB_FROM_WEB))).unwrap();
        g.on_update(wep("db", "node-a", &[("role", "db")], &[], &["10.0.0.9"]))
            .unwrap();
        g.on_update(wep("web", "node-a", &[("role", "web")], &[], &["10.0.0.5"]))
            .unwrap();
        let peer = peer_id("role == 'web'");
        assert_eq!(g.ip_set_members(&peer), set(&["10.0.0.5"]));

        let deltas = g
            .on_update(wep(
                "web",
                "node-a",
                &[("role", "cache")],
                &[],
                &["10.0.0.5"],
            ))
            .unwrap();
        assert!(g.ip_set_members(&peer).is_empty());
        // The eviction surfaces as a Removed member delta.
        assert!(deltas.ip_set_member_deltas.iter().any(|d| {
            d.ip_set_id == peer
                && d.member == "10.0.0.5"
                && d.change == crate::MemberChange::Removed
        }));
    }

    /// Removing the only local db endpoint deactivates the policy and
    /// unregisters its peer IP set.
    #[test]
    fn removing_applies_to_endpoint_deactivates_policy_and_ipset() {
        let mut g = CalcGraph::new("node-a");
        g.on_update(policy("np1", np(DB_FROM_WEB))).unwrap();
        g.on_update(wep("db", "node-a", &[("role", "db")], &[], &["10.0.0.9"]))
            .unwrap();
        g.on_update(wep("web", "node-a", &[("role", "web")], &[], &["10.0.0.5"]))
            .unwrap();
        let peer = peer_id("role == 'web'");
        assert!(g.is_policy_active("np1"));
        assert!(g.is_ip_set_active(&peer));

        g.on_update(remove_wep("db", "node-a")).unwrap();
        assert!(!g.is_policy_active("np1"));
        assert!(!g.is_ip_set_active(&peer));
        assert!(g.resolved_policy("np1").is_none());
    }

    /// A remote endpoint matching applies-to does NOT activate the policy, but a
    /// remote endpoint matching a peer selector still contributes its IP.
    #[test]
    fn remote_endpoint_filtered_from_active_but_contributes_to_ipset() {
        let mut g = CalcGraph::new("node-a");
        g.on_update(policy("np1", np(DB_FROM_WEB))).unwrap();

        // A REMOTE endpoint matching the applies-to selector role=='db'.
        g.on_update(wep(
            "db-remote",
            "node-b",
            &[("role", "db")],
            &[],
            &["10.0.0.9"],
        ))
        .unwrap();
        assert!(
            !g.is_policy_active("np1"),
            "remote endpoint must not activate"
        );
        assert!(g.endpoint_order("db-remote").tiers.is_empty());

        // A LOCAL db endpoint activates the policy and registers the peer set.
        g.on_update(wep("db", "node-a", &[("role", "db")], &[], &["10.0.0.8"]))
            .unwrap();
        assert!(g.is_policy_active("np1"));
        let peer = peer_id("role == 'web'");

        // A REMOTE web endpoint still joins the peer IP set (IP sets are cluster-wide).
        g.on_update(wep(
            "web-remote",
            "node-b",
            &[("role", "web")],
            &[],
            &["10.0.0.5"],
        ))
        .unwrap();
        assert_eq!(g.ip_set_members(&peer), set(&["10.0.0.5"]));
        // ...but it acquires no resolved policy order (not enforced here).
        assert!(g.endpoint_order("web-remote").tiers.is_empty());
    }

    /// A profile's labelsToApply are inherited by referencing endpoints for
    /// peer IP-set membership.
    #[test]
    fn profile_labels_inherited_for_peer_ipset_membership() {
        let mut g = CalcGraph::new("node-a");
        // Policy applies to all local endpoints; peer selects stage=='frontend'.
        let spec = np(r#"{"selector":"all()","types":["Ingress"],
            "ingress":[{"action":"Allow","source":{"selector":"stage == 'frontend'"}}]}"#);
        g.on_update(policy("np1", spec)).unwrap();
        // A local endpoint activates the policy (all() matches it).
        g.on_update(wep("local", "node-a", &[("k", "v")], &[], &["10.0.0.1"]))
            .unwrap();
        assert!(g.is_policy_active("np1"));

        // Profile carries stage=frontend; a peer endpoint references it but has
        // no own stage label — it inherits and thus matches the peer selector.
        g.on_update(profile_labels("frontends", &[("stage", "frontend")]))
            .unwrap();
        g.on_update(wep("peer", "node-b", &[], &["frontends"], &["10.0.0.5"]))
            .unwrap();

        let peer = peer_id("stage == 'frontend'");
        assert_eq!(g.ip_set_members(&peer), set(&["10.0.0.5"]));
    }

    /// A local endpoint's applies-to match can come from an inherited profile
    /// label, and a later profile-label change re-drives the active set.
    #[test]
    fn local_endpoint_active_via_inherited_label_and_redrive() {
        let mut g = CalcGraph::new("node-a");
        // Policy applies to endpoints with the inherited label stage=='frontend'.
        let spec = np(r#"{"selector":"stage == 'frontend'","types":["Ingress"]}"#);
        g.on_update(policy("np1", spec)).unwrap();

        // Endpoint arrives BEFORE the profile's labels are known → not yet active.
        g.on_update(wep("ep", "node-a", &[], &["frontends"], &["10.0.0.1"]))
            .unwrap();
        assert!(!g.is_policy_active("np1"));

        // Profile labels arrive → the graph re-drives the endpoint → active.
        g.on_update(profile_labels("frontends", &[("stage", "frontend")]))
            .unwrap();
        assert!(g.is_policy_active("np1"));
        // The resolver now governs the endpoint too.
        let order = g.endpoint_order("ep");
        assert_eq!(order.tiers[0].ingress_policies, vec!["np1"]);
    }

    /// A shared peer selector stays registered until the last active policy
    /// referencing it goes inactive (ref-counting through the graph).
    #[test]
    fn shared_peer_ipset_refcounted_across_policies() {
        let mut g = CalcGraph::new("node-a");
        let a = np(r#"{"selector":"role == 'db'","types":["Ingress"],
            "ingress":[{"action":"Allow","source":{"selector":"role == 'web'"}}]}"#);
        let b = np(r#"{"selector":"role == 'cache'","types":["Ingress"],
            "ingress":[{"action":"Allow","source":{"selector":"role == 'web'"}}]}"#);
        g.on_update(policy("a", a)).unwrap();
        g.on_update(policy("b", b)).unwrap();
        g.on_update(wep("db", "node-a", &[("role", "db")], &[], &["10.0.0.1"]))
            .unwrap();
        g.on_update(wep(
            "cache",
            "node-a",
            &[("role", "cache")],
            &[],
            &["10.0.0.2"],
        ))
        .unwrap();
        let peer = peer_id("role == 'web'");
        assert!(g.is_ip_set_active(&peer));

        // Remove one referrer: still held by the other.
        g.on_update(remove_wep("db", "node-a")).unwrap();
        assert!(g.is_ip_set_active(&peer));
        // Remove the last referrer: unregistered.
        g.on_update(remove_wep("cache", "node-a")).unwrap();
        assert!(!g.is_ip_set_active(&peer));
    }

    /// A network set contributes its nets to any peer selector it matches.
    #[test]
    fn network_set_contributes_to_matching_peer_ipset() {
        let mut g = CalcGraph::new("node-a");
        let spec = np(r#"{"selector":"all()","types":["Ingress"],
            "ingress":[{"action":"Allow","source":{"selector":"env == 'corp'"}}]}"#);
        g.on_update(policy("np1", spec)).unwrap();
        g.on_update(wep("local", "node-a", &[("k", "v")], &[], &["10.0.0.1"]))
            .unwrap();
        let peer = peer_id("env == 'corp'");

        g.on_update(ResourceUpdate::NetworkSet {
            id: "corpnet".into(),
            labels: labels(&[("env", "corp")]),
            nets: vec!["192.168.0.0/16".into()],
            remove: false,
        })
        .unwrap();
        assert_eq!(g.ip_set_members(&peer), set(&["192.168.0.0/16"]));

        // Removing the network set evicts its nets.
        g.on_update(ResourceUpdate::NetworkSet {
            id: "corpnet".into(),
            labels: BTreeMap::new(),
            nets: vec![],
            remove: true,
        })
        .unwrap();
        assert!(g.ip_set_members(&peer).is_empty());
    }
}
