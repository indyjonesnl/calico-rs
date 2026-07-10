//! Active-rules calculation: which policies/profiles are *active* on this node,
//! and which rule selectors must be materialised as IP sets.
//!
//! This is the Rust counterpart of upstream Felix's
//! `felix/calc/active_rules_calculator.go` + `rule_scanner.go`. It sits between
//! the datastore and the [`MembershipIndex`](crate::MembershipIndex) +
//! policy resolver, reproducing two invariants:
//!
//! # 1. Active-set transitions ([`ActiveRulesCalculator`])
//!
//! - A **policy is active** iff its applies-to selector matches at least one
//!   LOCAL endpoint (a workload on this node). It flips `active`⇄`inactive`
//!   exactly on the edge where its selector starts / stops matching *any* local
//!   endpoint — in particular, the last matching endpoint leaving drives it
//!   inactive.
//! - A **profile is active** iff at least one local endpoint references it by
//!   profile id (and its rules are known — an unknown-but-referenced profile is
//!   not activated, since there are no rules to scan; upstream's dummy-drop
//!   fallback is intentionally deferred).
//!
//! Each mutation returns the exact set of [`Transition`]s (no full re-list).
//!
//! # 2. Reference-counted IP-set registration ([`RuleScanner`])
//!
//! Each active policy/profile's rules reference peer selectors (a rule's
//! `source`/`destination` `selector`, optionally combined with its
//! `namespaceSelector`). Every distinct selector is hashed to a stable
//! [`ip_set_id`] and registered with a [`MembershipIndex`]. Registration is
//! **ref-counted across active owners**: a selector shared by two active
//! policies stays registered until the *last* active referrer goes inactive
//! (`0 -> 1` registers, `1 -> 0` unregisters). This mirrors upstream's
//! `rulesIDToUIDs` / `uidsToRulesIDs` bookkeeping.
//!
//! CIDR (`nets`) and port matches are NOT materialised as IP sets; they pass
//! through the resolved rules unchanged.
//!
//! # MembershipIndex wiring
//!
//! The [`RuleScanner`] **owns and drives** a [`MembershipIndex`]: it calls
//! [`MembershipIndex::add_selector`] on a `0 -> 1` ref-count transition and
//! [`MembershipIndex::remove_selector`] on `1 -> 0`, and forwards endpoint /
//! namespace membership updates to the index. Every such call surfaces the
//! index's member [`Delta`]s back to the caller, which (in T055) become
//! `proto::IpSetUpdate` / `IpSetDeltaUpdate`. This keeps the IP-set lifecycle in
//! one place and testable end-to-end.
//!
//! # Endpoint effective-labels assumption
//!
//! [`ActiveRulesCalculator::on_endpoint_update`] takes the endpoint's
//! **effective** labels (own labels already merged with inherited
//! namespace/profile labels). The active-set match uses [`Selector::matches`]
//! directly against those labels. The [`MembershipIndex`] the [`RuleScanner`]
//! owns performs its own inheritance for IP-set membership (it is fed raw item
//! labels + parents).

use std::collections::{BTreeMap, BTreeSet};

use apis::{Action, EntityRule, NetworkPolicySpec, ProfileSpec, Protocol, Rule};

use crate::labelindex::{Delta, IpSetId, Member, MembershipIndex, ParentId};
use crate::selector::{Selector, SelectorError};

/// Local endpoint identifier.
pub type EndpointId = String;
/// Policy identifier.
pub type PolicyId = String;
/// Profile identifier.
pub type ProfileId = String;

/// A stable IP-set id for a rule peer selector.
///
/// Computed as `"s:"` + a 64-bit FNV-1a hash (hex) of the selector's canonical
/// string ([`Selector`]'s [`std::fmt::Display`]). The scheme is deterministic
/// and stable across runs; the `"s:"` prefix mirrors upstream's selector
/// IP-set namespace. It is not cryptographic, but the property policy
/// correctness relies on holds: two rules referencing the *same* selector
/// always hash to the *same* id (so ref-counting coalesces them), and distinct
/// canonical selectors get distinct ids.
pub fn ip_set_id(selector: &Selector) -> IpSetId {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in selector.to_string().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("s:{hash:016x}")
}

// ---- ActiveRulesCalculator -----------------------------------------------

/// An active/inactive transition for a policy or profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// A policy's selector started matching a local endpoint.
    PolicyActive(PolicyId),
    /// A policy's selector stopped matching any local endpoint.
    PolicyInactive(PolicyId),
    /// A profile became referenced by a local endpoint (and its rules are known).
    ProfileActive(ProfileId),
    /// A profile stopped being referenced (or its rules were removed while active).
    ProfileInactive(ProfileId),
}

/// A rule prepared for scanning: peer selectors already parsed and combined,
/// CIDR/port matches carried through verbatim.
#[derive(Debug, Clone)]
pub struct ScanRule {
    /// Rule action.
    pub action: Action,
    /// Protocol constraint, if any (rendered form).
    pub protocol: Option<String>,
    /// Source peer selector (`source.selector` combined with
    /// `source.namespaceSelector`), if present.
    pub src_selector: Option<Selector>,
    /// Destination peer selector.
    pub dst_selector: Option<Selector>,
    /// Source CIDRs (pass-through, never materialised as an IP set).
    pub src_nets: Vec<String>,
    /// Destination CIDRs (pass-through).
    pub dst_nets: Vec<String>,
    /// Destination ports (pass-through).
    pub dst_ports: Vec<u16>,
}

/// A policy or profile's inbound/outbound rules prepared for scanning.
#[derive(Debug, Clone, Default)]
pub struct PolicyRules {
    /// Inbound (ingress) rules.
    pub inbound: Vec<ScanRule>,
    /// Outbound (egress) rules.
    pub outbound: Vec<ScanRule>,
}

#[derive(Debug, Clone)]
struct StoredPolicy {
    selector: Selector,
    rules: PolicyRules,
}

/// Tracks which policies/profiles are active for the local endpoints it knows
/// about, emitting [`Transition`]s as the active set changes.
#[derive(Debug, Default)]
pub struct ActiveRulesCalculator {
    /// Local endpoints: id -> (effective labels, profile ids).
    endpoints: BTreeMap<EndpointId, (BTreeMap<String, String>, Vec<ProfileId>)>,
    /// Known policies.
    policies: BTreeMap<PolicyId, StoredPolicy>,
    /// Known profiles' rules.
    profiles: BTreeMap<ProfileId, PolicyRules>,
    /// Currently-active policy ids.
    active_policies: BTreeSet<PolicyId>,
    /// Currently-active profile ids (referenced ∩ known).
    active_profiles: BTreeSet<ProfileId>,
}

impl ActiveRulesCalculator {
    /// Create an empty calculator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a local endpoint with its effective labels and profile
    /// ids. Returns the resulting active-set transitions.
    pub fn on_endpoint_update(
        &mut self,
        id: impl Into<EndpointId>,
        labels: BTreeMap<String, String>,
        profile_ids: Vec<ProfileId>,
    ) -> Vec<Transition> {
        self.endpoints.insert(id.into(), (labels, profile_ids));
        self.recompute()
    }

    /// Remove a local endpoint. Returns the resulting transitions.
    pub fn on_endpoint_remove(&mut self, id: &str) -> Vec<Transition> {
        self.endpoints.remove(id);
        self.recompute()
    }

    /// Insert or replace a policy from its v3 spec. Fails only if a selector
    /// does not parse. Returns the resulting transitions.
    pub fn on_policy_update(
        &mut self,
        id: impl Into<PolicyId>,
        spec: &NetworkPolicySpec,
    ) -> Result<Vec<Transition>, SelectorError> {
        let stored = StoredPolicy {
            selector: selector_or_all(&spec.selector)?,
            rules: PolicyRules {
                inbound: scan_rules(&spec.ingress)?,
                outbound: scan_rules(&spec.egress)?,
            },
        };
        self.policies.insert(id.into(), stored);
        Ok(self.recompute())
    }

    /// Remove a policy. Returns the resulting transitions.
    pub fn on_policy_remove(&mut self, id: &str) -> Vec<Transition> {
        self.policies.remove(id);
        self.recompute()
    }

    /// Insert or replace a profile's rules. Returns the resulting transitions.
    pub fn on_profile_update(
        &mut self,
        id: impl Into<ProfileId>,
        spec: &ProfileSpec,
    ) -> Result<Vec<Transition>, SelectorError> {
        let rules = PolicyRules {
            inbound: scan_rules(&spec.ingress)?,
            outbound: scan_rules(&spec.egress)?,
        };
        self.profiles.insert(id.into(), rules);
        Ok(self.recompute())
    }

    /// Remove a profile's rules. Returns the resulting transitions.
    pub fn on_profile_remove(&mut self, id: &str) -> Vec<Transition> {
        self.profiles.remove(id);
        self.recompute()
    }

    /// The scan-ready rules of an active (or known) policy, for driving a
    /// [`RuleScanner`].
    pub fn policy_rules(&self, id: &str) -> Option<&PolicyRules> {
        self.policies.get(id).map(|p| &p.rules)
    }

    /// The scan-ready rules of a known profile.
    pub fn profile_rules(&self, id: &str) -> Option<&PolicyRules> {
        self.profiles.get(id)
    }

    /// Whether a policy is currently active.
    pub fn is_policy_active(&self, id: &str) -> bool {
        self.active_policies.contains(id)
    }

    /// Whether a profile is currently active.
    pub fn is_profile_active(&self, id: &str) -> bool {
        self.active_profiles.contains(id)
    }

    /// Recompute the active sets and diff against the previous ones to produce
    /// transitions.
    fn recompute(&mut self) -> Vec<Transition> {
        // Policies: active iff selector matches some local endpoint.
        let mut new_policies = BTreeSet::new();
        for (pid, pol) in &self.policies {
            if self
                .endpoints
                .values()
                .any(|(labels, _)| pol.selector.matches(labels))
            {
                new_policies.insert(pid.clone());
            }
        }

        // Profiles: active iff referenced by a local endpoint AND rules known.
        let mut referenced = BTreeSet::new();
        for (_, profile_ids) in self.endpoints.values() {
            for pid in profile_ids {
                referenced.insert(pid.clone());
            }
        }
        let new_profiles: BTreeSet<ProfileId> = referenced
            .into_iter()
            .filter(|pid| self.profiles.contains_key(pid))
            .collect();

        let mut transitions = Vec::new();
        for pid in new_policies.difference(&self.active_policies) {
            transitions.push(Transition::PolicyActive(pid.clone()));
        }
        for pid in self.active_policies.difference(&new_policies) {
            transitions.push(Transition::PolicyInactive(pid.clone()));
        }
        for pid in new_profiles.difference(&self.active_profiles) {
            transitions.push(Transition::ProfileActive(pid.clone()));
        }
        for pid in self.active_profiles.difference(&new_profiles) {
            transitions.push(Transition::ProfileInactive(pid.clone()));
        }

        self.active_policies = new_policies;
        self.active_profiles = new_profiles;
        transitions
    }
}

// ---- RuleScanner ----------------------------------------------------------

/// A rule with its peer selectors resolved to IP-set ids.
///
/// Mirrors the shape of `proto::PolicyRule`: selector peers become
/// `src_ip_set_ids` / `dst_ip_set_ids`; CIDRs and ports pass through. T053/T055
/// map this into the wire form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRule {
    /// Rule action.
    pub action: Action,
    /// Protocol constraint, if any.
    pub protocol: Option<String>,
    /// IP-set ids resolved from the source selector.
    pub src_ip_set_ids: Vec<IpSetId>,
    /// IP-set ids resolved from the destination selector.
    pub dst_ip_set_ids: Vec<IpSetId>,
    /// Source CIDRs (pass-through).
    pub src_nets: Vec<String>,
    /// Destination CIDRs (pass-through).
    pub dst_nets: Vec<String>,
    /// Destination ports (pass-through).
    pub dst_ports: Vec<u16>,
}

/// An active policy/profile's rules with peer selectors resolved to IP-set ids.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvedPolicy {
    /// Resolved inbound rules.
    pub inbound: Vec<ResolvedRule>,
    /// Resolved outbound rules.
    pub outbound: Vec<ResolvedRule>,
}

/// The result of feeding one active/inactive event to a [`RuleScanner`].
#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    /// The resolved rules for an *active* event; `None` for an inactive one.
    pub resolved: Option<ResolvedPolicy>,
    /// IP-set ids that just became active (`0 -> 1` referrers).
    pub newly_active: Vec<IpSetId>,
    /// IP-set ids that just became inactive (`1 -> 0` referrers).
    pub newly_inactive: Vec<IpSetId>,
    /// Member deltas surfaced by the owned [`MembershipIndex`] from
    /// (un)registering the selectors above.
    pub deltas: Vec<Delta>,
}

/// Identifies who references an IP set, keeping policy and profile id spaces
/// distinct.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum OwnerKey {
    Policy(PolicyId),
    Profile(ProfileId),
}

/// Scans active policies/profiles for rule selectors, ref-counts the resulting
/// IP sets, and drives an owned [`MembershipIndex`].
#[derive(Debug, Default)]
pub struct RuleScanner {
    index: MembershipIndex,
    /// Selector backing each known IP-set id (present iff ref-count >= 1).
    selectors: BTreeMap<IpSetId, Selector>,
    /// Ref-count per IP-set id across active owners.
    refcount: BTreeMap<IpSetId, usize>,
    /// The set of IP-set ids each owner currently references.
    owner_ip_sets: BTreeMap<OwnerKey, BTreeSet<IpSetId>>,
}

impl RuleScanner {
    /// Create an empty scanner.
    pub fn new() -> Self {
        Self::default()
    }

    /// A policy became active: scan and register its rule selectors.
    pub fn on_policy_active(&mut self, id: impl Into<PolicyId>, rules: &PolicyRules) -> ScanResult {
        self.on_active(OwnerKey::Policy(id.into()), rules)
    }

    /// A policy became inactive: drop its selector references.
    pub fn on_policy_inactive(&mut self, id: impl Into<PolicyId>) -> ScanResult {
        self.on_inactive(OwnerKey::Policy(id.into()))
    }

    /// A profile became active: scan and register its rule selectors.
    pub fn on_profile_active(
        &mut self,
        id: impl Into<ProfileId>,
        rules: &PolicyRules,
    ) -> ScanResult {
        self.on_active(OwnerKey::Profile(id.into()), rules)
    }

    /// A profile became inactive: drop its selector references.
    pub fn on_profile_inactive(&mut self, id: impl Into<ProfileId>) -> ScanResult {
        self.on_inactive(OwnerKey::Profile(id.into()))
    }

    /// Whether an IP set is currently active (ref-count >= 1).
    pub fn is_ip_set_active(&self, ip_set_id: &str) -> bool {
        self.refcount.get(ip_set_id).is_some_and(|c| *c >= 1)
    }

    /// The currently-active IP-set ids with their selectors.
    pub fn active_ip_sets(&self) -> Vec<(IpSetId, &Selector)> {
        self.selectors.iter().map(|(k, v)| (k.clone(), v)).collect()
    }

    /// The current members of an IP set (from the owned index).
    pub fn members(&self, ip_set_id: &str) -> BTreeSet<Member> {
        self.index.members(ip_set_id)
    }

    /// Feed the owned index an endpoint's raw labels/parents/members for IP-set
    /// membership. Returns the member deltas.
    pub fn update_endpoint(
        &mut self,
        id: impl Into<String>,
        own_labels: BTreeMap<String, String>,
        parents: Vec<ParentId>,
        members: BTreeSet<Member>,
    ) -> Vec<Delta> {
        self.index.update_item(id, own_labels, parents, members)
    }

    /// Remove an endpoint from the owned index. Returns the member deltas.
    pub fn remove_endpoint(&mut self, id: &str) -> Vec<Delta> {
        self.index.delete_item(id)
    }

    /// Update a namespace/profile parent's labels in the owned index.
    pub fn update_namespace(
        &mut self,
        id: impl Into<ParentId>,
        labels: BTreeMap<String, String>,
    ) -> Vec<Delta> {
        self.index.update_parent(id, labels)
    }

    /// Delete a namespace/profile parent from the owned index.
    pub fn remove_namespace(&mut self, id: &str) -> Vec<Delta> {
        self.index.delete_parent(id)
    }

    fn on_active(&mut self, owner: OwnerKey, rules: &PolicyRules) -> ScanResult {
        let resolved = ResolvedPolicy {
            inbound: rules.inbound.iter().map(|r| self.resolve_rule(r)).collect(),
            outbound: rules
                .outbound
                .iter()
                .map(|r| self.resolve_rule(r))
                .collect(),
        };
        // The full set of (id -> selector) this owner now references.
        let mut wanted: BTreeMap<IpSetId, Selector> = BTreeMap::new();
        for rule in rules.inbound.iter().chain(&rules.outbound) {
            for sel in [&rule.src_selector, &rule.dst_selector]
                .into_iter()
                .flatten()
            {
                wanted.insert(ip_set_id(sel), sel.clone());
            }
        }
        let wanted_ids: BTreeSet<IpSetId> = wanted.keys().cloned().collect();
        let mut result = self.reconcile_owner(owner, &wanted_ids, &wanted);
        result.resolved = Some(resolved);
        result
    }

    fn on_inactive(&mut self, owner: OwnerKey) -> ScanResult {
        self.reconcile_owner(owner, &BTreeSet::new(), &BTreeMap::new())
    }

    /// Move an owner's referenced IP-set id set to `wanted`, applying ref-count
    /// deltas and (un)registering selectors with the index on `0 -> 1`/`1 -> 0`.
    fn reconcile_owner(
        &mut self,
        owner: OwnerKey,
        wanted: &BTreeSet<IpSetId>,
        selectors: &BTreeMap<IpSetId, Selector>,
    ) -> ScanResult {
        let current = self.owner_ip_sets.get(&owner).cloned().unwrap_or_default();
        let mut result = ScanResult::default();

        // Newly referenced by this owner.
        for id in wanted.difference(&current) {
            let count = self.refcount.entry(id.clone()).or_insert(0);
            *count += 1;
            if *count == 1 {
                let sel = selectors[id].clone();
                self.selectors.insert(id.clone(), sel.clone());
                result
                    .deltas
                    .extend(self.index.add_selector(id.clone(), sel));
                result.newly_active.push(id.clone());
            }
        }
        // No longer referenced by this owner.
        for id in current.difference(wanted) {
            if let Some(count) = self.refcount.get_mut(id) {
                *count -= 1;
                if *count == 0 {
                    self.refcount.remove(id);
                    self.selectors.remove(id);
                    result.deltas.extend(self.index.remove_selector(id));
                    result.newly_inactive.push(id.clone());
                }
            }
        }

        if wanted.is_empty() {
            self.owner_ip_sets.remove(&owner);
        } else {
            self.owner_ip_sets.insert(owner, wanted.clone());
        }
        result
    }

    fn resolve_rule(&self, rule: &ScanRule) -> ResolvedRule {
        ResolvedRule {
            action: rule.action,
            protocol: rule.protocol.clone(),
            src_ip_set_ids: rule.src_selector.iter().map(ip_set_id).collect(),
            dst_ip_set_ids: rule.dst_selector.iter().map(ip_set_id).collect(),
            src_nets: rule.src_nets.clone(),
            dst_nets: rule.dst_nets.clone(),
            dst_ports: rule.dst_ports.clone(),
        }
    }
}

// ---- v3 spec -> scan-ready conversion -------------------------------------

/// Parse an applies-to selector; empty means "all endpoints".
fn selector_or_all(s: &str) -> Result<Selector, SelectorError> {
    if s.trim().is_empty() {
        Ok(Selector::All)
    } else {
        Selector::parse(s)
    }
}

/// Combine an entity's `selector` and `namespaceSelector` into a single peer
/// selector.
///
/// If both are present they are AND-combined as `(namespaceSelector) &&
/// (selector)`; if only one is present that one is used; if neither, `None`.
/// Note: full namespace-label prefixing (the `projectcalico.org/namespace`
/// mapping the update-processor applies upstream) is deferred — we AND the raw
/// expressions, which is correct when endpoint effective labels already carry
/// the inherited namespace labels (as the [`MembershipIndex`] models them).
fn combine_peer_selector(entity: &EntityRule) -> Result<Option<Selector>, SelectorError> {
    let sel = entity
        .selector
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let ns = entity
        .namespace_selector
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let expr = match (ns, sel) {
        (Some(ns), Some(sel)) => format!("({ns}) && ({sel})"),
        (Some(ns), None) => ns.to_string(),
        (None, Some(sel)) => sel.to_string(),
        (None, None) => return Ok(None),
    };
    Ok(Some(Selector::parse(&expr)?))
}

fn render_protocol(p: &Option<Protocol>) -> Option<String> {
    p.as_ref().map(|p| match p {
        Protocol::Named(s) => s.clone(),
        Protocol::Number(n) => n.to_string(),
    })
}

fn scan_rules(rules: &[Rule]) -> Result<Vec<ScanRule>, SelectorError> {
    rules
        .iter()
        .map(|r| {
            Ok(ScanRule {
                action: r.action,
                protocol: render_protocol(&r.protocol),
                src_selector: combine_peer_selector(&r.source)?,
                dst_selector: combine_peer_selector(&r.destination)?,
                src_nets: r.source.nets.clone(),
                dst_nets: r.destination.nets.clone(),
                dst_ports: r.destination.ports.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn members(items: &[&str]) -> BTreeSet<Member> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn spec(json: &str) -> NetworkPolicySpec {
        serde_json::from_str(json).unwrap()
    }

    fn profile(json: &str) -> ProfileSpec {
        serde_json::from_str(json).unwrap()
    }

    // ---- ActiveRulesCalculator: active-set transitions -------------------

    #[test]
    fn policy_active_only_when_selector_matches_a_local_endpoint() {
        let mut arc = ActiveRulesCalculator::new();
        // Policy known but no endpoints: inactive.
        let t = arc
            .on_policy_update(
                "p1",
                &spec(r#"{"selector":"role == 'db'","types":["Ingress"]}"#),
            )
            .unwrap();
        assert!(t.is_empty());
        assert!(!arc.is_policy_active("p1"));

        // Non-matching endpoint: still inactive.
        let t = arc.on_endpoint_update("ep1", labels(&[("role", "web")]), vec![]);
        assert!(t.is_empty());
        assert!(!arc.is_policy_active("p1"));

        // Matching endpoint arrives: becomes active exactly once.
        let t = arc.on_endpoint_update("ep2", labels(&[("role", "db")]), vec![]);
        assert_eq!(t, vec![Transition::PolicyActive("p1".into())]);
        assert!(arc.is_policy_active("p1"));
    }

    #[test]
    fn policy_goes_inactive_when_last_matching_endpoint_leaves() {
        let mut arc = ActiveRulesCalculator::new();
        arc.on_policy_update(
            "p1",
            &spec(r#"{"selector":"role == 'db'","types":["Ingress"]}"#),
        )
        .unwrap();
        arc.on_endpoint_update("ep1", labels(&[("role", "db")]), vec![]);
        arc.on_endpoint_update("ep2", labels(&[("role", "db")]), vec![]);
        assert!(arc.is_policy_active("p1"));

        // One of two matching endpoints leaves: still active, no transition.
        let t = arc.on_endpoint_remove("ep1");
        assert!(t.is_empty());
        assert!(arc.is_policy_active("p1"));

        // Last matching endpoint leaves: inactive.
        let t = arc.on_endpoint_remove("ep2");
        assert_eq!(t, vec![Transition::PolicyInactive("p1".into())]);
        assert!(!arc.is_policy_active("p1"));
    }

    #[test]
    fn relabelling_endpoint_flips_policy_active_edge() {
        let mut arc = ActiveRulesCalculator::new();
        arc.on_policy_update(
            "p1",
            &spec(r#"{"selector":"role == 'db'","types":["Ingress"]}"#),
        )
        .unwrap();
        arc.on_endpoint_update("ep1", labels(&[("role", "db")]), vec![]);
        assert!(arc.is_policy_active("p1"));
        // Relabel away from the selector: policy goes inactive.
        let t = arc.on_endpoint_update("ep1", labels(&[("role", "web")]), vec![]);
        assert_eq!(t, vec![Transition::PolicyInactive("p1".into())]);
    }

    #[test]
    fn profile_active_iff_referenced_by_local_endpoint() {
        let mut arc = ActiveRulesCalculator::new();
        arc.on_profile_update("prof1", &profile(r#"{"ingress":[{"action":"Allow"}]}"#))
            .unwrap();
        // Endpoint referencing prof1: active.
        let t = arc.on_endpoint_update("ep1", labels(&[]), vec!["prof1".into()]);
        assert_eq!(t, vec![Transition::ProfileActive("prof1".into())]);
        assert!(arc.is_profile_active("prof1"));

        // Endpoint stops referencing it: inactive.
        let t = arc.on_endpoint_update("ep1", labels(&[]), vec![]);
        assert_eq!(t, vec![Transition::ProfileInactive("prof1".into())]);
        assert!(!arc.is_profile_active("prof1"));
    }

    #[test]
    fn referenced_but_unknown_profile_is_not_active_until_rules_arrive() {
        let mut arc = ActiveRulesCalculator::new();
        let t = arc.on_endpoint_update("ep1", labels(&[]), vec!["prof1".into()]);
        assert!(t.is_empty());
        assert!(!arc.is_profile_active("prof1"));
        // Rules arrive while referenced: now active.
        let t = arc
            .on_profile_update("prof1", &profile(r#"{"ingress":[{"action":"Allow"}]}"#))
            .unwrap();
        assert_eq!(t, vec![Transition::ProfileActive("prof1".into())]);
    }

    // ---- RuleScanner: ref-counted IP-set registration --------------------

    fn sel(s: &str) -> Selector {
        Selector::parse(s).unwrap()
    }

    /// A single ingress rule whose source is the given selector.
    fn src_sel_rules(selector: &str) -> PolicyRules {
        PolicyRules {
            inbound: vec![ScanRule {
                action: Action::Allow,
                protocol: None,
                src_selector: Some(sel(selector)),
                dst_selector: None,
                src_nets: vec![],
                dst_nets: vec![],
                dst_ports: vec![],
            }],
            outbound: vec![],
        }
    }

    #[test]
    fn scanner_registers_and_unregisters_selector_on_active_inactive() {
        let mut rs = RuleScanner::new();
        let id = ip_set_id(&sel("role == 'web'"));

        let r = rs.on_policy_active("p1", &src_sel_rules("role == 'web'"));
        assert_eq!(r.newly_active, vec![id.clone()]);
        assert!(r.newly_inactive.is_empty());
        assert!(rs.is_ip_set_active(&id));
        // The resolved rule carries the ip-set id on the source side.
        let resolved = r.resolved.unwrap();
        assert_eq!(resolved.inbound[0].src_ip_set_ids, vec![id.clone()]);
        assert!(resolved.inbound[0].dst_ip_set_ids.is_empty());

        let r = rs.on_policy_inactive("p1");
        assert_eq!(r.newly_inactive, vec![id.clone()]);
        assert!(!rs.is_ip_set_active(&id));
    }

    #[test]
    fn shared_selector_stays_registered_until_last_referrer_gone() {
        let mut rs = RuleScanner::new();
        let id = ip_set_id(&sel("role == 'web'"));

        let r = rs.on_policy_active("p1", &src_sel_rules("role == 'web'"));
        assert_eq!(r.newly_active, vec![id.clone()]);

        // Second policy references the SAME selector: no new registration.
        let r = rs.on_policy_active("p2", &src_sel_rules("role == 'web'"));
        assert!(r.newly_active.is_empty());
        assert!(rs.is_ip_set_active(&id));

        // First goes inactive: still referenced by p2, no unregister.
        let r = rs.on_policy_inactive("p1");
        assert!(r.newly_inactive.is_empty());
        assert!(rs.is_ip_set_active(&id));

        // Second goes inactive: now unregistered.
        let r = rs.on_policy_inactive("p2");
        assert_eq!(r.newly_inactive, vec![id.clone()]);
        assert!(!rs.is_ip_set_active(&id));
    }

    #[test]
    fn cidr_peer_registers_no_ip_set() {
        let mut rs = RuleScanner::new();
        let rules = PolicyRules {
            inbound: vec![ScanRule {
                action: Action::Allow,
                protocol: None,
                src_selector: None,
                dst_selector: None,
                src_nets: vec!["10.0.0.0/8".into()],
                dst_nets: vec![],
                dst_ports: vec![],
            }],
            outbound: vec![],
        };
        let r = rs.on_policy_active("p1", &rules);
        assert!(r.newly_active.is_empty());
        assert!(rs.active_ip_sets().is_empty());
        let resolved = r.resolved.unwrap();
        assert!(resolved.inbound[0].src_ip_set_ids.is_empty());
        assert_eq!(resolved.inbound[0].src_nets, vec!["10.0.0.0/8".to_string()]);
    }

    #[test]
    fn scanner_drives_membership_index_for_active_selectors() {
        let mut rs = RuleScanner::new();
        let id = ip_set_id(&sel("role == 'web'"));

        // Endpoint present before the selector is registered.
        rs.update_endpoint(
            "ep1",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.1"]),
        );

        // Activating a policy registers the selector; members show up as deltas.
        let r = rs.on_policy_active("p1", &src_sel_rules("role == 'web'"));
        assert_eq!(r.newly_active, vec![id.clone()]);
        assert_eq!(rs.members(&id), members(&["10.0.0.1"]));

        // A second matching endpoint contributes an incremental delta.
        let deltas = rs.update_endpoint(
            "ep2",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.2"]),
        );
        assert_eq!(deltas.len(), 1);
        assert_eq!(rs.members(&id), members(&["10.0.0.1", "10.0.0.2"]));

        // Deactivating removes the selector and its members.
        let r = rs.on_policy_inactive("p1");
        assert_eq!(r.newly_inactive, vec![id.clone()]);
        assert!(rs.members(&id).is_empty());
    }

    #[test]
    fn namespace_and_selector_combine_into_one_ip_set() {
        // A rule source with both namespaceSelector and selector combines to a
        // single peer selector / ip-set id.
        let s = spec(
            r#"{"selector":"all()","types":["Ingress"],
                "ingress":[{"action":"Allow","source":{
                    "namespaceSelector":"kns == 'prod'","selector":"app == 'web'"}}]}"#,
        );
        let rules = PolicyRules {
            inbound: scan_rules(&s.ingress).unwrap(),
            outbound: vec![],
        };
        let combined = rules.inbound[0].src_selector.clone().unwrap();
        let expected_id = ip_set_id(&sel("(kns == 'prod') && (app == 'web')"));
        assert_eq!(ip_set_id(&combined), expected_id);

        let mut rs = RuleScanner::new();
        let r = rs.on_policy_active("p1", &rules);
        assert_eq!(r.newly_active, vec![expected_id]);
    }

    // ---- integration: ARC transitions drive the scanner ------------------

    #[test]
    fn arc_transitions_drive_scanner_registration() {
        let mut arc = ActiveRulesCalculator::new();
        let mut rs = RuleScanner::new();
        arc.on_policy_update(
            "p1",
            &spec(
                r#"{"selector":"role == 'db'","types":["Ingress"],
                    "ingress":[{"action":"Allow","source":{"selector":"role == 'web'"}}]}"#,
            ),
        )
        .unwrap();
        let peer_id = ip_set_id(&sel("role == 'web'"));

        // No local endpoint yet: policy inactive, nothing registered.
        assert!(!rs.is_ip_set_active(&peer_id));

        // A matching endpoint activates the policy; drive the scanner.
        let transitions = arc.on_endpoint_update("ep1", labels(&[("role", "db")]), vec![]);
        for t in transitions {
            match t {
                Transition::PolicyActive(id) => {
                    let r = rs.on_policy_active(&id, arc.policy_rules(&id).unwrap());
                    assert_eq!(r.newly_active, vec![peer_id.clone()]);
                }
                _ => panic!("unexpected transition"),
            }
        }
        assert!(rs.is_ip_set_active(&peer_id));

        // Endpoint leaves: policy inactive, scanner unregisters.
        let transitions = arc.on_endpoint_remove("ep1");
        for t in transitions {
            match t {
                Transition::PolicyInactive(id) => {
                    let r = rs.on_policy_inactive(&id);
                    assert_eq!(r.newly_inactive, vec![peer_id.clone()]);
                }
                _ => panic!("unexpected transition"),
            }
        }
        assert!(!rs.is_ip_set_active(&peer_id));
    }
}
