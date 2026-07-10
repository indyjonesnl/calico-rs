//! Per-endpoint policy resolution and ordering (spec FR-007, FR-012; the
//! conformance target SC-003).
//!
//! Where this sits: [`crate::policy_eval`] is the *decision* engine — given an
//! already-ordered set of tiers it classifies a packet Allow/Deny. The
//! `PolicyResolver` here is the step *before* that: given every policy (with its
//! tier, order and applies-to selector), every tier (with its order) and the set
//! of local endpoints (with their labels), it computes for **each endpoint** the
//! ordered list of tiers → the ordered policy ids that govern that endpoint in
//! each direction. That ordered view is what the dataplane endpoint manager turns
//! into policy chains; it maps directly onto `proto::TierInfo { name,
//! ingress_policies, egress_policies }`.
//!
//! Semantics are anchored to upstream `felix/calc/policy_resolver.go` and its
//! `felix/calc/policy_sorter.go`:
//!
//! - **Tier order** (`TierLess`): tiers sort by `order` ascending; a tier with no
//!   `order` (`None`) sorts *last*; ties broken by tier name lexically. There is
//!   no special case for the `default` tier or for profiles — the `default` tier
//!   is an ordinary tier that comes last only because it conventionally carries
//!   the largest order (or none), and profiles are not tiers at all (they are the
//!   evaluator's fallback, handled in [`crate::policy_eval`]).
//! - **Policy order within a tier** (`PolKVLess`): policies sort by `order`
//!   ascending; a policy with no `order` maps to `+Inf` upstream and so sorts
//!   *last*; ties broken by name lexically.
//! - **Direction** (`addPolicyToTierInfo`): a matching policy is listed in a
//!   tier's `ingress_policies` iff it governs ingress and in `egress_policies`
//!   iff it governs egress, each in the tier's sorted policy order.
//!
//! `order` is an `Option<f64>`. We treat a `NaN` order the same as `None` (sorts
//! last) so that ordering is always a total order and never panics — Rust's `f64`
//! is only `PartialOrd`.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

use crate::selector::Selector;

/// The ordered policies for one tier as they apply to a single endpoint.
///
/// Mirrors `proto::TierInfo`; the caller maps this into the dataplane view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierPolicies {
    pub name: String,
    pub ingress_policies: Vec<String>,
    pub egress_policies: Vec<String>,
}

/// One endpoint's fully resolved, ordered tier list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPolicyOrder {
    pub endpoint_id: String,
    pub tiers: Vec<TierPolicies>,
}

/// Stored metadata for a policy the resolver knows about.
#[derive(Debug, Clone)]
struct PolicyMeta {
    tier: String,
    order: Option<f64>,
    selector: Selector,
    ingress: bool,
    egress: bool,
}

/// Marries active policies with local endpoints and computes, per endpoint, the
/// ordered set of tiers/policies that govern it. Incremental: each `on_*`
/// mutation returns only the endpoints whose resolved order may have changed.
#[derive(Debug, Default)]
pub struct PolicyResolver {
    /// Tier name → its order (absent order is `None`). A tier is only present
    /// once a `Tier` resource has been seen for it.
    tiers: HashMap<String, Option<f64>>,
    /// Policy id → metadata.
    policies: HashMap<String, PolicyMeta>,
    /// Endpoint id → labels.
    endpoints: HashMap<String, BTreeMap<String, String>>,
}

impl PolicyResolver {
    pub fn new() -> Self {
        Self::default()
    }

    // ---- tier mutations -------------------------------------------------

    /// Record/replace a tier's order. Recomputes all endpoints (a tier reorder
    /// can move any endpoint's tiers), mirroring upstream `markAllEndpointsDirty`.
    pub fn on_tier_update(&mut self, name: &str, order: Option<f64>) -> Vec<EndpointPolicyOrder> {
        self.tiers.insert(name.to_string(), order);
        self.resolve_all()
    }

    /// Forget a tier's order (it reverts to sorting last). Recomputes all
    /// endpoints.
    pub fn on_tier_remove(&mut self, name: &str) -> Vec<EndpointPolicyOrder> {
        self.tiers.remove(name);
        self.resolve_all()
    }

    // ---- policy mutations -----------------------------------------------

    /// Add or update a policy. Recomputes every endpoint the policy matched
    /// before *or* matches after the update (its selector may have changed).
    pub fn on_policy_update(
        &mut self,
        id: &str,
        tier: &str,
        order: Option<f64>,
        selector: Selector,
        ingress: bool,
        egress: bool,
    ) -> Vec<EndpointPolicyOrder> {
        let mut affected = self.endpoints_matching(self.policies.get(id).map(|m| &m.selector));
        self.policies.insert(
            id.to_string(),
            PolicyMeta {
                tier: tier.to_string(),
                order,
                selector,
                ingress,
                egress,
            },
        );
        affected.extend(self.endpoints_matching(self.policies.get(id).map(|m| &m.selector)));
        self.resolve_set(affected)
    }

    /// Remove a policy. Recomputes the endpoints that matched it.
    pub fn on_policy_remove(&mut self, id: &str) -> Vec<EndpointPolicyOrder> {
        let affected = match self.policies.remove(id) {
            Some(meta) => self.endpoints_matching(Some(&meta.selector)),
            None => return Vec::new(),
        };
        self.resolve_set(affected)
    }

    // ---- endpoint mutations ---------------------------------------------

    /// Add or relabel a local endpoint. Recomputes just that endpoint.
    pub fn on_endpoint_update(
        &mut self,
        id: &str,
        labels: BTreeMap<String, String>,
    ) -> EndpointPolicyOrder {
        self.endpoints.insert(id.to_string(), labels);
        self.resolve(id)
    }

    /// Remove a local endpoint. Returns its now-empty order (a removal signal).
    pub fn on_endpoint_remove(&mut self, id: &str) -> EndpointPolicyOrder {
        self.endpoints.remove(id);
        EndpointPolicyOrder {
            endpoint_id: id.to_string(),
            tiers: Vec::new(),
        }
    }

    // ---- resolution -----------------------------------------------------

    /// Resolve a single endpoint's ordered tier list. Pure w.r.t. current state.
    pub fn resolve(&self, endpoint_id: &str) -> EndpointPolicyOrder {
        let labels = match self.endpoints.get(endpoint_id) {
            Some(l) => l,
            None => {
                return EndpointPolicyOrder {
                    endpoint_id: endpoint_id.to_string(),
                    tiers: Vec::new(),
                }
            }
        };

        // Group the policies that select this endpoint by tier.
        let mut by_tier: HashMap<&str, Vec<(&str, &PolicyMeta)>> = HashMap::new();
        for (id, meta) in &self.policies {
            if meta.selector.matches(labels) {
                by_tier.entry(&meta.tier).or_default().push((id, meta));
            }
        }

        // Order the tiers that have at least one matching policy.
        let mut tier_keys: Vec<(String, Option<f64>)> = by_tier
            .keys()
            .map(|name| (name.to_string(), self.tiers.get(*name).copied().flatten()))
            .collect();
        tier_keys.sort_by(|a, b| cmp_order_then_name(a.1, &a.0, b.1, &b.0));

        let mut tiers = Vec::new();
        for (tier_name, _) in tier_keys {
            let mut pols = by_tier.remove(tier_name.as_str()).unwrap_or_default();
            // Order policies within the tier.
            pols.sort_by(|a, b| cmp_order_then_name(a.1.order, a.0, b.1.order, b.0));

            let mut ingress_policies = Vec::new();
            let mut egress_policies = Vec::new();
            for (id, meta) in pols {
                if meta.ingress {
                    ingress_policies.push(id.to_string());
                }
                if meta.egress {
                    egress_policies.push(id.to_string());
                }
            }
            // Only surface tiers that actually govern a direction for this endpoint.
            if !ingress_policies.is_empty() || !egress_policies.is_empty() {
                tiers.push(TierPolicies {
                    name: tier_name,
                    ingress_policies,
                    egress_policies,
                });
            }
        }

        EndpointPolicyOrder {
            endpoint_id: endpoint_id.to_string(),
            tiers,
        }
    }

    /// Endpoints whose labels match the given selector (sorted by id for
    /// determinism). `None` selector matches nothing.
    fn endpoints_matching(&self, selector: Option<&Selector>) -> Vec<String> {
        let sel = match selector {
            Some(s) => s,
            None => return Vec::new(),
        };
        let mut out: Vec<String> = self
            .endpoints
            .iter()
            .filter(|(_, labels)| sel.matches(labels))
            .map(|(id, _)| id.clone())
            .collect();
        out.sort();
        out
    }

    /// Recompute a de-duplicated, sorted set of endpoints.
    fn resolve_set(&self, mut ids: Vec<String>) -> Vec<EndpointPolicyOrder> {
        ids.sort();
        ids.dedup();
        ids.iter().map(|id| self.resolve(id)).collect()
    }

    /// Recompute every known endpoint (sorted by id for determinism).
    fn resolve_all(&self) -> Vec<EndpointPolicyOrder> {
        let mut ids: Vec<&String> = self.endpoints.keys().collect();
        ids.sort();
        ids.into_iter().map(|id| self.resolve(id)).collect()
    }
}

/// Total-order comparator matching upstream `TierLess` / `PolKVLess`: order
/// ascending, `None` (and defensively `NaN`) last, ties broken by name lexically.
fn cmp_order_then_name(a: Option<f64>, a_name: &str, b: Option<f64>, b_name: &str) -> Ordering {
    match (finite(a), finite(b)) {
        (Some(x), Some(y)) => x
            .partial_cmp(&y)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a_name.cmp(b_name)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a_name.cmp(b_name),
    }
}

/// `None` for absent-or-NaN order (which both sort last), else the value.
fn finite(order: Option<f64>) -> Option<f64> {
    order.filter(|v| !v.is_nan())
}

/// Pure helper: sort `(name, order)` tiers by the upstream tier ordering.
/// Exposed so the SC-003-sensitive ordering can be unit-tested directly.
pub fn sort_tiers(mut tiers: Vec<(String, Option<f64>)>) -> Vec<(String, Option<f64>)> {
    tiers.sort_by(|a, b| cmp_order_then_name(a.1, &a.0, b.1, &b.0));
    tiers
}

/// Pure helper: sort `(name, order)` policies by the upstream within-tier
/// policy ordering.
pub fn sort_policies(mut policies: Vec<(String, Option<f64>)>) -> Vec<(String, Option<f64>)> {
    policies.sort_by(|a, b| cmp_order_then_name(a.1, &a.0, b.1, &b.0));
    policies
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

    fn sel(s: &str) -> Selector {
        Selector::parse(s).unwrap()
    }

    fn names(pairs: Vec<(&str, Option<f64>)>) -> Vec<String> {
        sort_tiers(pairs.into_iter().map(|(n, o)| (n.to_string(), o)).collect())
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    }

    // ---- pure sorter: tiers ---------------------------------------------

    #[test]
    fn tier_order_asc_none_last_name_tiebreak() {
        // orders [20, 10, None(b), None(a)] → [10, 20, then None by name a,b].
        let got = names(vec![
            ("t20", Some(20.0)),
            ("t10", Some(10.0)),
            ("nb", None),
            ("na", None),
        ]);
        assert_eq!(got, vec!["t10", "t20", "na", "nb"]);
    }

    #[test]
    fn tier_equal_order_breaks_by_name() {
        let got = names(vec![("z", Some(5.0)), ("a", Some(5.0)), ("m", Some(5.0))]);
        assert_eq!(got, vec!["a", "m", "z"]);
    }

    #[test]
    fn tier_nan_order_sorts_last() {
        let got = names(vec![
            ("nan", Some(f64::NAN)),
            ("ten", Some(10.0)),
            ("none", None),
        ]);
        // Both NaN and None sort last, tie-broken by name ("nan" < "none").
        assert_eq!(got, vec!["ten", "nan", "none"]);
    }

    // ---- pure sorter: policies ------------------------------------------

    #[test]
    fn policy_order_asc_none_last_name_tiebreak() {
        // orders [None, 5(b), 5(a), 1] → [1, 5(a), 5(b), None].
        let got: Vec<String> = sort_policies(vec![
            ("pnone".to_string(), None),
            ("p5b".to_string(), Some(5.0)),
            ("p5a".to_string(), Some(5.0)),
            ("p1".to_string(), Some(1.0)),
        ])
        .into_iter()
        .map(|(n, _)| n)
        .collect();
        assert_eq!(got, vec!["p1", "p5a", "p5b", "pnone"]);
    }

    // ---- applies-to -----------------------------------------------------

    #[test]
    fn policy_applies_iff_selector_matches() {
        let mut r = PolicyResolver::new();
        r.on_tier_update("default", Some(100.0));
        r.on_policy_update("p", "default", Some(1.0), sel("app == 'db'"), true, true);

        let ep = r.on_endpoint_update("e", labels(&[("app", "db")]));
        assert_eq!(ep.tiers.len(), 1);
        assert_eq!(ep.tiers[0].ingress_policies, vec!["p"]);

        let ep = r.on_endpoint_update("e2", labels(&[("app", "web")]));
        assert!(ep.tiers.is_empty());
    }

    #[test]
    fn relabel_joins_and_leaves_policy_set() {
        let mut r = PolicyResolver::new();
        r.on_tier_update("default", Some(100.0));
        r.on_policy_update("p", "default", Some(1.0), sel("app == 'db'"), true, true);
        r.on_endpoint_update("e", labels(&[("app", "web")]));

        // Relabel to match → joins.
        let ep = r.on_endpoint_update("e", labels(&[("app", "db")]));
        assert_eq!(ep.tiers[0].ingress_policies, vec!["p"]);

        // Relabel away → leaves.
        let ep = r.on_endpoint_update("e", labels(&[("app", "web")]));
        assert!(ep.tiers.is_empty());
    }

    // ---- direction ------------------------------------------------------

    #[test]
    fn ingress_only_policy_only_in_ingress() {
        let mut r = PolicyResolver::new();
        r.on_tier_update("default", Some(100.0));
        r.on_policy_update("ing", "default", Some(1.0), sel("all()"), true, false);
        let ep = r.on_endpoint_update("e", labels(&[("app", "db")]));
        assert_eq!(ep.tiers[0].ingress_policies, vec!["ing"]);
        assert!(ep.tiers[0].egress_policies.is_empty());
    }

    #[test]
    fn egress_only_policy_only_in_egress() {
        let mut r = PolicyResolver::new();
        r.on_tier_update("default", Some(100.0));
        r.on_policy_update("eg", "default", Some(1.0), sel("all()"), false, true);
        let ep = r.on_endpoint_update("e", labels(&[("app", "db")]));
        assert!(ep.tiers[0].ingress_policies.is_empty());
        assert_eq!(ep.tiers[0].egress_policies, vec!["eg"]);
    }

    // ---- full ordering across tiers -------------------------------------

    #[test]
    fn resolves_ordered_tiers_and_policies() {
        let mut r = PolicyResolver::new();
        r.on_tier_update("sec", Some(10.0));
        r.on_tier_update("default", Some(100.0));
        // Two policies in sec (orders 5 then None), one in default.
        r.on_policy_update("s-none", "sec", None, sel("all()"), true, true);
        r.on_policy_update("s-5", "sec", Some(5.0), sel("all()"), true, true);
        r.on_policy_update("d-1", "default", Some(1.0), sel("all()"), true, true);

        let ep = r.on_endpoint_update("e", labels(&[("app", "db")]));
        assert_eq!(ep.tiers.len(), 2);
        assert_eq!(ep.tiers[0].name, "sec");
        assert_eq!(ep.tiers[0].ingress_policies, vec!["s-5", "s-none"]);
        assert_eq!(ep.tiers[1].name, "default");
        assert_eq!(ep.tiers[1].ingress_policies, vec!["d-1"]);
    }

    // ---- incremental ----------------------------------------------------

    #[test]
    fn adding_policy_recomputes_only_matching_endpoints() {
        let mut r = PolicyResolver::new();
        r.on_tier_update("default", Some(100.0));
        r.on_endpoint_update("db", labels(&[("app", "db")]));
        r.on_endpoint_update("web", labels(&[("app", "web")]));

        let affected =
            r.on_policy_update("p", "default", Some(1.0), sel("app == 'db'"), true, true);
        let ids: Vec<&str> = affected.iter().map(|e| e.endpoint_id.as_str()).collect();
        assert_eq!(ids, vec!["db"]); // only the matching endpoint recomputed
        assert_eq!(affected[0].tiers[0].ingress_policies, vec!["p"]);
    }

    #[test]
    fn removing_policy_drops_it_from_endpoint() {
        let mut r = PolicyResolver::new();
        r.on_tier_update("default", Some(100.0));
        r.on_endpoint_update("db", labels(&[("app", "db")]));
        r.on_policy_update("p", "default", Some(1.0), sel("app == 'db'"), true, true);

        let affected = r.on_policy_remove("p");
        assert_eq!(affected.len(), 1);
        assert_eq!(affected[0].endpoint_id, "db");
        assert!(affected[0].tiers.is_empty());
    }

    #[test]
    fn policy_reselect_recomputes_old_and_new_endpoints() {
        let mut r = PolicyResolver::new();
        r.on_tier_update("default", Some(100.0));
        r.on_endpoint_update("db", labels(&[("app", "db")]));
        r.on_endpoint_update("web", labels(&[("app", "web")]));
        r.on_policy_update("p", "default", Some(1.0), sel("app == 'db'"), true, true);

        // Re-point the selector at web: both db (lost it) and web (gained it) recompute.
        let affected =
            r.on_policy_update("p", "default", Some(1.0), sel("app == 'web'"), true, true);
        let ids: Vec<&str> = affected.iter().map(|e| e.endpoint_id.as_str()).collect();
        assert_eq!(ids, vec!["db", "web"]);
        // db no longer governed, web now governed.
        let db = affected.iter().find(|e| e.endpoint_id == "db").unwrap();
        let web = affected.iter().find(|e| e.endpoint_id == "web").unwrap();
        assert!(db.tiers.is_empty());
        assert_eq!(web.tiers[0].ingress_policies, vec!["p"]);
    }

    #[test]
    fn tier_update_recomputes_all_endpoints() {
        let mut r = PolicyResolver::new();
        r.on_tier_update("a", Some(10.0));
        r.on_tier_update("b", Some(20.0));
        r.on_policy_update("pa", "a", Some(1.0), sel("all()"), true, true);
        r.on_policy_update("pb", "b", Some(1.0), sel("all()"), true, true);
        r.on_endpoint_update("e1", labels(&[("x", "1")]));
        r.on_endpoint_update("e2", labels(&[("x", "2")]));

        // Re-order tiers so b comes first.
        let affected = r.on_tier_update("b", Some(5.0));
        assert_eq!(affected.len(), 2); // all endpoints recomputed
        for ep in &affected {
            assert_eq!(ep.tiers[0].name, "b");
            assert_eq!(ep.tiers[1].name, "a");
        }
    }

    // ---- determinism ----------------------------------------------------

    #[test]
    fn same_state_yields_identical_output() {
        let build = || {
            let mut r = PolicyResolver::new();
            r.on_tier_update("sec", Some(10.0));
            r.on_tier_update("default", Some(100.0));
            r.on_policy_update("s2", "sec", Some(5.0), sel("all()"), true, true);
            r.on_policy_update("s1", "sec", Some(5.0), sel("all()"), true, true);
            r.on_policy_update("d", "default", Some(1.0), sel("all()"), true, true);
            r.on_endpoint_update("e", labels(&[("app", "db")]))
        };
        assert_eq!(build(), build());
        // Equal-order policies tie-break by name: s1 before s2.
        let ep = build();
        assert_eq!(ep.tiers[0].ingress_policies, vec!["s1", "s2"]);
    }

    #[test]
    fn policy_in_tier_without_resource_sorts_last() {
        // A policy referencing a tier that has no Tier resource: that tier's
        // order is treated as None and so sorts after ordered tiers.
        let mut r = PolicyResolver::new();
        r.on_tier_update("default", Some(100.0));
        r.on_policy_update("d", "default", Some(1.0), sel("all()"), true, true);
        r.on_policy_update("g", "ghost", Some(1.0), sel("all()"), true, true);
        let ep = r.on_endpoint_update("e", labels(&[("app", "db")]));
        assert_eq!(ep.tiers[0].name, "default");
        assert_eq!(ep.tiers[1].name, "ghost");
    }
}
