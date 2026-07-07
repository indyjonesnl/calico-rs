//! Build a [`PolicyEvaluator`] from the resource model (`apis` v3 policy specs).
//!
//! This is the bridge from stored `NetworkPolicy`/`GlobalNetworkPolicy`/`Profile`
//! resources to the decision engine: parse selectors, map rules, order policies
//! into a tier. It makes a full parse→evaluate path — a manifest's allow/deny
//! behavior can be checked directly (spec SC-003 conformance).

use apis::{Action, EntityRule, NetworkPolicySpec, PolicyType, ProfileSpec, Protocol, Rule};

use crate::policy_eval::{EvalPolicy, EvalRule, PolicyEvaluator, RuleAction, Tier, TierDefault};
use crate::selector::{Selector, SelectorError};

/// Parse a policy applies-to selector; an empty selector means "all endpoints".
fn selector_or_all(s: &str) -> Result<Selector, SelectorError> {
    if s.trim().is_empty() {
        Ok(Selector::All)
    } else {
        Selector::parse(s)
    }
}

/// Parse an optional peer selector; empty/absent means "any peer" (`None`).
fn peer_selector(s: &Option<String>) -> Result<Option<Selector>, SelectorError> {
    match s {
        Some(v) if !v.trim().is_empty() => Ok(Some(Selector::parse(v)?)),
        _ => Ok(None),
    }
}

fn map_action(a: Action) -> RuleAction {
    match a {
        Action::Allow => RuleAction::Allow,
        Action::Deny => RuleAction::Deny,
        Action::Log => RuleAction::Log,
        Action::Pass => RuleAction::Pass,
    }
}

fn map_protocol(p: &Option<Protocol>) -> Option<String> {
    p.as_ref().map(|p| match p {
        Protocol::Named(s) => s.clone(),
        Protocol::Number(n) => n.to_string(),
    })
}

/// Convert one rule for the given direction. For ingress the peer is the rule's
/// `source`; for egress it is the `destination`. Destination ports apply in both.
fn map_rule(rule: &Rule, ingress: bool) -> Result<EvalRule, SelectorError> {
    let peer: &EntityRule = if ingress {
        &rule.source
    } else {
        &rule.destination
    };
    Ok(EvalRule {
        action: map_action(rule.action),
        protocol: map_protocol(&rule.protocol),
        peer_selector: peer_selector(&peer.selector)?,
        ports: rule.destination.ports.clone(),
    })
}

/// Convert a `NetworkPolicySpec` (or the shared shape of a GlobalNetworkPolicy)
/// into an [`EvalPolicy`].
pub fn network_policy_to_eval(spec: &NetworkPolicySpec) -> Result<EvalPolicy, SelectorError> {
    // Direction applicability: honor `types` when set; otherwise derive from
    // which rule lists are present (defaulting to ingress), matching upstream.
    let (applies_ingress, applies_egress) = if spec.types.is_empty() {
        let ing = !spec.ingress.is_empty() || spec.egress.is_empty();
        (ing, !spec.egress.is_empty())
    } else {
        (
            spec.types.contains(&PolicyType::Ingress),
            spec.types.contains(&PolicyType::Egress),
        )
    };
    Ok(EvalPolicy {
        selector: selector_or_all(&spec.selector)?,
        applies_ingress,
        applies_egress,
        ingress: spec
            .ingress
            .iter()
            .map(|r| map_rule(r, true))
            .collect::<Result<_, _>>()?,
        egress: spec
            .egress
            .iter()
            .map(|r| map_rule(r, false))
            .collect::<Result<_, _>>()?,
    })
}

/// Convert a `ProfileSpec` into an [`EvalPolicy`] applied to all endpoints that
/// reference it (used as the evaluator's fallback layer).
pub fn profile_to_eval(spec: &ProfileSpec) -> Result<EvalPolicy, SelectorError> {
    Ok(EvalPolicy {
        selector: Selector::All,
        applies_ingress: true,
        applies_egress: true,
        ingress: spec
            .ingress
            .iter()
            .map(|r| map_rule(r, true))
            .collect::<Result<_, _>>()?,
        egress: spec
            .egress
            .iter()
            .map(|r| map_rule(r, false))
            .collect::<Result<_, _>>()?,
    })
}

/// Build a single default-tier [`PolicyEvaluator`] from ordered policies +
/// profiles. `policies` are `(order, spec)`; `None` order sorts last (as in
/// Calico). The default tier drops at end-of-tier.
pub fn evaluator_from(
    policies: &[(Option<f64>, NetworkPolicySpec)],
    profiles: &[ProfileSpec],
) -> Result<PolicyEvaluator, SelectorError> {
    let mut ordered: Vec<&(Option<f64>, NetworkPolicySpec)> = policies.iter().collect();
    ordered.sort_by(|a, b| match (a.0, b.0) {
        (Some(x), Some(y)) => x.total_cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less, // ordered policies before unordered
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    let tier = Tier {
        policies: ordered
            .iter()
            .map(|(_, spec)| network_policy_to_eval(spec))
            .collect::<Result<_, _>>()?,
        default_action: TierDefault::Deny,
    };
    let profiles = profiles
        .iter()
        .map(profile_to_eval)
        .collect::<Result<_, _>>()?;
    Ok(PolicyEvaluator {
        tiers: if tier.policies.is_empty() {
            vec![]
        } else {
            vec![tier]
        },
        profiles,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_eval::{Decision, Direction, Packet};
    use std::collections::BTreeMap;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn manifest_json_to_decision() {
        // A typical NetworkPolicy: allow TCP:5432 from app==web to app==db.
        let doc = r#"{
            "selector": "app == 'db'",
            "types": ["Ingress"],
            "ingress": [{
                "action": "Allow",
                "protocol": "TCP",
                "source": { "selector": "app == 'web'" },
                "destination": { "ports": [5432] }
            }]
        }"#;
        let spec: NetworkPolicySpec = serde_json::from_str(doc).unwrap();
        let ev = evaluator_from(&[(Some(100.0), spec)], &[]).unwrap();

        let db = labels(&[("app", "db")]);
        let web = labels(&[("app", "web")]);
        let other = labels(&[("app", "cache")]);

        // web → db:5432 allowed.
        assert_eq!(
            ev.evaluate(
                &db,
                &Packet {
                    direction: Direction::Ingress,
                    peer_labels: &web,
                    protocol: Some("TCP"),
                    port: Some(5432)
                }
            ),
            Decision::Allow
        );
        // web → db:80 hits end-of-tier drop (wrong port).
        assert_eq!(
            ev.evaluate(
                &db,
                &Packet {
                    direction: Direction::Ingress,
                    peer_labels: &web,
                    protocol: Some("TCP"),
                    port: Some(80)
                }
            ),
            Decision::Deny
        );
        // cache → db denied (wrong source).
        assert_eq!(
            ev.evaluate(
                &db,
                &Packet {
                    direction: Direction::Ingress,
                    peer_labels: &other,
                    protocol: Some("TCP"),
                    port: Some(5432)
                }
            ),
            Decision::Deny
        );
    }

    #[test]
    fn default_deny_namespace_pattern() {
        // A default-deny policy (selects all, no ingress rules) + no profiles.
        let deny_all: NetworkPolicySpec =
            serde_json::from_str(r#"{"selector":"","types":["Ingress"]}"#).unwrap();
        let ev = evaluator_from(&[(None, deny_all)], &[]).unwrap();
        let any = labels(&[("app", "x")]);
        assert_eq!(
            ev.evaluate(
                &any,
                &Packet {
                    direction: Direction::Ingress,
                    peer_labels: &labels(&[]),
                    protocol: None,
                    port: None
                }
            ),
            Decision::Deny
        );
    }

    #[test]
    fn profile_provides_default_allow_when_unselected() {
        let np: NetworkPolicySpec = serde_json::from_str(
            r#"{"selector":"app == 'other'","types":["Ingress"],"ingress":[{"action":"Deny"}]}"#,
        )
        .unwrap();
        let profile: ProfileSpec =
            serde_json::from_str(r#"{"ingress":[{"action":"Allow"}]}"#).unwrap();
        let ev = evaluator_from(&[(None, np)], &[profile]).unwrap();
        // Endpoint not selected by the policy → profile allow.
        let ep = labels(&[("app", "db")]);
        assert_eq!(
            ev.evaluate(
                &ep,
                &Packet {
                    direction: Direction::Ingress,
                    peer_labels: &labels(&[]),
                    protocol: None,
                    port: None
                }
            ),
            Decision::Allow
        );
    }

    #[test]
    fn order_sorts_lower_first_none_last() {
        // Lower-order Deny should win over higher-order Allow (same selector).
        let deny: NetworkPolicySpec = serde_json::from_str(
            r#"{"selector":"all()","types":["Ingress"],"ingress":[{"action":"Deny"}]}"#,
        )
        .unwrap();
        let allow: NetworkPolicySpec = serde_json::from_str(
            r#"{"selector":"all()","types":["Ingress"],"ingress":[{"action":"Allow"}]}"#,
        )
        .unwrap();
        // Give allow order 10, deny order 5 → deny evaluated first.
        let ev = evaluator_from(&[(Some(10.0), allow), (Some(5.0), deny)], &[]).unwrap();
        assert_eq!(
            ev.evaluate(
                &labels(&[]),
                &Packet {
                    direction: Direction::Ingress,
                    peer_labels: &labels(&[]),
                    protocol: None,
                    port: None
                }
            ),
            Decision::Deny
        );
    }
}
