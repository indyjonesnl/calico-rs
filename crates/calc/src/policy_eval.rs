//! Deterministic policy evaluation — the decision core behind Calico-rs network
//! policy (spec FR-007, FR-012; the sig-calico-style conformance target SC-003).
//!
//! Semantics anchored to upstream `felix/rules/endpoints.go`:
//! - Tiers are evaluated in order. Within a tier, the policies that *select* the
//!   endpoint (for the traffic direction) are evaluated in order, and their
//!   rules in order.
//! - The first rule that matches with `Allow`/`Deny` is terminal. `Pass` skips
//!   the rest of the tier and continues at the next tier. `Log` keeps going.
//! - If a tier had at least one selecting policy but nothing allowed/denied/passed,
//!   the packet hits the **end-of-tier drop** (deny) — unless the tier's default
//!   action is `Pass`, in which case evaluation continues at the next tier.
//! - A tier whose policies do not select the endpoint has no effect.
//! - After all tiers, profiles are evaluated the same way; if nothing matched at
//!   all (no policy selected the endpoint and no profile matched), traffic is
//!   allowed (an endpoint with no applicable policy is open — workloads normally
//!   carry a default-allow namespace profile).

use std::collections::BTreeMap;

use crate::selector::Selector;

/// Traffic direction relative to the subject endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Ingress,
    Egress,
}

/// The action a rule takes when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
    Pass,
    Log,
}

/// The end-of-tier behavior when a tier selected the endpoint but no rule matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierDefault {
    /// Drop the packet (Calico's default end-of-tier action).
    Deny,
    /// Continue at the next tier.
    Pass,
}

/// The final allow/deny outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// A computed policy rule (selectors already parsed).
#[derive(Debug, Clone)]
pub struct EvalRule {
    pub action: RuleAction,
    /// Protocol constraint (e.g. `"TCP"`); `None` matches any protocol.
    pub protocol: Option<String>,
    /// Peer (source for ingress, destination for egress) label selector; `None`
    /// matches any peer.
    pub peer_selector: Option<Selector>,
    /// Destination ports; empty matches any port.
    pub ports: Vec<u16>,
}

impl EvalRule {
    /// A bare rule with just an action (matches everything).
    pub fn action(action: RuleAction) -> Self {
        Self {
            action,
            protocol: None,
            peer_selector: None,
            ports: Vec::new(),
        }
    }
}

/// A policy: which endpoints it applies to, and its per-direction rules.
#[derive(Debug, Clone)]
pub struct EvalPolicy {
    /// Applies-to selector, matched against the *subject* endpoint's labels.
    pub selector: Selector,
    pub applies_ingress: bool,
    pub applies_egress: bool,
    pub ingress: Vec<EvalRule>,
    pub egress: Vec<EvalRule>,
}

/// An ordered group of policies plus its end-of-tier default.
#[derive(Debug, Clone)]
pub struct Tier {
    pub policies: Vec<EvalPolicy>,
    pub default_action: TierDefault,
}

/// The full policy model for an evaluation.
#[derive(Debug, Clone, Default)]
pub struct PolicyEvaluator {
    pub tiers: Vec<Tier>,
    pub profiles: Vec<EvalPolicy>,
}

/// A packet/flow to classify.
pub struct Packet<'a> {
    pub direction: Direction,
    /// Labels of the peer endpoint (source for ingress, dest for egress).
    pub peer_labels: &'a BTreeMap<String, String>,
    pub protocol: Option<&'a str>,
    pub port: Option<u16>,
}

impl PolicyEvaluator {
    /// Evaluate a packet against this policy model for the given subject labels.
    pub fn evaluate(&self, subject_labels: &BTreeMap<String, String>, pkt: &Packet) -> Decision {
        'tiers: for tier in &self.tiers {
            let mut selected = false;
            for pol in &tier.policies {
                if !pol.applies_to(pkt.direction) || !pol.selector.matches(subject_labels) {
                    continue;
                }
                selected = true;
                for rule in pol.rules(pkt.direction) {
                    if rule_matches(rule, pkt) {
                        match rule.action {
                            RuleAction::Allow => return Decision::Allow,
                            RuleAction::Deny => return Decision::Deny,
                            RuleAction::Pass => continue 'tiers, // skip rest of tier
                            RuleAction::Log => {}                // keep evaluating
                        }
                    }
                }
            }
            if selected {
                match tier.default_action {
                    TierDefault::Deny => return Decision::Deny, // end-of-tier drop
                    TierDefault::Pass => {}                     // fall through to next tier
                }
            }
        }

        // Profiles (namespace / service-account fallback).
        for prof in &self.profiles {
            if !prof.applies_to(pkt.direction) {
                continue;
            }
            for rule in prof.rules(pkt.direction) {
                if rule_matches(rule, pkt) {
                    match rule.action {
                        RuleAction::Allow => return Decision::Allow,
                        RuleAction::Deny => return Decision::Deny,
                        _ => {}
                    }
                }
            }
        }

        // No policy selected the endpoint and no profile matched → open.
        Decision::Allow
    }
}

impl EvalPolicy {
    fn applies_to(&self, dir: Direction) -> bool {
        match dir {
            Direction::Ingress => self.applies_ingress,
            Direction::Egress => self.applies_egress,
        }
    }
    fn rules(&self, dir: Direction) -> &[EvalRule] {
        match dir {
            Direction::Ingress => &self.ingress,
            Direction::Egress => &self.egress,
        }
    }
}

fn rule_matches(rule: &EvalRule, pkt: &Packet) -> bool {
    // Protocol.
    if let Some(proto) = &rule.protocol {
        match pkt.protocol {
            Some(p) if p.eq_ignore_ascii_case(proto) => {}
            _ => return false,
        }
    }
    // Ports (destination). A rule constrained to ports requires a matching port.
    if !rule.ports.is_empty() {
        match pkt.port {
            Some(p) if rule.ports.contains(&p) => {}
            _ => return false,
        }
    }
    // Peer selector.
    if let Some(sel) = &rule.peer_selector {
        if !sel.matches(pkt.peer_labels) {
            return false;
        }
    }
    true
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

    fn ingress_policy(applies: &str, rules: Vec<EvalRule>) -> EvalPolicy {
        EvalPolicy {
            selector: sel(applies),
            applies_ingress: true,
            applies_egress: false,
            ingress: rules,
            egress: vec![],
        }
    }

    fn tier(policies: Vec<EvalPolicy>, default_action: TierDefault) -> Tier {
        Tier {
            policies,
            default_action,
        }
    }

    fn ingress(peer_labels: &BTreeMap<String, String>, port: Option<u16>) -> Packet<'_> {
        Packet {
            direction: Direction::Ingress,
            peer_labels,
            protocol: Some("TCP"),
            port,
        }
    }

    #[test]
    fn allow_rule_matches() {
        let ev = PolicyEvaluator {
            tiers: vec![tier(
                vec![ingress_policy(
                    "app == 'db'",
                    vec![EvalRule {
                        action: RuleAction::Allow,
                        protocol: Some("TCP".into()),
                        peer_selector: Some(sel("app == 'web'")),
                        ports: vec![5432],
                    }],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        };
        let subject = labels(&[("app", "db")]);
        let peer = labels(&[("app", "web")]);
        assert_eq!(
            ev.evaluate(&subject, &ingress(&peer, Some(5432))),
            Decision::Allow
        );
    }

    #[test]
    fn selected_but_no_rule_matches_is_end_of_tier_deny() {
        let ev = PolicyEvaluator {
            tiers: vec![tier(
                vec![ingress_policy(
                    "app == 'db'",
                    vec![EvalRule {
                        action: RuleAction::Allow,
                        protocol: None,
                        peer_selector: Some(sel("app == 'web'")),
                        ports: vec![],
                    }],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        };
        let subject = labels(&[("app", "db")]);
        // Peer is not 'web' → no rule matches → end-of-tier drop.
        let peer = labels(&[("app", "attacker")]);
        assert_eq!(
            ev.evaluate(&subject, &ingress(&peer, Some(5432))),
            Decision::Deny
        );
    }

    #[test]
    fn wrong_port_denied_by_end_of_tier() {
        let ev = PolicyEvaluator {
            tiers: vec![tier(
                vec![ingress_policy(
                    "app == 'db'",
                    vec![EvalRule {
                        action: RuleAction::Allow,
                        protocol: Some("TCP".into()),
                        peer_selector: None,
                        ports: vec![5432],
                    }],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        };
        let subject = labels(&[("app", "db")]);
        let peer = labels(&[]);
        assert_eq!(
            ev.evaluate(&subject, &ingress(&peer, Some(80))),
            Decision::Deny
        );
        assert_eq!(
            ev.evaluate(&subject, &ingress(&peer, Some(5432))),
            Decision::Allow
        );
    }

    #[test]
    fn unselected_endpoint_falls_through_to_profile_allow() {
        let ev = PolicyEvaluator {
            tiers: vec![tier(
                vec![ingress_policy(
                    "app == 'other'",
                    vec![EvalRule::action(RuleAction::Deny)],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![ingress_policy(
                "all()",
                vec![EvalRule::action(RuleAction::Allow)],
            )],
        };
        // Subject not selected by the tier's policy → tier skipped → profile allows.
        let subject = labels(&[("app", "db")]);
        let peer = labels(&[]);
        assert_eq!(
            ev.evaluate(&subject, &ingress(&peer, None)),
            Decision::Allow
        );
    }

    #[test]
    fn pass_skips_to_next_tier() {
        let ev = PolicyEvaluator {
            tiers: vec![
                tier(
                    vec![ingress_policy(
                        "app == 'db'",
                        vec![EvalRule::action(RuleAction::Pass)],
                    )],
                    TierDefault::Deny,
                ),
                tier(
                    vec![ingress_policy(
                        "app == 'db'",
                        vec![EvalRule::action(RuleAction::Deny)],
                    )],
                    TierDefault::Deny,
                ),
            ],
            profiles: vec![],
        };
        // First tier passes; second tier denies.
        let subject = labels(&[("app", "db")]);
        let peer = labels(&[]);
        assert_eq!(ev.evaluate(&subject, &ingress(&peer, None)), Decision::Deny);
    }

    #[test]
    fn first_matching_rule_wins() {
        let ev = PolicyEvaluator {
            tiers: vec![tier(
                vec![ingress_policy(
                    "all()",
                    vec![
                        EvalRule {
                            action: RuleAction::Deny,
                            protocol: None,
                            peer_selector: Some(sel("bad == 'true'")),
                            ports: vec![],
                        },
                        EvalRule::action(RuleAction::Allow),
                    ],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        };
        let subject = labels(&[]);
        assert_eq!(
            ev.evaluate(&subject, &ingress(&labels(&[("bad", "true")]), None)),
            Decision::Deny
        );
        assert_eq!(
            ev.evaluate(&subject, &ingress(&labels(&[]), None)),
            Decision::Allow
        );
    }

    #[test]
    fn no_policy_no_profile_defaults_allow() {
        let ev = PolicyEvaluator::default();
        assert_eq!(
            ev.evaluate(&labels(&[("app", "db")]), &ingress(&labels(&[]), None)),
            Decision::Allow
        );
    }

    #[test]
    fn tier_default_pass_continues() {
        let ev = PolicyEvaluator {
            tiers: vec![
                // Selects the endpoint but no rule matches; default Pass → next tier.
                tier(
                    vec![ingress_policy(
                        "app == 'db'",
                        vec![EvalRule {
                            action: RuleAction::Allow,
                            protocol: None,
                            peer_selector: Some(sel("app == 'nope'")),
                            ports: vec![],
                        }],
                    )],
                    TierDefault::Pass,
                ),
                tier(
                    vec![ingress_policy(
                        "app == 'db'",
                        vec![EvalRule::action(RuleAction::Allow)],
                    )],
                    TierDefault::Deny,
                ),
            ],
            profiles: vec![],
        };
        let subject = labels(&[("app", "db")]);
        assert_eq!(
            ev.evaluate(&subject, &ingress(&labels(&[]), None)),
            Decision::Allow
        );
    }
}
