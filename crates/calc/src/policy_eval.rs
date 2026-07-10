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
    /// Human-readable policy identifier for decision attribution (flow logs).
    /// Optional and provenance-only: it never affects [`PolicyEvaluator::evaluate`].
    /// When `None`, traced evaluation falls back to a positional id (`policy#N`).
    pub name: Option<String>,
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

    /// Evaluate a packet and record *why* the decision was reached (spec FR-029).
    ///
    /// This mirrors [`PolicyEvaluator::evaluate`] control-flow-for-control-flow: the
    /// same tier/policy/rule walk, the same `Pass`/end-of-tier-drop/profile/default
    /// semantics, and therefore the same terminal [`Decision`] for every input. It
    /// only adds provenance — it must never diverge from the conformance-critical
    /// `evaluate` (a drift-guard test asserts `evaluate_traced(..).decision ==
    /// evaluate(..)` across the evaluation scenarios).
    pub fn evaluate_traced(
        &self,
        subject_labels: &BTreeMap<String, String>,
        pkt: &Packet,
    ) -> TracedDecision {
        'tiers: for (ti, tier) in self.tiers.iter().enumerate() {
            let mut selected = false;
            for (pi, pol) in tier.policies.iter().enumerate() {
                if !pol.applies_to(pkt.direction) || !pol.selector.matches(subject_labels) {
                    continue;
                }
                selected = true;
                for (ri, rule) in pol.rules(pkt.direction).iter().enumerate() {
                    if rule_matches(rule, pkt) {
                        match rule.action {
                            RuleAction::Allow | RuleAction::Deny => {
                                let decision = if rule.action == RuleAction::Allow {
                                    Decision::Allow
                                } else {
                                    Decision::Deny
                                };
                                return TracedDecision {
                                    decision,
                                    reason: DecisionReason::RuleMatch {
                                        tier: tier_id(ti),
                                        policy: policy_id(pi, pol),
                                        direction: pkt.direction,
                                        rule_index: ri,
                                        action: rule.action,
                                    },
                                };
                            }
                            RuleAction::Pass => continue 'tiers, // skip rest of tier
                            RuleAction::Log => {}                // keep evaluating
                        }
                    }
                }
            }
            if selected {
                match tier.default_action {
                    TierDefault::Deny => {
                        return TracedDecision {
                            decision: Decision::Deny,
                            reason: DecisionReason::EndOfTierDrop { tier: tier_id(ti) },
                        }
                    }
                    TierDefault::Pass => {} // fall through to next tier
                }
            }
        }

        // Profiles (namespace / service-account fallback).
        for (pi, prof) in self.profiles.iter().enumerate() {
            if !prof.applies_to(pkt.direction) {
                continue;
            }
            for (ri, rule) in prof.rules(pkt.direction).iter().enumerate() {
                if rule_matches(rule, pkt) {
                    match rule.action {
                        RuleAction::Allow | RuleAction::Deny => {
                            let decision = if rule.action == RuleAction::Allow {
                                Decision::Allow
                            } else {
                                Decision::Deny
                            };
                            return TracedDecision {
                                decision,
                                reason: DecisionReason::ProfileMatch {
                                    profile: policy_id(pi, prof),
                                    rule_index: ri,
                                    action: rule.action,
                                },
                            };
                        }
                        _ => {}
                    }
                }
            }
        }

        // No policy selected the endpoint and no profile matched → open.
        TracedDecision {
            decision: Decision::Allow,
            reason: DecisionReason::DefaultAllow,
        }
    }
}

/// The outcome of [`PolicyEvaluator::evaluate_traced`]: the verdict plus why.
///
/// `decision` is guaranteed identical to [`PolicyEvaluator::evaluate`] for the same
/// input; `reason` attributes it to the tier/policy/rule (or profile/default) that
/// produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracedDecision {
    pub decision: Decision,
    pub reason: DecisionReason,
}

/// Why a [`Decision`] was reached — the terminal outcome of the evaluation walk.
/// Each variant mirrors one terminal branch of [`PolicyEvaluator::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionReason {
    /// A policy rule matched and was terminal (`Allow`/`Deny`).
    RuleMatch {
        tier: String,
        policy: String,
        direction: Direction,
        rule_index: usize,
        action: RuleAction,
    },
    /// A tier selected the endpoint but no rule matched, and its default is `Deny`.
    EndOfTierDrop { tier: String },
    /// A profile rule matched (namespace/service-account fallback layer).
    ProfileMatch {
        profile: String,
        rule_index: usize,
        action: RuleAction,
    },
    /// No policy selected the endpoint and no profile matched → open-by-default.
    DefaultAllow,
}

/// Positional tier identifier used when tiers carry no explicit name.
fn tier_id(index: usize) -> String {
    format!("tier#{index}")
}

/// A policy's attribution id: its `name` if set, else a positional fallback.
fn policy_id(index: usize, pol: &EvalPolicy) -> String {
    pol.name
        .clone()
        .unwrap_or_else(|| format!("policy#{index}"))
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
            name: None,
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

    fn named_ingress_policy(name: &str, applies: &str, rules: Vec<EvalRule>) -> EvalPolicy {
        EvalPolicy {
            name: Some(name.to_string()),
            ..ingress_policy(applies, rules)
        }
    }

    /// One drift-guard case: (evaluator, subject labels, peer labels, dest port).
    type Scenario = (
        PolicyEvaluator,
        BTreeMap<String, String>,
        BTreeMap<String, String>,
        Option<u16>,
    );

    /// Build the set of representative scenarios used by the drift guard, mirroring
    /// the standalone `evaluate` tests: allow, end-of-tier-drop, pass-to-next-tier,
    /// profile-fallback, and default-allow.
    fn drift_scenarios() -> Vec<Scenario> {
        vec![
            // allow-by-rule
            (
                PolicyEvaluator {
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
                },
                labels(&[("app", "db")]),
                labels(&[("app", "web")]),
                Some(5432),
            ),
            // end-of-tier drop (selected, no rule matches)
            (
                PolicyEvaluator {
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
                },
                labels(&[("app", "db")]),
                labels(&[("app", "attacker")]),
                Some(5432),
            ),
            // pass-to-next-tier then deny
            (
                PolicyEvaluator {
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
                },
                labels(&[("app", "db")]),
                labels(&[]),
                None,
            ),
            // profile-fallback allow (tier does not select)
            (
                PolicyEvaluator {
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
                },
                labels(&[("app", "db")]),
                labels(&[]),
                None,
            ),
            // default-allow (nothing selects, no profiles)
            (
                PolicyEvaluator::default(),
                labels(&[("app", "db")]),
                labels(&[]),
                None,
            ),
        ]
    }

    #[test]
    fn traced_decision_never_drifts_from_evaluate() {
        for (i, (ev, subject, peer, port)) in drift_scenarios().into_iter().enumerate() {
            let pkt = ingress(&peer, port);
            let plain = ev.evaluate(&subject, &pkt);
            let traced = ev.evaluate_traced(&subject, &pkt);
            assert_eq!(
                traced.decision, plain,
                "scenario {i}: traced decision {:?} != evaluate {:?}",
                traced.decision, plain
            );
        }
    }

    #[test]
    fn traced_allow_by_rule_records_provenance() {
        let ev = PolicyEvaluator {
            tiers: vec![tier(
                vec![named_ingress_policy(
                    "allow-web",
                    "app == 'db'",
                    vec![
                        EvalRule::action(RuleAction::Log),
                        EvalRule {
                            action: RuleAction::Allow,
                            protocol: Some("TCP".into()),
                            peer_selector: Some(sel("app == 'web'")),
                            ports: vec![5432],
                        },
                    ],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        };
        let subject = labels(&[("app", "db")]);
        let peer = labels(&[("app", "web")]);
        let traced = ev.evaluate_traced(&subject, &ingress(&peer, Some(5432)));
        assert_eq!(traced.decision, Decision::Allow);
        assert_eq!(
            traced.reason,
            DecisionReason::RuleMatch {
                tier: "tier#0".to_string(),
                policy: "allow-web".to_string(),
                direction: Direction::Ingress,
                rule_index: 1,
                action: RuleAction::Allow,
            }
        );
    }

    #[test]
    fn traced_end_of_tier_drop_records_tier() {
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
        let peer = labels(&[("app", "attacker")]);
        let traced = ev.evaluate_traced(&subject, &ingress(&peer, Some(5432)));
        assert_eq!(traced.decision, Decision::Deny);
        assert_eq!(
            traced.reason,
            DecisionReason::EndOfTierDrop {
                tier: "tier#0".to_string(),
            }
        );
    }

    #[test]
    fn traced_profile_fallback_records_profile() {
        let ev = PolicyEvaluator {
            tiers: vec![tier(
                vec![ingress_policy(
                    "app == 'other'",
                    vec![EvalRule::action(RuleAction::Deny)],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![named_ingress_policy(
                "ns-default",
                "all()",
                vec![EvalRule::action(RuleAction::Allow)],
            )],
        };
        let subject = labels(&[("app", "db")]);
        let peer = labels(&[]);
        let traced = ev.evaluate_traced(&subject, &ingress(&peer, None));
        assert_eq!(traced.decision, Decision::Allow);
        assert_eq!(
            traced.reason,
            DecisionReason::ProfileMatch {
                profile: "ns-default".to_string(),
                rule_index: 0,
                action: RuleAction::Allow,
            }
        );
    }

    #[test]
    fn traced_default_allow_when_nothing_selects() {
        let ev = PolicyEvaluator::default();
        let subject = labels(&[("app", "db")]);
        let peer = labels(&[]);
        let traced = ev.evaluate_traced(&subject, &ingress(&peer, None));
        assert_eq!(traced.decision, Decision::Allow);
        assert_eq!(traced.reason, DecisionReason::DefaultAllow);
    }

    /// A policy with no name falls back to its positional identifier.
    #[test]
    fn traced_unnamed_policy_uses_positional_id() {
        let ev = PolicyEvaluator {
            tiers: vec![tier(
                vec![ingress_policy(
                    "app == 'db'",
                    vec![EvalRule::action(RuleAction::Deny)],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        };
        let subject = labels(&[("app", "db")]);
        let peer = labels(&[]);
        let traced = ev.evaluate_traced(&subject, &ingress(&peer, None));
        assert_eq!(
            traced.reason,
            DecisionReason::RuleMatch {
                tier: "tier#0".to_string(),
                policy: "policy#0".to_string(),
                direction: Direction::Ingress,
                rule_index: 0,
                action: RuleAction::Deny,
            }
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
