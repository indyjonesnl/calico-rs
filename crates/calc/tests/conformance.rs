//! Policy decision conformance harness (spec SC-003, task T048 remainder).
//!
//! A **data-driven** corpus of policy-evaluation vectors. Each [`Case`] is a
//! self-contained scenario — a [`PolicyEvaluator`] model, a subject endpoint's
//! labels, a [`Packet`], and the `expected` [`Decision`] — and the single
//! parametric test [`conformance_corpus`] runs every case through the public
//! [`PolicyEvaluator::evaluate`] API, asserting the verdict matches. It also
//! runs each case through [`PolicyEvaluator::evaluate_traced`] and asserts the
//! traced decision agrees (reusing the T060 no-drift guarantee).
//!
//! Adding a vector is a one-liner: push another [`Case`] onto the [`corpus`]
//! table. Every expected outcome is anchored to upstream Calico Felix policy
//! semantics (`felix/rules/endpoints.go`), cited per-case.
//!
//! This is a TEST-ONLY target: it never modifies the evaluator. A case that
//! disagreed with `evaluate` would be a reported finding, not a silenced test.

use std::collections::BTreeMap;

use calc::{
    Decision, Direction, EvalPolicy, EvalRule, Packet, PolicyEvaluator, RuleAction, Selector, Tier,
    TierDefault,
};

// ---------------------------------------------------------------------------
// Compact builders over the public API (kept tiny so cases read as data).
// ---------------------------------------------------------------------------

fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn sel(s: &str) -> Selector {
    Selector::parse(s).expect("selector should parse")
}

/// A rule matching any protocol/port/peer with the given action.
fn any(action: RuleAction) -> EvalRule {
    EvalRule::action(action)
}

/// A rule with an explicit peer selector (still any protocol/port).
fn peer_rule(action: RuleAction, peer: &str) -> EvalRule {
    EvalRule {
        action,
        protocol: None,
        peer_selector: Some(sel(peer)),
        ports: Vec::new(),
    }
}

/// A rule constrained to a protocol + port set.
fn proto_port_rule(action: RuleAction, protocol: &str, ports: Vec<u16>) -> EvalRule {
    EvalRule {
        action,
        protocol: Some(protocol.to_string()),
        peer_selector: None,
        ports,
    }
}

/// A policy applying to the given direction only, selecting `applies`.
fn policy(name: &str, applies: &str, dir: Direction, rules: Vec<EvalRule>) -> EvalPolicy {
    EvalPolicy {
        name: Some(name.to_string()),
        selector: sel(applies),
        applies_ingress: matches!(dir, Direction::Ingress),
        applies_egress: matches!(dir, Direction::Egress),
        ingress: if matches!(dir, Direction::Ingress) {
            rules.clone()
        } else {
            Vec::new()
        },
        egress: if matches!(dir, Direction::Egress) {
            rules
        } else {
            Vec::new()
        },
    }
}

fn tier(policies: Vec<EvalPolicy>, default_action: TierDefault) -> Tier {
    Tier {
        policies,
        default_action,
    }
}

// ---------------------------------------------------------------------------
// Case model.
// ---------------------------------------------------------------------------

/// One conformance vector: a policy model plus an input packet and the
/// expected terminal decision.
struct Case {
    /// Unique, human-readable case name (printed on failure).
    name: &'static str,
    /// Which upstream semantic / rule this vector pins down.
    anchor: &'static str,
    evaluator: PolicyEvaluator,
    subject: BTreeMap<String, String>,
    direction: Direction,
    peer: BTreeMap<String, String>,
    protocol: Option<&'static str>,
    port: Option<u16>,
    expected: Decision,
}

impl Case {
    fn packet(&self) -> Packet<'_> {
        Packet {
            direction: self.direction,
            peer_labels: &self.peer,
            protocol: self.protocol,
            port: self.port,
        }
    }
}

/// The conformance corpus. Add a vector by pushing another [`Case`].
// The push-per-case shape is deliberate: it keeps every vector a self-contained
// block that reads top-to-bottom and makes adding one a localized diff.
#[allow(clippy::vec_init_then_push)]
fn corpus() -> Vec<Case> {
    let mut cases = Vec::new();

    // -- ALLOW ---------------------------------------------------------------
    // felix/rules/endpoints.go: the first matching Allow rule is terminal.
    cases.push(Case {
        name: "allow/matching-allow-rule",
        anchor: "endpoints.go: first matching Allow rule terminates with accept",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "allow-web",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![peer_rule(RuleAction::Allow, "app == 'web'")],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[("app", "web")]),
        protocol: Some("TCP"),
        port: Some(5432),
        expected: Decision::Allow,
    });
    cases.push(Case {
        name: "allow/log-then-allow-keeps-evaluating",
        anchor: "endpoints.go: Log/nflog is non-terminal, evaluation continues to Allow",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "log-then-allow",
                    "all()",
                    Direction::Ingress,
                    vec![any(RuleAction::Log), any(RuleAction::Allow)],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });

    // -- DENY -----------------------------------------------------------------
    // felix/rules/endpoints.go: the first matching Deny rule is terminal.
    cases.push(Case {
        name: "deny/matching-deny-rule",
        anchor: "endpoints.go: first matching Deny rule terminates with drop",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "deny-attacker",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![peer_rule(RuleAction::Deny, "app == 'attacker'")],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[("app", "attacker")]),
        protocol: None,
        port: None,
        expected: Decision::Deny,
    });

    // -- END-OF-TIER DEFAULT-DENY --------------------------------------------
    // endpoints.go:690 `if endOfTierDrop && tier.DefaultAction != v3.Pass` →
    // selected-but-no-rule-matched drops at end of tier.
    cases.push(Case {
        name: "default-deny/selected-no-match-drops",
        anchor: "endpoints.go:690 endOfTierDrop when a policy selects but no rule matches",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "allow-web-only",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![peer_rule(RuleAction::Allow, "app == 'web'")],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[("app", "attacker")]),
        protocol: None,
        port: None,
        expected: Decision::Deny,
    });
    cases.push(Case {
        name: "default-deny/end-of-tier-beats-later-profile-allow",
        anchor: "endpoints.go:690 end-of-tier drop is terminal; profiles not reached",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "allow-web-only",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![peer_rule(RuleAction::Allow, "app == 'web'")],
                )],
                TierDefault::Deny,
            )],
            // A permissive profile exists but must NOT be consulted: the tier
            // already produced a terminal end-of-tier drop.
            profiles: vec![policy(
                "ns-default-allow",
                "all()",
                Direction::Ingress,
                vec![any(RuleAction::Allow)],
            )],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[("app", "attacker")]),
        protocol: None,
        port: None,
        expected: Decision::Deny,
    });

    // -- OPEN-BY-DEFAULT ------------------------------------------------------
    // endpoints.go: a tier whose policies do not select the endpoint has no
    // effect; with no profile matching either, traffic is allowed.
    cases.push(Case {
        name: "open-by-default/nothing-selects-no-profile",
        anchor: "endpoints.go: unselected endpoint + no profile → open (allow)",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "for-other",
                    "app == 'other'",
                    Direction::Ingress,
                    vec![any(RuleAction::Deny)],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });
    cases.push(Case {
        name: "open-by-default/empty-model",
        anchor: "endpoints.go: no tiers, no profiles → open (allow)",
        evaluator: PolicyEvaluator::default(),
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });

    // -- PRECEDENCE / ORDERING ------------------------------------------------
    // endpoints.go: policies in a tier are rendered in order; the first
    // matching terminal action wins. An earlier Deny beats a later Allow.
    cases.push(Case {
        name: "precedence/earlier-deny-beats-later-allow",
        anchor: "endpoints.go: policies evaluated in order; first terminal action wins",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![
                    policy(
                        "deny-first",
                        "all()",
                        Direction::Ingress,
                        vec![any(RuleAction::Deny)],
                    ),
                    policy(
                        "allow-second",
                        "all()",
                        Direction::Ingress,
                        vec![any(RuleAction::Allow)],
                    ),
                ],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Deny,
    });
    cases.push(Case {
        name: "precedence/earlier-allow-beats-later-deny",
        anchor: "endpoints.go: reversed order → earlier Allow wins",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![
                    policy(
                        "allow-first",
                        "all()",
                        Direction::Ingress,
                        vec![any(RuleAction::Allow)],
                    ),
                    policy(
                        "deny-second",
                        "all()",
                        Direction::Ingress,
                        vec![any(RuleAction::Deny)],
                    ),
                ],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });
    cases.push(Case {
        name: "precedence/first-matching-rule-within-policy-wins",
        anchor: "endpoints.go: rules within a policy evaluated in order",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "deny-bad-then-allow",
                    "all()",
                    Direction::Ingress,
                    vec![
                        peer_rule(RuleAction::Deny, "bad == 'true'"),
                        any(RuleAction::Allow),
                    ],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[]),
        direction: Direction::Ingress,
        peer: labels(&[("bad", "true")]),
        protocol: None,
        port: None,
        expected: Decision::Deny,
    });
    cases.push(Case {
        name: "precedence/earlier-tier-deny-beats-later-tier-allow",
        anchor: "endpoints.go: tiers evaluated in order; a terminal Deny in tier 0 wins",
        evaluator: PolicyEvaluator {
            tiers: vec![
                tier(
                    vec![policy(
                        "tier0-deny",
                        "app == 'db'",
                        Direction::Ingress,
                        vec![any(RuleAction::Deny)],
                    )],
                    TierDefault::Deny,
                ),
                tier(
                    vec![policy(
                        "tier1-allow",
                        "app == 'db'",
                        Direction::Ingress,
                        vec![any(RuleAction::Allow)],
                    )],
                    TierDefault::Deny,
                ),
            ],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Deny,
    });

    // -- PASS -----------------------------------------------------------------
    // endpoints.go: a Pass rule marks the packet "pass", skipping the rest of
    // the tier and continuing at the next tier.
    cases.push(Case {
        name: "pass/skips-rest-of-tier-to-next-tier-deny",
        anchor: "endpoints.go: Pass mark skips remaining tier policies to the next tier",
        evaluator: PolicyEvaluator {
            tiers: vec![
                tier(
                    vec![
                        policy(
                            "pass-out",
                            "app == 'db'",
                            Direction::Ingress,
                            vec![any(RuleAction::Pass)],
                        ),
                        // Must be skipped by the Pass above.
                        policy(
                            "would-allow",
                            "app == 'db'",
                            Direction::Ingress,
                            vec![any(RuleAction::Allow)],
                        ),
                    ],
                    TierDefault::Deny,
                ),
                tier(
                    vec![policy(
                        "next-tier-deny",
                        "app == 'db'",
                        Direction::Ingress,
                        vec![any(RuleAction::Deny)],
                    )],
                    TierDefault::Deny,
                ),
            ],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Deny,
    });
    cases.push(Case {
        name: "pass/nothing-after-falls-to-profile-allow",
        anchor: "endpoints.go:621 after Pass, continue to profiles; profile allows",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "pass-out",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![any(RuleAction::Pass)],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![policy(
                "ns-default-allow",
                "all()",
                Direction::Ingress,
                vec![any(RuleAction::Allow)],
            )],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });
    cases.push(Case {
        name: "pass/nothing-after-no-profile-defaults-open",
        anchor: "endpoints.go: Pass with no further tier/profile → open-by-default allow",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "pass-out",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![any(RuleAction::Pass)],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });
    cases.push(Case {
        name: "pass/tier-default-pass-continues-to-next-tier",
        anchor: "endpoints.go:690 DefaultAction==Pass suppresses end-of-tier drop",
        evaluator: PolicyEvaluator {
            tiers: vec![
                // Selects but no rule matches; default Pass → next tier (no drop).
                tier(
                    vec![policy(
                        "no-match-pass-tier",
                        "app == 'db'",
                        Direction::Ingress,
                        vec![peer_rule(RuleAction::Allow, "app == 'nope'")],
                    )],
                    TierDefault::Pass,
                ),
                tier(
                    vec![policy(
                        "second-tier-allow",
                        "app == 'db'",
                        Direction::Ingress,
                        vec![any(RuleAction::Allow)],
                    )],
                    TierDefault::Deny,
                ),
            ],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });

    // -- PROFILE FALLBACK -----------------------------------------------------
    // endpoints.go:741 after all tiers, jump to each profile in turn.
    cases.push(Case {
        name: "profile/fallback-allow-when-no-tier-decides",
        anchor: "endpoints.go:741 profiles consulted after tiers; profile allow",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "for-other",
                    "app == 'other'",
                    Direction::Ingress,
                    vec![any(RuleAction::Deny)],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![policy(
                "ns-default-allow",
                "all()",
                Direction::Ingress,
                vec![any(RuleAction::Allow)],
            )],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });
    cases.push(Case {
        name: "profile/fallback-deny-when-no-tier-decides",
        anchor: "endpoints.go:741 profile Deny rule is terminal",
        evaluator: PolicyEvaluator {
            tiers: vec![],
            profiles: vec![policy(
                "ns-deny-attacker",
                "all()",
                Direction::Ingress,
                vec![peer_rule(RuleAction::Deny, "app == 'attacker'")],
            )],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[("app", "attacker")]),
        protocol: None,
        port: None,
        expected: Decision::Deny,
    });
    cases.push(Case {
        name: "profile/no-profile-rule-matches-defaults-open",
        anchor: "endpoints.go: profiles exhausted with no match → open-by-default allow",
        evaluator: PolicyEvaluator {
            tiers: vec![],
            profiles: vec![policy(
                "ns-allow-web-only",
                "all()",
                Direction::Ingress,
                vec![peer_rule(RuleAction::Allow, "app == 'web'")],
            )],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[("app", "attacker")]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });

    // -- PORT / PROTOCOL ------------------------------------------------------
    // rule_matches: a rule constrained to protocol+port only matches the right
    // protocol+port; otherwise it falls through (here to end-of-tier drop).
    cases.push(Case {
        name: "port/right-port-allows",
        anchor: "rule protocol+port match → Allow (TCP/5432)",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "allow-pg",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![proto_port_rule(RuleAction::Allow, "TCP", vec![5432])],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: Some("TCP"),
        port: Some(5432),
        expected: Decision::Allow,
    });
    cases.push(Case {
        name: "port/wrong-port-falls-through-to-deny",
        anchor: "rule port mismatch → no match → end-of-tier drop",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "allow-pg",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![proto_port_rule(RuleAction::Allow, "TCP", vec![5432])],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: Some("TCP"),
        port: Some(80),
        expected: Decision::Deny,
    });
    cases.push(Case {
        name: "protocol/wrong-protocol-falls-through-to-deny",
        anchor: "rule protocol mismatch (UDP vs TCP) → no match → end-of-tier drop",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "allow-tcp-pg",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![proto_port_rule(RuleAction::Allow, "TCP", vec![5432])],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: Some("UDP"),
        port: Some(5432),
        expected: Decision::Deny,
    });
    cases.push(Case {
        name: "protocol/case-insensitive-match-allows",
        anchor: "rule_matches: protocol compared case-insensitively (tcp == TCP)",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "allow-tcp-pg",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![proto_port_rule(RuleAction::Allow, "TCP", vec![5432])],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: Some("tcp"),
        port: Some(5432),
        expected: Decision::Allow,
    });

    // -- DIRECTION ------------------------------------------------------------
    // endpoints.go: ingress and egress chains are separate; a policy that
    // applies to only one direction has no effect on the other.
    cases.push(Case {
        name: "direction/ingress-only-policy-ignored-on-egress",
        anchor: "endpoints.go: ingress-only policy does not select for egress → open",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "ingress-deny",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![any(RuleAction::Deny)],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        // Egress packet: the ingress-only policy does not apply → open-by-default.
        direction: Direction::Egress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });
    cases.push(Case {
        name: "direction/egress-only-policy-ignored-on-ingress",
        anchor: "endpoints.go: egress-only policy does not select for ingress → open",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "egress-deny",
                    "app == 'db'",
                    Direction::Egress,
                    vec![any(RuleAction::Deny)],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });
    cases.push(Case {
        name: "direction/egress-policy-applies-on-egress",
        anchor: "endpoints.go: egress-only policy selects for egress → its rule applies",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "egress-deny",
                    "app == 'db'",
                    Direction::Egress,
                    vec![any(RuleAction::Deny)],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Egress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Deny,
    });

    // -- NAMESPACE / SELECTOR -------------------------------------------------
    // rule_matches: a peer (source/dest) selector must match the peer's labels.
    cases.push(Case {
        name: "selector/peer-selector-match-allows",
        anchor: "rule_matches: peer selector matches source labels → Allow",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "allow-frontend",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![peer_rule(RuleAction::Allow, "role == 'frontend'")],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[("role", "frontend")]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });
    cases.push(Case {
        name: "selector/peer-selector-nonmatch-drops",
        anchor: "rule_matches: peer selector fails → no match → end-of-tier drop",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "allow-frontend",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![peer_rule(RuleAction::Allow, "role == 'frontend'")],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[("role", "backend")]),
        protocol: None,
        port: None,
        expected: Decision::Deny,
    });
    cases.push(Case {
        name: "selector/subject-selector-nonmatch-does-not-select",
        anchor: "endpoints.go: applies-to selector fails → policy does not select → open",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "deny-cache",
                    "app == 'cache'",
                    Direction::Ingress,
                    vec![any(RuleAction::Deny)],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        // Subject is 'db', policy selects 'cache' → not selected → open.
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });
    cases.push(Case {
        name: "selector/namespace-in-set-allows",
        anchor: "selector 'in {..}' set membership on peer namespace label → Allow",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "allow-trusted-ns",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![peer_rule(
                        RuleAction::Allow,
                        "namespace in {'prod','staging'}",
                    )],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[("namespace", "prod")]),
        protocol: None,
        port: None,
        expected: Decision::Allow,
    });
    cases.push(Case {
        name: "selector/namespace-not-in-set-drops",
        anchor: "selector 'in {..}' fails for out-of-set namespace → end-of-tier drop",
        evaluator: PolicyEvaluator {
            tiers: vec![tier(
                vec![policy(
                    "allow-trusted-ns",
                    "app == 'db'",
                    Direction::Ingress,
                    vec![peer_rule(
                        RuleAction::Allow,
                        "namespace in {'prod','staging'}",
                    )],
                )],
                TierDefault::Deny,
            )],
            profiles: vec![],
        },
        subject: labels(&[("app", "db")]),
        direction: Direction::Ingress,
        peer: labels(&[("namespace", "dev")]),
        protocol: None,
        port: None,
        expected: Decision::Deny,
    });

    cases
}

// ---------------------------------------------------------------------------
// The single parametric conformance test.
// ---------------------------------------------------------------------------

#[test]
fn conformance_corpus() {
    let cases = corpus();
    assert!(!cases.is_empty(), "conformance corpus must not be empty");

    // Case names must be unique (they are the failure identifiers).
    let mut seen = std::collections::BTreeSet::new();
    for c in &cases {
        assert!(
            seen.insert(c.name),
            "duplicate conformance case name: {}",
            c.name
        );
    }

    let mut failures = Vec::new();
    for c in &cases {
        let pkt = c.packet();

        // 1) evaluate() must produce the upstream-anchored expected decision.
        let got = c.evaluator.evaluate(&c.subject, &pkt);
        if got != c.expected {
            failures.push(format!(
                "case '{}' [{}]: evaluate → {:?}, expected {:?}",
                c.name, c.anchor, got, c.expected
            ));
        }

        // 2) evaluate_traced() must never drift from evaluate() (T060 guarantee).
        let traced = c.evaluator.evaluate_traced(&c.subject, &pkt);
        if traced.decision != got {
            failures.push(format!(
                "case '{}': evaluate_traced → {:?} disagrees with evaluate → {:?} (reason {:?})",
                c.name, traced.decision, got, traced.reason
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} conformance case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
