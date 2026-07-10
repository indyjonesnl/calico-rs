//! Flow-log records — the "why" behind an allow/deny decision (spec FR-029).
//!
//! [`PolicyEvaluator::evaluate_traced`] answers *which* tier/policy/rule decided a
//! packet's fate; this module packages that provenance into a [`FlowLogRecord`]
//! and renders a concise human-readable line for logs.
//!
//! Placement note: the plan names `crates/felix/src/flowlogs.rs`, but the decision
//! logic lives in `calc` (`felix` does not depend on `calc`), so the pure record
//! model + formatter live here alongside the evaluator. The dataplane-side emitter
//! that attaches these to *observed* packets (supplying real peer IPs and the
//! `rule_id` from the wire protocol) is a later wiring step; until then `rule_id`
//! is `None`.

use std::fmt;

use crate::policy_eval::{Decision, DecisionReason, Direction, Packet, PolicyEvaluator};

/// One classified flow with the reason it was allowed or denied.
///
/// Pure and I/O-free: callers own emission (e.g. via `tracing`). `subject`/`peer`
/// are caller-supplied endpoint identifiers (a workload name, an IP) since they are
/// not derivable from label sets; `rule_id` is the dataplane's attribution key and
/// stays `None` until the wire protocol supplies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowLogRecord {
    pub subject: String,
    pub peer: String,
    pub direction: Direction,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub action: Decision,
    pub reason: DecisionReason,
    pub rule_id: Option<String>,
}

impl FlowLogRecord {
    /// Render a concise one-line "why" string, e.g.
    /// `ALLOW ingress db<-web:5432 by tier=tier#0 policy=allow-web rule#1`.
    pub fn to_line(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for FlowLogRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self.action {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY",
        };
        let (dir, arrow) = match self.direction {
            // Ingress: peer is the source of the flow into the subject.
            Direction::Ingress => ("ingress", "<-"),
            // Egress: subject is the source of the flow out to the peer.
            Direction::Egress => ("egress", "->"),
        };
        write!(f, "{action} {dir} {}{arrow}{}", self.subject, self.peer)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        write!(f, " by {}", render_reason(&self.reason))?;
        if let Some(rule_id) = &self.rule_id {
            write!(f, " rule_id={rule_id}")?;
        }
        Ok(())
    }
}

fn render_reason(reason: &DecisionReason) -> String {
    match reason {
        DecisionReason::RuleMatch {
            tier,
            policy,
            rule_index,
            ..
        } => format!("tier={tier} policy={policy} rule#{rule_index}"),
        DecisionReason::EndOfTierDrop { tier } => format!("end-of-tier-drop tier={tier}"),
        DecisionReason::ProfileMatch {
            profile,
            rule_index,
            ..
        } => format!("profile={profile} rule#{rule_index}"),
        DecisionReason::DefaultAllow => "default-allow".to_string(),
    }
}

/// Run [`PolicyEvaluator::evaluate_traced`] and package the result into a
/// [`FlowLogRecord`]. `subject`/`peer` are the caller's endpoint identifiers;
/// `rule_id` is left `None` for the dataplane to fill in later.
pub fn flow_log(
    subject: impl Into<String>,
    peer: impl Into<String>,
    subject_labels: &std::collections::BTreeMap<String, String>,
    pkt: &Packet,
    evaluator: &PolicyEvaluator,
) -> FlowLogRecord {
    let traced = evaluator.evaluate_traced(subject_labels, pkt);
    FlowLogRecord {
        subject: subject.into(),
        peer: peer.into(),
        direction: pkt.direction,
        protocol: pkt.protocol.map(str::to_string),
        port: pkt.port,
        action: traced.decision,
        reason: traced.reason,
        rule_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_eval::{EvalPolicy, EvalRule, RuleAction, Tier, TierDefault};
    use crate::selector::Selector;
    use std::collections::BTreeMap;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn to_line_renders_allow_by_rule() {
        let rec = FlowLogRecord {
            subject: "db".to_string(),
            peer: "web".to_string(),
            direction: Direction::Ingress,
            protocol: Some("TCP".to_string()),
            port: Some(5432),
            action: Decision::Allow,
            reason: DecisionReason::RuleMatch {
                tier: "tier#0".to_string(),
                policy: "allow-web".to_string(),
                direction: Direction::Ingress,
                rule_index: 1,
                action: RuleAction::Allow,
            },
            rule_id: None,
        };
        assert_eq!(
            rec.to_line(),
            "ALLOW ingress db<-web:5432 by tier=tier#0 policy=allow-web rule#1"
        );
    }

    #[test]
    fn to_line_renders_deny_end_of_tier() {
        let rec = FlowLogRecord {
            subject: "db".to_string(),
            peer: "attacker".to_string(),
            direction: Direction::Ingress,
            protocol: Some("TCP".to_string()),
            port: Some(5432),
            action: Decision::Deny,
            reason: DecisionReason::EndOfTierDrop {
                tier: "tier#0".to_string(),
            },
            rule_id: None,
        };
        assert_eq!(
            rec.to_line(),
            "DENY ingress db<-attacker:5432 by end-of-tier-drop tier=tier#0"
        );
    }

    #[test]
    fn to_line_renders_egress_and_rule_id_and_no_port() {
        let rec = FlowLogRecord {
            subject: "web".to_string(),
            peer: "db".to_string(),
            direction: Direction::Egress,
            protocol: None,
            port: None,
            action: Decision::Allow,
            reason: DecisionReason::ProfileMatch {
                profile: "ns-default".to_string(),
                rule_index: 0,
                action: RuleAction::Allow,
            },
            rule_id: Some("np/allow-egress:0".to_string()),
        };
        assert_eq!(
            rec.to_line(),
            "ALLOW egress web->db by profile=ns-default rule#0 rule_id=np/allow-egress:0"
        );
    }

    #[test]
    fn flow_log_packages_traced_decision() {
        let ev = PolicyEvaluator {
            tiers: vec![Tier {
                policies: vec![EvalPolicy {
                    name: Some("allow-web".to_string()),
                    selector: Selector::parse("app == 'db'").unwrap(),
                    applies_ingress: true,
                    applies_egress: false,
                    ingress: vec![EvalRule {
                        action: RuleAction::Allow,
                        protocol: Some("TCP".to_string()),
                        peer_selector: Some(Selector::parse("app == 'web'").unwrap()),
                        ports: vec![5432],
                    }],
                    egress: vec![],
                }],
                default_action: TierDefault::Deny,
            }],
            profiles: vec![],
        };
        let subject = labels(&[("app", "db")]);
        let peer = labels(&[("app", "web")]);
        let pkt = Packet {
            direction: Direction::Ingress,
            peer_labels: &peer,
            protocol: Some("TCP"),
            port: Some(5432),
        };
        let rec = flow_log("db", "web", &subject, &pkt, &ev);
        assert_eq!(rec.action, Decision::Allow);
        assert_eq!(rec.protocol.as_deref(), Some("TCP"));
        assert_eq!(rec.port, Some(5432));
        assert_eq!(rec.rule_id, None);
        assert_eq!(
            rec.to_line(),
            "ALLOW ingress db<-web:5432 by tier=tier#0 policy=allow-web rule#0"
        );
    }
}
