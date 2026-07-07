//! Translate a native Kubernetes `NetworkPolicy` (`networking.k8s.io/v1`) into
//! the Calico-rs decision model (spec FR-008: enforce both K8s and Calico policy).
//!
//! K8s semantics reproduced:
//! - A pod selected by `podSelector` is *isolated* for the listed `policyTypes`;
//!   traffic is allowed only if it matches some rule → this maps to Allow rules
//!   in a default-deny tier.
//! - Rules are allow-only. Within a rule, `from`/`to` peers and `ports` are ORed;
//!   an empty `from` means all sources, an empty `ports` means all ports.
//! - Selectors are namespace-scoped: the policy's `podSelector` and a peer's
//!   `podSelector` (when no `namespaceSelector` is given) are confined to the
//!   policy's namespace, expressed via the `projectcalico.org/namespace` label.
//!   A peer `namespaceSelector` matches namespaces via the `pcns.` label prefix
//!   (the labels our namespace→Profile controller applies).
//!
//! Not yet handled (documented gaps): `ipBlock` peers, named ports, `endPort`.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::policy_eval::{EvalPolicy, EvalRule, RuleAction};
use crate::selector::Selector;

const NS_LABEL: &str = "projectcalico.org/namespace";
const NS_PREFIX: &str = "pcns.";

/// A Kubernetes `LabelSelector`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
    #[serde(default)]
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

/// A `matchExpressions` requirement.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelectorRequirement {
    pub key: String,
    pub operator: String, // In | NotIn | Exists | DoesNotExist
    #[serde(default)]
    pub values: Vec<String>,
}

/// A peer in a `from`/`to` list.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicyPeer {
    #[serde(default)]
    pub pod_selector: Option<LabelSelector>,
    #[serde(default)]
    pub namespace_selector: Option<LabelSelector>,
    // ipBlock intentionally omitted (label model cannot express CIDR peers yet).
}

/// A port constraint.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicyPort {
    #[serde(default)]
    pub protocol: Option<String>,
    /// Numeric port; named ports (strings) are not yet supported.
    #[serde(default)]
    pub port: Option<u16>,
}

/// An ingress/egress rule.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicyRule {
    #[serde(default, alias = "to")]
    pub from: Vec<NetworkPolicyPeer>,
    #[serde(default)]
    pub ports: Vec<NetworkPolicyPort>,
}

/// The spec of a native Kubernetes `NetworkPolicy`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct K8sNetworkPolicySpec {
    #[serde(default)]
    pub pod_selector: LabelSelector,
    #[serde(default)]
    pub policy_types: Vec<String>,
    #[serde(default)]
    pub ingress: Vec<NetworkPolicyRule>,
    #[serde(default)]
    pub egress: Vec<NetworkPolicyRule>,
}

fn fold_and(terms: Vec<Selector>) -> Selector {
    terms
        .into_iter()
        .reduce(|a, b| Selector::And(Box::new(a), Box::new(b)))
        .unwrap_or(Selector::All)
}

/// Translate a K8s `LabelSelector` to a Calico [`Selector`], with an optional
/// key prefix (used to map a peer's `namespaceSelector` onto `pcns.` labels).
fn label_selector(ls: &LabelSelector, prefix: &str) -> Selector {
    let mut terms = Vec::new();
    for (k, v) in &ls.match_labels {
        terms.push(Selector::Equal(format!("{prefix}{k}"), v.clone()));
    }
    for req in &ls.match_expressions {
        let key = format!("{prefix}{}", req.key);
        match req.operator.as_str() {
            "In" => terms.push(Selector::In(key, req.values.clone())),
            "NotIn" => terms.push(Selector::NotIn(key, req.values.clone())),
            "Exists" => terms.push(Selector::Has(key)),
            "DoesNotExist" => terms.push(Selector::Not(Box::new(Selector::Has(key)))),
            _ => {} // unknown operator: ignore
        }
    }
    fold_and(terms)
}

/// Peer selector: pod + namespace scoping. No `namespaceSelector` ⇒ confined to
/// `namespace`. Empty peer ⇒ any peer (`None`).
fn peer_selector(peer: &NetworkPolicyPeer, namespace: &str) -> Option<Selector> {
    let mut terms = Vec::new();
    match &peer.namespace_selector {
        Some(ns) => terms.push(label_selector(ns, NS_PREFIX)),
        None => {
            // Same-namespace: the peer pod must be in the policy's namespace.
            terms.push(Selector::Equal(NS_LABEL.to_string(), namespace.to_string()));
        }
    }
    if let Some(pods) = &peer.pod_selector {
        terms.push(label_selector(pods, ""));
    }
    if terms.is_empty() {
        None
    } else {
        Some(fold_and(terms))
    }
}

fn rule_to_evals(rule: &NetworkPolicyRule, namespace: &str) -> Vec<EvalRule> {
    let ports: Vec<u16> = rule.ports.iter().filter_map(|p| p.port).collect();
    let protocol = rule.ports.iter().find_map(|p| p.protocol.clone());

    if rule.from.is_empty() {
        // No peers ⇒ allow from anywhere (subject to ports).
        return vec![EvalRule {
            action: RuleAction::Allow,
            protocol,
            peer_selector: None,
            ports,
        }];
    }
    // One Allow rule per peer (peers are ORed).
    rule.from
        .iter()
        .map(|peer| EvalRule {
            action: RuleAction::Allow,
            protocol: protocol.clone(),
            peer_selector: peer_selector(peer, namespace),
            ports: ports.clone(),
        })
        .collect()
}

/// Translate a K8s NetworkPolicy spec (in `namespace`) into a Calico
/// [`EvalPolicy`] to be placed in the default-deny tier.
pub fn k8s_network_policy_to_eval(spec: &K8sNetworkPolicySpec, namespace: &str) -> EvalPolicy {
    // Subject selector = podSelector confined to the policy's namespace.
    let subject = Selector::And(
        Box::new(Selector::Equal(NS_LABEL.to_string(), namespace.to_string())),
        Box::new(label_selector(&spec.pod_selector, "")),
    );

    let (applies_ingress, applies_egress) = if spec.policy_types.is_empty() {
        // K8s default: Ingress always; Egress only if egress rules present.
        (true, !spec.egress.is_empty())
    } else {
        (
            spec.policy_types.iter().any(|x| x == "Ingress"),
            spec.policy_types.iter().any(|x| x == "Egress"),
        )
    };

    EvalPolicy {
        selector: subject,
        applies_ingress,
        applies_egress,
        ingress: spec
            .ingress
            .iter()
            .flat_map(|r| rule_to_evals(r, namespace))
            .collect(),
        egress: spec
            .egress
            .iter()
            .flat_map(|r| rule_to_evals(r, namespace))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_eval::{Decision, Direction, Packet, PolicyEvaluator, Tier, TierDefault};

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn evaluator(spec: &K8sNetworkPolicySpec, ns: &str) -> PolicyEvaluator {
        PolicyEvaluator {
            tiers: vec![Tier {
                policies: vec![k8s_network_policy_to_eval(spec, ns)],
                default_action: TierDefault::Deny,
            }],
            profiles: vec![],
        }
    }

    #[test]
    fn allow_from_pod_selector_same_namespace() {
        let spec: K8sNetworkPolicySpec = serde_json::from_str(
            r#"{
                "podSelector": { "matchLabels": { "app": "db" } },
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "from": [{ "podSelector": { "matchLabels": { "app": "web" } } }],
                    "ports": [{ "protocol": "TCP", "port": 5432 }]
                }]
            }"#,
        )
        .unwrap();
        let ev = evaluator(&spec, "prod");

        let db = labels(&[("projectcalico.org/namespace", "prod"), ("app", "db")]);
        let web_prod = labels(&[("projectcalico.org/namespace", "prod"), ("app", "web")]);
        let web_other = labels(&[("projectcalico.org/namespace", "dev"), ("app", "web")]);

        fn pkt(peer: &BTreeMap<String, String>, port: u16) -> Packet<'_> {
            Packet {
                direction: Direction::Ingress,
                peer_labels: peer,
                protocol: Some("TCP"),
                port: Some(port),
            }
        }
        // web in prod → db:5432 allowed.
        assert_eq!(ev.evaluate(&db, &pkt(&web_prod, 5432)), Decision::Allow);
        // web in a different namespace → denied (namespace scoping).
        assert_eq!(ev.evaluate(&db, &pkt(&web_other, 5432)), Decision::Deny);
        // wrong port → denied.
        assert_eq!(ev.evaluate(&db, &pkt(&web_prod, 80)), Decision::Deny);
    }

    #[test]
    fn empty_ingress_is_default_deny() {
        let spec: K8sNetworkPolicySpec =
            serde_json::from_str(r#"{"podSelector":{},"policyTypes":["Ingress"]}"#).unwrap();
        let ev = evaluator(&spec, "prod");
        let subject = labels(&[("projectcalico.org/namespace", "prod"), ("app", "x")]);
        assert_eq!(
            ev.evaluate(
                &subject,
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
    fn namespace_selector_allows_cross_namespace() {
        let spec: K8sNetworkPolicySpec = serde_json::from_str(
            r#"{
                "podSelector": { "matchLabels": { "app": "db" } },
                "policyTypes": ["Ingress"],
                "ingress": [{ "from": [{ "namespaceSelector": { "matchLabels": { "team": "net" } } }] }]
            }"#,
        )
        .unwrap();
        let ev = evaluator(&spec, "prod");
        let db = labels(&[("projectcalico.org/namespace", "prod"), ("app", "db")]);
        // Peer carries the pcns.team label (applied by the namespace controller).
        let peer = labels(&[("pcns.team", "net")]);
        assert_eq!(
            ev.evaluate(
                &db,
                &Packet {
                    direction: Direction::Ingress,
                    peer_labels: &peer,
                    protocol: None,
                    port: None
                }
            ),
            Decision::Allow
        );
    }

    #[test]
    fn match_expressions_translate() {
        let ls: LabelSelector = serde_json::from_str(
            r#"{ "matchExpressions": [
                { "key": "env", "operator": "In", "values": ["prod","staging"] },
                { "key": "temp", "operator": "DoesNotExist" }
            ]}"#,
        )
        .unwrap();
        let sel = label_selector(&ls, "");
        assert!(sel.matches(&labels(&[("env", "prod")])));
        assert!(!sel.matches(&labels(&[("env", "dev")])));
        assert!(!sel.matches(&labels(&[("env", "prod"), ("temp", "1")])));
    }
}
