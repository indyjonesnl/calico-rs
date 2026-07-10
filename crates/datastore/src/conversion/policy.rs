//! Pure projection: native Kubernetes `NetworkPolicy` (`networking.k8s.io/v1`)
//! → Calico [`apis::NetworkPolicySpec`].
//!
//! K8s-native NetworkPolicies are enforced through the **same** pipeline as
//! Calico policies: datastore → CalcGraph → dataplane. That requires projecting
//! a K8s NetworkPolicy into the canonical Calico `NetworkPolicySpec` the graph
//! consumes. This reproduces upstream `libcalico-go`
//! `backend/k8s/conversion/conversion.go` `K8sNetworkPolicyToCalico` /
//! `k8sSelectorToCalico` / `k8sRuleToCalico` / `k8sPeerToCalicoFields` as a pure,
//! I/O-free function.
//!
//! ## Input type & dep direction
//! Input is `k8s_openapi::api::networking::v1::NetworkPolicy` — `datastore`
//! already depends on `k8s-openapi`, so there is no need to reach into `calc`'s
//! [`k8s_policy`] types. (`calc` depends on `apis`+`proto` only, so a
//! `datastore → calc` dep would not cycle *today*, but coupling the datastore
//! projection to the calc evaluator's private wire structs is undesirable, and
//! reusing the upstream k8s wire types keeps the two paths independently
//! testable.)
//!
//! ## Relationship to `calc::k8s_policy`
//! `calc::k8s_policy::k8s_network_policy_to_eval` is a *parallel* path that
//! lowers a K8s NP straight to `calc`'s `EvalPolicy` for direct in-memory
//! evaluation. This function targets the **canonical Calico `NetworkPolicySpec`**
//! instead, so K8s NPs flow through the whole graph like Calico NPs. The two
//! necessarily differ in one place — namespace-selector handling — see below.
//!
//! ## namespaceSelector / `pcns.` handling
//! Upstream stores a peer's `namespaceSelector` **raw** (unprefixed) in the
//! dedicated `EntityRule.namespaceSelector` field; the graph applies the `pcns.`
//! prefixing when it interprets that field against namespace labels. This
//! function matches upstream verbatim (raw string in `namespace_selector`). By
//! contrast `calc::k8s_policy` folds the namespace selector into a single
//! `pcns.`-prefixed selector string because its `EvalRule` has only one selector
//! and matches endpoint effective-labels directly. Both are correct for their
//! respective consumers.
//!
//! ## Default-deny composition
//! K8s isolation semantics = *default-deny* for a selected pod in each governed
//! direction; traffic is allowed only if some rule matches. This projection emits
//! **Allow-only** rules and never an explicit `Deny`: the dataplane's
//! per-endpoint default-deny (the tier default applied once a pod is selected by
//! any policy) supplies the deny. Double-adding an explicit deny here would be
//! redundant and could shadow policies in later tiers. This matches upstream,
//! which likewise emits only Allow rules.

use std::collections::BTreeMap;

use apis::{Action, EntityRule, NetworkPolicySpec, PolicyType, Protocol, Rule};
use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort, NetworkPolicySpec as K8sNetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// WEP label key carrying the orchestrator (`v3/constants.go` `LabelOrchestrator`).
pub const LABEL_ORCHESTRATOR: &str = "projectcalico.org/orchestrator";
/// The Kubernetes orchestrator identifier.
pub const ORCHESTRATOR_K8S: &str = "k8s";
/// Tier that converted K8s NetworkPolicies land in (`names.DefaultTierName`).
pub const DEFAULT_TIER: &str = "default";
/// Fixed order upstream assigns to converted K8s NetworkPolicies
/// (`K8sNetworkPolicyToCalico`: "insert ... at order 1000.0").
pub const K8S_NETWORK_POLICY_ORDER: f64 = 1000.0;
/// Implicit protocol for a `NetworkPolicyPort` with no protocol (per the k8s API
/// definition of `NetworkPolicyPort`); made explicit as our data-model requires a
/// protocol whenever a port match is present.
const DEFAULT_PROTOCOL: &str = "TCP";

/// Project a Kubernetes [`NetworkPolicy`] into a Calico [`NetworkPolicySpec`].
///
/// This function does **not** apply namespace confinement: the emitted
/// top-level `selector` and rule-peer selectors match across **all**
/// namespaces, not just the policy's own. Upstream does not scope a converted
/// K8s NetworkPolicy at the resource level either — namespace-scoping is
/// injected as a *later* pipeline stage, by rewriting the selector text with a
/// `projectcalico.org/namespace == '<ns>'` term (`libcalico-go`
/// `updateprocessors/rules.go` `getEndpointSelector` /
/// `ConvertNetworkPolicyV3ToV1Value`).
///
/// TODO(namespace-scoping): a future update-processor stage in this crate must
/// reproduce that rewrite using [`super::LABEL_NAMESPACE`]
/// (`projectcalico.org/namespace`), confining both the top-level `selector`
/// and any rule peer whose `namespace_selector` is `None` (which — per K8s
/// `NetworkPolicy` semantics — means "the policy's own namespace", not "any
/// namespace") to the policy's namespace. Until that stage exists, a converted
/// K8s NetworkPolicy produced by this function applies across all namespaces —
/// an isolation gap — so callers MUST NOT feed its output directly into the
/// dataplane without that confinement applied.
pub fn k8s_network_policy_to_calico(np: &NetworkPolicy) -> NetworkPolicySpec {
    match np.spec.as_ref() {
        Some(spec) => k8s_network_policy_spec_to_calico(spec),
        None => k8s_network_policy_spec_to_calico(&K8sNetworkPolicySpec::default()),
    }
}

/// Project a Kubernetes [`NetworkPolicySpec`](K8sNetworkPolicySpec) into a Calico
/// [`NetworkPolicySpec`].
pub fn k8s_network_policy_spec_to_calico(spec: &K8sNetworkPolicySpec) -> NetworkPolicySpec {
    let selector = selector_to_calico(spec.pod_selector.as_ref(), SelectorKind::Pod);

    let ingress: Vec<Rule> = spec
        .ingress
        .iter()
        .flatten()
        .flat_map(|r| {
            build_rules(
                r.from.as_deref().unwrap_or(&[]),
                r.ports.as_deref().unwrap_or(&[]),
                true,
            )
        })
        .collect();

    let egress: Vec<Rule> = spec
        .egress
        .iter()
        .flatten()
        .flat_map(|r| {
            build_rules(
                r.to.as_deref().unwrap_or(&[]),
                r.ports.as_deref().unwrap_or(&[]),
                false,
            )
        })
        .collect();

    // Types come from `policyTypes` only. On a cluster that predates the field
    // (empty), upstream defaults to Ingress-only. (On modern clusters the API
    // server always populates policyTypes, so the empty case is a legacy
    // fallback — this deliberately does NOT infer Egress from egress rules, which
    // is where it differs from calc::k8s_policy's evaluator inference.)
    let mut ingress_t = false;
    let mut egress_t = false;
    for t in spec.policy_types.iter().flatten() {
        match t.as_str() {
            "Ingress" => ingress_t = true,
            "Egress" => egress_t = true,
            _ => {}
        }
    }
    let mut types = Vec::new();
    if ingress_t {
        types.push(PolicyType::Ingress);
    }
    if egress_t {
        types.push(PolicyType::Egress);
    }
    if types.is_empty() {
        types.push(PolicyType::Ingress);
    }

    NetworkPolicySpec {
        tier: Some(DEFAULT_TIER.to_string()),
        order: Some(K8S_NETWORK_POLICY_ORDER),
        selector,
        types,
        ingress,
        egress,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SelectorKind {
    Pod,
    Namespace,
}

/// Reproduce upstream `k8sSelectorToCalico`. Pod selectors are prefixed with the
/// `projectcalico.org/orchestrator == 'k8s'` term; namespace selectors are not.
/// A `nil` selector yields the orchestrator term (pod) or `""` (namespace); a
/// present-but-empty namespace selector yields `all()`.
fn selector_to_calico(s: Option<&LabelSelector>, kind: SelectorKind) -> String {
    let mut terms: Vec<String> = Vec::new();
    if kind == SelectorKind::Pod {
        terms.push(format!("{LABEL_ORCHESTRATOR} == '{ORCHESTRATOR_K8S}'"));
    }

    let Some(s) = s else {
        return terms.join(" && ");
    };

    let labels_empty = s.match_labels.as_ref().is_none_or(|m| m.is_empty());
    let exprs_empty = s.match_expressions.as_ref().is_none_or(|e| e.is_empty());
    if kind == SelectorKind::Namespace && labels_empty && exprs_empty {
        // A present-but-empty namespace selector means "all namespaces".
        return "all()".to_string();
    }

    // matchLabels: BTreeMap iterates in sorted key order (upstream sorts keys).
    if let Some(labels) = &s.match_labels {
        for (k, v) in labels {
            terms.push(format!("{k} == '{v}'"));
        }
    }

    if let Some(exprs) = &s.match_expressions {
        for e in exprs {
            let values = e.values.clone().unwrap_or_default().join("', '");
            match e.operator.as_str() {
                "In" => terms.push(format!("{} in {{ '{}' }}", e.key, values)),
                "NotIn" => terms.push(format!("{} not in {{ '{}' }}", e.key, values)),
                "Exists" => terms.push(format!("has({})", e.key)),
                "DoesNotExist" => terms.push(format!("! has({})", e.key)),
                _ => {} // unknown operator: ignore (matches upstream)
            }
        }
    }

    terms.join(" && ")
}

/// The peer selector fields for one `from`/`to` entry: `(selector,
/// namespace_selector, nets, not_nets)`. Mirrors `k8sPeerToCalicoFields`. A
/// `None` peer (rule with no peers) yields all-empty = "any peer". An `ipBlock`
/// peer yields nets/not_nets and no selectors.
fn peer_fields(
    peer: Option<&NetworkPolicyPeer>,
) -> (Option<String>, Option<String>, Vec<String>, Vec<String>) {
    let Some(peer) = peer else {
        return (None, None, Vec::new(), Vec::new());
    };

    if let Some(ip) = &peer.ip_block {
        // ipBlock is mutually exclusive with pod/namespace selectors.
        // NOTE: CIDR strings are passed through as-is. Upstream re-masks host
        // bits via net.ParseCIDR; the k8s API server validates CIDR syntax but
        // does not canonicalize, so a policy with host bits set (e.g.
        // "10.0.0.5/16") is emitted verbatim rather than as "10.0.0.0/16". This
        // avoids pulling in an IP-parsing dependency; all upstream test vectors
        // use already-canonical CIDRs.
        let nets = vec![ip.cidr.clone()];
        let not_nets = ip.except.clone().unwrap_or_default();
        return (None, None, nets, not_nets);
    }

    // Pod selector always carries the orchestrator term, so it is never empty.
    let selector = selector_to_calico(peer.pod_selector.as_ref(), SelectorKind::Pod);
    // Namespace selector is empty ("") when absent → represented as None.
    let ns = selector_to_calico(peer.namespace_selector.as_ref(), SelectorKind::Namespace);
    let ns = if ns.is_empty() { None } else { Some(ns) };
    (Some(selector), ns, Vec::new(), Vec::new())
}

/// A single `NetworkPolicyPort`'s port field, reduced to what our data-model can
/// represent (a numeric `u16`).
enum PortKind {
    /// A representable numeric port.
    Number(u16),
    /// No `port` field → the rule matches all ports for its protocol.
    Absent,
    /// A named port, a port range (`endPort`), or an out-of-range number — not
    /// representable in `EntityRule.ports` (`Vec<u16>`); skipped.
    Unsupported,
}

fn port_kind(p: &NetworkPolicyPort) -> PortKind {
    match &p.port {
        None => PortKind::Absent,
        Some(IntOrString::Int(i)) => match u16::try_from(*i) {
            // endPort (a port range) can't be expressed as a single u16 → skip.
            Ok(n) if p.end_port.is_none() => PortKind::Number(n),
            _ => PortKind::Unsupported,
        },
        Some(IntOrString::String(_)) => PortKind::Unsupported,
    }
}

/// Group a rule's ports by protocol into `(protocol, ports)` buckets, mirroring
/// upstream `k8sRuleToCalico`'s protocol grouping. Empty ports → a single bucket
/// with no protocol and no ports (allow all). A port entry with no port number
/// makes its protocol's bucket "all ports" (an empty `ports` vec), which sticks.
fn grouped_ports(ports: &[NetworkPolicyPort]) -> Vec<(Option<Protocol>, Vec<u16>)> {
    if ports.is_empty() {
        return vec![(None, Vec::new())];
    }

    // protocol name → (all_ports?, numeric ports). BTreeMap gives deterministic,
    // sorted protocol order (upstream sorts protocol keys).
    let mut map: BTreeMap<String, (bool, Vec<u16>)> = BTreeMap::new();
    for p in ports {
        let proto = p
            .protocol
            .clone()
            .unwrap_or_else(|| DEFAULT_PROTOCOL.to_string());
        let entry = map.entry(proto).or_default();
        match port_kind(p) {
            PortKind::Number(n) => {
                if !entry.0 {
                    entry.1.push(n);
                }
            }
            PortKind::Absent => {
                // "All ports" wins and sticks for this protocol.
                entry.0 = true;
                entry.1.clear();
            }
            PortKind::Unsupported => {} // skip; does not widen the match
        }
    }

    map.into_iter()
        .map(|(proto, (all, nums))| {
            let ports = if all { Vec::new() } else { nums };
            (Some(Protocol::Named(proto)), ports)
        })
        .collect()
}

/// Build Calico Allow rules for one k8s rule (its peers + ports), one rule per
/// `(protocol bucket × peer)`. Ingress places peer fields in `source` and ports
/// in `destination`; egress places both in `destination`.
fn build_rules(
    peers: &[NetworkPolicyPeer],
    ports: &[NetworkPolicyPort],
    ingress: bool,
) -> Vec<Rule> {
    let peer_refs: Vec<Option<&NetworkPolicyPeer>> = if peers.is_empty() {
        vec![None]
    } else {
        peers.iter().map(Some).collect()
    };

    let mut rules = Vec::new();
    for (protocol, port_nums) in grouped_ports(ports) {
        for peer in &peer_refs {
            let (selector, namespace_selector, nets, not_nets) = peer_fields(*peer);
            let rule = if ingress {
                Rule {
                    action: Action::Allow,
                    protocol: protocol.clone(),
                    source: EntityRule {
                        selector,
                        namespace_selector,
                        nets,
                        not_nets,
                        ..Default::default()
                    },
                    destination: EntityRule {
                        ports: port_nums.clone(),
                        ..Default::default()
                    },
                }
            } else {
                Rule {
                    action: Action::Allow,
                    protocol: protocol.clone(),
                    source: EntityRule::default(),
                    destination: EntityRule {
                        selector,
                        namespace_selector,
                        nets,
                        not_nets,
                        ports: port_nums.clone(),
                        ..Default::default()
                    },
                }
            };
            rules.push(rule);
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    fn np(json: &str) -> NetworkPolicy {
        serde_json::from_str(json).expect("valid NetworkPolicy JSON")
    }

    // Upstream vector: "should parse a basic k8s NetworkPolicy" — selector sorted
    // + orchestrator-prefixed, ingress Allow rule, protocol defaulted to TCP,
    // numeric port 80 kept (named "foo" dropped), Types = [Ingress].
    #[test]
    fn basic_ingress_policy() {
        let policy = np(r#"{
            "metadata": {"name": "test.policy", "namespace": "default"},
            "spec": {
                "podSelector": {"matchLabels": {"label": "value", "label2": "value2"}},
                "ingress": [{
                    "ports": [{"port": 80}, {"port": "foo"}],
                    "from": [{"podSelector": {"matchLabels": {"k": "v", "k2": "v2"}}}]
                }],
                "policyTypes": ["Ingress"]
            }
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);

        assert_eq!(spec.order, Some(1000.0));
        assert_eq!(spec.tier.as_deref(), Some("default"));
        assert_eq!(
            spec.selector,
            "projectcalico.org/orchestrator == 'k8s' && label == 'value' && label2 == 'value2'"
        );
        assert_eq!(spec.types, vec![PolicyType::Ingress]);
        assert!(spec.egress.is_empty());
        assert_eq!(spec.ingress.len(), 1);
        let r = &spec.ingress[0];
        assert_eq!(r.action, Action::Allow);
        assert_eq!(r.protocol, Some(Protocol::Named("TCP".into())));
        assert_eq!(
            r.source.selector.as_deref(),
            Some("projectcalico.org/orchestrator == 'k8s' && k == 'v' && k2 == 'v2'")
        );
        assert!(r.source.namespace_selector.is_none());
        assert_eq!(r.destination.ports, vec![80]);
    }

    // Upstream vector: "empty pod selector" → orchestrator term only.
    #[test]
    fn empty_pod_selector_is_orchestrator_scoped() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        assert_eq!(spec.selector, "projectcalico.org/orchestrator == 'k8s'");
    }

    // Upstream vector: "no ports" — protocol nil, ports empty (allow all ports).
    #[test]
    fn rule_with_no_ports_allows_all_ports() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"k": "v"}}}]}],
                "policyTypes": ["Ingress"]
            }
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        assert_eq!(spec.ingress.len(), 1);
        assert!(spec.ingress[0].protocol.is_none());
        assert!(spec.ingress[0].destination.ports.is_empty());
        assert_eq!(
            spec.ingress[0].source.selector.as_deref(),
            Some("projectcalico.org/orchestrator == 'k8s' && k == 'v'")
        );
    }

    // Upstream vector: "namespaceSelector" — stored raw (no pcns.) in the
    // dedicated namespace_selector field; pod selector still carries orchestrator.
    #[test]
    fn namespace_selector_is_raw_and_separate() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "ingress": [{"from": [{"namespaceSelector": {
                    "matchLabels": {"namespaceFoo": "bar", "namespaceRole": "dev"}
                }}]}],
                "policyTypes": ["Ingress"]
            }
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        let src = &spec.ingress[0].source;
        assert_eq!(
            src.namespace_selector.as_deref(),
            Some("namespaceFoo == 'bar' && namespaceRole == 'dev'")
        );
        // No pcns. prefix here — the graph applies it when interpreting the field.
        assert!(!src.namespace_selector.as_deref().unwrap().contains("pcns."));
        assert_eq!(
            src.selector.as_deref(),
            Some("projectcalico.org/orchestrator == 'k8s'")
        );
    }

    // Upstream vector: "empty namespaceSelector" → all().
    #[test]
    fn empty_namespace_selector_is_all() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "ingress": [{"from": [{"namespaceSelector": {}}]}],
                "policyTypes": ["Ingress"]
            }
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        assert_eq!(
            spec.ingress[0].source.namespace_selector.as_deref(),
            Some("all()")
        );
    }

    // Upstream vector: "Ingress rule with an IPBlock Peer" — nets + not_nets.
    #[test]
    fn ip_block_maps_to_nets_and_not_nets() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "ingress": [{"from": [{"ipBlock": {
                    "cidr": "192.168.0.0/16",
                    "except": ["192.168.3.0/24", "192.168.4.0/24"]
                }}]}],
                "policyTypes": ["Ingress"]
            }
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        let src = &spec.ingress[0].source;
        assert_eq!(src.nets, vec!["192.168.0.0/16".to_string()]);
        assert_eq!(
            src.not_nets,
            vec!["192.168.3.0/24".to_string(), "192.168.4.0/24".to_string()]
        );
        assert!(src.selector.is_none());
        assert!(src.namespace_selector.is_none());
    }

    // Egress ipBlock lands in destination (not source).
    #[test]
    fn egress_ip_block_lands_in_destination() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "egress": [{"to": [{"ipBlock": {"cidr": "10.10.0.0/16"}}]}],
                "policyTypes": ["Egress"]
            }
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        assert_eq!(spec.types, vec![PolicyType::Egress]);
        let dst = &spec.egress[0].destination;
        assert_eq!(dst.nets, vec!["10.10.0.0/16".to_string()]);
        assert!(dst.not_nets.is_empty());
    }

    // Ports + explicit protocol are mapped onto destination.ports + protocol.
    #[test]
    fn ports_and_protocol_mapped() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "egress": [{
                    "ports": [{"port": 53, "protocol": "UDP"}],
                    "to": [{"podSelector": {"matchLabels": {"app": "dns"}}}]
                }],
                "policyTypes": ["Egress"]
            }
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        let r = &spec.egress[0];
        assert_eq!(r.protocol, Some(Protocol::Named("UDP".into())));
        assert_eq!(r.destination.ports, vec![53]);
        assert_eq!(
            r.destination.selector.as_deref(),
            Some("projectcalico.org/orchestrator == 'k8s' && app == 'dns'")
        );
    }

    // policyTypes drives Types; absent → Ingress-only (upstream legacy default),
    // NOT inferred from egress rules.
    #[test]
    fn absent_policy_types_default_to_ingress_only() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "egress": [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}]
            }
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        assert_eq!(spec.types, vec![PolicyType::Ingress]);
        // The egress rule is still converted even though Types omits Egress.
        assert_eq!(spec.egress.len(), 1);
    }

    // Both directions in policyTypes yield both Types.
    #[test]
    fn both_policy_types_yield_both() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        assert_eq!(spec.types, vec![PolicyType::Ingress, PolicyType::Egress]);
    }

    // matchExpressions render in Calico selector syntax.
    #[test]
    fn match_expressions_render() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {
                "podSelector": {"matchExpressions": [
                    {"key": "env", "operator": "In", "values": ["prod", "staging"]},
                    {"key": "temp", "operator": "DoesNotExist"}
                ]},
                "policyTypes": ["Ingress"]
            }
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        assert_eq!(
            spec.selector,
            "projectcalico.org/orchestrator == 'k8s' && env in { 'prod', 'staging' } && ! has(temp)"
        );
    }

    // Default-deny composition: every emitted rule is Allow; no Deny is added.
    #[test]
    fn only_allow_rules_are_emitted() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {
                "podSelector": {"matchLabels": {"app": "db"}},
                "ingress": [
                    {"from": [{"podSelector": {"matchLabels": {"app": "web"}}}]},
                    {"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}
                ],
                "egress": [{"to": [{"namespaceSelector": {}}]}],
                "policyTypes": ["Ingress", "Egress"]
            }
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        assert!(!spec.ingress.is_empty());
        assert!(!spec.egress.is_empty());
        for r in spec.ingress.iter().chain(spec.egress.iter()) {
            assert_eq!(r.action, Action::Allow, "no explicit deny is emitted");
        }
    }

    // Empty `from` = allow from anywhere: rule with fully-empty source entity.
    #[test]
    fn empty_from_allows_all_sources() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "ingress": [{"ports": [{"port": 443}]}],
                "policyTypes": ["Ingress"]
            }
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        assert_eq!(spec.ingress.len(), 1);
        let r = &spec.ingress[0];
        assert_eq!(r.source, EntityRule::default());
        assert_eq!(r.destination.ports, vec![443]);
    }

    // One rule per peer: two `from` peers → two ingress rules.
    #[test]
    fn one_rule_per_peer() {
        let policy = np(r#"{
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "ingress": [{"from": [
                    {"podSelector": {"matchLabels": {"a": "1"}}},
                    {"podSelector": {"matchLabels": {"b": "2"}}}
                ]}],
                "policyTypes": ["Ingress"]
            }
        }"#);
        let spec = k8s_network_policy_to_calico(&policy);
        assert_eq!(spec.ingress.len(), 2);
    }
}
