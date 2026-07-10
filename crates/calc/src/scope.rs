//! Namespace scoping for policies (closes tracker T059 in the runtime path).
//!
//! A v3 `NetworkPolicy`/`GlobalNetworkPolicy` spec, as stored, is **not**
//! confined to its namespace: its applies-to `selector` matches any
//! identically-labelled endpoint cluster-wide, and a rule's `namespaceSelector`
//! is expressed against *namespace* labels that only appear on endpoints under
//! the `pcns.` prefix. Upstream Felix folds both concerns into a single v1
//! endpoint selector before the calc graph ever sees them
//! (`libcalico-go/lib/backend/syncersv1/updateprocessors/rules.go`
//! `getEndpointSelector` + `networkpolicyprocessor.go`
//! `ConvertNetworkPolicyV3ToV1Value`). This module reproduces that fold so the
//! runtime `felix::policy_agent` adapter can feed the calc graph a **scoped**
//! spec, and cross-namespace over-application can no longer happen.
//!
//! The fold targets [`apis::EntityRule::selector`] only — `calc`'s
//! [`crate::from_resources::map_rule`] reads that field and never
//! `namespace_selector` — so scoping computes the combined selector string and
//! **clears** `namespace_selector`.
//!
//! # Faithfulness notes
//!
//! * **Operand order.** Upstream `getEndpointSelector` combines a rule peer as
//!   `(<nsSelector>) && (<selector>)` — namespace selector first — while the
//!   *policy* applies-to selector is `(<selector>) && <nsSelector>` — policy
//!   selector first (`ConvertNetworkPolicyV3ToV1Value`). We reproduce both
//!   orders exactly (the upstream `rules_test.go`/`networkpolicyprocessor_test.go`
//!   vectors are byte-anchored below). `&&` commutes, so this is cosmetic — but
//!   it keeps us byte-identical to upstream.
//! * **Quoting.** The `pcns.`-prefixed namespace selector is rendered through
//!   [`Selector`]'s canonical `Display` (double-quoted values, e.g.
//!   `pcns.env == "prod"`), exactly as upstream's `parser.Selector.String()`
//!   does; the untouched endpoint selector keeps its original text.
//! * **Not modeled.** `serviceAccountSelector`/`serviceAccounts` and a rule
//!   `notSelector` are absent from [`apis::EntityRule`], so upstream's
//!   `saSelector` combination and the `notSelector != ""` scoping trigger have
//!   no input to act on here. `global()` in a rule `namespaceSelector` is not in
//!   `calc`'s selector grammar; it fails to parse and yields no namespace
//!   selector (documented divergence — `all()` *is* supported and translated).

use apis::{EntityRule, NetworkPolicySpec, Rule};

use crate::selector::Selector;

/// The endpoint label carrying its namespace (`apiv3.LabelNamespace`).
const LABEL_NAMESPACE: &str = "projectcalico.org/namespace";
/// Prefix under which a namespace's labels are projected onto endpoints
/// (`conversion.NamespaceLabelPrefix`).
const NAMESPACE_LABEL_PREFIX: &str = "pcns.";

/// Scope a **namespaced** `NetworkPolicy` spec to `namespace`, returning a copy
/// whose applies-to `selector` is confined to the namespace and whose every
/// rule peer selector is folded per upstream `getEndpointSelector` (with
/// `namespace_selector` cleared). Additive: `nets`/`ports`/`not_nets`,
/// action/protocol/types/order/tier are carried through untouched.
pub fn scope_network_policy(spec: &NetworkPolicySpec, namespace: &str) -> NetworkPolicySpec {
    let mut out = spec.clone();
    out.selector = confine_policy_selector(&spec.selector, namespace);
    out.ingress = spec
        .ingress
        .iter()
        .map(|r| scope_rule(r, Some(namespace)))
        .collect();
    out.egress = spec
        .egress
        .iter()
        .map(|r| scope_rule(r, Some(namespace)))
        .collect();
    out
}

/// Scope a **GlobalNetworkPolicy** (mapped onto a [`NetworkPolicySpec`]).
///
/// A GNP is cluster-scoped, so — unlike a namespaced `NetworkPolicy` — it is
/// **not** own-namespace-confined. Reproducing upstream
/// `ConvertGlobalNetworkPolicyV3ToV1Value`:
/// * the GNP spec-level `namespace_selector` (passed as `namespace_selector`) is
///   `pcns.`-prefixed and appended to the applies-to selector
///   (`(<selector>) && pcns.<nsSel>`), with `all()` translated to
///   `has(projectcalico.org/namespace)`;
/// * each rule peer's `namespaceSelector` is `pcns.`-prefixed (via
///   `getEndpointSelector` with no owning namespace), and `namespace_selector`
///   is cleared. A rule with only a plain `selector` is left unconfined.
pub fn scope_global_network_policy(
    spec: &NetworkPolicySpec,
    namespace_selector: &str,
) -> NetworkPolicySpec {
    let mut out = spec.clone();
    out.selector = scope_gnp_selector(&spec.selector, namespace_selector);
    out.ingress = spec.ingress.iter().map(|r| scope_rule(r, None)).collect();
    out.egress = spec.egress.iter().map(|r| scope_rule(r, None)).collect();
    out
}

/// Confine a policy applies-to selector to its namespace, mirroring
/// `ConvertNetworkPolicyV3ToV1Value`: `(<sel>) && <ns>`, or just `<ns>` when the
/// policy selector is empty.
fn confine_policy_selector(selector: &str, namespace: &str) -> String {
    let ns_sel = format!("{LABEL_NAMESPACE} == '{namespace}'");
    if selector.is_empty() {
        ns_sel
    } else {
        format!("({selector}) && {ns_sel}")
    }
}

/// GNP applies-to selector: append the `pcns.`-prefixed spec-level
/// `namespace_selector` (`prefixAndAppendSelector`), then translate `all()`.
fn scope_gnp_selector(selector: &str, namespace_selector: &str) -> String {
    if namespace_selector.is_empty() {
        return selector.to_string();
    }
    let prefixed = match Selector::parse(namespace_selector) {
        Ok(s) => s.prefix_keys(NAMESPACE_LABEL_PREFIX).to_string(),
        // Upstream logs and drops an unparseable selector; leave applies-to as-is.
        Err(_) => return selector.to_string(),
    };
    let combined = if selector.is_empty() {
        prefixed
    } else {
        format!("({selector}) && {prefixed}")
    };
    combined.replace("all()", "has(projectcalico.org/namespace)")
}

/// Scope both peers of a rule. `ns` is the owning namespace for a namespaced
/// policy, or `None` for a GNP (no own-namespace confinement).
fn scope_rule(r: &Rule, ns: Option<&str>) -> Rule {
    Rule {
        action: r.action,
        protocol: r.protocol.clone(),
        source: scope_entity(&r.source, ns),
        destination: scope_entity(&r.destination, ns),
    }
}

/// Fold one `EntityRule`'s selector + namespaceSelector into a single
/// `selector`, clearing `namespace_selector`. `nets`/`not_nets`/`ports`/
/// `service_accounts` are preserved verbatim.
fn scope_entity(er: &EntityRule, ns: Option<&str>) -> EntityRule {
    let folded = get_endpoint_selector(
        er.namespace_selector.as_deref().unwrap_or(""),
        er.selector.as_deref().unwrap_or(""),
        ns,
    );
    EntityRule {
        selector: if folded.is_empty() {
            None
        } else {
            Some(folded)
        },
        namespace_selector: None,
        nets: er.nets.clone(),
        not_nets: er.not_nets.clone(),
        ports: er.ports.clone(),
        service_accounts: er.service_accounts.clone(),
    }
}

/// Reproduce upstream `getEndpointSelector(namespaceSelector, endpointSelector,
/// "", notSelector="", ns, _)` for the fields `apis::EntityRule` models.
///
/// Three cases (isolation-critical):
/// 1. `namespace_selector` non-empty → it selects *namespaces*; project its keys
///    into `pcns.` (no own-namespace confinement is added).
/// 2. `namespace_selector` empty **and** this is a namespaced policy
///    (`ns == Some(non-empty)`) → confine to the owning namespace
///    (`projectcalico.org/namespace == '<ns>'`).
/// 3. both empty (or a GNP with `ns == None`) → no namespace selector.
///
/// The namespace selector is then combined with the endpoint selector as
/// `(<nsSelector>) && (<selector>)`, but **only** when a namespace selector was
/// produced *and* the rule actually uses a selector or namespaceSelector — so a
/// nets-only / all-sources peer is never namespace-confined (matching upstream,
/// which deliberately does not over-confine).
fn get_endpoint_selector(
    namespace_selector: &str,
    endpoint_selector: &str,
    ns: Option<&str>,
) -> String {
    let ns_selector = if !namespace_selector.is_empty() {
        match Selector::parse(namespace_selector) {
            Ok(s) => s
                .prefix_keys(NAMESPACE_LABEL_PREFIX)
                .to_string()
                .replace("all()", "has(projectcalico.org/namespace)")
                .replace("global()", "!has(projectcalico.org/namespace)"),
            Err(_) => String::new(),
        }
    } else if let Some(ns) = ns.filter(|n| !n.is_empty()) {
        format!("{LABEL_NAMESPACE} == '{ns}'")
    } else {
        String::new()
    };

    // Combine. Upstream also scopes when a `notSelector` is set; `EntityRule`
    // has no such field, so the trigger is (endpoint selector | namespaceSelector).
    if !ns_selector.is_empty() && (!endpoint_selector.is_empty() || !namespace_selector.is_empty())
    {
        if endpoint_selector.is_empty() {
            ns_selector
        } else {
            format!("({ns_selector}) && ({endpoint_selector})")
        }
    } else {
        endpoint_selector.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::from_resources::network_policy_to_eval;
    use apis::{Action, PolicyType};
    use std::collections::BTreeMap;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// A one-ingress-rule policy whose `source` is `source`.
    fn np_with_source(source: EntityRule) -> NetworkPolicySpec {
        NetworkPolicySpec {
            types: vec![PolicyType::Ingress],
            ingress: vec![Rule {
                action: Action::Allow,
                protocol: None,
                source,
                destination: EntityRule::default(),
            }],
            ..Default::default()
        }
    }

    // ---- policy applies-to selector (ConvertNetworkPolicyV3ToV1Value) ----

    #[test]
    fn policy_selector_confined_to_namespace() {
        let spec = NetworkPolicySpec {
            selector: "role == 'db'".into(),
            ..Default::default()
        };
        let scoped = scope_network_policy(&spec, "prod");
        assert_eq!(
            scoped.selector,
            "(role == 'db') && projectcalico.org/namespace == 'prod'"
        );
    }

    #[test]
    fn empty_policy_selector_becomes_bare_namespace_confinement() {
        let scoped = scope_network_policy(&NetworkPolicySpec::default(), "prod");
        assert_eq!(scoped.selector, "projectcalico.org/namespace == 'prod'");
    }

    // ---- rule peer selector (getEndpointSelector) ----
    // Vectors anchored to upstream rules_test.go (nsSelector-first ordering;
    // pcns keys rendered double-quoted by Selector::Display, matching
    // parser.Selector.String()).

    #[test]
    fn rule_namespace_selector_only_is_pcns_prefixed_and_not_own_ns_confined() {
        let spec = np_with_source(EntityRule {
            namespace_selector: Some("env == 'prod'".into()),
            ..Default::default()
        });
        let scoped = scope_network_policy(&spec, "prod");
        assert_eq!(
            scoped.ingress[0].source.selector.as_deref(),
            Some("pcns.env == \"prod\"")
        );
        // namespace_selector is folded away.
        assert!(scoped.ingress[0].source.namespace_selector.is_none());
    }

    #[test]
    fn rule_selector_and_namespace_selector_combine_ns_first() {
        let spec = np_with_source(EntityRule {
            selector: Some("app == 'web'".into()),
            namespace_selector: Some("env == 'prod'".into()),
            ..Default::default()
        });
        let scoped = scope_network_policy(&spec, "prod");
        assert_eq!(
            scoped.ingress[0].source.selector.as_deref(),
            Some("(pcns.env == \"prod\") && (app == 'web')")
        );
    }

    #[test]
    fn rule_selector_only_is_confined_to_own_namespace() {
        let spec = np_with_source(EntityRule {
            selector: Some("app == 'web'".into()),
            ..Default::default()
        });
        let scoped = scope_network_policy(&spec, "prod");
        assert_eq!(
            scoped.ingress[0].source.selector.as_deref(),
            Some("(projectcalico.org/namespace == 'prod') && (app == 'web')")
        );
    }

    #[test]
    fn rule_with_only_nets_is_not_namespace_confined() {
        let spec = np_with_source(EntityRule {
            nets: vec!["10.0.0.0/8".into()],
            ..Default::default()
        });
        let scoped = scope_network_policy(&spec, "prod");
        assert!(scoped.ingress[0].source.selector.is_none());
        assert_eq!(
            scoped.ingress[0].source.nets,
            vec!["10.0.0.0/8".to_string()]
        );
    }

    #[test]
    fn rule_namespace_selector_all_translates_to_has_namespace() {
        let spec = np_with_source(EntityRule {
            namespace_selector: Some("all()".into()),
            ..Default::default()
        });
        let scoped = scope_network_policy(&spec, "prod");
        assert_eq!(
            scoped.ingress[0].source.selector.as_deref(),
            Some("has(projectcalico.org/namespace)")
        );
    }

    // ---- GlobalNetworkPolicy (ConvertGlobalNetworkPolicyV3ToV1Value) ----

    #[test]
    fn gnp_selector_not_confined_but_namespace_selector_is_prefixed() {
        let spec = NetworkPolicySpec {
            selector: "role == 'db'".into(),
            ..Default::default()
        };
        let scoped = scope_global_network_policy(&spec, "env == 'prod'");
        assert_eq!(scoped.selector, "(role == 'db') && pcns.env == \"prod\"");
    }

    #[test]
    fn gnp_empty_namespace_selector_leaves_policy_selector_untouched() {
        let spec = NetworkPolicySpec {
            selector: "role == 'db'".into(),
            ..Default::default()
        };
        let scoped = scope_global_network_policy(&spec, "");
        assert_eq!(scoped.selector, "role == 'db'");
    }

    #[test]
    fn gnp_rule_namespace_selector_prefixed_without_own_namespace_confinement() {
        let spec = np_with_source(EntityRule {
            selector: Some("app == 'web'".into()),
            namespace_selector: Some("env == 'prod'".into()),
            ..Default::default()
        });
        let scoped = scope_global_network_policy(&spec, "");
        assert_eq!(
            scoped.ingress[0].source.selector.as_deref(),
            Some("(pcns.env == \"prod\") && (app == 'web')")
        );
    }

    #[test]
    fn gnp_rule_selector_only_is_not_namespace_confined() {
        let spec = np_with_source(EntityRule {
            selector: Some("app == 'web'".into()),
            ..Default::default()
        });
        let scoped = scope_global_network_policy(&spec, "");
        // No owning namespace ⇒ no own-namespace confinement.
        assert_eq!(
            scoped.ingress[0].source.selector.as_deref(),
            Some("app == 'web'")
        );
    }

    // ---- end-to-end cross-namespace isolation (the bug T059 closes) ----

    #[test]
    fn cross_namespace_isolation_scoped_policy_does_not_select_foreign_endpoint() {
        let spec = NetworkPolicySpec {
            selector: "role == 'db'".into(),
            types: vec![PolicyType::Ingress],
            ..Default::default()
        };
        let scoped = scope_network_policy(&spec, "ns-a");
        let ev = network_policy_to_eval(&scoped).unwrap();

        // An identically-labelled endpoint IN the policy's namespace is selected.
        let ep_a = labels(&[("role", "db"), (LABEL_NAMESPACE, "ns-a")]);
        assert!(
            ev.selector.matches(&ep_a),
            "same-namespace endpoint selected"
        );

        // The same labels in ANOTHER namespace are NOT selected — the
        // cross-namespace over-application bug is closed.
        let ep_b = labels(&[("role", "db"), (LABEL_NAMESPACE, "ns-b")]);
        assert!(
            !ev.selector.matches(&ep_b),
            "foreign-namespace endpoint must not be selected"
        );
    }
}
