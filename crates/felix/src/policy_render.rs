//! Render Calico NetworkPolicy specs to the nftables model — the bridge from the
//! resource model (`apis`) to programmed dataplane rules (`nft`).
//!
//! Each policy becomes a chain (`cali-pi-<name>` for ingress) of rules ending in
//! a default drop, plus a base `cali-input` chain that jumps to each policy
//! chain. Selector-based peers require named nft sets (resolved from the calc
//! IP-set computation) and are skipped here — CIDR (`nets`), ports, and protocol
//! render directly. Actions map: Allow→accept, Deny→drop, Pass→return, Log→(skip).

#![allow(dead_code)] // wired into the felix reconcile loop in a later task

use std::collections::BTreeMap;

use apis::{Action, NetworkPolicySpec, Rule};
use calc::Selector;

use crate::nft::{BaseHook, ChainType, NftChain, NftMatch, NftRule, NftSet, NftTable, Verdict};

/// A workload endpoint's routing-relevant facts for IP-set resolution.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub labels: BTreeMap<String, String>,
    /// The endpoint's address (bare IP).
    pub ip: String,
}

fn map_verdict(a: Action) -> Option<Verdict> {
    match a {
        Action::Allow => Some(Verdict::Accept),
        Action::Deny => Some(Verdict::Drop),
        Action::Pass => Some(Verdict::Return),
        Action::Log => None, // no terminal verdict; skipped in this subset
    }
}

/// Render one ingress rule into 0+ nft rules (expanding source nets × dest ports).
/// A rule whose peer is selector-based (no `nets`) is skipped — it needs an
/// IP-set match this renderer does not yet emit.
fn render_ingress_rule(rule: &Rule) -> Vec<NftRule> {
    let Some(verdict) = map_verdict(rule.action) else {
        return Vec::new();
    };
    // Skip rules that rely on a selector but have no concrete nets.
    if rule.source.selector.is_some() && rule.source.nets.is_empty() {
        return Vec::new();
    }
    let proto = rule.protocol.as_ref().and_then(|p| match p {
        apis::Protocol::Named(s) => Some(s.to_lowercase()),
        apis::Protocol::Number(_) => None,
    });

    let nets: Vec<Option<&String>> = if rule.source.nets.is_empty() {
        vec![None]
    } else {
        rule.source.nets.iter().map(Some).collect()
    };
    let ports: Vec<Option<u16>> = if rule.destination.ports.is_empty() {
        vec![None]
    } else {
        rule.destination.ports.iter().copied().map(Some).collect()
    };

    let mut out = Vec::new();
    for net in &nets {
        for port in &ports {
            let mut matches = Vec::new();
            if let Some(p) = &proto {
                matches.push(NftMatch::L4Proto(p.clone()));
            }
            if let Some(n) = net {
                matches.push(NftMatch::SrcAddr((*n).clone()));
            }
            if let Some(pt) = port {
                matches.push(NftMatch::DestPort(*pt));
            }
            out.push(NftRule {
                matches,
                verdict: verdict.clone(),
                comment: None,
            });
        }
    }
    out
}

/// Render a set of named ingress policies into an nft table: a base `cali-input`
/// chain jumping to each policy's chain, and one chain per policy ending in a
/// default drop (Calico's default-deny for selected endpoints).
pub fn render_ingress_policies(
    family: &str,
    table: &str,
    policies: &[(String, NetworkPolicySpec)],
) -> NftTable {
    let mut chains = Vec::new();

    // Base chain: jump to each policy chain in order.
    let base_rules: Vec<NftRule> = policies
        .iter()
        .map(|(name, _)| NftRule::new(Verdict::Jump(format!("cali-pi-{name}"))))
        .collect();
    chains.push(NftChain::base(
        "cali-input",
        BaseHook {
            chain_type: ChainType::Filter,
            hook: "input".into(),
            priority: 0,
            policy_accept: true,
        },
        base_rules,
    ));

    // Per-policy chains.
    for (name, spec) in policies {
        let mut rules: Vec<NftRule> = spec.ingress.iter().flat_map(render_ingress_rule).collect();
        // Default-deny for endpoints this policy selects.
        rules.push(NftRule::new(Verdict::Drop).comment("end-of-policy default deny"));
        chains.push(NftChain::regular(format!("cali-pi-{name}"), rules));
    }

    NftTable::new(family, table, chains)
}

/// Resolves selectors to named nft sets, deduplicating by selector string.
struct SetResolver<'a> {
    endpoints: &'a [Endpoint],
    by_selector: BTreeMap<String, String>, // selector string -> set name
    sets: Vec<NftSet>,
}

impl<'a> SetResolver<'a> {
    fn new(endpoints: &'a [Endpoint]) -> Self {
        Self {
            endpoints,
            by_selector: BTreeMap::new(),
            sets: Vec::new(),
        }
    }

    /// Get-or-create the set for `selector` (members = endpoints matching it).
    /// Returns `None` if the selector fails to parse.
    fn resolve(&mut self, selector: &str) -> Option<String> {
        if let Some(name) = self.by_selector.get(selector) {
            return Some(name.clone());
        }
        let sel = Selector::parse(selector).ok()?;
        let mut members: Vec<String> = self
            .endpoints
            .iter()
            .filter(|e| sel.matches(&e.labels))
            .map(|e| e.ip.clone())
            .collect();
        members.sort();
        members.dedup();
        let name = format!("cali-s-{}", self.sets.len());
        self.sets.push(NftSet {
            name: name.clone(),
            elements: members,
        });
        self.by_selector.insert(selector.to_string(), name.clone());
        Some(name)
    }
}

/// Render an ingress rule, resolving a selector-based source into a named set
/// (`ip saddr @set`). Falls back to CIDR/port rendering; a rule that is neither
/// selector- nor net-based (with a parse failure) yields nothing.
fn render_ingress_rule_resolved(rule: &Rule, res: &mut SetResolver) -> Vec<NftRule> {
    // Selector-based source: resolve to a set.
    if let Some(sel) = &rule.source.selector {
        if !sel.trim().is_empty() && rule.source.nets.is_empty() {
            let Some(verdict) = map_verdict(rule.action) else {
                return Vec::new();
            };
            let Some(set_name) = res.resolve(sel) else {
                return Vec::new();
            };
            let proto = proto_of(rule);
            let ports = port_opts(rule);
            return ports
                .into_iter()
                .map(|port| {
                    let mut matches = Vec::new();
                    if let Some(p) = &proto {
                        matches.push(NftMatch::L4Proto(p.clone()));
                    }
                    matches.push(NftMatch::SrcSet(set_name.clone()));
                    if let Some(pt) = port {
                        matches.push(NftMatch::DestPort(pt));
                    }
                    NftRule {
                        matches,
                        verdict: verdict.clone(),
                        comment: None,
                    }
                })
                .collect();
        }
    }
    // Otherwise the CIDR/port renderer.
    render_ingress_rule(rule)
}

fn proto_of(rule: &Rule) -> Option<String> {
    rule.protocol.as_ref().and_then(|p| match p {
        apis::Protocol::Named(s) => Some(s.to_lowercase()),
        apis::Protocol::Number(_) => None,
    })
}

fn port_opts(rule: &Rule) -> Vec<Option<u16>> {
    if rule.destination.ports.is_empty() {
        vec![None]
    } else {
        rule.destination.ports.iter().copied().map(Some).collect()
    }
}

/// Like [`render_ingress_policies`] but resolves selector-based peers to named
/// nft sets using the given endpoints (their labels → member IPs).
pub fn render_ingress_policies_with_endpoints(
    family: &str,
    table: &str,
    policies: &[(String, NetworkPolicySpec)],
    endpoints: &[Endpoint],
) -> NftTable {
    let mut res = SetResolver::new(endpoints);
    let mut chains = Vec::new();

    let base_rules: Vec<NftRule> = policies
        .iter()
        .map(|(name, _)| NftRule::new(Verdict::Jump(format!("cali-pi-{name}"))))
        .collect();
    chains.push(NftChain::base(
        "cali-input",
        BaseHook {
            chain_type: ChainType::Filter,
            hook: "input".into(),
            priority: 0,
            policy_accept: true,
        },
        base_rules,
    ));

    for (name, spec) in policies {
        let mut rules: Vec<NftRule> = spec
            .ingress
            .iter()
            .flat_map(|r| render_ingress_rule_resolved(r, &mut res))
            .collect();
        rules.push(NftRule::new(Verdict::Drop).comment("end-of-policy default deny"));
        chains.push(NftChain::regular(format!("cali-pi-{name}"), rules));
    }

    NftTable::new(family, table, chains).with_sets(res.sets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn np(json: &str) -> NetworkPolicySpec {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn renders_cidr_port_rule() {
        let spec = np(r#"{
            "selector": "app == 'db'",
            "types": ["Ingress"],
            "ingress": [{
                "action": "Allow",
                "protocol": "TCP",
                "source": { "nets": ["10.0.0.0/24"] },
                "destination": { "ports": [5432] }
            }]
        }"#);
        let table = render_ingress_policies("inet", "calico", &[("allow-db".into(), spec)]);
        let doc = table.render();
        assert!(doc.contains("chain cali-pi-allow-db"));
        assert!(doc.contains("chain cali-input"));
        assert!(doc.contains("jump cali-pi-allow-db"));
        assert!(doc.contains("meta l4proto tcp ip saddr 10.0.0.0/24 th dport 5432 accept"));
        assert!(doc.contains("drop comment \"end-of-policy default deny\""));
    }

    #[test]
    fn expands_multiple_nets_and_ports() {
        let spec = np(r#"{
            "selector": "all()",
            "types": ["Ingress"],
            "ingress": [{
                "action": "Allow",
                "source": { "nets": ["10.0.0.0/24", "10.1.0.0/24"] },
                "destination": { "ports": [80, 443] }
            }]
        }"#);
        let rules = render_ingress_rule(&spec.ingress[0]);
        // 2 nets × 2 ports = 4 rules.
        assert_eq!(rules.len(), 4);
    }

    #[test]
    fn skips_selector_only_peer() {
        let spec = np(r#"{
            "selector": "all()",
            "types": ["Ingress"],
            "ingress": [{ "action": "Allow", "source": { "selector": "app == 'web'" } }]
        }"#);
        // Selector-only source has no renderable nft match here → skipped.
        assert!(render_ingress_rule(&spec.ingress[0]).is_empty());
    }

    #[test]
    fn selector_peer_resolves_to_named_set() {
        let spec = np(r#"{
            "selector": "app == 'db'",
            "types": ["Ingress"],
            "ingress": [{
                "action": "Allow",
                "protocol": "TCP",
                "source": { "selector": "app == 'web'" },
                "destination": { "ports": [5432] }
            }]
        }"#);
        let ep = |app: &str, ip: &str| Endpoint {
            labels: [("app".to_string(), app.to_string())].into_iter().collect(),
            ip: ip.to_string(),
        };
        let endpoints = vec![
            ep("web", "10.0.0.1"),
            ep("web", "10.0.0.2"),
            ep("db", "10.0.0.9"),
        ];
        let table = render_ingress_policies_with_endpoints(
            "inet",
            "calico",
            &[("allow-db".into(), spec)],
            &endpoints,
        );
        let doc = table.render();
        // A set with the two web IPs (not the db one) + a rule referencing it.
        assert!(doc.contains("set cali-s-0"));
        assert!(doc.contains("10.0.0.1"));
        assert!(doc.contains("10.0.0.2"));
        assert!(!doc.contains("10.0.0.9"));
        assert!(doc.contains("ip saddr @cali-s-0"));
        assert!(doc.contains("tcp") || doc.contains("l4proto tcp"));
    }

    #[test]
    fn deny_and_pass_map_to_drop_and_return() {
        let deny = np(
            r#"{"selector":"all()","ingress":[{"action":"Deny","source":{"nets":["1.2.3.0/24"]}}]}"#,
        );
        assert_eq!(
            render_ingress_rule(&deny.ingress[0])[0].verdict,
            Verdict::Drop
        );
        let pass = np(
            r#"{"selector":"all()","ingress":[{"action":"Pass","source":{"nets":["1.2.3.0/24"]}}]}"#,
        );
        assert_eq!(
            render_ingress_rule(&pass.ingress[0])[0].verdict,
            Verdict::Return
        );
    }
}
