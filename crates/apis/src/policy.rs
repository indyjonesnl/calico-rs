//! Policy resource specs: NetworkPolicy, GlobalNetworkPolicy, Tier, Profile, and
//! the shared Rule / EntityRule model.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Rule action. Wire values match upstream: `Allow` / `Deny` / `Log` / `Pass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Action {
    Allow,
    Deny,
    Log,
    Pass,
}

/// Which directions a policy governs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PolicyType {
    Ingress,
    Egress,
}

/// Rule protocol — a name (`TCP`/`UDP`/`ICMP`/…) or a numeric protocol. This is
/// a Kubernetes int-or-string field; the derived `JsonSchema` would produce a
/// non-structural `anyOf`, so we emit `x-kubernetes-int-or-string` (the accepted
/// structural-schema idiom) by hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Protocol {
    Named(String),
    Number(u8),
}

impl JsonSchema for Protocol {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Protocol".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "x-kubernetes-int-or-string": true })
    }
}

/// One side (source or destination) of a rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EntityRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_nets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_accounts: Vec<String>,
}

/// A single policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(default, skip_serializing_if = "is_default_entity")]
    pub source: EntityRule,
    #[serde(default, skip_serializing_if = "is_default_entity")]
    pub destination: EntityRule,
}

fn is_default_entity(e: &EntityRule) -> bool {
    e == &EntityRule::default()
}

/// Spec for the namespaced `NetworkPolicy` resource.
#[derive(CustomResource, Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "NetworkPolicy",
    plural = "networkpolicies",
    singular = "networkpolicy",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicySpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<f64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub selector: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<PolicyType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<Rule>,
}

/// Spec for the cluster-scoped `GlobalNetworkPolicy` resource.
#[derive(CustomResource, Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "GlobalNetworkPolicy",
    plural = "globalnetworkpolicies",
    singular = "globalnetworkpolicy"
)]
#[serde(rename_all = "camelCase")]
pub struct GlobalNetworkPolicySpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<f64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub selector: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace_selector: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<PolicyType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<Rule>,
    #[serde(default)]
    pub apply_on_forward: bool,
    #[serde(default)]
    pub do_not_track: bool,
    #[serde(rename = "preDNAT", default)]
    pub pre_dnat: bool,
}

/// Spec for the `Tier` resource — an ordered grouping of policies.
#[derive(CustomResource, Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "Tier",
    plural = "tiers",
    singular = "tier"
)]
#[serde(rename_all = "camelCase")]
pub struct TierSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<f64>,
}

/// Spec for the `Profile` resource — default rules + labels applied to endpoints.
#[derive(
    CustomResource, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "Profile",
    plural = "profiles",
    singular = "profile"
)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<Rule>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub labels_to_apply: std::collections::BTreeMap<String, String>,
}

/// The action a staged policy would take if promoted to its enforced
/// counterpart. Wire values match upstream: `Set` / `Delete` / `Learn` /
/// `Ignore`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum StagedAction {
    #[default]
    Set,
    Delete,
    Learn,
    Ignore,
}

/// Spec for the namespaced `StagedNetworkPolicy` resource — a dry-run
/// counterpart of [`NetworkPolicy`] used to preview policy changes without
/// enforcing them. Mirrors [`NetworkPolicySpec`] plus `stagedAction`.
#[derive(CustomResource, Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "StagedNetworkPolicy",
    plural = "stagednetworkpolicies",
    singular = "stagednetworkpolicy",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct StagedNetworkPolicySpec {
    #[serde(default)]
    pub staged_action: StagedAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<f64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub selector: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<PolicyType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<Rule>,
}

/// Spec for the cluster-scoped `StagedGlobalNetworkPolicy` resource. Mirrors
/// [`GlobalNetworkPolicySpec`] plus `stagedAction`.
#[derive(CustomResource, Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "StagedGlobalNetworkPolicy",
    plural = "stagedglobalnetworkpolicies",
    singular = "stagedglobalnetworkpolicy"
)]
#[serde(rename_all = "camelCase")]
pub struct StagedGlobalNetworkPolicySpec {
    #[serde(default)]
    pub staged_action: StagedAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<f64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub selector: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace_selector: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<PolicyType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<Rule>,
    #[serde(default)]
    pub apply_on_forward: bool,
    #[serde(default)]
    pub do_not_track: bool,
    #[serde(rename = "preDNAT", default)]
    pub pre_dnat: bool,
}

/// Spec for the namespaced `StagedKubernetesNetworkPolicy` resource — a
/// staged counterpart of a native Kubernetes `NetworkPolicy`. The
/// pod-selector/ingress/egress/policy-types fields reuse the upstream
/// Kubernetes wire types (`k8s_openapi::api::networking::v1`) directly rather
/// than reproducing them; this also gets `NetworkPolicyPort::port`'s
/// hand-written int-or-string `JsonSchema` for free.
#[derive(CustomResource, Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "crd.projectcalico.org",
    version = "v1",
    kind = "StagedKubernetesNetworkPolicy",
    plural = "stagedkubernetesnetworkpolicies",
    singular = "stagedkubernetesnetworkpolicy",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct StagedKubernetesNetworkPolicySpec {
    #[serde(default)]
    pub staged_action: StagedAction,
    #[serde(default)]
    pub pod_selector: k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<k8s_openapi::api::networking::v1::NetworkPolicyIngressRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<k8s_openapi::api::networking::v1::NetworkPolicyEgressRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_types: Vec<PolicyType>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_and_protocol_wire_values() {
        let r = Rule {
            action: Action::Allow,
            protocol: Some(Protocol::Named("TCP".into())),
            source: EntityRule {
                selector: Some("role == 'frontend'".into()),
                ..Default::default()
            },
            destination: EntityRule {
                ports: vec![443],
                ..Default::default()
            },
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"action\":\"Allow\""));
        assert!(json.contains("\"protocol\":\"TCP\""));
        assert!(json.contains("\"ports\":[443]"));
        let round: Rule = serde_json::from_str(&json).unwrap();
        assert_eq!(round, r);
    }

    #[test]
    fn numeric_protocol_roundtrips() {
        let r: Rule = serde_json::from_str(r#"{"action":"Deny","protocol":17}"#).unwrap();
        assert_eq!(r.action, Action::Deny);
        assert_eq!(r.protocol, Some(Protocol::Number(17)));
    }

    #[test]
    fn default_entities_are_omitted() {
        let r = Rule {
            action: Action::Pass,
            protocol: None,
            source: EntityRule::default(),
            destination: EntityRule::default(),
        };
        let json = serde_json::to_string(&r).unwrap();
        // Empty source/destination should not clutter the wire form.
        assert_eq!(json, r#"{"action":"Pass"}"#);
    }

    #[test]
    fn global_policy_predanat_casing() {
        let gnp = GlobalNetworkPolicySpec {
            selector: "all()".into(),
            pre_dnat: true,
            apply_on_forward: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&gnp).unwrap();
        assert!(json.contains("\"preDNAT\":true"));
        assert!(json.contains("\"applyOnForward\":true"));
        let round: GlobalNetworkPolicySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(round, gnp);
    }

    #[test]
    fn network_policy_deserializes_typical_manifest() {
        let doc = r#"{
            "selector": "app == 'db'",
            "types": ["Ingress"],
            "ingress": [
                {"action":"Allow","protocol":"TCP",
                 "source":{"selector":"app == 'web'"},
                 "destination":{"ports":[5432]}}
            ]
        }"#;
        let spec: NetworkPolicySpec = serde_json::from_str(doc).unwrap();
        assert_eq!(spec.types, vec![PolicyType::Ingress]);
        assert_eq!(spec.ingress.len(), 1);
        assert_eq!(spec.ingress[0].action, Action::Allow);
    }

    #[test]
    fn staged_action_defaults_to_set_and_roundtrips() {
        let spec: StagedNetworkPolicySpec = serde_json::from_str("{}").unwrap();
        assert_eq!(spec.staged_action, StagedAction::Set);
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"stagedAction\":\"Set\""));

        let spec = StagedNetworkPolicySpec {
            staged_action: StagedAction::Delete,
            selector: "app == 'db'".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"stagedAction\":\"Delete\""));
        let round: StagedNetworkPolicySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(round, spec);
    }

    #[test]
    fn staged_network_policy_mirrors_network_policy_fields() {
        let doc = r#"{
            "stagedAction": "Learn",
            "tier": "security",
            "order": 100.0,
            "selector": "app == 'db'",
            "types": ["Ingress"],
            "ingress": [
                {"action":"Allow","protocol":"TCP",
                 "destination":{"ports":[5432]}}
            ]
        }"#;
        let spec: StagedNetworkPolicySpec = serde_json::from_str(doc).unwrap();
        assert_eq!(spec.staged_action, StagedAction::Learn);
        assert_eq!(spec.tier.as_deref(), Some("security"));
        assert_eq!(spec.ingress.len(), 1);
    }

    #[test]
    fn staged_global_network_policy_predanat_and_staged_action() {
        let spec = StagedGlobalNetworkPolicySpec {
            staged_action: StagedAction::Ignore,
            selector: "all()".into(),
            pre_dnat: true,
            apply_on_forward: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"stagedAction\":\"Ignore\""));
        assert!(json.contains("\"preDNAT\":true"));
        assert!(json.contains("\"applyOnForward\":true"));
        let round: StagedGlobalNetworkPolicySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(round, spec);
    }

    #[test]
    fn staged_kubernetes_network_policy_roundtrips_and_reuses_k8s_types() {
        let doc = r#"{
            "stagedAction": "Delete",
            "podSelector": {"matchLabels": {"app": "web"}},
            "ingress": [{
                "ports": [{"protocol": "TCP", "port": 80}],
                "from": [{"podSelector": {}}]
            }],
            "policyTypes": ["Ingress"]
        }"#;
        let spec: StagedKubernetesNetworkPolicySpec = serde_json::from_str(doc).unwrap();
        assert_eq!(spec.staged_action, StagedAction::Delete);
        assert_eq!(spec.policy_types, vec![PolicyType::Ingress]);
        assert_eq!(spec.ingress.len(), 1);
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"podSelector\""));
        assert!(json.contains("\"stagedAction\":\"Delete\""));
        let round: StagedKubernetesNetworkPolicySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(round, spec);
    }

    #[test]
    fn staged_kubernetes_network_policy_port_is_int_or_string() {
        // The reused k8s NetworkPolicyPort.port field must accept both numeric
        // and named ports (Kubernetes int-or-string), matching upstream.
        let named = r#"{"podSelector":{},"ingress":[{"ports":[{"port":"http"}]}]}"#;
        let spec: StagedKubernetesNetworkPolicySpec = serde_json::from_str(named).unwrap();
        assert_eq!(spec.ingress.len(), 1);

        let numeric = r#"{"podSelector":{},"ingress":[{"ports":[{"port":80}]}]}"#;
        let spec: StagedKubernetesNetworkPolicySpec = serde_json::from_str(numeric).unwrap();
        assert_eq!(spec.ingress.len(), 1);
    }
}
