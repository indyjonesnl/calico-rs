//! v3 → v1 backend-model update processors.
//!
//! Upstream Calico's watcher-syncer converts each user-facing **v3** resource
//! into a lean, felix-facing **v1 backend model** before Felix consumes it
//! (`libcalico-go/lib/backend/syncersv1/updateprocessors`). Each processor maps
//! one v3 spec (plus its key) to one-or-more v1 KVPairs. The v1 model here is
//! deliberately distinct from:
//! * the user-facing [`apis`] v3 specs (the *input*), and
//! * calc's `EvalPolicy` (the policy *decision* engine).
//!
//! It is the "what Felix ingests" model: policies with namespace-scoped
//! selectors, IP pools with felix-facing encap fields, workload endpoints keyed
//! by interface, and *flattened* config key/value pairs. Only fields justified
//! by a reproduced upstream invariant or a concrete felix need are modeled —
//! see each struct's doc comment.
//!
//! These are **pure functions**: input is a v3 spec (+ key context), output is
//! v1 KVPair(s). No I/O.

use std::collections::BTreeMap;

use apis::{
    Action, EntityRule, FelixConfigurationSpec, IpPoolSpec, NetworkPolicySpec, PolicyType,
    Protocol, Rule, WorkloadEndpointSpec,
};

use crate::model::{Key, ResourceKind};

/// The label key Felix uses to scope endpoints to a namespace. Matches upstream
/// `apiv3.LabelNamespace` (`projectcalico.org/namespace`).
pub const LABEL_NAMESPACE: &str = "projectcalico.org/namespace";
/// The label key carrying a workload's service account. Matches upstream
/// `apiv3.LabelServiceAccount`.
pub const LABEL_SERVICE_ACCOUNT: &str = "projectcalico.org/serviceaccount";

/// Error from converting a v3 resource to the v1 backend model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessError {
    /// The `spec` JSON did not deserialize into the expected v3 spec type.
    Deserialize(String),
    /// A key field required to build the v1 key was empty (e.g. a namespaced
    /// policy with no namespace). Mirrors upstream's "Missing Name or Namespace"
    /// error.
    MissingKeyField(&'static str),
    /// The resource kind has no v1 update processor (only the four felix-facing
    /// kinds are handled here).
    UnsupportedKind(ResourceKind),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessError::Deserialize(e) => write!(f, "failed to deserialize v3 spec: {e}"),
            ProcessError::MissingKeyField(field) => {
                write!(f, "missing key field for v1 conversion: {field}")
            }
            ProcessError::UnsupportedKind(k) => {
                write!(f, "no v1 update processor for kind {}", k.kind_name())
            }
        }
    }
}
impl std::error::Error for ProcessError {}

// ===========================================================================
// v1 keys / values
// ===========================================================================

/// Which policy kind a [`PolicyV1Key`] multiplexes. Upstream keys several policy
/// kinds into one `PolicyKey`; only `NetworkPolicy` is in scope here, but the
/// discriminator is retained so keys stay unique if more kinds are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyKind {
    NetworkPolicy,
}

/// v1 key for a policy (`model.PolicyKey`): tier + name + optional namespace +
/// kind. Namespace is `Some` for namespaced policies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyV1Key {
    pub tier: String,
    pub name: String,
    pub namespace: Option<String>,
    pub kind: PolicyKind,
}

/// Felix-facing v1 policy (`model.Policy`). The one non-trivial field is
/// [`selector`](Self::selector): it is the v3 selector *augmented* with the
/// namespace scoping Felix needs to attach the policy to the right endpoints.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyV1 {
    /// Owning namespace (namespaced policies only).
    pub namespace: Option<String>,
    /// Tier — defaulted to `"default"` when the v3 tier is empty.
    pub tier: String,
    /// Policy order within its tier.
    pub order: Option<f64>,
    /// Namespace-augmented endpoint selector (see [`augment_policy_selector`]).
    pub selector: String,
    /// Directions governed, lower-cased (`"ingress"`/`"egress"`).
    pub types: Vec<String>,
    /// Ingress rules with namespace-scoped peer selectors.
    pub inbound_rules: Vec<RuleV1>,
    /// Egress rules with namespace-scoped peer selectors.
    pub outbound_rules: Vec<RuleV1>,
}

/// Felix-facing v1 rule (`model.Rule`, lean subset). Distinct from [`apis::Rule`]
/// in three reproduced ways: the action is remapped (`Pass` → `"next-tier"`,
/// otherwise lower-cased), the protocol is converted to its v1 (lower-cased)
/// form, and the peer selectors are *computed* with namespace scoping. The
/// remaining match fields (nets/ports) are carried through for Felix's IP-set
/// and port matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleV1 {
    pub action: String,
    pub protocol: Option<String>,
    pub src_selector: String,
    pub dst_selector: String,
    pub src_nets: Vec<String>,
    pub dst_nets: Vec<String>,
    pub not_src_nets: Vec<String>,
    pub not_dst_nets: Vec<String>,
    pub src_ports: Vec<u16>,
    pub dst_ports: Vec<u16>,
}

/// v1 key for an IP pool (`model.IPPoolKey`), keyed by CIDR.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpPoolV1Key {
    pub cidr: String,
}

/// Felix/BGP-facing v1 IP pool (`model.IPPool`). Field set mirrors upstream
/// `IPPoolV3ToV1` exactly — note upstream's v1 `IPPool` has **no** block size, so
/// `blockSize` is intentionally not modeled here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPoolV1 {
    pub cidr: String,
    pub ipip_mode: apis::EncapMode,
    /// `"tunl0"` when IPIP is active (`Always`/`CrossSubnet`), else empty.
    pub ipip_interface: String,
    pub vxlan_mode: apis::EncapMode,
    /// = v3 `natOutgoing`.
    pub masquerade: bool,
    /// = `!disabled` (whether the pool is usable for IPAM).
    pub ipam: bool,
    pub disabled: bool,
    pub disable_bgp_export: bool,
    pub assignment_mode: apis::AssignmentMode,
    pub allowed_uses: Vec<apis::AllowedUse>,
}

/// v1 key for a workload endpoint (`model.WorkloadEndpointKey`). We key by the
/// host plus the namespaced resource name rather than reproducing the full
/// orchestrator/workload/endpoint 4-tuple parse (documented simplification).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkloadEndpointV1Key {
    pub hostname: String,
    pub namespace: Option<String>,
    pub name: String,
}

/// A named port exposed by a workload, v1 form (`model.EndpointPort`), protocol
/// lower-cased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPortV1 {
    pub name: String,
    pub protocol: String,
    pub port: u16,
}

/// Felix-facing v1 workload endpoint (`model.WorkloadEndpoint`, lean subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadEndpointV1 {
    /// Always `"active"` (upstream sets this literal).
    pub state: &'static str,
    /// = v3 `interfaceName` (the host-side veth Felix programs).
    pub name: String,
    pub mac: Option<String>,
    pub profile_ids: Vec<String>,
    pub ipv4_nets: Vec<String>,
    pub ipv6_nets: Vec<String>,
    /// Endpoint labels. Only the service-account label is injected here; pod
    /// metadata labels are outside the current input surface — the lean
    /// `apis::WorkloadEndpointSpec` this processor consumes carries no labels
    /// of its own (they live on the pod's object metadata). There is no
    /// `pcns.`/`pcsa.` stripping happening because there is nothing to strip
    /// yet; if/when pod metadata labels are wired in (felix P3 consumer),
    /// upstream's `pcns.`/`pcsa.` handling will need to be replicated here.
    pub labels: BTreeMap<String, String>,
    pub ports: Vec<EndpointPortV1>,
    pub allow_spoofed_source_prefixes: Vec<String>,
}

/// One flattened Felix config entry. A single `FelixConfiguration` resource
/// decomposes into *many* of these, because Felix consumes flat config keys, not
/// a nested struct (`configUpdateProcessor`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigV1 {
    /// Host this entry applies to (`None` = global `default` resource; `Some` =
    /// per-host `node.<host>` resource).
    pub host: Option<String>,
    /// v1 config key (upstream `confignamev1` name, defaulting to the field name).
    pub name: String,
    /// Stringified value.
    pub value: String,
}

/// A v1 key emitted by [`process`].
#[derive(Debug, Clone, PartialEq)]
pub enum V1Key {
    Policy(PolicyV1Key),
    IpPool(IpPoolV1Key),
    WorkloadEndpoint(WorkloadEndpointV1Key),
    /// A flattened config key (host + name).
    Config { host: Option<String>, name: String },
}

/// A v1 value emitted by [`process`].
#[derive(Debug, Clone, PartialEq)]
pub enum V1Value {
    Policy(PolicyV1),
    IpPool(IpPoolV1),
    WorkloadEndpoint(WorkloadEndpointV1),
    /// A flattened config value.
    Config(String),
}

/// A v1 key/value pair — the unit a processor emits.
#[derive(Debug, Clone, PartialEq)]
pub struct V1KVPair {
    pub key: V1Key,
    pub value: V1Value,
}

// ===========================================================================
// selector helpers
// ===========================================================================

/// Return `tier` unless empty, in which case `"default"` (`tierOrDefault`).
fn tier_or_default(tier: Option<&str>) -> String {
    match tier {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => "default".to_string(),
    }
}

/// Augment a namespaced *policy* selector with namespace scoping, mirroring
/// upstream `ConvertNetworkPolicyV3ToV1Value`: append
/// `projectcalico.org/namespace == '<ns>'`, combining as `(<sel>) && <nsSel>`
/// (or just the namespace selector if the policy selector is empty).
pub fn augment_policy_selector(selector: &str, namespace: &str) -> String {
    let ns_sel = format!("{LABEL_NAMESPACE} == '{namespace}'");
    if selector.is_empty() {
        ns_sel
    } else {
        format!("({selector}) && {ns_sel}")
    }
}

/// Compute the namespace-scoped v1 selector for one side of a rule, reproducing
/// the core of upstream `getEndpointSelector`:
/// * if a `namespace_selector` is set, use it (translating `all()` /`global()`);
/// * else, for a namespaced policy, scope to the policy's own namespace;
/// * then, when scoping applies and a selector/namespace-selector is present,
///   combine as `(<nsSel>) && (<sel>)`, or just `<nsSel>`.
///
/// Documented simplifications vs upstream (both need the upstream selector
/// parser, which we have no dependency for): the `namespace_selector` label keys
/// are **not** `pcns.`-prefixed, and the `service_accounts` names are **not**
/// converted into a `pcsa.`-prefixed selector or treated as a scoping trigger.
fn rule_endpoint_selector(er: &EntityRule, ns: Option<&str>) -> String {
    let namespace_selector = er.namespace_selector.as_deref().unwrap_or("");
    let selector = er.selector.as_deref().unwrap_or("");

    let ns_selector = if !namespace_selector.is_empty() {
        namespace_selector
            .replace("all()", "has(projectcalico.org/namespace)")
            .replace("global()", "!has(projectcalico.org/namespace)")
    } else if let Some(ns) = ns.filter(|n| !n.is_empty()) {
        format!("{LABEL_NAMESPACE} == '{ns}'")
    } else {
        String::new()
    };

    if !ns_selector.is_empty() && (!selector.is_empty() || !namespace_selector.is_empty()) {
        if selector.is_empty() {
            ns_selector
        } else {
            format!("({ns_selector}) && ({selector})")
        }
    } else {
        selector.to_string()
    }
}

/// Rule action → v1 string: `Pass` → `"next-tier"`, else lower-cased.
fn rule_action(action: Action) -> String {
    match action {
        Action::Pass => "next-tier".to_string(),
        Action::Allow => "allow".to_string(),
        Action::Deny => "deny".to_string(),
        Action::Log => "log".to_string(),
    }
}

/// v3 protocol → v1 protocol string (`ToV1`): named protocols are lower-cased,
/// numeric protocols stringified.
fn protocol_to_v1(p: &Protocol) -> String {
    match p {
        Protocol::Named(s) => s.to_lowercase(),
        Protocol::Number(n) => n.to_string(),
    }
}

fn rule_to_v1(r: &Rule, ns: Option<&str>) -> RuleV1 {
    RuleV1 {
        action: rule_action(r.action),
        protocol: r.protocol.as_ref().map(protocol_to_v1),
        src_selector: rule_endpoint_selector(&r.source, ns),
        dst_selector: rule_endpoint_selector(&r.destination, ns),
        src_nets: r.source.nets.clone(),
        dst_nets: r.destination.nets.clone(),
        not_src_nets: r.source.not_nets.clone(),
        not_dst_nets: r.destination.not_nets.clone(),
        src_ports: r.source.ports.clone(),
        dst_ports: r.destination.ports.clone(),
    }
}

fn policy_type_to_v1(t: PolicyType) -> String {
    match t {
        PolicyType::Ingress => "ingress".to_string(),
        PolicyType::Egress => "egress".to_string(),
    }
}

// ===========================================================================
// processors
// ===========================================================================

/// Convert a v3 `NetworkPolicy` (key + spec) to its v1 KVPair. Reproduces
/// `npKeyConverter` + `ConvertNetworkPolicyV3ToV1Value`: errors if name or
/// namespace is empty, defaults the tier, and augments the selector.
pub fn process_network_policy(
    namespace: Option<&str>,
    name: &str,
    spec: &NetworkPolicySpec,
) -> Result<(PolicyV1Key, PolicyV1), ProcessError> {
    if name.is_empty() {
        return Err(ProcessError::MissingKeyField("name"));
    }
    let ns = match namespace {
        Some(n) if !n.is_empty() => n,
        _ => return Err(ProcessError::MissingKeyField("namespace")),
    };

    let selector = augment_policy_selector(&spec.selector, ns);
    let key = PolicyV1Key {
        tier: tier_or_default(spec.tier.as_deref()),
        name: name.to_string(),
        namespace: Some(ns.to_string()),
        kind: PolicyKind::NetworkPolicy,
    };
    let value = PolicyV1 {
        namespace: Some(ns.to_string()),
        tier: tier_or_default(spec.tier.as_deref()),
        order: spec.order,
        selector,
        types: spec.types.iter().copied().map(policy_type_to_v1).collect(),
        inbound_rules: spec.ingress.iter().map(|r| rule_to_v1(r, Some(ns))).collect(),
        outbound_rules: spec.egress.iter().map(|r| rule_to_v1(r, Some(ns))).collect(),
    };
    Ok((key, value))
}

/// Convert a v3 `IPPool` spec to its v1 KVPair, mirroring `IPPoolV3ToV1`.
pub fn process_ip_pool(spec: &IpPoolSpec) -> (IpPoolV1Key, IpPoolV1) {
    let ipip_interface = match spec.ipip_mode {
        apis::EncapMode::Always | apis::EncapMode::CrossSubnet => "tunl0".to_string(),
        apis::EncapMode::Never => String::new(),
    };
    let key = IpPoolV1Key {
        cidr: spec.cidr.clone(),
    };
    let value = IpPoolV1 {
        cidr: spec.cidr.clone(),
        ipip_mode: spec.ipip_mode,
        ipip_interface,
        vxlan_mode: spec.vxlan_mode,
        masquerade: spec.nat_outgoing,
        ipam: !spec.disabled,
        disabled: spec.disabled,
        disable_bgp_export: spec.disable_bgp_export,
        assignment_mode: spec.assignment_mode,
        allowed_uses: spec.allowed_uses.clone(),
    };
    (key, value)
}

/// Whether a CIDR/IP string is IPv6 (contains a colon).
fn is_ipv6(net: &str) -> bool {
    net.contains(':')
}

/// Convert a v3 `WorkloadEndpoint` (key + spec) to its v1 KVPair, mirroring
/// `convertWorkloadEndpointV2ToV1Value`. Returns `Ok(None)` when the WEP has no
/// IP networks (upstream filters these out — Felix can't render rules for them).
pub fn process_workload_endpoint(
    namespace: Option<&str>,
    name: &str,
    spec: &WorkloadEndpointSpec,
) -> Result<Option<(WorkloadEndpointV1Key, WorkloadEndpointV1)>, ProcessError> {
    if spec.ipnetworks.is_empty() {
        return Ok(None);
    }

    let mut ipv4_nets = Vec::new();
    let mut ipv6_nets = Vec::new();
    for net in &spec.ipnetworks {
        if is_ipv6(net) {
            ipv6_nets.push(net.clone());
        } else {
            ipv4_nets.push(net.clone());
        }
    }

    // Ports without a name are used only by the CNI plugin; Felix ignores them.
    let ports = spec
        .ports
        .iter()
        .filter(|p| !p.name.is_empty())
        .map(|p| EndpointPortV1 {
            name: p.name.clone(),
            protocol: p.protocol.to_lowercase(),
            port: p.port,
        })
        .collect();

    // Inject the service-account label if present. Pod metadata labels are out
    // of scope here: the lean `apis::WorkloadEndpointSpec` this processor
    // consumes carries no labels of its own (they live on object metadata,
    // outside this input surface), so there is nothing to strip — no
    // `pcns.`/`pcsa.` prefixed labels can appear. If pod metadata labels are
    // ever wired into this input surface (felix P3 consumer), upstream's
    // `pcns.`/`pcsa.` stripping will need to be replicated here.
    let mut labels = BTreeMap::new();
    if let Some(sa) = spec
        .service_account_name
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        labels.insert(LABEL_SERVICE_ACCOUNT.to_string(), sa.to_string());
    }

    let key = WorkloadEndpointV1Key {
        hostname: spec.node.clone(),
        namespace: namespace.map(str::to_string),
        name: name.to_string(),
    };
    let value = WorkloadEndpointV1 {
        state: "active",
        name: spec.interface_name.clone(),
        mac: spec.mac.clone(),
        profile_ids: spec.profiles.clone(),
        ipv4_nets,
        ipv6_nets,
        labels,
        ports,
        allow_spoofed_source_prefixes: spec.allow_spoofed_source_prefixes.clone(),
    };
    Ok(Some((key, value)))
}

/// Flatten a v3 `FelixConfiguration` (resource name + spec) into individual v1
/// config entries, mirroring `configUpdateProcessor`:
/// * `default` → global config (`host = None`);
/// * `node.<host>` → per-host config (`host = Some(host)`);
/// * any other name → selector-scoped, not decomposed here → empty vec.
///
/// Only *set* fields are emitted (unset `Option`s and empty strings are omitted).
/// The field → key mapping uses the upstream `confignamev1`/field name.
pub fn process_felix_configuration(name: &str, spec: &FelixConfigurationSpec) -> Vec<ConfigV1> {
    let host = if name == "default" {
        None
    } else if let Some(node) = name.strip_prefix("node.") {
        Some(node.to_string())
    } else {
        // Selector-scoped FelixConfiguration — handled elsewhere upstream.
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut push = |name: &str, value: String| {
        out.push(ConfigV1 {
            host: host.clone(),
            name: name.to_string(),
            value,
        });
    };

    if let Some(b) = spec.bpf_enabled {
        push("BPFEnabled", b.to_string());
    }
    if let Some(s) = spec.log_severity_screen.as_deref().filter(|s| !s.is_empty()) {
        push("LogSeverityScreen", s.to_string());
    }
    if let Some(s) = spec.interface_prefix.as_deref().filter(|s| !s.is_empty()) {
        push("InterfacePrefix", s.to_string());
    }
    if let Some(s) = spec
        .default_endpoint_to_host_action
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        push("DefaultEndpointToHostAction", s.to_string());
    }

    out
}

// ===========================================================================
// dispatch
// ===========================================================================

/// Dispatch: deserialize `spec` for `kind` and run the matching processor,
/// returning the v1 KVPair(s). Only the four felix-facing kinds
/// (`NetworkPolicy`, `IPPool`, `WorkloadEndpoint`, `FelixConfiguration`) are
/// handled; any other kind is [`ProcessError::UnsupportedKind`].
pub fn process(
    kind: ResourceKind,
    key: &Key,
    spec: &serde_json::Value,
) -> Result<Vec<V1KVPair>, ProcessError> {
    let (namespace, name) = match key {
        Key::Resource {
            namespace, name, ..
        } => (namespace.as_deref(), name.as_str()),
        _ => return Err(ProcessError::MissingKeyField("resource key")),
    };

    fn de<T: serde::de::DeserializeOwned>(v: &serde_json::Value) -> Result<T, ProcessError> {
        serde_json::from_value(v.clone()).map_err(|e| ProcessError::Deserialize(e.to_string()))
    }

    match kind {
        ResourceKind::NetworkPolicy => {
            let spec: NetworkPolicySpec = de(spec)?;
            let (k, v) = process_network_policy(namespace, name, &spec)?;
            Ok(vec![V1KVPair {
                key: V1Key::Policy(k),
                value: V1Value::Policy(v),
            }])
        }
        ResourceKind::IpPool => {
            let spec: IpPoolSpec = de(spec)?;
            let (k, v) = process_ip_pool(&spec);
            Ok(vec![V1KVPair {
                key: V1Key::IpPool(k),
                value: V1Value::IpPool(v),
            }])
        }
        ResourceKind::WorkloadEndpoint => {
            let spec: WorkloadEndpointSpec = de(spec)?;
            match process_workload_endpoint(namespace, name, &spec)? {
                Some((k, v)) => Ok(vec![V1KVPair {
                    key: V1Key::WorkloadEndpoint(k),
                    value: V1Value::WorkloadEndpoint(v),
                }]),
                None => Ok(Vec::new()),
            }
        }
        ResourceKind::FelixConfiguration => {
            let spec: FelixConfigurationSpec = de(spec)?;
            Ok(process_felix_configuration(name, &spec)
                .into_iter()
                .map(|c| V1KVPair {
                    key: V1Key::Config {
                        host: c.host,
                        name: c.name,
                    },
                    value: V1Value::Config(c.value),
                })
                .collect())
        }
        other => Err(ProcessError::UnsupportedKind(other)),
    }
}

/// Derive just the v1 **key(s)** a v3 resource maps to, discarding the v1
/// values. This is what a purpose-built syncer uses on **delete**: it reuses
/// [`process`]'s exact key conversion (run over the last-known spec the delete
/// event carries) so the emitted v1 delete key(s) match the v1 update key(s)
/// the same resource produced. A resource that flattens into many v1 pairs (a
/// `FelixConfiguration`) yields many keys; a filtered-out resource (a
/// `WorkloadEndpoint` with no IP networks) yields none.
pub fn process_keys(
    kind: ResourceKind,
    key: &Key,
    spec: &serde_json::Value,
) -> Result<Vec<V1Key>, ProcessError> {
    Ok(process(kind, key, spec)?
        .into_iter()
        .map(|kv| kv.key)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use apis::{EncapMode, WorkloadPort};

    // ---- NetworkPolicy: tier default + selector augmentation ----

    #[test]
    fn np_empty_selector_gets_just_namespace_selector_and_default_tier() {
        let spec = NetworkPolicySpec::default();
        let (key, val) = process_network_policy(Some("namespace1"), "empty", &spec).unwrap();
        assert_eq!(key.tier, "default");
        assert_eq!(key.namespace.as_deref(), Some("namespace1"));
        assert_eq!(val.tier, "default");
        assert_eq!(val.selector, "projectcalico.org/namespace == 'namespace1'");
    }

    #[test]
    fn np_nonempty_selector_is_combined_with_namespace_selector() {
        let spec = NetworkPolicySpec {
            selector: "mylabel == 'selectme'".into(),
            ..Default::default()
        };
        let (_key, val) = process_network_policy(Some("namespace2"), "minimal", &spec).unwrap();
        assert_eq!(
            val.selector,
            "(mylabel == 'selectme') && projectcalico.org/namespace == 'namespace2'"
        );
    }

    #[test]
    fn np_explicit_tier_is_preserved() {
        let spec = NetworkPolicySpec {
            tier: Some("security".into()),
            ..Default::default()
        };
        let (key, val) = process_network_policy(Some("ns"), "p", &spec).unwrap();
        assert_eq!(key.tier, "security");
        assert_eq!(val.tier, "security");
    }

    #[test]
    fn np_missing_namespace_and_name_error() {
        let spec = NetworkPolicySpec::default();
        assert_eq!(
            process_network_policy(None, "p", &spec),
            Err(ProcessError::MissingKeyField("namespace"))
        );
        assert_eq!(
            process_network_policy(Some(""), "p", &spec),
            Err(ProcessError::MissingKeyField("namespace"))
        );
        assert_eq!(
            process_network_policy(Some("ns"), "", &spec),
            Err(ProcessError::MissingKeyField("name"))
        );
    }

    #[test]
    fn np_types_and_action_and_protocol_converted() {
        let spec = NetworkPolicySpec {
            types: vec![PolicyType::Ingress, PolicyType::Egress],
            ingress: vec![Rule {
                action: Action::Allow,
                protocol: Some(Protocol::Named("TCP".into())),
                source: EntityRule::default(),
                destination: EntityRule {
                    ports: vec![5432],
                    ..Default::default()
                },
            }],
            egress: vec![Rule {
                action: Action::Pass,
                protocol: None,
                source: EntityRule::default(),
                destination: EntityRule::default(),
            }],
            ..Default::default()
        };
        let (_k, val) = process_network_policy(Some("ns"), "p", &spec).unwrap();
        assert_eq!(val.types, vec!["ingress", "egress"]);
        assert_eq!(val.inbound_rules[0].action, "allow");
        assert_eq!(val.inbound_rules[0].protocol.as_deref(), Some("tcp"));
        assert_eq!(val.inbound_rules[0].dst_ports, vec![5432]);
        // Pass maps to next-tier.
        assert_eq!(val.outbound_rules[0].action, "next-tier");
    }

    // ---- Rule namespace scoping (getEndpointSelector core) ----

    #[test]
    fn rule_peer_selector_scoped_to_policy_namespace() {
        let spec = NetworkPolicySpec {
            ingress: vec![Rule {
                action: Action::Allow,
                protocol: None,
                source: EntityRule {
                    selector: Some("role == 'client'".into()),
                    ..Default::default()
                },
                destination: EntityRule::default(),
            }],
            ..Default::default()
        };
        let (_k, val) = process_network_policy(Some("ns1"), "p", &spec).unwrap();
        // Source selector gets namespace-scoped; empty dest stays empty.
        assert_eq!(
            val.inbound_rules[0].src_selector,
            "(projectcalico.org/namespace == 'ns1') && (role == 'client')"
        );
        assert_eq!(val.inbound_rules[0].dst_selector, "");
    }

    #[test]
    fn rule_namespace_selector_simplified_translation() {
        let all = EntityRule {
            namespace_selector: Some("all()".into()),
            ..Default::default()
        };
        assert_eq!(
            rule_endpoint_selector(&all, Some("ns1")),
            "has(projectcalico.org/namespace)"
        );
        let global = EntityRule {
            namespace_selector: Some("global()".into()),
            ..Default::default()
        };
        assert_eq!(
            rule_endpoint_selector(&global, Some("ns1")),
            "!has(projectcalico.org/namespace)"
        );
        // namespaceSelector + endpoint selector combine.
        //
        // NOTE: this asserts the CURRENT SIMPLIFIED output (raw label keys),
        // NOT verified upstream parity. Upstream `getEndpointSelector` /
        // `parseSelectorAttachPrefix` rewrites a namespaceSelector's label
        // keys with a `pcns.` prefix (and service-account-derived selectors
        // with `pcsa.`), so the faithful upstream result here would be
        // `(pcns.env == 'prod') && (role == 'db')`. We have no selector
        // parser/dependency to do that rewrite yet, so `rule_endpoint_selector`
        // passes the namespaceSelector through unprefixed — see the
        // "Documented simplifications" note on that function. Fixing this to
        // match upstream requires a real selector parser and is tracked for
        // the T021 felix consumer; do not mistake this assertion for
        // confirmed parity.
        let both = EntityRule {
            namespace_selector: Some("env == 'prod'".into()),
            selector: Some("role == 'db'".into()),
            ..Default::default()
        };
        assert_eq!(
            rule_endpoint_selector(&both, Some("ns1")),
            "(env == 'prod') && (role == 'db')"
        );
    }

    // ---- IPPool ----

    #[test]
    fn ippool_maps_nat_outgoing_to_masquerade_and_modes() {
        let spec = IpPoolSpec {
            cidr: "192.168.0.0/16".into(),
            ipip_mode: EncapMode::CrossSubnet,
            vxlan_mode: EncapMode::Always,
            nat_outgoing: true,
            disabled: false,
            disable_bgp_export: true,
            ..Default::default()
        };
        let (key, val) = process_ip_pool(&spec);
        assert_eq!(key.cidr, "192.168.0.0/16");
        assert!(val.masquerade); // natOutgoing -> masquerade
        assert!(val.ipam); // !disabled
        assert_eq!(val.ipip_mode, EncapMode::CrossSubnet);
        assert_eq!(val.ipip_interface, "tunl0"); // IPIP active
        assert_eq!(val.vxlan_mode, EncapMode::Always);
        assert!(val.disable_bgp_export);
    }

    #[test]
    fn ippool_never_ipip_has_no_tunnel_and_disabled_disables_ipam() {
        let spec = IpPoolSpec {
            cidr: "10.0.0.0/16".into(),
            disabled: true,
            ..Default::default()
        };
        let (_k, val) = process_ip_pool(&spec);
        assert_eq!(val.ipip_interface, "");
        assert!(!val.ipam);
        assert!(val.disabled);
        assert!(!val.masquerade);
    }

    // ---- WorkloadEndpoint ----

    #[test]
    fn wep_maps_fields_and_splits_nets_by_version() {
        let spec = WorkloadEndpointSpec {
            node: "node-1".into(),
            orchestrator: "k8s".into(),
            endpoint: "eth0".into(),
            interface_name: "cali123".into(),
            mac: Some("ee:ee:ee:ee:ee:ee".into()),
            ipnetworks: vec!["10.0.0.5/32".into(), "fd00::5/128".into()],
            profiles: vec!["kns.default".into()],
            ports: vec![
                WorkloadPort {
                    name: "http".into(),
                    port: 80,
                    protocol: "TCP".into(),
                },
                WorkloadPort {
                    name: String::new(), // unnamed -> filtered out
                    port: 90,
                    protocol: "TCP".into(),
                },
            ],
            service_account_name: Some("sa-1".into()),
            ..Default::default()
        };
        let (key, val) = process_workload_endpoint(Some("default"), "wep-1", &spec)
            .unwrap()
            .unwrap();
        assert_eq!(key.hostname, "node-1");
        assert_eq!(key.namespace.as_deref(), Some("default"));
        assert_eq!(val.state, "active");
        assert_eq!(val.name, "cali123"); // = interfaceName
        assert_eq!(val.ipv4_nets, vec!["10.0.0.5/32"]);
        assert_eq!(val.ipv6_nets, vec!["fd00::5/128"]);
        assert_eq!(val.profile_ids, vec!["kns.default"]);
        // Only the named port survives, protocol lower-cased.
        assert_eq!(val.ports.len(), 1);
        assert_eq!(val.ports[0].protocol, "tcp");
        // Service-account label injected.
        assert_eq!(
            val.labels.get("projectcalico.org/serviceaccount").map(String::as_str),
            Some("sa-1")
        );
    }

    #[test]
    fn wep_with_no_ipnetworks_is_filtered_out() {
        let spec = WorkloadEndpointSpec {
            node: "node-1".into(),
            orchestrator: "k8s".into(),
            endpoint: "eth0".into(),
            interface_name: "cali123".into(),
            ..Default::default()
        };
        assert_eq!(
            process_workload_endpoint(Some("default"), "wep-1", &spec).unwrap(),
            None
        );
    }

    // ---- FelixConfiguration flattening ----

    #[test]
    fn felixconfig_default_flattens_set_fields_only() {
        let spec = FelixConfigurationSpec {
            bpf_enabled: Some(true),
            log_severity_screen: Some("Warning".into()),
            interface_prefix: None,
            default_endpoint_to_host_action: Some(String::new()), // empty -> omitted
        };
        let entries = process_felix_configuration("default", &spec);
        // Two set, non-empty fields.
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.host.is_none()));
        assert!(entries
            .iter()
            .any(|e| e.name == "BPFEnabled" && e.value == "true"));
        assert!(entries
            .iter()
            .any(|e| e.name == "LogSeverityScreen" && e.value == "Warning"));
        // Unset / empty fields omitted.
        assert!(entries.iter().all(|e| e.name != "InterfacePrefix"));
        assert!(entries
            .iter()
            .all(|e| e.name != "DefaultEndpointToHostAction"));
    }

    #[test]
    fn felixconfig_per_node_name_sets_host() {
        let spec = FelixConfigurationSpec {
            interface_prefix: Some("eni".into()),
            ..Default::default()
        };
        let entries = process_felix_configuration("node.worker-1", &spec);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host.as_deref(), Some("worker-1"));
        assert_eq!(entries[0].name, "InterfacePrefix");
        assert_eq!(entries[0].value, "eni");
    }

    #[test]
    fn felixconfig_selector_scoped_name_is_not_decomposed() {
        let spec = FelixConfigurationSpec {
            bpf_enabled: Some(true),
            ..Default::default()
        };
        assert!(process_felix_configuration("my-scoped-config", &spec).is_empty());
    }

    #[test]
    fn felixconfig_empty_spec_yields_nothing() {
        assert!(process_felix_configuration("default", &FelixConfigurationSpec::default()).is_empty());
    }

    // ---- dispatch ----

    #[test]
    fn dispatch_network_policy_from_json() {
        let key = Key::Resource {
            kind: ResourceKind::NetworkPolicy,
            namespace: Some("ns1".into()),
            name: "p".into(),
        };
        let spec = serde_json::json!({ "selector": "a == 'b'" });
        let out = process(ResourceKind::NetworkPolicy, &key, &spec).unwrap();
        assert_eq!(out.len(), 1);
        match &out[0].value {
            V1Value::Policy(p) => {
                assert_eq!(p.selector, "(a == 'b') && projectcalico.org/namespace == 'ns1'")
            }
            _ => panic!("expected policy value"),
        }
    }

    #[test]
    fn dispatch_felixconfig_flattens() {
        let key = Key::Resource {
            kind: ResourceKind::FelixConfiguration,
            namespace: None,
            name: "default".into(),
        };
        let spec = serde_json::json!({ "bpfEnabled": true, "logSeverityScreen": "Debug" });
        let out = process(ResourceKind::FelixConfiguration, &key, &spec).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out
            .iter()
            .any(|kv| kv.key == V1Key::Config { host: None, name: "BPFEnabled".into() }));
    }

    #[test]
    fn dispatch_wep_with_no_ips_yields_empty() {
        let key = Key::Resource {
            kind: ResourceKind::WorkloadEndpoint,
            namespace: Some("default".into()),
            name: "wep".into(),
        };
        let spec = serde_json::json!({
            "node": "n1", "orchestrator": "k8s", "endpoint": "eth0", "interfaceName": "cali1"
        });
        let out = process(ResourceKind::WorkloadEndpoint, &key, &spec).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn dispatch_unsupported_kind_errors() {
        let key = Key::Resource {
            kind: ResourceKind::Tier,
            namespace: None,
            name: "default".into(),
        };
        assert_eq!(
            process(ResourceKind::Tier, &key, &serde_json::json!({})),
            Err(ProcessError::UnsupportedKind(ResourceKind::Tier))
        );
    }
}
