//! `proto` — the calculation-graph ↔ dataplane protocol for Calico-rs.
//!
//! The calc graph emits *computed* dataplane instructions ([`ToDataplane`]); a
//! dataplane implementation (nftables, eBPF, external) consumes them and reports
//! status back ([`FromDataplane`]). This is an internal, Rust-native protocol
//! (see `contracts/dataplane-proto.md` and `research.md` §10 — it is intentionally
//! not wire-compatible with upstream Calico's protobuf). It mirrors the
//! *semantics* of upstream `felix/proto/felixbackend.proto`.
//!
//! The types derive `serde` so they can be framed over any codec (a `tonic`/
//! `prost` transport, or a length-delimited channel) without changing the model.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Identifier of an IP set referenced by policy rules.
pub type IpSetId = String;

/// The member encoding of an IP set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpSetKind {
    /// `hash:ip` — bare addresses.
    Ip,
    /// `hash:ip,port` — address + port (named ports).
    IpAndPort,
    /// `hash:net` — CIDRs.
    Net,
}

/// Full (re)definition of an IP set's membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpSetUpdate {
    pub id: IpSetId,
    pub kind: IpSetKind,
    pub members: Vec<String>,
}

/// Incremental membership change for an IP set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpSetDeltaUpdate {
    pub id: IpSetId,
    pub added_members: Vec<String>,
    pub removed_members: Vec<String>,
}

/// Rule action (computed form).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Deny,
    Log,
    Pass,
}

/// A computed policy rule: selectors have already been resolved to IP-set ids.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub action_field: Option<RuleAction>,
    pub protocol: Option<String>,
    pub src_nets: Vec<String>,
    pub dst_nets: Vec<String>,
    pub src_ports: Vec<u16>,
    pub dst_ports: Vec<u16>,
    pub src_ip_set_ids: Vec<IpSetId>,
    pub dst_ip_set_ids: Vec<IpSetId>,
    /// Stable id used to attribute flow-log / policy-decision records (FR-029).
    pub rule_id: Option<String>,
}

impl PolicyRule {
    /// A minimal rule with just an action.
    pub fn action(action: RuleAction) -> Self {
        Self {
            action_field: Some(action),
            ..Default::default()
        }
    }
}

/// Identifier of a policy within a tier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId {
    pub tier: String,
    pub name: String,
}

/// A policy's resolved inbound/outbound rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub inbound_rules: Vec<PolicyRule>,
    pub outbound_rules: Vec<PolicyRule>,
}

/// Ordered policies for one tier applied to an endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierInfo {
    pub name: String,
    pub ingress_policies: Vec<String>,
    pub egress_policies: Vec<String>,
}

/// A workload's dataplane view.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadEndpoint {
    pub name: String,
    pub mac: Option<String>,
    pub profile_ids: Vec<String>,
    pub tiers: Vec<TierInfo>,
    pub ipv4_nets: Vec<String>,
    pub ipv6_nets: Vec<String>,
}

/// Identifier of a workload endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadEndpointId {
    pub orchestrator: String,
    pub workload: String,
    pub endpoint: String,
}

/// L3 route type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteType {
    LocalWorkload,
    RemoteWorkload,
    LocalHost,
    RemoteHost,
}

/// A route to program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteUpdate {
    pub route_type: RouteType,
    pub dst: String,
    pub dst_node_name: Option<String>,
    pub gateway: Option<String>,
}

/// Messages from the calc graph to the dataplane. Ordering matters: the calc
/// graph emits in dependency-safe order (IP sets before the policies that
/// reference them) — the dataplane must apply them in the order received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToDataplane {
    IpSetUpdate(IpSetUpdate),
    IpSetDeltaUpdate(IpSetDeltaUpdate),
    IpSetRemove(IpSetId),
    ActivePolicyUpdate {
        id: PolicyId,
        policy: Policy,
    },
    ActivePolicyRemove(PolicyId),
    ActiveProfileUpdate {
        id: String,
        profile: Policy,
    },
    ActiveProfileRemove(String),
    WorkloadEndpointUpdate {
        id: WorkloadEndpointId,
        endpoint: WorkloadEndpoint,
    },
    WorkloadEndpointRemove(WorkloadEndpointId),
    RouteUpdate(RouteUpdate),
    RouteRemove(String),
    ConfigUpdate(BTreeMap<String, String>),
    /// The datastore is now in sync — the initial burst of state is complete.
    InSync,
}

/// Messages from the dataplane back to the calc graph / status reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FromDataplane {
    /// Programming status for a workload endpoint (e.g. "up", "error").
    WorkloadEndpointStatus {
        id: WorkloadEndpointId,
        status: String,
    },
    /// Overall dataplane process status.
    ProcessStatus { status: String },
    /// The dataplane has finished applying the initial in-sync state.
    InSync,
}

/// A sink the calc graph pushes [`ToDataplane`] messages into. Implemented by
/// each dataplane (nftables, eBPF, external-process driver). Kept synchronous
/// here; an async transport wraps it.
pub trait DataplaneSink {
    type Error;
    /// Apply one message. Implementations must respect arrival order.
    fn apply(&mut self, msg: ToDataplane) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_dataplane_roundtrips_via_serde() {
        let msg = ToDataplane::ActivePolicyUpdate {
            id: PolicyId {
                tier: "default".into(),
                name: "allow-web".into(),
            },
            policy: Policy {
                inbound_rules: vec![PolicyRule {
                    action_field: Some(RuleAction::Allow),
                    protocol: Some("TCP".into()),
                    dst_ports: vec![443],
                    src_ip_set_ids: vec!["s:frontend".into()],
                    rule_id: Some("r0".into()),
                    ..Default::default()
                }],
                outbound_rules: vec![],
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        let round: ToDataplane = serde_json::from_str(&json).unwrap();
        assert_eq!(round, msg);
    }

    #[test]
    fn ipset_delta_roundtrips() {
        let msg = ToDataplane::IpSetDeltaUpdate(IpSetDeltaUpdate {
            id: "s:frontend".into(),
            added_members: vec!["10.0.0.1".into()],
            removed_members: vec!["10.0.0.2".into()],
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ToDataplane>(&json).unwrap(), msg);
    }

    /// A mock sink that records messages in order — models what the dataplane
    /// managers do and lets tests assert ordering.
    #[derive(Default)]
    struct RecordingSink {
        seen: Vec<ToDataplane>,
    }
    impl DataplaneSink for RecordingSink {
        type Error = std::convert::Infallible;
        fn apply(&mut self, msg: ToDataplane) -> Result<(), Self::Error> {
            self.seen.push(msg);
            Ok(())
        }
    }

    #[test]
    fn sink_preserves_arrival_order() {
        let mut sink = RecordingSink::default();
        sink.apply(ToDataplane::IpSetUpdate(IpSetUpdate {
            id: "s".into(),
            kind: IpSetKind::Ip,
            members: vec!["10.0.0.1".into()],
        }))
        .unwrap();
        sink.apply(ToDataplane::InSync).unwrap();
        assert_eq!(sink.seen.len(), 2);
        // IP set must arrive before the InSync barrier.
        assert!(matches!(sink.seen[0], ToDataplane::IpSetUpdate(_)));
        assert!(matches!(sink.seen[1], ToDataplane::InSync));
    }

    #[test]
    fn policy_rule_action_helper() {
        let r = PolicyRule::action(RuleAction::Deny);
        assert_eq!(r.action_field, Some(RuleAction::Deny));
        assert!(r.dst_ports.is_empty());
    }
}
