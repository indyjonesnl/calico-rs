//! `calc` — Calico-rs calculation graph.
//!
//! Turns datastore state into per-endpoint dataplane instructions: which
//! policies are active on which workloads, which selectors resolve to which
//! members (IP sets), ordered tiers, and routes. Built incrementally.
//!
//! Implemented so far: the **label selector engine** ([`Selector`]) — Calico's
//! selector language, the primitive underneath policy `selector`,
//! `namespaceSelector`, and every IP-set membership computation. This is the
//! core of label-based policy matching (spec FR-007, FR-010).

mod active_rules;
mod event_sequencer;
mod flowlogs;
mod from_resources;
mod graph;
mod k8s_policy;
mod labelindex;
mod policy_eval;
mod policy_resolver;
mod routes;
mod scope;
mod selector;

pub use active_rules::{
    ip_set_id, ActiveRulesCalculator, PolicyRules, ResolvedPolicy, ResolvedRule, RuleScanner,
    ScanResult, ScanRule, Transition,
};
pub use event_sequencer::EventSequencer;
pub use flowlogs::{flow_log, FlowLogRecord};
pub use from_resources::{evaluator_from, network_policy_to_eval, profile_to_eval};
pub use graph::{CalcGraph, GraphDeltas, ResourceUpdate};
pub use k8s_policy::{k8s_network_policy_to_eval, K8sNetworkPolicySpec};
pub use labelindex::{Delta, IpSetId, ItemId, Member, MemberChange, MembershipIndex, ParentId};
pub use policy_eval::{
    Decision, DecisionReason, Direction, EvalPolicy, EvalRule, Packet, PolicyEvaluator, RuleAction,
    Tier, TierDefault, TracedDecision,
};
pub use policy_resolver::{
    sort_policies, sort_tiers, EndpointPolicyOrder, PolicyResolver, TierPolicies,
};
pub use routes::{BlockInfo, Route, RouteResolver, RouteType, WorkloadInfo};
pub use scope::{scope_global_network_policy, scope_network_policy};
pub use selector::{Selector, SelectorError};
