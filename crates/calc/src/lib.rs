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

mod from_resources;
mod k8s_policy;
mod policy_eval;
mod routes;
mod selector;

pub use from_resources::{evaluator_from, network_policy_to_eval, profile_to_eval};
pub use k8s_policy::{k8s_network_policy_to_eval, K8sNetworkPolicySpec};
pub use policy_eval::{
    Decision, Direction, EvalPolicy, EvalRule, Packet, PolicyEvaluator, RuleAction, Tier,
    TierDefault,
};
pub use routes::{Route, RouteResolver, RouteType, WorkloadInfo};
pub use selector::{Selector, SelectorError};
