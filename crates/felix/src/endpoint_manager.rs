//! The felix [`EndpointManager`]: programs the per-workload policy dataplane —
//! per-policy nftables chains (from the *resolved* proto rules) and per-endpoint
//! dispatch chains that jump to an endpoint's policies in tier order and end in
//! Calico's default-deny.
//!
//! Modelled on upstream `felix/dataplane/linux/endpoint_mgr.go` +
//! `rules/policy.go`. Unlike [`crate::policy_render`] (which renders v3 resource
//! specs and resolves selectors itself), this manager is **proto-driven**: the
//! calc graph has already resolved selectors to IP-set ids, so a
//! [`proto::PolicyRule`] carries `src_ip_set_ids`/`dst_ip_set_ids` that map
//! directly to `ip saddr @<set>` / `ip daddr @<set>` matches against the named
//! sets the [`crate::ipset_manager`] programs into the shared `inet calico` table
//! (via the identical [`crate::ipset_manager::set_name_for`]).
//!
//! ## Non-destructive apply — coordination with the IpSetManager (T057)
//!
//! nft named sets are **table-scoped** and the [`crate::ipset_manager`] never
//! flushes the `inet calico` table. Policy chains that reference `@<set>` must live
//! in that same table, so this manager MUST NOT flush the table either. It applies
//! **per chain** via [`crate::nft::render_chain_updates`] (`add`/`flush chain` +
//! re-add rules, `delete chain` for the rest) — never `flush ruleset`/table
//! replace — so the sets (and any untouched chains) survive every apply.
//!
//! ## Chain structure (what gets programmed)
//!
//! - **Per-policy chain** `cali-pi-<tier>-<name>` (ingress) / `cali-po-<tier>-<name>`
//!   (egress): the translated rules only. A rule falls through (implicit `return`)
//!   when it does not match, so control returns to the dispatch chain and the next
//!   policy is tried. Action mapping: `Allow→accept`, `Deny→drop`, `Pass→return`,
//!   `Log→`(skipped — no terminal verdict emitted yet).
//! - **Per-profile chain** `cali-pri-<id>` (ingress) / `cali-pro-<id>` (egress):
//!   the translated profile rules, with NO trailing drop. A profile `Allow`
//!   accepts; a non-match falls through to the endpoint chain's default-deny.
//!   Calico's open-by-default is the per-namespace `kns.<ns>` allow-all profile.
//! - **Per-endpoint dispatch chain** `cali-tw-<iface>` (to-workload / ingress) and
//!   `cali-fw-<iface>` (from-workload / egress): `jump` to each of the endpoint's
//!   tier policies in order; then, **only if no policy selects the endpoint in that
//!   direction**, `jump` to its profiles (the open-by-default fallback); then a
//!   terminal `drop` (Calico's per-endpoint default-deny). A policy-selected
//!   endpoint therefore ends at the end-of-policy drop and does NOT fall through to
//!   its profiles — this gates profiles per-direction (ingress/egress independent).
//! - **Base dispatch chain** `cali-forward` (filter/forward hook): for each
//!   endpoint, `oifname <iface> jump cali-tw-<iface>` (traffic *to* the pod) and
//!   `iifname <iface> jump cali-fw-<iface>` (traffic *from* the pod).
//!
//! ### Multi-tier simplification (documented, per the US2 target)
//!
//! The dispatch chain flattens all of an endpoint's tiers into one ordered list of
//! policy jumps, then the endpoint's profile jumps, followed by a single
//! end-of-endpoint default-deny. It does **not** yet implement per-tier
//! `pass`/`next-tier` fall-through semantics. Per-tier boundaries are a follow-up.
//!
//! `on_update` only mutates in-memory desired state (cheap, no I/O); all kernel
//! work happens in the async `complete_deferred_work`.

use std::collections::BTreeMap;

use proto::{
    Policy, PolicyId, PolicyRule, RuleAction, ToDataplane, WorkloadEndpoint, WorkloadEndpointId,
};
use reconcile::DeltaTracker;

use crate::dataplane::{DataplaneError, Manager};
use crate::ipset_manager::{set_name_for, TABLE_FAMILY, TABLE_NAME};
use crate::nft::{BaseHook, ChainType, NftChain, NftMatch, NftRule, Verdict};

/// The base chain that steers workload traffic to per-endpoint dispatch chains.
const FORWARD_CHAIN: &str = "cali-forward";

/// Which direction a policy chain enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Ingress,
    Egress,
}

/// Map a proto [`RuleAction`] to an nft [`Verdict`]. `Log` has no terminal verdict
/// in this subset, so it is skipped (`None`).
fn map_action(action: RuleAction) -> Option<Verdict> {
    match action {
        RuleAction::Allow => Some(Verdict::Accept),
        RuleAction::Deny => Some(Verdict::Drop),
        RuleAction::Pass => Some(Verdict::Return),
        RuleAction::Log => None,
    }
}

/// nft-safe token: keep `[A-Za-z0-9_-]`, map everything else to `-`.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Deterministic per-policy chain name, e.g. `cali-pi-default-allow-web`.
fn policy_chain_name(id: &PolicyId, dir: Direction) -> String {
    let prefix = match dir {
        Direction::Ingress => "cali-pi",
        Direction::Egress => "cali-po",
    };
    format!("{prefix}-{}-{}", sanitize(&id.tier), sanitize(&id.name))
}

/// Deterministic per-profile chain name, e.g. `cali-pri-kns.nettest` (ingress) /
/// `cali-pro-kns.nettest` (egress). Mirrors [`policy_chain_name`] but profiles are
/// tier-less, so the id is the sole discriminator.
fn profile_chain_name(id: &str, dir: Direction) -> String {
    let prefix = match dir {
        Direction::Ingress => "cali-pri",
        Direction::Egress => "cali-pro",
    };
    // Profile ids (e.g. `kns.nettest`) carry a `.` that nft accepts unquoted and
    // that Calico preserves in the chain name, so keep it (unlike `sanitize`).
    let safe: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("{prefix}-{safe}")
}

/// Per-endpoint dispatch chain name for a given interface and direction.
fn dispatch_chain_name(iface: &str, dir: Direction) -> String {
    let prefix = match dir {
        Direction::Ingress => "cali-tw", // to-workload
        Direction::Egress => "cali-fw",  // from-workload
    };
    format!("{prefix}-{}", sanitize(iface))
}

/// Translate one resolved proto [`PolicyRule`] into 0+ nft rules.
///
/// Expands the cross-product of {source alternatives} × {dest alternatives} ×
/// {source ports} × {dest ports}, where a "source alternative" is each `src_nets`
/// CIDR (`ip saddr <cidr>`) plus each `src_ip_set_ids` id (`ip saddr @<set>`), and
/// likewise for the destination. Absent dimensions contribute a single `None`.
fn render_rule(rule: &PolicyRule) -> Vec<NftRule> {
    let Some(action) = rule.action_field else {
        return Vec::new();
    };
    let Some(verdict) = map_action(action) else {
        return Vec::new(); // Log (or any non-terminal): no rule in this subset.
    };

    let proto = rule.protocol.as_ref().map(|p| p.to_lowercase());

    // Source / destination match alternatives (nets first, then resolved sets).
    let sources = addr_alternatives(&rule.src_nets, &rule.src_ip_set_ids, true);
    let dests = addr_alternatives(&rule.dst_nets, &rule.dst_ip_set_ids, false);
    let sports = port_alternatives(&rule.src_ports, true);
    let dports = port_alternatives(&rule.dst_ports, false);

    let mut out = Vec::new();
    for src in &sources {
        for dst in &dests {
            for sp in &sports {
                for dp in &dports {
                    let mut matches = Vec::new();
                    if let Some(p) = &proto {
                        matches.push(NftMatch::L4Proto(p.clone()));
                    }
                    if let Some(m) = src {
                        matches.push(m.clone());
                    }
                    if let Some(m) = dst {
                        matches.push(m.clone());
                    }
                    if let Some(m) = sp {
                        matches.push(m.clone());
                    }
                    if let Some(m) = dp {
                        matches.push(m.clone());
                    }
                    let mut r = NftRule {
                        matches,
                        verdict: verdict.clone(),
                        comment: None,
                    };
                    if let Some(id) = &rule.rule_id {
                        r = r.comment(id.clone());
                    }
                    out.push(r);
                }
            }
        }
    }
    out
}

/// Build the address-match alternatives for one direction: each CIDR then each
/// resolved IP-set id. Empty ⇒ a single `None` (no address constraint).
fn addr_alternatives(nets: &[String], set_ids: &[String], is_src: bool) -> Vec<Option<NftMatch>> {
    let mut out: Vec<Option<NftMatch>> = Vec::new();
    for n in nets {
        out.push(Some(if is_src {
            NftMatch::SrcAddr(n.clone())
        } else {
            NftMatch::DestAddr(n.clone())
        }));
    }
    for id in set_ids {
        let name = set_name_for(id);
        out.push(Some(if is_src {
            NftMatch::SrcSet(name)
        } else {
            NftMatch::DestSet(name)
        }));
    }
    if out.is_empty() {
        out.push(None);
    }
    out
}

/// Build the port-match alternatives for one direction. Empty ⇒ a single `None`.
fn port_alternatives(ports: &[u16], is_src: bool) -> Vec<Option<NftMatch>> {
    if ports.is_empty() {
        return vec![None];
    }
    ports
        .iter()
        .map(|p| {
            Some(if is_src {
                NftMatch::SrcPort(*p)
            } else {
                NftMatch::DestPort(*p)
            })
        })
        .collect()
}

/// The nft side of chain programming, factored out so the delta logic is
/// unit-testable with a spy. The production impl is [`NftChainApplier`].
#[async_trait::async_trait(?Send)]
pub trait ChainApplier {
    /// Feed a full `nft -f -` document (per-chain add/flush/delete) to the kernel.
    async fn apply_document(&self, doc: &str) -> Result<(), String>;
}

/// Reconciles the kernel's nftables policy/endpoint chains to the calc graph's
/// desired policies + endpoints, applying only the per-chain delta and NEVER
/// flushing the shared `inet calico` table. Generic over [`ChainApplier`] so tests
/// inject a spy; production uses [`EndpointManager::with_nft`].
pub struct EndpointManager<A: ChainApplier> {
    /// Active policies by id (source of the per-policy chains' rules).
    policies: BTreeMap<PolicyId, Policy>,
    /// Active profiles by id (source of the per-profile `cali-pri`/`cali-pro`
    /// chains; supply Calico's open-by-default via the `kns.<ns>` allow profile).
    profiles: BTreeMap<String, Policy>,
    /// Local workload endpoints by id (source of the dispatch chains).
    endpoints: BTreeMap<WorkloadEndpointId, WorkloadEndpoint>,
    /// Desired vs. programmed chains, keyed by chain name.
    chains: DeltaTracker<String, NftChain>,
    applier: A,
}

impl<A: ChainApplier> EndpointManager<A> {
    /// Build a manager over an explicit applier (used in tests).
    pub fn new(applier: A) -> Self {
        Self {
            policies: BTreeMap::new(),
            profiles: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            chains: DeltaTracker::new(),
            applier,
        }
    }

    /// Number of active policies tracked (test/introspection helper).
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Number of local endpoints tracked (test/introspection helper).
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Count of chains whose kernel state still differs from desired (pending
    /// updates + pending deletions) — zero once fully reconciled. Recomputes the
    /// desired chain set first, so it reflects the latest absorbed state.
    pub fn pending_count(&mut self) -> usize {
        self.refresh_desired();
        self.chains.pending_update_count() + self.chains.pending_deletion_count()
    }

    /// Recompute the desired chain set from the current policies + endpoints and
    /// load it into the delta tracker (adding/updating/removing desired keys). Does
    /// not touch the kernel.
    fn refresh_desired(&mut self) {
        let desired = self.build_desired_chains();
        // Drop desired keys that are no longer wanted (become pending deletions).
        let stale: Vec<String> = self
            .chains
            .iter_desired()
            .map(|(k, _)| k.clone())
            .filter(|k| !desired.contains_key(k))
            .collect();
        for k in stale {
            self.chains.remove_desired(&k);
        }
        for (name, chain) in desired {
            self.chains.set_desired(name, chain);
        }
    }

    /// The full desired chain set derived from stored policies + endpoints.
    fn build_desired_chains(&self) -> BTreeMap<String, NftChain> {
        let mut chains: BTreeMap<String, NftChain> = BTreeMap::new();

        // 1. Per-policy chains (ingress + egress) from the resolved proto rules.
        for (id, policy) in &self.policies {
            let iname = policy_chain_name(id, Direction::Ingress);
            let irules = policy.inbound_rules.iter().flat_map(render_rule).collect();
            chains.insert(iname.clone(), NftChain::regular(iname, irules));

            let ename = policy_chain_name(id, Direction::Egress);
            let erules = policy.outbound_rules.iter().flat_map(render_rule).collect();
            chains.insert(ename.clone(), NftChain::regular(ename, erules));
        }

        // 2. Per-profile chains (ingress + egress) from the resolved proto rules.
        //    Unlike policy chains these carry NO trailing drop: a profile Allow
        //    accepts, otherwise control falls through to the endpoint chain's
        //    end-of-endpoint default-deny (open-by-default comes from the
        //    per-namespace `kns.<ns>` allow-all profile).
        for (id, profile) in &self.profiles {
            let iname = profile_chain_name(id, Direction::Ingress);
            let irules = profile.inbound_rules.iter().flat_map(render_rule).collect();
            chains.insert(iname.clone(), NftChain::regular(iname, irules));

            let ename = profile_chain_name(id, Direction::Egress);
            let erules = profile
                .outbound_rules
                .iter()
                .flat_map(render_rule)
                .collect();
            chains.insert(ename.clone(), NftChain::regular(ename, erules));
        }

        // 3. Per-endpoint dispatch chains + the aggregating base forward chain.
        let mut forward_rules: Vec<NftRule> = Vec::new();
        for ep in self.endpoints.values() {
            let iface = &ep.name;

            let tw = dispatch_chain_name(iface, Direction::Ingress);
            let tw_rules = self.dispatch_rules(ep, Direction::Ingress, &mut chains);
            chains.insert(tw.clone(), NftChain::regular(tw.clone(), tw_rules));
            forward_rules
                .push(NftRule::new(Verdict::Jump(tw)).with(NftMatch::OutInterface(iface.clone())));

            let fw = dispatch_chain_name(iface, Direction::Egress);
            let fw_rules = self.dispatch_rules(ep, Direction::Egress, &mut chains);
            chains.insert(fw.clone(), NftChain::regular(fw.clone(), fw_rules));
            forward_rules
                .push(NftRule::new(Verdict::Jump(fw)).with(NftMatch::InInterface(iface.clone())));
        }
        if !forward_rules.is_empty() {
            chains.insert(
                FORWARD_CHAIN.to_string(),
                NftChain::base(
                    FORWARD_CHAIN,
                    BaseHook {
                        chain_type: ChainType::Filter,
                        hook: "forward".into(),
                        priority: 0,
                        policy_accept: true,
                    },
                    forward_rules,
                ),
            );
        }

        chains
    }

    /// The rules for one endpoint's dispatch chain: a `jump` to each tier policy in
    /// order (flattening tiers — see the multi-tier simplification note); then, only
    /// when NO policy selects the endpoint in this direction, a `jump` to each of its
    /// profiles (the open-by-default fallback); then the end-of-endpoint default-deny
    /// `drop`. A policy-selected endpoint skips the profile fallback and relies on the
    /// end-of-policy drop. Ensures a (possibly empty stub) chain exists for every
    /// referenced policy — and every jumped profile — so all jumps resolve.
    fn dispatch_rules(
        &self,
        ep: &WorkloadEndpoint,
        dir: Direction,
        chains: &mut BTreeMap<String, NftChain>,
    ) -> Vec<NftRule> {
        let mut rules = Vec::new();
        let mut policy_selected = false;
        for tier in &ep.tiers {
            let names = match dir {
                Direction::Ingress => &tier.ingress_policies,
                Direction::Egress => &tier.egress_policies,
            };
            for pol in names {
                let id = PolicyId {
                    tier: tier.name.clone(),
                    name: pol.clone(),
                };
                let cn = policy_chain_name(&id, dir);
                // Stub an empty chain for a referenced-but-unknown policy so the
                // jump resolves; an empty chain falls through to the default-deny.
                chains
                    .entry(cn.clone())
                    .or_insert_with(|| NftChain::regular(cn.clone(), Vec::new()));
                rules.push(NftRule::new(Verdict::Jump(cn)));
                policy_selected = true;
            }
        }
        // Profiles are the fallback consulted ONLY when NO policy selects this
        // endpoint in this direction (Calico's open-by-default per-namespace
        // `kns.<ns>` allow profile). If ≥1 policy selected the endpoint, the policy
        // chains govern and control falls through to the end-of-policy default-deny
        // below — no profile fall-through. This is per-direction: an endpoint may be
        // policy-governed on ingress yet fall back to profiles on egress. A profile
        // Allow accepts; a non-match falls through to the default-deny below.
        if !policy_selected {
            for prof in &ep.profile_ids {
                let cn = profile_chain_name(prof, dir);
                // Stub an empty chain for a referenced-but-unknown profile so the
                // jump resolves; an empty chain falls through to the default-deny.
                chains
                    .entry(cn.clone())
                    .or_insert_with(|| NftChain::regular(cn.clone(), Vec::new()));
                rules.push(NftRule::new(Verdict::Jump(cn)));
            }
        }
        let dir_label = match dir {
            Direction::Ingress => "ingress",
            Direction::Egress => "egress",
        };
        rules.push(NftRule::new(Verdict::Drop).comment(format!("default deny ({dir_label})")));
        rules
    }
}

impl EndpointManager<NftChainApplier> {
    /// Build a production manager that programs the kernel via `nft -f -`.
    pub fn with_nft() -> Self {
        Self::new(NftChainApplier)
    }
}

#[async_trait::async_trait(?Send)]
impl<A: ChainApplier> Manager for EndpointManager<A> {
    fn on_update(&mut self, msg: &ToDataplane) {
        match msg {
            ToDataplane::ActivePolicyUpdate { id, policy } => {
                self.policies.insert(id.clone(), policy.clone());
            }
            ToDataplane::ActivePolicyRemove(id) => {
                self.policies.remove(id);
            }
            ToDataplane::ActiveProfileUpdate { id, profile } => {
                self.profiles.insert(id.clone(), profile.clone());
            }
            ToDataplane::ActiveProfileRemove(id) => {
                self.profiles.remove(id);
            }
            ToDataplane::WorkloadEndpointUpdate { id, endpoint } => {
                self.endpoints.insert(id.clone(), endpoint.clone());
            }
            ToDataplane::WorkloadEndpointRemove(id) => {
                self.endpoints.remove(id);
            }
            _ => {}
        }
    }

    async fn complete_deferred_work(&mut self) -> Result<(), DataplaneError> {
        self.refresh_desired();

        // Snapshot the pending delta into owned data so we can confirm each chain
        // while iterating. In-sync chains are skipped entirely (the delta's point).
        let updates: Vec<NftChain> = self
            .chains
            .iter_pending_updates()
            .map(|(_, v)| v.clone())
            .collect();
        let deletions: Vec<String> = self.chains.iter_pending_deletions().cloned().collect();

        if updates.is_empty() && deletions.is_empty() {
            return Ok(()); // Fully in sync — program nothing (idempotent).
        }

        let doc = crate::nft::render_chain_updates(TABLE_FAMILY, TABLE_NAME, &updates, &deletions);

        // Single atomic apply. On failure, return Err *without* confirming so the
        // framework retries with the desired state intact.
        self.applier
            .apply_document(&doc)
            .await
            .map_err(DataplaneError::new)?;

        // Commit: the kernel now matches desired for every touched chain.
        for c in &updates {
            self.chains.confirm_programmed(&c.name);
        }
        for name in &deletions {
            self.chains.confirm_programmed(name);
        }
        Ok(())
    }
}

/// `nft`-backed [`ChainApplier`] that feeds the per-chain document to `nft -f -`
/// via [`crate::nft::apply_ruleset`], off the async executor.
pub struct NftChainApplier;

#[async_trait::async_trait(?Send)]
impl ChainApplier for NftChainApplier {
    async fn apply_document(&self, doc: &str) -> Result<(), String> {
        let doc = doc.to_owned();
        tokio::task::spawn_blocking(move || crate::nft::apply_ruleset(&doc))
            .await
            .map_err(|e| format!("nft apply task join: {e}"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use proto::{TierInfo, WorkloadEndpoint};

    // ---- pure render tests (no manager, no kernel) ------------------------

    #[test]
    fn selector_peer_rule_renders_ip_saddr_set_match() {
        let rule = PolicyRule {
            action_field: Some(RuleAction::Allow),
            protocol: Some("TCP".into()),
            dst_ports: vec![80],
            src_ip_set_ids: vec!["s:frontend".into()],
            rule_id: Some("r0".into()),
            ..Default::default()
        };
        let rendered = render_rule(&rule);
        assert_eq!(rendered.len(), 1);
        let line = rendered[0].clone();
        assert_eq!(line.verdict, Verdict::Accept);
        let name = set_name_for("s:frontend");
        assert!(line.matches.contains(&NftMatch::SrcSet(name)));
        assert!(line.matches.contains(&NftMatch::L4Proto("tcp".into())));
        assert!(line.matches.contains(&NftMatch::DestPort(80)));
        assert_eq!(line.comment.as_deref(), Some("r0"));
    }

    #[test]
    fn dst_set_and_nets_and_ports_render() {
        let rule = PolicyRule {
            action_field: Some(RuleAction::Allow),
            src_nets: vec!["10.0.0.0/24".into()],
            dst_ip_set_ids: vec!["s:db".into()],
            ..Default::default()
        };
        let rendered = render_rule(&rule);
        assert_eq!(rendered.len(), 1);
        assert!(rendered[0]
            .matches
            .contains(&NftMatch::SrcAddr("10.0.0.0/24".into())));
        assert!(rendered[0]
            .matches
            .contains(&NftMatch::DestSet(set_name_for("s:db"))));
    }

    #[test]
    fn action_mapping_allow_deny_pass_log() {
        assert_eq!(map_action(RuleAction::Allow), Some(Verdict::Accept));
        assert_eq!(map_action(RuleAction::Deny), Some(Verdict::Drop));
        assert_eq!(map_action(RuleAction::Pass), Some(Verdict::Return));
        assert_eq!(map_action(RuleAction::Log), None);
        // A Log rule produces no nft rule at all.
        assert!(render_rule(&PolicyRule::action(RuleAction::Log)).is_empty());
    }

    #[test]
    fn cross_product_expands_nets_sets_and_ports() {
        // 2 sources (1 net + 1 set) × 2 dst ports = 4 rules.
        let rule = PolicyRule {
            action_field: Some(RuleAction::Deny),
            src_nets: vec!["10.0.0.0/24".into()],
            src_ip_set_ids: vec!["s:x".into()],
            dst_ports: vec![80, 443],
            ..Default::default()
        };
        let rendered = render_rule(&rule);
        assert_eq!(rendered.len(), 4);
        assert!(rendered.iter().all(|r| r.verdict == Verdict::Drop));
    }

    // ---- desired-chain structure tests ------------------------------------

    fn allow_from_set(set_id: &str) -> Policy {
        Policy {
            inbound_rules: vec![PolicyRule {
                action_field: Some(RuleAction::Allow),
                src_ip_set_ids: vec![set_id.into()],
                ..Default::default()
            }],
            outbound_rules: vec![],
        }
    }

    fn endpoint_with_ingress(iface: &str, tier: &str, policies: &[&str]) -> WorkloadEndpoint {
        WorkloadEndpoint {
            name: iface.into(),
            tiers: vec![TierInfo {
                name: tier.into(),
                ingress_policies: policies.iter().map(|s| s.to_string()).collect(),
                egress_policies: vec![],
            }],
            ..Default::default()
        }
    }

    #[derive(Clone, Default)]
    struct SpyApplier {
        docs: Rc<RefCell<Vec<String>>>,
        fail: Rc<RefCell<bool>>,
    }
    impl SpyApplier {
        fn last(&self) -> String {
            self.docs.borrow().last().cloned().unwrap_or_default()
        }
        fn clear(&self) {
            self.docs.borrow_mut().clear();
        }
        fn count(&self) -> usize {
            self.docs.borrow().len()
        }
        fn set_fail(&self, v: bool) {
            *self.fail.borrow_mut() = v;
        }
    }
    #[async_trait::async_trait(?Send)]
    impl ChainApplier for SpyApplier {
        async fn apply_document(&self, doc: &str) -> Result<(), String> {
            if *self.fail.borrow() {
                return Err("spy: injected failure".into());
            }
            self.docs.borrow_mut().push(doc.to_owned());
            Ok(())
        }
    }

    fn pol_update(tier: &str, name: &str, policy: Policy) -> ToDataplane {
        ToDataplane::ActivePolicyUpdate {
            id: PolicyId {
                tier: tier.into(),
                name: name.into(),
            },
            policy,
        }
    }
    fn wep_update(iface: &str, ep: WorkloadEndpoint) -> ToDataplane {
        ToDataplane::WorkloadEndpointUpdate {
            id: WorkloadEndpointId {
                orchestrator: "k8s".into(),
                workload: "ns/pod".into(),
                endpoint: iface.into(),
            },
            endpoint: ep,
        }
    }

    #[tokio::test]
    async fn endpoint_dispatch_jumps_policies_in_order_then_default_deny() {
        let spy = SpyApplier::default();
        let mut mgr = EndpointManager::new(spy.clone());

        mgr.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
        mgr.on_update(&pol_update("default", "allow-db", allow_from_set("s:db")));
        mgr.on_update(&wep_update(
            "cali123",
            endpoint_with_ingress("cali123", "default", &["allow-web", "allow-db"]),
        ));
        mgr.complete_deferred_work().await.unwrap();

        let doc = spy.last();
        // Per-policy chains with the resolved @set matches.
        assert!(doc.contains("add chain inet calico cali-pi-default-allow-web"));
        assert!(doc.contains(&format!(
            "add rule inet calico cali-pi-default-allow-web ip saddr @{} accept",
            set_name_for("s:web")
        )));
        // Dispatch chain jumps the two policies IN ORDER, then default-denies.
        let tw = "cali-tw-cali123";
        let jweb = doc
            .find(&format!(
                "add rule inet calico {tw} jump cali-pi-default-allow-web"
            ))
            .expect("jump to allow-web");
        let jdb = doc
            .find(&format!(
                "add rule inet calico {tw} jump cali-pi-default-allow-db"
            ))
            .expect("jump to allow-db");
        assert!(jweb < jdb, "policies jumped in tier order");
        assert!(doc.contains(&format!(
            "add rule inet calico {tw} drop comment \"default deny (ingress)\""
        )));
        // Base forward chain steers to-pod traffic to the dispatch chain.
        assert!(doc.contains(&format!(
            "add rule inet calico cali-forward oifname \"cali123\" jump {tw}"
        )));
        // NEVER a table flush (would wipe the T057 sets).
        assert!(!doc.contains("flush table"));
        assert!(!doc.contains("flush ruleset"));
    }

    #[tokio::test]
    async fn idempotent_reapply_programs_nothing() {
        let spy = SpyApplier::default();
        let mut mgr = EndpointManager::new(spy.clone());
        mgr.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
        mgr.on_update(&wep_update(
            "cali123",
            endpoint_with_ingress("cali123", "default", &["allow-web"]),
        ));
        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.count(), 1);

        spy.clear();
        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.count(), 0, "no change ⇒ no nft document at all");
    }

    #[tokio::test]
    async fn removing_endpoint_deletes_its_chains_not_the_table() {
        let spy = SpyApplier::default();
        let mut mgr = EndpointManager::new(spy.clone());
        mgr.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
        mgr.on_update(&wep_update(
            "cali123",
            endpoint_with_ingress("cali123", "default", &["allow-web"]),
        ));
        mgr.complete_deferred_work().await.unwrap();
        spy.clear();

        mgr.on_update(&ToDataplane::WorkloadEndpointRemove(WorkloadEndpointId {
            orchestrator: "k8s".into(),
            workload: "ns/pod".into(),
            endpoint: "cali123".into(),
        }));
        mgr.complete_deferred_work().await.unwrap();
        let doc = spy.last();
        assert!(doc.contains("delete chain inet calico cali-tw-cali123"));
        assert!(doc.contains("delete chain inet calico cali-forward"));
        assert!(!doc.contains("flush table"));
        assert!(!doc.contains("delete table"));
    }

    #[tokio::test]
    async fn failed_apply_retains_state_for_retry() {
        let spy = SpyApplier::default();
        let mut mgr = EndpointManager::new(spy.clone());
        mgr.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
        spy.set_fail(true);
        assert!(mgr.complete_deferred_work().await.is_err());
        assert!(mgr.pending_count() > 0, "state retained after failure");

        spy.set_fail(false);
        mgr.complete_deferred_work().await.unwrap();
        assert!(spy.last().contains("cali-pi-default-allow-web"));
        assert_eq!(mgr.pending_count(), 0, "reconciled after retry");
    }

    // ---- profile chain tests ---------------------------------------------

    fn allow_all_profile() -> Policy {
        Policy {
            inbound_rules: vec![PolicyRule {
                action_field: Some(RuleAction::Allow),
                ..Default::default()
            }],
            outbound_rules: vec![PolicyRule {
                action_field: Some(RuleAction::Allow),
                ..Default::default()
            }],
        }
    }

    fn prof_update(id: &str, profile: Policy) -> ToDataplane {
        ToDataplane::ActiveProfileUpdate {
            id: id.into(),
            profile,
        }
    }

    fn endpoint_with_profiles(iface: &str, profiles: &[&str]) -> WorkloadEndpoint {
        WorkloadEndpoint {
            name: iface.into(),
            profile_ids: profiles.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn default_allow_profile_jumps_profile_chain_not_bare_drop() {
        let spy = SpyApplier::default();
        let mut mgr = EndpointManager::new(spy.clone());

        // Open-by-default: per-namespace profile with ingress Allow, no policy.
        mgr.on_update(&prof_update("kns.nettest", allow_all_profile()));
        mgr.on_update(&wep_update(
            "cali123",
            endpoint_with_profiles("cali123", &["kns.nettest"]),
        ));
        mgr.complete_deferred_work().await.unwrap();

        let doc = spy.last();
        // Ingress profile chain rendered with an accept (open-by-default).
        assert!(doc.contains("add chain inet calico cali-pri-kns.nettest"));
        assert!(doc.contains("add rule inet calico cali-pri-kns.nettest accept"));

        // The to-workload dispatch chain JUMPS to the profile chain BEFORE its drop.
        let tw = "cali-tw-cali123";
        let jump = doc
            .find(&format!(
                "add rule inet calico {tw} jump cali-pri-kns.nettest"
            ))
            .expect("dispatch jumps to ingress profile chain");
        let drop = doc
            .find(&format!(
                "add rule inet calico {tw} drop comment \"default deny (ingress)\""
            ))
            .expect("dispatch still has final default deny");
        assert!(jump < drop, "profile jump precedes the default deny");
    }

    #[tokio::test]
    async fn profile_update_then_remove_renders_then_drops_chain() {
        let spy = SpyApplier::default();
        let mut mgr = EndpointManager::new(spy.clone());
        mgr.on_update(&prof_update("kns.nettest", allow_all_profile()));
        mgr.on_update(&wep_update(
            "cali123",
            endpoint_with_profiles("cali123", &["kns.nettest"]),
        ));
        mgr.complete_deferred_work().await.unwrap();
        assert!(spy.last().contains("cali-pri-kns.nettest accept"));
        spy.clear();

        // Removing the profile: the endpoint still references it, so a bare stub
        // chain remains (jump resolves), but its accept rule is gone → drop wins.
        mgr.on_update(&ToDataplane::ActiveProfileRemove("kns.nettest".into()));
        mgr.complete_deferred_work().await.unwrap();
        let doc = spy.last();
        assert!(
            !doc.contains("cali-pri-kns.nettest accept"),
            "accept rule gone after profile removed: {doc}"
        );
    }

    #[tokio::test]
    async fn policy_selected_endpoint_does_not_fall_through_to_profile() {
        // Isolation semantic: an endpoint selected by a policy in a direction ends
        // at the end-of-policy default-deny; profiles are NOT consulted. Here the
        // policy only allows from `s:web`; unmatched traffic must DROP, and must
        // NOT fall through to the default-allow profile.
        let spy = SpyApplier::default();
        let mut mgr = EndpointManager::new(spy.clone());
        mgr.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
        mgr.on_update(&prof_update("kns.nettest", allow_all_profile()));

        let mut ep = endpoint_with_ingress("cali123", "default", &["allow-web"]);
        ep.profile_ids = vec!["kns.nettest".into()];
        mgr.on_update(&wep_update("cali123", ep));
        mgr.complete_deferred_work().await.unwrap();

        let doc = spy.last();
        let tw = "cali-tw-cali123";
        // Ingress: the policy is jumped, then the default deny — no profile jump.
        assert!(
            doc.contains(&format!(
                "add rule inet calico {tw} jump cali-pi-default-allow-web"
            )),
            "ingress jumps the selecting policy: {doc}"
        );
        assert!(
            !doc.contains(&format!(
                "add rule inet calico {tw} jump cali-pri-kns.nettest"
            )),
            "policy-selected ingress must NOT fall through to the profile: {doc}"
        );
        assert!(
            doc.contains(&format!(
                "add rule inet calico {tw} drop comment \"default deny (ingress)\""
            )),
            "ingress still ends in default deny: {doc}"
        );
    }

    #[tokio::test]
    async fn policy_that_allows_is_jumped_profile_not() {
        // A policy that DOES allow the traffic: the policy chain accepts, and the
        // profile is still not jumped (selection, not verdict, gates the fallback).
        let spy = SpyApplier::default();
        let mut mgr = EndpointManager::new(spy.clone());
        mgr.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
        mgr.on_update(&prof_update("kns.nettest", allow_all_profile()));

        let mut ep = endpoint_with_ingress("cali123", "default", &["allow-web"]);
        ep.profile_ids = vec!["kns.nettest".into()];
        mgr.on_update(&wep_update("cali123", ep));
        mgr.complete_deferred_work().await.unwrap();

        let doc = spy.last();
        // The policy chain carries the accept for the allowed source.
        assert!(doc.contains(&format!(
            "add rule inet calico cali-pi-default-allow-web ip saddr @{} accept",
            set_name_for("s:web")
        )));
        // No profile jump in the policy-selected direction.
        assert!(
            !doc.contains("add rule inet calico cali-tw-cali123 jump cali-pri-kns.nettest"),
            "profile not jumped when a policy selects the endpoint: {doc}"
        );
    }

    #[tokio::test]
    async fn profile_fallback_is_per_direction() {
        // Per-direction independence: an ingress policy but NO egress policy.
        // Ingress = policy + drop (no profile). Egress has no policy, so it still
        // falls back to the profile chain + drop.
        let spy = SpyApplier::default();
        let mut mgr = EndpointManager::new(spy.clone());
        mgr.on_update(&pol_update("default", "allow-web", allow_from_set("s:web")));
        mgr.on_update(&prof_update("kns.nettest", allow_all_profile()));

        let mut ep = endpoint_with_ingress("cali123", "default", &["allow-web"]);
        ep.profile_ids = vec!["kns.nettest".into()];
        mgr.on_update(&wep_update("cali123", ep));
        mgr.complete_deferred_work().await.unwrap();

        let doc = spy.last();
        let tw = "cali-tw-cali123"; // ingress (to-workload)
        let fw = "cali-fw-cali123"; // egress (from-workload)

        // Ingress: policy jumped, profile NOT jumped.
        assert!(doc.contains(&format!(
            "add rule inet calico {tw} jump cali-pi-default-allow-web"
        )));
        assert!(
            !doc.contains(&format!(
                "add rule inet calico {tw} jump cali-pri-kns.nettest"
            )),
            "ingress is policy-governed → no profile fallback: {doc}"
        );

        // Egress: no policy → profile jumped as the fallback, before the drop.
        let prof = doc
            .find(&format!(
                "add rule inet calico {fw} jump cali-pro-kns.nettest"
            ))
            .expect("egress falls back to the profile chain");
        let drop = doc
            .find(&format!(
                "add rule inet calico {fw} drop comment \"default deny (egress)\""
            ))
            .expect("egress default deny");
        assert!(prof < drop, "egress profile jump precedes its default deny");
    }

    #[tokio::test]
    async fn endpoint_with_no_policy_or_profile_is_bare_drop() {
        let spy = SpyApplier::default();
        let mut mgr = EndpointManager::new(spy.clone());
        mgr.on_update(&wep_update(
            "cali123",
            endpoint_with_profiles("cali123", &[]),
        ));
        mgr.complete_deferred_work().await.unwrap();
        let doc = spy.last();
        // No jumps at all — the dispatch chain is just the default deny.
        assert!(!doc.contains("cali-tw-cali123 jump"));
        assert!(doc.contains(
            "add rule inet calico cali-tw-cali123 drop comment \"default deny (ingress)\""
        ));
    }

    #[tokio::test]
    async fn non_policy_messages_are_ignored() {
        let spy = SpyApplier::default();
        let mut mgr = EndpointManager::new(spy.clone());
        mgr.on_update(&ToDataplane::InSync);
        assert_eq!(mgr.policy_count(), 0);
        assert_eq!(mgr.endpoint_count(), 0);
        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.count(), 0);
    }
}
