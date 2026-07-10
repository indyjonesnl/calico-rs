//! Pure policy/endpoint chain rendering for the unified policy dataplane.
//!
//! These functions translate the calc graph's *resolved* proto policies,
//! profiles and workload endpoints into the nftables chain model
//! ([`crate::nft::NftChain`]): per-policy chains, per-profile chains, per-endpoint
//! dispatch chains (with Calico's default-deny and the "GG" profile-fallback
//! semantics), and the `cali-forward` base hook chain. They carry NO dataplane
//! state and program nothing themselves — the single table-owning
//! [`crate::policy_table::PolicyTableManager`] calls [`build_desired_chains`] and
//! renders the whole `inet calico` table in one atomic `nft -f -` document.
//!
//! Modelled on upstream `felix/dataplane/linux/endpoint_mgr.go` + `rules/policy.go`.
//! Proto-driven: the calc graph has already resolved selectors to IP-set ids, so a
//! [`proto::PolicyRule`] carries `src_ip_set_ids`/`dst_ip_set_ids` that map directly
//! to `ip saddr @<set>` / `ip daddr @<set>` matches against the named sets rendered
//! by [`crate::ipset_manager`] (via the identical [`crate::ipset_manager::set_name_for`]).
//!
//! ## History (why this used to be a manager)
//!
//! This module previously hosted an `EndpointManager` — the second of *two*
//! separate `InternalDataplane` managers, applying per-chain `add/flush/delete`
//! deltas in its own transaction. Splitting sets (the other manager) and chains
//! across two delta transactions produced cross-manager `@set` ordering races and
//! restart poisoning. It was replaced by the unified full-render
//! [`crate::policy_table`] manager, which reuses the *pure* rendering below.
//!
//! ## Chain structure (what gets rendered)
//!
//! - **Per-policy chain** `cali-pi-<tier>-<name>` (ingress) / `cali-po-<tier>-<name>`
//!   (egress): the translated rules only. A rule falls through (implicit `return`)
//!   when it does not match. Action mapping reproduces Calico's **accept-mark**
//!   pattern so an ALLOW is NON-terminal: `Allow→set` the accept mark + `return`,
//!   `Deny→drop`, `Pass→return`, `Log→`(skipped). See [`map_action`] /
//!   [`crate::nft::ACCEPT_MARK`].
//! - **Per-profile chain** `cali-pri-<id>` (ingress) / `cali-pro-<id>` (egress):
//!   the translated profile rules (same accept-mark ALLOW), NO trailing drop.
//!   Calico's open-by-default is the per-namespace `kns.<ns>` allow-all profile.
//! - **Per-endpoint dispatch chain** `cali-tw-<iface>` (to-workload / ingress) and
//!   `cali-fw-<iface>` (from-workload / egress): **clear the accept mark on entry**;
//!   `jump` each of the endpoint's tier policies in order, each followed by a
//!   `return`-if-accept-mark-set; then, **only if no policy selects the endpoint in
//!   that direction**, `jump` its profiles the same way (the open-by-default
//!   fallback); then a terminal `drop` (Calico's per-endpoint default-deny). A
//!   policy-selected endpoint ends at the end-of-policy drop and does NOT fall
//!   through to its profiles — gated per-direction (ingress/egress independent).
//! - **Base dispatch chain** `cali-forward` (filter/forward hook): for each
//!   endpoint, `oifname <iface> jump cali-tw-<iface>` (traffic *to* the pod) and
//!   `iifname <iface> jump cali-fw-<iface>` (traffic *from* the pod). It jumps BOTH
//!   directions for a forwarded packet and accepts only via its fall-through
//!   `policy accept`, after both direction chains `return`ed — so an ALLOW in one
//!   direction cannot short-circuit the other's enforcement.
//!
//! ### Multi-tier simplification (documented, per the US2 target)
//!
//! The dispatch chain flattens all of an endpoint's tiers into one ordered list of
//! policy jumps, then the endpoint's profile jumps, followed by a single
//! end-of-endpoint default-deny. Per-tier `pass`/`next-tier` fall-through is a
//! follow-up.

use std::collections::BTreeMap;

use proto::{Policy, PolicyId, PolicyRule, RuleAction, WorkloadEndpoint, WorkloadEndpointId};

use crate::ipset_manager::set_name_for;
use crate::nft::{BaseHook, ChainType, NftChain, NftMatch, NftRule, Verdict};

/// The base chain that steers workload traffic to per-endpoint dispatch chains.
pub(crate) const FORWARD_CHAIN: &str = "cali-forward";

/// Which direction a policy chain enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    Ingress,
    Egress,
}

/// Map a proto [`RuleAction`] to an nft [`Verdict`], reproducing Calico's
/// accept-mark semantics so an ALLOW is NON-terminal.
///
/// A policy/profile chain is jumped from a per-endpoint direction chain, which is in
/// turn jumped from `cali-forward` for BOTH directions of a forwarded packet. If an
/// ALLOW rendered as a terminal `accept`, the first direction to match would end the
/// whole `cali-forward` traversal and the other direction's policy would never run.
/// So:
/// - `Allow` → set the [`crate::nft::ACCEPT_MARK`] and `return`
///   ([`Verdict::SetAcceptMarkReturn`], non-terminal): the calling dispatch chain
///   sees the mark and returns, letting the other direction still be evaluated;
///   acceptance is only `cali-forward`'s fall-through after both directions passed.
/// - `Deny` → `drop` (the only terminal verdict).
/// - `Pass` → `return` (no mark) — fall through to the next tier/profile handling.
/// - `Log` → no terminal verdict in this subset (`None`, skipped).
pub(crate) fn map_action(action: RuleAction) -> Option<Verdict> {
    match action {
        RuleAction::Allow => Some(Verdict::SetAcceptMarkReturn),
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
/// `cali-pro-kns.nettest` (egress). Profiles are tier-less, so the id is the sole
/// discriminator. Profile ids (e.g. `kns.nettest`) carry a `.` that nft accepts
/// unquoted and that Calico preserves in the chain name, so keep it.
fn profile_chain_name(id: &str, dir: Direction) -> String {
    let prefix = match dir {
        Direction::Ingress => "cali-pri",
        Direction::Egress => "cali-pro",
    };
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
pub(crate) fn render_rule(rule: &PolicyRule) -> Vec<NftRule> {
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

/// The full desired chain set derived from the desired policies + profiles +
/// endpoints. Deterministic (`BTreeMap` keys), depending ONLY on the passed state
/// — so re-running on identical desired state yields an identical chain set (and,
/// once rendered, a byte-identical document).
pub(crate) fn build_desired_chains(
    policies: &BTreeMap<PolicyId, Policy>,
    profiles: &BTreeMap<String, Policy>,
    endpoints: &BTreeMap<WorkloadEndpointId, WorkloadEndpoint>,
) -> BTreeMap<String, NftChain> {
    let mut chains: BTreeMap<String, NftChain> = BTreeMap::new();

    // 1. Per-policy chains (ingress + egress) from the resolved proto rules.
    for (id, policy) in policies {
        let iname = policy_chain_name(id, Direction::Ingress);
        let irules = policy.inbound_rules.iter().flat_map(render_rule).collect();
        chains.insert(iname.clone(), NftChain::regular(iname, irules));

        let ename = policy_chain_name(id, Direction::Egress);
        let erules = policy.outbound_rules.iter().flat_map(render_rule).collect();
        chains.insert(ename.clone(), NftChain::regular(ename, erules));
    }

    // 2. Per-profile chains (ingress + egress). NO trailing drop: a profile Allow
    //    accepts, otherwise control falls through to the endpoint chain's
    //    end-of-endpoint default-deny (open-by-default comes from the per-namespace
    //    `kns.<ns>` allow-all profile).
    for (id, profile) in profiles {
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
    for ep in endpoints.values() {
        let iface = &ep.name;

        let tw = dispatch_chain_name(iface, Direction::Ingress);
        let tw_rules = dispatch_rules(ep, Direction::Ingress, &mut chains);
        chains.insert(tw.clone(), NftChain::regular(tw.clone(), tw_rules));
        forward_rules
            .push(NftRule::new(Verdict::Jump(tw)).with(NftMatch::OutInterface(iface.clone())));

        let fw = dispatch_chain_name(iface, Direction::Egress);
        let fw_rules = dispatch_rules(ep, Direction::Egress, &mut chains);
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

/// The rules for one endpoint's dispatch chain, implementing Calico's accept-mark
/// semantics (see [`crate::nft::ACCEPT_MARK`] and [`map_action`]):
///
/// 1. **Clear the accept mark on entry.** `cali-forward` jumps BOTH this endpoint's
///    direction chains for one forwarded packet, so a mark set while the packet
///    traversed the *other* direction's chain would still be set here — clearing it
///    makes this chain's verdict depend only on its own policies/profiles.
/// 2. **Jump each tier policy in order** (flattening tiers); after each jump, a
///    `return` guarded by "accept mark set" — as soon as one policy ALLOWs (sets the
///    mark + returns to here), we return to `cali-forward` so the *other* direction
///    is still evaluated. A DENY inside the policy chain `drop`s outright.
/// 3. **Only when NO policy selects the endpoint in this direction**, fall back to
///    the profile chains the same way (Calico's open-by-default `kns.<ns>` allow
///    profile) — the GG rule, now expressed via the mark: a policy-selected endpoint
///    reaches the default-deny below without consulting profiles.
/// 4. **End-of-endpoint default-deny `drop`** — reached only when nothing set the
///    accept mark (no ALLOW matched).
///
/// Ensures a (possibly empty stub) chain exists for every referenced policy — and
/// every jumped profile — so all jumps resolve. The gating is per-direction: an
/// endpoint may be policy-governed on ingress yet fall back to profiles on egress.
fn dispatch_rules(
    ep: &WorkloadEndpoint,
    dir: Direction,
    chains: &mut BTreeMap<String, NftChain>,
) -> Vec<NftRule> {
    // A `return` taken only when a jumped policy/profile chain set the accept mark
    // (i.e. this direction ALLOWed) — non-terminal so the other direction still runs.
    let return_if_accepted = || NftRule::new(Verdict::Return).with(NftMatch::AcceptMarkSet);

    let mut rules = Vec::new();
    // 1. Clear any accept mark leaked from the other direction's chain.
    rules.push(NftRule::new(Verdict::ClearAcceptMark));

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
            // Stub an empty chain for a referenced-but-unknown policy so the jump
            // resolves; an empty chain falls through (no mark) to the default-deny.
            chains
                .entry(cn.clone())
                .or_insert_with(|| NftChain::regular(cn.clone(), Vec::new()));
            rules.push(NftRule::new(Verdict::Jump(cn)));
            // 2. Return as soon as a policy allowed (first-match-wins within the
            //    direction; a later policy must not override an earlier ALLOW).
            rules.push(return_if_accepted());
            policy_selected = true;
        }
    }
    // 3. Profile fallback — ONLY when no policy selects this endpoint in this
    //    direction (the GG rule). If ≥1 policy selected it, control falls through to
    //    the end-of-policy default-deny below without consulting any profile.
    if !policy_selected {
        for prof in &ep.profile_ids {
            let cn = profile_chain_name(prof, dir);
            chains
                .entry(cn.clone())
                .or_insert_with(|| NftChain::regular(cn.clone(), Vec::new()));
            rules.push(NftRule::new(Verdict::Jump(cn)));
            rules.push(return_if_accepted());
        }
    }
    // 4. End-of-endpoint default-deny (reached only if nothing set the accept mark).
    let dir_label = match dir {
        Direction::Ingress => "ingress",
        Direction::Egress => "egress",
    };
    rules.push(NftRule::new(Verdict::Drop).comment(format!("default deny ({dir_label})")));
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::TierInfo;

    // ---- pure render tests ------------------------------------------------

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
        // ALLOW is non-terminal (set accept mark + return), NOT a terminal accept.
        assert_eq!(line.verdict, Verdict::SetAcceptMarkReturn);
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
        // ALLOW must be NON-terminal (accept-mark + return) so a forwarded packet
        // keeps traversing the other direction's chain; only DENY is terminal (drop).
        assert_eq!(
            map_action(RuleAction::Allow),
            Some(Verdict::SetAcceptMarkReturn)
        );
        assert_eq!(map_action(RuleAction::Deny), Some(Verdict::Drop));
        assert_eq!(map_action(RuleAction::Pass), Some(Verdict::Return));
        assert_eq!(map_action(RuleAction::Log), None);
        assert!(render_rule(&PolicyRule::action(RuleAction::Log)).is_empty());
    }

    // ---- dispatch chain accept-mark composition ---------------------------

    /// A dispatch chain for a policy-selected endpoint: clear the accept mark on
    /// entry, jump the policy, `return` if the policy set the accept mark, then the
    /// end-of-policy default deny. No terminal `accept`; profiles NOT consulted.
    #[test]
    fn dispatch_chain_uses_accept_mark_not_terminal_accept() {
        let mut chains: BTreeMap<String, NftChain> = BTreeMap::new();
        let mut ep = WorkloadEndpoint {
            name: "cali123".into(),
            tiers: vec![TierInfo {
                name: "default".into(),
                ingress_policies: vec!["allow-web".into()],
                egress_policies: vec![],
            }],
            ..Default::default()
        };
        ep.profile_ids = vec!["kns.nettest".into()];
        let rules = dispatch_rules(&ep, Direction::Ingress, &mut chains);

        // First rule clears the accept mark (independence from the other direction).
        assert_eq!(rules[0].verdict, Verdict::ClearAcceptMark);
        // The jump to the selecting policy, then a return-if-accepted.
        let jump = NftRule::new(Verdict::Jump("cali-pi-default-allow-web".into()));
        let ret = NftRule::new(Verdict::Return).with(NftMatch::AcceptMarkSet);
        let jump_i = rules.iter().position(|r| *r == jump).expect("policy jump");
        let ret_i = rules
            .iter()
            .position(|r| *r == ret)
            .expect("return-if-accepted after the jump");
        assert!(jump_i < ret_i, "return-if-accepted follows the policy jump");
        // No terminal accept anywhere in the chain.
        assert!(rules.iter().all(|r| r.verdict != Verdict::Accept));
        // Ends with the default-deny drop; profile NOT jumped (policy selected).
        assert_eq!(rules.last().unwrap().verdict, Verdict::Drop);
        assert!(!rules
            .iter()
            .any(|r| r.verdict == Verdict::Jump("cali-pri-kns.nettest".into())));
    }

    /// No policy in this direction ⇒ fall back to the profile chain (open-by-default),
    /// still via set-mark/return-if-accepted, then default deny.
    #[test]
    fn dispatch_chain_profile_fallback_uses_accept_mark() {
        let mut chains: BTreeMap<String, NftChain> = BTreeMap::new();
        let ep = WorkloadEndpoint {
            name: "cali123".into(),
            profile_ids: vec!["kns.nettest".into()],
            ..Default::default()
        };
        let rules = dispatch_rules(&ep, Direction::Ingress, &mut chains);
        assert_eq!(rules[0].verdict, Verdict::ClearAcceptMark);
        let jump = NftRule::new(Verdict::Jump("cali-pri-kns.nettest".into()));
        let ret = NftRule::new(Verdict::Return).with(NftMatch::AcceptMarkSet);
        let jump_i = rules.iter().position(|r| *r == jump).expect("profile jump");
        let ret_i = rules
            .iter()
            .position(|r| *r == ret)
            .expect("return-if-accepted");
        assert!(jump_i < ret_i);
        assert_eq!(rules.last().unwrap().verdict, Verdict::Drop);
        assert!(rules.iter().all(|r| r.verdict != Verdict::Accept));
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
}
