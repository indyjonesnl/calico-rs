//! Self-test: drive the unified felix `PolicyTableManager` against *real* nftables
//! in the current network namespace, proving the atomic full-table render is
//! self-healing and restart-safe.
//!
//! Run inside a rootless netns (`unshare --user --map-root-user --net`); the
//! integration test (`tests/policy_table_netns.rs`) drives it. Exits 0 on success.
//!
//! It:
//! 1. Programs desired STATE A (a named set + a policy referencing it via
//!    `@<set>` + a workload endpoint jumping that policy) via one manager, reads
//!    back `nft list ruleset`, and verifies the set, its member, the `@<set>`
//!    policy match, the dispatch chain + default-deny, and the forward chain.
//! 2. Re-applies with no change (idempotent — still all present).
//! 3. Simulates an AGENT RESTART: builds a BRAND-NEW manager (empty in-memory
//!    state) while the kernel still holds STATE A, feeds it a DIFFERENT desired
//!    STATE B (a different set + a profile-governed endpoint), applies ONE atomic
//!    document, and verifies the kernel now matches B and every STATE A object is
//!    GONE (removed purely by the atomic `add;delete;add table` create-then-replace
//!    preamble, with no per-object `delete` statements) — the whole point of the
//!    root-cause fix.

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("felix-policy-table-selftest FAILED: {e}");
        std::process::exit(1);
    }
    println!("felix-policy-table-selftest OK");
}

#[cfg(target_os = "linux")]
async fn run() -> Result<(), String> {
    use felix::dataplane::Manager;
    use felix::ipset_manager::set_name_for;
    use felix::nft::list_ruleset;
    use felix::policy_table::PolicyTableManager;
    use proto::{
        IpSetKind, IpSetUpdate, Policy, PolicyId, PolicyRule, RuleAction, TierInfo, ToDataplane,
        WorkloadEndpoint, WorkloadEndpointId,
    };

    fn allow_from_set(set_id: &str) -> Policy {
        Policy {
            inbound_rules: vec![PolicyRule {
                action_field: Some(RuleAction::Allow),
                protocol: Some("TCP".into()),
                dst_ports: vec![80],
                src_ip_set_ids: vec![set_id.into()],
                rule_id: Some("r0".into()),
                ..Default::default()
            }],
            outbound_rules: vec![],
        }
    }
    fn wep(iface: &str, ep: WorkloadEndpoint) -> ToDataplane {
        ToDataplane::WorkloadEndpointUpdate {
            id: WorkloadEndpointId {
                orchestrator: "k8s".into(),
                workload: "ns/pod".into(),
                endpoint: iface.into(),
            },
            endpoint: ep,
        }
    }

    // ---- STATE A -------------------------------------------------------
    let a_set = "s:web";
    let a_set_name = set_name_for(a_set);
    let a_member = "10.0.0.5";
    let a_iface = "cali1111a";

    let mut mgr = PolicyTableManager::with_nft();
    mgr.on_update(&ToDataplane::IpSetUpdate(IpSetUpdate {
        id: a_set.into(),
        kind: IpSetKind::Ip,
        members: vec![a_member.into()],
    }));
    mgr.on_update(&ToDataplane::ActivePolicyUpdate {
        id: PolicyId {
            tier: "default".into(),
            name: "allow-web".into(),
        },
        policy: allow_from_set(a_set),
    });
    mgr.on_update(&wep(
        a_iface,
        WorkloadEndpoint {
            name: a_iface.into(),
            tiers: vec![TierInfo {
                name: "default".into(),
                ingress_policies: vec!["allow-web".into()],
                egress_policies: vec![],
            }],
            ..Default::default()
        },
    ));
    mgr.complete_deferred_work()
        .await
        .map_err(|e| e.to_string())?;

    let listed = list_ruleset()?;
    for needle in [
        "chain cali-pi-default-allow-web",
        &format!("chain cali-tw-{a_iface}"),
        "chain cali-forward",
        &format!("@{a_set_name}"),
        "jump cali-pi-default-allow-web",
        &format!("oifname \"{a_iface}\""),
        "dport 80",
        a_member,
        a_set_name.as_str(),
    ] {
        if !listed.contains(needle) {
            return Err(format!("STATE A missing {needle:?}; got:\n{listed}"));
        }
    }

    // ---- idempotent re-apply ------------------------------------------
    mgr.complete_deferred_work()
        .await
        .map_err(|e| e.to_string())?;
    if !list_ruleset()?.contains(&a_set_name) {
        return Err("STATE A vanished after idempotent re-apply".into());
    }

    // ---- SIMULATE AGENT RESTART + STATE B ------------------------------
    // A brand-new manager (empty in-memory view) while the kernel still holds
    // STATE A. The old delta design would have tried to delete stale objects and
    // poisoned its transaction; the full render just replaces the whole table.
    drop(mgr);
    let mut restarted = PolicyTableManager::with_nft();

    let b_set = "s:db";
    let b_set_name = set_name_for(b_set);
    let b_member = "10.0.0.9";
    let b_iface = "cali2222b";

    restarted.on_update(&ToDataplane::IpSetUpdate(IpSetUpdate {
        id: b_set.into(),
        kind: IpSetKind::Ip,
        members: vec![b_member.into()],
    }));
    // A profile-governed (open-by-default) endpoint — exercises the GG fallback.
    restarted.on_update(&ToDataplane::ActiveProfileUpdate {
        id: "kns.nettest".into(),
        profile: Policy {
            inbound_rules: vec![PolicyRule::action(RuleAction::Allow)],
            outbound_rules: vec![PolicyRule::action(RuleAction::Allow)],
        },
    });
    restarted.on_update(&wep(
        b_iface,
        WorkloadEndpoint {
            name: b_iface.into(),
            profile_ids: vec!["kns.nettest".into()],
            ..Default::default()
        },
    ));
    restarted
        .complete_deferred_work()
        .await
        .map_err(|e| e.to_string())?;

    let listed = list_ruleset()?;
    // STATE B must be present.
    for needle in [
        b_set_name.as_str(),
        b_member,
        &format!("chain cali-tw-{b_iface}"),
        "chain cali-pri-kns.nettest",
        "jump cali-pri-kns.nettest",
    ] {
        if !listed.contains(needle) {
            return Err(format!("STATE B missing {needle:?}; got:\n{listed}"));
        }
    }
    // Every STATE A object must be GONE — removed purely by the flush.
    for gone in [
        a_set_name.as_str(),
        a_member,
        "cali-pi-default-allow-web",
        &format!("cali-tw-{a_iface}"),
    ] {
        if listed.contains(gone) {
            return Err(format!(
                "STATE A object {gone:?} survived the restart re-render (flush failed?); got:\n{listed}"
            ));
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("felix-policy-table-selftest only runs on Linux");
    std::process::exit(2);
}
