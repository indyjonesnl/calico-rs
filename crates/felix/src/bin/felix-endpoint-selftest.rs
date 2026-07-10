//! Self-test: drive the felix `EndpointManager` against *real* nftables in the
//! current network namespace, proving the policy/endpoint chains coexist with the
//! `IpSetManager`'s named sets in the shared `inet calico` table — and, crucially,
//! that programming the chains does NOT flush the table and wipe the sets.
//!
//! Run inside a rootless netns (`unshare --user --map-root-user --net`); the
//! integration test (`tests/endpoint_netns.rs`) drives it. Exits 0 on success.
//!
//! It: programs a named set with a member via the `IpSetManager`; programs a proto
//! `Policy` (selector peer → `src_ip_set_ids`) + a `WorkloadEndpoint` referencing
//! it via the `EndpointManager`; reads back `nft list ruleset` and verifies the
//! policy chain, the `ip saddr @<set>` match, the dispatch chain + default-deny —
//! AND that the set + its member SURVIVE (no table flush). Then removes the
//! endpoint/policy and verifies the chains are gone while the set persists.

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("felix-endpoint-selftest FAILED: {e}");
        std::process::exit(1);
    }
    println!("felix-endpoint-selftest OK");
}

#[cfg(target_os = "linux")]
async fn run() -> Result<(), String> {
    use felix::dataplane::Manager;
    use felix::endpoint_manager::EndpointManager;
    use felix::ipset_manager::{set_name_for, IpSetManager};
    use felix::nft::list_ruleset;
    use proto::{
        IpSetKind, IpSetUpdate, Policy, PolicyId, PolicyRule, RuleAction, TierInfo, ToDataplane,
        WorkloadEndpoint, WorkloadEndpointId,
    };

    let set_id = "s:web";
    let set_name = set_name_for(set_id);
    let member = "10.0.0.5";

    // 1. Program a named set with a member (shared inet calico table).
    let mut ipsets = IpSetManager::with_nft();
    ipsets.on_update(&ToDataplane::IpSetUpdate(IpSetUpdate {
        id: set_id.into(),
        kind: IpSetKind::Ip,
        members: vec![member.into()],
    }));
    ipsets
        .complete_deferred_work()
        .await
        .map_err(|e| e.to_string())?;

    // 2. Program a policy (selector peer resolved to the set) + a workload
    //    endpoint referencing it, via the EndpointManager.
    let mut eps = EndpointManager::with_nft();
    let policy = Policy {
        inbound_rules: vec![PolicyRule {
            action_field: Some(RuleAction::Allow),
            protocol: Some("TCP".into()),
            dst_ports: vec![80],
            src_ip_set_ids: vec![set_id.into()],
            rule_id: Some("r0".into()),
            ..Default::default()
        }],
        outbound_rules: vec![],
    };
    eps.on_update(&ToDataplane::ActivePolicyUpdate {
        id: PolicyId {
            tier: "default".into(),
            name: "allow-web".into(),
        },
        policy,
    });
    let iface = "cali12345";
    eps.on_update(&ToDataplane::WorkloadEndpointUpdate {
        id: WorkloadEndpointId {
            orchestrator: "k8s".into(),
            workload: "ns/pod".into(),
            endpoint: iface.into(),
        },
        endpoint: WorkloadEndpoint {
            name: iface.into(),
            tiers: vec![TierInfo {
                name: "default".into(),
                ingress_policies: vec!["allow-web".into()],
                egress_policies: vec![],
            }],
            ..Default::default()
        },
    });
    eps.complete_deferred_work()
        .await
        .map_err(|e| e.to_string())?;

    // 3. Verify: chains + @set match present, AND the set + member survived.
    let listed = list_ruleset()?;
    for needle in [
        "chain cali-pi-default-allow-web",
        "chain cali-tw-cali12345",
        "chain cali-forward",
        &format!("@{set_name}"), // the resolved set-match in the policy chain
        "jump cali-pi-default-allow-web",
        &format!("oifname \"{iface}\""),
        "dport 80",
        "drop",
    ] {
        if !listed.contains(needle) {
            return Err(format!(
                "programmed policy missing {needle:?}; got:\n{listed}"
            ));
        }
    }
    // The proof: programming the chains must NOT have wiped the set.
    if !listed.contains(&set_name) {
        return Err(format!(
            "the named set {set_name:?} was WIPED by chain programming (table flush?); got:\n{listed}"
        ));
    }
    if !listed.contains(member) {
        return Err(format!("set member {member:?} vanished; got:\n{listed}"));
    }

    // 4. Idempotent re-apply: nothing changed ⇒ no error (and no wipe).
    eps.complete_deferred_work()
        .await
        .map_err(|e| e.to_string())?;
    if !list_ruleset()?.contains(&set_name) {
        return Err("set vanished after idempotent re-apply".into());
    }

    // 5. Remove the endpoint + policy: their chains go, the set stays.
    eps.on_update(&ToDataplane::WorkloadEndpointRemove(WorkloadEndpointId {
        orchestrator: "k8s".into(),
        workload: "ns/pod".into(),
        endpoint: iface.into(),
    }));
    eps.on_update(&ToDataplane::ActivePolicyRemove(PolicyId {
        tier: "default".into(),
        name: "allow-web".into(),
    }));
    eps.complete_deferred_work()
        .await
        .map_err(|e| e.to_string())?;

    let listed = list_ruleset()?;
    if listed.contains("chain cali-tw-cali12345") {
        return Err(format!(
            "dispatch chain still present after remove:\n{listed}"
        ));
    }
    if listed.contains("chain cali-pi-default-allow-web") {
        return Err(format!(
            "policy chain still present after remove:\n{listed}"
        ));
    }
    if !listed.contains(&set_name) {
        return Err("the named set must survive endpoint/policy teardown".into());
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("felix-endpoint-selftest only runs on Linux");
    std::process::exit(2);
}
