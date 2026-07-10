//! Self-test / regression for the forward-path policy-chain semantics fix: an
//! ALLOW must be NON-terminal (accept-mark + return) so that BOTH direction chains
//! are evaluated for a forwarded pod→pod packet.
//!
//! It builds a real two-pod forwarding topology inside a rootless net+mount
//! namespace and drives the actual [`felix::policy_table::PolicyTableManager`]
//! against real nftables:
//!
//! ```text
//!   ns1 (src pod 10.0.0.1) --vsrc--[cali-src]  router  [cali-dst]--vdst-- ns2 (dst pod 10.0.1.1)
//! ```
//!
//! A packet src→dst is forwarded through the router: it enters on `cali-src`
//! (so `cali-forward` runs `iifname cali-src jump cali-fw-cali-src` — the SOURCE
//! EGRESS chain) and leaves on `cali-dst` (`oifname cali-dst jump cali-tw-cali-dst`
//! — the DEST INGRESS chain). The source's egress is open-by-default (a profile
//! ALLOW), and the dest's ingress is governed by a policy that (initially) does NOT
//! admit the source.
//!
//! - **DENY:** the source-egress ALLOW must NOT let the packet through; the
//!   dest-ingress policy default-denies it. `ping` must FAIL. (Under the old
//!   terminal-`accept` bug the egress ALLOW ended the `cali-forward` traversal and
//!   the ingress DROP was never reached, so `ping` wrongly SUCCEEDED.)
//! - **ALLOW:** add the source IP to the policy's allowed set → `ping` SUCCEEDS
//!   (and the return path is open-by-default in both directions).
//!
//! Exit codes: 0 = pass, 1 = failure (the bug), 2 = SKIP (environment can't build
//! the topology — e.g. no mount/netns permission). The integration test
//! (`tests/policy_forward_netns.rs`) runs this under `unshare` and treats 2 as skip.

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(run());
}

#[cfg(target_os = "linux")]
fn run() -> i32 {
    use std::process::Command;

    // Run a command, returning Ok(()) on success or Err(stderr) otherwise.
    fn sh(prog: &str, args: &[&str]) -> Result<(), String> {
        let out = Command::new(prog)
            .args(args)
            .output()
            .map_err(|e| format!("spawn {prog}: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{prog} {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    // ---- build the forwarding topology (skip on any setup failure) --------
    // `ip netns add` needs a writable /run/netns; in a rootless mount namespace we
    // get one by mounting a fresh tmpfs over /run. If this fails we cannot build the
    // topology here → SKIP rather than fail.
    let setup = || -> Result<(), String> {
        sh("mount", &["-t", "tmpfs", "none", "/run"])?;
        std::fs::create_dir_all("/run/netns").map_err(|e| format!("mkdir /run/netns: {e}"))?;
        sh("ip", &["netns", "add", "ns1"])?;
        sh("ip", &["netns", "add", "ns2"])?;
        sh(
            "ip",
            &[
                "link", "add", "cali-src", "type", "veth", "peer", "name", "vsrc",
            ],
        )?;
        sh(
            "ip",
            &[
                "link", "add", "cali-dst", "type", "veth", "peer", "name", "vdst",
            ],
        )?;
        sh("ip", &["link", "set", "vsrc", "netns", "ns1"])?;
        sh("ip", &["link", "set", "vdst", "netns", "ns2"])?;
        sh("ip", &["addr", "add", "10.0.0.254/24", "dev", "cali-src"])?;
        sh("ip", &["link", "set", "cali-src", "up"])?;
        sh("ip", &["addr", "add", "10.0.1.254/24", "dev", "cali-dst"])?;
        sh("ip", &["link", "set", "cali-dst", "up"])?;
        sh(
            "ip",
            &["-n", "ns1", "addr", "add", "10.0.0.1/24", "dev", "vsrc"],
        )?;
        sh("ip", &["-n", "ns1", "link", "set", "vsrc", "up"])?;
        sh("ip", &["-n", "ns1", "link", "set", "lo", "up"])?;
        sh(
            "ip",
            &["-n", "ns1", "route", "add", "default", "via", "10.0.0.254"],
        )?;
        sh(
            "ip",
            &["-n", "ns2", "addr", "add", "10.0.1.1/24", "dev", "vdst"],
        )?;
        sh("ip", &["-n", "ns2", "link", "set", "vdst", "up"])?;
        sh("ip", &["-n", "ns2", "link", "set", "lo", "up"])?;
        sh(
            "ip",
            &["-n", "ns2", "route", "add", "default", "via", "10.0.1.254"],
        )?;
        sh("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
        Ok(())
    };
    if let Err(e) = setup() {
        eprintln!("felix-policy-forward-selftest SKIP: cannot build topology: {e}");
        return 2;
    }

    // Sanity: forwarding must work with NO calico table (else the test is moot).
    if ping_src_to_dst().is_err() {
        eprintln!("felix-policy-forward-selftest SKIP: baseline forwarding does not work here");
        return 2;
    }

    // ---- program the real PolicyTableManager, then assert enforcement -----
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt.block_on(assert_both_directions_enforced()),
        Err(e) => {
            eprintln!("felix-policy-forward-selftest FAILED: build runtime: {e}");
            1
        }
    }
}

/// Ping ns1(10.0.0.1) → ns2(10.0.1.1) once; Ok if a reply arrived.
#[cfg(target_os = "linux")]
fn ping_src_to_dst() -> Result<(), ()> {
    use std::process::Command;
    let ok = Command::new("ip")
        .args([
            "netns", "exec", "ns1", "ping", "-c", "1", "-W", "1", "10.0.1.1",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(target_os = "linux")]
async fn assert_both_directions_enforced() -> i32 {
    use felix::dataplane::Manager;
    use felix::policy_table::PolicyTableManager;
    use proto::{
        IpSetKind, IpSetUpdate, Policy, PolicyId, PolicyRule, RuleAction, TierInfo, ToDataplane,
        WorkloadEndpoint, WorkloadEndpointId,
    };

    fn wep(iface: &str, ep: WorkloadEndpoint) -> ToDataplane {
        ToDataplane::WorkloadEndpointUpdate {
            id: WorkloadEndpointId {
                orchestrator: "k8s".into(),
                workload: format!("ns/{iface}"),
                endpoint: iface.into(),
            },
            endpoint: ep,
        }
    }

    let mut mgr = PolicyTableManager::with_nft();

    // Open-by-default profile (allow all, both directions).
    mgr.on_update(&ToDataplane::ActiveProfileUpdate {
        id: "open".into(),
        profile: Policy {
            inbound_rules: vec![PolicyRule::action(RuleAction::Allow)],
            outbound_rules: vec![PolicyRule::action(RuleAction::Allow)],
        },
    });
    // Dest ingress policy: allow ONLY from the (initially empty) `s:allowed` set.
    mgr.on_update(&ToDataplane::IpSetUpdate(IpSetUpdate {
        id: "s:allowed".into(),
        kind: IpSetKind::Ip,
        members: vec![],
    }));
    mgr.on_update(&ToDataplane::ActivePolicyUpdate {
        id: PolicyId {
            tier: "default".into(),
            name: "allow-listed".into(),
        },
        policy: Policy {
            inbound_rules: vec![PolicyRule {
                action_field: Some(RuleAction::Allow),
                src_ip_set_ids: vec!["s:allowed".into()],
                ..Default::default()
            }],
            outbound_rules: vec![],
        },
    });
    // Source pod: profile-governed both directions (egress open-by-default).
    mgr.on_update(&wep(
        "cali-src",
        WorkloadEndpoint {
            name: "cali-src".into(),
            profile_ids: vec!["open".into()],
            ..Default::default()
        },
    ));
    // Dest pod: ingress governed by the policy; egress open-by-default (return path).
    mgr.on_update(&wep(
        "cali-dst",
        WorkloadEndpoint {
            name: "cali-dst".into(),
            profile_ids: vec!["open".into()],
            tiers: vec![TierInfo {
                name: "default".into(),
                ingress_policies: vec!["allow-listed".into()],
                egress_policies: vec![],
            }],
            ..Default::default()
        },
    ));

    if let Err(e) = mgr.complete_deferred_work().await {
        eprintln!("felix-policy-forward-selftest FAILED: apply (deny state): {e}");
        return 1;
    }

    // DENY: source egress ALLOWs (profile), but dest ingress must DROP the packet.
    // The whole point of the fix: the egress ALLOW must NOT short-circuit ingress.
    if ping_src_to_dst().is_ok() {
        eprintln!(
            "felix-policy-forward-selftest FAILED: src→dst was ALLOWED despite the dst \
             ingress default-deny — the source-egress ALLOW short-circuited ingress \
             (the terminal-accept bug)."
        );
        return 1;
    }
    println!("felix-policy-forward-selftest: DENY scenario OK (dst ingress dropped the packet)");

    // ALLOW: add the source IP to the policy's allowed set → now admitted.
    mgr.on_update(&ToDataplane::IpSetUpdate(IpSetUpdate {
        id: "s:allowed".into(),
        kind: IpSetKind::Ip,
        members: vec!["10.0.0.1".into()],
    }));
    if let Err(e) = mgr.complete_deferred_work().await {
        eprintln!("felix-policy-forward-selftest FAILED: apply (allow state): {e}");
        return 1;
    }
    if ping_src_to_dst().is_err() {
        eprintln!(
            "felix-policy-forward-selftest FAILED: src→dst was DROPPED after being added to \
             the dst ingress allow-set — enforcement is over-blocking."
        );
        return 1;
    }
    println!("felix-policy-forward-selftest: ALLOW scenario OK (src→dst permitted)");

    println!("felix-policy-forward-selftest OK");
    0
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("felix-policy-forward-selftest only runs on Linux");
    std::process::exit(2);
}
