//! Regression test for the forward-path policy-chain semantics: for a forwarded
//! pod→pod packet, `cali-forward` jumps BOTH the source-egress and dest-ingress
//! chains, and an ALLOW in one direction must NOT terminate before the other is
//! evaluated. Runs `felix-policy-forward-selftest` inside a rootless net+mount
//! namespace: it builds a real two-pod forwarding topology, drives the actual
//! `PolicyTableManager`, and asserts src→dst is DROPPED by the dst-ingress policy
//! despite the src-egress open-by-default ALLOW, then PERMITTED once the src is
//! added to the ingress allow-set. Self-skips where the environment cannot build
//! the topology (exit code 2).

use std::process::Command;

#[test]
#[cfg(target_os = "linux")]
fn forwarded_packet_is_enforced_by_both_direction_chains() {
    if Command::new("unshare").arg("--version").output().is_err() {
        eprintln!("SKIP: `unshare` not available");
        return;
    }
    if Command::new("nft").arg("--version").output().is_err() {
        eprintln!("SKIP: `nft` not available");
        return;
    }
    if Command::new("ip").arg("-V").output().is_err() {
        eprintln!("SKIP: `ip` not available");
        return;
    }
    // Probe rootless net+mount namespace support.
    match Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--mount", "true"])
        .status()
    {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("SKIP: rootless net+mount namespaces not permitted here");
            return;
        }
    }

    let bin = env!("CARGO_BIN_EXE_felix-policy-forward-selftest");
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--mount", bin])
        .status()
        .expect("run felix-policy-forward-selftest under unshare");

    match status.code() {
        Some(0) => {}
        Some(2) => eprintln!("SKIP: selftest could not build the forwarding topology here"),
        other => panic!(
            "felix-policy-forward-selftest reported a policy-enforcement failure (exit {other:?})"
        ),
    }
}
