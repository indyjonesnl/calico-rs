//! Integration test for the unified felix `PolicyTableManager` against real
//! nftables. Runs `felix-policy-table-selftest` inside a rootless network
//! namespace (`unshare --user --map-root-user --net`), proving the atomic
//! full-table render programs sets + chains (with a resolving `@set` rule),
//! is idempotent, and — crucially — is RESTART-SAFE: a fresh manager fed a
//! different desired state flushes and rebuilds the table so stale objects are
//! gone, with no delete statements to poison the transaction. Skips where
//! unavailable.

use std::process::Command;

#[test]
#[cfg(target_os = "linux")]
fn policy_table_programming_is_self_healing_in_rootless_netns() {
    if Command::new("unshare").arg("--version").output().is_err() {
        eprintln!("SKIP: `unshare` not available");
        return;
    }
    if Command::new("nft").arg("--version").output().is_err() {
        eprintln!("SKIP: `nft` not available");
        return;
    }
    // Probe rootless netns support.
    match Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "true"])
        .status()
    {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("SKIP: rootless network namespaces not permitted here");
            return;
        }
    }

    let bin = env!("CARGO_BIN_EXE_felix-policy-table-selftest");
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", bin])
        .status()
        .expect("run felix-policy-table-selftest under unshare");
    assert!(
        status.success(),
        "felix-policy-table-selftest failed (exit {status:?})"
    );
}
