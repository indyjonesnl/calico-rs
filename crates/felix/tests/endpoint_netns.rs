//! Integration test for the felix `EndpointManager` against real nftables. Runs
//! `felix-endpoint-selftest` inside a rootless network namespace
//! (`unshare --user --map-root-user --net`), proving that per-policy + per-endpoint
//! chains are programmed non-destructively — the `IpSetManager`'s named set (in the
//! same `inet calico` table) survives, i.e. no table flush. Skips where
//! unavailable.

use std::process::Command;

#[test]
#[cfg(target_os = "linux")]
fn endpoint_policy_programming_in_rootless_netns() {
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

    let bin = env!("CARGO_BIN_EXE_felix-endpoint-selftest");
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", bin])
        .status()
        .expect("run felix-endpoint-selftest under unshare");
    assert!(
        status.success(),
        "felix-endpoint-selftest failed (exit {status:?})"
    );
}
