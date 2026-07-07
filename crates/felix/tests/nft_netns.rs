//! Integration test for real nftables programming. Runs `felix-nft-selftest`
//! inside a rootless network namespace (`unshare --user --map-root-user --net`),
//! exercising `nft -f -` apply + list + delete. Skips where unavailable.

use std::process::Command;

#[test]
#[cfg(target_os = "linux")]
fn nft_programming_in_rootless_netns() {
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

    let bin = env!("CARGO_BIN_EXE_felix-nft-selftest");
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", bin])
        .status()
        .expect("run felix-nft-selftest under unshare");
    assert!(
        status.success(),
        "felix-nft-selftest failed (exit {status:?})"
    );
}

/// Renders a Calico NetworkPolicy to nft and programs it, end to end, in a
/// rootless netns. Same gating.
#[test]
#[cfg(target_os = "linux")]
fn policy_render_and_program_in_rootless_netns() {
    if Command::new("unshare").arg("--version").output().is_err()
        || Command::new("nft").arg("--version").output().is_err()
    {
        eprintln!("SKIP: unshare/nft not available");
        return;
    }
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
    let bin = env!("CARGO_BIN_EXE_felix-policy-selftest");
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", bin])
        .status()
        .expect("run felix-policy-selftest under unshare");
    assert!(
        status.success(),
        "felix-policy-selftest failed (exit {status:?})"
    );
}
