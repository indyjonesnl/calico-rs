//! Integration test for real nftables named-set programming via the felix
//! `IpSetManager`. Runs `felix-ipset-selftest` inside a rootless network
//! namespace (`unshare --user --map-root-user --net`), exercising the real
//! `nft add/delete element` delta path. Skips where unavailable.

use std::process::Command;

#[test]
#[cfg(target_os = "linux")]
fn ipset_programming_in_rootless_netns() {
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

    let bin = env!("CARGO_BIN_EXE_felix-ipset-selftest");
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", bin])
        .status()
        .expect("run felix-ipset-selftest under unshare");
    assert!(
        status.success(),
        "felix-ipset-selftest failed (exit {status:?})"
    );
}
