//! Integration test for the felix VXLAN dataplane primitives. Runs
//! `felix-vxlan-selftest` inside a rootless network namespace (`unshare --user
//! --map-root-user --net`), which creates a dummy parent, then programs and reads
//! back a real `vxlan.calico` device, its tunnel address, a neighbour + FDB
//! entry, and an on-link block route — all without host root. Skips gracefully
//! where rootless netns is unavailable, keeping `cargo test` green in normal CI.

use std::process::Command;

#[test]
#[cfg(target_os = "linux")]
fn vxlan_dataplane_primitives_in_rootless_netns() {
    if Command::new("unshare").arg("--version").output().is_err() {
        eprintln!("SKIP: `unshare` not available");
        return;
    }
    // Probe rootless netns support: create a userns+netns and exit.
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

    let bin = env!("CARGO_BIN_EXE_felix-vxlan-selftest");
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", bin])
        .status()
        .expect("run felix-vxlan-selftest under unshare");
    assert!(
        status.success(),
        "felix-vxlan-selftest failed inside rootless netns (exit {status:?})"
    );
}
