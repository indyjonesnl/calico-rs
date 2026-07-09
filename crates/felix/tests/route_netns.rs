//! Integration test for the felix `RouteManager` netlink path. Runs
//! `felix-route-selftest` inside a rootless network namespace (`unshare --user
//! --map-root-user --net`), which programs, reads back, and removes real IPv4 and
//! IPv6 routes without host root. Skips gracefully where rootless netns is
//! unavailable, keeping `cargo test` green in normal CI.

use std::process::Command;

#[test]
#[cfg(target_os = "linux")]
fn route_manager_netlink_in_rootless_netns() {
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

    let bin = env!("CARGO_BIN_EXE_felix-route-selftest");
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", bin])
        .status()
        .expect("run felix-route-selftest under unshare");
    assert!(
        status.success(),
        "felix-route-selftest failed inside rootless netns (exit {status:?})"
    );
}
