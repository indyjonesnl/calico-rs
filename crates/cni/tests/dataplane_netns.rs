//! Integration test for the CNI netlink dataplane. Runs the `cni-selftest`
//! binary inside a rootless network namespace (`unshare --user --map-root-user
//! --net`), which exercises the real veth/addr/route/delete netlink path without
//! requiring host root. Skips gracefully where rootless netns is unavailable.

use std::process::Command;

#[test]
#[cfg(target_os = "linux")]
fn cni_netlink_dataplane_in_rootless_netns() {
    // `unshare` must exist.
    if Command::new("unshare").arg("--version").output().is_err() {
        eprintln!("SKIP: `unshare` not available");
        return;
    }

    // Sanity-probe rootless netns support: create a userns+netns and exit.
    let probe = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "true"])
        .status();
    match probe {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("SKIP: rootless network namespaces not permitted here");
            return;
        }
    }

    let bin = env!("CARGO_BIN_EXE_cni-selftest");
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", bin])
        .status()
        .expect("run cni-selftest under unshare");
    assert!(
        status.success(),
        "cni-selftest failed inside rootless netns (exit {status:?})"
    );
}

/// Exercises the full CNI ADD wiring across two namespaces: veth pair in the
/// host netns, container end moved into a separate pod netns, both sides
/// configured. Same rootless-netns gating.
#[test]
#[cfg(target_os = "linux")]
fn cni_container_netns_wiring() {
    if Command::new("unshare").arg("--version").output().is_err() {
        eprintln!("SKIP: `unshare` not available");
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
    let bin = env!("CARGO_BIN_EXE_cni-netns-selftest");
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", bin])
        .status()
        .expect("run cni-netns-selftest under unshare");
    assert!(
        status.success(),
        "cni-netns-selftest failed inside rootless netns (exit {status:?})"
    );
}

/// Full CNI ADD/DEL orchestration (`cmd_add`/`cmd_del`) against a pod netns,
/// end to end. Same rootless-netns gating.
#[test]
#[cfg(target_os = "linux")]
fn cni_add_del_orchestration() {
    if Command::new("unshare").arg("--version").output().is_err() {
        eprintln!("SKIP: `unshare` not available");
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
    let bin = env!("CARGO_BIN_EXE_cni-add-del-selftest");
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", bin])
        .status()
        .expect("run cni-add-del-selftest under unshare");
    assert!(
        status.success(),
        "cni-add-del-selftest failed inside rootless netns (exit {status:?})"
    );
}
