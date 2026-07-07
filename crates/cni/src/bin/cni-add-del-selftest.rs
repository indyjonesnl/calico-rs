//! End-to-end CNI ADD/DEL self-test: run `cmd_add` to wire a pod into a separate
//! netns, verify the pod interface + address exist, then `cmd_del` and verify
//! teardown. Run inside a rootless netns (`unshare -rn`); driven by the
//! integration test. Exits 0 on success.

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = run() {
        eprintln!("cni-add-del-selftest FAILED: {e}");
        std::process::exit(1);
    }
    println!("cni-add-del-selftest OK");
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    use cni::dataplane::link_index;
    use cni::orchestrate::{cmd_add, cmd_del};
    use nix::sched::{setns, unshare, CloneFlags};
    use std::fs::File;
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, BorrowedFd};

    let host_ns = File::open("/proc/self/ns/net").map_err(|e| e.to_string())?;

    // Create a pod netns on a dedicated thread; hand back its fd.
    let (tx, rx) = std::sync::mpsc::channel::<i32>();
    std::thread::spawn(move || {
        if unshare(CloneFlags::CLONE_NEWNET).is_err() {
            let _ = tx.send(-1);
            return;
        }
        match File::open("/proc/thread-self/ns/net") {
            Ok(f) => {
                let _ = tx.send(f.as_raw_fd());
                std::mem::forget(f);
                std::thread::park();
            }
            Err(_) => {
                let _ = tx.send(-1);
            }
        }
    });
    let pod_fd = rx.recv().map_err(|e| e.to_string())?;
    if pod_fd < 0 {
        return Err("could not create pod netns".into());
    }

    let host_veth = "cali-adtest01"; // 13 chars
    let pod_ip = Ipv4Addr::new(10, 99, 0, 7);

    // --- ADD ---
    let res = cmd_add(host_veth, "eth0", pod_fd, pod_ip, Some(1400))?;
    if res.pod_ip != pod_ip {
        return Err("unexpected pod ip in result".into());
    }
    // Host end exists after add.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        let (c, h, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
        tokio::spawn(c);
        if link_index(&h, host_veth).await?.is_none() {
            return Err("host veth missing after add".into());
        }
        Ok::<(), String>(())
    })?;

    // Verify inside the pod netns: eth0 exists (the temp name is gone).
    setns(
        unsafe { BorrowedFd::borrow_raw(pod_fd) },
        CloneFlags::CLONE_NEWNET,
    )
    .map_err(|e| format!("setns pod: {e}"))?;
    rt.block_on(async {
        let (c, h, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
        tokio::spawn(c);
        if link_index(&h, "eth0").await?.is_none() {
            return Err("pod eth0 missing after add".into());
        }
        // The container end is created with a per-process temp name, then
        // renamed to eth0 inside the pod netns; it must not linger.
        let temp = format!("cnitmp{}", std::process::id());
        if link_index(&h, &temp).await?.is_some() {
            return Err("temp interface name not renamed".into());
        }
        Ok::<(), String>(())
    })?;
    setns(&host_ns, CloneFlags::CLONE_NEWNET).map_err(|e| format!("setns host: {e}"))?;

    // --- DEL ---
    cmd_del(host_veth)?;
    rt.block_on(async {
        let (c, h, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
        tokio::spawn(c);
        if link_index(&h, host_veth).await?.is_some() {
            return Err("host veth present after del".into());
        }
        Ok::<(), String>(())
    })?;
    // Pod end should be gone too (deleting the pair).
    setns(
        unsafe { BorrowedFd::borrow_raw(pod_fd) },
        CloneFlags::CLONE_NEWNET,
    )
    .map_err(|e| format!("setns pod: {e}"))?;
    rt.block_on(async {
        let (c, h, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
        tokio::spawn(c);
        if link_index(&h, "eth0").await?.is_some() {
            return Err("pod eth0 survived del".into());
        }
        Ok::<(), String>(())
    })?;
    let _ = setns(&host_ns, CloneFlags::CLONE_NEWNET);

    // cmd_del is idempotent.
    cmd_del(host_veth)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("cni-add-del-selftest only runs on Linux");
    std::process::exit(2);
}
