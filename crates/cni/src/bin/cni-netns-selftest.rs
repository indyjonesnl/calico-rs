//! Two-namespace CNI self-test: create a veth pair in the host netns, move the
//! container end into a separate ("pod") netns, and configure both sides — the
//! real CNI ADD wiring. Run inside a rootless netns (`unshare -rn`); driven by
//! the integration test. Exits 0 on success.

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = run() {
        eprintln!("cni-netns-selftest FAILED: {e}");
        std::process::exit(1);
    }
    println!("cni-netns-selftest OK");
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    use cni::dataplane::*;
    use nix::sched::{setns, unshare, CloneFlags};
    use std::fs::File;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::fd::{AsRawFd, BorrowedFd};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;

    // Remember the host netns so we can return to it.
    let host_ns = File::open("/proc/self/ns/net").map_err(|e| format!("open host ns: {e}"))?;

    // Create a "container" netns on a dedicated thread and hand back its fd.
    let (tx, rx) = std::sync::mpsc::channel::<i32>();
    std::thread::spawn(move || {
        if unshare(CloneFlags::CLONE_NEWNET).is_err() {
            let _ = tx.send(-1);
            return;
        }
        // NB: `/proc/thread-self` (not `/proc/self`, which is the main thread's)
        // — this thread's freshly-unshared netns.
        match File::open("/proc/thread-self/ns/net") {
            Ok(f) => {
                let raw = f.as_raw_fd();
                let _ = tx.send(raw);
                std::mem::forget(f); // keep the fd (and netns) alive
                std::thread::park();
            }
            Err(_) => {
                let _ = tx.send(-1);
            }
        }
    });
    let cont_fd = rx.recv().map_err(|e| e.to_string())?;
    if cont_fd < 0 {
        return Err("could not create container netns".into());
    }

    let host = "cali-h-test";
    let cont = "cali-c-test";

    // --- host netns: create veth, move container end out, configure host end ---
    rt.block_on(async {
        let (conn, h, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        create_veth(&h, host, cont).await?;
        let cont_idx = link_index(&h, cont).await?.ok_or("container end missing")?;
        let host_idx = link_index(&h, host).await?.ok_or("host end missing")?;
        move_link_to_netns(&h, cont_idx, cont_fd).await?;
        if link_index(&h, cont).await?.is_some() {
            return Err("container end still in host netns after move".into());
        }
        set_up(&h, host_idx).await?;
        add_addr(&h, host_idx, IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), 32).await?;
        Ok::<(), String>(())
    })?;

    // --- enter the container netns and configure the pod end ---
    setns(
        unsafe { BorrowedFd::borrow_raw(cont_fd) },
        CloneFlags::CLONE_NEWNET,
    )
    .map_err(|e| format!("setns container: {e}"))?;
    rt.block_on(async {
        let (conn, h, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let cont_idx = link_index(&h, cont)
            .await?
            .ok_or("container end not in pod netns")?;
        set_up(&h, cont_idx).await?;
        add_addr(&h, cont_idx, IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2)), 32).await?;
        // The host end must NOT have followed into the pod netns.
        if link_index(&h, host).await?.is_some() {
            return Err("host end leaked into pod netns".into());
        }
        Ok::<(), String>(())
    })?;

    // --- back to the host netns; verify + clean up ---
    setns(&host_ns, CloneFlags::CLONE_NEWNET).map_err(|e| format!("setns host: {e}"))?;
    rt.block_on(async {
        let (conn, h, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let host_idx = link_index(&h, host)
            .await?
            .ok_or("host end missing after return")?;
        delete_link(&h, host_idx).await?; // removes the pair
        Ok::<(), String>(())
    })?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("cni-netns-selftest only runs on Linux");
    std::process::exit(2);
}
