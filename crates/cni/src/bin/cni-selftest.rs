//! Self-test binary that exercises the real CNI netlink dataplane end-to-end in
//! the current network namespace. Intended to be run inside a rootless network
//! namespace (`unshare -rn cni-selftest`); the integration test drives it.
//!
//! Exits 0 on success, non-zero on any failure (with a message on stderr).

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("cni-selftest FAILED: {e}");
        std::process::exit(1);
    }
    println!("cni-selftest OK");
}

#[cfg(target_os = "linux")]
async fn run() -> Result<(), String> {
    use cni::dataplane::*;
    use std::net::{IpAddr, Ipv4Addr};

    let (conn, handle, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
    tokio::spawn(conn);

    let host = "cali-selftest-h";
    let peer = "cali-selftest-c";

    // ADD path: veth pair → up → address → per-pod host route.
    create_veth(&handle, host, peer).await?;
    let idx = link_index(&handle, host)
        .await?
        .ok_or("host veth not found after create")?;
    let peer_idx = link_index(&handle, peer)
        .await?
        .ok_or("peer veth not found after create")?;
    set_up(&handle, idx).await?;
    set_up(&handle, peer_idx).await?;
    add_addr(&handle, idx, IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), 32).await?;
    add_dev_route(&handle, Ipv4Addr::new(10, 99, 0, 2), 32, idx).await?;

    // Verify the link is really there.
    if link_index(&handle, host).await?.is_none() {
        return Err("host veth missing after setup".into());
    }

    // DEL path: removing one end removes the pair.
    delete_link(&handle, idx).await?;
    if link_index(&handle, host).await?.is_some() {
        return Err("host veth still present after delete".into());
    }
    if link_index(&handle, peer).await?.is_some() {
        return Err("peer veth survived deletion of its pair".into());
    }
    let _ = peer_idx;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("cni-selftest only runs on Linux");
    std::process::exit(2);
}
