//! CNI ADD/DEL orchestration — the real per-pod wiring, composed from the
//! netlink dataplane primitives. IP allocation (IPAM) and datastore writes are
//! the caller's responsibility; this performs the network setup given an
//! assigned address and the pod's network-namespace fd.
//!
//! Flow (mirrors upstream CNI): create the veth pair (container end with a temp
//! name to avoid host clashes) → move the container end into the pod netns →
//! configure the host end (up, per-pod /32 route) → enter the pod netns, rename
//! to the requested interface, bring up, add the address + default route → back
//! to the host. `del` removes the host end, which tears down the pair.

use std::fs::File;
use std::net::Ipv4Addr;
use std::os::fd::{BorrowedFd, RawFd};

use nix::sched::{setns, CloneFlags};
use rtnetlink::new_connection;

use crate::dataplane::{
    add_addr, add_dev_route, add_gateway_route, add_link_route, create_veth, delete_link,
    link_index, move_link_to_netns, rename_link, set_mtu, set_up,
};

/// Result of a successful ADD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddResult {
    pub host_ifname: String,
    pub container_ifname: String,
    pub pod_ip: Ipv4Addr,
}

/// The point-to-point gateway Calico gives every pod. It never appears on the
/// wire: the host veth answers ARP for it via proxy_arp, so all pod egress goes
/// to the host, which then routes by the per-pod /32.
const POD_GATEWAY: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 1);

fn rt() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

/// Wire up a pod: create + configure the veth pair, placing the container end in
/// `container_netns_fd` as `container_ifname` with `pod_ip/32`.
pub fn cmd_add(
    host_veth: &str,
    container_ifname: &str,
    container_netns_fd: RawFd,
    pod_ip: Ipv4Addr,
    mtu: Option<u32>,
) -> Result<AddResult, String> {
    let rt = rt()?;
    let host_ns = File::open("/proc/self/ns/net").map_err(|e| format!("open host ns: {e}"))?;
    // Container end gets a unique temporary name in the host netns to avoid
    // collisions between concurrent ADDs (kubelet wires pods in parallel); it is
    // renamed to `container_ifname` once inside the pod netns.
    let temp_ifname = format!("cnitmp{}", std::process::id());

    // Host netns: create the pair, move the container end out, configure host end.
    rt.block_on(async {
        let (conn, h, _) = new_connection().map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        create_veth(&h, host_veth, &temp_ifname).await?;
        let tmp_idx = link_index(&h, &temp_ifname)
            .await?
            .ok_or("temp veth missing")?;
        let host_idx = link_index(&h, host_veth)
            .await?
            .ok_or("host veth missing")?;
        move_link_to_netns(&h, tmp_idx, container_netns_fd).await?;
        set_up(&h, host_idx).await?;
        if let Some(m) = mtu {
            set_mtu(&h, host_idx, m).await?;
        }
        // Host-side /32 route steering the pod address to the veth.
        add_dev_route(&h, pod_ip, 32, host_idx).await?;
        Ok::<(), String>(())
    })?;

    // The host veth must answer ARP for the pod's gateway (and for return
    // traffic), so enable proxy_arp on it. Written after the interface exists.
    set_proxy_arp(host_veth)?;

    // Pod netns: rename, bring up, address, gateway + default route.
    setns(
        unsafe { BorrowedFd::borrow_raw(container_netns_fd) },
        CloneFlags::CLONE_NEWNET,
    )
    .map_err(|e| format!("setns pod: {e}"))?;
    let pod_result = rt.block_on(async {
        let (conn, h, _) = new_connection().map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let tmp_idx = link_index(&h, &temp_ifname)
            .await?
            .ok_or("container end not in pod netns")?;
        rename_link(&h, tmp_idx, container_ifname).await?;
        let idx = link_index(&h, container_ifname)
            .await?
            .ok_or("renamed iface missing")?;
        if let Some(m) = mtu {
            set_mtu(&h, idx, m).await?;
        }
        set_up(&h, idx).await?;
        add_addr(&h, idx, std::net::IpAddr::V4(pod_ip), 32).await?;
        // Point-to-point gateway model: an on-link route to the link-local
        // gateway, then a default route via it. The host veth (proxy_arp)
        // answers the gateway's ARP.
        add_link_route(&h, POD_GATEWAY, 32, idx).await?;
        add_gateway_route(&h, Ipv4Addr::UNSPECIFIED, 0, POD_GATEWAY, idx).await?;
        Ok::<(), String>(())
    });

    // Always return to the host netns, even on error.
    setns(&host_ns, CloneFlags::CLONE_NEWNET).map_err(|e| format!("setns host: {e}"))?;
    pod_result?;

    Ok(AddResult {
        host_ifname: host_veth.to_string(),
        container_ifname: container_ifname.to_string(),
        pod_ip,
    })
}

/// Enable proxy_arp on the host-side veth so it answers ARP for the pod's
/// point-to-point gateway (and any address the pod tries to reach on-link).
fn set_proxy_arp(host_veth: &str) -> Result<(), String> {
    let path = format!("/proc/sys/net/ipv4/conf/{host_veth}/proxy_arp");
    std::fs::write(&path, b"1").map_err(|e| format!("enable proxy_arp ({path}): {e}"))
}

/// Tear down a pod's networking: delete the host veth end (removes the pair,
/// including the container end in the pod netns). Idempotent.
pub fn cmd_del(host_veth: &str) -> Result<(), String> {
    let rt = rt()?;
    rt.block_on(async {
        let (conn, h, _) = new_connection().map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        if let Some(idx) = link_index(&h, host_veth).await? {
            delete_link(&h, idx).await?;
        }
        Ok::<(), String>(())
    })
}
