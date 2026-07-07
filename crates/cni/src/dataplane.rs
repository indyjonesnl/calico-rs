//! CNI netlink dataplane operations (veth pair, addresses, routes) via
//! `rtnetlink`. These are the real host operations the CNI plugin performs on
//! ADD/DEL. They run against the caller's current network namespace, so callers
//! enter the target namespace (the pod's, or a rootless test namespace) first.
//!
//! Exercised by an integration test inside a rootless network namespace
//! (`unshare -rn`), which is sufficient to validate the netlink logic without
//! real root.

use std::net::{IpAddr, Ipv4Addr};

use futures::TryStreamExt;
use rtnetlink::{Handle, LinkUnspec, LinkVeth, RouteMessageBuilder};

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Create a veth pair `host` <-> `peer`.
pub async fn create_veth(h: &Handle, host: &str, peer: &str) -> Result<(), String> {
    h.link()
        .add(LinkVeth::new(host, peer).build())
        .execute()
        .await
        .map_err(err)
}

/// Look up an interface index by name; `None` if the interface does not exist.
pub async fn link_index(h: &Handle, name: &str) -> Result<Option<u32>, String> {
    let mut stream = h.link().get().match_name(name.to_string()).execute();
    match stream.try_next().await {
        Ok(Some(msg)) => Ok(Some(msg.header.index)),
        Ok(None) => Ok(None),
        // A get-by-name for a missing link returns ENODEV rather than an empty
        // stream — treat that as "not found".
        Err(e) if e.to_string().contains("No such device") => Ok(None),
        Err(e) => Err(err(e)),
    }
}

/// Bring an interface up.
pub async fn set_up(h: &Handle, index: u32) -> Result<(), String> {
    h.link()
        .set(LinkUnspec::new_with_index(index).up().build())
        .execute()
        .await
        .map_err(err)
}

/// Add an address to an interface.
pub async fn add_addr(h: &Handle, index: u32, ip: IpAddr, prefix: u8) -> Result<(), String> {
    h.address()
        .add(index, ip, prefix)
        .execute()
        .await
        .map_err(err)
}

/// Rename an interface (CNI renames the container end to `CNI_IFNAME`, e.g.
/// `eth0`, after moving it into the pod namespace).
pub async fn rename_link(h: &Handle, index: u32, new_name: &str) -> Result<(), String> {
    h.link()
        .set(
            LinkUnspec::new_with_index(index)
                .name(new_name.to_string())
                .build(),
        )
        .execute()
        .await
        .map_err(err)
}

/// Set an interface's MTU.
pub async fn set_mtu(h: &Handle, index: u32, mtu: u32) -> Result<(), String> {
    h.link()
        .set(LinkUnspec::new_with_index(index).mtu(mtu).build())
        .execute()
        .await
        .map_err(err)
}

/// Add a device-scoped route to `dst/prefix` out of interface `oif` (the
/// host-side /32 route Calico programs per pod).
pub async fn add_dev_route(h: &Handle, dst: Ipv4Addr, prefix: u8, oif: u32) -> Result<(), String> {
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dst, prefix)
        .output_interface(oif)
        .build();
    h.route().add(route).execute().await.map_err(err)
}

/// Add a link-scoped route to `dst/prefix` out of `oif` (e.g. the pod's on-link
/// route to the point-to-point gateway 169.254.1.1).
pub async fn add_link_route(h: &Handle, dst: Ipv4Addr, prefix: u8, oif: u32) -> Result<(), String> {
    use rtnetlink::packet_route::route::RouteScope;
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dst, prefix)
        .output_interface(oif)
        .scope(RouteScope::Link)
        .build();
    h.route().add(route).execute().await.map_err(err)
}

/// Add a route to `dst/prefix` via gateway `gw` out of `oif`, marked on-link
/// (the gateway need not be on a connected subnet — Calico's default route via
/// the link-local point-to-point gateway).
pub async fn add_gateway_route(
    h: &Handle,
    dst: Ipv4Addr,
    prefix: u8,
    gw: Ipv4Addr,
    oif: u32,
) -> Result<(), String> {
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dst, prefix)
        .gateway(gw)
        .output_interface(oif)
        .onlink()
        .build();
    h.route().add(route).execute().await.map_err(err)
}

/// Delete an interface by index (CNI DEL / cleanup; deleting one veth end
/// removes its peer too).
pub async fn delete_link(h: &Handle, index: u32) -> Result<(), String> {
    h.link().del(index).execute().await.map_err(err)
}

/// Move an interface into the network namespace referenced by `netns_fd` (how
/// the CNI plugin hands the container end of the veth to the pod's namespace).
pub async fn move_link_to_netns(
    h: &Handle,
    index: u32,
    netns_fd: std::os::fd::RawFd,
) -> Result<(), String> {
    h.link()
        .set(
            LinkUnspec::new_with_index(index)
                .setns_by_fd(netns_fd)
                .build(),
        )
        .execute()
        .await
        .map_err(err)
}
