//! VXLAN dataplane primitives (rtnetlink): create/maintain the `vxlan.calico`
//! tunnel device, program the per-remote-node VTEP entries (neighbour + FDB),
//! and the per-remote-block routes. This is the Felix-routed overlay — no BGP;
//! Felix programs everything from the datastore + node VTEP metadata.
//!
//! Model (mirrors upstream Calico VXLAN):
//! - Each node has one `vxlan.calico` device (unicast, `learning=off`) bound to
//!   the underlay interface, assigned a /32 tunnel address (the VTEP IP).
//! - For every *other* node we install: a neighbour entry mapping its VTEP IP →
//!   its VXLAN MAC, and an FDB entry mapping that MAC → the node's underlay IP
//!   (so the kernel knows which host to encapsulate to).
//! - For every IP block owned by a remote node, a route `<block> via <its VTEP>
//!   dev vxlan.calico onlink`. Pod traffic to a remote block is then encapsulated
//!   to the owning node, which routes the /32 to the local veth.

use std::net::{IpAddr, Ipv4Addr};

use futures::TryStreamExt;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::packet_route::neighbour::{NeighbourFlags, NeighbourState};
use rtnetlink::packet_route::route::RouteScope;
use rtnetlink::{Handle, LinkUnspec, LinkVxlan, RouteMessageBuilder};

pub const DEVICE: &str = "vxlan.calico";
pub const VNI: u32 = 4096;
pub const PORT: u16 = 4789;
/// Underlay MTU (1500 on the kind bridge) minus the VXLAN/UDP/IP overhead (50).
pub const MTU: u32 = 1450;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Look up an interface index by name; `None` if absent.
pub async fn link_index(h: &Handle, name: &str) -> Result<Option<u32>, String> {
    let mut s = h.link().get().match_name(name.to_string()).execute();
    match s.try_next().await {
        Ok(Some(m)) => Ok(Some(m.header.index)),
        Ok(None) => Ok(None),
        Err(e) if e.to_string().contains("No such device") => Ok(None),
        Err(e) => Err(err(e)),
    }
}

/// Find the interface carrying `ip` (the underlay device for the node IP).
pub async fn link_index_for_ip(h: &Handle, ip: Ipv4Addr) -> Result<Option<u32>, String> {
    use rtnetlink::packet_route::address::AddressAttribute;
    let mut s = h.address().get().execute();
    while let Some(msg) = s.try_next().await.map_err(err)? {
        for attr in &msg.attributes {
            if let AddressAttribute::Address(IpAddr::V4(a)) = attr {
                if *a == ip {
                    return Ok(Some(msg.header.index));
                }
            }
        }
    }
    Ok(None)
}

/// Read an interface's MAC address as `aa:bb:cc:dd:ee:ff`.
pub async fn mac_of(h: &Handle, index: u32) -> Result<Option<String>, String> {
    let mut s = h.link().get().match_index(index).execute();
    if let Some(msg) = s.try_next().await.map_err(err)? {
        for attr in &msg.attributes {
            if let LinkAttribute::Address(bytes) = attr {
                if bytes.len() == 6 {
                    return Ok(Some(fmt_mac(bytes)));
                }
            }
        }
    }
    Ok(None)
}

fn fmt_mac(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("bad MAC {s:?}"));
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).map_err(|e| format!("bad MAC byte {p:?}: {e}"))?;
    }
    Ok(out)
}

/// Ensure the `vxlan.calico` device exists, bound to the underlay interface with
/// the given local (node) IP, VNI, port, MTU, and `learning=off`. Idempotent:
/// creates it if missing and returns its index. Returns the device's MAC too.
pub async fn ensure_device(
    h: &Handle,
    local: Ipv4Addr,
    underlay_idx: u32,
) -> Result<(u32, String), String> {
    if link_index(h, DEVICE).await?.is_none() {
        let msg = LinkVxlan::new(DEVICE, VNI)
            .port(PORT)
            .local(local)
            .dev(underlay_idx)
            .learning(false)
            .up()
            .build();
        h.link().add(msg).execute().await.map_err(err)?;
    }
    let idx = link_index(h, DEVICE)
        .await?
        .ok_or("vxlan device missing after create")?;
    // Ensure MTU + up (idempotent for an existing device).
    h.link()
        .set(LinkUnspec::new_with_index(idx).mtu(MTU).up().build())
        .execute()
        .await
        .map_err(err)?;
    let mac = mac_of(h, idx).await?.ok_or("vxlan device has no MAC")?;
    Ok((idx, mac))
}

/// Assign the /32 VTEP address to the vxlan device (idempotent — ignores
/// "already exists").
pub async fn ensure_addr(h: &Handle, idx: u32, ip: Ipv4Addr) -> Result<(), String> {
    match h.address().add(idx, IpAddr::V4(ip), 32).execute().await {
        Ok(()) => Ok(()),
        Err(e) if e.to_string().contains("File exists") => Ok(()),
        Err(e) => Err(err(e)),
    }
}

/// Install the neighbour entry mapping a remote VTEP IP → its VXLAN MAC on our
/// vxlan device (permanent, replace).
pub async fn replace_neigh(
    h: &Handle,
    vxlan_idx: u32,
    vtep_ip: Ipv4Addr,
    mac: &str,
) -> Result<(), String> {
    let lla = parse_mac(mac)?;
    h.neighbours()
        .add(vxlan_idx, IpAddr::V4(vtep_ip))
        .link_layer_address(&lla)
        .state(NeighbourState::Permanent)
        .replace()
        .execute()
        .await
        .map_err(err)
}

/// Install the FDB entry mapping a remote VXLAN MAC → the remote node's underlay
/// IP (so the kernel encapsulates to the right host). `bridge fdb replace <mac>
/// dev vxlan.calico dst <node_ip>`.
pub async fn replace_fdb(
    h: &Handle,
    vxlan_idx: u32,
    mac: &str,
    node_ip: Ipv4Addr,
) -> Result<(), String> {
    let lla = parse_mac(mac)?;
    h.neighbours()
        .add_bridge(vxlan_idx, &lla)
        .destination(IpAddr::V4(node_ip))
        .state(NeighbourState::Permanent)
        .flags(NeighbourFlags::Own) // NTF_SELF
        .replace()
        .execute()
        .await
        .map_err(err)
}

/// Install a route for a remote block CIDR via a remote VTEP IP out of the vxlan
/// device (on-link — the VTEP is reachable over the tunnel). Replace semantics.
pub async fn replace_route(
    h: &Handle,
    dst: Ipv4Addr,
    prefix: u8,
    gw: Ipv4Addr,
    vxlan_idx: u32,
) -> Result<(), String> {
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dst, prefix)
        .gateway(gw)
        .output_interface(vxlan_idx)
        .scope(RouteScope::Universe)
        .onlink()
        .build();
    h.route().add(route).replace().execute().await.map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_round_trips() {
        let bytes = [0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f];
        let s = fmt_mac(&bytes);
        assert_eq!(s, "0a:1b:2c:3d:4e:5f");
        assert_eq!(parse_mac(&s).unwrap(), bytes);
    }

    #[test]
    fn parse_mac_rejects_malformed() {
        assert!(parse_mac("aa:bb:cc").is_err());
        assert!(parse_mac("zz:bb:cc:dd:ee:ff").is_err());
    }
}
