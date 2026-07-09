//! Self-test: drive the felix VXLAN dataplane primitives against the *real*
//! kernel in the current network namespace. Run inside a rootless netns
//! (`unshare --user --map-root-user --net`); the integration test
//! (`tests/vxlan_netns.rs`) drives it. Exits 0 on success, non-zero on failure.
//!
//! It creates a dummy parent interface (the "underlay"), then exercises the full
//! primitive chain — `ensure_device` → `ensure_addr` → `replace_neigh` →
//! `replace_fdb` → `replace_route` — and reads every object back via `rtnetlink`:
//!   - the `vxlan.calico` device with VNI 4096, port 4789, learning off;
//!   - the /32 tunnel address on that device;
//!   - the neighbour entry (VTEP IP → MAC);
//!   - the FDB entry (MAC → underlay IP, AF_BRIDGE);
//!   - the on-link route for a remote block via the VTEP.
//!
//! Then it tears the devices down. A vxlan device can be created rootless when
//! bound to a parent `dev`, which is why this works without host root.

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("felix-vxlan-selftest FAILED: {e}");
        std::process::exit(1);
    }
    println!("felix-vxlan-selftest OK");
}

#[cfg(target_os = "linux")]
async fn run() -> Result<(), String> {
    use std::net::{IpAddr, Ipv4Addr};

    use felix::vxlan;
    use futures::TryStreamExt;
    use rtnetlink::packet_route::address::AddressAttribute;
    use rtnetlink::packet_route::link::{InfoData, InfoVxlan, LinkAttribute, LinkInfo};
    use rtnetlink::packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};
    use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};
    use rtnetlink::packet_route::AddressFamily;
    use rtnetlink::{Handle, LinkDummy, LinkUnspec, RouteMessageBuilder};

    fn e<E: std::fmt::Display>(x: E) -> String {
        x.to_string()
    }

    // Test fixture values.
    let underlay_ip = Ipv4Addr::new(10, 99, 0, 1);
    let tunnel_ip = Ipv4Addr::new(10, 244, 0, 1);
    let remote_vtep = Ipv4Addr::new(10, 244, 0, 2);
    let remote_underlay = Ipv4Addr::new(10, 99, 0, 2);
    let remote_mac = "aa:bb:cc:dd:ee:02";
    let block_dst = Ipv4Addr::new(10, 244, 1, 0);
    let block_prefix = 24u8;

    let (conn, handle, _) = rtnetlink::new_connection().map_err(e)?;
    tokio::spawn(conn);

    // A dummy interface plays the role of the underlay device the vxlan tunnel
    // binds to. Bring it up and give it the "node IP".
    let parent = "cali-vx-dum";
    handle
        .link()
        .add(LinkDummy::new(parent).build())
        .execute()
        .await
        .map_err(e)?;
    let parent_idx = link_index(&handle, parent).await?;
    handle
        .link()
        .set(LinkUnspec::new_with_index(parent_idx).up().build())
        .execute()
        .await
        .map_err(e)?;
    handle
        .address()
        .add(parent_idx, IpAddr::V4(underlay_ip), 24)
        .execute()
        .await
        .map_err(e)?;

    // --- drive the primitives ---
    let (vxlan_idx, mac) = vxlan::ensure_device(&handle, underlay_ip, parent_idx).await?;
    if mac.split(':').count() != 6 {
        return Err(format!("device MAC not readable: {mac:?}"));
    }
    vxlan::ensure_addr(&handle, vxlan_idx, tunnel_ip).await?;
    vxlan::replace_neigh(&handle, vxlan_idx, remote_vtep, remote_mac).await?;
    vxlan::replace_fdb(&handle, vxlan_idx, remote_mac, remote_underlay).await?;
    vxlan::replace_route(&handle, block_dst, block_prefix, remote_vtep, vxlan_idx).await?;

    // Idempotent re-apply: running the primitives again must not error.
    let _ = vxlan::ensure_device(&handle, underlay_ip, parent_idx).await?;
    vxlan::ensure_addr(&handle, vxlan_idx, tunnel_ip).await?;
    vxlan::replace_neigh(&handle, vxlan_idx, remote_vtep, remote_mac).await?;
    vxlan::replace_fdb(&handle, vxlan_idx, remote_mac, remote_underlay).await?;
    vxlan::replace_route(&handle, block_dst, block_prefix, remote_vtep, vxlan_idx).await?;

    // --- read back and assert ---

    // Device attributes: VNI / port / learning=off.
    let (vni, port, learning) = read_vxlan_attrs(&handle, vxlan_idx).await?;
    if vni != Some(vxlan::VNI) {
        return Err(format!("VNI mismatch: got {vni:?}, want {}", vxlan::VNI));
    }
    if port != Some(vxlan::PORT) {
        return Err(format!("port mismatch: got {port:?}, want {}", vxlan::PORT));
    }
    if learning != Some(false) {
        return Err(format!(
            "learning mismatch: got {learning:?}, want Some(false)"
        ));
    }

    // The /32 tunnel address is on the device.
    if !addr_present(&handle, vxlan_idx, tunnel_ip).await? {
        return Err(format!("tunnel addr {tunnel_ip} missing on vxlan device"));
    }

    // Neighbour entry: VTEP IP → MAC on the vxlan device.
    if !neigh_present(
        &handle,
        AddressFamily::Inet,
        vxlan_idx,
        remote_vtep,
        remote_mac,
    )
    .await?
    {
        return Err(format!("neighbour {remote_vtep} -> {remote_mac} missing"));
    }

    // FDB entry: MAC → remote underlay IP (AF_BRIDGE).
    if !neigh_present(
        &handle,
        AddressFamily::Bridge,
        vxlan_idx,
        remote_underlay,
        remote_mac,
    )
    .await?
    {
        return Err(format!("FDB {remote_mac} -> {remote_underlay} missing"));
    }

    // Route for the remote block via the VTEP.
    if !route_present(&handle, block_dst, block_prefix).await? {
        return Err(format!("route {block_dst}/{block_prefix} missing"));
    }

    // --- cleanup ---
    handle.link().del(vxlan_idx).execute().await.map_err(e)?;
    handle.link().del(parent_idx).execute().await.map_err(e)?;

    return Ok(());

    // ---- helpers ----

    async fn link_index(h: &Handle, name: &str) -> Result<u32, String> {
        let mut s = h.link().get().match_name(name.to_string()).execute();
        match s.try_next().await {
            Ok(Some(msg)) => Ok(msg.header.index),
            Ok(None) => Err(format!("link {name} not found")),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn read_vxlan_attrs(
        h: &Handle,
        idx: u32,
    ) -> Result<(Option<u32>, Option<u16>, Option<bool>), String> {
        let mut s = h.link().get().match_index(idx).execute();
        let mut vni = None;
        let mut port = None;
        let mut learning = None;
        if let Some(msg) = s.try_next().await.map_err(|e| e.to_string())? {
            for attr in &msg.attributes {
                if let LinkAttribute::LinkInfo(infos) = attr {
                    for info in infos {
                        if let LinkInfo::Data(InfoData::Vxlan(nlas)) = info {
                            for nla in nlas {
                                match nla {
                                    InfoVxlan::Id(id) => vni = Some(*id),
                                    InfoVxlan::Port(p) => port = Some(*p),
                                    InfoVxlan::Learning(l) => learning = Some(*l),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok((vni, port, learning))
    }

    async fn addr_present(h: &Handle, idx: u32, want: Ipv4Addr) -> Result<bool, String> {
        let mut s = h.address().get().set_link_index_filter(idx).execute();
        while let Some(msg) = s.try_next().await.map_err(|e| e.to_string())? {
            for attr in &msg.attributes {
                if let AddressAttribute::Address(IpAddr::V4(a)) = attr {
                    if *a == want {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    async fn neigh_present(
        h: &Handle,
        family: AddressFamily,
        idx: u32,
        want_dst: Ipv4Addr,
        want_mac: &str,
    ) -> Result<bool, String> {
        let want_lla = parse_mac(want_mac)?;
        let mut req = h.neighbours().get();
        req.message_mut().header.family = family;
        let mut s = req.execute();
        while let Some(msg) = s.try_next().await.map_err(|e| e.to_string())? {
            if msg.header.ifindex != idx {
                continue;
            }
            let mut dst_ok = false;
            let mut mac_ok = false;
            for attr in &msg.attributes {
                match attr {
                    // AF_INET neighbours parse NDA_DST as Inet; AF_BRIDGE FDB
                    // entries parse the same 4 bytes as Other (the dump family
                    // drives the decode), so accept both encodings.
                    NeighbourAttribute::Destination(NeighbourAddress::Inet(a))
                        if *a == want_dst =>
                    {
                        dst_ok = true;
                    }
                    NeighbourAttribute::Destination(NeighbourAddress::Other(bytes))
                        if bytes.as_slice() == want_dst.octets() =>
                    {
                        dst_ok = true;
                    }
                    NeighbourAttribute::LinkLayerAddress(lla) if lla.as_slice() == want_lla => {
                        mac_ok = true;
                    }
                    _ => {}
                }
            }
            if dst_ok && mac_ok {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn route_present(h: &Handle, dst: Ipv4Addr, prefix: u8) -> Result<bool, String> {
        let dump = RouteMessageBuilder::<Ipv4Addr>::new().build();
        let mut s = h.route().get(dump).execute();
        while let Some(route) = s.try_next().await.map_err(|e| e.to_string())? {
            if route.header.destination_prefix_length != prefix {
                continue;
            }
            for attr in &route.attributes {
                if let RouteAttribute::Destination(RouteAddress::Inet(a)) = attr {
                    if *a == dst {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
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
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("felix-vxlan-selftest only runs on Linux");
    std::process::exit(2);
}
