//! Self-test: drive the felix `RouteManager` against the *real* kernel routing
//! table in the current network namespace, for both IPv4 and IPv6. Run inside a
//! rootless netns (`unshare --user --map-root-user --net`); the integration test
//! (`tests/route_netns.rs`) drives it. Exits 0 on success, non-zero on failure.
//!
//! For each family it: creates a connected veth (so the gateway is reachable),
//! has `RouteManager` program a `dst via gateway` route, reads it back via
//! `rtnetlink`, then removes it and verifies it is gone — proving the real
//! netlink add/del path and the delta commit.

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("felix-route-selftest FAILED: {e}");
        std::process::exit(1);
    }
    println!("felix-route-selftest OK");
}

#[cfg(target_os = "linux")]
async fn run() -> Result<(), String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use felix::dataplane::Manager;
    use felix::route_manager::{NetlinkProgrammer, RouteManager};
    use futures::TryStreamExt;
    use proto::{RouteType, RouteUpdate, ToDataplane};
    use rtnetlink::{Handle, LinkUnspec, LinkVeth};

    fn e<E: std::fmt::Display>(x: E) -> String {
        x.to_string()
    }

    async fn link_index(h: &Handle, name: &str) -> Result<u32, String> {
        let mut s = h.link().get().match_name(name.to_string()).execute();
        match s.try_next().await {
            Ok(Some(msg)) => Ok(msg.header.index),
            Ok(None) => Err(format!("link {name} not found")),
            Err(err) => Err(e(err)),
        }
    }

    /// Does the main table contain a route to exactly `dst/prefix`?
    async fn route_exists(h: &Handle, dst: IpAddr, prefix: u8) -> Result<bool, String> {
        use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};
        let dump = match dst {
            IpAddr::V4(_) => rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new().build(),
            IpAddr::V6(_) => rtnetlink::RouteMessageBuilder::<Ipv6Addr>::new().build(),
        };
        let mut stream = h.route().get(dump).execute();
        while let Some(route) = stream.try_next().await.map_err(e)? {
            if route.header.destination_prefix_length != prefix {
                continue;
            }
            for attr in &route.attributes {
                if let RouteAttribute::Destination(a) = attr {
                    let hit = matches!(
                        (dst, a),
                        (IpAddr::V4(v4), RouteAddress::Inet(a4)) if v4 == *a4,
                    ) || matches!(
                        (dst, a),
                        (IpAddr::V6(v6), RouteAddress::Inet6(a6)) if v6 == *a6,
                    );
                    if hit {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    let (conn, handle, _) = rtnetlink::new_connection().map_err(e)?;
    tokio::spawn(conn);

    // One connected veth so the gateways below are on-subnet and thus resolvable.
    let (host, peer) = ("cali-rt-h", "cali-rt-c");
    handle
        .link()
        .add(LinkVeth::new(host, peer).build())
        .execute()
        .await
        .map_err(e)?;
    let host_idx = link_index(&handle, host).await?;
    let peer_idx = link_index(&handle, peer).await?;
    handle
        .link()
        .set(LinkUnspec::new_with_index(host_idx).up().build())
        .execute()
        .await
        .map_err(e)?;
    handle
        .link()
        .set(LinkUnspec::new_with_index(peer_idx).up().build())
        .execute()
        .await
        .map_err(e)?;
    // v4 + v6 connected subnets on the host end.
    handle
        .address()
        .add(host_idx, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24)
        .execute()
        .await
        .map_err(e)?;
    handle
        .address()
        .add(host_idx, "fd00::1".parse().unwrap(), 64)
        .execute()
        .await
        .map_err(e)?;

    let mut mgr = RouteManager::new(NetlinkProgrammer::new(handle.clone()));

    // Cases: (dst cidr, gateway, parsed dst addr, prefix).
    let cases: [(&str, &str, IpAddr, u8); 2] = [
        (
            "192.168.9.0/24",
            "10.0.0.2",
            IpAddr::V4(Ipv4Addr::new(192, 168, 9, 0)),
            24,
        ),
        ("fd00:9::/64", "fd00::2", "fd00:9::".parse().unwrap(), 64),
    ];

    // Program both routes in one delta round.
    for (dst, gw, _, _) in &cases {
        mgr.on_update(&ToDataplane::RouteUpdate(RouteUpdate {
            route_type: RouteType::RemoteWorkload,
            dst: (*dst).into(),
            dst_node_name: Some("node-b".into()),
            gateway: Some((*gw).into()),
        }));
    }
    mgr.complete_deferred_work()
        .await
        .map_err(|err| err.to_string())?;

    for (dst, _, addr, prefix) in &cases {
        if !route_exists(&handle, *addr, *prefix).await? {
            return Err(format!("route {dst} missing after program"));
        }
    }

    // Idempotent re-apply: the delta is empty, so this is a no-op (must not error).
    mgr.complete_deferred_work()
        .await
        .map_err(|err| err.to_string())?;

    // Remove both and verify they are gone.
    for (dst, _, _, _) in &cases {
        mgr.on_update(&ToDataplane::RouteRemove((*dst).into()));
    }
    mgr.complete_deferred_work()
        .await
        .map_err(|err| err.to_string())?;
    for (dst, _, addr, prefix) in &cases {
        if route_exists(&handle, *addr, *prefix).await? {
            return Err(format!("route {dst} still present after remove"));
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("felix-route-selftest only runs on Linux");
    std::process::exit(2);
}
