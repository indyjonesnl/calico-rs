//! The VXLAN overlay reconcile loop (Felix-routed, no BGP).
//!
//! Once per pass, on each node:
//!   1. Ensure this node's `vxlan.calico` device + /32 VTEP address, allocating a
//!      tunnel IP from an IP pool on first run and publishing the VTEP (tunnel IP
//!      + device MAC) as annotations on the node's Kubernetes `Node` object.
//!   2. Read every node's published VTEP and every `BlockAffinity` (which node
//!      owns which IP block), and program, for each *remote* node: a neighbour
//!      entry (VTEP IP → MAC), an FDB entry (MAC → underlay IP), and a route for
//!      each of that node's blocks (`<block> via <VTEP> dev vxlan.calico onlink`).
//!
//! The result: pod traffic to a remote block is encapsulated to the owning node,
//! which routes the destination /32 to the local pod veth.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use apis::EncapMode;
use datastore::{KddBackend, ResourceKind};
use ipam::{Cidr, KddIpam};
use k8s_openapi::api::core::v1::Node;
use kube::api::{Api, Patch, PatchParams};
use kube::ResourceExt;
use rtnetlink::{new_connection, Handle};

use crate::vxlan;

const ANN_TUNNEL_IP: &str = "projectcalico.org/VXLANTunnelIPv4Address";
const ANN_TUNNEL_MAC: &str = "projectcalico.org/VXLANTunnelMACAddr";

/// A remote node's tunnel endpoint.
#[derive(Debug, Clone)]
struct Vtep {
    tunnel_ip: Ipv4Addr,
    mac: String,
    underlay_ip: Ipv4Addr,
}

/// Run the VXLAN reconcile loop, polling on `interval`.
pub async fn run(backend: KddBackend, node_name: String, interval: Duration) {
    loop {
        if let Err(e) = reconcile_once(&backend, &node_name).await {
            eprintln!("vxlan reconcile failed: {e}");
        }
        tokio::time::sleep(interval).await;
    }
}

fn handle() -> Result<(Handle, tokio::task::JoinHandle<()>), String> {
    let (conn, h, _) = new_connection().map_err(|e| e.to_string())?;
    let jh = tokio::spawn(conn);
    Ok((h, jh))
}

async fn reconcile_once(backend: &KddBackend, node_name: &str) -> Result<(), String> {
    let (h, _conn) = handle()?;
    let vxlan_idx = ensure_local(backend, node_name, &h).await?;
    reconcile_remotes(backend, node_name, &h, vxlan_idx).await?;
    Ok(())
}

/// Ensure the local VXLAN device, VTEP address, and published annotations.
/// Returns the vxlan device index.
async fn ensure_local(backend: &KddBackend, node_name: &str, h: &Handle) -> Result<u32, String> {
    let nodes: Api<Node> = Api::all(backend.client());
    let node = nodes
        .get(node_name)
        .await
        .map_err(|e| format!("get node {node_name}: {e}"))?;

    let underlay_ip = internal_ip(&node).ok_or("node has no InternalIP")?;
    let underlay_idx = vxlan::link_index_for_ip(h, underlay_ip)
        .await?
        .ok_or_else(|| format!("no local interface carries {underlay_ip}"))?;

    // Tunnel IP: reuse the published annotation if present, else allocate a /32.
    let tunnel_ip = match node
        .annotations()
        .get(ANN_TUNNEL_IP)
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
    {
        Some(ip) => ip,
        None => allocate_tunnel_ip(backend, node_name).await?,
    };

    let (vxlan_idx, mac) = vxlan::ensure_device(h, underlay_ip, underlay_idx).await?;
    vxlan::ensure_addr(h, vxlan_idx, tunnel_ip).await?;

    // Publish (idempotent server-side merge).
    let patch = serde_json::json!({
        "metadata": { "annotations": {
            ANN_TUNNEL_IP: tunnel_ip.to_string(),
            ANN_TUNNEL_MAC: mac,
        }}
    });
    nodes
        .patch(node_name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| format!("publish VTEP annotations: {e}"))?;

    Ok(vxlan_idx)
}

/// Allocate (or recover) this node's /32 VXLAN tunnel IP from the first enabled
/// IP pool.
///
/// The allocation is keyed by a stable handle (`vxlan-tunnel-<node>`), but
/// `auto_assign_from_pool` is *not* handle-idempotent — it always grabs a fresh
/// address. So before allocating we ask the handle for any address it already
/// owns and reuse it. This recovers the tunnel IP from a crashed prior pass
/// (process died after allocating but before publishing the node annotation),
/// which would otherwise leak the earlier address and grab a second one. Only
/// when the handle owns nothing do we allocate a new /32; a repeated run is then
/// a no-op.
async fn allocate_tunnel_ip(backend: &KddBackend, node_name: &str) -> Result<Ipv4Addr, String> {
    let ipam = KddIpam::new(KddBackend::new(backend.client()));
    let handle_id = format!("vxlan-tunnel-{node_name}");

    // Recover a tunnel IP a prior (possibly crashed) pass already allocated
    // under this handle instead of leaking it.
    let existing = ipam
        .ips_by_handle(&handle_id)
        .await
        .map_err(|e| format!("look up existing tunnel IP: {e}"))?;
    if let Some(v4) = existing.iter().find_map(|ip| match ip {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(_) => None,
    }) {
        return Ok(v4);
    }

    // No prior allocation for this handle — allocate a fresh /32.
    let (pool_cidr, block_size) = first_pool(backend).await?;
    let attrs = BTreeMap::from([
        ("node".to_string(), node_name.to_string()),
        ("type".to_string(), "vxlanTunnelAddress".to_string()),
    ]);
    let ips = ipam
        .auto_assign_from_pool_with_attrs(node_name, pool_cidr, block_size, &handle_id, &attrs, 1)
        .await
        .map_err(|e| format!("allocate tunnel IP: {e}"))?;
    match ips.into_iter().next() {
        Some(IpAddr::V4(v4)) => Ok(v4),
        _ => Err("no address available for VXLAN tunnel".to_string()),
    }
}

/// Program neighbour/FDB/routes for every remote node.
async fn reconcile_remotes(
    backend: &KddBackend,
    node_name: &str,
    h: &Handle,
    vxlan_idx: u32,
) -> Result<(), String> {
    let vteps = collect_vteps(backend).await?;
    let pools = pool_encaps(backend).await?;
    let affinities = backend
        .list(ResourceKind::BlockAffinity, None)
        .await
        .map_err(|e| e.to_string())?;

    // VTEP endpoints for remote nodes.
    for (node, vtep) in &vteps {
        if node == node_name {
            continue;
        }
        vxlan::replace_neigh(h, vxlan_idx, vtep.tunnel_ip, &vtep.mac).await?;
        vxlan::replace_fdb(h, vxlan_idx, &vtep.mac, vtep.underlay_ip).await?;
    }

    // Routes for each block owned by a remote node — gated by the owning pool's
    // encapsulation mode (the encapsulation resolver).
    for aff in &affinities {
        let owner = aff.spec.get("node").and_then(|v| v.as_str()).unwrap_or("");
        if owner.is_empty() || owner == node_name {
            continue;
        }
        let Some(vtep) = vteps.get(owner) else {
            continue; // owner has not published a VTEP yet
        };
        let Some(cidr_s) = aff.spec.get("cidr").and_then(|v| v.as_str()) else {
            continue;
        };
        let cidr = Cidr::parse(cidr_s).map_err(|e| e.to_string())?;

        // Only program a VXLAN route when the block's pool requests encap.
        match resolve_encap(&pools, cidr) {
            EncapDecision::Route => {}
            EncapDecision::Skip => continue, // pool vxlanMode: Never
            EncapDecision::NoPool => {
                eprintln!("vxlan: no IP pool contains block {cidr}; not programming a route");
                continue;
            }
        }

        let dst = match cidr.network() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => continue, // IPv6 overlay not yet supported
        };
        vxlan::replace_route(h, dst, cidr.prefix_len(), vtep.tunnel_ip, vxlan_idx).await?;
    }
    Ok(())
}

/// A pool's CIDR + its VXLAN encapsulation mode — the encap resolver's input.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PoolEncap {
    cidr: Cidr,
    vxlan_mode: EncapMode,
}

/// Outcome of resolving whether a remote block's traffic gets a VXLAN route.
#[derive(Debug, PartialEq, Eq)]
enum EncapDecision {
    /// The containing pool enables VXLAN (`Always`/`CrossSubnet`) — program the route.
    Route,
    /// The containing pool has `vxlanMode: Never` — do not encapsulate.
    Skip,
    /// No pool contains the block — cannot resolve encap; skip and warn.
    NoPool,
}

/// Resolve whether `block` should get a VXLAN route, from the pool that contains
/// it (longest-prefix match). This is the Rust analogue of upstream Felix's
/// VXLAN resolver / L3 route resolver intent: a route is only VXLAN-encapsulated
/// when its owning pool asks for VXLAN. A block with no containing pool is a
/// datastore inconsistency — skip it rather than program an unencapsulated route.
///
/// CrossSubnet handling (documented simplification): upstream encapsulates a
/// `CrossSubnet` pool's traffic only when the remote node is on a *different*
/// underlay subnet, routing directly to same-subnet peers. Distinguishing the
/// two needs each node's underlay subnet/CIDR, which this Felix-routed overlay
/// does not yet plumb — nodes publish only their `InternalIP`, no prefix length.
/// We therefore treat `CrossSubnet` conservatively as "always encapsulate":
/// encapsulation reaches every peer regardless of subnet, so connectivity is
/// preserved; the only cost is not taking the direct-route shortcut for
/// same-subnet peers. We deliberately do NOT collapse it to "route directly"
/// for same-subnet peers, which could black-hole traffic where no direct L2/L3
/// path exists. TODO(cross-subnet): publish per-node underlay CIDRs and route
/// same-subnet peers directly.
fn resolve_encap(pools: &[PoolEncap], block: Cidr) -> EncapDecision {
    let Some(pool) = pools
        .iter()
        .filter(|p| p.cidr.contains(&block))
        .max_by_key(|p| p.cidr.prefix_len())
    else {
        return EncapDecision::NoPool;
    };
    match pool.vxlan_mode {
        EncapMode::Always | EncapMode::CrossSubnet => EncapDecision::Route,
        EncapMode::Never => EncapDecision::Skip,
    }
}

/// Build the encap resolver's pool table: each enabled IP pool's CIDR +
/// `vxlanMode`. Pools without a parseable CIDR are skipped.
async fn pool_encaps(backend: &KddBackend) -> Result<Vec<PoolEncap>, String> {
    let pools = backend
        .list(ResourceKind::IpPool, None)
        .await
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for p in &pools {
        if p.spec
            .get("disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }
        let Some(cidr_s) = p.spec.get("cidr").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(cidr) = Cidr::parse(cidr_s) else {
            continue;
        };
        let vxlan_mode = parse_encap(p.spec.get("vxlanMode").and_then(|v| v.as_str()));
        out.push(PoolEncap { cidr, vxlan_mode });
    }
    Ok(out)
}

/// Parse a pool's `vxlanMode` wire value; anything unrecognized (or absent)
/// defaults to `Never`, matching the API default.
fn parse_encap(s: Option<&str>) -> EncapMode {
    match s {
        Some("Always") => EncapMode::Always,
        Some("CrossSubnet") => EncapMode::CrossSubnet,
        _ => EncapMode::Never,
    }
}

/// Build the map of node name → VTEP from the cluster's Node list.
async fn collect_vteps(backend: &KddBackend) -> Result<BTreeMap<String, Vtep>, String> {
    let nodes: Api<Node> = Api::all(backend.client());
    let list = nodes
        .list(&Default::default())
        .await
        .map_err(|e| format!("list nodes: {e}"))?;
    Ok(build_vteps(list.items.iter()))
}

/// Assemble node name → VTEP from an iterator of Nodes, keeping only nodes whose
/// VTEP is fully published. Pure (no cluster access) so it is unit-testable.
fn build_vteps<'a>(nodes: impl IntoIterator<Item = &'a Node>) -> BTreeMap<String, Vtep> {
    let mut out = BTreeMap::new();
    for n in nodes {
        if let Some(vtep) = vtep_from_node(n) {
            out.insert(n.name_any(), vtep);
        }
    }
    out
}

/// Parse a single node's published VTEP: tunnel-IP + MAC annotations plus its
/// `InternalIP`. Returns `None` if any of the three is missing or unparseable
/// (the node has not fully published its VTEP yet).
fn vtep_from_node(n: &Node) -> Option<Vtep> {
    let ann = n.annotations();
    let tunnel_ip = ann
        .get(ANN_TUNNEL_IP)
        .and_then(|s| s.parse::<Ipv4Addr>().ok())?;
    let mac = ann.get(ANN_TUNNEL_MAC).cloned()?;
    let underlay_ip = internal_ip(n)?;
    Some(Vtep {
        tunnel_ip,
        mac,
        underlay_ip,
    })
}

fn internal_ip(node: &Node) -> Option<Ipv4Addr> {
    node.status
        .as_ref()?
        .addresses
        .as_ref()?
        .iter()
        .find(|a| a.type_ == "InternalIP")
        .and_then(|a| a.address.parse::<Ipv4Addr>().ok())
}

/// First enabled IP pool's (cidr, blockSize).
async fn first_pool(backend: &KddBackend) -> Result<(Cidr, u8), String> {
    let pools = backend
        .list(ResourceKind::IpPool, None)
        .await
        .map_err(|e| e.to_string())?;
    let pool = pools
        .iter()
        .find(|p| {
            !p.spec
                .get("disabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .ok_or("no usable IP pool")?;
    let cidr_s = pool
        .spec
        .get("cidr")
        .and_then(|v| v.as_str())
        .ok_or("pool has no cidr")?;
    let block_size = pool
        .spec
        .get("blockSize")
        .and_then(|v| v.as_u64())
        .unwrap_or(26) as u8;
    Ok((Cidr::parse(cidr_s).map_err(|e| e.to_string())?, block_size))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap as Map;

    use apis::EncapMode;
    use k8s_openapi::api::core::v1::{Node, NodeAddress, NodeStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    use super::*;

    fn pool(cidr: &str, mode: EncapMode) -> PoolEncap {
        PoolEncap {
            cidr: Cidr::parse(cidr).unwrap(),
            vxlan_mode: mode,
        }
    }

    fn block(cidr: &str) -> Cidr {
        Cidr::parse(cidr).unwrap()
    }

    #[test]
    fn resolve_encap_always_routes() {
        let pools = vec![pool("192.168.0.0/16", EncapMode::Always)];
        assert_eq!(
            resolve_encap(&pools, block("192.168.5.0/26")),
            EncapDecision::Route
        );
    }

    #[test]
    fn resolve_encap_never_skips() {
        let pools = vec![pool("192.168.0.0/16", EncapMode::Never)];
        assert_eq!(
            resolve_encap(&pools, block("192.168.5.0/26")),
            EncapDecision::Skip
        );
    }

    #[test]
    fn resolve_encap_no_pool_skips() {
        // Block outside every pool -> NoPool (skip + warn).
        let pools = vec![pool("192.168.0.0/16", EncapMode::Always)];
        assert_eq!(
            resolve_encap(&pools, block("10.0.0.0/26")),
            EncapDecision::NoPool
        );
        // Empty pool table -> NoPool.
        assert_eq!(
            resolve_encap(&[], block("10.0.0.0/26")),
            EncapDecision::NoPool
        );
    }

    #[test]
    fn resolve_encap_cross_subnet_routes_conservatively() {
        // Documented simplification: CrossSubnet is treated as always-encapsulate.
        let pools = vec![pool("192.168.0.0/16", EncapMode::CrossSubnet)];
        assert_eq!(
            resolve_encap(&pools, block("192.168.5.0/26")),
            EncapDecision::Route
        );
    }

    #[test]
    fn resolve_encap_longest_prefix_wins() {
        // Overlapping pools: the more specific containing pool's mode decides.
        let pools = vec![
            pool("10.0.0.0/8", EncapMode::Always),
            pool("10.1.0.0/16", EncapMode::Never),
        ];
        assert_eq!(
            resolve_encap(&pools, block("10.1.2.0/26")),
            EncapDecision::Skip
        );
        assert_eq!(
            resolve_encap(&pools, block("10.2.2.0/26")),
            EncapDecision::Route
        );
    }

    fn node_with(
        name: &str,
        tunnel_ip: Option<&str>,
        mac: Option<&str>,
        internal: Option<&str>,
    ) -> Node {
        let mut ann = Map::new();
        if let Some(t) = tunnel_ip {
            ann.insert(ANN_TUNNEL_IP.to_string(), t.to_string());
        }
        if let Some(m) = mac {
            ann.insert(ANN_TUNNEL_MAC.to_string(), m.to_string());
        }
        let status = internal.map(|ip| NodeStatus {
            addresses: Some(vec![NodeAddress {
                type_: "InternalIP".to_string(),
                address: ip.to_string(),
            }]),
            ..Default::default()
        });
        Node {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                annotations: Some(ann),
                ..Default::default()
            },
            status,
            ..Default::default()
        }
    }

    #[test]
    fn build_vteps_parses_and_filters_incomplete() {
        let nodes = [
            node_with(
                "node-a",
                Some("10.244.0.1"),
                Some("aa:bb:cc:dd:ee:01"),
                Some("192.168.1.10"),
            ),
            node_with(
                "node-b",
                Some("10.244.0.2"),
                Some("aa:bb:cc:dd:ee:02"),
                Some("192.168.1.11"),
            ),
            // Missing MAC / tunnel IP / InternalIP each exclude the node (VTEP
            // not yet fully published).
            node_with("node-c", Some("10.244.0.3"), None, Some("192.168.1.12")),
            node_with(
                "node-d",
                None,
                Some("aa:bb:cc:dd:ee:04"),
                Some("192.168.1.13"),
            ),
            node_with(
                "node-e",
                Some("10.244.0.5"),
                Some("aa:bb:cc:dd:ee:05"),
                None,
            ),
        ];
        let vteps = build_vteps(nodes.iter());
        assert_eq!(vteps.len(), 2);
        let a = vteps.get("node-a").expect("node-a VTEP");
        assert_eq!(a.tunnel_ip, "10.244.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(a.mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(a.underlay_ip, "192.168.1.10".parse::<Ipv4Addr>().unwrap());
        assert!(!vteps.contains_key("node-c"));
        assert!(!vteps.contains_key("node-d"));
        assert!(!vteps.contains_key("node-e"));
    }

    #[test]
    fn self_vs_remote_filtering() {
        // The reconcile loop programs every published VTEP except the local
        // node's own — mirror that filter over the parsed map.
        let nodes = [
            node_with(
                "self",
                Some("10.244.0.1"),
                Some("aa:bb:cc:dd:ee:01"),
                Some("192.168.1.10"),
            ),
            node_with(
                "peer",
                Some("10.244.0.2"),
                Some("aa:bb:cc:dd:ee:02"),
                Some("192.168.1.11"),
            ),
        ];
        let vteps = build_vteps(nodes.iter());
        let remotes: Vec<&str> = vteps
            .keys()
            .map(String::as_str)
            .filter(|n| *n != "self")
            .collect();
        assert_eq!(remotes, vec!["peer"]);
    }
}
