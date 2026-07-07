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
use std::net::Ipv4Addr;
use std::time::Duration;

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

/// Allocate a /32 tunnel IP for this node from the first enabled IP pool. Uses a
/// stable handle so repeated calls (e.g. before the annotation is published) do
/// not leak addresses.
async fn allocate_tunnel_ip(backend: &KddBackend, node_name: &str) -> Result<Ipv4Addr, String> {
    let (pool_cidr, block_size) = first_pool(backend).await?;
    let ipam = KddIpam::new(KddBackend::new(backend.client()));
    let handle_id = format!("vxlan-tunnel-{node_name}");
    let attrs = BTreeMap::from([
        ("node".to_string(), node_name.to_string()),
        ("type".to_string(), "vxlanTunnelAddress".to_string()),
    ]);
    let ips = ipam
        .auto_assign_from_pool_with_attrs(node_name, pool_cidr, block_size, &handle_id, &attrs, 1)
        .await
        .map_err(|e| format!("allocate tunnel IP: {e}"))?;
    match ips.into_iter().next() {
        Some(std::net::IpAddr::V4(v4)) => Ok(v4),
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

    // Routes for each block owned by a remote node.
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
        let dst = match cidr.network() {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => continue, // IPv6 overlay not yet supported
        };
        vxlan::replace_route(h, dst, cidr.prefix_len(), vtep.tunnel_ip, vxlan_idx).await?;
    }
    Ok(())
}

/// Build the map of node name → VTEP from published annotations + InternalIP.
async fn collect_vteps(backend: &KddBackend) -> Result<BTreeMap<String, Vtep>, String> {
    let nodes: Api<Node> = Api::all(backend.client());
    let list = nodes
        .list(&Default::default())
        .await
        .map_err(|e| format!("list nodes: {e}"))?;
    let mut out = BTreeMap::new();
    for n in list {
        let ann = n.annotations();
        let tunnel_ip = ann
            .get(ANN_TUNNEL_IP)
            .and_then(|s| s.parse::<Ipv4Addr>().ok());
        let mac = ann.get(ANN_TUNNEL_MAC).cloned();
        let underlay_ip = internal_ip(&n);
        if let (Some(tunnel_ip), Some(mac), Some(underlay_ip)) = (tunnel_ip, mac, underlay_ip) {
            out.insert(
                n.name_any(),
                Vtep {
                    tunnel_ip,
                    mac,
                    underlay_ip,
                },
            );
        }
    }
    Ok(out)
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
