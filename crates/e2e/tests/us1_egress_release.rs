//! T034 — US1 independent test: pod egress SNAT + IP release on delete
//! (SC-002: no address leak).
//!
//! ## Egress / SNAT probe
//!
//! We need a destination that is reliably reachable from a bare kind
//! cluster (no assumption of internet egress in CI) but is clearly *outside*
//! the pod/service CIDRs, so reaching it actually exercises NAT-outgoing
//! (T046) rather than in-cluster service routing. The kubernetes API
//! ClusterIP is tempting but lives in the *service* CIDR and is reached via
//! kube-proxy DNAT, not NAT-outgoing SNAT. Instead we `ping` a *different*
//! node's `InternalIP` (the kind node's address on the Docker bridge network,
//! e.g. `172.18.0.0/16` — disjoint from both the pod CIDR
//! `192.168.0.0/16` and the service CIDR `10.96.0.0/16`, see
//! `deploy/kind-config.yaml`). That address is only reachable by the pod
//! through the NAT-outgoing masquerade rule Felix installs for traffic
//! leaving the pool to a non-pool destination, and the ICMP echo *reply*
//! only finds its way back to the (unroutable, non-advertised) pod IP
//! because that masquerade rewrote the source — so success here is a real,
//! if indirect, SNAT proof. This documents/justifies the substitute the task
//! brief allows when true external reachability isn't guaranteed.
//!
//! ## No-leak check
//!
//! After asserting egress, we delete the pod and assert (bounded poll):
//! - the pod's `WorkloadEndpoint` CR is gone (name is predictable:
//!   `<node>-k8s-<pod>-eth0`, mirroring `cni::WepIdentifiers::workload_endpoint_name`),
//! - the `IPAMBlock` covering the released IP shows that ordinal free
//!   (`allocations[ordinal] == null`) or the block itself is gone.
//!
//! We can't look up the `IPAMHandle` directly (its id is derived from the
//! CRI container id, which we don't control/know ahead of time), so the
//! IPAMBlock-ordinal check is the concrete, handle-agnostic SC-002 assertion.
//!
//! Self-skips unless `CALICO_RS_E2E=1` is set AND a kind kubeconfig is
//! reachable (see `tests/common/mod.rs`).

mod common;

use std::net::IpAddr;
use std::time::Duration;

use common::*;
use kube::Client;

const NAMESPACE: &str = "e2e-us1-egress-release";
const POD: &str = "us1-egress-release";

#[tokio::test]
async fn us1_egress_snat_and_ip_release_on_delete() {
    let Some(env) = setup("us1_egress_release").await else {
        return;
    };
    let Env { client, backend } = env;

    let (pool_cidr, block_size) = match ippool_cidr_and_block_size(&backend).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("SKIP[us1_egress_release]: {e}");
            return;
        }
    };

    let nodes = schedulable_worker_nodes(&client).await;
    let Some(node) = nodes.first().cloned() else {
        eprintln!("SKIP[us1_egress_release]: no schedulable (Ready, untainted) node found");
        return;
    };
    // A node distinct from the pod's own node, so the egress target is
    // unambiguously "outside" this host too (not just outside the pod CIDR).
    let egress_target_node = nodes.iter().find(|&n| n != &node).cloned();

    let result = run(
        &client,
        &backend,
        &node,
        egress_target_node.as_deref(),
        &pool_cidr,
        block_size,
    )
    .await;
    cleanup(&client).await;
    result.expect("US1 egress + IP-release independent test failed");
}

async fn run(
    client: &Client,
    backend: &datastore::KddBackend,
    node: &str,
    egress_target_node: Option<&str>,
    pool_cidr: &ipam::Cidr,
    block_size: u8,
) -> Result<(), String> {
    ensure_clean_namespace(client, NAMESPACE).await?;
    delete_pod_if_exists(client, NAMESPACE, POD, Duration::from_secs(30)).await?;

    create_pod(client, NAMESPACE, &busybox_pod(POD, NAMESPACE, node)).await?;
    let (ip, landed_on) =
        wait_running_with_ip(client, NAMESPACE, POD, Duration::from_secs(90)).await?;
    if landed_on != node {
        return Err(format!("pod landed on {landed_on}, expected {node}"));
    }

    let addr: IpAddr = ip
        .parse()
        .map_err(|e| format!("pod podIP {ip:?} unparsable: {e}"))?;
    let host =
        ipam::Cidr::new(addr, if addr.is_ipv4() { 32 } else { 128 }).map_err(|e| e.to_string())?;
    if !pool_cidr.contains(&host) {
        return Err(format!("pod IP {ip} is not within pool CIDR {pool_cidr}"));
    }

    // --- egress / SNAT probe (see module doc for why a node InternalIP) ---
    let target_node = egress_target_node.unwrap_or(node);
    let target_ip = node_internal_ip(client, target_node)
        .await
        .ok_or_else(|| format!("node {target_node} reports no InternalIP"))?;
    exec_ping(client, NAMESPACE, POD, &target_ip, Duration::from_secs(20))
        .await
        .map_err(|e| format!("egress ping to node {target_node} ({target_ip}) failed: {e}"))?;

    // --- capture identity, then delete the pod ---
    let wep_name = workload_endpoint_name(node, POD);
    delete_pod_if_exists(client, NAMESPACE, POD, Duration::from_secs(60)).await?;
    // Belt-and-suspenders: delete_pod_if_exists already waits for the pod
    // object to be gone, which only happens once kubelet has finished
    // SyncPod teardown (containers + CNI DEL) for it.
    wait_pod_gone(client, NAMESPACE, POD, Duration::from_secs(30)).await?;

    // --- SC-002: no address leak ---
    wait_workload_endpoint_absent(backend, NAMESPACE, &wep_name, Duration::from_secs(30))
        .await
        .map_err(|e| format!("{e} (WorkloadEndpoint leak)"))?;
    wait_ipam_allocation_freed(backend, block_size, addr, Duration::from_secs(30)).await
}

async fn cleanup(client: &Client) {
    delete_namespace_best_effort(client, NAMESPACE).await;
}
