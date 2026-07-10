//! T032 — US1 independent test: same-node pod networking.
//!
//! Schedules two `busybox` pods pinned to the SAME node (via the
//! `kubernetes.io/hostname` nodeSelector), waits for both to reach `Running`
//! with an assigned pod IP, and asserts:
//! - both IPs fall within the configured `IPPool` CIDR,
//! - the two IPs are distinct (unique pool allocation, no double-assign),
//! - pod A can `ping` pod B's IP (same-node pod-to-pod connectivity over the
//!   veth pair + host routes Felix programs — no VXLAN hop needed, that's
//!   T033's job).
//!
//! Self-skips unless `CALICO_RS_E2E=1` is set AND a kind kubeconfig is
//! reachable — see `tests/common/mod.rs` for the gating rules and how to
//! bring up the environment (`scripts/kind-cluster.sh` + `deploy/`). This
//! test only schedules workloads; it never deploys calico-rs itself.

mod common;

use std::time::Duration;

use common::*;
use kube::Client;

const NAMESPACE: &str = "e2e-us1-samenode";
const POD_A: &str = "us1-samenode-a";
const POD_B: &str = "us1-samenode-b";

#[tokio::test]
async fn us1_samenode_unique_ip_and_connectivity() {
    let Some(env) = setup("us1_samenode").await else {
        return;
    };
    let Env { client, backend } = env;

    let (pool_cidr, _block_size) = match ippool_cidr_and_block_size(&backend).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("SKIP[us1_samenode]: {e}");
            return;
        }
    };

    let nodes = schedulable_worker_nodes(&client).await;
    let Some(node) = nodes.first().cloned() else {
        eprintln!("SKIP[us1_samenode]: no schedulable (Ready, untainted) node found");
        return;
    };

    let result = run(&client, &node, &pool_cidr).await;
    cleanup(&client).await;
    result.expect("US1 same-node independent test failed");
}

async fn run(client: &Client, node: &str, pool_cidr: &ipam::Cidr) -> Result<(), String> {
    ensure_clean_namespace(client, NAMESPACE).await?;
    delete_pod_if_exists(client, NAMESPACE, POD_A, Duration::from_secs(30)).await?;
    delete_pod_if_exists(client, NAMESPACE, POD_B, Duration::from_secs(30)).await?;

    create_pod(client, NAMESPACE, &busybox_pod(POD_A, NAMESPACE, node)).await?;
    create_pod(client, NAMESPACE, &busybox_pod(POD_B, NAMESPACE, node)).await?;

    let (ip_a, node_a) =
        wait_running_with_ip(client, NAMESPACE, POD_A, Duration::from_secs(90)).await?;
    let (ip_b, node_b) =
        wait_running_with_ip(client, NAMESPACE, POD_B, Duration::from_secs(90)).await?;

    if node_a != node {
        return Err(format!("pod A landed on {node_a}, expected {node}"));
    }
    if node_b != node {
        return Err(format!("pod B landed on {node_b}, expected {node}"));
    }

    let addr_a: std::net::IpAddr = ip_a
        .parse()
        .map_err(|e| format!("pod A podIP {ip_a:?} unparsable: {e}"))?;
    let addr_b: std::net::IpAddr = ip_b
        .parse()
        .map_err(|e| format!("pod B podIP {ip_b:?} unparsable: {e}"))?;

    let host_a = ipam::Cidr::new(addr_a, if addr_a.is_ipv4() { 32 } else { 128 })
        .map_err(|e| e.to_string())?;
    let host_b = ipam::Cidr::new(addr_b, if addr_b.is_ipv4() { 32 } else { 128 })
        .map_err(|e| e.to_string())?;
    if !pool_cidr.contains(&host_a) {
        return Err(format!(
            "pod A IP {ip_a} is not within pool CIDR {pool_cidr}"
        ));
    }
    if !pool_cidr.contains(&host_b) {
        return Err(format!(
            "pod B IP {ip_b} is not within pool CIDR {pool_cidr}"
        ));
    }
    if ip_a == ip_b {
        return Err(format!(
            "pod A and pod B were both assigned {ip_a} — IPAM double-allocation"
        ));
    }

    exec_ping(client, NAMESPACE, POD_A, &ip_b, Duration::from_secs(20))
        .await
        .map_err(|e| format!("same-node connectivity pod A -> pod B ({ip_b}) failed: {e}"))
}

async fn cleanup(client: &Client) {
    delete_namespace_best_effort(client, NAMESPACE).await;
}
