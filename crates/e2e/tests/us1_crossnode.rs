//! T033 — US1 independent test: cross-node connectivity via the VXLAN
//! overlay.
//!
//! Schedules two `busybox` pods on two DIFFERENT nodes (explicit distinct
//! `kubernetes.io/hostname` nodeSelectors), waits for both `Running` with an
//! assigned pod IP, then `ping`s from pod-on-node-A to pod-on-node-B's IP.
//! Since the pods are on different hosts, the ICMP echo must cross the VXLAN
//! overlay (T045) using the routes Felix programs for remote workload
//! blocks (T043/T044) — this is exactly the dataplane path same-node tests
//! (T032) can't exercise.
//!
//! Self-skips unless `CALICO_RS_E2E=1` is set AND a kind kubeconfig is
//! reachable (see `tests/common/mod.rs`), and additionally skips with a
//! clear message if the cluster has fewer than 2 schedulable nodes.

mod common;

use std::time::Duration;

use common::*;
use kube::Client;

const NAMESPACE: &str = "e2e-us1-crossnode";
const POD_A: &str = "us1-crossnode-a";
const POD_B: &str = "us1-crossnode-b";

#[tokio::test]
async fn us1_crossnode_vxlan_connectivity() {
    let Some(env) = setup("us1_crossnode").await else {
        return;
    };
    let Env { client, backend } = env;

    let (pool_cidr, _block_size) = match ippool_cidr_and_block_size(&backend).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("SKIP[us1_crossnode]: {e}");
            return;
        }
    };

    let nodes = schedulable_worker_nodes(&client).await;
    if nodes.len() < 2 {
        eprintln!(
            "SKIP[us1_crossnode]: need >=2 schedulable nodes for a cross-node test, found {} ({nodes:?})",
            nodes.len()
        );
        return;
    }
    let node_a = nodes[0].clone();
    let node_b = nodes[1].clone();

    let result = run(&client, &node_a, &node_b, &pool_cidr).await;
    cleanup(&client).await;
    result.expect("US1 cross-node independent test failed");
}

async fn run(
    client: &Client,
    node_a: &str,
    node_b: &str,
    pool_cidr: &ipam::Cidr,
) -> Result<(), String> {
    ensure_clean_namespace(client, NAMESPACE).await?;
    delete_pod_if_exists(client, NAMESPACE, POD_A, Duration::from_secs(30)).await?;
    delete_pod_if_exists(client, NAMESPACE, POD_B, Duration::from_secs(30)).await?;

    create_pod(client, NAMESPACE, &busybox_pod(POD_A, NAMESPACE, node_a)).await?;
    create_pod(client, NAMESPACE, &busybox_pod(POD_B, NAMESPACE, node_b)).await?;

    let (ip_a, landed_a) =
        wait_running_with_ip(client, NAMESPACE, POD_A, Duration::from_secs(90)).await?;
    let (ip_b, landed_b) =
        wait_running_with_ip(client, NAMESPACE, POD_B, Duration::from_secs(90)).await?;

    if landed_a != node_a {
        return Err(format!("pod A landed on {landed_a}, expected {node_a}"));
    }
    if landed_b != node_b {
        return Err(format!("pod B landed on {landed_b}, expected {node_b}"));
    }
    if landed_a == landed_b {
        return Err(format!(
            "pod A and pod B both landed on {landed_a} — not actually a cross-node test"
        ));
    }

    for (label, ip) in [("A", &ip_a), ("B", &ip_b)] {
        let addr: std::net::IpAddr = ip
            .parse()
            .map_err(|e| format!("pod {label} podIP {ip:?} unparsable: {e}"))?;
        let host = ipam::Cidr::new(addr, if addr.is_ipv4() { 32 } else { 128 })
            .map_err(|e| e.to_string())?;
        if !pool_cidr.contains(&host) {
            return Err(format!(
                "pod {label} IP {ip} is not within pool CIDR {pool_cidr}"
            ));
        }
    }

    exec_ping(client, NAMESPACE, POD_A, &ip_b, Duration::from_secs(20))
        .await
        .map_err(|e| {
            format!(
                "cross-node connectivity {node_a}/pod A -> {node_b}/pod B ({ip_b}) over VXLAN failed: {e}"
            )
        })
}

async fn cleanup(client: &Client) {
    delete_namespace_best_effort(client, NAMESPACE).await;
}
