//! Shared support for the US1 end-to-end tests (T032 `us1_samenode`, T033
//! `us1_crossnode`, T034 `us1_egress_release`): kubeconfig discovery, the
//! `CALICO_RS_E2E` opt-in gate, minimal pod scheduling, exec-based
//! connectivity probing, and the WorkloadEndpoint/IPAMBlock no-leak checks.
//!
//! # Bringing up the environment these tests exercise
//!
//! These tests never deploy calico-rs themselves — they assume it is already
//! running as the cluster's CNI. Bring that up with:
//!
//! ```text
//! scripts/kind-cluster.sh up
//! scripts/kind-cluster.sh kubectl apply -f deploy/crds.yaml
//! scripts/kind-cluster.sh kubectl apply -f deploy/bootstrap.yaml
//! scripts/kind-cluster.sh kubectl apply -f deploy/calico-rs.yaml
//! scripts/kind-cluster.sh kubectl apply -f deploy/calico-rs-controllers.yaml
//! # wait for all nodes Ready and the calico-rs-node DaemonSet pods Running
//! CALICO_RS_E2E=1 cargo test -p e2e
//! ```
//!
//! # Gating
//!
//! Every test calls [`setup`] first. It self-skips (prints `SKIP: ...` and
//! returns `None`) unless BOTH:
//! - `CALICO_RS_E2E=1` is set (opt-in: these tests schedule real pods and
//!   need calico-rs actually deployed as the CNI — never run them by
//!   accident against an arbitrary cluster), AND
//! - a kind kubeconfig is locatable (`$KUBECONFIG`, `$E2E_KUBECONFIG`, or
//!   the repo's `.cluster/calico-rs-kind.kubeconfig`) and the cluster/CRDs
//!   are actually reachable.
//!
//! This keeps `cargo test` green with no cluster present.

#![allow(dead_code)] // not every test file exercises every helper here

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use datastore::{cidr_to_token, KddBackend, ResourceKind};
use k8s_openapi::api::core::v1::{Container, Namespace, Node, Pod, PodSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{AttachParams, DeleteParams, ListParams, PostParams};
use kube::runtime::wait::{await_condition, conditions};
use kube::{Api, Client};

/// Opt-in env var gating these tests.
const GATE_ENV: &str = "CALICO_RS_E2E";

/// A ready-to-use test environment: a kube client (for scheduling/exec) plus
/// the same datastore backend the CNI/Felix use (for CR-level assertions),
/// already gated on `CALICO_RS_E2E=1` and a reachable cluster.
pub struct Env {
    pub client: Client,
    pub backend: KddBackend,
}

/// Locate a usable kind kubeconfig: `$KUBECONFIG`, `$E2E_KUBECONFIG`, else the
/// repo's kind dev-cluster file. Returns `None` if none exist.
pub fn kubeconfig_path() -> Option<String> {
    for var in ["KUBECONFIG", "E2E_KUBECONFIG"] {
        if let Ok(p) = std::env::var(var) {
            if std::path::Path::new(&p).exists() {
                return Some(p);
            }
        }
    }
    // crates/e2e -> repo root
    let repo = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.cluster/calico-rs-kind.kubeconfig"
    );
    std::path::Path::new(repo)
        .exists()
        .then(|| repo.to_string())
}

/// Resolve gating + connect. Prints a clear `SKIP: ...` reason and returns
/// `None` if any precondition isn't met: opt-in env unset, no kubeconfig,
/// cluster unreachable, or the calico-rs CRDs this test needs aren't
/// installed. Callers should `return` immediately when this is `None`.
pub async fn setup(test_name: &str) -> Option<Env> {
    if std::env::var(GATE_ENV).as_deref() != Ok("1") {
        eprintln!(
            "SKIP[{test_name}]: {GATE_ENV}=1 not set (opt-in gate for real-cluster e2e tests)"
        );
        return None;
    }
    let Some(path) = kubeconfig_path() else {
        eprintln!(
            "SKIP[{test_name}]: no kind kubeconfig (KUBECONFIG/E2E_KUBECONFIG unset and \
             .cluster/calico-rs-kind.kubeconfig absent); run scripts/kind-cluster.sh up"
        );
        return None;
    };
    let backend = match KddBackend::from_kubeconfig_file(&path).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP[{test_name}]: cluster unreachable via {path} ({e})");
            return None;
        }
    };
    for kind in [
        ResourceKind::IpPool,
        ResourceKind::WorkloadEndpoint,
        ResourceKind::IpamBlock,
    ] {
        if let Err(e) = backend.list(kind, None).await {
            eprintln!(
                "SKIP[{test_name}]: {kind:?} CRD not reachable ({e}); apply deploy/crds.yaml"
            );
            return None;
        }
    }
    let client = backend.client();
    Some(Env { client, backend })
}

/// Whether a `kube::Error` is a 404 (Not Found) API error.
fn is_not_found(e: &kube::Error) -> bool {
    matches!(e, kube::Error::Api(s) if s.code == 404)
}

/// Poll `cond` every `interval` until it returns `true` or `timeout` elapses.
/// Returns whether it became true in time.
pub async fn poll_until<F, Fut>(timeout: Duration, interval: Duration, mut cond: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if cond().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(interval).await;
    }
}

// ---------------------------------------------------------------------------
// Namespace / pod hygiene
// ---------------------------------------------------------------------------

/// Ensure `ns` exists and is usable. If a namespace of the same (fixed) test
/// name is left over `Terminating` from a prior aborted run, wait (bounded)
/// for it to fully disappear before recreating it — creating objects in a
/// `Terminating` namespace is rejected by the API server. If it exists and is
/// `Active`, it's reused as-is (pods are pre-deleted individually by the
/// caller for a clean slate, see [`delete_pod_if_exists`]).
pub async fn ensure_clean_namespace(client: &Client, ns: &str) -> Result<(), String> {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    match namespaces.get(ns).await {
        Ok(existing) => {
            if existing.metadata.deletion_timestamp.is_some() {
                let gone = poll_until(Duration::from_secs(45), Duration::from_secs(2), || async {
                    matches!(namespaces.get(ns).await, Err(e) if is_not_found(&e))
                })
                .await;
                if !gone {
                    return Err(format!(
                        "namespace {ns} still Terminating from a prior run after 45s"
                    ));
                }
            } else {
                return Ok(());
            }
        }
        Err(e) if is_not_found(&e) => {}
        Err(e) => return Err(format!("get namespace {ns}: {e}")),
    }
    let obj = Namespace {
        metadata: ObjectMeta {
            name: Some(ns.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    match namespaces.create(&PostParams::default(), &obj).await {
        Ok(_) => Ok(()),
        // Lost a create race against a parallel test run; fine either way.
        Err(kube::Error::Api(s)) if s.code == 409 => Ok(()),
        Err(e) => Err(format!("create namespace {ns}: {e}")),
    }
}

/// Best-effort namespace delete at the end of a test. Fire-and-forget: does
/// not wait for termination to complete (that can take tens of seconds and
/// would slow every run down for no benefit — the next run's
/// [`ensure_clean_namespace`] tolerates a namespace still `Terminating`).
pub async fn delete_namespace_best_effort(client: &Client, ns: &str) {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let _ = namespaces.delete(ns, &DeleteParams::default()).await;
}

/// Delete `name` in `ns` if present (grace period 0) and wait for it to fully
/// disappear, for a clean slate before (re)creating a pod of the same fixed
/// name. A no-op if the pod isn't present.
pub async fn delete_pod_if_exists(
    client: &Client,
    ns: &str,
    name: &str,
    timeout: Duration,
) -> Result<(), String> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    let dp = DeleteParams {
        grace_period_seconds: Some(0),
        ..Default::default()
    };
    match pods.delete(name, &dp).await {
        Ok(_) => {}
        Err(e) if is_not_found(&e) => return Ok(()),
        Err(e) => return Err(format!("delete pod {ns}/{name}: {e}")),
    }
    let gone = poll_until(timeout, Duration::from_secs(1), || async {
        matches!(pods.get(name).await, Err(e) if is_not_found(&e))
    })
    .await;
    if gone {
        Ok(())
    } else {
        Err(format!(
            "pod {ns}/{name} did not disappear within {timeout:?} of a pre-test delete"
        ))
    }
}

/// Wait for `name` in `ns` to be fully gone from the API (used after deleting
/// a pod, so the T034 no-leak checks run only once teardown has completed).
pub async fn wait_pod_gone(
    client: &Client,
    ns: &str,
    name: &str,
    timeout: Duration,
) -> Result<(), String> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    let gone = poll_until(timeout, Duration::from_secs(1), || async {
        matches!(pods.get(name).await, Err(e) if is_not_found(&e))
    })
    .await;
    if gone {
        Ok(())
    } else {
        Err(format!(
            "pod {ns}/{name} still present {timeout:?} after delete"
        ))
    }
}

/// A minimal long-lived probe pod: `busybox`, pinned to `node` via
/// `kubernetes.io/hostname`, running `sleep 3600` so it stays up for exec
/// probes. `restartPolicy: Never` + a short grace period keep teardown fast.
pub fn busybox_pod(name: &str, ns: &str, node: &str) -> Pod {
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "calico-rs-e2e".to_string());

    let mut node_selector = BTreeMap::new();
    node_selector.insert("kubernetes.io/hostname".to_string(), node.to_string());

    Pod {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(ns.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(PodSpec {
            containers: vec![Container {
                name: "probe".to_string(),
                image: Some("busybox:1.36".to_string()),
                command: Some(vec!["sleep".to_string(), "3600".to_string()]),
                ..Default::default()
            }],
            node_selector: Some(node_selector),
            restart_policy: Some("Never".to_string()),
            termination_grace_period_seconds: Some(2),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub async fn create_pod(client: &Client, ns: &str, pod: &Pod) -> Result<(), String> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    let name = pod.metadata.name.clone().unwrap_or_default();
    pods.create(&PostParams::default(), pod)
        .await
        .map(|_| ())
        .map_err(|e| format!("create pod {ns}/{name}: {e}"))
}

/// Wait for `name` to reach `Running` (via [`conditions::is_pod_running`]),
/// then poll briefly for `status.podIP` (it usually lands with the phase
/// transition but can trail by a beat). Returns `(podIP, spec.nodeName)`.
pub async fn wait_running_with_ip(
    client: &Client,
    ns: &str,
    name: &str,
    timeout: Duration,
) -> Result<(String, String), String> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    tokio::time::timeout(
        timeout,
        await_condition(pods.clone(), name, conditions::is_pod_running()),
    )
    .await
    .map_err(|_| format!("pod {ns}/{name} did not reach Running within {timeout:?}"))?
    .map_err(|e| format!("watching pod {ns}/{name}: {e}"))?;

    let ip_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let pod = pods
            .get(name)
            .await
            .map_err(|e| format!("get pod {ns}/{name}: {e}"))?;
        if let Some(ip) = pod.status.as_ref().and_then(|s| s.pod_ip.clone()) {
            let node_name = pod
                .spec
                .as_ref()
                .and_then(|s| s.node_name.clone())
                .ok_or_else(|| format!("pod {ns}/{name} has no spec.nodeName"))?;
            return Ok((ip, node_name));
        }
        if tokio::time::Instant::now() >= ip_deadline {
            return Err(format!(
                "pod {ns}/{name} is Running but got no podIP within 10s of that"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

// ---------------------------------------------------------------------------
// Node inventory
// ---------------------------------------------------------------------------

/// Names of `Ready` nodes with no hard (`NoSchedule`/`NoExecute`) taint —
/// i.e. nodes a plain, toleration-less pod can actually land on. Sorted for
/// deterministic test behavior.
pub async fn schedulable_worker_nodes(client: &Client) -> Vec<String> {
    let nodes: Api<Node> = Api::all(client.clone());
    let Ok(list) = nodes.list(&ListParams::default()).await else {
        return Vec::new();
    };
    let mut names: Vec<String> = list
        .items
        .into_iter()
        .filter_map(|n| {
            let name = n.metadata.name?;
            let ready = n
                .status
                .as_ref()?
                .conditions
                .as_ref()?
                .iter()
                .any(|c| c.type_ == "Ready" && c.status == "True");
            if !ready {
                return None;
            }
            let hard_tainted =
                n.spec
                    .as_ref()
                    .and_then(|s| s.taints.as_ref())
                    .is_some_and(|taints| {
                        taints
                            .iter()
                            .any(|t| t.effect == "NoSchedule" || t.effect == "NoExecute")
                    });
            if hard_tainted {
                return None;
            }
            Some(name)
        })
        .collect();
    names.sort();
    names
}

/// The `InternalIP` address of node `name`, if reported.
pub async fn node_internal_ip(client: &Client, name: &str) -> Option<String> {
    let nodes: Api<Node> = Api::all(client.clone());
    let node = nodes.get(name).await.ok()?;
    node.status?
        .addresses?
        .into_iter()
        .find(|a| a.type_ == "InternalIP")
        .map(|a| a.address)
}

// ---------------------------------------------------------------------------
// Exec-based connectivity probing
// ---------------------------------------------------------------------------

/// Exec `cmd` in `pod`'s single container and wait for it to exit. `Ok(stdout)`
/// if the command's own exit code was 0 (per the Kubernetes exec subresource's
/// `Status`), `Err(details)` otherwise (non-zero exit, or a websocket/API
/// failure) — this checks the real process exit code, not just that the
/// exec call was accepted.
pub async fn exec_cmd(
    client: &Client,
    ns: &str,
    pod: &str,
    cmd: &[&str],
    timeout: Duration,
) -> Result<String, String> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    let ap = AttachParams::default().stdout(true).stderr(true);
    let mut proc = tokio::time::timeout(timeout, pods.exec(pod, cmd.to_vec(), &ap))
        .await
        .map_err(|_| format!("exec {cmd:?} in {ns}/{pod} timed out after {timeout:?}"))?
        .map_err(|e| format!("exec {cmd:?} in {ns}/{pod} failed to start: {e}"))?;

    let mut stdout = proc.stdout().expect("stdout requested via AttachParams");
    let mut stderr = proc.stderr().expect("stderr requested via AttachParams");
    let status_fut = proc.take_status().expect("take_status called at most once");

    let mut out = String::new();
    let mut err = String::new();
    let (_, _, status) = tokio::join!(
        async {
            let _ = tokio::io::AsyncReadExt::read_to_string(&mut stdout, &mut out).await;
        },
        async {
            let _ = tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut err).await;
        },
        status_fut,
    );
    proc.join()
        .await
        .map_err(|e| format!("exec {cmd:?} in {ns}/{pod}: connection error: {e}"))?;

    match status {
        Some(s) if s.status.as_deref() == Some("Success") => Ok(out),
        Some(s) => Err(format!(
            "exec {cmd:?} in {ns}/{pod}: exit status {:?} reason {:?}; stdout={out:?} stderr={err:?}",
            s.status, s.reason
        )),
        None => Err(format!(
            "exec {cmd:?} in {ns}/{pod}: no exit status received; stdout={out:?} stderr={err:?}"
        )),
    }
}

/// `ping -c1` from `pod` to `target_ip`, asserting success (exit code 0).
pub async fn exec_ping(
    client: &Client,
    ns: &str,
    pod: &str,
    target_ip: &str,
    timeout: Duration,
) -> Result<(), String> {
    exec_cmd(
        client,
        ns,
        pod,
        &["ping", "-c", "1", "-W", "3", target_ip],
        timeout,
    )
    .await
    .map(|_| ())
}

// ---------------------------------------------------------------------------
// IPAM / CR assertions
// ---------------------------------------------------------------------------

/// The CIDR + block size of the first enabled `IPPool`. Errors if none is
/// enabled or its `cidr` doesn't parse.
pub async fn ippool_cidr_and_block_size(backend: &KddBackend) -> Result<(ipam::Cidr, u8), String> {
    let pools = backend
        .list(ResourceKind::IpPool, None)
        .await
        .map_err(|e| format!("list IPPool: {e}"))?;
    for kv in pools {
        let spec: apis::IpPoolSpec = match serde_json::from_value(kv.spec.clone()) {
            Ok(s) => s,
            Err(e) => return Err(format!("IPPool {} spec did not parse: {e}", kv.name)),
        };
        if spec.disabled {
            continue;
        }
        let cidr = ipam::Cidr::parse(&spec.cidr)
            .map_err(|e| format!("IPPool {} cidr {:?}: {e}", kv.name, spec.cidr))?;
        let block_size = spec.block_size.unwrap_or(match cidr.network() {
            IpAddr::V4(_) => 26,
            IpAddr::V6(_) => 122,
        });
        return Ok((cidr, block_size));
    }
    Err("no enabled IPPool found".to_string())
}

/// The predictable `WorkloadEndpoint` name the CNI assigns, mirroring
/// `cni::WepIdentifiers::workload_endpoint_name`: `<node>-k8s-<pod>-eth0`
/// with dots in the pod name sanitized to dashes.
pub fn workload_endpoint_name(node: &str, pod: &str) -> String {
    format!("{node}-k8s-{}-eth0", pod.replace('.', "-"))
}

/// Poll (bounded) for the given `WorkloadEndpoint` CR to be gone — part of
/// the T034 SC-002 no-leak assertion: pod teardown must remove the WEP, not
/// just the pod.
pub async fn wait_workload_endpoint_absent(
    backend: &KddBackend,
    ns: &str,
    wep_name: &str,
    timeout: Duration,
) -> Result<(), String> {
    let gone = poll_until(timeout, Duration::from_secs(1), || async {
        matches!(
            backend
                .get(ResourceKind::WorkloadEndpoint, Some(ns), wep_name)
                .await,
            Ok(None)
        )
    })
    .await;
    if gone {
        Ok(())
    } else {
        Err(format!(
            "WorkloadEndpoint {ns}/{wep_name} still present after {timeout:?} (leak)"
        ))
    }
}

/// Poll (bounded) for the IPAMBlock allocation backing `ip` to be freed: the
/// block's `allocations[ordinal]` is `null`, or the whole block is gone. This
/// is the concrete SC-002 (no address leak) check for T034 — it doesn't rely
/// on knowing the IPAM handle id (which is derived from the container id, not
/// predictable ahead of time), only on the released IP and the pool's block
/// size.
pub async fn wait_ipam_allocation_freed(
    backend: &KddBackend,
    block_size: u8,
    ip: IpAddr,
    timeout: Duration,
) -> Result<(), String> {
    let block = ipam::Cidr::new(ip, block_size).map_err(|e| e.to_string())?;
    let ordinal = block
        .ordinal_of(ip)
        .ok_or_else(|| format!("{ip} not within its own computed block {block}?!"))?;
    let block_name = cidr_to_token(&format!("{}/{}", block.network(), block.prefix_len()));

    let free = poll_until(timeout, Duration::from_secs(1), || async {
        match backend
            .get(ResourceKind::IpamBlock, None, &block_name)
            .await
        {
            Ok(None) => true, // whole block gone -> trivially freed
            Ok(Some(kv)) => kv
                .spec
                .get("allocations")
                .and_then(|a| a.as_array())
                .and_then(|a| a.get(ordinal))
                .map(|v| v.is_null())
                .unwrap_or(false),
            Err(_) => false,
        }
    })
    .await;
    if free {
        Ok(())
    } else {
        Err(format!(
            "IPAMBlock {block_name} ordinal {ordinal} (ip {ip}) still allocated after {timeout:?} \
             (IP leak, SC-002 violated)"
        ))
    }
}
