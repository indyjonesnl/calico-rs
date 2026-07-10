//! T049 — US2 independent test: label-selector NetworkPolicy allow/deny +
//! policy-update latency, against a real cluster with calico-rs deployed as
//! CNI + policy enforcer.
//!
//! Schedules three `busybox`-family pods in a fresh namespace: a `role=server`
//! (a real listening TCP socket via `busybox httpd`), a `role=client`
//! ("allowed"), and a `role=other` ("blocked"). It then:
//! 1. asserts baseline open-by-default connectivity (no policy yet — both
//!    clients reach the server, per the namespace's default-allow Profile),
//! 2. applies a Calico `NetworkPolicy` selecting `role=server` that allows
//!    ingress only from `role=client`, and polls (bounded) for `role=other` to
//!    become denied while `role=client` stays allowed,
//! 3. edits that policy (extends the allow to `role=other` too) and measures
//!    how long the dataplane takes to reflect it, asserting < 5s (the spec's
//!    policy-propagation SC) while also confirming the already-allowed client
//!    stays connected across the edit,
//! 4. cleans up the namespace (best-effort, even on failure).
//!
//! Self-skips unless `CALICO_RS_E2E=1` is set AND a kind kubeconfig is
//! reachable — see `tests/common/mod.rs` for the gating rules and how to bring
//! up the environment:
//!
//! ```text
//! scripts/kind-cluster.sh up
//! scripts/kind-cluster.sh kubectl apply -f deploy/crds.yaml
//! scripts/kind-cluster.sh kubectl apply -f deploy/bootstrap.yaml
//! scripts/kind-cluster.sh kubectl apply -f deploy/calico-rs.yaml
//! scripts/kind-cluster.sh kubectl apply -f deploy/calico-rs-controllers.yaml
//! # wait for all nodes Ready and the calico-rs-node DaemonSet pods Running
//! CALICO_RS_E2E=1 cargo test -p e2e --test us2_policy
//! ```
//!
//! # Calico-native vs. K8s-native NetworkPolicy
//!
//! This test applies a **Calico-native** `crd.projectcalico.org/v1
//! NetworkPolicy` (`apis::NetworkPolicySpec`), not a plain Kubernetes
//! `networking.k8s.io/v1 NetworkPolicy`. That is a deliberate choice, not just
//! a preference: as of this task, `KddBackend::api_resource` (see
//! `crates/datastore/src/kdd.rs`) hardcodes the `crd.projectcalico.org` group
//! for every `ResourceKind::NetworkPolicy` list/watch/get, and
//! `felix_syncer_kinds()` (`crates/datastore/src/syncers.rs`) explicitly omits
//! the native K8s kinds from what felix watches. The K8s-NP → Calico
//! conversion exists (`calc::k8s_policy::k8s_network_policy_to_eval`, T059) but
//! is a pure, unwired projection function — no controller loop watches
//! `networking.k8s.io/v1` NetworkPolicy objects and writes the Calico CR yet
//! (that's T101, still open). Applying a plain K8s NetworkPolicy today would
//! have **no dataplane effect at all**; only the Calico-native CR is live.
//!
//! # Known current-implementation caveats (not bugs in this test)
//!
//! - `crates/node/src/main.rs` runs `felix::reconcile::run` scoped to a
//!   **single, fixed namespace** (`FELIX_POLICY_NAMESPACE`, default
//!   `"default"`) — not "all namespaces". A stock `deploy/calico-rs.yaml` will
//!   therefore not observe a `NetworkPolicy` created in this test's own
//!   namespace unless the DaemonSet is redeployed with
//!   `FELIX_POLICY_NAMESPACE=e2e-us2-policy` (or a future task generalizes the
//!   loop to watch every namespace). If step 2 below times out, that env var
//!   mismatch is the first thing to check.
//! - That reconcile loop polls the datastore on a **fixed 10s interval**
//!   (`Duration::from_secs(10)` in `crates/node/src/main.rs`) rather than
//!   watch-driven immediate reconcile (the event-sequencer/watch wiring is a
//!   later task). A fixed 10s poll cannot deterministically meet the <5s
//!   latency SC this test asserts — that assertion is intentionally written
//!   to the *target* spec behavior, so it is expected to fail against today's
//!   poll-only implementation until that wiring lands. This test still MUST
//!   self-skip cleanly with no cluster; it is not expected to "fake a pass".

mod common;

use std::time::Duration;

use apis::{Action, EntityRule, NetworkPolicySpec, PolicyType, Protocol, Rule};
use common::*;
use datastore::KddBackend;
use kube::Client;

const NAMESPACE: &str = "e2e-us2-policy";
const POD_SERVER: &str = "us2-server";
const POD_CLIENT_ALLOWED: &str = "us2-client-allowed";
const POD_CLIENT_BLOCKED: &str = "us2-client-blocked";
const POLICY_NAME: &str = "us2-allow-client";
const SERVER_PORT: u16 = 8080;

/// Bounded outer deadlines: felix's fixed 10s poll (see the module doc) means
/// convergence can trail an edit by up to ~10-20s in the current
/// implementation, so these deadlines are generous *convergence* bounds — the
/// separate <5s assertion on the second edit is the actual latency SC check.
const CONVERGE_DEADLINE: Duration = Duration::from_secs(30);
const CONVERGE_POLL_INTERVAL: Duration = Duration::from_millis(500);
const LATENCY_SC_BUDGET: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn us2_label_policy_allow_deny_and_update_latency() {
    let Some(env) = setup("us2_policy").await else {
        return;
    };
    let Env { client, backend } = env;

    let nodes = schedulable_worker_nodes(&client).await;
    let Some(node) = nodes.first().cloned() else {
        eprintln!("SKIP[us2_policy]: no schedulable (Ready, untainted) node found");
        return;
    };

    let result = run(&client, &backend, &node).await;
    cleanup(&client, &backend).await;
    result.expect("US2 label-policy independent test failed");
}

async fn run(client: &Client, backend: &KddBackend, node: &str) -> Result<(), String> {
    ensure_clean_namespace(client, NAMESPACE).await?;
    delete_pod_if_exists(client, NAMESPACE, POD_SERVER, Duration::from_secs(30)).await?;
    delete_pod_if_exists(
        client,
        NAMESPACE,
        POD_CLIENT_ALLOWED,
        Duration::from_secs(30),
    )
    .await?;
    delete_pod_if_exists(
        client,
        NAMESPACE,
        POD_CLIENT_BLOCKED,
        Duration::from_secs(30),
    )
    .await?;
    delete_network_policy_if_exists(backend, NAMESPACE, POLICY_NAME).await?;

    create_pod(
        client,
        NAMESPACE,
        &http_server_pod(
            POD_SERVER,
            NAMESPACE,
            node,
            SERVER_PORT,
            &[("role", "server")],
        ),
    )
    .await?;
    create_pod(
        client,
        NAMESPACE,
        &busybox_pod_with_labels(POD_CLIENT_ALLOWED, NAMESPACE, node, &[("role", "client")]),
    )
    .await?;
    create_pod(
        client,
        NAMESPACE,
        &busybox_pod_with_labels(POD_CLIENT_BLOCKED, NAMESPACE, node, &[("role", "other")]),
    )
    .await?;

    let (server_ip, _) =
        wait_running_with_ip(client, NAMESPACE, POD_SERVER, Duration::from_secs(90)).await?;
    wait_running_with_ip(
        client,
        NAMESPACE,
        POD_CLIENT_ALLOWED,
        Duration::from_secs(90),
    )
    .await?;
    wait_running_with_ip(
        client,
        NAMESPACE,
        POD_CLIENT_BLOCKED,
        Duration::from_secs(90),
    )
    .await?;

    // --- Step 1: baseline, no policy yet — open-by-default (namespace's
    // default-allow Profile), so BOTH clients can reach the server. ---
    exec_tcp_connect(
        client,
        NAMESPACE,
        POD_CLIENT_ALLOWED,
        &server_ip,
        SERVER_PORT,
        PROBE_TIMEOUT,
    )
    .await
    .map_err(|e| format!("baseline: allowed client could not reach server pre-policy: {e}"))?;
    exec_tcp_connect(client, NAMESPACE, POD_CLIENT_BLOCKED, &server_ip, SERVER_PORT, PROBE_TIMEOUT)
        .await
        .map_err(|e| format!("baseline: other client could not reach server pre-policy (expected open-by-default): {e}"))?;

    // --- Step 2: apply a policy selecting role=server that allows ingress
    // only from role=client. role=other becomes denied by the policy's
    // implicit end-of-chain default-deny; role=client must stay allowed. ---
    upsert_network_policy(
        backend,
        NAMESPACE,
        POLICY_NAME,
        serde_json::to_value(allow_from_role_policy("client"))
            .map_err(|e| format!("serialize initial NetworkPolicy spec: {e}"))?,
    )
    .await?;

    match poll_until_with_latency(CONVERGE_DEADLINE, CONVERGE_POLL_INTERVAL, || async {
        exec_tcp_connect(
            client,
            NAMESPACE,
            POD_CLIENT_BLOCKED,
            &server_ip,
            SERVER_PORT,
            Duration::from_secs(3),
        )
        .await
        .is_err()
    })
    .await
    {
        Ok(elapsed) => eprintln!("us2_policy: role=other became denied after {elapsed:?}"),
        Err(bound) => {
            return Err(format!(
                "policy {POLICY_NAME} (allow role=client only) did not deny role=other within \
                 {bound:?} — dataplane never converged; check FELIX_POLICY_NAMESPACE matches \
                 {NAMESPACE:?} on the calico-rs-node DaemonSet"
            ));
        }
    }
    exec_tcp_connect(
        client,
        NAMESPACE,
        POD_CLIENT_ALLOWED,
        &server_ip,
        SERVER_PORT,
        PROBE_TIMEOUT,
    )
    .await
    .map_err(|e| {
        format!("allowed client (role=client) was unexpectedly denied after policy apply: {e}")
    })?;

    // --- Step 3: edit the policy (extend the allow to role=other too) and
    // measure propagation latency; assert < 5s (SC: policy changes propagate
    // <5s). The already-allowed client must remain reachable across the edit
    // (best-effort: single post-edit check, not continuous monitoring). ---
    upsert_network_policy(
        backend,
        NAMESPACE,
        POLICY_NAME,
        serde_json::to_value(allow_from_roles_in(&["client", "other"]))
            .map_err(|e| format!("serialize edited NetworkPolicy spec: {e}"))?,
    )
    .await?;

    match poll_until_with_latency(CONVERGE_DEADLINE, CONVERGE_POLL_INTERVAL, || async {
        exec_tcp_connect(
            client,
            NAMESPACE,
            POD_CLIENT_BLOCKED,
            &server_ip,
            SERVER_PORT,
            Duration::from_secs(3),
        )
        .await
        .is_ok()
    })
    .await
    {
        Ok(elapsed) => {
            eprintln!("us2_policy: observed policy-update latency = {elapsed:?}");
            if elapsed > LATENCY_SC_BUDGET {
                return Err(format!(
                    "policy-update propagation took {elapsed:?}, exceeding the {LATENCY_SC_BUDGET:?} \
                     SC budget (policy changes must propagate in <5s)"
                ));
            }
        }
        Err(bound) => {
            return Err(format!(
                "policy edit (allow role=other too) did not take effect within {bound:?} \
                 (dataplane never converged)"
            ));
        }
    }
    exec_tcp_connect(
        client,
        NAMESPACE,
        POD_CLIENT_ALLOWED,
        &server_ip,
        SERVER_PORT,
        PROBE_TIMEOUT,
    )
    .await
    .map_err(|e| format!("allowed client (role=client) was dropped across the policy edit: {e}"))
}

/// `NetworkPolicySpec` selecting `role=server`, allowing TCP ingress on
/// [`SERVER_PORT`] only from the given single `role`.
fn allow_from_role_policy(allowed_role: &str) -> NetworkPolicySpec {
    allow_from_roles_in(&[allowed_role])
}

/// `NetworkPolicySpec` selecting `role=server`, allowing TCP ingress on
/// [`SERVER_PORT`] from any of the given `role` values.
fn allow_from_roles_in(allowed_roles: &[&str]) -> NetworkPolicySpec {
    let src_selector = if allowed_roles.len() == 1 {
        format!("role == '{}'", allowed_roles[0])
    } else {
        let quoted: Vec<String> = allowed_roles.iter().map(|r| format!("'{r}'")).collect();
        format!("role in {{{}}}", quoted.join(","))
    };
    NetworkPolicySpec {
        selector: "role == 'server'".to_string(),
        types: vec![PolicyType::Ingress],
        ingress: vec![Rule {
            action: Action::Allow,
            protocol: Some(Protocol::Named("TCP".to_string())),
            source: EntityRule {
                selector: Some(src_selector),
                ..Default::default()
            },
            destination: EntityRule {
                ports: vec![SERVER_PORT],
                ..Default::default()
            },
        }],
        egress: vec![],
        ..Default::default()
    }
}

async fn cleanup(client: &Client, backend: &KddBackend) {
    let _ = delete_network_policy_if_exists(backend, NAMESPACE, POLICY_NAME).await;
    delete_namespace_best_effort(client, NAMESPACE).await;
}
