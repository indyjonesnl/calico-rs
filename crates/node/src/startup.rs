//! Node minimal startup (T047) — ensure the cluster's baseline resources exist
//! and mark the datastore ready, before this node's felix reconcile loops
//! start. This is the gate the CNI plugin's readiness check
//! (`ClusterInformation.datastore_ready`) waits on, and it gives IPAM a pool
//! to allocate pod addresses from (without it, US1 can't assign addresses).
//!
//! [`startup`] is idempotent (safe on every boot) and deliberately
//! conservative: it never overwrites an existing `ClusterInformation` cluster
//! GUID, never creates a default IPPool when *any* IPPool already exists
//! (operator-provided pools win), and never touches fields the VXLAN overlay
//! reconcile loop manages — that loop annotates the *core* Kubernetes `Node`
//! object (see `felix::vxlan_reconcile`), a different object from the Calico
//! `Node` CRD this module ensures exists.
//!
//! Resource-spec construction is split into pure builder functions (unit
//! tested without a cluster below); `startup` and its helpers do the
//! get/create orchestration around them.

use apis::{ClusterInformationSpec, EncapMode, IpPoolSpec, NodeSpec, OrchRef};
use datastore::{CasError, KddBackend, ResourceKind};
use serde_json::json;

/// Name of the default IPv4 pool created when no IPPool exists yet.
const DEFAULT_IPV4_POOL_NAME: &str = "default-ipv4-ippool";
/// The singleton `ClusterInformation` resource name (upstream convention).
const CLUSTER_INFORMATION_NAME: &str = "default";
/// Fallback `calico_version` when `CALICO_VERSION` is unset: this crate's own
/// version (no extra dependency; `env!` is a compiler builtin).
const CALICO_RS_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Ensure the cluster's baseline resources exist and the datastore is marked
/// ready. Call once per boot, after the datastore connects and before any
/// reconcile loop starts (they assume the baseline is in place).
pub async fn startup(backend: &KddBackend, nodename: &str) -> Result<(), String> {
    ensure_default_ippool(backend).await?;
    ensure_cluster_information(backend, nodename).await?;
    ensure_node(backend, nodename).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Pure builders + env parsing (unit-testable without a cluster).
// ---------------------------------------------------------------------------

/// Parse `CALICO_IPV4POOL_VXLAN`: `Never` / `Always` / `CrossSubnet`
/// (case-insensitive). Absent or unrecognised values fall back to `Always`
/// (calico-rs's overlay is VXLAN).
pub fn parse_vxlan_mode(raw: Option<&str>) -> EncapMode {
    match raw.map(str::to_ascii_lowercase).as_deref() {
        Some("never") => EncapMode::Never,
        Some("crosssubnet") | Some("cross-subnet") => EncapMode::CrossSubnet,
        _ => EncapMode::Always,
    }
}

/// Parse `CALICO_IPV4POOL_BLOCK_SIZE`; absent or unparseable falls back to 26
/// (upstream Calico's default IPv4 block size).
pub fn parse_block_size(raw: Option<&str>) -> u8 {
    raw.and_then(|s| s.parse::<u8>().ok()).unwrap_or(26)
}

/// The default IPv4 pool CIDR: `CALICO_IPV4POOL_CIDR` or `192.168.0.0/16`.
pub fn default_pool_cidr(raw: Option<&str>) -> String {
    raw.filter(|s| !s.is_empty())
        .unwrap_or("192.168.0.0/16")
        .to_string()
}

/// Build the default IPv4 pool spec. Always `nat_outgoing = true` (pods reach
/// the outside world by masquerading through the node).
pub fn default_ippool_spec(cidr: &str, block_size: u8, vxlan_mode: EncapMode) -> IpPoolSpec {
    IpPoolSpec {
        cidr: cidr.to_string(),
        block_size: Some(block_size),
        vxlan_mode,
        nat_outgoing: true,
        ..Default::default()
    }
}

/// Build the `ClusterInformation` spec for first creation: `datastore_ready =
/// Some(true)`, the given (freshly generated) GUID, and a cluster type that
/// includes `"calico-rs"` (mirrors upstream's `"kdd"` marker for the
/// Kubernetes-datastore driver, plus our own marker).
pub fn cluster_information_spec(guid: &str, version: &str) -> ClusterInformationSpec {
    ClusterInformationSpec {
        cluster_guid: guid.to_string(),
        cluster_type: "kdd,calico-rs".to_string(),
        calico_version: version.to_string(),
        datastore_ready: Some(true),
        variant: String::new(),
    }
}

/// Build the minimal Calico `Node` spec: just an orchestrator ref back to the
/// Kubernetes node name. Deliberately minimal — BGP/VXLAN tunnel fields are
/// published by the reconcile loops, not here.
pub fn node_spec(nodename: &str) -> NodeSpec {
    NodeSpec {
        orch_refs: vec![OrchRef {
            node_name: Some(nodename.to_string()),
            orchestrator: "k8s".to_string(),
        }],
        ..Default::default()
    }
}

/// A 32-hex-char cluster GUID, the same shape as upstream's
/// `hex.EncodeToString(uuid.New())` but derived from stable process facts
/// instead of a UUID library (no new dependency, no `Math.random`-equivalent):
/// process id + wall-clock nanoseconds + node name, hashed twice with
/// different domain separators so the two halves aren't trivially related.
/// Pure given its inputs — the caller ([`generate_cluster_guid`]) supplies the
/// only impure bits (clock, pid).
pub fn cluster_guid_from(nodename: &str, nanos: u128, pid: u32) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    (nanos, pid, nodename, "calico-rs-guid-a").hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    (pid, nanos, nodename, "calico-rs-guid-b").hash(&mut h2);
    format!("{:016x}{:016x}", h1.finish(), h2.finish())
}

/// Generate a fresh cluster GUID. Only ever called on first
/// `ClusterInformation` creation; an existing GUID is never regenerated.
fn generate_cluster_guid(nodename: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    cluster_guid_from(nodename, nanos, std::process::id())
}

/// `CALICO_VERSION`, or this crate's own version as a fallback.
fn calico_version() -> String {
    std::env::var("CALICO_VERSION").unwrap_or_else(|_| CALICO_RS_VERSION.to_string())
}

fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

// ---------------------------------------------------------------------------
// Orchestration (async; thin wrappers around the builders above).
// ---------------------------------------------------------------------------

/// Ensure a default IPv4 pool exists — but only when *no* IPPool exists yet.
/// Respects operator-provided pools unconditionally: if any pool is present,
/// this is a no-op regardless of its name or contents.
async fn ensure_default_ippool(backend: &KddBackend) -> Result<(), String> {
    let existing = backend
        .list(ResourceKind::IpPool, None)
        .await
        .map_err(|e| format!("list IPPool: {e}"))?;
    if !existing.is_empty() {
        println!(
            "calico-rs-node: {} IPPool(s) already present; not creating {DEFAULT_IPV4_POOL_NAME}",
            existing.len()
        );
        return Ok(());
    }

    let cidr = default_pool_cidr(env_var("CALICO_IPV4POOL_CIDR").as_deref());
    let block_size = parse_block_size(env_var("CALICO_IPV4POOL_BLOCK_SIZE").as_deref());
    let vxlan_mode = parse_vxlan_mode(env_var("CALICO_IPV4POOL_VXLAN").as_deref());
    let spec = default_ippool_spec(&cidr, block_size, vxlan_mode);
    let value = serde_json::to_value(&spec).map_err(|e| format!("serialize IPPool spec: {e}"))?;

    match backend
        .create(ResourceKind::IpPool, None, DEFAULT_IPV4_POOL_NAME, value)
        .await
    {
        Ok(_) => {
            println!(
                "calico-rs-node: created default IPPool {DEFAULT_IPV4_POOL_NAME} (cidr={cidr}, \
                 blockSize={block_size}, vxlanMode={vxlan_mode:?})"
            );
            Ok(())
        }
        // Lost a create race against another node's startup: the pool exists
        // now either way, which is all this call needs.
        Err(CasError::AlreadyExists) => Ok(()),
        Err(e) => Err(format!("create default IPPool: {e}")),
    }
}

/// Ensure `ClusterInformation/default` exists with `datastore_ready = true`.
/// Never overwrites an existing `cluster_guid`, `cluster_type`, or
/// `calico_version` — those are only set on first creation; a subsequent run
/// that finds the object already `datastore_ready` is a pure no-op, and one
/// that finds it *not* ready flips only that one field via a merge patch.
async fn ensure_cluster_information(backend: &KddBackend, nodename: &str) -> Result<(), String> {
    match backend
        .get(
            ResourceKind::ClusterInformation,
            None,
            CLUSTER_INFORMATION_NAME,
        )
        .await
        .map_err(|e| format!("get ClusterInformation: {e}"))?
    {
        Some(existing) => {
            let already_ready = existing
                .spec
                .get("datastoreReady")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if already_ready {
                return Ok(());
            }
            // Merge patch: touches only `spec.datastoreReady`, so an existing
            // `clusterGUID`/`clusterType`/`calicoVersion` (and any metadata)
            // survive untouched.
            backend
                .merge_patch(
                    ResourceKind::ClusterInformation,
                    None,
                    CLUSTER_INFORMATION_NAME,
                    json!({ "spec": { "datastoreReady": true } }),
                    Some(&existing.raw_revision),
                )
                .await
                .map_err(|e| format!("mark datastore_ready: {e}"))?;
            println!(
                "calico-rs-node: marked datastore_ready=true on existing ClusterInformation/{CLUSTER_INFORMATION_NAME}"
            );
            Ok(())
        }
        None => {
            let guid = generate_cluster_guid(nodename);
            let spec = cluster_information_spec(&guid, &calico_version());
            let value = serde_json::to_value(&spec)
                .map_err(|e| format!("serialize ClusterInformation spec: {e}"))?;
            match backend
                .create(
                    ResourceKind::ClusterInformation,
                    None,
                    CLUSTER_INFORMATION_NAME,
                    value,
                )
                .await
            {
                Ok(_) => {
                    println!(
                        "calico-rs-node: created ClusterInformation/{CLUSTER_INFORMATION_NAME} \
                         (datastore_ready=true, guid={guid})"
                    );
                    Ok(())
                }
                // Another node's startup won the create race; leave its
                // datastore_ready value for this (or the next) boot to check.
                Err(CasError::AlreadyExists) => Ok(()),
                Err(e) => Err(format!("create ClusterInformation: {e}")),
            }
        }
    }
}

/// Ensure a Calico `Node` CR named `nodename` exists. Create-if-absent only —
/// never updates an existing one, so this can never clobber fields another
/// component (e.g. a future BGP address publisher) has written to it.
async fn ensure_node(backend: &KddBackend, nodename: &str) -> Result<(), String> {
    let existing = backend
        .get(ResourceKind::Node, None, nodename)
        .await
        .map_err(|e| format!("get Node: {e}"))?;
    if existing.is_some() {
        return Ok(());
    }
    let spec = node_spec(nodename);
    let value = serde_json::to_value(&spec).map_err(|e| format!("serialize Node spec: {e}"))?;
    match backend
        .create(ResourceKind::Node, None, nodename, value)
        .await
    {
        Ok(_) => {
            println!("calico-rs-node: created Node/{nodename}");
            Ok(())
        }
        Err(CasError::AlreadyExists) => Ok(()),
        Err(e) => Err(format!("create Node: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- env parsing -------------------------------------------------

    #[test]
    fn parse_vxlan_mode_recognises_all_values_case_insensitively() {
        assert_eq!(parse_vxlan_mode(Some("Never")), EncapMode::Never);
        assert_eq!(parse_vxlan_mode(Some("never")), EncapMode::Never);
        assert_eq!(parse_vxlan_mode(Some("Always")), EncapMode::Always);
        assert_eq!(
            parse_vxlan_mode(Some("CrossSubnet")),
            EncapMode::CrossSubnet
        );
        assert_eq!(
            parse_vxlan_mode(Some("crosssubnet")),
            EncapMode::CrossSubnet
        );
    }

    #[test]
    fn parse_vxlan_mode_defaults_to_always_when_absent_or_unrecognised() {
        assert_eq!(parse_vxlan_mode(None), EncapMode::Always);
        assert_eq!(parse_vxlan_mode(Some("bogus")), EncapMode::Always);
        assert_eq!(parse_vxlan_mode(Some("")), EncapMode::Always);
    }

    #[test]
    fn parse_block_size_uses_env_value_or_defaults_to_26() {
        assert_eq!(parse_block_size(Some("24")), 24);
        assert_eq!(parse_block_size(None), 26);
        assert_eq!(parse_block_size(Some("not-a-number")), 26);
        assert_eq!(parse_block_size(Some("999")), 26); // out of u8 range -> default
    }

    #[test]
    fn default_pool_cidr_uses_env_value_or_defaults() {
        assert_eq!(default_pool_cidr(Some("10.0.0.0/8")), "10.0.0.0/8");
        assert_eq!(default_pool_cidr(None), "192.168.0.0/16");
        assert_eq!(default_pool_cidr(Some("")), "192.168.0.0/16");
    }

    // ---- default_ippool_spec -------------------------------------------

    #[test]
    fn default_ippool_spec_has_expected_fields() {
        let spec = default_ippool_spec("192.168.0.0/16", 26, EncapMode::Always);
        assert_eq!(spec.cidr, "192.168.0.0/16");
        assert_eq!(spec.block_size, Some(26));
        assert_eq!(spec.vxlan_mode, EncapMode::Always);
        assert!(spec.nat_outgoing);
        // ipip is not the overlay calico-rs uses; must stay off.
        assert_eq!(spec.ipip_mode, EncapMode::Never);
    }

    #[test]
    fn default_ippool_spec_serializes_with_upstream_wire_names() {
        let spec = default_ippool_spec("10.244.0.0/16", 24, EncapMode::CrossSubnet);
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"cidr\":\"10.244.0.0/16\""));
        assert!(json.contains("\"blockSize\":24"));
        assert!(json.contains("\"vxlanMode\":\"CrossSubnet\""));
        assert!(json.contains("\"natOutgoing\":true"));
    }

    // ---- cluster_information_spec ---------------------------------------

    #[test]
    fn cluster_information_spec_marks_datastore_ready_and_carries_guid_version() {
        let spec = cluster_information_spec("deadbeef", "v0.1.0");
        assert_eq!(spec.datastore_ready, Some(true));
        assert_eq!(spec.cluster_guid, "deadbeef");
        assert_eq!(spec.calico_version, "v0.1.0");
        assert!(
            spec.cluster_type.contains("calico-rs"),
            "cluster_type should mention calico-rs, got {:?}",
            spec.cluster_type
        );
    }

    #[test]
    fn cluster_information_spec_serializes_datastore_ready_true() {
        let spec = cluster_information_spec("abc123", "v0.1.0");
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"datastoreReady\":true"));
        assert!(json.contains("\"clusterGUID\":\"abc123\""));
    }

    // ---- node_spec --------------------------------------------------------

    #[test]
    fn node_spec_references_nodename_via_k8s_orch_ref() {
        let spec = node_spec("worker-1");
        assert_eq!(spec.orch_refs.len(), 1);
        assert_eq!(spec.orch_refs[0].node_name.as_deref(), Some("worker-1"));
        assert_eq!(spec.orch_refs[0].orchestrator, "k8s");
        // Minimal: no BGP/VXLAN fields — those are the reconcile loops' turf.
        assert!(spec.bgp.is_none());
        assert!(spec.ipv4_vxlan_tunnel_addr.is_none());
        assert!(spec.ipv6_vxlan_tunnel_addr.is_none());
    }

    // ---- cluster_guid_from ------------------------------------------------

    #[test]
    fn cluster_guid_from_is_32_lowercase_hex_chars() {
        let guid = cluster_guid_from("node-a", 12345, 999);
        assert_eq!(guid.len(), 32, "guid: {guid}");
        assert!(
            guid.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "guid should be lowercase hex: {guid}"
        );
    }

    #[test]
    fn cluster_guid_from_is_deterministic_given_same_inputs() {
        assert_eq!(
            cluster_guid_from("node-a", 42, 7),
            cluster_guid_from("node-a", 42, 7)
        );
    }

    #[test]
    fn cluster_guid_from_differs_across_distinct_inputs() {
        let a = cluster_guid_from("node-a", 42, 7);
        let b = cluster_guid_from("node-b", 42, 7);
        let c = cluster_guid_from("node-a", 43, 7);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
