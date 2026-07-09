//! `calico-rs-node` — the per-node agent, run as a privileged DaemonSet (the
//! analog of upstream `calico-node`). On startup it installs the CNI plugin onto
//! the host (binary + conflist + a kubeconfig for the plugin to reach the API
//! server), records the node name, then runs the felix reconcile loop.
//!
//! Host paths are mounted into the container by the DaemonSet:
//!   /host/opt/cni/bin        <- node's /opt/cni/bin
//!   /host/etc/cni/net.d      <- node's /etc/cni/net.d
//!   /var/lib/calico          <- node's /var/lib/calico
//!
//! Environment (set by the DaemonSet):
//!   NODENAME              the Kubernetes node name (spec.nodeName)
//!   CNI_NET_DIR           host CNI conf dir mount (default /host/etc/cni/net.d)
//!   CNI_BIN_DIR           host CNI bin dir mount  (default /host/opt/cni/bin)
//!   CALICO_NETWORK_NAME   CNI network name (default "k8s-pod-network")
//!   FELIX_POLICY_NAMESPACE reconcile namespace for the first-cut policy loop

use std::time::Duration;

mod startup;

const SELF_CNI_BIN: &str = "/opt/calico-rs/bin/calico";
const KUBECONFIG_NAME: &str = "calico-rs-kubeconfig";
const CONFLIST_NAME: &str = "10-calico.conflist";

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("calico-rs-node: fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let nodename = env_or("NODENAME", "").trim().to_string();
    let nodename = if nodename.is_empty() {
        hostname()
    } else {
        nodename
    };
    let bin_dir = env_or("CNI_BIN_DIR", "/host/opt/cni/bin");
    let net_dir = env_or("CNI_NET_DIR", "/host/etc/cni/net.d");
    let net_name = env_or("CALICO_NETWORK_NAME", "k8s-pod-network");

    record_nodename(&nodename)?;
    let kubeconfig_host_path = install_cni(&bin_dir, &net_dir, &net_name)?;
    println!(
        "calico-rs-node: CNI installed (node={nodename}, conflist={net_dir}/{CONFLIST_NAME}, \
         kubeconfig={kubeconfig_host_path})"
    );

    // Felix reconcile loops (in-cluster config via the pod's service account).
    let backend = datastore::KddBackend::try_default()
        .await
        .map_err(|e| format!("connect datastore: {e}"))?;

    // Baseline bootstrap: default IPPool, ClusterInformation (datastore_ready
    // gate the CNI plugin waits on), and this node's Calico Node CR. Must
    // happen before the reconcile loops start — they assume the baseline is
    // already in place.
    startup::startup(&backend, &nodename).await?;
    println!("calico-rs-node: datastore baseline ensured (node={nodename})");

    // VXLAN overlay reconcile — runs in the host netns (this pod is hostNetwork),
    // programming this node's tunnel device + routes to remote nodes' blocks.
    let vxlan_backend = datastore::KddBackend::new(backend.client());
    let vxlan_node = nodename.clone();
    println!("calico-rs-node: starting VXLAN overlay reconcile (node={vxlan_node})");
    tokio::spawn(felix::vxlan_reconcile::run(
        vxlan_backend,
        vxlan_node,
        Duration::from_secs(10),
    ));

    // NAT-outgoing (masquerade pod → external) reconcile, host netns.
    let nat_backend = datastore::KddBackend::new(backend.client());
    println!("calico-rs-node: starting NAT-outgoing reconcile");
    tokio::spawn(felix::nat::run(nat_backend, Duration::from_secs(10)));

    let namespace = env_or("FELIX_POLICY_NAMESPACE", "default");
    println!("calico-rs-node: starting felix policy reconcile loop (namespace={namespace})");
    felix::reconcile::run(backend, namespace, Duration::from_secs(10)).await;
    Ok(())
}

/// Write the node name where the CNI plugin reads it (`/var/lib/calico/nodename`).
fn record_nodename(nodename: &str) -> Result<(), String> {
    let dir = "/var/lib/calico";
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {dir}: {e}"))?;
    std::fs::write(format!("{dir}/nodename"), nodename)
        .map_err(|e| format!("write nodename: {e}"))?;
    Ok(())
}

/// Copy the CNI binary to the host, write a kubeconfig the plugin can use, and
/// drop the conflist. Returns the on-host (node-namespace) path of the
/// kubeconfig, which is what the conflist must reference.
fn install_cni(bin_dir: &str, net_dir: &str, net_name: &str) -> Result<String, String> {
    std::fs::create_dir_all(bin_dir).map_err(|e| format!("mkdir {bin_dir}: {e}"))?;
    std::fs::create_dir_all(net_dir).map_err(|e| format!("mkdir {net_dir}: {e}"))?;

    // Binary: copy to a temp path then rename, so kubelet never sees a partial
    // file (rename is atomic within the same dir).
    let dst = format!("{bin_dir}/calico");
    let tmp = format!("{dst}.tmp");
    std::fs::copy(SELF_CNI_BIN, &tmp).map_err(|e| format!("copy {SELF_CNI_BIN} -> {tmp}: {e}"))?;
    set_executable(&tmp)?;
    std::fs::rename(&tmp, &dst).map_err(|e| format!("rename {tmp} -> {dst}: {e}"))?;

    // Kubeconfig for the standalone plugin. Build it from the pod's mounted
    // service-account token + the API server the node already knows.
    let kubeconfig = build_cni_kubeconfig()?;
    let kc_mount_path = format!("{net_dir}/{KUBECONFIG_NAME}");
    std::fs::write(&kc_mount_path, kubeconfig).map_err(|e| format!("write kubeconfig: {e}"))?;

    // The conflist references the kubeconfig by its path *in the node's*
    // filesystem, not the container mount. net_dir is typically
    // /host/etc/cni/net.d -> node /etc/cni/net.d.
    let node_net_dir = net_dir.strip_prefix("/host").unwrap_or(net_dir);
    let node_kc_path = format!("{node_net_dir}/{KUBECONFIG_NAME}");
    let conflist = conflist(net_name, &node_kc_path);
    std::fs::write(format!("{net_dir}/{CONFLIST_NAME}"), conflist)
        .map_err(|e| format!("write conflist: {e}"))?;
    Ok(node_kc_path)
}

/// Render the CNI conflist. Uses Calico IPAM and points the plugin at the
/// kubeconfig for datastore access.
fn conflist(net_name: &str, node_kc_path: &str) -> String {
    // The chained `portmap` plugin implements HostPort (kubelet passes the pod's
    // portMappings via the runtime config). Mirrors upstream Calico's conflist.
    format!(
        r#"{{
  "name": "{net_name}",
  "cniVersion": "1.0.0",
  "plugins": [
    {{
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 1450,
      "ipam": {{ "type": "calico-ipam" }},
      "policy": {{ "type": "k8s" }},
      "kubernetes": {{ "kubeconfig": "{node_kc_path}" }}
    }},
    {{
      "type": "portmap",
      "snat": true,
      "capabilities": {{ "portMappings": true }}
    }}
  ]
}}
"#
    )
}

/// Build a kubeconfig for the CNI plugin from the pod's in-cluster service
/// account (token + CA are mounted at the standard path), targeting the API
/// server via the in-cluster env vars.
fn build_cni_kubeconfig() -> Result<String, String> {
    use base64::Engine;
    const SA: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
    let token = std::fs::read_to_string(format!("{SA}/token"))
        .map_err(|e| format!("read SA token: {e}"))?;
    // Inline the CA as base64 — the plugin runs in the host mount namespace under
    // kubelet, where the pod's SA mount path does not exist, so a file reference
    // would not resolve.
    let ca = std::fs::read(format!("{SA}/ca.crt")).map_err(|e| format!("read SA ca: {e}"))?;
    let ca_b64 = base64::engine::general_purpose::STANDARD.encode(&ca);
    let host = env_or("KUBERNETES_SERVICE_HOST", "");
    let port = env_or("KUBERNETES_SERVICE_PORT", "443");
    if host.is_empty() {
        return Err("KUBERNETES_SERVICE_HOST not set (not running in-cluster?)".into());
    }
    // Bracket IPv6 literals for the URL.
    let hostport = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok(format!(
        r#"apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: https://{hostport}
    certificate-authority-data: {ca_b64}
users:
- name: calico-rs
  user:
    token: "{token}"
contexts:
- name: calico-rs@local
  context:
    cluster: local
    user: calico-rs
current-context: calico-rs@local
"#
    ))
}

#[cfg(unix)]
fn set_executable(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(path, perms).map_err(|e| format!("chmod {path}: {e}"))
}

#[cfg(not(unix))]
fn set_executable(_path: &str) -> Result<(), String> {
    Ok(())
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-node".to_string())
}
