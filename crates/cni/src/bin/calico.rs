//! The `calico` CNI plugin binary.
//!
//! Implements the CNI protocol: reads `CNI_COMMAND` + `CNI_ARGS` / `CNI_NETNS` /
//! `CNI_IFNAME` / `CNI_CONTAINERID` from the environment and the network config
//! from stdin, then wires the pod using the datastore-backed IPAM + the netlink
//! dataplane, printing a CNI result (or error) to stdout.
//!
//! End-to-end operation requires a cluster + a real pod netns (i.e. running as
//! the node CNI); the constituent pieces (netconf parse, IPAM, veth/netns
//! wiring, result JSON) are each unit/integration-tested elsewhere.

#[cfg(target_os = "linux")]
fn main() {
    use cni::result::CniError;

    let cni_version = "1.0.0";
    match run() {
        Ok(json) => {
            println!("{json}");
        }
        Err(msg) => {
            // CNI: print the error object to stdout and exit non-zero.
            println!("{}", CniError::new(cni_version, msg).to_json());
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<String, String> {
    use std::io::Read;

    let command = std::env::var("CNI_COMMAND").map_err(|_| "CNI_COMMAND not set")?;
    let mut stdin = String::new();
    std::io::stdin()
        .read_to_string(&mut stdin)
        .map_err(|e| format!("read stdin: {e}"))?;
    let netconf = cni::NetConf::parse(&stdin)?;

    match command.as_str() {
        "ADD" => cmd_add(&netconf),
        "DEL" => cmd_del(&netconf).map(|_| String::new()),
        "CHECK" => Ok(String::new()),
        "VERSION" => Ok(
            r#"{"cniVersion":"1.0.0","supportedVersions":["0.3.0","0.3.1","0.4.0","1.0.0"]}"#
                .to_string(),
        ),
        other => Err(format!("unknown CNI_COMMAND {other}")),
    }
}

#[cfg(target_os = "linux")]
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Connect to the datastore. On a node the plugin runs standalone under kubelet,
/// so it uses the kubeconfig calico-node wrote (referenced in the netconf's
/// `kubernetes` section); falls back to the ambient config for local testing.
#[cfg(target_os = "linux")]
async fn connect_backend(netconf: &cni::NetConf) -> Result<datastore::KddBackend, String> {
    use datastore::KddBackend;
    match netconf.kubernetes.kubeconfig.as_deref() {
        Some(path) if !path.is_empty() => KddBackend::from_kubeconfig_file(path)
            .await
            .map_err(|e| e.to_string()),
        _ => KddBackend::try_default().await.map_err(|e| e.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn node_name() -> String {
    // Calico reads the nodename from a file written by calico-node; fall back to
    // the hostname / NODENAME env.
    std::fs::read_to_string("/var/lib/calico/nodename")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("NODENAME").ok())
        .unwrap_or_else(|| "unknown-node".to_string())
}

#[cfg(target_os = "linux")]
fn cmd_add(netconf: &cni::NetConf) -> Result<String, String> {
    use cni::result::{CniResult, Interface, IpConfig, RouteEntry};
    use cni::{identifiers_from_cni_args, veth_name_for_workload};
    use datastore::ResourceKind;
    use ipam::{Cidr, KddIpam};
    use std::fs::File;
    use std::net::Ipv4Addr;
    use std::os::fd::AsRawFd;

    let container_id = env_or("CNI_CONTAINERID", "");
    let netns_path = std::env::var("CNI_NETNS").map_err(|_| "CNI_NETNS not set")?;
    let ifname = env_or("CNI_IFNAME", "eth0");
    let cni_args = env_or("CNI_ARGS", "");
    let node = node_name();
    let ids = identifiers_from_cni_args(&cni_args, &container_id, &node);
    let handle_id = format!("{}.{}", netconf.name, container_id);

    // Datastore + IPAM (own runtime, dropped before the netns work).
    let pod_ip: Ipv4Addr = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        rt.block_on(async {
            let backend = connect_backend(netconf).await?;

            // Readiness gate.
            let ci = backend
                .get(ResourceKind::ClusterInformation, None, "default")
                .await
                .map_err(|e| e.to_string())?;
            let ready = ci
                .as_ref()
                .and_then(|kv| kv.spec.get("datastoreReady").and_then(|v| v.as_bool()))
                .unwrap_or(false);
            if !ready {
                return Err("datastore is not ready".to_string());
            }

            // Pick the first enabled IPPool.
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
            let pool_cidr = Cidr::parse(cidr_s).map_err(|e| e.to_string())?;

            // Record pod identity on the allocation so kube-controllers' IPAM GC
            // can reclaim it by pod liveness if the pod dies without a CNI DEL.
            let secondary = std::collections::BTreeMap::from([
                ("namespace".to_string(), ids.namespace.clone()),
                ("pod".to_string(), ids.pod.clone()),
                ("node".to_string(), node.clone()),
            ]);
            let ipam = KddIpam::new(backend);
            let ips = ipam
                .auto_assign_from_pool_with_attrs(
                    &node, pool_cidr, block_size, &handle_id, &secondary, 1,
                )
                .await
                .map_err(|e| e.to_string())?;
            let ip = ips
                .into_iter()
                .next()
                .ok_or("no address available in pool")?;
            match ip {
                std::net::IpAddr::V4(v4) => Ok(v4),
                std::net::IpAddr::V6(_) => Err("IPv6 CNI not yet supported".to_string()),
            }
        })?
    };

    // Netlink dataplane wiring (own runtime, inside cmd_add).
    let host_veth = veth_name_for_workload(&ids.namespace, &ids.pod, "cali");
    let netns = File::open(&netns_path).map_err(|e| format!("open netns {netns_path}: {e}"))?;
    let add =
        cni::orchestrate::cmd_add(&host_veth, &ifname, netns.as_raw_fd(), pod_ip, netconf.mtu)?;

    let result = CniResult {
        cni_version: if netconf.cni_version.is_empty() {
            "1.0.0".into()
        } else {
            netconf.cni_version.clone()
        },
        interfaces: vec![
            Interface {
                name: add.host_ifname,
                mac: None,
                sandbox: None,
            },
            Interface {
                name: add.container_ifname,
                mac: None,
                sandbox: Some(netns_path),
            },
        ],
        ips: vec![IpConfig {
            address: format!("{pod_ip}/32"),
            interface: 1,
            gateway: None,
        }],
        routes: vec![RouteEntry {
            dst: "0.0.0.0/0".into(),
            gw: None,
        }],
    };
    Ok(result.to_json())
}

#[cfg(target_os = "linux")]
fn cmd_del(netconf: &cni::NetConf) -> Result<(), String> {
    use cni::{identifiers_from_cni_args, veth_name_for_workload};
    use ipam::KddIpam;

    let container_id = env_or("CNI_CONTAINERID", "");
    let cni_args = env_or("CNI_ARGS", "");
    let node = node_name();
    let ids = identifiers_from_cni_args(&cni_args, &container_id, &node);
    let handle_id = format!("{}.{}", netconf.name, container_id);

    // Release the addresses (best-effort — DEL must be idempotent).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        if let Ok(backend) = connect_backend(netconf).await {
            let ipam = KddIpam::new(backend);
            let _ = ipam.release_by_handle(&handle_id).await;
        }
    });

    // Tear down the veth (idempotent).
    let host_veth = veth_name_for_workload(&ids.namespace, &ids.pod, "cali");
    cni::orchestrate::cmd_del(&host_veth)
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("calico CNI plugin only runs on Linux");
    std::process::exit(2);
}
