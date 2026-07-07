//! `calicoctl` — command-line management for Calico-rs (subset).
//!
//! Reads/writes resources through the Kubernetes datastore (KDD backend):
//! `get`, `create`, `apply`, `delete`. Manifests are YAML or JSON (multi-doc
//! supported), matching the upstream `calicoctl` UX (tasks T093–T094).

use std::io::Read;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use datastore::{KddBackend, ResourceKind};
use serde::Deserialize;

#[derive(Parser)]
#[command(name = "calicoctl", about = "Manage Calico-rs resources", version)]
struct Cli {
    /// Path to a kubeconfig (overrides $KUBECONFIG / in-cluster).
    #[arg(long, global = true)]
    kubeconfig: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List resources of a kind.
    Get {
        kind: String,
        #[arg(short, long)]
        namespace: Option<String>,
        #[arg(short = 'A', long)]
        all_namespaces: bool,
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Ps)]
        output: OutputFormat,
    },
    /// Create resources from a manifest (errors if they already exist).
    Create {
        #[arg(short, long)]
        filename: String,
    },
    /// Create or update resources from a manifest (upsert).
    Apply {
        #[arg(short, long)]
        filename: String,
    },
    /// Delete a resource by kind + name, or the resources in a manifest.
    Delete {
        /// Resource kind (omit when using --filename).
        kind: Option<String>,
        /// Resource name (omit when using --filename).
        name: Option<String>,
        #[arg(short, long)]
        namespace: Option<String>,
        #[arg(short, long)]
        filename: Option<String>,
    },
    /// Add or remove labels on a resource: `key=value` to set, `key-` to remove.
    Label {
        kind: String,
        name: String,
        /// Label mutations: `key=value` (set) or `key-` (remove).
        #[arg(required = true)]
        labels: Vec<String>,
        #[arg(short, long)]
        namespace: Option<String>,
    },
    /// IPAM commands.
    Ipam {
        #[command(subcommand)]
        command: IpamCommand,
    },
}

#[derive(Subcommand)]
enum IpamCommand {
    /// Show IP address-management utilization.
    Show {
        /// Include a per-block breakdown.
        #[arg(long)]
        show_blocks: bool,
    },
    /// Release all addresses allocated under a handle (e.g. to reclaim a leaked
    /// allocation from a pod that was force-deleted before CNI DEL ran).
    Release {
        /// The IPAM handle id (e.g. `k8s-pod-network.<containerid>`).
        #[arg(long)]
        handle: String,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum OutputFormat {
    Ps,
    Yaml,
    Json,
}

/// A resource manifest document.
#[derive(Deserialize)]
struct Manifest {
    kind: String,
    metadata: Meta,
    #[serde(default)]
    spec: serde_json::Value,
}

#[derive(Deserialize)]
struct Meta {
    name: String,
    #[serde(default)]
    namespace: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let kc = cli.kubeconfig.as_deref();
    match cli.command {
        Command::Get {
            kind,
            namespace,
            all_namespaces,
            output,
        } => get(kc, &kind, namespace, all_namespaces, output).await,
        Command::Create { filename } => write_manifest(kc, &filename, false).await,
        Command::Apply { filename } => write_manifest(kc, &filename, true).await,
        Command::Delete {
            kind,
            name,
            namespace,
            filename,
        } => delete(kc, kind, name, namespace, filename).await,
        Command::Label {
            kind,
            name,
            labels,
            namespace,
        } => label(kc, &kind, &name, labels, namespace).await,
        Command::Ipam { command } => match command {
            IpamCommand::Show { show_blocks } => ipam_show(kc, show_blocks).await,
            IpamCommand::Release { handle } => ipam_release(kc, &handle).await,
        },
    }
}

async fn label(
    kubeconfig: Option<&str>,
    kind_str: &str,
    name: &str,
    labels: Vec<String>,
    namespace: Option<String>,
) -> Result<()> {
    let kind = ResourceKind::parse_cli(kind_str)
        .with_context(|| format!("unknown resource kind '{kind_str}'"))?;
    let backend = backend(kubeconfig).await?;
    let ns = if kind.is_namespaced() {
        Some(namespace.unwrap_or_else(|| "default".to_string()))
    } else {
        None
    };

    // Build a metadata.labels merge patch: `key=value` sets, `key-` removes (null).
    let mut patch_labels = serde_json::Map::new();
    for tok in &labels {
        if let Some(key) = tok.strip_suffix('-') {
            patch_labels.insert(key.to_string(), serde_json::Value::Null);
        } else if let Some((k, v)) = tok.split_once('=') {
            patch_labels.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        } else {
            bail!("invalid label '{tok}': use key=value to set or key- to remove");
        }
    }

    backend
        .merge_patch(
            kind,
            ns.as_deref(),
            name,
            serde_json::json!({ "metadata": { "labels": patch_labels } }),
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{kind_str}.crd.projectcalico.org/{name} labeled");
    Ok(())
}

async fn ipam_release(kubeconfig: Option<&str>, handle: &str) -> Result<()> {
    let backend = backend(kubeconfig).await?;
    let ipam = ipam::KddIpam::new(backend);
    let released = ipam
        .release_by_handle(handle)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("releasing handle {handle}"))?;
    if released.is_empty() {
        println!("handle {handle}: nothing to release (already gone)");
    } else {
        println!("handle {handle}: released {} address(es):", released.len());
        for ip in released {
            println!("  {ip}");
        }
    }
    Ok(())
}

async fn ipam_show(kubeconfig: Option<&str>, show_blocks: bool) -> Result<()> {
    let backend = backend(kubeconfig).await?;
    let blocks = backend
        .list(ResourceKind::IpamBlock, None)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("listing IPAM blocks")?;

    let mut total_cap = 0usize;
    let mut total_used = 0usize;
    let mut rows: Vec<(String, usize, usize)> = Vec::new(); // (cidr, used, capacity)
    for b in &blocks {
        let allocations = b.spec.get("allocations").and_then(|v| v.as_array());
        let capacity = allocations.map(|a| a.len()).unwrap_or(0);
        let used = allocations
            .map(|a| a.iter().filter(|x| !x.is_null()).count())
            .unwrap_or(0);
        let cidr = b
            .spec
            .get("cidr")
            .and_then(|v| v.as_str())
            .unwrap_or(&b.name)
            .to_string();
        total_cap += capacity;
        total_used += used;
        rows.push((cidr, used, capacity));
    }

    let pct = if total_cap > 0 {
        (total_used as f64 / total_cap as f64) * 100.0
    } else {
        0.0
    };
    println!("IPAM summary:");
    println!("  Blocks:     {}", blocks.len());
    println!("  Addresses:  {total_used} in use / {total_cap} total ({pct:.1}%)");

    if show_blocks {
        println!();
        println!(
            "{:<24} {:>8} {:>10} {:>7}",
            "BLOCK CIDR", "IN USE", "CAPACITY", "% USED"
        );
        for (cidr, used, cap) in rows {
            let p = if cap > 0 {
                (used as f64 / cap as f64) * 100.0
            } else {
                0.0
            };
            println!("{cidr:<24} {used:>8} {cap:>10} {p:>6.1}%");
        }
    }
    Ok(())
}

async fn backend(kubeconfig: Option<&str>) -> Result<KddBackend> {
    match kubeconfig {
        Some(path) => KddBackend::from_kubeconfig_file(path).await,
        None => KddBackend::try_default().await,
    }
    .map_err(|e| anyhow::anyhow!("{e}"))
    .context("connecting to the datastore")
}

fn read_input(filename: &str) -> Result<String> {
    if filename == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(filename).with_context(|| format!("reading {filename}"))
    }
}

/// Parse one or more YAML/JSON documents into manifests.
fn parse_manifests(input: &str) -> Result<Vec<Manifest>> {
    let mut out = Vec::new();
    for doc in serde_yaml_ng::Deserializer::from_str(input) {
        let value = serde_json::Value::deserialize(doc).context("parsing manifest document")?;
        if value.is_null() {
            continue; // empty doc (e.g. trailing `---`)
        }
        out.push(serde_json::from_value(value).context("manifest missing kind/metadata")?);
    }
    if out.is_empty() {
        bail!("no resources found in input");
    }
    Ok(out)
}

async fn write_manifest(kubeconfig: Option<&str>, filename: &str, upsert: bool) -> Result<()> {
    let backend = backend(kubeconfig).await?;
    for m in parse_manifests(&read_input(filename)?)? {
        let kind = ResourceKind::parse_cli(&m.kind)
            .with_context(|| format!("unknown resource kind '{}'", m.kind))?;
        let ns = m.metadata.namespace.as_deref();
        let existing = backend
            .get(kind, ns, &m.metadata.name)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        match (existing, upsert) {
            (Some(_), false) => bail!("resource {}/{} already exists", m.kind, m.metadata.name),
            (Some(cur), true) => {
                backend
                    .update(kind, ns, &m.metadata.name, m.spec, &cur.raw_revision)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!(
                    "{}.crd.projectcalico.org/{} configured",
                    m.kind, m.metadata.name
                );
            }
            (None, _) => {
                backend
                    .create(kind, ns, &m.metadata.name, m.spec)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!(
                    "{}.crd.projectcalico.org/{} created",
                    m.kind, m.metadata.name
                );
            }
        }
    }
    Ok(())
}

async fn delete(
    kubeconfig: Option<&str>,
    kind: Option<String>,
    name: Option<String>,
    namespace: Option<String>,
    filename: Option<String>,
) -> Result<()> {
    let backend = backend(kubeconfig).await?;
    let targets: Vec<(ResourceKind, String, Option<String>, String)> = if let Some(f) = filename {
        parse_manifests(&read_input(&f)?)?
            .into_iter()
            .map(|m| {
                let k = ResourceKind::parse_cli(&m.kind)
                    .with_context(|| format!("unknown resource kind '{}'", m.kind))?;
                Ok((k, m.kind, m.metadata.namespace, m.metadata.name))
            })
            .collect::<Result<_>>()?
    } else {
        let kind_str = kind.context("delete requires <kind> <name> or --filename")?;
        let name = name.context("delete requires a resource name")?;
        let k = ResourceKind::parse_cli(&kind_str)
            .with_context(|| format!("unknown resource kind '{kind_str}'"))?;
        vec![(k, kind_str, namespace, name)]
    };

    for (kind, kind_str, ns, name) in targets {
        match backend
            .get(kind, ns.as_deref(), &name)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
        {
            Some(cur) => {
                backend
                    .delete(kind, ns.as_deref(), &name, &cur.raw_revision)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("{kind_str}.crd.projectcalico.org/{name} deleted");
            }
            None => println!("{kind_str} '{name}' not found"),
        }
    }
    Ok(())
}

async fn get(
    kubeconfig: Option<&str>,
    kind_str: &str,
    namespace: Option<String>,
    all_namespaces: bool,
    output: OutputFormat,
) -> Result<()> {
    let kind = ResourceKind::parse_cli(kind_str)
        .with_context(|| format!("unknown resource kind '{kind_str}'"))?;
    let backend = backend(kubeconfig).await?;

    let ns = if kind.is_namespaced() && !all_namespaces {
        Some(namespace.unwrap_or_else(|| "default".to_string()))
    } else {
        None
    };

    let items = backend
        .list(kind, ns.as_deref())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("listing {}", kind.as_str()))?;

    match output {
        OutputFormat::Ps => {
            if items.is_empty() {
                println!("No resources found.");
            } else {
                println!("{:<40} REVISION", "NAME");
                for it in &items {
                    println!("{:<40} {}", it.name, it.raw_revision);
                }
            }
        }
        OutputFormat::Json | OutputFormat::Yaml => {
            let docs: Vec<_> = items
                .iter()
                .map(|it| {
                    serde_json::json!({
                        "apiVersion": "crd.projectcalico.org/v1",
                        "kind": kind.kind_name(),
                        "metadata": { "name": it.name },
                        "spec": it.spec,
                    })
                })
                .collect();
            match output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&docs)?),
                _ => println!("{}", serde_yaml_ng::to_string(&docs)?),
            }
        }
    }
    Ok(())
}
