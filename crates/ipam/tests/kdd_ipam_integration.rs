//! Cluster-backed IPAM integration test against `calico-rs-k0s`.
//!
//! Runs the real allocation flow (two-phase affinity claim → block create →
//! allocate → handle bump) against the Kubernetes datastore and verifies the
//! resulting `IPAMBlock` / `BlockAffinity` / `IPAMHandle` CRs. Skips gracefully
//! without a cluster. Requires the IPAM CRDs to be applied
//! (`cargo run -p apis --bin gen-crds | kubectl apply -f -`).

use datastore::{KddBackend, ResourceKind};
use ipam::{Cidr, KddIpam};

fn kubeconfig_path() -> Option<String> {
    if let Ok(p) = std::env::var("KUBECONFIG") {
        if std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    let repo = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.cluster/calico-rs-k0s.kubeconfig"
    );
    std::path::Path::new(repo)
        .exists()
        .then(|| repo.to_string())
}

#[tokio::test]
async fn cluster_backed_allocation_two_phase() {
    let Some(path) = kubeconfig_path() else {
        eprintln!("SKIP: no kubeconfig");
        return;
    };
    let backend = match KddBackend::from_kubeconfig_file(&path).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: no cluster ({e})");
            return;
        }
    };
    if backend.list(ResourceKind::IpamBlock, None).await.is_err() {
        eprintln!("SKIP: IPAM CRDs not applied");
        return;
    }

    let host = "calico-rs-k0s-controller";
    let cidr = Cidr::parse("10.123.0.0/26").unwrap();
    let handle = "it-kddipam-h";
    let block_name = "10-123-0-0-26";
    let aff_name = format!("{host}-10-123-0-0-26");

    // Clean slate.
    for (kind, name) in [
        (ResourceKind::IpamBlock, block_name.to_string()),
        (ResourceKind::BlockAffinity, aff_name.clone()),
        (ResourceKind::IpamHandle, handle.to_string()),
    ] {
        if let Ok(Some(kv)) = backend.get(kind, None, &name).await {
            let _ = backend.delete(kind, None, &name, &kv.raw_revision).await;
        }
    }

    let ipam = KddIpam::new(backend.clone());

    // --- first allocation: claims affinity + creates block ---
    let ips = ipam
        .assign_from_block(host, cidr, handle, 3)
        .await
        .expect("assign 3");
    let want: Vec<std::net::IpAddr> = ["10.123.0.0", "10.123.0.1", "10.123.0.2"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    assert_eq!(ips, want);
    assert_eq!(ipam.block_free_count(cidr).await.unwrap(), 61);

    // Affinity CR is confirmed.
    let aff = backend
        .get(ResourceKind::BlockAffinity, None, &aff_name)
        .await
        .unwrap()
        .expect("affinity CR");
    assert_eq!(aff.spec["state"], "confirmed");
    assert_eq!(aff.spec["node"], host);

    // Handle CR records 3 under this block.
    let h = backend
        .get(ResourceKind::IpamHandle, None, handle)
        .await
        .unwrap()
        .expect("handle CR");
    assert_eq!(h.spec["block"]["10.123.0.0/26"], 3);

    // Block CR is affine to the host and has 3 allocations.
    let blk = backend
        .get(ResourceKind::IpamBlock, None, block_name)
        .await
        .unwrap()
        .expect("block CR");
    assert_eq!(blk.spec["affinity"], format!("host:{host}"));

    // --- second allocation: reuses the same block (no new block created) ---
    let more = ipam
        .assign_from_block(host, cidr, handle, 2)
        .await
        .expect("assign 2 more");
    assert_eq!(more.len(), 2);
    assert_eq!(ipam.block_free_count(cidr).await.unwrap(), 59);
    // Still exactly one block for this CIDR.
    let blocks = backend.list(ResourceKind::IpamBlock, None).await.unwrap();
    assert_eq!(blocks.iter().filter(|b| b.name == block_name).count(), 1);

    // Cleanup.
    for (kind, name) in [
        (ResourceKind::IpamBlock, block_name.to_string()),
        (ResourceKind::BlockAffinity, aff_name.clone()),
        (ResourceKind::IpamHandle, handle.to_string()),
    ] {
        if let Ok(Some(kv)) = backend.get(kind, None, &name).await {
            let _ = backend.delete(kind, None, &name, &kv.raw_revision).await;
        }
    }
}

#[tokio::test]
async fn cluster_backed_release_by_handle_frees_addresses() {
    let Some(path) = kubeconfig_path() else {
        eprintln!("SKIP: no kubeconfig");
        return;
    };
    let backend = match KddBackend::from_kubeconfig_file(&path).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: no cluster ({e})");
            return;
        }
    };
    if backend.list(ResourceKind::IpamBlock, None).await.is_err() {
        eprintln!("SKIP: IPAM CRDs not applied");
        return;
    }

    let host = "calico-rs-k0s-controller";
    let cidr = Cidr::parse("10.124.0.0/26").unwrap();
    let handle = "it-kddipam-rel";
    let block_name = "10-124-0-0-26";
    let aff_name = format!("{host}-10-124-0-0-26");

    // Clean slate.
    for (kind, name) in [
        (ResourceKind::IpamBlock, block_name.to_string()),
        (ResourceKind::BlockAffinity, aff_name.clone()),
        (ResourceKind::IpamHandle, handle.to_string()),
    ] {
        if let Ok(Some(kv)) = backend.get(kind, None, &name).await {
            let _ = backend.delete(kind, None, &name, &kv.raw_revision).await;
        }
    }

    let ipam = KddIpam::new(backend.clone());

    // Allocate 4, then release the handle → block back to full, handle gone.
    let ips = ipam
        .assign_from_block(host, cidr, handle, 4)
        .await
        .expect("assign 4");
    assert_eq!(ips.len(), 4);
    assert_eq!(ipam.block_free_count(cidr).await.unwrap(), 60);

    let freed = ipam.release_by_handle(handle).await.expect("release");
    assert_eq!(freed.len(), 4);
    // No leaks: all addresses returned to the block.
    assert_eq!(ipam.block_free_count(cidr).await.unwrap(), 64);
    // Handle record is gone.
    assert!(backend
        .get(ResourceKind::IpamHandle, None, handle)
        .await
        .unwrap()
        .is_none());

    // Idempotent second release.
    assert!(ipam
        .release_by_handle(handle)
        .await
        .expect("release again")
        .is_empty());

    // Cleanup.
    for (kind, name) in [
        (ResourceKind::IpamBlock, block_name.to_string()),
        (ResourceKind::BlockAffinity, aff_name.clone()),
    ] {
        if let Ok(Some(kv)) = backend.get(kind, None, &name).await {
            let _ = backend.delete(kind, None, &name, &kv.raw_revision).await;
        }
    }
}
