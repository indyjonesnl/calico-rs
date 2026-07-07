//! `calico-rs-controllers` binary — runs the Calico-rs cluster-wide reconcilers:
//! the namespace→Profile controller plus a periodic IPAM garbage collector
//! (per-pod orphaned allocations + whole-node orphaned affinities).

use std::time::Duration;

use anyhow::Result;

const GC_INTERVAL: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let client = kube::Client::try_default().await?;

    // IPAM GC loop, alongside the namespace→Profile controller.
    let gc_client = client.clone();
    tokio::spawn(async move {
        loop {
            match controllers::gc_orphaned_allocations(gc_client.clone()).await {
                Ok(n) if n > 0 => tracing::info!("IPAM GC: reclaimed {n} orphaned allocation(s)"),
                Ok(_) => {}
                Err(e) => tracing::warn!("IPAM GC (allocations) failed: {e}"),
            }
            match controllers::gc_orphaned_affinities(gc_client.clone()).await {
                Ok(n) if n > 0 => tracing::info!("IPAM GC: reclaimed {n} orphaned affinity(ies)"),
                Ok(_) => {}
                Err(e) => tracing::warn!("IPAM GC (affinities) failed: {e}"),
            }
            tokio::time::sleep(GC_INTERVAL).await;
        }
    });

    controllers::run(client).await
}
