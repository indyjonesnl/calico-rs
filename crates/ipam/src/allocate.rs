//! Datastore-backed IPAM affinity driver: the two-phase block-affinity claim and
//! release, layered on the [`CasStore`] compare-and-swap primitive.
//!
//! This is the affinity half of the allocation driver (task T025). Cross-block
//! auto-assign over a pool, block borrowing, and the 100× CAS retry loop build
//! on the same primitives and are added next. Each operation here is a single
//! CAS attempt; on [`IpamError::Conflict`] the caller re-reads and retries.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use datastore::CasStore;

use crate::addr::Cidr;
use crate::affinity::BlockAffinity;
use crate::block::{AllocationAttribute, AllocationBlock};
use crate::config::IpamConfig;
use crate::handle::IpamHandle;
use crate::IpamError;

/// Datastore key for a block-affinity record.
pub fn affinity_key(host: &str, cidr: Cidr) -> String {
    format!("aff/{host}/{cidr}")
}

/// Datastore key for an allocation block.
pub fn block_key(cidr: Cidr) -> String {
    format!("block/{cidr}")
}

/// Datastore key for an IPAM handle.
pub fn handle_key(id: &str) -> String {
    format!("handle/{id}")
}

fn owner_string(host: &str) -> String {
    format!("host:{host}")
}

/// Claim block `cidr` for `host` using the two-phase protocol:
/// 1. create/verify a `Pending` affinity record,
/// 2. create the block affine to the host if absent,
/// 3. confirm the affinity (`Pending -> Confirmed`).
///
/// Idempotent: re-claiming an already-confirmed block owned by `host` succeeds.
/// Returns [`IpamError::Backend`] if the block is affine to a different host.
pub fn claim_affinity<A, B>(
    aff_store: &mut A,
    block_store: &mut B,
    host: &str,
    cidr: Cidr,
) -> Result<(), IpamError>
where
    A: CasStore<BlockAffinity>,
    B: CasStore<AllocationBlock>,
{
    let akey = affinity_key(host, cidr);

    // Phase 1: ensure a Pending (or already-Confirmed) affinity record exists.
    let aff_rev = match aff_store.get(&akey) {
        Some(existing) => {
            if existing.value.is_owned() {
                // Already confirmed by us — verify the block and return.
                ensure_block_owned(block_store, host, cidr)?;
                return Ok(());
            }
            existing.revision
        }
        None => {
            aff_store
                .create(&akey, BlockAffinity::claim(host, cidr))?
                .revision
        }
    };

    // Phase 2: create the block affine to this host if it does not exist.
    ensure_block_owned(block_store, host, cidr)?;

    // Phase 3: confirm the affinity.
    let mut aff = aff_store.get(&akey).ok_or(IpamError::Conflict)?;
    // Guard against a concurrent writer having advanced the record.
    if aff.revision != aff_rev {
        // Someone else touched it; re-read semantics — treat as conflict.
        return Err(IpamError::Conflict);
    }
    aff.value.confirm()?;
    aff_store.update(&akey, aff.value, aff.revision)?;
    Ok(())
}

fn ensure_block_owned<B>(block_store: &mut B, host: &str, cidr: Cidr) -> Result<(), IpamError>
where
    B: CasStore<AllocationBlock>,
{
    let want = owner_string(host);
    match block_store.get(&block_key(cidr)) {
        Some(existing) => {
            if existing.value.affinity() == Some(want.as_str()) {
                Ok(())
            } else {
                Err(IpamError::Backend(format!(
                    "block {cidr} is affine to {:?}, not {want}",
                    existing.value.affinity()
                )))
            }
        }
        None => {
            let block = AllocationBlock::with_affinity(cidr, want)?;
            block_store.create(&block_key(cidr), block)?;
            Ok(())
        }
    }
}

/// Release `host`'s affinity to `cidr` using the two-phase protocol:
/// 1. mark the affinity `PendingDeletion`,
/// 2. delete the block iff it is empty (errors [`IpamError::BlockNotEmpty`]
///    otherwise, leaving the affinity in `PendingDeletion`),
/// 3. delete the affinity record.
///
/// Idempotent: releasing an absent affinity succeeds.
pub fn release_affinity<A, B>(
    aff_store: &mut A,
    block_store: &mut B,
    host: &str,
    cidr: Cidr,
) -> Result<(), IpamError>
where
    A: CasStore<BlockAffinity>,
    B: CasStore<AllocationBlock>,
{
    let akey = affinity_key(host, cidr);
    let Some(mut aff) = aff_store.get(&akey) else {
        return Ok(()); // already gone
    };

    // Phase 1: mark PendingDeletion.
    aff.value.begin_deletion()?;
    let aff = aff_store.update(&akey, aff.value, aff.revision)?;

    // Phase 2: delete the block iff empty.
    let bkey = block_key(cidr);
    if let Some(block) = block_store.get(&bkey) {
        if !block.value.is_empty() {
            return Err(IpamError::BlockNotEmpty(cidr));
        }
        block_store.delete(&bkey, block.revision)?;
    }

    // Phase 3: delete the affinity record.
    aff_store.delete(&akey, aff.revision)?;
    Ok(())
}

/// Parameters for a pool-level auto-assignment.
pub struct AutoAssign<'a> {
    /// The pool to allocate from.
    pub pool: Cidr,
    /// Block prefix length to carve the pool into (e.g. 26).
    pub block_size: u8,
    /// The requesting host.
    pub host: &'a str,
    /// Number of addresses requested.
    pub count: usize,
    /// Handle id to attribute the allocations to.
    pub handle_id: &'a str,
    /// Cluster IPAM configuration (strict affinity, auto-allocation, caps).
    pub config: &'a IpamConfig,
}

/// Auto-assign `req.count` addresses for a host from a pool, layering over the
/// [`CasStore`] primitives. Strategy (a simplified port of upstream
/// `autoAssign`):
///
/// 1. allocate from blocks already affine+confirmed to the host;
/// 2. if short and auto-allocation is enabled (and under `max_blocks_per_host`),
///    claim new blocks from the pool (two-phase) and allocate from them;
/// 3. if still short and affinity is not strict, borrow from existing blocks
///    owned by other hosts.
///
/// Returns the assigned addresses (fewer than requested if the pool is
/// exhausted under the active constraints). Handle counts are updated so a later
/// [`release_by_handle`] can find them.
pub fn auto_assign<A, B, H>(
    req: &AutoAssign,
    aff_store: &mut A,
    block_store: &mut B,
    handle_store: &mut H,
    owner_attrs: BTreeMap<String, String>,
) -> Result<Vec<IpAddr>, IpamError>
where
    A: CasStore<BlockAffinity>,
    B: CasStore<AllocationBlock>,
    H: CasStore<IpamHandle>,
{
    let owner = owner_string(req.host);
    let candidates = req.pool.sub_blocks(req.block_size)?;
    let mut host_block_count = aff_store.list(&format!("aff/{}/", req.host)).len();
    let mut assigned: Vec<IpAddr> = Vec::new();

    // Pass 1: existing blocks affine to this host.
    for cidr in &candidates {
        if assigned.len() >= req.count {
            break;
        }
        if let Some(existing) = block_store.get(&block_key(*cidr)) {
            if existing.value.affinity() == Some(owner.as_str()) && !existing.value.is_deleted() {
                allocate_from_block(
                    block_store,
                    handle_store,
                    *cidr,
                    req,
                    &owner_attrs,
                    &mut assigned,
                )?;
            }
        }
    }

    // Pass 2: claim new blocks.
    if assigned.len() < req.count && req.config.auto_allocate_blocks {
        for cidr in &candidates {
            if assigned.len() >= req.count {
                break;
            }
            if block_store.get(&block_key(*cidr)).is_some() {
                continue; // already claimed by someone
            }
            if req.config.max_blocks_per_host > 0
                && host_block_count >= req.config.max_blocks_per_host as usize
            {
                break; // hit the per-host block cap
            }
            claim_affinity(aff_store, block_store, req.host, *cidr)?;
            host_block_count += 1;
            allocate_from_block(
                block_store,
                handle_store,
                *cidr,
                req,
                &owner_attrs,
                &mut assigned,
            )?;
        }
    }

    // Pass 3: borrow from other hosts' blocks (only when not strict).
    if assigned.len() < req.count && !req.config.strict_affinity {
        for cidr in &candidates {
            if assigned.len() >= req.count {
                break;
            }
            if let Some(existing) = block_store.get(&block_key(*cidr)) {
                if existing.value.affinity() != Some(owner.as_str()) && !existing.value.is_deleted()
                {
                    allocate_from_block(
                        block_store,
                        handle_store,
                        *cidr,
                        req,
                        &owner_attrs,
                        &mut assigned,
                    )?;
                }
            }
        }
    }

    Ok(assigned)
}

/// Allocate as many of the still-outstanding addresses as `cidr`'s block can
/// provide, persist the block (CAS), and bump the handle count.
fn allocate_from_block<B, H>(
    block_store: &mut B,
    handle_store: &mut H,
    cidr: Cidr,
    req: &AutoAssign,
    owner_attrs: &BTreeMap<String, String>,
    assigned: &mut Vec<IpAddr>,
) -> Result<(), IpamError>
where
    B: CasStore<AllocationBlock>,
    H: CasStore<IpamHandle>,
{
    let remaining = req.count - assigned.len();
    if remaining == 0 {
        return Ok(());
    }
    let bkey = block_key(cidr);
    let mut kv = block_store.get(&bkey).ok_or(IpamError::Conflict)?;
    let attr = AllocationAttribute {
        handle_id: Some(req.handle_id.to_string()),
        attrs: owner_attrs.clone(),
    };
    let got = kv.value.auto_assign(remaining, attr, &HashSet::new());
    if got.is_empty() {
        return Ok(());
    }
    block_store.update(&bkey, kv.value, kv.revision)?;

    // Update the handle index so release-by-handle can find these later.
    let hkey = handle_key(req.handle_id);
    match handle_store.get(&hkey) {
        Some(h) => {
            let mut hv = h.value;
            hv.increment(&cidr.to_string(), got.len() as u64);
            handle_store.update(&hkey, hv, h.revision)?;
        }
        None => {
            let mut hv = IpamHandle::new(req.handle_id);
            hv.increment(&cidr.to_string(), got.len() as u64);
            handle_store.create(&hkey, hv)?;
        }
    }

    assigned.extend(got);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use datastore::MemStore;

    fn cidr() -> Cidr {
        Cidr::parse("10.0.0.0/26").unwrap()
    }

    #[test]
    fn claim_creates_confirmed_affinity_and_block() {
        let mut affs: MemStore<BlockAffinity> = MemStore::new();
        let mut blocks: MemStore<AllocationBlock> = MemStore::new();

        claim_affinity(&mut affs, &mut blocks, "node-1", cidr()).unwrap();

        let aff = affs.get(&affinity_key("node-1", cidr())).unwrap();
        assert!(aff.value.is_owned());
        let block = blocks.get(&block_key(cidr())).unwrap();
        assert_eq!(block.value.affinity(), Some("host:node-1"));
    }

    #[test]
    fn reclaim_is_idempotent() {
        let mut affs: MemStore<BlockAffinity> = MemStore::new();
        let mut blocks: MemStore<AllocationBlock> = MemStore::new();
        claim_affinity(&mut affs, &mut blocks, "node-1", cidr()).unwrap();
        // Second claim by the same host succeeds without error.
        claim_affinity(&mut affs, &mut blocks, "node-1", cidr()).unwrap();
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn cannot_claim_block_owned_by_another_host() {
        let mut affs: MemStore<BlockAffinity> = MemStore::new();
        let mut blocks: MemStore<AllocationBlock> = MemStore::new();
        claim_affinity(&mut affs, &mut blocks, "node-1", cidr()).unwrap();

        // node-2 attempts to claim the same block.
        let err = claim_affinity(&mut affs, &mut blocks, "node-2", cidr()).unwrap_err();
        assert!(matches!(err, IpamError::Backend(_)));
    }

    #[test]
    fn release_empty_block_removes_affinity_and_block() {
        let mut affs: MemStore<BlockAffinity> = MemStore::new();
        let mut blocks: MemStore<AllocationBlock> = MemStore::new();
        claim_affinity(&mut affs, &mut blocks, "node-1", cidr()).unwrap();

        release_affinity(&mut affs, &mut blocks, "node-1", cidr()).unwrap();
        assert!(affs.get(&affinity_key("node-1", cidr())).is_none());
        assert!(blocks.get(&block_key(cidr())).is_none());
    }

    #[test]
    fn release_is_idempotent_when_absent() {
        let mut affs: MemStore<BlockAffinity> = MemStore::new();
        let mut blocks: MemStore<AllocationBlock> = MemStore::new();
        release_affinity(&mut affs, &mut blocks, "node-1", cidr()).unwrap();
    }

    // ---- pool-level auto_assign ------------------------------------------

    type Stores = (
        MemStore<BlockAffinity>,
        MemStore<AllocationBlock>,
        MemStore<IpamHandle>,
    );

    fn stores() -> Stores {
        (MemStore::new(), MemStore::new(), MemStore::new())
    }

    fn pool() -> Cidr {
        Cidr::parse("10.0.0.0/24").unwrap() // four /26 blocks of 64 addrs
    }

    #[test]
    fn auto_assign_claims_first_block_and_allocates() {
        let (mut affs, mut blocks, mut handles) = stores();
        let cfg = IpamConfig::default();
        let req = AutoAssign {
            pool: pool(),
            block_size: 26,
            host: "node-1",
            count: 3,
            handle_id: "net.pod-a",
            config: &cfg,
        };
        let ips = auto_assign(&req, &mut affs, &mut blocks, &mut handles, BTreeMap::new()).unwrap();
        assert_eq!(
            ips,
            vec![
                "10.0.0.0".parse::<IpAddr>().unwrap(),
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
            ]
        );
        // One block claimed + confirmed, handle records 3.
        assert_eq!(blocks.len(), 1);
        let aff = affs
            .get(&affinity_key("node-1", pool().sub_blocks(26).unwrap()[0]))
            .unwrap();
        assert!(aff.value.is_owned());
        let h = handles.get(&handle_key("net.pod-a")).unwrap();
        assert_eq!(h.value.total(), 3);
    }

    #[test]
    fn auto_assign_spans_multiple_blocks() {
        let (mut affs, mut blocks, mut handles) = stores();
        let cfg = IpamConfig::default();
        let req = AutoAssign {
            pool: pool(),
            block_size: 26,
            host: "node-1",
            count: 65, // more than one /26 (64) worth
            handle_id: "h",
            config: &cfg,
        };
        let ips = auto_assign(&req, &mut affs, &mut blocks, &mut handles, BTreeMap::new()).unwrap();
        assert_eq!(ips.len(), 65);
        assert_eq!(blocks.len(), 2); // needed a second block
    }

    #[test]
    fn max_blocks_per_host_caps_claims() {
        let (mut affs, mut blocks, mut handles) = stores();
        let cfg = IpamConfig {
            strict_affinity: true,
            auto_allocate_blocks: true,
            max_blocks_per_host: 1,
            ..Default::default()
        };
        let req = AutoAssign {
            pool: pool(),
            block_size: 26,
            host: "node-1",
            count: 100, // wants 2 blocks, but capped at 1
            handle_id: "h",
            config: &cfg,
        };
        let ips = auto_assign(&req, &mut affs, &mut blocks, &mut handles, BTreeMap::new()).unwrap();
        assert_eq!(ips.len(), 64); // only one block's worth
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn strict_affinity_does_not_borrow() {
        let (mut affs, mut blocks, mut handles) = stores();
        // node-2 owns and fills every block first.
        let fill_cfg = IpamConfig::default();
        let fill = AutoAssign {
            pool: pool(),
            block_size: 26,
            host: "node-2",
            count: 256, // all four blocks
            handle_id: "other",
            config: &fill_cfg,
        };
        auto_assign(&fill, &mut affs, &mut blocks, &mut handles, BTreeMap::new()).unwrap();
        assert_eq!(blocks.len(), 4);

        // node-1 with strict affinity + no room to claim => gets nothing.
        let cfg = IpamConfig {
            strict_affinity: true,
            auto_allocate_blocks: true,
            ..Default::default()
        };
        let req = AutoAssign {
            pool: pool(),
            block_size: 26,
            host: "node-1",
            count: 5,
            handle_id: "h",
            config: &cfg,
        };
        let ips = auto_assign(&req, &mut affs, &mut blocks, &mut handles, BTreeMap::new()).unwrap();
        assert!(ips.is_empty());
    }

    #[test]
    fn cannot_release_non_empty_block() {
        let mut affs: MemStore<BlockAffinity> = MemStore::new();
        let mut blocks: MemStore<AllocationBlock> = MemStore::new();
        claim_affinity(&mut affs, &mut blocks, "node-1", cidr()).unwrap();

        // Allocate an address in the block, then persist it back.
        let bkey = block_key(cidr());
        let mut block = blocks.get(&bkey).unwrap();
        block.value.auto_assign(
            1,
            AllocationAttribute {
                handle_id: Some("h1".into()),
                ..Default::default()
            },
            &std::collections::HashSet::new(),
        );
        blocks.update(&bkey, block.value, block.revision).unwrap();

        let err = release_affinity(&mut affs, &mut blocks, "node-1", cidr()).unwrap_err();
        assert!(matches!(err, IpamError::BlockNotEmpty(_)));
        // Block remains; affinity is left in PendingDeletion (not removed).
        assert!(blocks.get(&bkey).is_some());
    }
}
