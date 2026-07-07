//! Cluster-backed IPAM: runs the allocation flow against the Kubernetes
//! datastore (`KddBackend`), reusing the pure invariant-bearing logic
//! ([`AllocationBlock`], [`BlockAffinity`]) with an explicit runtime ↔ CRD-spec
//! mapping. Each step is a compare-and-swap on the corresponding CR
//! (`IPAMBlock` / `BlockAffinity` / `IPAMHandle`); the whole flow retries on a
//! CAS conflict, exactly as upstream's `datastoreRetries` loop does.

use std::collections::BTreeMap;
use std::net::IpAddr;

use apis::{AllocationAttributeSpec, BlockAffinitySpec, IpamBlockSpec, IpamHandleSpec};
use datastore::{cidr_to_token, KddBackend, ResourceKind};

use crate::addr::Cidr;
use crate::affinity::{AffinityState, BlockAffinity};
use crate::block::{AllocationAttribute, AllocationBlock, BlockSnapshot};
use crate::handle::IpamHandle;
use crate::IpamError;

const DATASTORE_RETRIES: usize = 10;

/// IPAM allocator backed by the Kubernetes datastore.
pub struct KddIpam {
    backend: KddBackend,
}

impl KddIpam {
    /// Wrap a datastore backend.
    pub fn new(backend: KddBackend) -> Self {
        Self { backend }
    }

    /// Assign up to `count` addresses for `host` from the block `block_cidr`,
    /// claiming affinity (two-phase) and creating the block on first use. Retries
    /// the whole flow on CAS conflict. Returns the assigned addresses (fewer than
    /// requested if the block is full).
    pub async fn assign_from_block(
        &self,
        host: &str,
        block_cidr: Cidr,
        handle_id: &str,
        count: usize,
    ) -> Result<Vec<IpAddr>, IpamError> {
        self.assign_from_block_with_attrs(host, block_cidr, handle_id, &BTreeMap::new(), count)
            .await
    }

    /// Like [`assign_from_block`], recording `secondary` owner attributes (e.g.
    /// pod namespace/name/node) on each allocation so orphaned addresses can be
    /// garbage-collected by pod liveness later.
    pub async fn assign_from_block_with_attrs(
        &self,
        host: &str,
        block_cidr: Cidr,
        handle_id: &str,
        secondary: &BTreeMap<String, String>,
        count: usize,
    ) -> Result<Vec<IpAddr>, IpamError> {
        for _ in 0..DATASTORE_RETRIES {
            match self
                .try_assign(host, block_cidr, handle_id, secondary, count)
                .await
            {
                Err(IpamError::Conflict) => continue, // re-read + retry
                other => return other,
            }
        }
        Err(IpamError::Conflict)
    }

    async fn try_assign(
        &self,
        host: &str,
        block_cidr: Cidr,
        handle_id: &str,
        secondary: &BTreeMap<String, String>,
        count: usize,
    ) -> Result<Vec<IpAddr>, IpamError> {
        let bname = cidr_to_token(&block_cidr.to_string());
        let existing = self
            .backend
            .get(ResourceKind::IpamBlock, None, &bname)
            .await?;

        // Strict affinity: never allocate from a block owned by another host.
        // Checked before claiming affinity so we don't leave a stray affinity
        // record on someone else's block.
        if let Some(kv) = &existing {
            if let Some(owner) = kv
                .spec
                .get("affinity")
                .and_then(|v| v.as_str())
                .and_then(|s| s.strip_prefix("host:"))
            {
                if owner != host {
                    return Ok(Vec::new());
                }
            }
        }

        self.ensure_affinity_confirmed(host, block_cidr).await?;

        let attr = AllocationAttribute {
            handle_id: Some(handle_id.to_string()),
            attrs: secondary.clone(),
        };
        let skip = std::collections::HashSet::new();

        let assigned = match existing {
            Some(kv) => {
                let spec: IpamBlockSpec = from_value(kv.spec)?;
                let mut block = spec_to_block(spec)?;
                let ips = block.auto_assign(count, attr, &skip);
                if ips.is_empty() {
                    return Ok(ips);
                }
                self.backend
                    .update(
                        ResourceKind::IpamBlock,
                        None,
                        &bname,
                        to_value(&block_to_spec(&block))?,
                        &kv.raw_revision,
                    )
                    .await?;
                ips
            }
            None => {
                let mut block = AllocationBlock::with_affinity(block_cidr, format!("host:{host}"))?;
                let ips = block.auto_assign(count, attr, &skip);
                self.backend
                    .create(
                        ResourceKind::IpamBlock,
                        None,
                        &bname,
                        to_value(&block_to_spec(&block))?,
                    )
                    .await?;
                ips
            }
        };

        if !assigned.is_empty() {
            self.bump_handle(handle_id, &block_cidr.to_string(), assigned.len() as u64)
                .await?;
        }
        Ok(assigned)
    }

    /// Assign `count` addresses for `host` from a pool, trying each block in the
    /// pool in turn (claiming affinity + creating blocks as needed). Returns the
    /// addresses assigned (fewer than `count` if the pool is exhausted).
    pub async fn auto_assign_from_pool(
        &self,
        host: &str,
        pool_cidr: Cidr,
        block_size: u8,
        handle_id: &str,
        count: usize,
    ) -> Result<Vec<IpAddr>, IpamError> {
        self.auto_assign_from_pool_with_attrs(
            host,
            pool_cidr,
            block_size,
            handle_id,
            &BTreeMap::new(),
            count,
        )
        .await
    }

    /// Like [`auto_assign_from_pool`], recording `secondary` owner attributes
    /// (pod namespace/name/node) on each allocation for later GC by pod liveness.
    pub async fn auto_assign_from_pool_with_attrs(
        &self,
        host: &str,
        pool_cidr: Cidr,
        block_size: u8,
        handle_id: &str,
        secondary: &BTreeMap<String, String>,
        count: usize,
    ) -> Result<Vec<IpAddr>, IpamError> {
        let mut assigned = Vec::new();
        let blocks = pool_cidr.sub_blocks(block_size)?;

        // Pass 1: fill from blocks already affine to this host. Keeping each
        // host's allocations within its own block(s) is what lets the VXLAN
        // routing advertise one block → one node.
        for block in &blocks {
            if assigned.len() >= count {
                break;
            }
            if self.block_owner(*block).await?.as_deref() != Some(host) {
                continue;
            }
            let remaining = count - assigned.len();
            let got = self
                .assign_from_block_with_attrs(host, *block, handle_id, secondary, remaining)
                .await?;
            assigned.extend(got);
        }

        // Pass 2: claim unclaimed blocks as needed. Never allocate from a block
        // affine to another host (strict affinity).
        for block in &blocks {
            if assigned.len() >= count {
                break;
            }
            if self.block_owner(*block).await?.is_some() {
                continue; // ours (already filled above) or another host's
            }
            let remaining = count - assigned.len();
            let got = self
                .assign_from_block_with_attrs(host, *block, handle_id, secondary, remaining)
                .await?;
            assigned.extend(got);
        }
        Ok(assigned)
    }

    /// The host a block is affine to (`None` if the block does not exist yet or
    /// has no affinity), read from the block's own `affinity` field
    /// (`"host:<name>"`) — the authoritative owner.
    async fn block_owner(&self, block_cidr: Cidr) -> Result<Option<String>, IpamError> {
        let bname = cidr_to_token(&block_cidr.to_string());
        match self
            .backend
            .get(ResourceKind::IpamBlock, None, &bname)
            .await?
        {
            Some(kv) => Ok(kv
                .spec
                .get("affinity")
                .and_then(|v| v.as_str())
                .and_then(|s| s.strip_prefix("host:").map(str::to_string))),
            None => Ok(None),
        }
    }

    /// Release every address allocated under `handle_id` (e.g. on CNI DEL),
    /// freeing them in their blocks and removing the handle. Retries on CAS
    /// conflict. Returns the released addresses. Idempotent when the handle is
    /// already gone.
    pub async fn release_by_handle(&self, handle_id: &str) -> Result<Vec<IpAddr>, IpamError> {
        for _ in 0..DATASTORE_RETRIES {
            match self.try_release_by_handle(handle_id).await {
                Err(IpamError::Conflict) => continue,
                other => return other,
            }
        }
        Err(IpamError::Conflict)
    }

    async fn try_release_by_handle(&self, handle_id: &str) -> Result<Vec<IpAddr>, IpamError> {
        let hname = sanitize_name(handle_id);
        let Some(hkv) = self
            .backend
            .get(ResourceKind::IpamHandle, None, &hname)
            .await?
        else {
            return Ok(Vec::new()); // already released
        };
        let hspec: IpamHandleSpec = from_value(hkv.spec)?;

        let mut released = Vec::new();
        for block_cidr_str in hspec.block.keys() {
            let bname = cidr_to_token(block_cidr_str);
            if let Some(bkv) = self
                .backend
                .get(ResourceKind::IpamBlock, None, &bname)
                .await?
            {
                let mut block = spec_to_block(from_value(bkv.spec)?)?;
                let freed = block.release_by_handle(handle_id);
                if !freed.is_empty() {
                    self.backend
                        .update(
                            ResourceKind::IpamBlock,
                            None,
                            &bname,
                            to_value(&block_to_spec(&block))?,
                            &bkv.raw_revision,
                        )
                        .await?;
                    released.extend(freed);
                }
            }
        }

        // Drop the handle record now that its allocations are freed.
        self.backend
            .delete(ResourceKind::IpamHandle, None, &hname, &hkv.raw_revision)
            .await?;
        Ok(released)
    }

    /// Ensure a confirmed block-affinity for `host` over `cidr` (two-phase claim).
    async fn ensure_affinity_confirmed(&self, host: &str, cidr: Cidr) -> Result<(), IpamError> {
        let name = affinity_name(host, cidr);
        match self
            .backend
            .get(ResourceKind::BlockAffinity, None, &name)
            .await?
        {
            Some(kv) => {
                let spec: BlockAffinitySpec = from_value(kv.spec)?;
                let mut aff = BlockAffinity::from_parts(
                    &spec.node,
                    cidr,
                    AffinityState::from_wire(&spec.state),
                );
                if aff.is_owned() {
                    return Ok(());
                }
                aff.confirm()?;
                self.backend
                    .update(
                        ResourceKind::BlockAffinity,
                        None,
                        &name,
                        to_value(&affinity_to_spec(&aff))?,
                        &kv.raw_revision,
                    )
                    .await?;
            }
            None => {
                // Phase 1: create pending.
                let pending = BlockAffinity::claim(host, cidr);
                let created = self
                    .backend
                    .create(
                        ResourceKind::BlockAffinity,
                        None,
                        &name,
                        to_value(&affinity_to_spec(&pending))?,
                    )
                    .await?;
                // Phase 2: confirm.
                let mut confirmed = pending;
                confirmed.confirm()?;
                self.backend
                    .update(
                        ResourceKind::BlockAffinity,
                        None,
                        &name,
                        to_value(&affinity_to_spec(&confirmed))?,
                        &created.raw_revision,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn bump_handle(
        &self,
        handle_id: &str,
        block_cidr: &str,
        n: u64,
    ) -> Result<(), IpamError> {
        let name = sanitize_name(handle_id);
        match self
            .backend
            .get(ResourceKind::IpamHandle, None, &name)
            .await?
        {
            Some(kv) => {
                let spec: IpamHandleSpec = from_value(kv.spec)?;
                let mut h = IpamHandle::restore(&spec.handle_id, u64_map(spec.block));
                h.increment(block_cidr, n);
                self.backend
                    .update(
                        ResourceKind::IpamHandle,
                        None,
                        &name,
                        to_value(&handle_to_spec(handle_id, &h))?,
                        &kv.raw_revision,
                    )
                    .await?;
            }
            None => {
                let mut h = IpamHandle::new(handle_id);
                h.increment(block_cidr, n);
                self.backend
                    .create(
                        ResourceKind::IpamHandle,
                        None,
                        &name,
                        to_value(&handle_to_spec(handle_id, &h))?,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Number of free addresses in the block, or the block capacity if it does
    /// not exist yet. Useful for tests / utilization.
    pub async fn block_free_count(&self, block_cidr: Cidr) -> Result<usize, IpamError> {
        let bname = cidr_to_token(&block_cidr.to_string());
        match self
            .backend
            .get(ResourceKind::IpamBlock, None, &bname)
            .await?
        {
            Some(kv) => Ok(spec_to_block(from_value(kv.spec)?)?.num_free()),
            None => block_cidr.capacity(),
        }
    }
}

// ---- name helpers --------------------------------------------------------

fn affinity_name(host: &str, cidr: Cidr) -> String {
    sanitize_name(&format!("{}-{}", host, cidr_to_token(&cidr.to_string())))
}

/// Coerce an arbitrary id into an RFC-1123-ish resource name.
fn sanitize_name(s: &str) -> String {
    let mut out: String = s
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    out.truncate(253);
    out
}

// ---- runtime <-> spec mapping --------------------------------------------

fn to_value<T: serde::Serialize>(v: &T) -> Result<serde_json::Value, IpamError> {
    serde_json::to_value(v).map_err(|e| IpamError::Backend(e.to_string()))
}

fn from_value<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, IpamError> {
    serde_json::from_value(v).map_err(|e| IpamError::Backend(e.to_string()))
}

fn u64_map(m: BTreeMap<String, i64>) -> BTreeMap<String, u64> {
    m.into_iter().map(|(k, v)| (k, v.max(0) as u64)).collect()
}

fn block_to_spec(b: &AllocationBlock) -> IpamBlockSpec {
    let s: BlockSnapshot = b.snapshot();
    IpamBlockSpec {
        cidr: s.cidr,
        affinity: s.affinity,
        allocations: s.allocations.iter().map(|o| o.map(|x| x as i64)).collect(),
        unallocated: s.unallocated.iter().map(|x| *x as i64).collect(),
        attributes: s
            .attributes
            .iter()
            .map(|a| AllocationAttributeSpec {
                handle_id: a.handle_id.clone(),
                secondary: a.attrs.clone(),
            })
            .collect(),
        deleted: s.deleted,
        sequence_number: s.sequence_number,
        sequence_number_for_allocation: s
            .sequence_number_for_allocation
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
    }
}

fn spec_to_block(spec: IpamBlockSpec) -> Result<AllocationBlock, IpamError> {
    let snap = BlockSnapshot {
        cidr: spec.cidr,
        affinity: spec.affinity,
        allocations: spec
            .allocations
            .iter()
            .map(|o| o.map(|x| x as usize))
            .collect(),
        unallocated: spec.unallocated.iter().map(|x| *x as usize).collect(),
        attributes: spec
            .attributes
            .into_iter()
            .map(|a| AllocationAttribute {
                handle_id: a.handle_id,
                attrs: a.secondary,
            })
            .collect(),
        sequence_number: spec.sequence_number,
        sequence_number_for_allocation: spec
            .sequence_number_for_allocation
            .iter()
            .filter_map(|(k, v)| k.parse::<usize>().ok().map(|ki| (ki, *v)))
            .collect(),
        deleted: spec.deleted,
    };
    AllocationBlock::restore(snap)
}

fn affinity_to_spec(a: &BlockAffinity) -> BlockAffinitySpec {
    BlockAffinitySpec {
        node: a.host().to_string(),
        cidr: a.cidr().to_string(),
        state: a.state().as_str().to_string(),
        deleted: false,
    }
}

fn handle_to_spec(handle_id: &str, h: &IpamHandle) -> IpamHandleSpec {
    IpamHandleSpec {
        handle_id: handle_id.to_string(),
        block: h
            .snapshot()
            .into_iter()
            .map(|(k, v)| (k, v as i64))
            .collect(),
        deleted: false,
    }
}
