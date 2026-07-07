//! [`AllocationBlock`]: the compare-and-swap unit of Calico IPAM, reproduced as
//! a pure in-memory structure (the datastore CAS wrapper lives above this).
//!
//! Ported semantics from `libcalico-go/lib/backend/model/block.go` and
//! `design/ipam/`:
//! - `allocations[ordinal]` = index into `attributes`, or `None` if free.
//! - `unallocated` is a **FIFO** free-list: allocation pops the front, release
//!   pushes the back. This rate-limits address reuse (a freed address is not
//!   immediately handed back out), which matters for conntrack/flow safety.
//! - `sequence_number` increments on every mutation; each allocation records the
//!   block sequence number at allocation time in `sequence_number_for_allocation`.
//!   A release that supplies a stale sequence number is rejected (the ABA guard)
//!   so a GC pass cannot free an address that was reallocated after it scanned.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;

use crate::addr::Cidr;
use crate::IpamError;

/// Ownership/metadata attached to an allocation (handle + owner attributes such
/// as pod, namespace, node).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AllocationAttribute {
    /// Primary handle id this allocation belongs to (e.g. `<network>.<containerid>`).
    pub handle_id: Option<String>,
    /// Free-form owner attributes (pod, namespace, node, ...).
    pub attrs: std::collections::BTreeMap<String, String>,
}

/// A serialization-friendly snapshot of an [`AllocationBlock`]'s full state,
/// used to map to/from the persisted CRD form (`apis::IpamBlockSpec`) without
/// exposing the block's internals or bypassing its invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSnapshot {
    pub cidr: String,
    pub affinity: Option<String>,
    pub allocations: Vec<Option<usize>>,
    pub unallocated: Vec<usize>,
    pub attributes: Vec<AllocationAttribute>,
    pub sequence_number: u64,
    pub sequence_number_for_allocation: std::collections::BTreeMap<usize, u64>,
    pub deleted: bool,
}

/// Result of a release attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// The address was allocated and is now free.
    Released,
    /// The address was already free — release is idempotent.
    WasNotAllocated,
}

/// An IPAM allocation block: a contiguous CIDR slice with per-ordinal allocation
/// state. All mutations are local and in-memory; persistence/CAS is layered on
/// top by the datastore-backed driver.
#[derive(Debug, Clone)]
pub struct AllocationBlock {
    cidr: Cidr,
    /// Optional affinity owner, e.g. `"host:node-1"` / `"virtual:name"`.
    affinity: Option<String>,
    /// `allocations[ordinal]` = Some(attr index) if allocated, else None.
    allocations: Vec<Option<usize>>,
    /// FIFO free-list of ordinals available for allocation.
    unallocated: VecDeque<usize>,
    /// Allocation attributes, indexed by the value stored in `allocations`.
    attributes: Vec<AllocationAttribute>,
    /// Bumped on every mutation.
    sequence_number: u64,
    /// Block sequence number recorded at the time each ordinal was allocated.
    sequence_number_for_allocation: HashMap<usize, u64>,
    /// Soft-delete marker (KDD lacks compare-and-delete by revision).
    deleted: bool,
}

impl AllocationBlock {
    /// Create an empty block over `cidr` with every ordinal free (FIFO order
    /// 0..capacity).
    pub fn new(cidr: Cidr) -> Result<Self, IpamError> {
        let capacity = cidr.capacity()?;
        Ok(Self {
            cidr,
            affinity: None,
            allocations: vec![None; capacity],
            unallocated: (0..capacity).collect(),
            attributes: Vec::new(),
            sequence_number: 0,
            sequence_number_for_allocation: HashMap::new(),
            deleted: false,
        })
    }

    /// Create an empty block affine to `owner` (e.g. `"host:node-1"`).
    pub fn with_affinity(cidr: Cidr, owner: impl Into<String>) -> Result<Self, IpamError> {
        let mut b = Self::new(cidr)?;
        b.affinity = Some(owner.into());
        Ok(b)
    }

    /// The block CIDR.
    pub fn cidr(&self) -> Cidr {
        self.cidr
    }

    /// The affinity owner, if any.
    pub fn affinity(&self) -> Option<&str> {
        self.affinity.as_deref()
    }

    /// Current block sequence number.
    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    /// Whether the block is soft-deleted.
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Mark the block soft-deleted (linearization point for KDD delete).
    pub fn mark_deleted(&mut self) {
        self.deleted = true;
        self.sequence_number += 1;
    }

    /// Number of free ordinals.
    pub fn num_free(&self) -> usize {
        self.unallocated.len()
    }

    /// Number of allocated ordinals.
    pub fn num_in_use(&self) -> usize {
        self.allocations.iter().filter(|a| a.is_some()).count()
    }

    /// Whether every ordinal is free.
    pub fn is_empty(&self) -> bool {
        self.num_in_use() == 0
    }

    /// The sequence number recorded when `ip` was allocated (for building the
    /// release guard). `None` if not allocated.
    pub fn allocation_sequence_number(&self, ip: IpAddr) -> Option<u64> {
        let ord = self.cidr.ordinal_of(ip)?;
        self.sequence_number_for_allocation.get(&ord).copied()
    }

    /// Auto-assign up to `count` addresses, skipping any ordinals in `skip`
    /// (e.g. reserved). Returns the assigned addresses in FIFO order. Fewer than
    /// `count` may be returned if the block runs out.
    pub fn auto_assign(
        &mut self,
        count: usize,
        attr: AllocationAttribute,
        skip: &std::collections::HashSet<usize>,
    ) -> Vec<IpAddr> {
        let attr_idx = self.intern_attribute(attr);
        let mut assigned = Vec::with_capacity(count);
        let mut skipped: Vec<usize> = Vec::new();

        while assigned.len() < count {
            let Some(ord) = self.unallocated.pop_front() else {
                break;
            };
            if skip.contains(&ord) {
                skipped.push(ord);
                continue;
            }
            self.commit_allocation(ord, attr_idx);
            assigned.push(self.cidr.nth(ord).expect("ordinal within capacity"));
        }
        // Return skipped-but-free ordinals to the back of the FIFO, preserving
        // their availability without handing them out this round.
        for ord in skipped {
            self.unallocated.push_back(ord);
        }
        assigned
    }

    /// Assign a specific address. Errors if outside the block or already taken.
    pub fn assign(&mut self, ip: IpAddr, attr: AllocationAttribute) -> Result<(), IpamError> {
        let ord = self
            .cidr
            .ordinal_of(ip)
            .ok_or(IpamError::AddressNotInBlock(ip))?;
        if self.allocations[ord].is_some() {
            return Err(IpamError::AlreadyAllocated(ip));
        }
        // Remove the ordinal from the free-list (linear scan; blocks are small).
        if let Some(pos) = self.unallocated.iter().position(|&o| o == ord) {
            self.unallocated.remove(pos);
        }
        let attr_idx = self.intern_attribute(attr);
        self.commit_allocation(ord, attr_idx);
        Ok(())
    }

    /// Release `ip`. If `expected_seq` is `Some`, the release is rejected with
    /// [`IpamError::BadSequenceNumber`] unless it matches the sequence number
    /// recorded at allocation time (the ABA guard) — the address is left
    /// allocated. Releasing an already-free address is a successful no-op.
    pub fn release(
        &mut self,
        ip: IpAddr,
        expected_seq: Option<u64>,
    ) -> Result<ReleaseOutcome, IpamError> {
        let ord = self
            .cidr
            .ordinal_of(ip)
            .ok_or(IpamError::AddressNotInBlock(ip))?;
        if self.allocations[ord].is_none() {
            return Ok(ReleaseOutcome::WasNotAllocated);
        }
        if let Some(expected) = expected_seq {
            let actual = self
                .sequence_number_for_allocation
                .get(&ord)
                .copied()
                .unwrap_or(0);
            if expected != actual {
                return Err(IpamError::BadSequenceNumber { expected, actual });
            }
        }
        self.free_ordinal(ord);
        Ok(ReleaseOutcome::Released)
    }

    /// Release every address allocated under `handle_id`. Returns the released
    /// addresses.
    pub fn release_by_handle(&mut self, handle_id: &str) -> Vec<IpAddr> {
        let mut released = Vec::new();
        let ordinals: Vec<usize> = (0..self.allocations.len())
            .filter(|&ord| self.handle_of(ord) == Some(handle_id))
            .collect();
        for ord in ordinals {
            let ip = self.cidr.nth(ord).expect("ordinal within capacity");
            self.free_ordinal(ord);
            released.push(ip);
        }
        if !released.is_empty() {
            self.compact_attributes();
        }
        released
    }

    /// Drop attribute entries no longer referenced by any allocation, reindexing
    /// the surviving `allocations` accordingly. Keeps the `attributes` array from
    /// growing without bound as addresses are allocated and released over the
    /// life of a block. Preserves the relative order of surviving attributes.
    fn compact_attributes(&mut self) {
        // old attribute index -> new index (None if unreferenced).
        let mut remap: Vec<Option<usize>> = vec![None; self.attributes.len()];
        let mut kept: Vec<AllocationAttribute> = Vec::new();
        for slot in self.allocations.iter().flatten() {
            if remap[*slot].is_none() {
                remap[*slot] = Some(kept.len());
                kept.push(self.attributes[*slot].clone());
            }
        }
        for slot in self.allocations.iter_mut().flatten() {
            *slot = remap[*slot].expect("referenced attribute is kept");
        }
        self.attributes = kept;
    }

    /// Export the block's full state for persistence.
    pub fn snapshot(&self) -> BlockSnapshot {
        BlockSnapshot {
            cidr: self.cidr.to_string(),
            affinity: self.affinity.clone(),
            allocations: self.allocations.clone(),
            unallocated: self.unallocated.iter().copied().collect(),
            attributes: self.attributes.clone(),
            sequence_number: self.sequence_number,
            sequence_number_for_allocation: self
                .sequence_number_for_allocation
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            deleted: self.deleted,
        }
    }

    /// Reconstruct a block from a persisted [`BlockSnapshot`].
    pub fn restore(snap: BlockSnapshot) -> Result<Self, IpamError> {
        let cidr = Cidr::parse(&snap.cidr)?;
        Ok(Self {
            cidr,
            affinity: snap.affinity,
            allocations: snap.allocations,
            unallocated: snap.unallocated.into_iter().collect(),
            attributes: snap.attributes,
            sequence_number: snap.sequence_number,
            sequence_number_for_allocation: snap
                .sequence_number_for_allocation
                .into_iter()
                .collect(),
            deleted: snap.deleted,
        })
    }

    /// The handle id owning `ip`, if allocated.
    pub fn handle_for(&self, ip: IpAddr) -> Option<&str> {
        let ord = self.cidr.ordinal_of(ip)?;
        self.handle_of(ord)
    }

    // ---- internals --------------------------------------------------------

    fn handle_of(&self, ord: usize) -> Option<&str> {
        let attr_idx = self.allocations.get(ord).copied().flatten()?;
        self.attributes[attr_idx].handle_id.as_deref()
    }

    fn intern_attribute(&mut self, attr: AllocationAttribute) -> usize {
        if let Some(idx) = self.attributes.iter().position(|a| a == &attr) {
            idx
        } else {
            self.attributes.push(attr);
            self.attributes.len() - 1
        }
    }

    fn commit_allocation(&mut self, ord: usize, attr_idx: usize) {
        self.sequence_number += 1;
        self.allocations[ord] = Some(attr_idx);
        self.sequence_number_for_allocation
            .insert(ord, self.sequence_number);
    }

    fn free_ordinal(&mut self, ord: usize) {
        self.sequence_number += 1;
        self.allocations[ord] = None;
        self.sequence_number_for_allocation.remove(&ord);
        self.unallocated.push_back(ord); // FIFO: freed goes to the back
                                         // Note: attribute entries are intentionally left interned; a real
                                         // implementation compacts them on persist. Correctness does not depend
                                         // on compaction here.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn block(cidr: &str) -> AllocationBlock {
        AllocationBlock::new(Cidr::parse(cidr).unwrap()).unwrap()
    }

    fn attr(handle: &str) -> AllocationAttribute {
        AllocationAttribute {
            handle_id: Some(handle.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn new_block_is_all_free() {
        let b = block("10.0.0.0/26");
        assert_eq!(b.num_free(), 64);
        assert_eq!(b.num_in_use(), 0);
        assert!(b.is_empty());
    }

    #[test]
    fn auto_assign_hands_out_fifo_from_front() {
        let mut b = block("10.0.0.0/26");
        let ips = b.auto_assign(3, attr("h1"), &HashSet::new());
        let want: Vec<IpAddr> = ["10.0.0.0", "10.0.0.1", "10.0.0.2"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(ips, want);
        assert_eq!(b.num_in_use(), 3);
        assert_eq!(b.num_free(), 61);
    }

    #[test]
    fn release_by_handle_compacts_attributes() {
        let mut b = block("10.0.0.0/26");
        b.auto_assign(1, attr("h1"), &HashSet::new());
        b.auto_assign(1, attr("h2"), &HashSet::new());
        b.auto_assign(1, attr("h3"), &HashSet::new());
        assert_eq!(b.attributes.len(), 3);

        // Releasing the middle handle prunes its attribute entry and reindexes
        // the survivors so their handles still resolve correctly.
        b.release_by_handle("h2");
        assert_eq!(b.num_in_use(), 2);
        assert_eq!(b.attributes.len(), 2);
        assert_eq!(b.handle_of(0), Some("h1"));
        assert_eq!(b.handle_of(1), None);
        assert_eq!(b.handle_of(2), Some("h3"));
    }

    #[test]
    fn released_address_goes_to_back_of_fifo() {
        let mut b = block("10.0.0.0/26");
        let ips = b.auto_assign(2, attr("h1"), &HashSet::new()); // .0, .1
                                                                 // Release .0; it must NOT be the next handed out (FIFO reuse).
        b.release(ips[0], None).unwrap();
        let next = b.auto_assign(1, attr("h2"), &HashSet::new());
        assert_eq!(next, vec!["10.0.0.2".parse::<IpAddr>().unwrap()]);
        // Drain the rest; the recycled .0 comes out last.
        let rest = b.auto_assign(100, attr("h3"), &HashSet::new());
        assert_eq!(*rest.last().unwrap(), "10.0.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn aba_guard_rejects_stale_release() {
        let mut b = block("10.0.0.0/26");
        let ip = b.auto_assign(1, attr("h1"), &HashSet::new())[0];
        let seq_at_alloc = b.allocation_sequence_number(ip).unwrap();

        // Simulate: address freed and reallocated (bumps the recorded seq).
        b.release(ip, None).unwrap();
        // Drain so the recycled ordinal comes back and is reallocated.
        let _ = b.auto_assign(64, attr("h2"), &HashSet::new());
        assert!(b.allocation_sequence_number(ip).unwrap() != seq_at_alloc);

        // A GC pass holding the OLD sequence number must be rejected.
        let err = b.release(ip, Some(seq_at_alloc)).unwrap_err();
        assert!(matches!(err, IpamError::BadSequenceNumber { .. }));
        // ...and the address is still allocated (to h2).
        assert_eq!(b.handle_for(ip), Some("h2"));
    }

    #[test]
    fn matching_sequence_number_releases() {
        let mut b = block("10.0.0.0/26");
        let ip = b.auto_assign(1, attr("h1"), &HashSet::new())[0];
        let seq = b.allocation_sequence_number(ip).unwrap();
        assert_eq!(b.release(ip, Some(seq)).unwrap(), ReleaseOutcome::Released);
        assert!(b.is_empty());
    }

    #[test]
    fn release_unallocated_is_noop() {
        let mut b = block("10.0.0.0/26");
        let ip = "10.0.0.5".parse().unwrap();
        assert_eq!(
            b.release(ip, None).unwrap(),
            ReleaseOutcome::WasNotAllocated
        );
    }

    #[test]
    fn assign_specific_and_conflict() {
        let mut b = block("10.0.0.0/26");
        let ip = "10.0.0.9".parse().unwrap();
        b.assign(ip, attr("h1")).unwrap();
        assert_eq!(b.handle_for(ip), Some("h1"));
        assert!(matches!(
            b.assign(ip, attr("h2")),
            Err(IpamError::AlreadyAllocated(_))
        ));
        // The specifically-assigned ordinal is not handed out by auto_assign.
        let ips = b.auto_assign(64, attr("h3"), &HashSet::new());
        assert!(!ips.contains(&ip));
    }

    #[test]
    fn auto_assign_skips_reserved() {
        let mut b = block("10.0.0.0/26");
        let reserved: HashSet<usize> = [0, 1].into_iter().collect();
        let ips = b.auto_assign(1, attr("h1"), &reserved);
        assert_eq!(ips, vec!["10.0.0.2".parse::<IpAddr>().unwrap()]);
        // Reserved ordinals remain free (returned to the pool, not allocated).
        assert!(b.num_free() >= 2);
    }

    #[test]
    fn release_by_handle_frees_all_its_addresses() {
        let mut b = block("10.0.0.0/26");
        b.auto_assign(3, attr("h1"), &HashSet::new());
        b.auto_assign(2, attr("h2"), &HashSet::new());
        assert_eq!(b.num_in_use(), 5);
        let freed = b.release_by_handle("h1");
        assert_eq!(freed.len(), 3);
        assert_eq!(b.num_in_use(), 2);
    }

    #[test]
    fn snapshot_restore_roundtrip_preserves_state() {
        let mut b = block("10.0.0.0/26");
        b.auto_assign(2, attr("h1"), &HashSet::new());
        let ip = b.auto_assign(1, attr("h2"), &HashSet::new())[0];
        let seq = b.allocation_sequence_number(ip).unwrap();

        let restored = AllocationBlock::restore(b.snapshot()).unwrap();
        assert_eq!(restored.num_in_use(), b.num_in_use());
        assert_eq!(restored.num_free(), b.num_free());
        assert_eq!(restored.allocation_sequence_number(ip), Some(seq));
        assert_eq!(restored.handle_for(ip), Some("h2"));
        assert_eq!(restored.sequence_number(), b.sequence_number());
    }

    #[test]
    fn exhaustion_returns_fewer_than_requested() {
        let mut b = block("10.0.0.0/30"); // 4 addresses
        let ips = b.auto_assign(10, attr("h1"), &HashSet::new());
        assert_eq!(ips.len(), 4);
        assert_eq!(b.num_free(), 0);
        let more = b.auto_assign(1, attr("h1"), &HashSet::new());
        assert!(more.is_empty());
    }
}
