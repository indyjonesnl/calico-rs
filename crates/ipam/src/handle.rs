//! [`IpamHandle`]: the by-handle allocation index. Ported from Calico's
//! IPAMHandle resource — a secondary index keyed by handle id so
//! release-by-handle and count-by-handle are O(1) in the number of blocks
//! rather than requiring a scan of every block.

use std::collections::HashMap;

/// Tracks how many addresses a given handle id has allocated in each block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpamHandle {
    handle_id: String,
    /// block CIDR string -> number of addresses allocated under this handle.
    block: HashMap<String, u64>,
    deleted: bool,
}

impl IpamHandle {
    /// Create an empty handle index for `handle_id`.
    pub fn new(handle_id: impl Into<String>) -> Self {
        Self {
            handle_id: handle_id.into(),
            block: HashMap::new(),
            deleted: false,
        }
    }

    /// The handle id.
    pub fn handle_id(&self) -> &str {
        &self.handle_id
    }

    /// Record `n` new allocations in `block_cidr`.
    pub fn increment(&mut self, block_cidr: &str, n: u64) {
        *self.block.entry(block_cidr.to_string()).or_insert(0) += n;
    }

    /// Record the release of `n` allocations in `block_cidr`. Saturates at 0 and
    /// drops the block entry when it reaches 0. Returns the remaining count for
    /// that block.
    pub fn decrement(&mut self, block_cidr: &str, n: u64) -> u64 {
        let remaining = match self.block.get_mut(block_cidr) {
            Some(c) => {
                *c = c.saturating_sub(n);
                *c
            }
            None => 0,
        };
        if remaining == 0 {
            self.block.remove(block_cidr);
        }
        remaining
    }

    /// Count for a specific block.
    pub fn count_in(&self, block_cidr: &str) -> u64 {
        self.block.get(block_cidr).copied().unwrap_or(0)
    }

    /// Total allocations across all blocks under this handle.
    pub fn total(&self) -> u64 {
        self.block.values().sum()
    }

    /// Whether this handle has no remaining allocations.
    pub fn is_empty(&self) -> bool {
        self.block.is_empty()
    }

    /// Export the per-block counts (for persistence).
    pub fn snapshot(&self) -> std::collections::BTreeMap<String, u64> {
        self.block.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }

    /// Reconstruct a handle from persisted per-block counts.
    pub fn restore(
        handle_id: impl Into<String>,
        blocks: std::collections::BTreeMap<String, u64>,
    ) -> Self {
        Self {
            handle_id: handle_id.into(),
            block: blocks.into_iter().collect(),
            deleted: false,
        }
    }

    /// Soft-delete marker.
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Mark soft-deleted (only valid once empty; caller enforces).
    pub fn mark_deleted(&mut self) {
        self.deleted = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_and_total() {
        let mut h = IpamHandle::new("net.container-abc");
        h.increment("10.0.0.0/26", 2);
        h.increment("10.0.1.0/26", 1);
        assert_eq!(h.total(), 3);
        assert_eq!(h.count_in("10.0.0.0/26"), 2);
        assert!(!h.is_empty());
    }

    #[test]
    fn decrement_drops_zeroed_block_and_empties() {
        let mut h = IpamHandle::new("h");
        h.increment("b1", 2);
        assert_eq!(h.decrement("b1", 1), 1);
        assert_eq!(h.decrement("b1", 5), 0); // saturates
        assert_eq!(h.count_in("b1"), 0);
        assert!(h.is_empty());
    }

    #[test]
    fn decrement_unknown_block_is_zero() {
        let mut h = IpamHandle::new("h");
        assert_eq!(h.decrement("nope", 3), 0);
    }
}
