//! [`SetDeltaTracker`]: the membership-only specialization of a delta tracker,
//! used where there is no value payload (e.g. IP-set / nftables named-set
//! members). Ported from upstream `felix/deltatracker` `SetDeltaTracker`.

use std::collections::HashSet;
use std::hash::Hash;

/// Tracks desired vs. dataplane *set membership* and yields the additions and
/// removals needed to reconcile them.
#[derive(Debug, Clone)]
pub struct SetDeltaTracker<K> {
    desired: HashSet<K>,
    dataplane: HashSet<K>,
}

impl<K> Default for SetDeltaTracker<K> {
    fn default() -> Self {
        Self {
            desired: HashSet::new(),
            dataplane: HashSet::new(),
        }
    }
}

impl<K> SetDeltaTracker<K>
where
    K: Eq + Hash + Clone,
{
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `member` to the desired set. Returns true if newly added.
    pub fn add_desired(&mut self, member: K) -> bool {
        self.desired.insert(member)
    }

    /// Remove `member` from the desired set. Returns true if it was present.
    pub fn remove_desired(&mut self, member: &K) -> bool {
        self.desired.remove(member)
    }

    /// Whether `member` is desired.
    pub fn is_desired(&self, member: &K) -> bool {
        self.desired.contains(member)
    }

    /// Replace the whole desired set.
    pub fn replace_desired(&mut self, members: impl IntoIterator<Item = K>) {
        self.desired = members.into_iter().collect();
    }

    /// Record that `member` has been programmed into the dataplane.
    pub fn add_dataplane(&mut self, member: K) -> bool {
        self.dataplane.insert(member)
    }

    /// Record that `member` has been removed from the dataplane.
    pub fn remove_dataplane(&mut self, member: &K) -> bool {
        self.dataplane.remove(member)
    }

    /// Replace the whole dataplane set — e.g. after a kernel read-back.
    pub fn replace_dataplane(&mut self, members: impl IntoIterator<Item = K>) {
        self.dataplane = members.into_iter().collect();
    }

    /// Members that must be added to the dataplane (desired − dataplane).
    pub fn iter_pending_additions(&self) -> impl Iterator<Item = &K> {
        self.desired.difference(&self.dataplane)
    }

    /// Members that must be removed from the dataplane (dataplane − desired).
    pub fn iter_pending_removals(&self) -> impl Iterator<Item = &K> {
        self.dataplane.difference(&self.desired)
    }

    /// Count of pending additions.
    pub fn pending_addition_count(&self) -> usize {
        self.iter_pending_additions().count()
    }

    /// Count of pending removals.
    pub fn pending_removal_count(&self) -> usize {
        self.iter_pending_removals().count()
    }

    /// True when dataplane membership equals desired membership.
    pub fn in_sync(&self) -> bool {
        self.desired == self.dataplane
    }

    /// Mark the dataplane as caught up to desired (no real backend touched).
    pub fn mark_in_sync(&mut self) {
        self.dataplane = self.desired.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additions_and_removals() {
        let mut t = SetDeltaTracker::new();
        t.add_desired("a");
        t.add_desired("b");
        t.add_dataplane("b");
        t.add_dataplane("c");

        let mut adds: Vec<_> = t.iter_pending_additions().copied().collect();
        adds.sort_unstable();
        assert_eq!(adds, vec!["a"]);

        let mut rems: Vec<_> = t.iter_pending_removals().copied().collect();
        rems.sort_unstable();
        assert_eq!(rems, vec!["c"]);

        assert!(!t.in_sync());
    }

    #[test]
    fn mark_in_sync_is_empty_delta() {
        let mut t = SetDeltaTracker::new();
        t.replace_desired(["a", "b", "c"]);
        t.mark_in_sync();
        assert!(t.in_sync());
        assert_eq!(t.pending_addition_count(), 0);
        assert_eq!(t.pending_removal_count(), 0);
    }

    #[test]
    fn replace_dataplane_recomputes() {
        let mut t = SetDeltaTracker::new();
        t.replace_desired(["a", "b"]);
        t.replace_dataplane(["b", "z"]);
        assert_eq!(t.pending_addition_count(), 1); // a
        assert_eq!(t.pending_removal_count(), 1); // z
    }
}
