//! [`DeltaTracker`]: tracks a *desired* map and the *dataplane* (last programmed)
//! map, and computes the delta needed to bring the dataplane in line.
//!
//! Ported from upstream `felix/deltatracker`. Correctness model: the desired
//! view is mutated by the calculation graph; the dataplane view is updated only
//! after a change has actually been programmed into the kernel. Pending work is
//! the difference between the two.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::Hash;

/// Tracks desired vs. dataplane state for a keyed collection and yields the
/// pending updates and deletions required to reconcile them.
///
/// `V: PartialEq` is used to detect in-place value changes (a key present in
/// both views but with a differing value is a pending *update*).
#[derive(Debug, Clone)]
pub struct DeltaTracker<K, V> {
    desired: HashMap<K, V>,
    dataplane: HashMap<K, V>,
}

impl<K, V> Default for DeltaTracker<K, V> {
    fn default() -> Self {
        Self {
            desired: HashMap::new(),
            dataplane: HashMap::new(),
        }
    }
}

impl<K, V> DeltaTracker<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone + PartialEq,
{
    /// Create an empty tracker (both views empty).
    pub fn new() -> Self {
        Self::default()
    }

    // ---- Desired view -----------------------------------------------------

    /// Set the desired value for `key`, returning the previous desired value.
    pub fn set_desired(&mut self, key: K, value: V) -> Option<V> {
        self.desired.insert(key, value)
    }

    /// Remove `key` from the desired view, returning the previous value.
    pub fn remove_desired(&mut self, key: &K) -> Option<V> {
        self.desired.remove(key)
    }

    /// Current desired value for `key`, if any.
    pub fn desired(&self, key: &K) -> Option<&V> {
        self.desired.get(key)
    }

    /// Iterate the desired view.
    pub fn iter_desired(&self) -> impl Iterator<Item = (&K, &V)> {
        self.desired.iter()
    }

    /// Number of desired entries.
    pub fn desired_len(&self) -> usize {
        self.desired.len()
    }

    // ---- Dataplane view ---------------------------------------------------

    /// Record that `key`=`value` has been programmed into the dataplane.
    pub fn set_dataplane(&mut self, key: K, value: V) -> Option<V> {
        self.dataplane.insert(key, value)
    }

    /// Record that `key` has been removed from the dataplane.
    pub fn remove_dataplane(&mut self, key: &K) -> Option<V> {
        self.dataplane.remove(key)
    }

    /// Current dataplane value for `key`, if any.
    pub fn dataplane(&self, key: &K) -> Option<&V> {
        self.dataplane.get(key)
    }

    /// Iterate the dataplane view.
    pub fn iter_dataplane(&self) -> impl Iterator<Item = (&K, &V)> {
        self.dataplane.iter()
    }

    /// Replace the entire dataplane view — e.g. after a fresh resync/read-back
    /// of kernel state.
    pub fn replace_dataplane(&mut self, entries: impl IntoIterator<Item = (K, V)>) {
        self.dataplane = entries.into_iter().collect();
    }

    // ---- Deltas -----------------------------------------------------------

    /// Keys that must be created or updated in the dataplane: present in desired
    /// and either absent from the dataplane or with a differing value.
    pub fn iter_pending_updates(&self) -> impl Iterator<Item = (&K, &V)> {
        self.desired
            .iter()
            .filter(move |(k, v)| match self.dataplane.get(*k) {
                Some(existing) => existing != *v,
                None => true,
            })
    }

    /// Keys that must be deleted from the dataplane: present in the dataplane but
    /// absent from desired.
    pub fn iter_pending_deletions(&self) -> impl Iterator<Item = &K> {
        self.dataplane
            .keys()
            .filter(move |k| !self.desired.contains_key(*k))
    }

    /// Count of pending updates.
    pub fn pending_update_count(&self) -> usize {
        self.iter_pending_updates().count()
    }

    /// Count of pending deletions.
    pub fn pending_deletion_count(&self) -> usize {
        self.iter_pending_deletions().count()
    }

    /// True when the dataplane view matches the desired view exactly.
    pub fn in_sync(&self) -> bool {
        self.desired.len() == self.dataplane.len()
            && self.iter_pending_updates().next().is_none()
            && self.iter_pending_deletions().next().is_none()
    }

    /// Mark the dataplane as fully caught up to desired without touching a real
    /// backend. Useful in tests and when the caller programs the whole desired
    /// set atomically.
    pub fn mark_in_sync(&mut self) {
        self.dataplane = self.desired.clone();
    }

    /// Convenience: apply the current desired value for `key` into the dataplane
    /// view (call after successfully programming it).
    pub fn confirm_programmed(&mut self, key: &K) {
        match self.desired.get(key) {
            Some(v) => {
                let v = v.clone();
                self.dataplane.insert(key.clone(), v);
            }
            None => {
                self.dataplane.remove(key);
            }
        }
    }
}

// Allow ergonomic Entry-style desired mutation for value types built in place.
impl<K, V> DeltaTracker<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone + PartialEq + Default,
{
    /// Get-or-insert-default the desired entry for in-place mutation.
    pub fn desired_entry_or_default(&mut self, key: K) -> &mut V {
        match self.desired.entry(key) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => v.insert(V::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tracker_is_in_sync() {
        let t: DeltaTracker<i32, i32> = DeltaTracker::new();
        assert!(t.in_sync());
        assert_eq!(t.pending_update_count(), 0);
        assert_eq!(t.pending_deletion_count(), 0);
    }

    #[test]
    fn new_desired_key_is_pending_update() {
        let mut t = DeltaTracker::new();
        t.set_desired("a", 1);
        assert_eq!(t.pending_update_count(), 1);
        assert_eq!(t.pending_deletion_count(), 0);
        assert!(!t.in_sync());
        let updates: Vec<_> = t.iter_pending_updates().map(|(k, v)| (*k, *v)).collect();
        assert_eq!(updates, vec![("a", 1)]);
    }

    #[test]
    fn changed_value_is_pending_update_not_deletion() {
        let mut t = DeltaTracker::new();
        t.set_desired("a", 1);
        t.set_dataplane("a", 1);
        assert!(t.in_sync());

        t.set_desired("a", 2); // value drift
        assert_eq!(t.pending_update_count(), 1);
        assert_eq!(t.pending_deletion_count(), 0);
    }

    #[test]
    fn removed_desired_key_is_pending_deletion() {
        let mut t = DeltaTracker::new();
        t.set_desired("a", 1);
        t.set_dataplane("a", 1);
        t.remove_desired(&"a");
        assert_eq!(t.pending_update_count(), 0);
        assert_eq!(t.pending_deletion_count(), 1);
        let dels: Vec<_> = t.iter_pending_deletions().copied().collect();
        assert_eq!(dels, vec!["a"]);
    }

    #[test]
    fn confirm_programmed_clears_pending() {
        let mut t = DeltaTracker::new();
        t.set_desired("a", 1);
        t.set_desired("b", 2);
        assert_eq!(t.pending_update_count(), 2);
        t.confirm_programmed(&"a");
        assert_eq!(t.pending_update_count(), 1);
        t.confirm_programmed(&"b");
        assert!(t.in_sync());

        // Confirming a removed key drops it from the dataplane view.
        t.remove_desired(&"a");
        t.confirm_programmed(&"a");
        assert_eq!(t.dataplane(&"a"), None);
    }

    #[test]
    fn mark_in_sync_matches_views() {
        let mut t = DeltaTracker::new();
        t.set_desired("a", 1);
        t.set_desired("b", 2);
        t.mark_in_sync();
        assert!(t.in_sync());
    }

    #[test]
    fn replace_dataplane_recomputes_delta() {
        let mut t = DeltaTracker::new();
        t.set_desired("a", 1);
        t.set_desired("b", 2);
        // Kernel read-back shows a stale "c" and a wrong "a".
        t.replace_dataplane([("a", 9), ("c", 3)]);
        assert_eq!(t.pending_update_count(), 2); // a (drift) + b (missing)
        assert_eq!(t.pending_deletion_count(), 1); // c
    }

    #[test]
    fn desired_entry_or_default_builds_in_place() {
        let mut t: DeltaTracker<&str, Vec<i32>> = DeltaTracker::new();
        t.desired_entry_or_default("a").push(1);
        t.desired_entry_or_default("a").push(2);
        assert_eq!(t.desired(&"a"), Some(&vec![1, 2]));
    }
}
