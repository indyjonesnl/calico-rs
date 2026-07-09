//! In-memory [`CasStore`] — a faithful compare-and-swap backend for tests and
//! for exercising CAS-dependent logic (IPAM affinity claim, controllers) without
//! a live Kubernetes datastore.

use std::collections::HashMap;

use crate::cas::{CasError, CasStore, Revision, Versioned};

/// A simple revisioned key/value map. Revisions are drawn from a single
/// monotonic counter across all keys (mirroring a shared resource-version
/// sequence), so a revision uniquely identifies a write.
#[derive(Debug, Default)]
pub struct MemStore<V: Clone> {
    entries: HashMap<String, Versioned<V>>,
    next_revision: Revision,
}

impl<V: Clone> MemStore<V> {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            next_revision: 1,
        }
    }

    /// Number of stored keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The last-assigned revision (a snapshot "resourceVersion" for the whole
    /// store); `0` before any write.
    pub fn revision(&self) -> Revision {
        self.next_revision.saturating_sub(1)
    }

    fn bump(&mut self) -> Revision {
        let r = self.next_revision;
        self.next_revision += 1;
        r
    }
}

impl<V: Clone> CasStore<V> for MemStore<V> {
    fn get(&self, key: &str) -> Option<Versioned<V>> {
        self.entries.get(key).cloned()
    }

    fn create(&mut self, key: &str, value: V) -> Result<Versioned<V>, CasError> {
        if self.entries.contains_key(key) {
            return Err(CasError::AlreadyExists);
        }
        let revision = self.bump();
        let versioned = Versioned { value, revision };
        self.entries.insert(key.to_string(), versioned.clone());
        Ok(versioned)
    }

    fn update(
        &mut self,
        key: &str,
        value: V,
        revision: Revision,
    ) -> Result<Versioned<V>, CasError> {
        match self.entries.get(key) {
            None => Err(CasError::NotFound),
            Some(existing) if existing.revision != revision => Err(CasError::Conflict {
                expected: revision,
                actual: Some(existing.revision),
            }),
            Some(_) => {
                let new_revision = self.bump();
                let versioned = Versioned {
                    value,
                    revision: new_revision,
                };
                self.entries.insert(key.to_string(), versioned.clone());
                Ok(versioned)
            }
        }
    }

    fn delete(&mut self, key: &str, revision: Revision) -> Result<(), CasError> {
        match self.entries.get(key) {
            None => Err(CasError::NotFound),
            Some(existing) if existing.revision != revision => Err(CasError::Conflict {
                expected: revision,
                actual: Some(existing.revision),
            }),
            Some(_) => {
                self.entries.remove(key);
                Ok(())
            }
        }
    }

    fn list(&self, prefix: &str) -> Vec<Versioned<V>> {
        self.entries
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(_, v)| v.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_get_roundtrip() {
        let mut s: MemStore<i32> = MemStore::new();
        let v = s.create("a", 1).unwrap();
        assert_eq!(s.get("a"), Some(v));
    }

    #[test]
    fn create_twice_conflicts() {
        let mut s: MemStore<i32> = MemStore::new();
        s.create("a", 1).unwrap();
        assert_eq!(s.create("a", 2), Err(CasError::AlreadyExists));
    }

    #[test]
    fn update_requires_matching_revision() {
        let mut s: MemStore<i32> = MemStore::new();
        let v = s.create("a", 1).unwrap();
        // Stale revision loses.
        let stale = v.revision;
        let v2 = s.update("a", 2, stale).unwrap();
        assert_eq!(v2.value, 2);
        assert!(v2.revision != stale);
        // Re-using the stale revision now conflicts.
        assert_eq!(
            s.update("a", 3, stale),
            Err(CasError::Conflict {
                expected: stale,
                actual: Some(v2.revision)
            })
        );
    }

    #[test]
    fn update_missing_is_not_found() {
        let mut s: MemStore<i32> = MemStore::new();
        assert_eq!(s.update("x", 1, 1), Err(CasError::NotFound));
    }

    #[test]
    fn delete_requires_matching_revision() {
        let mut s: MemStore<i32> = MemStore::new();
        let v = s.create("a", 1).unwrap();
        assert_eq!(
            s.delete("a", v.revision + 999),
            Err(CasError::Conflict {
                expected: v.revision + 999,
                actual: Some(v.revision)
            })
        );
        s.delete("a", v.revision).unwrap();
        assert_eq!(s.get("a"), None);
    }

    #[test]
    fn list_by_prefix() {
        let mut s: MemStore<i32> = MemStore::new();
        s.create("aff/host1/10.0.0.0-26", 1).unwrap();
        s.create("aff/host1/10.0.1.0-26", 2).unwrap();
        s.create("aff/host2/10.0.2.0-26", 3).unwrap();
        assert_eq!(s.list("aff/host1/").len(), 2);
        assert_eq!(s.list("aff/").len(), 3);
    }
}
