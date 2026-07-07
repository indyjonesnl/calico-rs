//! Compare-and-swap storage contract. Every mutating datastore operation in
//! Calico is a CAS on a resource revision; reproducing that precisely is what
//! makes concurrent IPAM and controller logic correct.

/// Monotonic resource revision (opaque version token).
pub type Revision = u64;

/// A stored value together with the revision at which it currently exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Versioned<V> {
    pub value: V,
    pub revision: Revision,
}

/// Errors from a [`CasStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasError {
    /// The key does not exist.
    NotFound,
    /// `create` was called for a key that already exists.
    AlreadyExists,
    /// A CAS update/delete lost: the supplied revision did not match the stored
    /// one (the caller should re-read and retry).
    Conflict {
        expected: Revision,
        actual: Option<Revision>,
    },
    /// Transport / backend failure.
    Backend(String),
}

impl std::fmt::Display for CasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CasError::NotFound => write!(f, "resource does not exist"),
            CasError::AlreadyExists => write!(f, "resource already exists"),
            CasError::Conflict { expected, actual } => write!(
                f,
                "update conflict: expected revision {expected}, store has {actual:?}"
            ),
            CasError::Backend(s) => write!(f, "datastore backend error: {s}"),
        }
    }
}

impl std::error::Error for CasError {}

/// A revisioned key/value store with compare-and-swap update/delete semantics.
///
/// Keys are opaque strings (typed key encoding is layered above); values are any
/// cloneable type. This is the minimal surface the CAS-dependent logic needs;
/// the full `Backend` (typed keys, watch, KDD) is built on top.
pub trait CasStore<V: Clone> {
    /// Fetch the current value + revision for `key`, if present.
    fn get(&self, key: &str) -> Option<Versioned<V>>;

    /// Create `key`. Errors [`CasError::AlreadyExists`] if it already exists.
    fn create(&mut self, key: &str, value: V) -> Result<Versioned<V>, CasError>;

    /// Update `key` iff its current revision equals `revision`. Errors
    /// [`CasError::NotFound`] if absent, [`CasError::Conflict`] on revision
    /// mismatch.
    fn update(&mut self, key: &str, value: V, revision: Revision)
        -> Result<Versioned<V>, CasError>;

    /// Delete `key` iff its current revision equals `revision`.
    fn delete(&mut self, key: &str, revision: Revision) -> Result<(), CasError>;

    /// List all values whose key starts with `prefix`.
    fn list(&self, prefix: &str) -> Vec<Versioned<V>>;
}
