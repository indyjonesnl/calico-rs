//! [`BlockAffinity`]: a per-host claim on an [`crate::AllocationBlock`], with the
//! two-phase state machine that makes block ownership safe under concurrency.
//!
//! State machine (from `design/ipam/`):
//! ```text
//!   (absent) --claim--> Pending --confirm--> Confirmed
//!       ^                  |                     |
//!       |                  +------ delete -------+
//!       |                                        |
//!       +----------- delete ----- PendingDeletion <-- begin_deletion
//! ```
//! - `Pending`: this host *wants* the block; for routing/ownership decisions the
//!   block is treated as **absent** (another host must not use it, this host must
//!   not yet route it).
//! - `Confirmed`: this host owns the block; routing is safe.
//! - `PendingDeletion`: this host is giving the block up; others must not reclaim
//!   it until the affinity record is gone.

use crate::addr::Cidr;
use crate::IpamError;

/// The lifecycle state of a [`BlockAffinity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityState {
    /// Claim in progress; treat the block as not-yet-owned.
    Pending,
    /// Ownership confirmed; safe to route.
    Confirmed,
    /// Release in progress; others must not reclaim until the record is gone.
    PendingDeletion,
}

impl AffinityState {
    /// Wire string form (as stored in the `BlockAffinity` CRD).
    pub fn as_str(self) -> &'static str {
        match self {
            AffinityState::Pending => "pending",
            AffinityState::Confirmed => "confirmed",
            AffinityState::PendingDeletion => "pendingDeletion",
        }
    }

    /// Parse from the wire string form; unknown values default to `Pending`.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "confirmed" => AffinityState::Confirmed,
            "pendingDeletion" => AffinityState::PendingDeletion,
            _ => AffinityState::Pending,
        }
    }
}

/// A host's affinity to a specific block CIDR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockAffinity {
    host: String,
    cidr: Cidr,
    state: AffinityState,
    /// Affinity type, defaulting to `"host"` (vs `"virtual"`).
    affinity_type: String,
}

impl BlockAffinity {
    /// Begin a claim: a new affinity starts in [`AffinityState::Pending`].
    pub fn claim(host: impl Into<String>, cidr: Cidr) -> Self {
        Self {
            host: host.into(),
            cidr,
            state: AffinityState::Pending,
            affinity_type: "host".to_string(),
        }
    }

    /// Reconstruct an affinity in a given state (e.g. loaded from the datastore).
    pub fn from_parts(host: impl Into<String>, cidr: Cidr, state: AffinityState) -> Self {
        Self {
            host: host.into(),
            cidr,
            state,
            affinity_type: "host".to_string(),
        }
    }

    /// The owning host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The block CIDR.
    pub fn cidr(&self) -> Cidr {
        self.cidr
    }

    /// Current state.
    pub fn state(&self) -> AffinityState {
        self.state
    }

    /// The affinity type (`"host"` by default).
    pub fn affinity_type(&self) -> &str {
        &self.affinity_type
    }

    /// Whether this affinity grants ownership for routing/allocation (only
    /// [`AffinityState::Confirmed`] does).
    pub fn is_owned(&self) -> bool {
        self.state == AffinityState::Confirmed
    }

    /// Confirm a pending claim: `Pending -> Confirmed`. Idempotent if already
    /// confirmed.
    pub fn confirm(&mut self) -> Result<(), IpamError> {
        match self.state {
            AffinityState::Pending | AffinityState::Confirmed => {
                self.state = AffinityState::Confirmed;
                Ok(())
            }
            AffinityState::PendingDeletion => Err(IpamError::InvalidAffinityTransition {
                from: self.state,
                to: AffinityState::Confirmed,
            }),
        }
    }

    /// Begin release: `Pending|Confirmed -> PendingDeletion`. Idempotent if
    /// already pending-deletion.
    pub fn begin_deletion(&mut self) -> Result<(), IpamError> {
        // Every state may move to PendingDeletion (idempotent for itself).
        self.state = AffinityState::PendingDeletion;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr() -> Cidr {
        Cidr::parse("10.0.0.0/26").unwrap()
    }

    #[test]
    fn claim_starts_pending_and_not_owned() {
        let a = BlockAffinity::claim("node-1", cidr());
        assert_eq!(a.state(), AffinityState::Pending);
        assert!(!a.is_owned());
        assert_eq!(a.affinity_type(), "host");
    }

    #[test]
    fn confirm_grants_ownership() {
        let mut a = BlockAffinity::claim("node-1", cidr());
        a.confirm().unwrap();
        assert_eq!(a.state(), AffinityState::Confirmed);
        assert!(a.is_owned());
        // Idempotent.
        a.confirm().unwrap();
        assert!(a.is_owned());
    }

    #[test]
    fn cannot_confirm_after_begin_deletion() {
        let mut a = BlockAffinity::claim("node-1", cidr());
        a.confirm().unwrap();
        a.begin_deletion().unwrap();
        assert_eq!(a.state(), AffinityState::PendingDeletion);
        assert!(!a.is_owned()); // pending-deletion is not ownership
        let err = a.confirm().unwrap_err();
        assert!(matches!(err, IpamError::InvalidAffinityTransition { .. }));
    }

    #[test]
    fn begin_deletion_from_pending_is_allowed() {
        let mut a = BlockAffinity::claim("node-1", cidr());
        a.begin_deletion().unwrap();
        assert_eq!(a.state(), AffinityState::PendingDeletion);
    }
}
