//! `ipam` — Calico-rs IP address management core.
//!
//! This crate reproduces the *semantics* of upstream Calico IPAM
//! (`libcalico-go/lib/ipam`, `design/ipam/`) idiomatically in Rust. It is split
//! into a pure, datastore-independent core (implemented here) and the
//! datastore-backed allocation driver (compare-and-swap, two-phase affinity,
//! cross-block auto-assign) which lives above the `datastore` backend.
//!
//! Pure core (no I/O — unit-testable without a cluster):
//! - [`AllocationBlock`] — a block's ordinal bitmap, FIFO free-list, per-ordinal
//!   sequence numbers, and the ABA-guarded release. (task T022)
//! - [`IpamHandle`] — the by-handle allocation index. (task T024)
//! - [`IpamConfig`] — configuration with the cross-field validation rules. (T026)
//! - [`IpReservation`] — reserved addresses as an ordinal filter. (T027)
//!
//! The load-bearing invariants (see `design/ipam/`): the FIFO `unallocated`
//! free-list drives rate-limited address reuse; each allocation records the
//! block sequence number at allocation time so a release with a stale sequence
//! number is rejected (the ABA guard) rather than freeing a reallocated address.

mod addr;
mod affinity;
mod allocate;
mod block;
mod config;
mod handle;
mod kdd;
mod reservation;

pub use addr::Cidr;
pub use affinity::{AffinityState, BlockAffinity};
pub use allocate::{
    affinity_key, auto_assign, block_key, claim_affinity, handle_key, release_affinity, AutoAssign,
};
pub use block::{AllocationAttribute, AllocationBlock, BlockSnapshot, ReleaseOutcome};
pub use config::IpamConfig;
pub use handle::IpamHandle;
pub use kdd::KddIpam;
pub use reservation::IpReservation;

/// Errors from the IPAM pure core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpamError {
    /// The supplied CIDR / prefix length is invalid for its address family.
    InvalidCidr(String),
    /// The requested block is larger than the core will materialize.
    BlockTooLarge { host_bits: u32 },
    /// The address does not fall within the block's CIDR.
    AddressNotInBlock(std::net::IpAddr),
    /// The address is already allocated.
    AlreadyAllocated(std::net::IpAddr),
    /// Release rejected: the caller's sequence number does not match the one
    /// recorded at allocation time (the ABA guard). The address is NOT freed.
    BadSequenceNumber { expected: u64, actual: u64 },
    /// The configuration is internally inconsistent.
    InvalidConfig(String),
    /// An illegal affinity state transition was attempted.
    InvalidAffinityTransition {
        from: AffinityState,
        to: AffinityState,
    },
    /// The block still has allocations and cannot be released.
    BlockNotEmpty(Cidr),
    /// A datastore compare-and-swap conflict (caller should retry).
    Conflict,
    /// A datastore backend error.
    Backend(String),
}

impl From<datastore::CasError> for IpamError {
    fn from(e: datastore::CasError) -> Self {
        match e {
            datastore::CasError::Conflict { .. } => IpamError::Conflict,
            // A concurrent create of the same resource (e.g. two hosts racing to
            // claim the same unclaimed block) is retryable: on re-read the loser
            // sees the winner's block and moves on.
            datastore::CasError::AlreadyExists => IpamError::Conflict,
            other => IpamError::Backend(other.to_string()),
        }
    }
}

impl std::fmt::Display for IpamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpamError::InvalidCidr(s) => write!(f, "invalid CIDR: {s}"),
            IpamError::BlockTooLarge { host_bits } => {
                write!(f, "block too large: {host_bits} host bits")
            }
            IpamError::AddressNotInBlock(ip) => write!(f, "address {ip} not in block"),
            IpamError::AlreadyAllocated(ip) => write!(f, "address {ip} already allocated"),
            IpamError::BadSequenceNumber { expected, actual } => write!(
                f,
                "bad sequence number: expected {expected}, block has {actual} (release rejected)"
            ),
            IpamError::InvalidConfig(s) => write!(f, "invalid IPAM config: {s}"),
            IpamError::InvalidAffinityTransition { from, to } => {
                write!(f, "invalid affinity transition: {from:?} -> {to:?}")
            }
            IpamError::BlockNotEmpty(cidr) => write!(f, "block {cidr} is not empty"),
            IpamError::Conflict => write!(f, "datastore compare-and-swap conflict (retry)"),
            IpamError::Backend(s) => write!(f, "datastore backend error: {s}"),
        }
    }
}

impl std::error::Error for IpamError {}
