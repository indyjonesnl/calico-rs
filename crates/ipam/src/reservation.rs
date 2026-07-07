//! [`IpReservation`]: addresses carved out of allocation (tunnel IPs,
//! externally-managed addresses). At allocation time these are resolved to a set
//! of block ordinals and passed to [`AllocationBlock::auto_assign`] as the skip
//! set; they never participate in compare-and-swap.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::addr::Cidr;

/// A set of reserved CIDRs/addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpReservation {
    reserved: Vec<Cidr>,
}

impl IpReservation {
    /// Create from a list of reserved CIDRs.
    pub fn new(reserved: impl IntoIterator<Item = Cidr>) -> Self {
        Self {
            reserved: reserved.into_iter().collect(),
        }
    }

    /// Add a reserved CIDR.
    pub fn add(&mut self, cidr: Cidr) {
        self.reserved.push(cidr);
    }

    /// Whether `ip` is reserved (falls within any reserved CIDR).
    pub fn is_reserved(&self, ip: IpAddr) -> bool {
        self.reserved.iter().any(|c| c.ordinal_of(ip).is_some())
    }

    /// Compute the set of ordinals within `block` that are reserved, suitable as
    /// the `skip` argument to [`crate::AllocationBlock::auto_assign`].
    pub fn reserved_ordinals(&self, block: Cidr) -> HashSet<usize> {
        let capacity = match block.capacity() {
            Ok(c) => c,
            Err(_) => return HashSet::new(),
        };
        let mut out = HashSet::new();
        for ord in 0..capacity {
            if let Ok(ip) = block.nth(ord) {
                if self.is_reserved(ip) {
                    out.insert(ord);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AllocationAttribute, AllocationBlock};

    #[test]
    fn is_reserved_matches_within_cidr() {
        let r = IpReservation::new([Cidr::parse("10.0.0.0/30").unwrap()]);
        assert!(r.is_reserved("10.0.0.1".parse().unwrap()));
        assert!(r.is_reserved("10.0.0.3".parse().unwrap()));
        assert!(!r.is_reserved("10.0.0.4".parse().unwrap()));
    }

    #[test]
    fn reserved_ordinals_feed_auto_assign_skip() {
        let block_cidr = Cidr::parse("10.0.0.0/26").unwrap();
        // Reserve the first two addresses of the block.
        let r = IpReservation::new([Cidr::parse("10.0.0.0/31").unwrap()]);
        let skip = r.reserved_ordinals(block_cidr);
        assert_eq!(skip, [0usize, 1].into_iter().collect());

        let mut block = AllocationBlock::new(block_cidr).unwrap();
        let attr = AllocationAttribute {
            handle_id: Some("h".into()),
            ..Default::default()
        };
        let ips = block.auto_assign(1, attr, &skip);
        // First allocatable address skips the two reserved ones.
        assert_eq!(ips, vec!["10.0.0.2".parse::<IpAddr>().unwrap()]);
    }
}
