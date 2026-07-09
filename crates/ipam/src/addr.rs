//! CIDR arithmetic for IPAM block ordinals — self-contained (std::net only) so
//! the IPAM core has no external dependency.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::IpamError;

/// Largest block the core will materialize as an ordinal list. Calico block
/// sizes are small (default /26 IPv4 = 64 addresses, /122 IPv6 = 64); this bound
/// guards against accidentally materializing an enormous block.
const MAX_HOST_BITS: u32 = 20; // up to ~1M addresses

/// A CIDR (network address + prefix length), normalized to its network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Construct a CIDR, masking `addr` down to its network address. Errors if
    /// the prefix length is invalid for the address family.
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, IpamError> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(IpamError::InvalidCidr(format!("{addr}/{prefix_len}")));
        }
        let network = mask_to_network(addr, prefix_len);
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Parse a CIDR from `"addr/prefix"`.
    pub fn parse(s: &str) -> Result<Self, IpamError> {
        let (a, p) = s
            .split_once('/')
            .ok_or_else(|| IpamError::InvalidCidr(s.to_string()))?;
        let addr: IpAddr = a
            .parse()
            .map_err(|_| IpamError::InvalidCidr(s.to_string()))?;
        let prefix_len: u8 = p
            .parse()
            .map_err(|_| IpamError::InvalidCidr(s.to_string()))?;
        Cidr::new(addr, prefix_len)
    }

    /// The network (base) address.
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Number of host bits.
    pub fn host_bits(&self) -> u32 {
        let total = match self.network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        total - self.prefix_len as u32
    }

    /// Total number of addresses in this block. Errors if the block is larger
    /// than [`MAX_HOST_BITS`] permits.
    pub fn capacity(&self) -> Result<usize, IpamError> {
        let hb = self.host_bits();
        if hb > MAX_HOST_BITS {
            return Err(IpamError::BlockTooLarge { host_bits: hb });
        }
        Ok(1usize << hb)
    }

    /// The `ordinal`-th address in the block (0-based).
    pub fn nth(&self, ordinal: usize) -> Result<IpAddr, IpamError> {
        let cap = self.capacity()?;
        if ordinal >= cap {
            return Err(IpamError::AddressNotInBlock(self.network));
        }
        Ok(match self.network {
            IpAddr::V4(v4) => {
                let base = u32::from(v4);
                IpAddr::V4(Ipv4Addr::from(base + ordinal as u32))
            }
            IpAddr::V6(v6) => {
                let base = u128::from(v6);
                IpAddr::V6(Ipv6Addr::from(base + ordinal as u128))
            }
        })
    }

    /// The ordinal of `ip` within this block, or `None` if `ip` is outside it.
    pub fn ordinal_of(&self, ip: IpAddr) -> Option<usize> {
        let cap = self.capacity().ok()?;
        let offset: u128 = match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                (u32::from(ip).checked_sub(u32::from(net))?) as u128
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => u128::from(ip).checked_sub(u128::from(net))?,
            _ => return None, // family mismatch
        };
        let ord = usize::try_from(offset).ok()?;
        (ord < cap).then_some(ord)
    }

    /// True if `other` is wholly contained within this CIDR: same address
    /// family, this prefix is no longer than `other`'s, and `other`'s network
    /// address masked down to this prefix equals this network address. A CIDR
    /// contains itself. Used for longest-prefix pool → block containment.
    pub fn contains(&self, other: &Cidr) -> bool {
        if self.prefix_len > other.prefix_len {
            return false;
        }
        match (self.network, other.network) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask_to_network(other.network, self.prefix_len) == self.network
            }
            _ => false, // family mismatch
        }
    }

    /// Enumerate the sub-blocks of prefix length `block_prefix` within this CIDR
    /// (e.g. the /26 blocks of a /16 pool). Errors if `block_prefix` is invalid
    /// for the family / smaller than this prefix, or if the pool would yield an
    /// impractically large number of blocks (capped at 2^16).
    pub fn sub_blocks(&self, block_prefix: u8) -> Result<Vec<Cidr>, IpamError> {
        let family_bits = match self.network {
            IpAddr::V4(_) => 32u32,
            IpAddr::V6(_) => 128,
        };
        let bp = block_prefix as u32;
        if bp < self.prefix_len as u32 || bp > family_bits {
            return Err(IpamError::InvalidCidr(format!(
                "{self} sub /{block_prefix}"
            )));
        }
        let count_bits = bp - self.prefix_len as u32;
        if count_bits > 16 {
            return Err(IpamError::BlockTooLarge {
                host_bits: count_bits,
            });
        }
        let num: u128 = 1 << count_bits;
        let span: u128 = 1 << (family_bits - bp);
        let base: u128 = match self.network {
            IpAddr::V4(v4) => u128::from(u32::from(v4)),
            IpAddr::V6(v6) => u128::from(v6),
        };
        let mut out = Vec::with_capacity(num as usize);
        for i in 0..num {
            let addr_int = base + i * span;
            let ip = match self.network {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(addr_int as u32)),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(addr_int)),
            };
            out.push(Cidr::new(ip, block_prefix)?);
        }
        Ok(out)
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

fn mask_to_network(addr: IpAddr, prefix_len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let masked = if prefix_len == 0 {
                0
            } else {
                bits & (u32::MAX << (32 - prefix_len as u32))
            };
            IpAddr::V4(Ipv4Addr::from(masked))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let masked = if prefix_len == 0 {
                0
            } else {
                bits & (u128::MAX << (128 - prefix_len as u32))
            };
            IpAddr::V6(Ipv6Addr::from(masked))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_capacity_and_nth() {
        let c = Cidr::parse("10.0.0.0/26").unwrap();
        assert_eq!(c.host_bits(), 6);
        assert_eq!(c.capacity().unwrap(), 64);
        assert_eq!(c.nth(0).unwrap(), "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(c.nth(5).unwrap(), "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(c.nth(63).unwrap(), "10.0.0.63".parse::<IpAddr>().unwrap());
        assert!(c.nth(64).is_err());
    }

    #[test]
    fn normalizes_to_network() {
        // A host address with a /26 prefix normalizes to the block base.
        let c = Cidr::new("10.0.0.37".parse().unwrap(), 26).unwrap();
        assert_eq!(c.network(), "10.0.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ordinal_roundtrip() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        for ord in [0usize, 1, 42, 255] {
            let ip = c.nth(ord).unwrap();
            assert_eq!(c.ordinal_of(ip), Some(ord));
        }
        assert_eq!(c.ordinal_of("192.168.2.1".parse().unwrap()), None);
    }

    #[test]
    fn v6_block() {
        let c = Cidr::parse("fd00::/122").unwrap();
        assert_eq!(c.capacity().unwrap(), 64);
        assert_eq!(c.nth(1).unwrap(), "fd00::1".parse::<IpAddr>().unwrap());
        assert_eq!(c.ordinal_of("fd00::a".parse().unwrap()), Some(10));
    }

    #[test]
    fn family_mismatch_is_none() {
        let c = Cidr::parse("10.0.0.0/24").unwrap();
        assert_eq!(c.ordinal_of("fd00::1".parse().unwrap()), None);
    }

    #[test]
    fn rejects_bad_prefix() {
        assert!(Cidr::new("10.0.0.0".parse().unwrap(), 33).is_err());
    }

    #[test]
    fn sub_blocks_enumerates_pool() {
        let pool = Cidr::parse("10.0.0.0/24").unwrap();
        let blocks = pool.sub_blocks(26).unwrap(); // /24 -> four /26
        assert_eq!(blocks.len(), 4);
        assert_eq!(blocks[0], Cidr::parse("10.0.0.0/26").unwrap());
        assert_eq!(blocks[1], Cidr::parse("10.0.0.64/26").unwrap());
        assert_eq!(blocks[3], Cidr::parse("10.0.0.192/26").unwrap());
    }

    #[test]
    fn contains_matches_pool_block_and_family() {
        let pool = Cidr::parse("192.168.0.0/16").unwrap();
        // A /26 block within the pool is contained; the pool contains itself.
        assert!(pool.contains(&Cidr::parse("192.168.5.0/26").unwrap()));
        assert!(pool.contains(&pool));
        // A block outside the pool is not contained.
        assert!(!pool.contains(&Cidr::parse("10.0.0.0/26").unwrap()));
        // A wider prefix cannot be contained by a narrower one.
        assert!(!Cidr::parse("192.168.5.0/26")
            .unwrap()
            .contains(&Cidr::parse("192.168.0.0/16").unwrap()));
        // Family mismatch is never contained.
        assert!(!pool.contains(&Cidr::parse("fd00::/122").unwrap()));
    }

    #[test]
    fn sub_blocks_rejects_smaller_prefix() {
        let pool = Cidr::parse("10.0.0.0/24").unwrap();
        assert!(pool.sub_blocks(16).is_err()); // /16 is bigger than the pool
    }
}
