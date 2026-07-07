//! [`IpamConfig`]: cluster IPAM configuration with the cross-field validation
//! rules that upstream enforces in `SetIPAMConfig` (not expressible in the CRD
//! schema alone).

use crate::IpamError;

/// Cluster-wide IPAM configuration (the singleton IPAMConfiguration resource).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpamConfig {
    /// When true, a node may only allocate from blocks affine to it (no
    /// borrowing from other nodes' blocks).
    pub strict_affinity: bool,
    /// When true, nodes may claim new blocks on demand.
    pub auto_allocate_blocks: bool,
    /// Cap on blocks a single host may claim (0 = unlimited). Caps *claims*, not
    /// allocations within already-owned blocks.
    pub max_blocks_per_host: u32,
    /// Minimum time a released address stays out of rotation (informational
    /// here; enforced by the allocation driver / FIFO reuse).
    pub ip_cooldown_seconds: u32,
}

impl Default for IpamConfig {
    fn default() -> Self {
        // Upstream defaults: strict affinity off, auto-allocation on.
        Self {
            strict_affinity: false,
            auto_allocate_blocks: true,
            max_blocks_per_host: 0,
            ip_cooldown_seconds: 0,
        }
    }
}

impl IpamConfig {
    /// Validate the cross-field invariants. Mirrors upstream `SetIPAMConfig`:
    /// - a config with neither strict affinity nor auto-allocation is unusable;
    /// - `max_blocks_per_host > 0` only makes sense with strict affinity.
    pub fn validate(&self) -> Result<(), IpamError> {
        if !self.strict_affinity && !self.auto_allocate_blocks {
            return Err(IpamError::InvalidConfig(
                "strict_affinity=false with auto_allocate_blocks=false leaves no way to allocate"
                    .into(),
            ));
        }
        if self.max_blocks_per_host > 0 && !self.strict_affinity {
            return Err(IpamError::InvalidConfig(
                "max_blocks_per_host requires strict_affinity=true".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        assert!(IpamConfig::default().validate().is_ok());
    }

    #[test]
    fn no_affinity_no_auto_is_rejected() {
        let c = IpamConfig {
            strict_affinity: false,
            auto_allocate_blocks: false,
            ..Default::default()
        };
        assert!(matches!(c.validate(), Err(IpamError::InvalidConfig(_))));
    }

    #[test]
    fn max_blocks_requires_strict_affinity() {
        let bad = IpamConfig {
            strict_affinity: false,
            auto_allocate_blocks: true,
            max_blocks_per_host: 4,
            ..Default::default()
        };
        assert!(matches!(bad.validate(), Err(IpamError::InvalidConfig(_))));

        let ok = IpamConfig {
            strict_affinity: true,
            max_blocks_per_host: 4,
            ..Default::default()
        };
        assert!(ok.validate().is_ok());
    }
}
