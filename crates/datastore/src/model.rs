//! Typed datastore keys and the key/value pair model.
//!
//! Upstream Calico funnels everything through a `KVPair` keyed by a typed `Key`
//! that knows its storage path (`libcalico-go/lib/backend/model`). This is the
//! Rust equivalent: a [`Key`] enum whose [`Key::path`] gives a stable string
//! encoding (used by the string-keyed [`crate::CasStore`]) and which parses back
//! from that path.

use crate::cas::Revision;

/// The kind of a v3 resource, for [`Key::Resource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    IpPool,
    IpReservation,
    WorkloadEndpoint,
    HostEndpoint,
    Node,
    NetworkPolicy,
    GlobalNetworkPolicy,
    Tier,
    NetworkSet,
    GlobalNetworkSet,
    Profile,
    ClusterInformation,
    FelixConfiguration,
    BgpConfiguration,
    BgpPeer,
    KubeControllersConfiguration,
    IpamBlock,
    BlockAffinity,
    IpamHandle,
    IpamConfiguration,
}

impl ResourceKind {
    /// Stable path segment for this kind.
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceKind::IpPool => "ippools",
            ResourceKind::IpReservation => "ipreservations",
            ResourceKind::WorkloadEndpoint => "workloadendpoints",
            ResourceKind::HostEndpoint => "hostendpoints",
            ResourceKind::Node => "nodes",
            ResourceKind::NetworkPolicy => "networkpolicies",
            ResourceKind::GlobalNetworkPolicy => "globalnetworkpolicies",
            ResourceKind::Tier => "tiers",
            ResourceKind::NetworkSet => "networksets",
            ResourceKind::GlobalNetworkSet => "globalnetworksets",
            ResourceKind::Profile => "profiles",
            ResourceKind::ClusterInformation => "clusterinformations",
            ResourceKind::FelixConfiguration => "felixconfigurations",
            ResourceKind::BgpConfiguration => "bgpconfigurations",
            ResourceKind::BgpPeer => "bgppeers",
            ResourceKind::KubeControllersConfiguration => "kubecontrollersconfigurations",
            ResourceKind::IpamBlock => "ipamblocks",
            ResourceKind::BlockAffinity => "blockaffinities",
            ResourceKind::IpamHandle => "ipamhandles",
            ResourceKind::IpamConfiguration => "ipamconfigurations",
        }
    }

    /// All kinds, for CLI enumeration / lookup.
    pub const ALL: [ResourceKind; 20] = [
        ResourceKind::IpPool,
        ResourceKind::IpReservation,
        ResourceKind::WorkloadEndpoint,
        ResourceKind::HostEndpoint,
        ResourceKind::Node,
        ResourceKind::NetworkPolicy,
        ResourceKind::GlobalNetworkPolicy,
        ResourceKind::Tier,
        ResourceKind::NetworkSet,
        ResourceKind::GlobalNetworkSet,
        ResourceKind::Profile,
        ResourceKind::ClusterInformation,
        ResourceKind::FelixConfiguration,
        ResourceKind::BgpConfiguration,
        ResourceKind::BgpPeer,
        ResourceKind::KubeControllersConfiguration,
        ResourceKind::IpamBlock,
        ResourceKind::BlockAffinity,
        ResourceKind::IpamHandle,
        ResourceKind::IpamConfiguration,
    ];

    /// Whether the resource is namespaced (vs cluster-scoped).
    pub fn is_namespaced(self) -> bool {
        matches!(
            self,
            ResourceKind::NetworkPolicy | ResourceKind::NetworkSet | ResourceKind::WorkloadEndpoint
        )
    }

    /// Resolve a kind from a CLI token: plural, singular, or (case-insensitive)
    /// kind name. e.g. `ippool`, `ippools`, `IPPool`.
    pub fn parse_cli(s: &str) -> Option<Self> {
        let l = s.to_lowercase();
        ResourceKind::ALL.into_iter().find(|k| {
            let plural = k.as_str();
            l == plural
                || l == plural.trim_end_matches('s')
                || l == plural.trim_end_matches("ies").to_string() + "y"
                || l == k.kind_name().to_lowercase()
        })
    }

    /// PascalCase Kubernetes `kind` for this resource.
    pub fn kind_name(self) -> &'static str {
        match self {
            ResourceKind::IpPool => "IPPool",
            ResourceKind::IpReservation => "IPReservation",
            ResourceKind::WorkloadEndpoint => "WorkloadEndpoint",
            ResourceKind::HostEndpoint => "HostEndpoint",
            ResourceKind::Node => "Node",
            ResourceKind::NetworkPolicy => "NetworkPolicy",
            ResourceKind::GlobalNetworkPolicy => "GlobalNetworkPolicy",
            ResourceKind::Tier => "Tier",
            ResourceKind::NetworkSet => "NetworkSet",
            ResourceKind::GlobalNetworkSet => "GlobalNetworkSet",
            ResourceKind::Profile => "Profile",
            ResourceKind::ClusterInformation => "ClusterInformation",
            ResourceKind::FelixConfiguration => "FelixConfiguration",
            ResourceKind::BgpConfiguration => "BGPConfiguration",
            ResourceKind::BgpPeer => "BGPPeer",
            ResourceKind::KubeControllersConfiguration => "KubeControllersConfiguration",
            ResourceKind::IpamBlock => "IPAMBlock",
            ResourceKind::BlockAffinity => "BlockAffinity",
            ResourceKind::IpamHandle => "IPAMHandle",
            ResourceKind::IpamConfiguration => "IPAMConfiguration",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "ippools" => ResourceKind::IpPool,
            "ipreservations" => ResourceKind::IpReservation,
            "workloadendpoints" => ResourceKind::WorkloadEndpoint,
            "hostendpoints" => ResourceKind::HostEndpoint,
            "nodes" => ResourceKind::Node,
            "networkpolicies" => ResourceKind::NetworkPolicy,
            "globalnetworkpolicies" => ResourceKind::GlobalNetworkPolicy,
            "tiers" => ResourceKind::Tier,
            "networksets" => ResourceKind::NetworkSet,
            "globalnetworksets" => ResourceKind::GlobalNetworkSet,
            "profiles" => ResourceKind::Profile,
            "clusterinformations" => ResourceKind::ClusterInformation,
            "felixconfigurations" => ResourceKind::FelixConfiguration,
            "bgpconfigurations" => ResourceKind::BgpConfiguration,
            "bgppeers" => ResourceKind::BgpPeer,
            "kubecontrollersconfigurations" => ResourceKind::KubeControllersConfiguration,
            "ipamblocks" => ResourceKind::IpamBlock,
            "blockaffinities" => ResourceKind::BlockAffinity,
            "ipamhandles" => ResourceKind::IpamHandle,
            "ipamconfigurations" => ResourceKind::IpamConfiguration,
            _ => return None,
        })
    }
}

/// A typed datastore key. Each variant maps to a stable path via [`Key::path`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Key {
    /// A v3 resource, namespaced (`namespace = Some`) or cluster-scoped.
    Resource {
        kind: ResourceKind,
        namespace: Option<String>,
        name: String,
    },
    /// An IPAM allocation block, keyed by CIDR.
    Block { cidr: String },
    /// A per-host block affinity, keyed by host + CIDR.
    BlockAffinity { host: String, cidr: String },
    /// An IPAM handle, keyed by handle id.
    IpamHandle { id: String },
}

/// Encode a CIDR into a path-safe token (`.`/`:`/`/` → `-`), mirroring upstream
/// CRD naming (`libcalico-go/lib/names/cidr.go`).
pub fn cidr_to_token(cidr: &str) -> String {
    cidr.replace(['.', ':', '/'], "-")
}

impl Key {
    /// The stable storage path for this key.
    pub fn path(&self) -> String {
        match self {
            Key::Resource {
                kind,
                namespace: Some(ns),
                name,
            } => format!("/{}/{}/{}", kind.as_str(), ns, name),
            Key::Resource {
                kind,
                namespace: None,
                name,
            } => format!("/{}/{}", kind.as_str(), name),
            Key::Block { cidr } => format!("/ipam/block/{}", cidr_to_token(cidr)),
            Key::BlockAffinity { host, cidr } => {
                format!("/ipam/affinity/{}/{}", host, cidr_to_token(cidr))
            }
            Key::IpamHandle { id } => format!("/ipam/handle/{}", id),
        }
    }

    /// Parse a resource key from its path. IPAM keys are not round-tripped here
    /// (their CIDR token is lossy); use the typed constructors for those.
    pub fn parse_resource(path: &str) -> Option<Key> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        match parts.as_slice() {
            [kind, name] => Some(Key::Resource {
                kind: ResourceKind::from_str(kind)?,
                namespace: None,
                name: (*name).to_string(),
            }),
            [kind, ns, name] => Some(Key::Resource {
                kind: ResourceKind::from_str(kind)?,
                namespace: Some((*ns).to_string()),
                name: (*name).to_string(),
            }),
            _ => None,
        }
    }
}

/// A key/value pair with an optional revision (present ⇒ enables CAS on update).
/// Generic over the value type — the typed layer above the string-keyed
/// [`crate::CasStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KVPair<V> {
    pub key: Key,
    pub value: V,
    pub revision: Option<Revision>,
}

impl<V> KVPair<V> {
    /// A pair with no revision (for create).
    pub fn new(key: Key, value: V) -> Self {
        Self {
            key,
            value,
            revision: None,
        }
    }

    /// A pair carrying a revision (for CAS update/delete).
    pub fn with_revision(key: Key, value: V, revision: Revision) -> Self {
        Self {
            key,
            value,
            revision: Some(revision),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_scoped_resource_path() {
        let k = Key::Resource {
            kind: ResourceKind::IpPool,
            namespace: None,
            name: "default-pool".into(),
        };
        assert_eq!(k.path(), "/ippools/default-pool");
    }

    #[test]
    fn namespaced_resource_path() {
        let k = Key::Resource {
            kind: ResourceKind::NetworkPolicy,
            namespace: Some("prod".into()),
            name: "deny-all".into(),
        };
        assert_eq!(k.path(), "/networkpolicies/prod/deny-all");
    }

    #[test]
    fn resource_path_roundtrips() {
        for k in [
            Key::Resource {
                kind: ResourceKind::IpPool,
                namespace: None,
                name: "p".into(),
            },
            Key::Resource {
                kind: ResourceKind::WorkloadEndpoint,
                namespace: Some("ns".into()),
                name: "wep".into(),
            },
        ] {
            assert_eq!(Key::parse_resource(&k.path()), Some(k));
        }
    }

    #[test]
    fn unknown_kind_does_not_parse() {
        assert_eq!(Key::parse_resource("/widgets/foo"), None);
    }

    #[test]
    fn parse_cli_accepts_plural_singular_kind() {
        assert_eq!(
            ResourceKind::parse_cli("ippools"),
            Some(ResourceKind::IpPool)
        );
        assert_eq!(
            ResourceKind::parse_cli("ippool"),
            Some(ResourceKind::IpPool)
        );
        assert_eq!(
            ResourceKind::parse_cli("IPPool"),
            Some(ResourceKind::IpPool)
        );
        assert_eq!(
            ResourceKind::parse_cli("networkpolicy"),
            Some(ResourceKind::NetworkPolicy)
        );
        assert_eq!(
            ResourceKind::parse_cli("blockaffinities"),
            Some(ResourceKind::BlockAffinity)
        );
        assert_eq!(ResourceKind::parse_cli("nope"), None);
        assert!(ResourceKind::NetworkPolicy.is_namespaced());
        assert!(!ResourceKind::IpPool.is_namespaced());
    }

    #[test]
    fn ipam_key_paths_are_token_safe() {
        assert_eq!(
            Key::Block {
                cidr: "10.0.0.0/26".into()
            }
            .path(),
            "/ipam/block/10-0-0-0-26"
        );
        assert_eq!(
            Key::BlockAffinity {
                host: "node-1".into(),
                cidr: "fd00::/122".into()
            }
            .path(),
            "/ipam/affinity/node-1/fd00---122"
        );
        assert_eq!(
            Key::IpamHandle {
                id: "net.abc".into()
            }
            .path(),
            "/ipam/handle/net.abc"
        );
    }

    #[test]
    fn kvpair_revision_semantics() {
        let create = KVPair::new(Key::IpamHandle { id: "h".into() }, 42u32);
        assert_eq!(create.revision, None);
        let upd = KVPair::with_revision(Key::IpamHandle { id: "h".into() }, 43u32, 7);
        assert_eq!(upd.revision, Some(7));
    }
}
