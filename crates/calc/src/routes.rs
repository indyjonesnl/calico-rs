//! L3 route computation (the calc-graph `L3RouteResolver` core).
//!
//! Given the workload endpoints and node addresses, compute the routes each node
//! must program: a local route (via the pod's veth) for workloads on this node,
//! and a route via the owning node's address for workloads elsewhere. This is
//! the pure derivation; programming the routes (netlink) and encapsulation
//! (VXLAN/IPIP next-hop rewriting) live in the dataplane. Central to cross-node
//! pod connectivity (spec US1 / SC-001).

use std::collections::BTreeMap;
use std::net::IpAddr;

/// The kind of route. Aligned with `proto::RouteType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteType {
    /// A workload on this node — reached directly via its veth (per-/32) or an
    /// aggregated local IPAM block.
    LocalWorkload,
    /// A workload on another node — reached via that node's address (per-/32 or
    /// aggregated at IPAM-block granularity).
    RemoteWorkload,
    /// This node's own address.
    LocalHost,
    /// Another node's own address — reached via that node.
    RemoteHost,
}

/// A computed route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Destination CIDR (a `/32` or `/128` for a single pod address).
    pub dst: String,
    pub route_type: RouteType,
    /// Next-hop (owning node's address) for remote routes.
    pub gateway: Option<IpAddr>,
    /// Outgoing interface for local routes.
    pub iface: Option<String>,
    /// Owning node (for remote routes).
    pub node: Option<String>,
}

/// A workload endpoint's routing-relevant facts.
#[derive(Debug, Clone)]
pub struct WorkloadInfo {
    pub node: String,
    /// Pod addresses (bare IP or CIDR).
    pub ipnets: Vec<String>,
    /// Host-side interface name (used for local routes).
    pub iface: String,
}

/// An allocatable IP pool. Carried for parity with upstream's calc inputs and
/// to fix the resolver's signature for T045, which will attach pool-derived
/// encapsulation / NAT-outgoing / cross-subnet metadata to routes. Pools do not
/// contribute a standalone forwarding route in this (encap-agnostic) increment.
#[derive(Debug, Clone)]
pub struct PoolInfo {
    /// Pool CIDR.
    pub cidr: String,
}

/// An IPAM block's affinity: which node owns which block CIDR. Remote blocks
/// yield one aggregated route per CIDR (the scale win over per-/32); the local
/// node's block yields a `LocalWorkload` aggregate.
#[derive(Debug, Clone)]
pub struct BlockInfo {
    /// Block CIDR (e.g. `10.0.1.0/26`).
    pub cidr: String,
    /// Node that owns (has affinity for) this block.
    pub node: String,
}

/// Resolves routes for one node given the cluster's node addresses.
pub struct RouteResolver {
    local_node: String,
    node_ips: BTreeMap<String, IpAddr>,
}

impl RouteResolver {
    pub fn new(local_node: impl Into<String>, node_ips: BTreeMap<String, IpAddr>) -> Self {
        Self {
            local_node: local_node.into(),
            node_ips,
        }
    }

    /// Compute the per-workload routes, sorted deterministically and
    /// de-duplicated. Remote workloads whose node address is unknown are skipped
    /// (no next hop yet).
    pub fn resolve(&self, workloads: &[WorkloadInfo]) -> Vec<Route> {
        let mut routes = Vec::new();
        self.push_workload_routes(workloads, &mut routes);
        finalize(routes)
    }

    /// Compute the full route set for this node: per-workload routes, host-IP
    /// routes for every known node address, and aggregated IPAM-block routes.
    /// Sorted deterministically and de-duplicated.
    ///
    /// Precedence: the specific per-`/32` local workload routes AND the wider
    /// block aggregates are both emitted (deduped). They carry distinct CIDRs,
    /// so nothing is dropped here; the dataplane RIB/LPM picks the
    /// longest-prefix match at forwarding time.
    ///
    /// `pools` is accepted for input parity with upstream (see [`PoolInfo`]) but
    /// does not contribute a route in this encap-agnostic increment.
    pub fn resolve_all(
        &self,
        workloads: &[WorkloadInfo],
        blocks: &[BlockInfo],
        _pools: &[PoolInfo],
    ) -> Vec<Route> {
        let mut routes = Vec::new();
        self.push_workload_routes(workloads, &mut routes);
        self.push_host_routes(&mut routes);
        self.push_block_routes(blocks, &mut routes);
        finalize(routes)
    }

    /// Per-`/32`/`/128` workload routes: local via veth, remote via owning node.
    fn push_workload_routes(&self, workloads: &[WorkloadInfo], routes: &mut Vec<Route>) {
        for w in workloads {
            let local = w.node == self.local_node;
            for ip in &w.ipnets {
                let dst = normalize_cidr(ip);
                if local {
                    routes.push(Route {
                        dst,
                        route_type: RouteType::LocalWorkload,
                        gateway: None,
                        iface: Some(w.iface.clone()),
                        node: None,
                    });
                } else if let Some(gw) = self.node_ips.get(&w.node) {
                    routes.push(Route {
                        dst,
                        route_type: RouteType::RemoteWorkload,
                        gateway: Some(*gw),
                        iface: None,
                        node: Some(w.node.clone()),
                    });
                }
                // else: remote node address unknown → no route yet.
            }
        }
    }

    /// Host-IP routes so node addresses are routable: `LocalHost` for this
    /// node's own address (upstream emits `LOCAL_HOST`), `RemoteHost` for every
    /// other node's address, reached via that node.
    fn push_host_routes(&self, routes: &mut Vec<Route>) {
        for (node, ip) in &self.node_ips {
            let dst = normalize_cidr(&ip.to_string());
            if *node == self.local_node {
                routes.push(Route {
                    dst,
                    route_type: RouteType::LocalHost,
                    gateway: None,
                    iface: None,
                    node: Some(node.clone()),
                });
            } else {
                routes.push(Route {
                    dst,
                    route_type: RouteType::RemoteHost,
                    gateway: Some(*ip),
                    iface: None,
                    node: Some(node.clone()),
                });
            }
        }
    }

    /// Aggregated IPAM-block routes: the local node's block yields a
    /// `LocalWorkload` aggregate; a remote block yields one `RemoteWorkload`
    /// route via the owning node. Remote blocks whose node address is unknown
    /// are skipped, mirroring the per-workload rule. No blackhole is emitted:
    /// upstream's calc L3RouteResolver emits none — the local-block blackhole is
    /// a dataplane concern (route_mgr.go), deferred to T045.
    fn push_block_routes(&self, blocks: &[BlockInfo], routes: &mut Vec<Route>) {
        for b in blocks {
            let dst = normalize_cidr(&b.cidr);
            if b.node == self.local_node {
                routes.push(Route {
                    dst,
                    route_type: RouteType::LocalWorkload,
                    gateway: None,
                    iface: None,
                    node: Some(b.node.clone()),
                });
            } else if let Some(gw) = self.node_ips.get(&b.node) {
                routes.push(Route {
                    dst,
                    route_type: RouteType::RemoteWorkload,
                    gateway: Some(*gw),
                    iface: None,
                    node: Some(b.node.clone()),
                });
            }
            // else: remote block's node address unknown → no route yet.
        }
    }
}

/// Total, deterministic ordering + de-duplication of a route set. Primary key
/// is `dst` (lexical, preserving the existing v4-before-v6 string order); ties
/// break on the remaining fields so routes sharing a CIDR order stably.
fn finalize(mut routes: Vec<Route>) -> Vec<Route> {
    routes.sort_by(|a, b| {
        a.dst
            .cmp(&b.dst)
            .then(a.route_type.cmp(&b.route_type))
            .then(a.node.cmp(&b.node))
            .then(a.gateway.cmp(&b.gateway))
            .then(a.iface.cmp(&b.iface))
    });
    routes.dedup();
    routes
}

/// Normalize a pod address to a host CIDR: a bare IP gets `/32` (v4) or `/128`
/// (v6); an existing CIDR is returned unchanged.
fn normalize_cidr(ip: &str) -> String {
    if ip.contains('/') {
        return ip.to_string();
    }
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => format!("{ip}/32"),
        Ok(IpAddr::V6(_)) => format!("{ip}/128"),
        Err(_) => ip.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_ips(pairs: &[(&str, &str)]) -> BTreeMap<String, IpAddr> {
        pairs
            .iter()
            .map(|(n, ip)| (n.to_string(), ip.parse().unwrap()))
            .collect()
    }

    fn wep(node: &str, ip: &str, iface: &str) -> WorkloadInfo {
        WorkloadInfo {
            node: node.to_string(),
            ipnets: vec![ip.to_string()],
            iface: iface.to_string(),
        }
    }

    #[test]
    fn local_workload_route_via_veth() {
        let r = RouteResolver::new("node-1", node_ips(&[]));
        let routes = r.resolve(&[wep("node-1", "10.0.0.5", "cali123")]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].dst, "10.0.0.5/32");
        assert_eq!(routes[0].route_type, RouteType::LocalWorkload);
        assert_eq!(routes[0].iface.as_deref(), Some("cali123"));
        assert_eq!(routes[0].gateway, None);
    }

    #[test]
    fn remote_workload_route_via_node_ip() {
        let r = RouteResolver::new("node-1", node_ips(&[("node-2", "192.168.0.2")]));
        let routes = r.resolve(&[wep("node-2", "10.0.1.7", "caliX")]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].route_type, RouteType::RemoteWorkload);
        assert_eq!(routes[0].dst, "10.0.1.7/32");
        assert_eq!(routes[0].gateway, Some("192.168.0.2".parse().unwrap()));
        assert_eq!(routes[0].node.as_deref(), Some("node-2"));
    }

    #[test]
    fn remote_workload_with_unknown_node_is_skipped() {
        let r = RouteResolver::new("node-1", node_ips(&[]));
        let routes = r.resolve(&[wep("node-3", "10.0.2.9", "caliY")]);
        assert!(routes.is_empty(), "no next hop known → no route");
    }

    #[test]
    fn ipv6_gets_128_prefix_and_results_are_sorted() {
        let r = RouteResolver::new("n1", node_ips(&[("n2", "fd00::2")]));
        let routes = r.resolve(&[
            wep("n1", "10.0.0.9", "caliA"),
            wep("n2", "fd00::a", "caliB"),
            wep("n1", "10.0.0.1", "caliC"),
        ]);
        let dsts: Vec<_> = routes.iter().map(|r| r.dst.as_str()).collect();
        // Sorted lexically by dst; the v6 workload gets /128.
        assert_eq!(dsts, vec!["10.0.0.1/32", "10.0.0.9/32", "fd00::a/128"]);
    }

    #[test]
    fn preserves_existing_cidr() {
        let r = RouteResolver::new("n1", node_ips(&[]));
        let routes = r.resolve(&[WorkloadInfo {
            node: "n1".into(),
            ipnets: vec!["10.0.0.0/26".into()],
            iface: "cali".into(),
        }]);
        assert_eq!(routes[0].dst, "10.0.0.0/26");
    }

    fn block(cidr: &str, node: &str) -> BlockInfo {
        BlockInfo {
            cidr: cidr.to_string(),
            node: node.to_string(),
        }
    }

    // --- host-IP routes -----------------------------------------------------

    #[test]
    fn two_nodes_each_get_a_remote_host_route_to_the_other() {
        // node-1 is local; both node addresses are known.
        let r = RouteResolver::new(
            "node-1",
            node_ips(&[("node-1", "192.168.0.1"), ("node-2", "192.168.0.2")]),
        );
        let routes = r.resolve_all(&[], &[], &[]);

        // Remote host route to node-2's address, via node-2.
        let remote = routes
            .iter()
            .find(|r| r.dst == "192.168.0.2/32")
            .expect("remote host route present");
        assert_eq!(remote.route_type, RouteType::RemoteHost);
        assert_eq!(remote.gateway, Some("192.168.0.2".parse().unwrap()));
        assert_eq!(remote.node.as_deref(), Some("node-2"));

        // Local host route to node-1's own address (upstream emits LOCAL_HOST).
        let local = routes
            .iter()
            .find(|r| r.dst == "192.168.0.1/32")
            .expect("local host route present");
        assert_eq!(local.route_type, RouteType::LocalHost);
        assert_eq!(local.gateway, None);
        assert_eq!(local.node.as_deref(), Some("node-1"));
    }

    // --- block aggregation --------------------------------------------------

    #[test]
    fn remote_block_becomes_one_aggregated_route_via_owning_node() {
        let r = RouteResolver::new("node-1", node_ips(&[("node-2", "192.168.0.2")]));
        let routes = r.resolve_all(&[], &[block("10.0.1.0/26", "node-2")], &[]);

        let agg: Vec<_> = routes.iter().filter(|r| r.dst == "10.0.1.0/26").collect();
        assert_eq!(agg.len(), 1, "one aggregated route, not per-/32");
        assert_eq!(agg[0].route_type, RouteType::RemoteWorkload);
        assert_eq!(agg[0].gateway, Some("192.168.0.2".parse().unwrap()));
        assert_eq!(agg[0].node.as_deref(), Some("node-2"));
    }

    #[test]
    fn remote_block_with_unknown_node_is_skipped() {
        let r = RouteResolver::new("node-1", node_ips(&[]));
        let routes = r.resolve_all(&[], &[block("10.0.9.0/26", "node-9")], &[]);
        assert!(routes.is_empty(), "no next hop known → no block route");
    }

    #[test]
    fn local_block_aggregate_is_local_workload_no_blackhole() {
        // Upstream calc emits the local block-via-host route as LOCAL_WORKLOAD;
        // the blackhole for local blocks is a dataplane concern, not calc's.
        let r = RouteResolver::new("node-1", node_ips(&[("node-1", "192.168.0.1")]));
        let routes = r.resolve_all(&[], &[block("10.0.0.0/26", "node-1")], &[]);

        let agg = routes
            .iter()
            .find(|r| r.dst == "10.0.0.0/26")
            .expect("local block aggregate present");
        assert_eq!(agg.route_type, RouteType::LocalWorkload);
        assert_eq!(agg.gateway, None);
        assert_eq!(agg.node.as_deref(), Some("node-1"));
        // No blackhole/unreachable variant is emitted by calc.
    }

    // --- precedence: per-/32 local AND aggregate both emitted ---------------

    #[test]
    fn local_workload_slash32_and_block_aggregate_coexist() {
        let r = RouteResolver::new("node-1", node_ips(&[]));
        let routes = r.resolve_all(
            &[wep("node-1", "10.0.0.5", "cali123")],
            &[block("10.0.0.0/26", "node-1")],
            &[],
        );

        let veth = routes
            .iter()
            .find(|r| r.dst == "10.0.0.5/32")
            .expect("specific /32 local route present");
        assert_eq!(veth.route_type, RouteType::LocalWorkload);
        assert_eq!(veth.iface.as_deref(), Some("cali123"));

        let agg = routes
            .iter()
            .find(|r| r.dst == "10.0.0.0/26")
            .expect("block aggregate present");
        assert_eq!(agg.route_type, RouteType::LocalWorkload);
        // Both are emitted; the dataplane RIB/LPM picks longest-prefix.
    }

    // --- pools do not (yet) contribute a route ------------------------------

    #[test]
    fn pools_do_not_change_the_route_set() {
        // Pool metadata (encap type / NAT-outgoing / cross-subnet) and the
        // local-block blackhole are T045/dataplane concerns, so pools emit no
        // forwarding route in this calc increment.
        let r = RouteResolver::new("node-1", node_ips(&[("node-2", "192.168.0.2")]));
        let without = r.resolve_all(&[], &[block("10.0.1.0/26", "node-2")], &[]);
        let with = r.resolve_all(
            &[],
            &[block("10.0.1.0/26", "node-2")],
            &[PoolInfo {
                cidr: "10.0.0.0/16".into(),
            }],
        );
        assert_eq!(without, with);
    }

    // --- determinism across the expanded set --------------------------------

    #[test]
    fn resolve_all_is_sorted_and_deterministic() {
        let r = RouteResolver::new(
            "node-1",
            node_ips(&[("node-1", "192.168.0.1"), ("node-2", "192.168.0.2")]),
        );
        let workloads = [
            wep("node-1", "10.0.0.5", "cali1"),
            wep("node-2", "10.0.1.7", "cali2"),
        ];
        let blocks = [
            block("10.0.1.0/26", "node-2"),
            block("10.0.0.0/26", "node-1"),
        ];
        let a = r.resolve_all(&workloads, &blocks, &[]);
        let b = r.resolve_all(&workloads, &blocks, &[]);
        assert_eq!(a, b, "output is deterministic");

        let dsts: Vec<_> = a.iter().map(|r| r.dst.as_str()).collect();
        let mut sorted = dsts.clone();
        sorted.sort();
        assert_eq!(dsts, sorted, "routes are sorted by dst");
    }
}
