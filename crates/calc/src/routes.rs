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

/// The kind of route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteType {
    /// A workload on this node — reached directly via its veth.
    LocalWorkload,
    /// A workload on another node — reached via that node's address.
    RemoteWorkload,
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

    /// Compute the routes for the given workloads, sorted deterministically and
    /// de-duplicated. Remote workloads whose node address is unknown are skipped
    /// (no next hop yet).
    pub fn resolve(&self, workloads: &[WorkloadInfo]) -> Vec<Route> {
        let mut routes = Vec::new();
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
        routes.sort_by(|a, b| a.dst.cmp(&b.dst));
        routes.dedup();
        routes
    }
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
}
