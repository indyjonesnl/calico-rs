//! Per-interface sysctls for the pod's veth, mirroring the subset upstream
//! Calico sets in its Linux dataplane (`configureSysctls` /
//! `configureContainerSysctls`).
//!
//! These builders are pure (the proc paths + values), so the exact set is
//! unit-tested; the actual `/proc/sys` writes live in [`crate::orchestrate`].
//!
//! Scope: IPv4 only (the plugin does not yet assign IPv6). The IPv6 sysctls
//! upstream sets (`disable_ipv6=0`, `accept_dad=0`, `proxy_ndp=1`,
//! `accept_ra=0`, `conf/all/forwarding`) are deferred until IPv6 CNI lands.

/// Extra host-side sysctls on the host veth, beyond `proxy_arp` (which the
/// orchestrator sets as a hard requirement for the point-to-point gateway).
/// Matches upstream `configureSysctls` for IPv4:
/// - `route_localnet=1` — allow routing of loopback-destined traffic used by
///   kube-proxy/host-networking service handling.
/// - `neigh/<veth>/proxy_delay=0` — answer proxy-ARP immediately.
/// - `forwarding=1` — forward packets arriving from the pod.
pub fn host_veth_extra_sysctls(host_veth: &str) -> Vec<(String, &'static str)> {
    vec![
        (
            format!("/proc/sys/net/ipv4/conf/{host_veth}/route_localnet"),
            "1",
        ),
        (
            format!("/proc/sys/net/ipv4/neigh/{host_veth}/proxy_delay"),
            "0",
        ),
        (
            format!("/proc/sys/net/ipv4/conf/{host_veth}/forwarding"),
            "1",
        ),
    ]
}

/// Container-side sysctls set inside the pod netns, mirroring upstream
/// `configureContainerSysctls` for IPv4. Pod IP forwarding is disabled — the
/// upstream default when `allowIPForwarding` is off (a pod is not a router).
pub fn container_sysctls() -> Vec<(&'static str, &'static str)> {
    vec![("/proc/sys/net/ipv4/ip_forward", "0")]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_veth_sysctls_target_the_named_interface() {
        let s = host_veth_extra_sysctls("cali123");
        let paths: Vec<&str> = s.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"/proc/sys/net/ipv4/conf/cali123/route_localnet"));
        assert!(paths.contains(&"/proc/sys/net/ipv4/neigh/cali123/proxy_delay"));
        assert!(paths.contains(&"/proc/sys/net/ipv4/conf/cali123/forwarding"));
        // route_localnet + forwarding are enabled; proxy_delay is zeroed.
        for (p, v) in &s {
            if p.ends_with("proxy_delay") {
                assert_eq!(*v, "0");
            } else {
                assert_eq!(*v, "1");
            }
        }
    }

    #[test]
    fn container_disables_pod_forwarding() {
        assert_eq!(
            container_sysctls(),
            vec![("/proc/sys/net/ipv4/ip_forward", "0")]
        );
    }
}
