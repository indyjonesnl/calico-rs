//! The felix [`RouteManager`]: programs the kernel L3 routing table (`main`
//! table) from calc-graph [`RouteUpdate`]/[`RouteRemove`] messages, applying only
//! the *delta* between desired and last-programmed state.
//!
//! Modelled on upstream `felix/dataplane/linux/route_table.go` (`RouteTable`). The
//! desired routes live in a [`reconcile::DeltaTracker`] keyed by destination CIDR;
//! [`Manager::complete_deferred_work`] computes the pending updates/deletions and
//! programs *only those* via `rtnetlink`, then records what it programmed so the
//! next round's diff is minimal. Re-running with no change programs nothing.
//!
//! ## Netlink scope (what is programmed)
//!
//! The netlink layer is factored behind [`RouteProgrammer`] so the delta logic is
//! unit-testable without a kernel. The real [`NetlinkProgrammer`] programs, for
//! both IPv4 and IPv6:
//!
//! - **Routes with a `gateway`** (the cross-node backbone — `RemoteWorkload` /
//!   `RemoteHost` reached via the owning node's IP): `dst via gateway` in the main
//!   table. The kernel resolves the gateway through existing connected/host
//!   routes.
//! - **Gateway-less routes** (e.g. a `LocalWorkload`): the current [`proto`]
//!   [`RouteUpdate`] carries no outgoing interface, and a device route needs an
//!   `oif`, so these are tracked in the delta but not pushed to the kernel (a
//!   warning is logged once per apply). Local pod reachability is already
//!   programmed by the CNI plugin's per-veth `/32` route (see
//!   `cni::dataplane::add_dev_route`). Programming them here is deferred until the
//!   proto carries the interface — see the module TODO.
//!
//! `on_update` only mutates in-memory desired state (cheap, no I/O); all kernel
//! work happens in the async `complete_deferred_work`.

use std::net::IpAddr;

use proto::{RouteType, RouteUpdate, ToDataplane};
use reconcile::DeltaTracker;

use crate::dataplane::{DataplaneError, Manager};

/// The desired attributes of one route, keyed in the [`DeltaTracker`] by its
/// destination CIDR (the [`RouteUpdate::dst`] / [`ToDataplane::RouteRemove`]
/// string). A value change (e.g. a different gateway) is detected by `PartialEq`
/// and reprogrammed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteValue {
    /// Semantic route kind (local vs. remote workload/host).
    pub route_type: RouteType,
    /// Next-hop / owning-node IP for remote routes (`None` ⇒ connected/local).
    pub gateway: Option<String>,
    /// Node that owns the destination (informational; not programmed).
    pub dst_node_name: Option<String>,
}

impl RouteValue {
    fn from_update(u: &RouteUpdate) -> Self {
        Self {
            route_type: u.route_type,
            gateway: u.gateway.clone(),
            dst_node_name: u.dst_node_name.clone(),
        }
    }
}

/// The netlink side of route programming, factored out so [`RouteManager`]'s delta
/// logic can be unit-tested with a spy. `dst`/`prefix` are the parsed destination
/// CIDR; the real implementation is [`NetlinkProgrammer`].
#[async_trait::async_trait(?Send)]
pub trait RouteProgrammer {
    /// Add or replace the route to `dst/prefix` described by `value`.
    async fn add_route(&self, dst: IpAddr, prefix: u8, value: &RouteValue) -> Result<(), String>;

    /// Delete the route to `dst/prefix` from the main table.
    async fn del_route(&self, dst: IpAddr, prefix: u8) -> Result<(), String>;
}

/// Parse a `"addr/prefix"` CIDR string into its address and prefix length,
/// defaulting the prefix to the full host length when absent.
fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), String> {
    let (addr_part, prefix_part) = match cidr.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (cidr, None),
    };
    let addr: IpAddr = addr_part
        .parse()
        .map_err(|_| format!("invalid route destination address: {cidr:?}"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_part {
        Some(p) => p
            .parse::<u8>()
            .map_err(|_| format!("invalid route prefix length: {cidr:?}"))?,
        None => max,
    };
    if prefix > max {
        return Err(format!("route prefix length out of range: {cidr:?}"));
    }
    Ok((addr, prefix))
}

/// Reconciles the kernel `main` routing table to the calc graph's desired routes,
/// applying only the delta. Generic over the [`RouteProgrammer`] so tests can
/// inject a spy; production uses [`RouteManager::with_netlink`].
pub struct RouteManager<P: RouteProgrammer> {
    /// Desired vs. last-programmed routes, keyed by destination CIDR string.
    routes: DeltaTracker<String, RouteValue>,
    programmer: P,
}

impl<P: RouteProgrammer> RouteManager<P> {
    /// Build a route manager over an explicit programmer (used in tests).
    pub fn new(programmer: P) -> Self {
        Self {
            routes: DeltaTracker::new(),
            programmer,
        }
    }

    /// Number of desired routes currently tracked (test/introspection helper).
    pub fn desired_len(&self) -> usize {
        self.routes.desired_len()
    }

    /// Count of routes whose kernel state still differs from desired (pending
    /// adds/updates + pending deletions) — zero once fully reconciled.
    pub fn pending_count(&self) -> usize {
        self.routes.pending_update_count() + self.routes.pending_deletion_count()
    }
}

impl RouteManager<NetlinkProgrammer> {
    /// Build a production route manager that programs the kernel via `rtnetlink`.
    /// The caller supplies a `Handle` obtained from `rtnetlink::new_connection()`
    /// with the connection task already spawned.
    pub fn with_netlink(handle: rtnetlink::Handle) -> Self {
        Self::new(NetlinkProgrammer::new(handle))
    }
}

#[async_trait::async_trait(?Send)]
impl<P: RouteProgrammer> Manager for RouteManager<P> {
    fn on_update(&mut self, msg: &ToDataplane) {
        match msg {
            ToDataplane::RouteUpdate(u) => {
                self.routes
                    .set_desired(u.dst.clone(), RouteValue::from_update(u));
            }
            ToDataplane::RouteRemove(dst) => {
                self.routes.remove_desired(dst);
            }
            _ => {}
        }
    }

    async fn complete_deferred_work(&mut self) -> Result<(), DataplaneError> {
        // Snapshot the pending delta into owned data so we can mutate the tracker
        // (confirm_programmed) while iterating. Only these keys touch the kernel;
        // in-sync routes are skipped entirely — the whole point of the delta.
        let updates: Vec<(String, RouteValue)> = self
            .routes
            .iter_pending_updates()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let deletions: Vec<String> = self.routes.iter_pending_deletions().cloned().collect();

        // Program each pending add/update, confirming per-item so a mid-batch
        // failure retries only the not-yet-programmed remainder (state is never
        // lost — the framework re-runs us).
        for (dst, value) in &updates {
            let (addr, prefix) = match parse_cidr(dst) {
                Ok(v) => v,
                Err(e) => {
                    // Malformed CIDR would otherwise pin the delta dirty forever.
                    // Log and drop it from pending rather than spin.
                    tracing::warn!(route = %dst, error = %e, "dropping malformed route update");
                    self.routes.confirm_programmed(dst);
                    continue;
                }
            };
            self.programmer
                .add_route(addr, prefix, value)
                .await
                .map_err(DataplaneError::new)?;
            self.routes.confirm_programmed(dst);
        }

        for dst in &deletions {
            let (addr, prefix) = match parse_cidr(dst) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(route = %dst, error = %e, "dropping malformed route deletion");
                    self.routes.confirm_programmed(dst);
                    continue;
                }
            };
            self.programmer
                .del_route(addr, prefix)
                .await
                .map_err(DataplaneError::new)?;
            self.routes.confirm_programmed(dst);
        }

        Ok(())
    }
}

/// `rtnetlink`-backed [`RouteProgrammer`] that programs the host's `main` routing
/// table. Holds a cloneable `rtnetlink::Handle`; construct via
/// [`NetlinkProgrammer::new`] after spawning the connection task (see
/// `rtnetlink::new_connection`).
#[derive(Clone)]
pub struct NetlinkProgrammer {
    handle: rtnetlink::Handle,
}

impl NetlinkProgrammer {
    /// Wrap an existing `rtnetlink` handle.
    pub fn new(handle: rtnetlink::Handle) -> Self {
        Self { handle }
    }
}

#[async_trait::async_trait(?Send)]
impl RouteProgrammer for NetlinkProgrammer {
    async fn add_route(&self, dst: IpAddr, prefix: u8, value: &RouteValue) -> Result<(), String> {
        // The family-agnostic `RouteMessageBuilder<IpAddr>` sets the address family
        // from the destination and validates prefix/gateway families for us.
        let mut builder = rtnetlink::RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(dst, prefix)
            .map_err(|e| e.to_string())?;

        match &value.gateway {
            Some(gw) => {
                let gw: IpAddr = gw
                    .parse()
                    .map_err(|_| format!("invalid route gateway address: {gw:?}"))?;
                builder = builder.gateway(gw).map_err(|e| e.to_string())?;
            }
            None => {
                // Gateway-less route (e.g. LocalWorkload). The proto carries no
                // outgoing interface, so we cannot build a device route here; the
                // CNI plugin already programs the per-veth /32. Track it in the
                // delta but issue no kernel op. TODO: program a device route once
                // RouteUpdate carries the interface.
                tracing::warn!(
                    destination = %format!("{dst}/{prefix}"),
                    route_type = ?value.route_type,
                    "skipping gateway-less route (no interface in proto); not programmed"
                );
                return Ok(());
            }
        }

        // `.replace()` sets NLM_F_REPLACE|NLM_F_CREATE — an *upsert*: create the
        // route if absent, replace it (e.g. a changed gateway) if present. Plain
        // `add` uses NLM_F_EXCL and would fail EEXIST on a value change, silently
        // leaving the stale route in place. This is the "add/replace" the delta's
        // pending-update semantics require.
        self.handle
            .route()
            .add(builder.build())
            .replace()
            .execute()
            .await
            .map_err(|e| e.to_string())
    }

    async fn del_route(&self, dst: IpAddr, prefix: u8) -> Result<(), String> {
        let msg = rtnetlink::RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(dst, prefix)
            .map_err(|e| e.to_string())?
            .build();
        // Deleting an already-absent route (ESRCH / "No such process") is benign
        // during resync — treat as success so we don't spin on a phantom delta.
        match self.handle.route().del(msg).execute().await {
            Ok(()) => Ok(()),
            Err(e) if e.to_string().contains("No such process") => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use proto::{IpSetKind, IpSetUpdate, RouteUpdate};

    /// A spy programmer recording every add/del so tests can assert exactly which
    /// netlink operations the delta produced. Cloneable (shared inner) so the test
    /// keeps a handle after moving one into the manager. A `fail` toggle drives the
    /// retry test.
    #[derive(Clone, Default)]
    struct SpyProgrammer {
        inner: Rc<SpyInner>,
    }

    #[derive(Default)]
    struct SpyInner {
        adds: RefCell<Vec<(String, RouteValue)>>,
        dels: RefCell<Vec<String>>,
        fail: RefCell<bool>,
    }

    impl SpyProgrammer {
        fn cidr(dst: IpAddr, prefix: u8) -> String {
            format!("{dst}/{prefix}")
        }
        fn adds(&self) -> Vec<String> {
            self.inner
                .adds
                .borrow()
                .iter()
                .map(|(c, _)| c.clone())
                .collect()
        }
        fn dels(&self) -> Vec<String> {
            self.inner.dels.borrow().clone()
        }
        fn clear(&self) {
            self.inner.adds.borrow_mut().clear();
            self.inner.dels.borrow_mut().clear();
        }
        fn set_fail(&self, v: bool) {
            *self.inner.fail.borrow_mut() = v;
        }
    }

    #[async_trait::async_trait(?Send)]
    impl RouteProgrammer for SpyProgrammer {
        async fn add_route(
            &self,
            dst: IpAddr,
            prefix: u8,
            value: &RouteValue,
        ) -> Result<(), String> {
            if *self.inner.fail.borrow() {
                return Err("spy: injected failure".into());
            }
            self.inner
                .adds
                .borrow_mut()
                .push((Self::cidr(dst, prefix), value.clone()));
            Ok(())
        }
        async fn del_route(&self, dst: IpAddr, prefix: u8) -> Result<(), String> {
            if *self.inner.fail.borrow() {
                return Err("spy: injected failure".into());
            }
            self.inner.dels.borrow_mut().push(Self::cidr(dst, prefix));
            Ok(())
        }
    }

    fn remote_route(dst: &str, gw: &str) -> ToDataplane {
        ToDataplane::RouteUpdate(RouteUpdate {
            route_type: RouteType::RemoteWorkload,
            dst: dst.into(),
            dst_node_name: Some("node-b".into()),
            gateway: Some(gw.into()),
        })
    }

    #[tokio::test]
    async fn new_route_is_pending_then_programmed_once() {
        let spy = SpyProgrammer::default();
        let mut mgr = RouteManager::new(spy.clone());

        mgr.on_update(&remote_route("192.168.9.0/24", "10.0.0.2"));
        assert_eq!(mgr.pending_count(), 1, "one route awaits programming");
        assert!(spy.adds().is_empty(), "on_update must not touch the kernel");

        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.adds(), vec!["192.168.9.0/24".to_string()]);
        assert!(spy.dels().is_empty());
        assert_eq!(mgr.pending_count(), 0, "fully reconciled after apply");
    }

    #[tokio::test]
    async fn apply_twice_second_delta_is_empty() {
        let spy = SpyProgrammer::default();
        let mut mgr = RouteManager::new(spy.clone());

        mgr.on_update(&remote_route("192.168.9.0/24", "10.0.0.2"));
        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.adds().len(), 1);

        // Re-apply with no desired change: the delta is empty, so NO netlink ops.
        spy.clear();
        mgr.complete_deferred_work().await.unwrap();
        assert!(
            spy.adds().is_empty() && spy.dels().is_empty(),
            "idempotent re-apply must program nothing"
        );
    }

    #[tokio::test]
    async fn remove_programs_a_single_del() {
        let spy = SpyProgrammer::default();
        let mut mgr = RouteManager::new(spy.clone());

        mgr.on_update(&remote_route("192.168.9.0/24", "10.0.0.2"));
        mgr.complete_deferred_work().await.unwrap();
        spy.clear();

        mgr.on_update(&ToDataplane::RouteRemove("192.168.9.0/24".into()));
        assert_eq!(mgr.pending_count(), 1, "one deletion pending");
        mgr.complete_deferred_work().await.unwrap();

        assert!(spy.adds().is_empty(), "removal adds nothing");
        assert_eq!(spy.dels(), vec!["192.168.9.0/24".to_string()]);
        assert_eq!(mgr.pending_count(), 0);
    }

    #[tokio::test]
    async fn changed_gateway_reprograms_the_route() {
        let spy = SpyProgrammer::default();
        let mut mgr = RouteManager::new(spy.clone());

        mgr.on_update(&remote_route("192.168.9.0/24", "10.0.0.2"));
        mgr.complete_deferred_work().await.unwrap();
        spy.clear();

        // Same dst, different gateway → a pending *update*, not a deletion.
        mgr.on_update(&remote_route("192.168.9.0/24", "10.0.0.3"));
        assert_eq!(mgr.pending_count(), 1);
        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.adds(), vec!["192.168.9.0/24".to_string()]);
        assert!(spy.dels().is_empty());
    }

    #[tokio::test]
    async fn ipv6_route_is_programmed() {
        let spy = SpyProgrammer::default();
        let mut mgr = RouteManager::new(spy.clone());

        mgr.on_update(&remote_route("fd00:9::/64", "fd00::2"));
        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.adds(), vec!["fd00:9::/64".to_string()]);
    }

    #[tokio::test]
    async fn non_route_messages_are_ignored() {
        let spy = SpyProgrammer::default();
        let mut mgr = RouteManager::new(spy.clone());

        mgr.on_update(&ToDataplane::IpSetUpdate(IpSetUpdate {
            id: "s1".into(),
            kind: IpSetKind::Ip,
            members: vec![],
        }));
        mgr.on_update(&ToDataplane::InSync);
        assert_eq!(mgr.desired_len(), 0, "route manager self-filters");

        mgr.complete_deferred_work().await.unwrap();
        assert!(spy.adds().is_empty() && spy.dels().is_empty());
    }

    #[tokio::test]
    async fn failed_programming_leaves_route_pending_for_retry() {
        let spy = SpyProgrammer::default();
        let mut mgr = RouteManager::new(spy.clone());

        mgr.on_update(&remote_route("192.168.9.0/24", "10.0.0.2"));
        spy.set_fail(true);
        let err = mgr.complete_deferred_work().await;
        assert!(err.is_err(), "netlink failure surfaces as DataplaneError");
        assert_eq!(mgr.pending_count(), 1, "state retained for retry");

        // Recover: the retry programs the still-pending route.
        spy.set_fail(false);
        mgr.complete_deferred_work().await.unwrap();
        assert_eq!(spy.adds(), vec!["192.168.9.0/24".to_string()]);
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn parse_cidr_handles_v4_v6_and_bare() {
        assert_eq!(
            parse_cidr("10.0.0.0/24").unwrap(),
            ("10.0.0.0".parse::<IpAddr>().unwrap(), 24)
        );
        assert_eq!(
            parse_cidr("10.0.0.5").unwrap(),
            ("10.0.0.5".parse::<IpAddr>().unwrap(), 32)
        );
        assert_eq!(
            parse_cidr("fd00::/64").unwrap(),
            ("fd00::".parse::<IpAddr>().unwrap(), 64)
        );
        assert!(parse_cidr("not-an-ip").is_err());
        assert!(parse_cidr("10.0.0.0/99").is_err());
    }
}
