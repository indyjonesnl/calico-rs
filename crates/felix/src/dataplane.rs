//! The felix `InternalDataplane` framework: a [`Manager`] trait plus a throttled,
//! coalescing apply loop. This is the backbone later tasks plug concrete managers
//! into (route programming, VXLAN, masquerade, policy/endpoint chains); it builds
//! no concrete managers itself.
//!
//! Modelled on upstream `felix/dataplane/linux/int_dataplane.go`:
//!
//! - Each [`Manager`] absorbs calc-graph messages into its *desired* state in
//!   [`Manager::on_update`] (cheap, must not touch the kernel) and reconciles that
//!   desired state to the dataplane in [`Manager::complete_deferred_work`] (called
//!   by the apply loop after a *batch* of updates — throttled/coalesced).
//! - [`InternalDataplane`] fans every message to every manager (managers
//!   self-filter), marks the dataplane dirty, and — on a throttled schedule —
//!   drives one `complete_deferred_work` round across all managers. A burst of N
//!   messages collapses to a *single* apply round.
//! - A manager that returns `Err` from `complete_deferred_work` leaves the
//!   dataplane dirty, so the round is retried (with bounded backoff) without
//!   losing the desired state the manager already absorbed.
//!
//! ## Pure core vs. async wrapper
//!
//! The dispatch/throttle/retry logic lives in the *pure, synchronous*
//! [`InternalDataplane`] (its throttle bookkeeping is [`DataplaneState`]). Time is
//! **injected** — the core never reads a clock — so it is deterministically
//! unit-testable without a kernel or tokio timers. The async [`run`] driver is a
//! thin wrapper that feeds messages from a channel and services the throttle
//! timer, converting wall-clock elapsed time into the integer "tick" the core
//! consumes.

use proto::{DataplaneSink, FromDataplane, ToDataplane};

/// A dataplane-programming error surfaced by a [`Manager`]. String-backed to match
/// the crate's existing error style (`config::ConfigError`, `nft`'s `Result<_,
/// String>`); returning it from [`Manager::complete_deferred_work`] triggers a
/// retry of the apply round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataplaneError(pub String);

impl DataplaneError {
    /// Construct a dataplane error from anything string-like.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for DataplaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dataplane error: {}", self.0)
    }
}

impl std::error::Error for DataplaneError {}

impl From<String> for DataplaneError {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for DataplaneError {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// A dataplane manager: owns some slice of dataplane state (routes, IP sets,
/// policy chains, …) and keeps it in sync with the calc graph.
///
/// Mirrors upstream's `Manager` interface. Managers ignore messages they don't
/// care about (self-filtering).
///
/// `complete_deferred_work` is `async` because reconciliation programs the kernel
/// over async I/O (`rtnetlink`, kube-backed managers, …). `on_update` stays
/// synchronous and cheap — it only mutates in-memory desired state and must never
/// touch the kernel or block. The trait uses [`async_trait`] with `?Send`: the
/// pure core drives managers on a single-threaded (current-thread) runtime, so it
/// does not require `Send` futures, which also keeps the non-`Send` unit-test
/// mocks (`Rc<RefCell<_>>`) valid.
#[async_trait::async_trait(?Send)]
pub trait Manager {
    /// Absorb one calc-graph message into this manager's *desired* state. Cheap;
    /// must not touch the kernel. Called for every message — managers self-filter.
    fn on_update(&mut self, msg: &ToDataplane);

    /// Reconcile desired state to the dataplane (program the kernel). Called by the
    /// apply loop after a coalesced batch of updates. Returns `Err` to trigger a
    /// retry (the desired state is preserved). Must be idempotent.
    async fn complete_deferred_work(&mut self) -> Result<(), DataplaneError>;
}

/// Outcome of one [`InternalDataplane::apply_all`] round.
#[derive(Debug, Default)]
pub struct ApplyOutcome {
    /// Errors from managers whose `complete_deferred_work` failed this round,
    /// paired with the manager's registration index. Non-empty ⇒ a retry is
    /// pending.
    pub errors: Vec<(usize, DataplaneError)>,
    /// `true` exactly once: on the first fully-successful apply round after the
    /// datastore has signalled [`ToDataplane::InSync`]. Drives readiness reporting.
    pub became_ready: bool,
}

impl ApplyOutcome {
    /// Whether every manager reconciled successfully this round.
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Pure throttle + readiness bookkeeping for [`InternalDataplane`]. Time is an
/// injected integer "tick"; no wall-clock is read here.
///
/// Coalescing: `dirty` is set whenever a message arrives; a burst therefore
/// collapses to a single apply round. The throttle admits an apply only when
/// `now >= next_eligible` (or when forced by `InSync`), so repeated bursts within
/// one interval still yield one round.
///
/// Retry: a failed round leaves `dirty` set and pushes `next_eligible` out by a
/// bounded exponential backoff, so state is never lost and retries don't spin.
#[derive(Debug, Clone)]
pub struct DataplaneState {
    /// Dataplane is out of sync and an apply round is owed.
    dirty: bool,
    /// The datastore has sent `InSync`.
    datastore_in_sync: bool,
    /// Readiness has already been reported once.
    in_sync_reported: bool,
    /// Force the next apply regardless of throttle (set on `InSync`).
    force: bool,
    /// Minimum ticks between successful applies (leaky-bucket rate).
    min_apply_interval: u64,
    /// Base backoff (ticks) applied after a failed round.
    retry_base: u64,
    /// Ceiling on the backoff (ticks).
    retry_max: u64,
    /// Consecutive failed rounds (drives backoff growth).
    consecutive_failures: u32,
    /// Earliest tick at which an apply may run.
    next_eligible: u64,
}

impl Default for DataplaneState {
    fn default() -> Self {
        Self::new(1)
    }
}

impl DataplaneState {
    /// New throttle state with the given minimum interval (in ticks) between
    /// successful applies. `next_eligible` starts at 0 so the first apply is
    /// immediate.
    pub fn new(min_apply_interval: u64) -> Self {
        Self {
            dirty: false,
            datastore_in_sync: false,
            in_sync_reported: false,
            force: false,
            min_apply_interval: min_apply_interval.max(1),
            retry_base: 1,
            retry_max: 10,
            consecutive_failures: 0,
            next_eligible: 0,
        }
    }

    /// Record that a message arrived: the dataplane is now dirty.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Record `InSync`: dirty + force an apply so readiness is surfaced promptly.
    pub fn mark_in_sync(&mut self) {
        self.datastore_in_sync = true;
        self.dirty = true;
        self.force = true;
    }

    /// Whether an apply round should run at `now` (dirty, and either forced or the
    /// throttle interval has elapsed).
    pub fn should_apply(&self, now: u64) -> bool {
        self.dirty && (self.force || now >= self.next_eligible)
    }

    /// Whether an apply round is owed (independent of the throttle).
    pub fn needs_apply(&self) -> bool {
        self.dirty
    }

    /// Begin an apply round: clear the dirty flag (re-set later if a manager fails).
    fn begin_apply(&mut self) {
        self.dirty = false;
    }

    /// End an apply round. `failed` ⇒ stay dirty and back off; otherwise schedule
    /// the next throttle slot and, if the datastore is in sync, report readiness
    /// exactly once. Returns `became_ready`.
    fn end_apply(&mut self, now: u64, failed: bool) -> bool {
        self.force = false;
        if failed {
            // Preserve pending work and retry after a bounded exponential backoff.
            self.dirty = true;
            let shift = self.consecutive_failures.min(31);
            let backoff = self
                .retry_base
                .saturating_mul(1u64 << shift)
                .min(self.retry_max);
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            self.next_eligible = now.saturating_add(backoff);
            return false;
        }
        self.consecutive_failures = 0;
        self.next_eligible = now.saturating_add(self.min_apply_interval);
        if self.datastore_in_sync && !self.in_sync_reported {
            self.in_sync_reported = true;
            return true;
        }
        false
    }
}

/// The felix `InternalDataplane`: the concrete [`DataplaneSink`] for the node.
///
/// Holds the registered managers and the pure throttle [`DataplaneState`]. The
/// throttle/dispatch bookkeeping is clock-free (time is injected) so the whole
/// framework is deterministically unit-testable; only [`apply_all`](Self::apply_all)
/// is `async` (it awaits each manager's kernel programming). The async [`run`]
/// driver is a thin wrapper.
#[derive(Default)]
pub struct InternalDataplane {
    managers: Vec<Box<dyn Manager>>,
    state: DataplaneState,
}

impl InternalDataplane {
    /// New dataplane with a default throttle (min interval = 1 tick).
    pub fn new() -> Self {
        Self::default()
    }

    /// New dataplane with an explicit throttle interval (ticks between applies).
    pub fn with_throttle(min_apply_interval: u64) -> Self {
        Self {
            managers: Vec::new(),
            state: DataplaneState::new(min_apply_interval),
        }
    }

    /// Register a manager. Managers are driven in registration order.
    pub fn add_manager(&mut self, manager: Box<dyn Manager>) {
        self.managers.push(manager);
    }

    /// Number of registered managers.
    pub fn manager_count(&self) -> usize {
        self.managers.len()
    }

    /// Fan one message to every manager's `on_update` (in registration order),
    /// then mark the dataplane dirty. `InSync` additionally forces the next apply.
    /// Does *not* program the kernel.
    pub fn dispatch(&mut self, msg: &ToDataplane) {
        for manager in &mut self.managers {
            manager.on_update(msg);
        }
        if matches!(msg, ToDataplane::InSync) {
            self.state.mark_in_sync();
        } else {
            self.state.mark_dirty();
        }
    }

    /// Whether an apply round should run at `now`.
    pub fn should_apply(&self, now: u64) -> bool {
        self.state.should_apply(now)
    }

    /// Whether an apply round is owed (independent of the throttle).
    pub fn needs_apply(&self) -> bool {
        self.state.needs_apply()
    }

    /// Whether readiness has been reported.
    pub fn is_ready(&self) -> bool {
        self.state.in_sync_reported
    }

    /// Run one coalesced apply round at `now`: call `complete_deferred_work` on
    /// every manager (registration order), collecting failures. Any failure leaves
    /// the dataplane dirty for a retry; a fully-clean round after `InSync` reports
    /// readiness once.
    pub async fn apply_all(&mut self, now: u64) -> ApplyOutcome {
        // Clear the dirty flag up front; a failing manager re-sets it via
        // `end_apply`, so pending work is never dropped.
        self.state.begin_apply();
        let mut errors = Vec::new();
        for (idx, manager) in self.managers.iter_mut().enumerate() {
            if let Err(err) = manager.complete_deferred_work().await {
                errors.push((idx, err));
            }
        }
        let became_ready = self.state.end_apply(now, !errors.is_empty());
        ApplyOutcome {
            errors,
            became_ready,
        }
    }
}

impl DataplaneSink for InternalDataplane {
    type Error = DataplaneError;

    /// Queue one message: fan out to managers and mark dirty. Never fails — actual
    /// kernel programming happens in the throttled [`InternalDataplane::apply_all`].
    fn apply(&mut self, msg: ToDataplane) -> Result<(), Self::Error> {
        self.dispatch(&msg);
        Ok(())
    }
}

/// How often the async [`run`] loop services its throttle timer.
const THROTTLE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Async driver: consume [`ToDataplane`] messages from `updates`, coalesce them,
/// and drive the throttled apply loop. When a clean apply completes after
/// `InSync`, emit [`FromDataplane::InSync`] on `ready` (if provided).
///
/// This is a *thin* wrapper: all dispatch/throttle/retry logic lives in the pure
/// [`InternalDataplane`]. The only thing added here is turning wall-clock elapsed
/// time into the integer tick the core consumes, and awaiting the timer/channel.
pub async fn run(
    mut dataplane: InternalDataplane,
    mut updates: tokio::sync::mpsc::Receiver<ToDataplane>,
    ready: Option<tokio::sync::mpsc::Sender<FromDataplane>>,
) {
    let start = std::time::Instant::now();
    let mut ticker = tokio::time::interval(THROTTLE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first tick fires immediately; consume it so it doesn't count as an event.
    ticker.tick().await;

    loop {
        tokio::select! {
            maybe_msg = updates.recv() => {
                match maybe_msg {
                    Some(msg) => dataplane.dispatch(&msg),
                    None => {
                        tracing::info!("dataplane update channel closed; apply loop exiting");
                        break;
                    }
                }
            }
            _ = ticker.tick() => {}
        }

        // Inject "now" as the number of throttle intervals elapsed since start.
        let now = (start.elapsed().as_millis() / THROTTLE_INTERVAL.as_millis()) as u64;
        if dataplane.should_apply(now) {
            let outcome = dataplane.apply_all(now).await;
            for (idx, err) in &outcome.errors {
                tracing::warn!(manager = idx, %err, "manager failed to apply; will retry");
            }
            if outcome.became_ready {
                if let Some(tx) = &ready {
                    let _ = tx.send(FromDataplane::InSync).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use proto::{IpSetKind, IpSetUpdate, RouteType, RouteUpdate};

    /// Shared, inspectable record of a mock manager's activity.
    #[derive(Default)]
    struct Record {
        /// Messages the manager *acted on* (after self-filtering).
        seen: Vec<ToDataplane>,
        /// Number of `complete_deferred_work` calls.
        apply_calls: usize,
        /// When `> 0`, `complete_deferred_work` fails and decrements this counter,
        /// so the manager fails the next N applies then starts succeeding.
        fail_next: usize,
    }

    type Handle = Rc<RefCell<Record>>;

    /// A mock manager that records everything it acts on. `filter` decides which
    /// messages it "cares about"; a togglable failure counter drives retry tests.
    struct MockManager {
        rec: Handle,
        filter: fn(&ToDataplane) -> bool,
    }

    impl MockManager {
        fn new(filter: fn(&ToDataplane) -> bool) -> (Self, Handle) {
            let rec = Rc::new(RefCell::new(Record::default()));
            (
                Self {
                    rec: Rc::clone(&rec),
                    filter,
                },
                rec,
            )
        }
    }

    #[async_trait::async_trait(?Send)]
    impl Manager for MockManager {
        fn on_update(&mut self, msg: &ToDataplane) {
            if (self.filter)(msg) {
                self.rec.borrow_mut().seen.push(msg.clone());
            }
        }

        async fn complete_deferred_work(&mut self) -> Result<(), DataplaneError> {
            let mut r = self.rec.borrow_mut();
            r.apply_calls += 1;
            if r.fail_next > 0 {
                r.fail_next -= 1;
                return Err(DataplaneError::new("mock failure"));
            }
            Ok(())
        }
    }

    fn accept_all(_: &ToDataplane) -> bool {
        true
    }
    fn only_routes(m: &ToDataplane) -> bool {
        matches!(m, ToDataplane::RouteUpdate(_) | ToDataplane::RouteRemove(_))
    }

    fn ipset_msg(id: &str) -> ToDataplane {
        ToDataplane::IpSetUpdate(IpSetUpdate {
            id: id.into(),
            kind: IpSetKind::Ip,
            members: vec![],
        })
    }
    fn route_msg(dst: &str) -> ToDataplane {
        ToDataplane::RouteUpdate(RouteUpdate {
            route_type: RouteType::LocalWorkload,
            dst: dst.into(),
            dst_node_name: None,
            gateway: None,
        })
    }

    #[test]
    fn dispatch_fans_out_on_update_to_all_managers() {
        let mut dp = InternalDataplane::new();
        let (m1, h1) = MockManager::new(accept_all);
        let (m2, h2) = MockManager::new(accept_all);
        dp.add_manager(Box::new(m1));
        dp.add_manager(Box::new(m2));

        dp.dispatch(&ipset_msg("s1"));

        assert_eq!(h1.borrow().seen.len(), 1);
        assert_eq!(h2.borrow().seen.len(), 1);
        assert!(
            dp.needs_apply(),
            "a message should mark the dataplane dirty"
        );
    }

    #[tokio::test]
    async fn burst_coalesces_to_single_apply() {
        let mut dp = InternalDataplane::with_throttle(1);
        let (m, h) = MockManager::new(accept_all);
        dp.add_manager(Box::new(m));

        // A burst of five messages at the same tick.
        for i in 0..5 {
            dp.dispatch(&ipset_msg(&format!("s{i}")));
        }
        assert!(h.borrow().seen.len() == 5, "on_update runs per message");

        // One apply round at tick 0.
        assert!(dp.should_apply(0));
        dp.apply_all(0).await;

        assert_eq!(
            h.borrow().apply_calls,
            1,
            "N messages in a burst must coalesce to ONE complete_deferred_work"
        );
        assert!(!dp.needs_apply(), "clean apply clears the dirty flag");
        assert!(
            !dp.should_apply(0),
            "no further apply owed within the same interval"
        );
    }

    #[tokio::test]
    async fn insync_forces_apply_and_reports_readiness() {
        // Throttle interval large so a normal apply would be blocked at tick 0
        // after a prior apply — InSync must still force one.
        let mut dp = InternalDataplane::with_throttle(100);
        let (m, _h) = MockManager::new(accept_all);
        dp.add_manager(Box::new(m));

        dp.dispatch(&ipset_msg("s1"));
        dp.apply_all(0).await; // consumes the first slot; next_eligible now = 100
        assert!(!dp.is_ready());

        // Not in sync yet, throttled within the interval.
        dp.dispatch(&ipset_msg("s2"));
        assert!(!dp.should_apply(1), "throttled before InSync");

        dp.dispatch(&ToDataplane::InSync);
        assert!(
            dp.should_apply(1),
            "InSync forces an apply despite throttle"
        );
        let outcome = dp.apply_all(1).await;
        assert!(
            outcome.became_ready,
            "clean apply after InSync reports ready"
        );
        assert!(dp.is_ready());

        // Readiness is reported exactly once.
        dp.dispatch(&ipset_msg("s3"));
        dp.dispatch(&ToDataplane::InSync);
        let outcome2 = dp.apply_all(2).await;
        assert!(!outcome2.became_ready, "readiness reported only once");
    }

    #[tokio::test]
    async fn failed_manager_is_retried_without_state_loss_then_stops() {
        let mut dp = InternalDataplane::with_throttle(1);
        let (m, h) = MockManager::new(accept_all);
        h.borrow_mut().fail_next = 1; // fail the first apply, succeed afterwards
        dp.add_manager(Box::new(m));

        dp.dispatch(&route_msg("10.0.0.0/24"));

        // First round: manager fails.
        assert!(dp.should_apply(0));
        let o0 = dp.apply_all(0).await;
        assert!(!o0.is_clean(), "manager failed this round");
        assert!(
            dp.needs_apply(),
            "failed apply stays dirty (state not lost)"
        );
        assert_eq!(h.borrow().seen.len(), 1, "absorbed state is retained");

        // Retry on a later tick: manager now succeeds.
        assert!(dp.should_apply(5), "retry is scheduled after backoff");
        let o1 = dp.apply_all(5).await;
        assert!(o1.is_clean(), "retry succeeds");
        assert!(!dp.needs_apply(), "clean retry clears dirty");
        assert_eq!(h.borrow().apply_calls, 2, "one fail + one success");

        // Nothing new: no further applies (stops being retried).
        assert!(!dp.should_apply(6));
    }

    #[test]
    fn managers_self_filter_messages() {
        let mut dp = InternalDataplane::new();
        let (route_mgr, rh) = MockManager::new(only_routes);
        dp.add_manager(Box::new(route_mgr));

        dp.dispatch(&ipset_msg("s1")); // ignored by a route-only manager
        dp.dispatch(&route_msg("10.0.0.0/24")); // acted on

        let seen = &rh.borrow().seen;
        assert_eq!(seen.len(), 1, "route manager ignores IP-set updates");
        assert!(matches!(seen[0], ToDataplane::RouteUpdate(_)));
    }

    #[test]
    fn arrival_order_is_preserved_into_on_update() {
        let mut dp = InternalDataplane::new();
        let (m, h) = MockManager::new(accept_all);
        dp.add_manager(Box::new(m));

        dp.dispatch(&ipset_msg("s1"));
        dp.dispatch(&route_msg("10.0.0.0/24"));
        dp.dispatch(&ToDataplane::InSync);

        let seen = &h.borrow().seen;
        assert_eq!(seen.len(), 3);
        assert!(matches!(seen[0], ToDataplane::IpSetUpdate(_)));
        assert!(matches!(seen[1], ToDataplane::RouteUpdate(_)));
        assert!(matches!(seen[2], ToDataplane::InSync));
    }

    #[test]
    fn sink_impl_queues_without_programming() {
        // DataplaneSink::apply just queues; it never programs the kernel itself.
        let mut dp = InternalDataplane::new();
        let (m, h) = MockManager::new(accept_all);
        dp.add_manager(Box::new(m));

        DataplaneSink::apply(&mut dp, ipset_msg("s1")).unwrap();
        assert_eq!(h.borrow().seen.len(), 1);
        assert_eq!(h.borrow().apply_calls, 0, "sink apply does not reconcile");
        assert!(dp.needs_apply());
    }
}
