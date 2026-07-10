//! Bounded retry-with-backoff for the node's startup datastore operations
//! (T-HH). Upstream calico-node crash-loops on any startup datastore error;
//! that turns a transient API-server blip (e.g. `client error (Connect)`
//! while the apiserver/etcd is still coming up) into a visible crash-loop.
//! Wrapping the initial connect + baseline-bootstrap calls in this helper
//! lets a handful of early failures resolve themselves instead of fatal
//! exiting the pod.
//!
//! Errors from the datastore layer ([`datastore::DsError`] /
//! [`datastore::CasError`]) are stringly-typed by the time they reach
//! `node::startup` (see `crates/node/src/startup.rs`), so this helper does
//! not attempt fine-grained transient-vs-logical classification of the
//! underlying error. Instead it retries *any* error from the wrapped
//! operation up to a bounded attempt count with capped exponential backoff.
//! This is intentionally conservative: startup calls here are idempotent
//! (`node::startup::startup` never overwrites existing state — see its
//! module docs), so retrying a non-transient error is harmless beyond the
//! wasted time budget (bounded by `max_attempts`), and a persistent error
//! still surfaces (as a fatal exit) once the cap is reached.

use std::time::Duration;

/// Retry an async operation up to `max_attempts` times, sleeping between
/// attempts with exponential backoff starting at `initial_backoff` and
/// capped at `max_backoff`. Returns the operation's success value, or its
/// final error once `max_attempts` have been made.
///
/// `op_name` is used only for the `tracing::warn!` emitted before each retry
/// sleep, to identify which startup step is retrying.
pub async fn retry_with_backoff<T, E, F, Fut>(
    max_attempts: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
    op_name: &str,
    mut op: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    assert!(max_attempts >= 1, "max_attempts must be at least 1");
    let mut backoff = initial_backoff;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt >= max_attempts => return Err(e),
            Err(e) => {
                tracing::warn!(
                    op = op_name,
                    attempt,
                    max_attempts,
                    backoff_ms = backoff.as_millis() as u64,
                    error = %e,
                    "startup operation failed, retrying after backoff"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fake op that fails with `"transient"` on its first `fail_count`
    /// calls, then succeeds returning the call count.
    fn flaky_op(
        fail_count: u32,
    ) -> (
        impl FnMut() -> std::future::Ready<Result<u32, String>>,
        std::sync::Arc<AtomicU32>,
    ) {
        let calls = std::sync::Arc::new(AtomicU32::new(0));
        let calls_inner = calls.clone();
        let op = move || {
            let n = calls_inner.fetch_add(1, Ordering::SeqCst) + 1;
            if n <= fail_count {
                std::future::ready(Err(format!("transient failure #{n}")))
            } else {
                std::future::ready(Ok(n))
            }
        };
        (op, calls)
    }

    #[tokio::test]
    async fn succeeds_immediately_when_op_never_fails() {
        let (mut op, calls) = flaky_op(0);
        let result = retry_with_backoff(
            5,
            Duration::from_millis(1),
            Duration::from_millis(10),
            "test-op",
            &mut op,
        )
        .await;
        assert_eq!(result, Ok(1));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn succeeds_after_transient_failures_within_cap() {
        // Fails 3 times, succeeds on the 4th call; cap allows 5 attempts.
        let (mut op, calls) = flaky_op(3);
        let result = retry_with_backoff(
            5,
            Duration::from_millis(1),
            Duration::from_millis(10),
            "test-op",
            &mut op,
        )
        .await;
        assert_eq!(result, Ok(4));
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn errors_after_cap_when_op_fails_forever() {
        let (mut op, calls) = flaky_op(u32::MAX);
        let result = retry_with_backoff(
            4,
            Duration::from_millis(1),
            Duration::from_millis(10),
            "test-op",
            &mut op,
        )
        .await;
        assert_eq!(result, Err("transient failure #4".to_string()));
        // Never exceeds the attempt cap.
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn backoff_is_capped_and_does_not_grow_unbounded() {
        // With a tiny max_backoff, even many attempts should complete quickly
        // (this mostly guards against a regression that forgets to cap).
        let (mut op, _calls) = flaky_op(20);
        let start = tokio::time::Instant::now();
        let result = retry_with_backoff(
            25,
            Duration::from_millis(1),
            Duration::from_millis(5),
            "test-op",
            &mut op,
        )
        .await;
        assert!(result.is_ok());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "capped backoff should keep total retry time small in this test"
        );
    }

    #[tokio::test]
    #[should_panic(expected = "max_attempts must be at least 1")]
    async fn panics_on_zero_max_attempts() {
        let _ = retry_with_backoff(
            0,
            Duration::from_millis(1),
            Duration::from_millis(1),
            "test-op",
            || std::future::ready(Ok::<(), String>(())),
        )
        .await;
    }
}
