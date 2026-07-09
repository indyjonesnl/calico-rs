//! Shared `tracing` initialization for Calico-rs binaries (felix, node, typha,
//! controllers, calicoctl): a structured, human-readable `fmt` subscriber
//! writing to stderr, filtered by `RUST_LOG` (falling back to `info` when
//! unset or unparsable).
//!
//! Every binary calls [`init_tracing`] once at startup. Because integration
//! tests and multiple library entry points may call it more than once in the
//! same process, initialization is idempotent: a second call is a no-op
//! rather than a panic.

use tracing_subscriber::EnvFilter;

/// Default filter directive used when `RUST_LOG` is unset or fails to parse.
const DEFAULT_DIRECTIVE: &str = "info";

/// Build an [`EnvFilter`] from an optional directive string (typically
/// `std::env::var("RUST_LOG").ok()`), falling back to [`DEFAULT_DIRECTIVE`]
/// when `directive` is `None` or fails to parse.
///
/// Pure function (no global state, no env access) so it is unit-testable in
/// isolation from the process-wide `RUST_LOG` variable.
pub fn build_env_filter(directive: Option<&str>) -> EnvFilter {
    match directive {
        Some(d) => EnvFilter::try_new(d).unwrap_or_else(|_| EnvFilter::new(DEFAULT_DIRECTIVE)),
        None => EnvFilter::new(DEFAULT_DIRECTIVE),
    }
}

/// Initialize the global `tracing` subscriber with a filter built from the
/// `RUST_LOG` environment variable (default `info`).
///
/// Safe to call more than once (e.g. from multiple binaries in a shared test
/// harness, or repeatedly in `#[test]` functions): subsequent calls are
/// swallowed rather than panicking.
pub fn init_tracing() {
    init_tracing_with(std::env::var("RUST_LOG").ok().as_deref());
}

/// Like [`init_tracing`], but with an explicit filter directive instead of
/// reading `RUST_LOG` from the environment. Pass `None` to use the default.
pub fn init_tracing_with(directive: Option<&str>) {
    let filter = build_env_filter(directive);
    // `try_init` fails only because a global subscriber is already set; that
    // is expected when called more than once, so it is intentionally ignored.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_filter_builds_and_renders_info() {
        let filter = build_env_filter(None);
        assert_eq!(filter.to_string(), DEFAULT_DIRECTIVE);
    }

    #[test]
    fn bad_directive_degrades_to_default() {
        let filter = build_env_filter(Some("!!!not a valid directive!!!"));
        assert_eq!(filter.to_string(), DEFAULT_DIRECTIVE);
    }

    #[test]
    fn valid_directive_is_honored() {
        let filter = build_env_filter(Some("debug"));
        assert_eq!(filter.to_string(), "debug");
    }

    #[test]
    fn init_tracing_is_idempotent() {
        // First call installs the global subscriber (or observes one already
        // installed by an earlier test in this binary); the second call must
        // not panic.
        init_tracing_with(Some("info"));
        init_tracing_with(Some("debug"));
    }
}
