//! Minimal health/readiness + metrics HTTP helper shared by Calico-rs
//! binaries (felix, node, typha, controllers, calicoctl).
//!
//! Serves exactly three routes, hand-rolled over a raw
//! [`tokio::net::TcpListener`] (no HTTP framework dependency):
//! - `GET /healthz` — 200 once the process is alive (always).
//! - `GET /readyz` — 200 once [`Readiness`] has been flipped to ready, else
//!   503.
//! - `GET /metrics` — 200, body = [`Metrics::render`] (Prometheus text
//!   exposition format).
//!
//! Anything else → 404. Malformed request lines → 400.
//!
//! The routing/response decision is a pure function, [`handle_request`], so
//! it is unit-testable without binding a socket. [`serve`] is the thin async
//! wrapper that reads a request line off an accepted connection and writes
//! the resulting response.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

// ---- Metrics ---------------------------------------------------------------

/// A tiny thread-safe metrics registry: named monotonic counters and named
/// gauges, rendered as Prometheus text exposition format.
///
/// Cheaply `Clone`-able (internally `Arc`-shared) so it can be handed to both
/// the reconciliation code that updates it and the [`serve`] task that reads
/// it.
#[derive(Clone, Default)]
pub struct Metrics(Arc<MetricsInner>);

#[derive(Default)]
struct MetricsInner {
    counters: Mutex<BTreeMap<String, u64>>,
    gauges: Mutex<BTreeMap<String, f64>>,
}

impl Metrics {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the named counter by 1, creating it at 0 first if unseen.
    pub fn incr_counter(&self, name: &str) {
        self.add_counter(name, 1);
    }

    /// Increment the named counter by `delta`, creating it at 0 first if
    /// unseen.
    pub fn add_counter(&self, name: &str, delta: u64) {
        let mut counters = self.0.counters.lock().unwrap();
        *counters.entry(name.to_string()).or_insert(0) += delta;
    }

    /// Set the named gauge to `value`, overwriting any previous value.
    pub fn set_gauge(&self, name: &str, value: f64) {
        self.0
            .gauges
            .lock()
            .unwrap()
            .insert(name.to_string(), value);
    }

    /// Render the registry as Prometheus text exposition format: for each
    /// metric, a `# TYPE` line followed by a `name value` sample line.
    /// Counters are emitted (sorted by name) before gauges (sorted by name).
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (name, value) in self.0.counters.lock().unwrap().iter() {
            out.push_str(&format!("# TYPE {name} counter\n{name} {value}\n"));
        }
        for (name, value) in self.0.gauges.lock().unwrap().iter() {
            out.push_str(&format!("# TYPE {name} gauge\n{name} {value}\n"));
        }
        out
    }
}

// ---- Readiness ---------------------------------------------------------------

/// A shared, cheaply-`Clone`-able readiness flag. The owning component (e.g.
/// a syncer reaching `InSync`) flips this to `true`; `/readyz` reports it.
#[derive(Clone, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    /// Create a new flag, initially not ready.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark the component ready (or not ready).
    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::SeqCst);
    }

    /// Current readiness state.
    pub fn get(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

// ---- Pure request handling ---------------------------------------------------

/// A minimal HTTP response: status line + body, rendered as a well-formed
/// HTTP/1.1 message with `Content-Length` and `Connection: close`.
#[derive(Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: &'static str,
    pub body: String,
}

impl HttpResponse {
    fn new(status: u16, reason: &'static str, body: impl Into<String>) -> Self {
        Self {
            status,
            reason,
            body: body.into(),
        }
    }

    /// Serialize to the bytes to write directly to the socket.
    pub fn to_bytes(&self) -> Vec<u8> {
        format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{}",
            self.status,
            self.reason,
            self.body.len(),
            self.body
        )
        .into_bytes()
    }
}

/// Decide the response for a single HTTP request line (e.g.
/// `"GET /healthz HTTP/1.1"`), given current readiness and the pre-rendered
/// metrics body. Pure — no I/O — so it is unit-testable without a socket.
pub fn handle_request(line: &str, ready: bool, metrics_body: &str) -> HttpResponse {
    let mut parts = line.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some("GET"), Some("/healthz")) => HttpResponse::new(200, "OK", "ok"),
        (Some("GET"), Some("/readyz")) if ready => HttpResponse::new(200, "OK", "ok"),
        (Some("GET"), Some("/readyz")) => {
            HttpResponse::new(503, "Service Unavailable", "not ready")
        }
        (Some("GET"), Some("/metrics")) => HttpResponse::new(200, "OK", metrics_body),
        (Some(_), Some(_)) => HttpResponse::new(404, "Not Found", "not found"),
        _ => HttpResponse::new(400, "Bad Request", "bad request"),
    }
}

// ---- Async server -------------------------------------------------------------

/// A running health/metrics server. Dropping it aborts the accept loop and
/// closes the listening socket — there is no explicit shutdown handshake
/// (YAGNI: this is a probe/scrape endpoint, not a graceful-drain service).
pub struct HealthServer {
    local_addr: SocketAddr,
    handle: JoinHandle<()>,
}

impl HealthServer {
    /// The actual bound address (useful when `addr`'s port was `0`).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for HealthServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Bind `addr` and serve `/healthz`, `/readyz`, `/metrics` until the returned
/// [`HealthServer`] is dropped.
pub async fn serve(
    addr: SocketAddr,
    ready: Readiness,
    metrics: Metrics,
) -> io::Result<HealthServer> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let ready = ready.clone();
                    let metrics = metrics.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(stream, &ready, &metrics).await {
                            tracing::debug!(%err, "health server connection error");
                        }
                    });
                }
                Err(err) => {
                    tracing::warn!(%err, "health server accept error");
                }
            }
        }
    });
    Ok(HealthServer { local_addr, handle })
}

/// Read one request line off `stream`, decide the response via
/// [`handle_request`], and write it back. Never panics on malformed/partial
/// input (an empty or unparsable line simply routes to 400).
async fn handle_connection(
    mut stream: TcpStream,
    ready: &Readiness,
    metrics: &Metrics,
) -> io::Result<()> {
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let line = request.lines().next().unwrap_or("");
    let body = metrics.render();
    let response = handle_request(line, ready.get(), &body);
    stream.write_all(&response.to_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Metrics ----

    #[test]
    fn render_empty_registry_is_empty() {
        let m = Metrics::new();
        assert_eq!(m.render(), "");
    }

    #[test]
    fn render_counter_and_gauge() {
        let m = Metrics::new();
        m.incr_counter("requests_total");
        m.incr_counter("requests_total");
        m.add_counter("requests_total", 3);
        m.set_gauge("queue_depth", 2.5);

        assert_eq!(
            m.render(),
            "# TYPE requests_total counter\nrequests_total 5\n\
             # TYPE queue_depth gauge\nqueue_depth 2.5\n"
        );
    }

    #[test]
    fn set_gauge_overwrites() {
        let m = Metrics::new();
        m.set_gauge("x", 1.0);
        m.set_gauge("x", 2.0);
        assert_eq!(m.render(), "# TYPE x gauge\nx 2\n");
    }

    // ---- Readiness ----

    #[test]
    fn readiness_defaults_false_and_is_settable() {
        let r = Readiness::new();
        assert!(!r.get());
        r.set(true);
        assert!(r.get());
    }

    // ---- Pure handler ----

    #[test]
    fn healthz_always_ok() {
        let resp = handle_request("GET /healthz HTTP/1.1", false, "");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "ok");
    }

    #[test]
    fn readyz_ok_when_ready() {
        let resp = handle_request("GET /readyz HTTP/1.1", true, "");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "ok");
    }

    #[test]
    fn readyz_503_when_not_ready() {
        let resp = handle_request("GET /readyz HTTP/1.1", false, "");
        assert_eq!(resp.status, 503);
    }

    #[test]
    fn metrics_returns_rendered_body() {
        let resp = handle_request("GET /metrics HTTP/1.1", true, "# TYPE x counter\nx 1\n");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "# TYPE x counter\nx 1\n");
    }

    #[test]
    fn unknown_path_is_404() {
        let resp = handle_request("GET /nope HTTP/1.1", true, "");
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn malformed_line_is_400() {
        assert_eq!(handle_request("", true, "").status, 400);
        assert_eq!(handle_request("garbage", true, "").status, 400);
    }

    #[test]
    fn response_serializes_with_content_length() {
        let resp = HttpResponse::new(200, "OK", "ok");
        let bytes = resp.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.ends_with("\r\n\r\nok"));
    }

    // ---- Integration: real ephemeral-port socket ----

    #[tokio::test]
    async fn serve_answers_over_a_real_socket() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ready = Readiness::new();
        let metrics = Metrics::new();
        metrics.incr_counter("hits");

        let server = serve(addr, ready.clone(), metrics).await.unwrap();
        let bound = server.local_addr();

        // /readyz before the component signals readiness -> 503.
        let (status, _) = raw_get(bound, "/readyz").await;
        assert_eq!(status, 503);

        ready.set(true);

        let (status, body) = raw_get(bound, "/healthz").await;
        assert_eq!(status, 200);
        assert_eq!(body, "ok");

        let (status, body) = raw_get(bound, "/metrics").await;
        assert_eq!(status, 200);
        assert!(body.contains("hits 1"));

        drop(server);
    }

    /// Connect, write a raw GET request line, read back the full response,
    /// and return (status, body).
    async fn raw_get(addr: SocketAddr, path: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();

        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        let resp = String::from_utf8(resp).unwrap();

        let mut lines = resp.split("\r\n\r\n");
        let head = lines.next().unwrap();
        let body = lines.next().unwrap_or("").to_string();
        let status: u16 = head
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (status, body)
    }
}
