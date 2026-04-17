//! Observability: per-client metrics trait + built-in recorders.
//!
//! The [`PirMetrics`] trait is an **observer** — it receives callbacks
//! at well-defined boundaries in each PIR client and transport, and
//! implementations aggregate those events into whatever backend the
//! caller prefers (in-memory atomic counters, Prometheus, StatsD,
//! OpenTelemetry, custom log format, etc.).
//!
//! The trait is additive and opt-in: every callback has a no-op
//! default body, so installing no recorder (or installing
//! [`NoopMetrics`]) is the same as not having metrics at all. This
//! lets us ship metrics hooks without forcing a dependency on any
//! particular observability stack.
//!
//! # Backend-field convention
//!
//! Every callback takes a `backend: &'static str` argument set to one
//! of `"dpf"`, `"harmony"`, or `"onion"`. This mirrors the `backend
//! = …` field on the tracing spans added in Phase 1 of the
//! observability milestone — a downstream implementation can filter or
//! aggregate by backend without caring about the specific client
//! type. The `&'static str` type is chosen so the cost of a callback
//! is a pointer compare / copy, not a `String` clone.
//!
//! # Thread safety
//!
//! Trait objects are `Send + Sync` because PIR clients are
//! `Send + Sync` and the recorder is shared across `.await`
//! boundaries. Implementations that hold interior mutability must
//! therefore use atomics or a synchronization primitive — see
//! [`AtomicMetrics`] below for a lock-free example.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//! use pir_sdk::{AtomicMetrics, PirMetrics};
//!
//! let recorder = Arc::new(AtomicMetrics::new());
//!
//! // Imagine a `DpfClient` has fired a few callbacks here.
//! recorder.on_connect("dpf", "wss://server0");
//! recorder.on_bytes_sent("dpf", 1024);
//! recorder.on_bytes_received("dpf", 2048);
//! recorder.on_query_end("dpf", 0, 10, true);
//!
//! let snap = recorder.snapshot();
//! assert_eq!(snap.connects, 1);
//! assert_eq!(snap.bytes_sent, 1024);
//! assert_eq!(snap.bytes_received, 2048);
//! assert_eq!(snap.queries_completed, 1);
//! assert_eq!(snap.query_errors, 0);
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

// ─── Trait ──────────────────────────────────────────────────────────────────

/// Observer trait for PIR client + transport metrics.
///
/// All callbacks are no-op by default; implementations override only
/// the events they care about. The trait is designed so that the
/// compiler can inline every call site to a no-op when the default
/// impl is used, making the "no recorder installed" path essentially
/// free.
///
/// The trait is `Send + Sync` because PIR clients are `Send + Sync`
/// and recorders are shared across `.await` points (they're held
/// behind `Arc<dyn PirMetrics>`). Implementations with interior
/// mutability must use atomics or locks.
pub trait PirMetrics: Send + Sync {
    /// Fired when a PIR query batch starts — before any wire I/O.
    /// `num_queries` is the number of script hashes in the batch.
    fn on_query_start(&self, _backend: &'static str, _db_id: u8, _num_queries: usize) {}

    /// Fired when a PIR query batch completes.
    /// `success = true` means the client produced a well-formed
    /// `Vec<Option<QueryResult>>`; `false` means the batch errored
    /// (connection lost, server error, Merkle verification failure,
    /// etc.).
    fn on_query_end(
        &self,
        _backend: &'static str,
        _db_id: u8,
        _num_queries: usize,
        _success: bool,
    ) {
    }

    /// Fired for every binary frame the transport sends. `bytes` is
    /// the payload length (excluding the 4-byte length prefix that
    /// the framing layer adds). Transports that don't care about
    /// per-frame counting can leave this as the default no-op — the
    /// client still receives aggregated query-level callbacks.
    fn on_bytes_sent(&self, _backend: &'static str, _bytes: usize) {}

    /// Fired for every binary frame the transport receives.
    /// Symmetric to [`on_bytes_sent`](Self::on_bytes_sent).
    fn on_bytes_received(&self, _backend: &'static str, _bytes: usize) {}

    /// Fired on successful TLS/WebSocket handshake. `url` is the
    /// endpoint that was connected to (for display/logging only —
    /// recorders should avoid using it as a metric dimension since
    /// that would create unbounded cardinality).
    fn on_connect(&self, _backend: &'static str, _url: &str) {}

    /// Fired when the transport is intentionally closed. Not fired
    /// on unexpected disconnects (those surface as `on_query_end`
    /// with `success = false` plus whatever the error taxonomy
    /// raises).
    fn on_disconnect(&self, _backend: &'static str) {}
}

// ─── NoopMetrics ────────────────────────────────────────────────────────────

/// No-op metrics recorder. Use this as a placeholder when you need
/// an `Arc<dyn PirMetrics>` but don't actually want to record
/// anything — e.g. in unit tests where the metrics surface isn't
/// what's being exercised.
///
/// Functionally equivalent to simply not installing a recorder at
/// all; the only reason to use this is API symmetry.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopMetrics;

impl PirMetrics for NoopMetrics {}

// ─── AtomicMetrics ──────────────────────────────────────────────────────────

/// In-memory, lock-free metrics recorder backed by atomic counters.
///
/// This is the recommended default for callers that want "give me
/// numbers, I'll look at them later" without plugging in a full
/// observability stack. All counters are `u64` and monotonically
/// non-decreasing; callers snapshot via [`snapshot`](Self::snapshot)
/// and diff two snapshots to get a rate.
///
/// For histograms, rates, tags, or derived metrics, install a
/// custom `PirMetrics` impl that forwards to
/// Prometheus/StatsD/OpenTelemetry/etc.
#[derive(Debug, Default)]
pub struct AtomicMetrics {
    queries_started: AtomicU64,
    queries_completed: AtomicU64,
    query_errors: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    frames_sent: AtomicU64,
    frames_received: AtomicU64,
    connects: AtomicU64,
    disconnects: AtomicU64,
}

impl AtomicMetrics {
    /// Create a new recorder with all counters zeroed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a snapshot of every counter. Individual counters are
    /// atomic, but the snapshot as a whole is NOT atomic — two
    /// counters may be observed at slightly different instants. For
    /// most diagnostic purposes this is fine; if you need a
    /// consistent cross-counter view, lock the recorder before
    /// reading (wrap it in a `Mutex` in your own code).
    pub fn snapshot(&self) -> AtomicMetricsSnapshot {
        AtomicMetricsSnapshot {
            queries_started: self.queries_started.load(Ordering::Relaxed),
            queries_completed: self.queries_completed.load(Ordering::Relaxed),
            query_errors: self.query_errors.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            frames_sent: self.frames_sent.load(Ordering::Relaxed),
            frames_received: self.frames_received.load(Ordering::Relaxed),
            connects: self.connects.load(Ordering::Relaxed),
            disconnects: self.disconnects.load(Ordering::Relaxed),
        }
    }
}

impl PirMetrics for AtomicMetrics {
    fn on_query_start(&self, _backend: &'static str, _db_id: u8, _num_queries: usize) {
        self.queries_started.fetch_add(1, Ordering::Relaxed);
    }

    fn on_query_end(
        &self,
        _backend: &'static str,
        _db_id: u8,
        _num_queries: usize,
        success: bool,
    ) {
        if success {
            self.queries_completed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.query_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn on_bytes_sent(&self, _backend: &'static str, bytes: usize) {
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
        self.frames_sent.fetch_add(1, Ordering::Relaxed);
    }

    fn on_bytes_received(&self, _backend: &'static str, bytes: usize) {
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.frames_received.fetch_add(1, Ordering::Relaxed);
    }

    fn on_connect(&self, _backend: &'static str, _url: &str) {
        self.connects.fetch_add(1, Ordering::Relaxed);
    }

    fn on_disconnect(&self, _backend: &'static str) {
        self.disconnects.fetch_add(1, Ordering::Relaxed);
    }
}

/// Snapshot of an [`AtomicMetrics`] recorder's counters at a single
/// instant. See [`AtomicMetrics::snapshot`] for the consistency
/// caveat (counter-level atomic but not cross-counter atomic).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AtomicMetricsSnapshot {
    pub queries_started: u64,
    pub queries_completed: u64,
    pub query_errors: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub connects: u64,
    pub disconnects: u64,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_metrics_is_silent() {
        let m = NoopMetrics;
        m.on_query_start("dpf", 0, 10);
        m.on_query_end("dpf", 0, 10, true);
        m.on_bytes_sent("dpf", 1024);
        m.on_bytes_received("dpf", 2048);
        m.on_connect("dpf", "wss://example");
        m.on_disconnect("dpf");
        // Nothing to assert — the point of NoopMetrics is that it
        // compiles and doesn't panic.
    }

    #[test]
    fn atomic_metrics_starts_at_zero() {
        let m = AtomicMetrics::new();
        assert_eq!(m.snapshot(), AtomicMetricsSnapshot::default());
    }

    #[test]
    fn atomic_metrics_counts_query_lifecycle() {
        let m = AtomicMetrics::new();
        m.on_query_start("dpf", 0, 10);
        m.on_query_end("dpf", 0, 10, true);
        m.on_query_start("dpf", 1, 5);
        m.on_query_end("dpf", 1, 5, false);

        let s = m.snapshot();
        assert_eq!(s.queries_started, 2);
        assert_eq!(s.queries_completed, 1);
        assert_eq!(s.query_errors, 1);
    }

    #[test]
    fn atomic_metrics_counts_bytes_and_frames() {
        let m = AtomicMetrics::new();
        m.on_bytes_sent("dpf", 100);
        m.on_bytes_sent("dpf", 200);
        m.on_bytes_received("dpf", 500);

        let s = m.snapshot();
        assert_eq!(s.bytes_sent, 300);
        assert_eq!(s.bytes_received, 500);
        assert_eq!(s.frames_sent, 2);
        assert_eq!(s.frames_received, 1);
    }

    #[test]
    fn atomic_metrics_counts_connect_disconnect() {
        let m = AtomicMetrics::new();
        m.on_connect("dpf", "wss://a");
        m.on_connect("dpf", "wss://b");
        m.on_disconnect("dpf");

        let s = m.snapshot();
        assert_eq!(s.connects, 2);
        assert_eq!(s.disconnects, 1);
    }

    /// A recorder installed behind `Arc<dyn PirMetrics>` still
    /// observes atomically — this is the actual usage shape (clients
    /// hold `Option<Arc<dyn PirMetrics>>`).
    #[test]
    fn atomic_metrics_through_dyn_trait_object() {
        use std::sync::Arc;
        let m = Arc::new(AtomicMetrics::new());
        let dyn_recorder: Arc<dyn PirMetrics> = m.clone();

        dyn_recorder.on_query_start("harmony", 3, 7);
        dyn_recorder.on_bytes_sent("harmony", 512);

        let s = m.snapshot();
        assert_eq!(s.queries_started, 1);
        assert_eq!(s.bytes_sent, 512);
    }

    /// Snapshot is `Copy` — users can freely diff `Instant t1 - t0`
    /// style without worrying about ownership.
    #[test]
    fn snapshot_is_copy() {
        let m = AtomicMetrics::new();
        m.on_connect("dpf", "wss://a");
        let a = m.snapshot();
        let b = a; // copy
        assert_eq!(a, b);
        assert_eq!(a.connects, 1);
    }

    /// Recording from multiple threads converges to the expected
    /// total — the whole point of using atomic counters.
    #[test]
    fn atomic_metrics_is_thread_safe() {
        use std::sync::Arc;
        use std::thread;

        let m = Arc::new(AtomicMetrics::new());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let m = m.clone();
                thread::spawn(move || {
                    for _ in 0..1000 {
                        m.on_bytes_sent("dpf", 1);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(m.snapshot().bytes_sent, 8 * 1000);
        assert_eq!(m.snapshot().frames_sent, 8 * 1000);
    }
}
