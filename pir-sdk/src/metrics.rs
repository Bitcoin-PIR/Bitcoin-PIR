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
//! # Latency tracking
//!
//! [`on_query_end`](PirMetrics::on_query_end) carries a [`Duration`]
//! measured by the client between matching `on_query_start` and
//! `on_query_end` calls. The clock source is [`Instant`] from the
//! [`web-time`](https://crates.io/crates/web-time) crate — a drop-in
//! `std::time::Instant` substitute that uses `performance.now()` on
//! `wasm32-unknown-unknown` (where `std::time::Instant` is not
//! available). Both [`Instant`] and [`Duration`] are re-exported at
//! the crate root so callers don't need their own `web-time` dep.
//!
//! Clients only capture an [`Instant`] when a recorder is installed
//! — when no recorder is present the timing path is fully optimized
//! out, preserving the "no recorder = zero overhead" property.
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
//! use pir_sdk::{AtomicMetrics, Duration, PirMetrics};
//!
//! let recorder = Arc::new(AtomicMetrics::new());
//!
//! // Imagine a `DpfClient` has fired a few callbacks here.
//! recorder.on_connect("dpf", "wss://server0");
//! recorder.on_bytes_sent("dpf", 1024);
//! recorder.on_bytes_received("dpf", 2048);
//! recorder.on_query_end("dpf", 0, 10, true, Duration::from_millis(42));
//!
//! let snap = recorder.snapshot();
//! assert_eq!(snap.connects, 1);
//! assert_eq!(snap.bytes_sent, 1024);
//! assert_eq!(snap.bytes_received, 2048);
//! assert_eq!(snap.queries_completed, 1);
//! assert_eq!(snap.query_errors, 0);
//! assert_eq!(snap.total_query_latency_micros, 42_000);
//! assert_eq!(snap.min_query_latency_micros, 42_000);
//! assert_eq!(snap.max_query_latency_micros, 42_000);
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

pub use web_time::{Duration, Instant};

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
    ///
    /// `success = true` means the client produced a well-formed
    /// `Vec<Option<QueryResult>>`; `false` means the batch errored
    /// (connection lost, server error, Merkle verification failure,
    /// etc.).
    ///
    /// `duration` is the wall-clock time between matching
    /// [`on_query_start`](Self::on_query_start) and `on_query_end`
    /// calls. Clients capture an [`Instant`] only when a recorder is
    /// installed (so the timing path is free for the
    /// no-recorder case). If a recorder is installed mid-query — i.e.
    /// after `on_query_start` would have fired but before
    /// `on_query_end` — the duration may be `Duration::ZERO`,
    /// signalling that the start instant was not captured. Recorders
    /// that aggregate latency should treat zero-duration entries as
    /// best-effort rather than precise measurements.
    fn on_query_end(
        &self,
        _backend: &'static str,
        _db_id: u8,
        _num_queries: usize,
        _success: bool,
        _duration: Duration,
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

/// Sentinel value stored in [`AtomicMetrics::min_query_latency_micros`]
/// when no completion has been recorded yet. Choosing `u64::MAX`
/// makes the lock-free `fetch_min` update branch-free: the first
/// real measurement always wins regardless of magnitude.
const MIN_LATENCY_SENTINEL: u64 = u64::MAX;

/// In-memory, lock-free metrics recorder backed by atomic counters.
///
/// This is the recommended default for callers that want "give me
/// numbers, I'll look at them later" without plugging in a full
/// observability stack. All counters are `u64` and monotonically
/// non-decreasing (with the exception of `min_query_latency_micros`,
/// which is monotonically non-increasing once any completion is
/// recorded — see [`Self::snapshot`] for sentinel semantics);
/// callers snapshot via [`snapshot`](Self::snapshot) and diff two
/// snapshots to get a rate.
///
/// Latency tracking lives alongside the counters: every successful
/// or failed call to [`on_query_end`](PirMetrics::on_query_end)
/// updates `total_query_latency_micros` (sum), `min_query_latency_micros`
/// (lock-free `fetch_min`), and `max_query_latency_micros` (lock-free
/// `fetch_max`). Compute mean = total / (queries_completed +
/// query_errors). For percentile estimation, install a custom
/// `PirMetrics` impl that maintains a histogram (e.g. via the
/// [`hdrhistogram`](https://crates.io/crates/hdrhistogram) crate).
#[derive(Debug)]
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
    /// Sum of all observed query durations, in microseconds. Combined
    /// with `queries_completed + query_errors` gives a running mean.
    total_query_latency_micros: AtomicU64,
    /// Smallest observed query duration. Initialized to
    /// [`MIN_LATENCY_SENTINEL`] (`u64::MAX`) so the first real
    /// measurement always wins via `fetch_min`. A snapshot reading
    /// this value as `u64::MAX` indicates no completions have been
    /// recorded yet.
    min_query_latency_micros: AtomicU64,
    /// Largest observed query duration, in microseconds.
    max_query_latency_micros: AtomicU64,
}

impl Default for AtomicMetrics {
    fn default() -> Self {
        // Hand-written `Default` because `AtomicU64::default()` is 0
        // but `min_query_latency_micros` needs to start at `u64::MAX`
        // for the lock-free `fetch_min` first-write logic to work.
        Self {
            queries_started: AtomicU64::new(0),
            queries_completed: AtomicU64::new(0),
            query_errors: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            frames_sent: AtomicU64::new(0),
            frames_received: AtomicU64::new(0),
            connects: AtomicU64::new(0),
            disconnects: AtomicU64::new(0),
            total_query_latency_micros: AtomicU64::new(0),
            min_query_latency_micros: AtomicU64::new(MIN_LATENCY_SENTINEL),
            max_query_latency_micros: AtomicU64::new(0),
        }
    }
}

impl AtomicMetrics {
    /// Create a new recorder with all counters zeroed (and
    /// `min_query_latency_micros` initialized to its sentinel).
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a snapshot of every counter. Individual counters are
    /// atomic, but the snapshot as a whole is NOT atomic — two
    /// counters may be observed at slightly different instants. For
    /// most diagnostic purposes this is fine; if you need a
    /// consistent cross-counter view, lock the recorder before
    /// reading (wrap it in a `Mutex` in your own code).
    ///
    /// Latency-snapshot semantics:
    /// - `total_query_latency_micros` and `max_query_latency_micros`
    ///   are 0 when no completions have been recorded.
    /// - `min_query_latency_micros` is `u64::MAX` (the sentinel) when
    ///   no completions have been recorded; otherwise it is the
    ///   smallest observed duration in microseconds. Use the helper
    ///   [`AtomicMetricsSnapshot::min_query_latency_micros_or_zero`]
    ///   if a normalized 0-when-empty value is preferable.
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
            total_query_latency_micros: self
                .total_query_latency_micros
                .load(Ordering::Relaxed),
            min_query_latency_micros: self.min_query_latency_micros.load(Ordering::Relaxed),
            max_query_latency_micros: self.max_query_latency_micros.load(Ordering::Relaxed),
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
        duration: Duration,
    ) {
        if success {
            self.queries_completed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.query_errors.fetch_add(1, Ordering::Relaxed);
        }

        // `as_micros() -> u128`; saturate to `u64` so multi-decade
        // measurements (>584,000 years) don't wrap. Real PIR queries
        // are milliseconds-to-seconds so this is purely defensive.
        let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);

        self.total_query_latency_micros
            .fetch_add(micros, Ordering::Relaxed);
        // `fetch_min` and `fetch_max` are stable on `AtomicU64` since
        // Rust 1.45; the lock-free CAS loop is internal to libstd.
        // Initial sentinel (`u64::MAX`) means the first measurement
        // always wins on `fetch_min`.
        self.min_query_latency_micros
            .fetch_min(micros, Ordering::Relaxed);
        self.max_query_latency_micros
            .fetch_max(micros, Ordering::Relaxed);
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Sum of every observed query duration in microseconds. Divide
    /// by `queries_completed + query_errors` for the running mean.
    pub total_query_latency_micros: u64,
    /// Smallest observed query duration in microseconds. `u64::MAX`
    /// when no completions have been recorded — see
    /// [`Self::min_query_latency_micros_or_zero`] for a normalized
    /// helper.
    pub min_query_latency_micros: u64,
    /// Largest observed query duration in microseconds. 0 when no
    /// completions have been recorded.
    pub max_query_latency_micros: u64,
}

impl Default for AtomicMetricsSnapshot {
    fn default() -> Self {
        // Mirrors `AtomicMetrics::default()` — `min_query_latency_micros`
        // starts at the sentinel so two snapshots from a fresh
        // recorder compare equal.
        Self {
            queries_started: 0,
            queries_completed: 0,
            query_errors: 0,
            bytes_sent: 0,
            bytes_received: 0,
            frames_sent: 0,
            frames_received: 0,
            connects: 0,
            disconnects: 0,
            total_query_latency_micros: 0,
            min_query_latency_micros: MIN_LATENCY_SENTINEL,
            max_query_latency_micros: 0,
        }
    }
}

impl AtomicMetricsSnapshot {
    /// Total observed query completions: `queries_completed +
    /// query_errors`. Useful as the denominator for mean-latency
    /// calculations.
    pub fn total_query_completions(&self) -> u64 {
        self.queries_completed + self.query_errors
    }

    /// Mean query latency in microseconds, or `None` if no
    /// completions have been recorded.
    pub fn mean_query_latency_micros(&self) -> Option<u64> {
        let n = self.total_query_completions();
        if n == 0 {
            None
        } else {
            Some(self.total_query_latency_micros / n)
        }
    }

    /// Returns the minimum observed query latency in microseconds,
    /// or 0 if no completions have been recorded. Convenience helper
    /// for callers that prefer a normalized 0-when-empty value over
    /// the raw sentinel.
    pub fn min_query_latency_micros_or_zero(&self) -> u64 {
        if self.min_query_latency_micros == MIN_LATENCY_SENTINEL {
            0
        } else {
            self.min_query_latency_micros
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_metrics_is_silent() {
        let m = NoopMetrics;
        m.on_query_start("dpf", 0, 10);
        m.on_query_end("dpf", 0, 10, true, Duration::from_millis(5));
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
        let s = m.snapshot();
        assert_eq!(s, AtomicMetricsSnapshot::default());
        // The min sentinel is what makes "no completions yet" detectable.
        assert_eq!(s.min_query_latency_micros, u64::MAX);
        assert_eq!(s.max_query_latency_micros, 0);
        assert_eq!(s.total_query_latency_micros, 0);
        assert_eq!(s.mean_query_latency_micros(), None);
        assert_eq!(s.min_query_latency_micros_or_zero(), 0);
    }

    #[test]
    fn atomic_metrics_counts_query_lifecycle() {
        let m = AtomicMetrics::new();
        m.on_query_start("dpf", 0, 10);
        m.on_query_end("dpf", 0, 10, true, Duration::from_millis(50));
        m.on_query_start("dpf", 1, 5);
        m.on_query_end("dpf", 1, 5, false, Duration::from_millis(20));

        let s = m.snapshot();
        assert_eq!(s.queries_started, 2);
        assert_eq!(s.queries_completed, 1);
        assert_eq!(s.query_errors, 1);
        assert_eq!(s.total_query_completions(), 2);
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

    // ─── Latency-tracking tests ─────────────────────────────────────────────

    /// Single completion sets all three latency counters to the
    /// observed value — `total`, `min`, and `max` all match.
    #[test]
    fn atomic_metrics_records_first_latency() {
        let m = AtomicMetrics::new();
        m.on_query_end("dpf", 0, 10, true, Duration::from_millis(42));

        let s = m.snapshot();
        assert_eq!(s.total_query_latency_micros, 42_000);
        assert_eq!(s.min_query_latency_micros, 42_000);
        assert_eq!(s.max_query_latency_micros, 42_000);
        assert_eq!(s.mean_query_latency_micros(), Some(42_000));
    }

    /// Several completions: `total` sums, `min` tracks smallest,
    /// `max` tracks largest, mean works.
    #[test]
    fn atomic_metrics_tracks_min_max_total() {
        let m = AtomicMetrics::new();
        m.on_query_end("dpf", 0, 10, true, Duration::from_millis(50));
        m.on_query_end("dpf", 0, 10, true, Duration::from_millis(20));
        m.on_query_end("dpf", 0, 10, true, Duration::from_millis(80));
        m.on_query_end("dpf", 0, 10, false, Duration::from_millis(10));

        let s = m.snapshot();
        assert_eq!(s.queries_completed, 3);
        assert_eq!(s.query_errors, 1);
        assert_eq!(s.total_query_latency_micros, 160_000);
        assert_eq!(s.min_query_latency_micros, 10_000);
        assert_eq!(s.max_query_latency_micros, 80_000);
        assert_eq!(s.mean_query_latency_micros(), Some(40_000));
    }

    /// `Duration::ZERO` is a valid (and meaningful) observation — it
    /// signals the client didn't have a recorder installed at
    /// `on_query_start` time. Recording it should still increment
    /// completions but leaves min at zero.
    #[test]
    fn atomic_metrics_handles_zero_duration() {
        let m = AtomicMetrics::new();
        m.on_query_end("dpf", 0, 10, true, Duration::ZERO);

        let s = m.snapshot();
        assert_eq!(s.queries_completed, 1);
        assert_eq!(s.total_query_latency_micros, 0);
        assert_eq!(s.min_query_latency_micros, 0);
        assert_eq!(s.max_query_latency_micros, 0);
        // Mean exists (1 completion, 0 micros) — distinct from "no
        // completions" which would be `None`.
        assert_eq!(s.mean_query_latency_micros(), Some(0));
    }

    /// `min_query_latency_micros` stays at the sentinel until the
    /// first completion fires.
    #[test]
    fn atomic_metrics_min_sentinel_until_first_completion() {
        let m = AtomicMetrics::new();
        // Pre-completion: only `on_query_start` and bytes — no
        // `on_query_end`.
        m.on_query_start("dpf", 0, 10);
        m.on_bytes_sent("dpf", 1024);

        let s = m.snapshot();
        assert_eq!(s.queries_started, 1);
        assert_eq!(s.bytes_sent, 1024);
        assert_eq!(s.min_query_latency_micros, u64::MAX);
        assert_eq!(s.max_query_latency_micros, 0);

        // First completion replaces the sentinel.
        m.on_query_end("dpf", 0, 10, true, Duration::from_millis(7));
        let s = m.snapshot();
        assert_eq!(s.min_query_latency_micros, 7_000);
        assert_eq!(s.max_query_latency_micros, 7_000);
    }

    /// `min_query_latency_micros_or_zero` normalizes the sentinel
    /// for callers that prefer 0-when-empty. Once a real value is
    /// recorded the helper returns it unchanged.
    #[test]
    fn min_or_zero_helper_normalizes_sentinel() {
        let m = AtomicMetrics::new();
        assert_eq!(m.snapshot().min_query_latency_micros_or_zero(), 0);

        m.on_query_end("dpf", 0, 10, true, Duration::from_millis(3));
        assert_eq!(m.snapshot().min_query_latency_micros_or_zero(), 3_000);
    }

    /// Latency counters are atomic across threads — concurrent
    /// `on_query_end` from many threads converges to a deterministic
    /// total.
    #[test]
    fn atomic_metrics_latency_thread_safe() {
        use std::sync::Arc;
        use std::thread;

        let m = Arc::new(AtomicMetrics::new());
        let threads: Vec<_> = (0..8)
            .map(|tid| {
                let m = m.clone();
                thread::spawn(move || {
                    for i in 0..100 {
                        // Mix in tid so durations vary across threads
                        // and the min/max race is meaningful.
                        let micros = (tid as u64 * 1000) + i as u64 + 1;
                        m.on_query_end(
                            "dpf",
                            0,
                            10,
                            true,
                            Duration::from_micros(micros),
                        );
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let s = m.snapshot();
        // 8 threads × 100 completions = 800 successes
        assert_eq!(s.queries_completed, 800);
        assert_eq!(s.query_errors, 0);
        // Smallest possible: tid=0, i=0 → 0*1000 + 0 + 1 = 1
        assert_eq!(s.min_query_latency_micros, 1);
        // Largest possible: tid=7, i=99 → 7*1000 + 99 + 1 = 7100
        assert_eq!(s.max_query_latency_micros, 7100);
        // Sum of 1..=100 plus tid offsets:
        // = sum_{tid=0..8} sum_{i=0..100} (tid*1000 + i + 1)
        // = sum_{tid=0..8} (100*tid*1000 + sum_{i=1..=100} i)
        // = sum_{tid=0..8} (100_000*tid + 5050)
        // = 100_000 * (0+1+2+3+4+5+6+7) + 8*5050
        // = 100_000 * 28 + 40_400
        // = 2_840_400
        assert_eq!(s.total_query_latency_micros, 2_840_400);
    }

    /// Saturation: a `Duration` larger than `u64::MAX` microseconds
    /// (i.e. >584,000 years) saturates instead of wrapping. Real PIR
    /// queries never approach this, but the saturation is cheap
    /// defensive coding against a runaway clock.
    #[test]
    fn atomic_metrics_saturates_on_huge_duration() {
        let m = AtomicMetrics::new();
        // u128::MAX micros >> u64::MAX; the conversion saturates.
        m.on_query_end(
            "dpf",
            0,
            10,
            true,
            Duration::new(u64::MAX, 999_999_999),
        );
        let s = m.snapshot();
        assert_eq!(s.max_query_latency_micros, u64::MAX);
    }
}
