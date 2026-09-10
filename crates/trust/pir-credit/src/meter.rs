//! Hourly per-opcode aggregates of what a server actually spent.
//!
//! Servers log one line per (opcode, database) per interval with counts
//! and means only: no per-request lines, no client identifiers, no query
//! contents. The line is how pir2 (which cannot be sampled from outside)
//! reports its costs and how the calibration in [`crate::gas`] is checked
//! against production over time.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// One finished request as the meter sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeterSample {
    pub variant: u8,
    pub db_id: u8,
    /// Gas the frame was priced at (work + base fee + egress), 0 when the
    /// frame is unmetered.
    pub gas: u64,
    /// Process CPU time consumed while the request was in flight (all
    /// threads; inflated by concurrent requests, see `inflight_max`).
    pub cpu: Duration,
    pub wall: Duration,
    pub egress_bytes: u64,
    /// Requests in flight, this one included, when it started.
    pub in_flight: usize,
}

#[derive(Default)]
struct Bucket {
    n: u64,
    gas: u64,
    cpu: Duration,
    wall: Duration,
    egress: u64,
    max_in_flight: usize,
}

/// Aggregates samples per (opcode, database) and renders them once per
/// interval.
pub struct MeterWindow {
    interval: Duration,
    started: Instant,
    buckets: BTreeMap<(u8, u8), Bucket>,
}

impl MeterWindow {
    pub fn new(interval: Duration, now: Instant) -> Self {
        Self {
            interval,
            started: now,
            buckets: BTreeMap::new(),
        }
    }

    pub fn record(&mut self, sample: MeterSample) {
        let bucket = self
            .buckets
            .entry((sample.variant, sample.db_id))
            .or_default();
        bucket.n += 1;
        bucket.gas = bucket.gas.saturating_add(sample.gas);
        bucket.cpu += sample.cpu;
        bucket.wall += sample.wall;
        bucket.egress = bucket.egress.saturating_add(sample.egress_bytes);
        bucket.max_in_flight = bucket.max_in_flight.max(sample.in_flight);
    }

    /// The report lines once `interval` has passed (one per bucket with
    /// samples, then one total line), and a fresh window; `None` before.
    pub fn due(&mut self, now: Instant) -> Option<Vec<String>> {
        if now.saturating_duration_since(self.started) < self.interval {
            return None;
        }
        let secs = self.interval.as_secs();
        let mut lines = Vec::with_capacity(self.buckets.len() + 1);
        let (mut frames, mut gas_total, mut cpu_total) = (0u64, 0u64, Duration::ZERO);
        for ((variant, db_id), bucket) in &self.buckets {
            if bucket.n == 0 {
                continue;
            }
            frames += bucket.n;
            gas_total = gas_total.saturating_add(bucket.gas);
            cpu_total += bucket.cpu;
            let n = bucket.n as f64;
            lines.push(format!(
                "[meter op=0x{variant:02x} db={db_id}] last {secs}s: n={} gas_mean={} cpu_mean_ms={:.0} wall_mean_ms={:.0} egress_mean_kib={:.0} inflight_max={}",
                bucket.n,
                bucket.gas / bucket.n,
                bucket.cpu.as_secs_f64() * 1e3 / n,
                bucket.wall.as_secs_f64() * 1e3 / n,
                bucket.egress as f64 / 1024.0 / n,
                bucket.max_in_flight,
            ));
        }
        lines.push(format!(
            "[meter] last {secs}s: frames={frames} gas_total={gas_total} cpu_total_s={:.1}",
            cpu_total.as_secs_f64()
        ));
        self.started = now;
        self.buckets.clear();
        Some(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(variant: u8, gas: u64, cpu_ms: u64, egress: u64, in_flight: usize) -> MeterSample {
        MeterSample {
            variant,
            db_id: 0,
            gas,
            cpu: Duration::from_millis(cpu_ms),
            wall: Duration::from_millis(cpu_ms / 10),
            egress_bytes: egress,
            in_flight,
        }
    }

    #[test]
    fn reports_means_per_opcode_once_per_interval_then_resets() {
        let t0 = Instant::now();
        let mut w = MeterWindow::new(Duration::from_secs(3600), t0);
        assert!(w.due(t0 + Duration::from_secs(3599)).is_none());
        w.record(sample(0x11, 1_400, 1_350, 8_192, 1));
        w.record(sample(0x11, 1_400, 1_410, 8_192, 2));
        w.record(sample(0x21, 4_570, 4_600, 40_960, 2));
        let lines = w.due(t0 + Duration::from_secs(3600)).unwrap();
        assert_eq!(
            lines,
            vec![
                "[meter op=0x11 db=0] last 3600s: n=2 gas_mean=1400 cpu_mean_ms=1380 wall_mean_ms=138 egress_mean_kib=8 inflight_max=2".to_owned(),
                "[meter op=0x21 db=0] last 3600s: n=1 gas_mean=4570 cpu_mean_ms=4600 wall_mean_ms=460 egress_mean_kib=40 inflight_max=2".to_owned(),
                "[meter] last 3600s: frames=3 gas_total=7370 cpu_total_s=7.4".to_owned(),
            ]
        );
        // The window restarted: nothing is due for another hour, and an
        // empty window still prints its total line so the heartbeat exists.
        assert!(w.due(t0 + Duration::from_secs(7199)).is_none());
        assert_eq!(
            w.due(t0 + Duration::from_secs(7200)).unwrap(),
            vec!["[meter] last 3600s: frames=0 gas_total=0 cpu_total_s=0.0".to_owned()]
        );
    }

    #[test]
    fn samples_never_carry_per_request_identity() {
        // The sample type is the whole interface: opcode, database, and
        // four numbers. No peer, connection id, or query field exists.
        let s = sample(0x60, 22, 3, 100, 1);
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("peer"));
        assert!(!rendered.contains("client"));
    }
}
