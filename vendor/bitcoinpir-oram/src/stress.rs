//! Metadata-only stress simulator for the planned Circuit ORAM controller.
//!
//! The simulator tracks logical block ids, leaf labels, tree occupancy, stash
//! occupancy, and public eviction debt. It intentionally does not store payload
//! bytes, so it can exercise BitcoinPIR-sized INDEX/CHUNK tables quickly before
//! the production controller exists.

use crate::{CircuitEvictionSchedule, Error, OramParams, Result};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const EMPTY_BLOCK: u32 = u32::MAX;

/// Public access pattern used by the stress simulator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitStressPattern {
    /// Uniform random logical ids.
    Random,
    /// `0, 1, ..., N - 1, 0, ...`.
    RoundRobin,
}

impl CircuitStressPattern {
    /// Lowercase label for machine-readable output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Random => "random",
            Self::RoundRobin => "round_robin",
        }
    }
}

/// Configuration for one Circuit ORAM stress run.
#[derive(Clone, Debug)]
pub struct CircuitStressConfig {
    /// ORAM tree and stash sizing parameters.
    pub params: OramParams,
    /// Measured real accesses.
    pub ops: usize,
    /// Warm-up accesses excluded from reported stash percentiles.
    pub warmup_ops: usize,
    /// Public logical-id sequence.
    pub pattern: CircuitStressPattern,
    /// RNG seed used for leaf remapping and random queries.
    pub seed: [u8; 32],
    /// Public eviction paths drained after every real access.
    pub drain_per_access: u64,
    /// Optional public burst interval. Zero disables burst draining.
    pub burst_interval: usize,
    /// Public eviction paths drained when `burst_interval` fires.
    pub burst_budget: u64,
    /// Optional public maximum eviction debt. When exceeded, request admission
    /// waits while the simulator drains public eviction paths down to this cap.
    pub max_debt: Option<u64>,
}

/// Summary for one Circuit ORAM stress run.
#[derive(Clone, Debug)]
pub struct CircuitStressReport {
    /// Logical ORAM blocks.
    pub logical_blocks: usize,
    /// ORAM leaves.
    pub leaves: usize,
    /// Tree height including root and leaf levels.
    pub height: usize,
    /// Slots per bucket.
    pub bucket_size: usize,
    /// Configured stash capacity.
    pub stash_capacity: usize,
    /// Physical tree slots.
    pub tree_slots: usize,
    /// Physical tree slot load before counting stash.
    pub tree_slot_load_percent: f64,
    /// Stash occupancy after trusted initialization.
    pub init_stash: usize,
    /// Stash occupancy at the end of the run.
    pub final_stash: usize,
    /// Maximum observed stash occupancy in measured samples.
    pub max_stash: usize,
    /// Average stash occupancy in measured samples.
    pub avg_stash: f64,
    /// Median stash occupancy.
    pub p50_stash: usize,
    /// 99th percentile stash occupancy.
    pub p99_stash: usize,
    /// 99.9th percentile stash occupancy.
    pub p999_stash: usize,
    /// Number of measured samples over `params.stash_capacity`.
    pub overflow_samples: usize,
    /// Number of real accesses used for warm-up.
    pub warmup_ops: usize,
    /// Number of measured real accesses.
    pub ops: usize,
    /// Public access pattern.
    pub pattern: CircuitStressPattern,
    /// Eviction paths scheduled per access.
    pub evictions_per_access: u64,
    /// Public eviction paths drained after each access.
    pub drain_per_access: u64,
    /// Public burst interval.
    pub burst_interval: usize,
    /// Public burst drain budget.
    pub burst_budget: u64,
    /// Public maximum eviction debt cap.
    pub max_debt_cap: Option<u64>,
    /// Maximum observed pending public eviction debt.
    pub max_eviction_debt: u64,
    /// Final pending public eviction debt.
    pub final_eviction_debt: u64,
    /// Completed public eviction paths.
    pub completed_evictions: u64,
    /// Scheduled public eviction paths.
    pub scheduled_evictions: u64,
    /// Metadata path scans per measured access, amortized.
    pub metadata_path_scans_per_access: f64,
    /// Payload path scans per measured access, amortized.
    pub payload_path_scans_per_access: f64,
}

/// Run a metadata-only Circuit ORAM stress simulation.
pub fn stress_circuit(config: CircuitStressConfig) -> Result<CircuitStressReport> {
    validate_config(&config)?;
    let mut sim = CircuitStressSim::new(config.params.clone(), config.seed)?;
    let mut schedule = CircuitEvictionSchedule::new(&config.params);
    let mut rng = ChaCha20Rng::from_seed(config.seed);
    let mut samples = Vec::with_capacity(config.ops);
    let mut overflow_samples = 0usize;
    let mut max_debt = schedule.pending_evictions()?;
    let mut metadata_path_scans = 0u64;
    let mut payload_path_scans = 0u64;
    let total_ops = config.warmup_ops + config.ops;

    for step in 0..total_ops {
        let measured_step = step >= config.warmup_ops;
        let logical_id =
            next_logical_id(config.pattern, step, config.params.logical_blocks, &mut rng);
        sim.access(logical_id, &mut rng)?;
        schedule.record_access()?;
        if measured_step {
            metadata_path_scans += 1;
            payload_path_scans += 1;
        }

        let drained = drain_public_evictions(&mut sim, &mut schedule, config.drain_per_access)?;
        if measured_step {
            metadata_path_scans += drained * 2;
            payload_path_scans += drained;
        }

        if config.burst_interval != 0 && (step + 1) % config.burst_interval == 0 {
            let drained = drain_public_evictions(&mut sim, &mut schedule, config.burst_budget)?;
            if measured_step {
                metadata_path_scans += drained * 2;
                payload_path_scans += drained;
            }
        }

        if let Some(max_debt_cap) = config.max_debt {
            while schedule.pending_evictions()? > max_debt_cap {
                let drained = drain_public_evictions(&mut sim, &mut schedule, 1)?;
                if measured_step {
                    metadata_path_scans += drained * 2;
                    payload_path_scans += drained;
                }
            }
        }

        max_debt = max_debt.max(schedule.pending_evictions()?);

        if step >= config.warmup_ops {
            let stash_len = sim.stash_len();
            if stash_len > config.params.stash_capacity {
                overflow_samples += 1;
            }
            samples.push(stash_len);
        }
    }

    let stats = StashStats::from_samples(samples);
    let final_debt = schedule.pending_evictions()?;
    let scheduled_evictions = schedule
        .issued_accesses()
        .checked_mul(schedule.evictions_per_access())
        .ok_or_else(|| Error::InvalidInput("eviction counter overflow".into()))?;
    let measured_ops = config.ops.max(1) as f64;

    Ok(CircuitStressReport {
        logical_blocks: config.params.logical_blocks,
        leaves: config.params.leaves,
        height: config.params.height(),
        bucket_size: config.params.bucket_size,
        stash_capacity: config.params.stash_capacity,
        tree_slots: sim.tree_slots(),
        tree_slot_load_percent: config.params.logical_blocks as f64 * 100.0
            / sim.tree_slots() as f64,
        init_stash: sim.init_stash,
        final_stash: sim.stash_len(),
        max_stash: stats.max,
        avg_stash: stats.avg,
        p50_stash: stats.p50,
        p99_stash: stats.p99,
        p999_stash: stats.p999,
        overflow_samples,
        warmup_ops: config.warmup_ops,
        ops: config.ops,
        pattern: config.pattern,
        evictions_per_access: schedule.evictions_per_access(),
        drain_per_access: config.drain_per_access,
        burst_interval: config.burst_interval,
        burst_budget: config.burst_budget,
        max_debt_cap: config.max_debt,
        max_eviction_debt: max_debt,
        final_eviction_debt: final_debt,
        completed_evictions: schedule.completed_evictions(),
        scheduled_evictions,
        metadata_path_scans_per_access: metadata_path_scans as f64 / measured_ops,
        payload_path_scans_per_access: payload_path_scans as f64 / measured_ops,
    })
}

fn validate_config(config: &CircuitStressConfig) -> Result<()> {
    if config.params.logical_blocks > u32::MAX as usize {
        return Err(Error::InvalidParams(
            "stress simulator supports at most u32::MAX logical blocks".into(),
        ));
    }
    let tree_slots = config
        .params
        .bucket_count()
        .checked_mul(config.params.bucket_size)
        .ok_or_else(|| Error::InvalidParams("tree slot count overflow".into()))?;
    if config.params.logical_blocks > tree_slots {
        return Err(Error::InvalidParams(format!(
            "logical blocks {} exceed physical tree slots {}",
            config.params.logical_blocks, tree_slots
        )));
    }
    if config.burst_interval == 0 && config.burst_budget != 0 {
        return Err(Error::InvalidParams(
            "burst_budget requires burst_interval > 0".into(),
        ));
    }
    Ok(())
}

fn drain_public_evictions(
    sim: &mut CircuitStressSim,
    schedule: &mut CircuitEvictionSchedule,
    budget: u64,
) -> Result<u64> {
    let mut drained = 0u64;
    for _ in 0..budget {
        match schedule.complete_one_eviction()? {
            Some(leaf) => {
                sim.evict_path(leaf)?;
                drained += 1;
            }
            None => break,
        }
    }
    Ok(drained)
}

fn next_logical_id(
    pattern: CircuitStressPattern,
    step: usize,
    logical_blocks: usize,
    rng: &mut ChaCha20Rng,
) -> u32 {
    match pattern {
        CircuitStressPattern::Random => (rng.next_u64() % logical_blocks as u64) as u32,
        CircuitStressPattern::RoundRobin => (step % logical_blocks) as u32,
    }
}

#[derive(Clone, Copy, Debug)]
struct SimBlock {
    id: u32,
    leaf: u32,
}

struct CircuitStressSim {
    params: OramParams,
    slots: Vec<u32>,
    position_map: Vec<u32>,
    stash: Vec<SimBlock>,
    init_stash: usize,
}

impl CircuitStressSim {
    fn new(params: OramParams, seed: [u8; 32]) -> Result<Self> {
        let tree_slots = params
            .bucket_count()
            .checked_mul(params.bucket_size)
            .ok_or_else(|| Error::InvalidParams("tree slot count overflow".into()))?;
        let mut sim = Self {
            position_map: Vec::with_capacity(params.logical_blocks),
            slots: vec![EMPTY_BLOCK; tree_slots],
            stash: Vec::new(),
            init_stash: 0,
            params,
        };
        let mut rng = ChaCha20Rng::from_seed(seed);
        for logical_id in 0..sim.params.logical_blocks {
            let leaf = sim.random_leaf(&mut rng);
            sim.position_map.push(leaf);
            sim.place_or_stash(SimBlock {
                id: logical_id as u32,
                leaf,
            });
        }
        sim.init_stash = sim.stash.len();
        Ok(sim)
    }

    fn access(&mut self, logical_id: u32, rng: &mut ChaCha20Rng) -> Result<()> {
        let old_leaf = self.position_map[logical_id as usize];
        let mut block = self
            .remove_from_path(logical_id, old_leaf)
            .or_else(|| self.remove_from_stash(logical_id))
            .ok_or(Error::BlockNotFound(logical_id as u64))?;
        block.leaf = self.random_leaf(rng);
        self.position_map[logical_id as usize] = block.leaf;
        self.stash.push(block);
        Ok(())
    }

    fn evict_path(&mut self, leaf: u32) -> Result<()> {
        self.read_path_into_stash(leaf);
        self.write_path_from_stash(leaf);
        Ok(())
    }

    fn stash_len(&self) -> usize {
        self.stash.len()
    }

    fn tree_slots(&self) -> usize {
        self.slots.len()
    }

    fn random_leaf(&self, rng: &mut ChaCha20Rng) -> u32 {
        let mask = self.params.leaves as u32 - 1;
        rng.next_u32() & mask
    }

    fn place_or_stash(&mut self, block: SimBlock) {
        if !self.place_deepest(block) {
            self.stash.push(block);
        }
    }

    fn place_deepest(&mut self, block: SimBlock) -> bool {
        for depth in (0..self.params.height()).rev() {
            let node_idx = self.params.node_index(depth, block.leaf);
            let base = self.bucket_base(node_idx);
            for slot in &mut self.slots[base..base + self.params.bucket_size] {
                if *slot == EMPTY_BLOCK {
                    *slot = block.id;
                    return true;
                }
            }
        }
        false
    }

    fn remove_from_path(&mut self, logical_id: u32, leaf: u32) -> Option<SimBlock> {
        for depth in 0..self.params.height() {
            let node_idx = self.params.node_index(depth, leaf);
            let base = self.bucket_base(node_idx);
            for slot in &mut self.slots[base..base + self.params.bucket_size] {
                if *slot == logical_id {
                    *slot = EMPTY_BLOCK;
                    return Some(SimBlock {
                        id: logical_id,
                        leaf,
                    });
                }
            }
        }
        None
    }

    fn remove_from_stash(&mut self, logical_id: u32) -> Option<SimBlock> {
        self.stash
            .iter()
            .position(|block| block.id == logical_id)
            .map(|idx| self.stash.swap_remove(idx))
    }

    fn read_path_into_stash(&mut self, leaf: u32) {
        for depth in 0..self.params.height() {
            let node_idx = self.params.node_index(depth, leaf);
            let base = self.bucket_base(node_idx);
            for slot in &mut self.slots[base..base + self.params.bucket_size] {
                if *slot != EMPTY_BLOCK {
                    let id = *slot;
                    *slot = EMPTY_BLOCK;
                    self.stash.push(SimBlock {
                        id,
                        leaf: self.position_map[id as usize],
                    });
                }
            }
        }
    }

    fn write_path_from_stash(&mut self, leaf: u32) {
        for depth in (0..self.params.height()).rev() {
            let node_idx = self.params.node_index(depth, leaf);
            let base = self.bucket_base(node_idx);
            for slot_idx in base..base + self.params.bucket_size {
                if self.slots[slot_idx] != EMPTY_BLOCK {
                    continue;
                }
                if let Some(stash_idx) = self
                    .stash
                    .iter()
                    .position(|block| self.params.node_contains_leaf(depth, node_idx, block.leaf))
                {
                    let block = self.stash.swap_remove(stash_idx);
                    self.slots[slot_idx] = block.id;
                }
            }
        }
    }

    fn bucket_base(&self, node_idx: usize) -> usize {
        node_idx * self.params.bucket_size
    }
}

struct StashStats {
    max: usize,
    avg: f64,
    p50: usize,
    p99: usize,
    p999: usize,
}

impl StashStats {
    fn from_samples(mut samples: Vec<usize>) -> Self {
        if samples.is_empty() {
            return Self {
                max: 0,
                avg: 0.0,
                p50: 0,
                p99: 0,
                p999: 0,
            };
        }
        let sum = samples.iter().copied().sum::<usize>();
        samples.sort_unstable();
        let max = *samples.last().expect("not empty");
        Self {
            max,
            avg: sum as f64 / samples.len() as f64,
            p50: percentile(&samples, 500, 1000),
            p99: percentile(&samples, 990, 1000),
            p999: percentile(&samples, 999, 1000),
        }
    }
}

fn percentile(sorted_samples: &[usize], numerator: usize, denominator: usize) -> usize {
    debug_assert!(!sorted_samples.is_empty());
    debug_assert!(numerator <= denominator);
    let len = sorted_samples.len();
    let rank = (len * numerator).div_ceil(denominator).max(1);
    sorted_samples[rank - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(pattern: CircuitStressPattern) -> CircuitStressConfig {
        CircuitStressConfig {
            params: OramParams::with_leaves(256, 32, 128)
                .unwrap()
                .with_bucket_size(2)
                .unwrap()
                .with_stash_capacity(128)
                .unwrap(),
            ops: 1000,
            warmup_ops: 100,
            pattern,
            seed: [5; 32],
            drain_per_access: 2,
            burst_interval: 0,
            burst_budget: 0,
            max_debt: None,
        }
    }

    #[test]
    fn random_stress_run_completes() {
        let report = stress_circuit(config(CircuitStressPattern::Random)).unwrap();

        assert_eq!(report.logical_blocks, 256);
        assert_eq!(report.ops, 1000);
        assert_eq!(report.final_eviction_debt, 0);
        assert_eq!(report.completed_evictions, 2200);
        assert!(report.max_stash <= 128);
    }

    #[test]
    fn round_robin_stress_run_completes() {
        let report = stress_circuit(config(CircuitStressPattern::RoundRobin)).unwrap();

        assert_eq!(report.pattern, CircuitStressPattern::RoundRobin);
        assert_eq!(report.overflow_samples, 0);
    }

    #[test]
    fn delayed_public_eviction_accumulates_bounded_debt() {
        let mut cfg = config(CircuitStressPattern::Random);
        cfg.drain_per_access = 0;
        cfg.max_debt = Some(16);
        let report = stress_circuit(cfg).unwrap();

        assert!(report.max_eviction_debt <= 16);
        assert!(report.completed_evictions > 0);
    }

    #[test]
    fn overfull_tree_is_rejected() {
        let mut cfg = config(CircuitStressPattern::Random);
        cfg.params = OramParams::with_leaves(64, 32, 16)
            .unwrap()
            .with_bucket_size(2)
            .unwrap()
            .with_stash_capacity(128)
            .unwrap();

        assert!(matches!(
            stress_circuit(cfg).unwrap_err(),
            Error::InvalidParams(_)
        ));
    }
}
