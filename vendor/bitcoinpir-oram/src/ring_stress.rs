//! Metadata-only Ring ORAM stress simulator over BitcoinPIR-shaped arrays.
//!
//! This module intentionally stops before a disk-backed Ring ORAM controller.
//! It tracks the state needed to answer the first experiment-plan questions:
//! tree/stash pressure, public eviction period, early reshuffle pressure, and
//! coarse IO estimates for current bucket-page storage versus a future
//! slot-addressable layout.

use crate::{circuit_meta_page_bytes, Error, OramBlock, OramParams, Result, AEAD_OVERHEAD};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::stress::CircuitStressPattern;

const EMPTY_BLOCK: u32 = u32::MAX;
const READ_COUNTER_BYTES: usize = 4;
const PERMUTATION_INDEX_BYTES: usize = 2;

/// Configuration for one metadata-only Ring ORAM stress run.
#[derive(Clone, Debug)]
pub struct RingStressConfig {
    /// ORAM tree and real-slot sizing. `bucket_size` is Ring ORAM's `Z`.
    pub params: OramParams,
    /// Reserved dummy slots per bucket. This is Ring ORAM's `S`.
    pub dummy_slots: usize,
    /// Real accesses included in reported stash percentiles.
    pub ops: usize,
    /// Warm-up accesses excluded from reported stash percentiles.
    pub warmup_ops: usize,
    /// Logical-id sequence.
    pub pattern: CircuitStressPattern,
    /// RNG seed used for leaf remapping and random queries.
    pub seed: [u8; 32],
    /// Public eviction period `A`: one EvictPath after every `A` accesses.
    pub eviction_period: usize,
    /// Public top ORAM tree levels cached in trusted memory.
    pub cache_levels: usize,
    /// Include tiered Merkle hash-store IO estimates.
    pub auth_store: bool,
    /// Trusted Merkle top levels kept in state when `auth_store` is enabled.
    pub auth_trusted_levels: usize,
    /// Plaintext hash-store page size for auth IO estimates.
    pub auth_hash_page_size: usize,
}

/// Summary for one metadata-only Ring ORAM stress run.
#[derive(Clone, Debug)]
pub struct RingStressReport {
    /// Logical ORAM blocks.
    pub logical_blocks: usize,
    /// ORAM leaves.
    pub leaves: usize,
    /// Tree height including root and leaf levels.
    pub height: usize,
    /// Real slots per bucket, Ring ORAM `Z`.
    pub bucket_size: usize,
    /// Dummy slots per bucket, Ring ORAM `S`.
    pub dummy_slots: usize,
    /// Real plus dummy slots per bucket.
    pub total_slots_per_bucket: usize,
    /// Configured stash capacity.
    pub stash_capacity: usize,
    /// Physical tree buckets.
    pub tree_buckets: usize,
    /// Physical real slots across all buckets.
    pub real_tree_slots: usize,
    /// Physical real plus dummy slots across all buckets.
    pub total_tree_slots: usize,
    /// Real-slot load, ignoring dummy slots.
    pub real_tree_slot_load_percent: f64,
    /// Total-slot load, counting dummy slots.
    pub total_tree_slot_load_percent: f64,
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
    /// Warm-up accesses.
    pub warmup_ops: usize,
    /// Measured real accesses.
    pub ops: usize,
    /// Access pattern.
    pub pattern: CircuitStressPattern,
    /// Public eviction period `A`.
    pub eviction_period: usize,
    /// Total completed public eviction paths, including warm-up.
    pub completed_evictions: u64,
    /// Completed public eviction paths during measured accesses.
    pub measured_evictions: u64,
    /// Total early-reshuffled buckets, including warm-up.
    pub early_reshuffle_buckets: u64,
    /// Early-reshuffled buckets during measured accesses.
    pub measured_early_reshuffle_buckets: u64,
    /// Measured early reshuffles that hit uncached buckets.
    pub measured_uncached_early_reshuffle_buckets: u64,
    /// Maximum observed per-bucket read counter.
    pub max_read_counter: u32,
    /// Effective cached tree levels.
    pub cache_levels: usize,
    /// Uncached path buckets per root-to-leaf path.
    pub uncached_levels: usize,
    /// Whether auth-store estimates were included.
    pub auth_store: bool,
    /// Merkle trusted top levels used for auth-store estimates.
    pub auth_trusted_levels: usize,
    /// Merkle hash-store page size used for auth-store estimates.
    pub auth_hash_page_size: usize,
    /// IO estimate for the measured portion of the run.
    pub io: RingIoEstimate,
    /// Crash-state inventory estimate.
    pub crash_state: RingCrashStateEstimate,
}

/// Coarse IO estimate derived from a Ring ORAM metadata run.
#[derive(Clone, Debug)]
pub struct RingIoEstimate {
    /// Metadata page bytes per bucket.
    pub meta_page_plaintext_bytes: usize,
    /// Current page-store payload page bytes per bucket.
    pub current_payload_page_plaintext_bytes: usize,
    /// Slot-addressable payload bytes per slot.
    pub slot_payload_plaintext_bytes: usize,
    /// Current page-store primary data-page reads per measured access.
    pub current_primary_page_reads_per_access: f64,
    /// Current page-store primary data-page writes per measured access.
    pub current_primary_page_writes_per_access: f64,
    /// Current page-store primary data-page touches per measured access.
    pub current_primary_page_touches_per_access: f64,
    /// Current page-store primary plaintext bytes per measured access.
    pub current_primary_plaintext_bytes_per_access: f64,
    /// Current page-store AEAD-sized bytes per measured access.
    pub current_primary_aead_bytes_per_access: f64,
    /// Current page-store auth hash-page touches per measured access.
    pub current_auth_hash_page_touches_per_access: f64,
    /// Current page-store auth hash bytes per measured access.
    pub current_auth_hash_bytes_per_access: f64,
    /// Current page-store total estimated backing bytes per measured access.
    pub current_total_backing_bytes_per_access: f64,
    /// Slot-addressable metadata page touches per measured access.
    pub slot_metadata_page_touches_per_access: f64,
    /// Slot-addressable payload slot reads per measured access.
    pub slot_payload_reads_per_access: f64,
    /// Slot-addressable payload slot writes per measured access.
    pub slot_payload_writes_per_access: f64,
    /// Slot-addressable payload plaintext bytes per measured access.
    pub slot_payload_plaintext_bytes_per_access: f64,
    /// Slot-addressable payload AEAD-sized bytes per measured access.
    pub slot_payload_aead_bytes_per_access: f64,
    /// Slot-addressable auth hash-page touches per measured access.
    pub slot_auth_hash_page_touches_per_access: f64,
    /// Slot-addressable auth hash bytes per measured access.
    pub slot_auth_hash_bytes_per_access: f64,
    /// Slot-addressable total estimated backing bytes per measured access.
    pub slot_total_backing_bytes_per_access: f64,
}

/// Crash-state inventory estimate for a Ring ORAM controller.
#[derive(Clone, Debug)]
pub struct RingCrashStateEstimate {
    /// Trusted position map bytes.
    pub position_map_bytes: u64,
    /// Trusted stash lower-bound bytes.
    pub stash_bytes: u64,
    /// Persistent per-bucket read-counter bytes.
    pub read_counter_bytes: u64,
    /// Persistent per-bucket permutation bytes.
    pub permutation_bytes: u64,
    /// Current page-store trusted auth top-tree bytes.
    pub current_auth_trusted_hash_bytes: u64,
    /// Slot-addressable trusted auth top-tree bytes.
    pub slot_auth_trusted_hash_bytes: u64,
    /// Current page-store controller/auth state floor.
    pub current_total_state_floor_bytes: u64,
    /// Slot-addressable controller/auth state floor.
    pub slot_total_state_floor_bytes: u64,
}

/// Run a metadata-only Ring ORAM stress simulation.
pub fn stress_ring(config: RingStressConfig) -> Result<RingStressReport> {
    validate_config(&config)?;
    let mut sim = RingStressSim::new(config.params.clone(), config.seed)?;
    let mut rng = ChaCha20Rng::from_seed(config.seed);
    let total_ops = config.warmup_ops + config.ops;
    let effective_cache_levels = config.cache_levels.min(config.params.height());
    let mut samples = Vec::with_capacity(config.ops);
    let mut overflow_samples = 0usize;
    let mut completed_evictions = 0u64;
    let mut measured_evictions = 0u64;
    let mut early_reshuffle_buckets = 0u64;
    let mut measured_early_reshuffle_buckets = 0u64;
    let mut measured_uncached_early_reshuffle_buckets = 0u64;

    for step in 0..total_ops {
        let measured_step = step >= config.warmup_ops;
        let logical_id =
            next_logical_id(config.pattern, step, config.params.logical_blocks, &mut rng);
        let read_path = sim.access(logical_id, &mut rng)?;

        if (step + 1) % config.eviction_period == 0 {
            let leaf = eviction_leaf_at(&config.params, completed_evictions);
            sim.evict_path(leaf)?;
            completed_evictions += 1;
            if measured_step {
                measured_evictions += 1;
            }
        }

        for &(depth, node_idx) in read_path.iter().rev() {
            if sim.read_counters[node_idx] < config.dummy_slots as u32 {
                continue;
            }
            sim.reshuffle_bucket(depth, node_idx);
            early_reshuffle_buckets += 1;
            if measured_step {
                measured_early_reshuffle_buckets += 1;
                if depth >= effective_cache_levels {
                    measured_uncached_early_reshuffle_buckets += 1;
                }
            }
        }

        if measured_step {
            let stash_len = sim.stash_len();
            if stash_len > config.params.stash_capacity {
                overflow_samples += 1;
            }
            samples.push(stash_len);
        }
    }

    let stats = StashStats::from_samples(samples);
    let tree_buckets = config.params.bucket_count();
    let real_tree_slots = tree_buckets
        .checked_mul(config.params.bucket_size)
        .ok_or_else(|| Error::InvalidParams("real tree slot count overflow".into()))?;
    let total_slots_per_bucket = config
        .params
        .bucket_size
        .checked_add(config.dummy_slots)
        .ok_or_else(|| Error::InvalidParams("Ring slot count overflow".into()))?;
    let total_tree_slots = tree_buckets
        .checked_mul(total_slots_per_bucket)
        .ok_or_else(|| Error::InvalidParams("total tree slot count overflow".into()))?;
    let uncached_levels = config.params.height() - effective_cache_levels;
    let io = estimate_ring_io(
        &config,
        total_slots_per_bucket,
        measured_evictions,
        measured_uncached_early_reshuffle_buckets,
        uncached_levels,
    )?;
    let crash_state = estimate_crash_state(&config, tree_buckets, total_slots_per_bucket)?;

    Ok(RingStressReport {
        logical_blocks: config.params.logical_blocks,
        leaves: config.params.leaves,
        height: config.params.height(),
        bucket_size: config.params.bucket_size,
        dummy_slots: config.dummy_slots,
        total_slots_per_bucket,
        stash_capacity: config.params.stash_capacity,
        tree_buckets,
        real_tree_slots,
        total_tree_slots,
        real_tree_slot_load_percent: config.params.logical_blocks as f64 * 100.0
            / real_tree_slots as f64,
        total_tree_slot_load_percent: config.params.logical_blocks as f64 * 100.0
            / total_tree_slots as f64,
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
        eviction_period: config.eviction_period,
        completed_evictions,
        measured_evictions,
        early_reshuffle_buckets,
        measured_early_reshuffle_buckets,
        measured_uncached_early_reshuffle_buckets,
        max_read_counter: sim.max_read_counter,
        cache_levels: effective_cache_levels,
        uncached_levels,
        auth_store: config.auth_store,
        auth_trusted_levels: config.auth_trusted_levels,
        auth_hash_page_size: config.auth_hash_page_size,
        io,
        crash_state,
    })
}

fn validate_config(config: &RingStressConfig) -> Result<()> {
    if config.params.logical_blocks > u32::MAX as usize {
        return Err(Error::InvalidParams(
            "Ring stress simulator supports at most u32::MAX logical blocks".into(),
        ));
    }
    if config.dummy_slots == 0 {
        return Err(Error::InvalidParams("dummy_slots must be > 0".into()));
    }
    if config.dummy_slots > u32::MAX as usize {
        return Err(Error::InvalidParams(
            "dummy_slots must fit in u32 read counters".into(),
        ));
    }
    if config.eviction_period == 0 {
        return Err(Error::InvalidParams("eviction_period must be > 0".into()));
    }
    if config.auth_hash_page_size < 32 {
        return Err(Error::InvalidParams(
            "auth_hash_page_size must be at least 32".into(),
        ));
    }
    let tree_slots = config
        .params
        .bucket_count()
        .checked_mul(config.params.bucket_size)
        .ok_or_else(|| Error::InvalidParams("tree slot count overflow".into()))?;
    if config.params.logical_blocks > tree_slots {
        return Err(Error::InvalidParams(format!(
            "logical blocks {} exceed Ring real tree slots {}",
            config.params.logical_blocks, tree_slots
        )));
    }
    if config.auth_store {
        merkle_hash_touch_cost(config.params.bucket_count(), config.auth_trusted_levels)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn estimate_ring_io(
    config: &RingStressConfig,
    total_slots_per_bucket: usize,
    measured_evictions: u64,
    measured_uncached_early_reshuffle_buckets: u64,
    uncached_levels: usize,
) -> Result<RingIoEstimate> {
    let ops = config.ops.max(1) as f64;
    let read_paths = config.ops as f64;
    let evict_paths = measured_evictions as f64;
    let early_buckets = measured_uncached_early_reshuffle_buckets as f64;
    let uncached = uncached_levels as f64;
    let meta_page_plaintext_bytes =
        ring_meta_page_bytes(config.params.bucket_size, config.dummy_slots)?;
    let current_payload_page_plaintext_bytes = total_slots_per_bucket
        .checked_mul(config.params.block_size)
        .ok_or_else(|| Error::InvalidParams("Ring payload page size overflow".into()))?;
    let slot_payload_plaintext_bytes = config.params.block_size;

    let meta_reads = read_paths * uncached + evict_paths * uncached + early_buckets;
    let meta_writes = read_paths * uncached + evict_paths * uncached + early_buckets;
    let current_payload_reads = read_paths * uncached + evict_paths * uncached + early_buckets;
    let current_payload_writes = evict_paths * uncached + early_buckets;
    let current_primary_reads = meta_reads + current_payload_reads;
    let current_primary_writes = meta_writes + current_payload_writes;
    let current_primary_plaintext_bytes = (meta_reads + meta_writes)
        * meta_page_plaintext_bytes as f64
        + (current_payload_reads + current_payload_writes)
            * current_payload_page_plaintext_bytes as f64;
    let current_primary_aead_bytes = (meta_reads + meta_writes)
        * (meta_page_plaintext_bytes + AEAD_OVERHEAD) as f64
        + (current_payload_reads + current_payload_writes)
            * (current_payload_page_plaintext_bytes + AEAD_OVERHEAD) as f64;

    let slot_payload_reads = read_paths * uncached
        + evict_paths * uncached * total_slots_per_bucket as f64
        + early_buckets * total_slots_per_bucket as f64;
    let slot_payload_writes = evict_paths * uncached * total_slots_per_bucket as f64
        + early_buckets * total_slots_per_bucket as f64;
    let slot_payload_plaintext_bytes_total =
        (slot_payload_reads + slot_payload_writes) * slot_payload_plaintext_bytes as f64;
    let slot_payload_aead_bytes_total = (slot_payload_reads + slot_payload_writes)
        * (slot_payload_plaintext_bytes + AEAD_OVERHEAD) as f64;
    let slot_metadata_aead_bytes =
        (meta_reads + meta_writes) * (meta_page_plaintext_bytes + AEAD_OVERHEAD) as f64;

    let (current_auth_hash_touches, current_auth_hash_bytes) = if config.auth_store {
        let data_page_count = config.params.bucket_count();
        let hash_cost = merkle_hash_touch_cost(data_page_count, config.auth_trusted_levels)?;
        let touches = current_primary_reads * hash_cost.read_hash_page_touches as f64
            + current_primary_writes * hash_cost.write_hash_page_touches as f64;
        (touches, touches * config.auth_hash_page_size as f64)
    } else {
        (0.0, 0.0)
    };

    let (slot_auth_hash_touches, slot_auth_hash_bytes) = if config.auth_store {
        let meta_hash_cost =
            merkle_hash_touch_cost(config.params.bucket_count(), config.auth_trusted_levels)?;
        let slot_page_count = config
            .params
            .bucket_count()
            .checked_mul(total_slots_per_bucket)
            .ok_or_else(|| Error::InvalidParams("slot auth page count overflow".into()))?;
        let slot_hash_cost = merkle_hash_touch_cost(slot_page_count, config.auth_trusted_levels)?;
        let touches = meta_reads * meta_hash_cost.read_hash_page_touches as f64
            + meta_writes * meta_hash_cost.write_hash_page_touches as f64
            + slot_payload_reads * slot_hash_cost.read_hash_page_touches as f64
            + slot_payload_writes * slot_hash_cost.write_hash_page_touches as f64;
        (touches, touches * config.auth_hash_page_size as f64)
    } else {
        (0.0, 0.0)
    };

    Ok(RingIoEstimate {
        meta_page_plaintext_bytes,
        current_payload_page_plaintext_bytes,
        slot_payload_plaintext_bytes,
        current_primary_page_reads_per_access: current_primary_reads / ops,
        current_primary_page_writes_per_access: current_primary_writes / ops,
        current_primary_page_touches_per_access: (current_primary_reads + current_primary_writes)
            / ops,
        current_primary_plaintext_bytes_per_access: current_primary_plaintext_bytes / ops,
        current_primary_aead_bytes_per_access: current_primary_aead_bytes / ops,
        current_auth_hash_page_touches_per_access: current_auth_hash_touches / ops,
        current_auth_hash_bytes_per_access: current_auth_hash_bytes / ops,
        current_total_backing_bytes_per_access: (current_primary_aead_bytes
            + current_auth_hash_bytes)
            / ops,
        slot_metadata_page_touches_per_access: (meta_reads + meta_writes) / ops,
        slot_payload_reads_per_access: slot_payload_reads / ops,
        slot_payload_writes_per_access: slot_payload_writes / ops,
        slot_payload_plaintext_bytes_per_access: slot_payload_plaintext_bytes_total / ops,
        slot_payload_aead_bytes_per_access: slot_payload_aead_bytes_total / ops,
        slot_auth_hash_page_touches_per_access: slot_auth_hash_touches / ops,
        slot_auth_hash_bytes_per_access: slot_auth_hash_bytes / ops,
        slot_total_backing_bytes_per_access: (slot_metadata_aead_bytes
            + slot_payload_aead_bytes_total
            + slot_auth_hash_bytes)
            / ops,
    })
}

fn estimate_crash_state(
    config: &RingStressConfig,
    tree_buckets: usize,
    total_slots_per_bucket: usize,
) -> Result<RingCrashStateEstimate> {
    let position_map_bytes = checked_u64_mul(config.params.logical_blocks, 4, "position map")?;
    let stash_slot_bytes = OramBlock::serialized_len(config.params.block_size);
    let stash_bytes = checked_u64_mul(config.params.stash_capacity, stash_slot_bytes, "stash")?;
    let read_counter_bytes = checked_u64_mul(tree_buckets, READ_COUNTER_BYTES, "read counters")?;
    let permutation_bytes = checked_u64_mul(
        tree_buckets
            .checked_mul(total_slots_per_bucket)
            .ok_or_else(|| Error::InvalidParams("permutation slot count overflow".into()))?,
        PERMUTATION_INDEX_BYTES,
        "permutations",
    )?;

    let current_auth_trusted_hash_bytes = if config.auth_store {
        checked_u64_mul(
            trusted_merkle_hashes(config.params.bucket_count(), config.auth_trusted_levels)?,
            32 * 2,
            "current auth trusted hashes",
        )?
    } else {
        0
    };
    let slot_auth_trusted_hash_bytes = if config.auth_store {
        let slot_page_count = config
            .params
            .bucket_count()
            .checked_mul(total_slots_per_bucket)
            .ok_or_else(|| Error::InvalidParams("slot auth page count overflow".into()))?;
        let meta_hashes =
            trusted_merkle_hashes(config.params.bucket_count(), config.auth_trusted_levels)?;
        let slot_hashes = trusted_merkle_hashes(slot_page_count, config.auth_trusted_levels)?;
        ((meta_hashes + slot_hashes) as u64) * 32
    } else {
        0
    };
    let controller_state = position_map_bytes
        .checked_add(stash_bytes)
        .and_then(|value| value.checked_add(read_counter_bytes))
        .and_then(|value| value.checked_add(permutation_bytes))
        .ok_or_else(|| Error::InvalidParams("Ring crash state size overflow".into()))?;

    Ok(RingCrashStateEstimate {
        position_map_bytes,
        stash_bytes,
        read_counter_bytes,
        permutation_bytes,
        current_auth_trusted_hash_bytes,
        slot_auth_trusted_hash_bytes,
        current_total_state_floor_bytes: controller_state
            .checked_add(current_auth_trusted_hash_bytes)
            .ok_or_else(|| Error::InvalidParams("current crash state size overflow".into()))?,
        slot_total_state_floor_bytes: controller_state
            .checked_add(slot_auth_trusted_hash_bytes)
            .ok_or_else(|| Error::InvalidParams("slot crash state size overflow".into()))?,
    })
}

fn checked_u64_mul(lhs: usize, rhs: usize, label: &str) -> Result<u64> {
    lhs.checked_mul(rhs)
        .map(|value| value as u64)
        .ok_or_else(|| Error::InvalidParams(format!("{label} byte count overflow")))
}

fn ring_meta_page_bytes(real_slots: usize, dummy_slots: usize) -> Result<usize> {
    let total_slots = real_slots
        .checked_add(dummy_slots)
        .ok_or_else(|| Error::InvalidParams("Ring metadata slot count overflow".into()))?;
    let real_meta = circuit_meta_page_bytes(real_slots);
    let permutation = total_slots
        .checked_mul(PERMUTATION_INDEX_BYTES)
        .ok_or_else(|| Error::InvalidParams("Ring permutation metadata overflow".into()))?;
    real_meta
        .checked_add(permutation)
        .and_then(|value| value.checked_add(READ_COUNTER_BYTES))
        .ok_or_else(|| Error::InvalidParams("Ring metadata page size overflow".into()))
}

#[derive(Clone, Copy, Debug)]
struct MerkleHashTouchCost {
    read_hash_page_touches: usize,
    write_hash_page_touches: usize,
}

fn merkle_hash_touch_cost(page_count: usize, trusted_levels: usize) -> Result<MerkleHashTouchCost> {
    let leaf_base = page_count
        .checked_next_power_of_two()
        .ok_or_else(|| Error::InvalidParams("auth page_count is too large".into()))?;
    let merkle_levels = leaf_base.trailing_zeros() as usize + 1;
    if trusted_levels == 0 || trusted_levels > merkle_levels {
        return Err(Error::InvalidParams(format!(
            "auth_trusted_levels {} out of range 1..={}",
            trusted_levels, merkle_levels
        )));
    }
    let disk_levels_touched = merkle_levels - trusted_levels;
    Ok(MerkleHashTouchCost {
        read_hash_page_touches: disk_levels_touched,
        // Updating a disk-backed hash reads and writes its packed hash page,
        // and each level also reads the sibling hash needed to recompute the
        // parent frontier.
        write_hash_page_touches: disk_levels_touched * 3,
    })
}

fn trusted_merkle_hashes(page_count: usize, trusted_levels: usize) -> Result<usize> {
    let leaf_base = page_count
        .checked_next_power_of_two()
        .ok_or_else(|| Error::InvalidParams("auth page_count is too large".into()))?;
    let merkle_levels = leaf_base.trailing_zeros() as usize + 1;
    if trusted_levels == 0 || trusted_levels > merkle_levels {
        return Err(Error::InvalidParams(format!(
            "auth_trusted_levels {} out of range 1..={}",
            trusted_levels, merkle_levels
        )));
    }
    let trusted_node_limit = 1usize
        .checked_shl(trusted_levels as u32)
        .ok_or_else(|| Error::InvalidParams("auth trusted level is too large".into()))?;
    Ok(trusted_node_limit - 1)
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

fn eviction_leaf_at(params: &OramParams, eviction_index: u64) -> u32 {
    let leaf_bits = params.leaf_bits() as u32;
    let mask = if leaf_bits == 32 {
        u32::MAX
    } else {
        (1u32 << leaf_bits) - 1
    };
    ((eviction_index as u32) & mask).reverse_bits() >> (32 - leaf_bits)
}

#[derive(Clone, Copy, Debug)]
struct SimBlock {
    id: u32,
    leaf: u32,
}

struct RingStressSim {
    params: OramParams,
    slots: Vec<u32>,
    read_counters: Vec<u32>,
    position_map: Vec<u32>,
    stash: Vec<SimBlock>,
    init_stash: usize,
    max_read_counter: u32,
}

impl RingStressSim {
    fn new(params: OramParams, seed: [u8; 32]) -> Result<Self> {
        let tree_slots = params
            .bucket_count()
            .checked_mul(params.bucket_size)
            .ok_or_else(|| Error::InvalidParams("tree slot count overflow".into()))?;
        let mut sim = Self {
            position_map: Vec::with_capacity(params.logical_blocks),
            slots: vec![EMPTY_BLOCK; tree_slots],
            read_counters: vec![0; params.bucket_count()],
            stash: Vec::new(),
            init_stash: 0,
            max_read_counter: 0,
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

    fn access(&mut self, logical_id: u32, rng: &mut ChaCha20Rng) -> Result<Vec<(usize, usize)>> {
        let old_leaf = self.position_map[logical_id as usize];
        let mut block = self
            .remove_from_path(logical_id, old_leaf)
            .or_else(|| self.remove_from_stash(logical_id))
            .ok_or(Error::BlockNotFound(logical_id as u64))?;
        block.leaf = self.random_leaf(rng);
        self.position_map[logical_id as usize] = block.leaf;
        self.stash.push(block);

        let path = self.path(old_leaf);
        for &(_, node_idx) in &path {
            self.read_counters[node_idx] = self.read_counters[node_idx].saturating_add(1);
            self.max_read_counter = self.max_read_counter.max(self.read_counters[node_idx]);
        }
        Ok(path)
    }

    fn evict_path(&mut self, leaf: u32) -> Result<()> {
        let path = self.path(leaf);
        for &(_, node_idx) in &path {
            self.read_bucket_into_stash(node_idx);
            self.read_counters[node_idx] = 0;
        }
        for &(depth, node_idx) in path.iter().rev() {
            self.write_bucket_from_stash(depth, node_idx);
        }
        Ok(())
    }

    fn reshuffle_bucket(&mut self, depth: usize, node_idx: usize) {
        self.read_bucket_into_stash(node_idx);
        self.read_counters[node_idx] = 0;
        self.write_bucket_from_stash(depth, node_idx);
    }

    fn stash_len(&self) -> usize {
        self.stash.len()
    }

    fn random_leaf(&self, rng: &mut ChaCha20Rng) -> u32 {
        let mask = self.params.leaves as u32 - 1;
        rng.next_u32() & mask
    }

    fn path(&self, leaf: u32) -> Vec<(usize, usize)> {
        (0..self.params.height())
            .map(|depth| (depth, self.params.node_index(depth, leaf)))
            .collect()
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

    fn read_bucket_into_stash(&mut self, node_idx: usize) {
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

    fn write_bucket_from_stash(&mut self, depth: usize, node_idx: usize) {
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

    fn config(pattern: CircuitStressPattern) -> RingStressConfig {
        let mut params = OramParams::with_leaves(256, 64, 128)
            .unwrap()
            .with_bucket_size(4)
            .unwrap();
        params.stash_capacity = 128;
        RingStressConfig {
            params,
            dummy_slots: 4,
            ops: 1000,
            warmup_ops: 100,
            pattern,
            seed: [10; 32],
            eviction_period: 4,
            cache_levels: 0,
            auth_store: true,
            auth_trusted_levels: 1,
            auth_hash_page_size: 4096,
        }
    }

    #[test]
    fn random_ring_stress_run_completes() {
        let report = stress_ring(config(CircuitStressPattern::Random)).unwrap();

        assert_eq!(report.logical_blocks, 256);
        assert_eq!(report.ops, 1000);
        assert_eq!(report.eviction_period, 4);
        assert_eq!(report.completed_evictions, 275);
        assert!(report.max_stash <= report.stash_capacity);
        assert!(report.io.current_primary_page_touches_per_access > 0.0);
        assert!(report.io.slot_total_backing_bytes_per_access > 0.0);
    }

    #[test]
    fn round_robin_ring_stress_run_completes() {
        let report = stress_ring(config(CircuitStressPattern::RoundRobin)).unwrap();

        assert_eq!(report.pattern, CircuitStressPattern::RoundRobin);
        assert_eq!(report.overflow_samples, 0);
    }

    #[test]
    fn invalid_eviction_period_is_rejected() {
        let mut cfg = config(CircuitStressPattern::Random);
        cfg.eviction_period = 0;

        assert!(matches!(
            stress_ring(cfg).unwrap_err(),
            Error::InvalidParams(_)
        ));
    }
}
