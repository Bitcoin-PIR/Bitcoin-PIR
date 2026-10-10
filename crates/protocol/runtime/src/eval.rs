//! DPF evaluation for both index-level and chunk-level PIR.

use libdpf::{Block, Dpf, DpfKey};
use pir_core::params::{CHUNK_SLOTS_PER_BIN, INDEX_SLOTS_PER_BIN, INDEX_SLOT_SIZE, UNIT_DATA_SIZE};
use std::time::{Duration, Instant};

// ─── Software prefetch intrinsics ────────────────────────────────────────────

/// Prefetch a memory address into the CPU cache for reading.
/// Uses `_mm_prefetch` on x86_64, no-op on other architectures.
#[inline(always)]
fn prefetch_read(ptr: *const u8) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::x86_64::_mm_prefetch(ptr as *const i8, std::arch::x86_64::_MM_HINT_T0);
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = ptr;
    }
}

// ─── Index-level constants ──────────────────────────────────────────────────

/// Each cuckoo bin has INDEX_SLOTS_PER_BIN (4) slots, each INDEX_SLOT_SIZE (13) bytes.
pub const INDEX_SLOTS: usize = INDEX_SLOTS_PER_BIN; // 4
pub const INDEX_RESULT_SIZE: usize = INDEX_SLOTS * INDEX_SLOT_SIZE; // 4 * 13 = 52

// ─── Chunk-level constants ──────────────────────────────────────────────────

/// Each slot: [4B chunk_id LE | UNIT_DATA_SIZE data]
pub const CHUNK_SLOT_SIZE: usize = 4 + UNIT_DATA_SIZE;
pub const CHUNK_SLOTS: usize = CHUNK_SLOTS_PER_BIN; // 3
pub const CHUNK_RESULT_SIZE: usize = CHUNK_SLOTS * CHUNK_SLOT_SIZE;

// ─── DPF bit extraction ────────────────────────────────────────────────────

#[inline]
fn get_dpf_bit(block: &Block, bit_within_block: usize) -> bool {
    if bit_within_block < 64 {
        (block.low >> bit_within_block) & 1 == 1
    } else {
        (block.high >> (bit_within_block - 64)) & 1 == 1
    }
}

/// XOR src into dst using u64 chunks.
#[inline]
pub fn xor_into(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    let n = dst.len() / 8;
    let d = unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut u64, n) };
    let s = unsafe { std::slice::from_raw_parts(src.as_ptr() as *const u64, n) };
    for i in 0..n {
        d[i] ^= s[i];
    }
    // Handle remaining bytes
    for i in (n * 8)..dst.len() {
        dst[i] ^= src[i];
    }
}

// ─── Generic DPF evaluation (supports N queries) ──────────────────────────

/// Lookahead distance for software prefetching (in bins).
/// Issue prefetch for bin N+LOOKAHEAD while processing bin N.
const PREFETCH_LOOKAHEAD: usize = 4;

/// Maximum number of DPF keys a single group may carry.
///
/// `process_group_generic` tracks per-key DPF bits in a fixed
/// `[bool; MAX_KEYS_PER_GROUP]` on the hot path (no per-bin heap
/// allocation), so any larger count would write out of bounds.
/// `protocol::decode_batch_query` rejects frames above this cap;
/// legitimate clients send at most INDEX/CHUNK_CUCKOO_NUM_HASHES (2)
/// keys per group, and 1 for Merkle sibling batches.
pub const MAX_KEYS_PER_GROUP: usize = 8;

/// Per-group timing breakdown.
pub struct GroupTiming {
    pub dpf_eval: Duration,
    pub fetch_xor: Duration,
}

/// Evaluate N DPF keys over a table, XOR-accumulating results.
/// Returns Vec of N accumulators, each `result_size` bytes, plus timing.
/// `prefetch_bin` is an optional callback to prefetch data for an upcoming bin.
#[allow(clippy::type_complexity)]
fn process_group_generic(
    keys: &[&DpfKey],
    table_bytes: &[u8],
    bins_per_table: usize,
    result_size: usize,
    fetch_bin: &dyn Fn(&[u8], usize, &mut [u8]),
    prefetch_bin: Option<&dyn Fn(&[u8], usize)>,
) -> (Vec<Vec<u8>>, GroupTiming) {
    let dpf = Dpf::with_default_key();
    let num_keys = keys.len();

    // Defense-in-depth (S2): never read `evals[0]` of an empty batch or
    // index `bits[i]` past the fixed array below. Decode + handler
    // validation make these unreachable from the wire; programmatic
    // callers get zero-filled accumulators instead of a panic
    // (the release profile's panic = 'abort' would kill the whole server).
    if num_keys == 0 || num_keys > MAX_KEYS_PER_GROUP {
        let accs = (0..num_keys).map(|_| vec![0u8; result_size]).collect();
        return (
            accs,
            GroupTiming {
                dpf_eval: Duration::ZERO,
                fetch_xor: Duration::ZERO,
            },
        );
    }

    let t_dpf = Instant::now();
    let evals: Vec<Vec<Block>> = keys
        .iter()
        .map(|k| dpf.eval_partial(k, bins_per_table as u64))
        .collect();
    let dpf_eval = t_dpf.elapsed();

    // Use the shortest eval vector: a key declaring a smaller DPF domain
    // than the table's yields fewer blocks, and indexing
    // `evals[i][block_idx]` beyond it would panic. Legitimate keys all
    // share the table's domain, so this equals `evals[0].len()` for them.
    let num_blocks = evals.iter().map(|e| e.len()).min().unwrap_or(0);

    let t_fetch = Instant::now();
    let mut accs: Vec<Vec<u8>> = (0..num_keys).map(|_| vec![0u8; result_size]).collect();
    let mut bin_buf = vec![0u8; result_size];

    #[allow(clippy::needless_range_loop)] // `evals[i][block_idx]` across all keys
    for block_idx in 0..num_blocks {
        // Skip if all blocks are zero
        let all_zero = (0..num_keys).all(|i| evals[i][block_idx].is_equal(&Block::zero()));
        if all_zero {
            continue;
        }

        let base_bin = block_idx * 128;
        let end_bin = (base_bin + 128).min(bins_per_table);

        for bin in base_bin..end_bin {
            let bit_within = bin - base_bin;

            // Software prefetch: issue read for a future bin's data
            if let Some(pf) = prefetch_bin {
                let ahead = bin + PREFETCH_LOOKAHEAD;
                if ahead < end_bin {
                    pf(table_bytes, ahead);
                }
            }

            // Check which keys have bit set
            let mut any_set = false;
            let mut bits = [false; MAX_KEYS_PER_GROUP];
            for i in 0..num_keys {
                bits[i] = get_dpf_bit(&evals[i][block_idx], bit_within);
                if bits[i] {
                    any_set = true;
                }
            }

            if !any_set {
                continue;
            }

            for v in bin_buf.iter_mut() {
                *v = 0;
            }
            fetch_bin(table_bytes, bin, &mut bin_buf);

            for i in 0..num_keys {
                if bits[i] {
                    xor_into(&mut accs[i], &bin_buf);
                }
            }
        }
    }
    let fetch_xor = t_fetch.elapsed();

    (
        accs,
        GroupTiming {
            dpf_eval,
            fetch_xor,
        },
    )
}

// ─── Index-level evaluation (inlined cuckoo tables) ─────────────────────────

/// Fetch INDEX_SLOTS inlined index entries at `bin` directly from the table.
/// Each slot is INDEX_SLOT_SIZE (17) bytes, stored contiguously.
#[inline]
fn fetch_index_bin(table_bytes: &[u8], bin: usize, out: &mut [u8]) {
    let src_offset = bin * INDEX_RESULT_SIZE;
    out.copy_from_slice(&table_bytes[src_offset..src_offset + INDEX_RESULT_SIZE]);
}

/// Process one index-level group: evaluate two DPF keys, XOR-accumulate.
/// Returns (result_q0, result_q1, timing).
pub fn process_index_group(
    key_q0: &DpfKey,
    key_q1: &DpfKey,
    table_bytes: &[u8],
    bins_per_table: usize,
) -> (Vec<u8>, Vec<u8>, GroupTiming) {
    let (results, timing) = process_group_generic(
        &[key_q0, key_q1],
        table_bytes,
        bins_per_table,
        INDEX_RESULT_SIZE,
        &|tbl, bin, out| fetch_index_bin(tbl, bin, out),
        None,
    );
    (results[0].clone(), results[1].clone(), timing)
}

// ─── Chunk-level evaluation (inlined cuckoo tables) ─────────────────────────

/// Prefetch inlined chunk data for a future bin so it's in cache when we need it.
#[inline]
fn prefetch_chunk_bin(table_bytes: &[u8], bin: usize) {
    let src_offset = bin * CHUNK_RESULT_SIZE;
    if src_offset < table_bytes.len() {
        prefetch_read(table_bytes[src_offset..].as_ptr());
    }
}

/// Fetch CHUNK_SLOTS inlined slots at `bin` directly from the table.
/// Each slot is CHUNK_SLOT_SIZE (44) bytes: [4B chunk_id | 40B data], stored contiguously.
#[inline]
fn fetch_chunk_bin(table_bytes: &[u8], bin: usize, out: &mut [u8]) {
    let src_offset = bin * CHUNK_RESULT_SIZE;
    out.copy_from_slice(&table_bytes[src_offset..src_offset + CHUNK_RESULT_SIZE]);
}

/// Process one chunk-level group: evaluate CHUNK_CUCKOO_NUM_HASHES (2) DPF keys, XOR-accumulate.
/// Returns Vec of 2 results, each CHUNK_RESULT_SIZE bytes, plus timing.
pub fn process_chunk_group(
    keys: &[&DpfKey],
    table_bytes: &[u8],
    bins_per_table: usize,
) -> (Vec<Vec<u8>>, GroupTiming) {
    process_group_generic(
        keys,
        table_bytes,
        bins_per_table,
        CHUNK_RESULT_SIZE,
        &|tbl, bin, out| fetch_chunk_bin(tbl, bin, out),
        Some(&|tbl, bin| prefetch_chunk_bin(tbl, bin)),
    )
}

// ─── Merkle sibling evaluation ────────────────────────────────────────────

/// Process one Merkle sibling group: evaluate 2 DPF keys, XOR-accumulate.
/// `result_size` = slots_per_bin × slot_size (e.g. 4 × 260 = 1040 for arity=8).
pub fn process_merkle_sibling_group(
    keys: &[&DpfKey],
    table_bytes: &[u8],
    bins_per_table: usize,
    result_size: usize,
) -> (Vec<Vec<u8>>, GroupTiming) {
    process_group_generic(
        keys,
        table_bytes,
        bins_per_table,
        result_size,
        &|tbl, bin, out| {
            let src = bin * result_size;
            out.copy_from_slice(&tbl[src..src + result_size]);
        },
        None,
    )
}

#[cfg(test)]
mod dpf_eval_guard_tests {
    use super::*;
    use libdpf::Dpf;

    /// 256 bins → DPF domain n = 8, two 128-bin eval blocks.
    const BINS: usize = 256;

    fn chunk_table() -> Vec<u8> {
        vec![0xA5u8; BINS * CHUNK_RESULT_SIZE]
    }

    /// S2 regression: `evals[0]` used to panic on an empty key list.
    #[test]
    fn process_chunk_group_with_zero_keys_returns_empty() {
        let table = chunk_table();
        let (accs, _t) = process_chunk_group(&[], &table, BINS);
        assert!(accs.is_empty());
    }

    /// S2 regression: more than MAX_KEYS_PER_GROUP keys used to write
    /// past the fixed `bits` array. Now yields zero-filled accumulators.
    #[test]
    fn process_chunk_group_with_too_many_keys_returns_zero_fills() {
        let dpf = Dpf::with_default_key();
        let keys: Vec<DpfKey> = (0..(MAX_KEYS_PER_GROUP as u64 + 1))
            .map(|i| dpf.gen(i, 8).0)
            .collect();
        let refs: Vec<&DpfKey> = keys.iter().collect();
        let table = chunk_table();
        let (accs, _t) = process_chunk_group(&refs, &table, BINS);
        assert_eq!(accs.len(), MAX_KEYS_PER_GROUP + 1);
        assert!(accs.iter().all(|a| a.len() == CHUNK_RESULT_SIZE));
        assert!(accs.iter().all(|a| a.iter().all(|&b| b == 0)));
    }

    /// Keys with mismatched DPF domains produce eval vectors of
    /// different lengths: n=8 yields 2 blocks for 256 bins, n=7 yields 1.
    /// The old `evals[0].len()` block count indexed past the short key's
    /// vector.
    #[test]
    fn ragged_key_domains_do_not_panic() {
        let dpf = Dpf::with_default_key();
        let k_long = dpf.gen(5, 8).0;
        let k_short = dpf.gen(5, 7).0;
        let refs = [&k_long, &k_short];
        let table = chunk_table();
        let (accs, _t) = process_chunk_group(&refs[..], &table, BINS);
        assert_eq!(accs.len(), 2);
        assert!(accs.iter().all(|a| a.len() == CHUNK_RESULT_SIZE));
    }
}
