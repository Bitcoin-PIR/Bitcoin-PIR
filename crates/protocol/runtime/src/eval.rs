//! DPF evaluation over the cuckoo tables of every DPF level (INDEX, CHUNK,
//! Merkle siblings).

use libdpf::{Block, Dpf, DpfKey};
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

// ─── DPF evaluation over one group's table ──────────────────────────────────

/// Lookahead distance for software prefetching (in bins).
/// Issue prefetch for bin N+LOOKAHEAD while processing bin N.
const PREFETCH_LOOKAHEAD: usize = 4;

/// Keys evaluated per pass over a group's table. The hot loop tracks per-key
/// DPF bits in a fixed `[bool; MAX_KEYS_PER_GROUP]` (no per-bin heap
/// allocation); `process_table_group` splits larger key sets into passes.
/// `protocol::decode_batch_query` also caps one frame's keys per group here.
pub const MAX_KEYS_PER_GROUP: usize = 8;

/// Per-group timing breakdown.
#[derive(Default)]
pub struct GroupTiming {
    pub dpf_eval: Duration,
    pub fetch_xor: Duration,
}

/// Evaluate DPF keys over one group's table of `bins_per_table` bins, each
/// `result_size` bytes, XOR-accumulating the bins each key selects. Returns
/// one accumulator per key. Each accumulator depends only on its own key, so
/// keys from different queries can share the scan; they are evaluated
/// MAX_KEYS_PER_GROUP per pass over the table.
pub fn process_table_group(
    keys: &[&DpfKey],
    table_bytes: &[u8],
    bins_per_table: usize,
    result_size: usize,
) -> (Vec<Vec<u8>>, GroupTiming) {
    let mut accs = Vec::with_capacity(keys.len());
    let mut timing = GroupTiming::default();
    for pass in keys.chunks(MAX_KEYS_PER_GROUP) {
        let (r, t) = process_pass(pass, table_bytes, bins_per_table, result_size);
        accs.extend(r);
        timing.dpf_eval += t.dpf_eval;
        timing.fetch_xor += t.fetch_xor;
    }
    (accs, timing)
}

fn process_pass(
    keys: &[&DpfKey],
    table_bytes: &[u8],
    bins_per_table: usize,
    result_size: usize,
) -> (Vec<Vec<u8>>, GroupTiming) {
    let dpf = Dpf::with_default_key();
    let num_keys = keys.len();

    let t_dpf = Instant::now();
    let evals: Vec<Vec<Block>> = keys
        .iter()
        .map(|k| dpf.eval_partial(k, bins_per_table as u64))
        .collect();
    let dpf_eval = t_dpf.elapsed();

    // A key declaring a smaller DPF domain than the table's yields fewer
    // blocks. Its bits past its own blocks count as zero, so the other keys
    // of the pass still cover the whole table.
    let num_blocks = evals.iter().map(|e| e.len()).max().unwrap_or(0);

    let t_fetch = Instant::now();
    let mut accs: Vec<Vec<u8>> = (0..num_keys).map(|_| vec![0u8; result_size]).collect();
    let mut bin_buf = vec![0u8; result_size];

    for block_idx in 0..num_blocks {
        let blocks: Vec<Option<&Block>> = evals.iter().map(|e| e.get(block_idx)).collect();
        if blocks
            .iter()
            .all(|b| b.map_or(true, |b| b.is_equal(&Block::zero())))
        {
            continue;
        }

        let base_bin = block_idx * 128;
        let end_bin = (base_bin + 128).min(bins_per_table);

        for bin in base_bin..end_bin {
            let bit_within = bin - base_bin;

            let ahead = bin + PREFETCH_LOOKAHEAD;
            if ahead < end_bin {
                prefetch_read(table_bytes[ahead * result_size..].as_ptr());
            }

            let mut any_set = false;
            let mut bits = [false; MAX_KEYS_PER_GROUP];
            for (i, block) in blocks.iter().enumerate() {
                bits[i] = block.is_some_and(|b| get_dpf_bit(b, bit_within));
                any_set |= bits[i];
            }
            if !any_set {
                continue;
            }

            let src = bin * result_size;
            bin_buf.copy_from_slice(&table_bytes[src..src + result_size]);
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

#[cfg(test)]
mod dpf_eval_guard_tests {
    use super::*;
    use libdpf::Dpf;

    /// 256 bins → DPF domain n = 8, two 128-bin eval blocks.
    const BINS: usize = 256;
    const RESULT_SIZE: usize = 132;

    fn table() -> Vec<u8> {
        (0..BINS * RESULT_SIZE).map(|i| (i % 251) as u8).collect()
    }

    fn alone(key: &DpfKey, table: &[u8]) -> Vec<u8> {
        process_table_group(&[key], table, BINS, RESULT_SIZE)
            .0
            .remove(0)
    }

    #[test]
    fn zero_keys_return_empty() {
        let (accs, _t) = process_table_group(&[], &table(), BINS, RESULT_SIZE);
        assert!(accs.is_empty());
    }

    /// More keys than one pass holds: every accumulator equals the key's
    /// result evaluated alone, which is what lets queries share a scan.
    #[test]
    fn shared_scan_matches_each_key_alone() {
        let dpf = Dpf::with_default_key();
        let keys: Vec<DpfKey> = (0..(2 * MAX_KEYS_PER_GROUP as u64 + 3))
            .map(|i| dpf.gen(i * 7 % BINS as u64, 8).0)
            .collect();
        let refs: Vec<&DpfKey> = keys.iter().collect();
        let table = table();
        let (accs, _t) = process_table_group(&refs, &table, BINS, RESULT_SIZE);
        assert_eq!(accs.len(), keys.len());
        for (key, acc) in keys.iter().zip(&accs) {
            assert_eq!(acc, &alone(key, &table));
        }
    }

    /// A key with a smaller DPF domain (n=7 yields 1 block for 256 bins,
    /// n=8 yields 2) neither panics nor truncates the other keys' scan.
    #[test]
    fn ragged_key_domains_stay_independent() {
        let dpf = Dpf::with_default_key();
        let k_long = dpf.gen(200, 8).0;
        let k_short = dpf.gen(5, 7).0;
        let table = table();
        let (accs, _t) = process_table_group(&[&k_long, &k_short], &table, BINS, RESULT_SIZE);
        assert_eq!(accs[0], alone(&k_long, &table));
        assert_eq!(accs[1], alone(&k_short, &table));
    }
}
