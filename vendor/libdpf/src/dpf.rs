//! Distributed Point Function (DPF) implementation
//!
//! This module implements the core DPF algorithms from
//! "Function Secret Sharing: Improvements and Extensions" (Boyle et al., CCS'16)

use rand::RngCore;
use rayon::prelude::*;

use crate::aes::Prg;
use crate::block::Block;
use crate::key::DpfKey;

/// Minimum parents to use batch PRG (AES pipelining)
const BATCH_THRESHOLD: usize = 8;
/// Minimum parents to use rayon thread parallelism
const PARALLEL_THRESHOLD: usize = 512;

/// Get a specific bit from an integer (bit b from position n)
/// In C: ((unsigned int)(x) >> (n - b)) & 1
#[inline]
fn get_bit(x: u64, n: u32, b: u32) -> u8 {
    ((x >> (n - b)) & 1) as u8
}

/// DPF context for key generation and evaluation
pub struct Dpf {
    prg: Prg,
}

impl Dpf {
    /// Create a new DPF context with the given AES key
    pub fn new(key: &Block) -> Self {
        Dpf {
            prg: Prg::new(key),
        }
    }

    /// Create a DPF context with the default key from the C implementation
    pub fn with_default_key() -> Self {
        Dpf::new(&Block::new(597349, 121379))
    }

    /// Generate two DPF keys for a point function f where f(α) = 1 and f(x) = 0 for x ≠ α
    ///
    /// # Arguments
    /// * `alpha` - The special point where f(α) = 1
    /// * `n` - Domain parameter (domain size is 2^n)
    ///
    /// # Returns
    /// * `(k0, k1)` - Two DPF keys for parties 0 and 1
    pub fn gen(&self, alpha: u64, n: u8) -> (DpfKey, DpfKey) {
        let maxlayer = (n - 7) as usize;

        // Arrays to track seeds and control bits through the tree
        // s[layer][party] and t[layer][party]
        let mut s = vec![[Block::zero(), Block::zero()]; maxlayer + 1];
        let mut t = vec![[0u8, 0u8]; maxlayer + 1];

        // Correction words
        let mut scw = vec![Block::zero(); maxlayer];
        let mut tcw = vec![[0u8, 0u8]; maxlayer];

        // Initialize random seeds for both parties
        let mut rng = rand::thread_rng();
        let mut s0_bytes = [0u8; 16];
        let mut s1_bytes = [0u8; 16];
        rng.fill_bytes(&mut s0_bytes);
        rng.fill_bytes(&mut s1_bytes);
        s[0][0] = Block::from_bytes(&s0_bytes);
        s[0][1] = Block::from_bytes(&s1_bytes);

        // Set initial control bits
        t[0][0] = s[0][0].lsb();
        t[0][1] = t[0][0] ^ 1;

        // Zero LSBs of initial seeds
        s[0][0] = s[0][0].set_lsb_zero();
        s[0][1] = s[0][1].set_lsb_zero();

        // Iterate through layers
        for i in 1..=maxlayer {
            // PRG expand for both parties
            let (s0_left, s0_right, t0_left, t0_right) = self.prg.generate(&s[i - 1][0]);
            let (s1_left, s1_right, t1_left, t1_right) = self.prg.generate(&s[i - 1][1]);

            // Determine keep/lose based on alpha's bit at this position
            let alpha_bit = get_bit(alpha, n as u32, i as u32);
            let (keep, _lose): (usize, usize) = if alpha_bit == 0 {
                (0, 1) // LEFT=0, RIGHT=1
            } else {
                (1, 0)
            };

            // Compute correction word for this layer
            let s0 = [s0_left, s0_right];
            let s1 = [s1_left, s1_right];
            let t0 = [t0_left, t0_right];
            let t1 = [t1_left, t1_right];

            // Correction word for seeds
            scw[i - 1] = s0[1 - keep].xor(&s1[1 - keep]); // lose side

            // Correction bits
            tcw[i - 1][0] = t0[0] ^ t1[0] ^ alpha_bit ^ 1;
            tcw[i - 1][1] = t0[1] ^ t1[1] ^ alpha_bit;

            // Propagate for party 0
            if t[i - 1][0] == 1 {
                s[i][0] = s0[keep].xor(&scw[i - 1]);
                t[i][0] = t0[keep] ^ tcw[i - 1][keep];
            } else {
                s[i][0] = s0[keep];
                t[i][0] = t0[keep];
            }

            // Propagate for party 1
            if t[i - 1][1] == 1 {
                s[i][1] = s1[keep].xor(&scw[i - 1]);
                t[i][1] = t1[keep] ^ tcw[i - 1][keep];
            } else {
                s[i][1] = s1[keep];
                t[i][1] = t1[keep];
            }
        }

        // Compute final correction block
        // Start with a block that has LSB=1 and bit at position alpha set
        let mut final_block = Block::zero().reverse_lsb();

        // Shift to set the appropriate bit based on alpha & 127
        let shift = (alpha & 127) as u32;
        final_block = final_block.left_shift(shift);

        // Reverse LSB (now the bit pattern is set, toggle LSB back)
        final_block = final_block.reverse_lsb();

        // XOR with final seeds
        final_block = final_block.xor(&s[maxlayer][0]);
        final_block = final_block.xor(&s[maxlayer][1]);

        // Create keys for both parties
        // Party 0's key
        let k0 = DpfKey::new(
            n,
            s[0][0],
            t[0][0],
            scw.clone(),
            tcw.clone(),
            final_block,
        );

        // Party 1's key
        let k1 = DpfKey::new(
            n,
            s[0][1],
            t[0][1],
            scw,
            tcw,
            final_block,
        );

        (k0, k1)
    }

    /// Evaluate the DPF at a single point
    ///
    /// # Arguments
    /// * `key` - The DPF key
    /// * `x` - The point to evaluate at
    ///
    /// # Returns
    /// * A 128-bit block representing the evaluation result
    pub fn eval(&self, key: &DpfKey, x: u64) -> Block {
        let maxlayer = key.max_layer();

        // Current seed and control bit
        let mut s = key.s0;
        let mut t = key.t0;

        // Traverse the tree
        for i in 1..=maxlayer {
            let (sL, sR, tL, tR) = self.prg.generate(&s);

            // Apply correction if needed
            let (sL_corr, sR_corr, tL_corr, tR_corr) = if t == 1 {
                (
                    sL.xor(&key.scw[i - 1]),
                    sR.xor(&key.scw[i - 1]),
                    tL ^ key.tcw[i - 1][0],
                    tR ^ key.tcw[i - 1][1],
                )
            } else {
                (sL, sR, tL, tR)
            };

            // Choose left or right based on x's bit
            let x_bit = get_bit(x, key.n as u32, i as u32);
            if x_bit == 0 {
                s = sL_corr;
                t = tL_corr;
            } else {
                s = sR_corr;
                t = tR_corr;
            }
        }

        // Apply final corrections
        let mut res = s;
        if t == 1 {
            res = res.reverse_lsb();
        }
        if t == 1 {
            res = res.xor(&key.final_block);
        }

        res
    }

    /// Evaluate the DPF at all points in the domain
    ///
    /// # Arguments
    /// * `key` - The DPF key
    ///
    /// # Returns
    /// * A vector of 2^(n-7) blocks representing all evaluation results
    pub fn eval_full(&self, key: &DpfKey) -> Vec<Block> {
        let num_points = 1u64 << key.n;
        self.eval_partial(key, num_points)
    }

    /// Evaluate the DPF at the first `num_points` points of the domain (0..num_points)
    ///
    /// This is more efficient than eval_full when num_points < 2^n, as it skips
    /// expanding tree nodes that would only produce results beyond the requested range.
    /// Both memory and computation scale with num_points rather than the full domain.
    ///
    /// Uses two levels of parallelism:
    /// - **AES batching**: All PRG operations in a layer are batched into a single
    ///   `encrypt_blocks` call, enabling AES-NI to pipeline ~8 blocks at once (~4-8x
    ///   throughput on the encryption step).
    /// - **Thread parallelism**: For layers with ≥512 parents, the work is split
    ///   across threads using rayon. Each thread batch-encrypts its chunk independently.
    ///
    /// # Arguments
    /// * `key` - The DPF key
    /// * `num_points` - Number of domain points to evaluate (from 0 to num_points-1)
    ///
    /// # Returns
    /// * A vector of ceil(num_points / 128) blocks representing evaluation results
    pub fn eval_partial(&self, key: &DpfKey, num_points: u64) -> Vec<Block> {
        let maxlayer = key.max_layer();
        let full_domain_blocks = 1usize << maxlayer;

        // Number of leaf blocks needed: ceil(num_points / 128)
        let num_blocks = ((num_points as usize) + 127) / 128;
        let num_blocks = num_blocks.min(full_domain_blocks);

        if num_blocks == 0 {
            return Vec::new();
        }

        // Buffer size: at the last layer we may produce one extra right child
        let buf_size = if num_blocks == full_domain_blocks {
            full_domain_blocks
        } else {
            num_blocks + 1
        };

        // Separate ping-pong buffers (not nested Vec) so the borrow checker
        // allows &read_buf and &mut write_buf simultaneously for rayon
        let mut s_a = vec![Block::zero(); buf_size];
        let mut s_b = vec![Block::zero(); buf_size];
        let mut t_a = vec![0u8; buf_size];
        let mut t_b = vec![0u8; buf_size];

        s_a[0] = key.s0;
        t_a[0] = key.t0;

        // Pre-allocate AES scratch buffer — reused across layers to avoid per-layer allocation
        let max_parents_per_layer = (num_blocks + 1) / 2;
        let mut aes_scratch: Vec<aes::cipher::Block<aes::Aes128>> =
            Vec::with_capacity(2 * max_parents_per_layer);

        // Traverse the tree breadth-first, only expanding nodes that
        // contribute to the first num_blocks leaves
        for i in 1..=maxlayer {
            let shift = maxlayer - i + 1;
            let parents_needed = if num_blocks == full_domain_blocks {
                1usize << (i - 1)
            } else {
                (num_blocks + (1 << shift) - 1) >> shift
            };

            // Odd layers: read A, write B. Even layers: read B, write A.
            let (s_prev, s_cur, t_prev, t_cur) = if i % 2 == 1 {
                (&s_a[..], &mut s_b[..], &t_a[..], &mut t_b[..])
            } else {
                (&s_b[..], &mut s_a[..], &t_b[..], &mut t_a[..])
            };

            let scw_i = &key.scw[i - 1];
            let tcw_i = &key.tcw[i - 1];

            if parents_needed >= PARALLEL_THRESHOLD {
                // ── Rayon parallel path ──
                // Each thread gets a chunk of parents, does batch PRG + corrections.
                // Each thread allocates its own small scratch buffer.
                let chunk_size: usize = 256;
                let children_out = &mut s_cur[..2 * parents_needed];
                let tbits_out = &mut t_cur[..2 * parents_needed];

                children_out
                    .par_chunks_mut(2 * chunk_size)
                    .zip(tbits_out.par_chunks_mut(2 * chunk_size))
                    .enumerate()
                    .for_each(|(chunk_idx, (s_chunk, t_chunk))| {
                        let start = chunk_idx * chunk_size;
                        let chunk_parents = s_chunk.len() / 2;
                        let parent_slice = &s_prev[start..start + chunk_parents];

                        // Each thread gets its own scratch (allocated once per thread)
                        let mut local_scratch = Vec::with_capacity(2 * chunk_parents);

                        self.prg.generate_batch(
                            parent_slice,
                            s_chunk,
                            t_chunk,
                            &mut local_scratch,
                        );

                        // Apply corrections in-place
                        for j in 0..chunk_parents {
                            if t_prev[start + j] == 1 {
                                s_chunk[2 * j] = s_chunk[2 * j].xor(scw_i);
                                s_chunk[2 * j + 1] = s_chunk[2 * j + 1].xor(scw_i);
                                t_chunk[2 * j] ^= tcw_i[0];
                                t_chunk[2 * j + 1] ^= tcw_i[1];
                            }
                        }
                    });
            } else if parents_needed >= BATCH_THRESHOLD {
                // ── Sequential batch PRG path ──
                // One encrypt_blocks call for the whole layer → AES pipelining.
                // Reuses pre-allocated scratch buffer.
                self.prg.generate_batch(
                    &s_prev[..parents_needed],
                    &mut s_cur[..2 * parents_needed],
                    &mut t_cur[..2 * parents_needed],
                    &mut aes_scratch,
                );

                // Apply corrections
                for j in 0..parents_needed {
                    if t_prev[j] == 1 {
                        s_cur[2 * j] = s_cur[2 * j].xor(scw_i);
                        s_cur[2 * j + 1] = s_cur[2 * j + 1].xor(scw_i);
                        t_cur[2 * j] ^= tcw_i[0];
                        t_cur[2 * j + 1] ^= tcw_i[1];
                    }
                }
            } else {
                // ── Sequential per-element path ──
                // For very small parent counts, no allocation overhead
                for j in 0..parents_needed {
                    let (sl, sr, tl, tr) = self.prg.generate(&s_prev[j]);

                    if t_prev[j] == 1 {
                        s_cur[2 * j] = sl.xor(scw_i);
                        s_cur[2 * j + 1] = sr.xor(scw_i);
                        t_cur[2 * j] = tl ^ tcw_i[0];
                        t_cur[2 * j + 1] = tr ^ tcw_i[1];
                    } else {
                        s_cur[2 * j] = sl;
                        s_cur[2 * j + 1] = sr;
                        t_cur[2 * j] = tl;
                        t_cur[2 * j + 1] = tr;
                    }
                }
            }
        }

        // Results are in the last-written buffer
        let (final_s, final_t) = if maxlayer % 2 == 1 {
            (&s_b, &t_b)
        } else {
            (&s_a, &t_a)
        };

        // Compute final corrections
        if num_blocks >= PARALLEL_THRESHOLD {
            (0..num_blocks)
                .into_par_iter()
                .map(|j| {
                    let mut block = final_s[j];
                    if final_t[j] == 1 {
                        block = block.reverse_lsb();
                        block = block.xor(&key.final_block);
                    }
                    block
                })
                .collect()
        } else {
            let mut res = Vec::with_capacity(num_blocks);
            for j in 0..num_blocks {
                let mut block = final_s[j];
                if final_t[j] == 1 {
                    block = block.reverse_lsb();
                    block = block.xor(&key.final_block);
                }
                res.push(block);
            }
            res
        }
    }
}

/// Convenience function to generate DPF keys
pub fn gen(alpha: u64, n: u8) -> (DpfKey, DpfKey) {
    let dpf = Dpf::with_default_key();
    dpf.gen(alpha, n)
}

/// Convenience function to evaluate DPF at a point
pub fn eval(key: &DpfKey, x: u64) -> Block {
    let dpf = Dpf::with_default_key();
    dpf.eval(key, x)
}

/// Convenience function for full domain evaluation
pub fn eval_full(key: &DpfKey) -> Vec<Block> {
    let dpf = Dpf::with_default_key();
    dpf.eval_full(key)
}

/// Convenience function for partial domain evaluation
pub fn eval_partial(key: &DpfKey, num_points: u64) -> Vec<Block> {
    let dpf = Dpf::with_default_key();
    dpf.eval_partial(key, num_points)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_basic() {
        let dpf = Dpf::with_default_key();
        let (k0, k1) = dpf.gen(26943, 16);
        
        assert_eq!(k0.n, 16);
        assert_eq!(k1.n, 16);
        assert_eq!(k0.scw.len(), k0.max_layer());
        assert_eq!(k1.scw.len(), k1.max_layer());
    }

    #[test]
    fn test_eval_xor_property() {
        // The XOR of evaluations from both keys should give the point function value
        let dpf = Dpf::with_default_key();
        let alpha: u64 = 26943;
        let n: u8 = 16;
        
        let (k0, k1) = dpf.gen(alpha, n);

        // Evaluate at alpha - should get non-zero result when XOR'd
        let res0 = dpf.eval(&k0, alpha);
        let res1 = dpf.eval(&k1, alpha);
        let xor_result = res0.xor(&res1);
        
        // At alpha, the XOR should have a non-zero pattern (the special point)
        // The result encodes the position within the block
        assert!(!xor_result.is_equal(&Block::zero()));
    }

    #[test]
    fn test_eval_zero_at_other_points() {
        let dpf = Dpf::with_default_key();
        let alpha: u64 = 26943;
        let n: u8 = 16;
        
        let (k0, k1) = dpf.gen(alpha, n);

        // Evaluate at a different point - should get zero when XOR'd
        for x in [0u64, 128, 1000, 50000].iter() {
            if *x != alpha {
                let res0 = dpf.eval(&k0, *x);
                let res1 = dpf.eval(&k1, *x);
                let xor_result = res0.xor(&res1);
                assert!(xor_result.is_equal(&Block::zero()), 
                    "Expected zero at x={}, got {:?}", x, xor_result);
            }
        }
    }

    #[test]
    fn test_eval_full() {
        let dpf = Dpf::with_default_key();
        let alpha: u64 = 26943;
        let n: u8 = 16;
        
        let (k0, k1) = dpf.gen(alpha, n);

        let res0 = dpf.eval_full(&k0);
        let res1 = dpf.eval_full(&k1);

        let expected_len = 1 << (n - 7);
        assert_eq!(res0.len(), expected_len as usize);
        assert_eq!(res1.len(), expected_len as usize);

        // Check that XOR results match point-by-point evaluation
        for (i, (r0, r1)) in res0.iter().zip(res1.iter()).enumerate() {
            let xor_result = r0.xor(r1);
            // Check if this is the block containing alpha
            let block_start = (i * 128) as u64;
            let block_end = block_start + 128;
            
            if alpha >= block_start && alpha < block_end {
                // This block should be non-zero
                assert!(!xor_result.is_equal(&Block::zero()),
                    "Block {} containing alpha should be non-zero", i);
            } else {
                // This block should be zero
                assert!(xor_result.is_equal(&Block::zero()),
                    "Block {} not containing alpha should be zero", i);
            }
        }
    }

    #[test]
    fn test_eval_partial_matches_full() {
        // eval_partial(num_points) should return the first ceil(num_points/128) blocks
        // identical to eval_full
        let dpf = Dpf::with_default_key();
        let alpha: u64 = 26943;
        let n: u8 = 16;

        let (k0, k1) = dpf.gen(alpha, n);

        let full0 = dpf.eval_full(&k0);
        let full1 = dpf.eval_full(&k1);

        // Test various partial sizes
        for num_points in [1u64, 128, 129, 1000, 5000, 26943, 27008, 30000, 65536] {
            let partial0 = dpf.eval_partial(&k0, num_points);
            let partial1 = dpf.eval_partial(&k1, num_points);

            let expected_blocks = ((num_points as usize) + 127) / 128;
            assert_eq!(partial0.len(), expected_blocks,
                "partial k0 length mismatch for num_points={}", num_points);
            assert_eq!(partial1.len(), expected_blocks,
                "partial k1 length mismatch for num_points={}", num_points);

            // Each block must match the corresponding block from eval_full
            for i in 0..expected_blocks {
                assert_eq!(partial0[i], full0[i],
                    "k0 block {} mismatch for num_points={}", i, num_points);
                assert_eq!(partial1[i], full1[i],
                    "k1 block {} mismatch for num_points={}", i, num_points);
            }
        }
    }

    #[test]
    fn test_eval_partial_correctness() {
        // Verify the DPF property holds for partial evaluation:
        // XOR of both keys is non-zero at alpha's block, zero elsewhere
        let dpf = Dpf::with_default_key();
        let alpha: u64 = 500;
        let n: u8 = 16;

        let (k0, k1) = dpf.gen(alpha, n);

        // Evaluate only the first 1024 points (alpha=500 is within this range)
        let partial0 = dpf.eval_partial(&k0, 1024);
        let partial1 = dpf.eval_partial(&k1, 1024);

        assert_eq!(partial0.len(), 8); // 1024 / 128 = 8 blocks

        for (i, (r0, r1)) in partial0.iter().zip(partial1.iter()).enumerate() {
            let xor_result = r0.xor(r1);
            let block_start = (i * 128) as u64;
            let block_end = block_start + 128;

            if alpha >= block_start && alpha < block_end {
                assert!(!xor_result.is_equal(&Block::zero()),
                    "Block {} containing alpha should be non-zero", i);
            } else {
                assert!(xor_result.is_equal(&Block::zero()),
                    "Block {} should be zero", i);
            }
        }
    }

    #[test]
    fn test_eval_partial_edge_cases() {
        let dpf = Dpf::with_default_key();
        let (k0, _) = dpf.gen(100, 16);

        // Zero points
        let res = dpf.eval_partial(&k0, 0);
        assert_eq!(res.len(), 0);

        // 1 point -> 1 block
        let res = dpf.eval_partial(&k0, 1);
        assert_eq!(res.len(), 1);

        // Exactly 128 points -> 1 block
        let res = dpf.eval_partial(&k0, 128);
        assert_eq!(res.len(), 1);

        // 129 points -> 2 blocks
        let res = dpf.eval_partial(&k0, 129);
        assert_eq!(res.len(), 2);

        // Beyond domain size -> clamped to full domain
        let res = dpf.eval_partial(&k0, 100000);
        assert_eq!(res.len(), 1 << (16 - 7));
    }

    #[test]
    fn test_eval_partial_different_domain_sizes() {
        let dpf = Dpf::with_default_key();

        for n in [8u8, 10, 12, 16] {
            let domain = 1u64 << n;
            let alpha = domain / 3;
            let (k0, k1) = dpf.gen(alpha, n);

            // Evaluate half the domain
            let half = domain / 2;
            let partial0 = dpf.eval_partial(&k0, half);
            let partial1 = dpf.eval_partial(&k1, half);
            let full0 = dpf.eval_full(&k0);
            let full1 = dpf.eval_full(&k1);

            let expected_blocks = (half as usize) / 128;
            assert_eq!(partial0.len(), expected_blocks, "n={}", n);

            for i in 0..expected_blocks {
                assert_eq!(partial0[i], full0[i], "n={} k0 block {}", n, i);
                assert_eq!(partial1[i], full1[i], "n={} k1 block {}", n, i);
            }
        }
    }

    #[test]
    fn test_eval_partial_all_code_paths() {
        // Use n=24 so that larger layers hit the batch and parallel thresholds:
        // maxlayer = 24-7 = 17, so the largest layer has 2^16 = 65536 parents
        // which exercises: per-element (<8), batch (8-511), and rayon (>=512)
        let dpf = Dpf::with_default_key();
        let n: u8 = 24;
        let alpha: u64 = 1_000_000;
        let (k0, k1) = dpf.gen(alpha, n);

        // Evaluate enough points to include alpha
        let num_points = 1_100_000u64;
        let partial0 = dpf.eval_partial(&k0, num_points);
        let partial1 = dpf.eval_partial(&k1, num_points);

        let expected_blocks = ((num_points as usize) + 127) / 128;
        assert_eq!(partial0.len(), expected_blocks);

        // Verify DPF property: XOR is non-zero at alpha's block, zero elsewhere
        let alpha_block = (alpha / 128) as usize;
        let xor_at_alpha = partial0[alpha_block].xor(&partial1[alpha_block]);
        assert!(!xor_at_alpha.is_equal(&Block::zero()),
            "XOR at alpha's block should be non-zero");

        // Spot-check some zero blocks
        for blk in [0usize, 100, 1000, 5000] {
            if blk != alpha_block {
                let xor = partial0[blk].xor(&partial1[blk]);
                assert!(xor.is_equal(&Block::zero()),
                    "Block {} should be zero", blk);
            }
        }
    }

    #[test]
    fn test_eval_full_large_domain() {
        // Test full eval at n=20 which exercises all three code paths
        let dpf = Dpf::with_default_key();
        let n: u8 = 20;
        let alpha: u64 = 500_000;
        let (k0, k1) = dpf.gen(alpha, n);

        let full0 = dpf.eval_full(&k0);
        let full1 = dpf.eval_full(&k1);

        let alpha_block = (alpha / 128) as usize;
        let xor_at_alpha = full0[alpha_block].xor(&full1[alpha_block]);
        assert!(!xor_at_alpha.is_equal(&Block::zero()));

        // Verify a sampling of zero blocks
        for blk in [0usize, 1000, 3000, 8000] {
            if blk != alpha_block {
                let xor = full0[blk].xor(&full1[blk]);
                assert!(xor.is_equal(&Block::zero()),
                    "Block {} should be zero at n={}", blk, n);
            }
        }
    }

    #[test]
    fn test_key_serialization_preserves_evaluation() {
        let dpf = Dpf::with_default_key();
        let alpha: u64 = 12345;
        let n: u8 = 16;
        
        let (k0, k1) = dpf.gen(alpha, n);

        // Serialize and deserialize
        let k0_bytes = k0.to_bytes();
        let k0_restored = DpfKey::from_bytes(&k0_bytes).unwrap();
        let k1_bytes = k1.to_bytes();
        let k1_restored = DpfKey::from_bytes(&k1_bytes).unwrap();

        // Evaluations should match
        for x in [0u64, alpha, 50000].iter() {
            let res0_orig = dpf.eval(&k0, *x);
            let res0_rest = dpf.eval(&k0_restored, *x);
            let res1_orig = dpf.eval(&k1, *x);
            let res1_rest = dpf.eval(&k1_restored, *x);

            assert_eq!(res0_orig, res0_rest, "k0 evaluation mismatch at x={}", x);
            assert_eq!(res1_orig, res1_rest, "k1 evaluation mismatch at x={}", x);
        }
    }
}