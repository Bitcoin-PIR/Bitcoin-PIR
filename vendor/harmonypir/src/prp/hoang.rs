//! Optimized small-domain PRP based on Hoang, Morris, and Rogaway (Crypto 2012).
//!
//! # Overview
//!
//! This implements Algorithm 5 from the HarmonyPIR paper: an optimized variant of the
//! Hoang et al. card-shuffle that reduces AES calls by 4× through **phase grouping**.
//!
//! ## How the card shuffle works (Algorithm 4, original)
//!
//! A random permutation over [N'] is viewed as shuffling N' cards. Over `r` rounds:
//! 1. A round key K[i] ∈ [N'] is sampled.
//! 2. Cards at positions X and X ⊕ K[i] are paired.
//! 3. They swap if the round function F_i(min(X, X')) = 1.
//!
//! To track a single card at position X, we only need to follow X through each round
//! (we don't track other cards). This takes O(r) AES calls.
//!
//! ## Phase optimization (Algorithm 5, our implementation)
//!
//! Rounds are grouped into phases of β = 4 rounds. Within a phase:
//!
//! 1. Compute the **phase group** G: the 2^β = 16 positions reachable from X
//!    by XORing subsets of the β round keys. Sort G.
//! 2. A single AES call on G[0] produces 128 bits. Each of the 16 positions
//!    in G is assigned β = 4 bits, giving 64 bits total (fits in 128-bit AES output).
//! 3. For each round within the phase, the round function for any pair is read
//!    from the appropriate bit of the AES output.
//!
//! This reduces AES calls from `r` to `r/β = r/4`.
//!
//! ## Round key derivation
//!
//! Round keys and round functions are derived from a single AES key `k`:
//! - Round key: `K[i] = AES_k("key" || i) mod N'`
//! - Round function: via phase group (see above)
//!
//! ## Security
//!
//! From Lemma 6.1: HarmonyPIR only needs an (N'/2, ε)-secure PRP, because the
//! server sees at most half the permutation evaluations. With r = Θ(log N' + |log ε|)
//! rounds, this is achieved.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Block};

use super::Prp;

/// Small-domain PRP using the optimized Hoang et al. card shuffle (Algorithm 5).
///
/// Suitable for HarmonyPIR0. Security reduces to AES.
pub struct HoangPrp {
    /// Domain size N'. Valid inputs are 0..N'-1.
    domain_size: usize,
    /// Number of rounds. Must be a multiple of BETA.
    r: usize,
    /// Precomputed round keys: K[i] ∈ [0, domain_size).
    round_keys: Vec<usize>,
    /// The AES cipher instance, used for deriving round functions.
    cipher: Aes128,
}

/// Phase size: number of rounds per phase.
const BETA: usize = 4;

impl HoangPrp {
    /// Create a new small-domain PRP.
    ///
    /// - `domain_size`: the permutation domain [N'].
    /// - `r`: number of rounds (must be a multiple of BETA = 4).
    /// - `key`: 16-byte AES key.
    pub fn new(domain_size: usize, r: usize, key: &[u8; 16]) -> Self {
        assert!(r % BETA == 0, "r must be a multiple of BETA={BETA}");
        assert!(domain_size >= 2, "domain must be >= 2");

        let cipher = Aes128::new(key.into());

        // Precompute round keys: K[i] = AES_k("key" || i) mod domain_size
        let round_keys: Vec<usize> = (0..r)
            .map(|i| {
                let plaintext = round_key_plaintext(i);
                let mut block = Block::from(plaintext);
                cipher.encrypt_block(&mut block);
                // Interpret first 8 bytes as u64, mod domain_size.
                let val = u64::from_le_bytes(block[..8].try_into().unwrap());
                (val % domain_size as u64) as usize
            })
            .collect();

        HoangPrp {
            domain_size,
            r,
            round_keys,
            cipher,
        }
    }

    /// Execute the shuffle on position X for a range of phases, in given direction.
    /// `forward = true` means phases 0..num_phases, forward rounds.
    /// `forward = false` means phases in reverse, rounds within each phase in reverse.
    fn shuffle(&self, mut x: usize, forward: bool) -> usize {
        let num_phases = self.r / BETA;
        let ds = self.domain_size;

        // Avoid Box<dyn Iterator> per call — unroll the direction logic.
        if forward {
            for phase_idx in 0..num_phases {
                x = self.apply_phase(x, phase_idx, ds, true);
            }
        } else {
            for phase_idx in (0..num_phases).rev() {
                x = self.apply_phase(x, phase_idx, ds, false);
            }
        }
        x
    }

    /// Apply a single phase (β=4 rounds) to position x.
    #[inline]
    fn apply_phase(&self, mut x: usize, phase_idx: usize, ds: usize, forward: bool) -> usize {
        let round_base = phase_idx * BETA;
        let pk = [
            self.round_keys[round_base],
            self.round_keys[round_base + 1],
            self.round_keys[round_base + 2],
            self.round_keys[round_base + 3],
        ];

        // Phase group: 16 positions reachable from x via subsets of round keys.
        let mut sorted = [0usize; 16];
        // Unrolled: XOR combinations of 4 keys → 16 values.
        sorted[0]  = x;
        sorted[1]  = x ^ pk[0];
        sorted[2]  = x ^ pk[1];
        sorted[3]  = x ^ pk[0] ^ pk[1];
        sorted[4]  = x ^ pk[2];
        sorted[5]  = x ^ pk[0] ^ pk[2];
        sorted[6]  = x ^ pk[1] ^ pk[2];
        sorted[7]  = x ^ pk[0] ^ pk[1] ^ pk[2];
        sorted[8]  = x ^ pk[3];
        sorted[9]  = x ^ pk[0] ^ pk[3];
        sorted[10] = x ^ pk[1] ^ pk[3];
        sorted[11] = x ^ pk[0] ^ pk[1] ^ pk[3];
        sorted[12] = x ^ pk[2] ^ pk[3];
        sorted[13] = x ^ pk[0] ^ pk[2] ^ pk[3];
        sorted[14] = x ^ pk[1] ^ pk[2] ^ pk[3];
        sorted[15] = x ^ pk[0] ^ pk[1] ^ pk[2] ^ pk[3];
        sorted.sort_unstable();

        // One AES call per phase.
        let mut blk = Block::from(round_func_plaintext(phase_idx, sorted[0]));
        self.cipher.encrypt_block(&mut blk);
        let f: u128 = u128::from_le_bytes(blk.into());

        if forward {
            for j in 0..BETA {
                x = self.apply_round(x, pk[j], ds, &sorted, f, j);
            }
        } else {
            for j in (0..BETA).rev() {
                x = self.apply_round(x, pk[j], ds, &sorted, f, j);
            }
        }
        x
    }

    /// Apply a single round within a phase.
    #[inline(always)]
    fn apply_round(&self, x: usize, rk: usize, ds: usize, sorted: &[usize; 16], f: u128, j: usize) -> usize {
        let xp = x ^ rk;
        if xp >= ds { return x; }
        let xmin = x.min(xp);
        // Binary search on 16-element sorted array (4 comparisons vs ~8 for linear).
        let p = sorted.binary_search(&xmin).unwrap();
        if (f >> (p * BETA + j)) & 1 == 1 { xp } else { x }
    }

    /// Apply one phase to 4 elements simultaneously with AES-NI pipelining.
    #[inline]
    fn apply_phase_4way(&self, x: &mut [usize; 4], phase_idx: usize, forward: bool) {
        let ds = self.domain_size;
        let round_base = phase_idx * BETA;
        let pk = [
            self.round_keys[round_base],
            self.round_keys[round_base + 1],
            self.round_keys[round_base + 2],
            self.round_keys[round_base + 3],
        ];

        // Compute + sort phase groups for all 4 elements.
        let mut sorted = [[0usize; 16]; 4];
        for e in 0..4 {
            let xe = x[e];
            sorted[e][0]  = xe;
            sorted[e][1]  = xe ^ pk[0];
            sorted[e][2]  = xe ^ pk[1];
            sorted[e][3]  = xe ^ pk[0] ^ pk[1];
            sorted[e][4]  = xe ^ pk[2];
            sorted[e][5]  = xe ^ pk[0] ^ pk[2];
            sorted[e][6]  = xe ^ pk[1] ^ pk[2];
            sorted[e][7]  = xe ^ pk[0] ^ pk[1] ^ pk[2];
            sorted[e][8]  = xe ^ pk[3];
            sorted[e][9]  = xe ^ pk[0] ^ pk[3];
            sorted[e][10] = xe ^ pk[1] ^ pk[3];
            sorted[e][11] = xe ^ pk[0] ^ pk[1] ^ pk[3];
            sorted[e][12] = xe ^ pk[2] ^ pk[3];
            sorted[e][13] = xe ^ pk[0] ^ pk[2] ^ pk[3];
            sorted[e][14] = xe ^ pk[1] ^ pk[2] ^ pk[3];
            sorted[e][15] = xe ^ pk[0] ^ pk[1] ^ pk[2] ^ pk[3];
            sorted[e].sort_unstable();
        }

        // 4-way AES encrypt — pipelined through AES-NI.
        let mut blocks: [Block; 4] = [
            Block::from(round_func_plaintext(phase_idx, sorted[0][0])),
            Block::from(round_func_plaintext(phase_idx, sorted[1][0])),
            Block::from(round_func_plaintext(phase_idx, sorted[2][0])),
            Block::from(round_func_plaintext(phase_idx, sorted[3][0])),
        ];
        self.cipher.encrypt_blocks(&mut blocks);

        let f = [
            u128::from_le_bytes(blocks[0].into()),
            u128::from_le_bytes(blocks[1].into()),
            u128::from_le_bytes(blocks[2].into()),
            u128::from_le_bytes(blocks[3].into()),
        ];

        if forward {
            for j in 0..BETA {
                for e in 0..4 { x[e] = self.apply_round(x[e], pk[j], ds, &sorted[e], f[e], j); }
            }
        } else {
            for j in (0..BETA).rev() {
                for e in 0..4 { x[e] = self.apply_round(x[e], pk[j], ds, &sorted[e], f[e], j); }
            }
        }
    }

    /// Shuffle 4 elements forward simultaneously with AES-NI pipelining.
    fn shuffle_forward_4way(&self, mut x: [usize; 4]) -> [usize; 4] {
        let num_phases = self.r / BETA;
        for phase_idx in 0..num_phases {
            self.apply_phase_4way(&mut x, phase_idx, true);
        }
        x
    }

    /// Shuffle 4 elements inverse simultaneously with AES-NI pipelining.
    fn shuffle_inverse_4way(&self, mut x: [usize; 4]) -> [usize; 4] {
        let num_phases = self.r / BETA;
        for phase_idx in (0..num_phases).rev() {
            self.apply_phase_4way(&mut x, phase_idx, false);
        }
        x
    }
}

impl Prp for HoangPrp {
    fn forward(&self, x: usize) -> usize {
        assert!(x < self.domain_size, "input {x} >= domain {}", self.domain_size);
        self.shuffle(x, true)
    }

    fn inverse(&self, y: usize) -> usize {
        assert!(y < self.domain_size, "input {y} >= domain {}", self.domain_size);
        self.shuffle(y, false)
    }

    fn domain(&self) -> usize {
        self.domain_size
    }

    fn forward_4(&self, xs: [usize; 4]) -> [usize; 4] {
        self.shuffle_forward_4way(xs)
    }

    fn inverse_4(&self, ys: [usize; 4]) -> [usize; 4] {
        self.shuffle_inverse_4way(ys)
    }
}

#[cfg(feature = "alf")]
impl super::BatchPrp for HoangPrp {
    fn batch_forward(&self) -> Vec<usize> {
        use rayon::prelude::*;
        let n = self.domain_size;
        let mut result = vec![0usize; n];
        // Process in chunks of 4 for AES-NI pipelining, parallelized across cores.
        result
            .par_chunks_mut(4)
            .enumerate()
            .for_each(|(ci, out)| {
                let base = ci * 4;
                // Clamp to valid domain for the last (possibly partial) chunk.
                let xs = [
                    base,
                    (base + 1).min(n - 1),
                    (base + 2).min(n - 1),
                    (base + 3).min(n - 1),
                ];
                let ys = self.shuffle_forward_4way(xs);
                for (o, &y) in out.iter_mut().zip(ys.iter()) {
                    *o = y;
                }
            });
        result
    }
}

#[cfg(not(feature = "alf"))]
impl super::BatchPrp for HoangPrp {
    fn batch_forward(&self) -> Vec<usize> {
        let n = self.domain_size;
        let mut result = vec![0usize; n];
        // Process in chunks of 4 for AES-NI pipelining (single-threaded fallback).
        for ci in 0..(n + 3) / 4 {
            let base = ci * 4;
            let xs = [
                base,
                (base + 1).min(n - 1),
                (base + 2).min(n - 1),
                (base + 3).min(n - 1),
            ];
            let ys = self.shuffle_forward_4way(xs);
            let end = (base + 4).min(n);
            for (i, &y) in (base..end).zip(ys.iter()) {
                result[i] = y;
            }
        }
        result
    }
}

/// Build the 16-byte AES plaintext for round key derivation.
/// Format: "key\0" (4 bytes) || round_index (4 bytes LE) || padding (8 bytes of 0).
fn round_key_plaintext(round: usize) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..3].copy_from_slice(b"key");
    buf[4..8].copy_from_slice(&(round as u32).to_le_bytes());
    buf
}

/// Build the 16-byte AES plaintext for the round function.
/// Format: "fn\0" (3 bytes) || phase_index (4 bytes LE) || g0 (4 bytes LE) || padding.
fn round_func_plaintext(phase: usize, g0: usize) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(b"fn");
    buf[3..7].copy_from_slice(&(phase as u32).to_le_bytes());
    buf[7..11].copy_from_slice(&(g0 as u32).to_le_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_inverse_roundtrip() {
        let key = [0x42u8; 16];
        let domain = 64;
        let r = 44; // must be multiple of 4
        let prp = HoangPrp::new(domain, r, &key);

        for x in 0..domain {
            let y = prp.forward(x);
            assert!(y < domain, "forward({x}) = {y} out of range");
            let x_back = prp.inverse(y);
            assert_eq!(x_back, x, "inverse(forward({x})) = {x_back} != {x}");
        }
    }

    #[test]
    fn test_is_permutation() {
        let key = [0xAB; 16];
        let domain = 32;
        let r = 44;
        let prp = HoangPrp::new(domain, r, &key);

        let mut outputs: Vec<usize> = (0..domain).map(|x| prp.forward(x)).collect();
        outputs.sort();
        let expected: Vec<usize> = (0..domain).collect();
        assert_eq!(outputs, expected, "forward is not a permutation");
    }

    #[test]
    fn test_non_power_of_two_domain() {
        let key = [0x42u8; 16];
        let domain = 100; // Not a power of 2
        let r = 44;
        let prp = HoangPrp::new(domain, r, &key);

        // forward must stay in range
        for x in 0..domain {
            let y = prp.forward(x);
            assert!(y < domain, "forward({x}) = {y} out of range (domain={domain})");
        }

        // must be a permutation
        let mut outputs: Vec<usize> = (0..domain).map(|x| prp.forward(x)).collect();
        outputs.sort();
        assert_eq!(outputs, (0..domain).collect::<Vec<_>>(), "not a permutation");

        // inverse must round-trip
        for x in 0..domain {
            let y = prp.forward(x);
            let x_back = prp.inverse(y);
            assert_eq!(x_back, x, "inverse(forward({x})) = {x_back} != {x}");
        }
    }

    #[test]
    fn test_large_non_power_of_two() {
        let key = [0xAB; 16];
        let domain = 754245; // Real index bucket size
        let r = 64;
        let prp = HoangPrp::new(domain, r, &key);

        // Spot-check a handful of values stay in range and round-trip.
        for x in [0, 1, 2, 100, domain / 2, domain - 1] {
            let y = prp.forward(x);
            assert!(y < domain, "forward({x}) = {y} >= {domain}");
            let x_back = prp.inverse(y);
            assert_eq!(x_back, x, "round-trip failed for x={x}");
        }
    }

    #[test]
    fn test_different_keys_different_permutations() {
        let domain = 16;
        let r = 44;
        let prp1 = HoangPrp::new(domain, r, &[1u8; 16]);
        let prp2 = HoangPrp::new(domain, r, &[2u8; 16]);

        let out1: Vec<usize> = (0..domain).map(|x| prp1.forward(x)).collect();
        let out2: Vec<usize> = (0..domain).map(|x| prp2.forward(x)).collect();
        assert_ne!(out1, out2, "different keys should give different permutations");
    }

    #[test]
    fn test_4way_matches_sequential() {
        let key = [0x42u8; 16];
        // Non-power-of-2 domain (like real usage).
        let domain = 100;
        let r = 44;
        let prp = HoangPrp::new(domain, r, &key);

        // Sequential: forward() one at a time.
        let sequential: Vec<usize> = (0..domain).map(|x| prp.forward(x)).collect();

        // 4-way: shuffle_forward_4way in chunks.
        let mut four_way = vec![0usize; domain];
        for ci in 0..(domain + 3) / 4 {
            let base = ci * 4;
            let xs = [
                base,
                (base + 1).min(domain - 1),
                (base + 2).min(domain - 1),
                (base + 3).min(domain - 1),
            ];
            let ys = prp.shuffle_forward_4way(xs);
            for (i, &y) in (base..(base + 4).min(domain)).zip(ys.iter()) {
                four_way[i] = y;
            }
        }

        assert_eq!(sequential, four_way, "4-way must match sequential forward()");
    }

    #[test]
    fn test_4way_large_domain() {
        // Test with a domain size close to real Bitcoin index bucket.
        let key = [0xAB; 16];
        let domain = 10007; // prime, non-power-of-2
        let r = 56;
        let prp = HoangPrp::new(domain, r, &key);

        let sequential: Vec<usize> = (0..domain).map(|x| prp.forward(x)).collect();

        let mut four_way = vec![0usize; domain];
        for ci in 0..(domain + 3) / 4 {
            let base = ci * 4;
            let xs = [
                base,
                (base + 1).min(domain - 1),
                (base + 2).min(domain - 1),
                (base + 3).min(domain - 1),
            ];
            let ys = prp.shuffle_forward_4way(xs);
            for (i, &y) in (base..(base + 4).min(domain)).zip(ys.iter()) {
                four_way[i] = y;
            }
        }

        assert_eq!(sequential, four_way, "4-way must match sequential at domain={}", domain);
    }
}
