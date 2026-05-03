use crate::bitstring::BitstringGen;
use crate::cache::{CounterCache, PartitionCache};

/// FastPRP: Fast Pseudo-Random Permutation for small domains.
///
/// Implements the algorithm from Stefanov & Shi (2012).
/// Provides both Permute (encryption) and Unpermute (decryption)
/// operations over an arbitrary domain {0, 1, ..., N-1}.
pub struct FastPrp {
    gen: BitstringGen,
    cache: CounterCache,
    pcache: PartitionCache,
    n: u64,
    max_depth: u32,
}

impl FastPrp {
    /// Create a new FastPRP instance.
    ///
    /// - `key`: 128-bit AES key
    /// - `n`: domain size (elements are in {0, 1, ..., n-1})
    pub fn new(key: &[u8; 16], n: u64) -> Self {
        assert!(n >= 2, "domain size must be at least 2");

        let gen = BitstringGen::new(key, n);

        // Cache stride s = 2 * sqrt(N)
        let stride = (2.0 * (n as f64).sqrt()).ceil() as u64;
        let stride = stride.max(2).min(n);
        let cache = CounterCache::new(&gen, stride);

        // Max depth: 8 * 2 * ln(N) per Corollary 2 (k=1)
        let max_depth = (16.0 * (n as f64).ln()).ceil() as u32;
        let max_depth = max_depth.max(64);

        // Partition-boundary cache (Section 4.2): covers same depths as stride cache.
        let pcache = PartitionCache::new(&gen, n, cache.num_depths);

        Self {
            gen,
            cache,
            pcache,
            n,
            max_depth,
        }
    }

    /// Create with a custom cache stride.
    pub fn with_stride(key: &[u8; 16], n: u64, stride: u64) -> Self {
        assert!(n >= 2, "domain size must be at least 2");

        let gen = BitstringGen::new(key, n);
        let stride = stride.max(2).min(n);
        let cache = CounterCache::new(&gen, stride);
        let max_depth = (16.0 * (n as f64).ln()).ceil() as u32;
        let max_depth = max_depth.max(64);

        let pcache = PartitionCache::new(&gen, n, cache.num_depths);

        Self {
            gen,
            cache,
            pcache,
            n,
            max_depth,
        }
    }

    /// Permute (encrypt): compute PRP(K, x).
    ///
    /// Maps x in {0, ..., N-1} to a pseudo-random output in {0, ..., N-1}.
    pub fn permute(&self, x: u64) -> u64 {
        assert!(x < self.n, "input {x} out of domain [0, {})", self.n);
        self.permute_rec(x, 0, self.n, 0)
    }

    /// Recursive permutation (Figure 2 + Section 4.2 counter alignment).
    ///
    /// When the partition cache has boundaries for depth d:
    ///   - c0_len = O(1) from partition cache (both alpha and alpha+len are boundaries)
    ///   - c1(0, alpha) = O(1) from partition cache
    ///   - c1(0, alpha+x) = 1 stride-cache scan
    /// Total: **1 scan** per depth instead of 3.
    fn permute_rec(&self, x: u64, alpha: u64, len: u64, d: u32) -> u64 {
        if len <= 1 {
            return alpha;
        }

        if d >= self.max_depth {
            return alpha + x;
        }

        let bit = self.gen.get_bit(d, alpha + x);

        let (c0_x, c0_len) = match self.pcache.cumulative_ones(d, alpha) {
            Some(c1_alpha) => {
                // Partition cache hit: c0_len is free, c0_x needs 1 scan.
                let c1_end = self.pcache.cumulative_ones(d, alpha + len).unwrap();
                let c0_len = len - (c1_end - c1_alpha);
                let c1_at_ax = self.cache.cumulative_ones(&self.gen, d, alpha + x);
                let c0_x = x - (c1_at_ax - c1_alpha);
                (c0_x, c0_len)
            }
            None => {
                // Beyond partition cache depth — fall back to stride cache.
                self.cache.c0_pair(&self.gen, d, alpha, x, len)
            }
        };

        if bit == 0 {
            if c0_len == 0 { return alpha; }
            self.permute_rec(c0_x, alpha, c0_len, d + 1)
        } else {
            let c1_x = x - c0_x;
            let c1_len = len - c0_len;
            if c1_len == 0 { return alpha + c0_len; }
            self.permute_rec(c1_x, alpha + c0_len, c1_len, d + 1)
        }
    }

    /// Unpermute (decrypt): compute PRP^{-1}(K, y).
    ///
    /// Maps y in {0, ..., N-1} back to the original input.
    pub fn unpermute(&self, y: u64) -> u64 {
        assert!(y < self.n, "input {y} out of domain [0, {})", self.n);
        self.unpermute_rec(y, 0, self.n, 0)
    }

    /// Recursive inverse permutation (Figure 3 + Sections 4.1/4.2).
    ///
    /// Uses partition cache for O(1) c0_len, and passes the pre-known
    /// ones_before_alpha into c0_inv/c1_inv to avoid recomputing it.
    /// The inner scan is bidirectional (Section 4.1).
    fn unpermute_rec(&self, y: u64, alpha: u64, len: u64, d: u32) -> u64 {
        if len <= 1 {
            return 0;
        }

        if d >= self.max_depth {
            return y;
        }

        // Try partition cache for both c0 and the ones_before_alpha hint.
        match self.pcache.cumulative_ones(d, alpha) {
            Some(c1_alpha) => {
                let c1_end = self.pcache.cumulative_ones(d, alpha + len).unwrap();
                let c0 = len - (c1_end - c1_alpha);

                if y < c0 {
                    let x_prime = self.unpermute_rec(y, alpha, c0, d + 1);
                    self.cache.c0_inv_hint(&self.gen, d, alpha, x_prime + 1, c1_alpha)
                } else {
                    let y_prime = y - c0;
                    let c1 = len - c0;
                    let x_prime = self.unpermute_rec(y_prime, alpha + c0, c1, d + 1);
                    self.cache.c1_inv_hint(&self.gen, d, alpha, x_prime + 1, c1_alpha)
                }
            }
            None => {
                let c0 = self.cache.c0(&self.gen, d, alpha, len);
                if y < c0 {
                    let x_prime = self.unpermute_rec(y, alpha, c0, d + 1);
                    self.cache.c0_inv(&self.gen, d, alpha, x_prime + 1)
                } else {
                    let y_prime = y - c0;
                    let c1 = len - c0;
                    let x_prime = self.unpermute_rec(y_prime, alpha + c0, c1, d + 1);
                    self.cache.c1_inv(&self.gen, d, alpha, x_prime + 1)
                }
            }
        }
    }

    /// Permute 4 inputs simultaneously.
    ///
    /// Two-phase per-element C0 computation:
    /// - **Large partitions** (len > threshold): use counter cache with `c0_pair`
    ///   (shares the `ones_before_alpha` scan, saving 25% of AES work).
    /// - **Small partitions** (len <= threshold): precompute AES blocks for
    ///   [alpha..alpha+len) via `encrypt_blocks`, then answer C0 queries with
    ///   `count_zeros_bulk` on the precomputed blocks (no per-query AES).
    pub fn permute_4(&self, inputs: [u64; 4]) -> [u64; 4] {
        let mut x = inputs;
        let mut alpha = [0u64; 4];
        let mut len = [self.n; 4];
        let mut results = [0u64; 4];
        let mut done = [false; 4];

        // Below this threshold, precompute blocks instead of using cache.
        // The cache scans up to 2s bits per c0 call. When the partition is
        // smaller than that, a full precompute + prefix lookup is cheaper
        // (one bulk encrypt_blocks vs two scanning passes).
        let threshold = self.cache.stride * 2;

        // Reusable buffer for precomputed partition blocks.
        let mut part_blocks: Vec<u128> = Vec::new();

        for d in 0u32..self.max_depth {
            if done[0] & done[1] & done[2] & done[3] {
                break;
            }

            for i in 0..4 {
                if !done[i] && len[i] <= 1 {
                    results[i] = alpha[i];
                    done[i] = true;
                }
            }
            if done[0] & done[1] & done[2] & done[3] {
                break;
            }

            // Pipelined 4-way bit lookup.
            let bits = self.gen.get_bits_4(
                d,
                alpha[0] + x[0],
                alpha[1] + x[1],
                alpha[2] + x[2],
                alpha[3] + x[3],
            );

            let gs = d as u64 * self.n;

            for i in 0..4 {
                if done[i] {
                    continue;
                }

                let a = alpha[i];
                let l = len[i];
                let xi = x[i];
                let bit = bits[i];

                let (c0_x, c0_len) = if l <= threshold {
                    // Small partition: precompute blocks, answer from buffer.
                    let base = self.gen.fill_range_blocks(d, a, l, &mut part_blocks);
                    (
                        Self::count_zeros_bulk(&part_blocks, base, gs, a, xi),
                        Self::count_zeros_bulk(&part_blocks, base, gs, a, l),
                    )
                } else if let Some(c1_alpha) = self.pcache.cumulative_ones(d, a) {
                    // Partition cache hit: c0_len free, c0_x needs 1 scan.
                    let c1_end = self.pcache.cumulative_ones(d, a + l).unwrap();
                    let c0_len = l - (c1_end - c1_alpha);
                    let c1_ax = self.cache.cumulative_ones(&self.gen, d, a + xi);
                    let c0_x = xi - (c1_ax - c1_alpha);
                    (c0_x, c0_len)
                } else {
                    // Fall back to stride cache.
                    self.cache.c0_pair(&self.gen, d, a, xi, l)
                };

                if bit == 0 {
                    x[i] = c0_x;
                    len[i] = c0_len;
                } else {
                    x[i] = xi - c0_x;
                    alpha[i] += c0_len;
                    len[i] = l - c0_len;
                }
            }
        }

        for i in 0..4 {
            if !done[i] {
                results[i] = alpha[i] + x[i];
            }
        }
        results
    }

    /// Batch-permute the entire domain at once.
    ///
    /// Returns a Vec where `result[x] = permute(x)` for all x in {0, ..., N-1}.
    ///
    /// This is the radix-sort view from Section 3.2: process ALL elements level-by-level.
    /// O(N) work per depth × O(log N) depths = O(N log N) total.
    ///
    /// Optimizations:
    /// - **u32 element arrays**: halves memory bandwidth (N < 2^32)
    /// - **Bulk AES generation**: `encrypt_blocks` pipelines 8 AES ops on AES-NI
    /// - **Block-oriented inner loop**: loads one AES block, processes up to 128 elements
    /// - **Branchless partition**: avoids branch mispredictions on random bits
    /// - **Double-buffered arrays**: O(1) pointer swap instead of O(N) memcpy per depth
    pub fn batch_permute(&self) -> Vec<u64> {
        let n = self.n as usize;

        // Use u32 internally — halves memory traffic vs u64.
        let mut buf_a: Vec<u32> = (0..n as u32).collect();
        let mut buf_b: Vec<u32> = vec![0u32; n];

        // Partition tracking — reuse Vecs across depths.
        let mut partitions: Vec<(u32, u32)> = vec![(0, self.n as u32)];
        let mut new_partitions: Vec<(u32, u32)> = Vec::with_capacity(n.min(1 << 20));

        // Pre-allocated blocks buffer — reused each depth.
        let mut blocks: Vec<u128> = Vec::new();

        let mut non_singletons = 1usize;

        for d in 0u32..self.max_depth {
            if non_singletons == 0 {
                break;
            }

            // Bulk AES generation with pipelining.
            let base_block = self.gen.fill_bitstring_blocks(d, &mut blocks);
            let global_start = d as u64 * self.n;

            new_partitions.clear();
            non_singletons = 0;

            for &(alpha, len) in &partitions {
                if len <= 1 {
                    if len == 1 {
                        buf_b[alpha as usize] = buf_a[alpha as usize];
                    }
                    new_partitions.push((alpha, len));
                    continue;
                }

                // Popcount-based zero counting on bulk blocks.
                let c0 = Self::count_zeros_bulk(
                    &blocks, base_block, global_start, alpha as u64, len as u64,
                ) as u32;
                let c1 = len - c0;

                // Block-oriented + branchless stable partition.
                let mut zi = alpha as usize;
                let mut oi = (alpha + c0) as usize;

                let abs_start = global_start + alpha as u64;
                let abs_end = abs_start + len as u64;
                let first_blk = abs_start / 128;
                let last_blk = (abs_end - 1) / 128;
                let mut elem_idx = alpha as usize;

                for blk_idx in first_blk..=last_blk {
                    let local_blk = (blk_idx - base_block) as usize;
                    let block_val = blocks[local_blk];

                    let bit_lo = if blk_idx == first_blk {
                        (abs_start % 128) as u32
                    } else {
                        0
                    };
                    let bit_hi = if blk_idx == last_blk {
                        let e = (abs_end % 128) as u32;
                        if e == 0 { 128 } else { e }
                    } else {
                        128
                    };

                    // Process u64 halves for cheaper bit extraction.
                    let lo = block_val as u64;
                    let hi = (block_val >> 64) as u64;

                    let half_boundary = 64u32.clamp(bit_lo, bit_hi);

                    // Lower 64 bits
                    for bit_pos in bit_lo..half_boundary {
                        let bit = ((lo >> bit_pos) & 1) as usize;
                        let elem = buf_a[elem_idx];
                        // Branchless: zi when bit=0, oi when bit=1
                        let write_pos = zi + (oi - zi) * bit;
                        buf_b[write_pos] = elem;
                        zi += 1 - bit;
                        oi += bit;
                        elem_idx += 1;
                    }

                    // Upper 64 bits
                    let upper_start = if bit_lo > 64 { bit_lo } else { 64 };
                    for bit_pos in upper_start..bit_hi {
                        let bit = ((hi >> (bit_pos - 64)) & 1) as usize;
                        let elem = buf_a[elem_idx];
                        let write_pos = zi + (oi - zi) * bit;
                        buf_b[write_pos] = elem;
                        zi += 1 - bit;
                        oi += bit;
                        elem_idx += 1;
                    }
                }

                if c0 > 0 {
                    new_partitions.push((alpha, c0));
                    if c0 > 1 { non_singletons += 1; }
                }
                if c1 > 0 {
                    new_partitions.push((alpha + c0, c1));
                    if c1 > 1 { non_singletons += 1; }
                }
            }

            // O(1) pointer swap instead of O(N) memcpy.
            std::mem::swap(&mut buf_a, &mut buf_b);
            std::mem::swap(&mut partitions, &mut new_partitions);
        }

        // Convert: result[element] = position.
        let mut result = vec![0u64; n];
        for (pos, &elem) in buf_a.iter().enumerate() {
            result[elem as usize] = pos as u64;
        }
        result
    }

    /// Count zeros in a range of pre-generated blocks using popcount.
    fn count_zeros_bulk(
        blocks: &[u128],
        base_block: u64,
        global_start: u64,
        local_start: u64,
        count: u64,
    ) -> u64 {
        if count == 0 {
            return 0;
        }
        let abs_start = global_start + local_start;
        let abs_end = abs_start + count;

        let first_blk = abs_start / 128;
        let last_blk = (abs_end - 1) / 128;

        let first_local = (first_blk - base_block) as usize;
        let last_local = (last_blk - base_block) as usize;

        let ones: u64;

        if first_local == last_local {
            let block = blocks[first_local];
            let start_bit = (abs_start % 128) as u32;
            let end_bit = (abs_end % 128) as u32;
            let end_bit = if end_bit == 0 { 128 } else { end_bit };
            let num_bits = end_bit - start_bit;
            let mask = if num_bits == 128 {
                u128::MAX
            } else {
                ((1u128 << num_bits) - 1) << start_bit
            };
            ones = (block & mask).count_ones() as u64;
        } else {
            let mut acc = 0u64;
            let start_bit = (abs_start % 128) as u32;
            let mask = if start_bit == 0 { u128::MAX } else { u128::MAX << start_bit };
            acc += (blocks[first_local] & mask).count_ones() as u64;

            for i in (first_local + 1)..last_local {
                acc += blocks[i].count_ones() as u64;
            }

            let end_bit = (abs_end % 128) as u32;
            if end_bit == 0 {
                acc += blocks[last_local].count_ones() as u64;
            } else {
                let mask = (1u128 << end_bit) - 1;
                acc += (blocks[last_local] & mask).count_ones() as u64;
            }
            ones = acc;
        }

        count - ones
    }

    pub fn domain_size(&self) -> u64 {
        self.n
    }

    /// Cache stride used for single-element permute/unpermute.
    pub fn cache_stride(&self) -> u64 {
        self.cache.stride
    }

    /// Cache memory usage in bytes (for single-element operations).
    pub fn cache_size_bytes(&self) -> usize {
        self.cache.size_bytes()
    }

    /// Access the counter cache (for serialization / persistence).
    pub fn counter_cache(&self) -> &CounterCache {
        &self.cache
    }

    /// Access the partition cache (for serialization / persistence).
    pub fn partition_cache(&self) -> &PartitionCache {
        &self.pcache
    }

    /// Reconstruct a FastPrp from a key, domain size, and pre-built caches.
    ///
    /// The BitstringGen is deterministic from (key, n) and needs no persistence.
    /// Use this with caches obtained from `counter_cache()` / `partition_cache()`
    /// and reconstructed via `CounterCache::from_raw()` / `PartitionCache::from_raw()`.
    pub fn from_parts(key: &[u8; 16], n: u64, cache: CounterCache, pcache: PartitionCache) -> Self {
        assert!(n >= 2, "domain size must be at least 2");
        let gen = BitstringGen::new(key, n);
        let max_depth = (16.0 * (n as f64).ln()).ceil() as u32;
        let max_depth = max_depth.max(64);
        Self { gen, cache, pcache, n, max_depth }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permute_unpermute_small() {
        let key = [0u8; 16];
        let n = 8u64;
        let prp = FastPrp::new(&key, n);

        for x in 0..n {
            let y = prp.permute(x);
            assert!(y < n, "permute({x}) = {y} out of range");
            let x_back = prp.unpermute(y);
            assert_eq!(x_back, x, "unpermute(permute({x})) = {x_back} != {x}");
        }
    }

    #[test]
    fn test_is_permutation_small() {
        let key = [1u8; 16];
        let n = 16u64;
        let prp = FastPrp::new(&key, n);

        let mut outputs: Vec<u64> = (0..n).map(|x| prp.permute(x)).collect();
        outputs.sort();
        let expected: Vec<u64> = (0..n).collect();
        assert_eq!(outputs, expected, "not a valid permutation");
    }

    #[test]
    fn test_is_permutation_medium() {
        let key = [42u8; 16];
        let n = 256u64;
        let prp = FastPrp::new(&key, n);

        let mut outputs: Vec<u64> = (0..n).map(|x| prp.permute(x)).collect();
        outputs.sort();
        let expected: Vec<u64> = (0..n).collect();
        assert_eq!(outputs, expected, "not a valid permutation for N=256");
    }

    #[test]
    fn test_roundtrip_256() {
        let key = [99u8; 16];
        let n = 256u64;
        let prp = FastPrp::new(&key, n);

        for x in 0..n {
            let y = prp.permute(x);
            let x_back = prp.unpermute(y);
            assert_eq!(x_back, x, "roundtrip failed for x={x}, y={y}");
        }
    }

    #[test]
    fn test_different_keys_different_permutations() {
        let n = 64u64;
        let prp1 = FastPrp::new(&[0u8; 16], n);
        let prp2 = FastPrp::new(&[1u8; 16], n);

        let out1: Vec<u64> = (0..n).map(|x| prp1.permute(x)).collect();
        let out2: Vec<u64> = (0..n).map(|x| prp2.permute(x)).collect();

        assert_ne!(out1, out2, "different keys should produce different permutations");
    }

    #[test]
    fn test_permute_1024() {
        let key = [7u8; 16];
        let n = 1024u64;
        let prp = FastPrp::new(&key, n);

        let mut outputs: Vec<u64> = (0..n).map(|x| prp.permute(x)).collect();
        outputs.sort();
        let expected: Vec<u64> = (0..n).collect();
        assert_eq!(outputs, expected);

        for x in (0..n).step_by(10) {
            let y = prp.permute(x);
            let x_back = prp.unpermute(y);
            assert_eq!(x_back, x);
        }
    }

    #[test]
    fn test_non_power_of_two() {
        let key = [55u8; 16];
        let n = 100u64;
        let prp = FastPrp::new(&key, n);

        let mut outputs: Vec<u64> = (0..n).map(|x| prp.permute(x)).collect();
        outputs.sort();
        let expected: Vec<u64> = (0..n).collect();
        assert_eq!(outputs, expected, "not a valid permutation for N=100");

        for x in 0..n {
            let y = prp.permute(x);
            let x_back = prp.unpermute(y);
            assert_eq!(x_back, x);
        }
    }

    #[test]
    fn test_domain_size_2() {
        let key = [0u8; 16];
        let prp = FastPrp::new(&key, 2);
        let y0 = prp.permute(0);
        let y1 = prp.permute(1);
        assert!(y0 < 2 && y1 < 2);
        assert_ne!(y0, y1);
        assert_eq!(prp.unpermute(y0), 0);
        assert_eq!(prp.unpermute(y1), 1);
    }

    #[test]
    fn test_larger_domain_2048() {
        let key = [123u8; 16];
        let n = 2048u64;
        let prp = FastPrp::new(&key, n);

        let mut outputs: Vec<u64> = (0..n).map(|x| prp.permute(x)).collect();
        outputs.sort();
        let expected: Vec<u64> = (0..n).collect();
        assert_eq!(outputs, expected);

        for x in [0, 1, 100, 500, 1000, 2047] {
            assert_eq!(prp.unpermute(prp.permute(x)), x);
        }
    }

    #[test]
    fn test_permute_4_matches_pointwise() {
        let key = [42u8; 16];
        let n = 2048u64;
        let prp = FastPrp::new(&key, n);

        for base in (0..n).step_by(4) {
            let inputs = [base, base + 1, base + 2, base + 3];
            let results = prp.permute_4(inputs);
            for i in 0..4 {
                assert_eq!(
                    results[i],
                    prp.permute(inputs[i]),
                    "permute_4 mismatch at input {}",
                    inputs[i]
                );
            }
        }
    }

    #[test]
    fn test_batch_permute_matches_pointwise() {
        let key = [42u8; 16];
        let n = 256u64;
        let prp = FastPrp::new(&key, n);

        let batch = prp.batch_permute();
        for x in 0..n {
            assert_eq!(
                batch[x as usize],
                prp.permute(x),
                "batch[{x}] != permute({x})"
            );
        }
    }

    #[test]
    fn test_batch_permute_is_permutation() {
        let key = [7u8; 16];
        let n = 1024u64;
        let prp = FastPrp::new(&key, n);

        let batch = prp.batch_permute();
        assert_eq!(batch.len(), n as usize);

        let mut sorted = batch.clone();
        sorted.sort();
        let expected: Vec<u64> = (0..n).collect();
        assert_eq!(sorted, expected, "batch_permute is not a valid permutation");
    }

    #[test]
    fn test_batch_permute_non_power_of_two() {
        let key = [55u8; 16];
        let n = 100u64;
        let prp = FastPrp::new(&key, n);

        let batch = prp.batch_permute();
        for x in 0..n {
            assert_eq!(batch[x as usize], prp.permute(x));
        }
    }

    #[test]
    fn test_batch_permute_small() {
        let key = [0u8; 16];
        let n = 8u64;
        let prp = FastPrp::new(&key, n);

        let batch = prp.batch_permute();
        for x in 0..n {
            assert_eq!(batch[x as usize], prp.permute(x));
        }
    }

    #[test]
    fn test_batch_permute_2048() {
        let key = [123u8; 16];
        let n = 2048u64;
        let prp = FastPrp::new(&key, n);

        let batch = prp.batch_permute();
        let mut sorted = batch.clone();
        sorted.sort();
        let expected: Vec<u64> = (0..n).collect();
        assert_eq!(sorted, expected);

        for x in (0..n).step_by(100) {
            assert_eq!(batch[x as usize], prp.permute(x));
        }
    }
}
