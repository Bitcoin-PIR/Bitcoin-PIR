use crate::bitstring::BitstringGen;

/// Partition-boundary cache (Section 4.2: Counter Alignment).
///
/// At each depth d, stores cumulative C1(β_d, 0, pos) at every partition
/// boundary position. This makes C0(β_d, alpha, len) a pure O(1) lookup
/// when both alpha and alpha+len are partition boundaries — which they
/// always are in the permute/unpermute recursion.
///
/// Also provides cumulative_ones(d, alpha) so that the stride cache only
/// needs one scan (for alpha+x) instead of three.
pub struct PartitionCache {
    /// For each depth: sorted Vec of (position, cumulative_C1_from_0_to_pos).
    depths: Vec<Vec<(u64, u32)>>,
}

impl PartitionCache {
    /// Reconstruct a PartitionCache from previously extracted raw data.
    pub fn from_raw(depths: Vec<Vec<(u64, u32)>>) -> Self {
        Self { depths }
    }

    /// Access the raw partition boundary data for serialization.
    pub fn raw_depths(&self) -> &Vec<Vec<(u64, u32)>> {
        &self.depths
    }

    /// Build by simulating the partition tree (boundary tracking only, no element shuffling).
    pub fn new(gen: &BitstringGen, n: u64, num_depths: u32) -> Self {
        let mut depths: Vec<Vec<(u64, u32)>> = Vec::new();
        let mut partitions: Vec<(u64, u64)> = vec![(0, n)];

        for d in 0..num_depths {
            if partitions.iter().all(|&(_, l)| l <= 1) {
                break;
            }

            // Boundaries are contiguous: [alpha_0, alpha_1, ..., alpha_k, N].
            // Scan β_d left-to-right, accumulating C1 at each boundary.
            let num_bounds = partitions.len() + 1;
            let mut entries: Vec<(u64, u32)> = Vec::with_capacity(num_bounds);

            let mut prev_pos = 0u64;
            let mut cum_c1 = 0u32;

            for &(alpha, _) in &partitions {
                if alpha > prev_pos {
                    cum_c1 += gen.count_ones_range(d, prev_pos, alpha - prev_pos) as u32;
                }
                entries.push((alpha, cum_c1));
                prev_pos = alpha;
            }
            // Final boundary at N.
            let &(last_a, last_l) = partitions.last().unwrap();
            let end = last_a + last_l;
            if end > prev_pos {
                cum_c1 += gen.count_ones_range(d, prev_pos, end - prev_pos) as u32;
            }
            entries.push((end, cum_c1));

            // Split partitions for depth d+1.
            let mut new_partitions: Vec<(u64, u64)> =
                Vec::with_capacity(partitions.len() * 2);

            for (i, &(alpha, len)) in partitions.iter().enumerate() {
                if len <= 1 {
                    new_partitions.push((alpha, len));
                    continue;
                }
                let c1 = (entries[i + 1].1 - entries[i].1) as u64;
                let c0 = len - c1;
                if c0 > 0 { new_partitions.push((alpha, c0)); }
                if c1 > 0 { new_partitions.push((alpha + c0, c1)); }
            }

            depths.push(entries);
            partitions = new_partitions;
        }

        Self { depths }
    }

    /// Look up cumulative C1(β_d, 0, pos). Returns None if pos is not a boundary.
    #[inline]
    pub fn cumulative_ones(&self, d: u32, pos: u64) -> Option<u64> {
        let d = d as usize;
        if d >= self.depths.len() { return None; }
        let entries = &self.depths[d];
        match entries.binary_search_by_key(&pos, |&(p, _)| p) {
            Ok(i) => Some(entries[i].1 as u64),
            Err(_) => None,
        }
    }

    /// Compute C0(β_d, alpha, len) from cached boundaries. O(1).
    /// Returns None if alpha or alpha+len is not a cached boundary.
    #[inline]
    pub fn c0(&self, d: u32, alpha: u64, len: u64) -> Option<u64> {
        let c1_a = self.cumulative_ones(d, alpha)?;
        let c1_e = self.cumulative_ones(d, alpha + len)?;
        Some(len - (c1_e - c1_a))
    }

    /// Total memory in bytes.
    pub fn size_bytes(&self) -> usize {
        self.depths.iter().map(|v| v.len() * 12).sum()
    }
}

/// Cached counters for efficient C1 computation.
///
/// Stores C1(β_d, 0, s*i) for each depth d and stride index i,
/// where s is the cache stride.
pub struct CounterCache {
    /// Cache stride (interval between cached counters)
    pub stride: u64,
    /// Number of depths cached
    pub num_depths: u32,
    /// Domain size
    pub n: u64,
    /// Cached C1 values: cache[d][i] = C1(β_d, 0, stride * (i+1))
    /// i.e., cumulative count of ones from position 0 to stride*(i+1)-1
    cache: Vec<Vec<u32>>,
}

impl CounterCache {
    /// Build the counter cache for the given bitstring generator.
    /// stride = 2 * sqrt(N) by default.
    pub fn new(gen: &BitstringGen, stride: u64) -> Self {
        let n = gen.domain_size();
        // Cache depths up to log2(N/stride)
        let num_depths = if n > stride {
            ((n as f64) / (stride as f64)).log2().ceil() as u32 + 1
        } else {
            1
        };
        // Add some extra depths for safety
        let num_depths = num_depths + 4;
        let entries_per_depth = (n / stride) as usize;

        let mut cache = Vec::with_capacity(num_depths as usize);

        for d in 0..num_depths {
            let mut depth_cache = Vec::with_capacity(entries_per_depth);
            let mut cumulative: u64 = 0;
            for i in 0..entries_per_depth {
                let start = (i as u64) * stride;
                let ones = gen.count_ones_range(d, start, stride);
                cumulative += ones;
                depth_cache.push(cumulative as u32);
            }
            cache.push(depth_cache);
        }

        Self {
            stride,
            num_depths,
            n,
            cache,
        }
    }

    /// Get cached cumulative C1(β_d, 0, stride * (i+1)).
    /// Returns 0 if i < 0 (conceptually).
    #[inline]
    fn get_cached(&self, d: u32, i: usize) -> u64 {
        if d >= self.num_depths || i >= self.cache[d as usize].len() {
            return 0; // Fall back to uncached
        }
        self.cache[d as usize][i] as u64
    }

    /// Reconstruct a CounterCache from previously extracted raw data.
    ///
    /// Use with `raw_cache()` for cache persistence.
    pub fn from_raw(stride: u64, num_depths: u32, n: u64, cache: Vec<Vec<u32>>) -> Self {
        Self { stride, num_depths, n, cache }
    }

    /// Access the raw cached counters for serialization.
    pub fn raw_cache(&self) -> &Vec<Vec<u32>> {
        &self.cache
    }

    /// Total cache memory usage in bytes.
    pub fn size_bytes(&self) -> usize {
        self.cache.iter().map(|v| v.len() * 4).sum()
    }

    /// Halve the cache stride by computing midpoint counters.
    ///
    /// Each midpoint requires scanning only `stride/2` bits (one call to
    /// `count_ones_range`). This is the incremental caching from Section 5.3.
    ///
    /// Example: a cache at stride 1000 has entries at positions
    /// {1000, 2000, 3000, ...}. After `refine()`, the stride is 500 and
    /// entries are at {500, 1000, 1500, 2000, ...}. The even entries came
    /// from the old cache; the odd entries were computed by scanning 500
    /// bits each.
    pub fn refine(&mut self, gen: &BitstringGen) {
        let old_s = self.stride;
        let new_s = old_s / 2;
        if new_s < 1 { return; }

        let new_count = (self.n / new_s) as usize;

        for d in 0..self.num_depths as usize {
            let old = &self.cache[d];
            let mut refined = Vec::with_capacity(new_count);

            for i in 0..new_count {
                let pos = (i as u64 + 1) * new_s;

                if pos % old_s == 0 {
                    // Existing entry from old cache.
                    let old_i = (pos / old_s - 1) as usize;
                    refined.push(old[old_i]);
                } else {
                    // Midpoint: previous old boundary + scan new_s bits.
                    let prev_old_pos = (pos / old_s) * old_s;
                    let prev_c1 = if prev_old_pos == 0 {
                        0u64
                    } else {
                        old[(prev_old_pos / old_s - 1) as usize] as u64
                    };
                    let scan = gen.count_ones_range(d as u32, prev_old_pos, new_s);
                    refined.push((prev_c1 + scan) as u32);
                }
            }

            self.cache[d] = refined;
        }

        self.stride = new_s;
    }

    /// Refine repeatedly until the stride is at most `target_stride`.
    /// Returns the number of refinement steps performed.
    pub fn refine_to(&mut self, gen: &BitstringGen, target_stride: u64) -> u32 {
        let mut steps = 0u32;
        while self.stride > target_stride && self.stride >= 2 {
            self.refine(gen);
            steps += 1;
        }
        steps
    }

    /// Check if depth d is cached.
    #[inline]
    pub fn is_depth_cached(&self, d: u32) -> bool {
        d < self.num_depths && !self.cache[d as usize].is_empty()
    }

    /// Compute cumulative C1(β_d, 0, pos) using the stride cache.
    ///
    /// **Bidirectional scanning** (Section 4.1): picks the shorter direction
    /// (forward from lower boundary or backward from upper boundary).
    /// Average scan = s/2 instead of s.
    #[inline]
    pub fn cumulative_ones(&self, gen: &BitstringGen, d: u32, pos: u64) -> u64 {
        if pos == 0 { return 0; }
        if !self.is_depth_cached(d) {
            return gen.count_ones_range(d, 0, pos);
        }
        let s = self.stride;
        let full = pos / s; // pos is in stride block [full*s, (full+1)*s)
        let lower_bound = full * s;
        let forward_dist = pos - lower_bound;

        if forward_dist == 0 {
            // Exactly on a stride boundary.
            return if full > 0 { self.get_cached(d, (full - 1) as usize) } else { 0 };
        }

        let lower_cached = if full > 0 {
            self.get_cached(d, (full - 1) as usize)
        } else {
            0
        };

        // Check if backward scan from the upper boundary is shorter.
        let upper_idx = full as usize;
        let cache_d = &self.cache[d as usize];
        if upper_idx < cache_d.len() {
            let upper_bound = (full + 1) * s;
            let backward_dist = upper_bound - pos;
            if backward_dist < forward_dist {
                let upper_cached = cache_d[upper_idx] as u64;
                let ones_after = gen.count_ones_range(d, pos, backward_dist);
                return upper_cached - ones_after;
            }
        }

        // Forward scan.
        lower_cached + gen.count_ones_range(d, lower_bound, forward_dist)
    }

    /// Compute C1(β_d, α, count) using cached values.
    /// Returns the number of 1-bits in β_d[α..α+count].
    pub fn c1(&self, gen: &BitstringGen, d: u32, alpha: u64, count: u64) -> u64 {
        if count == 0 { return 0; }
        // For uncached depths, scan the range directly (avoid scanning from 0).
        if !self.is_depth_cached(d) {
            return gen.count_ones_range(d, alpha, count);
        }
        self.cumulative_ones(gen, d, alpha + count) - self.cumulative_ones(gen, d, alpha)
    }

    /// Compute C0(β_d, α, count) using cached values.
    #[inline]
    pub fn c0(&self, gen: &BitstringGen, d: u32, alpha: u64, count: u64) -> u64 {
        count - self.c1(gen, d, alpha, count)
    }

    /// Compute C0(β_d, α, x) and C0(β_d, α, len) in one call.
    /// Returns (c0_x, c0_len).
    pub fn c0_pair(&self, gen: &BitstringGen, d: u32, alpha: u64, x: u64, len: u64) -> (u64, u64) {
        if !self.is_depth_cached(d) {
            return (
                x - gen.count_ones_range(d, alpha, x),
                len - gen.count_ones_range(d, alpha, len),
            );
        }
        let ca = self.cumulative_ones(gen, d, alpha);
        let cx = self.cumulative_ones(gen, d, alpha + x);
        let cl = self.cumulative_ones(gen, d, alpha + len);
        (x - (cx - ca), len - (cl - ca))
    }

    /// Find the k-th one bit (1-indexed) in β_d starting at position `alpha`.
    /// Uses binary search + bidirectional scan within the stride block.
    pub fn c1_inv(&self, gen: &BitstringGen, d: u32, alpha: u64, k: u64) -> u64 {
        if !self.is_depth_cached(d) || k == 0 {
            return gen.find_kth_one(d, alpha, k);
        }
        let ones_before_alpha = self.cumulative_ones(gen, d, alpha);
        self.c1_inv_inner(gen, d, alpha, k, ones_before_alpha)
    }

    /// Like `c1_inv` but with pre-known `ones_before_alpha` (avoids 1 scan).
    pub fn c1_inv_hint(&self, gen: &BitstringGen, d: u32, alpha: u64, k: u64, ones_before_alpha: u64) -> u64 {
        if !self.is_depth_cached(d) || k == 0 {
            return gen.find_kth_one(d, alpha, k);
        }
        self.c1_inv_inner(gen, d, alpha, k, ones_before_alpha)
    }

    fn c1_inv_inner(&self, gen: &BitstringGen, d: u32, alpha: u64, k: u64, ones_before_alpha: u64) -> u64 {
        let s = self.stride;
        let target = ones_before_alpha + k;
        let cache_d = &self.cache[d as usize];

        // Binary search for the stride block containing the target-th one.
        let mut lo = 0usize;
        let mut hi = cache_d.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if (cache_d[mid] as u64) < target {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        let block_start = (lo as u64) * s;
        let ones_at_start = if lo > 0 { cache_d[lo - 1] as u64 } else { 0 };
        let remaining_fwd = target - ones_at_start;

        // Bidirectional: if within cached range, pick shorter direction.
        if lo < cache_d.len() {
            let ones_at_end = cache_d[lo] as u64;
            let total_ones = ones_at_end - ones_at_start;
            let remaining_rev = total_ones - remaining_fwd + 1;
            if remaining_rev < remaining_fwd {
                let offset = gen.find_kth_one_from_end(d, block_start, s, remaining_rev);
                return block_start + offset - alpha;
            }
        }

        let offset = gen.find_kth_one(d, block_start, remaining_fwd);
        block_start + offset - alpha
    }

    /// Find the k-th zero bit (1-indexed) in β_d starting at position `alpha`.
    /// Uses binary search + bidirectional scan within the stride block.
    pub fn c0_inv(&self, gen: &BitstringGen, d: u32, alpha: u64, k: u64) -> u64 {
        if !self.is_depth_cached(d) || k == 0 {
            return gen.find_kth_zero(d, alpha, k);
        }
        let ones_before_alpha = self.cumulative_ones(gen, d, alpha);
        self.c0_inv_inner(gen, d, alpha, k, ones_before_alpha)
    }

    /// Like `c0_inv` but with pre-known `ones_before_alpha` (avoids 1 scan).
    pub fn c0_inv_hint(&self, gen: &BitstringGen, d: u32, alpha: u64, k: u64, ones_before_alpha: u64) -> u64 {
        if !self.is_depth_cached(d) || k == 0 {
            return gen.find_kth_zero(d, alpha, k);
        }
        self.c0_inv_inner(gen, d, alpha, k, ones_before_alpha)
    }

    fn c0_inv_inner(&self, gen: &BitstringGen, d: u32, alpha: u64, k: u64, ones_before_alpha: u64) -> u64 {
        let s = self.stride;
        let zeros_before_alpha = alpha - ones_before_alpha;
        let target_zeros = zeros_before_alpha + k;
        let cache_d = &self.cache[d as usize];

        // Binary search for the stride block containing the target-th zero.
        let mut lo = 0usize;
        let mut hi = cache_d.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let total_bits = ((mid + 1) as u64) * s;
            let zeros = total_bits - cache_d[mid] as u64;
            if zeros < target_zeros {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        let block_start = (lo as u64) * s;
        let ones_at_start = if lo > 0 { cache_d[lo - 1] as u64 } else { 0 };
        let zeros_at_start = block_start - ones_at_start;
        let remaining_fwd = target_zeros - zeros_at_start;

        // Bidirectional: if within cached range, pick shorter direction.
        if lo < cache_d.len() {
            let ones_at_end = cache_d[lo] as u64;
            let total_zeros = s - (ones_at_end - ones_at_start);
            let remaining_rev = total_zeros - remaining_fwd + 1;
            if remaining_rev < remaining_fwd {
                let offset = gen.find_kth_zero_from_end(d, block_start, s, remaining_rev);
                return block_start + offset - alpha;
            }
        }

        let offset = gen.find_kth_zero(d, block_start, remaining_fwd);
        block_start + offset - alpha
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_c1_matches_raw() {
        let key = [42u8; 16];
        let n = 1024u64;
        let gen = BitstringGen::new(&key, n);
        let cache = CounterCache::new(&gen, 64);

        for d in 0..3 {
            for alpha in [0, 10, 64, 100, 500] {
                for count in [1, 10, 50, 100, 200] {
                    if alpha + count <= n {
                        let raw = gen.count_ones_range(d, alpha, count);
                        let cached = cache.c1(&gen, d, alpha, count);
                        assert_eq!(raw, cached, "d={d} alpha={alpha} count={count}");
                    }
                }
            }
        }
    }

    #[test]
    fn test_cached_c0_matches_raw() {
        let key = [42u8; 16];
        let n = 1024u64;
        let gen = BitstringGen::new(&key, n);
        let cache = CounterCache::new(&gen, 64);

        for d in 0..3 {
            let raw = gen.count_zeros_range(d, 0, n);
            let cached = cache.c0(&gen, d, 0, n);
            assert_eq!(raw, cached, "d={d}");
        }
    }

    #[test]
    fn test_cached_c1_inv() {
        let key = [42u8; 16];
        let n = 512u64;
        let gen = BitstringGen::new(&key, n);
        let cache = CounterCache::new(&gen, 32);

        for d in 0..2 {
            let total_ones = gen.count_ones_range(d, 0, n);
            for k in 1..=total_ones.min(20) {
                let raw = gen.find_kth_one(d, 0, k);
                let cached = cache.c1_inv(&gen, d, 0, k);
                assert_eq!(raw, cached, "d={d} k={k}");
            }
        }
    }

    #[test]
    fn test_cached_c0_inv() {
        let key = [42u8; 16];
        let n = 512u64;
        let gen = BitstringGen::new(&key, n);
        let cache = CounterCache::new(&gen, 32);

        for d in 0..2 {
            let total_zeros = gen.count_zeros_range(d, 0, n);
            for k in 1..=total_zeros.min(20) {
                let raw = gen.find_kth_zero(d, 0, k);
                let cached = cache.c0_inv(&gen, d, 0, k);
                assert_eq!(raw, cached, "d={d} k={k}");
            }
        }
    }

    #[test]
    fn test_refine_matches_direct() {
        // A cache refined from stride 128 → 64 should match one built directly at 64.
        let key = [42u8; 16];
        let n = 1024u64;
        let gen = BitstringGen::new(&key, n);

        let direct = CounterCache::new(&gen, 64);

        let mut refined = CounterCache::new(&gen, 128);
        refined.refine(&gen);

        assert_eq!(refined.stride, 64);
        for d in 0..direct.num_depths.min(refined.num_depths) {
            let dc = &direct.cache[d as usize];
            let rc = &refined.cache[d as usize];
            let len = dc.len().min(rc.len());
            for i in 0..len {
                assert_eq!(dc[i], rc[i], "d={d} i={i} stride=64");
            }
        }
    }

    #[test]
    fn test_refine_to_matches_direct() {
        let key = [99u8; 16];
        let n = 2048u64;
        let gen = BitstringGen::new(&key, n);

        // Build at stride 256, refine down to 32.
        let mut refined = CounterCache::new(&gen, 256);
        let steps = refined.refine_to(&gen, 32);
        assert_eq!(steps, 3); // 256→128→64→32
        assert_eq!(refined.stride, 32);

        let direct = CounterCache::new(&gen, 32);

        for d in 0..direct.num_depths.min(refined.num_depths) {
            let dc = &direct.cache[d as usize];
            let rc = &refined.cache[d as usize];
            let len = dc.len().min(rc.len());
            for i in 0..len {
                assert_eq!(dc[i], rc[i], "d={d} i={i}");
            }
        }
    }

    #[test]
    fn test_refined_cache_permute_roundtrip() {
        // Build FastPrp with a refined cache and verify permute/unpermute still work.
        use crate::FastPrp;

        let key = [77u8; 16];
        let n = 512u64;

        // Direct build.
        let prp_direct = FastPrp::new(&key, n);

        // Build with coarse cache, refine, reconstruct.
        let gen = BitstringGen::new(&key, n);
        let mut cache = CounterCache::new(&gen, 128);
        cache.refine_to(&gen, 32);
        let pcache = PartitionCache::new(&gen, n, cache.num_depths);
        let prp_refined = FastPrp::from_parts(&key, n, cache, pcache);

        for x in 0..n {
            let y_d = prp_direct.permute(x);
            let y_r = prp_refined.permute(x);
            assert_eq!(y_d, y_r, "permute mismatch at x={x}");
            assert_eq!(prp_refined.unpermute(y_r), x, "roundtrip failed at x={x}");
        }
    }
}
