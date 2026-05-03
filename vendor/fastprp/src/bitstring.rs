use aes::Block;

#[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
use aes::cipher::{BlockEncrypt, KeyInit};
#[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
use aes::Aes128;

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
use crate::aes_wasm_simd::SimdAes128;

/// AES-based pseudo-random bitstring generator.
///
/// Generates the stream S = AES_K(0) || AES_K(1) || AES_K(2) || ...
/// Bitstring β_d is the d-th chunk of N bits from this stream.
/// β_d[i] is bit i of the d-th bitstring.
pub struct BitstringGen {
    #[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
    cipher: Aes128,
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    cipher: SimdAes128,
    n: u64,
}

impl BitstringGen {
    pub fn new(key: &[u8; 16], n: u64) -> Self {
        #[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
        let cipher = Aes128::new(key.into());
        #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
        let cipher = SimdAes128::new(key);
        Self { cipher, n }
    }

    /// Get a single AES block (128 bits) by encrypting the block index.
    #[inline(always)]
    fn aes_block(&self, block_idx: u64) -> u128 {
        let mut block = Block::default();
        block[..8].copy_from_slice(&block_idx.to_le_bytes());
        self.cipher.encrypt_block(&mut block);
        u128::from_le_bytes(block.into())
    }

    /// Encrypt 4 AES blocks in parallel.
    /// On AArch64, this pipelines AESE+AESMC across 4 independent blocks.
    #[inline(always)]
    fn aes_blocks_4(&self, idx0: u64, idx1: u64, idx2: u64, idx3: u64) -> [u128; 4] {
        let mut blocks = [Block::default(); 4];
        blocks[0][..8].copy_from_slice(&idx0.to_le_bytes());
        blocks[1][..8].copy_from_slice(&idx1.to_le_bytes());
        blocks[2][..8].copy_from_slice(&idx2.to_le_bytes());
        blocks[3][..8].copy_from_slice(&idx3.to_le_bytes());
        self.cipher.encrypt_blocks(&mut blocks);
        [
            u128::from_le_bytes(blocks[0].into()),
            u128::from_le_bytes(blocks[1].into()),
            u128::from_le_bytes(blocks[2].into()),
            u128::from_le_bytes(blocks[3].into()),
        ]
    }

    /// Encrypt 8 AES blocks in parallel (max pipeline depth on most ARM cores).
    #[inline(always)]
    fn aes_blocks_8(&self, idxs: [u64; 8]) -> [u128; 8] {
        let mut blocks = [Block::default(); 8];
        for i in 0..8 {
            blocks[i][..8].copy_from_slice(&idxs[i].to_le_bytes());
        }
        self.cipher.encrypt_blocks(&mut blocks);
        let mut out = [0u128; 8];
        for i in 0..8 {
            out[i] = u128::from_le_bytes(blocks[i].into());
        }
        out
    }

    /// Get bit at global position `pos` in the AES stream.
    #[inline]
    pub fn get_stream_bit(&self, pos: u64) -> u8 {
        let block_idx = pos / 128;
        let bit_offset = pos % 128;
        let block = self.aes_block(block_idx);
        ((block >> bit_offset) & 1) as u8
    }

    /// Get β_d[i]: bit i of bitstring d.
    #[inline]
    pub fn get_bit(&self, d: u32, i: u64) -> u8 {
        let pos = (d as u64) * self.n + i;
        self.get_stream_bit(pos)
    }

    /// Get 4 bits from β_d at positions i0..i3 using pipelined AES.
    #[inline]
    pub fn get_bits_4(&self, d: u32, i0: u64, i1: u64, i2: u64, i3: u64) -> [u8; 4] {
        let base = (d as u64) * self.n;
        let p = [base + i0, base + i1, base + i2, base + i3];
        let blocks = self.aes_blocks_4(p[0] / 128, p[1] / 128, p[2] / 128, p[3] / 128);
        [
            ((blocks[0] >> (p[0] % 128)) & 1) as u8,
            ((blocks[1] >> (p[1] % 128)) & 1) as u8,
            ((blocks[2] >> (p[2] % 128)) & 1) as u8,
            ((blocks[3] >> (p[3] % 128)) & 1) as u8,
        ]
    }

    /// Count the number of 1-bits in β_d[start..start+count].
    /// Uses 8-way pipelined AES for the bulk middle blocks.
    pub fn count_ones_range(&self, d: u32, start: u64, count: u64) -> u64 {
        if count == 0 {
            return 0;
        }

        let global_start = (d as u64) * self.n + start;
        let global_end = global_start + count;

        let first_block = global_start / 128;
        let last_block = (global_end - 1) / 128;

        let mut ones = 0u64;

        if first_block == last_block {
            let block = self.aes_block(first_block);
            let start_bit = (global_start % 128) as u32;
            let end_bit = (global_end % 128) as u32;
            let end_bit = if end_bit == 0 { 128 } else { end_bit };
            let mask = if end_bit - start_bit == 128 {
                u128::MAX
            } else {
                ((1u128 << (end_bit - start_bit)) - 1) << start_bit
            };
            ones = (block & mask).count_ones() as u64;
        } else {
            // First partial block
            let start_bit = (global_start % 128) as u32;
            let block = self.aes_block(first_block);
            let mask = if start_bit == 0 { u128::MAX } else { u128::MAX << start_bit };
            ones += (block & mask).count_ones() as u64;

            // Middle blocks — process 8 at a time for AES pipelining
            let mid_start = first_block + 1;
            let mid_end = last_block; // exclusive
            let mut blk = mid_start;

            while blk + 8 <= mid_end {
                let idxs = [blk, blk + 1, blk + 2, blk + 3, blk + 4, blk + 5, blk + 6, blk + 7];
                let vals = self.aes_blocks_8(idxs);
                ones += vals[0].count_ones() as u64;
                ones += vals[1].count_ones() as u64;
                ones += vals[2].count_ones() as u64;
                ones += vals[3].count_ones() as u64;
                ones += vals[4].count_ones() as u64;
                ones += vals[5].count_ones() as u64;
                ones += vals[6].count_ones() as u64;
                ones += vals[7].count_ones() as u64;
                blk += 8;
            }

            // Remaining middle blocks (1-7)
            while blk < mid_end {
                ones += self.aes_block(blk).count_ones() as u64;
                blk += 1;
            }

            // Last partial block
            let end_bit = (global_end % 128) as u32;
            let block = self.aes_block(last_block);
            if end_bit == 0 {
                ones += block.count_ones() as u64;
            } else {
                let mask = (1u128 << end_bit) - 1;
                ones += (block & mask).count_ones() as u64;
            }
        }

        ones
    }

    /// Count the number of 0-bits in β_d[start..start+count].
    #[inline]
    pub fn count_zeros_range(&self, d: u32, start: u64, count: u64) -> u64 {
        count - self.count_ones_range(d, start, count)
    }

    /// Extract the position of the k-th set bit (1-indexed) from a masked u128.
    #[inline]
    fn extract_kth_set_bit(mut masked: u128, k: u64) -> u32 {
        for _ in 1..k {
            masked &= masked - 1; // clear lowest set bit
        }
        masked.trailing_zeros()
    }

    /// Find the index of the k-th one bit (1-indexed) in β_d starting from position `start`.
    /// Returns the offset relative to `start`.
    /// Uses 8-way pipelined AES for the block scan.
    pub fn find_kth_one(&self, d: u32, start: u64, k: u64) -> u64 {
        debug_assert!(k >= 1);
        let mut remaining = k;
        let global_base = (d as u64) * self.n;
        let global_start = global_base + start;
        let first_block = global_start / 128;
        let first_bit_offset = (global_start % 128) as u32;

        // Handle first partial block.
        let mut blk = first_block;
        if first_bit_offset > 0 {
            let block = self.aes_block(blk);
            let masked = block & (u128::MAX << first_bit_offset);
            let ones = masked.count_ones() as u64;
            if ones >= remaining {
                let bit_pos = Self::extract_kth_set_bit(masked, remaining) as u64;
                return blk * 128 + bit_pos - global_base - start;
            }
            remaining -= ones;
            blk += 1;
        }

        // Process full blocks in batches of 8 for AES pipelining.
        loop {
            let vals = self.aes_blocks_8([blk, blk+1, blk+2, blk+3, blk+4, blk+5, blk+6, blk+7]);
            for i in 0..8u64 {
                let ones = vals[i as usize].count_ones() as u64;
                if ones >= remaining {
                    let bit_pos = Self::extract_kth_set_bit(vals[i as usize], remaining) as u64;
                    return (blk + i) * 128 + bit_pos - global_base - start;
                }
                remaining -= ones;
            }
            blk += 8;
        }
    }

    /// Find the index of the k-th zero bit (1-indexed) in β_d starting from position `start`.
    /// Returns the offset relative to `start`.
    /// Uses 8-way pipelined AES for the block scan.
    pub fn find_kth_zero(&self, d: u32, start: u64, k: u64) -> u64 {
        debug_assert!(k >= 1);
        let mut remaining = k;
        let global_base = (d as u64) * self.n;
        let global_start = global_base + start;
        let first_block = global_start / 128;
        let first_bit_offset = (global_start % 128) as u32;

        let mut blk = first_block;
        if first_bit_offset > 0 {
            let block = self.aes_block(blk);
            let masked = !block & (u128::MAX << first_bit_offset);
            let zeros = masked.count_ones() as u64;
            if zeros >= remaining {
                let bit_pos = Self::extract_kth_set_bit(masked, remaining) as u64;
                return blk * 128 + bit_pos - global_base - start;
            }
            remaining -= zeros;
            blk += 1;
        }

        loop {
            let vals = self.aes_blocks_8([blk, blk+1, blk+2, blk+3, blk+4, blk+5, blk+6, blk+7]);
            for i in 0..8u64 {
                let inv = !vals[i as usize];
                let zeros = inv.count_ones() as u64;
                if zeros >= remaining {
                    let bit_pos = Self::extract_kth_set_bit(inv, remaining) as u64;
                    return (blk + i) * 128 + bit_pos - global_base - start;
                }
                remaining -= zeros;
            }
            blk += 8;
        }
    }

    /// Find the k-th one bit FROM THE END (1-indexed from right) in β_d[start..start+len).
    /// Returns the offset relative to `start`.
    /// Uses 8-way pipelined AES for the block scan.
    pub fn find_kth_one_from_end(&self, d: u32, start: u64, len: u64, k: u64) -> u64 {
        debug_assert!(k >= 1);
        let mut remaining = k;
        let global_base = (d as u64) * self.n;
        let global_start = global_base + start;
        let global_end = global_start + len;
        let last_block = (global_end - 1) / 128;
        let first_block = global_start / 128;

        // Handle last partial block.
        let hi_bit = (global_end % 128) as u32;
        let mut blk = last_block;
        if hi_bit != 0 {
            let block = self.aes_block(blk);
            let lo_bit = if blk * 128 < global_start { (global_start - blk * 128) as u32 } else { 0 };
            let mask = ((1u128 << hi_bit) - 1) & if lo_bit == 0 { u128::MAX } else { u128::MAX << lo_bit };
            let masked = block & mask;
            let ones = masked.count_ones() as u64;
            if ones >= remaining {
                let from_left = ones - remaining + 1;
                let bit_pos = Self::extract_kth_set_bit(masked, from_left) as u64;
                return blk * 128 + bit_pos - global_base - start;
            }
            remaining -= ones;
            if blk == first_block { panic!("find_kth_one_from_end: not enough ones"); }
            blk -= 1;
        } else {
            // global_end is block-aligned, start from last_block itself
        }

        // Process full blocks in batches of 8, scanning right-to-left.
        loop {
            if blk >= 7 && blk - 7 >= first_block {
                let b = blk - 7;
                let vals = self.aes_blocks_8([b, b+1, b+2, b+3, b+4, b+5, b+6, b+7]);
                // Check right-to-left
                for i in (0..8u64).rev() {
                    let ones = vals[i as usize].count_ones() as u64;
                    if ones >= remaining {
                        let from_left = ones - remaining + 1;
                        let bit_pos = Self::extract_kth_set_bit(vals[i as usize], from_left) as u64;
                        return (b + i) * 128 + bit_pos - global_base - start;
                    }
                    remaining -= ones;
                }
                blk -= 8;
            } else {
                // Remaining blocks one at a time
                loop {
                    let block = self.aes_block(blk);
                    let lo_bit = if blk * 128 < global_start { (global_start - blk * 128) as u32 } else { 0 };
                    let masked = if lo_bit == 0 { block } else { block & (u128::MAX << lo_bit) };
                    let ones = masked.count_ones() as u64;
                    if ones >= remaining {
                        let from_left = ones - remaining + 1;
                        let bit_pos = Self::extract_kth_set_bit(masked, from_left) as u64;
                        return blk * 128 + bit_pos - global_base - start;
                    }
                    remaining -= ones;
                    if blk == first_block { panic!("find_kth_one_from_end: not enough ones"); }
                    blk -= 1;
                }
            }
        }
    }

    /// Find the k-th zero bit FROM THE END (1-indexed from right) in β_d[start..start+len).
    /// Returns the offset relative to `start`.
    /// Uses 8-way pipelined AES for the block scan.
    pub fn find_kth_zero_from_end(&self, d: u32, start: u64, len: u64, k: u64) -> u64 {
        debug_assert!(k >= 1);
        let mut remaining = k;
        let global_base = (d as u64) * self.n;
        let global_start = global_base + start;
        let global_end = global_start + len;
        let last_block = (global_end - 1) / 128;
        let first_block = global_start / 128;

        let hi_bit = (global_end % 128) as u32;
        let mut blk = last_block;
        if hi_bit != 0 {
            let block = self.aes_block(blk);
            let lo_bit = if blk * 128 < global_start { (global_start - blk * 128) as u32 } else { 0 };
            let mask = ((1u128 << hi_bit) - 1) & if lo_bit == 0 { u128::MAX } else { u128::MAX << lo_bit };
            let masked = !block & mask;
            let zeros = masked.count_ones() as u64;
            if zeros >= remaining {
                let from_left = zeros - remaining + 1;
                let bit_pos = Self::extract_kth_set_bit(masked, from_left) as u64;
                return blk * 128 + bit_pos - global_base - start;
            }
            remaining -= zeros;
            if blk == first_block { panic!("find_kth_zero_from_end: not enough zeros"); }
            blk -= 1;
        }

        loop {
            if blk >= 7 && blk - 7 >= first_block {
                let b = blk - 7;
                let vals = self.aes_blocks_8([b, b+1, b+2, b+3, b+4, b+5, b+6, b+7]);
                for i in (0..8u64).rev() {
                    let inv = !vals[i as usize];
                    let zeros = inv.count_ones() as u64;
                    if zeros >= remaining {
                        let from_left = zeros - remaining + 1;
                        let bit_pos = Self::extract_kth_set_bit(inv, from_left) as u64;
                        return (b + i) * 128 + bit_pos - global_base - start;
                    }
                    remaining -= zeros;
                }
                blk -= 8;
            } else {
                loop {
                    let block = self.aes_block(blk);
                    let lo_bit = if blk * 128 < global_start { (global_start - blk * 128) as u32 } else { 0 };
                    let masked = if lo_bit == 0 { !block } else { !block & (u128::MAX << lo_bit) };
                    let zeros = masked.count_ones() as u64;
                    if zeros >= remaining {
                        let from_left = zeros - remaining + 1;
                        let bit_pos = Self::extract_kth_set_bit(masked, from_left) as u64;
                        return blk * 128 + bit_pos - global_base - start;
                    }
                    remaining -= zeros;
                    if blk == first_block { panic!("find_kth_zero_from_end: not enough zeros"); }
                    blk -= 1;
                }
            }
        }
    }

    /// Generate AES blocks covering β_d[start..start+count] into a reusable buffer.
    /// Uses `encrypt_blocks` for AES pipelining.
    /// Returns the first AES block index (base_block).
    pub fn fill_range_blocks(&self, d: u32, start: u64, count: u64, out: &mut Vec<u128>) -> u64 {
        let global_start = (d as u64) * self.n + start;
        let global_end = global_start + count;
        let first_block = global_start / 128;
        let num_blocks = ((global_end + 127) / 128 - first_block) as usize;

        let mut aes_blocks: Vec<Block> = Vec::with_capacity(num_blocks);
        for i in 0..num_blocks {
            let mut block = Block::default();
            block[..8].copy_from_slice(&(first_block + i as u64).to_le_bytes());
            aes_blocks.push(block);
        }
        self.cipher.encrypt_blocks(&mut aes_blocks);

        out.clear();
        out.reserve(num_blocks);
        for block in &aes_blocks {
            out.push(u128::from_le_bytes((*block).into()));
        }
        first_block
    }

    /// Generate all AES blocks covering β_d in bulk.
    pub fn generate_bitstring_blocks(&self, d: u32) -> (Vec<u128>, u64) {
        let mut out = Vec::new();
        let base = self.fill_bitstring_blocks(d, &mut out);
        (out, base)
    }

    /// Fill a pre-allocated buffer with all AES blocks for β_d.
    /// Uses `encrypt_blocks` for AES pipelining (8 blocks in parallel on AArch64 crypto extensions).
    pub fn fill_bitstring_blocks(&self, d: u32, out: &mut Vec<u128>) -> u64 {
        let global_start = (d as u64) * self.n;
        let global_end = global_start + self.n;
        let first_block = global_start / 128;
        let num_blocks = ((global_end + 127) / 128 - first_block) as usize;

        let mut aes_blocks: Vec<Block> = Vec::with_capacity(num_blocks);
        for i in 0..num_blocks {
            let mut block = Block::default();
            let idx = first_block + i as u64;
            block[..8].copy_from_slice(&idx.to_le_bytes());
            aes_blocks.push(block);
        }

        self.cipher.encrypt_blocks(&mut aes_blocks);

        out.clear();
        out.reserve(num_blocks);
        for block in &aes_blocks {
            out.push(u128::from_le_bytes((*block).into()));
        }

        first_block
    }

    /// Compute AES_K(i) for i = 0..N, returning 64-bit hashes.
    /// Uses bulk encrypt_blocks for AES pipelining.
    pub fn compute_hashes_u64(&self, out: &mut Vec<u64>) {
        let n = self.n as usize;
        out.clear();
        out.reserve(n);

        const CHUNK: usize = 4096;
        let mut blocks = vec![Block::default(); CHUNK];

        for chunk_start in (0..n).step_by(CHUNK) {
            let count = CHUNK.min(n - chunk_start);
            for j in 0..count {
                blocks[j] = Block::default();
                blocks[j][..8].copy_from_slice(&((chunk_start + j) as u64).to_le_bytes());
            }
            self.cipher.encrypt_blocks(&mut blocks[..count]);
            for j in 0..count {
                out.push(u64::from_le_bytes(blocks[j][..8].try_into().unwrap()));
            }
        }
    }

    /// Expose bulk encryption for parallel hash generation.
    pub fn encrypt_blocks_pub(&self, blocks: &mut [Block]) {
        self.cipher.encrypt_blocks(blocks);
    }

    pub fn domain_size(&self) -> u64 {
        self.n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_ones_small() {
        let key = [0u8; 16];
        let gen = BitstringGen::new(&key, 128);

        let block = gen.aes_block(0);
        let expected = block.count_ones() as u64;
        let got = gen.count_ones_range(0, 0, 128);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_count_ones_zeros_sum() {
        let key = [42u8; 16];
        let gen = BitstringGen::new(&key, 1024);

        let ones = gen.count_ones_range(0, 10, 500);
        let zeros = gen.count_zeros_range(0, 10, 500);
        assert_eq!(ones + zeros, 500);
    }

    #[test]
    fn test_find_kth_one() {
        let key = [7u8; 16];
        let gen = BitstringGen::new(&key, 256);

        let idx = gen.find_kth_one(0, 0, 1);
        assert_eq!(gen.get_bit(0, idx), 1);

        if idx > 0 {
            let ones_before = gen.count_ones_range(0, 0, idx);
            assert_eq!(ones_before, 0);
        }
    }

    #[test]
    fn test_find_kth_zero() {
        let key = [7u8; 16];
        let gen = BitstringGen::new(&key, 256);

        let idx = gen.find_kth_zero(0, 0, 1);
        assert_eq!(gen.get_bit(0, idx), 0);

        if idx > 0 {
            let zeros_before = gen.count_zeros_range(0, 0, idx);
            assert_eq!(zeros_before, 0);
        }
    }

    #[test]
    fn test_find_kth_consistency() {
        let key = [99u8; 16];
        let gen = BitstringGen::new(&key, 512);

        let total_ones = gen.count_ones_range(0, 0, 512);

        for k in 1..=total_ones.min(20) {
            let idx = gen.find_kth_one(0, 0, k);
            assert_eq!(gen.get_bit(0, idx), 1);
            let ones_up_to = gen.count_ones_range(0, 0, idx + 1);
            assert_eq!(ones_up_to, k);
        }
    }

    #[test]
    fn test_get_bits_4() {
        let key = [42u8; 16];
        let gen = BitstringGen::new(&key, 1024);

        let bits = gen.get_bits_4(0, 0, 1, 100, 500);
        assert_eq!(bits[0], gen.get_bit(0, 0));
        assert_eq!(bits[1], gen.get_bit(0, 1));
        assert_eq!(bits[2], gen.get_bit(0, 100));
        assert_eq!(bits[3], gen.get_bit(0, 500));
    }
}
