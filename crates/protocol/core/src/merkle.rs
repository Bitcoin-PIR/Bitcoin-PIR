//! SHA-256 and the N-ary Merkle trees the databases commit to: per-bucket
//! bin leaves (`compute_bin_leaf_hash`) and arity-N parents
//! (`compute_parent_n`, `MerkleTreeN`).

/// Size of a SHA-256 hash in bytes.
pub const HASH_SIZE: usize = 32;

/// A 32-byte SHA-256 hash.
pub type Hash256 = [u8; HASH_SIZE];

/// The zero hash (all zeros) used for padding leaves.
pub const ZERO_HASH: Hash256 = [0u8; HASH_SIZE];

// ─── SHA-256 (minimal, no-dependency implementation) ────────────────────────

/// Compute SHA-256 of input data.
pub fn sha256(data: &[u8]) -> Hash256 {
    // SHA-256 constants
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Padding
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process blocks
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, &val) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

// ─── Leaf and node hashes ──────────────────────────────────────────────────

/// Per-bucket bin Merkle: leaf = SHA256(bin_index_u32_LE || bin_content).
///
/// Each leaf in a per-PBC-group Merkle tree commits to the bin index and
/// all slot data at that bin. This binds the cuckoo placement to the tree.
pub fn compute_bin_leaf_hash(bin_index: u32, bin_content: &[u8]) -> Hash256 {
    let mut preimage = Vec::with_capacity(4 + bin_content.len());
    preimage.extend_from_slice(&bin_index.to_le_bytes());
    preimage.extend_from_slice(bin_content);
    sha256(&preimage)
}

/// Compute an internal node (arity N): SHA256(child_0 || child_1 || ... || child_{N-1}).
pub fn compute_parent_n(children: &[Hash256]) -> Hash256 {
    let mut preimage = Vec::with_capacity(children.len() * HASH_SIZE);
    for child in children {
        preimage.extend_from_slice(child);
    }
    sha256(&preimage)
}

// ─── N-ary Merkle tree ────────────────────────────────────────────────────

/// An N-ary Merkle tree stored level-by-level.
///
/// `levels[0]` = leaf hashes (padded to a multiple of arity^depth)
/// `levels[depth]` = `[root_hash]`
///
/// At each level L, `levels[L+1][i] = SHA256(levels[L][i*A] || ... || levels[L][i*A + A-1])`
pub struct MerkleTreeN {
    /// Per-level hash arrays. levels[0] = leaves, levels[depth] = [root].
    pub levels: Vec<Vec<Hash256>>,
    /// Branching factor.
    pub arity: usize,
    /// Number of real (non-padding) leaves.
    pub num_real_leaves: usize,
}

impl MerkleTreeN {
    /// Build an N-ary Merkle tree from leaf hashes.
    ///
    /// Pads leaves to the next power of `arity` with ZERO_HASH.
    pub fn build(leaf_hashes: &[Hash256], arity: usize) -> Self {
        assert!(arity >= 2, "arity must be >= 2");
        let num_real = leaf_hashes.len();

        // Pad to next power of arity
        let num_leaves = next_power_of(num_real, arity);

        let mut levels: Vec<Vec<Hash256>> = Vec::new();

        // Level 0: leaves
        let mut level0 = Vec::with_capacity(num_leaves);
        level0.extend_from_slice(leaf_hashes);
        level0.resize(num_leaves, ZERO_HASH);
        levels.push(level0);

        // Build bottom-up
        loop {
            let prev = levels.last().unwrap();
            if prev.len() <= 1 {
                break;
            }
            let next_len = prev.len().div_ceil(arity);
            let mut next_level = Vec::with_capacity(next_len);
            for i in 0..next_len {
                let start = i * arity;
                let end = (start + arity).min(prev.len());
                let mut children: Vec<Hash256> = prev[start..end].to_vec();
                // Pad if last group is incomplete
                children.resize(arity, ZERO_HASH);
                next_level.push(compute_parent_n(&children));
            }
            levels.push(next_level);
        }

        MerkleTreeN {
            levels,
            arity,
            num_real_leaves: num_real,
        }
    }

    /// Number of levels (0 = leaves, depth = root).
    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    /// Number of leaves (including padding).
    pub fn num_leaves(&self) -> usize {
        self.levels[0].len()
    }

    /// Root hash.
    pub fn root(&self) -> &Hash256 {
        &self.levels[self.depth()][0]
    }

    /// Get the A-1 sibling hashes for node at `local_idx` at `level`.
    ///
    /// Returns the sibling hashes in order (all children of the same parent,
    /// excluding the node itself).
    pub fn siblings_of(&self, level: usize, local_idx: usize) -> Vec<Hash256> {
        let a = self.arity;
        let parent_idx = local_idx / a;
        let first_child = parent_idx * a;
        let level_nodes = &self.levels[level];

        let mut sibs = Vec::with_capacity(a - 1);
        for c in first_child..first_child + a {
            if c == local_idx {
                continue;
            }
            if c < level_nodes.len() {
                sibs.push(level_nodes[c]);
            } else {
                sibs.push(ZERO_HASH);
            }
        }
        sibs
    }

    /// Extract the tree-top cache: all hashes at levels where nodes ≤ threshold.
    ///
    /// Returns (cache_from_level, cached_levels) where cache_from_level is the
    /// first level (from leaves) that is fully cached.
    /// Each cached level is a Vec<Hash256> of all node hashes at that level.
    pub fn tree_top_cache(&self, threshold: usize) -> (usize, Vec<Vec<Hash256>>) {
        let mut cache_from_level = self.depth();
        for (level_idx, level) in self.levels.iter().enumerate() {
            if level.len() <= threshold {
                cache_from_level = level_idx;
                break;
            }
        }
        let cached: Vec<Vec<Hash256>> = self.levels[cache_from_level..].to_vec();
        (cache_from_level, cached)
    }
}

/// Compute the smallest power of `base` that is >= `n`.
fn next_power_of(n: usize, base: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    let mut v = 1;
    while v < n {
        v *= base;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        // Known SHA-256 of empty string
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }
}
