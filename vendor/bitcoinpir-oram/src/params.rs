use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Public ORAM sizing parameters.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OramParams {
    /// Number of logical blocks addressed by callers.
    pub logical_blocks: usize,
    /// Number of usable payload bytes in each logical block.
    pub block_size: usize,
    /// Number of physical blocks in each tree bucket.
    pub bucket_size: usize,
    /// Number of leaves in the ORAM tree. Must be a power of two.
    pub leaves: usize,
    /// Maximum stash length accepted by this prototype.
    pub stash_capacity: usize,
}

impl OramParams {
    /// Construct conservative ORAM parameters.
    ///
    /// The default uses one leaf per logical block, rounded up to a power of
    /// two. That is intentionally storage-heavy but easy to reason about for
    /// the first benchmark.
    pub fn new(logical_blocks: usize, block_size: usize) -> Result<Self> {
        let leaves = logical_blocks.max(2).next_power_of_two();
        Self::with_leaves(logical_blocks, block_size, leaves)
    }

    /// Construct parameters with an explicit leaf count.
    pub fn with_leaves(logical_blocks: usize, block_size: usize, leaves: usize) -> Result<Self> {
        if logical_blocks == 0 {
            return Err(Error::InvalidParams("logical_blocks must be > 0".into()));
        }
        if block_size == 0 {
            return Err(Error::InvalidParams("block_size must be > 0".into()));
        }
        if !leaves.is_power_of_two() || leaves < 2 {
            return Err(Error::InvalidParams(
                "leaves must be a power of two >= 2".into(),
            ));
        }
        if leaves > u32::MAX as usize {
            return Err(Error::InvalidParams(
                "leaves must fit in u32 leaf labels".into(),
            ));
        }

        Ok(Self {
            logical_blocks,
            block_size,
            bucket_size: 4,
            leaves,
            stash_capacity: 512,
        })
    }

    /// Override the number of blocks per bucket.
    pub fn with_bucket_size(mut self, bucket_size: usize) -> Result<Self> {
        if bucket_size == 0 {
            return Err(Error::InvalidParams("bucket_size must be > 0".into()));
        }
        self.bucket_size = bucket_size;
        Ok(self)
    }

    /// Override the stash capacity.
    pub fn with_stash_capacity(mut self, stash_capacity: usize) -> Result<Self> {
        if stash_capacity < self.bucket_size * self.height() {
            return Err(Error::InvalidParams(
                "stash_capacity should be at least bucket_size * height".into(),
            ));
        }
        self.stash_capacity = stash_capacity;
        Ok(self)
    }

    /// Number of levels in the tree, including root and leaf levels.
    pub fn height(&self) -> usize {
        self.leaf_bits() + 1
    }

    /// Number of bits needed to represent a leaf.
    pub fn leaf_bits(&self) -> usize {
        self.leaves.trailing_zeros() as usize
    }

    /// Number of buckets in the complete binary tree.
    pub fn bucket_count(&self) -> usize {
        self.leaves * 2 - 1
    }

    /// Plaintext bytes per physical bucket.
    pub fn bucket_bytes(&self) -> usize {
        self.bucket_size * crate::block::OramBlock::serialized_len(self.block_size)
    }

    /// Heap-array node index for `leaf` at `depth`.
    pub fn node_index(&self, depth: usize, leaf: u32) -> usize {
        debug_assert!(depth < self.height());
        debug_assert!((leaf as usize) < self.leaves);
        let level_offset = (1usize << depth) - 1;
        if depth == 0 {
            return level_offset;
        }
        let shift = self.leaf_bits() - depth;
        level_offset + (((leaf as usize) >> shift) & ((1usize << depth) - 1))
    }

    /// Node path from root to leaf.
    pub fn path_nodes(&self, leaf: u32) -> Vec<usize> {
        (0..self.height())
            .map(|depth| self.node_index(depth, leaf))
            .collect()
    }

    /// True if `node_idx` at `depth` is on the path to `leaf`.
    pub fn node_contains_leaf(&self, depth: usize, node_idx: usize, leaf: u32) -> bool {
        self.node_index(depth, leaf) == node_idx
    }
}
