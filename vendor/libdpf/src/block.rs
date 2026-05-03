//! 128-bit block operations for DPF
//!
//! This module provides efficient 128-bit block operations using native integer types.
//! On platforms with SIMD support, operations can be further optimized.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A 128-bit block represented as two 64-bit integers.
/// 
/// Memory layout: `[low, high]` where `low` is bits 0-63 and `high` is bits 64-127.
/// This matches the little-endian representation used in the original C implementation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Zeroize, Serialize, Deserialize)]
#[repr(C)]
pub struct Block {
    pub low: u64,
    pub high: u64,
}

impl Block {
    /// Create a new block from two 64-bit integers
    #[inline]
    pub fn new(high: u64, low: u64) -> Self {
        Block { low, high }
    }

    /// Create a zero block
    #[inline]
    pub fn zero() -> Self {
        Block { low: 0, high: 0 }
    }

    /// Create a block from a byte array (16 bytes)
    #[inline]
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        let low = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let high = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        Block { low, high }
    }

    /// Convert block to a byte array
    #[inline]
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&self.low.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.high.to_le_bytes());
        bytes
    }

    /// XOR two blocks
    #[inline]
    pub fn xor(&self, other: &Block) -> Block {
        Block {
            low: self.low ^ other.low,
            high: self.high ^ other.high,
        }
    }

    /// Get the least significant bit
    #[inline]
    pub fn lsb(&self) -> u8 {
        (self.low & 1) as u8
    }

    /// Check if two blocks are equal
    #[inline]
    pub fn is_equal(&self, other: &Block) -> bool {
        self.low == other.low && self.high == other.high
    }

    /// Check if two blocks are unequal
    #[inline]
    pub fn is_unequal(&self, other: &Block) -> bool {
        !self.is_equal(other)
    }

    /// Reverse the LSB of the block
    #[inline]
    pub fn reverse_lsb(&self) -> Block {
        // XOR with block that has LSB = 1
        Block {
            low: self.low ^ 1,
            high: self.high,
        }
    }

    /// Set the LSB to zero
    #[inline]
    pub fn set_lsb_zero(&self) -> Block {
        if self.lsb() == 1 {
            self.reverse_lsb()
        } else {
            *self
        }
    }

    /// Left shift the entire 128-bit block by n bits (0-127)
    #[inline]
    pub fn left_shift(&self, n: u32) -> Block {
        if n == 0 {
            return *self;
        }
        if n >= 128 {
            return Block::zero();
        }

        if n >= 64 {
            // Shift crosses the boundary - all low bits go to high
            Block {
                low: 0,
                high: self.low << (n - 64),
            }
        } else {
            // Normal case: both parts have bits
            Block {
                low: self.low << n,
                high: (self.high << n) | (self.low >> (64 - n)),
            }
        }
    }

    /// Right shift the entire 128-bit block by n bits (0-127)
    #[inline]
    pub fn right_shift(&self, n: u32) -> Block {
        if n == 0 {
            return *self;
        }
        if n >= 128 {
            return Block::zero();
        }

        if n >= 64 {
            Block {
                low: self.high >> (n - 64),
                high: 0,
            }
        } else {
            Block {
                low: (self.low >> n) | (self.high << (64 - n)),
                high: self.high >> n,
            }
        }
    }

    /// Double the block (left shift by 1)
    #[inline]
    pub fn double(&self) -> Block {
        self.left_shift(1)
    }

    /// Create a random block using the provided RNG
    #[cfg(feature = "std")]
    pub fn random(rng: &mut impl rand::Rng) -> Self {
        Block {
            low: rng.gen(),
            high: rng.gen(),
        }
    }
}

impl std::fmt::Binary for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Print low bits first (as in C implementation), then high bits
        for i in 0..64 {
            write!(f, "{}", (self.low >> i) & 1)?;
        }
        for i in 0..64 {
            write!(f, "{}", (self.high >> i) & 1)?;
        }
        Ok(())
    }
}

impl From<[u8; 16]> for Block {
    fn from(bytes: [u8; 16]) -> Self {
        Block::from_bytes(&bytes)
    }
}

impl From<Block> for [u8; 16] {
    fn from(block: Block) -> Self {
        block.to_bytes()
    }
}

impl std::ops::BitXor for Block {
    type Output = Block;

    fn bitxor(self, other: Block) -> Block {
        self.xor(&other)
    }
}

impl std::ops::BitXorAssign for Block {
    fn bitxor_assign(&mut self, other: Block) {
        self.low ^= other.low;
        self.high ^= other.high;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_xor() {
        let a = Block::new(0xFFFF, 0xAAAA);
        let b = Block::new(0x0000, 0x5555);
        let result = a.xor(&b);
        assert_eq!(result.low, 0xFFFF);
        assert_eq!(result.high, 0xFFFF);
    }

    #[test]
    fn test_block_lsb() {
        let a = Block::new(0, 0);
        assert_eq!(a.lsb(), 0);

        let b = Block::new(0, 1);
        assert_eq!(b.lsb(), 1);

        let c = Block::new(1, 0);
        assert_eq!(c.lsb(), 0);
    }

    #[test]
    fn test_block_reverse_lsb() {
        let a = Block::new(0, 0);
        assert_eq!(a.reverse_lsb().lsb(), 1);

        let b = Block::new(0, 1);
        assert_eq!(b.reverse_lsb().lsb(), 0);
    }

    #[test]
    fn test_block_set_lsb_zero() {
        let a = Block::new(0, 1);
        assert_eq!(a.set_lsb_zero().lsb(), 0);

        let b = Block::new(0, 0);
        assert_eq!(b.set_lsb_zero().lsb(), 0);
    }

    #[test]
    fn test_block_left_shift() {
        // Test shift within low
        let a = Block::new(0, 1);
        let shifted = a.left_shift(1);
        assert_eq!(shifted.low, 2);
        assert_eq!(shifted.high, 0);

        // Test shift crossing boundary
        let b = Block::new(0, 1);
        let shifted = b.left_shift(64);
        assert_eq!(shifted.low, 0);
        assert_eq!(shifted.high, 1);

        // Test shift crossing boundary partially
        let c = Block::new(0, 0x8000000000000000); // high bit of low
        let shifted = c.left_shift(1);
        assert_eq!(shifted.low, 0);
        assert_eq!(shifted.high, 1);
    }

    #[test]
    fn test_block_bytes_roundtrip() {
        let original = Block::new(0x123456789ABCDEF0, 0xFEDCBA9876543210);
        let bytes = original.to_bytes();
        let restored = Block::from_bytes(&bytes);
        assert_eq!(original, restored);
    }
}