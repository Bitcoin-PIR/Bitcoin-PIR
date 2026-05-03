//! AES-128 encryption wrapper with hardware acceleration
//!
//! This module provides AES-128 encryption using the `aes` crate which
//! automatically uses AES-NI when available on x86/x86_64 platforms.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::block::Block;

/// AES-128 key for DPF operations
pub struct AesKey {
    key: Aes128,
}

impl AesKey {
    /// Create a new AES key from a 128-bit block
    pub fn new(key: &Block) -> Self {
        let key_bytes = key.to_bytes();
        let key_array: [u8; 16] = key_bytes;
        AesKey {
            key: Aes128::new(&key_array.into()),
        }
    }

    /// Encrypt a single block in-place
    #[inline]
    pub fn encrypt_block(&self, block: &mut Block) {
        let mut bytes = block.to_bytes();
        self.key.encrypt_block(aes::Block::from_mut_slice(&mut bytes));
        *block = Block::from_bytes(&bytes);
    }

    /// Encrypt multiple blocks
    #[inline]
    pub fn encrypt_blocks(&self, blocks: &mut [Block]) {
        for block in blocks.iter_mut() {
            self.encrypt_block(block);
        }
    }

    /// Encrypt two blocks for PRG operation
    /// This is optimized for the common case in DPF
    #[inline]
    pub fn encrypt_two_blocks(&self, block0: &mut Block, block1: &mut Block) {
        self.encrypt_block(block0);
        self.encrypt_block(block1);
    }
}

/// PRG (Pseudorandom Generator) for DPF
/// 
/// Takes a single block and produces two output blocks plus two control bits.
/// Uses AES-128 in a specific construction to ensure pseudorandomness.
pub struct Prg {
    key: AesKey,
}

impl Prg {
    /// Create a new PRG with the given AES key
    pub fn new(key: &Block) -> Self {
        Prg {
            key: AesKey::new(key),
        }
    }

    /// Generate pseudorandom outputs from a seed block
    ///
    /// # Arguments
    /// * `input` - The seed block (LSB will be zeroed before use)
    ///
    /// # Returns
    /// * `(output1, output2, bit1, bit2)` - Two output blocks and two control bits
    #[inline]
    pub fn generate(&self, input: &Block) -> (Block, Block, u8, u8) {
        // Zero the LSB
        let mut stash0 = input.set_lsb_zero();
        let mut stash1 = stash0.reverse_lsb();

        // Encrypt both blocks
        self.key.encrypt_two_blocks(&mut stash0, &mut stash1);

        // XOR with input
        let input_zeroed = input.set_lsb_zero();
        stash0 = stash0.xor(&input_zeroed);
        stash1 = stash1.xor(&input_zeroed);
        stash1 = stash1.reverse_lsb();

        // Extract bits
        let bit1 = stash0.lsb();
        let bit2 = stash1.lsb();

        // Zero LSBs in outputs
        let output1 = stash0.set_lsb_zero();
        let output2 = stash1.set_lsb_zero();

        (output1, output2, bit1, bit2)
    }

    /// Batch generate pseudorandom outputs from multiple seed blocks.
    ///
    /// More efficient than calling `generate()` in a loop because
    /// `Aes128::encrypt_blocks` pipelines ~8 blocks simultaneously via AES-NI,
    /// giving up to ~4-8x throughput on the encryption step.
    ///
    /// `out_s` must have length `2 * inputs.len()` (left at `2*j`, right at `2*j+1`).
    /// `out_t` must have length `2 * inputs.len()`.
    /// `scratch` is a reusable Vec to avoid repeated allocation across calls.
    pub(crate) fn generate_batch(
        &self,
        inputs: &[Block],
        out_s: &mut [Block],
        out_t: &mut [u8],
        scratch: &mut Vec<aes::cipher::Block<Aes128>>,
    ) {
        let n = inputs.len();
        if n == 0 {
            return;
        }

        // Prepare 2*n AES cipher blocks: [stash0_0, stash1_0, stash0_1, stash1_1, ...]
        scratch.clear();
        scratch.reserve(2 * n);
        for input in inputs {
            let zeroed = input.set_lsb_zero();
            let bytes0 = zeroed.to_bytes();
            let bytes1 = zeroed.reverse_lsb().to_bytes();
            scratch.push(*aes::cipher::Block::<Aes128>::from_slice(&bytes0));
            scratch.push(*aes::cipher::Block::<Aes128>::from_slice(&bytes1));
        }

        // Batch encrypt — AES-NI processes 8 blocks in parallel per pipeline fill
        self.key.key.encrypt_blocks(scratch);

        // Post-process: XOR with zeroed input, extract bits, write outputs
        for i in 0..n {
            let zeroed = inputs[i].set_lsb_zero();

            let enc0_bytes: [u8; 16] = scratch[2 * i].as_slice().try_into().unwrap();
            let enc1_bytes: [u8; 16] = scratch[2 * i + 1].as_slice().try_into().unwrap();

            let stash0 = Block::from_bytes(&enc0_bytes).xor(&zeroed);
            let stash1 = Block::from_bytes(&enc1_bytes).xor(&zeroed).reverse_lsb();

            out_s[2 * i] = stash0.set_lsb_zero();
            out_s[2 * i + 1] = stash1.set_lsb_zero();
            out_t[2 * i] = stash0.lsb();
            out_t[2 * i + 1] = stash1.lsb();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_key_creation() {
        let key = Block::new(597349, 121379);
        let aes_key = AesKey::new(&key);
        // Just verify it doesn't panic
        drop(aes_key);
    }

    #[test]
    fn test_aes_encrypt_block() {
        let key = Block::new(597349, 121379);
        let aes_key = AesKey::new(&key);

        let mut block = Block::new(0, 0);
        aes_key.encrypt_block(&mut block);

        // Block should have changed
        assert_ne!(block, Block::zero());
    }

    #[test]
    fn test_prg_generate() {
        let key = Block::new(597349, 121379);
        let prg = Prg::new(&key);

        let input = Block::new(12345, 67890);
        let (out1, out2, bit1, bit2) = prg.generate(&input);

        // Outputs should have LSB zero
        assert_eq!(out1.lsb(), 0);
        assert_eq!(out2.lsb(), 0);

        // Bits should be 0 or 1
        assert!(bit1 <= 1);
        assert!(bit2 <= 1);

        // Outputs should generally be different
        // (collision is extremely unlikely with proper PRG)
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_prg_deterministic() {
        let key = Block::new(597349, 121379);
        let prg = Prg::new(&key);

        let input = Block::new(12345, 67890);
        let (out1a, out2a, bit1a, bit2a) = prg.generate(&input);
        let (out1b, out2b, bit1b, bit2b) = prg.generate(&input);

        // Same input should produce same output
        assert_eq!(out1a, out1b);
        assert_eq!(out2a, out2b);
        assert_eq!(bit1a, bit1b);
        assert_eq!(bit2a, bit2b);
    }

    #[test]
    fn test_prg_lsb_handling() {
        let key = Block::new(597349, 121379);
        let prg = Prg::new(&key);

        // Input with LSB=0
        let input0 = Block::new(12345, 67890).set_lsb_zero();
        // Input with LSB=1 (same except LSB)
        let input1 = input0.reverse_lsb();

        let (out1a, out2a, bit1a, bit2a) = prg.generate(&input0);
        let (out1b, out2b, bit1b, bit2b) = prg.generate(&input1);

        // Since PRG zeros the LSB before encryption, both inputs produce the same outputs
        // This is the intended behavior
        assert_eq!(out1a, out1b);
        assert_eq!(out2a, out2b);
        assert_eq!(bit1a, bit1b);
        assert_eq!(bit2a, bit2b);
    }
}