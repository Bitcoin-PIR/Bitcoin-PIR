//! # libdpf - Distributed Point Function Library
//!
//! A Rust implementation of 2-party 1-bit Distributed Point Function (DPF)
//! from "Function Secret Sharing: Improvements and Extensions" (Boyle et al., CCS'16).
//!
//! ## Overview
//!
//! A Distributed Point Function (DPF) allows two parties to generate keys such that
//! when they each evaluate their key at any point x, the XOR of their results reveals
//! whether x equals a secret point α. This is useful for:
//!
//! - Private Information Retrieval (PIR)
//! - Secure computation
//! - Privacy-preserving data access
//!
//! ## Example
//!
//! ```rust
//! use libdpf::{Dpf, DpfKey, Block};
//!
//! // Create a DPF context
//! let dpf = Dpf::with_default_key();
//!
//! // Generate keys for point α = 12345 in domain of size 2^16
//! let alpha: u64 = 12345;
//! let n: u8 = 16;
//! let (k0, k1) = dpf.gen(alpha, n);
//!
//! // Evaluate at point α - XOR of results is non-zero
//! let r0 = dpf.eval(&k0, alpha);
//! let r1 = dpf.eval(&k1, alpha);
//! assert!(!r0.xor(&r1).is_equal(&Block::zero()));
//!
//! // Evaluate at other points - XOR of results is zero
//! let r0 = dpf.eval(&k0, 0);
//! let r1 = dpf.eval(&k1, 0);
//! assert!(r0.xor(&r1).is_equal(&Block::zero()));
//! ```

pub mod block;
pub mod aes;
pub mod key;
pub mod dpf;

// Re-export main types for convenience
pub use block::Block;
pub use aes::{AesKey, Prg};
pub use key::DpfKey;
pub use dpf::{Dpf, gen, eval, eval_full, eval_partial};

/// Default AES key high value (from C implementation)
pub const DEFAULT_KEY_HIGH: u64 = 597349;

/// Default AES key low value (from C implementation)
pub const DEFAULT_KEY_LOW: u64 = 121379;

/// Get the default AES key block
pub fn default_key() -> Block {
    Block::new(DEFAULT_KEY_HIGH, DEFAULT_KEY_LOW)
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_workflow() {
        let dpf = Dpf::with_default_key();
        
        // Test with different alpha values
        for alpha in [0u64, 100, 26943, 50000, 65535] {
            let (k0, k1) = dpf.gen(alpha, 16);
            
            // At alpha: non-zero XOR
            let r0 = dpf.eval(&k0, alpha);
            let r1 = dpf.eval(&k1, alpha);
            assert!(!r0.xor(&r1).is_equal(&Block::zero()),
                "At alpha={}, XOR should be non-zero", alpha);
            
            // At other points: zero XOR (spot check)
            // Note: DPF groups 128 values into one block, so x must be in a different
            // 128-element block from alpha to get zero XOR result
            let alpha_block = alpha / 128;
            for x in [0u64, 1000, 60000] {
                let x_block = x / 128;
                // Only test points that are in different blocks from alpha
                if x_block != alpha_block {
                    let r0 = dpf.eval(&k0, x);
                    let r1 = dpf.eval(&k1, x);
                    assert!(r0.xor(&r1).is_equal(&Block::zero()),
                        "At x={} (block {}) with alpha={} (block {}), XOR should be zero", 
                        x, x_block, alpha, alpha_block);
                }
            }
        }
    }

    #[test]
    fn test_different_domain_sizes() {
        let dpf = Dpf::with_default_key();
        
        for n in 8u8..=20 {
            let alpha: u64 = (1u64 << (n - 1)) + 123; // Middle-ish point
            let (k0, k1) = dpf.gen(alpha, n);
            
            // Verify key sizes
            let expected_size = 1 + 16 + 1 + 18 * ((n - 7) as usize) + 16;
            assert_eq!(k0.to_bytes().len(), expected_size);
            assert_eq!(k1.to_bytes().len(), expected_size);
            
            // Verify correctness
            let r0 = dpf.eval(&k0, alpha);
            let r1 = dpf.eval(&k1, alpha);
            assert!(!r0.xor(&r1).is_equal(&Block::zero()),
                "Domain size 2^{}: XOR at alpha should be non-zero", n);
        }
    }

    #[test]
    fn test_eval_partial_consistency() {
        let dpf = Dpf::with_default_key();
        let alpha: u64 = 26943;
        let n: u8 = 16;

        let (k0, k1) = dpf.gen(alpha, n);

        // Full evaluation
        let full0 = dpf.eval_full(&k0);
        let full1 = dpf.eval_full(&k1);

        // Partial evaluation of first 30000 points
        let partial0 = dpf.eval_partial(&k0, 30000);
        let partial1 = dpf.eval_partial(&k1, 30000);

        // 30000 / 128 = 234.375 -> 235 blocks
        assert_eq!(partial0.len(), 235);

        // Partial should match the first 235 blocks of full
        for i in 0..235 {
            assert_eq!(partial0[i], full0[i], "k0 partial mismatch at block {}", i);
            assert_eq!(partial1[i], full1[i], "k1 partial mismatch at block {}", i);
        }
    }

    #[test]
    fn test_eval_full_consistency() {
        let dpf = Dpf::with_default_key();
        let alpha: u64 = 26943;
        let n: u8 = 16;
        
        let (k0, k1) = dpf.gen(alpha, n);
        
        // Full evaluation
        let full0 = dpf.eval_full(&k0);
        let full1 = dpf.eval_full(&k1);
        
        // Point-by-point evaluation should match
        for i in 0..(1 << (n - 7)) {
            let x = (i * 128) as u64; // Start of each block
            let r0 = dpf.eval(&k0, x);
            let r1 = dpf.eval(&k1, x);
            
            assert_eq!(full0[i], r0, "eval_full mismatch at block {}", i);
            assert_eq!(full1[i], r1, "eval_full mismatch at block {}", i);
        }
    }
}