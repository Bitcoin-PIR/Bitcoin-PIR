//! DPF Key serialization and deserialization
//!
//! Key format (matching C implementation):
//! - Byte 0: n (domain parameter)
//! - Bytes 1-16: s₀ (initial seed block)
//! - Byte 17: t₀ (initial control bit)
//! - For each layer i (1 to maxlayer):
//!   - Bytes [18*i .. 18*i+16]: sCW[i-1] (correction word)
//!   - Byte 18*i+16: tCW[i-1][0] (left correction bit)
//!   - Byte 18*i+17: tCW[i-1][1] (right correction bit)
//! - Final 16 bytes: finalblock

use crate::block::Block;
use serde::{Deserialize, Serialize};

/// A DPF key for evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DpfKey {
    /// Domain parameter (size is 2^n)
    pub n: u8,
    /// Initial seed block
    pub s0: Block,
    /// Initial control bit
    pub t0: u8,
    /// Correction words (one per layer)
    pub scw: Vec<Block>,
    /// Correction bits (two per layer)
    pub tcw: Vec<[u8; 2]>,
    /// Final correction block
    pub final_block: Block,
}

impl DpfKey {
    /// Create a new DPF key
    pub fn new(
        n: u8,
        s0: Block,
        t0: u8,
        scw: Vec<Block>,
        tcw: Vec<[u8; 2]>,
        final_block: Block,
    ) -> Self {
        DpfKey {
            n,
            s0,
            t0,
            scw,
            tcw,
            final_block,
        }
    }

    /// Get the number of layers (maxlayer = n - 7)
    pub fn max_layer(&self) -> usize {
        (self.n - 7) as usize
    }

    /// Get the key size in bytes
    pub fn size(&self) -> usize {
        let maxlayer = self.max_layer();
        1 + 16 + 1 + 18 * maxlayer + 16
    }

    /// Serialize the key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = self.size();
        let mut bytes = vec![0u8; size];

        bytes[0] = self.n;
        bytes[1..17].copy_from_slice(&self.s0.to_bytes());
        bytes[17] = self.t0;

        for i in 0..self.scw.len() {
            let offset = 18 * (i + 1);
            bytes[offset..offset + 16].copy_from_slice(&self.scw[i].to_bytes());
            bytes[offset + 16] = self.tcw[i][0];
            bytes[offset + 17] = self.tcw[i][1];
        }

        let final_offset = 18 * (self.max_layer() + 1);
        bytes[final_offset..final_offset + 16].copy_from_slice(&self.final_block.to_bytes());

        bytes
    }

    /// Deserialize a key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 18 {
            return Err("Key too short");
        }

        let n = bytes[0];
        let maxlayer = (n - 7) as usize;
        let expected_size = 1 + 16 + 1 + 18 * maxlayer + 16;

        if bytes.len() < expected_size {
            return Err("Key has incorrect length");
        }

        let s0 = Block::from_bytes(&bytes[1..17].try_into().unwrap());
        let t0 = bytes[17];

        let mut scw = Vec::with_capacity(maxlayer);
        let mut tcw = Vec::with_capacity(maxlayer);

        for i in 0..maxlayer {
            let offset = 18 * (i + 1);
            let cw = Block::from_bytes(&bytes[offset..offset + 16].try_into().unwrap());
            scw.push(cw);
            tcw.push([bytes[offset + 16], bytes[offset + 17]]);
        }

        let final_offset = 18 * (maxlayer + 1);
        let final_block = Block::from_bytes(&bytes[final_offset..final_offset + 16].try_into().unwrap());

        Ok(DpfKey {
            n,
            s0,
            t0,
            scw,
            tcw,
            final_block,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_json_roundtrip() {
        let n: u8 = 16;
        let maxlayer = (n - 7) as usize;

        let key = DpfKey {
            n,
            s0: Block::new(12345, 67890),
            t0: 1,
            scw: vec![Block::new(111, 222); maxlayer],
            tcw: vec![[0, 1]; maxlayer],
            final_block: Block::new(999, 888),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&key).unwrap();
        
        // Deserialize from JSON
        let restored: DpfKey = serde_json::from_str(&json).unwrap();

        assert_eq!(key.n, restored.n);
        assert_eq!(key.s0, restored.s0);
        assert_eq!(key.t0, restored.t0);
        assert_eq!(key.scw, restored.scw);
        assert_eq!(key.tcw, restored.tcw);
        assert_eq!(key.final_block, restored.final_block);
    }

    #[test]
    fn test_serde_bincode_roundtrip() {
        let n: u8 = 16;
        let maxlayer = (n - 7) as usize;

        let key = DpfKey {
            n,
            s0: Block::new(12345, 67890),
            t0: 1,
            scw: vec![Block::new(111, 222); maxlayer],
            tcw: vec![[0, 1]; maxlayer],
            final_block: Block::new(999, 888),
        };

        // Serialize to binary (bincode)
        let binary = bincode::serialize(&key).unwrap();
        
        // Deserialize from binary
        let restored: DpfKey = bincode::deserialize(&binary).unwrap();

        assert_eq!(key.n, restored.n);
        assert_eq!(key.s0, restored.s0);
        assert_eq!(key.t0, restored.t0);
        assert_eq!(key.scw, restored.scw);
        assert_eq!(key.tcw, restored.tcw);
        assert_eq!(key.final_block, restored.final_block);
    }

    #[test]
    fn test_key_serialization_roundtrip() {
        let n: u8 = 16;
        let maxlayer = (n - 7) as usize;

        let key = DpfKey {
            n,
            s0: Block::new(12345, 67890),
            t0: 1,
            scw: vec![Block::new(111, 222); maxlayer],
            tcw: vec![[0, 1]; maxlayer],
            final_block: Block::new(999, 888),
        };

        let bytes = key.to_bytes();
        let restored = DpfKey::from_bytes(&bytes).unwrap();

        assert_eq!(key.n, restored.n);
        assert_eq!(key.s0, restored.s0);
        assert_eq!(key.t0, restored.t0);
        assert_eq!(key.scw, restored.scw);
        assert_eq!(key.tcw, restored.tcw);
        assert_eq!(key.final_block, restored.final_block);
    }

    #[test]
    fn test_key_size() {
        let n: u8 = 16;
        let maxlayer = (n - 7) as usize;
        let expected_size = 1 + 16 + 1 + 18 * maxlayer + 16;

        let key = DpfKey {
            n,
            s0: Block::zero(),
            t0: 0,
            scw: vec![Block::zero(); maxlayer],
            tcw: vec![[0, 0]; maxlayer],
            final_block: Block::zero(),
        };

        assert_eq!(key.size(), expected_size);
        assert_eq!(key.to_bytes().len(), expected_size);
    }
}