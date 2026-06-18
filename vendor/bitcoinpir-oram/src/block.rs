use crate::{ct, Error, Result};
use serde::{Deserialize, Serialize};

const OCCUPIED: u8 = 1;
const EMPTY: u8 = 0;

/// One fixed-size logical ORAM block.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OramBlock {
    /// Whether the slot contains a real logical block.
    pub occupied: bool,
    /// Logical block id. Meaningful only when `occupied`.
    pub logical_id: u64,
    /// Current random leaf label. Meaningful only when `occupied`.
    pub leaf: u32,
    /// Fixed-size payload.
    pub payload: Vec<u8>,
}

impl OramBlock {
    /// Construct a dummy block.
    pub fn dummy(block_size: usize) -> Self {
        Self {
            occupied: false,
            logical_id: u64::MAX,
            leaf: u32::MAX,
            payload: vec![0; block_size],
        }
    }

    /// Construct a real block.
    pub fn real(logical_id: u64, leaf: u32, payload: Vec<u8>, block_size: usize) -> Result<Self> {
        if payload.len() != block_size {
            return Err(Error::InvalidInput(format!(
                "payload len {} != block_size {}",
                payload.len(),
                block_size
            )));
        }
        Ok(Self {
            occupied: true,
            logical_id,
            leaf,
            payload,
        })
    }

    /// Return 1 iff this slot is occupied by `logical_id`.
    #[inline]
    pub fn logical_id_choice(&self, logical_id: u64) -> ct::Choice {
        ct::and(
            ct::choice_from_bool(self.occupied),
            ct::eq_u64(self.logical_id, logical_id),
        )
    }

    /// Conditionally assign `other` into this block.
    #[inline]
    pub fn cmov_from(&mut self, other: &Self, choice: ct::Choice) {
        debug_assert_eq!(self.payload.len(), other.payload.len());
        let mut occupied = self.occupied as u8;
        ct::cmov_u8(&mut occupied, other.occupied as u8, choice);
        self.occupied = occupied != 0;
        ct::cmov_u64(&mut self.logical_id, other.logical_id, choice);
        ct::cmov_u32(&mut self.leaf, other.leaf, choice);
        ct::cmov_bytes(&mut self.payload, &other.payload, choice);
    }

    /// Conditionally clear this slot to a dummy block.
    #[inline]
    pub fn clear_if(&mut self, choice: ct::Choice, block_size: usize) {
        debug_assert_eq!(self.payload.len(), block_size);
        let mut occupied = self.occupied as u8;
        ct::cmov_u8(&mut occupied, EMPTY, choice);
        self.occupied = occupied != 0;
        ct::cmov_u64(&mut self.logical_id, u64::MAX, choice);
        ct::cmov_u32(&mut self.leaf, u32::MAX, choice);
        for byte in &mut self.payload {
            ct::cmov_u8(byte, 0, choice);
        }
    }

    /// Serialized length for a block at the given payload size.
    pub const fn serialized_len(block_size: usize) -> usize {
        1 + 8 + 4 + block_size
    }

    /// Serialize into a fixed-size destination.
    pub fn encode_into(&self, out: &mut [u8], block_size: usize) -> Result<()> {
        let expected = Self::serialized_len(block_size);
        if out.len() != expected {
            return Err(Error::InvalidInput(format!(
                "block output len {} != expected {}",
                out.len(),
                expected
            )));
        }
        if self.payload.len() != block_size {
            return Err(Error::InvalidInput(format!(
                "payload len {} != block_size {}",
                self.payload.len(),
                block_size
            )));
        }

        out[0] = if self.occupied { OCCUPIED } else { EMPTY };
        out[1..9].copy_from_slice(&self.logical_id.to_le_bytes());
        out[9..13].copy_from_slice(&self.leaf.to_le_bytes());
        out[13..].copy_from_slice(&self.payload);
        Ok(())
    }

    /// Decode from a fixed-size source.
    pub fn decode_from(input: &[u8], block_size: usize) -> Result<Self> {
        let expected = Self::serialized_len(block_size);
        if input.len() != expected {
            return Err(Error::InvalidInput(format!(
                "block input len {} != expected {}",
                input.len(),
                expected
            )));
        }
        let occupied = match input[0] {
            EMPTY => false,
            OCCUPIED => true,
            other => {
                return Err(Error::InvalidInput(format!(
                    "invalid occupied byte {other}"
                )));
            }
        };
        let mut logical_id = [0u8; 8];
        logical_id.copy_from_slice(&input[1..9]);
        let mut leaf = [0u8; 4];
        leaf.copy_from_slice(&input[9..13]);
        Ok(Self {
            occupied,
            logical_id: u64::from_le_bytes(logical_id),
            leaf: u32::from_le_bytes(leaf),
            payload: input[13..].to_vec(),
        })
    }
}

/// A physical Path ORAM bucket.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Bucket {
    /// Fixed number of physical block slots.
    pub blocks: Vec<OramBlock>,
}

impl Bucket {
    /// Construct an all-dummy bucket.
    pub fn dummy(bucket_size: usize, block_size: usize) -> Self {
        Self {
            blocks: (0..bucket_size)
                .map(|_| OramBlock::dummy(block_size))
                .collect(),
        }
    }

    /// Encode the bucket into bytes.
    pub fn encode(&self, bucket_size: usize, block_size: usize) -> Result<Vec<u8>> {
        if self.blocks.len() != bucket_size {
            return Err(Error::InvalidInput(format!(
                "bucket has {} blocks, expected {}",
                self.blocks.len(),
                bucket_size
            )));
        }
        let block_len = OramBlock::serialized_len(block_size);
        let mut out = vec![0u8; bucket_size * block_len];
        for (i, block) in self.blocks.iter().enumerate() {
            let start = i * block_len;
            block.encode_into(&mut out[start..start + block_len], block_size)?;
        }
        Ok(out)
    }

    /// Decode a bucket from bytes.
    pub fn decode(input: &[u8], bucket_size: usize, block_size: usize) -> Result<Self> {
        let block_len = OramBlock::serialized_len(block_size);
        let expected = bucket_size * block_len;
        if input.len() != expected {
            return Err(Error::InvalidInput(format!(
                "bucket input len {} != expected {}",
                input.len(),
                expected
            )));
        }
        let mut blocks = Vec::with_capacity(bucket_size);
        for chunk in input.chunks_exact(block_len) {
            blocks.push(OramBlock::decode_from(chunk, block_size)?);
        }
        Ok(Self { blocks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_cmov_and_clear_work() {
        let mut block = OramBlock::real(7, 3, vec![1, 2, 3, 4], 4).unwrap();
        let other = OramBlock::real(9, 5, vec![9, 8, 7, 6], 4).unwrap();

        block.cmov_from(&other, 0);
        assert_eq!(block.logical_id, 7);
        assert_eq!(block.leaf, 3);
        assert_eq!(block.payload, vec![1, 2, 3, 4]);

        block.cmov_from(&other, 1);
        assert_eq!(block.logical_id, 9);
        assert_eq!(block.leaf, 5);
        assert_eq!(block.payload, vec![9, 8, 7, 6]);

        block.clear_if(0, 4);
        assert!(block.occupied);
        block.clear_if(1, 4);
        assert!(!block.occupied);
        assert_eq!(block.logical_id, u64::MAX);
        assert_eq!(block.leaf, u32::MAX);
        assert_eq!(block.payload, vec![0, 0, 0, 0]);
    }
}
