//! Application-level WebSocket chunk reassembly for the browser transport.
//!
//! Cloudflare does not reliably preserve multi-megabyte WebSocket messages, so
//! the server can split one logical PIR record into 256 KiB messages shaped as
//! `[4B len][0xc7][seq:u16][total:u16][piece]`. The native transport performs
//! the same reassembly in `connection.rs`; this module keeps the browser path
//! wire-compatible without depending on `web-sys`, which also makes the state
//! machine directly unit-testable on the native test runner.

use pir_sdk::{PirError, PirResult};

pub(crate) const CHUNK_MAGIC: u8 = 0xc7;
pub(crate) const CHUNK_SIZE: usize = 256 * 1024;
const CHUNK_HEADER_BYTES: usize = 1 + 2 + 2;
pub(crate) const MAX_REASSEMBLED_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReassemblyResult {
    Pending,
    Complete(Vec<u8>),
}

#[derive(Default)]
pub(crate) struct WasmChunkReassembler {
    bytes: Vec<u8>,
    expected: u16,
    total: u16,
}

impl WasmChunkReassembler {
    /// Accept one complete browser WebSocket message. Non-chunk messages pass
    /// through unchanged; chunk messages remain pending until the terminal
    /// sequence number arrives, then yield the original logical PIR record.
    pub(crate) fn push(&mut self, message: Vec<u8>) -> PirResult<ReassemblyResult> {
        if message.len() < 4 + CHUNK_HEADER_BYTES || message[4] != CHUNK_MAGIC {
            return Ok(ReassemblyResult::Complete(message));
        }

        let seq = u16::from_le_bytes([message[5], message[6]]);
        let total = u16::from_le_bytes([message[7], message[8]]);
        if total == 0 {
            return Err(PirError::Protocol("chunk frame with total=0".into()));
        }
        if seq != self.expected {
            return Err(PirError::Protocol(format!(
                "chunk out of order: seq {} expected {}",
                seq, self.expected
            )));
        }
        if seq == 0 {
            self.total = total;
            self.bytes.clear();
        } else if total != self.total {
            return Err(PirError::Protocol("chunk total changed mid-stream".into()));
        }

        let piece = &message[4 + CHUNK_HEADER_BYTES..];
        if piece.is_empty() || piece.len() > CHUNK_SIZE {
            return Err(PirError::Protocol(format!(
                "chunk piece length {} is outside 1..={}",
                piece.len(),
                CHUNK_SIZE
            )));
        }
        let next_len = self
            .bytes
            .len()
            .checked_add(piece.len())
            .ok_or_else(|| PirError::Protocol("reassembled message length overflow".into()))?;
        if next_len > MAX_REASSEMBLED_BYTES {
            return Err(PirError::Protocol("reassembled message exceeds cap".into()));
        }
        self.bytes.extend_from_slice(piece);
        self.expected = self
            .expected
            .checked_add(1)
            .ok_or_else(|| PirError::Protocol("chunk sequence overflow".into()))?;

        if self.expected == self.total {
            self.expected = 0;
            self.total = 0;
            return Ok(ReassemblyResult::Complete(std::mem::take(&mut self.bytes)));
        }
        Ok(ReassemblyResult::Pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRODUCTION_TREE_TOPS_RECORD_BYTES: usize = 9_155_414;

    fn chunk_message(message: &[u8]) -> Vec<Vec<u8>> {
        let total = message.len().div_ceil(CHUNK_SIZE);
        (0..total)
            .map(|seq| {
                let start = seq * CHUNK_SIZE;
                let end = (start + CHUNK_SIZE).min(message.len());
                let piece = &message[start..end];
                let body_len = CHUNK_HEADER_BYTES + piece.len();
                let mut frame = Vec::with_capacity(4 + body_len);
                frame.extend_from_slice(&(body_len as u32).to_le_bytes());
                frame.push(CHUNK_MAGIC);
                frame.extend_from_slice(&(seq as u16).to_le_bytes());
                frame.extend_from_slice(&(total as u16).to_le_bytes());
                frame.extend_from_slice(piece);
                frame
            })
            .collect()
    }

    #[test]
    fn reassembles_production_sized_tree_tops_record() {
        let mut logical = vec![0x5a; PRODUCTION_TREE_TOPS_RECORD_BYTES];
        let payload_len = (logical.len() - 4) as u32;
        logical[..4].copy_from_slice(&payload_len.to_le_bytes());
        logical[4] = 0xfe;
        let chunks = chunk_message(&logical);
        assert_eq!(chunks.len(), 35);

        let mut reassembler = WasmChunkReassembler::default();
        for chunk in &chunks[..chunks.len() - 1] {
            assert_eq!(
                reassembler.push(chunk.clone()).unwrap(),
                ReassemblyResult::Pending
            );
        }
        assert_eq!(
            reassembler.push(chunks.last().unwrap().clone()).unwrap(),
            ReassemblyResult::Complete(logical)
        );
    }

    #[test]
    fn rejects_out_of_order_chunk_without_delivering_partial_bytes() {
        let logical = vec![0x33; CHUNK_SIZE + 1];
        let chunks = chunk_message(&logical);
        let mut reassembler = WasmChunkReassembler::default();

        let error = reassembler.push(chunks[1].clone()).unwrap_err();
        assert!(error.to_string().contains("chunk out of order"));
    }
}
