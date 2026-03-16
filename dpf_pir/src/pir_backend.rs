//! PIR Backend Abstraction
//!
//! This module defines the `PirBackend` trait that abstracts server-side
//! query processing for different PIR protocols. Each backend implements
//! the protocol-specific logic for transforming client queries into results.
//!
//! Current implementations:
//! - `DpfPirBackend`: Two-server DPF-based PIR (Distributed Point Functions)
//!
//! Future implementations might include:
//! - SimplePIR (single-server, matrix-vector product)
//! - YPIR (single-server, optimized)
//! - Other two-server protocols

use crate::websocket::DataStore;

/// Trait for PIR protocol backends.
///
/// A backend encapsulates the server-side query processing logic for a
/// specific PIR protocol. The server receives opaque query bytes from the
/// client and delegates processing to the backend.
pub trait PirBackend: Send + Sync {
    /// Name of this PIR protocol (e.g., "dpf-pir", "simplepir")
    fn name(&self) -> &str;

    /// Process a single PIR query against a data store.
    ///
    /// Takes opaque query bytes (protocol-specific) and a data store,
    /// returns the PIR result bytes.
    fn process_query(
        &self,
        query_data: &[u8],
        store: &DataStore,
    ) -> Result<Vec<u8>, String>;
}

/// DPF-PIR backend using Distributed Point Functions.
///
/// This is a two-server protocol where:
/// 1. Client generates two DPF keys (one per server)
/// 2. Each server evaluates its key to produce a bitmap
/// 3. Server XORs selected buckets according to the bitmap
/// 4. Client XORs the two server responses to recover the target bucket
pub struct DpfPirBackend;

impl DpfPirBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DpfPirBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl PirBackend for DpfPirBackend {
    fn name(&self) -> &str {
        "dpf-pir"
    }

    fn process_query(
        &self,
        query_data: &[u8],
        store: &DataStore,
    ) -> Result<Vec<u8>, String> {
        use libdpf::{Dpf, DpfKey};
        use log::info;

        let key = DpfKey::from_bytes(query_data)
            .map_err(|e| format!("Invalid DPF key: {}", e))?;

        info!("DPF key parsed: n={}, domain=2^{}", key.n, key.n);

        let dpf = Dpf::with_default_key();
        let results = dpf.eval_full(&key);

        info!("DPF evaluation complete: {} blocks", results.len());

        let bitmap = dpf_results_to_bitmap(&results, store.num_buckets());

        store.xor_buckets(&bitmap)
    }
}

/// Convert DPF evaluation results (Vec<Block>) to a bitmap
fn dpf_results_to_bitmap(results: &[libdpf::Block], num_buckets: usize) -> Vec<u8> {
    let bitmap_size = (num_buckets + 7) / 8;
    let mut bitmap = vec![0u8; bitmap_size];

    for (block_idx, block) in results.iter().enumerate() {
        let block_bytes = block.to_bytes();

        for (byte_idx, &byte) in block_bytes.iter().enumerate() {
            let bucket_base = block_idx * 128 + byte_idx * 8;
            if bucket_base >= num_buckets {
                break;
            }

            let bitmap_byte_idx = bucket_base / 8;
            let bits_to_copy = if bucket_base + 8 <= num_buckets {
                8
            } else {
                num_buckets - bucket_base
            };

            if byte_idx == 0 && block_idx * 128 % 8 == 0 {
                if bitmap_byte_idx < bitmap.len() {
                    let valid_mask = if bits_to_copy < 8 {
                        (1u8 << bits_to_copy) - 1
                    } else {
                        0xFF
                    };
                    bitmap[bitmap_byte_idx] = byte & valid_mask;
                }
            } else {
                for bit_idx in 0..bits_to_copy {
                    let bucket_idx = bucket_base + bit_idx;
                    if bucket_idx >= num_buckets {
                        break;
                    }

                    if (byte >> bit_idx) & 1 == 1 {
                        let bitmap_byte = bucket_idx / 8;
                        let bitmap_bit = bucket_idx % 8;
                        if bitmap_byte < bitmap.len() {
                            bitmap[bitmap_byte] |= 1 << bitmap_bit;
                        }
                    }
                }
            }
        }
    }

    bitmap
}
