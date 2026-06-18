//! BitcoinPIR-shaped Path ORAM prototype.
//!
//! This crate intentionally implements an oblivious *array*, not a generic
//! oblivious map. BitcoinPIR already owns the public mapping from scripthash to
//! PBC/cuckoo positions; this layer hides which logical block the SEV guest
//! reads from disk-backed storage.

pub mod aead;
pub mod block;
pub mod circuit;
pub mod ct;
pub mod cuckoo;
pub mod direct;
pub mod error;
pub mod merkle;
pub mod oram;
pub mod params;
pub mod state;
pub mod store;
pub mod stress;

pub use aead::{AeadPageStore, AEAD_OVERHEAD};
pub use block::{Bucket, OramBlock};
pub use circuit::{
    circuit_meta_page_bytes, circuit_payload_page_bytes, CircuitEvictionSchedule, CircuitMetaSlot,
    CircuitOram, TrustedBlockSource,
};
pub use cuckoo::{
    locate_packed_cuckoo_bin, CircuitCuckooBinRead, CircuitCuckooBinReader, CuckooLevel,
    CuckooOramEstimate, CuckooOramSizing, CuckooPackedBlockReader, CuckooTableInfo,
    PackedCuckooBinLocation,
};
pub use direct::{
    direct_index_candidate_bins, locate_packed_direct_item, CircuitDirectChunkReader,
    CircuitDirectIndexReader, DirectChunkPackedBlockReader, DirectChunkRead, DirectIndexLookup,
    DirectIndexPackedBlockReader, DirectLevel, DirectOramEstimate, DirectOramSizing,
    DirectTableInfo, DirectTableMetadata, PackedDirectItemLocation, DIRECT_CHUNKS_INPUT_FILE,
    DIRECT_CHUNK_RECORD_SIZE, DIRECT_INDEX_DEFAULT_HASH_FNS, DIRECT_INDEX_DEFAULT_LOAD_FACTOR,
    DIRECT_INDEX_DEFAULT_SEED, DIRECT_INDEX_DEFAULT_SLOTS_PER_BIN, DIRECT_INDEX_INPUT_FILE,
    DIRECT_INDEX_INPUT_RECORD_SIZE, DIRECT_INDEX_SLOT_SIZE, DIRECT_SCRIPT_HASH_SIZE,
};
pub use error::{Error, Result};
pub use merkle::{MerklePageStore, TieredMerklePageStore, TieredMerkleState};
pub use oram::PathOram;
pub use params::OramParams;
pub use state::{CircuitOramState, CircuitStoreAuthState, OramState};
pub use store::{FilePageStore, FrontCachedPageStore, MemPageStore, PageStore, TracingStore};
pub use stress::{stress_circuit, CircuitStressConfig, CircuitStressPattern, CircuitStressReport};
