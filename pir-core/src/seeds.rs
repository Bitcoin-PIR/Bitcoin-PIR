//! Chain-derived seed generation for reproducible PIR database builds.
//!
//! ## Why
//!
//! The build pipeline historically used hardcoded magic constants
//! (e.g. `MASTER_SEED = 0x71a2ef38b4c90d15`) for cuckoo hash families
//! and fingerprint tags. That pipeline is byte-deterministic across
//! operators — but the seed values are chosen at compile time by the
//! repo maintainer. A maintainer who controlled seed selection before
//! the chain state was fixed could pick seeds that group surveillance-
//! target scripthashes pathologically (e.g., into colliding cuckoo
//! bins or with colliding fingerprint tags).
//!
//! Deriving seeds from the chain anchor (`block_hash` + `block_height`)
//! defeats adversarial seed-shopping: an attacker does not control the
//! block hash, so the resulting seeds are unpredictable until the
//! anchor block is mined.
//!
//! See [`docs/BUILD_REPRODUCIBILITY.md`](../../../docs/BUILD_REPRODUCIBILITY.md)
//! for the full design and roadmap.

use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;

/// A Bitcoin chain anchor — block hash + height.
///
/// Used as the `SeedContext` for snapshot builds. Both fields participate
/// in seed derivation, so a build cannot be replayed with the same seeds
/// under a mismatched height even if the hash were fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainAnchor {
    /// Block hash as reported by `bitcoin-cli dumptxoutset`.
    pub block_hash: [u8; 32],
    /// Block height at the snapshot anchor.
    pub block_height: u32,
}

/// A delta's chain anchor — the block span the delta covers.
///
/// Used as the `SeedContext` for incremental delta builds. Both endpoints
/// participate in seed derivation, so a delta cannot be replayed against
/// a different `from` snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeltaAnchor {
    /// Snapshot the delta applies to.
    pub from: ChainAnchor,
    /// Chain tip after applying the delta.
    pub to: ChainAnchor,
}

/// Bytes that uniquely identify a build context for seed derivation.
///
/// Implementations absorb a distinct leading tag so two different
/// `SeedContext` kinds (e.g., snapshot vs delta) cannot produce the
/// same seed even when their numeric fields coincide.
pub trait SeedContext {
    fn absorb(&self, h: &mut Sha256);
}

impl SeedContext for ChainAnchor {
    fn absorb(&self, h: &mut Sha256) {
        h.update(b"snapshot/");
        h.update(self.block_height.to_le_bytes());
        h.update(self.block_hash);
    }
}

impl SeedContext for DeltaAnchor {
    fn absorb(&self, h: &mut Sha256) {
        h.update(b"delta/");
        h.update(self.from.block_height.to_le_bytes());
        h.update(self.from.block_hash);
        h.update(self.to.block_height.to_le_bytes());
        h.update(self.to.block_hash);
    }
}

/// Tag-prefix string for the v1 seed-derivation scheme. Bumping this
/// breaks reproducibility of pre-existing builds — coordinate carefully.
const TAG_PREFIX_V1: &[u8] = b"BitcoinPIR/seed/v1/";

/// BIP-340-style tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
///
/// The double-`SHA256(tag)` block is 32 fixed bytes, so the tag/msg
/// boundary is unambiguous without length-prefixing.
fn tagged_hash(domain: &str, ctx: &impl SeedContext) -> [u8; 32] {
    let mut tag_hasher = Sha256::new();
    tag_hasher.update(TAG_PREFIX_V1);
    tag_hasher.update(domain.as_bytes());
    let tag_hash = tag_hasher.finalize();

    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    ctx.absorb(&mut h);
    h.finalize().into()
}

/// Derive a 64-bit seed from a chain context for a given domain.
///
/// `domain` selects the use the seed is for. Use the constants in the
/// [`domain`] module rather than free-form strings.
pub fn derive_seed_u64<C: SeedContext>(domain: &str, ctx: &C) -> u64 {
    let bytes = tagged_hash(domain, ctx);
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

/// Derive a full 32-byte seed from a chain context for a given domain.
///
/// Use when 64 bits is insufficient (e.g., future FHE pre-randomization).
pub fn derive_seed_32<C: SeedContext>(domain: &str, ctx: &C) -> [u8; 32] {
    tagged_hash(domain, ctx)
}

/// Canonical domain identifiers for chain-derived seeds.
///
/// Centralizing these prevents typos across the build pipeline. New
/// per-protocol overrides (e.g., a hypothetical `onion/index/cuckoo/master`
/// with a different cuckoo layout) can be added here without changing
/// the derivation rule — they just use a different domain string.
pub mod domain {
    /// Master PRG seed for INDEX cuckoo hash families (all backends).
    pub const INDEX_CUCKOO_MASTER: &str = "index/cuckoo/master";

    /// Master PRG seed for CHUNK cuckoo hash families (all backends).
    pub const CHUNK_CUCKOO_MASTER: &str = "chunk/cuckoo/master";

    /// Keyed-hash seed for INDEX entry fingerprint tags.
    pub const INDEX_TAG_FINGERPRINT: &str = "index/tag/fingerprint";

    /// Master PRG seed for the Merkle data sub-table cuckoo (gen_4).
    pub const MERKLE_DATA_CUCKOO_MASTER: &str = "merkle/data/cuckoo/master";
}

/// Full set of seeds derived from a chain anchor for the snapshot build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotSeeds {
    pub index_master: u64,
    pub chunk_master: u64,
    pub index_tag: u64,
    pub merkle_data_master: u64,
}

impl SnapshotSeeds {
    pub fn derive(anchor: &ChainAnchor) -> Self {
        Self {
            index_master: derive_seed_u64(domain::INDEX_CUCKOO_MASTER, anchor),
            chunk_master: derive_seed_u64(domain::CHUNK_CUCKOO_MASTER, anchor),
            index_tag: derive_seed_u64(domain::INDEX_TAG_FINGERPRINT, anchor),
            merkle_data_master: derive_seed_u64(domain::MERKLE_DATA_CUCKOO_MASTER, anchor),
        }
    }
}

/// Full set of seeds derived from a delta anchor for the delta build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeltaSeeds {
    pub index_master: u64,
    pub chunk_master: u64,
    pub index_tag: u64,
}

impl DeltaSeeds {
    pub fn derive(anchor: &DeltaAnchor) -> Self {
        Self {
            index_master: derive_seed_u64(domain::INDEX_CUCKOO_MASTER, anchor),
            chunk_master: derive_seed_u64(domain::CHUNK_CUCKOO_MASTER, anchor),
            index_tag: derive_seed_u64(domain::INDEX_TAG_FINGERPRINT, anchor),
        }
    }
}

// ─── File I/O ─────────────────────────────────────────────────────────────

/// Canonical filename for the snapshot chain anchor inside a data directory.
pub const CHAIN_ANCHOR_FILENAME: &str = "chain_anchor.bin";

/// Canonical filename for the delta chain anchor inside a delta data directory.
pub const DELTA_ANCHOR_FILENAME: &str = "delta_anchor.bin";

/// On-disk byte size of a serialised `ChainAnchor`.
pub const CHAIN_ANCHOR_BYTES: usize = 36;

/// On-disk byte size of a serialised `DeltaAnchor`.
pub const DELTA_ANCHOR_BYTES: usize = 72;

impl ChainAnchor {
    /// Serialise into the 36-byte on-disk format: `block_hash[0..32] || height_le[32..36]`.
    pub fn to_bytes(&self) -> [u8; CHAIN_ANCHOR_BYTES] {
        let mut out = [0u8; CHAIN_ANCHOR_BYTES];
        out[..32].copy_from_slice(&self.block_hash);
        out[32..].copy_from_slice(&self.block_height.to_le_bytes());
        out
    }

    /// Parse from the 36-byte on-disk format. Errors on length mismatch.
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != CHAIN_ANCHOR_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ChainAnchor expects {} bytes, got {}",
                    CHAIN_ANCHOR_BYTES,
                    bytes.len()
                ),
            ));
        }
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&bytes[..32]);
        let block_height = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        Ok(ChainAnchor { block_hash, block_height })
    }

    /// Write to a file. Overwrites if the file exists.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        fs::write(path, self.to_bytes())
    }

    /// Read from a file.
    pub fn load(path: &Path) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Convenience: load from `<data_dir>/chain_anchor.bin`.
    pub fn load_from_data_dir(data_dir: &Path) -> io::Result<Self> {
        Self::load(&data_dir.join(CHAIN_ANCHOR_FILENAME))
    }
}

impl DeltaAnchor {
    /// Serialise into the 72-byte on-disk format: `from.to_bytes() || to.to_bytes()`.
    pub fn to_bytes(&self) -> [u8; DELTA_ANCHOR_BYTES] {
        let mut out = [0u8; DELTA_ANCHOR_BYTES];
        out[..CHAIN_ANCHOR_BYTES].copy_from_slice(&self.from.to_bytes());
        out[CHAIN_ANCHOR_BYTES..].copy_from_slice(&self.to.to_bytes());
        out
    }

    /// Parse from the 72-byte on-disk format.
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != DELTA_ANCHOR_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "DeltaAnchor expects {} bytes, got {}",
                    DELTA_ANCHOR_BYTES,
                    bytes.len()
                ),
            ));
        }
        let from = ChainAnchor::from_bytes(&bytes[..CHAIN_ANCHOR_BYTES])?;
        let to = ChainAnchor::from_bytes(&bytes[CHAIN_ANCHOR_BYTES..])?;
        Ok(DeltaAnchor { from, to })
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        fs::write(path, self.to_bytes())
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Convenience: load from `<data_dir>/delta_anchor.bin`.
    pub fn load_from_data_dir(data_dir: &Path) -> io::Result<Self> {
        Self::load(&data_dir.join(DELTA_ANCHOR_FILENAME))
    }
}

/// Polymorphic seed set produced by either a snapshot or delta anchor.
///
/// Build sites that don't care which kind of anchor they're given
/// (e.g., `build_cuckoo_generic` runs over both snapshot and delta
/// cuckoo tables) can use [`AnchorSeeds::load`] with length-based
/// discrimination: 36 bytes → snapshot, 72 bytes → delta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorSeeds {
    Snapshot(SnapshotSeeds),
    Delta(DeltaSeeds),
}

impl AnchorSeeds {
    /// Load from a file whose length discriminates the anchor kind.
    pub fn load(path: &Path) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        match bytes.len() {
            CHAIN_ANCHOR_BYTES => Ok(AnchorSeeds::Snapshot(SnapshotSeeds::derive(
                &ChainAnchor::from_bytes(&bytes)?,
            ))),
            DELTA_ANCHOR_BYTES => Ok(AnchorSeeds::Delta(DeltaSeeds::derive(
                &DeltaAnchor::from_bytes(&bytes)?,
            ))),
            n => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "anchor file {} has unknown size {} (expected {} or {})",
                    path.display(),
                    n,
                    CHAIN_ANCHOR_BYTES,
                    DELTA_ANCHOR_BYTES
                ),
            )),
        }
    }

    pub fn index_master(&self) -> u64 {
        match self {
            AnchorSeeds::Snapshot(s) => s.index_master,
            AnchorSeeds::Delta(d) => d.index_master,
        }
    }

    pub fn chunk_master(&self) -> u64 {
        match self {
            AnchorSeeds::Snapshot(s) => s.chunk_master,
            AnchorSeeds::Delta(d) => d.chunk_master,
        }
    }

    pub fn index_tag(&self) -> u64 {
        match self {
            AnchorSeeds::Snapshot(s) => s.index_tag,
            AnchorSeeds::Delta(d) => d.index_tag,
        }
    }

    /// Merkle data table master seed. Snapshot builds only — deltas
    /// don't construct a Merkle data table, so this returns `None`
    /// for `AnchorSeeds::Delta`.
    pub fn merkle_data_master(&self) -> Option<u64> {
        match self {
            AnchorSeeds::Snapshot(s) => Some(s.merkle_data_master),
            AnchorSeeds::Delta(_) => None,
        }
    }

    /// Whether this is a snapshot anchor.
    pub fn is_snapshot(&self) -> bool {
        matches!(self, AnchorSeeds::Snapshot(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor1() -> ChainAnchor {
        ChainAnchor {
            block_hash: [0xab; 32],
            block_height: 850_000,
        }
    }

    fn anchor2() -> ChainAnchor {
        ChainAnchor {
            block_hash: [0xcd; 32],
            block_height: 850_000,
        }
    }

    #[test]
    fn derive_is_deterministic() {
        let a = anchor1();
        assert_eq!(
            derive_seed_u64(domain::INDEX_CUCKOO_MASTER, &a),
            derive_seed_u64(domain::INDEX_CUCKOO_MASTER, &a),
        );
        assert_eq!(
            derive_seed_32(domain::INDEX_CUCKOO_MASTER, &a),
            derive_seed_32(domain::INDEX_CUCKOO_MASTER, &a),
        );
    }

    #[test]
    fn domain_separation() {
        let a = anchor1();
        let s1 = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, &a);
        let s2 = derive_seed_u64(domain::CHUNK_CUCKOO_MASTER, &a);
        let s3 = derive_seed_u64(domain::INDEX_TAG_FINGERPRINT, &a);
        let s4 = derive_seed_u64(domain::MERKLE_DATA_CUCKOO_MASTER, &a);
        assert_ne!(s1, s2);
        assert_ne!(s1, s3);
        assert_ne!(s1, s4);
        assert_ne!(s2, s3);
        assert_ne!(s2, s4);
        assert_ne!(s3, s4);
    }

    #[test]
    fn block_hash_matters() {
        let s1 = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, &anchor1());
        let s2 = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, &anchor2());
        assert_ne!(s1, s2, "different block_hash must yield different seed");
    }

    #[test]
    fn block_height_matters() {
        let mut a = anchor1();
        let s1 = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, &a);
        a.block_height += 1;
        let s2 = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, &a);
        assert_ne!(s1, s2, "different block_height must yield different seed");
    }

    #[test]
    fn snapshot_vs_delta_separated() {
        let a = anchor1();
        // A degenerate delta with from == to has the same hashes and heights
        // as the snapshot anchor, but the per-context tag (`snapshot/` vs
        // `delta/`) must still produce different seeds.
        let delta = DeltaAnchor { from: a, to: a };
        let s_snap = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, &a);
        let s_delta = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, &delta);
        assert_ne!(s_snap, s_delta);
    }

    #[test]
    fn delta_endpoints_matter() {
        let a = anchor1();
        let b = anchor2();
        let d_ab = DeltaAnchor { from: a, to: b };
        let d_ba = DeltaAnchor { from: b, to: a };
        let s_ab = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, &d_ab);
        let s_ba = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, &d_ba);
        assert_ne!(s_ab, s_ba, "delta endpoint order is part of the binding");
    }

    #[test]
    fn chain_anchor_bytes_roundtrip() {
        let a = anchor1();
        let b = ChainAnchor::from_bytes(&a.to_bytes()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_bytes().len(), CHAIN_ANCHOR_BYTES);
    }

    #[test]
    fn chain_anchor_from_bytes_rejects_wrong_length() {
        assert!(ChainAnchor::from_bytes(&[0u8; 35]).is_err());
        assert!(ChainAnchor::from_bytes(&[0u8; 37]).is_err());
        assert!(ChainAnchor::from_bytes(&[0u8; 0]).is_err());
    }

    #[test]
    fn delta_anchor_bytes_roundtrip() {
        let d = DeltaAnchor { from: anchor1(), to: anchor2() };
        let d2 = DeltaAnchor::from_bytes(&d.to_bytes()).unwrap();
        assert_eq!(d, d2);
        assert_eq!(d.to_bytes().len(), DELTA_ANCHOR_BYTES);
    }

    #[test]
    fn chain_anchor_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("pir-core-seeds-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = anchor1();
        a.save(&dir.join(CHAIN_ANCHOR_FILENAME)).unwrap();
        let b = ChainAnchor::load_from_data_dir(&dir).unwrap();
        assert_eq!(a, b);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn snapshot_seeds_fields_distinct() {
        // Tabular sanity: SnapshotSeeds returns four distinct values for
        // a generic anchor. (A SHA-256 collision across 4 outputs at the
        // u64 prefix is negligible — if this trips, something is wrong
        // with the domain wiring.)
        let s = SnapshotSeeds::derive(&anchor1());
        let xs = [s.index_master, s.chunk_master, s.index_tag, s.merkle_data_master];
        for i in 0..xs.len() {
            for j in (i + 1)..xs.len() {
                assert_ne!(xs[i], xs[j], "SnapshotSeeds fields {} and {} collided", i, j);
            }
        }
    }
}
