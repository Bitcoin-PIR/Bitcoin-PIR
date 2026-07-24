//! Canonical signed root bundle.
//!
//! The bundle is the single client-facing trust artifact of the attested
//! builder design (see ../PLAN.md): it binds the PIR database Merkle
//! roots to a chain anchor (block hash + height), the Bitcoin Core
//! `muhash` of the UTXO set the database was built from, and every
//! build parameter that affects the output bytes. Builders (plain
//! hosts, Nitro enclaves, SEV guests) each sign the identical canonical
//! payload; clients accept a database root iff at least `threshold`
//! signatures from distinct pinned builder keys verify.
//!
//! Encoding follows the same hand-rolled, length-prefixed, canonical
//! style as `pir-identity` (no serde): one and only one byte string per
//! payload, strict decoding (no trailing bytes), so a signature commits
//! to exactly one interpretation.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;

/// Domain-separation prefix for bundle signatures. Versioned: any change
/// to the payload layout must bump both this tag and `PAYLOAD_VERSION`.
pub const SIGNING_DOMAIN: &[u8] = b"BitcoinPIR/attested-builder/root-bundle/v1\0";
pub const PARAMS_HASH_DOMAIN: &[u8] = b"BitcoinPIR/attested-builder/build-params/v1\0";
pub const PARAMS_HASH_V2_DOMAIN: &[u8] = b"BPIR_BUILD_PARAMS_V2\0";
pub const SEED_TAG_PREFIX_V1: &[u8] = b"BitcoinPIR/seed/v1/";

/// Payload layout version (field of the payload itself).
pub const PAYLOAD_VERSION: u16 = 1;

/// Hard caps keeping decode allocation-bounded.
pub const MAX_ROOTS: usize = 1024;
pub const MAX_LABEL_LEN: usize = 64;
pub const CHAIN_ANCHOR_BYTES: usize = 36;
pub const DELTA_ANCHOR_BYTES: usize = CHAIN_ANCHOR_BYTES * 2;

/// What was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildKind {
    /// Full snapshot at `anchor`.
    Snapshot,
    /// Delta from `from_anchor` (exclusive) to `anchor` (inclusive).
    Delta,
}

impl BuildKind {
    fn to_byte(self) -> u8 {
        match self {
            BuildKind::Snapshot => 0,
            BuildKind::Delta => 1,
        }
    }

    fn from_byte(b: u8) -> Result<Self, BundleError> {
        match b {
            0 => Ok(BuildKind::Snapshot),
            1 => Ok(BuildKind::Delta),
            _ => Err(BundleError::Malformed("unknown build kind")),
        }
    }
}

/// A Bitcoin chain anchor: block hash (internal byte order, as in
/// `chain_anchor.bin`) plus height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAnchor {
    pub block_hash: [u8; 32],
    pub height: u32,
}

impl ChainAnchor {
    /// Serialize as `block_hash[32] || height_le[4]`, matching
    /// `chain_anchor.bin` from the build pipeline.
    pub fn to_bytes(&self) -> [u8; CHAIN_ANCHOR_BYTES] {
        let mut out = [0u8; CHAIN_ANCHOR_BYTES];
        out[..32].copy_from_slice(&self.block_hash);
        out[32..].copy_from_slice(&self.height.to_le_bytes());
        out
    }

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
        Ok(Self {
            block_hash,
            height: u32::from_le_bytes(bytes[32..].try_into().unwrap()),
        })
    }

    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::from_bytes(&fs::read(path)?)
    }
}

/// A delta's chain anchor: the snapshot it applies to plus the resulting
/// chain state. This is the seed context for delta DB cuckoo layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaAnchor {
    pub from: ChainAnchor,
    pub to: ChainAnchor,
}

impl DeltaAnchor {
    pub fn to_bytes(&self) -> [u8; DELTA_ANCHOR_BYTES] {
        let mut out = [0u8; DELTA_ANCHOR_BYTES];
        out[..CHAIN_ANCHOR_BYTES].copy_from_slice(&self.from.to_bytes());
        out[CHAIN_ANCHOR_BYTES..].copy_from_slice(&self.to.to_bytes());
        out
    }

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
        Ok(Self {
            from: ChainAnchor::from_bytes(&bytes[..CHAIN_ANCHOR_BYTES])?,
            to: ChainAnchor::from_bytes(&bytes[CHAIN_ANCHOR_BYTES..])?,
        })
    }

    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::from_bytes(&fs::read(path)?)
    }
}

pub mod seed_domain {
    pub const INDEX_CUCKOO_MASTER: &str = "index/cuckoo/master";
    pub const CHUNK_CUCKOO_MASTER: &str = "chunk/cuckoo/master";
    pub const INDEX_TAG_FINGERPRINT: &str = "index/tag/fingerprint";
    pub const MERKLE_DATA_CUCKOO_MASTER: &str = "merkle/data/cuckoo/master";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotSeeds {
    pub index_master: u64,
    pub chunk_master: u64,
    pub index_tag: u64,
    pub merkle_data_master: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaSeeds {
    pub index_master: u64,
    pub chunk_master: u64,
    pub index_tag: u64,
}

impl SnapshotSeeds {
    pub fn derive(anchor: &ChainAnchor) -> Self {
        Self {
            index_master: derive_snapshot_seed_u64(seed_domain::INDEX_CUCKOO_MASTER, anchor),
            chunk_master: derive_snapshot_seed_u64(seed_domain::CHUNK_CUCKOO_MASTER, anchor),
            index_tag: derive_snapshot_seed_u64(seed_domain::INDEX_TAG_FINGERPRINT, anchor),
            merkle_data_master: derive_snapshot_seed_u64(
                seed_domain::MERKLE_DATA_CUCKOO_MASTER,
                anchor,
            ),
        }
    }
}

impl DeltaSeeds {
    pub fn derive(anchor: &DeltaAnchor) -> Self {
        Self {
            index_master: derive_delta_seed_u64(seed_domain::INDEX_CUCKOO_MASTER, anchor),
            chunk_master: derive_delta_seed_u64(seed_domain::CHUNK_CUCKOO_MASTER, anchor),
            index_tag: derive_delta_seed_u64(seed_domain::INDEX_TAG_FINGERPRINT, anchor),
        }
    }
}

pub fn derive_snapshot_seed_u64(domain: &str, anchor: &ChainAnchor) -> u64 {
    let bytes = tagged_snapshot_seed_hash(domain, anchor);
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

pub fn derive_delta_seed_u64(domain: &str, anchor: &DeltaAnchor) -> u64 {
    let bytes = tagged_delta_seed_hash(domain, anchor);
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

fn tagged_snapshot_seed_hash(domain: &str, anchor: &ChainAnchor) -> [u8; 32] {
    tagged_seed_hash(domain, |h| {
        h.update(b"snapshot/");
        h.update(anchor.height.to_le_bytes());
        h.update(anchor.block_hash);
    })
}

fn tagged_delta_seed_hash(domain: &str, anchor: &DeltaAnchor) -> [u8; 32] {
    tagged_seed_hash(domain, |h| {
        h.update(b"delta/");
        h.update(anchor.from.height.to_le_bytes());
        h.update(anchor.from.block_hash);
        h.update(anchor.to.height.to_le_bytes());
        h.update(anchor.to.block_hash);
    })
}

fn tagged_seed_hash(domain: &str, absorb: impl FnOnce(&mut Sha256)) -> [u8; 32] {
    let mut tag_hasher = Sha256::new();
    tag_hasher.update(SEED_TAG_PREFIX_V1);
    tag_hasher.update(domain.as_bytes());
    let tag_hash = tag_hasher.finalize();

    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    absorb(&mut h);
    h.finalize().into()
}

/// One named Merkle root, e.g. `("dpf/index/super_root", …)`. Labels are
/// printable ASCII, unique, and sorted, so the payload bytes are
/// canonical for a given root set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedRoot {
    pub label: String,
    pub root: [u8; 32],
}

/// Canonical layout parameters for one cuckoo/PBC table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableParamsV1 {
    pub k: u16,
    pub pbc_num_hashes: u16,
    pub bins_per_table: u32,
    pub slots_per_bin: u16,
    pub cuckoo_num_hashes: u16,
    pub slot_size: u16,
    pub dpf_n: u8,
    pub magic: u64,
    pub header_size: u16,
    pub has_tag_seed: bool,
}

/// Versioned build/layout parameters committed by `params_hash`.
///
/// These are the knobs that change the interpretation of Merkle roots and
/// query/proof bytes. Filter knobs (`dust_threshold_sats`,
/// `max_utxos_per_spk`) are separate first-class bundle fields, not hidden
/// inside this hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildParamsV1 {
    pub flat_utxo_entry_size: u16,
    pub script_hash_size: u16,
    pub txid_size: u16,
    pub index_record_size: u16,
    pub chunk_size: u16,
    pub chunks_per_unit: u16,
    pub index: TableParamsV1,
    pub chunk: TableParamsV1,
    pub onion_entry_size: u32,
    pub onion_index_record_size: u16,
    pub onion_index_slot_size: u16,
    pub onion_index_slots_per_bin: u16,
    pub onion_chunk_k: u16,
    pub merkle_arity: u16,
    pub merkle_hash_bytes: u16,
    /// Zero documents the Phase-4 decision to remove M=16 chunk-Merkle
    /// item-count padding.
    pub chunk_merkle_item_pad: u16,
}

impl BuildParamsV1 {
    /// Current production-ish defaults, with the sizing values that vary by
    /// database instance passed explicitly.
    pub fn current_snapshot(
        index_bins_per_table: u32,
        chunk_bins_per_table: u32,
        onion_entry_size: u32,
    ) -> Self {
        let onion_index_slot_size = 15;
        Self {
            flat_utxo_entry_size: 68,
            script_hash_size: 20,
            txid_size: 32,
            index_record_size: 25,
            chunk_size: 40,
            chunks_per_unit: 1,
            index: TableParamsV1 {
                k: 75,
                pbc_num_hashes: 3,
                bins_per_table: index_bins_per_table,
                slots_per_bin: 4,
                cuckoo_num_hashes: 2,
                slot_size: 13,
                dpf_n: compute_dpf_n(index_bins_per_table),
                magic: 0xBA7C_C000_C000_0004,
                header_size: 40,
                has_tag_seed: true,
            },
            chunk: TableParamsV1 {
                k: 80,
                pbc_num_hashes: 3,
                bins_per_table: chunk_bins_per_table,
                slots_per_bin: 3,
                cuckoo_num_hashes: 2,
                slot_size: 44,
                dpf_n: compute_dpf_n(chunk_bins_per_table),
                magic: 0xBA7C_C000_C000_0002,
                header_size: 32,
                has_tag_seed: false,
            },
            onion_entry_size,
            onion_index_record_size: 27,
            onion_index_slot_size,
            onion_index_slots_per_bin: (onion_entry_size / onion_index_slot_size as u32) as u16,
            onion_chunk_k: 80,
            merkle_arity: 8,
            merkle_hash_bytes: 32,
            chunk_merkle_item_pad: 0,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        put_bytes(&mut out, &1u16.to_le_bytes());
        put_bytes(&mut out, &self.flat_utxo_entry_size.to_le_bytes());
        put_bytes(&mut out, &self.script_hash_size.to_le_bytes());
        put_bytes(&mut out, &self.txid_size.to_le_bytes());
        put_bytes(&mut out, &self.index_record_size.to_le_bytes());
        put_bytes(&mut out, &self.chunk_size.to_le_bytes());
        put_bytes(&mut out, &self.chunks_per_unit.to_le_bytes());
        self.index.encode_into(&mut out);
        self.chunk.encode_into(&mut out);
        put_bytes(&mut out, &self.onion_entry_size.to_le_bytes());
        put_bytes(&mut out, &self.onion_index_record_size.to_le_bytes());
        put_bytes(&mut out, &self.onion_index_slot_size.to_le_bytes());
        put_bytes(&mut out, &self.onion_index_slots_per_bin.to_le_bytes());
        put_bytes(&mut out, &self.onion_chunk_k.to_le_bytes());
        put_bytes(&mut out, &self.merkle_arity.to_le_bytes());
        put_bytes(&mut out, &self.merkle_hash_bytes.to_le_bytes());
        put_bytes(&mut out, &self.chunk_merkle_item_pad.to_le_bytes());
        out
    }

    pub fn params_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(PARAMS_HASH_DOMAIN);
        h.update(self.encode());
        h.finalize().into()
    }
}

/// Complete, typed OnionPIR query layout committed by database proof v2.
///
/// V2 deliberately embeds every V1 field rather than hashing an unsigned
/// extension.  The final three values are the production query dimensions
/// that could previously only be learned from an untrusted server-info
/// response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildParamsV2 {
    pub base: BuildParamsV1,
    pub onion_total_packed_entries: u32,
    pub onion_index_bins_per_table: u32,
    pub onion_chunk_bins_per_table: u32,
}

impl BuildParamsV2 {
    pub fn current_snapshot(
        index_bins_per_table: u32,
        chunk_bins_per_table: u32,
        onion_entry_size: u32,
        onion_total_packed_entries: u32,
        onion_index_bins_per_table: u32,
        onion_chunk_bins_per_table: u32,
    ) -> Self {
        Self {
            base: BuildParamsV1::current_snapshot(
                index_bins_per_table,
                chunk_bins_per_table,
                onion_entry_size,
            ),
            onion_total_packed_entries,
            onion_index_bins_per_table,
            onion_chunk_bins_per_table,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.base.encode();
        out[0..2].copy_from_slice(&2u16.to_le_bytes());
        put_bytes(&mut out, &self.onion_total_packed_entries.to_le_bytes());
        put_bytes(&mut out, &self.onion_index_bins_per_table.to_le_bytes());
        put_bytes(&mut out, &self.onion_chunk_bins_per_table.to_le_bytes());
        out
    }

    /// Decode the fixed-width canonical representation. Unknown versions,
    /// invalid booleans, truncation, and trailing bytes are all rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        struct Reader<'a> {
            bytes: &'a [u8],
            pos: usize,
        }
        impl Reader<'_> {
            fn take<const N: usize>(&mut self) -> Result<[u8; N], &'static str> {
                let end = self.pos.checked_add(N).ok_or("parameter length overflow")?;
                let value = self
                    .bytes
                    .get(self.pos..end)
                    .ok_or("truncated build parameters")?;
                self.pos = end;
                Ok(value.try_into().unwrap())
            }
            fn u8(&mut self) -> Result<u8, &'static str> {
                Ok(self.take::<1>()?[0])
            }
            fn u16(&mut self) -> Result<u16, &'static str> {
                Ok(u16::from_le_bytes(self.take()?))
            }
            fn u32(&mut self) -> Result<u32, &'static str> {
                Ok(u32::from_le_bytes(self.take()?))
            }
            fn u64(&mut self) -> Result<u64, &'static str> {
                Ok(u64::from_le_bytes(self.take()?))
            }
            fn table(&mut self) -> Result<TableParamsV1, &'static str> {
                let value = TableParamsV1 {
                    k: self.u16()?,
                    pbc_num_hashes: self.u16()?,
                    bins_per_table: self.u32()?,
                    slots_per_bin: self.u16()?,
                    cuckoo_num_hashes: self.u16()?,
                    slot_size: self.u16()?,
                    dpf_n: self.u8()?,
                    magic: self.u64()?,
                    header_size: self.u16()?,
                    has_tag_seed: match self.u8()? {
                        0 => false,
                        1 => true,
                        _ => return Err("invalid has_tag_seed boolean"),
                    },
                };
                Ok(value)
            }
        }

        let mut r = Reader { bytes, pos: 0 };
        if r.u16()? != 2 {
            return Err("unsupported build parameters version");
        }
        let base = BuildParamsV1 {
            flat_utxo_entry_size: r.u16()?,
            script_hash_size: r.u16()?,
            txid_size: r.u16()?,
            index_record_size: r.u16()?,
            chunk_size: r.u16()?,
            chunks_per_unit: r.u16()?,
            index: r.table()?,
            chunk: r.table()?,
            onion_entry_size: r.u32()?,
            onion_index_record_size: r.u16()?,
            onion_index_slot_size: r.u16()?,
            onion_index_slots_per_bin: r.u16()?,
            onion_chunk_k: r.u16()?,
            merkle_arity: r.u16()?,
            merkle_hash_bytes: r.u16()?,
            chunk_merkle_item_pad: r.u16()?,
        };
        let decoded = Self {
            base,
            onion_total_packed_entries: r.u32()?,
            onion_index_bins_per_table: r.u32()?,
            onion_chunk_bins_per_table: r.u32()?,
        };
        if r.pos != bytes.len() {
            return Err("trailing build parameter bytes");
        }
        Ok(decoded)
    }

    pub fn params_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(PARAMS_HASH_V2_DOMAIN);
        h.update(self.encode());
        h.finalize().into()
    }
}

impl TableParamsV1 {
    fn encode_into(&self, out: &mut Vec<u8>) {
        put_bytes(out, &self.k.to_le_bytes());
        put_bytes(out, &self.pbc_num_hashes.to_le_bytes());
        put_bytes(out, &self.bins_per_table.to_le_bytes());
        put_bytes(out, &self.slots_per_bin.to_le_bytes());
        put_bytes(out, &self.cuckoo_num_hashes.to_le_bytes());
        put_bytes(out, &self.slot_size.to_le_bytes());
        out.push(self.dpf_n);
        put_bytes(out, &self.magic.to_le_bytes());
        put_bytes(out, &self.header_size.to_le_bytes());
        out.push(u8::from(self.has_tag_seed));
    }
}

pub fn compute_dpf_n(bins_per_table: u32) -> u8 {
    if bins_per_table <= 1 {
        return 1;
    }
    let mut n = 0u8;
    let mut v = 1u32;
    while v < bins_per_table {
        v <<= 1;
        n += 1;
    }
    n
}

/// The unsigned, canonical bundle payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootBundlePayload {
    /// Network magic (mainnet `f9beb4d9`), so a testnet bundle can never
    /// satisfy a mainnet client.
    pub network_magic: [u8; 4],
    pub build_kind: BuildKind,
    /// Start anchor for deltas; all-zero hash + height 0 for snapshots.
    pub from_anchor: ChainAnchor,
    /// The chain state this database serves (end anchor for deltas).
    pub anchor: ChainAnchor,
    /// Bitcoin Core `gettxoutsetinfo muhash` of the FULL UTXO set at
    /// `anchor`, in Core's display byte order reversed back to raw
    /// digest bytes (i.e. `SHA256(residue)` output order).
    pub utxo_muhash: [u8; 32],
    /// Filter parameters — bound so "correct roots for different
    /// filtering" can't be substituted.
    pub dust_threshold_sats: u64,
    pub max_utxos_per_spk: u32,
    /// SHA256 of the canonical build-parameter blob (K, K_CHUNK, bin
    /// counts, slot sizes, format versions…). Clients pin the expected
    /// value for the format they speak.
    pub params_hash: [u8; 32],
    /// Unix seconds at signing time (advisory; freshness policy is the
    /// client's).
    pub issued_at: i64,
    /// Sorted-by-label, unique. See [`NamedRoot`].
    pub roots: Vec<NamedRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    Malformed(&'static str),
    /// Roots not strictly sorted by label, label invalid, or too many.
    InvalidRoots(&'static str),
    /// A signature from a pinned (trusted) key failed verification.
    BadSignature,
    /// The same builder key appears twice in the signature list.
    DuplicateSigner,
    /// Fewer than `threshold` valid signatures from distinct trusted keys.
    QuorumNotMet {
        valid: usize,
        threshold: usize,
    },
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::Malformed(m) => write!(f, "malformed bundle: {m}"),
            BundleError::InvalidRoots(m) => write!(f, "invalid roots: {m}"),
            BundleError::BadSignature => write!(f, "bad signature from trusted key"),
            BundleError::DuplicateSigner => write!(f, "duplicate signer pubkey"),
            BundleError::QuorumNotMet { valid, threshold } => {
                write!(f, "quorum not met: {valid} valid of {threshold} required")
            }
        }
    }
}

impl std::error::Error for BundleError {}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(b);
}

fn take<'a>(cur: &mut &'a [u8], n: usize, what: &'static str) -> Result<&'a [u8], BundleError> {
    if cur.len() < n {
        return Err(BundleError::Malformed(what));
    }
    let (head, rest) = cur.split_at(n);
    *cur = rest;
    Ok(head)
}

fn take_arr<const N: usize>(cur: &mut &[u8], what: &'static str) -> Result<[u8; N], BundleError> {
    Ok(take(cur, N, what)?.try_into().unwrap())
}

fn validate_roots(roots: &[NamedRoot]) -> Result<(), BundleError> {
    if roots.is_empty() {
        return Err(BundleError::InvalidRoots("empty root list"));
    }
    if roots.len() > MAX_ROOTS {
        return Err(BundleError::InvalidRoots("too many roots"));
    }
    for r in roots {
        if r.label.is_empty() || r.label.len() > MAX_LABEL_LEN {
            return Err(BundleError::InvalidRoots("label length"));
        }
        if !r.label.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(BundleError::InvalidRoots(
                "label must be printable ASCII, no spaces",
            ));
        }
    }
    for w in roots.windows(2) {
        if w[0].label >= w[1].label {
            return Err(BundleError::InvalidRoots("labels must be strictly sorted"));
        }
    }
    Ok(())
}

impl RootBundlePayload {
    /// Canonical byte encoding. Fails if the root list is not canonical
    /// (so a non-canonical payload can never be signed).
    pub fn encode(&self) -> Result<Vec<u8>, BundleError> {
        validate_roots(&self.roots)?;
        let mut out = Vec::with_capacity(192 + self.roots.len() * 100);
        put_bytes(&mut out, &PAYLOAD_VERSION.to_le_bytes());
        put_bytes(&mut out, &self.network_magic);
        out.push(self.build_kind.to_byte());
        put_bytes(&mut out, &self.from_anchor.block_hash);
        put_bytes(&mut out, &self.from_anchor.height.to_le_bytes());
        put_bytes(&mut out, &self.anchor.block_hash);
        put_bytes(&mut out, &self.anchor.height.to_le_bytes());
        put_bytes(&mut out, &self.utxo_muhash);
        put_bytes(&mut out, &self.dust_threshold_sats.to_le_bytes());
        put_bytes(&mut out, &self.max_utxos_per_spk.to_le_bytes());
        put_bytes(&mut out, &self.params_hash);
        put_bytes(&mut out, &self.issued_at.to_le_bytes());
        put_bytes(&mut out, &(self.roots.len() as u16).to_le_bytes());
        for r in &self.roots {
            out.push(r.label.len() as u8);
            put_bytes(&mut out, r.label.as_bytes());
            put_bytes(&mut out, &r.root);
        }
        Ok(out)
    }

    /// Strict decode of [`encode`] output: rejects unknown versions,
    /// non-canonical root lists, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleError> {
        let cur = &mut &bytes[..];
        let version = u16::from_le_bytes(take_arr::<2>(cur, "version")?);
        if version != PAYLOAD_VERSION {
            return Err(BundleError::Malformed("unsupported payload version"));
        }
        let network_magic = take_arr::<4>(cur, "network magic")?;
        let build_kind = BuildKind::from_byte(take_arr::<1>(cur, "build kind")?[0])?;
        let from_anchor = ChainAnchor {
            block_hash: take_arr::<32>(cur, "from block hash")?,
            height: u32::from_le_bytes(take_arr::<4>(cur, "from height")?),
        };
        let anchor = ChainAnchor {
            block_hash: take_arr::<32>(cur, "block hash")?,
            height: u32::from_le_bytes(take_arr::<4>(cur, "height")?),
        };
        let utxo_muhash = take_arr::<32>(cur, "muhash")?;
        let dust_threshold_sats = u64::from_le_bytes(take_arr::<8>(cur, "dust threshold")?);
        let max_utxos_per_spk = u32::from_le_bytes(take_arr::<4>(cur, "max utxos")?);
        let params_hash = take_arr::<32>(cur, "params hash")?;
        let issued_at = i64::from_le_bytes(take_arr::<8>(cur, "issued at")?);
        let n_roots = u16::from_le_bytes(take_arr::<2>(cur, "root count")?) as usize;
        if n_roots > MAX_ROOTS {
            return Err(BundleError::InvalidRoots("too many roots"));
        }
        let mut roots = Vec::with_capacity(n_roots);
        for _ in 0..n_roots {
            let label_len = take_arr::<1>(cur, "label len")?[0] as usize;
            let label_bytes = take(cur, label_len, "label")?;
            let label = String::from_utf8(label_bytes.to_vec())
                .map_err(|_| BundleError::InvalidRoots("label not UTF-8"))?;
            let root = take_arr::<32>(cur, "root")?;
            roots.push(NamedRoot { label, root });
        }
        if !cur.is_empty() {
            return Err(BundleError::Malformed("trailing bytes"));
        }
        let payload = Self {
            network_magic,
            build_kind,
            from_anchor,
            anchor,
            utxo_muhash,
            dust_threshold_sats,
            max_utxos_per_spk,
            params_hash,
            issued_at,
            roots,
        };
        validate_roots(&payload.roots)?;
        Ok(payload)
    }

    /// The exact bytes a builder signs: domain tag ‖ canonical payload.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, BundleError> {
        let mut out = SIGNING_DOMAIN.to_vec();
        out.extend_from_slice(&self.encode()?);
        Ok(out)
    }

    /// Look up a root by label.
    pub fn root(&self, label: &str) -> Option<&[u8; 32]> {
        self.roots
            .binary_search_by(|r| r.label.as_str().cmp(label))
            .ok()
            .map(|i| &self.roots[i].root)
    }
}

/// One builder's detached signature over a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSignature {
    pub signer_pubkey: [u8; 32],
    pub signature: [u8; 64],
}

/// Payload + any number of builder signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRootBundle {
    pub payload: RootBundlePayload,
    pub signatures: Vec<BundleSignature>,
}

/// Sign `payload` with a builder key, returning the detached signature.
pub fn sign_root_bundle(
    payload: &RootBundlePayload,
    key: &SigningKey,
) -> Result<BundleSignature, BundleError> {
    let preimage = payload.signing_preimage()?;
    Ok(BundleSignature {
        signer_pubkey: key.verifying_key().to_bytes(),
        signature: key.sign(&preimage).to_bytes(),
    })
}

impl SignedRootBundle {
    /// Verify a k-of-n quorum: at least `threshold` cryptographically
    /// valid signatures from **distinct** keys in `trusted`.
    ///
    /// Policy:
    /// - Signatures from unknown (non-pinned) keys are ignored — forward
    ///   compatible with builder-set growth.
    /// - An *invalid* signature from a pinned key is a hard error, not a
    ///   skip: it is evidence of tampering, never of an honest builder.
    /// - Duplicate signer pubkeys are a hard error.
    ///
    /// Returns the number of valid trusted signatures on success.
    pub fn verify_quorum(
        &self,
        trusted: &[[u8; 32]],
        threshold: usize,
    ) -> Result<usize, BundleError> {
        if threshold == 0 {
            return Err(BundleError::Malformed("threshold must be >= 1"));
        }
        let preimage = self.payload.signing_preimage()?;
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(self.signatures.len());
        let mut valid = 0usize;
        for sig in &self.signatures {
            if seen.contains(&sig.signer_pubkey) {
                return Err(BundleError::DuplicateSigner);
            }
            seen.push(sig.signer_pubkey);
            if !trusted.contains(&sig.signer_pubkey) {
                continue;
            }
            let vk = VerifyingKey::from_bytes(&sig.signer_pubkey)
                .map_err(|_| BundleError::BadSignature)?;
            let signature = Signature::from_bytes(&sig.signature);
            vk.verify_strict(&preimage, &signature)
                .map_err(|_| BundleError::BadSignature)?;
            valid += 1;
        }
        if valid < threshold {
            return Err(BundleError::QuorumNotMet { valid, threshold });
        }
        Ok(valid)
    }

    /// Wire encoding: payload ‖ u16 sig count ‖ (pubkey ‖ sig)*.
    pub fn encode(&self) -> Result<Vec<u8>, BundleError> {
        let mut out = self.payload.encode()?;
        if self.signatures.len() > u16::MAX as usize {
            return Err(BundleError::Malformed("too many signatures"));
        }
        out.extend_from_slice(&(self.signatures.len() as u16).to_le_bytes());
        for s in &self.signatures {
            out.extend_from_slice(&s.signer_pubkey);
            out.extend_from_slice(&s.signature);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BundleError> {
        // Payload length is self-describing only via full parse; decode
        // payload greedily by re-using its strict parser on a prefix is
        // not possible, so parse inline: payload fields are fixed-size
        // except roots, which are length-prefixed — reparse via
        // RootBundlePayload::decode on the payload slice we can compute.
        //
        // Simpler: parse payload fields with the same cursor.
        let cur = &mut &bytes[..];
        let payload_start = *cur;
        // Skip through the payload using the same field sizes.
        let _version = take(cur, 2, "version")?;
        let _ = take(cur, 4 + 1 + 36 + 36 + 32 + 8 + 4 + 32 + 8, "fixed fields")?;
        let n_roots = u16::from_le_bytes(take_arr::<2>(cur, "root count")?) as usize;
        if n_roots > MAX_ROOTS {
            return Err(BundleError::InvalidRoots("too many roots"));
        }
        for _ in 0..n_roots {
            let label_len = take_arr::<1>(cur, "label len")?[0] as usize;
            let _ = take(cur, label_len + 32, "root entry")?;
        }
        let payload_len = payload_start.len() - cur.len();
        let payload = RootBundlePayload::decode(&payload_start[..payload_len])?;

        let n_sigs = u16::from_le_bytes(take_arr::<2>(cur, "sig count")?) as usize;
        let mut signatures = Vec::with_capacity(n_sigs.min(64));
        for _ in 0..n_sigs {
            signatures.push(BundleSignature {
                signer_pubkey: take_arr::<32>(cur, "signer pubkey")?,
                signature: take_arr::<64>(cur, "signature")?,
            });
        }
        if !cur.is_empty() {
            return Err(BundleError::Malformed("trailing bytes"));
        }
        Ok(Self {
            payload,
            signatures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn payload() -> RootBundlePayload {
        let params_hash = BuildParamsV1::current_snapshot(565_684, 1_064_454, 3_328).params_hash();
        RootBundlePayload {
            network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
            build_kind: BuildKind::Snapshot,
            from_anchor: ChainAnchor {
                block_hash: [0; 32],
                height: 0,
            },
            anchor: ChainAnchor {
                block_hash: [0xab; 32],
                height: 950_000,
            },
            utxo_muhash: [0xcd; 32],
            dust_threshold_sats: 576,
            max_utxos_per_spk: 100,
            params_hash,
            issued_at: 1_780_000_000,
            roots: vec![
                NamedRoot {
                    label: "dpf/chunk/super_root".into(),
                    root: [2; 32],
                },
                NamedRoot {
                    label: "dpf/index/super_root".into(),
                    root: [1; 32],
                },
                NamedRoot {
                    label: "onion/super_root".into(),
                    root: [3; 32],
                },
            ],
        }
    }

    #[test]
    fn payload_roundtrip() {
        let p = payload();
        let bytes = p.encode().unwrap();
        assert_eq!(RootBundlePayload::decode(&bytes).unwrap(), p);
    }

    #[test]
    fn rejects_unsorted_or_bad_roots() {
        let mut p = payload();
        p.roots.swap(0, 1);
        assert!(matches!(p.encode(), Err(BundleError::InvalidRoots(_))));

        let mut p = payload();
        p.roots[0].label = "has space".into();
        assert!(matches!(p.encode(), Err(BundleError::InvalidRoots(_))));

        let mut p = payload();
        p.roots.clear();
        assert!(matches!(p.encode(), Err(BundleError::InvalidRoots(_))));
    }

    #[test]
    fn root_lookup() {
        let p = payload();
        assert_eq!(p.root("dpf/index/super_root"), Some(&[1u8; 32]));
        assert_eq!(p.root("nope"), None);
    }

    #[test]
    fn quorum_2_of_3() {
        let p = payload();
        let (k1, k2, k3) = (key(1), key(2), key(3));
        let trusted = [
            k1.verifying_key().to_bytes(),
            k2.verifying_key().to_bytes(),
            k3.verifying_key().to_bytes(),
        ];
        let bundle = SignedRootBundle {
            payload: p.clone(),
            signatures: vec![
                sign_root_bundle(&p, &k1).unwrap(),
                sign_root_bundle(&p, &k3).unwrap(),
            ],
        };
        assert_eq!(bundle.verify_quorum(&trusted, 2), Ok(2));
        assert!(matches!(
            bundle.verify_quorum(&trusted, 3),
            Err(BundleError::QuorumNotMet {
                valid: 2,
                threshold: 3
            })
        ));
    }

    #[test]
    fn unknown_signer_ignored_but_not_counted() {
        let p = payload();
        let (k1, stranger) = (key(1), key(9));
        let trusted = [
            key(1).verifying_key().to_bytes(),
            key(2).verifying_key().to_bytes(),
        ];
        let bundle = SignedRootBundle {
            payload: p.clone(),
            signatures: vec![
                sign_root_bundle(&p, &k1).unwrap(),
                sign_root_bundle(&p, &stranger).unwrap(),
            ],
        };
        assert_eq!(bundle.verify_quorum(&trusted, 1), Ok(1));
        assert!(bundle.verify_quorum(&trusted, 2).is_err());
    }

    #[test]
    fn tampered_payload_fails() {
        let p = payload();
        let k1 = key(1);
        let trusted = [k1.verifying_key().to_bytes()];
        let mut bundle = SignedRootBundle {
            payload: p.clone(),
            signatures: vec![sign_root_bundle(&p, &k1).unwrap()],
        };
        bundle.payload.roots[0].root = [0xff; 32];
        assert_eq!(
            bundle.verify_quorum(&trusted, 1),
            Err(BundleError::BadSignature)
        );
    }

    #[test]
    fn duplicate_signer_rejected() {
        let p = payload();
        let k1 = key(1);
        let trusted = [k1.verifying_key().to_bytes()];
        let sig = sign_root_bundle(&p, &k1).unwrap();
        let bundle = SignedRootBundle {
            payload: p,
            signatures: vec![sig.clone(), sig],
        };
        assert_eq!(
            bundle.verify_quorum(&trusted, 1),
            Err(BundleError::DuplicateSigner)
        );
    }

    #[test]
    fn signed_bundle_roundtrip() {
        let p = payload();
        let bundle = SignedRootBundle {
            payload: p.clone(),
            signatures: vec![
                sign_root_bundle(&p, &key(1)).unwrap(),
                sign_root_bundle(&p, &key(2)).unwrap(),
            ],
        };
        let bytes = bundle.encode().unwrap();
        assert_eq!(SignedRootBundle::decode(&bytes).unwrap(), bundle);
    }

    #[test]
    fn domain_separation() {
        // A signature over the raw payload (no domain tag) must not verify.
        let p = payload();
        let k1 = key(1);
        let trusted = [k1.verifying_key().to_bytes()];
        let raw_sig = k1.sign(&p.encode().unwrap());
        let bundle = SignedRootBundle {
            payload: p,
            signatures: vec![BundleSignature {
                signer_pubkey: k1.verifying_key().to_bytes(),
                signature: raw_sig.to_bytes(),
            }],
        };
        assert_eq!(
            bundle.verify_quorum(&trusted, 1),
            Err(BundleError::BadSignature)
        );
    }

    #[test]
    fn build_params_canonical_hash_surface() {
        let p = BuildParamsV1::current_snapshot(565_684, 1_064_454, 3_328);
        assert_eq!(p.index.dpf_n, 20);
        assert_eq!(p.chunk.dpf_n, 21);
        assert_eq!(p.onion_index_slots_per_bin, 221);
        assert_eq!(p.encode().len(), 84);
        assert_eq!(
            hex::encode(p.params_hash()),
            "5138dd0d022c4bbb386860a56fb0fd837e4cd947ed71cbbeab058023b839ec12"
        );

        let same = BuildParamsV1::current_snapshot(565_684, 1_064_454, 3_328);
        let different_bins = BuildParamsV1::current_snapshot(565_685, 1_064_454, 3_328);
        let different_onion = BuildParamsV1::current_snapshot(565_684, 1_064_454, 3_840);
        assert_eq!(p.params_hash(), same.params_hash());
        assert_ne!(p.params_hash(), different_bins.params_hash());
        assert_ne!(p.params_hash(), different_onion.params_hash());
    }

    #[test]
    fn build_params_v2_canonical_hash_and_roundtrip() {
        let p = BuildParamsV2::current_snapshot(
            565_684, 1_064_454, 3_328, 1_234_567, 612_345, 1_345_678,
        );
        assert_eq!(p.encode().len(), 96);
        assert_eq!(BuildParamsV2::decode(&p.encode()).unwrap(), p);
        assert_eq!(
            hex::encode(p.params_hash()),
            "da2d3ad06596a646c8a9c516a904d1d79d8fbb8df0591a8a8f3135283d88592c"
        );

        let mut trailing = p.encode();
        trailing.push(0);
        assert_eq!(
            BuildParamsV2::decode(&trailing),
            Err("trailing build parameter bytes")
        );
        let different_total = BuildParamsV2 {
            onion_total_packed_entries: p.onion_total_packed_entries + 1,
            ..p
        };
        assert_ne!(p.params_hash(), different_total.params_hash());
    }

    #[test]
    fn dpf_n_matches_pir_core_cases() {
        assert_eq!(compute_dpf_n(0), 1);
        assert_eq!(compute_dpf_n(1), 1);
        assert_eq!(compute_dpf_n(2), 1);
        assert_eq!(compute_dpf_n(3), 2);
        assert_eq!(compute_dpf_n(4), 2);
        assert_eq!(compute_dpf_n(5), 3);
        assert_eq!(compute_dpf_n(1024), 10);
        assert_eq!(compute_dpf_n(1025), 11);
        assert_eq!(compute_dpf_n(565_684), 20);
        assert_eq!(compute_dpf_n(1_064_454), 21);
        assert_eq!(compute_dpf_n(10_000), 14);
    }

    #[test]
    fn chain_anchor_bytes_roundtrip() {
        let anchor = ChainAnchor {
            block_hash: [0xab; 32],
            height: 950_000,
        };
        let bytes = anchor.to_bytes();
        assert_eq!(bytes.len(), CHAIN_ANCHOR_BYTES);
        assert_eq!(ChainAnchor::from_bytes(&bytes).unwrap(), anchor);
        assert!(ChainAnchor::from_bytes(&bytes[..35]).is_err());
        assert!(ChainAnchor::from_bytes(&[0u8; 37]).is_err());
    }

    #[test]
    fn snapshot_seed_vectors_match_pir_core_rule() {
        let anchor = ChainAnchor {
            block_hash: [0xab; 32],
            height: 950_000,
        };
        let seeds = SnapshotSeeds::derive(&anchor);
        assert_eq!(seeds.index_master, 0xe919_b727_bd4e_852b);
        assert_eq!(seeds.chunk_master, 0x9ef8_8b24_8bd6_1a6e);
        assert_eq!(seeds.index_tag, 0xb72a_9d06_a468_37d6);
        assert_eq!(seeds.merkle_data_master, 0xbbf0_9e2f_95d1_e02c);

        let mut different_height = anchor;
        different_height.height += 1;
        assert_ne!(
            SnapshotSeeds::derive(&different_height).index_master,
            seeds.index_master
        );
    }
}
