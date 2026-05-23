//! Generic cuckoo table building utilities.
//!
//! Provides the core cuckoo insertion algorithm used by both INDEX and CHUNK
//! level table builders, parameterized by `TableParams`.

use crate::hash;
use crate::params::TableParams;

/// Maximum number of eviction kicks before declaring insertion failure.
pub const CUCKOO_MAX_KICKS: usize = 10000;

/// Default load factor for sizing cuckoo tables.
pub const CUCKOO_LOAD_FACTOR: f64 = 0.95;

/// An empty slot sentinel value.
pub const EMPTY: u32 = u32::MAX;

/// Compute the required number of bins per table given the max load across groups.
pub fn compute_bins_per_table(max_load: usize, slots_per_bin: usize) -> usize {
    let capacity_per_bin = slots_per_bin as f64 * CUCKOO_LOAD_FACTOR;
    (max_load as f64 / capacity_per_bin).ceil() as usize
}

/// Insert an entry into a cuckoo table with eviction.
///
/// `table[bin * slots_per_bin + slot]` holds item indices (u32).
/// Returns true if insertion succeeded.
///
/// # Arguments
/// * `table` - Flat array of slots, length = `num_bins * slots_per_bin`.
/// * `num_bins` - Number of bins in this table.
/// * `slots_per_bin` - Slots per bin.
/// * `entry_idx` - The item index to insert.
/// * `hash_fns` - Closure that maps (entry_idx) → bin index for each hash function.
/// * `num_hash_fns` - Number of cuckoo hash functions (typically 2).
/// * `max_kicks` - Maximum eviction chain length.
pub fn cuckoo_insert<F>(
    table: &mut [u32],
    _num_bins: usize,
    slots_per_bin: usize,
    entry_idx: u32,
    hash_fns: &F,
    num_hash_fns: usize,
    max_kicks: usize,
) -> bool
where
    F: Fn(u32, usize) -> usize,
{
    // Try each hash function for a free slot
    for hf in 0..num_hash_fns {
        let bin = hash_fns(entry_idx, hf);
        let base = bin * slots_per_bin;
        for s in 0..slots_per_bin {
            if table[base + s] == EMPTY {
                table[base + s] = entry_idx;
                return true;
            }
        }
    }

    // Eviction chain — vary eviction slot to avoid 2-cycles
    let mut current = entry_idx;
    let mut current_bin = hash_fns(current, 0);

    for kick in 0..max_kicks {
        let base = current_bin * slots_per_bin;
        let evict_slot = kick % slots_per_bin;
        let evicted = table[base + evict_slot];
        table[base + evict_slot] = current;

        // Find the alternative bin for the evicted entry
        let mut alt_bin = current_bin;
        for hf in 0..num_hash_fns {
            let bin = hash_fns(evicted, hf);
            if bin != current_bin {
                alt_bin = bin;
                break;
            }
        }

        // Try to place evicted entry in its alternative bin
        let alt_base = alt_bin * slots_per_bin;
        let mut placed = false;
        for s in 0..slots_per_bin {
            if table[alt_base + s] == EMPTY {
                table[alt_base + s] = evicted;
                placed = true;
                break;
            }
        }

        if placed {
            return true;
        }

        current = evicted;
        current_bin = alt_bin;
    }

    false
}

/// Build a cuckoo table for byte-keyed items (e.g., script hashes in INDEX level).
///
/// Returns the flat table of entry indices and the number of bins.
///
/// # Arguments
/// * `entries` - Slice of 20-byte script hashes assigned to this group.
/// * `group_id` - Which PBC group this table serves.
/// * `params` - Table parameters.
/// * `num_bins` - Pre-computed number of bins for this table.
pub fn build_byte_keyed_table(
    entries: &[&[u8]],
    group_id: usize,
    params: &TableParams,
    num_bins: usize,
) -> Vec<u32> {
    let table_size = num_bins * params.slots_per_bin;
    let mut table = vec![EMPTY; table_size];

    // Derive cuckoo keys for this group
    let keys: Vec<u64> = (0..params.cuckoo_num_hashes)
        .map(|hf| hash::derive_cuckoo_key(params.master_seed, group_id, hf))
        .collect();

    let hash_fn = |entry_idx: u32, hf: usize| -> usize {
        hash::cuckoo_hash(entries[entry_idx as usize], keys[hf], num_bins)
    };

    for i in 0..entries.len() {
        if !cuckoo_insert(
            &mut table,
            num_bins,
            params.slots_per_bin,
            i as u32,
            &hash_fn,
            params.cuckoo_num_hashes,
            CUCKOO_MAX_KICKS,
        ) {
            panic!(
                "Cuckoo insertion failed for entry {} in group {} after {} kicks",
                i, group_id, CUCKOO_MAX_KICKS
            );
        }
    }

    table
}

/// Build a cuckoo table for integer-keyed items (e.g., chunk IDs in CHUNK level).
///
/// Returns the flat table of entry indices and the number of bins.
pub fn build_int_keyed_table(
    ids: &[u32],
    group_id: usize,
    params: &TableParams,
    num_bins: usize,
) -> Vec<u32> {
    let table_size = num_bins * params.slots_per_bin;
    let mut table = vec![EMPTY; table_size];

    let keys: Vec<u64> = (0..params.cuckoo_num_hashes)
        .map(|hf| hash::derive_cuckoo_key(params.master_seed, group_id, hf))
        .collect();

    let hash_fn = |entry_idx: u32, hf: usize| -> usize {
        hash::cuckoo_hash_int(ids[entry_idx as usize], keys[hf], num_bins)
    };

    // Enumerate to avoid clippy::needless_range_loop — both the
    // `i as u32` cuckoo entry index and the panic's `ids[i]` lookup
    // are satisfied by the (i, id) pair from enumerate.
    for (i, id) in ids.iter().enumerate() {
        if !cuckoo_insert(
            &mut table,
            num_bins,
            params.slots_per_bin,
            i as u32,
            &hash_fn,
            params.cuckoo_num_hashes,
            CUCKOO_MAX_KICKS,
        ) {
            panic!(
                "Cuckoo insertion failed for chunk_id {} in group {} after {} kicks",
                id, group_id, CUCKOO_MAX_KICKS
            );
        }
    }

    table
}

/// Write a cuckoo table file header.
///
/// Layout depends on `params.header_size` and `params.has_tag_seed`:
/// - Bytes 0..8: magic (u64 LE)
/// - Bytes 8..12: k (u32 LE)
/// - Bytes 12..16: slots_per_bin (u32 LE)
/// - Bytes 16..20: bins_per_table (u32 LE)
/// - Bytes 20..24: num_hashes (u32 LE)
/// - Bytes 24..32: master_seed (u64 LE)
/// - Bytes 32..40: tag_seed (u64 LE) — only if has_tag_seed
pub fn write_header(params: &TableParams, bins_per_table: usize, tag_seed: u64) -> Vec<u8> {
    let mut header = vec![0u8; params.header_size];
    header[0..8].copy_from_slice(&params.magic.to_le_bytes());
    header[8..12].copy_from_slice(&(params.k as u32).to_le_bytes());
    header[12..16].copy_from_slice(&(params.slots_per_bin as u32).to_le_bytes());
    header[16..20].copy_from_slice(&(bins_per_table as u32).to_le_bytes());
    header[20..24].copy_from_slice(&(params.num_hashes as u32).to_le_bytes());
    header[24..32].copy_from_slice(&params.master_seed.to_le_bytes());
    if params.has_tag_seed && params.header_size >= 40 {
        header[32..40].copy_from_slice(&tag_seed.to_le_bytes());
    }
    header
}

// ─── v2 chain-anchored header (Phase C) ─────────────────────────────────────

use crate::seeds::{
    derive_seed_u64, ChainAnchor, DeltaAnchor, CHAIN_ANCHOR_BYTES, DELTA_ANCHOR_BYTES,
};

/// XOR'd into the legacy magic to discriminate snapshot-anchored v2 headers.
pub const ANCHOR_MAGIC_SNAPSHOT_XOR: u64 = 0x0000_0001_0000_0000;
/// XOR'd into the legacy magic to discriminate delta-anchored v2 headers.
pub const ANCHOR_MAGIC_DELTA_XOR: u64 = 0x0000_0002_0000_0000;

/// A chain anchor that may be embedded in a cuckoo file header.
///
/// Choice of variant determines which v2 MAGIC the writer emits and how
/// many trailing bytes are appended:
/// - `Snapshot` → MAGIC ^ ANCHOR_MAGIC_SNAPSHOT_XOR, +36 bytes
/// - `Delta`    → MAGIC ^ ANCHOR_MAGIC_DELTA_XOR,    +72 bytes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderAnchor {
    Snapshot(ChainAnchor),
    Delta(DeltaAnchor),
}

impl HeaderAnchor {
    fn magic_xor(&self) -> u64 {
        match self {
            HeaderAnchor::Snapshot(_) => ANCHOR_MAGIC_SNAPSHOT_XOR,
            HeaderAnchor::Delta(_) => ANCHOR_MAGIC_DELTA_XOR,
        }
    }

    fn anchor_bytes_len(&self) -> usize {
        match self {
            HeaderAnchor::Snapshot(_) => CHAIN_ANCHOR_BYTES,
            HeaderAnchor::Delta(_) => DELTA_ANCHOR_BYTES,
        }
    }
}

/// Write a cuckoo file header, optionally embedding a chain anchor at the tail.
///
/// When `anchor` is `None`, the output is byte-identical to
/// [`write_header`] — same MAGIC, same length. Compatible with pre-Phase-C
/// readers.
///
/// When `anchor` is `Some`, the leading 8 bytes hold a v2 MAGIC (legacy
/// MAGIC XOR'd with a snapshot/delta marker), and the anchor bytes are
/// appended after the legacy header section. Total header size grows by
/// 36 (snapshot) or 72 (delta) bytes.
pub fn write_header_with_anchor(
    params: &TableParams,
    bins_per_table: usize,
    tag_seed: u64,
    anchor: Option<&HeaderAnchor>,
) -> Vec<u8> {
    let mut header = write_header(params, bins_per_table, tag_seed);
    if let Some(a) = anchor {
        // Overwrite magic with the v2 variant.
        let new_magic = params.magic ^ a.magic_xor();
        header[0..8].copy_from_slice(&new_magic.to_le_bytes());
        // Append anchor bytes.
        match a {
            HeaderAnchor::Snapshot(c) => header.extend_from_slice(&c.to_bytes()),
            HeaderAnchor::Delta(d) => header.extend_from_slice(&d.to_bytes()),
        }
        debug_assert_eq!(header.len(), params.header_size + a.anchor_bytes_len());
    }
    header
}

/// Fully parsed cuckoo file header (legacy or Phase-C v2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CuckooHeader {
    pub bins_per_table: usize,
    pub master_seed: u64,
    pub tag_seed: u64,
    /// `None` for legacy (pre-Phase-C) headers; `Some` for v2 anchored
    /// headers. Use [`verify_anchor_seeds`] to check that the embedded
    /// seed values match what the anchor would derive.
    pub anchor: Option<HeaderAnchor>,
    /// Total bytes consumed by the header (where the cuckoo bin data
    /// begins). For legacy: `params.header_size`. For v2: that plus
    /// 36 (snapshot) or 72 (delta).
    pub header_size: usize,
}

/// Read a cuckoo file header, recognising both legacy and Phase-C v2 formats.
///
/// `legacy_params` provides the expected legacy MAGIC and header_size;
/// the v2 variants are derived by XOR'ing `ANCHOR_MAGIC_*_XOR`.
pub fn read_cuckoo_header_with_anchor(
    data: &[u8],
    legacy_params: &TableParams,
) -> std::io::Result<CuckooHeader> {
    use std::io;
    if data.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cuckoo header: file too small (need 8 bytes for magic)",
        ));
    }
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let legacy_magic = legacy_params.magic;
    let snapshot_magic = legacy_magic ^ ANCHOR_MAGIC_SNAPSHOT_XOR;
    let delta_magic = legacy_magic ^ ANCHOR_MAGIC_DELTA_XOR;

    let (anchor_payload_len, anchor_variant) = if magic == legacy_magic {
        (0usize, None)
    } else if magic == snapshot_magic {
        (CHAIN_ANCHOR_BYTES, Some("snapshot"))
    } else if magic == delta_magic {
        (DELTA_ANCHOR_BYTES, Some("delta"))
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cuckoo header: bad magic — expected 0x{:016x} (legacy), 0x{:016x} (v2 snapshot), or 0x{:016x} (v2 delta); got 0x{:016x}",
                legacy_magic, snapshot_magic, delta_magic, magic
            ),
        ));
    };

    let total_header_size = legacy_params.header_size + anchor_payload_len;
    if data.len() < total_header_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cuckoo header: truncated — expected {} bytes, got {}",
                total_header_size,
                data.len()
            ),
        ));
    }

    let bins_per_table = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    let master_seed = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let tag_seed = if legacy_params.has_tag_seed && legacy_params.header_size >= 40 {
        u64::from_le_bytes(data[32..40].try_into().unwrap())
    } else {
        0
    };

    let anchor = match anchor_variant {
        None => None,
        Some("snapshot") => {
            let start = legacy_params.header_size;
            Some(HeaderAnchor::Snapshot(ChainAnchor::from_bytes(
                &data[start..start + CHAIN_ANCHOR_BYTES],
            )?))
        }
        Some("delta") => {
            let start = legacy_params.header_size;
            Some(HeaderAnchor::Delta(DeltaAnchor::from_bytes(
                &data[start..start + DELTA_ANCHOR_BYTES],
            )?))
        }
        _ => unreachable!(),
    };

    Ok(CuckooHeader {
        bins_per_table,
        master_seed,
        tag_seed,
        anchor,
        header_size: total_header_size,
    })
}

/// End-to-end seed verification: the header's `master_seed` (and optionally
/// `tag_seed`) must equal what the embedded chain anchor would derive.
///
/// This is the property a client uses to defeat adversarial seed selection:
/// even if a malicious server fabricates `master_seed`, it cannot also
/// fabricate a `ChainAnchor` that hashes to that seed (the chain produces
/// the anchor, not the operator).
///
/// `master_domain` selects which seed the header is being used for —
/// e.g. [`seeds::domain::INDEX_CUCKOO_MASTER`](crate::seeds::domain::INDEX_CUCKOO_MASTER).
/// `tag_domain` is `Some` only for INDEX tables which carry a tag seed.
///
/// Returns `Err(reason)` if no anchor is present, the master_seed doesn't
/// match, or the tag_seed doesn't match.
pub fn verify_anchor_seeds(
    header: &CuckooHeader,
    master_domain: &str,
    tag_domain: Option<&str>,
) -> Result<(), String> {
    let Some(anchor) = &header.anchor else {
        return Err("no anchor in header (pre-Phase-C database)".to_string());
    };
    let (derived_master, derived_tag): (u64, Option<u64>) = match anchor {
        HeaderAnchor::Snapshot(a) => (
            derive_seed_u64(master_domain, a),
            tag_domain.map(|d| derive_seed_u64(d, a)),
        ),
        HeaderAnchor::Delta(a) => (
            derive_seed_u64(master_domain, a),
            tag_domain.map(|d| derive_seed_u64(d, a)),
        ),
    };
    if derived_master != header.master_seed {
        return Err(format!(
            "master_seed mismatch under domain {:?}: derived 0x{:016x}, header has 0x{:016x}",
            master_domain, derived_master, header.master_seed
        ));
    }
    if let Some(dt) = derived_tag {
        if dt != header.tag_seed {
            return Err(format!(
                "tag_seed mismatch under domain {:?}: derived 0x{:016x}, header has 0x{:016x}",
                tag_domain.unwrap(),
                dt,
                header.tag_seed
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{INDEX_PARAMS, CHUNK_PARAMS};
    use crate::hash::read_cuckoo_header;

    #[test]
    fn test_compute_bins_per_table() {
        let bins = compute_bins_per_table(100, 4);
        // 100 / (4 * 0.95) = 26.3 → 27
        assert_eq!(bins, 27);
    }

    #[test]
    fn test_header_roundtrip_index() {
        let header = write_header(&INDEX_PARAMS, 753707, 0xd4e5f6a7b8c91023);
        let (bins, tag_seed) = read_cuckoo_header(
            &header,
            INDEX_PARAMS.magic,
            INDEX_PARAMS.header_size,
            INDEX_PARAMS.has_tag_seed,
        );
        assert_eq!(bins, 753707);
        assert_eq!(tag_seed, 0xd4e5f6a7b8c91023);
    }

    #[test]
    fn test_header_with_anchor_snapshot_roundtrip() {
        use crate::seeds::{domain, ChainAnchor, SnapshotSeeds};

        let anchor = ChainAnchor {
            block_hash: [0x42; 32],
            block_height: 850_123,
        };
        let seeds = SnapshotSeeds::derive(&anchor);

        // Build an INDEX-PARAMS-like TableParams with the derived master seed.
        let params = INDEX_PARAMS.with_master_seed(seeds.index_master);
        let bytes = write_header_with_anchor(
            &params,
            12345,
            seeds.index_tag,
            Some(&HeaderAnchor::Snapshot(anchor)),
        );

        // v2 magic = legacy XOR snapshot marker; total size = legacy + 36.
        let expected_magic = INDEX_PARAMS.magic ^ ANCHOR_MAGIC_SNAPSHOT_XOR;
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), expected_magic);
        assert_eq!(bytes.len(), INDEX_PARAMS.header_size + 36);

        let parsed = read_cuckoo_header_with_anchor(&bytes, &INDEX_PARAMS).unwrap();
        assert_eq!(parsed.bins_per_table, 12345);
        assert_eq!(parsed.master_seed, seeds.index_master);
        assert_eq!(parsed.tag_seed, seeds.index_tag);
        assert_eq!(parsed.anchor, Some(HeaderAnchor::Snapshot(anchor)));

        // End-to-end seed verification passes for an honest header.
        verify_anchor_seeds(
            &parsed,
            domain::INDEX_CUCKOO_MASTER,
            Some(domain::INDEX_TAG_FINGERPRINT),
        )
        .expect("honest anchor should verify");
    }

    #[test]
    fn test_header_with_anchor_delta_roundtrip() {
        use crate::seeds::{domain, ChainAnchor, DeltaAnchor, DeltaSeeds};

        let from = ChainAnchor { block_hash: [0xaa; 32], block_height: 900_000 };
        let to = ChainAnchor { block_hash: [0xbb; 32], block_height: 902_016 };
        let delta = DeltaAnchor { from, to };
        let seeds = DeltaSeeds::derive(&delta);

        let params = CHUNK_PARAMS.with_master_seed(seeds.chunk_master);
        let bytes = write_header_with_anchor(
            &params,
            54321,
            0, // CHUNK has no tag seed
            Some(&HeaderAnchor::Delta(delta)),
        );

        let expected_magic = CHUNK_PARAMS.magic ^ ANCHOR_MAGIC_DELTA_XOR;
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), expected_magic);
        assert_eq!(bytes.len(), CHUNK_PARAMS.header_size + 72);

        let parsed = read_cuckoo_header_with_anchor(&bytes, &CHUNK_PARAMS).unwrap();
        assert_eq!(parsed.bins_per_table, 54321);
        assert_eq!(parsed.master_seed, seeds.chunk_master);
        assert_eq!(parsed.anchor, Some(HeaderAnchor::Delta(delta)));

        verify_anchor_seeds(&parsed, domain::CHUNK_CUCKOO_MASTER, None)
            .expect("honest delta anchor should verify");
    }

    #[test]
    fn test_header_with_anchor_legacy_passthrough() {
        // anchor=None must produce byte-identical output to the legacy
        // write_header, so pre-Phase-C readers keep working.
        let legacy = write_header(&INDEX_PARAMS, 999, 0xdeadbeefcafebabe);
        let v2 = write_header_with_anchor(&INDEX_PARAMS, 999, 0xdeadbeefcafebabe, None);
        assert_eq!(legacy, v2);

        let parsed = read_cuckoo_header_with_anchor(&v2, &INDEX_PARAMS).unwrap();
        assert!(parsed.anchor.is_none());
        assert_eq!(parsed.bins_per_table, 999);
        assert_eq!(parsed.tag_seed, 0xdeadbeefcafebabe);
        assert_eq!(parsed.header_size, INDEX_PARAMS.header_size);
    }

    #[test]
    fn test_verify_anchor_rejects_mismatched_seed() {
        use crate::seeds::{domain, ChainAnchor};

        let anchor = ChainAnchor { block_hash: [0; 32], block_height: 1 };
        // Use a deliberately WRONG master seed — not what the anchor would derive.
        let params = INDEX_PARAMS.with_master_seed(0xdeadbeef);
        let bytes = write_header_with_anchor(
            &params,
            100,
            0xcafef00d,
            Some(&HeaderAnchor::Snapshot(anchor)),
        );
        let parsed = read_cuckoo_header_with_anchor(&bytes, &INDEX_PARAMS).unwrap();

        // The anchor is present but seeds don't match → reject.
        let err = verify_anchor_seeds(&parsed, domain::INDEX_CUCKOO_MASTER, None)
            .expect_err("mismatched seed must fail");
        assert!(err.contains("master_seed mismatch"), "got: {}", err);
    }

    #[test]
    fn test_read_rejects_unknown_magic() {
        let mut bytes = vec![0u8; INDEX_PARAMS.header_size];
        bytes[0..8].copy_from_slice(&0xffff_ffff_ffff_ffff_u64.to_le_bytes());
        let err = read_cuckoo_header_with_anchor(&bytes, &INDEX_PARAMS).unwrap_err();
        assert!(err.to_string().contains("bad magic"));
    }

    #[test]
    fn test_read_rejects_truncated_anchor() {
        use crate::seeds::ChainAnchor;
        let anchor = ChainAnchor { block_hash: [0; 32], block_height: 0 };
        let bytes = write_header_with_anchor(
            &INDEX_PARAMS,
            1,
            0,
            Some(&HeaderAnchor::Snapshot(anchor)),
        );
        // Lop off the last 10 bytes of the anchor — truncated.
        let truncated = &bytes[..bytes.len() - 10];
        let err = read_cuckoo_header_with_anchor(truncated, &INDEX_PARAMS).unwrap_err();
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn test_header_roundtrip_chunk() {
        let header = write_header(&CHUNK_PARAMS, 1286191, 0);
        let (bins, tag_seed) = read_cuckoo_header(
            &header,
            CHUNK_PARAMS.magic,
            CHUNK_PARAMS.header_size,
            CHUNK_PARAMS.has_tag_seed,
        );
        assert_eq!(bins, 1286191);
        assert_eq!(tag_seed, 0); // CHUNK has no tag_seed
    }

    #[test]
    fn test_build_byte_keyed_table() {
        // Small test: 10 items, 4 bins
        let items: Vec<[u8; 20]> = (0..10u8).map(|i| {
            let mut sh = [0u8; 20];
            sh[0] = i;
            sh
        }).collect();
        let refs: Vec<&[u8]> = items.iter().map(|s| s.as_slice()).collect();

        let table = build_byte_keyed_table(&refs, 0, &INDEX_PARAMS, 10);
        // All items should be placed (no EMPTY for them)
        let placed: Vec<u32> = table.iter().filter(|&&v| v != EMPTY).copied().collect();
        assert_eq!(placed.len(), 10);
    }

    #[test]
    fn test_build_int_keyed_table() {
        let ids: Vec<u32> = (0..10).collect();
        let table = build_int_keyed_table(&ids, 0, &CHUNK_PARAMS, 10);
        let placed: Vec<u32> = table.iter().filter(|&&v| v != EMPTY).copied().collect();
        assert_eq!(placed.len(), 10);
    }
}
