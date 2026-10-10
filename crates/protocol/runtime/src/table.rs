//! Cuckoo table loading for PIR servers: `MappedSubTable` /
//! `MappedDatabase`, one per configured database.

use crate::manifest::{hex_encode, DbManifest};
use crate::protocol::DatabaseProofBundle;
use memmap2::Mmap;
use pir_core::merkle::Hash256;
use pir_core::params::TableParams;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

/// A single memory-mapped cuckoo sub-table with its parameters.
pub struct MappedSubTable {
    /// Memory-mapped file contents.
    pub mmap: Arc<Mmap>,
    /// Parameters that describe this table's layout.
    pub params: TableParams,
    /// Number of cuckoo bins per PBC group (read from header).
    pub bins_per_table: usize,
    /// Byte size of one group's sub-table (bins × slots_per_bin × slot_size).
    pub table_byte_size: usize,
    /// Byte offset where the per-group tables begin = legacy header size +
    /// chain-anchor length (0 legacy / 36 snapshot / 72 delta). On a v2
    /// database the anchor is written BETWEEN the header and the tables, so
    /// `group_bytes` MUST use this — not the hardcoded `params.header_size`,
    /// which would read every group's bins `anchor_len` bytes too early and
    /// silently serve misaligned data. Mirrors the OnionPIR
    /// `OnionChunkHeader.data_offset` fix (commit ea4ee8c8).
    pub data_offset: usize,
    /// Tag seed from header (0 if the table has no tag seed).
    pub tag_seed: u64,
    /// Master cuckoo seed as read from the file header (the real on-disk
    /// value — `params.master_seed` is only a sentinel post-Phase-B).
    pub master_seed: u64,
    /// Chain anchor embedded in a Phase-C v2 header, if present. `None`
    /// for legacy (pre-anchor) databases. Reported to clients, which derive
    /// the seeds from it.
    pub anchor: Option<pir_core::cuckoo::HeaderAnchor>,
}

impl MappedSubTable {
    /// A table that carries a database's geometry and seeds but holds no
    /// bins. An ORAM-only server learns these values from the attested build
    /// evidence and never reads table data: `try_group_bytes` finds nothing,
    /// and the server refuses every request that would read bins.
    pub fn metadata_only(
        params: TableParams,
        bins_per_table: usize,
        master_seed: u64,
        tag_seed: u64,
        anchor: pir_core::cuckoo::HeaderAnchor,
    ) -> Self {
        let mmap = memmap2::MmapOptions::new()
            .len(1)
            .map_anon()
            .and_then(|mmap| mmap.make_read_only())
            .expect("anonymous one-byte mapping");
        let table_byte_size = params.table_byte_size(bins_per_table);
        MappedSubTable {
            mmap: Arc::new(mmap),
            params,
            bins_per_table,
            table_byte_size,
            data_offset: 0,
            tag_seed,
            master_seed,
            anchor: Some(anchor),
        }
    }

    /// Load and memory-map a cuckoo table file.
    pub fn load(path: &Path, params: TableParams) -> Self {
        println!("  Loading sub-table: {}", path.display());
        let f = File::open(path).unwrap_or_else(|e| panic!("open {}: {}", path.display(), e));
        let mmap =
            unsafe { Mmap::map(&f) }.unwrap_or_else(|e| panic!("mmap {}: {}", path.display(), e));

        // Phase C: accept legacy MAGIC and v2 MAGIC variants (snapshot/delta
        // anchor appended). Caller already validates the file via the
        // pir-core header parser; this only extracts bins_per_table + tag_seed.
        let parsed = pir_core::cuckoo::read_cuckoo_header_with_anchor(&mmap, &params)
            .unwrap_or_else(|e| panic!("cuckoo header parse {}: {}", path.display(), e));
        let bins_per_table = parsed.bins_per_table;
        let tag_seed = parsed.tag_seed;
        let master_seed = parsed.master_seed;
        let anchor = parsed.anchor;
        let table_byte_size = params.table_byte_size(bins_per_table);
        // Anchor-aware: legacy header size + anchor payload length. The v2
        // anchor sits between the header and the tables, so the per-group
        // table data starts here, not at `params.header_size`.
        let data_offset = parsed.header_size;

        // Fail loudly if a v2 (chain-anchored) table's on-disk size is
        // inconsistent with the anchor-aware layout, instead of silently
        // serving misaligned bins. Anchored tables are only ever the
        // INDEX/CHUNK cuckoo files, written as [header][anchor][k ×
        // table_byte_size]; non-anchored tables (legacy cuckoo + Merkle
        // siblings) have other layouts, so the check is scoped to anchored.
        if anchor.is_some() {
            let expected = data_offset + params.k * table_byte_size;
            assert_eq!(
                mmap.len(),
                expected,
                "cuckoo table {} size {} != expected {} (data_offset {} + k {} × table_byte_size {}) \
                 — anchor-aware offset mismatch, refusing to serve",
                path.display(),
                mmap.len(),
                expected,
                data_offset,
                params.k,
                table_byte_size,
            );
        }

        println!(
            "    bins_per_table={}, slot={}B, table={:.1}MB, file={:.2}GB",
            bins_per_table,
            params.slot_size,
            table_byte_size as f64 / (1024.0 * 1024.0),
            mmap.len() as f64 / (1024.0 * 1024.0 * 1024.0),
        );
        if params.has_tag_seed {
            println!("    tag_seed=0x{:016x}", tag_seed);
        }

        #[cfg(unix)]
        {
            use libc::{madvise, MADV_SEQUENTIAL};
            unsafe {
                madvise(
                    mmap.as_ptr() as *mut libc::c_void,
                    mmap.len(),
                    MADV_SEQUENTIAL,
                );
            }
        }

        MappedSubTable {
            mmap: Arc::new(mmap),
            params,
            bins_per_table,
            table_byte_size,
            data_offset,
            tag_seed,
            master_seed,
            anchor,
        }
    }

    /// Get the byte slice for a specific group's sub-table.
    ///
    /// Panics if `group_id` maps past the mmap — callers must iterate
    /// within `0..params.k` (the batch paths do). For ids that arrive
    /// off the wire, use [`Self::try_group_bytes`] instead.
    pub fn group_bytes(&self, group_id: usize) -> &[u8] {
        let offset = self.data_offset + group_id * self.table_byte_size;
        &self.mmap[offset..offset + self.table_byte_size]
    }

    /// Bounds-checked variant of [`Self::group_bytes`] for group ids
    /// that arrive off the wire (HarmonyPIR query paths, S4). Returns
    /// `None` when `group_id >= params.k` or when the computed range
    /// would overrun the mmap (possible for legacy anchor-less files,
    /// whose on-disk size is not asserted at load) — a panic here would
    /// abort the whole server under the release profile's `panic = 'abort'`.
    pub fn try_group_bytes(&self, group_id: usize) -> Option<&[u8]> {
        if group_id >= self.params.k {
            return None;
        }
        let offset = self
            .data_offset
            .checked_add(group_id.checked_mul(self.table_byte_size)?)?;
        let end = offset.checked_add(self.table_byte_size)?;
        if end > self.mmap.len() {
            return None;
        }
        Some(&self.mmap[offset..end])
    }
}

/// Describes a complete PIR database (INDEX + CHUNK + optional Merkle sub-tables).
/// Whether a database is a full UTXO snapshot or a delta between two heights.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DatabaseType {
    /// Full UTXO set at a single height (base_height is always 0).
    Full,
    /// Delta (new + spent UTXOs) between base_height and height.
    Delta,
}

pub struct DatabaseDescriptor {
    /// Human-readable name (e.g. "main", "delta_940611_944000").
    pub name: String,
    /// Full or delta.
    pub db_type: DatabaseType,
    /// Starting height (0 for full snapshots, >0 for deltas).
    pub base_height: u32,
    /// Snapshot height (full) or end height (delta).
    pub height: u32,
    /// Parameters for the INDEX-level sub-table.
    pub index_params: TableParams,
    /// Parameters for the CHUNK-level sub-table.
    pub chunk_params: TableParams,
}

/// A fully loaded database with all sub-tables memory-mapped.
pub struct MappedDatabase {
    /// Descriptor for this database.
    pub descriptor: DatabaseDescriptor,
    /// INDEX-level cuckoo table.
    pub index: MappedSubTable,
    /// CHUNK-level cuckoo table.
    pub chunk: MappedSubTable,

    // ── Per-bucket bin Merkle ────────────────────────────────────────────
    /// Flat sibling tables for INDEX-level per-bucket Merkle (L0, L1, ...).
    pub bucket_merkle_index_siblings: Vec<MappedSubTable>,
    /// Flat sibling tables for CHUNK-level per-bucket Merkle (L0, L1, ...).
    pub bucket_merkle_chunk_siblings: Vec<MappedSubTable>,
    /// Tree-top caches for all 155 per-bucket trees.
    pub bucket_merkle_tree_tops: Option<Vec<u8>>,
    /// Per-group roots: 155 × 32B (75 index + 80 chunk).
    pub bucket_merkle_roots: Option<Vec<u8>>,
    /// Super-root: SHA256 of all 155 roots concatenated.
    pub bucket_merkle_root: Option<Vec<u8>>,

    /// SHA-256 of `MANIFEST.toml` if one was present and verified.
    /// `None` for legacy DBs that pre-date the manifest format.
    /// Folded into REPORT_DATA when the server signs an attestation report.
    pub manifest_root: Option<Hash256>,
    /// The parsed manifest (kept around so `/attest` can return per-file
    /// hashes to the client without re-reading the file). `None` iff
    /// `manifest_root` is `None`.
    pub manifest: Option<DbManifest>,
    /// Optional attested-builder proof sidecar served via REQ_GET_DB_PROOF.
    /// The runtime only transports this bundle; clients/admin tooling verify it.
    pub db_proof: Option<DatabaseProofBundle>,
    /// Optional v2 sidecar served separately so strict v2 clients never fall
    /// back to a v1 proof that omits the complete Onion query layout.
    pub db_proof_v2: Option<DatabaseProofBundle>,
}

impl MappedDatabase {
    /// A database served only through Direct ORAM (`unified_server
    /// --oram-only`). The host holds none of the PIR table files: the
    /// geometry and anchor come from the attested build evidence, the seeds
    /// are derived from that anchor exactly as clients derive them, and the
    /// manifest is the exact `server-db` manifest the evidence binds. The
    /// manifest must carry a `[direct_oram]` section, which the Direct ORAM
    /// image is bound to before the server listens.
    pub fn direct_oram_only(
        descriptor: DatabaseDescriptor,
        manifest: DbManifest,
        manifest_root: Hash256,
        index_bins_per_table: usize,
        chunk_bins_per_table: usize,
        anchor: pir_core::cuckoo::HeaderAnchor,
    ) -> Result<Self, String> {
        use pir_core::cuckoo::HeaderAnchor;
        use pir_core::seeds::{DeltaSeeds, SnapshotSeeds};

        if manifest.direct_oram.is_none() {
            return Err(format!(
                "[DB:{}] an ORAM-only database needs a [direct_oram] manifest section",
                descriptor.name
            ));
        }
        let (index_master, index_tag, chunk_master) = match anchor {
            HeaderAnchor::Snapshot(a) => {
                let seeds = SnapshotSeeds::derive(&a);
                (seeds.index_master, seeds.index_tag, seeds.chunk_master)
            }
            HeaderAnchor::Delta(a) => {
                let seeds = DeltaSeeds::derive(&a);
                (seeds.index_master, seeds.index_tag, seeds.chunk_master)
            }
        };
        let index = MappedSubTable::metadata_only(
            descriptor.index_params.clone(),
            index_bins_per_table,
            index_master,
            index_tag,
            anchor,
        );
        let chunk = MappedSubTable::metadata_only(
            descriptor.chunk_params.clone(),
            chunk_bins_per_table,
            chunk_master,
            0,
            anchor,
        );
        println!(
            "[DB:{}] ORAM-only: INDEX bins={}, CHUNK bins={}, manifest root=sha256({}...) from the build evidence",
            descriptor.name,
            index_bins_per_table,
            chunk_bins_per_table,
            &hex_encode(&manifest_root)[..16]
        );
        Ok(MappedDatabase {
            descriptor,
            index,
            chunk,
            bucket_merkle_index_siblings: Vec::new(),
            bucket_merkle_chunk_siblings: Vec::new(),
            bucket_merkle_tree_tops: None,
            bucket_merkle_roots: None,
            bucket_merkle_root: None,
            manifest_root: Some(manifest_root),
            manifest: Some(manifest),
            db_proof: None,
            db_proof_v2: None,
        })
    }

    /// Load a database from a directory containing cuckoo table files.
    ///
    /// Automatically detects and loads Merkle sub-tables if present.
    pub fn load(base_dir: &Path, descriptor: DatabaseDescriptor) -> Self {
        println!(
            "[DB:{}] Loading from {}",
            descriptor.name,
            base_dir.display()
        );

        // Verify MANIFEST.toml first if present and abort on a mismatch: the
        // attested manifest_root must describe the files this server serves.
        let (manifest, manifest_root) = match DbManifest::load_and_verify(base_dir) {
            Ok(Some((m, root))) => {
                println!(
                    "  Manifest verified: {} files, root=sha256({}...)",
                    m.files.len(),
                    &hex_encode(&root)[..16]
                );
                (Some(m), Some(root))
            }
            Ok(None) => {
                eprintln!(
                    "[DB:{}] WARN: no MANIFEST.toml in {} — manifest verification SKIPPED (back-compat). \
                     Generate one with scripts/build_db_manifest.sh to enable attestation coverage.",
                    descriptor.name,
                    base_dir.display()
                );
                (None, None)
            }
            Err(e) => panic!(
                "[DB:{}] manifest verification failed: {}. Refusing to load.",
                descriptor.name, e
            ),
        };

        let index = MappedSubTable::load(
            &base_dir.join("batch_pir_cuckoo.bin"),
            descriptor.index_params.clone(),
        );
        let chunk = MappedSubTable::load(
            &base_dir.join("chunk_pir_cuckoo.bin"),
            descriptor.chunk_params.clone(),
        );

        // ── Load per-bucket bin Merkle files ──────────────────────────────
        let mut bucket_merkle_index_siblings = Vec::new();
        let mut bucket_merkle_chunk_siblings = Vec::new();

        // INDEX sibling tables: merkle_bucket_index_sib_L0.bin, L1.bin, ...
        for level in 0.. {
            let path = base_dir.join(format!("merkle_bucket_index_sib_L{}.bin", level));
            if !path.exists() {
                break;
            }
            let magic = 0xBA7C_B000_0000_0000u64 | ((level as u64) << 16);
            let params = pir_core::params::TableParams {
                k: descriptor.index_params.k,
                num_hashes: 0,
                master_seed: 0,
                slots_per_bin: 1,
                cuckoo_num_hashes: 0,
                slot_size: 8 * 32, // 256B per row (arity=8 × 32B hashes)
                dpf_n: 0,
                magic,
                header_size: 32,
                has_tag_seed: false,
            };
            println!(
                "  Loading bucket Merkle INDEX sib L{} (slot=256B)...",
                level
            );
            bucket_merkle_index_siblings.push(MappedSubTable::load(&path, params));
        }

        // CHUNK sibling tables: merkle_bucket_chunk_sib_L0.bin, L1.bin, ...
        for level in 0.. {
            let path = base_dir.join(format!("merkle_bucket_chunk_sib_L{}.bin", level));
            if !path.exists() {
                break;
            }
            let magic = 0xBA7C_B000_0000_0000u64 | (1u64 << 40) | ((level as u64) << 16);
            let params = pir_core::params::TableParams {
                k: descriptor.chunk_params.k,
                num_hashes: 0,
                master_seed: 0,
                slots_per_bin: 1,
                cuckoo_num_hashes: 0,
                slot_size: 8 * 32,
                dpf_n: 0,
                magic,
                header_size: 32,
                has_tag_seed: false,
            };
            println!(
                "  Loading bucket Merkle CHUNK sib L{} (slot=256B)...",
                level
            );
            bucket_merkle_chunk_siblings.push(MappedSubTable::load(&path, params));
        }

        // A missing or unreadable file means no bucket Merkle. Clients check
        // what is served against the attested roots.
        let read = |name: &str| std::fs::read(base_dir.join(name)).ok();
        let bucket_merkle_tree_tops = read("merkle_bucket_tree_tops.bin");
        let bucket_merkle_roots = read("merkle_bucket_roots.bin");
        let bucket_merkle_root = read("merkle_bucket_root.bin");
        // Requests slice one 32-byte root per group out of this list.
        if let Some(roots) = &bucket_merkle_roots {
            let expected = (descriptor.index_params.k + descriptor.chunk_params.k) * 32;
            assert_eq!(
                roots.len(),
                expected,
                "[DB:{}] merkle_bucket_roots.bin has {} bytes, expected {}",
                descriptor.name,
                roots.len(),
                expected
            );
        }
        if bucket_merkle_tree_tops.is_some() {
            println!(
                "  Bucket Merkle: {} INDEX sib levels, {} CHUNK sib levels, roots={}, super-root={}",
                bucket_merkle_index_siblings.len(),
                bucket_merkle_chunk_siblings.len(),
                if bucket_merkle_roots.is_some() { "yes" } else { "no" },
                if bucket_merkle_root.is_some() { "yes" } else { "no" },
            );
        }

        MappedDatabase {
            descriptor,
            index,
            chunk,
            bucket_merkle_index_siblings,
            bucket_merkle_chunk_siblings,
            bucket_merkle_tree_tops,
            bucket_merkle_roots,
            bucket_merkle_root,
            manifest,
            manifest_root,
            db_proof: None,
            db_proof_v2: None,
        }
    }

    /// Whether this database has per-bucket bin Merkle verification data.
    pub fn has_bucket_merkle(&self) -> bool {
        self.bucket_merkle_tree_tops.is_some()
            && self.bucket_merkle_roots.is_some()
            && self.bucket_merkle_root.is_some()
    }
}

/// Server state holding multiple databases plus the long-lived
/// channel-encryption pubkey.
pub struct ServerState {
    /// All loaded databases. Index 0 is typically the main UTXO database.
    pub databases: Vec<MappedDatabase>,
    /// X25519 public key the server generates inside the SEV-SNP guest
    /// at startup. Bound into REPORT_DATA via
    /// `pir_core::attest::build_report_data` (V2 layout). Echoed back
    /// to clients in `AttestResult::server_static_pub` so they can
    /// verify the chip-attested key matches what they'll handshake
    /// against. All-zero on servers that don't yet have a channel key
    /// (transitional — unified_server should always set one).
    pub server_static_pub: [u8; 32],
    /// PEM-encoded AMD ARK / ASK / VCEK certificates. The operator
    /// fetches the cert chain once from `https://kdsintf.amd.com/vcek/`
    /// (chain endpoint for the chip's family + per-chip VCEK URL) and
    /// places the PEMs in `--vcek-dir`; unified_server reads them at
    /// startup and ships them out in every AttestResult so the
    /// browser-side `pir-attest-verify` can chain-validate the SNP
    /// report's ECDSA-P384 signature back to AMD's known root —
    /// without having to fetch from AMD KDS itself (CORS-blocked
    /// from the browser context).
    ///
    /// Empty on servers that haven't loaded the chain (development,
    /// non-SEV hosts, transitional). The verifier falls back to V2-
    /// binding-only mode in that case.
    pub ark_pem: Vec<u8>,
    pub ask_pem: Vec<u8>,
    pub vcek_pem: Vec<u8>,
    /// Pre-encoded `pir_identity::AnnouncementBundle` bytes that
    /// REQ_ANNOUNCE returns verbatim. Populated at startup by
    /// `crate::identity::build_announcement_bundle` if both the
    /// `--identity-key-path` and `--identity-cert-path` files are
    /// present and consistent; left `None` (and a warning is logged)
    /// when either file is missing or the cert / key disagree. With
    /// `None`, REQ_ANNOUNCE returns a `Response::Error` and the rest
    /// of the protocol is unaffected.
    pub announcement_bundle: Option<Vec<u8>>,
}

impl ServerState {
    /// Get a database by index. Returns None if db_id is out of range.
    pub fn get_db(&self, db_id: u8) -> Option<&MappedDatabase> {
        self.databases.get(db_id as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pir_core::cuckoo::{write_header_with_anchor, HeaderAnchor};
    use pir_core::params::INDEX_PARAMS;
    use pir_core::seeds::{ChainAnchor, CHAIN_ANCHOR_BYTES};
    use std::io::Write as _;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "mst_{}_{}_{}.bin",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    /// Regression: on a v2 (chain-anchored) INDEX cuckoo file the per-group
    /// tables begin AFTER the 36-byte snapshot anchor. `group_bytes` must use
    /// the anchor-aware `data_offset` (40 + 36 = 76) — not `params.header_size`
    /// (40), which read every group 36 bytes too early and silently served
    /// misaligned bins (the DPF/HarmonyPIR 0-UTXO regression).
    #[test]
    fn group_bytes_skips_v2_snapshot_anchor() {
        let params = INDEX_PARAMS;
        let bins_per_table = 1usize;
        let table_byte_size = params.table_byte_size(bins_per_table);

        let anchor = ChainAnchor {
            block_hash: [0xAB; 32],
            block_height: 948_454,
        };
        let header = write_header_with_anchor(
            &params,
            bins_per_table,
            0xdead_beef_cafe_babe, // tag_seed (load does not verify it)
            Some(&HeaderAnchor::Snapshot(anchor)),
        );
        let expected_offset = params.header_size + CHAIN_ANCHOR_BYTES;
        assert_eq!(
            header.len(),
            expected_offset,
            "anchored header = legacy + 36"
        );

        // Marker at the first byte of group 0's real table. The anchor bytes
        // are never 0x5A, so reading it back proves we skipped the anchor.
        let mut tables = vec![0u8; params.k * table_byte_size];
        tables[0] = 0x5A;
        let mut bytes = header;
        bytes.extend_from_slice(&tables);

        let path = temp_path("snap");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let st = MappedSubTable::load(&path, params);

        assert_eq!(
            st.data_offset, expected_offset,
            "data_offset must skip the v2 anchor"
        );
        let g0 = st.group_bytes(0);
        assert_eq!(g0.len(), table_byte_size);
        assert_eq!(
            g0[0], 0x5A,
            "group_bytes(0) must start at real table data, past the anchor"
        );

        std::fs::remove_file(&path).ok();
    }

    /// S4: wire-supplied group ids must be bounds-checked. With k groups
    /// on disk, ids ≥ k (e.g. the 250 a crafted Harmony frame can carry)
    /// return None instead of panicking on an out-of-range mmap slice.
    #[test]
    fn try_group_bytes_rejects_out_of_range_group_id() {
        let params = INDEX_PARAMS;
        let k = params.k;
        let bins_per_table = 1usize;
        let table_byte_size = params.table_byte_size(bins_per_table);

        let mut bytes = write_header_with_anchor(&params, bins_per_table, 0, None);
        bytes.extend_from_slice(&vec![0u8; k * table_byte_size]);

        let path = temp_path("tgb_range");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let st = MappedSubTable::load(&path, params);

        assert_eq!(st.try_group_bytes(0).unwrap(), st.group_bytes(0));
        assert!(st.try_group_bytes(k - 1).is_some());
        assert!(st.try_group_bytes(k).is_none());
        assert!(st.try_group_bytes(250).is_none());
        assert!(st.try_group_bytes(usize::MAX).is_none());

        std::fs::remove_file(&path).ok();
    }

    /// A legacy (anchor-less) file's size is not asserted at load, so a
    /// group id that is < k but maps past the end of the mmap must also
    /// be refused.
    #[test]
    fn try_group_bytes_rejects_mmap_overrun_on_undersized_legacy_file() {
        let params = INDEX_PARAMS;
        let bins_per_table = 1usize;
        let table_byte_size = params.table_byte_size(bins_per_table);

        // Only ONE group's worth of table data despite params.k = 75.
        let mut bytes = write_header_with_anchor(&params, bins_per_table, 0, None);
        bytes.extend_from_slice(&vec![0u8; table_byte_size]);

        let path = temp_path("tgb_short");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let st = MappedSubTable::load(&path, params);

        assert!(st.try_group_bytes(0).is_some());
        assert!(st.try_group_bytes(1).is_none(), "id < k but past mmap end");

        std::fs::remove_file(&path).ok();
    }

    /// A legacy (anchor-less) file is unchanged: data_offset == header_size,
    /// so the fix is a no-op for pre-Phase-C databases.
    #[test]
    fn group_bytes_legacy_no_anchor_unchanged() {
        let params = INDEX_PARAMS;
        let bins_per_table = 1usize;
        let table_byte_size = params.table_byte_size(bins_per_table);

        let header_size = params.header_size; // capture before `params` is moved into load()
        let header = write_header_with_anchor(&params, bins_per_table, 0, None);
        assert_eq!(header.len(), header_size, "legacy header carries no anchor");

        let mut tables = vec![0u8; table_byte_size];
        tables[0] = 0x5A;
        let mut bytes = header;
        bytes.extend_from_slice(&tables);

        let path = temp_path("legacy");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let st = MappedSubTable::load(&path, params);

        assert_eq!(st.data_offset, header_size);
        assert_eq!(st.group_bytes(0)[0], 0x5A);

        std::fs::remove_file(&path).ok();
    }
}
