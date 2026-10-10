#![cfg(test)]
use super::*;
use runtime::protocol::*;

mod announce_dispatch_tests {
    //! Tests for the REQ_ANNOUNCE response builder used by the
    //! production dispatch loop. The full per-connection match lives
    //! inline in `main` and needs a multi-GB checkpoint to boot, so we
    //! exercise the shared `build_announce_response` seam directly.
    //! Routing (opcode 0x07 reaching this arm rather than the catch-all
    //! "unsupported request" arm) is verified live by the operator-
    //! identity end-to-end check, since it can only be observed against
    //! a running binary.
    use super::*;

    #[test]
    fn announce_response_configured_returns_bundle_verbatim() {
        let bundle = vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x07];
        match build_announce_response(&Some(bundle.clone())) {
            Response::Announce(b) => assert_eq!(b, bundle),
            other => panic!("expected Announce, got {:?}", other),
        }
    }

    #[test]
    fn announce_response_configured_wire_roundtrips_to_same_bundle() {
        // The arm sends `resp.encode()` on the wire; a client decodes it
        // back to identical bundle bytes — proving the dispatch arm emits
        // a well-formed RESP_ANNOUNCE frame the SDK `announce()` parses.
        let bundle = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let wire = build_announce_response(&Some(bundle.clone())).encode();
        // Wire layout: [u32 LE outer len][RESP_ANNOUNCE][u32 LE blen][bundle];
        // `Response::decode` consumes everything after the outer length.
        match Response::decode(&wire[4..]).expect("decode RESP_ANNOUNCE") {
            Response::Announce(b) => assert_eq!(b, bundle),
            other => panic!("expected Announce after round-trip, got {:?}", other),
        }
    }

    #[test]
    fn announce_response_unconfigured_returns_error() {
        // None (server started without --identity-* flags, or with an
        // inconsistent key/cert pair) must surface as RESP_ERROR carrying
        // the documented "announce not configured" message — the client's
        // `announce()` maps this to PirError::ServerError.
        match build_announce_response(&None) {
            Response::Error(msg) => assert!(
                msg.contains("announce not configured"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected Error, got {:?}", other),
        }
    }
}

mod harmony_dos_guard_tests {
    //! S4/S5 guards for this binary's inline Harmony handlers. With the release profile's
    //! `panic = 'abort'`, each unguarded path was a single-frame
    //! unauthenticated full-process kill.
    //!
    //! Exercised through the free-function seams
    //! (`harmony_query_response`, `harmony_batch_response`,
    //! `validate_harmony_hints_request`, `compute_hints_for_group`)
    //! because the full `UnifiedServerData` needs a multi-GB
    //! checkpoint to boot — same pattern as `announce_dispatch_tests`.
    use super::*;
    #[cfg(feature = "cuckoo-oram")]
    use bitcoinpir_oram::{
        circuit_meta_page_bytes, circuit_payload_page_bytes, CircuitOram, CircuitOramState,
        CircuitStoreAuthState, DirectChunkPackedBlockReader, DirectIndexPackedBlockReader,
        DirectLevel, DirectTableInfo, DirectTableMetadata, FilePageStore, OramParams, PageStore,
        TieredMerklePageStore, DIRECT_CHUNK_RECORD_SIZE, DIRECT_INDEX_INPUT_RECORD_SIZE,
    };
    use pir_core::cuckoo::write_header_with_anchor;
    use runtime::table::MappedSubTable;
    use std::io::Write as _;

    /// bins_per_table for the synthetic test DB (mirrors the
    /// pir-runtime-core dos_guard_tests geometry).
    const TEST_BINS: usize = 256;

    static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn temp_suffix() -> String {
        let n = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!(
            "{}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            n,
        )
    }

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("unified_dos_{}_{}.bin", tag, temp_suffix()));
        p
    }

    #[cfg(feature = "cuckoo-oram")]
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("unified_dos_{}_{}", tag, temp_suffix()));
        p
    }

    fn write_subtable_file(
        path: &std::path::Path,
        params: &pir_core::params::TableParams,
        bins_per_table: usize,
    ) {
        let bin_size = params.bin_size();
        let mut bytes = write_header_with_anchor(params, bins_per_table, 0, None);
        for g in 0..params.k {
            for bin in 0..bins_per_table {
                let marker = (g as u8) ^ (bin as u8);
                bytes.extend(std::iter::repeat_n(marker, bin_size));
            }
        }
        std::fs::File::create(path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }

    /// Write a legacy (anchor-less) cuckoo file with k groups of
    /// TEST_BINS bins, every byte of bin `b` in group `g` set to
    /// `g ^ b`, then mmap it.
    fn make_subtable(tag: &str, params: pir_core::params::TableParams) -> MappedSubTable {
        let path = temp_path(tag);
        write_subtable_file(&path, &params, TEST_BINS);
        let st = MappedSubTable::load(&path, params);
        // mmap keeps the inode alive; unlink immediately so failing
        // tests don't leak temp files.
        std::fs::remove_file(&path).ok();
        st
    }

    /// Synthetic DB with one bucket-Merkle INDEX sibling level so the
    /// sibling branches of `harmony_level_table` are reachable.
    fn make_db() -> MappedDatabase {
        MappedDatabase {
            descriptor: DatabaseDescriptor {
                name: "dos-test".into(),
                db_type: DatabaseType::Full,
                base_height: 0,
                height: 0,
                index_params: INDEX_PARAMS.clone(),
                chunk_params: CHUNK_PARAMS.clone(),
            },
            index: make_subtable("idx", INDEX_PARAMS.clone()),
            chunk: make_subtable("chk", CHUNK_PARAMS.clone()),
            bucket_merkle_index_siblings: vec![make_subtable("isib0", INDEX_PARAMS.clone())],
            bucket_merkle_chunk_siblings: Vec::new(),
            bucket_merkle_tree_tops: None,
            bucket_merkle_roots: None,
            bucket_merkle_root: None,
            manifest_root: None,
            manifest: None,
            db_proof: None,
            db_proof_v2: None,
        }
    }

    fn expect_error(resp: Response, needle: &str) {
        match resp {
            Response::Error(msg) => {
                assert!(msg.contains(needle), "error {:?} missing {:?}", msg, needle)
            }
            other => panic!("expected Error, got {:?}", other),
        }
    }

    #[test]
    fn mmap_table_access_matches_direct_group_slice() {
        let db = make_db();
        let access = MmapCuckooTable::new(&db.chunk, db.chunk.params.bin_size());
        let group_id = 4usize;
        let indices = [0usize, 17, TEST_BINS - 1];

        let mut via_access = Vec::new();
        for idx in indices {
            access.append_entry(group_id, idx, &mut via_access).unwrap();
        }

        let entry_size = db.chunk.params.bin_size();
        let group_bytes = db.chunk.group_bytes(group_id);
        let mut direct = Vec::new();
        for idx in indices {
            let off = idx * entry_size;
            direct.extend_from_slice(&group_bytes[off..off + entry_size]);
        }

        assert_eq!(via_access, direct);
    }

    #[cfg(feature = "cuckoo-oram")]
    struct DirectLookupFixture {
        found_sh: [u8; pir_core::params::SCRIPT_HASH_SIZE],
        whale_sh: [u8; pir_core::params::SCRIPT_HASH_SIZE],
        missing_sh: [u8; pir_core::params::SCRIPT_HASH_SIZE],
        chunks: Vec<Vec<u8>>,
    }

    #[cfg(feature = "cuckoo-oram")]
    fn direct_chunk_record(txid_byte: u8, vout: u32, amount: u64) -> Vec<u8> {
        let mut raw = pir_core::codec::serialize_utxo_data(&[pir_core::codec::UtxoEntry {
            txid: [txid_byte; 32],
            vout,
            amount,
        }]);
        assert!(raw.len() <= DIRECT_CHUNK_RECORD_SIZE);
        raw.resize(DIRECT_CHUNK_RECORD_SIZE, 0);
        raw
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_response_padding_fills_public_chunk_budget() {
        let access_budget = 8usize;
        let slots = 3usize;
        let hash_fns = 2usize;
        let actual_chunk_bytes = DIRECT_CHUNK_RECORD_SIZE;

        assert_eq!(
            direct_oram_response_padding_bytes(access_budget, slots, hash_fns, actual_chunk_bytes)
                .unwrap(),
            DIRECT_CHUNK_RECORD_SIZE,
        );
        assert!(direct_oram_response_padding_bytes(
            access_budget,
            slots,
            hash_fns,
            3 * DIRECT_CHUNK_RECORD_SIZE,
        )
        .is_err());
    }

    #[cfg(feature = "cuckoo-oram")]
    fn write_direct_lookup_files(db_dir: &std::path::Path) -> DirectLookupFixture {
        std::fs::create_dir_all(db_dir).unwrap();

        let found_sh = [0x51u8; pir_core::params::SCRIPT_HASH_SIZE];
        let whale_sh = [0x52u8; pir_core::params::SCRIPT_HASH_SIZE];
        let missing_sh = [0x53u8; pir_core::params::SCRIPT_HASH_SIZE];

        let mut index_bytes = Vec::new();
        index_bytes.extend_from_slice(&found_sh);
        index_bytes.extend_from_slice(&3u32.to_le_bytes());
        index_bytes.push(2);
        index_bytes.extend_from_slice(&whale_sh);
        index_bytes.extend_from_slice(&1u32.to_le_bytes());
        index_bytes.push(0);
        assert_eq!(index_bytes.len(), 2 * DIRECT_INDEX_INPUT_RECORD_SIZE);

        let chunks = vec![
            vec![0u8; DIRECT_CHUNK_RECORD_SIZE],
            vec![0u8; DIRECT_CHUNK_RECORD_SIZE],
            vec![0u8; DIRECT_CHUNK_RECORD_SIZE],
            direct_chunk_record(0xA1, 1, 42),
            direct_chunk_record(0xB2, 2, 77),
            vec![0u8; DIRECT_CHUNK_RECORD_SIZE],
        ];
        let mut chunk_bytes = Vec::new();
        for chunk in &chunks {
            chunk_bytes.extend_from_slice(chunk);
        }

        std::fs::write(db_dir.join("utxo_chunks_index_nodust.bin"), index_bytes).unwrap();
        std::fs::write(db_dir.join("utxo_chunks_nodust.bin"), chunk_bytes).unwrap();

        DirectLookupFixture {
            found_sh,
            whale_sh,
            missing_sh,
            chunks,
        }
    }

    #[cfg(feature = "cuckoo-oram")]
    fn build_test_direct_oram_image(
        db_dir: &std::path::Path,
        oram_dir: &std::path::Path,
        level: DirectLevel,
        pack: usize,
    ) {
        match level {
            DirectLevel::Index => {
                let info = DirectTableInfo::from_index_file(
                    db_dir.join("utxo_chunks_index_nodust.bin"),
                    4,
                    2,
                    0.20,
                    0x6469_7265_6374_0001,
                )
                .unwrap();
                let source = DirectIndexPackedBlockReader::build(info, pack).unwrap();
                let metadata = source.metadata().clone();
                build_test_direct_oram_from_source(oram_dir, level, metadata, source);
            }
            DirectLevel::Chunk => {
                let info = DirectTableInfo::from_chunks_file(db_dir.join("utxo_chunks_nodust.bin"))
                    .unwrap();
                let source = DirectChunkPackedBlockReader::open(info, pack).unwrap();
                let metadata = source.metadata().clone();
                build_test_direct_oram_from_source(oram_dir, level, metadata, source);
            }
        }
    }

    #[cfg(feature = "cuckoo-oram")]
    fn build_test_direct_oram_from_source<S: bitcoinpir_oram::TrustedBlockSource>(
        oram_dir: &std::path::Path,
        level: DirectLevel,
        metadata: DirectTableMetadata,
        source: S,
    ) {
        let params = OramParams::with_leaves(
            source.logical_blocks(),
            source.block_size(),
            source.logical_blocks().max(2).next_power_of_two(),
        )
        .unwrap()
        .with_bucket_size(2)
        .unwrap()
        .with_stash_capacity(128)
        .unwrap();
        let paths = DirectOramPaths::new(oram_dir, level);
        let meta_store = FilePageStore::open(
            &paths.meta_image,
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
        )
        .unwrap();
        let payload_store = FilePageStore::open(
            &paths.payload_image,
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
        )
        .unwrap();
        let mut oram = CircuitOram::build_trusted_from_source(
            params,
            meta_store,
            payload_store,
            source,
            [5; 32],
        )
        .unwrap();
        oram.flush().unwrap();
        oram.snapshot().save_atomic(&paths.state).unwrap();
        metadata.save(&paths.metadata).unwrap();
    }

    #[cfg(feature = "cuckoo-oram")]
    fn build_test_direct_oram_auth_store(
        oram_dir: &std::path::Path,
        level: DirectLevel,
        trusted_levels: usize,
    ) {
        let paths = DirectOramPaths::new(oram_dir, level);
        let state = CircuitOramState::load(&paths.state).unwrap();
        let params = state.params.clone();
        let hash_page_size = 4096usize;
        let meta_store = FilePageStore::open(
            &paths.meta_image,
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
        )
        .unwrap();
        let payload_store = FilePageStore::open(
            &paths.payload_image,
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
        )
        .unwrap();
        let meta_hash_store = FilePageStore::open(
            &paths.meta_hash_image,
            tiered_hash_pages(params.bucket_count(), hash_page_size, trusted_levels).unwrap(),
            hash_page_size,
        )
        .unwrap();
        let payload_hash_store = FilePageStore::open(
            &paths.payload_hash_image,
            tiered_hash_pages(params.bucket_count(), hash_page_size, trusted_levels).unwrap(),
            hash_page_size,
        )
        .unwrap();
        let mut meta = TieredMerklePageStore::build(
            meta_store,
            meta_hash_store,
            direct_auth_store_id(level, CircuitAuthStoreKind::Meta),
            trusted_levels,
        )
        .unwrap();
        let mut payload = TieredMerklePageStore::build(
            payload_store,
            payload_hash_store,
            direct_auth_store_id(level, CircuitAuthStoreKind::Payload),
            trusted_levels,
        )
        .unwrap();
        PageStore::flush(&mut meta).unwrap();
        PageStore::flush(&mut payload).unwrap();
        CircuitStoreAuthState::new(meta.trusted_state(), payload.trusted_state())
            .save_atomic(&paths.auth_state)
            .unwrap();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_lookup_reads_direct_entries_without_pbc() {
        let db_dir = temp_dir("direct_lookup_db");
        let oram_dir = temp_dir("direct_lookup_img");
        std::fs::create_dir_all(&oram_dir).unwrap();
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Index, pack);
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Chunk, pack);

        let tables =
            DirectOramTables::open(&oram_dir, 2, 8, false, None, None, 0, false, true).unwrap();
        let got = direct_native_lookup_batch(
            &tables,
            &[fixture.found_sh, fixture.missing_sh, fixture.whale_sh],
        )
        .unwrap();

        let mut expected_payload = Vec::new();
        expected_payload.extend_from_slice(&fixture.chunks[3]);
        expected_payload.extend_from_slice(&fixture.chunks[4]);

        assert_eq!(got.len(), 3);
        assert!(got[0].found);
        assert!(!got[0].whale);
        assert_eq!(got[0].start_chunk_id, Some(3));
        assert_eq!(got[0].num_chunks, 2);
        assert_eq!(got[0].raw_chunk_data, expected_payload);

        assert!(!got[1].found);
        assert!(!got[1].whale);
        assert_eq!(got[1].raw_chunk_data.len(), 0);

        assert!(got[2].found);
        assert!(got[2].whale);
        assert_eq!(got[2].start_chunk_id, Some(1));
        assert_eq!(got[2].num_chunks, 0);
        assert_eq!(got[2].raw_chunk_data.len(), 0);

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_opens_controller_state_and_metadata_from_trusted_directory() {
        let db_dir = temp_dir("direct_lookup_trusted_db");
        let oram_dir = temp_dir("direct_lookup_trusted_img");
        let trusted_state_dir = temp_dir("direct_lookup_trusted_state");
        std::fs::create_dir_all(&oram_dir).unwrap();
        std::fs::create_dir_all(&trusted_state_dir).unwrap();
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        for level in [DirectLevel::Index, DirectLevel::Chunk] {
            build_test_direct_oram_image(&db_dir, &oram_dir, level, pack);
            let disk_paths = DirectOramPaths::new(&oram_dir, level);
            let trusted_paths =
                DirectOramPaths::new_with_trusted_state(&oram_dir, Some(&trusted_state_dir), level);
            std::fs::rename(&disk_paths.state, &trusted_paths.state).unwrap();
            std::fs::rename(&disk_paths.metadata, &trusted_paths.metadata).unwrap();
        }

        let tables = DirectOramTables::open_with_trusted_state(
            &oram_dir,
            Some(&trusted_state_dir),
            2,
            8,
            false,
            None,
            None,
            0,
            false,
            true,
        )
        .unwrap();
        let got = direct_native_lookup_batch(&tables, &[fixture.found_sh]).unwrap();
        assert!(got[0].found);
        assert!(trusted_state_dir.join("direct-index.state").exists());
        assert!(trusted_state_dir.join("direct-chunk.state").exists());
        assert!(!oram_dir.join("direct-index.state").exists());
        assert!(!oram_dir.join("direct-chunk.state").exists());

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
        std::fs::remove_dir_all(&trusted_state_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_lookup_spends_dummy_index_reads_for_empty_slots() {
        let db_dir = temp_dir("direct_lookup_padded_db");
        let oram_dir = temp_dir("direct_lookup_padded_img");
        std::fs::create_dir_all(&oram_dir).unwrap();
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Index, pack);
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Chunk, pack);

        let tables =
            DirectOramTables::open(&oram_dir, 2, 8, false, None, None, 0, false, true).unwrap();
        let got = tables
            .lookup_batch(
                &[
                    fixture.found_sh,
                    [0u8; pir_core::params::SCRIPT_HASH_SIZE],
                    fixture.missing_sh,
                ],
                &[true, false, true],
            )
            .unwrap();

        let mut expected_payload = Vec::new();
        expected_payload.extend_from_slice(&fixture.chunks[3]);
        expected_payload.extend_from_slice(&fixture.chunks[4]);

        assert_eq!(got.len(), 3);
        assert!(got[0].found);
        assert_eq!(got[0].raw_chunk_data, expected_payload);
        assert!(!got[1].found);
        assert_eq!(got[1].num_chunks, 0);
        assert_eq!(got[1].raw_chunk_data.len(), 0);
        assert!(!got[2].found);

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_same_db_requests_serialize_complete_state_commits() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        let db_dir = temp_dir("direct_lookup_serial_db");
        let oram_dir = temp_dir("direct_lookup_serial_img");
        std::fs::create_dir_all(&oram_dir).unwrap();
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Index, pack);
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Chunk, pack);
        build_test_direct_oram_auth_store(&oram_dir, DirectLevel::Index, 2);
        build_test_direct_oram_auth_store(&oram_dir, DirectLevel::Chunk, 2);

        let tables = Arc::new(
            DirectOramTables::open(&oram_dir, 2, 8, false, None, None, 0, true, true).unwrap(),
        );

        // Hold the per-DB transaction gate while both workers reach the
        // production lookup entrypoint. Neither request may complete until
        // the gate is released; afterwards both must commit cleanly in turn.
        let gate = tables.request_transaction.lock().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let mut workers = Vec::new();
        for _ in 0..2 {
            let tables = Arc::clone(&tables);
            let ready_tx = ready_tx.clone();
            let done_tx = done_tx.clone();
            let script_hash = fixture.found_sh;
            workers.push(std::thread::spawn(move || {
                ready_tx.send(()).unwrap();
                done_tx
                    .send(tables.lookup_batch(&[script_hash], &[true]))
                    .unwrap();
            }));
        }
        drop(ready_tx);
        drop(done_tx);
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        drop(gate);
        for _ in 0..2 {
            let got = done_rx
                .recv_timeout(Duration::from_secs(15))
                .expect("serialized direct ORAM request did not finish")
                .expect("serialized direct ORAM request failed");
            assert_eq!(got.len(), 1);
            assert!(got[0].found);
        }
        for worker in workers {
            worker.join().unwrap();
        }

        tables.index.check_not_poisoned().unwrap();
        tables.chunk.check_not_poisoned().unwrap();
        for name in [
            "direct-index.state.tmp",
            "direct-index.auth.state.tmp",
            "direct-chunk.state.tmp",
            "direct-chunk.auth.state.tmp",
        ] {
            assert!(
                !oram_dir.join(name).exists(),
                "serialized save left temporary file {name}"
            );
        }

        // Reopening validates that state and authenticated roots were saved as
        // one coherent sequence, not merely that neither worker saw ENOENT.
        drop(tables);
        let reopened =
            DirectOramTables::open(&oram_dir, 2, 8, false, None, None, 0, true, true).unwrap();
        let got = reopened.lookup_batch(&[fixture.found_sh], &[true]).unwrap();
        assert!(got[0].found);

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_different_databases_keep_independent_transaction_gates() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        let db_dir = temp_dir("direct_lookup_parallel_db");
        let oram_dir_0 = temp_dir("direct_lookup_parallel_img_0");
        let oram_dir_1 = temp_dir("direct_lookup_parallel_img_1");
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        for oram_dir in [&oram_dir_0, &oram_dir_1] {
            std::fs::create_dir_all(oram_dir).unwrap();
            build_test_direct_oram_image(&db_dir, oram_dir, DirectLevel::Index, pack);
            build_test_direct_oram_image(&db_dir, oram_dir, DirectLevel::Chunk, pack);
        }

        let db0 =
            DirectOramTables::open(&oram_dir_0, 2, 8, false, None, None, 0, false, true).unwrap();
        let db1 = Arc::new(
            DirectOramTables::open(&oram_dir_1, 2, 8, false, None, None, 0, false, true).unwrap(),
        );

        let db0_gate = db0.request_transaction.lock().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let worker_db1 = Arc::clone(&db1);
        let script_hash = fixture.found_sh;
        let worker = std::thread::spawn(move || {
            done_tx
                .send(worker_db1.lookup_batch(&[script_hash], &[true]))
                .unwrap();
        });

        let got = done_rx
            .recv_timeout(Duration::from_secs(15))
            .expect("DB1 request was incorrectly blocked by DB0 transaction")
            .expect("DB1 request failed while DB0 transaction was held");
        assert!(got[0].found);
        worker.join().unwrap();
        drop(db0_gate);

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir_0).ok();
        std::fs::remove_dir_all(&oram_dir_1).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_lookup_rejects_when_index_reads_exceed_budget() {
        let db_dir = temp_dir("direct_lookup_db");
        let oram_dir = temp_dir("direct_lookup_img");
        std::fs::create_dir_all(&oram_dir).unwrap();
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Index, pack);
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Chunk, pack);

        let tables =
            DirectOramTables::open(&oram_dir, 2, 1, false, None, None, 0, false, true).unwrap();
        let err = direct_native_lookup_batch(&tables, &[fixture.found_sh]).unwrap_err();
        assert!(err.contains("access budget 1 too small"));

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_lookup_rejects_when_chunk_demand_exceeds_remaining_budget() {
        let db_dir = temp_dir("direct_lookup_db");
        let oram_dir = temp_dir("direct_lookup_img");
        std::fs::create_dir_all(&oram_dir).unwrap();
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Index, pack);
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Chunk, pack);

        let tables =
            DirectOramTables::open(&oram_dir, 2, 3, false, None, None, 0, false, true).unwrap();
        let err = direct_native_lookup_batch(&tables, &[fixture.found_sh]).unwrap_err();
        assert!(err.contains("chunk demand 2 exceeds remaining access budget 1"));

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    // ─── S4: wire group_id slices the mmap ──────────────────────────────

    #[test]
    fn batch_query_group_id_out_of_range_returns_error() {
        let db = make_db();
        let q = HarmonyBatchQuery {
            level: 1,
            round_id: 7,
            sub_queries_per_group: 1,
            items: vec![HarmonyBatchItem {
                group_id: 250,
                sub_queries: vec![vec![0]],
            }],
            db_id: 0,
        };
        expect_error(harmony_batch_response(&db, &q), "out of range");
    }

    #[test]
    fn batch_query_unknown_level_returns_error() {
        // Sibling levels that don't exist for this DB (INDEX sib L1,
        // any CHUNK sib) and junk levels all map to a clean error.
        let db = make_db();
        for level in [2u8, 11, 19, 20, 29, 42, 255] {
            let q = HarmonyBatchQuery {
                level,
                round_id: 0,
                sub_queries_per_group: 1,
                items: vec![HarmonyBatchItem {
                    group_id: 0,
                    sub_queries: vec![vec![0]],
                }],
                db_id: 0,
            };
            expect_error(harmony_batch_response(&db, &q), "invalid level");
        }
    }

    // ─── S5: index count drives the pre-allocation ───────────────────────

    #[test]
    fn batch_query_too_many_indices_returns_error() {
        let db = make_db();
        let q = HarmonyBatchQuery {
            level: 0,
            round_id: 0,
            sub_queries_per_group: 1,
            items: vec![HarmonyBatchItem {
                group_id: 0,
                sub_queries: vec![vec![0; TEST_BINS + 1]],
            }],
            db_id: 0,
        };
        expect_error(harmony_batch_response(&db, &q), "too many indices");
    }

    // ─── Happy paths: legitimate traffic is byte-identical ───────────────

    #[test]
    fn batch_query_serves_main_and_sibling_levels_and_zero_fills() {
        let db = make_db();
        // level 10 = INDEX sibling L0 — exists in make_db.
        for level in [0u8, 1, 10] {
            let (sub_table, bin_size, _) = harmony_level_table(&db, level).unwrap();
            assert_eq!(sub_table.bins_per_table, TEST_BINS);
            let q = HarmonyBatchQuery {
                level,
                round_id: 4,
                sub_queries_per_group: 1,
                // One in-range index and one out-of-range *value*
                // (zero-filled — pre-existing wire behavior).
                items: vec![HarmonyBatchItem {
                    group_id: 2,
                    sub_queries: vec![vec![1, TEST_BINS as u32]],
                }],
                db_id: 0,
            };
            match harmony_batch_response(&db, &q) {
                Response::HarmonyBatchResult(r) => {
                    assert_eq!(r.level, level);
                    assert_eq!(r.items.len(), 1);
                    let data = &r.items[0].sub_results[0];
                    assert_eq!(data.len(), 2 * bin_size);
                    assert!(data[..bin_size].iter().all(|&b| b == 2u8 ^ 1u8));
                    assert!(data[bin_size..].iter().all(|&b| b == 0));
                }
                other => panic!(
                    "level {}: expected HarmonyBatchResult, got {:?}",
                    level, other
                ),
            }
        }
    }

    // ─── REQ_HARMONY_HINTS pre-validation + total hint computation ──────

    #[test]
    fn hints_validation_rejects_bad_level_group_and_count() {
        let db = make_db();
        // Unknown levels (11 = INDEX sib L1 doesn't exist, 20 = no
        // CHUNK sibs at all).
        for level in [2u8, 11, 20, 42] {
            assert!(validate_harmony_hints_request(&db, level, &[0]).is_err());
        }
        // group_id ≥ k (k = 75 for INDEX).
        assert!(validate_harmony_hints_request(&db, 0, &[0, 74]).is_ok());
        assert!(validate_harmony_hints_request(&db, 0, &[75]).is_err());
        assert!(validate_harmony_hints_request(&db, 0, &[250]).is_err());
        // More group_ids than groups (duplicate-amplification cap).
        let too_many = vec![0u8; INDEX_PARAMS.k + 1];
        assert!(validate_harmony_hints_request(&db, 0, &too_many).is_err());
        // The full legitimate sweep 0..k is accepted for every level
        // that exists.
        for (level, k) in [
            (0u8, INDEX_PARAMS.k),
            (1, CHUNK_PARAMS.k),
            (10, INDEX_PARAMS.k),
        ] {
            let all: Vec<u8> = (0..k as u8).collect();
            assert!(validate_harmony_hints_request(&db, level, &all).is_ok());
        }
    }

    #[test]
    fn compute_hints_invalid_level_returns_err_not_panic() {
        // Previously `panic!("invalid hint level {}")` inside the rayon
        // pool → abort.
        let db = make_db();
        let key = [7u8; 16];
        let backend = hint_pool::default_prp_backend();
        assert!(compute_hints_for_group(&db, &key, backend, 42, 0).is_err());
        assert!(compute_hints_for_group(&db, &key, backend, 11, 0).is_err());
    }

    #[test]
    fn compute_hints_group_out_of_range_returns_err_not_panic() {
        // Previously sliced the mmap at group 250 of 75 → panic → abort.
        let db = make_db();
        let key = [7u8; 16];
        assert!(
            compute_hints_for_group(&db, &key, hint_pool::default_prp_backend(), 0, 250).is_err()
        );
    }

    #[test]
    fn compute_hints_happy_path_still_serves() {
        let db = make_db();
        let key = [7u8; 16];
        let (group_id, n, t, m, flat) =
            compute_hints_for_group(&db, &key, hint_pool::default_prp_backend(), 0, 3)
                .expect("legitimate hint request must still be served");
        assert_eq!(group_id, 3);
        assert!(n as usize >= TEST_BINS);
        assert!(t > 0 && m > 0);
        assert_eq!(flat.len(), m as usize * db.index.params.bin_size());
    }

    #[test]
    fn compute_hints_unsupported_backend_returns_err() {
        let db = make_db();
        let error = compute_hints_for_group(&db, &[7u8; 16], 0xfe, 0, 3).unwrap_err();
        assert!(error.contains("unsupported"));
    }

    #[test]
    fn v2_half_pending_token_rejects_a_different_database_id() {
        assert!(validate_harmony_v2_half_database(0, 0).is_ok());
        assert!(validate_harmony_v2_half_database(7, 7).is_ok());
        let error = validate_harmony_v2_half_database(0, 1).unwrap_err();
        assert!(error.contains("bound to db 0"));
        assert!(error.contains("requested db 1"));
    }
}

mod cli_informational_tests {
    //! `--help`/`--version` are answered before the parser runs.
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        std::iter::once("unified_server")
            .chain(items.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn help_and_version_are_answered_only_as_the_sole_argument() {
        let help = informational_argument_v1(&argv(&["--help"])).expect("--help");
        assert!(help.contains("--serve-queries"));
        assert_eq!(
            informational_argument_v1(&argv(&["-h"])),
            Some(USAGE_V1.to_owned())
        );
        let version = informational_argument_v1(&argv(&["--version"])).expect("--version");
        assert!(version.starts_with("unified_server "));
        assert!(version.contains(" git_rev=") && version.contains(" binary_sha256="));
        assert_eq!(
            informational_argument_v1(&argv(&["-V"])),
            Some(version_line_v1())
        );
        assert_eq!(informational_argument_v1(&argv(&[])), None);
        assert_eq!(informational_argument_v1(&argv(&["--port", "8091"])), None);
        assert_eq!(
            informational_argument_v1(&argv(&["--help", "--port"])),
            None
        );
    }
}

mod oram_only_tests {
    use super::*;
    use pir_core::cuckoo::HeaderAnchor;
    use pir_core::seeds::{DeltaSeeds, SnapshotSeeds};
    use runtime::table::DatabaseType;
    use std::path::Path;

    /// Lay a committed V2 proof out the way `load_database_proof_bundle`
    /// reads it (the web copy flattens `server-db/MANIFEST.toml`).
    fn proof_dir(name: &str) -> tempfile::TempDir {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../web/public/proofs/oram-source")
            .join(name);
        let dir = tempfile::tempdir().unwrap();
        for file in [
            "build-evidence.bin",
            "root-bundle-payload.bin",
            "build-evidence.sev-snp-report.bin",
            "database.manifest.sha256",
            "all-artifacts.manifest.sha256",
        ] {
            std::fs::copy(source.join(file), dir.path().join(file)).unwrap();
        }
        std::fs::create_dir(dir.path().join("server-db")).unwrap();
        std::fs::copy(
            source.join("server-db-MANIFEST.toml"),
            dir.path().join("server-db/MANIFEST.toml"),
        )
        .unwrap();
        dir
    }

    fn descriptor(db_type: DatabaseType, base_height: u32, height: u32) -> DatabaseDescriptor {
        DatabaseDescriptor {
            name: "test".into(),
            db_type,
            base_height,
            height,
            index_params: INDEX_PARAMS,
            chunk_params: CHUNK_PARAMS,
        }
    }

    #[test]
    fn oram_only_databases_take_geometry_anchor_and_manifest_from_the_v2_evidence() {
        let snapshot = proof_dir("mainnet-948454-v2");
        let db = io::load_oram_only_database_v1(
            0,
            snapshot.path(),
            descriptor(DatabaseType::Full, 0, 948_454),
        )
        .unwrap();
        assert_eq!(
            hex::encode(db.manifest_root.unwrap()),
            "91421138ba94e44665bef2617af296b1c1847dea13c4df29b565012d1e0b74a6"
        );
        assert!(db.manifest.as_ref().unwrap().direct_oram.is_some());
        assert_eq!(
            (db.index.bins_per_table, db.chunk.bins_per_table),
            (567_558, 1_066_928)
        );
        let Some(HeaderAnchor::Snapshot(anchor)) = db.index.anchor else {
            panic!("snapshot anchor expected");
        };
        assert_eq!(anchor.block_height, 948_454);
        let seeds = SnapshotSeeds::derive(&anchor);
        assert_eq!(
            (
                db.index.master_seed,
                db.index.tag_seed,
                db.chunk.master_seed
            ),
            (seeds.index_master, seeds.index_tag, seeds.chunk_master)
        );
        assert!(db.db_proof_v2.is_some());
        assert!(db.index.try_group_bytes(0).is_none());

        let delta = proof_dir("delta-940611-948454-v2");
        let db = io::load_oram_only_database_v1(
            1,
            delta.path(),
            descriptor(DatabaseType::Delta, 940_611, 948_454),
        )
        .unwrap();
        assert_eq!(
            hex::encode(db.manifest_root.unwrap()),
            "047a5b6713bf0df29d9de308fb47ff757243e365a9818cf746f399bea457d00c"
        );
        assert_eq!(
            (db.index.bins_per_table, db.chunk.bins_per_table),
            (53_282, 112_332)
        );
        let Some(HeaderAnchor::Delta(anchor)) = db.chunk.anchor else {
            panic!("delta anchor expected");
        };
        assert_eq!(
            (anchor.from.block_height, anchor.to.block_height),
            (940_611, 948_454)
        );
        let seeds = DeltaSeeds::derive(&anchor);
        assert_eq!(db.chunk.master_seed, seeds.chunk_master);
    }

    #[test]
    fn oram_only_refuses_a_configuration_the_evidence_does_not_describe() {
        let snapshot = proof_dir("mainnet-948454-v2");
        for wrong in [
            descriptor(DatabaseType::Full, 0, 948_453),
            descriptor(DatabaseType::Delta, 940_611, 948_454),
        ] {
            let Err(error) = io::load_oram_only_database_v1(0, snapshot.path(), wrong) else {
                panic!("a configuration the evidence does not describe was accepted");
            };
            assert!(error.contains("does not match"), "{error}");
        }
        let tampered = proof_dir("mainnet-948454-v2");
        let manifest = tampered.path().join("server-db/MANIFEST.toml");
        let mut bytes = std::fs::read(&manifest).unwrap();
        bytes.push(b'\n');
        std::fs::write(&manifest, bytes).unwrap();
        let Err(error) = io::load_oram_only_database_v1(
            0,
            tampered.path(),
            descriptor(DatabaseType::Full, 0, 948_454),
        ) else {
            panic!("a manifest the evidence does not bind was accepted");
        };
        assert!(error.contains("the build evidence binds"), "{error}");
    }

    #[test]
    fn oram_only_servers_attest_the_tagged_root_of_each_manifest() {
        let snapshot = proof_dir("mainnet-948454-v2");
        let db = io::load_oram_only_database_v1(
            0,
            snapshot.path(),
            descriptor(DatabaseType::Full, 0, 948_454),
        )
        .unwrap();
        let root = db.manifest_root.unwrap();
        let databases = [db];
        assert_eq!(
            state::attested_manifest_roots(&databases, false),
            vec![root]
        );
        assert_eq!(
            state::attested_manifest_roots(&databases, true),
            vec![pir_core::attest::oram_only_manifest_root(&root)]
        );
    }
}
