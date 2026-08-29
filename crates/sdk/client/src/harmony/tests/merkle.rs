use super::super::*;
use super::fixtures::*;
use crate::transport::mock::MockTransport;
use pir_core::merkle::{compute_bin_leaf_hash, compute_parent_n, sha256, Hash256, ZERO_HASH};
use pir_db_attest::BuildKind;
use pir_sdk::BufferingLeakageRecorder;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

#[test]
fn split_inspector_quarantines_found_and_absent_results() {
    let mut found = QueryResult::empty();
    found.is_whale = true;
    found.merkle_verified = true;
    let results = vec![Some(found), None];
    let traces = vec![
        QueryTraces {
            index_bins: vec![IndexBinTrace {
                pbc_group: 3,
                bin_index: 7,
                bin_content: vec![0x31],
            }],
            matched_index_idx: Some(0),
            chunk_bins: vec![ChunkBinTrace {
                pbc_group: 4,
                bin_index: 8,
                bin_content: vec![0x41],
            }],
        },
        QueryTraces {
            index_bins: vec![IndexBinTrace {
                pbc_group: 5,
                bin_index: 9,
                bin_content: vec![0x51],
            }],
            matched_index_idx: None,
            chunk_bins: Vec::new(),
        },
    ];

    let attached = attach_inspector_traces(results, traces).unwrap();
    assert_eq!(attached.len(), 2);
    assert!(attached.iter().all(|result| result.is_some()));
    assert!(attached
        .iter()
        .flatten()
        .all(|result| !result.merkle_verified));
    assert_eq!(attached[0].as_ref().unwrap().matched_index_idx, Some(0));
    assert_eq!(attached[0].as_ref().unwrap().chunk_bins.len(), 1);
    assert!(attached[1].as_ref().unwrap().entries.is_empty());
    assert_eq!(attached[1].as_ref().unwrap().index_bins.len(), 1);
}

#[test]
fn split_inspector_rejects_result_trace_length_skew() {
    let error = attach_inspector_traces(vec![Some(QueryResult::empty())], Vec::new())
        .expect_err("length skew must fail closed");
    assert!(error.to_string().contains("length mismatch"), "{error}");
}

#[test]
fn split_verifier_shape_rejects_missing_or_empty_results() {
    let db_info = session_db_info();
    for results in [
        Vec::<Option<QueryResult>>::new(),
        vec![None],
        vec![Some(QueryResult::empty())],
    ] {
        let error = validate_inspector_results(&results, &db_info)
            .expect_err("incomplete inspector proof must fail closed");
        assert!(error.is_verification_failure(), "{error}");
    }
}

#[test]
fn split_verifier_shape_accepts_exact_two_index_traces() {
    let db_info = session_db_info();
    let result = QueryResult {
        entries: Vec::new(),
        is_whale: false,
        merkle_verified: false,
        raw_chunk_data: None,
        index_bins: vec![
            BucketRef {
                pbc_group: 0,
                bin_index: 2,
                bin_content: vec![0; INDEX_SLOT_SIZE * INDEX_SLOTS_PER_BIN],
            },
            BucketRef {
                pbc_group: 0,
                bin_index: 3,
                bin_content: vec![0; INDEX_SLOT_SIZE * INDEX_SLOTS_PER_BIN],
            },
        ],
        chunk_bins: Vec::new(),
        matched_index_idx: None,
    };
    validate_inspector_results(&[Some(result)], &db_info).unwrap();
}

fn semantic_fixture(db_info: &DatabaseInfo, script_hash: ScriptHash) -> QueryResult {
    let group = pir_core::hash::derive_groups_3(&script_hash, db_info.index_k as usize)[0];
    let tag = pir_core::hash::compute_tag(db_info.tag_seed, &script_hash);
    let nonmatch = tag.wrapping_add(1);
    let mut index_bins = Vec::new();
    for h in 0..INDEX_CUCKOO_NUM_HASHES {
        let mut content = vec![0u8; INDEX_SLOT_SIZE * INDEX_SLOTS_PER_BIN];
        for slot in 0..INDEX_SLOTS_PER_BIN {
            let base = slot * INDEX_SLOT_SIZE;
            content[base..base + TAG_SIZE].copy_from_slice(&nonmatch.to_le_bytes());
        }
        if h == 0 {
            content[..TAG_SIZE].copy_from_slice(&tag.to_le_bytes());
            content[TAG_SIZE..TAG_SIZE + 4].copy_from_slice(&5u32.to_le_bytes());
            content[TAG_SIZE + 4] = 1;
        }
        let key = pir_core::hash::derive_cuckoo_key(db_info.index_master_seed, group, h);
        let bin_index =
            pir_core::hash::cuckoo_hash(&script_hash, key, db_info.index_bins as usize) as u32;
        index_bins.push(BucketRef {
            pbc_group: group as u32,
            bin_index,
            bin_content: content,
        });
    }

    let mut raw = Vec::new();
    pir_core::codec::write_varint(1, &mut raw);
    raw.extend_from_slice(&[0x55; 32]);
    pir_core::codec::write_varint(3, &mut raw);
    pir_core::codec::write_varint(11, &mut raw);
    raw.resize(pir_core::params::CHUNK_SIZE, 0);
    let chunk_id = 5u32;
    let chunk_group = pir_core::hash::derive_int_groups_3(chunk_id, db_info.chunk_k as usize)[0];
    let chunk_key = pir_core::hash::derive_cuckoo_key(db_info.chunk_master_seed, chunk_group, 0);
    let chunk_bin_index =
        pir_core::hash::cuckoo_hash_int(chunk_id, chunk_key, db_info.chunk_bins as usize) as u32;
    let mut chunk_content = vec![0u8; CHUNK_SLOT_SIZE * CHUNK_SLOTS_PER_BIN];
    chunk_content[..4].copy_from_slice(&chunk_id.to_le_bytes());
    chunk_content[4..4 + pir_core::params::CHUNK_SIZE].copy_from_slice(&raw);

    QueryResult {
        entries: decode_utxo_entries(&raw).unwrap(),
        is_whale: false,
        merkle_verified: false,
        raw_chunk_data: None,
        index_bins,
        chunk_bins: vec![BucketRef {
            pbc_group: chunk_group as u32,
            bin_index: chunk_bin_index,
            bin_content: chunk_content,
        }],
        matched_index_idx: Some(0),
    }
}

#[test]
fn verified_inspector_semantics_bind_input_entries_and_all_chunks() {
    let db_info = sample_db_info();
    let script_hash = [0x41; 20];
    let result = semantic_fixture(&db_info, script_hash);
    validate_inspector_semantics(&[script_hash], &[Some(result.clone())], &db_info).unwrap();

    let mut missing_chunk = result.clone();
    missing_chunk.chunk_bins.clear();
    let error = validate_inspector_semantics(&[script_hash], &[Some(missing_chunk)], &db_info)
        .expect_err("INDEX-declared CHUNK omission must fail closed");
    assert!(error.is_verification_failure(), "{error}");

    let mut forged_entries = result.clone();
    forged_entries.entries[0].amount_sats += 1;
    let error = validate_inspector_semantics(&[script_hash], &[Some(forged_entries)], &db_info)
        .expect_err("entries not decoded from verified bins must fail closed");
    assert!(error.is_verification_failure(), "{error}");

    let error = validate_inspector_semantics(&[[0x42; 20]], &[Some(result)], &db_info)
        .expect_err("a result cannot be rebound to another input");
    assert!(error.is_verification_failure(), "{error}");
}

#[tokio::test]
async fn malicious_harmony_provider_cannot_omit_an_expected_chunk() {
    let db_info = sample_db_info();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mut client = HarmonyClient::new("mock://hint", "mock://query");
    // Keep this synthetic 32-bin fixture focused on the expected
    // fail-closed verification error, not random relocation cycles.
    client.set_master_key([0x42; 16]);
    client.connect_with_transport(
        Box::new(MockTransport::new("mock://hint")),
        Box::new(ZeroHarmonyQueryTransport::new(sent.clone())),
    );
    populate_main_groups(&mut client, &db_info);

    let error = client
        .query_chunk_phase_batched(&[vec![5]], &db_info)
        .await
        .expect_err("an intact Harmony response that omits a CHUNK must fail closed");
    assert!(error.is_verification_failure(), "{error}");
    assert_eq!(sent.lock().unwrap().len(), CHUNK_CUCKOO_NUM_HASHES);
}

#[tokio::test]
async fn split_verifier_rejects_database_without_merkle_commitment() {
    let db_info = sample_db_info();
    let mut client = HarmonyClient::new("mock://hint", "mock://query");
    client.connect_with_transport(
        Box::new(MockTransport::new("mock://hint")),
        Box::new(MockTransport::new("mock://query")),
    );
    client.catalog = Some(DatabaseCatalog {
        databases: vec![db_info.clone()],
    });
    client
        .install_verified_database_roots(session_roots(&db_info))
        .unwrap();
    let error = client
        .verify_merkle_batch_for_results(&[None], db_info.db_id)
        .await
        .expect_err("Merkle-unavailable split verification must fail closed");
    assert!(error.is_verification_failure(), "{error}");
}

#[test]
fn two_address_index_plan_is_one_payment_logical_job_when_it_fits_one_pbc_round() {
    let candidates = vec![[0, 1, 2], [1, 2, 3]];
    let rounds = pir_core::pbc::pbc_plan_rounds(&candidates, 4, NUM_HASHES, 500);
    assert_eq!(rounds.len(), 1);
    assert_eq!(rounds[0].len(), 2);
}

#[tokio::test]
async fn two_address_split_inspector_uses_one_index_pair_and_one_batch_verdict() {
    let mut db_info = sample_db_info();
    db_info.has_bucket_merkle = true;
    let script_hashes = [[0x39; 20], [0x3a; 20]];
    let candidates: Vec<[usize; NUM_HASHES]> = script_hashes
        .iter()
        .map(|hash| pir_core::hash::derive_groups_3(hash, db_info.index_k as usize))
        .collect();
    let rounds =
        pir_core::pbc::pbc_plan_rounds(&candidates, db_info.index_k as usize, NUM_HASHES, 500);
    assert_eq!(rounds.len(), 1);
    assert_eq!(rounds[0].len(), 2);
    assert_ne!(rounds[0][0].1, rounds[0][1].1);

    let sent = Arc::new(Mutex::new(Vec::new()));
    let mut client = HarmonyClient::new("mock://hint", "mock://query");
    // This test exercises batching, leakage accounting, and the shared
    // Merkle verdict. Pin the synthetic 32-bin fixture's PRP layout so
    // unrelated relocation-chain randomness cannot make it flaky.
    client.set_master_key([0x42; 16]);
    client.connect_with_transport(
        Box::new(MockTransport::new("mock://hint")),
        Box::new(ZeroHarmonyQueryTransport::new(sent.clone())),
    );
    client.catalog = Some(DatabaseCatalog {
        databases: vec![db_info.clone()],
    });

    let index_top = zero_tree_top(db_info.index_bins, INDEX_SLOT_SIZE * INDEX_SLOTS_PER_BIN);
    let chunk_top = zero_tree_top(db_info.chunk_bins, CHUNK_SLOT_SIZE * CHUNK_SLOTS_PER_BIN);
    let mut tree_tops = Vec::new();
    tree_tops.extend((0..db_info.index_k).map(|_| index_top.clone()));
    tree_tops.extend((0..db_info.chunk_k).map(|_| chunk_top.clone()));
    let mut ordered_roots = Vec::with_capacity(tree_tops.len() * 32);
    for top in &tree_tops {
        ordered_roots.extend_from_slice(&top.root().unwrap());
    }
    let mut roots = session_roots(&db_info);
    roots.bucket_super_root = sha256(&ordered_roots);
    client.install_verified_database_roots(roots).unwrap();
    client.verified_tree_tops.insert(db_info.db_id, tree_tops);
    populate_main_groups(&mut client, &db_info);

    let leakage = Arc::new(BufferingLeakageRecorder::new());
    client.set_leakage_recorder(Some(leakage.clone()));
    let mut results = client
        .query_batch_with_inspector(&script_hashes, db_info.db_id)
        .await
        .unwrap();
    let raw_profile = leakage.take_profile("harmony");
    assert_eq!(raw_profile.count_of_kind(&RoundKind::Index), 2);
    assert_eq!(raw_profile.count_of_kind(&RoundKind::Chunk), 2);
    assert!(results
        .iter()
        .flatten()
        .all(|result| !result.merkle_verified));

    let headers: Vec<(u8, u16, usize)> = sent
        .lock()
        .unwrap()
        .iter()
        .map(|request| harmony_request_header(request))
        .collect();
    assert_eq!(headers, vec![(0, 0, 4), (0, 1, 4), (1, 0, 4), (1, 1, 4)]);

    results[0]
        .as_mut()
        .unwrap()
        .index_bins
        .first_mut()
        .unwrap()
        .bin_content[0] ^= 1;
    let verdicts = client
        .verify_merkle_batch_for_results(&results, db_info.db_id)
        .await
        .unwrap();
    assert_eq!(verdicts, vec![false, true]);
    assert!(results
        .iter()
        .flatten()
        .all(|result| !result.merkle_verified));
    assert_eq!(sent.lock().unwrap().len(), 4);
}
