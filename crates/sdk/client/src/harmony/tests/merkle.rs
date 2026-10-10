use super::super::*;
use super::fixtures::*;
use crate::transport::mock::MockTransport;
use pir_core::merkle::sha256;
use pir_sdk::BufferingLeakageRecorder;
use std::sync::{Arc, Mutex};

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

#[test]
fn two_address_index_plan_fits_one_pbc_round() {
    let candidates = vec![[0, 1, 2], [1, 2, 3]];
    let rounds = pir_core::pbc::pbc_plan_rounds(&candidates, 4, NUM_HASHES, 500);
    assert_eq!(rounds.len(), 1);
    assert_eq!(rounds[0].len(), 2);
}

#[tokio::test]
async fn two_address_batch_uses_one_index_pair_and_one_chunk_pair() {
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
    // This test exercises batching and leakage accounting. Pin the
    // synthetic 32-bin fixture's PRP layout so unrelated relocation-chain
    // randomness cannot make it flaky.
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
    let step = SyncStep::from_db_info(&db_info);
    let (results, traces) = client
        .execute_step_unverified(&script_hashes, &step, &db_info)
        .await
        .unwrap();
    let raw_profile = leakage.take_profile("harmony");
    assert_eq!(raw_profile.count_of_kind(&RoundKind::Index), 2);
    assert_eq!(raw_profile.count_of_kind(&RoundKind::Chunk), 2);
    assert_eq!(results.len(), 2);
    assert!(traces
        .iter()
        .all(|trace| trace.index_bins.len() == INDEX_CUCKOO_NUM_HASHES));

    let headers: Vec<(u8, u16, usize)> = sent
        .lock()
        .unwrap()
        .iter()
        .map(|request| harmony_request_header(request))
        .collect();
    assert_eq!(headers, vec![(0, 0, 4), (0, 1, 4), (1, 0, 4), (1, 1, 4)]);
}
