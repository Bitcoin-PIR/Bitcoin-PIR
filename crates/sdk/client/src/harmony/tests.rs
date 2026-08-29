use super::*;
use crate::transport::mock::MockTransport;
use pir_core::merkle::{compute_bin_leaf_hash, compute_parent_n, sha256, Hash256, ZERO_HASH};
use pir_db_attest::BuildKind;
use pir_sdk::BufferingLeakageRecorder;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

#[derive(Default)]
struct RecordingSyncProgress {
    events: Mutex<Vec<String>>,
}

impl pir_sdk::SyncProgress for RecordingSyncProgress {
    fn on_step_start(&self, step_index: usize, total_steps: usize, _description: &str) {
        self.events
            .lock()
            .unwrap()
            .push(format!("start:{step_index}/{total_steps}"));
    }

    fn on_step_progress(&self, step_index: usize, progress: f32) {
        self.events
            .lock()
            .unwrap()
            .push(format!("progress:{step_index}:{progress}"));
    }

    fn on_step_complete(&self, step_index: usize) {
        self.events
            .lock()
            .unwrap()
            .push(format!("step-complete:{step_index}"));
    }

    fn on_complete(&self, synced_height: u32) {
        self.events
            .lock()
            .unwrap()
            .push(format!("complete:{synced_height}"));
    }

    fn on_error(&self, error: &PirError) {
        self.events.lock().unwrap().push(format!("error:{error}"));
    }
}

/// Test-only query server for an all-zero Harmony database. It derives a
/// canonical zero response from each client request, preserving level,
/// round id, group order, and exact response width while sharing the sent
/// transcript with the assertion side of the test.
struct ZeroHarmonyQueryTransport {
    pending: VecDeque<Vec<u8>>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ZeroHarmonyQueryTransport {
    fn new(sent: Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
        Self {
            pending: VecDeque::new(),
            sent,
        }
    }
}

#[async_trait::async_trait]
impl PirTransport for ZeroHarmonyQueryTransport {
    async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
        self.sent.lock().unwrap().push(data.clone());
        self.pending.push_back(data);
        Ok(())
    }

    async fn recv(&mut self) -> PirResult<Vec<u8>> {
        let request = self
            .pending
            .pop_front()
            .ok_or_else(|| PirError::Protocol("zero Harmony transport has no request".into()))?;
        Ok(zero_harmony_response(&request))
    }

    async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
        self.sent.lock().unwrap().push(request.to_vec());
        let frame = zero_harmony_response(request);
        Ok(frame[4..].to_vec())
    }

    async fn close(&mut self) -> PirResult<()> {
        Ok(())
    }

    fn url(&self) -> &str {
        "mock://zero-harmony-query"
    }
}

fn harmony_request_header(request: &[u8]) -> (u8, u16, usize) {
    assert!(request.len() >= 11);
    assert_eq!(request[4], REQ_HARMONY_BATCH_QUERY);
    (
        request[5],
        u16::from_le_bytes(request[6..8].try_into().unwrap()),
        u16::from_le_bytes(request[8..10].try_into().unwrap()) as usize,
    )
}

fn zero_harmony_response(request: &[u8]) -> Vec<u8> {
    let (level, round_id, num_groups) = harmony_request_header(request);
    assert_eq!(request[10], 1);
    let row_width = match level {
        0 => INDEX_SLOT_SIZE * INDEX_SLOTS_PER_BIN,
        1 => CHUNK_SLOT_SIZE * CHUNK_SLOTS_PER_BIN,
        _ => panic!("unexpected Harmony level {level}"),
    };
    let mut pos = 11;
    let mut groups = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        let group_id = request[pos];
        let count = u32::from_le_bytes(request[pos + 1..pos + 5].try_into().unwrap()) as usize;
        pos += 5 + count * 4;
        groups.push((group_id, vec![0; count * row_width]));
    }
    let group_refs: Vec<(u8, &[u8])> = groups
        .iter()
        .map(|(group_id, data)| (*group_id, data.as_slice()))
        .collect();
    response_frame(harmony_batch_body(level, round_id, &group_refs))
}

fn zero_tree_top(bins: u32, row_width: usize) -> TreeTop {
    let zero_row = vec![0; row_width];
    let mut levels: Vec<Vec<Hash256>> = vec![(0..bins)
        .map(|bin_index| compute_bin_leaf_hash(bin_index, &zero_row))
        .collect()];
    while levels.last().unwrap().len() > 1 {
        let previous = levels.last().unwrap();
        let mut next = Vec::with_capacity(previous.len().div_ceil(BUCKET_MERKLE_ARITY));
        for offset in (0..previous.len()).step_by(BUCKET_MERKLE_ARITY) {
            let mut children = [ZERO_HASH; BUCKET_MERKLE_ARITY];
            let available = (previous.len() - offset).min(BUCKET_MERKLE_ARITY);
            children[..available].copy_from_slice(&previous[offset..offset + available]);
            next.push(compute_parent_n(&children));
        }
        levels.push(next);
    }
    TreeTop {
        cache_from_level: 0,
        levels,
    }
}

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

fn session_db_info() -> DatabaseInfo {
    DatabaseInfo {
        db_id: 7,
        kind: DatabaseKind::Full,
        name: "session-test".into(),
        height: 100,
        index_bins: 8,
        chunk_bins: 8,
        index_k: 1,
        chunk_k: 1,
        tag_seed: 0,
        dpf_n_index: 3,
        dpf_n_chunk: 3,
        has_bucket_merkle: true,
        index_master_seed: 1,
        chunk_master_seed: 2,
        anchor_kind: 0,
        anchor_bytes: Vec::new(),
    }
}

fn session_roots(db: &DatabaseInfo) -> VerifiedDatabaseRoots {
    VerifiedDatabaseRoots {
        db_id: db.db_id,
        manifest_root: [0; 32],
        build_kind: BuildKind::Snapshot,
        from_height: db.base_height(),
        from_block_hash: [0; 32],
        height: db.height,
        block_hash: [1; 32],
        muhash: [2; 32],
        bucket_super_root: [3; 32],
        onion_super_root: [4; 32],
        onion_entry_size: 3328,
        params_hash: [5; 32],
        network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
        builder_binary_sha256: [6; 32],
        builder_git_commit: "session-test".into(),
        onion_layout_v2: None,
    }
}

#[tokio::test]
async fn empty_sync_requires_verified_roots_and_preflight_before_skipping_query_work() {
    let db = session_db_info();
    let mut client = HarmonyClient::new("mock://hint", "mock://query");
    client.connect_with_transport(
        Box::new(MockTransport::new("mock://hint")),
        Box::new(MockTransport::new("mock://query")),
    );
    client.catalog = Some(DatabaseCatalog {
        databases: vec![db.clone()],
    });
    client.set_root_policy(RootPolicy::RequireVerified);

    let error = client.sync(&[], None).await.unwrap_err();
    assert!(matches!(error, PirError::VerificationFailed(_)));

    client
        .install_verified_database_roots(session_roots(&db))
        .unwrap();
    let preflight_error = client.sync(&[], None).await.unwrap_err();
    assert!(
        preflight_error
            .to_string()
            .contains("mock: no enqueued response"),
        "installed roots must not let empty sync bypass tree-top preflight: {preflight_error}"
    );

    // Verified roots/tree-tops satisfy strict preflight. With no hint
    // state or queued responses, success proves execute_step skips hint
    // acquisition, Payment-V1 planning, and query traffic for empty input.
    seed_verified_session(&mut client);
    let sync = client.sync(&[], None).await.unwrap();
    let recorder = RecordingSyncProgress::default();
    let progress = client
        .sync_with_progress(&[], None, &recorder)
        .await
        .unwrap();

    for result in [sync, progress] {
        assert!(result.results.is_empty());
        assert_eq!(result.synced_height, db.height);
        assert!(result.was_fresh_sync);
    }
    assert_eq!(
        recorder.events.lock().unwrap().as_slice(),
        [
            "start:0/1",
            "progress:0:1",
            "step-complete:0",
            "complete:100"
        ]
    );
    assert!(client.is_connected());
}

fn seed_verified_session(client: &mut HarmonyClient) -> u8 {
    let db = session_db_info();
    let db_id = db.db_id;
    client.catalog = Some(DatabaseCatalog {
        databases: vec![db.clone()],
    });
    client
        .install_verified_database_roots(session_roots(&db))
        .unwrap();
    client.verified_tree_tops.insert(
        db_id,
        vec![TreeTop {
            cache_from_level: 0,
            levels: vec![vec![[7; 32]]],
        }],
    );
    db_id
}

struct CloseTrackingTransport {
    url: &'static str,
    closed: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl PirTransport for CloseTrackingTransport {
    async fn send(&mut self, _data: Vec<u8>) -> PirResult<()> {
        unreachable!("secondary transport must not be used during upgrade")
    }

    async fn recv(&mut self) -> PirResult<Vec<u8>> {
        unreachable!("secondary transport must not be used during upgrade")
    }

    async fn roundtrip(&mut self, _request: &[u8]) -> PirResult<Vec<u8>> {
        unreachable!("secondary transport must not be used during upgrade")
    }

    async fn close(&mut self) -> PirResult<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn url(&self) -> &str {
        self.url
    }
}

struct ScriptedCloseTransport {
    url: &'static str,
    responses: VecDeque<Vec<u8>>,
    closed: Arc<AtomicBool>,
    sends: Arc<AtomicUsize>,
}

impl ScriptedCloseTransport {
    fn new(
        url: &'static str,
        responses: impl IntoIterator<Item = Vec<u8>>,
        closed: Arc<AtomicBool>,
        sends: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            url,
            responses: responses.into_iter().collect(),
            closed,
            sends,
        }
    }
}

#[async_trait::async_trait]
impl PirTransport for ScriptedCloseTransport {
    async fn send(&mut self, _data: Vec<u8>) -> PirResult<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(PirError::ConnectionClosed(
                "scripted transport closed".into(),
            ));
        }
        self.sends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn recv(&mut self) -> PirResult<Vec<u8>> {
        self.responses
            .pop_front()
            .ok_or_else(|| PirError::Protocol("scripted transport has no response".into()))
    }

    async fn roundtrip(&mut self, _request: &[u8]) -> PirResult<Vec<u8>> {
        unreachable!("scripted half-stream transport only uses send/recv")
    }

    async fn close(&mut self) -> PirResult<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn url(&self) -> &str {
        self.url
    }
}

struct PendingCloseTransport {
    url: &'static str,
    closed: Arc<AtomicBool>,
    sends: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl PirTransport for PendingCloseTransport {
    async fn send(&mut self, _data: Vec<u8>) -> PirResult<()> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn recv(&mut self) -> PirResult<Vec<u8>> {
        std::future::pending().await
    }

    async fn roundtrip(&mut self, _request: &[u8]) -> PirResult<Vec<u8>> {
        unreachable!("pending half-stream transport only uses send/recv")
    }

    async fn close(&mut self) -> PirResult<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn url(&self) -> &str {
        self.url
    }
}

fn handshake_frame(server_eph_byte: u8) -> Vec<u8> {
    let mut payload = vec![0x06];
    payload.extend_from_slice(&[server_eph_byte; 32]);
    let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&payload);
    frame
}

fn response_frame(body: Vec<u8>) -> Vec<u8> {
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

fn harmony_batch_body(level: u8, round_id: u16, groups: &[(u8, &[u8])]) -> Vec<u8> {
    let mut body = vec![RESP_HARMONY_BATCH_QUERY, level];
    body.extend_from_slice(&round_id.to_le_bytes());
    body.extend_from_slice(&(groups.len() as u16).to_le_bytes());
    body.push(1);
    for (group_id, result) in groups {
        body.push(*group_id);
        body.extend_from_slice(&(result.len() as u32).to_le_bytes());
        body.extend_from_slice(result);
    }
    body
}

fn v1_hint_frame(group_id: u8, n: u32, t: u32, m: u32, hint_bytes: usize) -> Vec<u8> {
    let mut body = vec![RESP_HARMONY_HINTS, group_id];
    body.extend_from_slice(&n.to_le_bytes());
    body.extend_from_slice(&t.to_le_bytes());
    body.extend_from_slice(&m.to_le_bytes());
    body.resize(body.len() + hint_bytes, 0);
    response_frame(body)
}

fn v2_pool_unavailable_frame() -> Vec<u8> {
    v2_error_frame(V2_HINT_POOL_UNAVAILABLE)
}

fn v2_error_frame(reason: &str) -> Vec<u8> {
    let mut body = vec![RESP_ERROR];
    body.extend_from_slice(&(reason.len() as u32).to_le_bytes());
    body.extend_from_slice(reason.as_bytes());
    response_frame(body)
}

fn v2_key_preamble_frame(backend: u8, level: u8, total_groups: u8, key: [u8; 16]) -> Vec<u8> {
    let mut body = vec![RESP_HARMONY_HINTS_KEY, backend, level, total_groups];
    body.extend_from_slice(&key);
    response_frame(body)
}

fn v2_terminal_frame(group_id: u8) -> Vec<u8> {
    response_frame(vec![RESP_HARMONY_HINTS, group_id])
}

#[tokio::test]
async fn explicit_preflight_rejects_missing_root_even_in_advisory_mode() {
    let mut client = HarmonyClient::new("wss://hint", "wss://query");
    let error = client.preflight_verified_database(0).await.unwrap_err();
    assert!(matches!(error, PirError::VerificationFailed(message) if
        message.contains("no installed database proof")));
}

#[test]
fn test_new_client() {
    let client = HarmonyClient::new("ws://localhost:8080", "ws://localhost:8081");
    assert!(!client.is_connected());
    assert_eq!(client.backend_type(), PirBackendType::Harmony);
    assert_eq!(client.prp_backend, PRP_HMR12);
}

#[test]
fn batch_response_binds_opcode_level_round_and_canonical_error() {
    let body = harmony_batch_body(1, 17, &[(0, &[9, 8])]);
    let decoded = decode_batch_response_body(&body, 1, 17, 1, "test").unwrap();
    assert_eq!(decoded.get(&0).unwrap(), &[9, 8]);

    let wrong_level = decode_batch_response_body(&body, 0, 17, 1, "test").unwrap_err();
    assert!(matches!(wrong_level, PirError::Protocol(ref text) if text.contains("level mismatch")));
    let wrong_round = decode_batch_response_body(&body, 1, 18, 1, "test").unwrap_err();
    assert!(
        matches!(wrong_round, PirError::Protocol(ref text) if text.contains("round_id mismatch"))
    );

    let mut wrong_opcode = body.clone();
    wrong_opcode[0] = 0x91;
    assert!(matches!(
        decode_batch_response_body(&wrong_opcode, 1, 17, 1, "test"),
        Err(PirError::UnexpectedResponse { .. })
    ));

    let message = b"authorization required";
    let mut error = vec![RESP_ERROR];
    error.extend_from_slice(&(message.len() as u32).to_le_bytes());
    error.extend_from_slice(message);
    assert!(matches!(
        decode_batch_response_body(&error, 1, 17, 1, "test"),
        Err(PirError::ServerError(ref text)) if text.contains("authorization required")
    ));
}

#[test]
fn batch_response_rejects_truncation_duplicates_and_trailing_bytes() {
    let body = harmony_batch_body(0, 4, &[(0, &[1]), (1, &[2])]);
    let mut truncated = body.clone();
    truncated.pop();
    assert!(matches!(
        decode_batch_response_body(&truncated, 0, 4, 2, "test"),
        Err(PirError::Decode(_))
    ));

    let duplicate = harmony_batch_body(0, 4, &[(0, &[1]), (0, &[2])]);
    assert!(matches!(
        decode_batch_response_body(&duplicate, 0, 4, 2, "test"),
        Err(PirError::Protocol(ref text)) if text.contains("duplicate group")
    ));

    assert!(matches!(
        decode_batch_response_body(&body, 0, 4, 1, "test"),
        Err(PirError::Protocol(ref text)) if text.contains("group count mismatch")
    ));
    let out_of_range = harmony_batch_body(0, 4, &[(1, &[1])]);
    assert!(matches!(
        decode_batch_response_body(&out_of_range, 0, 4, 1, "test"),
        Err(PirError::Protocol(ref text)) if text.contains("out-of-range group id")
    ));

    let mut trailing_body = body.clone();
    trailing_body.push(0xaa);
    assert!(matches!(
        decode_batch_response_body(&trailing_body, 0, 4, 2, "test"),
        Err(PirError::Decode(ref text)) if text.contains("trailing bytes")
    ));

    let mut trailing_frame = response_frame(body.clone());
    trailing_frame.push(0xaa);
    assert!(matches!(
        decode_batch_response_frame(&trailing_frame, 0, 4, 2, "test"),
        Err(PirError::Decode(ref text)) if text.contains("length mismatch")
    ));
    assert!(decode_batch_response_frame(&response_frame(body), 0, 4, 2, "test").is_ok());
}

#[test]
fn legacy_non_main_database_does_not_assume_a_v2_hint_pool() {
    assert!(should_use_v2_hint_pool(true, 0));
    assert!(!should_use_v2_hint_pool(true, 1));
    assert!(!should_use_v2_hint_pool(true, u8::MAX));
    assert!(!should_use_v2_hint_pool(false, 0));
}

#[test]
fn v2_pool_fallback_requires_exact_message() {
    assert!(is_v2_hint_pool_unavailable_message(
        V2_HINT_POOL_UNAVAILABLE
    ));
    assert!(!is_v2_hint_pool_unavailable_message(&format!(
        "{V2_HINT_POOL_UNAVAILABLE}; retry later"
    )));
}

#[tokio::test]
async fn exact_v2_pool_unavailable_preamble_falls_back_to_v1() {
    let mut hint = MockTransport::new("wss://hint");
    hint.enqueue_response(v2_pool_unavailable_frame());
    hint.enqueue_response(v1_hint_frame(
        0,
        8,
        4,
        4,
        4 * INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE,
    ));
    hint.enqueue_response(v1_hint_frame(
        0,
        8,
        4,
        4,
        4 * CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE,
    ));

    let mut db = session_db_info();
    db.db_id = 0;
    let mut client = HarmonyClient::new("wss://hint", "wss://query");
    client.connect_with_transport(Box::new(hint), Box::new(MockTransport::new("wss://query")));

    client.ensure_groups_ready(&db, None).await.unwrap();
    assert_eq!(client.loaded_db_id, Some(0));
    assert_eq!(client.index_groups.len(), 1);
    assert_eq!(client.chunk_groups.len(), 1);
}

#[tokio::test]
async fn exact_v2_half_pool_unavailable_restores_both_sockets_for_v1() {
    let mut primary = MockTransport::new("wss://hint-primary");
    primary.enqueue_response(v2_pool_unavailable_frame());
    primary.enqueue_response(v1_hint_frame(
        0,
        8,
        4,
        4,
        4 * INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE,
    ));

    let mut secondary = MockTransport::new("wss://hint-secondary");
    secondary.enqueue_response(v2_pool_unavailable_frame());
    secondary.enqueue_response(v1_hint_frame(
        0,
        8,
        4,
        4,
        4 * CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE,
    ));

    let mut db = session_db_info();
    db.db_id = 0;
    let mut client = HarmonyClient::new("wss://hint", "wss://query");
    client.connect_with_transport(
        Box::new(primary),
        Box::new(MockTransport::new("wss://query")),
    );
    client.hint_conn_secondary = Some(Box::new(secondary));

    client.ensure_groups_ready(&db, None).await.unwrap();
    assert_eq!(client.loaded_db_id, Some(0));
    assert_eq!(client.index_groups.len(), 1);
    assert_eq!(client.chunk_groups.len(), 1);
    assert!(client.hint_conn.is_some());
    assert!(client.hint_conn_secondary.is_some());
}

#[test]
fn v2_metadata_parsers_reject_inconsistent_preamble_and_terminal() {
    let wrong_level = v2_key_preamble_frame(PRP_HMR12, 0, 2, [7; 16]);
    let error = parse_v2_key_preamble(&wrong_level, 2, "test").unwrap_err();
    assert!(matches!(error, PirError::Protocol(message) if
        message.contains("expected 0xff")));

    let wrong_total = v2_key_preamble_frame(PRP_HMR12, 0xFF, 3, [7; 16]);
    let error = parse_v2_key_preamble(&wrong_total, 2, "test").unwrap_err();
    assert!(matches!(error, PirError::Protocol(message) if
        message.contains("declares 3 groups, expected 2")));

    let trailing_terminal = response_frame(vec![RESP_HARMONY_HINTS, 0xFF, 0]);
    let error = validate_v2_terminal(&trailing_terminal, "test").unwrap_err();
    assert!(matches!(error, PirError::Protocol(message) if
        message.contains("invalid terminal sentinel")));
}

#[tokio::test]
async fn v2_full_duplicate_group_closes_and_discards_stream() {
    let closed = Arc::new(AtomicBool::new(false));
    let sends = Arc::new(AtomicUsize::new(0));
    let key = [0x31; 16];

    let primary = ScriptedCloseTransport::new(
        "wss://hint-primary",
        [
            v2_key_preamble_frame(PRP_HMR12, 0xFF, 3, key),
            v1_hint_frame(0, 8, 4, 4, 4 * INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE),
            v1_hint_frame(0, 8, 4, 4, 4 * INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE),
        ],
        closed.clone(),
        sends.clone(),
    );

    let mut db = session_db_info();
    db.db_id = 0;
    db.index_k = 2;
    let mut client = HarmonyClient::new("wss://hint", "wss://query");
    client.connect_with_transport(
        Box::new(primary),
        Box::new(MockTransport::new("wss://query")),
    );

    let error = client.ensure_groups_ready(&db, None).await.unwrap_err();
    assert!(matches!(error, PirError::Protocol(message) if
        message.contains("duplicate INDEX group 0")));
    assert!(closed.load(Ordering::SeqCst));
    assert_eq!(sends.load(Ordering::SeqCst), 1);
    assert!(client.hint_conn.is_none());
    assert!(client.index_groups.is_empty());
    assert!(client.chunk_groups.is_empty());
    assert!(client.loaded_db_id.is_none());
}

#[tokio::test]
async fn v2_full_valid_stream_restores_socket() {
    let closed = Arc::new(AtomicBool::new(false));
    let sends = Arc::new(AtomicUsize::new(0));
    let key = [0x3a; 16];

    let primary = ScriptedCloseTransport::new(
        "wss://hint-primary",
        [
            v2_key_preamble_frame(PRP_HMR12, 0xFF, 2, key),
            v1_hint_frame(0, 8, 4, 4, 4 * INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE),
            v1_hint_frame(0, 8, 4, 4, 4 * CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE),
            v2_terminal_frame(0xFF),
        ],
        closed.clone(),
        sends.clone(),
    );

    let mut db = session_db_info();
    db.db_id = 0;
    let mut client = HarmonyClient::new("wss://hint", "wss://query");
    client.connect_with_transport(
        Box::new(primary),
        Box::new(MockTransport::new("wss://query")),
    );

    client.ensure_groups_ready(&db, None).await.unwrap();
    assert!(!closed.load(Ordering::SeqCst));
    assert_eq!(sends.load(Ordering::SeqCst), 1);
    assert!(client.hint_conn.is_some());
    assert_eq!(client.index_groups.len(), 1);
    assert_eq!(client.chunk_groups.len(), 1);
    assert_eq!(client.loaded_db_id, Some(0));
}

#[tokio::test]
async fn v2_full_invalid_terminal_closes_and_discards_stream() {
    let closed = Arc::new(AtomicBool::new(false));
    let sends = Arc::new(AtomicUsize::new(0));
    let key = [0x42; 16];

    let primary = ScriptedCloseTransport::new(
        "wss://hint-primary",
        [
            v2_key_preamble_frame(PRP_HMR12, 0xFF, 2, key),
            v1_hint_frame(0, 8, 4, 4, 4 * INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE),
            v1_hint_frame(0, 8, 4, 4, 4 * CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE),
            v2_terminal_frame(0xFE),
        ],
        closed.clone(),
        sends.clone(),
    );

    let mut db = session_db_info();
    db.db_id = 0;
    let mut client = HarmonyClient::new("wss://hint", "wss://query");
    client.connect_with_transport(
        Box::new(primary),
        Box::new(MockTransport::new("wss://query")),
    );

    let error = client.ensure_groups_ready(&db, None).await.unwrap_err();
    assert!(matches!(error, PirError::Protocol(message) if
        message.contains("invalid terminal sentinel")));
    assert!(closed.load(Ordering::SeqCst));
    assert_eq!(sends.load(Ordering::SeqCst), 1);
    assert!(client.hint_conn.is_none());
    assert!(client.loaded_db_id.is_none());
}

#[tokio::test]
async fn v2_half_duplicate_group_closes_both_streams() {
    let primary_closed = Arc::new(AtomicBool::new(false));
    let secondary_closed = Arc::new(AtomicBool::new(false));
    let primary_sends = Arc::new(AtomicUsize::new(0));
    let secondary_sends = Arc::new(AtomicUsize::new(0));
    let key = [0x53; 16];

    let primary = ScriptedCloseTransport::new(
        "wss://hint-primary",
        [
            v2_key_preamble_frame(PRP_HMR12, 0xFF, 3, key),
            v1_hint_frame(0, 8, 4, 4, 4 * INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE),
            v1_hint_frame(0, 8, 4, 4, 4 * INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE),
        ],
        primary_closed.clone(),
        primary_sends.clone(),
    );
    let secondary = ScriptedCloseTransport::new(
        "wss://hint-secondary",
        [
            v2_key_preamble_frame(PRP_HMR12, 0xFF, 3, key),
            v1_hint_frame(0, 8, 4, 4, 4 * CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE),
            v2_terminal_frame(0xFF),
        ],
        secondary_closed.clone(),
        secondary_sends.clone(),
    );

    let mut db = session_db_info();
    db.db_id = 0;
    db.index_k = 2;
    let mut client = HarmonyClient::new("wss://hint", "wss://query");
    client.connect_with_transport(
        Box::new(primary),
        Box::new(MockTransport::new("wss://query")),
    );
    client.hint_conn_secondary = Some(Box::new(secondary));

    let error = client.ensure_groups_ready(&db, None).await.unwrap_err();
    assert!(matches!(error, PirError::Protocol(message) if
        message.contains("duplicate group 0")));
    assert!(primary_closed.load(Ordering::SeqCst));
    assert!(secondary_closed.load(Ordering::SeqCst));
    assert!(client.hint_conn.is_none());
    assert!(client.hint_conn_secondary.is_none());
}

#[tokio::test]
async fn v2_half_single_side_unknown_error_closes_both_without_v1_fallback() {
    let primary_closed = Arc::new(AtomicBool::new(false));
    let secondary_closed = Arc::new(AtomicBool::new(false));
    let primary_sends = Arc::new(AtomicUsize::new(0));
    let secondary_sends = Arc::new(AtomicUsize::new(0));

    let primary = ScriptedCloseTransport::new(
        "wss://hint-primary",
        [v2_error_frame("unexpected V2 failure")],
        primary_closed.clone(),
        primary_sends.clone(),
    );
    let secondary = ScriptedCloseTransport::new(
        "wss://hint-secondary",
        [v2_pool_unavailable_frame()],
        secondary_closed.clone(),
        secondary_sends.clone(),
    );

    let mut db = session_db_info();
    db.db_id = 0;
    let mut client = HarmonyClient::new("wss://hint", "wss://query");
    client.connect_with_transport(
        Box::new(primary),
        Box::new(MockTransport::new("wss://query")),
    );
    client.hint_conn_secondary = Some(Box::new(secondary));

    let error = client.ensure_groups_ready(&db, None).await.unwrap_err();
    assert!(
        matches!(error, PirError::ServerError(reason) if reason == "V2-half INDEX: unexpected V2 failure")
    );
    assert!(primary_closed.load(Ordering::SeqCst));
    assert!(secondary_closed.load(Ordering::SeqCst));
    assert!(client.hint_conn.is_none());
    assert!(client.hint_conn_secondary.is_none());
    assert_eq!(primary_sends.load(Ordering::SeqCst), 1);
    assert!(secondary_sends.load(Ordering::SeqCst) <= 1);
}

#[tokio::test]
async fn v2_half_one_pool_empty_one_silent_times_out_and_closes_both() {
    let primary_closed = Arc::new(AtomicBool::new(false));
    let secondary_closed = Arc::new(AtomicBool::new(false));
    let primary_sends = Arc::new(AtomicUsize::new(0));
    let secondary_sends = Arc::new(AtomicUsize::new(0));

    let primary = ScriptedCloseTransport::new(
        "wss://hint-primary",
        [v2_pool_unavailable_frame()],
        primary_closed.clone(),
        primary_sends.clone(),
    );
    let secondary = PendingCloseTransport {
        url: "wss://hint-secondary",
        closed: secondary_closed.clone(),
        sends: secondary_sends.clone(),
    };

    let mut db = session_db_info();
    db.db_id = 0;
    let mut client = HarmonyClient::new("wss://hint", "wss://query");
    client.connect_with_transport(
        Box::new(primary),
        Box::new(MockTransport::new("wss://query")),
    );
    client.hint_conn_secondary = Some(Box::new(secondary));

    let error = client.ensure_groups_ready(&db, None).await.unwrap_err();
    assert!(matches!(error, PirError::Timeout(message) if
        message.contains("V2-half hint fetch exceeded")));
    assert!(primary_closed.load(Ordering::SeqCst));
    assert!(secondary_closed.load(Ordering::SeqCst));
    assert!(client.hint_conn.is_none());
    assert!(client.hint_conn_secondary.is_none());
    assert_eq!(primary_sends.load(Ordering::SeqCst), 1);
    assert_eq!(secondary_sends.load(Ordering::SeqCst), 1);
}

/// C4 (docs/history/CODE_REVIEW_2026-06.md): the master PRP key comes from
/// the OS CSPRNG. Two fresh clients must hold distinct non-zero keys
/// — the old splitmix64(wall-clock) derivation could collide for
/// clients created in the same clock tick and was brute-forceable
/// from a timestamp guess.
#[test]
fn test_master_prp_key_is_random_per_client() {
    let a = HarmonyClient::new("wss://h", "wss://q");
    let b = HarmonyClient::new("wss://h", "wss://q");
    assert_ne!(a.master_prp_key, [0u8; 16]);
    assert_ne!(b.master_prp_key, [0u8; 16]);
    assert_ne!(a.master_prp_key, b.master_prp_key);
}

#[test]
fn test_set_master_key_invalidates_groups() {
    let mut client = HarmonyClient::new("ws://localhost:8080", "ws://localhost:8081");
    client.loaded_db_id = Some(0);
    // No groups yet, but invalidation should clear the id.
    client.set_master_key([7u8; 16]);
    assert!(client.loaded_db_id.is_none());
}

#[test]
fn cache_binding_accessors_track_effective_state() {
    let mut client = HarmonyClient::new("ws://localhost:8080", "ws://localhost:8081");
    client.set_master_key([0x5au8; 16]);
    client.set_prp_backend(PRP_FASTPRP);
    assert_eq!(client.cache_master_key(), [0x5au8; 16]);
    assert_eq!(client.cache_prp_backend(), PRP_FASTPRP);
}

#[test]
fn test_encode_batch_roundtrip() {
    let items = vec![
        BatchItem {
            group_id: 3,
            indices: vec![1, 2, 3, 4],
        },
        BatchItem {
            group_id: 7,
            indices: vec![],
        },
    ];
    let wire = encode_batch_query(0, 5, 0, &items);
    // First 4 bytes are length; skip them.
    assert_eq!(wire[4], REQ_HARMONY_BATCH_QUERY);
    assert_eq!(wire[5], 0); // level
    assert_eq!(u16::from_le_bytes([wire[6], wire[7]]), 5); // round_id
    assert_eq!(u16::from_le_bytes([wire[8], wire[9]]), 2); // num_groups
    assert_eq!(wire[10], 1); // sub_queries_per_group
}

#[test]
fn test_bytes_to_u32_vec() {
    let bytes = vec![1u8, 0, 0, 0, 2, 0, 0, 0];
    let v = bytes_to_u32_vec(&bytes).unwrap();
    assert_eq!(v, vec![1u32, 2u32]);
    assert!(bytes_to_u32_vec(&[1, 2, 3]).is_err());
}

/// C2 (docs/history/CODE_REVIEW_2026-06.md): malformed varints in
/// server-controlled chunk data must surface as `PirError::Decode`,
/// never a panic — mirrors the equivalent test in `dpf.rs`.
#[test]
fn test_decode_utxo_entries_malformed_varint_is_decode_error() {
    // Count varint runs past 64 bits (previously panicked).
    let err = decode_utxo_entries(&[0xFF; 16]).unwrap_err();
    assert!(matches!(err, PirError::Decode(_)), "got {err:?}");

    // Count varint never terminates before the data ends.
    let err = decode_utxo_entries(&[0x80]).unwrap_err();
    assert!(matches!(err, PirError::Decode(_)), "got {err:?}");

    // Valid count + txid, then a vout varint cut mid-stream.
    let mut data = Vec::new();
    pir_core::codec::write_varint(1, &mut data);
    data.extend_from_slice(&[0xAB; 32]);
    data.push(0x80); // dangling continuation bit
    let err = decode_utxo_entries(&data).unwrap_err();
    assert!(matches!(err, PirError::Decode(_)), "got {err:?}");
}

/// Honest chunk data (including trailing zero padding) still decodes
/// exactly as before the panic-free rework.
#[test]
fn test_decode_utxo_entries_decodes_honest_data() {
    let mut data = Vec::new();
    pir_core::codec::write_varint(1, &mut data);
    data.extend_from_slice(&[0x33; 32]);
    pir_core::codec::write_varint(7, &mut data); // vout
    pir_core::codec::write_varint(987_654, &mut data); // amount
    data.extend_from_slice(&[0u8; 5]); // chunk padding, ignored

    let entries = decode_utxo_entries(&data).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].txid, [0x33; 32]);
    assert_eq!(entries[0].vout, 7);
    assert_eq!(entries[0].amount_sats, 987_654);

    assert!(decode_utxo_entries(&[]).unwrap().is_empty());
}

/// Demonstrates the test-injection escape hatch: a client built with a
/// pair of [`MockTransport`](crate::transport::mock::MockTransport)s
/// reports `is_connected()` without ever opening a real socket. This is
/// the core value prop of the `PirTransport` trait.
#[test]
fn connect_with_transport_marks_connected() {
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    assert!(!client.is_connected());
    client.connect_with_transport(
        Box::new(MockTransport::new("wss://mock-hint")),
        Box::new(MockTransport::new("wss://mock-query")),
    );
    assert!(client.is_connected());
}

#[test]
fn connect_with_transport_replacement_invalidates_verified_session() {
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.connect_with_transport(
        Box::new(MockTransport::new("wss://old-hint")),
        Box::new(MockTransport::new("wss://old-query")),
    );
    let db_id = seed_verified_session(&mut client);
    populate_main_groups(&mut client, &session_db_info());
    assert!(!client.index_groups.is_empty());
    assert!(!client.chunk_groups.is_empty());
    client.hint_conn_secondary = Some(Box::new(MockTransport::new("wss://old-hint-2")));
    client.query_conn_secondary = Some(Box::new(MockTransport::new("wss://old-query-2")));

    client.connect_with_transport(
        Box::new(MockTransport::new("wss://new-hint")),
        Box::new(MockTransport::new("wss://new-query")),
    );

    assert!(client.is_connected());
    assert!(client.hint_conn_secondary.is_none());
    assert!(client.query_conn_secondary.is_none());
    assert!(client.catalog.is_none());
    assert!(client.verified_database_roots(db_id).is_none());
    assert!(!client.verified_tree_tops.contains_key(&db_id));
    assert!(client.loaded_db_id.is_none());
    assert!(client.index_groups.is_empty());
    assert!(client.chunk_groups.is_empty());
}

#[tokio::test]
async fn duplicate_connect_is_idempotent_for_verified_session() {
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.connect_with_transport(
        Box::new(MockTransport::new("wss://mock-hint")),
        Box::new(MockTransport::new("wss://mock-query")),
    );
    let db_id = seed_verified_session(&mut client);
    populate_main_groups(&mut client, &session_db_info());

    client.connect().await.unwrap();

    assert!(client.catalog.is_some());
    assert!(client.verified_database_roots(db_id).is_some());
    assert!(client.verified_tree_tops.contains_key(&db_id));
    assert_eq!(client.loaded_db_id, Some(db_id));
    assert!(!client.index_groups.is_empty());
    assert!(!client.chunk_groups.is_empty());
}

#[tokio::test]
async fn staged_hint_disconnect_preserves_bindings_until_last_leg() {
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.connect_with_transport(
        Box::new(MockTransport::new("wss://mock-hint")),
        Box::new(MockTransport::new("wss://mock-query")),
    );
    let db_id = seed_verified_session(&mut client);

    client.disconnect_provider(0).await.unwrap();

    assert!(!client.is_provider_connected(0).unwrap());
    assert!(client.is_provider_connected(1).unwrap());
    assert!(client.catalog.is_some());
    assert!(client.verified_database_roots(db_id).is_some());
    assert!(client.verified_tree_tops.contains_key(&db_id));

    client.disconnect_provider(1).await.unwrap();

    assert!(client.catalog.is_none());
    assert!(client.verified_database_roots(db_id).is_none());
    assert!(!client.verified_tree_tops.contains_key(&db_id));
}

#[tokio::test]
async fn staged_secure_upgrade_closes_only_the_same_role_secondary_transport() {
    let mut hint_primary = MockTransport::new("wss://hint-primary");
    hint_primary.enqueue_response(handshake_frame(0x51));
    let query_primary = MockTransport::new("wss://query-primary");
    let hint_closed = Arc::new(AtomicBool::new(false));
    let query_closed = Arc::new(AtomicBool::new(false));
    let mut client = HarmonyClient::new("wss://hint", "wss://query");
    client.connect_with_transport(Box::new(hint_primary), Box::new(query_primary));
    client.hint_conn_secondary = Some(Box::new(CloseTrackingTransport {
        url: "wss://hint-secondary",
        closed: hint_closed.clone(),
    }));
    client.query_conn_secondary = Some(Box::new(CloseTrackingTransport {
        url: "wss://query-secondary",
        closed: query_closed.clone(),
    }));

    client
        .upgrade_provider_to_secure_channel_with_seed(0, [0x11; 32], [0x21; 32], [0x31; 32])
        .await
        .unwrap();

    assert!(client.hint_conn_secondary.is_none());
    assert!(hint_closed.load(Ordering::SeqCst));
    assert!(client.query_conn_secondary.is_some());
    assert!(!query_closed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn secure_upgrade_closes_both_plaintext_secondary_transports() {
    let mut hint_primary = MockTransport::new("wss://hint-primary");
    hint_primary.enqueue_response(handshake_frame(0x41));
    let mut query_primary = MockTransport::new("wss://query-primary");
    query_primary.enqueue_response(handshake_frame(0x42));

    let hint_closed = Arc::new(AtomicBool::new(false));
    let query_closed = Arc::new(AtomicBool::new(false));
    let mut client = HarmonyClient::new("wss://hint", "wss://query");
    client.connect_with_transport(Box::new(hint_primary), Box::new(query_primary));
    client.hint_conn_secondary = Some(Box::new(CloseTrackingTransport {
        url: "wss://hint-secondary",
        closed: hint_closed.clone(),
    }));
    client.query_conn_secondary = Some(Box::new(CloseTrackingTransport {
        url: "wss://query-secondary",
        closed: query_closed.clone(),
    }));

    client
        .upgrade_to_secure_channel_with_seeds(
            [0x11; 32], [0x21; 32], [0x31; 32], [0x12; 32], [0x22; 32], [0x32; 32],
        )
        .await
        .unwrap();

    assert!(client.hint_conn_secondary.is_none());
    assert!(client.query_conn_secondary.is_none());
    assert!(hint_closed.load(Ordering::SeqCst));
    assert!(query_closed.load(Ordering::SeqCst));
}

// ─── Hint cache plumbing tests ─────────────────────────────────────────

fn sample_db_info() -> DatabaseInfo {
    DatabaseInfo {
        db_id: 0,
        kind: DatabaseKind::Full,
        name: "test".into(),
        height: 100,
        // Keep params tiny so HarmonyGroup::new runs in milliseconds.
        // INDEX + CHUNK bins don't need to be realistic; we only
        // exercise state round-trip, not PIR correctness.
        index_bins: 32,
        chunk_bins: 32,
        // >= 3 so the fixture stays valid for PBC planning
        // (`derive_groups_3` spins forever below 3 distinct groups).
        index_k: 4,
        chunk_k: 4,
        tag_seed: 0x1234_5678_9ABC_DEF0,
        dpf_n_index: 5,
        dpf_n_chunk: 5,
        has_bucket_merkle: false,
        index_master_seed: 0xAAAA_BBBB_CCCC_DDDD,
        chunk_master_seed: 0xEEEE_FFFF_0000_1111,
        anchor_kind: 0,
        anchor_bytes: Vec::new(),
    }
}

/// Populate a client's main groups locally without touching the
/// network — mirrors what `ensure_groups_ready` does on a cache
/// miss, minus the `fetch_and_load_hints` network roundtrips.
/// This lets us exercise `save_hints_bytes` / `load_hints_bytes`
/// purely in-process.
fn populate_main_groups(client: &mut HarmonyClient, info: &DatabaseInfo) {
    let k_index = info.index_k as usize;
    let k_chunk = info.chunk_k as usize;
    let index_w = (INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE) as u32;
    let chunk_w = (CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE) as u32;

    for g in 0..k_index {
        let group = new_harmony_group(
            info.index_bins,
            index_w,
            0,
            &client.master_prp_key,
            g as u32,
            client.prp_backend,
        )
        .expect("HarmonyGroup init");
        client.index_groups.insert(g as u8, group);
    }
    for g in 0..k_chunk {
        let group = new_harmony_group(
            info.chunk_bins,
            chunk_w,
            0,
            &client.master_prp_key,
            (k_index + g) as u32,
            client.prp_backend,
        )
        .expect("HarmonyGroup init");
        client.chunk_groups.insert(g as u8, group);
    }
    client.loaded_db_id = Some(info.db_id);
}

fn seed_verified_complete_hint_shape(
    client: &mut HarmonyClient,
    info: &DatabaseInfo,
    index_sib_levels: usize,
    chunk_sib_levels: usize,
) {
    client.catalog = Some(DatabaseCatalog {
        databases: vec![info.clone()],
    });
    client
        .install_verified_database_roots(session_roots(info))
        .unwrap();
    let mut tops = Vec::with_capacity(info.index_k as usize + info.chunk_k as usize);
    tops.extend((0..info.index_k).map(|_| TreeTop {
        cache_from_level: index_sib_levels,
        levels: Vec::new(),
    }));
    tops.extend((0..info.chunk_k).map(|_| TreeTop {
        cache_from_level: chunk_sib_levels,
        levels: Vec::new(),
    }));
    client.verified_tree_tops.insert(info.db_id, tops);
}

fn populate_sibling_groups(
    client: &mut HarmonyClient,
    info: &DatabaseInfo,
    index_sib_levels: usize,
    chunk_sib_levels: usize,
) {
    let k_index = info.index_k as usize;
    let k_chunk = info.chunk_k as usize;
    let index_w = (INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE) as u32;
    let chunk_w = (CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE) as u32;
    for level in 0..index_sib_levels {
        for group in 0..k_index {
            let group_id = (k_index + k_chunk) + level * k_index + group;
            let state = new_harmony_group(
                info.index_bins,
                index_w,
                0,
                &client.master_prp_key,
                group_id as u32,
                client.prp_backend,
            )
            .expect("INDEX sibling HarmonyGroup init");
            client.index_sib_groups.insert((level, group as u8), state);
        }
    }
    for level in 0..chunk_sib_levels {
        for group in 0..k_chunk {
            let group_id =
                (k_index + k_chunk) + index_sib_levels * k_index + level * k_chunk + group;
            let state = new_harmony_group(
                info.chunk_bins,
                chunk_w,
                0,
                &client.master_prp_key,
                group_id as u32,
                client.prp_backend,
            )
            .expect("CHUNK sibling HarmonyGroup init");
            client.chunk_sib_groups.insert((level, group as u8), state);
        }
    }
    client.sibling_hints_loaded = Some(info.db_id);
}

#[test]
fn with_hint_cache_dir_sets_and_reads() {
    let client =
        HarmonyClient::new("wss://h", "wss://q").with_hint_cache_dir("/tmp/pir-test-cache");
    assert_eq!(
        client.hint_cache_dir(),
        Some(std::path::Path::new("/tmp/pir-test-cache"))
    );
}

#[test]
fn set_hint_cache_dir_mutates_and_clears() {
    let mut client = HarmonyClient::new("wss://h", "wss://q");
    assert!(client.hint_cache_dir().is_none());
    client.set_hint_cache_dir(Some(PathBuf::from("/tmp/x")));
    assert_eq!(
        client.hint_cache_dir(),
        Some(std::path::Path::new("/tmp/x"))
    );
    client.set_hint_cache_dir(None);
    assert!(client.hint_cache_dir().is_none());
}

#[test]
fn save_hints_bytes_returns_none_when_nothing_loaded() {
    let client = HarmonyClient::new("wss://h", "wss://q");
    // Even though loaded_db_id is None by default, also require a
    // populated catalog to avoid false positives.
    let out = client.save_hints_bytes().unwrap();
    assert!(out.is_none());
}

#[test]
fn save_hints_bytes_errors_when_catalog_missing() {
    let mut client = HarmonyClient::new("wss://h", "wss://q");
    client.loaded_db_id = Some(0);
    // No catalog installed → InvalidState.
    let err = client.save_hints_bytes().unwrap_err();
    assert!(matches!(err, PirError::InvalidState(_)));
}

#[test]
fn save_and_load_hints_bytes_round_trips_main_groups() {
    let info = sample_db_info();
    let mut client = HarmonyClient::new("wss://h", "wss://q");
    client.set_master_key([0x42u8; 16]);
    client.catalog = Some(DatabaseCatalog {
        databases: vec![info.clone()],
    });
    populate_main_groups(&mut client, &info);

    let bytes = client.save_hints_bytes().unwrap().expect("some bytes");
    assert!(!bytes.is_empty());

    // Reset the client and reload from the blob.
    let mut client2 = HarmonyClient::new("wss://h", "wss://q");
    client2.set_master_key([0x42u8; 16]);
    client2.catalog = Some(DatabaseCatalog {
        databases: vec![info.clone()],
    });
    client2.load_hints_bytes(&bytes, &info).unwrap();

    assert_eq!(client2.loaded_db_id, Some(info.db_id));
    assert_eq!(client2.index_groups.len(), info.index_k as usize);
    assert_eq!(client2.chunk_groups.len(), info.chunk_k as usize);
    // Sibling state wasn't populated; shouldn't be claimed.
    assert!(client2.sibling_hints_loaded.is_none());
}

#[test]
fn paid_cache_rejects_main_only_bundle_and_clears_partial_state() {
    let mut info = sample_db_info();
    info.has_bucket_merkle = true;
    let mut source = HarmonyClient::new("wss://h", "wss://q");
    source.set_master_key([0x61; 16]);
    source.catalog = Some(DatabaseCatalog {
        databases: vec![info.clone()],
    });
    populate_main_groups(&mut source, &info);
    let bytes = source.save_hints_bytes().unwrap().expect("main-only bytes");

    let mut restored = HarmonyClient::new("wss://h", "wss://q");
    restored.set_master_key([0x61; 16]);
    seed_verified_complete_hint_shape(&mut restored, &info, 1, 2);
    let error = restored
        .load_complete_hints_bytes(&bytes, &info)
        .unwrap_err();
    assert!(matches!(error, PirError::InvalidState(message) if
        message.contains("incomplete")));
    assert!(restored.loaded_db_id.is_none());
    assert!(restored.index_groups.is_empty());
    assert!(restored.chunk_groups.is_empty());
    assert!(restored.index_sib_groups.is_empty());
    assert!(restored.chunk_sib_groups.is_empty());
}

#[test]
fn paid_cache_round_trips_exact_main_and_sibling_shape() {
    let mut info = sample_db_info();
    info.has_bucket_merkle = true;
    let mut source = HarmonyClient::new("wss://h", "wss://q");
    source.set_master_key([0x62; 16]);
    seed_verified_complete_hint_shape(&mut source, &info, 1, 2);
    populate_main_groups(&mut source, &info);
    populate_sibling_groups(&mut source, &info, 1, 2);
    assert!(source
        .has_complete_hints_for_verified_database(&info)
        .unwrap());
    let bytes = source.save_hints_bytes().unwrap().expect("complete bytes");

    let mut restored = HarmonyClient::new("wss://h", "wss://q");
    restored.set_master_key([0x62; 16]);
    seed_verified_complete_hint_shape(&mut restored, &info, 1, 2);
    restored.load_complete_hints_bytes(&bytes, &info).unwrap();
    assert!(restored
        .has_complete_hints_for_verified_database(&info)
        .unwrap());
    assert_eq!(restored.index_sib_groups.len(), info.index_k as usize);
    assert_eq!(restored.chunk_sib_groups.len(), 2 * info.chunk_k as usize);
}

#[test]
fn paid_cache_requires_verified_tree_tops_before_restore() {
    let mut info = sample_db_info();
    info.has_bucket_merkle = true;
    let mut source = HarmonyClient::new("wss://h", "wss://q");
    source.set_master_key([0x63; 16]);
    source.catalog = Some(DatabaseCatalog {
        databases: vec![info.clone()],
    });
    populate_main_groups(&mut source, &info);
    let bytes = source.save_hints_bytes().unwrap().expect("bytes");

    let mut restored = HarmonyClient::new("wss://h", "wss://q");
    restored.set_master_key([0x63; 16]);
    restored.catalog = Some(DatabaseCatalog {
        databases: vec![info.clone()],
    });
    restored
        .install_verified_database_roots(session_roots(&info))
        .unwrap();
    let error = restored
        .load_complete_hints_bytes(&bytes, &info)
        .unwrap_err();
    assert!(matches!(error, PirError::InvalidState(message) if
        message.contains("tree tops")));
    assert!(restored.loaded_db_id.is_none());
}

#[test]
fn load_hints_bytes_rejects_master_key_mismatch() {
    let info = sample_db_info();
    let mut client = HarmonyClient::new("wss://h", "wss://q");
    client.set_master_key([0x11u8; 16]);
    client.catalog = Some(DatabaseCatalog {
        databases: vec![info.clone()],
    });
    populate_main_groups(&mut client, &info);
    let bytes = client.save_hints_bytes().unwrap().expect("some bytes");

    // Second client with a different master key should refuse.
    let mut client2 = HarmonyClient::new("wss://h", "wss://q");
    client2.set_master_key([0x22u8; 16]);
    let err = client2.load_hints_bytes(&bytes, &info).unwrap_err();
    assert!(
        matches!(err, PirError::InvalidState(_)),
        "expected InvalidState, got {:?}",
        err
    );
}

#[test]
fn load_hints_bytes_rejects_shape_mismatch() {
    let info_a = sample_db_info();
    let mut info_b = sample_db_info();
    info_b.index_bins *= 2;

    let mut client = HarmonyClient::new("wss://h", "wss://q");
    client.set_master_key([0x33u8; 16]);
    client.catalog = Some(DatabaseCatalog {
        databases: vec![info_a.clone()],
    });
    populate_main_groups(&mut client, &info_a);
    let bytes = client.save_hints_bytes().unwrap().expect("bytes");

    // Load with db info that has different shape → fingerprint
    // mismatch.
    let mut client2 = HarmonyClient::new("wss://h", "wss://q");
    client2.set_master_key([0x33u8; 16]);
    let err = client2.load_hints_bytes(&bytes, &info_b).unwrap_err();
    assert!(matches!(err, PirError::InvalidState(_)));
}

#[test]
fn persist_and_restore_hints_to_cache_round_trips() {
    let info = sample_db_info();
    let tmp = std::env::temp_dir().join(format!(
        "pir-sdk-harmony-cache-{}-{}",
        std::process::id(),
        pir_core::merkle::sha256(b"persist-restore")[0]
    ));
    // Fresh client writes a cache file.
    let mut client = HarmonyClient::new("wss://h", "wss://q").with_hint_cache_dir(&tmp);
    client.set_master_key([0x77u8; 16]);
    client.catalog = Some(DatabaseCatalog {
        databases: vec![info.clone()],
    });
    populate_main_groups(&mut client, &info);
    client.persist_hints_to_cache(&info).unwrap();

    // Second client reads it back.
    let mut client2 = HarmonyClient::new("wss://h", "wss://q").with_hint_cache_dir(&tmp);
    client2.set_master_key([0x77u8; 16]);
    // No catalog needed on restore — fingerprint includes db shape
    // + master key, both of which we supply here directly.
    let restored = client2.restore_hints_from_cache(&info).unwrap();
    assert!(restored);
    assert_eq!(client2.loaded_db_id, Some(info.db_id));
    assert_eq!(client2.index_groups.len(), info.index_k as usize);
    assert_eq!(client2.chunk_groups.len(), info.chunk_k as usize);

    // Cold-cache path: different master key → fingerprint mismatch
    // → `restore_hints_from_cache` returns false (not an error),
    // the groups stay invalidated.
    let mut client3 = HarmonyClient::new("wss://h", "wss://q").with_hint_cache_dir(&tmp);
    client3.set_master_key([0x88u8; 16]); // different key
    let restored3 = client3.restore_hints_from_cache(&info).unwrap();
    assert!(!restored3);
    assert!(client3.loaded_db_id.is_none());
    assert!(client3.index_groups.is_empty());

    // Cleanup.
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn restore_hints_from_cache_returns_false_when_dir_unset() {
    let info = sample_db_info();
    let mut client = HarmonyClient::new("wss://h", "wss://q");
    assert!(!client.restore_hints_from_cache(&info).unwrap());
}

#[test]
fn restore_hints_from_cache_returns_false_when_file_missing() {
    let info = sample_db_info();
    let tmp = std::env::temp_dir().join(format!(
        "pir-sdk-harmony-missing-{}-{}",
        std::process::id(),
        pir_core::merkle::sha256(b"missing")[0]
    ));
    let mut client = HarmonyClient::new("wss://h", "wss://q").with_hint_cache_dir(&tmp);
    // No file yet → cold cache returns false.
    let restored = client.restore_hints_from_cache(&info).unwrap();
    assert!(!restored);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn persist_hints_to_cache_is_noop_when_nothing_loaded() {
    // Sanity: if we haven't loaded anything, persist is a no-op
    // even with a cache directory set (no panics, no stray files).
    let info = sample_db_info();
    let tmp = std::env::temp_dir().join(format!(
        "pir-sdk-harmony-noop-{}-{}",
        std::process::id(),
        pir_core::merkle::sha256(b"noop")[0]
    ));
    let client = HarmonyClient::new("wss://h", "wss://q").with_hint_cache_dir(&tmp);
    client.persist_hints_to_cache(&info).unwrap();
    // No file should have been written.
    let path = client.cache_path_for(&info).unwrap();
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn cache_path_for_is_none_when_dir_unset() {
    let client = HarmonyClient::new("wss://h", "wss://q");
    assert!(client.cache_path_for(&sample_db_info()).is_none());
}

#[test]
fn cache_path_for_uses_fingerprint_filename() {
    let info = sample_db_info();
    let client = HarmonyClient::new("wss://h", "wss://q").with_hint_cache_dir("/tmp/dir");
    let path = client.cache_path_for(&info).unwrap();
    assert_eq!(path.parent(), Some(std::path::Path::new("/tmp/dir")));
    let filename = path.file_name().unwrap().to_string_lossy();
    assert!(filename.ends_with(".hints"));
    assert_eq!(filename.len(), 32 + ".hints".len());
}

// ─── Session 5: state listener + server_urls + db_id tests ─────────────

/// Recorder impl of [`StateListener`] — records every transition in a
/// mutex-guarded vec so assertions can check ordering across the
/// async connect/disconnect transitions.
struct RecordingListener {
    events: std::sync::Mutex<Vec<ConnectionState>>,
}

impl StateListener for RecordingListener {
    fn on_state_change(&self, state: ConnectionState) {
        self.events.lock().unwrap().push(state);
    }
}

/// `connect_with_transport` fires a `Connected` event on the
/// registered listener. This is the main state-listener contract
/// the WASM `onStateChange` surface relies on.
#[test]
fn state_listener_fires_on_connect_with_transport() {
    use crate::transport::mock::MockTransport;
    let listener = Arc::new(RecordingListener {
        events: std::sync::Mutex::new(Vec::new()),
    });
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.set_state_listener(Some(listener.clone()));
    client.connect_with_transport(
        Box::new(MockTransport::new("wss://mock-hint")),
        Box::new(MockTransport::new("wss://mock-query")),
    );
    let events = listener.events.lock().unwrap();
    assert_eq!(&*events, &[ConnectionState::Connected]);
}

/// `set_state_listener(None)` silences a previously registered
/// listener — subsequent transitions must not reach it.
#[test]
fn set_state_listener_none_silences_listener() {
    use crate::transport::mock::MockTransport;
    let listener = Arc::new(RecordingListener {
        events: std::sync::Mutex::new(Vec::new()),
    });
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.set_state_listener(Some(listener.clone()));
    client.set_state_listener(None);
    client.connect_with_transport(
        Box::new(MockTransport::new("wss://mock-hint")),
        Box::new(MockTransport::new("wss://mock-query")),
    );
    assert!(listener.events.lock().unwrap().is_empty());
}

/// Replacing the listener must swap the sink cleanly — only the
/// new listener sees subsequent events.
#[test]
fn set_state_listener_replaces_previous() {
    use crate::transport::mock::MockTransport;
    let old = Arc::new(RecordingListener {
        events: std::sync::Mutex::new(Vec::new()),
    });
    let new = Arc::new(RecordingListener {
        events: std::sync::Mutex::new(Vec::new()),
    });
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.set_state_listener(Some(old.clone()));
    client.set_state_listener(Some(new.clone()));
    client.connect_with_transport(
        Box::new(MockTransport::new("wss://mock-hint")),
        Box::new(MockTransport::new("wss://mock-query")),
    );
    assert!(old.events.lock().unwrap().is_empty());
    assert_eq!(&*new.events.lock().unwrap(), &[ConnectionState::Connected]);
}

/// Smoke test: `server_urls()` echoes the constructor arguments in
/// `(hint, query)` order — mirrors DPF's `(server0, server1)`.
#[test]
fn server_urls_returns_configured_urls() {
    let client = HarmonyClient::new("wss://hint.example", "wss://query.example");
    let (h, q) = client.server_urls();
    assert_eq!(h, "wss://hint.example");
    assert_eq!(q, "wss://query.example");
}

/// `db_id()` initially None, becomes `Some(id)` after hints populate,
/// and `set_db_id(same)` is an idempotent no-op.
#[test]
fn db_id_roundtrip_with_same_id_is_noop() {
    let info = sample_db_info();
    let mut client = HarmonyClient::new("wss://h", "wss://q");
    assert_eq!(client.db_id(), None);
    populate_main_groups(&mut client, &info);
    assert_eq!(client.db_id(), Some(info.db_id));
    // Same id → groups stay loaded.
    client.set_db_id(info.db_id);
    assert_eq!(client.db_id(), Some(info.db_id));
    assert!(!client.index_groups.is_empty());
}

/// `set_db_id(different)` must invalidate ALL group maps — main
/// AND sibling. Different db has different tree tops, so stale
/// siblings would fail verification on next use.
#[test]
fn set_db_id_different_invalidates_all_groups() {
    let info = sample_db_info();
    let mut client = HarmonyClient::new("wss://h", "wss://q");
    populate_main_groups(&mut client, &info);
    // Simulate some sibling state being loaded too.
    client.sibling_hints_loaded = Some(info.db_id);

    client.set_db_id(info.db_id + 1);
    assert_eq!(client.db_id(), None);
    assert!(client.index_groups.is_empty());
    assert!(client.chunk_groups.is_empty());
    assert!(client.index_sib_groups.is_empty());
    assert!(client.chunk_sib_groups.is_empty());
    assert!(client.sibling_hints_loaded.is_none());
}

/// `min_queries_remaining()` is None when no groups are loaded, and
/// returns the *min* across all loaded group maps once populated.
#[test]
fn min_queries_remaining_aggregates_across_group_maps() {
    let info = sample_db_info();
    let mut client = HarmonyClient::new("wss://h", "wss://q");
    assert_eq!(client.min_queries_remaining(), None);
    populate_main_groups(&mut client, &info);
    // All freshly-populated groups carry `max_queries` budget; the
    // min must be Some and equal the group budget.
    let min = client.min_queries_remaining();
    assert!(min.is_some());
    let max_q = client.index_groups.values().next().unwrap().max_queries();
    assert_eq!(min, Some(max_q));
}

/// `estimate_hint_size_bytes` is 0 when nothing is loaded, and
/// positive (and matches `save_hints_bytes().len()`) when loaded.
#[test]
fn estimate_hint_size_bytes_matches_save_hints_length() {
    let info = sample_db_info();
    let mut client = HarmonyClient::new("wss://h", "wss://q");
    client.set_master_key([0x55u8; 16]);
    assert_eq!(client.estimate_hint_size_bytes(), 0);

    client.catalog = Some(DatabaseCatalog {
        databases: vec![info.clone()],
    });
    populate_main_groups(&mut client, &info);
    let bytes = client.save_hints_bytes().unwrap().expect("bytes");
    assert_eq!(client.estimate_hint_size_bytes(), bytes.len());
    assert!(bytes.len() > 0);
}

/// `cache_fingerprint` is a pure function of `(master_key,
/// prp_backend, db_info)` — calling it twice returns identical bytes,
/// and it matches the fingerprint embedded in the save-hints blob
/// header (bytes 6..22 after `PSH1` magic + 2-byte version + 32-byte
/// schema-hash).
#[test]
fn cache_fingerprint_is_stable_and_matches_blob_header() {
    let info = sample_db_info();
    let mut client = HarmonyClient::new("wss://h", "wss://q");
    client.set_master_key([0xA5u8; 16]);

    let fp1 = client.cache_fingerprint(&info);
    let fp2 = client.cache_fingerprint(&info);
    assert_eq!(fp1, fp2);

    // Different master key → different fingerprint.
    let mut other = HarmonyClient::new("wss://h", "wss://q");
    other.set_master_key([0xB6u8; 16]);
    assert_ne!(fp1, other.cache_fingerprint(&info));

    // Cross-check against hint_cache::CacheKey directly — that's
    // the authoritative source for the blob-header fingerprint.
    let expected =
        hint_cache::CacheKey::from_db_info(client.master_prp_key, client.prp_backend, &info)
            .fingerprint();
    assert_eq!(fp1, expected);
}

// ─── Tracing smoke test ──────────────────────────────────────────────
//
// Companion to the `tracing_instrument_emits_backend_field_for_dpf`
// test in `dpf.rs`. Installs a scoped `tracing_subscriber::fmt`
// subscriber backed by an in-memory buffer, drives an instrumented
// method, and asserts the Harmony span emitted `backend="harmony"`.
// Catches accidental `#[tracing::instrument]` removal or a
// `backend` field rename at test time instead of only in production
// log searches.

#[derive(Clone)]
struct BufferWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufferWriter {
    type Writer = BufferWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn tracing_instrument_emits_backend_field_for_harmony() {
    use crate::transport::mock::MockTransport;
    use tracing_subscriber::fmt;

    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = fmt::Subscriber::builder()
        .with_span_events(fmt::format::FmtSpan::CLOSE)
        .with_writer(BufferWriter(buf.clone()))
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-hint")),
            Box::new(MockTransport::new("wss://mock-query")),
        );
    });

    let captured = String::from_utf8(buf.lock().unwrap().clone())
        .expect("tracing writer produced valid UTF-8");
    assert!(
        captured.contains("connect_with_transport"),
        "expected span name in captured output, got: {}",
        captured
    );
    assert!(
        captured.contains("backend=\"harmony\""),
        "expected backend=\"harmony\" field in captured output, got: {}",
        captured
    );
}

// ─── Metrics recorder tests ─────────────────────────────────────────────

/// Installing a recorder before `connect_with_transport` fires one
/// `on_connect` per transport (hint + query) and propagates the
/// recorder to both transports.
#[test]
fn metrics_recorder_fires_on_connect_via_inject() {
    use crate::transport::mock::MockTransport;
    use pir_sdk::AtomicMetrics;

    let recorder = Arc::new(AtomicMetrics::new());
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.set_metrics_recorder(Some(recorder.clone()));

    client.connect_with_transport(
        Box::new(MockTransport::new("wss://mock-hint")),
        Box::new(MockTransport::new("wss://mock-query")),
    );

    let snap = recorder.snapshot();
    assert_eq!(
        snap.connects, 2,
        "expected one on_connect per transport (2 total)"
    );
    assert_eq!(snap.disconnects, 0);
}

/// `disconnect` fires a single `on_disconnect`.
#[tokio::test]
async fn metrics_recorder_fires_on_disconnect() {
    use crate::transport::mock::MockTransport;
    use pir_sdk::AtomicMetrics;

    let recorder = Arc::new(AtomicMetrics::new());
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.set_metrics_recorder(Some(recorder.clone()));

    client.connect_with_transport(
        Box::new(MockTransport::new("wss://mock-hint")),
        Box::new(MockTransport::new("wss://mock-query")),
    );
    client.disconnect().await.unwrap();

    let snap = recorder.snapshot();
    assert_eq!(snap.connects, 2);
    assert_eq!(snap.disconnects, 1);
}

/// Installing the recorder after `connect_with_transport` still
/// propagates the handle to both transports. Proved by driving a
/// `send` through each and reading back the byte counts.
#[tokio::test]
async fn metrics_recorder_propagates_to_transports_after_connect() {
    use crate::transport::mock::MockTransport;
    use crate::transport::PirTransport;
    use pir_sdk::AtomicMetrics;

    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.connect_with_transport(
        Box::new(MockTransport::new("wss://mock-hint")),
        Box::new(MockTransport::new("wss://mock-query")),
    );

    let recorder = Arc::new(AtomicMetrics::new());
    client.set_metrics_recorder(Some(recorder.clone()));

    client
        .hint_conn
        .as_mut()
        .unwrap()
        .send(vec![1, 2, 3])
        .await
        .unwrap();
    client
        .query_conn
        .as_mut()
        .unwrap()
        .send(vec![4, 5])
        .await
        .unwrap();

    let snap = recorder.snapshot();
    assert_eq!(snap.bytes_sent, 5);
    assert_eq!(snap.frames_sent, 2);
}

/// `set_metrics_recorder(None)` silences both client-level and
/// transport-level callbacks.
#[tokio::test]
async fn metrics_recorder_uninstall_silences_everything() {
    use crate::transport::mock::MockTransport;
    use crate::transport::PirTransport;
    use pir_sdk::AtomicMetrics;

    let recorder = Arc::new(AtomicMetrics::new());
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.set_metrics_recorder(Some(recorder.clone()));
    client.connect_with_transport(
        Box::new(MockTransport::new("wss://mock-hint")),
        Box::new(MockTransport::new("wss://mock-query")),
    );

    client.set_metrics_recorder(None);
    client
        .hint_conn
        .as_mut()
        .unwrap()
        .send(vec![9; 42])
        .await
        .unwrap();
    client.disconnect().await.unwrap();

    let snap = recorder.snapshot();
    assert_eq!(snap.connects, 2);
    assert_eq!(snap.disconnects, 0);
    assert_eq!(snap.bytes_sent, 0);
    assert_eq!(snap.frames_sent, 0);
}

/// `fire_query_start` returns `Some(Instant)` only when a recorder
/// is installed — keeps the no-recorder path at zero overhead.
#[test]
fn fire_query_start_returns_instant_only_when_recorder_installed() {
    use pir_sdk::AtomicMetrics;

    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    assert!(client.fire_query_start(0, 10).is_none());

    let recorder = Arc::new(AtomicMetrics::new());
    client.set_metrics_recorder(Some(recorder));
    assert!(client.fire_query_start(0, 10).is_some());
}

/// `fire_query_end` records non-zero duration when threading the
/// captured `Instant`. We sleep a few ms to make the measured
/// duration comfortably distinguishable from clock jitter.
#[test]
fn fire_query_end_records_non_zero_duration_with_recorder() {
    use pir_sdk::AtomicMetrics;
    use std::thread::sleep;
    use std::time::Duration as StdDuration;

    let recorder = Arc::new(AtomicMetrics::new());
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.set_metrics_recorder(Some(recorder.clone()));

    let started = client.fire_query_start(0, 10);
    assert!(started.is_some());
    sleep(StdDuration::from_millis(5));
    client.fire_query_end(0, 10, true, started);

    let snap = recorder.snapshot();
    assert_eq!(snap.queries_started, 1);
    assert_eq!(snap.queries_completed, 1);
    assert!(
        snap.min_query_latency_micros >= 1_000,
        "expected min_query_latency_micros >= 1000, got {}",
        snap.min_query_latency_micros
    );
}

/// `fire_query_end` with `started_at = None` records `Duration::ZERO`
/// — best-effort observation per [`PirMetrics::on_query_end`].
#[test]
fn fire_query_end_with_none_start_records_zero_duration() {
    use pir_sdk::AtomicMetrics;

    let recorder = Arc::new(AtomicMetrics::new());
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");

    let started = client.fire_query_start(0, 10); // None (no recorder yet)
    client.set_metrics_recorder(Some(recorder.clone()));
    client.fire_query_end(0, 10, true, started);

    let snap = recorder.snapshot();
    assert_eq!(snap.queries_completed, 1);
    assert_eq!(snap.min_query_latency_micros, 0);
    assert_eq!(snap.max_query_latency_micros, 0);
}

// ─── Merkle INDEX item-count symmetry invariant ─────────────────
//
// Mirrors the DPF tests in `dpf.rs`. CLAUDE.md "Merkle INDEX
// Item-Count Symmetry" requires every INDEX query to emit exactly
// `INDEX_CUCKOO_NUM_HASHES` Merkle items regardless of outcome.
// For HarmonyPIR specifically, the extra probe costs one extra
// wire round per `found@h=0` query (the two cuckoo positions are
// separate per-h batch queries, not a single XOR'd response like
// DPF/Onion), so the loop in `query_single` must NOT early-exit
// on match.

fn h_idx_bin(bin_index: u32) -> IndexBinTrace {
    IndexBinTrace {
        pbc_group: 3,
        bin_index,
        bin_content: vec![0u8; 16],
    }
}

fn h_chk_bin(bin_index: u32) -> ChunkBinTrace {
    ChunkBinTrace {
        pbc_group: 5,
        bin_index,
        bin_content: vec![0u8; 32],
    }
}

#[test]
fn items_from_trace_found_at_h0_emits_two() {
    let trace = QueryTraces {
        index_bins: vec![h_idx_bin(100), h_idx_bin(200)],
        matched_index_idx: Some(0),
        chunk_bins: vec![h_chk_bin(50)],
    };
    let items = items_from_trace(&trace);
    assert_eq!(items.len(), INDEX_CUCKOO_NUM_HASHES);
    assert_eq!(items[0].chunk_bin_indices.len(), 1);
    assert_eq!(items[1].chunk_bin_indices.len(), 0);
}

#[test]
fn items_from_trace_found_at_h1_emits_two() {
    let trace = QueryTraces {
        index_bins: vec![h_idx_bin(100), h_idx_bin(200)],
        matched_index_idx: Some(1),
        chunk_bins: vec![h_chk_bin(50)],
    };
    let items = items_from_trace(&trace);
    assert_eq!(items.len(), INDEX_CUCKOO_NUM_HASHES);
    // Chunks always live on items[0], regardless of which INDEX
    // position matched. Mirrors the dpf::items_from_trace shape.
    assert_eq!(items[0].chunk_bin_indices.len(), 1);
    assert_eq!(items[1].chunk_bin_indices.len(), 0);
}

#[test]
fn items_from_trace_not_found_emits_two() {
    let trace = QueryTraces {
        index_bins: vec![h_idx_bin(100), h_idx_bin(200)],
        matched_index_idx: None,
        chunk_bins: vec![],
    };
    let items = items_from_trace(&trace);
    assert_eq!(items.len(), INDEX_CUCKOO_NUM_HASHES);
    assert_eq!(items[0].chunk_bin_indices.len(), 0);
    assert_eq!(items[1].chunk_bin_indices.len(), 0);
}

#[test]
fn items_from_trace_whale_emits_two_no_chunks() {
    let trace = QueryTraces {
        index_bins: vec![h_idx_bin(100), h_idx_bin(200)],
        matched_index_idx: Some(0),
        chunk_bins: vec![],
    };
    let items = items_from_trace(&trace);
    assert_eq!(items.len(), INDEX_CUCKOO_NUM_HASHES);
    assert_eq!(items[0].chunk_bin_indices.len(), 0);
    assert_eq!(items[1].chunk_bin_indices.len(), 0);
}

// ─── Leakage recorder wiring ────────────────────────────────────────────

/// `record_round` emits to an installed buffering recorder.
#[test]
fn leakage_recorder_records_via_helper_harmony() {
    use pir_sdk::BufferingLeakageRecorder;

    let rec = Arc::new(BufferingLeakageRecorder::new());
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.set_leakage_recorder(Some(rec.clone()));

    // T - 1 indices per slot is the HarmonyPIR per-group invariant —
    // a hypothetical T=8 here yields items[g] = 7.
    client.record_round(RoundProfile {
        kind: RoundKind::Index,
        server_id: 0,
        db_id: Some(3),
        request_bytes: 1234,
        response_bytes: 5678,
        items: vec![7; 75],
    });

    let snap = rec.snapshot();
    assert_eq!(snap.len(), 1);
    assert!(matches!(snap[0].kind, RoundKind::Index));
    assert_eq!(snap[0].server_id, 0); // 0 = query server for harmony
    assert_eq!(snap[0].items.len(), 75);
    assert!(snap[0].items.iter().all(|&x| x == 7));
}

/// `set_leakage_recorder(None)` silences subsequent emissions.
#[test]
fn leakage_recorder_uninstall_silences_harmony() {
    use pir_sdk::BufferingLeakageRecorder;

    let rec = Arc::new(BufferingLeakageRecorder::new());
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.set_leakage_recorder(Some(rec.clone()));
    client.set_leakage_recorder(None);

    client.record_round(RoundProfile {
        kind: RoundKind::HarmonyHintRefresh,
        server_id: 1,
        db_id: Some(0),
        request_bytes: 100,
        response_bytes: 200,
        items: vec![1; 75],
    });

    assert!(rec.is_empty());
}

/// Driving a real `fetch_legacy_info` through `MockTransport` emits
/// exactly one `Info` round on server 1 (hint server).
#[tokio::test]
async fn leakage_recorder_captures_info_round_end_to_end_harmony() {
    use crate::transport::mock::MockTransport;
    use pir_sdk::BufferingLeakageRecorder;

    let rec = Arc::new(BufferingLeakageRecorder::new());
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.set_leakage_recorder(Some(rec.clone()));

    // Valid REQ_HARMONY_GET_INFO (0x40) response shape mirrors
    // REQ_GET_INFO: [4B len=19][1B variant=0x40][4B index_bins]
    // [4B chunk_bins][1B index_k][1B chunk_k][8B tag_seed].
    let mut hint_mock = MockTransport::new("wss://mock-hint");
    let mut info_resp = Vec::with_capacity(23);
    info_resp.extend_from_slice(&19u32.to_le_bytes());
    info_resp.push(0x40); // RESP_HARMONY_INFO
    info_resp.extend_from_slice(&1024u32.to_le_bytes()); // index_bins
    info_resp.extend_from_slice(&2048u32.to_le_bytes()); // chunk_bins
    info_resp.push(75); // index_k
    info_resp.push(80); // chunk_k
    info_resp.extend_from_slice(&0u64.to_le_bytes()); // tag_seed
    assert_eq!(info_resp.len(), 23);
    hint_mock.enqueue_response(info_resp);

    client.connect_with_transport(
        Box::new(hint_mock),
        Box::new(MockTransport::new("wss://mock-query")),
    );
    let _info = client.fetch_legacy_info().await.unwrap();

    let snap = rec.snapshot();
    assert_eq!(snap.len(), 1, "expected exactly one Info round");
    let r = &snap[0];
    assert!(matches!(r.kind, RoundKind::Info));
    assert_eq!(r.server_id, 1, "harmony info goes to hint server");
    assert_eq!(r.db_id, None);
    // request: REQ_HARMONY_GET_INFO is `[4B len=1][1B 0x40]` = 5 bytes.
    assert_eq!(r.request_bytes, 5);
    // response: 23 bytes on the wire (4-byte prefix + 19-byte payload).
    assert_eq!(r.response_bytes, 23);
    assert!(r.items.is_empty());
}

/// Leakage and metrics recorders coexist independently.
#[tokio::test]
async fn leakage_and_metrics_recorders_are_independent_harmony() {
    use crate::transport::mock::MockTransport;
    use pir_sdk::{AtomicMetrics, BufferingLeakageRecorder};

    let leakage = Arc::new(BufferingLeakageRecorder::new());
    let metrics = Arc::new(AtomicMetrics::new());
    let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
    client.set_leakage_recorder(Some(leakage.clone()));
    client.set_metrics_recorder(Some(metrics.clone()));

    let mut hint_mock = MockTransport::new("wss://mock-hint");
    let mut info_resp = Vec::with_capacity(23);
    info_resp.extend_from_slice(&19u32.to_le_bytes());
    info_resp.push(0x40);
    info_resp.extend_from_slice(&1024u32.to_le_bytes());
    info_resp.extend_from_slice(&2048u32.to_le_bytes());
    info_resp.push(75);
    info_resp.push(80);
    info_resp.extend_from_slice(&0u64.to_le_bytes());
    hint_mock.enqueue_response(info_resp);

    client.connect_with_transport(
        Box::new(hint_mock),
        Box::new(MockTransport::new("wss://mock-query")),
    );
    let _info = client.fetch_legacy_info().await.unwrap();

    assert_eq!(leakage.len(), 1);
    let snap = metrics.snapshot();
    assert!(snap.bytes_sent > 0);
    assert!(snap.bytes_received > 0);
}
