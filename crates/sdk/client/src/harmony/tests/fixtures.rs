use super::super::*;
use crate::transport::mock::MockTransport;
use pir_core::merkle::{compute_bin_leaf_hash, compute_parent_n, Hash256, ZERO_HASH};
use pir_db_attest::BuildKind;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

#[derive(Default)]
pub(super) struct RecordingSyncProgress {
    pub(super) events: Mutex<Vec<String>>,
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
pub(super) struct ZeroHarmonyQueryTransport {
    pending: VecDeque<Vec<u8>>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ZeroHarmonyQueryTransport {
    pub(super) fn new(sent: Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
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

pub(super) fn harmony_request_header(request: &[u8]) -> (u8, u16, usize) {
    assert!(request.len() >= 11);
    assert_eq!(request[4], REQ_HARMONY_BATCH_QUERY);
    (
        request[5],
        u16::from_le_bytes(request[6..8].try_into().unwrap()),
        u16::from_le_bytes(request[8..10].try_into().unwrap()) as usize,
    )
}

pub(super) fn zero_harmony_response(request: &[u8]) -> Vec<u8> {
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

pub(super) fn zero_tree_top(bins: u32, row_width: usize) -> TreeTop {
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

pub(super) fn session_db_info() -> DatabaseInfo {
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

pub(super) fn session_roots(db: &DatabaseInfo) -> VerifiedDatabaseRoots {
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

pub(super) fn seed_verified_session(client: &mut HarmonyClient) -> u8 {
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

pub(super) struct CloseTrackingTransport {
    pub(super) url: &'static str,
    pub(super) closed: Arc<AtomicBool>,
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

pub(super) struct ScriptedCloseTransport {
    url: &'static str,
    responses: VecDeque<Vec<u8>>,
    closed: Arc<AtomicBool>,
    sends: Arc<AtomicUsize>,
}

impl ScriptedCloseTransport {
    pub(super) fn new(
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

pub(super) struct PendingCloseTransport {
    pub(super) url: &'static str,
    pub(super) closed: Arc<AtomicBool>,
    pub(super) sends: Arc<AtomicUsize>,
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

pub(super) fn handshake_frame(server_eph_byte: u8) -> Vec<u8> {
    let mut payload = vec![0x06];
    payload.extend_from_slice(&[server_eph_byte; 32]);
    let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&payload);
    frame
}

pub(super) fn response_frame(body: Vec<u8>) -> Vec<u8> {
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

pub(super) fn harmony_batch_body(level: u8, round_id: u16, groups: &[(u8, &[u8])]) -> Vec<u8> {
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

pub(super) fn v1_hint_frame(group_id: u8, n: u32, t: u32, m: u32, hint_bytes: usize) -> Vec<u8> {
    let mut body = vec![RESP_HARMONY_HINTS, group_id];
    body.extend_from_slice(&n.to_le_bytes());
    body.extend_from_slice(&t.to_le_bytes());
    body.extend_from_slice(&m.to_le_bytes());
    body.resize(body.len() + hint_bytes, 0);
    response_frame(body)
}

pub(super) fn v2_pool_unavailable_frame() -> Vec<u8> {
    v2_error_frame(V2_HINT_POOL_UNAVAILABLE)
}

pub(super) fn v2_error_frame(reason: &str) -> Vec<u8> {
    let mut body = vec![RESP_ERROR];
    body.extend_from_slice(&(reason.len() as u32).to_le_bytes());
    body.extend_from_slice(reason.as_bytes());
    response_frame(body)
}

pub(super) fn v2_key_preamble_frame(
    backend: u8,
    level: u8,
    total_groups: u8,
    key: [u8; 16],
) -> Vec<u8> {
    let mut body = vec![RESP_HARMONY_HINTS_KEY, backend, level, total_groups];
    body.extend_from_slice(&key);
    response_frame(body)
}

pub(super) fn v2_terminal_frame(group_id: u8) -> Vec<u8> {
    response_frame(vec![RESP_HARMONY_HINTS, group_id])
}

pub(super) fn sample_db_info() -> DatabaseInfo {
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
pub(super) fn populate_main_groups(client: &mut HarmonyClient, info: &DatabaseInfo) {
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

pub(super) fn seed_verified_complete_hint_shape(
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

pub(super) fn populate_sibling_groups(
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
