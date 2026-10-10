//! A plan that only carries changes must run on the previous sync's results.
//! `sync()` keeps none, so it only accepts a full sync.

use super::*;
use pir_core::params::{
    CHUNK_SLOTS_PER_BIN, CHUNK_SLOT_SIZE, INDEX_SLOTS_PER_BIN, INDEX_SLOT_SIZE,
};
use pir_sdk::DatabaseKind;
use std::collections::VecDeque;
use std::sync::Mutex;

const BASE: u32 = 100;
const TIP: u32 = 110;
const ADDRS: [ScriptHash; 2] = [[0x11; 20], [0x22; 20]];

fn test_db(db_id: u8, kind: DatabaseKind, height: u32) -> DatabaseInfo {
    DatabaseInfo {
        db_id,
        kind,
        name: format!("db{db_id}"),
        height,
        index_bins: 128,
        chunk_bins: 128,
        index_k: 4,
        chunk_k: 4,
        tag_seed: 0,
        // libdpf needs a domain of at least 2^7.
        dpf_n_index: 7,
        dpf_n_chunk: 7,
        // No bucket Merkle keeps the empty-database transport free of sibling
        // rounds; the default advisory root policy needs no installed roots.
        has_bucket_merkle: false,
        index_master_seed: 1,
        chunk_master_seed: 2,
        anchor_kind: 0,
        anchor_bytes: Vec::new(),
    }
}

/// Full snapshot at BASE (db 0) and one delta BASE -> TIP (db 1).
fn full_plus_delta_catalog() -> DatabaseCatalog {
    DatabaseCatalog {
        databases: vec![
            test_db(0, DatabaseKind::Full, BASE),
            test_db(1, DatabaseKind::Delta { base_height: BASE }, TIP),
        ],
    }
}

fn utxo(txid_byte: u8, vout: u32, amount_sats: u64) -> UtxoEntry {
    UtxoEntry {
        txid: [txid_byte; 32],
        vout,
        amount_sats,
    }
}

/// A wallet's results at BASE: both addresses funded.
fn previous_results() -> Vec<Option<QueryResult>> {
    vec![
        Some(QueryResult::with_entries(vec![
            utxo(0xa1, 0, 5_000),
            utxo(0xa2, 1, 7_000),
        ])),
        Some(QueryResult::with_entries(vec![utxo(0xb1, 0, 9_000)])),
    ]
}

fn entries(results: &[Option<QueryResult>]) -> Vec<Option<Vec<UtxoEntry>>> {
    results
        .iter()
        .map(|r| r.as_ref().map(|r| r.entries.clone()))
        .collect()
}

/// `encode_batch_query` layout: `[u32 len][variant][u16 round_id][u8 groups]
/// [u8 keys/group] ([u16 key_len][key])* [db_id if != 0]`.
/// Returns `(variant, round_id, groups, keys_per_group, db_id, request_len)`.
fn batch_shape(request: &[u8]) -> (u8, u16, usize, usize, u8, usize) {
    let variant = request[4];
    let round_id = u16::from_le_bytes([request[5], request[6]]);
    let groups = request[7] as usize;
    let per_group = request[8] as usize;
    let mut pos = 9;
    for _ in 0..groups * per_group {
        let len = u16::from_le_bytes([request[pos], request[pos + 1]]) as usize;
        pos += 2 + len;
    }
    let db_id = request.get(pos).copied().unwrap_or(0);
    (variant, round_id, groups, per_group, db_id, request.len())
}

/// DPF server stand-in for an EMPTY database: every batch request gets
/// all-zero bins, so the two shares XOR to zero and no address is present.
/// For a delta database that means "nothing changed since the base height".
struct ZeroDpfTransport {
    url: &'static str,
    pending: VecDeque<Vec<u8>>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait]
impl PirTransport for ZeroDpfTransport {
    async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
        self.sent.lock().unwrap().push(data.clone());
        self.pending.push_back(data);
        Ok(())
    }

    async fn recv(&mut self) -> PirResult<Vec<u8>> {
        let request = self
            .pending
            .pop_front()
            .ok_or_else(|| PirError::Protocol("zero DPF transport: no request".into()))?;
        let (variant, round_id, groups, per_group, _, _) = batch_shape(&request);
        let width = match variant {
            0x11 => INDEX_SLOT_SIZE * INDEX_SLOTS_PER_BIN,
            0x21 => CHUNK_SLOT_SIZE * CHUNK_SLOTS_PER_BIN,
            other => panic!("unexpected DPF request variant {other:#04x}"),
        };
        let mut body = vec![variant];
        body.extend_from_slice(&round_id.to_le_bytes());
        body.push(groups as u8);
        body.push(per_group as u8);
        for _ in 0..groups * per_group {
            body.extend_from_slice(&(width as u16).to_le_bytes());
            body.resize(body.len() + width, 0);
        }
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    async fn roundtrip(&mut self, _request: &[u8]) -> PirResult<Vec<u8>> {
        Err(PirError::Protocol(
            "zero DPF transport: unexpected roundtrip".into(),
        ))
    }

    async fn close(&mut self) -> PirResult<()> {
        Ok(())
    }

    fn url(&self) -> &str {
        self.url
    }
}

/// A connected client over the empty database, plus every request it sends.
fn zero_db_client() -> (DpfClient, Arc<Mutex<Vec<Vec<u8>>>>) {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mut client = DpfClient::new("mock://dpf-0", "mock://dpf-1");
    client.connect_with_transport(
        Box::new(ZeroDpfTransport {
            url: "mock://dpf-0",
            pending: VecDeque::new(),
            sent: sent.clone(),
        }),
        Box::new(ZeroDpfTransport {
            url: "mock://dpf-1",
            pending: VecDeque::new(),
            sent: sent.clone(),
        }),
    );
    client.catalog = Some(full_plus_delta_catalog());
    (client, sent)
}

fn take_db_ids(sent: &Mutex<Vec<Vec<u8>>>) -> Vec<u8> {
    std::mem::take(&mut *sent.lock().unwrap())
        .iter()
        .map(|request| batch_shape(request).4)
        .collect()
}

#[derive(Default)]
struct ErrorRecorder {
    errors: Mutex<Vec<String>>,
}

impl SyncProgress for ErrorRecorder {
    fn on_step_start(&self, _: usize, _: usize, _: &str) {}
    fn on_step_progress(&self, _: usize, _: f32) {}
    fn on_step_complete(&self, _: usize) {}
    fn on_complete(&self, _: u32) {}
    fn on_error(&self, error: &PirError) {
        self.errors.lock().unwrap().push(error.to_string());
    }
}

#[tokio::test]
async fn sync_rejects_any_height_before_sending() {
    let (mut client, sent) = zero_db_client();
    // From 50 there is no delta chain, so the plan would fall back to a full
    // sync; it is refused anyway, so the outcome never depends on the catalog.
    for height in [50, BASE, TIP] {
        let error = client.sync(&ADDRS, Some(height)).await.unwrap_err();
        assert!(
            matches!(error, PirError::InvalidState(_)),
            "{height}: {error}"
        );

        let recorder = ErrorRecorder::default();
        let error = client
            .sync_with_progress(&ADDRS, Some(height), &recorder)
            .await
            .unwrap_err();
        assert!(
            matches!(error, PirError::InvalidState(_)),
            "{height}: {error}"
        );
        assert_eq!(recorder.errors.lock().unwrap().len(), 1);
    }
    assert!(sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn full_sync_still_runs_without_previous_results() {
    let (mut client, sent) = zero_db_client();
    let plain = client.sync(&ADDRS, None).await.unwrap();
    let plain_ids = take_db_ids(&sent);
    let progress = client
        .sync_with_progress(&ADDRS, Some(0), &ErrorRecorder::default())
        .await
        .unwrap();
    let progress_ids = take_db_ids(&sent);
    for (result, ids) in [(plain, plain_ids), (progress, progress_ids)] {
        assert!(result.was_fresh_sync);
        assert_eq!(result.synced_height, TIP);
        assert_eq!(entries(&result.results), vec![None, None]);
        let first_delta = ids.iter().position(|&id| id == 1).unwrap();
        assert!(first_delta > 0, "{ids:?}");
        assert!(ids[..first_delta].iter().all(|&id| id == 0), "{ids:?}");
        assert!(ids[first_delta..].iter().all(|&id| id == 1), "{ids:?}");
    }
}

#[tokio::test]
async fn delta_and_tip_plans_need_the_previous_results() {
    let (mut client, sent) = zero_db_client();
    let catalog = full_plus_delta_catalog();
    let delta = compute_sync_plan(&catalog, Some(BASE)).unwrap();
    let at_tip = compute_sync_plan(&catalog, Some(TIP)).unwrap();
    for plan in [&delta, &at_tip] {
        let error = client.sync_with_plan(&ADDRS, plan, None).await.unwrap_err();
        assert!(matches!(error, PirError::InvalidState(_)), "{error}");
        let error = client
            .sync_with_plan(&ADDRS, plan, Some(&[None][..]))
            .await
            .unwrap_err();
        assert!(matches!(error, PirError::InvalidState(_)), "{error}");
    }
    assert!(sent.lock().unwrap().is_empty());

    // With the previous results: the empty delta leaves both wallets as they
    // were, and at the tip nothing is sent at all.
    let previous = previous_results();
    let synced = client
        .sync_with_plan(&ADDRS, &delta, Some(&previous))
        .await
        .unwrap();
    assert_eq!(synced.synced_height, TIP);
    assert_eq!(entries(&synced.results), entries(&previous));
    let ids = take_db_ids(&sent);
    assert!(!ids.is_empty() && ids.iter().all(|&id| id == 1), "{ids:?}");

    let synced = client
        .sync_with_plan(&ADDRS, &at_tip, Some(&previous))
        .await
        .unwrap();
    assert_eq!(entries(&synced.results), entries(&previous));
    assert!(sent.lock().unwrap().is_empty());
}

/// The previous results stay local: what they contain never changes the
/// requests, so resuming leaks nothing about which addresses were found.
#[tokio::test]
async fn previous_results_never_change_what_is_sent() {
    let delta = compute_sync_plan(&full_plus_delta_catalog(), Some(BASE)).unwrap();
    let mut shapes = Vec::new();
    for previous in [previous_results(), vec![None, None]] {
        let (mut client, sent) = zero_db_client();
        client
            .sync_with_plan(&ADDRS, &delta, Some(&previous))
            .await
            .unwrap();
        let requests = std::mem::take(&mut *sent.lock().unwrap());
        shapes.push(requests.iter().map(|r| batch_shape(r)).collect::<Vec<_>>());
    }
    assert!(!shapes[0].is_empty());
    assert_eq!(shapes[0], shapes[1]);
}
