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
