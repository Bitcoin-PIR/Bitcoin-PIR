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
