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

// ─── Hint cache plumbing tests ─────────────────────────────────────────
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
