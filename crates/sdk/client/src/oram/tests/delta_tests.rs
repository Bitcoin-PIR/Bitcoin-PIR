//! A delta record is not a UTXO list: for a delta database the query keeps
//! its bytes for the merge and does not decode them as one.

use super::*;
use pir_sdk::{decode_delta_data, DatabaseInfo, DatabaseKind};

/// Two spent outpoints and no new ones. The second txid starts with ten
/// bytes >= 0x80, which the UTXO-list decoder reads as an over-long amount
/// varint.
fn two_spent_record() -> Vec<u8> {
    let mut txid = [0u8; 32];
    txid[..10].fill(0xff);
    let mut out = vec![2];
    out.extend_from_slice(&[0x02; 32]);
    out.push(0);
    out.extend_from_slice(&txid);
    out.push(0);
    out.push(0);
    out
}

fn found(raw: Vec<u8>) -> OramLookupItem {
    OramLookupItem {
        found: true,
        whale: false,
        start_chunk_id: 0,
        num_chunks: 2,
        raw_chunk_data: raw,
    }
}

fn catalog(kind: DatabaseKind) -> DatabaseCatalog {
    DatabaseCatalog {
        databases: vec![DatabaseInfo {
            db_id: 1,
            kind,
            name: "db1".into(),
            height: 110,
            index_bins: 128,
            chunk_bins: 128,
            index_k: 4,
            chunk_k: 4,
            tag_seed: 0,
            dpf_n_index: 7,
            dpf_n_chunk: 7,
            has_bucket_merkle: false,
            index_master_seed: 1,
            chunk_master_seed: 2,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        }],
    }
}

fn connected(response: Vec<u8>, catalog: Option<DatabaseCatalog>) -> OramClient {
    let mut mock = MockTransport::new("mock://oram");
    mock.enqueue_response(response);
    let mut client = OramClient::new("mock://oram");
    client.connect_with_transport(Box::new(mock));
    client.catalog = catalog;
    client
}

#[test]
fn the_record_breaks_the_utxo_list_decoder() {
    assert!(decode_delta_data(&two_spent_record()).is_ok());
    assert!(decode_utxo_entries(&two_spent_record()).is_err());
}

#[tokio::test]
async fn delta_results_keep_raw_bytes_without_decoding() {
    let record = two_spent_record();
    let mut client = connected(
        encode_test_response(1, &[found(record.clone())]),
        Some(catalog(DatabaseKind::Delta { base_height: 100 })),
    );
    let results = client
        .query_batch(&[[9u8; SCRIPT_HASH_SIZE]], 1)
        .await
        .unwrap();
    let qr = results[0].as_ref().unwrap();
    assert!(qr.entries.is_empty());
    assert_eq!(qr.raw_chunk_data.as_ref(), Some(&record));

    let mut client = connected(
        encode_test_response(
            1,
            &[found(record.clone()), found(Vec::new()), found(Vec::new())],
        ),
        Some(catalog(DatabaseKind::Delta { base_height: 100 })),
    );
    let results = client
        .query_batch_padded(&[[9u8; SCRIPT_HASH_SIZE]], 3, 1)
        .await
        .unwrap();
    assert_eq!(
        results[0].as_ref().unwrap().raw_chunk_data.as_ref(),
        Some(&record)
    );
}

#[tokio::test]
async fn full_results_are_still_decoded() {
    let raw = pir_core::codec::serialize_utxo_data(&[pir_core::codec::UtxoEntry {
        txid: [0xab; 32],
        vout: 2,
        amount: 50_000,
    }]);
    let mut client = connected(
        encode_test_response(1, &[found(raw)]),
        Some(catalog(DatabaseKind::Full)),
    );
    let results = client
        .query_batch(&[[9u8; SCRIPT_HASH_SIZE]], 1)
        .await
        .unwrap();
    assert_eq!(results[0].as_ref().unwrap().entries[0].amount_sats, 50_000);

    // With no catalog the kind is unknown; results are decoded as before.
    let mut client = connected(encode_test_response(1, &[found(two_spent_record())]), None);
    assert!(client
        .query_batch(&[[9u8; SCRIPT_HASH_SIZE]], 1)
        .await
        .is_err());
}
