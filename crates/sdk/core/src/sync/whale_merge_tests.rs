//! A delta whale (a delta record too large to store) means the changes are
//! unknown, so the merge reports a whale instead of the old snapshot.

use super::*;

fn entry(txid_byte: u8, amount: u64) -> UtxoEntry {
    let mut txid = [0u8; 32];
    txid[0] = txid_byte;
    UtxoEntry {
        txid,
        vout: 0,
        amount_sats: amount,
    }
}

/// Delta payload: no spends, one new UTXO (vout and amount below 128, so
/// each varint is one byte).
fn delta_one_new(new: &UtxoEntry) -> Vec<u8> {
    let mut out = vec![0, 1];
    out.extend_from_slice(&new.txid);
    out.push(new.vout as u8);
    out.push(new.amount_sats as u8);
    out
}

fn snapshot(verified: bool) -> QueryResult {
    let mut qr = QueryResult::with_entries(vec![entry(1, 40)]);
    qr.merkle_verified = verified;
    qr
}

fn delta_whale_result(verified: bool) -> QueryResult {
    let mut qr = QueryResult::empty();
    qr.is_whale = true;
    qr.merkle_verified = verified;
    qr
}

fn whale_snapshot() -> QueryResult {
    let mut qr = QueryResult::empty();
    qr.is_whale = true;
    qr.merkle_verified = true;
    qr
}

#[test]
fn delta_whale_marks_the_merge_whale() {
    for (snap_ok, del_ok) in [(true, true), (true, false), (false, true)] {
        let out = merge_delta_batch(
            &[Some(snapshot(snap_ok))],
            &[Some(delta_whale_result(del_ok))],
        )
        .unwrap();
        let merged = out[0].as_ref().unwrap();
        assert!(merged.is_whale);
        assert!(merged.entries.is_empty());
        assert!(merged.raw_chunk_data.is_none());
        assert_eq!(merged.merkle_verified, snap_ok && del_ok);
    }
}

#[test]
fn delta_whale_without_snapshot_is_whale() {
    let out = merge_delta_batch(&[None], &[Some(delta_whale_result(true))]).unwrap();
    let merged = out[0].as_ref().unwrap();
    assert!(merged.is_whale);
    assert!(merged.entries.is_empty());
    assert!(merged.merkle_verified);
}

#[test]
fn whale_snapshot_ignores_a_delta() {
    let mut del = QueryResult::empty();
    del.merkle_verified = true;
    del.raw_chunk_data = Some(delta_one_new(&entry(2, 50)));

    let out = merge_delta_batch(&[Some(whale_snapshot())], &[Some(del)]).unwrap();
    let merged = out[0].as_ref().unwrap();
    assert!(merged.is_whale);
    assert!(merged.entries.is_empty());

    let out =
        merge_delta_batch(&[Some(whale_snapshot())], &[Some(delta_whale_result(true))]).unwrap();
    let merged = out[0].as_ref().unwrap();
    assert!(merged.is_whale);
    assert!(merged.entries.is_empty());
    assert!(merged.merkle_verified);
}

#[test]
fn merge_delta_leaves_a_whale_snapshot_unchanged() {
    let merged = merge_delta(&whale_snapshot(), &delta_one_new(&entry(2, 50))).unwrap();
    assert!(merged.is_whale);
    assert!(merged.entries.is_empty());
    assert!(merged.merkle_verified);
}

#[test]
fn mixed_batch_changes_only_the_delta_whale() {
    let mut normal = QueryResult::empty();
    normal.merkle_verified = true;
    normal.raw_chunk_data = Some(delta_one_new(&entry(2, 50)));

    let out = merge_delta_batch(
        &[
            Some(snapshot(true)),
            Some(snapshot(true)),
            Some(snapshot(true)),
        ],
        &[Some(normal), Some(delta_whale_result(true)), None],
    )
    .unwrap();

    let first = out[0].as_ref().unwrap();
    assert!(!first.is_whale);
    assert_eq!(first.entries, vec![entry(1, 40), entry(2, 50)]);
    assert!(out[1].as_ref().unwrap().is_whale);
    let third = out[2].as_ref().unwrap();
    assert!(!third.is_whale);
    assert_eq!(third.entries, vec![entry(1, 40)]);
}
