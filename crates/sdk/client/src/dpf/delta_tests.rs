//! A delta record is not a UTXO list: the query keeps its bytes for the
//! merge and does not decode them as one. Decoding it as one used to fail
//! the whole step for every address in the batch.

use super::*;
use pir_core::params::{
    CHUNK_SIZE, CHUNK_SLOTS_PER_BIN, CHUNK_SLOT_SIZE, INDEX_SLOTS_PER_BIN, INDEX_SLOT_SIZE,
    TAG_SIZE,
};
use pir_sdk::{merge_delta_batch, DatabaseKind};
use std::collections::VecDeque;

const GOOD: ScriptHash = [0x11; 20];
const BAD: ScriptHash = [0x22; 20];

fn test_db(kind: DatabaseKind) -> DatabaseInfo {
    DatabaseInfo {
        db_id: 1,
        kind,
        name: "db1".into(),
        height: 110,
        index_bins: 128,
        chunk_bins: 128,
        index_k: 4,
        chunk_k: 4,
        tag_seed: 0,
        // libdpf needs a domain of at least 2^7.
        dpf_n_index: 7,
        dpf_n_chunk: 7,
        has_bucket_merkle: false,
        index_master_seed: 1,
        chunk_master_seed: 2,
        anchor_kind: 0,
        anchor_bytes: Vec::new(),
    }
}

fn step(db: &DatabaseInfo) -> SyncStep {
    SyncStep {
        db_id: db.db_id,
        kind: db.kind,
        name: db.name.clone(),
        base_height: 100,
        tip_height: db.height,
    }
}

/// One spent outpoint (txid 0x01.., vout 0), nothing new.
fn one_spent_record() -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&[0x01; 32]);
    out.extend_from_slice(&[0, 0]);
    out
}

/// Two spent outpoints, nothing new. The second txid starts with ten bytes
/// >= 0x80, which the UTXO-list decoder reads as an over-long amount varint.
fn two_spent_record() -> Vec<u8> {
    let mut out = vec![2];
    out.extend_from_slice(&[0x02; 32]);
    out.push(0);
    out.extend_from_slice(&second_txid());
    out.extend_from_slice(&[0, 0]);
    out
}

fn second_txid() -> [u8; 32] {
    let mut txid = [0u8; 32];
    txid[..10].fill(0xff);
    txid
}

/// INDEX and CHUNK bin contents holding `records`, each stored from its own
/// consecutive chunk ids. Every bin returned carries all of them, so any
/// probe finds them.
fn bins(records: &[(ScriptHash, Vec<u8>)]) -> (Vec<u8>, Vec<u8>) {
    let mut index = Vec::new();
    let mut chunk = Vec::new();
    let mut next_chunk = 0u32;
    for (sh, record) in records {
        let pieces: Vec<&[u8]> = record.chunks(CHUNK_SIZE).collect();
        index.extend_from_slice(&pir_core::hash::compute_tag(0, sh).to_le_bytes());
        index.extend_from_slice(&next_chunk.to_le_bytes());
        index.push(pieces.len() as u8);
        for piece in pieces {
            chunk.extend_from_slice(&next_chunk.to_le_bytes());
            chunk.extend_from_slice(piece);
            chunk.resize(chunk.len() + CHUNK_SIZE - piece.len(), 0);
            next_chunk += 1;
        }
    }
    assert_eq!(INDEX_SLOT_SIZE, TAG_SIZE + 5);
    assert!(index.len() <= INDEX_SLOT_SIZE * INDEX_SLOTS_PER_BIN);
    assert!(chunk.len() <= CHUNK_SLOT_SIZE * CHUNK_SLOTS_PER_BIN);
    index.resize(INDEX_SLOT_SIZE * INDEX_SLOTS_PER_BIN, 0);
    chunk.resize(CHUNK_SLOT_SIZE * CHUNK_SLOTS_PER_BIN, 0);
    (index, chunk)
}

/// DPF server stand-in answering every bin with fixed contents. Pairing one
/// carrying the records with one answering zeros makes the client's XOR of
/// the two shares equal the records.
struct FixedDpfTransport {
    url: &'static str,
    index_bin: Vec<u8>,
    chunk_bin: Vec<u8>,
    pending: VecDeque<Vec<u8>>,
}

#[async_trait]
impl PirTransport for FixedDpfTransport {
    async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
        self.pending.push_back(data);
        Ok(())
    }

    async fn recv(&mut self) -> PirResult<Vec<u8>> {
        let request = self
            .pending
            .pop_front()
            .ok_or_else(|| PirError::Protocol("fixed DPF transport: no request".into()))?;
        // `[u32 len][variant][u16 round_id][u8 groups][u8 keys/group] ...`
        let variant = request[4];
        let groups = request[7] as usize;
        let per_group = request[8] as usize;
        let bin = match variant {
            0x11 => &self.index_bin,
            0x21 => &self.chunk_bin,
            other => panic!("unexpected DPF request variant {other:#04x}"),
        };
        let mut body = request[4..9].to_vec();
        for _ in 0..groups * per_group {
            body.extend_from_slice(&(bin.len() as u16).to_le_bytes());
            body.extend_from_slice(bin);
        }
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    async fn roundtrip(&mut self, _request: &[u8]) -> PirResult<Vec<u8>> {
        Err(PirError::Protocol(
            "fixed DPF transport: unexpected roundtrip".into(),
        ))
    }

    async fn close(&mut self) -> PirResult<()> {
        Ok(())
    }

    fn url(&self) -> &str {
        self.url
    }
}

fn client_serving(records: &[(ScriptHash, Vec<u8>)]) -> DpfClient {
    let (index_bin, chunk_bin) = bins(records);
    let zeros = (vec![0; index_bin.len()], vec![0; chunk_bin.len()]);
    let mut client = DpfClient::new("mock://dpf-0", "mock://dpf-1");
    client.connect_with_transport(
        Box::new(FixedDpfTransport {
            url: "mock://dpf-0",
            index_bin,
            chunk_bin,
            pending: VecDeque::new(),
        }),
        Box::new(FixedDpfTransport {
            url: "mock://dpf-1",
            index_bin: zeros.0,
            chunk_bin: zeros.1,
            pending: VecDeque::new(),
        }),
    );
    client
}

#[test]
fn the_record_breaks_the_utxo_list_decoder() {
    assert!(pir_sdk::decode_delta_data(&two_spent_record()).is_ok());
    assert!(decode_utxo_entries(&two_spent_record()).is_err());
}

#[tokio::test]
async fn a_delta_step_keeps_raw_bytes_and_merges() {
    let good = one_spent_record();
    let bad = two_spent_record();
    let mut client = client_serving(&[(GOOD, good.clone()), (BAD, bad.clone())]);
    let db = test_db(DatabaseKind::Delta { base_height: 100 });

    let results = client
        .execute_step(&[GOOD, BAD], &step(&db), &db)
        .await
        .unwrap();

    for (result, record) in results.iter().zip([&good, &bad]) {
        let result = result.as_ref().unwrap();
        assert!(result.entries.is_empty());
        // The raw bytes are whole chunks: the record, then zero padding.
        let raw = result.raw_chunk_data.as_ref().unwrap();
        assert_eq!(&raw[..record.len()], record.as_slice());
        assert!(raw[record.len()..].iter().all(|&b| b == 0));
    }

    let utxo = |txid: [u8; 32], amount_sats: u64| UtxoEntry {
        txid,
        vout: 0,
        amount_sats,
    };
    let snapshots = [
        Some(QueryResult::with_entries(vec![
            utxo([0x01; 32], 1_000),
            utxo([0x03; 32], 3_000),
        ])),
        Some(QueryResult::with_entries(vec![
            utxo([0x02; 32], 2_000),
            utxo(second_txid(), 4_000),
        ])),
    ];
    let merged = merge_delta_batch(&snapshots, &results).unwrap();
    assert_eq!(
        merged[0].as_ref().unwrap().entries,
        vec![utxo([0x03; 32], 3_000)]
    );
    assert!(merged[1].as_ref().unwrap().entries.is_empty());
}

#[tokio::test]
async fn a_full_step_still_decodes_entries() {
    let record = pir_core::codec::serialize_utxo_data(&[pir_core::codec::UtxoEntry {
        txid: [0xab; 32],
        vout: 2,
        amount: 50_000,
    }]);
    let mut client = client_serving(&[(GOOD, record)]);
    let db = test_db(DatabaseKind::Full);

    let results = client.execute_step(&[GOOD], &step(&db), &db).await.unwrap();

    let result = results[0].as_ref().unwrap();
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].amount_sats, 50_000);
    assert!(result.raw_chunk_data.is_none());
}
