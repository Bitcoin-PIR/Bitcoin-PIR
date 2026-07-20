//! Build a tiny INDEX+CHUNK cuckoo DB for local ORAM smoke tests.
//!
//! Usage:
//!   cargo run -p pir-sdk-client --example oram_make_fixture -- --out-dir /tmp/bpir-oram-db

use pir_core::codec::{serialize_utxo_data, UtxoEntry as CoreUtxoEntry};
use pir_core::cuckoo::write_header_with_anchor;
use pir_core::hash::{
    compute_tag, cuckoo_hash, cuckoo_hash_int, derive_cuckoo_key, derive_groups_3,
    derive_int_groups_3,
};
use pir_core::params::{TableParams, CHUNK_PARAMS, CHUNK_SIZE, INDEX_PARAMS, SCRIPT_HASH_SIZE};
use std::path::PathBuf;

const BINS_PER_TABLE: usize = 64;
const INDEX_MASTER_SEED: u64 = 0x1111_2222_3333_4444;
const CHUNK_MASTER_SEED: u64 = 0x5555_6666_7777_8888;
const TAG_SEED: u64 = 0x9999_AAAA_BBBB_CCCC;
const START_CHUNK_ID: u32 = 700;
const WHALE_START_CHUNK_ID: u32 = 900;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = parse_out_dir()?;
    std::fs::create_dir_all(&out_dir)?;

    let found_script_hash = [0x42u8; SCRIPT_HASH_SIZE];
    let whale_script_hash = [0x24u8; SCRIPT_HASH_SIZE];
    let missing_script_hash = [0x99u8; SCRIPT_HASH_SIZE];

    let index_params = INDEX_PARAMS.with_master_seed(INDEX_MASTER_SEED);
    let chunk_params = CHUNK_PARAMS.with_master_seed(CHUNK_MASTER_SEED);

    let mut index_bytes = empty_table(&index_params, TAG_SEED);
    insert_index_record(
        &mut index_bytes,
        &index_params,
        &found_script_hash,
        START_CHUNK_ID,
        1,
    );
    insert_index_record(
        &mut index_bytes,
        &index_params,
        &whale_script_hash,
        WHALE_START_CHUNK_ID,
        0,
    );

    let mut txid = [0u8; 32];
    txid[0] = 0xab;
    txid[31] = 0xcd;
    let raw_utxo = serialize_utxo_data(&[CoreUtxoEntry {
        txid,
        vout: 2,
        amount: 50_000,
    }]);
    assert!(
        raw_utxo.len() <= CHUNK_SIZE,
        "fixture UTXO must fit in one chunk"
    );
    let mut chunk_payload = vec![0u8; CHUNK_SIZE];
    chunk_payload[..raw_utxo.len()].copy_from_slice(&raw_utxo);

    let mut chunk_bytes = empty_table(&chunk_params, 0);
    insert_chunk_record(&mut chunk_bytes, &chunk_params, START_CHUNK_ID, &chunk_payload);

    std::fs::write(out_dir.join("batch_pir_cuckoo.bin"), index_bytes)?;
    std::fs::write(out_dir.join("chunk_pir_cuckoo.bin"), chunk_bytes)?;

    println!("db_dir={}", out_dir.display());
    println!("found_script_hash={}", hex::encode(found_script_hash));
    println!("missing_script_hash={}", hex::encode(missing_script_hash));
    println!("whale_script_hash={}", hex::encode(whale_script_hash));
    println!("expected_amount_sats=50000");
    println!("expected_vout=2");
    Ok(())
}

fn parse_out_dir() -> Result<PathBuf, String> {
    let mut args = std::env::args().skip(1);
    let mut out_dir = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--out-dir requires a path".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                println!("Usage: oram_make_fixture --out-dir <path>");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    out_dir.ok_or_else(|| "--out-dir is required".to_string())
}

fn empty_table(params: &TableParams, tag_seed: u64) -> Vec<u8> {
    let mut bytes = write_header_with_anchor(params, BINS_PER_TABLE, tag_seed, None);
    bytes.resize(
        bytes.len() + params.k * params.table_byte_size(BINS_PER_TABLE),
        0,
    );
    bytes
}

fn insert_index_record(
    table: &mut [u8],
    params: &TableParams,
    script_hash: &[u8; SCRIPT_HASH_SIZE],
    start_chunk_id: u32,
    num_chunks: u8,
) {
    let tag = compute_tag(TAG_SEED, script_hash);
    let mut slot = Vec::with_capacity(params.slot_size);
    slot.extend_from_slice(&tag.to_le_bytes());
    slot.extend_from_slice(&start_chunk_id.to_le_bytes());
    slot.push(num_chunks);

    for group_id in derive_groups_3(script_hash, params.k) {
        let key = derive_cuckoo_key(params.master_seed, group_id, 0);
        let bin_index = cuckoo_hash(script_hash, key, BINS_PER_TABLE);
        insert_slot(table, params, group_id, bin_index, &slot);
    }
}

fn insert_chunk_record(table: &mut [u8], params: &TableParams, chunk_id: u32, payload: &[u8]) {
    assert_eq!(payload.len(), CHUNK_SIZE);
    let mut slot = Vec::with_capacity(params.slot_size);
    slot.extend_from_slice(&chunk_id.to_le_bytes());
    slot.extend_from_slice(payload);

    for group_id in derive_int_groups_3(chunk_id, params.k) {
        let key = derive_cuckoo_key(params.master_seed, group_id, 0);
        let bin_index = cuckoo_hash_int(chunk_id, key, BINS_PER_TABLE);
        insert_slot(table, params, group_id, bin_index, &slot);
    }
}

fn insert_slot(
    table: &mut [u8],
    params: &TableParams,
    group_id: usize,
    bin_index: usize,
    slot_bytes: &[u8],
) {
    assert_eq!(slot_bytes.len(), params.slot_size);
    for slot in 0..params.slots_per_bin {
        let off = params.header_size
            + group_id * params.table_byte_size(BINS_PER_TABLE)
            + bin_index * params.bin_size()
            + slot * params.slot_size;
        if table[off..off + params.slot_size].iter().all(|&b| b == 0) {
            table[off..off + params.slot_size].copy_from_slice(slot_bytes);
            return;
        }
    }
    panic!("fixture cuckoo bin is full: group={group_id}, bin={bin_index}");
}
