use std::env;
use std::path::PathBuf;

use pir_db_attest::{build_kind_label, display_hash_hex, hex32, ProofDirectory};

fn main() {
    let mut args = env::args_os().skip(1);
    let path = PathBuf::from(args.next().unwrap_or_else(|| {
        eprintln!("usage: verify-proof-directory <artifact-directory>");
        std::process::exit(2);
    }));
    if args.next().is_some() {
        eprintln!("usage: verify-proof-directory <artifact-directory>");
        std::process::exit(2);
    }

    let verified = ProofDirectory::load_and_verify(&path).unwrap_or_else(|error| {
        eprintln!("proof directory verification failed: {error}");
        std::process::exit(1);
    });
    let evidence = verified.evidence;
    let layout = evidence.onion_layout_v2.unwrap_or_else(|| {
        eprintln!("proof directory verification failed: v2 Onion layout is missing");
        std::process::exit(1);
    });

    println!("proofVersion={}", evidence.version);
    println!("buildKind={}", build_kind_label(evidence.build_kind));
    println!("fromHeight={}", evidence.from_anchor.height);
    println!(
        "fromBlockHashHex={}",
        display_hash_hex(&evidence.from_anchor.block_hash)
    );
    println!("height={}", evidence.anchor.height);
    println!(
        "blockHashHex={}",
        display_hash_hex(&evidence.anchor.block_hash)
    );
    println!("muhashHex={}", display_hash_hex(&evidence.utxo_muhash));
    println!("bucketSuperRootHex={}", hex32(&evidence.bucket_super_root));
    println!("onionSuperRootHex={}", hex32(&evidence.onion_super_root));
    println!("paramsHashHex={}", hex32(&evidence.params_hash));
    println!("networkMagicHex={}", hex::encode(evidence.network_magic));
    println!(
        "builderBinarySha256Hex={}",
        hex32(&evidence.builder_binary_sha256)
    );
    println!("builderGitCommit={}", evidence.builder_git_commit);
    println!("onionEntrySize={}", evidence.onion_entry_size);
    println!("onionTotalPackedEntries={}", layout.total_packed_entries);
    println!("onionIndexBinsPerTable={}", layout.index_bins_per_table);
    println!("onionChunkBinsPerTable={}", layout.chunk_bins_per_table);
    println!("onionIndexSlotsPerBin={}", layout.index_slots_per_bin);
    println!("onionIndexSlotSize={}", layout.index_slot_size);
}
