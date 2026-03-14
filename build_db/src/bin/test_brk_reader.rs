//! Test file for brk_reader crate
//!
//! This demonstrates how to use brk_reader to read blocks directly from
//! Bitcoin Core's blk*.dat files, which is much faster than using RPC.
//!
//! Usage: cargo run --bin test_brk_reader -- <bitcoin_datadir>
//! Example: cargo run --bin test_brk_reader -- /Volumes/Bitcoin/bitcoin

use std::path::PathBuf;
use std::time::Instant;
use std::{env, time::Duration};

use bitcoin::hashes::Hash;
use brk_reader::Reader;
use brk_rpc::{Auth, Client};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <bitcoin_datadir>", args[0]);
        eprintln!("Example: {} /Volumes/Bitcoin/bitcoin", args[0]);
        std::process::exit(1);
    }

    let bitcoin_dir = PathBuf::from(&args[1]);

    // Check if the directory exists
    if !bitcoin_dir.exists() {
        eprintln!("Error: Bitcoin directory does not exist: {:?}", bitcoin_dir);
        std::process::exit(1);
    }

    let blocks_dir = bitcoin_dir.join("blocks");
    if !blocks_dir.exists() {
        eprintln!("Error: blocks directory does not exist: {:?}", blocks_dir);
        std::process::exit(1);
    }

    println!("=== brk_reader Test ===");
    println!("Bitcoin directory: {:?}", bitcoin_dir);
    println!("Blocks directory: {:?}", blocks_dir);
    println!();

    // Create RPC client for authentication
    // brk_reader needs an RPC client for:
    // 1. Getting the current block height
    // 2. Handling recent blocks that may not be in blk files yet
    let cookie_path = bitcoin_dir.join(".cookie");

    if !cookie_path.exists() {
        eprintln!("Error: Cookie file does not exist: {:?}", cookie_path);
        eprintln!("Make sure Bitcoin Core is running.");
        std::process::exit(1);
    }

    println!("Using cookie file: {:?}", cookie_path);

    // Create the RPC client
    let client = match Client::new_with(
        "http://127.0.0.1:8332",
        Auth::CookieFile(cookie_path),
        10,
        Duration::from_secs(5),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error creating RPC client: {:?}", e);
            std::process::exit(1);
        }
    };

    // Get the current block height
    let block_count = match client.get_block_count() {
        Ok(count) => count,
        Err(e) => {
            eprintln!("Error getting block count: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("Current block height: {}", block_count);
    println!();

    // Create the block reader
    let reader = Reader::new(blocks_dir, &client);

    // Test 1: Read the first 10 blocks
    println!("--- Test 1: Reading first 10 blocks ---");
    let start = Instant::now();
    let mut block_count_test = 0u64;
    let mut total_txs = 0u64;

    // Read blocks from height 0 to 9
    let receiver = reader.read(Some(0u32.into()), Some(10u32.into()));

    for block in receiver.iter() {
        let height = block.height();
        let hash = block.hash();
        let tx_count = block.txdata.len();

        println!("Block {}: {} ({} transactions)", height, hash, tx_count);

        // Show transaction IDs for the first block (genesis block)
        if height == 0u64 {
            println!("  Genesis block transactions:");
            for (i, tx) in block.txdata.iter().enumerate() {
                let txid = tx.compute_txid();
                println!("    TX {}: {}", i, txid);
            }
        }

        block_count_test += 1;
        total_txs += tx_count as u64;
    }

    println!("Read {} blocks in {:?}", block_count_test, start.elapsed());
    println!("Total transactions: {}", total_txs);
    println!();

    // Test 2: Read blocks from a specific range (e.g., around block 100000)
    println!("--- Test 2: Reading blocks 100000-100009 ---");
    let start = Instant::now();
    let receiver = reader.read(Some(100000u32.into()), Some(100010u32.into()));

    for block in receiver.iter() {
        let height = block.height();
        let hash = block.hash();
        let tx_count = block.txdata.len();
        println!("Block {}: {} ({} transactions)", height, hash, tx_count);
    }

    println!("Completed in {:?}", start.elapsed());
    println!();

    // Test 3: Extract transaction IDs from a block
    println!("--- Test 3: Extracting transaction IDs from block 100000 ---");
    let start = Instant::now();
    let receiver = reader.read(Some(100000u32.into()), Some(100001u32.into()));

    for block in receiver.iter() {
        let txdata = &block.txdata;
        println!(
            "Block {} has {} transactions:",
            block.height(),
            txdata.len()
        );

        for (i, tx) in txdata.iter().enumerate() {
            let txid = tx.compute_txid();
            // Convert txid to bytes (internal byte order, not display order)
            let txid_bytes: [u8; 32] = txid.to_byte_array();

            if i < 5 || i >= txdata.len() - 2 {
                println!("  TX[{}]: {} (bytes: {})", i, txid, hex::encode(txid_bytes));
            } else if i == 5 {
                println!("  ... (showing first 5 and last 2)");
            }
        }
    }

    println!("Completed in {:?}", start.elapsed());
    println!();

    println!("=== All tests completed successfully! ===");
}
