//! Generate txid.bin file by reading blocks directly from blk*.dat files
//! 
//! This version uses brk_reader for much faster block reading compared to RPC.
//!
//! Usage: cargo run --bin generate_txid_file -- <bitcoin_datadir>
//! Example: cargo run --bin generate_txid_file -- /Volumes/Bitcoin/bitcoin

use std::env;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use bitcoin::hashes::Hash;
use brk_reader::Reader;
use brk_rpc::{Auth, Client};

const TXID_FILE: &str = "/Volumes/Bitcoin/data/txid.bin";
const PROGRESS_FILE: &str = "/Volumes/Bitcoin/data/txid_progress.txt";
const BLOCK_TX_COUNTS_FILE: &str = "/Volumes/Bitcoin/data/block_tx_counts.bin";

const BLOCKS_TO_PROCESS: u64 = 100000;

/// Get current progress (block number) from progress file
fn get_progress() -> u64 {
    match std::fs::read_to_string(PROGRESS_FILE) {
        Ok(s) => s.trim().parse().unwrap_or(0),
        Err(_) => 0,
    }
}

/// Save current progress
fn save_progress(block_number: u64) {
    if let Err(e) = std::fs::write(PROGRESS_FILE, block_number.to_string()) {
        eprintln!("Warning: Failed to save progress: {}", e);
    }
}

/// Get the number of indexed blocks from block_tx_counts.bin
/// Each block uses 2 bytes in the file (u16 for transaction count)
fn get_indexed_block_count() -> u64 {
    match std::fs::metadata(BLOCK_TX_COUNTS_FILE) {
        Ok(metadata) => metadata.len() / 2,
        Err(_) => 0,
    }
}

/// Print a progress bar
fn print_progress(current: u64, total: u64, block_number: u64, tx_count: usize, elapsed: std::time::Duration) {
    let percent = (current * 100) / total;
    let filled = (current * 50) / total;
    let empty = 50 - filled;

    let blocks_per_sec = if elapsed.as_secs() > 0 {
        current as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    let bar = format!(
        "[{}{}] {}% | Block {}: {} txs | {:.1} blocks/s",
        "=".repeat(filled as usize),
        " ".repeat(empty as usize),
        percent,
        block_number,
        tx_count,
        blocks_per_sec
    );

    print!("\r{}", bar);
    std::io::stdout().flush().unwrap();
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <bitcoin_datadir>", args[0]);
        eprintln!("Example: {} /Volumes/Bitcoin/bitcoin", args[0]);
        eprintln!("\nThis tool will:");
        eprintln!("1. Read progress from {}", PROGRESS_FILE);
        eprintln!("2. Fetch transaction IDs for next {} blocks using brk_reader", BLOCKS_TO_PROCESS);
        eprintln!("3. Append 32-byte binary transaction IDs to {}", TXID_FILE);
        eprintln!("\nOutput file will be ~{} bytes per transaction", 32);
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

    let cookie_path = bitcoin_dir.join(".cookie");
    if !cookie_path.exists() {
        eprintln!("Error: Cookie file does not exist: {:?}", cookie_path);
        eprintln!("Make sure Bitcoin Core is running.");
        std::process::exit(1);
    }

    println!("=== Transaction ID Generator (brk_reader version) ===");
    println!("Bitcoin directory: {:?}", bitcoin_dir);
    println!("Blocks directory: {:?}", blocks_dir);
    println!("Output file: {}", TXID_FILE);
    println!("Progress file: {}", PROGRESS_FILE);
    println!("Blocks to process: {}", BLOCKS_TO_PROCESS);
    println!();

    // Create RPC client
    let rpc_url = "http://127.0.0.1:8332";
    println!("Connecting to RPC at: {}", rpc_url);
    
    let client = match Client::new(rpc_url, Auth::CookieFile(cookie_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error creating RPC client: {:?}", e);
            std::process::exit(1);
        }
    };

    // Get the current block height
    let blockchain_height = match client.get_block_count() {
        Ok(count) => count,
        Err(e) => {
            eprintln!("Error getting block count: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("Current blockchain height: {}", blockchain_height);
    println!();

    // Check current progress
    let start_block = get_progress();
    println!("✓ Starting from block: {}", start_block);

    // Get the number of indexed blocks from block_tx_counts.bin
    let indexed_block_count = get_indexed_block_count();
    println!(
        "✓ Indexed blocks in {}: {}",
        BLOCK_TX_COUNTS_FILE, indexed_block_count
    );

    // Check current output file size
    let current_file_size = match std::fs::metadata(TXID_FILE) {
        Ok(m) => m.len(),
        Err(_) => 0,
    };

    if current_file_size > 0 {
        println!(
            "✓ Current output file size: {} bytes ({} transactions)",
            current_file_size,
            current_file_size / 32
        );
    }

    println!();

    // Calculate end block
    let end_block = std::cmp::min(
        start_block + BLOCKS_TO_PROCESS,
        indexed_block_count
    );

    if start_block >= indexed_block_count {
        println!("✓ All indexed blocks have been processed.");
        println!("✓ Run again after indexing more blocks.");
        return;
    }

    println!("Processing blocks {} to {}...", start_block, end_block - 1);
    println!();

    // Open output file for appending
    let file = OpenOptions::new().create(true).append(true).open(TXID_FILE);

    let mut writer = match file {
        Ok(f) => BufWriter::with_capacity(1024 * 1024, f), // 1MB buffer
        Err(e) => {
            eprintln!("✗ Failed to open output file '{}': {}", TXID_FILE, e);
            std::process::exit(1);
        }
    };

    // Create the block reader
    let reader = Reader::new(blocks_dir, &client);

    // Process blocks using brk_reader
    let start_time = Instant::now();
    let mut processed = 0u64;
    let mut total_txs_in_batch = 0u64;
    let mut last_progress_update = Instant::now();

    // Read blocks from start_block to end_block
    let receiver = reader.read(
        Some((start_block as u32).into()),
        Some((end_block as u32).into())
    );

    for block in receiver.iter() {
        let height = block.height();
        let height_u64: u64 = height.into();
        
        // Extract transaction IDs and write to file
        let tx_count = block.txdata.len();
        
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            let txid_bytes: [u8; 32] = txid.to_byte_array();
            
            if let Err(e) = writer.write_all(&txid_bytes) {
                eprintln!("\n✗ Failed to write to file: {}", e);
                std::process::exit(1);
            }
        }

        total_txs_in_batch += tx_count as u64;
        processed += 1;

        // Print progress every 1000 blocks or 1 second
        if last_progress_update.elapsed().as_millis() >= 1000 || processed % 1000 == 0 || height_u64 == end_block - 1 {
            print_progress(
                processed,
                end_block - start_block,
                height_u64,
                tx_count,
                start_time.elapsed()
            );

            // Save progress
            save_progress(height_u64 + 1);

            // Flush buffer periodically
            if let Err(e) = writer.flush() {
                eprintln!("\n✗ Failed to flush buffer: {}", e);
                std::process::exit(1);
            }
            
            last_progress_update = Instant::now();
        }
    }

    // Final flush
    if let Err(e) = writer.flush() {
        eprintln!("\n✗ Failed to flush buffer: {}", e);
        std::process::exit(1);
    }

    let total_elapsed = start_time.elapsed();

    println!();
    println!();
    println!("=== Summary ===");
    if processed > 0 {
        println!(
            "Processed {} blocks ({} to {})",
            processed,
            start_block,
            start_block + processed - 1
        );
        println!(
            "Total time: {:.2} seconds ({:.1} blocks/s)",
            total_elapsed.as_secs_f64(),
            processed as f64 / total_elapsed.as_secs_f64()
        );
    } else {
        println!("Processed 0 blocks");
    }
    println!("Transaction IDs written: {}", total_txs_in_batch);
    println!("Bytes written: {}", total_txs_in_batch * 32);

    // Check new file size
    let new_file_size = match std::fs::metadata(TXID_FILE) {
        Ok(m) => m.len(),
        Err(_) => current_file_size,
    };

    println!(
        "Total file size: {} bytes (~{:.2} GB)",
        new_file_size,
        new_file_size as f64 / (1024.0 * 1024.0 * 1024.0)
    );

    println!("\nRun this tool again to continue from where you left off!");
    println!("Progress is saved in {}", PROGRESS_FILE);
}