use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Seek, Write};
use std::process::Command;

const TX_COUNT_FILE: &str = "/Volumes/Bitcoin/data/block_tx_counts.bin";

/// Get block hash for a given block number
fn get_block_hash(datadir: &str, block_number: u64) -> Result<String, String> {
    let output = Command::new("bitcoin-cli")
        .args([
            format!("-datadir={}", datadir),
            "getblockhash".to_string(),
            block_number.to_string(),
        ])
        .output()
        .map_err(|e| format!("Failed to execute bitcoin-cli: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "bitcoin-cli failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Get block information in JSON format and extract transaction count
fn get_block_tx_count(datadir: &str, block_hash: &str) -> Result<u64, String> {
    let output = Command::new("bitcoin-cli")
        .args([
            format!("-datadir={}", datadir),
            "getblock".to_string(),
            block_hash.to_string(),
            "1".to_string(), // JSON format
        ])
        .output()
        .map_err(|e| format!("Failed to execute bitcoin-cli: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "bitcoin-cli failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Parse JSON and extract tx count
    let json_str = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| format!("Failed to parse JSON: {}", e))?;

    // The 'tx' field is an array of transaction IDs
    let tx_array = json
        .get("tx")
        .and_then(|v| v.as_array())
        .ok_or("Missing or invalid 'tx' field in block JSON")?;

    Ok(tx_array.len() as u64)
}

/// Get current file size (returns 0 if file doesn't exist)
fn get_file_size(path: &str) -> io::Result<u64> {
    File::open(path)
        .and_then(|mut f| f.seek(io::SeekFrom::End(0)))
        .or(Ok(0))
}

/// Append a transaction count to a buffered writer
fn append_tx_count(writer: &mut BufWriter<File>, tx_count: u16) -> io::Result<()> {
    writer.write_all(&tx_count.to_le_bytes())
}

/// Print a progress bar
fn print_progress(processed: u64, block_number: u64, tx_count: u16) {
    let bar = format!(
        "Processed {} blocks | Block {}: {} txs",
        processed, block_number, tx_count
    );

    print!("\r{}", bar);
    std::io::stdout().flush().unwrap();
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <datadir>", args[0]);
        eprintln!("Example: {} /Volumes/Bitcoin/bitcoin", args[0]);
        eprintln!("\nThis tool will:");
        eprintln!("1. Read block_tx_counts.bin to see current progress");
        eprintln!("2. Fetch transaction counts for ALL remaining blocks");
        eprintln!("3. Append results to {}", TX_COUNT_FILE);
        std::process::exit(1);
    }

    let datadir = &args[1];

    println!("=== Block Transaction Counter ===");
    println!("Datadir: {}", datadir);
    println!("Output file: {}", TX_COUNT_FILE);
    println!();

    // Step 1: Check current file size to determine starting position
    let file_size = match get_file_size(TX_COUNT_FILE) {
        Ok(size) => {
            let block_count = size / 2;
            println!("✓ Current progress: {} blocks indexed", block_count);
            block_count
        }
        Err(e) => {
            println!("✗ Failed to read file size: {}", e);
            0
        }
    };

    let start_block = file_size;
    println!("✓ Starting from block: {}", start_block);
    println!();

    // Step 2: Process blocks until we can't find more
    let mut processed = 0u64;
    let mut last_tx_count = 0u16;

    // Open file with buffered writer for efficient writes
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(TX_COUNT_FILE);

    let mut writer = match file {
        Ok(f) => BufWriter::new(f),
        Err(e) => {
            eprintln!("✗ Failed to open file for writing: {}", e);
            std::process::exit(1);
        }
    };

    loop {
        let block_number = start_block + processed;

        // Get block hash
        let block_hash = match get_block_hash(datadir, block_number) {
            Ok(hash) => hash,
            Err(e) => {
                // Assume we've reached the end of blockchain
                println!();
                println!(
                    "✓ Reached end of blockchain or error getting block {}: {}",
                    block_number, e
                );
                break;
            }
        };

        // Get transaction count
        let tx_count = match get_block_tx_count(datadir, &block_hash) {
            Ok(count) => {
                if count > u16::MAX as u64 {
                    eprintln!(
                        "✗ Transaction count {} exceeds u16::MAX for block {}",
                        count, block_number
                    );
                    break;
                }
                count as u16
            }
            Err(e) => {
                eprintln!(
                    "✗ Failed to get transaction count for block {}: {}",
                    block_number, e
                );
                break;
            }
        };

        // Append to binary file
        if let Err(e) = append_tx_count(&mut writer, tx_count) {
            eprintln!("✗ Failed to write to file: {}", e);
            break;
        }

        last_tx_count = tx_count;
        processed += 1;

        // Print progress every 100 blocks
        if processed % 100 == 0 {
            print_progress(processed, block_number, tx_count);

            // Flush buffer periodically
            if let Err(e) = writer.flush() {
                eprintln!("\n✗ Failed to flush buffer: {}", e);
                break;
            }
        }
    }

    // Flush the buffer to ensure all data is written
    if let Err(e) = writer.flush() {
        eprintln!("✗ Failed to flush buffer: {}", e);
    }

    println!();
    println!("=== Summary ===");
    println!(
        "Processed {} new blocks ({} to {})",
        processed,
        start_block,
        start_block + processed - 1
    );
    println!(
        "Current file size: {} bytes ({} blocks)",
        get_file_size(TX_COUNT_FILE).unwrap_or(0),
        get_file_size(TX_COUNT_FILE).unwrap_or(0) / 2
    );
    if processed > 0 {
        println!(
            "Last block: {} with {} transactions",
            start_block + processed - 1,
            last_tx_count
        );
    }
    println!("Run this tool again to continue from where you left off!");
}
