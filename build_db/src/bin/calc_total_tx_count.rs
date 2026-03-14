use std::fs::File;
use std::io::Read;

const TX_COUNT_FILE: &str = "/Volumes/Bitcoin/data/block_tx_counts.bin";

fn main() {
    println!("=== Total Transaction Counter ===");
    println!("Reading from: {}", TX_COUNT_FILE);
    println!();

    // Open the binary file
    let mut file = match File::open(TX_COUNT_FILE) {
        Ok(f) => {
            println!("✓ File opened successfully");
            f
        }
        Err(e) => {
            eprintln!("✗ Failed to open file '{}': {}", TX_COUNT_FILE, e);
            eprintln!("Make sure you've run block_tx_count first to generate the data file.");
            std::process::exit(1);
        }
    };

    // Read all bytes from the file
    let metadata = match file.metadata() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("✗ Failed to read file metadata: {}", e);
            std::process::exit(1);
        }
    };

    let file_size = metadata.len();
    println!("✓ File size: {} bytes", file_size);

    if file_size == 0 {
        println!("✗ File is empty - no blocks indexed yet");
        std::process::exit(0);
    }

    // Each block uses 2 bytes (u16)
    if file_size % 2 != 0 {
        eprintln!("✗ File size is not a multiple of 2 bytes - corrupted data");
        std::process::exit(1);
    }

    let num_blocks = file_size / 2;
    println!("✓ Number of blocks indexed: {}", num_blocks);
    println!();

    // Read all data into a buffer
    let mut buffer = vec![0u8; file_size as usize];
    if let Err(e) = file.read_exact(&mut buffer) {
        eprintln!("✗ Failed to read file contents: {}", e);
        std::process::exit(1);
    }

    // Sum all transaction counts
    let mut total_txs: u64 = 0;
    let mut chunks = buffer.chunks_exact(2);

    while let Some(chunk) = chunks.next() {
        let tx_count = u16::from_le_bytes([chunk[0], chunk[1]]);
        total_txs += tx_count as u64;
    }

    println!("=== Results ===");
    println!("Total number of transactions: {}", total_txs);
    println!(
        "Average transactions per block: {:.2}",
        total_txs as f64 / num_blocks as f64
    );
}
