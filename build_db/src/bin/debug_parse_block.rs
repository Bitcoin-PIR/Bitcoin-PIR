use bitcoin::bip158::BlockFilterWriter;
use bitcoin::{consensus::Decodable, hex::FromHex, Block};
use std::env;
use std::process::Command;
use std::time::{Duration, Instant};

fn get_block_hash(datadir: &str, block_number: u64) -> Result<(String, Duration), String> {
    let start = Instant::now();
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

    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let elapsed = start.elapsed();
    Ok((hash, elapsed))
}

fn get_block_hex(datadir: &str, block_hash: &str) -> Result<(String, Duration), String> {
    let start = Instant::now();
    let output = Command::new("bitcoin-cli")
        .args([
            format!("-datadir={}", datadir),
            "getblock".to_string(),
            block_hash.to_string(),
            "0".to_string(),
        ])
        .output()
        .map_err(|e| format!("Failed to execute bitcoin-cli: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "bitcoin-cli failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let hex = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let elapsed = start.elapsed();
    Ok((hex, elapsed))
}

fn parse_block_and_transactions(
    block_hex: &str,
) -> Result<(Block, Duration), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let block_bytes = Vec::from_hex(block_hex)?;
    let block = Block::consensus_decode(&mut block_bytes.as_slice())?;

    println!("=== Block Information ===");
    println!("Block hash: {}", block.block_hash());
    println!("Version: {:?}", block.header.version);
    println!("Number of transactions: {}", block.txdata.len());
    println!();

    // Iterate over all transactions in the block
    for (i, tx) in block.txdata.iter().enumerate() {
        let txid = tx.compute_txid();
        println!("Transaction {} in block:", i);
        println!("  TXID: {}", txid);
        println!("  Version: {}", tx.version);
        println!("  Lock time: {}", tx.lock_time);

        // Print inputs
        println!("  Inputs: {}", tx.input.len());
        for (j, input) in tx.input.iter().enumerate() {
            println!("    Input {}:", j);
            println!("      Previous output: {:?}", input.previous_output);
            println!("      Script sig: {}", input.script_sig);
            println!("      Sequence: {}", input.sequence);
        }

        // Print outputs
        println!("  Outputs: {}", tx.output.len());
        for (j, output) in tx.output.iter().enumerate() {
            println!("    Output {}:", j);
            println!("      Value: {} satoshis", output.value);
            println!("      Script pubkey: {}", output.script_pubkey);
        }

        println!();
    }

    let elapsed = start.elapsed();
    Ok((block, elapsed))
}

fn build_bip158_filter(block: &Block) -> Result<(Vec<u8>, Duration), Box<dyn std::error::Error>> {
    let start = Instant::now();

    let mut filter_data = Vec::new();
    {
        let mut writer = BlockFilterWriter::new(&mut filter_data, block);
        writer.add_output_scripts();
        // For input scripts, we need the UTXO set to resolve previous outputs.
        // For a single-block test without full UTXO context, we skip input scripts
        // for the coinbase (which has no real previous output) and handle missing
        // UTXOs gracefully by only adding output scripts.
        //
        // In a full node context, you would call:
        //   writer.add_input_scripts(|outpoint| { ... lookup utxo ... })?;
        writer.finish()?;
    }

    let elapsed = start.elapsed();
    Ok((filter_data, elapsed))
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <datadir> <block_number>", args[0]);
        eprintln!("Example: {} /Volumes/Bitcoin/bitcoin 100000", args[0]);
        std::process::exit(1);
    }

    let datadir = &args[1];
    let block_number: u64 = match args[2].parse() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Invalid block number: {}", e);
            std::process::exit(1);
        }
    };

    let total_start = Instant::now();

    println!("Fetching block {} from datadir: {}", block_number, datadir);
    println!();

    // Step 1: Get block hash
    let (block_hash, hash_time) = match get_block_hash(datadir, block_number) {
        Ok((hash, time)) => {
            println!("✓ Block hash: {}", hash);
            println!("  ⏱  Time taken: {:?}", time);
            (hash, time)
        }
        Err(e) => {
            eprintln!("✗ Failed to get block hash: {}", e);
            std::process::exit(1);
        }
    };

    // Step 2: Get block hex
    let (block_hex, hex_time) = match get_block_hex(datadir, &block_hash) {
        Ok((hex, time)) => {
            println!("✓ Block hex retrieved (length: {} chars)", hex.len());
            println!("  ⏱  Time taken: {:?}", time);
            (hex, time)
        }
        Err(e) => {
            eprintln!("✗ Failed to get block hex: {}", e);
            std::process::exit(1);
        }
    };

    println!();

    // Step 3: Parse block and transactions
    let (block, parse_time) = match parse_block_and_transactions(&block_hex) {
        Ok((block, time)) => {
            println!("✓ Block parsed successfully!");
            println!("  ⏱  Time taken: {:?}", time);
            (block, time)
        }
        Err(e) => {
            eprintln!("✗ Failed to parse block: {}", e);
            std::process::exit(1);
        }
    };

    // Step 4: Build BIP158 compact block filter
    println!();
    let (filter_data, filter_time) = match build_bip158_filter(&block) {
        Ok((data, time)) => {
            let block_raw_size = block_hex.len() / 2; // hex chars -> bytes
            println!("=== BIP158 Compact Block Filter ===");
            println!("Filter size:       {} bytes", data.len());
            println!("Block raw size:    {} bytes", block_raw_size);
            if block_raw_size > 0 {
                let ratio = (data.len() as f64 / block_raw_size as f64) * 100.0;
                println!("Filter/Block ratio: {:.2}%", ratio);
            }
            println!(
                "Filter hex:        {}",
                data.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );
            println!("  ⏱  Time taken: {:?}", time);
            (data, time)
        }
        Err(e) => {
            eprintln!("✗ Failed to build BIP158 filter: {}", e);
            std::process::exit(1);
        }
    };

    let total_time = total_start.elapsed();

    println!();
    println!("=== Timing Summary ===");
    println!("Get block hash:    {:?}", hash_time);
    println!("Get block hex:     {:?}", hex_time);
    println!("Parse block data:  {:?}", parse_time);
    println!("Build BIP158 filter: {:?}", filter_time);
    println!("Total time:        {:?}", total_time);

    println!();
    println!("=== Size Summary ===");
    println!("Block raw size:    {} bytes", block_hex.len() / 2);
    println!("BIP158 filter:     {} bytes", filter_data.len());
}
