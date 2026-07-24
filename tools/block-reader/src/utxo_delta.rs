//! Compute UTXO delta over a block range
//!
//! Streams blocks from blk*.dat files and computes:
//! - MINUS: pre-existing UTXOs spent during the range → (txid, vout)
//! - PLUS: new UTXOs created during the range still unspent at end → (txid, vout, amount)
//!
//! UTXOs created AND consumed within the range are excluded from both sets.
//!
//! Usage: utxo_delta <bitcoin_datadir> <start_height> <end_height>
//! Example: utxo_delta /Volumes/Bitcoin/bitcoin 938612 940612

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use bitcoin::hashes::Hash;
use bitcoin::Txid;
use brk_reader::Reader;
use brk_rpc::{Auth, Client};

const OUTPUT_DIR: &str = "/Volumes/Bitcoin/data";
const DUST_THRESHOLD: u64 = 576;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage: {} <bitcoin_datadir> <start_height> <end_height>", args[0]);
        eprintln!("Example: {} /Volumes/Bitcoin/bitcoin 938612 940612", args[0]);
        eprintln!();
        eprintln!("Computes the UTXO delta for the inclusive block range [start, end].");
        eprintln!("Outputs:");
        eprintln!("  {}/utxo_delta_minus.bin  — 36B entries: [32B txid][4B vout]", OUTPUT_DIR);
        eprintln!("  {}/utxo_delta_plus.bin   — 44B entries: [32B txid][4B vout][8B amount]", OUTPUT_DIR);
        std::process::exit(1);
    }

    let bitcoin_dir = PathBuf::from(&args[1]);
    let start_height: u64 = args[2].parse().expect("start_height must be a number");
    let end_height: u64 = args[3].parse().expect("end_height must be a number");

    if start_height > end_height {
        eprintln!("Error: start_height ({}) > end_height ({})", start_height, end_height);
        std::process::exit(1);
    }

    let blocks_dir = bitcoin_dir.join("blocks");
    if !blocks_dir.exists() {
        eprintln!("Error: blocks directory does not exist: {:?}", blocks_dir);
        std::process::exit(1);
    }

    let cookie_path = bitcoin_dir.join(".cookie");
    if !cookie_path.exists() {
        eprintln!("Error: Cookie file not found: {:?}", cookie_path);
        eprintln!("Make sure Bitcoin Core is running.");
        std::process::exit(1);
    }

    let client = Client::new("http://127.0.0.1:8332", Auth::CookieFile(cookie_path))
        .expect("Failed to create RPC client");

    let chain_height = client.get_block_count().expect("Failed to get block count");
    if end_height > chain_height {
        eprintln!(
            "Error: end_height ({}) > chain height ({})",
            end_height, chain_height
        );
        std::process::exit(1);
    }

    let num_blocks = end_height - start_height + 1;

    println!("=== UTXO Delta Computation ===");
    println!("Chain height:  {}", chain_height);
    println!("Range:         {} to {} ({} blocks, inclusive)", start_height, end_height, num_blocks);
    println!();

    // Data structures
    // created: in-range outputs not yet spent → becomes PLUS set at the end
    // minus: pre-range UTXOs that were spent during the range
    let mut created: HashMap<(Txid, u32), u64> = HashMap::new();
    let mut minus: Vec<([u8; 32], u32)> = Vec::new();
    let mut created_and_consumed: u64 = 0;
    let mut total_inputs: u64 = 0;
    let mut total_outputs: u64 = 0;
    let mut total_txs: u64 = 0;
    let mut coinbase_count: u64 = 0;

    // Stream blocks
    let reader = Reader::new(blocks_dir, &client);
    let receiver = reader.read(
        Some((start_height as u32).into()),
        Some(((end_height + 1) as u32).into()), // exclusive end
    );

    let start_time = Instant::now();
    let mut blocks_done: u64 = 0;
    let mut last_print = Instant::now();

    for block in receiver.iter() {
        for tx in &block.txdata {
            total_txs += 1;

            // Process inputs (consume UTXOs)
            if tx.is_coinbase() {
                coinbase_count += 1;
            } else {
                for input in &tx.input {
                    total_inputs += 1;
                    let prev = &input.previous_output;
                    let key = (prev.txid, prev.vout);

                    if created.remove(&key).is_some() {
                        // Created and consumed within range — exclude from both
                        created_and_consumed += 1;
                    } else {
                        // Pre-range UTXO spent → MINUS
                        minus.push((prev.txid.to_byte_array(), prev.vout));
                    }
                }
            }

            // Process outputs (create UTXOs)
            let txid = tx.compute_txid();
            for (vout, output) in tx.output.iter().enumerate() {
                total_outputs += 1;
                created.insert((txid, vout as u32), output.value.to_sat());
            }
        }

        blocks_done += 1;

        if last_print.elapsed().as_millis() >= 500 || blocks_done == num_blocks {
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = blocks_done as f64 / elapsed;
            let eta = if rate > 0.0 {
                (num_blocks - blocks_done) as f64 / rate
            } else {
                0.0
            };
            print!(
                "\rProcessing: {}/{} blocks ({:.1}%) | {:.0} blk/s | ETA {:.0}s | MINUS {} | PLUS {} | created+consumed {}   ",
                blocks_done, num_blocks,
                100.0 * blocks_done as f64 / num_blocks as f64,
                rate, eta,
                minus.len(), created.len(), created_and_consumed
            );
            io::stdout().flush().ok();
            last_print = Instant::now();
        }
    }

    let elapsed = start_time.elapsed();
    println!(
        "\rStreamed {} blocks in {:.1}s ({:.0} blk/s)                                                                         ",
        blocks_done,
        elapsed.as_secs_f64(),
        blocks_done as f64 / elapsed.as_secs_f64()
    );
    println!();

    // ── Filter dust from PLUS set (after all created/consumed accounting) ──

    let plus_before_dust = created.len() as u64;
    created.retain(|_, amt| *amt > DUST_THRESHOLD);
    let dust_filtered = plus_before_dust - created.len() as u64;

    // ── Summary ──────────────────────────────────────────────────────

    let minus_count = minus.len();
    let plus_count = created.len();

    // Compute total BTC in PLUS set
    let plus_total_sats: u64 = created.values().sum();

    println!("=== Summary ===");
    println!("Total transactions:     {}", total_txs);
    println!("  Coinbase:             {}", coinbase_count);
    println!("Total inputs consumed:  {}", total_inputs);
    println!("Total outputs created:  {}", total_outputs);
    println!();
    println!("MINUS (pre-range spent):     {}", minus_count);
    println!("PLUS  (new, still unspent):  {}", plus_count);
    println!("  Total BTC in PLUS:         {:.8} BTC", plus_total_sats as f64 / 1e8);
    println!("Created & consumed (excluded): {}", created_and_consumed);
    println!("Dust filtered (amt <= {}):     {}", DUST_THRESHOLD, dust_filtered);
    println!();

    // Sanity check: total_outputs = plus_count + created_and_consumed + dust_filtered
    // total_inputs = minus_count + created_and_consumed
    println!("Sanity checks:");
    println!(
        "  outputs = plus + created_consumed + dust: {} = {} + {} + {} → {}",
        total_outputs,
        plus_count,
        created_and_consumed,
        dust_filtered,
        if total_outputs == (plus_count as u64 + created_and_consumed + dust_filtered) {
            "OK"
        } else {
            "MISMATCH"
        }
    );
    println!(
        "  inputs  = minus + created_consumed: {} = {} + {} → {}",
        total_inputs,
        minus_count,
        created_and_consumed,
        if total_inputs == (minus_count as u64 + created_and_consumed) {
            "OK"
        } else {
            "MISMATCH"
        }
    );
    println!();

    // ── Write MINUS file ─────────────────────────────────────────────

    let minus_path = format!("{}/utxo_delta_minus.bin", OUTPUT_DIR);
    println!("Writing MINUS to {} ...", minus_path);
    {
        let file = File::create(&minus_path).expect("Failed to create minus file");
        let mut w = BufWriter::with_capacity(1024 * 1024, file);
        for (txid_bytes, vout) in &minus {
            w.write_all(txid_bytes).unwrap();
            w.write_all(&vout.to_le_bytes()).unwrap();
        }
        w.flush().unwrap();
    }
    let minus_size = std::fs::metadata(&minus_path).map(|m| m.len()).unwrap_or(0);
    println!(
        "  {} entries, {} bytes ({:.2} MB)",
        minus_count,
        minus_size,
        minus_size as f64 / 1e6
    );

    // ── Write PLUS file ──────────────────────────────────────────────

    let plus_path = format!("{}/utxo_delta_plus.bin", OUTPUT_DIR);
    println!("Writing PLUS to {} ...", plus_path);
    {
        let file = File::create(&plus_path).expect("Failed to create plus file");
        let mut w = BufWriter::with_capacity(1024 * 1024, file);
        for ((txid, vout), amount) in &created {
            w.write_all(&txid.to_byte_array()).unwrap();
            w.write_all(&vout.to_le_bytes()).unwrap();
            w.write_all(&amount.to_le_bytes()).unwrap();
        }
        w.flush().unwrap();
    }
    let plus_size = std::fs::metadata(&plus_path).map(|m| m.len()).unwrap_or(0);
    println!(
        "  {} entries, {} bytes ({:.2} MB)",
        plus_count,
        plus_size,
        plus_size as f64 / 1e6
    );

    println!();
    println!("Done.");
}
