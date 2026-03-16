use bitcoinpir::mpfh::bitvector::BitVector;
use bitcoinpir::mpfh::Mphf;
use bitcoinpir::utils;
use log::error;
use std::fs::File;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::stdout;
use std::io::{self, BufReader, Read, Write};
use std::iter::ExactSizeIterator;
use std::marker::PhantomData;
use std::path::Path;

const TXID_FILE: &str = "/Volumes/Bitcoin/data/txid.bin";
const MPHF_FILE: &str = "/Volumes/Bitcoin/data/txid_mphf.bin";
const TXID_SIZE: usize = 32;
const REMAINING_FILE: &str = "/Volumes/Bitcoin/data/remaining_txids.txt";
const REMAINING_THRESHOLD: u64 = 4;

/// Streaming iterator for reading transaction IDs from a file
/// This allows lazy loading without loading all txids into memory
/// Uses RefCell for interior mutability to allow Iterator on &TxidIterator
struct TxidIterator {
    reader: BufReader<File>,
    remaining: u64,
    total: u64,
    count: u64,
}

impl TxidIterator {
    fn new(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        // Calculate number of transactions
        if file_size % TXID_SIZE as u64 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("File size {} is not a multiple of {}", file_size, TXID_SIZE),
            ));
        }

        let total = file_size / TXID_SIZE as u64;
        Ok(TxidIterator {
            reader: BufReader::with_capacity(1024 * 1024 * 100, file), // 100MB buffer
            remaining: total,
            total,
            count: 0,
        })
    }
}

// Implement Iterator for &TxidIterator (immutable reference)
// This is needed because from_chunked_iterator_parallel takes &I
impl Iterator for TxidIterator {
    type Item = [u8; 32];

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = vec![0u8; TXID_SIZE];
        if self.reader.read_exact(&mut buf).is_ok() {
            self.remaining -= 1;
            self.count += 1;
            Some(buf.try_into().unwrap())
        } else {
            None
        }
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.remaining -= n as u64;
        self.count += n as u64;
        let offset = (n as u64) * (TXID_SIZE as u64);
        self.reader.seek_relative(offset as i64).ok()?;
        self.next()
    }
}

impl ExactSizeIterator for TxidIterator {
    fn len(&self) -> usize {
        self.remaining as usize
    }
}

/// Build MPHF using boomphf with new_parallel method
/// This uses streaming iteration to avoid loading all txids into memory
fn build_mphf(path: &Path) -> Mphf<[u8; 32]> {
    println!("Building MPHF using parallel method...");
    println!("Collecting txids for parallel MPHF construction...");

    // Calculate total number of txids for display
    let total_txids = TxidIterator::new(path).unwrap().total;
    println!("Total txids to process: {}", total_txids);

    let start = std::time::Instant::now();

    // Use new_parallel for faster construction
    // gamma parameter controls trade-off between speed and space (typically 1.0-2.0)
    let gamma = 2.0;
    let build_start = std::time::Instant::now();

    let mphf = construct_mpdf_direct(gamma, path, total_txids);

    let build_duration = build_start.elapsed();
    let total_duration = start.elapsed();

    println!("MPHF built successfully in {:?}", build_duration);
    println!("Total time (read + build): {:?}", total_duration);

    mphf
}

#[inline]
fn fold(v: u64) -> u32 {
    ((v & 0xFFFFFFFF) as u32) ^ ((v >> 32) as u32)
}

#[inline]
fn hash_with_seed<T: Hash + ?Sized>(iter: u64, v: &T) -> u64 {
    let mut state = wyhash::WyHash::with_seed(1 << (iter + iter));
    v.hash(&mut state);
    state.finish()
}

#[inline]
fn hash_with_seed32<T: Hash + ?Sized>(iter: u64, v: &T) -> u32 {
    fold(hash_with_seed(iter, v))
}

#[inline]
fn fastmod(hash: u32, n: u32) -> u64 {
    ((hash as u64) * (n as u64)) >> 32
}

#[inline]
fn hashmod<T: Hash + ?Sized>(iter: u64, v: &T, n: u64) -> u64 {
    // when n < 2^32, use the fast alternative to modulo described here:
    // https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
    if n < (1 << 32) {
        let h = hash_with_seed32(iter, v);
        fastmod(h, n as u32) as u64
    } else {
        let h = hash_with_seed(iter, v);
        h % (n as u64)
    }
}

pub fn construct_mpdf_direct(gamma: f64, path: &Path, n: u64) -> Mphf<[u8; 32]> {
    let mut iter = 0;
    let mut bitvecs = Vec::new();
    #[allow(unused_mut)]
    let mut done_keys = BitVector::new(std::cmp::max(255, n));
    assert!(gamma > 1.01);

    loop {
        if iter > 100 {
            error!("ran out of key space. items: {:?}", done_keys.len());
            panic!("counldn't find unique hashes");
        }

        let keys_remaining = if iter == 0 {
            n
        } else {
            n - (done_keys.len() as u64)
        };

        // Check if remaining keys are at or below threshold - finish early
        if keys_remaining <= REMAINING_THRESHOLD {
            println!(
                "\n=== Only {} keys remaining (threshold: {}) ===",
                keys_remaining, REMAINING_THRESHOLD
            );
            println!("Writing remaining txids to {}...", REMAINING_FILE);

            // Collect and write remaining txids to file
            if let Err(e) = write_remaining_txids(path, &done_keys, n) {
                error!("Failed to write remaining txids: {}", e);
            } else {
                println!(
                    "Successfully wrote remaining {} txids to {}",
                    keys_remaining, REMAINING_FILE
                );
            }
            break;
        }

        let size = std::cmp::max(255, (gamma * keys_remaining as f64) as u64);

        let mut a = BitVector::new(size);
        let mut collide = BitVector::new(size);

        let seed = iter;

        println!(
            "\n=== Iteration {} (keys remaining: {}) ===",
            iter, keys_remaining
        );

        let mut object_iter = TxidIterator::new(path).unwrap().into_iter();

        // Note: we will use Iterator::nth() to advance the iterator if
        // we've skipped over some items.
        let mut object_pos = 0;
        let len = object_iter.len() as u64;

        // Progress tracking for Pass 1 (every 0.1%)
        let one_tenth_percent = std::cmp::max(1, len / 1000);
        let mut last_reported_permille = 0u64;
        let pass1_start = std::time::Instant::now();
        print!("Pass 1 (collision detection): 0.0% | ETA: calculating...");
        stdout().flush().ok();

        for object_index in 0..len {
            let index = object_index;

            // Update progress every 0.1%
            let current_permille = object_index / one_tenth_percent;
            if current_permille > last_reported_permille && current_permille <= 1000 {
                let elapsed = pass1_start.elapsed().as_secs_f64();
                let progress_fraction = current_permille as f64 / 1000.0;
                let eta_secs = if progress_fraction > 0.0 {
                    (elapsed / progress_fraction) * (1.0 - progress_fraction)
                } else {
                    0.0
                };
                let eta_str = utils::format_duration(eta_secs);
                print!(
                    "\rPass 1 (collision detection): {:.1}% | ETA: {}",
                    current_permille as f64 / 10.0,
                    eta_str
                );
                stdout().flush().ok();
                last_reported_permille = current_permille;
            }

            if !done_keys.contains(index) {
                let key = match object_iter.nth((object_index - object_pos) as usize) {
                    None => panic!("ERROR: max number of items overflowed"),
                    Some(key) => key,
                };

                object_pos = object_index + 1;

                let idx = hashmod(seed, &key, size);

                if collide.contains(idx) {
                    continue;
                }
                let a_was_set = !a.insert_sync(idx);
                if a_was_set {
                    collide.insert_sync(idx);
                }
            }
        } // end-window for
        println!("\rPass 1 (collision detection): 100% - complete");

        // Note: we will use Iterator::nth() to advance the iterator if
        // we've skipped over some items.

        let mut object_iter = TxidIterator::new(path).unwrap().into_iter();
        let mut object_pos = 0;
        let len = object_iter.len() as u64;

        // Progress tracking for Pass 2 (every 0.1%)
        let one_tenth_percent = std::cmp::max(1, len / 1000);
        let mut last_reported_permille = 0u64;
        let pass2_start = std::time::Instant::now();
        print!("Pass 2 (key assignment): 0.0% | ETA: calculating...");
        stdout().flush().ok();

        for object_index in 0..len {
            let index = object_index;

            // Update progress every 0.1%
            let current_permille = object_index / one_tenth_percent;
            if current_permille > last_reported_permille && current_permille <= 1000 {
                let elapsed = pass2_start.elapsed().as_secs_f64();
                let progress_fraction = current_permille as f64 / 1000.0;
                let eta_secs = if progress_fraction > 0.0 {
                    (elapsed / progress_fraction) * (1.0 - progress_fraction)
                } else {
                    0.0
                };
                let eta_str = utils::format_duration(eta_secs);
                print!(
                    "\rPass 2 (key assignment): {:.1}% | ETA: {}",
                    current_permille as f64 / 10.0,
                    eta_str
                );
                stdout().flush().ok();
                last_reported_permille = current_permille;
            }

            if !done_keys.contains(index) {
                // This will fast-forward the iterator over unneeded items.
                let key = match object_iter.nth((object_index - object_pos) as usize) {
                    None => panic!("ERROR: max number of items overflowed"),
                    Some(key) => key,
                };

                object_pos = object_index + 1;

                let idx = hashmod(seed, &key, size);

                if collide.contains(idx) {
                    a.remove(idx);
                } else {
                    done_keys.insert(index);
                }
            }
        } // end-window for
        println!("\rPass 2 (key assignment): 100% - complete");

        bitvecs.push(a);
        if done_keys.len() as u64 == n {
            break;
        }
        iter += 1;
    }

    Mphf::<[u8; 32]> {
        bitvecs: Mphf::<[u8; 32]>::compute_ranks(bitvecs),
        phantom: PhantomData,
    }
}

/// Save MPHF to file using serde serialization
fn save_mphf(mphf: &Mphf<[u8; 32]>, path: &Path) -> io::Result<()> {
    println!("Saving MPHF to {}...", path.display());

    // With serde feature enabled, we can directly serialize the MPHF
    let serialized = bincode::serialize(mphf).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Serialization failed: {}", e))
    })?;

    let mut file = File::create(path)?;
    file.write_all(&serialized)?;

    println!("MPHF saved successfully ({} bytes)", serialized.len());
    Ok(())
}

/// Write remaining txids (those not in done_keys) to a text file
/// Each txid is written as a hex string on a separate line
fn write_remaining_txids(path: &Path, done_keys: &BitVector, total: u64) -> io::Result<()> {
    let mut file = File::create(REMAINING_FILE)?;

    // Write header with count
    let remaining_count = total - done_keys.len() as u64;
    writeln!(
        file,
        "# Remaining txids that could not be assigned unique hashes"
    )?;
    writeln!(file, "# Count: {}", remaining_count)?;
    writeln!(file, "# Format: index<TAB>txid_hex")?;
    writeln!(file)?;

    let mut object_iter = TxidIterator::new(path)?;
    let mut object_pos = 0;

    for index in 0..total {
        if !done_keys.contains(index) {
            // Fast-forward to the needed item
            let key = match object_iter.nth((index - object_pos) as usize) {
                Some(k) => k,
                None => break,
            };
            object_pos = index + 1;

            // Convert to hex string
            let hex_str: String = key.iter().map(|b| format!("{:02x}", b)).collect();
            writeln!(file, "{}\t{}", index, hex_str)?;
        }
    }

    Ok(())
}

fn main() {
    println!("=== MPHF Builder for Bitcoin Transaction IDs ===");
    println!("Using streaming iterator to avoid loading all txids into memory");
    println!("Using parallel processing for faster MPHF construction");
    println!();

    // Step 1: Check if txid.bin exists
    let txid_path = Path::new(TXID_FILE);
    if !txid_path.exists() {
        eprintln!("✗ Error: File '{}' not found!", TXID_FILE);
        eprintln!("  Please run generate_txid_file first to create the transaction ID file.");
        std::process::exit(1);
    }

    // Step 2: Build MPHF using streaming iterator
    let mphf = build_mphf(txid_path);

    println!();

    // Step 4: Save MPHF
    let mphf_path = Path::new(MPHF_FILE);
    if let Err(e) = save_mphf(&mphf, mphf_path) {
        eprintln!("✗ Error saving MPHF: {}", e);
        std::process::exit(1);
    }

    println!();
    println!("=== Summary ===");
    println!("MPHF built using true streaming iterator (memory efficient)");
    println!("MPHF output: {}", MPHF_FILE);
    println!();
    println!("You can now use this MPHF for fast txid lookups!");
}
