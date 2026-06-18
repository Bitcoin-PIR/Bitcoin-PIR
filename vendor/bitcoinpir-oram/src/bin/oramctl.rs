use bitcoinpir_oram::{
    circuit_meta_page_bytes, circuit_payload_page_bytes, stress_circuit, AeadPageStore,
    CircuitCuckooBinReader, CircuitOram, CircuitOramState, CircuitStoreAuthState,
    CircuitStressConfig, CircuitStressPattern, CircuitStressReport, CuckooLevel,
    CuckooOramEstimate, CuckooOramSizing, CuckooPackedBlockReader, CuckooTableInfo,
    DirectChunkPackedBlockReader, DirectIndexPackedBlockReader, DirectLevel, DirectOramEstimate,
    DirectOramSizing, DirectTableInfo, Error, FilePageStore, FrontCachedPageStore, OramParams,
    OramState, PageStore, PathOram, Result, TieredMerklePageStore, TrustedBlockSource,
    AEAD_OVERHEAD, DIRECT_INDEX_DEFAULT_HASH_FNS, DIRECT_INDEX_DEFAULT_LOAD_FACTOR,
    DIRECT_INDEX_DEFAULT_SEED, DIRECT_INDEX_DEFAULT_SLOTS_PER_BIN,
};
use clap::{Parser, Subcommand, ValueEnum};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{
    fs::{self, File, OpenOptions},
    hint::black_box,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Debug, Parser)]
#[command(about = "BitcoinPIR Path ORAM prototype utility")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build a trusted ORAM image containing deterministic test payloads.
    Build {
        /// ORAM bucket image path.
        #[arg(long)]
        image: PathBuf,
        /// Trusted controller-state output path.
        #[arg(long)]
        state: PathBuf,
        /// 32-byte hex state encryption key. If omitted, state is written in plaintext.
        #[arg(long)]
        state_key_hex: Option<String>,
        /// Number of logical blocks.
        #[arg(long)]
        blocks: usize,
        /// Payload bytes per logical block.
        #[arg(long)]
        block_size: usize,
        /// Optional explicit leaf count. Must be a power of two.
        #[arg(long)]
        leaves: Option<usize>,
        /// Physical blocks per bucket.
        #[arg(long, default_value_t = 4)]
        bucket_size: usize,
        /// Stash capacity.
        #[arg(long, default_value_t = 512)]
        stash_capacity: usize,
        /// Enable page AEAD.
        #[arg(long)]
        encrypted: bool,
        /// 32-byte hex page encryption key. Required with --encrypted.
        #[arg(long)]
        key_hex: Option<String>,
        /// Cache this many public top ORAM tree levels in trusted memory.
        #[arg(long, default_value_t = 0)]
        cache_levels: usize,
        /// 32-byte hex RNG seed. Defaults to all 0x07 for reproducible tests.
        #[arg(long)]
        seed_hex: Option<String>,
    },
    /// Run random reads against an existing image and update the state file.
    Bench {
        /// ORAM bucket image path.
        #[arg(long)]
        image: PathBuf,
        /// Trusted controller-state path.
        #[arg(long)]
        state: PathBuf,
        /// 32-byte hex state encryption key. Required if the state was encrypted.
        #[arg(long)]
        state_key_hex: Option<String>,
        /// Number of random reads.
        #[arg(long, default_value_t = 1000)]
        ops: usize,
        /// Enable page AEAD.
        #[arg(long)]
        encrypted: bool,
        /// 32-byte hex page encryption key. Required with --encrypted.
        #[arg(long)]
        key_hex: Option<String>,
        /// Cache this many public top ORAM tree levels in trusted memory.
        #[arg(long, default_value_t = 0)]
        cache_levels: usize,
        /// 32-byte hex query RNG seed. Defaults to all 0x03.
        #[arg(long)]
        query_seed_hex: Option<String>,
        /// Do not write back state. ORAM reads still mutate image pages; use only for disposable images.
        #[arg(long)]
        no_save: bool,
    },
    /// Estimate ORAM sizes for existing DPF/Harmony cuckoo table directories.
    SizeCuckoo {
        /// BitcoinPIR DB directory containing batch_pir_cuckoo.bin and chunk_pir_cuckoo.bin.
        #[arg(long = "db-dir", required = true)]
        db_dirs: Vec<PathBuf>,
        /// Comma-separated bins packed into one ORAM logical block.
        #[arg(long, value_delimiter = ',', default_value = "8")]
        packs: Vec<usize>,
        /// Comma-separated divisors for leaves = next_power_of_two(ceil(blocks / divisor)).
        #[arg(long, value_delimiter = ',', default_value = "1,2,4,8")]
        leaf_divisors: Vec<usize>,
        /// Physical blocks per ORAM bucket.
        #[arg(long, default_value_t = 4)]
        bucket_size: usize,
        /// Fixed stash capacity in trusted memory.
        #[arg(long, default_value_t = 512)]
        stash_capacity: usize,
        /// Public top ORAM tree levels cached in trusted memory.
        #[arg(long, default_value_t = 5)]
        cache_levels: usize,
    },
    /// Estimate ORAM sizes for direct non-PBC INDEX/CHUNK source files.
    SizeDirect {
        /// Direct INDEX source file: utxo_chunks_index_nodust.bin.
        #[arg(long)]
        index_file: PathBuf,
        /// Direct CHUNK source file: utxo_chunks_nodust.bin.
        #[arg(long)]
        chunks_file: PathBuf,
        /// Comma-separated direct items packed into one ORAM logical block.
        #[arg(long, value_delimiter = ',', default_value = "16")]
        packs: Vec<usize>,
        /// Comma-separated divisors for leaves = next_power_of_two(ceil(blocks / divisor)).
        #[arg(long, value_delimiter = ',', default_value = "1,2,4,8")]
        leaf_divisors: Vec<usize>,
        /// Physical blocks per ORAM bucket.
        #[arg(long, default_value_t = 2)]
        bucket_size: usize,
        /// Fixed stash capacity in trusted memory.
        #[arg(long, default_value_t = 4096)]
        stash_capacity: usize,
        /// Public top ORAM tree levels cached in trusted memory.
        #[arg(long, default_value_t = 5)]
        cache_levels: usize,
        /// Direct INDEX slots per cuckoo bin.
        #[arg(long, default_value_t = DIRECT_INDEX_DEFAULT_SLOTS_PER_BIN)]
        index_slots_per_bin: usize,
        /// Direct INDEX cuckoo hash functions.
        #[arg(long, default_value_t = DIRECT_INDEX_DEFAULT_HASH_FNS)]
        index_hash_fns: usize,
        /// Direct INDEX cuckoo target load factor.
        #[arg(long, default_value_t = DIRECT_INDEX_DEFAULT_LOAD_FACTOR)]
        index_load_factor: f64,
        /// Direct INDEX cuckoo seed, as a u64.
        #[arg(long, default_value_t = DIRECT_INDEX_DEFAULT_SEED)]
        index_seed: u64,
    },
    /// Reconstruct direct CHUNK source bytes from a deployed PBC chunk cuckoo table.
    ///
    /// This is lossless for CHUNK because PBC chunk slots contain
    /// `[4B chunk_id][40B chunk_data]`. It cannot reconstruct the direct INDEX
    /// source because PBC index slots store only an 8-byte fingerprint tag, not
    /// the original 20-byte script hash.
    ExtractDirectChunks {
        /// DPF/Harmony chunk_pir_cuckoo.bin.
        #[arg(long)]
        chunk_cuckoo_file: PathBuf,
        /// Output direct CHUNK source file, usually utxo_chunks_nodust.bin.
        #[arg(long)]
        out_file: PathBuf,
    },
    /// Build split-store Circuit ORAM images from DPF/Harmony cuckoo tables.
    BuildCircuit {
        /// BitcoinPIR DB directory containing batch_pir_cuckoo.bin and chunk_pir_cuckoo.bin.
        #[arg(long)]
        db_dir: PathBuf,
        /// Output directory for index/chunk metadata, payload, and state files.
        #[arg(long)]
        out_dir: PathBuf,
        /// Which Circuit ORAM instance to build.
        #[arg(long, value_enum, default_value_t = LevelArg::All)]
        level: LevelArg,
        /// Consecutive cuckoo bins packed into one ORAM logical block.
        #[arg(long, default_value_t = 16)]
        pack: usize,
        /// Leaves = next_power_of_two(ceil(blocks / divisor)).
        #[arg(long, default_value_t = 4)]
        leaf_divisor: usize,
        /// Physical blocks per Circuit ORAM bucket.
        #[arg(long, default_value_t = 2)]
        bucket_size: usize,
        /// Fixed stash capacity in trusted memory.
        #[arg(long, default_value_t = 4096)]
        stash_capacity: usize,
        /// Enable page AEAD for metadata and payload images.
        #[arg(long)]
        encrypted: bool,
        /// 32-byte hex page encryption key. Required with --encrypted.
        #[arg(long)]
        key_hex: Option<String>,
        /// 32-byte hex state encryption key. If omitted, state is written in plaintext.
        #[arg(long)]
        state_key_hex: Option<String>,
        /// Cache this many public top ORAM tree levels in trusted memory during build.
        #[arg(long, default_value_t = 0)]
        cache_levels: usize,
        /// Generate tiered Merkle authentication images for runtime rollback checks.
        #[arg(long)]
        auth_store: bool,
        /// Trusted Merkle top levels kept in state when --auth-store is enabled.
        #[arg(long, default_value_t = 1)]
        auth_trusted_levels: usize,
        /// Plaintext page size for packed Merkle hash-node stores.
        #[arg(long, default_value_t = 4096)]
        auth_hash_page_size: usize,
        /// 32-byte hex RNG seed. Defaults to all 0x06 for reproducible builds.
        #[arg(long)]
        seed_hex: Option<String>,
    },
    /// Build split-store Circuit ORAM images from direct non-PBC INDEX/CHUNK source files.
    BuildDirect {
        /// Direct INDEX source file: utxo_chunks_index_nodust.bin.
        #[arg(long)]
        index_file: PathBuf,
        /// Direct CHUNK source file: utxo_chunks_nodust.bin.
        #[arg(long)]
        chunks_file: PathBuf,
        /// Output directory for direct index/chunk metadata, payload, state, and direct metadata files.
        #[arg(long)]
        out_dir: PathBuf,
        /// Which direct ORAM instance to build.
        #[arg(long, value_enum, default_value_t = DirectLevelArg::All)]
        level: DirectLevelArg,
        /// Consecutive direct items packed into one ORAM logical block.
        #[arg(long, default_value_t = 16)]
        pack: usize,
        /// Leaves = next_power_of_two(ceil(blocks / divisor)).
        #[arg(long, default_value_t = 2)]
        leaf_divisor: usize,
        /// Physical blocks per Circuit ORAM bucket.
        #[arg(long, default_value_t = 2)]
        bucket_size: usize,
        /// Fixed stash capacity in trusted memory.
        #[arg(long, default_value_t = 4096)]
        stash_capacity: usize,
        /// Enable page AEAD for metadata and payload images.
        #[arg(long)]
        encrypted: bool,
        /// 32-byte hex page encryption key. Required with --encrypted.
        #[arg(long)]
        key_hex: Option<String>,
        /// 32-byte hex state encryption key. If omitted, state is written in plaintext.
        #[arg(long)]
        state_key_hex: Option<String>,
        /// Cache this many public top ORAM tree levels in trusted memory during build.
        #[arg(long, default_value_t = 0)]
        cache_levels: usize,
        /// Generate tiered Merkle authentication images for runtime rollback checks.
        #[arg(long)]
        auth_store: bool,
        /// Trusted Merkle top levels kept in state when --auth-store is enabled.
        #[arg(long, default_value_t = 1)]
        auth_trusted_levels: usize,
        /// Plaintext page size for packed Merkle hash-node stores.
        #[arg(long, default_value_t = 4096)]
        auth_hash_page_size: usize,
        /// Direct INDEX slots per cuckoo bin.
        #[arg(long, default_value_t = DIRECT_INDEX_DEFAULT_SLOTS_PER_BIN)]
        index_slots_per_bin: usize,
        /// Direct INDEX cuckoo hash functions.
        #[arg(long, default_value_t = DIRECT_INDEX_DEFAULT_HASH_FNS)]
        index_hash_fns: usize,
        /// Direct INDEX cuckoo target load factor.
        #[arg(long, default_value_t = DIRECT_INDEX_DEFAULT_LOAD_FACTOR)]
        index_load_factor: f64,
        /// Direct INDEX cuckoo seed, as a u64.
        #[arg(long, default_value_t = DIRECT_INDEX_DEFAULT_SEED)]
        index_seed: u64,
        /// 32-byte hex ORAM RNG seed. Defaults to all 0x0a for reproducible direct builds.
        #[arg(long)]
        seed_hex: Option<String>,
    },
    /// Run random reads against split-store Circuit ORAM images.
    BenchCircuit {
        /// ORAM image directory containing index/chunk metadata, payload, and state files.
        #[arg(long)]
        oram_dir: PathBuf,
        /// Optional BitcoinPIR DB directory for byte-for-byte read verification.
        #[arg(long)]
        db_dir: Option<PathBuf>,
        /// Which Circuit ORAM instance to benchmark.
        #[arg(long, value_enum, default_value_t = LevelArg::All)]
        level: LevelArg,
        /// Consecutive cuckoo bins packed into one ORAM logical block.
        #[arg(long, default_value_t = 16)]
        pack: usize,
        /// Number of random reads per selected level.
        #[arg(long, default_value_t = 1000)]
        ops: usize,
        /// Public eviction paths drained after each read.
        #[arg(long, default_value_t = 2)]
        drain_per_access: u64,
        /// Enable page AEAD for metadata and payload images.
        #[arg(long)]
        encrypted: bool,
        /// 32-byte hex page encryption key. Required with --encrypted.
        #[arg(long)]
        key_hex: Option<String>,
        /// 32-byte hex state encryption key. Required if state was encrypted.
        #[arg(long)]
        state_key_hex: Option<String>,
        /// Cache this many public top ORAM tree levels in trusted memory.
        #[arg(long, default_value_t = 0)]
        cache_levels: usize,
        /// Use tiered Merkle authentication images generated by build-circuit.
        #[arg(long)]
        auth_store: bool,
        /// 32-byte hex query RNG seed. Defaults to all 0x04.
        #[arg(long)]
        query_seed_hex: Option<String>,
        /// Do not write back state. ORAM reads still mutate image pages; use only for disposable images.
        #[arg(long)]
        no_save: bool,
    },
    /// Verify original cuckoo bins read through split-store Circuit ORAM images.
    VerifyCircuitBins {
        /// ORAM image directory containing index/chunk metadata, payload, and state files.
        #[arg(long)]
        oram_dir: PathBuf,
        /// BitcoinPIR DB directory containing batch_pir_cuckoo.bin and chunk_pir_cuckoo.bin.
        #[arg(long)]
        db_dir: PathBuf,
        /// Which Circuit ORAM instance to verify.
        #[arg(long, value_enum, default_value_t = LevelArg::All)]
        level: LevelArg,
        /// Consecutive cuckoo bins packed into one ORAM logical block.
        #[arg(long, default_value_t = 16)]
        pack: usize,
        /// Number of random cuckoo bins per selected level.
        #[arg(long, default_value_t = 1000)]
        bins: usize,
        /// Public eviction paths drained after each bin read.
        #[arg(long, default_value_t = 2)]
        drain_per_access: u64,
        /// Enable page AEAD for metadata and payload images.
        #[arg(long)]
        encrypted: bool,
        /// 32-byte hex page encryption key. Required with --encrypted.
        #[arg(long)]
        key_hex: Option<String>,
        /// 32-byte hex state encryption key. Required if state was encrypted.
        #[arg(long)]
        state_key_hex: Option<String>,
        /// Cache this many public top ORAM tree levels in trusted memory.
        #[arg(long, default_value_t = 0)]
        cache_levels: usize,
        /// Use tiered Merkle authentication images generated by build-circuit.
        #[arg(long)]
        auth_store: bool,
        /// 32-byte hex query RNG seed. Defaults to all 0x08.
        #[arg(long)]
        query_seed_hex: Option<String>,
        /// Do not write back state. ORAM reads still mutate image pages; use only for disposable images.
        #[arg(long)]
        no_save: bool,
    },
    /// Stress-test Circuit ORAM stash pressure over DPF/Harmony cuckoo table sizes.
    StressCircuit {
        /// BitcoinPIR DB directory containing batch_pir_cuckoo.bin and chunk_pir_cuckoo.bin.
        #[arg(long = "db-dir", required = true)]
        db_dirs: Vec<PathBuf>,
        /// Comma-separated bins packed into one ORAM logical block.
        #[arg(long, value_delimiter = ',', default_value = "16")]
        packs: Vec<usize>,
        /// Comma-separated divisors for leaves = next_power_of_two(ceil(blocks / divisor)).
        #[arg(long, value_delimiter = ',', default_value = "4")]
        leaf_divisors: Vec<usize>,
        /// Physical blocks per Circuit ORAM bucket.
        #[arg(long, default_value_t = 2)]
        bucket_size: usize,
        /// Fixed stash capacity in trusted memory.
        #[arg(long, default_value_t = 512)]
        stash_capacity: usize,
        /// Measured real accesses per table/config.
        #[arg(long, default_value_t = 100_000)]
        ops: usize,
        /// Warm-up accesses excluded from stash percentiles.
        #[arg(long, default_value_t = 10_000)]
        warmup_ops: usize,
        /// Public logical-id sequence.
        #[arg(long, value_enum, default_value_t = StressPatternArg::Random)]
        pattern: StressPatternArg,
        /// Public eviction paths drained after each real access.
        #[arg(long, default_value_t = 2)]
        drain_per_access: u64,
        /// Public burst interval. Zero disables burst draining.
        #[arg(long, default_value_t = 0)]
        burst_interval: usize,
        /// Public eviction paths drained when --burst-interval fires.
        #[arg(long, default_value_t = 0)]
        burst_budget: u64,
        /// Optional public maximum pending eviction debt.
        #[arg(long)]
        max_debt: Option<u64>,
        /// 32-byte hex simulator RNG seed. Defaults to all 0x05.
        #[arg(long)]
        seed_hex: Option<String>,
    },
    /// Benchmark branchless linear scans over trusted position maps.
    BenchPosMap {
        /// Comma-separated position-map lengths to benchmark.
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "249760,561660,2660429,5334640"
        )]
        sizes: Vec<usize>,
        /// Measured lookups per size and mode.
        #[arg(long, default_value_t = 100)]
        ops: usize,
        /// Warm-up lookups per size before timing.
        #[arg(long, default_value_t = 10)]
        warmup_ops: usize,
        /// 32-byte hex query RNG seed. Defaults to all 0x09.
        #[arg(long)]
        query_seed_hex: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum StressPatternArg {
    Random,
    RoundRobin,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LevelArg {
    All,
    Index,
    Chunk,
}

impl LevelArg {
    const fn levels(self) -> &'static [CuckooLevel] {
        match self {
            Self::All => &[CuckooLevel::Index, CuckooLevel::Chunk],
            Self::Index => &[CuckooLevel::Index],
            Self::Chunk => &[CuckooLevel::Chunk],
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DirectLevelArg {
    All,
    Index,
    Chunk,
}

impl DirectLevelArg {
    const fn levels(self) -> &'static [DirectLevel] {
        match self {
            Self::All => &[DirectLevel::Index, DirectLevel::Chunk],
            Self::Index => &[DirectLevel::Index],
            Self::Chunk => &[DirectLevel::Chunk],
        }
    }
}

impl From<StressPatternArg> for CircuitStressPattern {
    fn from(value: StressPatternArg) -> Self {
        match value {
            StressPatternArg::Random => Self::Random,
            StressPatternArg::RoundRobin => Self::RoundRobin,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Build {
            image,
            state,
            state_key_hex,
            blocks,
            block_size,
            leaves,
            bucket_size,
            stash_capacity,
            encrypted,
            key_hex,
            cache_levels,
            seed_hex,
        } => {
            if block_size < 8 {
                return Err(Error::InvalidInput(
                    "block-size must be at least 8 for deterministic CLI payloads".into(),
                ));
            }
            let params = match leaves {
                Some(leaves) => OramParams::with_leaves(blocks, block_size, leaves)?,
                None => OramParams::new(blocks, block_size)?,
            }
            .with_bucket_size(bucket_size)?
            .with_stash_capacity(stash_capacity)?;
            let seed = parse_seed(seed_hex.as_deref(), 0x07)?;
            let cached_pages = cached_pages_for_levels(&params, cache_levels)?;
            let store = open_file_store(
                &image,
                &params,
                encrypted,
                key_hex.as_deref(),
                cached_pages,
                false,
            )?;
            let payloads = deterministic_payloads(blocks, block_size);

            let started = Instant::now();
            let mut oram = PathOram::build_trusted(params.clone(), store, payloads, seed)?;
            oram.flush()?;
            save_state(&oram.snapshot(), &state, state_key_hex.as_deref())?;
            let elapsed = started.elapsed();

            println!("built=true");
            println!("image={}", image.display());
            println!("state={}", state.display());
            println!("logical_blocks={}", params.logical_blocks);
            println!("block_size={}", params.block_size);
            println!("bucket_size={}", params.bucket_size);
            println!("leaves={}", params.leaves);
            println!("tree_height={}", params.height());
            println!("bucket_pages={}", params.bucket_count());
            println!("plaintext_page_bytes={}", params.bucket_bytes());
            println!("cached_pages={cached_pages}");
            println!("stash_len={}", oram.stash_len());
            println!("state_encrypted={}", state_key_hex.is_some());
            println!("elapsed_ms={}", elapsed.as_millis());
        }
        Command::Bench {
            image,
            state,
            state_key_hex,
            ops,
            encrypted,
            key_hex,
            cache_levels,
            query_seed_hex,
            no_save,
        } => {
            let loaded = load_state(&state, state_key_hex.as_deref())?;
            let params = loaded.params.clone();
            if params.block_size < 8 {
                return Err(Error::InvalidInput(
                    "state block_size must be at least 8 for benchmark checksum".into(),
                ));
            }
            let cached_pages = cached_pages_for_levels(&params, cache_levels)?;
            let store = open_file_store(
                &image,
                &params,
                encrypted,
                key_hex.as_deref(),
                cached_pages,
                true,
            )?;
            let mut oram = PathOram::from_state(store, loaded)?;
            let query_seed = parse_seed(query_seed_hex.as_deref(), 0x03)?;
            let mut query_rng = ChaCha20Rng::from_seed(query_seed);

            let started = Instant::now();
            let mut checksum = 0u64;
            for _ in 0..ops {
                let logical_id = query_rng.next_u64() % params.logical_blocks as u64;
                let payload = oram.read(logical_id)?;
                checksum ^= u64::from_le_bytes(payload[..8].try_into().expect("payload >= 8"));
            }
            let elapsed = started.elapsed();
            oram.flush()?;
            if !no_save {
                save_state(&oram.snapshot(), &state, state_key_hex.as_deref())?;
            }

            println!("bench=true");
            println!("ops={ops}");
            println!("logical_blocks={}", params.logical_blocks);
            println!("tree_height={}", params.height());
            println!("cached_pages={cached_pages}");
            println!("stash_len={}", oram.stash_len());
            println!("state_encrypted={}", state_key_hex.is_some());
            println!("elapsed_ms={}", elapsed.as_millis());
            println!(
                "avg_us={:.3}",
                elapsed.as_secs_f64() * 1_000_000.0 / ops.max(1) as f64
            );
            println!("checksum={checksum}");
        }
        Command::SizeCuckoo {
            db_dirs,
            packs,
            leaf_divisors,
            bucket_size,
            stash_capacity,
            cache_levels,
        } => {
            print_cuckoo_sizes(
                &db_dirs,
                &packs,
                &leaf_divisors,
                bucket_size,
                stash_capacity,
                cache_levels,
            )?;
        }
        Command::SizeDirect {
            index_file,
            chunks_file,
            packs,
            leaf_divisors,
            bucket_size,
            stash_capacity,
            cache_levels,
            index_slots_per_bin,
            index_hash_fns,
            index_load_factor,
            index_seed,
        } => {
            print_direct_sizes(
                &index_file,
                &chunks_file,
                &packs,
                &leaf_divisors,
                bucket_size,
                stash_capacity,
                cache_levels,
                index_slots_per_bin,
                index_hash_fns,
                index_load_factor,
                index_seed,
            )?;
        }
        Command::ExtractDirectChunks {
            chunk_cuckoo_file,
            out_file,
        } => {
            extract_direct_chunks(&chunk_cuckoo_file, &out_file)?;
        }
        Command::BuildCircuit {
            db_dir,
            out_dir,
            level,
            pack,
            leaf_divisor,
            bucket_size,
            stash_capacity,
            encrypted,
            key_hex,
            state_key_hex,
            cache_levels,
            auth_store,
            auth_trusted_levels,
            auth_hash_page_size,
            seed_hex,
        } => {
            build_circuit_images(
                &db_dir,
                &out_dir,
                level,
                pack,
                leaf_divisor,
                bucket_size,
                stash_capacity,
                encrypted,
                key_hex.as_deref(),
                state_key_hex.as_deref(),
                cache_levels,
                auth_store,
                auth_trusted_levels,
                auth_hash_page_size,
                parse_seed(seed_hex.as_deref(), 0x06)?,
            )?;
        }
        Command::BuildDirect {
            index_file,
            chunks_file,
            out_dir,
            level,
            pack,
            leaf_divisor,
            bucket_size,
            stash_capacity,
            encrypted,
            key_hex,
            state_key_hex,
            cache_levels,
            auth_store,
            auth_trusted_levels,
            auth_hash_page_size,
            index_slots_per_bin,
            index_hash_fns,
            index_load_factor,
            index_seed,
            seed_hex,
        } => {
            build_direct_images(
                &index_file,
                &chunks_file,
                &out_dir,
                level,
                pack,
                leaf_divisor,
                bucket_size,
                stash_capacity,
                encrypted,
                key_hex.as_deref(),
                state_key_hex.as_deref(),
                cache_levels,
                auth_store,
                auth_trusted_levels,
                auth_hash_page_size,
                index_slots_per_bin,
                index_hash_fns,
                index_load_factor,
                index_seed,
                parse_seed(seed_hex.as_deref(), 0x0a)?,
            )?;
        }
        Command::BenchCircuit {
            oram_dir,
            db_dir,
            level,
            pack,
            ops,
            drain_per_access,
            encrypted,
            key_hex,
            state_key_hex,
            cache_levels,
            auth_store,
            query_seed_hex,
            no_save,
        } => {
            bench_circuit_images(
                &oram_dir,
                db_dir.as_deref(),
                level,
                pack,
                ops,
                drain_per_access,
                encrypted,
                key_hex.as_deref(),
                state_key_hex.as_deref(),
                cache_levels,
                auth_store,
                parse_seed(query_seed_hex.as_deref(), 0x04)?,
                no_save,
            )?;
        }
        Command::VerifyCircuitBins {
            oram_dir,
            db_dir,
            level,
            pack,
            bins,
            drain_per_access,
            encrypted,
            key_hex,
            state_key_hex,
            cache_levels,
            auth_store,
            query_seed_hex,
            no_save,
        } => {
            verify_circuit_bins(
                &oram_dir,
                &db_dir,
                level,
                pack,
                bins,
                drain_per_access,
                encrypted,
                key_hex.as_deref(),
                state_key_hex.as_deref(),
                cache_levels,
                auth_store,
                parse_seed(query_seed_hex.as_deref(), 0x08)?,
                no_save,
            )?;
        }
        Command::StressCircuit {
            db_dirs,
            packs,
            leaf_divisors,
            bucket_size,
            stash_capacity,
            ops,
            warmup_ops,
            pattern,
            drain_per_access,
            burst_interval,
            burst_budget,
            max_debt,
            seed_hex,
        } => {
            print_circuit_stress(
                &db_dirs,
                &packs,
                &leaf_divisors,
                bucket_size,
                stash_capacity,
                ops,
                warmup_ops,
                pattern.into(),
                drain_per_access,
                burst_interval,
                burst_budget,
                max_debt,
                parse_seed(seed_hex.as_deref(), 0x05)?,
            )?;
        }
        Command::BenchPosMap {
            sizes,
            ops,
            warmup_ops,
            query_seed_hex,
        } => {
            bench_pos_maps(
                &sizes,
                ops,
                warmup_ops,
                parse_seed(query_seed_hex.as_deref(), 0x09)?,
            )?;
        }
    }
    Ok(())
}

fn bench_pos_maps(
    sizes: &[usize],
    ops: usize,
    warmup_ops: usize,
    query_seed: [u8; 32],
) -> Result<()> {
    if sizes.is_empty() {
        return Err(Error::InvalidInput(
            "at least one --sizes value is required".into(),
        ));
    }
    if ops == 0 {
        return Err(Error::InvalidInput("--ops must be > 0".into()));
    }

    println!("bench_pos_map=true");
    println!("ops={ops}");
    println!("warmup_ops={warmup_ops}");

    for &size in sizes {
        if size == 0 {
            return Err(Error::InvalidInput("--sizes entries must be > 0".into()));
        }
        let mut pos_map = make_pos_map(size);
        let queries = make_queries(size, ops + warmup_ops, query_seed);

        let mut checksum = 0u64;
        for &logical_id in &queries[..warmup_ops] {
            checksum ^= direct_pos_map_lookup(&pos_map, logical_id) as u64;
            checksum ^= linear_scan_pos_map_lookup(&pos_map, logical_id) as u64;
            checksum ^=
                linear_scan_pos_map_access(&mut pos_map, logical_id, logical_id as u32) as u64;
        }

        let measured = &queries[warmup_ops..];

        let started = Instant::now();
        for &logical_id in measured {
            checksum ^= direct_pos_map_lookup(&pos_map, logical_id) as u64;
        }
        let direct_elapsed = started.elapsed();

        let started = Instant::now();
        for &logical_id in measured {
            checksum ^= linear_scan_pos_map_lookup(&pos_map, logical_id) as u64;
        }
        let scan_elapsed = started.elapsed();

        let started = Instant::now();
        for (op_idx, &logical_id) in measured.iter().enumerate() {
            let new_leaf = ((op_idx as u32).wrapping_mul(0x9e37_79b9)) ^ logical_id as u32;
            checksum ^= linear_scan_pos_map_access(&mut pos_map, logical_id, new_leaf) as u64;
        }
        let access_elapsed = started.elapsed();

        let map_bytes = size as u64 * std::mem::size_of::<u32>() as u64;
        print_pos_map_bench("direct", size, map_bytes, ops, direct_elapsed, checksum);
        print_pos_map_bench("scan", size, map_bytes, ops, scan_elapsed, checksum);
        print_pos_map_bench(
            "scan_update",
            size,
            map_bytes,
            ops,
            access_elapsed,
            checksum,
        );
    }

    Ok(())
}

fn make_pos_map(size: usize) -> Vec<u32> {
    (0..size)
        .map(|idx| {
            (idx as u32)
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223)
        })
        .collect()
}

fn make_queries(size: usize, count: usize, seed: [u8; 32]) -> Vec<usize> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    (0..count)
        .map(|_| (rng.next_u64() as usize) % size)
        .collect()
}

#[inline(never)]
fn direct_pos_map_lookup(pos_map: &[u32], logical_id: usize) -> u32 {
    black_box(pos_map[black_box(logical_id)])
}

#[inline(never)]
fn linear_scan_pos_map_lookup(pos_map: &[u32], logical_id: usize) -> u32 {
    let logical_id = black_box(logical_id);
    let mut out = 0u32;
    for (idx, &leaf) in pos_map.iter().enumerate() {
        let choice = bitcoinpir_oram::ct::eq_usize(idx, logical_id);
        bitcoinpir_oram::ct::cmov_u32(&mut out, leaf, choice);
    }
    black_box(out)
}

#[inline(never)]
fn linear_scan_pos_map_access(pos_map: &mut [u32], logical_id: usize, new_leaf: u32) -> u32 {
    let logical_id = black_box(logical_id);
    let new_leaf = black_box(new_leaf);
    let mut old_leaf = 0u32;
    for (idx, leaf) in pos_map.iter_mut().enumerate() {
        let choice = bitcoinpir_oram::ct::eq_usize(idx, logical_id);
        bitcoinpir_oram::ct::cmov_u32(&mut old_leaf, *leaf, choice);
        bitcoinpir_oram::ct::cmov_u32(leaf, new_leaf, choice);
    }
    black_box(old_leaf)
}

fn print_pos_map_bench(
    mode: &str,
    size: usize,
    map_bytes: u64,
    ops: usize,
    elapsed: std::time::Duration,
    checksum: u64,
) {
    let elapsed_secs = elapsed.as_secs_f64();
    let avg_us = elapsed_secs * 1_000_000.0 / ops as f64;
    let scanned_bytes = match mode {
        "direct" => ops as u64 * std::mem::size_of::<u32>() as u64,
        "scan" => ops as u64 * map_bytes,
        "scan_update" => ops as u64 * map_bytes * 2,
        _ => 0,
    };
    let bandwidth_gib_s = if elapsed_secs > 0.0 {
        scanned_bytes as f64 / elapsed_secs / 1024.0 / 1024.0 / 1024.0
    } else {
        0.0
    };
    println!(
        "pos_map mode={} size={} map_bytes={} map_mib={:.3} ops={} elapsed_ms={} avg_us={:.3} effective_gib_s={:.3} checksum={}",
        mode,
        size,
        map_bytes,
        mib(map_bytes),
        ops,
        elapsed.as_millis(),
        avg_us,
        bandwidth_gib_s,
        checksum,
    );
}

fn print_cuckoo_sizes(
    db_dirs: &[PathBuf],
    packs: &[usize],
    leaf_divisors: &[usize],
    bucket_size: usize,
    stash_capacity: usize,
    cache_levels: usize,
) -> Result<()> {
    if packs.is_empty() {
        return Err(Error::InvalidInput(
            "at least one --packs value is required".into(),
        ));
    }
    if leaf_divisors.is_empty() {
        return Err(Error::InvalidInput(
            "at least one --leaf-divisors value is required".into(),
        ));
    }

    println!("size_cuckoo=true");
    println!("bucket_size={bucket_size}");
    println!("stash_capacity={stash_capacity}");
    println!("cache_levels={cache_levels}");

    for db_dir in db_dirs {
        let tables = CuckooTableInfo::load_pair(db_dir)?;
        let original_cuckoo_bytes: u64 = tables.iter().map(|t| t.file_bytes).sum();
        println!(
            "db db_dir={} original_cuckoo_bytes={} original_cuckoo_gib={:.3}",
            db_dir.display(),
            original_cuckoo_bytes,
            gib(original_cuckoo_bytes)
        );
        for table in &tables {
            println!(
                "table db_dir={} level={} file_bytes={} file_gib={:.3} anchor={} data_offset={} k={} bins_per_table={} slots_per_bin={} slot_size={} bin_size={} total_bins={} table_byte_size={} master_seed=0x{:016x} tag_seed={}",
                db_dir.display(),
                table.level,
                table.file_bytes,
                gib(table.file_bytes),
                table.anchor_kind,
                table.data_offset,
                table.k,
                table.bins_per_table,
                table.slots_per_bin,
                table.slot_size,
                table.bin_size(),
                table.total_bins(),
                table.table_byte_size(),
                table.master_seed,
                table
                    .tag_seed
                    .map(|seed| format!("0x{seed:016x}"))
                    .unwrap_or_else(|| "none".to_string())
            );
        }

        for &pack in packs {
            for &leaf_divisor in leaf_divisors {
                let sizing = CuckooOramSizing {
                    bins_per_block: pack,
                    leaf_divisor,
                    bucket_size,
                    stash_capacity,
                    cache_levels,
                };
                let mut total_image_plaintext = 0u64;
                let mut total_image_aead = 0u64;
                let mut total_pos_map = 0u64;
                let mut total_trusted_state_floor = 0u64;
                let mut total_front_cache_plaintext = 0u64;
                let mut total_front_cache_aead = 0u64;

                for table in &tables {
                    let estimate = sizing.estimate(table)?;
                    print_estimate(db_dir, &estimate);
                    total_image_plaintext += estimate.image_plaintext_bytes;
                    total_image_aead += estimate.image_aead_bytes;
                    total_pos_map += estimate.pos_map_bytes;
                    total_trusted_state_floor += estimate.trusted_state_floor_bytes;
                    total_front_cache_plaintext += estimate.front_cache_plaintext_bytes;
                    total_front_cache_aead += estimate.front_cache_aead_bytes;
                }

                println!(
                    "total db_dir={} pack={} leaf_divisor={} image_plaintext_bytes={} image_plaintext_gib={:.3} image_aead_bytes={} image_aead_gib={:.3} original_cuckoo_bytes={} original_cuckoo_gib={:.3} expansion_aead_vs_cuckoo={:.3} pos_map_bytes={} pos_map_mib={:.3} trusted_state_floor_bytes={} trusted_state_floor_mib={:.3} front_cache_plaintext_bytes={} front_cache_plaintext_mib={:.3} front_cache_aead_bytes={} front_cache_aead_mib={:.3}",
                    db_dir.display(),
                    pack,
                    leaf_divisor,
                    total_image_plaintext,
                    gib(total_image_plaintext),
                    total_image_aead,
                    gib(total_image_aead),
                    original_cuckoo_bytes,
                    gib(original_cuckoo_bytes),
                    total_image_aead as f64 / original_cuckoo_bytes.max(1) as f64,
                    total_pos_map,
                    mib(total_pos_map),
                    total_trusted_state_floor,
                    mib(total_trusted_state_floor),
                    total_front_cache_plaintext,
                    mib(total_front_cache_plaintext),
                    total_front_cache_aead,
                    mib(total_front_cache_aead),
                );
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn direct_infos(
    index_file: &Path,
    chunks_file: &Path,
    index_slots_per_bin: usize,
    index_hash_fns: usize,
    index_load_factor: f64,
    index_seed: u64,
) -> Result<[DirectTableInfo; 2]> {
    Ok([
        DirectTableInfo::from_index_file(
            index_file,
            index_slots_per_bin,
            index_hash_fns,
            index_load_factor,
            index_seed,
        )?,
        DirectTableInfo::from_chunks_file(chunks_file)?,
    ])
}

fn extract_direct_chunks(chunk_cuckoo_file: &Path, out_file: &Path) -> Result<()> {
    const CHUNK_ID_BYTES: usize = 4;
    const CHUNK_DATA_BYTES: usize = 40;
    const CHUNK_SLOT_BYTES: usize = CHUNK_ID_BYTES + CHUNK_DATA_BYTES;

    let info = CuckooTableInfo::from_file(CuckooLevel::Chunk, chunk_cuckoo_file)?;
    if info.slot_size != CHUNK_SLOT_BYTES {
        return Err(Error::InvalidInput(format!(
            "chunk cuckoo slot size {} != expected {}",
            info.slot_size, CHUNK_SLOT_BYTES
        )));
    }

    let input = File::open(chunk_cuckoo_file)?;
    let mmap = unsafe { memmap2::MmapOptions::new().map(&input)? };
    let table = &mmap[info.data_offset..];
    if table.len() % CHUNK_SLOT_BYTES != 0 {
        return Err(Error::InvalidInput(format!(
            "chunk cuckoo payload size {} is not a multiple of {}",
            table.len(),
            CHUNK_SLOT_BYTES
        )));
    }

    let started = Instant::now();
    let mut non_empty_slots = 0usize;
    let mut max_chunk_id = None::<u32>;
    for slot in table.chunks_exact(CHUNK_SLOT_BYTES) {
        if is_zero_slot(slot) {
            continue;
        }
        non_empty_slots += 1;
        let chunk_id = u32::from_le_bytes(slot[..CHUNK_ID_BYTES].try_into().expect("chunk id"));
        max_chunk_id = Some(max_chunk_id.map_or(chunk_id, |m| m.max(chunk_id)));
    }

    let Some(max_chunk_id) = max_chunk_id else {
        return Err(Error::InvalidInput(format!(
            "no non-empty CHUNK slots found in {}",
            chunk_cuckoo_file.display()
        )));
    };
    let chunk_count = max_chunk_id as usize + 1;
    let out_bytes = chunk_count
        .checked_mul(CHUNK_DATA_BYTES)
        .ok_or_else(|| Error::InvalidInput("direct chunk output size overflow".into()))?;

    if let Some(parent) = out_file.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let out = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_file)?;
    out.set_len(out_bytes as u64)?;
    let mut out_map = unsafe { memmap2::MmapOptions::new().len(out_bytes).map_mut(&out)? };
    let mut seen = vec![0u8; chunk_count.div_ceil(8)];
    let mut unique_chunks = 0usize;
    let mut duplicate_slots = 0usize;
    let mut conflicting_duplicates = 0usize;

    for slot in table.chunks_exact(CHUNK_SLOT_BYTES) {
        if is_zero_slot(slot) {
            continue;
        }
        let chunk_id =
            u32::from_le_bytes(slot[..CHUNK_ID_BYTES].try_into().expect("chunk id")) as usize;
        let chunk = &slot[CHUNK_ID_BYTES..CHUNK_SLOT_BYTES];
        let out_start = chunk_id
            .checked_mul(CHUNK_DATA_BYTES)
            .ok_or_else(|| Error::InvalidInput("direct chunk offset overflow".into()))?;
        let out_end = out_start + CHUNK_DATA_BYTES;
        if bit_is_set(&seen, chunk_id) {
            duplicate_slots += 1;
            if &out_map[out_start..out_end] != chunk {
                conflicting_duplicates += 1;
                if conflicting_duplicates <= 5 {
                    eprintln!("conflicting duplicate for chunk_id={chunk_id}");
                }
            }
            continue;
        }
        set_bit(&mut seen, chunk_id);
        unique_chunks += 1;
        out_map[out_start..out_end].copy_from_slice(chunk);
    }

    if conflicting_duplicates > 0 {
        return Err(Error::InvalidInput(format!(
            "found {} conflicting duplicate chunk slots in {}",
            conflicting_duplicates,
            chunk_cuckoo_file.display()
        )));
    }

    if unique_chunks != chunk_count {
        let mut missing = Vec::new();
        for chunk_id in 0..chunk_count {
            if !bit_is_set(&seen, chunk_id) {
                missing.push(chunk_id);
                if missing.len() == 8 {
                    break;
                }
            }
        }
        return Err(Error::InvalidInput(format!(
            "chunk ids are not contiguous: recovered {} unique chunks but max_chunk_id={} implies {}; first missing ids={:?}",
            unique_chunks, max_chunk_id, chunk_count, missing
        )));
    }

    out_map.flush()?;
    drop(out_map);
    out.sync_all()?;

    println!("extract_direct_chunks=true");
    println!("chunk_cuckoo_file={}", chunk_cuckoo_file.display());
    println!("out_file={}", out_file.display());
    println!("anchor={}", info.anchor_kind);
    println!("data_offset={}", info.data_offset);
    println!("k={}", info.k);
    println!("bins_per_table={}", info.bins_per_table);
    println!("slots_per_bin={}", info.slots_per_bin);
    println!("non_empty_slots={non_empty_slots}");
    println!("duplicate_slots={duplicate_slots}");
    println!("unique_chunks={unique_chunks}");
    println!("output_bytes={out_bytes}");
    println!("output_gib={:.3}", gib(out_bytes as u64));
    println!("elapsed_ms={}", started.elapsed().as_millis());
    Ok(())
}

fn is_zero_slot(slot: &[u8]) -> bool {
    slot.iter().all(|&b| b == 0)
}

fn bit_is_set(bits: &[u8], idx: usize) -> bool {
    bits[idx / 8] & (1u8 << (idx % 8)) != 0
}

fn set_bit(bits: &mut [u8], idx: usize) {
    bits[idx / 8] |= 1u8 << (idx % 8);
}

#[allow(clippy::too_many_arguments)]
fn print_direct_sizes(
    index_file: &Path,
    chunks_file: &Path,
    packs: &[usize],
    leaf_divisors: &[usize],
    bucket_size: usize,
    stash_capacity: usize,
    cache_levels: usize,
    index_slots_per_bin: usize,
    index_hash_fns: usize,
    index_load_factor: f64,
    index_seed: u64,
) -> Result<()> {
    if packs.is_empty() {
        return Err(Error::InvalidInput(
            "at least one --packs value is required".into(),
        ));
    }
    if leaf_divisors.is_empty() {
        return Err(Error::InvalidInput(
            "at least one --leaf-divisors value is required".into(),
        ));
    }
    let infos = direct_infos(
        index_file,
        chunks_file,
        index_slots_per_bin,
        index_hash_fns,
        index_load_factor,
        index_seed,
    )?;
    let original_direct_bytes: u64 = infos.iter().map(|info| info.file_bytes).sum();

    println!("size_direct=true");
    println!("index_file={}", index_file.display());
    println!("chunks_file={}", chunks_file.display());
    println!("bucket_size={bucket_size}");
    println!("stash_capacity={stash_capacity}");
    println!("cache_levels={cache_levels}");
    println!("index_slots_per_bin={index_slots_per_bin}");
    println!("index_hash_fns={index_hash_fns}");
    println!("index_load_factor={index_load_factor:.6}");
    println!("index_seed=0x{index_seed:016x}");
    println!(
        "direct_source_bytes={} direct_source_gib={:.3}",
        original_direct_bytes,
        gib(original_direct_bytes)
    );
    for info in &infos {
        println!(
            "direct_table level={} source={} file_bytes={} file_gib={:.3} source_records={} total_items={} item_size={} slots_per_bin={} hash_fns={} load_factor={:.6} seed=0x{:016x}",
            info.level,
            info.path.display(),
            info.file_bytes,
            gib(info.file_bytes),
            info.records,
            info.total_items,
            info.item_size,
            info.slots_per_bin,
            info.hash_fns,
            info.load_factor,
            info.seed,
        );
    }

    for &pack in packs {
        for &leaf_divisor in leaf_divisors {
            let sizing = DirectOramSizing {
                items_per_block: pack,
                leaf_divisor,
                bucket_size,
                stash_capacity,
                cache_levels,
            };
            let mut total_image_plaintext = 0u64;
            let mut total_image_aead = 0u64;
            let mut total_pos_map = 0u64;
            let mut total_trusted_state_floor = 0u64;
            let mut total_front_cache_plaintext = 0u64;
            let mut total_front_cache_aead = 0u64;

            for info in &infos {
                let estimate = sizing.estimate(info)?;
                print_direct_estimate(info, &estimate);
                total_image_plaintext += estimate.image_plaintext_bytes;
                total_image_aead += estimate.image_aead_bytes;
                total_pos_map += estimate.pos_map_bytes;
                total_trusted_state_floor += estimate.trusted_state_floor_bytes;
                total_front_cache_plaintext += estimate.front_cache_plaintext_bytes;
                total_front_cache_aead += estimate.front_cache_aead_bytes;
            }

            println!(
                "direct_total pack={} leaf_divisor={} image_plaintext_bytes={} image_plaintext_gib={:.3} image_aead_bytes={} image_aead_gib={:.3} direct_source_bytes={} direct_source_gib={:.3} expansion_aead_vs_direct_source={:.3} pos_map_bytes={} pos_map_mib={:.3} trusted_state_floor_bytes={} trusted_state_floor_mib={:.3} front_cache_plaintext_bytes={} front_cache_plaintext_mib={:.3} front_cache_aead_bytes={} front_cache_aead_mib={:.3}",
                pack,
                leaf_divisor,
                total_image_plaintext,
                gib(total_image_plaintext),
                total_image_aead,
                gib(total_image_aead),
                original_direct_bytes,
                gib(original_direct_bytes),
                total_image_aead as f64 / original_direct_bytes.max(1) as f64,
                total_pos_map,
                mib(total_pos_map),
                total_trusted_state_floor,
                mib(total_trusted_state_floor),
                total_front_cache_plaintext,
                mib(total_front_cache_plaintext),
                total_front_cache_aead,
                mib(total_front_cache_aead),
            );
        }
    }

    Ok(())
}

fn print_direct_estimate(info: &DirectTableInfo, e: &DirectOramEstimate) {
    println!(
        "direct_estimate level={} source={} pack={} leaf_divisor={} source_records={} total_items={} item_size={} logical_blocks={} block_payload_bytes={} bucket_size={} leaves={} height={} bucket_pages={} page_plaintext_bytes={} page_aead_bytes={} image_plaintext_bytes={} image_plaintext_gib={:.3} image_aead_bytes={} image_aead_gib={:.3} pos_map_bytes={} pos_map_mib={:.3} trusted_stash_bytes={} trusted_stash_mib={:.3} trusted_state_floor_bytes={} trusted_state_floor_mib={:.3} cached_pages={} front_cache_plaintext_bytes={} front_cache_plaintext_mib={:.3} front_cache_aead_bytes={} front_cache_aead_mib={:.3} disk_pages_per_access_no_flush={} disk_aead_bytes_per_access_no_flush={} disk_aead_mib_per_access_no_flush={:.3} tree_slot_load_percent={:.3}",
        e.level,
        info.path.display(),
        e.items_per_block,
        e.leaf_divisor,
        e.source_records,
        e.total_items,
        e.item_size,
        e.logical_blocks,
        e.block_payload_bytes,
        e.bucket_size,
        e.leaves,
        e.height,
        e.bucket_pages,
        e.page_plaintext_bytes,
        e.page_aead_bytes,
        e.image_plaintext_bytes,
        gib(e.image_plaintext_bytes),
        e.image_aead_bytes,
        gib(e.image_aead_bytes),
        e.pos_map_bytes,
        mib(e.pos_map_bytes),
        e.trusted_stash_bytes,
        mib(e.trusted_stash_bytes),
        e.trusted_state_floor_bytes,
        mib(e.trusted_state_floor_bytes),
        e.cached_pages,
        e.front_cache_plaintext_bytes,
        mib(e.front_cache_plaintext_bytes),
        e.front_cache_aead_bytes,
        mib(e.front_cache_aead_bytes),
        e.disk_pages_per_access_no_flush,
        e.disk_aead_bytes_per_access_no_flush,
        mib(e.disk_aead_bytes_per_access_no_flush),
        e.tree_slot_load_percent,
    );
}

#[allow(clippy::too_many_arguments)]
fn build_direct_images(
    index_file: &Path,
    chunks_file: &Path,
    out_dir: &Path,
    level: DirectLevelArg,
    pack: usize,
    leaf_divisor: usize,
    bucket_size: usize,
    stash_capacity: usize,
    encrypted: bool,
    key_hex: Option<&str>,
    state_key_hex: Option<&str>,
    cache_levels: usize,
    auth_store: bool,
    auth_trusted_levels: usize,
    auth_hash_page_size: usize,
    index_slots_per_bin: usize,
    index_hash_fns: usize,
    index_load_factor: f64,
    index_seed: u64,
    seed: [u8; 32],
) -> Result<()> {
    if pack == 0 {
        return Err(Error::InvalidInput("--pack must be > 0".into()));
    }
    if leaf_divisor == 0 {
        return Err(Error::InvalidInput("--leaf-divisor must be > 0".into()));
    }
    if encrypted {
        parse_required_key(key_hex)?;
    }
    fs::create_dir_all(out_dir)?;

    let infos = direct_infos(
        index_file,
        chunks_file,
        index_slots_per_bin,
        index_hash_fns,
        index_load_factor,
        index_seed,
    )?;
    println!("build_direct=true");
    println!("index_file={}", index_file.display());
    println!("chunks_file={}", chunks_file.display());
    println!("out_dir={}", out_dir.display());
    println!("level={level:?}");
    println!("pack={pack}");
    println!("leaf_divisor={leaf_divisor}");
    println!("bucket_size={bucket_size}");
    println!("stash_capacity={stash_capacity}");
    println!("encrypted={encrypted}");
    println!("state_encrypted={}", state_key_hex.is_some());
    println!("cache_levels={cache_levels}");
    println!("auth_store={auth_store}");
    println!("auth_trusted_levels={auth_trusted_levels}");
    println!("auth_hash_page_size={auth_hash_page_size}");
    println!("index_slots_per_bin={index_slots_per_bin}");
    println!("index_hash_fns={index_hash_fns}");
    println!("index_load_factor={index_load_factor:.6}");
    println!("index_seed=0x{index_seed:016x}");
    println!("seed_hex={}", hex::encode(seed));

    for &selected_level in level.levels() {
        let info = infos
            .iter()
            .find(|info| info.level == selected_level)
            .expect("direct_infos returns both levels");
        build_direct_table(
            out_dir,
            info,
            pack,
            leaf_divisor,
            bucket_size,
            stash_capacity,
            encrypted,
            key_hex,
            state_key_hex,
            cache_levels,
            auth_store,
            auth_trusted_levels,
            auth_hash_page_size,
            derive_direct_level_seed(seed, info.level),
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_direct_table(
    out_dir: &Path,
    info: &DirectTableInfo,
    pack: usize,
    leaf_divisor: usize,
    bucket_size: usize,
    stash_capacity: usize,
    encrypted: bool,
    key_hex: Option<&str>,
    state_key_hex: Option<&str>,
    cache_levels: usize,
    auth_store: bool,
    auth_trusted_levels: usize,
    auth_hash_page_size: usize,
    seed: [u8; 32],
) -> Result<()> {
    let sizing = DirectOramSizing {
        items_per_block: pack,
        leaf_divisor,
        bucket_size,
        stash_capacity,
        cache_levels,
    };
    let estimate = sizing.estimate(info)?;
    let params = OramParams::with_leaves(
        estimate.logical_blocks,
        estimate.block_payload_bytes,
        estimate.leaves,
    )?
    .with_bucket_size(bucket_size)?
    .with_stash_capacity(stash_capacity)?;
    let paths = direct_output_paths(out_dir, info.level);

    match info.level {
        DirectLevel::Index => {
            let source = DirectIndexPackedBlockReader::build(info.clone(), pack)?;
            let metadata = source.metadata().clone();
            build_direct_table_from_source(
                &paths,
                info,
                &estimate,
                &params,
                source,
                metadata,
                encrypted,
                key_hex,
                state_key_hex,
                cache_levels,
                auth_store,
                auth_trusted_levels,
                auth_hash_page_size,
                seed,
            )
        }
        DirectLevel::Chunk => {
            let source = DirectChunkPackedBlockReader::open(info.clone(), pack)?;
            let metadata = source.metadata().clone();
            build_direct_table_from_source(
                &paths,
                info,
                &estimate,
                &params,
                source,
                metadata,
                encrypted,
                key_hex,
                state_key_hex,
                cache_levels,
                auth_store,
                auth_trusted_levels,
                auth_hash_page_size,
                seed,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_direct_table_from_source<S: TrustedBlockSource>(
    paths: &CircuitOutputPaths,
    info: &DirectTableInfo,
    estimate: &DirectOramEstimate,
    params: &OramParams,
    source: S,
    metadata: bitcoinpir_oram::DirectTableMetadata,
    encrypted: bool,
    key_hex: Option<&str>,
    state_key_hex: Option<&str>,
    cache_levels: usize,
    auth_store: bool,
    auth_trusted_levels: usize,
    auth_hash_page_size: usize,
    seed: [u8; 32],
) -> Result<()> {
    if source.logical_blocks() != params.logical_blocks || source.block_size() != params.block_size
    {
        return Err(Error::InvalidInput(
            "direct source dimensions do not match ORAM params".into(),
        ));
    }
    let cached_pages = cached_pages_for_levels(params, cache_levels)?;
    let (meta_store, payload_store) = open_circuit_file_stores(
        &paths.meta_image,
        &paths.payload_image,
        params,
        encrypted,
        key_hex,
        cached_pages,
        false,
    )?;

    let started = Instant::now();
    let mut oram = CircuitOram::build_trusted_from_source(
        params.clone(),
        meta_store,
        payload_store,
        source,
        seed,
    )?;
    oram.flush()?;
    save_circuit_state(&oram.snapshot(), &paths.state, state_key_hex)?;
    metadata.save(&paths.metadata)?;
    if auth_store {
        let auth_state = build_direct_store_auth(
            paths,
            info.level,
            params,
            encrypted,
            key_hex,
            cached_pages,
            auth_trusted_levels,
            auth_hash_page_size,
        )?;
        save_circuit_store_auth(&auth_state, &paths.auth_state, state_key_hex)?;
    }
    let elapsed = started.elapsed();

    println!(
        "built_direct level={} source={} meta_image={} payload_image={} state={} direct_metadata={} auth_state={} auth_store={} source_records={} total_items={} item_size={} logical_blocks={} block_payload_bytes={} bucket_size={} leaves={} height={} bucket_pages={} cached_pages={} meta_page_plaintext_bytes={} payload_page_plaintext_bytes={} meta_image_bytes={} payload_image_bytes={} stash_len={} pending_evictions={} elapsed_ms={}",
        info.level,
        info.path.display(),
        paths.meta_image.display(),
        paths.payload_image.display(),
        paths.state.display(),
        paths.metadata.display(),
        paths.auth_state.display(),
        auth_store,
        estimate.source_records,
        estimate.total_items,
        estimate.item_size,
        params.logical_blocks,
        params.block_size,
        params.bucket_size,
        params.leaves,
        params.height(),
        params.bucket_count(),
        cached_pages,
        circuit_meta_page_bytes(params.bucket_size),
        circuit_payload_page_bytes(params.bucket_size, params.block_size),
        params.bucket_count() as u64
            * backing_page_bytes(circuit_meta_page_bytes(params.bucket_size), encrypted) as u64,
        params.bucket_count() as u64
            * backing_page_bytes(
                circuit_payload_page_bytes(params.bucket_size, params.block_size),
                encrypted
            ) as u64,
        oram.stash_len(),
        oram.pending_evictions()?,
        elapsed.as_millis()
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_circuit_images(
    db_dir: &Path,
    out_dir: &Path,
    level: LevelArg,
    pack: usize,
    leaf_divisor: usize,
    bucket_size: usize,
    stash_capacity: usize,
    encrypted: bool,
    key_hex: Option<&str>,
    state_key_hex: Option<&str>,
    cache_levels: usize,
    auth_store: bool,
    auth_trusted_levels: usize,
    auth_hash_page_size: usize,
    seed: [u8; 32],
) -> Result<()> {
    if pack == 0 {
        return Err(Error::InvalidInput("--pack must be > 0".into()));
    }
    if leaf_divisor == 0 {
        return Err(Error::InvalidInput("--leaf-divisor must be > 0".into()));
    }
    if encrypted {
        parse_required_key(key_hex)?;
    }
    fs::create_dir_all(out_dir)?;

    let tables = CuckooTableInfo::load_pair(db_dir)?;
    println!("build_circuit=true");
    println!("db_dir={}", db_dir.display());
    println!("out_dir={}", out_dir.display());
    println!("level={level:?}");
    println!("pack={pack}");
    println!("leaf_divisor={leaf_divisor}");
    println!("bucket_size={bucket_size}");
    println!("stash_capacity={stash_capacity}");
    println!("encrypted={encrypted}");
    println!("state_encrypted={}", state_key_hex.is_some());
    println!("cache_levels={cache_levels}");
    println!("auth_store={auth_store}");
    println!("auth_trusted_levels={auth_trusted_levels}");
    println!("auth_hash_page_size={auth_hash_page_size}");
    println!("seed_hex={}", hex::encode(seed));

    for &selected_level in level.levels() {
        let table = tables
            .iter()
            .find(|table| table.level == selected_level)
            .expect("load_pair returns both levels");
        build_circuit_table(
            out_dir,
            table,
            pack,
            leaf_divisor,
            bucket_size,
            stash_capacity,
            encrypted,
            key_hex,
            state_key_hex,
            cache_levels,
            auth_store,
            auth_trusted_levels,
            auth_hash_page_size,
            derive_level_seed(seed, table.level),
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_circuit_table(
    out_dir: &Path,
    table: &CuckooTableInfo,
    pack: usize,
    leaf_divisor: usize,
    bucket_size: usize,
    stash_capacity: usize,
    encrypted: bool,
    key_hex: Option<&str>,
    state_key_hex: Option<&str>,
    cache_levels: usize,
    auth_store: bool,
    auth_trusted_levels: usize,
    auth_hash_page_size: usize,
    seed: [u8; 32],
) -> Result<()> {
    let sizing = CuckooOramSizing {
        bins_per_block: pack,
        leaf_divisor,
        bucket_size,
        stash_capacity,
        cache_levels,
    };
    let estimate = sizing.estimate(table)?;
    let params = OramParams::with_leaves(
        estimate.logical_blocks,
        estimate.block_payload_bytes,
        estimate.leaves,
    )?
    .with_bucket_size(bucket_size)?
    .with_stash_capacity(stash_capacity)?;
    let cached_pages = cached_pages_for_levels(&params, cache_levels)?;
    let paths = circuit_output_paths(out_dir, table.level);
    let (meta_store, payload_store) = open_circuit_file_stores(
        &paths.meta_image,
        &paths.payload_image,
        &params,
        encrypted,
        key_hex,
        cached_pages,
        false,
    )?;
    let reader = CuckooPackedBlockReader::open(table.clone(), pack)?;
    if reader.logical_blocks() != params.logical_blocks
        || reader.block_payload_bytes() != params.block_size
    {
        return Err(Error::InvalidInput(
            "packed cuckoo reader dimensions do not match ORAM params".into(),
        ));
    }

    let started = Instant::now();
    let mut oram = CircuitOram::build_trusted_from_source(
        params.clone(),
        meta_store,
        payload_store,
        reader,
        seed,
    )?;
    oram.flush()?;
    save_circuit_state(&oram.snapshot(), &paths.state, state_key_hex)?;
    if auth_store {
        let auth_state = build_circuit_store_auth(
            &paths,
            table.level,
            &params,
            encrypted,
            key_hex,
            cached_pages,
            auth_trusted_levels,
            auth_hash_page_size,
        )?;
        save_circuit_store_auth(&auth_state, &paths.auth_state, state_key_hex)?;
    }
    let elapsed = started.elapsed();

    println!(
        "built level={} source={} meta_image={} payload_image={} state={} auth_state={} auth_store={} total_bins={} logical_blocks={} block_payload_bytes={} bucket_size={} leaves={} height={} bucket_pages={} cached_pages={} meta_page_plaintext_bytes={} payload_page_plaintext_bytes={} meta_image_bytes={} payload_image_bytes={} stash_len={} pending_evictions={} elapsed_ms={}",
        table.level,
        table.path.display(),
        paths.meta_image.display(),
        paths.payload_image.display(),
        paths.state.display(),
        paths.auth_state.display(),
        auth_store,
        estimate.total_bins,
        params.logical_blocks,
        params.block_size,
        params.bucket_size,
        params.leaves,
        params.height(),
        params.bucket_count(),
        cached_pages,
        circuit_meta_page_bytes(params.bucket_size),
        circuit_payload_page_bytes(params.bucket_size, params.block_size),
        params.bucket_count() as u64
            * backing_page_bytes(circuit_meta_page_bytes(params.bucket_size), encrypted) as u64,
        params.bucket_count() as u64
            * backing_page_bytes(
                circuit_payload_page_bytes(params.bucket_size, params.block_size),
                encrypted
            ) as u64,
        oram.stash_len(),
        oram.pending_evictions()?,
        elapsed.as_millis()
    );

    Ok(())
}

struct CircuitOutputPaths {
    meta_image: PathBuf,
    payload_image: PathBuf,
    meta_hash_image: PathBuf,
    payload_hash_image: PathBuf,
    state: PathBuf,
    auth_state: PathBuf,
    metadata: PathBuf,
}

fn circuit_output_paths(out_dir: &Path, level: CuckooLevel) -> CircuitOutputPaths {
    let label = level.label();
    CircuitOutputPaths {
        meta_image: out_dir.join(format!("{label}.meta.oram")),
        payload_image: out_dir.join(format!("{label}.payload.oram")),
        meta_hash_image: out_dir.join(format!("{label}.meta.hash.oram")),
        payload_hash_image: out_dir.join(format!("{label}.payload.hash.oram")),
        state: out_dir.join(format!("{label}.state")),
        auth_state: out_dir.join(format!("{label}.auth.state")),
        metadata: out_dir.join(format!("{label}.metadata")),
    }
}

fn direct_output_paths(out_dir: &Path, level: DirectLevel) -> CircuitOutputPaths {
    let label = format!("direct-{}", level.label());
    CircuitOutputPaths {
        meta_image: out_dir.join(format!("{label}.meta.oram")),
        payload_image: out_dir.join(format!("{label}.payload.oram")),
        meta_hash_image: out_dir.join(format!("{label}.meta.hash.oram")),
        payload_hash_image: out_dir.join(format!("{label}.payload.hash.oram")),
        state: out_dir.join(format!("{label}.state")),
        auth_state: out_dir.join(format!("{label}.auth.state")),
        metadata: out_dir.join(format!("{label}.metadata")),
    }
}

fn derive_level_seed(mut seed: [u8; 32], level: CuckooLevel) -> [u8; 32] {
    seed[31] ^= match level {
        CuckooLevel::Index => 0x11,
        CuckooLevel::Chunk => 0x22,
    };
    seed
}

fn derive_direct_level_seed(mut seed: [u8; 32], level: DirectLevel) -> [u8; 32] {
    seed[31] ^= match level {
        DirectLevel::Index => 0x33,
        DirectLevel::Chunk => 0x44,
    };
    seed
}

#[allow(clippy::too_many_arguments)]
fn bench_circuit_images(
    oram_dir: &Path,
    db_dir: Option<&Path>,
    level: LevelArg,
    pack: usize,
    ops: usize,
    drain_per_access: u64,
    encrypted: bool,
    key_hex: Option<&str>,
    state_key_hex: Option<&str>,
    cache_levels: usize,
    auth_store: bool,
    query_seed: [u8; 32],
    no_save: bool,
) -> Result<()> {
    if pack == 0 {
        return Err(Error::InvalidInput("--pack must be > 0".into()));
    }
    if encrypted {
        parse_required_key(key_hex)?;
    }
    let tables = match db_dir {
        Some(db_dir) => Some(CuckooTableInfo::load_pair(db_dir)?),
        None => None,
    };

    println!("bench_circuit=true");
    println!("oram_dir={}", oram_dir.display());
    println!(
        "db_dir={}",
        db_dir
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!("level={level:?}");
    println!("pack={pack}");
    println!("ops={ops}");
    println!("drain_per_access={drain_per_access}");
    println!("encrypted={encrypted}");
    println!("state_encrypted={}", state_key_hex.is_some());
    println!("cache_levels={cache_levels}");
    println!("auth_store={auth_store}");
    println!("query_seed_hex={}", hex::encode(query_seed));
    println!("no_save={no_save}");

    for &selected_level in level.levels() {
        let table = tables
            .as_ref()
            .and_then(|tables| tables.iter().find(|table| table.level == selected_level));
        bench_circuit_table(
            oram_dir,
            selected_level,
            table,
            pack,
            ops,
            drain_per_access,
            encrypted,
            key_hex,
            state_key_hex,
            cache_levels,
            auth_store,
            derive_level_seed(query_seed, selected_level),
            no_save,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn bench_circuit_table(
    oram_dir: &Path,
    level: CuckooLevel,
    table: Option<&CuckooTableInfo>,
    pack: usize,
    ops: usize,
    drain_per_access: u64,
    encrypted: bool,
    key_hex: Option<&str>,
    state_key_hex: Option<&str>,
    cache_levels: usize,
    auth_store: bool,
    query_seed: [u8; 32],
    no_save: bool,
) -> Result<()> {
    let paths = circuit_output_paths(oram_dir, level);
    let loaded = load_circuit_state(&paths.state, state_key_hex)?;
    let params = loaded.params.clone();
    let cached_pages = cached_pages_for_levels(&params, cache_levels)?;
    let (meta_store, payload_store) = open_circuit_file_stores_for_reopen(
        &paths,
        level,
        &params,
        encrypted,
        key_hex,
        cached_pages,
        auth_store,
        state_key_hex,
    )?;
    let mut oram = CircuitOram::from_state(meta_store, payload_store, loaded)?;
    let mut verifier = match table {
        Some(table) => {
            let reader = CuckooPackedBlockReader::open(table.clone(), pack)?;
            if reader.logical_blocks() != params.logical_blocks
                || reader.block_payload_bytes() != params.block_size
            {
                return Err(Error::InvalidInput(format!(
                    "{} verifier dimensions do not match Circuit ORAM state",
                    level
                )));
            }
            Some(reader)
        }
        None => None,
    };
    let mut query_rng = ChaCha20Rng::from_seed(query_seed);
    let pending_before = oram.pending_evictions()?;

    let started = Instant::now();
    let mut checksum = 0u64;
    let mut verified = 0usize;
    let mut drained = 0u64;
    for _ in 0..ops {
        let logical_id = query_rng.next_u64() % params.logical_blocks as u64;
        let payload = oram.read(logical_id)?;
        checksum = checksum_payload(checksum, &payload);
        if let Some(verifier) = verifier.as_mut() {
            let expected = verifier.read_block(logical_id as usize)?;
            if payload != expected {
                return Err(Error::InvalidInput(format!(
                    "{} logical block {} did not match original cuckoo payload",
                    level, logical_id
                )));
            }
            verified += 1;
        }
        drained += oram.drain_evictions(drain_per_access)?;
    }
    let elapsed = started.elapsed();
    oram.flush()?;
    if !no_save {
        save_circuit_state(&oram.snapshot(), &paths.state, state_key_hex)?;
        if auth_store {
            let auth_state = oram.store_auth_state().ok_or_else(|| {
                Error::InvalidInput("authenticated stores did not expose auth state".into())
            })?;
            save_circuit_store_auth(&auth_state, &paths.auth_state, state_key_hex)?;
        }
    }

    println!(
        "bench level={} meta_image={} payload_image={} state={} auth_state={} auth_store={} ops={} verified={} logical_blocks={} block_payload_bytes={} leaves={} height={} cached_pages={} stash_len={} pending_before={} pending_after={} drained_evictions={} elapsed_ms={} avg_us={:.3} checksum={}",
        level,
        paths.meta_image.display(),
        paths.payload_image.display(),
        paths.state.display(),
        paths.auth_state.display(),
        auth_store,
        ops,
        verified,
        params.logical_blocks,
        params.block_size,
        params.leaves,
        params.height(),
        cached_pages,
        oram.stash_len(),
        pending_before,
        oram.pending_evictions()?,
        drained,
        elapsed.as_millis(),
        elapsed.as_secs_f64() * 1_000_000.0 / ops.max(1) as f64,
        checksum,
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_circuit_bins(
    oram_dir: &Path,
    db_dir: &Path,
    level: LevelArg,
    pack: usize,
    bins: usize,
    drain_per_access: u64,
    encrypted: bool,
    key_hex: Option<&str>,
    state_key_hex: Option<&str>,
    cache_levels: usize,
    auth_store: bool,
    query_seed: [u8; 32],
    no_save: bool,
) -> Result<()> {
    if pack == 0 {
        return Err(Error::InvalidInput("--pack must be > 0".into()));
    }
    if encrypted {
        parse_required_key(key_hex)?;
    }
    let tables = CuckooTableInfo::load_pair(db_dir)?;

    println!("verify_circuit_bins=true");
    println!("oram_dir={}", oram_dir.display());
    println!("db_dir={}", db_dir.display());
    println!("level={level:?}");
    println!("pack={pack}");
    println!("bins={bins}");
    println!("drain_per_access={drain_per_access}");
    println!("encrypted={encrypted}");
    println!("state_encrypted={}", state_key_hex.is_some());
    println!("cache_levels={cache_levels}");
    println!("auth_store={auth_store}");
    println!("query_seed_hex={}", hex::encode(query_seed));
    println!("no_save={no_save}");

    for &selected_level in level.levels() {
        let table = tables
            .iter()
            .find(|table| table.level == selected_level)
            .expect("load_pair returns both levels");
        verify_circuit_bin_table(
            oram_dir,
            table,
            pack,
            bins,
            drain_per_access,
            encrypted,
            key_hex,
            state_key_hex,
            cache_levels,
            auth_store,
            derive_level_seed(query_seed, selected_level),
            no_save,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_circuit_bin_table(
    oram_dir: &Path,
    table: &CuckooTableInfo,
    pack: usize,
    bins: usize,
    drain_per_access: u64,
    encrypted: bool,
    key_hex: Option<&str>,
    state_key_hex: Option<&str>,
    cache_levels: usize,
    auth_store: bool,
    query_seed: [u8; 32],
    no_save: bool,
) -> Result<()> {
    let paths = circuit_output_paths(oram_dir, table.level);
    let loaded = load_circuit_state(&paths.state, state_key_hex)?;
    let params = loaded.params.clone();
    let cached_pages = cached_pages_for_levels(&params, cache_levels)?;
    let (meta_store, payload_store) = open_circuit_file_stores_for_reopen(
        &paths,
        table.level,
        &params,
        encrypted,
        key_hex,
        cached_pages,
        auth_store,
        state_key_hex,
    )?;
    let oram = CircuitOram::from_state(meta_store, payload_store, loaded)?;
    let mut oram_reader = CircuitCuckooBinReader::new(table, pack, oram)?;
    let mut source_reader = CuckooPackedBlockReader::open(table.clone(), pack)?;
    let mut query_rng = ChaCha20Rng::from_seed(query_seed);
    let pending_before = oram_reader.oram().pending_evictions()?;

    let started = Instant::now();
    let mut checksum = 0u64;
    let mut verified = 0usize;
    let mut drained = 0u64;
    for _ in 0..bins {
        let bin_id = query_rng.next_u64() as usize % table.total_bins();
        let got = oram_reader.read_bin(bin_id, drain_per_access)?;
        let expected = source_reader.read_bin(bin_id)?;
        if got.payload != expected {
            return Err(Error::InvalidInput(format!(
                "{} bin {} did not match original cuckoo payload",
                table.level, bin_id
            )));
        }
        checksum = checksum_payload(checksum, &got.payload);
        verified += 1;
        drained += got.drained_evictions;
    }
    let elapsed = started.elapsed();
    let mut oram = oram_reader.into_oram();
    oram.flush()?;
    if !no_save {
        save_circuit_state(&oram.snapshot(), &paths.state, state_key_hex)?;
        if auth_store {
            let auth_state = oram.store_auth_state().ok_or_else(|| {
                Error::InvalidInput("authenticated stores did not expose auth state".into())
            })?;
            save_circuit_store_auth(&auth_state, &paths.auth_state, state_key_hex)?;
        }
    }

    println!(
        "verify_bins level={} meta_image={} payload_image={} state={} auth_state={} auth_store={} bins={} verified={} total_bins={} bin_size={} pack={} logical_blocks={} block_payload_bytes={} leaves={} height={} cached_pages={} stash_len={} pending_before={} pending_after={} drained_evictions={} elapsed_ms={} avg_us={:.3} checksum={}",
        table.level,
        paths.meta_image.display(),
        paths.payload_image.display(),
        paths.state.display(),
        paths.auth_state.display(),
        auth_store,
        bins,
        verified,
        table.total_bins(),
        table.bin_size(),
        pack,
        params.logical_blocks,
        params.block_size,
        params.leaves,
        params.height(),
        cached_pages,
        oram.stash_len(),
        pending_before,
        oram.pending_evictions()?,
        drained,
        elapsed.as_millis(),
        elapsed.as_secs_f64() * 1_000_000.0 / bins.max(1) as f64,
        checksum,
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn print_circuit_stress(
    db_dirs: &[PathBuf],
    packs: &[usize],
    leaf_divisors: &[usize],
    bucket_size: usize,
    stash_capacity: usize,
    ops: usize,
    warmup_ops: usize,
    pattern: CircuitStressPattern,
    drain_per_access: u64,
    burst_interval: usize,
    burst_budget: u64,
    max_debt: Option<u64>,
    seed: [u8; 32],
) -> Result<()> {
    if packs.is_empty() {
        return Err(Error::InvalidInput(
            "at least one --packs value is required".into(),
        ));
    }
    if leaf_divisors.is_empty() {
        return Err(Error::InvalidInput(
            "at least one --leaf-divisors value is required".into(),
        ));
    }

    println!("stress_circuit=true");
    println!("bucket_size={bucket_size}");
    println!("stash_capacity={stash_capacity}");
    println!("ops={ops}");
    println!("warmup_ops={warmup_ops}");
    println!("pattern={}", pattern.label());
    println!("drain_per_access={drain_per_access}");
    println!("burst_interval={burst_interval}");
    println!("burst_budget={burst_budget}");
    println!("seed_hex={}", hex::encode(seed));
    println!(
        "max_debt={}",
        max_debt
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string())
    );

    for db_dir in db_dirs {
        let tables = CuckooTableInfo::load_pair(db_dir)?;
        for table in &tables {
            for &pack in packs {
                for &leaf_divisor in leaf_divisors {
                    let sizing = CuckooOramSizing {
                        bins_per_block: pack,
                        leaf_divisor,
                        bucket_size,
                        stash_capacity,
                        cache_levels: 0,
                    };
                    let estimate = sizing.estimate(table)?;
                    let params = OramParams::with_leaves(
                        estimate.logical_blocks,
                        estimate.block_payload_bytes,
                        estimate.leaves,
                    )?
                    .with_bucket_size(bucket_size)?
                    .with_stash_capacity(stash_capacity)?;
                    let report = stress_circuit(CircuitStressConfig {
                        params,
                        ops,
                        warmup_ops,
                        pattern,
                        seed,
                        drain_per_access,
                        burst_interval,
                        burst_budget,
                        max_debt,
                    })?;
                    print_stress_report(db_dir, table, &estimate, &report);
                }
            }
        }
    }

    Ok(())
}

fn print_stress_report(
    db_dir: &Path,
    table: &CuckooTableInfo,
    estimate: &CuckooOramEstimate,
    report: &CircuitStressReport,
) {
    println!(
        "stress db_dir={} level={} anchor={} pack={} leaf_divisor={} total_bins={} logical_blocks={} block_payload_bytes={} bucket_size={} leaves={} height={} tree_slots={} tree_slot_load_percent={:.3} ops={} warmup_ops={} pattern={} stash_capacity={} init_stash={} final_stash={} max_stash={} avg_stash={:.3} p50_stash={} p99_stash={} p999_stash={} overflow_samples={} evictions_per_access={} drain_per_access={} burst_interval={} burst_budget={} max_debt_cap={} max_eviction_debt={} final_eviction_debt={} completed_evictions={} scheduled_evictions={} metadata_path_scans_per_access={:.3} payload_path_scans_per_access={:.3}",
        db_dir.display(),
        table.level,
        table.anchor_kind,
        estimate.bins_per_block,
        estimate.leaf_divisor,
        estimate.total_bins,
        report.logical_blocks,
        estimate.block_payload_bytes,
        report.bucket_size,
        report.leaves,
        report.height,
        report.tree_slots,
        report.tree_slot_load_percent,
        report.ops,
        report.warmup_ops,
        report.pattern.label(),
        report.stash_capacity,
        report.init_stash,
        report.final_stash,
        report.max_stash,
        report.avg_stash,
        report.p50_stash,
        report.p99_stash,
        report.p999_stash,
        report.overflow_samples,
        report.evictions_per_access,
        report.drain_per_access,
        report.burst_interval,
        report.burst_budget,
        report
            .max_debt_cap
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string()),
        report.max_eviction_debt,
        report.final_eviction_debt,
        report.completed_evictions,
        report.scheduled_evictions,
        report.metadata_path_scans_per_access,
        report.payload_path_scans_per_access,
    );
}

fn print_estimate(db_dir: &Path, e: &CuckooOramEstimate) {
    println!(
        "estimate db_dir={} level={} pack={} leaf_divisor={} total_bins={} logical_blocks={} block_payload_bytes={} bucket_size={} leaves={} height={} bucket_pages={} page_plaintext_bytes={} page_aead_bytes={} image_plaintext_bytes={} image_plaintext_gib={:.3} image_aead_bytes={} image_aead_gib={:.3} pos_map_bytes={} pos_map_mib={:.3} trusted_stash_bytes={} trusted_stash_mib={:.3} trusted_state_floor_bytes={} trusted_state_floor_mib={:.3} cached_pages={} front_cache_plaintext_bytes={} front_cache_plaintext_mib={:.3} front_cache_aead_bytes={} front_cache_aead_mib={:.3} disk_pages_per_access_no_flush={} disk_aead_bytes_per_access_no_flush={} disk_aead_mib_per_access_no_flush={:.3} tree_slot_load_percent={:.3}",
        db_dir.display(),
        e.level,
        e.bins_per_block,
        e.leaf_divisor,
        e.total_bins,
        e.logical_blocks,
        e.block_payload_bytes,
        e.bucket_size,
        e.leaves,
        e.height,
        e.bucket_pages,
        e.page_plaintext_bytes,
        e.page_aead_bytes,
        e.image_plaintext_bytes,
        gib(e.image_plaintext_bytes),
        e.image_aead_bytes,
        gib(e.image_aead_bytes),
        e.pos_map_bytes,
        mib(e.pos_map_bytes),
        e.trusted_stash_bytes,
        mib(e.trusted_stash_bytes),
        e.trusted_state_floor_bytes,
        mib(e.trusted_state_floor_bytes),
        e.cached_pages,
        e.front_cache_plaintext_bytes,
        mib(e.front_cache_plaintext_bytes),
        e.front_cache_aead_bytes,
        mib(e.front_cache_aead_bytes),
        e.disk_pages_per_access_no_flush,
        e.disk_aead_bytes_per_access_no_flush,
        mib(e.disk_aead_bytes_per_access_no_flush),
        e.tree_slot_load_percent,
    );
}

fn gib(bytes: u64) -> f64 {
    bytes as f64 / 1024.0 / 1024.0 / 1024.0
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / 1024.0 / 1024.0
}

fn load_state(path: &Path, state_key_hex: Option<&str>) -> Result<OramState> {
    match state_key_hex {
        Some(key_hex) => OramState::load_encrypted(path, parse_32_hex(key_hex)?),
        None => OramState::load(path),
    }
}

fn load_circuit_state(path: &Path, state_key_hex: Option<&str>) -> Result<CircuitOramState> {
    match state_key_hex {
        Some(key_hex) => CircuitOramState::load_encrypted(path, parse_32_hex(key_hex)?),
        None => CircuitOramState::load(path),
    }
}

fn load_circuit_store_auth(
    path: &Path,
    state_key_hex: Option<&str>,
) -> Result<CircuitStoreAuthState> {
    match state_key_hex {
        Some(key_hex) => CircuitStoreAuthState::load_encrypted(path, parse_32_hex(key_hex)?),
        None => CircuitStoreAuthState::load(path),
    }
}

fn save_state(state: &OramState, path: &Path, state_key_hex: Option<&str>) -> Result<()> {
    match state_key_hex {
        Some(key_hex) => state.save_encrypted_atomic(path, parse_32_hex(key_hex)?),
        None => state.save_atomic(path),
    }
}

fn save_circuit_state(
    state: &CircuitOramState,
    path: &Path,
    state_key_hex: Option<&str>,
) -> Result<()> {
    match state_key_hex {
        Some(key_hex) => state.save_encrypted_atomic(path, parse_32_hex(key_hex)?),
        None => state.save_atomic(path),
    }
}

fn save_circuit_store_auth(
    state: &CircuitStoreAuthState,
    path: &Path,
    state_key_hex: Option<&str>,
) -> Result<()> {
    match state_key_hex {
        Some(key_hex) => state.save_encrypted_atomic(path, parse_32_hex(key_hex)?),
        None => state.save_atomic(path),
    }
}

fn open_file_store(
    image: &Path,
    params: &OramParams,
    encrypted: bool,
    key_hex: Option<&str>,
    cached_pages: usize,
    load_cached_pages: bool,
) -> Result<Box<dyn PageStore>> {
    open_sized_file_store(
        image,
        params.bucket_count(),
        params.bucket_bytes(),
        encrypted,
        key_hex,
        cached_pages,
        load_cached_pages,
    )
}

#[allow(clippy::too_many_arguments)]
fn open_circuit_file_stores(
    meta_image: &Path,
    payload_image: &Path,
    params: &OramParams,
    encrypted: bool,
    key_hex: Option<&str>,
    cached_pages: usize,
    load_cached_pages: bool,
) -> Result<(Box<dyn PageStore>, Box<dyn PageStore>)> {
    let meta_store = open_sized_file_store(
        meta_image,
        params.bucket_count(),
        circuit_meta_page_bytes(params.bucket_size),
        encrypted,
        key_hex,
        cached_pages,
        load_cached_pages,
    )?;
    let payload_store = open_sized_file_store(
        payload_image,
        params.bucket_count(),
        circuit_payload_page_bytes(params.bucket_size, params.block_size),
        encrypted,
        key_hex,
        cached_pages,
        load_cached_pages,
    )?;
    Ok((meta_store, payload_store))
}

#[allow(clippy::too_many_arguments)]
fn build_circuit_store_auth(
    paths: &CircuitOutputPaths,
    level: CuckooLevel,
    params: &OramParams,
    encrypted: bool,
    key_hex: Option<&str>,
    cached_pages: usize,
    trusted_levels: usize,
    hash_page_size: usize,
) -> Result<CircuitStoreAuthState> {
    let (meta_store, payload_store) = open_circuit_file_stores(
        &paths.meta_image,
        &paths.payload_image,
        params,
        encrypted,
        key_hex,
        cached_pages,
        true,
    )?;

    let meta_hash_pages = tiered_hash_pages(params.bucket_count(), hash_page_size, trusted_levels)?;
    let payload_hash_pages =
        tiered_hash_pages(params.bucket_count(), hash_page_size, trusted_levels)?;
    let mut meta_hash_store = open_sized_file_store(
        &paths.meta_hash_image,
        meta_hash_pages,
        hash_page_size,
        encrypted,
        key_hex,
        0,
        false,
    )?;
    let mut payload_hash_store = open_sized_file_store(
        &paths.payload_hash_image,
        payload_hash_pages,
        hash_page_size,
        encrypted,
        key_hex,
        0,
        false,
    )?;
    zero_page_store(&mut *meta_hash_store)?;
    zero_page_store(&mut *payload_hash_store)?;

    let mut meta = TieredMerklePageStore::build(
        meta_store,
        meta_hash_store,
        circuit_auth_store_id(level, CircuitAuthStoreKind::Meta),
        trusted_levels,
    )?;
    let mut payload = TieredMerklePageStore::build(
        payload_store,
        payload_hash_store,
        circuit_auth_store_id(level, CircuitAuthStoreKind::Payload),
        trusted_levels,
    )?;
    meta.flush()?;
    payload.flush()?;

    println!(
        "auth_built level={} meta_hash_image={} payload_hash_image={} auth_state={} trusted_levels={} hash_page_size={} meta_hash_pages={} payload_hash_pages={} meta_trusted_hash_bytes={} payload_trusted_hash_bytes={}",
        level,
        paths.meta_hash_image.display(),
        paths.payload_hash_image.display(),
        paths.auth_state.display(),
        trusted_levels,
        hash_page_size,
        meta_hash_pages,
        payload_hash_pages,
        meta.trusted_hash_bytes(),
        payload.trusted_hash_bytes(),
    );

    Ok(CircuitStoreAuthState::new(
        meta.trusted_state(),
        payload.trusted_state(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_direct_store_auth(
    paths: &CircuitOutputPaths,
    level: DirectLevel,
    params: &OramParams,
    encrypted: bool,
    key_hex: Option<&str>,
    cached_pages: usize,
    trusted_levels: usize,
    hash_page_size: usize,
) -> Result<CircuitStoreAuthState> {
    let (meta_store, payload_store) = open_circuit_file_stores(
        &paths.meta_image,
        &paths.payload_image,
        params,
        encrypted,
        key_hex,
        cached_pages,
        true,
    )?;

    let meta_hash_pages = tiered_hash_pages(params.bucket_count(), hash_page_size, trusted_levels)?;
    let payload_hash_pages =
        tiered_hash_pages(params.bucket_count(), hash_page_size, trusted_levels)?;
    let mut meta_hash_store = open_sized_file_store(
        &paths.meta_hash_image,
        meta_hash_pages,
        hash_page_size,
        encrypted,
        key_hex,
        0,
        false,
    )?;
    let mut payload_hash_store = open_sized_file_store(
        &paths.payload_hash_image,
        payload_hash_pages,
        hash_page_size,
        encrypted,
        key_hex,
        0,
        false,
    )?;
    zero_page_store(&mut *meta_hash_store)?;
    zero_page_store(&mut *payload_hash_store)?;

    let mut meta = TieredMerklePageStore::build(
        meta_store,
        meta_hash_store,
        direct_auth_store_id(level, CircuitAuthStoreKind::Meta),
        trusted_levels,
    )?;
    let mut payload = TieredMerklePageStore::build(
        payload_store,
        payload_hash_store,
        direct_auth_store_id(level, CircuitAuthStoreKind::Payload),
        trusted_levels,
    )?;
    meta.flush()?;
    payload.flush()?;

    println!(
        "direct_auth_built level={} meta_hash_image={} payload_hash_image={} auth_state={} trusted_levels={} hash_page_size={} meta_hash_pages={} payload_hash_pages={} meta_trusted_hash_bytes={} payload_trusted_hash_bytes={}",
        level,
        paths.meta_hash_image.display(),
        paths.payload_hash_image.display(),
        paths.auth_state.display(),
        trusted_levels,
        hash_page_size,
        meta_hash_pages,
        payload_hash_pages,
        meta.trusted_hash_bytes(),
        payload.trusted_hash_bytes(),
    );

    Ok(CircuitStoreAuthState::new(
        meta.trusted_state(),
        payload.trusted_state(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn open_circuit_file_stores_for_reopen(
    paths: &CircuitOutputPaths,
    level: CuckooLevel,
    params: &OramParams,
    encrypted: bool,
    key_hex: Option<&str>,
    cached_pages: usize,
    auth_store: bool,
    state_key_hex: Option<&str>,
) -> Result<(Box<dyn PageStore>, Box<dyn PageStore>)> {
    if !auth_store {
        return open_circuit_file_stores(
            &paths.meta_image,
            &paths.payload_image,
            params,
            encrypted,
            key_hex,
            cached_pages,
            true,
        );
    }

    let auth = load_circuit_store_auth(&paths.auth_state, state_key_hex)?;
    let (meta_store, payload_store) = open_circuit_file_stores(
        &paths.meta_image,
        &paths.payload_image,
        params,
        encrypted,
        key_hex,
        cached_pages,
        true,
    )?;
    let meta_hash_store =
        open_hash_store_for_auth(&paths.meta_hash_image, &auth.meta, encrypted, key_hex)?;
    let payload_hash_store =
        open_hash_store_for_auth(&paths.payload_hash_image, &auth.payload, encrypted, key_hex)?;

    let meta = TieredMerklePageStore::from_trusted_state(meta_store, meta_hash_store, auth.meta)?;
    let payload =
        TieredMerklePageStore::from_trusted_state(payload_store, payload_hash_store, auth.payload)?;
    if meta.store_id() != circuit_auth_store_id(level, CircuitAuthStoreKind::Meta)
        || payload.store_id() != circuit_auth_store_id(level, CircuitAuthStoreKind::Payload)
    {
        return Err(Error::InvalidInput(format!(
            "{} auth sidecar store_id does not match expected level/store domains",
            level
        )));
    }

    Ok((Box::new(meta), Box::new(payload)))
}

fn open_hash_store_for_auth(
    image: &Path,
    auth: &bitcoinpir_oram::TieredMerkleState,
    encrypted: bool,
    key_hex: Option<&str>,
) -> Result<Box<dyn PageStore>> {
    let hash_pages = tiered_hash_pages(auth.page_count, auth.hash_page_size, auth.trusted_levels)?;
    open_sized_file_store(
        image,
        hash_pages,
        auth.hash_page_size,
        encrypted,
        key_hex,
        0,
        false,
    )
}

fn tiered_hash_pages(
    data_pages: usize,
    hash_page_size: usize,
    trusted_levels: usize,
) -> Result<usize> {
    TieredMerklePageStore::<Box<dyn PageStore>, Box<dyn PageStore>>::required_hash_pages(
        data_pages,
        hash_page_size,
        trusted_levels,
    )
}

fn zero_page_store(store: &mut dyn PageStore) -> Result<()> {
    let zero = vec![0u8; store.page_size()];
    for page_idx in 0..store.page_count() {
        store.write_page(page_idx, &zero)?;
    }
    store.flush()
}

#[derive(Clone, Copy)]
enum CircuitAuthStoreKind {
    Meta,
    Payload,
}

fn circuit_auth_store_id(level: CuckooLevel, kind: CircuitAuthStoreKind) -> [u8; 16] {
    match (level, kind) {
        (CuckooLevel::Index, CircuitAuthStoreKind::Meta) => *b"bpir-idx-meta-v1",
        (CuckooLevel::Index, CircuitAuthStoreKind::Payload) => *b"bpir-idx-data-v1",
        (CuckooLevel::Chunk, CircuitAuthStoreKind::Meta) => *b"bpir-chk-meta-v1",
        (CuckooLevel::Chunk, CircuitAuthStoreKind::Payload) => *b"bpir-chk-data-v1",
    }
}

fn direct_auth_store_id(level: DirectLevel, kind: CircuitAuthStoreKind) -> [u8; 16] {
    match (level, kind) {
        (DirectLevel::Index, CircuitAuthStoreKind::Meta) => *b"bpir-diridx-meta",
        (DirectLevel::Index, CircuitAuthStoreKind::Payload) => *b"bpir-diridx-data",
        (DirectLevel::Chunk, CircuitAuthStoreKind::Meta) => *b"bpir-dirchk-meta",
        (DirectLevel::Chunk, CircuitAuthStoreKind::Payload) => *b"bpir-dirchk-data",
    }
}

#[allow(clippy::too_many_arguments)]
fn open_sized_file_store(
    image: &Path,
    page_count: usize,
    plaintext_page_size: usize,
    encrypted: bool,
    key_hex: Option<&str>,
    cached_pages: usize,
    load_cached_pages: bool,
) -> Result<Box<dyn PageStore>> {
    let store: Box<dyn PageStore> = if encrypted {
        let key = parse_required_key(key_hex)?;
        let file = FilePageStore::open(
            image,
            page_count,
            backing_page_bytes(plaintext_page_size, true),
        )?;
        Box::new(AeadPageStore::new(file, key, plaintext_page_size)?)
    } else {
        Box::new(FilePageStore::open(image, page_count, plaintext_page_size)?)
    };

    if cached_pages == 0 {
        Ok(store)
    } else if load_cached_pages {
        Ok(Box::new(FrontCachedPageStore::new(store, cached_pages)?))
    } else {
        Ok(Box::new(FrontCachedPageStore::new_zeroed(
            store,
            cached_pages,
        )?))
    }
}

fn backing_page_bytes(plaintext_page_size: usize, encrypted: bool) -> usize {
    plaintext_page_size + if encrypted { AEAD_OVERHEAD } else { 0 }
}

fn cached_pages_for_levels(params: &OramParams, cache_levels: usize) -> Result<usize> {
    if cache_levels == 0 {
        return Ok(0);
    }
    if cache_levels > params.height() {
        return Err(Error::InvalidInput(format!(
            "cache-levels {} > tree height {}",
            cache_levels,
            params.height()
        )));
    }
    Ok((1usize << cache_levels) - 1)
}

fn parse_seed(seed_hex: Option<&str>, default_byte: u8) -> Result<[u8; 32]> {
    match seed_hex {
        Some(seed_hex) => parse_32_hex(seed_hex),
        None => Ok([default_byte; 32]),
    }
}

fn parse_required_key(key_hex: Option<&str>) -> Result<[u8; 32]> {
    let key_hex = key_hex
        .ok_or_else(|| Error::InvalidInput("--key-hex is required with --encrypted".into()))?;
    parse_32_hex(key_hex)
}

fn parse_32_hex(input: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(input)?;
    if bytes.len() != 32 {
        return Err(Error::InvalidInput(format!(
            "expected 32-byte hex string, got {} bytes",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn deterministic_payloads(blocks: usize, block_size: usize) -> Vec<Vec<u8>> {
    debug_assert!(block_size >= 8);
    (0..blocks)
        .map(|logical_id| {
            let mut payload = vec![0u8; block_size];
            payload[..8].copy_from_slice(&(logical_id as u64).to_le_bytes());
            payload
        })
        .collect()
}

fn checksum_payload(mut checksum: u64, payload: &[u8]) -> u64 {
    for chunk in payload.chunks(8) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        checksum = checksum.rotate_left(5) ^ u64::from_le_bytes(buf);
    }
    checksum
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn build_and_bench_circuit_with_auth_store_reopens() {
        let db = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        write_table(
            &db.path().join("batch_pir_cuckoo.bin"),
            CuckooLevel::Index,
            4,
        );
        write_table(
            &db.path().join("chunk_pir_cuckoo.bin"),
            CuckooLevel::Chunk,
            4,
        );

        build_circuit_images(
            db.path(),
            out.path(),
            LevelArg::Index,
            8,
            4,
            2,
            512,
            false,
            None,
            None,
            0,
            true,
            2,
            64,
            [6; 32],
        )
        .unwrap();

        assert!(out.path().join("index.meta.hash.oram").exists());
        assert!(out.path().join("index.payload.hash.oram").exists());
        assert!(out.path().join("index.auth.state").exists());

        bench_circuit_images(
            out.path(),
            Some(db.path()),
            LevelArg::Index,
            8,
            8,
            2,
            false,
            None,
            None,
            0,
            true,
            [4; 32],
            false,
        )
        .unwrap();
    }

    fn write_table(path: &Path, level: CuckooLevel, bins_per_table: u32) {
        let k = match level {
            CuckooLevel::Index => 75u32,
            CuckooLevel::Chunk => 80u32,
        };
        let (magic, slots, slot_size, header_size) = match level {
            CuckooLevel::Index => (0xBA7C_C000_C000_0004u64, 4u32, 13usize, 40usize),
            CuckooLevel::Chunk => (0xBA7C_C000_C000_0002u64, 3u32, 44usize, 32usize),
        };
        let mut header = vec![0u8; header_size];
        header[0..8].copy_from_slice(&magic.to_le_bytes());
        header[8..12].copy_from_slice(&k.to_le_bytes());
        header[12..16].copy_from_slice(&slots.to_le_bytes());
        header[16..20].copy_from_slice(&bins_per_table.to_le_bytes());
        header[20..24].copy_from_slice(&3u32.to_le_bytes());
        header[24..32].copy_from_slice(&7u64.to_le_bytes());
        if level == CuckooLevel::Index {
            header[32..40].copy_from_slice(&9u64.to_le_bytes());
        }
        let bin_size = slots as usize * slot_size;
        let total_bins = k as usize * bins_per_table as usize;
        let mut body = vec![0u8; total_bins * bin_size];
        for bin_idx in 0..total_bins {
            let start = bin_idx * bin_size;
            body[start..start + bin_size].fill((bin_idx % 251) as u8);
        }

        let mut file = fs::File::create(path).unwrap();
        file.write_all(&header).unwrap();
        file.write_all(&body).unwrap();
    }
}
