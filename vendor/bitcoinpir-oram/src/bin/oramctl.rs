use bitcoinpir_oram::{
    circuit_meta_page_bytes, circuit_payload_page_bytes, stress_circuit, AeadPageStore,
    CircuitCuckooBinReader, CircuitOram, CircuitOramState, CircuitStoreAuthState,
    CircuitStressConfig, CircuitStressPattern, CircuitStressReport, CuckooLevel,
    CuckooOramEstimate, CuckooOramSizing, CuckooPackedBlockReader, CuckooTableInfo, Error,
    FilePageStore, FrontCachedPageStore, OramParams, OramState, PageStore, PathOram, Result,
    TieredMerklePageStore, AEAD_OVERHEAD,
};
use clap::{Parser, Subcommand, ValueEnum};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{
    fs,
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
    }
    Ok(())
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
    }
}

fn derive_level_seed(mut seed: [u8; 32], level: CuckooLevel) -> [u8; 32] {
    seed[31] ^= match level {
        CuckooLevel::Index => 0x11,
        CuckooLevel::Chunk => 0x22,
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
