//! `bpir-admin db-proof` — verify attested-builder database proof artifacts.

use clap::{Args, Subcommand, ValueEnum};
use pir_db_attest::{
    build_kind_label, display_hash_hex, hex32, BuildKind, DbAttestError, ProofDirectory,
};
use pir_sdk_client::db_proof::{
    fetch_database_catalog, fetch_database_proof, verify_database_proof, DatabaseProofPolicy,
};
use pir_sdk_client::WsConnection;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Args, Debug)]
pub struct DbProofArgs {
    #[command(subcommand)]
    command: DbProofCommand,
}

#[derive(Subcommand, Debug)]
enum DbProofCommand {
    /// Verify a local attested-builder proof directory.
    Verify(VerifyArgs),
    /// Fetch and verify a database proof from a live PIR server.
    #[command(name = "verify-live")]
    VerifyLive(VerifyLiveArgs),
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Directory containing build-evidence.bin, root-bundle-payload.bin,
    /// build-evidence.sev-snp-report.bin, and manifest sidecars.
    #[arg(long)]
    proof_dir: PathBuf,

    #[command(flatten)]
    expected: ExpectedProofArgs,
}

#[derive(Args, Debug)]
pub struct VerifyLiveArgs {
    /// WebSocket URL of the server, e.g. `wss://weikeng2.bitcoinpir.org`.
    #[arg(long)]
    server: String,

    /// Database id to request from the server's catalog/proof map.
    #[arg(long)]
    db_id: u8,

    /// Override the proof-request timeout in seconds.
    #[arg(long, default_value_t = 60)]
    timeout_seconds: u64,

    #[command(flatten)]
    expected: ExpectedProofArgs,
}

#[derive(Args, Debug, Default)]
pub struct ExpectedProofArgs {
    /// Expected build kind.
    #[arg(long, value_enum)]
    expect_build_kind: Option<ExpectedBuildKind>,

    /// Expected starting anchor height for a delta.
    #[arg(long)]
    expect_from_height: Option<u32>,

    /// Expected ending anchor height.
    #[arg(long)]
    expect_height: Option<u32>,

    /// Expected starting anchor block hash, in Bitcoin display hex order.
    #[arg(long)]
    expect_from_block_hash: Option<String>,

    /// Expected ending anchor block hash, in Bitcoin display hex order.
    #[arg(long)]
    expect_block_hash: Option<String>,

    /// Expected UTXO MuHash, in Bitcoin Core display hex order.
    #[arg(long)]
    expect_muhash: Option<String>,

    /// Expected bucket Merkle super-root, raw hex.
    #[arg(long)]
    expect_bucket_root: Option<String>,

    /// Expected OnionPIR Merkle super-root, raw hex.
    #[arg(long)]
    expect_onion_root: Option<String>,

    /// Expected builder binary sha256, raw hex.
    #[arg(long)]
    expect_builder_binary_sha256: Option<String>,

    /// Expected builder git commit.
    #[arg(long)]
    expect_builder_git_commit: Option<String>,

    /// Expected network magic, raw hex.
    #[arg(long)]
    expect_network_magic: Option<String>,

    /// Expected build params hash, raw hex.
    #[arg(long)]
    expect_params_hash: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ExpectedBuildKind {
    Snapshot,
    Delta,
}

impl From<ExpectedBuildKind> for BuildKind {
    fn from(value: ExpectedBuildKind) -> Self {
        match value {
            ExpectedBuildKind::Snapshot => BuildKind::Snapshot,
            ExpectedBuildKind::Delta => BuildKind::Delta,
        }
    }
}

pub async fn run(args: DbProofArgs) -> Result<(), String> {
    match args.command {
        DbProofCommand::Verify(args) => verify(args),
        DbProofCommand::VerifyLive(args) => verify_live(args).await,
    }
}

fn verify(args: VerifyArgs) -> Result<(), String> {
    let proof = ProofDirectory::load_and_verify(&args.proof_dir).map_err(|e| e.to_string())?;
    apply_expectations(&args.expected, &proof)?;
    print_local_summary(&args.proof_dir, &proof)?;
    Ok(())
}

async fn verify_live(args: VerifyLiveArgs) -> Result<(), String> {
    let mut conn = WsConnection::connect(&args.server)
        .await
        .map_err(|e| format!("connect to {} failed: {}", args.server, e))?
        .with_request_timeout(Duration::from_secs(args.timeout_seconds));
    let catalog = fetch_database_catalog(&mut conn)
        .await
        .map_err(|e| format!("fetch catalog from {} failed: {}", args.server, e))?;
    let db_info = catalog
        .databases
        .iter()
        .find(|db| db.db_id == args.db_id)
        .ok_or_else(|| format!("db_id {} not present in live catalog", args.db_id))?;
    let bundle = fetch_database_proof(&mut conn, args.db_id)
        .await
        .map_err(|e| format!("fetch db proof from {} failed: {}", args.server, e))?;
    if bundle.db_id != args.db_id {
        return Err(mismatch(
            "db_id",
            args.db_id.to_string(),
            bundle.db_id.to_string(),
        ));
    }
    let proof = bundle
        .as_attest_bundle()
        .verify()
        .map_err(|e| e.to_string())?;
    let policy = policy_from_expectations(&args.expected)?;
    verify_database_proof(db_info, &bundle, &policy)
        .map_err(|e| format!("db proof does not match live catalog/policy: {e}"))?;
    apply_expectations(&args.expected, &proof)?;
    print_live_summary(&args.server, bundle.db_id, &proof)?;
    Ok(())
}

fn policy_from_expectations(args: &ExpectedProofArgs) -> Result<DatabaseProofPolicy, String> {
    let mut policy = DatabaseProofPolicy::default();
    if let Some(expected) = &args.expect_network_magic {
        policy.expected_network_magic = Some(parse_hex_array("network_magic", expected)?);
    }
    if let Some(expected) = &args.expect_params_hash {
        policy.expected_params_hash = Some(parse_hex_array("params_hash", expected)?);
    }
    if let Some(expected) = &args.expect_builder_binary_sha256 {
        policy
            .allowed_builder_binary_sha256
            .push(parse_hex_array("builder_binary_sha256", expected)?);
    }
    if let Some(expected) = &args.expect_builder_git_commit {
        policy.allowed_builder_git_commits.push(expected.clone());
    }
    Ok(policy)
}

fn apply_expectations(args: &ExpectedProofArgs, proof: &ProofDirectory) -> Result<(), String> {
    let evidence = &proof.evidence;

    if let Some(expected) = args.expect_build_kind {
        let expected = BuildKind::from(expected);
        if evidence.build_kind != expected {
            return Err(mismatch(
                "build_kind",
                build_kind_label(expected),
                build_kind_label(evidence.build_kind),
            ));
        }
    }
    if let Some(expected) = args.expect_from_height {
        expect_eq(
            "from_height",
            expected.to_string(),
            evidence.from_anchor.height.to_string(),
        )?;
    }
    if let Some(expected) = args.expect_height {
        expect_eq(
            "height",
            expected.to_string(),
            evidence.anchor.height.to_string(),
        )?;
    }
    if let Some(expected) = &args.expect_from_block_hash {
        expect_display_hash(
            "from_block_hash",
            expected,
            &evidence.from_anchor.block_hash,
        )?;
    }
    if let Some(expected) = &args.expect_block_hash {
        expect_display_hash("block_hash", expected, &evidence.anchor.block_hash)?;
    }
    if let Some(expected) = &args.expect_muhash {
        expect_display_hash("muhash", expected, &evidence.utxo_muhash)?;
    }
    if let Some(expected) = &args.expect_bucket_root {
        expect_hex32("bucket_super_root", expected, &evidence.bucket_super_root)?;
    }
    if let Some(expected) = &args.expect_onion_root {
        expect_hex32("onion_super_root", expected, &evidence.onion_super_root)?;
    }
    if let Some(expected) = &args.expect_builder_binary_sha256 {
        expect_hex32(
            "builder_binary_sha256",
            expected,
            &evidence.builder_binary_sha256,
        )?;
    }
    if let Some(expected) = &args.expect_builder_git_commit {
        expect_eq("builder_git_commit", expected, &evidence.builder_git_commit)?;
    }
    if let Some(expected) = &args.expect_network_magic {
        let expected = normalize_hex(expected)?;
        let actual = hex::encode(evidence.network_magic);
        expect_eq("network_magic", expected, actual)?;
    }
    if let Some(expected) = &args.expect_params_hash {
        expect_hex32("params_hash", expected, &evidence.params_hash)?;
    }

    Ok(())
}

fn print_local_summary(proof_dir: &PathBuf, proof: &ProofDirectory) -> Result<(), String> {
    print_summary_header(
        "local",
        Some(("proof_dir", &proof_dir.display().to_string())),
        None,
    );
    print_summary_body(proof)
}

fn print_live_summary(server: &str, db_id: u8, proof: &ProofDirectory) -> Result<(), String> {
    print_summary_header("live", Some(("server", server)), Some(db_id));
    print_summary_body(proof)
}

fn print_summary_header(source: &str, location: Option<(&str, &str)>, db_id: Option<u8>) {
    println!("status=ok");
    println!("proof_source={source}");
    if let Some((key, value)) = location {
        println!("{key}={value}");
    }
    if let Some(db_id) = db_id {
        println!("db_id={db_id}");
    }
}

fn print_summary_body(proof: &ProofDirectory) -> Result<(), String> {
    let evidence = &proof.evidence;
    let evidence_sha256 = evidence.evidence_file_sha256().map_err(|e| e.to_string())?;
    let report_data = evidence.report_data().map_err(|e| e.to_string())?;

    println!("build_kind={}", build_kind_label(evidence.build_kind));
    println!("builder_git_commit={}", evidence.builder_git_commit);
    println!(
        "builder_binary_sha256={}",
        hex32(&evidence.builder_binary_sha256)
    );
    println!("tee_platform={}", evidence.tee_platform);
    println!(
        "tee_image_measurement={}",
        hex::encode(&evidence.tee_image_measurement)
    );
    println!("core_version={}", evidence.core_version);
    println!("network_magic={}", hex::encode(evidence.network_magic));
    println!("from_height={}", evidence.from_anchor.height);
    println!(
        "from_block_hash={}",
        display_hash_hex(&evidence.from_anchor.block_hash)
    );
    println!("height={}", evidence.anchor.height);
    println!(
        "block_hash={}",
        display_hash_hex(&evidence.anchor.block_hash)
    );
    println!("muhash={}", display_hash_hex(&evidence.utxo_muhash));
    println!("snapshot_sha256={}", hex32(&evidence.snapshot_sha256));
    println!("snapshot_bytes={}", evidence.snapshot_bytes);
    println!("params_hash={}", hex32(&evidence.params_hash));
    println!("dust_threshold_sats={}", evidence.dust_threshold_sats);
    println!("max_utxos_per_spk={}", evidence.max_utxos_per_spk);
    println!("index_bins_per_table={}", evidence.index_bins_per_table);
    println!("chunk_bins_per_table={}", evidence.chunk_bins_per_table);
    println!("onion_entry_size={}", evidence.onion_entry_size);
    println!("bucket_super_root={}", hex32(&evidence.bucket_super_root));
    println!("onion_super_root={}", hex32(&evidence.onion_super_root));
    println!(
        "root_bundle_payload_sha256={}",
        hex32(&evidence.root_bundle_payload_sha256)
    );
    if let Some(h) = evidence.signed_root_bundle_sha256 {
        println!("signed_root_bundle_sha256={}", hex32(&h));
    }
    println!("build_evidence_sha256={}", hex32(&evidence_sha256));
    println!("sev_snp_report_data={}", hex::encode(report_data));
    println!(
        "database_manifest_sha256={}",
        hex32(&evidence.database_manifest_sha256)
    );
    println!(
        "all_artifacts_manifest_sha256={}",
        hex32(&evidence.all_artifacts_manifest_sha256)
    );
    println!(
        "server_db_manifest_sha256={}",
        hex32(&evidence.server_db_manifest_sha256)
    );
    println!("root_count={}", proof.root_bundle_payload.roots.len());
    for root in &proof.root_bundle_payload.roots {
        println!("root.{}={}", root.label, hex32(&root.root));
    }
    Ok(())
}

fn expect_display_hash(
    field: &'static str,
    expected: &str,
    actual: &[u8; 32],
) -> Result<(), String> {
    expect_eq(
        field,
        normalize_hex(expected)?,
        display_hash_hex(actual).to_ascii_lowercase(),
    )
}

fn expect_hex32(field: &'static str, expected: &str, actual: &[u8; 32]) -> Result<(), String> {
    let expected = normalize_hex(expected)?;
    if expected.len() != 64 {
        return Err(format!(
            "{field}: expected 32-byte hex, got {}",
            expected.len()
        ));
    }
    expect_eq(field, expected, hex32(actual))
}

fn expect_eq(
    field: &'static str,
    expected: impl AsRef<str>,
    actual: impl AsRef<str>,
) -> Result<(), String> {
    if expected.as_ref() == actual.as_ref() {
        Ok(())
    } else {
        Err(mismatch(field, expected, actual))
    }
}

fn mismatch(field: &'static str, expected: impl AsRef<str>, actual: impl AsRef<str>) -> String {
    DbAttestError::Mismatch {
        field,
        expected: expected.as_ref().to_owned(),
        actual: actual.as_ref().to_owned(),
    }
    .to_string()
}

fn normalize_hex(value: &str) -> Result<String, String> {
    let hex = value.trim().to_ascii_lowercase();
    if hex.len() % 2 != 0 {
        return Err(format!("hex value has odd length: {value}"));
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("hex value contains non-hex characters: {value}"));
    }
    Ok(hex)
}

fn parse_hex_array<const N: usize>(field: &'static str, value: &str) -> Result<[u8; N], String> {
    let normalized = normalize_hex(value)?;
    let bytes = hex::decode(&normalized).map_err(|e| format!("{field}: invalid hex: {e}"))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "{field}: expected {}-byte hex, got {} bytes",
            N,
            bytes.len()
        )
    })
}
