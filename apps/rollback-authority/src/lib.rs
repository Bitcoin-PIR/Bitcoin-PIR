#![forbid(unsafe_code)]

mod http;
mod material;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use pir_rollback_authority_protocol::AuthorityServerSignerV1;
use pir_rollback_authority_store::{
    RollbackAuthorityOperationCapacityInventoryV1, RollbackAuthorityStoreErrorV1,
    SqliteRollbackAuthorityProvisionerV1, SqliteRollbackAuthorityStoreV1,
    MAX_CALL_ROWS_PER_NAMESPACE_V1, MAX_OPERATION_ROWS_PER_NAMESPACE_V1,
    MIN_CALL_ROWS_PER_NAMESPACE_V1, MIN_OPERATION_ROWS_PER_NAMESPACE_V1,
};
use zeroize::Zeroize;

pub use http::{
    AUTHORITY_CALL_MEDIA_TYPE_V1, AUTHORITY_CALL_PATH_V1, AUTHORITY_RESPONSE_MEDIA_TYPE_V1,
};

const DEFAULT_BUSY_TIMEOUT_MILLIS_V1: u64 = 5_000;
const DEFAULT_IO_TIMEOUT_MILLIS_V1: u64 = 5_000;
const DEFAULT_MAX_CONNECTIONS_V1: usize = 32;

#[derive(Parser, Debug)]
#[command(
    name = "rollback-authority",
    version,
    about = "BitcoinPIR remote rollback-authority administration and loopback service"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate an authority signing seed, instance ID, and public metadata.
    GenerateAuthority(GenerateMaterialArgs),
    /// Generate client signing/value keys, namespace, and provisioning metadata.
    GenerateClient(GenerateClientMaterialArgs),
    /// Exclusively initialize an empty authority SQLite database.
    InitStore(StoreMetadataArgs),
    /// Insert the one exact namespace/client-key/capacity binding offline.
    Provision(ProvisionArgs),
    /// Run full schema, identity, integrity, and semantic checks offline.
    CheckStore(StoreMetadataArgs),
    /// Serve the authenticated protocol on one loopback HTTP listener.
    Serve(ServeArgs),
}

#[derive(Args, Debug)]
struct GenerateMaterialArgs {
    #[arg(long)]
    secret_out: PathBuf,
    #[arg(long)]
    metadata_out: PathBuf,
}

#[derive(Args, Debug)]
struct GenerateClientMaterialArgs {
    #[arg(long)]
    secret_out: PathBuf,
    #[arg(long)]
    value_root_key_out: PathBuf,
    #[arg(long)]
    metadata_out: PathBuf,
}

#[derive(Args, Debug)]
struct StoreMetadataArgs {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    authority_metadata: PathBuf,
    #[arg(long, default_value_t = DEFAULT_BUSY_TIMEOUT_MILLIS_V1)]
    busy_timeout_ms: u64,
}

#[derive(Args, Debug)]
struct ProvisionArgs {
    #[command(flatten)]
    authority: StoreMetadataArgs,
    #[arg(long)]
    client_metadata: PathBuf,
    /// Finite lifetime CAS-operation capacity; V1 never prunes this log.
    #[arg(long)]
    max_operation_rows: u64,
    /// Finite lifetime authenticated-call replay capacity; V1 never prunes it.
    #[arg(long)]
    max_call_rows: u64,
}

#[derive(Args, Debug)]
struct ServeArgs {
    #[arg(long)]
    bind: SocketAddr,
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    authority_secret: PathBuf,
    #[arg(long)]
    authority_metadata: PathBuf,
    #[arg(long)]
    expected_authority_pubkey_hex: String,
    #[arg(long, default_value_t = DEFAULT_BUSY_TIMEOUT_MILLIS_V1)]
    busy_timeout_ms: u64,
    #[arg(long, default_value_t = DEFAULT_IO_TIMEOUT_MILLIS_V1)]
    io_timeout_ms: u64,
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS_V1)]
    max_connections: usize,
}

pub fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::GenerateAuthority(args) => {
            material::generate_authority_v1(&args.secret_out, &args.metadata_out)?;
            print!(
                "{}",
                generated_material_summary_v1("authority", &args.metadata_out)
            );
            Ok(())
        }
        Command::GenerateClient(args) => {
            material::generate_client_v1(
                &args.secret_out,
                &args.value_root_key_out,
                &args.metadata_out,
            )?;
            print!(
                "{}",
                generated_material_summary_v1("client", &args.metadata_out)
            );
            Ok(())
        }
        Command::InitStore(args) => {
            let metadata = material::read_authority_metadata_v1(&args.authority_metadata)?;
            SqliteRollbackAuthorityProvisionerV1::create(
                &args.store,
                metadata.authority_instance_id,
                checked_busy_timeout_v1(args.busy_timeout_ms)?,
            )
            .map_err(|error| init_store_error_v1(&args.store, error))?;
            println!("result=ok");
            Ok(())
        }
        Command::Provision(args) => {
            if !(MIN_OPERATION_ROWS_PER_NAMESPACE_V1..=MAX_OPERATION_ROWS_PER_NAMESPACE_V1)
                .contains(&args.max_operation_rows)
            {
                return Err(format!(
                    "--max-operation-rows must be in {MIN_OPERATION_ROWS_PER_NAMESPACE_V1}..={MAX_OPERATION_ROWS_PER_NAMESPACE_V1}"
                ));
            }
            if !(MIN_CALL_ROWS_PER_NAMESPACE_V1..=MAX_CALL_ROWS_PER_NAMESPACE_V1)
                .contains(&args.max_call_rows)
            {
                return Err(format!(
                    "--max-call-rows must be in {MIN_CALL_ROWS_PER_NAMESPACE_V1}..={MAX_CALL_ROWS_PER_NAMESPACE_V1}"
                ));
            }
            let authority =
                material::read_authority_metadata_v1(&args.authority.authority_metadata)?;
            let client = material::read_client_metadata_v1(&args.client_metadata)?;
            if client.client_verifying_key == authority.authority_verifying_key {
                return Err(
                    "authority signing and provisioned client request keys must be independent"
                        .to_owned(),
                );
            }
            material::validate_existing_private_file_v1(&args.authority.store, "authority store")?;
            let provisioner = SqliteRollbackAuthorityProvisionerV1::open_existing(
                &args.authority.store,
                authority.authority_instance_id,
                checked_busy_timeout_v1(args.authority.busy_timeout_ms)?,
            )
            .map_err(|error| format!("open rollback authority store failed: {error}"))?;
            provisioner
                .provision_namespace(
                    client.namespace,
                    &client.client_verifying_key,
                    args.max_operation_rows,
                    args.max_call_rows,
                )
                .map_err(|error| {
                    format!("provision rollback authority namespace failed: {error}")
                })?;
            println!("result=ok");
            Ok(())
        }
        Command::CheckStore(args) => {
            material::validate_existing_private_file_v1(&args.store, "authority store")?;
            let metadata = material::read_authority_metadata_v1(&args.authority_metadata)?;
            let provisioner = SqliteRollbackAuthorityProvisionerV1::open_existing(
                &args.store,
                metadata.authority_instance_id,
                checked_busy_timeout_v1(args.busy_timeout_ms)?,
            )
            .map_err(|error| format!("check rollback authority store failed: {error}"))?;
            let inventory = provisioner
                .operation_capacity_inventory()
                .map_err(|error| format!("check rollback authority store failed: {error}"))?;
            print!("{}", operation_capacity_summary_v1(&inventory)?);
            Ok(())
        }
        Command::Serve(args) => serve_v1(args),
    }
}

fn operation_capacity_summary_v1(
    inventory: &RollbackAuthorityOperationCapacityInventoryV1,
) -> Result<String, String> {
    let Some((used, maximum)) = inventory.provisioned_capacity() else {
        return Err("check rollback authority store failed: namespace is unprovisioned".to_owned());
    };
    let Some((used_calls, maximum_calls)) = inventory.provisioned_call_capacity() else {
        return Err("check rollback authority store failed: namespace is unprovisioned".to_owned());
    };
    Ok(format!(
        "result=ok\nnamespace_status=provisioned\noperation_rows_used={used}\noperation_rows_max={maximum}\ncall_rows_used={used_calls}\ncall_rows_max={maximum_calls}\n"
    ))
}

fn generated_material_summary_v1(kind: &'static str, metadata_path: &Path) -> String {
    format!("result=ok\nmaterial_kind={kind}\nmetadata_path={metadata_path:?}\n")
}

fn init_store_error_v1(path: &Path, error: RollbackAuthorityStoreErrorV1) -> String {
    let initial = format!("initialize rollback authority store failed: {error}");
    if matches!(
        error,
        RollbackAuthorityStoreErrorV1::InvalidConfiguration
            | RollbackAuthorityStoreErrorV1::DatabaseAlreadyExists
            | RollbackAuthorityStoreErrorV1::UnsafeDatabasePath
    ) {
        return initial;
    }
    format!(
        "{initial}; partial initialization may remain at {path:?}; do not delete, overwrite, or rerun automatically: inspect the path and run check-store with the exact same authority metadata before deciding recovery"
    )
}

fn serve_v1(args: ServeArgs) -> Result<(), String> {
    if !args.bind.ip().is_loopback() {
        return Err("--bind must be an IPv4 or IPv6 loopback address".to_owned());
    }
    if !(1..=http::MAX_ADMITTED_CONNECTIONS_V1).contains(&args.max_connections) {
        return Err("--max-connections must be in 1..=256".to_owned());
    }
    let io_timeout = checked_io_timeout_v1(args.io_timeout_ms)?;
    let busy_timeout = checked_busy_timeout_v1(args.busy_timeout_ms)?;
    material::validate_existing_private_file_v1(&args.store, "authority store")?;
    let metadata = material::read_authority_metadata_v1(&args.authority_metadata)?;
    let expected_pin = material::decode_canonical_hex_v1::<32>(
        &args.expected_authority_pubkey_hex,
        "expected authority public-key pin",
    )?;
    if metadata.authority_verifying_key.to_bytes() != expected_pin {
        return Err("authority metadata does not match the expected public-key pin".to_owned());
    }
    let mut secret = material::read_secret_seed_v1(&args.authority_secret)?;
    let signing_key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    if signing_key.verifying_key() != metadata.authority_verifying_key {
        return Err("authority secret does not match metadata and expected pin".to_owned());
    }
    let server_signer = AuthorityServerSignerV1::new(metadata.authority_instance_id, signing_key)
        .map_err(|_| "authority signer configuration is invalid".to_owned())?;
    let store = SqliteRollbackAuthorityStoreV1::open_existing(
        &args.store,
        metadata.authority_instance_id,
        busy_timeout,
    )
    .map_err(|error| format!("open rollback authority store failed: {error}"))?;
    http::serve_loopback_v1(
        args.bind,
        store,
        server_signer,
        args.max_connections,
        io_timeout,
    )
}

fn checked_busy_timeout_v1(milliseconds: u64) -> Result<Duration, String> {
    if !(1..=60_000).contains(&milliseconds) {
        return Err("--busy-timeout-ms must be in 1..=60000".to_owned());
    }
    Ok(Duration::from_millis(milliseconds))
}

fn checked_io_timeout_v1(milliseconds: u64) -> Result<Duration, String> {
    if !(100..=30_000).contains(&milliseconds) {
        return Err("--io-timeout-ms must be in 100..=30000".to_owned());
    }
    Ok(Duration::from_millis(milliseconds))
}

#[cfg(test)]
mod tests;
