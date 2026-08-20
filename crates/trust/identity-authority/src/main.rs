#![forbid(unsafe_code)]

use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pir_identity::{
    sign_generation_bound_identity_cert_v2, GenerationBoundIdentityCertV2, IdentityCert,
};
use pir_identity_authority::{
    IdentityAuthorityErrorV1, IdentityAuthorityHeadV1, IdentityAuthorityStoreV1,
    IdentityAuthorityWriteDispositionV1, IdentityGenerationReservationStateV2,
    IdentityGenerationReservationV2, IDENTITY_AUTHORITY_HEAD_BYTES_V1,
    MAX_IDENTITY_ACTIVATION_BYTES_V2,
};
use pir_private_files::PrivateFileModeV1;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(
    name = "identity-authority",
    version,
    about = "Owner-only BitcoinPIR identity generation reservation registry"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a fresh registry and persist its exact external genesis head.
    Init(InitArgs),
    /// Allocate one inactive server identity generation before key generation.
    ReserveGeneration(MutationArgs),
    /// Read back one exact inactive or active generation.
    ReadGeneration(ReadArgs),
    /// Bind one reserved generation to an exact signed V2 certificate.
    ActivateGeneration(ActivateArgs),
    /// Sign a generation-bound V2 certificate without activating it.
    SignGenerationCertificate(SignArgs),
    /// Recover only an exact lost reserve-generation successor.
    RecoverReservationHead(MutationArgs),
    /// Recover only an exact lost activate-generation successor.
    RecoverActivationHead(ActivateArgs),
}

#[derive(Args, Debug)]
struct InitArgs {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    head_out: PathBuf,
    #[arg(long)]
    registry_id_hex: String,
    /// File containing exactly the 32-byte public operator verifying key.
    #[arg(long)]
    operator_verifying_key: PathBuf,
}

#[derive(Args, Debug)]
struct ExactOpenArgs {
    #[arg(long)]
    store: PathBuf,
    /// Exact previously persisted authority head; never inferred from SQLite.
    #[arg(long)]
    head_in: PathBuf,
}

#[derive(Args, Debug)]
struct MutationArgs {
    #[command(flatten)]
    authority: ExactOpenArgs,
    /// New no-overwrite file for the successor head.
    #[arg(long)]
    head_out: PathBuf,
    #[arg(long)]
    server_id: String,
    #[arg(long)]
    identity_generation: u64,
}

#[derive(Args, Debug)]
struct ReadArgs {
    #[command(flatten)]
    authority: ExactOpenArgs,
    #[arg(long)]
    server_id: String,
    #[arg(long)]
    identity_generation: u64,
}

#[derive(Args, Debug)]
struct ActivateArgs {
    #[command(flatten)]
    authority: ExactOpenArgs,
    /// New no-overwrite file for the committed or replayed exact head.
    #[arg(long)]
    head_out: PathBuf,
    /// Canonical signed GenerationBoundIdentityCertV2 bytes.
    #[arg(long)]
    certificate: PathBuf,
}

#[derive(Args, Debug)]
struct SignArgs {
    /// Owner-only raw 32-byte Ed25519 operator signing seed.
    #[arg(long)]
    operator_signing_key: PathBuf,
    #[arg(long)]
    server_id: String,
    #[arg(long)]
    identity_generation: u64,
    /// Boot-0 raw 32-byte identity verifying key.
    #[arg(long)]
    identity_verifying_key: PathBuf,
    #[arg(long)]
    valid_from: i64,
    /// Zero means no upper bound.
    #[arg(long)]
    valid_until: i64,
    /// New no-overwrite canonical V2 certificate file.
    #[arg(long)]
    certificate_out: PathBuf,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("identity-authority: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Init(args) => init(args),
        Command::ReserveGeneration(args) => reserve(args),
        Command::ReadGeneration(args) => read(args),
        Command::ActivateGeneration(args) => activate(args),
        Command::SignGenerationCertificate(args) => sign_certificate(args),
        Command::RecoverReservationHead(args) => recover_reservation(args),
        Command::RecoverActivationHead(args) => recover_activation(args),
    }
}

fn init(args: InitArgs) -> Result<(), String> {
    let registry_id = decode_canonical_hex::<16>(&args.registry_id_hex, "registry ID")?;
    if registry_id.iter().all(|byte| *byte == 0) {
        return Err("registry ID must not be all zero".to_owned());
    }
    let operator_pubkey = pir_private_files::read_exact_private_file_v1::<32>(
        &args.operator_verifying_key,
        "identity operator verifying key",
    )?;
    let initial = IdentityAuthorityHeadV1::initial(registry_id, operator_pubkey)
        .map_err(|error| format!("validate identity authority identity: {error}"))?;
    let head_out = prepare_head_output(&args.head_out, None)?;
    let new_store = match std::fs::symlink_metadata(&args.store) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Some(pir_private_files::prepare_new_private_file_v1(
                &args.store,
                false,
                "identity authority database",
            )?)
        }
        Err(error) => return Err(format!("inspect identity authority database: {error}")),
        Ok(_) => None,
    };
    if new_store.as_ref().is_some_and(|store| store == &head_out) {
        return Err("--store and --head-out must be distinct paths".to_owned());
    }
    let store_path = new_store.as_deref().unwrap_or(&args.store);
    let store = match IdentityAuthorityStoreV1::create(store_path, registry_id, operator_pubkey) {
        Ok(store) => store,
        Err(IdentityAuthorityErrorV1::DatabaseAlreadyExists) => {
            IdentityAuthorityStoreV1::open_existing(
                store_path,
                registry_id,
                operator_pubkey,
                initial,
            )
            .map_err(|error| {
                format!(
                    "existing store is not the exact unmutated registry requested for init recovery: {error}"
                )
            })?
        }
        Err(error) => return Err(format!("initialize identity authority store: {error}")),
    };
    persist_head(&head_out, store.head(), "init")?;
    print_head("committed", &head_out, store.head());
    Ok(())
}

fn reserve(args: MutationArgs) -> Result<(), String> {
    let expected = read_head(&args.authority.head_in)?;
    let head_out = prepare_head_output(&args.head_out, Some(&args.authority.head_in))?;
    let mut store = open_exact(&args.authority.store, expected)?;
    let write = store
        .reserve_generation(IdentityGenerationReservationV2 {
            server_id: args.server_id,
            identity_generation: args.identity_generation,
        })
        .map_err(|error| format!("reserve identity generation: {error}"))?;
    persist_head(&head_out, write.head, "reserve-generation")?;
    print_head(disposition(write.disposition), &head_out, write.head);
    print_record(&write.value);
    Ok(())
}

fn read(args: ReadArgs) -> Result<(), String> {
    let expected = read_head(&args.authority.head_in)?;
    let store = open_exact(&args.authority.store, expected)?;
    let record = store
        .reservation(&args.server_id, args.identity_generation)
        .map_err(|error| format!("read identity generation: {error}"))?
        .ok_or_else(|| "identity generation reservation is missing".to_owned())?;
    println!("result=ok");
    print_record(&record);
    Ok(())
}

fn activate(args: ActivateArgs) -> Result<(), String> {
    let expected = read_head(&args.authority.head_in)?;
    let head_out = prepare_head_output(&args.head_out, Some(&args.authority.head_in))?;
    let certificate = read_certificate(&args.certificate)?;
    let now_unix = system_time_unix()?;
    let mut store = open_exact(&args.authority.store, expected)?;
    let write = store
        .activate(&certificate, now_unix)
        .map_err(|error| format!("activate identity generation: {error}"))?;
    persist_head(&head_out, write.head, "activate-generation")?;
    print_head(disposition(write.disposition), &head_out, write.head);
    print_record(&write.value);
    Ok(())
}

fn sign_certificate(args: SignArgs) -> Result<(), String> {
    if args.server_id.is_empty() || args.server_id.len() > 256 {
        return Err("--server-id length must be in 1..=256 bytes".to_owned());
    }
    if args.identity_generation == 0 {
        return Err("--identity-generation must be non-zero".to_owned());
    }
    if args.valid_until != 0 && args.valid_until < args.valid_from {
        return Err("--valid-until must be zero or at least --valid-from".to_owned());
    }
    let identity_pubkey = pir_private_files::read_exact_private_file_v1::<32>(
        &args.identity_verifying_key,
        "Boot-0 identity verifying key",
    )?;
    VerifyingKey::from_bytes(&identity_pubkey)
        .map_err(|_| "Boot-0 identity verifying key is invalid".to_owned())?;
    let certificate_out = pir_private_files::prepare_new_private_file_v1(
        &args.certificate_out,
        false,
        "generation-bound identity certificate",
    )?;

    // The signing seed is deliberately the final input read, after all public
    // fields and the no-replace destination have passed their preflight.
    let mut operator_seed = pir_private_files::read_exact_private_file_v1::<32>(
        &args.operator_signing_key,
        "identity operator signing seed",
    )?;
    let operator = SigningKey::from_bytes(&operator_seed);
    operator_seed.zeroize();
    if operator.verifying_key().to_bytes() == identity_pubkey {
        return Err("identity and authority operator role keys must be distinct".to_owned());
    }
    let certificate = sign_generation_bound_identity_cert_v2(
        &operator,
        &args.server_id,
        args.identity_generation,
        identity_pubkey,
        args.valid_from,
        args.valid_until,
    )
    .map_err(|error| format!("sign generation-bound identity certificate: {error}"))?;
    certificate
        .verify()
        .map_err(|error| format!("self-verify generation-bound identity certificate: {error}"))?;
    let exact = certificate.encode();
    let decoded = GenerationBoundIdentityCertV2::decode(&exact)
        .map_err(|error| format!("self-decode generation-bound identity certificate: {error}"))?;
    if decoded != certificate || decoded.encode() != exact || IdentityCert::decode(&exact).is_ok() {
        return Err("generation-bound identity certificate self-check failed".to_owned());
    }
    pir_private_files::write_atomic_noreplace_private_file_v1(
        &certificate_out,
        &exact,
        false,
        "generation-bound identity certificate",
    )?;
    let readback = read_certificate(&certificate_out)?;
    if readback != certificate {
        return Err("generation-bound identity certificate readback mismatch".to_owned());
    }
    println!("result=ok");
    println!("certificate_path={}", certificate_out.display());
    println!("server_id={}", certificate.server_id);
    println!("identity_generation={}", certificate.identity_generation);
    println!(
        "operator_pubkey={}",
        hex::encode(certificate.operator_pubkey)
    );
    println!(
        "identity_pubkey={}",
        hex::encode(certificate.identity_pubkey)
    );
    Ok(())
}

fn recover_reservation(args: MutationArgs) -> Result<(), String> {
    let expected = read_head(&args.authority.head_in)?;
    let head_out = prepare_head_output(&args.head_out, Some(&args.authority.head_in))?;
    let expected_reservation = IdentityGenerationReservationV2 {
        server_id: args.server_id,
        identity_generation: args.identity_generation,
    };
    let store = IdentityAuthorityStoreV1::recover_reservation_successor(
        &args.authority.store,
        expected,
        &expected_reservation,
    )
    .map_err(|error| format!("recover exact identity reservation successor: {error}"))?;
    persist_head(&head_out, store.head(), "recover-reservation-head")?;
    print_head("recovered_exact_reservation", &head_out, store.head());
    print_record(
        &store
            .reservation(
                &expected_reservation.server_id,
                expected_reservation.identity_generation,
            )
            .map_err(|error| format!("read recovered identity reservation: {error}"))?
            .ok_or_else(|| "recovered identity reservation is missing".to_owned())?,
    );
    Ok(())
}

fn recover_activation(args: ActivateArgs) -> Result<(), String> {
    let expected = read_head(&args.authority.head_in)?;
    let head_out = prepare_head_output(&args.head_out, Some(&args.authority.head_in))?;
    let certificate = read_certificate(&args.certificate)?;
    let store = IdentityAuthorityStoreV1::recover_activation_successor(
        &args.authority.store,
        expected,
        &certificate,
    )
    .map_err(|error| format!("recover exact identity activation successor: {error}"))?;
    persist_head(&head_out, store.head(), "recover-activation-head")?;
    print_head("recovered_exact_activation", &head_out, store.head());
    print_record(
        &store
            .reservation(&certificate.server_id, certificate.identity_generation)
            .map_err(|error| format!("read recovered identity activation: {error}"))?
            .ok_or_else(|| "recovered identity activation is missing".to_owned())?,
    );
    Ok(())
}

fn open_exact(
    store: &Path,
    head: IdentityAuthorityHeadV1,
) -> Result<IdentityAuthorityStoreV1, String> {
    IdentityAuthorityStoreV1::open_existing(store, head.registry_id, head.operator_pubkey, head)
        .map_err(|error| format!("open identity authority at exact external head: {error}"))
}

fn read_head(path: &Path) -> Result<IdentityAuthorityHeadV1, String> {
    let encoded = pir_private_files::read_private_file_bounded_v1(
        path,
        IDENTITY_AUTHORITY_HEAD_BYTES_V1,
        PrivateFileModeV1::ReadOnlyOrReadWrite,
        "identity authority external head",
    )?;
    IdentityAuthorityHeadV1::decode(&encoded)
        .map_err(|error| format!("decode identity authority external head: {error}"))
}

fn read_certificate(path: &Path) -> Result<GenerationBoundIdentityCertV2, String> {
    let exact = pir_private_files::read_private_file_bounded_v1(
        path,
        MAX_IDENTITY_ACTIVATION_BYTES_V2,
        PrivateFileModeV1::ReadOnlyOrReadWrite,
        "generation-bound identity certificate",
    )?;
    let certificate = GenerationBoundIdentityCertV2::decode(&exact)
        .map_err(|error| format!("decode generation-bound identity certificate: {error}"))?;
    certificate
        .verify()
        .map_err(|error| format!("verify generation-bound identity certificate: {error}"))?;
    if certificate.encode().as_slice() != exact.as_slice() {
        return Err("generation-bound identity certificate is non-canonical".to_owned());
    }
    Ok(certificate)
}

fn prepare_head_output(path: &Path, input: Option<&Path>) -> Result<PathBuf, String> {
    if input.is_some_and(|input| input == path) {
        return Err("--head-out must differ from --head-in".to_owned());
    }
    pir_private_files::prepare_new_private_file_v1(path, false, "identity authority next head")
}

fn persist_head(path: &Path, head: IdentityAuthorityHeadV1, operation: &str) -> Result<(), String> {
    pir_private_files::write_atomic_noreplace_private_file_v1(
        path,
        &head.encode(),
        false,
        "identity authority next head",
    )
    .map_err(|error| {
        let recovery = if operation == "init" {
            "rerun init with the exact same registry ID, operator key and absent head-out"
        } else {
            "run only the matching recover-reservation-head or recover-activation-head command with the exact lost operation and old head"
        };
        format!(
            "{operation} database commit reached head {} but external head persistence failed: {error}; do not run another mutation with the old head; inspect any output file, or {recovery} only when it is absent",
            head.commit_seq
        )
    })
}

fn print_head(disposition: &str, path: &Path, head: IdentityAuthorityHeadV1) {
    println!("result=ok");
    println!("disposition={disposition}");
    println!("head_path={}", path.display());
    println!("registry_id={}", hex::encode(head.registry_id));
    println!("operator_pubkey={}", hex::encode(head.operator_pubkey));
    println!("head_commit_seq={}", head.commit_seq);
    println!("head_commitment={}", hex::encode(head.commitment));
}

fn print_record(record: &pir_identity_authority::IdentityGenerationReservationRecordV2) {
    println!("server_id={}", record.reservation.server_id);
    println!(
        "identity_generation={}",
        record.reservation.identity_generation
    );
    println!("reservation_commit_seq={}", record.reservation_commit_seq);
    match &record.state {
        IdentityGenerationReservationStateV2::Inactive => {
            println!("reservation_state=inactive");
        }
        IdentityGenerationReservationStateV2::Active {
            identity_pubkey,
            activation_commit_seq,
            ..
        } => {
            println!("reservation_state=active");
            println!("identity_pubkey={}", hex::encode(identity_pubkey));
            println!("activation_commit_seq={activation_commit_seq}");
        }
    }
}

fn disposition(value: IdentityAuthorityWriteDispositionV1) -> &'static str {
    match value {
        IdentityAuthorityWriteDispositionV1::Committed => "committed",
        IdentityAuthorityWriteDispositionV1::ExactReplay => "exact_replay",
    }
}

fn decode_canonical_hex<const N: usize>(input: &str, label: &str) -> Result<[u8; N], String> {
    if input.len() != N * 2 {
        return Err(format!(
            "{label} must contain exactly {} lowercase hex characters",
            N * 2
        ));
    }
    let decoded: [u8; N] = hex::decode(input)
        .map_err(|_| format!("{label} is invalid hex"))?
        .try_into()
        .map_err(|_| format!("{label} has the wrong length"))?;
    if hex::encode(decoded) != input {
        return Err(format!("{label} must be canonical lowercase hex"));
    }
    Ok(decoded)
}

fn system_time_unix() -> Result<i64, String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_owned())?
        .as_secs();
    let seconds = i64::try_from(seconds).map_err(|_| "system clock exceeds i64".to_owned())?;
    if seconds == 0 {
        Err("system clock is zero".to_owned())
    } else {
        Ok(seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn owner_subcommands_require_explicit_head_flow() {
        let reserve = Cli::try_parse_from([
            "identity-authority",
            "reserve-generation",
            "--store",
            "/tmp/store",
            "--head-in",
            "/tmp/head-1",
            "--head-out",
            "/tmp/head-2",
            "--server-id",
            "pir2",
            "--identity-generation",
            "2",
        ])
        .unwrap();
        assert!(matches!(reserve.command, Command::ReserveGeneration(_)));
        assert!(Cli::try_parse_from([
            "identity-authority",
            "reserve-generation",
            "--store",
            "/tmp/store",
            "--head-in",
            "/tmp/head-1",
            "--server-id",
            "pir2",
            "--identity-generation",
            "2",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "identity-authority",
            "recover-head",
            "--store",
            "/tmp/store",
            "--head-in",
            "/tmp/head-1",
            "--head-out",
            "/tmp/head-2",
        ])
        .is_err());
    }

    #[test]
    fn owner_cli_init_reserve_activate_read_and_exact_replay() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store = directory.path().join("identity.sqlite");
        let operator_path = directory.path().join("operator.pub");
        let operator_seed_path = directory.path().join("operator.seed");
        let identity_path = directory.path().join("identity.pub");
        let certificate_path = directory.path().join("identity-cert-v2.bin");
        let head_0 = directory.path().join("head-0.bin");
        let head_1 = directory.path().join("head-1.bin");
        let head_2 = directory.path().join("head-2.bin");
        let head_2_replay = directory.path().join("head-2-replay.bin");
        let operator = SigningKey::from_bytes(&[0x51; 32]);
        pir_private_files::write_new_private_file_v1(
            &operator_path,
            &operator.verifying_key().to_bytes(),
            "test operator public key",
        )
        .unwrap();
        pir_private_files::write_new_private_file_v1(
            &operator_seed_path,
            &[0x51; 32],
            "test operator signing seed",
        )
        .unwrap();
        let aliased_init_path = directory.path().join("aliased-init.bin");
        assert!(run(Cli {
            command: Command::Init(InitArgs {
                store: aliased_init_path.clone(),
                head_out: aliased_init_path.clone(),
                registry_id_hex: hex::encode([0x54; 16]),
                operator_verifying_key: operator_path.clone(),
            }),
        })
        .is_err());
        assert!(!aliased_init_path.exists());

        run(Cli {
            command: Command::Init(InitArgs {
                store: store.clone(),
                head_out: head_0.clone(),
                registry_id_hex: hex::encode([0x53; 16]),
                operator_verifying_key: operator_path,
            }),
        })
        .unwrap();
        run(Cli {
            command: Command::ReserveGeneration(MutationArgs {
                authority: ExactOpenArgs {
                    store: store.clone(),
                    head_in: head_0,
                },
                head_out: head_1.clone(),
                server_id: "pir2".to_owned(),
                identity_generation: 1,
            }),
        })
        .unwrap();

        let identity = SigningKey::from_bytes(&[0x52; 32]);
        pir_private_files::write_new_private_file_v1(
            &identity_path,
            &identity.verifying_key().to_bytes(),
            "test identity public key",
        )
        .unwrap();
        let now = system_time_unix().unwrap();
        let sign_args = || SignArgs {
            operator_signing_key: operator_seed_path.clone(),
            server_id: "pir2".to_owned(),
            identity_generation: 1,
            identity_verifying_key: identity_path.clone(),
            valid_from: now - 1,
            valid_until: 0,
            certificate_out: certificate_path.clone(),
        };
        run(Cli {
            command: Command::SignGenerationCertificate(sign_args()),
        })
        .unwrap();
        let signed = read_certificate(&certificate_path).unwrap();
        assert!(IdentityCert::decode(&signed.encode()).is_err());
        assert!(run(Cli {
            command: Command::SignGenerationCertificate(sign_args()),
        })
        .is_err());
        let reused_identity_path = directory.path().join("operator-as-identity.pub");
        let rejected_certificate_path = directory.path().join("rejected-cert.bin");
        pir_private_files::write_new_private_file_v1(
            &reused_identity_path,
            &operator.verifying_key().to_bytes(),
            "test reused identity public key",
        )
        .unwrap();
        assert!(run(Cli {
            command: Command::SignGenerationCertificate(SignArgs {
                operator_signing_key: operator_seed_path.clone(),
                server_id: "pir2".to_owned(),
                identity_generation: 2,
                identity_verifying_key: reused_identity_path,
                valid_from: now - 1,
                valid_until: 0,
                certificate_out: rejected_certificate_path.clone(),
            }),
        })
        .is_err());
        assert!(!rejected_certificate_path.exists());
        run(Cli {
            command: Command::ActivateGeneration(ActivateArgs {
                authority: ExactOpenArgs {
                    store: store.clone(),
                    head_in: head_1,
                },
                head_out: head_2.clone(),
                certificate: certificate_path.clone(),
            }),
        })
        .unwrap();
        run(Cli {
            command: Command::ReadGeneration(ReadArgs {
                authority: ExactOpenArgs {
                    store: store.clone(),
                    head_in: head_2.clone(),
                },
                server_id: "pir2".to_owned(),
                identity_generation: 1,
            }),
        })
        .unwrap();
        run(Cli {
            command: Command::ActivateGeneration(ActivateArgs {
                authority: ExactOpenArgs {
                    store,
                    head_in: head_2.clone(),
                },
                head_out: head_2_replay.clone(),
                certificate: certificate_path,
            }),
        })
        .unwrap();
        assert_eq!(
            read_head(&head_2).unwrap(),
            read_head(&head_2_replay).unwrap()
        );
    }
}
