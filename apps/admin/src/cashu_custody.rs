//! Owner-only standard-Cashu provider custody operations.
//!
//! Provider-owned notes move only through owner-only files, and the provider
//! store records an exact sealed artifact before that artifact may be released.
//! The explicit `spent-confirm` command makes one bounded strict-HTTPS NUT-07
//! request with no polling or automatic retry. In production, any subcommand
//! that opens the provider store also performs the fresh signed Read/CAS calls
//! required by its pinned-HTTPS remote rollback authority; local SQLite
//! development/test mode remains offline. An acknowledgement means only that
//! an external wallet took custody and does not release exposure. A later
//! explicit NUT-07 confirmation proves only that those old notes are spent;
//! neither operation proves NUT-05, Lightning
//! settlement, or payout.

use clap::{Args, Subcommand};
use pir_cashu_client::{
    check_cashu_custody_bundles_once_v1, derive_cashu_nut07_export_observation_digest_v1,
    encode_cashub_from_custody_bundles_v1, CashuCustodyAadV1, CashuCustodyBundleV1,
    CashuMintRouteV1, CashuMintTransportFailureKindV1, CashuMintTransportFailureV1,
    CashuMintTransportV1, CashuMintTrustV1, CashuNut07LotResultV1, CashuNut07NoteStateV1,
    CashuSealedCustodyV1, CashuTokenV4V1, ChaCha20Poly1305CustodyDecryptorV1,
    MAX_CASHU_NUT07_BUNDLES_V1,
};
use pir_cashu_custody::{
    open_cashu_custody_v1, seal_cashu_custody_with_os_random_v1, CashuCustodyEnvelopeV1,
    CashuCustodyRecipientPublicKeyV1, CashuCustodyRecipientSecretKeyV1,
    MAX_CASHU_CUSTODY_ENVELOPE_BYTES_V1,
};
use pir_service_store::{
    CashuCustodyExportBatchV1, CashuCustodyExportStateV1, CashuCustodyLotStateV1,
    CashuCustodyRetirementCheckableSnapshotV1, CashuCustodyRetirementCompletedSnapshotV1,
    CashuCustodyRetirementNoteCheckV1, CashuCustodyRetirementNoteStateV1,
    CashuCustodyRetirementSnapshotRequestV1, CashuCustodyRetirementSnapshotV1,
    CashuCustodySpentConfirmationRequestV1, NewCashuCustodyExportV1, ProviderStore,
    RollbackFloorAuthorityV1, SqliteRollbackFloorAuthorityV1, StoreOptions,
    MAX_CASHU_CUSTODY_EXPORT_LOTS_V1,
};
use pir_strict_https::{HttpsPostErrorV1, StrictHttpsClientV1};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const RECIPIENT_SECRET_MAGIC_V1: &[u8; 8] = b"BPCCSK1\0";
const RECIPIENT_PUBLIC_MAGIC_V1: &[u8; 8] = b"BPCCPK1\0";
// Secret artifact: magic || provider_id || raw X25519 secret || binding digest.
// Public artifact: magic || provider_id || public key || key_id || binding digest.
// The binding digest covers provider and derived public key, detecting either
// secret or provider corruption before funds move.
const RECIPIENT_SECRET_ARTIFACT_BYTES_V1: usize = 8 + 32 + 32 + 32;
const RECIPIENT_PUBLIC_ARTIFACT_BYTES_V1: usize = 8 + 32 + 32 + 32 + 32;

#[derive(Args, Debug)]
pub struct CashuCustodyArgs {
    #[command(subcommand)]
    command: CashuCustodyCommand,
}

#[derive(Subcommand, Debug)]
enum CashuCustodyCommand {
    /// Generate or idempotently recover one provider-bound recipient keypair.
    /// The secret is never printed and both artifacts are owner-only files.
    #[command(name = "recipient-keygen")]
    RecipientKeygen(RecipientKeygenArgs),
    /// Print aggregate-only custody inventory for one mint/unit cohort.
    Inventory(InventoryArgs),
    /// Reserve lots, decrypt them locally, persist one exact recipient-sealed
    /// cashuB artifact, then atomically release it to an owner-only file.
    #[command(name = "export-prepare")]
    ExportPrepare(ExportPrepareArgs),
    /// Replay the exact already-persisted recipient-sealed export artifact.
    #[command(name = "export-replay")]
    ExportReplay(ExportReplayArgs),
    /// On the recipient workstation, decrypt an export to an owner-only cashuB
    /// file. The bearer token is never printed.
    Decrypt(DecryptArgs),
    /// Record that an external wallet took custody. This is NOT NUT-05 or
    /// Lightning settlement, does not prove provider payout, and does not
    /// release exposure.
    Acknowledge(AcknowledgeArgs),
    /// Explicitly check one or more same-manifest/pin/mint/unit acknowledged
    /// exports once with NUT-07, then retire only exports whose exact notes are
    /// all SPENT.
    #[command(name = "spent-confirm")]
    SpentConfirm(SpentConfirmArgs),
}

#[derive(Args, Debug)]
pub struct RecipientKeygenArgs {
    /// Provider audience bound into both key artifacts (32-byte lowercase hex).
    #[arg(long)]
    provider_id_hex: String,
    /// Owner-only provider-bound recipient secret artifact.
    #[arg(long)]
    secret_out: PathBuf,
    /// Owner-only non-secret artifact containing provider, public key, and key ID.
    #[arg(long)]
    public_out: PathBuf,
}

#[derive(Args, Clone, Debug)]
struct ProviderStoreArgs {
    /// Exact provider audience (32-byte canonical lowercase hex).
    #[arg(long)]
    provider_id_hex: String,
    /// Existing owner-only provider admission/custody SQLite file.
    #[arg(long)]
    store: PathBuf,
    /// Existing local SQLite rollback floor (development/test only).
    #[arg(
        long,
        required_unless_present = "remote_rollback_authority_config",
        conflicts_with = "remote_rollback_authority_config"
    )]
    rollback_authority: Option<PathBuf>,
    /// Existing owner-only production remote-authority deployment config.
    #[arg(
        long,
        required_unless_present = "rollback_authority",
        conflicts_with = "rollback_authority"
    )]
    remote_rollback_authority_config: Option<PathBuf>,
    /// SQLite busy timeout in milliseconds (1..=60000).
    #[arg(long, default_value_t = 5_000)]
    busy_timeout_ms: u64,
}

#[derive(Args, Debug)]
pub struct InventoryArgs {
    #[command(flatten)]
    store: ProviderStoreArgs,
    /// Standard-Cashu mint ID (32-byte canonical lowercase hex).
    #[arg(long)]
    mint_id_hex: String,
    /// Canonical lowercase Cashu unit, for example `sat`.
    #[arg(long)]
    unit: String,
}

#[derive(Args, Debug)]
pub struct ExportPrepareArgs {
    #[command(flatten)]
    store: ProviderStoreArgs,
    /// Fresh random idempotency identity (16-byte lowercase hex). Never reuse
    /// an invoice, payment, PIR query, or credential identifier here.
    #[arg(long)]
    export_id_hex: String,
    /// Standard-Cashu mint ID (32-byte canonical lowercase hex).
    #[arg(long)]
    mint_id_hex: String,
    /// Canonical lowercase Cashu unit, for example `sat`.
    #[arg(long)]
    unit: String,
    /// Maximum available lots to reserve into this immutable export request.
    #[arg(long)]
    max_lots: u32,
    /// Provider-bound public recipient artifact from `recipient-keygen`.
    #[arg(long)]
    recipient_public: PathBuf,
    /// Historical custody AEAD key as `EPOCH=RAW_32_BYTE_OWNER_ONLY_PATH`.
    /// Repeat for every epoch that may occur in the reserved lots. These are
    /// distinct from the standard-Cashu swap-recovery keys.
    #[arg(long = "custody-key", value_name = "EPOCH=PATH")]
    custody_key_specs: Vec<String>,
    /// Owner-only exact recipient-sealed artifact output. Existing identical
    /// bytes are accepted; different bytes are never overwritten.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug)]
pub struct ExportReplayArgs {
    #[command(flatten)]
    store: ProviderStoreArgs,
    /// Existing export identity (16-byte canonical lowercase hex).
    #[arg(long)]
    export_id_hex: String,
    /// Owner-only exact artifact output. Existing identical bytes are accepted;
    /// different bytes are never overwritten.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug)]
pub struct DecryptArgs {
    /// Recipient-sealed binary artifact from export-prepare/export-replay.
    #[arg(long)]
    artifact: PathBuf,
    /// Matching provider-bound owner-only recipient secret artifact.
    #[arg(long)]
    recipient_secret: PathBuf,
    /// Owner-only canonical cashuB bearer-token file. The token is never sent
    /// over HTTP and never printed to stdout/stderr.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug)]
pub struct AcknowledgeArgs {
    #[command(flatten)]
    store: ProviderStoreArgs,
    /// Existing export identity (16-byte canonical lowercase hex).
    #[arg(long)]
    export_id_hex: String,
    /// SHA-256 of the exact persisted export artifact (32-byte lowercase hex).
    #[arg(long)]
    artifact_digest_hex: String,
    /// Required operator assertion. It records only that an external wallet
    /// safely took custody and does NOT release exposure or assert NUT-05,
    /// Lightning settlement, or provider payout.
    #[arg(long)]
    confirm_external_wallet_took_custody_not_settlement: bool,
}

#[derive(Args, Debug)]
pub struct SpentConfirmArgs {
    #[command(flatten)]
    store: ProviderStoreArgs,
    /// Existing export identity. Repeat this option to batch multiple exports;
    /// every export must use the same canonical mint endpoint and unit.
    #[arg(long = "export-id-hex", required = true)]
    export_id_hexes: Vec<String>,
    /// Historical custody AEAD key as `EPOCH=RAW_32_BYTE_OWNER_ONLY_PATH`.
    /// Repeat for every key epoch present in selected exports that are not
    /// already spent-confirmed. Exact terminal replays require no custody key.
    #[arg(long = "custody-key", value_name = "EPOCH=PATH")]
    custody_key_specs: Vec<String>,
    /// Absolute DNS-plus-connect deadline in milliseconds (1..=60000).
    #[arg(long, default_value_t = 5_000)]
    connect_timeout_ms: u64,
    /// Absolute TLS-plus-request-and-response deadline in milliseconds (1..=60000).
    #[arg(long, default_value_t = 15_000)]
    io_timeout_ms: u64,
    /// Required operator acknowledgement: NUT-07 proves only that the old
    /// exported notes are spent. It does not prove settlement or payout.
    #[arg(long)]
    confirm_nut07_old_notes_spent_not_settlement_or_payout: bool,
}

pub fn run(args: CashuCustodyArgs) -> Result<(), String> {
    match args.command {
        CashuCustodyCommand::RecipientKeygen(args) => recipient_keygen(args),
        CashuCustodyCommand::Inventory(args) => inventory(args),
        CashuCustodyCommand::ExportPrepare(args) => export_prepare(args),
        CashuCustodyCommand::ExportReplay(args) => export_replay(args),
        CashuCustodyCommand::Decrypt(args) => decrypt(args),
        CashuCustodyCommand::Acknowledge(args) => acknowledge(args),
        CashuCustodyCommand::SpentConfirm(args) => spent_confirm(args),
    }
}

fn recipient_keygen(args: RecipientKeygenArgs) -> Result<(), String> {
    let provider_id = parse_nonzero_hex::<32>("--provider-id-hex", &args.provider_id_hex)?;
    reject_same_output_path(&args.secret_out, &args.public_out)?;

    let secret_exists = path_exists_no_symlink(&args.secret_out, "recipient secret")?;
    let public_exists = path_exists_no_symlink(&args.public_out, "recipient public artifact")?;
    if public_exists && !secret_exists {
        return Err(format!(
            "{} exists but {} is missing; refusing to generate a different secret for an existing public artifact",
            args.public_out.display(),
            args.secret_out.display()
        ));
    }

    let (recipient, secret_artifact) = if secret_exists {
        let secret_artifact = read_private_bounded(
            &args.secret_out,
            RECIPIENT_SECRET_ARTIFACT_BYTES_V1,
            "recipient secret artifact",
        )?;
        let (stored_provider, recipient) = decode_recipient_secret_artifact(&secret_artifact)?;
        if stored_provider != provider_id {
            return Err("recipient secret artifact is bound to another provider".to_owned());
        }
        sync_private_file_and_parent(&args.secret_out)?;
        (recipient, secret_artifact)
    } else {
        let mut raw_secret = Zeroizing::new([0u8; 32]);
        let mut recipient = None;
        for _ in 0..4 {
            getrandom::getrandom(raw_secret.as_mut())
                .map_err(|error| format!("operating-system randomness failed: {error}"))?;
            if let Ok(candidate) = CashuCustodyRecipientSecretKeyV1::from_bytes(*raw_secret) {
                recipient = Some(candidate);
                break;
            }
            raw_secret.zeroize();
        }
        let recipient = recipient.ok_or_else(|| {
            "operating-system randomness returned invalid recipient keys".to_owned()
        })?;
        let artifact = encode_recipient_secret_artifact(provider_id, &raw_secret, &recipient);
        let created = write_or_verify_exact_private(&args.secret_out, &artifact)?;
        if !created {
            return Err(
                "recipient secret appeared concurrently; rerun after inspection".to_owned(),
            );
        }
        (recipient, artifact)
    };

    // Keep the secret artifact alive and zeroizing until the complete two-file
    // ceremony has succeeded. Its bytes are never formatted or logged.
    let _secret_artifact = secret_artifact;
    let public = recipient.public_key();
    let public_artifact = encode_recipient_public_artifact(provider_id, &public);
    write_or_verify_exact_private(&args.public_out, &public_artifact).map_err(|error| {
        format!(
            "{error}; recipient key ceremony is incomplete but recoverable: preserve {}, then rerun the exact same command to reconstruct {}",
            args.secret_out.display(),
            args.public_out.display()
        )
    })?;

    println!("provider_id={}", hex::encode(provider_id));
    println!("recipient_key_id={}", hex::encode(public.key_id()));
    println!("recipient_secret={}", args.secret_out.display());
    println!("recipient_public={}", args.public_out.display());
    Ok(())
}

fn inventory(args: InventoryArgs) -> Result<(), String> {
    let (store, provider_id) = open_provider_store(&args.store)?;
    let mint_id = parse_nonzero_hex::<32>("--mint-id-hex", &args.mint_id_hex)?;
    validate_unit(&args.unit)?;
    let value = store
        .cashu_custody_inventory_v1(&mint_id, &args.unit)
        .map_err(|error| format!("read Cashu custody inventory: {error}"))?;
    println!("provider_id={}", hex::encode(provider_id));
    println!("mint_id={}", hex::encode(mint_id));
    println!("unit={}", args.unit);
    println!("pending_intent_value={}", value.pending_intent_value);
    println!("pending_intent_notes={}", value.pending_intent_notes);
    println!("available_lot_count={}", value.available_lot_count);
    println!("available_value={}", value.available_value);
    println!("available_notes={}", value.available_notes);
    println!("reserved_lot_count={}", value.reserved_lot_count);
    println!("reserved_value={}", value.reserved_value);
    println!("reserved_notes={}", value.reserved_notes);
    println!("acknowledged_lot_count={}", value.acknowledged_lot_count);
    println!("acknowledged_value={}", value.acknowledged_value);
    println!("acknowledged_notes={}", value.acknowledged_notes);
    println!(
        "spent_confirmed_lot_count={}",
        value.spent_confirmed_lot_count
    );
    println!("spent_confirmed_value={}", value.spent_confirmed_value);
    println!("spent_confirmed_notes={}", value.spent_confirmed_notes);
    println!("reserved_export_count={}", value.reserved_export_count);
    println!(
        "materialized_export_count={}",
        value.materialized_export_count
    );
    println!(
        "acknowledged_export_count={}",
        value.acknowledged_export_count
    );
    println!(
        "spent_confirmed_export_count={}",
        value.spent_confirmed_export_count
    );
    println!("acknowledgement_releases_exposure=false");
    println!("spent_confirmed_releases_exposure=true");
    Ok(())
}

fn export_prepare(args: ExportPrepareArgs) -> Result<(), String> {
    let (store, provider_id) = open_provider_store(&args.store)?;
    let export_id = parse_nonzero_hex::<16>("--export-id-hex", &args.export_id_hex)?;
    let mint_id = parse_nonzero_hex::<32>("--mint-id-hex", &args.mint_id_hex)?;
    validate_unit(&args.unit)?;
    if args.max_lots == 0
        || usize::try_from(args.max_lots).unwrap_or(usize::MAX) > MAX_CASHU_CUSTODY_EXPORT_LOTS_V1
    {
        return Err(format!(
            "--max-lots must be in 1..={MAX_CASHU_CUSTODY_EXPORT_LOTS_V1}"
        ));
    }
    let public_bytes = read_private_bounded(
        &args.recipient_public,
        RECIPIENT_PUBLIC_ARTIFACT_BYTES_V1,
        "recipient public artifact",
    )?;
    let (public_provider_id, recipient) = decode_recipient_public_artifact(&public_bytes)?;
    if public_provider_id != provider_id {
        return Err(
            "recipient public artifact is bound to another provider; each provider requires a distinct recipient key"
                .to_owned(),
        );
    }

    let reservation = store
        .reserve_cashu_custody_export_v1(&NewCashuCustodyExportV1 {
            export_id,
            mint_id,
            unit: args.unit.clone(),
            max_lots: args.max_lots,
            recipient_key_id: recipient.key_id(),
        })
        .map_err(|error| format!("reserve Cashu custody export: {error}"))?;
    validate_export_request(
        &reservation.batch,
        export_id,
        mint_id,
        &args.unit,
        args.max_lots,
        recipient.key_id(),
    )?;

    let batch = if let Some(artifact) = reservation.batch.artifact.as_ref() {
        validate_stored_artifact(&reservation.batch, provider_id, artifact.bytes.as_slice())?;
        release_exact_artifact(&args.out, &reservation.batch)?;
        reservation.batch
    } else {
        if reservation.batch.state != CashuCustodyExportStateV1::Reserved
            || reservation.sealed_lots.is_empty()
        {
            return Err("reserved Cashu export has no decryptable custody lots".to_owned());
        }

        let decryptor = load_custody_decryptor(&args.custody_key_specs)?;
        let mut bundles = Vec::with_capacity(reservation.sealed_lots.len());
        for lot in &reservation.sealed_lots {
            // The exact AAD conversion and bundle merge are centralized in
            // pir-cashu-client; admin must not duplicate private Cashu formats
            // or the AAD domain-separation construction.
            let aad = lot_cashu_custody_aad(lot)?;
            let sealed = CashuSealedCustodyV1 {
                key_epoch: lot.sealed_notes.key_epoch,
                nonce: lot.sealed_notes.nonce.clone(),
                ciphertext: lot.sealed_notes.ciphertext.clone(),
            };
            bundles.push(
                decryptor
                    .open_bundle(&aad, &sealed)
                    .map_err(|error| format!("decrypt reserved Cashu custody lot: {error}"))?,
            );
        }
        let cashub = merge_cashu_custody_bundles(bundles)?;
        validate_cashub_for_batch(&cashub, &reservation.batch)?;
        let envelope = seal_cashu_custody_with_os_random_v1(
            export_id,
            provider_id,
            &recipient,
            cashub.as_bytes(),
        )
        .map_err(|error| format!("seal Cashu custody export: {error}"))?;
        drop(cashub);
        let proposed_artifact = Zeroizing::new(envelope.into_bytes());
        let persisted = match store
            .persist_cashu_custody_export_artifact_v1(&export_id, &proposed_artifact)
        {
            Ok(value) => value.batch,
            Err(first_error) => {
                // A concurrent exact request or an acknowledged-but-lost
                // response may already have committed an artifact. Release
                // only after a checked reopen returns that durable exact row.
                store
                    .cashu_custody_export_v1(&export_id)
                    .map_err(|recovery_error| {
                        format!(
                            "persist Cashu custody artifact failed ({first_error}); durable recovery read also failed: {recovery_error}"
                        )
                    })?
                    .filter(|batch| batch.artifact.is_some())
                    .ok_or_else(|| {
                        format!(
                            "persist Cashu custody artifact failed and no durable artifact is recoverable: {first_error}"
                        )
                    })?
            }
        };
        validate_export_request(
            &persisted,
            export_id,
            mint_id,
            &args.unit,
            args.max_lots,
            recipient.key_id(),
        )?;
        validate_batch_artifact(&persisted, provider_id)?;
        release_exact_artifact(&args.out, &persisted)?;
        persisted
    };

    print_export_summary(&batch, &args.out)
}

fn export_replay(args: ExportReplayArgs) -> Result<(), String> {
    let (store, provider_id) = open_provider_store(&args.store)?;
    let export_id = parse_nonzero_hex::<16>("--export-id-hex", &args.export_id_hex)?;
    let batch = store
        .cashu_custody_export_v1(&export_id)
        .map_err(|error| format!("read Cashu custody export: {error}"))?
        .ok_or_else(|| "Cashu custody export does not exist".to_owned())?;
    validate_batch_artifact(&batch, provider_id)?;
    release_exact_artifact(&args.out, &batch)?;
    print_export_summary(&batch, &args.out)
}

fn decrypt(args: DecryptArgs) -> Result<(), String> {
    let artifact_bytes = read_private_bounded(
        &args.artifact,
        MAX_CASHU_CUSTODY_ENVELOPE_BYTES_V1,
        "Cashu custody export artifact",
    )?;
    let envelope = CashuCustodyEnvelopeV1::decode(&artifact_bytes)
        .map_err(|error| format!("decode Cashu custody export artifact: {error}"))?;
    let secret_bytes = read_private_bounded(
        &args.recipient_secret,
        RECIPIENT_SECRET_ARTIFACT_BYTES_V1,
        "recipient secret artifact",
    )?;
    let (secret_provider_id, recipient) = decode_recipient_secret_artifact(&secret_bytes)?;
    if envelope.provider_id() != secret_provider_id {
        return Err(
            "export artifact and recipient secret belong to different providers".to_owned(),
        );
    }
    if envelope.recipient_key_id() != recipient.public_key().key_id() {
        return Err(
            "export artifact recipient key ID does not match the secret artifact".to_owned(),
        );
    }
    let plaintext = open_cashu_custody_v1(&envelope, &recipient)
        .map_err(|error| format!("open Cashu custody export: {error}"))?;
    let serialized = std::str::from_utf8(plaintext.as_bytes())
        .map_err(|_| "Cashu custody export plaintext is not UTF-8".to_owned())?;
    let token = CashuTokenV4V1::decode_cashub(serialized)
        .map_err(|error| format!("Cashu custody export is not valid cashuB: {error}"))?;
    let canonical = token
        .encode_cashub()
        .map_err(|error| format!("re-encode Cashu custody cashuB: {error}"))?;
    if canonical.as_str() != serialized {
        return Err("Cashu custody export plaintext is not canonical cashuB".to_owned());
    }
    write_or_verify_exact_private(&args.out, plaintext.as_bytes())?;
    println!("provider_id={}", hex::encode(secret_provider_id));
    println!("export_id={}", hex::encode(envelope.export_id()));
    println!(
        "recipient_key_id={}",
        hex::encode(envelope.recipient_key_id())
    );
    println!("cashub_file={}", args.out.display());
    Ok(())
}

fn acknowledge(args: AcknowledgeArgs) -> Result<(), String> {
    if !args.confirm_external_wallet_took_custody_not_settlement {
        return Err(
            "--confirm-external-wallet-took-custody-not-settlement is required; acknowledgement records external custody but does NOT release exposure or prove NUT-05, Lightning settlement, or provider payout"
                .to_owned(),
        );
    }
    let (store, provider_id) = open_provider_store(&args.store)?;
    let export_id = parse_nonzero_hex::<16>("--export-id-hex", &args.export_id_hex)?;
    let artifact_digest =
        parse_nonzero_hex::<32>("--artifact-digest-hex", &args.artifact_digest_hex)?;
    let batch = store
        .cashu_custody_export_v1(&export_id)
        .map_err(|error| format!("read Cashu custody export before acknowledgement: {error}"))?
        .ok_or_else(|| "Cashu custody export does not exist".to_owned())?;
    validate_batch_artifact(&batch, provider_id)?;
    if batch.artifact.as_ref().map(|artifact| artifact.digest) != Some(artifact_digest) {
        return Err("--artifact-digest-hex does not match the durable exact artifact".to_owned());
    }
    let changed = store
        .acknowledge_cashu_custody_export_v1(&export_id, &artifact_digest)
        .map_err(|error| format!("acknowledge external Cashu custody: {error}"))?;
    println!("provider_id={}", hex::encode(provider_id));
    println!("export_id={}", hex::encode(export_id));
    println!("artifact_digest={}", hex::encode(artifact_digest));
    println!(
        "acknowledgement={}",
        if changed { "recorded" } else { "exact-replay" }
    );
    println!("meaning=external-wallet-custody-only");
    println!("exposure_released=false");
    println!("exposure_release_requires_spent_confirm=true");
    println!("nut05_settlement=false");
    println!("lightning_settlement=false");
    println!("provider_payout_proven=false");
    Ok(())
}

#[derive(Clone, Debug)]
struct CashuCustodyHttpsTransportV1 {
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl CashuMintTransportV1 for CashuCustodyHttpsTransportV1 {
    fn post_json(
        &self,
        trust: CashuMintTrustV1<'_>,
        route: CashuMintRouteV1,
        request_json: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, CashuMintTransportFailureV1> {
        StrictHttpsClientV1::new_with_leaf_spki_sha256_pins(
            self.connect_timeout,
            self.io_timeout,
            trust.leaf_spki_sha256_pins(),
        )
        .map_err(|_| {
            CashuMintTransportFailureV1::ambiguous(CashuMintTransportFailureKindV1::Network, None)
        })?
        .post(
            trust.mint_endpoint(),
            route.path(),
            "application/json",
            "application/json",
            request_json,
            max_response_bytes,
        )
        .map_err(|error| match error {
            HttpsPostErrorV1::DefinitelyNotSent => CashuMintTransportFailureV1::ambiguous(
                CashuMintTransportFailureKindV1::Network,
                None,
            ),
            HttpsPostErrorV1::OutcomeUnknown => CashuMintTransportFailureV1::ambiguous(
                CashuMintTransportFailureKindV1::Timeout,
                None,
            ),
            HttpsPostErrorV1::HttpStatus { status, body } => {
                CashuMintTransportFailureV1::from_http_status(status, body.as_slice())
            }
            HttpsPostErrorV1::InvalidResponse => CashuMintTransportFailureV1::ambiguous(
                CashuMintTransportFailureKindV1::InvalidContentType,
                None,
            ),
        })
    }
}

fn spent_confirm(args: SpentConfirmArgs) -> Result<(), String> {
    validate_spent_confirm_args(&args)?;
    let transport = CashuCustodyHttpsTransportV1 {
        connect_timeout: Duration::from_millis(args.connect_timeout_ms),
        io_timeout: Duration::from_millis(args.io_timeout_ms),
    };
    spent_confirm_with_transport(args, &transport)
}

fn validate_spent_confirm_args(args: &SpentConfirmArgs) -> Result<(), String> {
    if !args.confirm_nut07_old_notes_spent_not_settlement_or_payout {
        return Err(
            "--confirm-nut07-old-notes-spent-not-settlement-or-payout is required; NUT-07 proves only that the old exported notes are spent, not settlement, Lightning settlement, or provider payout"
                .to_owned(),
        );
    }
    if args.export_id_hexes.is_empty() || args.export_id_hexes.len() > MAX_CASHU_NUT07_BUNDLES_V1 {
        return Err(format!(
            "--export-id-hex must be repeated 1..={MAX_CASHU_NUT07_BUNDLES_V1} times"
        ));
    }
    if !(1..=60_000).contains(&args.connect_timeout_ms)
        || !(1..=60_000).contains(&args.io_timeout_ms)
    {
        return Err("NUT-07 HTTPS timeouts must be in 1..=60000 milliseconds".to_owned());
    }
    Ok(())
}

fn parse_spent_confirm_export_ids(args: &SpentConfirmArgs) -> Result<Vec<[u8; 16]>, String> {
    let mut export_ids = args
        .export_id_hexes
        .iter()
        .map(|value| parse_nonzero_hex::<16>("--export-id-hex", value))
        .collect::<Result<Vec<_>, _>>()?;
    export_ids.sort_unstable();
    if export_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("--export-id-hex values must be unique".to_owned());
    }
    Ok(export_ids)
}

struct CashuRetirementCohortV1 {
    mint_id: [u8; 32],
    unit: String,
}

struct PreparedRetirementLotV1 {
    lot_id: [u8; 16],
    note_set_digest: [u8; 32],
    settlement_value: u64,
    note_count: u32,
    binding_digest: [u8; 32],
}

struct PreparedRetirementExportV1 {
    export_id: [u8; 16],
    artifact_digest: [u8; 32],
    batch_binding_digest: [u8; 32],
    member_lot_ids: Vec<[u8; 16]>,
    lots: Vec<PreparedRetirementLotV1>,
    settlement_value: u64,
    note_count: u64,
}

struct CheckedRetirementExportV1 {
    prepared: PreparedRetirementExportV1,
    lots: Vec<CashuNut07LotResultV1>,
    observation_digest: [u8; 32],
}

struct SpentConfirmSummaryV1 {
    requested_exports: usize,
    checked_exports: usize,
    recorded_confirmations: usize,
    exact_replays: usize,
    settlement_value: u64,
    note_count: u64,
}

impl SpentConfirmSummaryV1 {
    fn add_value_and_notes(&mut self, value: u64, notes: u64) -> Result<(), String> {
        self.settlement_value = self
            .settlement_value
            .checked_add(value)
            .ok_or_else(|| "spent-confirm aggregate value overflow".to_owned())?;
        self.note_count = self
            .note_count
            .checked_add(notes)
            .ok_or_else(|| "spent-confirm aggregate note count overflow".to_owned())?;
        Ok(())
    }
}

fn spent_confirm_with_transport(
    args: SpentConfirmArgs,
    transport: &dyn CashuMintTransportV1,
) -> Result<(), String> {
    validate_spent_confirm_args(&args)?;
    let export_ids = parse_spent_confirm_export_ids(&args)?;
    let (store, provider_id) = open_provider_store(&args.store)?;
    let initial_identity = store
        .identity()
        .map_err(|error| format!("read provider-store identity for spent-confirm: {error}"))?;
    if initial_identity.provider_id != provider_id {
        return Err("provider-store identity changed after checked open".to_owned());
    }

    let mut cohort = None;
    let mut decryptor = None;
    let mut bundles = Vec::<CashuCustodyBundleV1>::new();
    let mut prepared_exports = Vec::<PreparedRetirementExportV1>::new();
    let mut summary = SpentConfirmSummaryV1 {
        requested_exports: export_ids.len(),
        checked_exports: 0,
        recorded_confirmations: 0,
        exact_replays: 0,
        settlement_value: 0,
        note_count: 0,
    };

    for export_id in export_ids {
        let snapshot = store
            .cashu_custody_retirement_snapshot_owner_v1(&CashuCustodyRetirementSnapshotRequestV1 {
                provider_id,
                store_instance_id: initial_identity.store_instance_id,
                export_id,
            })
            .map_err(|error| format!("read owner-only Cashu retirement snapshot: {error}"))?;
        match snapshot {
            CashuCustodyRetirementSnapshotV1::SpentConfirmed(completed) => {
                validate_completed_retirement_snapshot_v1(
                    &completed,
                    provider_id,
                    initial_identity.store_instance_id,
                    &export_id,
                )?;
                bind_retirement_cohort_v1(&mut cohort, completed.mint_id, &completed.unit)?;
                summary.add_value_and_notes(completed.settlement_value, completed.note_count)?;
                summary.exact_replays += 1;
            }
            CashuCustodyRetirementSnapshotV1::Checkable(checkable) => {
                validate_checkable_retirement_snapshot_v1(
                    &checkable,
                    provider_id,
                    initial_identity.store_instance_id,
                    &export_id,
                )?;
                bind_retirement_cohort_v1(
                    &mut cohort,
                    checkable.batch.mint_id,
                    &checkable.batch.unit,
                )?;
                if decryptor.is_none() {
                    if args.custody_key_specs.is_empty() {
                        return Err(
                            "at least one --custody-key is required for an acknowledged export that still needs NUT-07 checking"
                                .to_owned(),
                        );
                    }
                    decryptor = Some(load_custody_decryptor(&args.custody_key_specs)?);
                }
                let prepared = prepare_retirement_export_v1(
                    &checkable,
                    decryptor.as_ref().expect("decryptor initialized"),
                    &mut bundles,
                )?;
                summary.add_value_and_notes(prepared.settlement_value, prepared.note_count)?;
                prepared_exports.push(prepared);
            }
        }
    }

    let cohort = cohort.ok_or_else(|| "spent-confirm selection is empty".to_owned())?;
    if prepared_exports.is_empty() {
        return print_spent_confirm_summary_v1(provider_id, &cohort, &summary, false);
    }
    if bundles.len() > MAX_CASHU_NUT07_BUNDLES_V1 {
        return Err(format!(
            "selected exports contain {} lots, exceeding one NUT-07 batch bound of {MAX_CASHU_NUT07_BUNDLES_V1}",
            bundles.len()
        ));
    }

    let checked = check_cashu_custody_bundles_once_v1(transport, &bundles)
        .map_err(|error| format!("perform strict one-shot Cashu NUT-07 check: {error}"))?;
    if checked.mint_id() != &cohort.mint_id || checked.unit() != cohort.unit.as_str() {
        return Err("NUT-07 result does not match the selected mint/unit cohort".to_owned());
    }
    let expected_checked_notes = prepared_exports
        .iter()
        .try_fold(0u64, |total, export| total.checked_add(export.note_count));
    let expected_checked_value = prepared_exports.iter().try_fold(0u64, |total, export| {
        total.checked_add(export.settlement_value)
    });
    if expected_checked_notes != Some(u64::from(checked.note_count()))
        || expected_checked_value != Some(checked.settlement_value())
    {
        return Err("NUT-07 result aggregate does not match selected exports".to_owned());
    }
    if !checked.all_spent() {
        return Err(format!(
            "NUT-07 did not report all selected old notes SPENT (unspent={}, pending={}, total={}); no retirement writes were attempted",
            checked.unspent_count(),
            checked.pending_count(),
            checked.note_count(),
        ));
    }

    let checked_exports = bind_checked_retirement_exports_v1(prepared_exports, checked)?;
    drop(bundles);
    summary.checked_exports = checked_exports.len();
    for (index, checked_export) in checked_exports.into_iter().enumerate() {
        let confirmation = confirm_checked_retirement_export_v1(
            &store,
            provider_id,
            initial_identity.store_instance_id,
            checked_export,
        );
        match confirmation {
            Ok(true) => summary.recorded_confirmations += 1,
            Ok(false) => summary.exact_replays += 1,
            Err(error) => {
                return Err(format!(
                    "spent-confirm failed at export position {} of {} after {} confirmation(s) committed; no automatic retry was attempted and rerunning the exact command is safe: {error}",
                    index + 1,
                    summary.checked_exports,
                    summary.recorded_confirmations,
                ));
            }
        }
    }

    print_spent_confirm_summary_v1(provider_id, &cohort, &summary, true)
}

fn bind_retirement_cohort_v1(
    cohort: &mut Option<CashuRetirementCohortV1>,
    mint_id: [u8; 32],
    unit: &str,
) -> Result<(), String> {
    validate_unit(unit)?;
    match cohort {
        Some(existing) if existing.mint_id != mint_id || existing.unit != unit => Err(
            "all --export-id-hex values in one NUT-07 batch must use the same mint and unit"
                .to_owned(),
        ),
        Some(_) => Ok(()),
        None => {
            *cohort = Some(CashuRetirementCohortV1 {
                mint_id,
                unit: unit.to_owned(),
            });
            Ok(())
        }
    }
}

fn validate_completed_retirement_snapshot_v1(
    completed: &CashuCustodyRetirementCompletedSnapshotV1,
    expected_provider_id: [u8; 32],
    expected_store_instance_id: [u8; 16],
    expected_export_id: &[u8; 16],
) -> Result<(), String> {
    if completed.checked_identity.provider_id != expected_provider_id
        || completed.checked_identity.store_instance_id != expected_store_instance_id
        || &completed.export_id != expected_export_id
        || completed.settlement_value == 0
        || completed.note_count == 0
        || completed.artifact_digest.iter().all(|byte| *byte == 0)
        || completed.evidence.export_id != completed.export_id
        || completed.evidence.provider_id != expected_provider_id
        || completed.evidence.store_instance_id != expected_store_instance_id
        || completed.evidence.artifact_digest != completed.artifact_digest
        || completed.evidence.note_count != completed.note_count
        || completed
            .evidence
            .nut07_response_digest
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err("completed Cashu retirement snapshot is internally inconsistent".to_owned());
    }
    Ok(())
}

fn validate_checkable_retirement_snapshot_v1(
    snapshot: &CashuCustodyRetirementCheckableSnapshotV1,
    expected_provider_id: [u8; 32],
    expected_store_instance_id: [u8; 16],
    expected_export_id: &[u8; 16],
) -> Result<(), String> {
    if snapshot.checked_identity.provider_id != expected_provider_id
        || snapshot.checked_identity.store_instance_id != expected_store_instance_id
        || &snapshot.batch.export_id != expected_export_id
    {
        return Err(
            "checkable Cashu retirement snapshot belongs to another store/export".to_owned(),
        );
    }
    if snapshot.batch.state != CashuCustodyExportStateV1::DeliveryAcknowledged {
        return Err(
            "Cashu export must be delivery-acknowledged before NUT-07 spent-confirm; acknowledgement itself does not release exposure"
                .to_owned(),
        );
    }
    validate_batch_artifact(&snapshot.batch, expected_provider_id)?;
    let expected_lots = usize::try_from(snapshot.batch.lot_count).unwrap_or(usize::MAX);
    if snapshot.member_lot_ids.len() != expected_lots
        || snapshot.sealed_lots.len() != expected_lots
        || snapshot.member_lot_ids.is_empty()
    {
        return Err("checkable Cashu retirement snapshot has inconsistent lot counts".to_owned());
    }
    let mut seen_lot_ids = BTreeSet::new();
    let mut seen_note_sets = BTreeSet::new();
    let mut value = 0u64;
    let mut notes = 0u64;
    for (member_lot_id, lot) in snapshot.member_lot_ids.iter().zip(&snapshot.sealed_lots) {
        if &lot.lot_id != member_lot_id
            || lot.mint_id != snapshot.batch.mint_id
            || lot.unit != snapshot.batch.unit
            || lot.state != CashuCustodyLotStateV1::DeliveryAcknowledged
            || !seen_lot_ids.insert(lot.lot_id)
            || !seen_note_sets.insert(lot.note_set_digest)
        {
            return Err("checkable Cashu retirement snapshot lot binding mismatch".to_owned());
        }
        value = value
            .checked_add(lot.settlement_value)
            .ok_or_else(|| "checkable Cashu retirement value overflow".to_owned())?;
        notes = notes
            .checked_add(u64::from(lot.note_count))
            .ok_or_else(|| "checkable Cashu retirement note count overflow".to_owned())?;
    }
    if value != snapshot.batch.settlement_value || notes != snapshot.batch.note_count {
        return Err("checkable Cashu retirement aggregate mismatch".to_owned());
    }
    Ok(())
}

fn prepare_retirement_export_v1(
    snapshot: &CashuCustodyRetirementCheckableSnapshotV1,
    decryptor: &ChaCha20Poly1305CustodyDecryptorV1,
    bundles: &mut Vec<CashuCustodyBundleV1>,
) -> Result<PreparedRetirementExportV1, String> {
    let artifact_digest = snapshot
        .batch
        .artifact
        .as_ref()
        .ok_or_else(|| "checkable Cashu retirement artifact is missing".to_owned())?
        .digest;
    let mut prepared_lots = Vec::with_capacity(snapshot.sealed_lots.len());
    for lot in &snapshot.sealed_lots {
        let aad = lot_cashu_custody_aad(lot)?;
        let mut sealed = CashuSealedCustodyV1 {
            key_epoch: lot.sealed_notes.key_epoch,
            nonce: lot.sealed_notes.nonce.clone(),
            ciphertext: lot.sealed_notes.ciphertext.clone(),
        };
        let opened = decryptor
            .open_bundle(&aad, &sealed)
            .map_err(|error| format!("decrypt acknowledged Cashu custody lot: {error}"));
        sealed.nonce.zeroize();
        sealed.ciphertext.zeroize();
        let bundle = opened?;
        if bundle.note_set_digest() != &lot.note_set_digest
            || u32::try_from(bundle.notes().len()).ok() != Some(lot.note_count)
            || bundle
                .notes()
                .iter()
                .try_fold(0u64, |sum, note| sum.checked_add(note.amount()))
                != Some(lot.settlement_value)
        {
            return Err("decrypted Cashu custody lot does not match durable metadata".to_owned());
        }
        prepared_lots.push(PreparedRetirementLotV1 {
            lot_id: lot.lot_id,
            note_set_digest: lot.note_set_digest,
            settlement_value: lot.settlement_value,
            note_count: lot.note_count,
            binding_digest: retirement_lot_binding_digest_v1(lot),
        });
        bundles.push(bundle);
    }
    Ok(PreparedRetirementExportV1 {
        export_id: snapshot.batch.export_id,
        artifact_digest,
        batch_binding_digest: retirement_batch_binding_digest_v1(&snapshot.batch),
        member_lot_ids: snapshot.member_lot_ids.clone(),
        lots: prepared_lots,
        settlement_value: snapshot.batch.settlement_value,
        note_count: snapshot.batch.note_count,
    })
}

fn bind_checked_retirement_exports_v1(
    prepared_exports: Vec<PreparedRetirementExportV1>,
    checked: pir_cashu_client::CashuNut07BatchResultV1,
) -> Result<Vec<CheckedRetirementExportV1>, String> {
    let mut per_export_digests = BTreeMap::new();
    for export in &prepared_exports {
        let note_sets = export
            .lots
            .iter()
            .map(|lot| lot.note_set_digest)
            .collect::<Vec<_>>();
        let digest = derive_cashu_nut07_export_observation_digest_v1(
            &checked,
            &export.export_id,
            &note_sets,
        )
        .map_err(|error| format!("derive per-export NUT-07 observation digest: {error}"))?;
        per_export_digests.insert(export.export_id, digest);
    }

    let mut checked_lots = BTreeMap::new();
    for lot in checked.into_lots() {
        let note_set_digest = *lot.note_set_digest();
        if checked_lots.insert(note_set_digest, lot).is_some() {
            return Err("NUT-07 result contains a duplicate lot".to_owned());
        }
    }
    let mut exports = Vec::with_capacity(prepared_exports.len());
    for prepared in prepared_exports {
        let mut lots = Vec::with_capacity(prepared.lots.len());
        for expected in &prepared.lots {
            let lot = checked_lots
                .remove(&expected.note_set_digest)
                .ok_or_else(|| "NUT-07 result is missing an exact export lot".to_owned())?;
            if lot.settlement_value() != expected.settlement_value
                || lot.note_count() != expected.note_count
                || !lot.all_spent()
                || lot
                    .checked_notes()
                    .iter()
                    .any(|note| note.state() != CashuNut07NoteStateV1::Spent)
            {
                return Err("NUT-07 lot result does not exactly match an all-SPENT lot".to_owned());
            }
            lots.push(lot);
        }
        let observation_digest = per_export_digests
            .remove(&prepared.export_id)
            .ok_or_else(|| "per-export NUT-07 observation digest is missing".to_owned())?;
        exports.push(CheckedRetirementExportV1 {
            prepared,
            lots,
            observation_digest,
        });
    }
    if !checked_lots.is_empty() || !per_export_digests.is_empty() {
        return Err("NUT-07 result contains lots outside the selected exports".to_owned());
    }
    Ok(exports)
}

fn confirm_checked_retirement_export_v1(
    store: &ProviderStore,
    provider_id: [u8; 32],
    store_instance_id: [u8; 16],
    checked: CheckedRetirementExportV1,
) -> Result<bool, String> {
    let fresh = store
        .cashu_custody_retirement_snapshot_owner_v1(&CashuCustodyRetirementSnapshotRequestV1 {
            provider_id,
            store_instance_id,
            export_id: checked.prepared.export_id,
        })
        .map_err(|error| format!("refresh Cashu retirement snapshot before write: {error}"))?;
    match fresh {
        CashuCustodyRetirementSnapshotV1::SpentConfirmed(completed) => {
            validate_completed_retirement_snapshot_v1(
                &completed,
                provider_id,
                store_instance_id,
                &checked.prepared.export_id,
            )?;
            if completed.export_id != checked.prepared.export_id
                || completed.artifact_digest != checked.prepared.artifact_digest
                || completed.settlement_value != checked.prepared.settlement_value
                || completed.note_count != checked.prepared.note_count
                || completed.evidence.nut07_response_digest != checked.observation_digest
            {
                return Err(
                    "Cashu export was concurrently retired with different immutable/evidence binding"
                        .to_owned(),
                );
            }
            Ok(false)
        }
        CashuCustodyRetirementSnapshotV1::Checkable(snapshot) => {
            validate_checkable_retirement_snapshot_v1(
                &snapshot,
                provider_id,
                store_instance_id,
                &checked.prepared.export_id,
            )?;
            if snapshot.batch.state != CashuCustodyExportStateV1::DeliveryAcknowledged
                || snapshot.member_lot_ids != checked.prepared.member_lot_ids
                || retirement_batch_binding_digest_v1(&snapshot.batch)
                    != checked.prepared.batch_binding_digest
                || snapshot.sealed_lots.len() != checked.prepared.lots.len()
                || snapshot.sealed_lots.iter().zip(&checked.prepared.lots).any(
                    |(fresh_lot, expected)| {
                        fresh_lot.lot_id != expected.lot_id
                            || fresh_lot.note_set_digest != expected.note_set_digest
                            || retirement_lot_binding_digest_v1(fresh_lot)
                                != expected.binding_digest
                    },
                )
            {
                return Err(
                    "Cashu export immutable membership/artifact changed after NUT-07 check"
                        .to_owned(),
                );
            }

            let expected_notes = usize::try_from(checked.prepared.note_count)
                .map_err(|_| "Cashu export note count does not fit memory bounds".to_owned())?;
            let mut note_checks = Vec::with_capacity(expected_notes);
            for (lot, expected) in checked.lots.into_iter().zip(&checked.prepared.lots) {
                if lot.note_set_digest() != &expected.note_set_digest {
                    return Err("checked Cashu lot order changed before confirmation".to_owned());
                }
                for note in lot.into_checked_notes() {
                    let (mut y, state) = note.into_sensitive_parts();
                    let store_state = match state {
                        CashuNut07NoteStateV1::Spent => CashuCustodyRetirementNoteStateV1::Spent,
                        CashuNut07NoteStateV1::Unspent => {
                            CashuCustodyRetirementNoteStateV1::Unspent
                        }
                        CashuNut07NoteStateV1::Pending => {
                            CashuCustodyRetirementNoteStateV1::Pending
                        }
                    };
                    note_checks.push(CashuCustodyRetirementNoteCheckV1 {
                        y,
                        state: store_state,
                    });
                    y.zeroize();
                }
            }
            if note_checks.len() != expected_notes
                || note_checks
                    .iter()
                    .any(|note| note.state != CashuCustodyRetirementNoteStateV1::Spent)
            {
                return Err("Cashu export is not exactly all-SPENT at confirmation".to_owned());
            }
            let request = CashuCustodySpentConfirmationRequestV1 {
                provider_id,
                store_instance_id,
                precondition_store_generation: snapshot.checked_identity.store_generation,
                precondition_spend_commit_seq: snapshot.checked_identity.spend_commit_seq,
                precondition_rollback_commitment: snapshot.checked_identity.rollback_commitment,
                export_id: checked.prepared.export_id,
                artifact_digest: checked.prepared.artifact_digest,
                member_lot_ids: checked.prepared.member_lot_ids,
                note_checks,
                // Despite the legacy field name this is intentionally an
                // export-specific observation digest, never the shared HTTP
                // batch digest.
                nut07_response_digest: checked.observation_digest,
            };
            let result = store
                .confirm_cashu_custody_export_spent_v1(&request)
                .map_err(|error| format!("atomically confirm Cashu export spent: {error}"))?;
            if result.evidence.export_id != request.export_id
                || result.evidence.provider_id != provider_id
                || result.evidence.store_instance_id != store_instance_id
                || result.evidence.artifact_digest != request.artifact_digest
                || result.evidence.nut07_response_digest != request.nut07_response_digest
                || result.evidence.note_count
                    != u64::try_from(request.note_checks.len()).unwrap_or(u64::MAX)
            {
                return Err("Cashu spent-confirm response evidence mismatch".to_owned());
            }
            Ok(result.confirmed)
        }
    }
}

fn retirement_batch_binding_digest_v1(batch: &CashuCustodyExportBatchV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BitcoinPIR/admin-cashu-retirement-batch-binding/v1");
    hasher.update(batch.export_id);
    hasher.update(batch.mint_id);
    hasher.update((batch.unit.len() as u32).to_le_bytes());
    hasher.update(batch.unit.as_bytes());
    hasher.update(batch.recipient_key_id);
    hasher.update(batch.requested_max_lots.to_le_bytes());
    hasher.update(batch.lot_count.to_le_bytes());
    hasher.update(batch.keyset_group_count.to_le_bytes());
    hasher.update(batch.settlement_value.to_le_bytes());
    hasher.update(batch.note_count.to_le_bytes());
    hasher.update([batch.state as u8]);
    if let Some(artifact) = &batch.artifact {
        hasher.update([1u8]);
        hasher.update(artifact.digest);
    } else {
        hasher.update([0u8]);
    }
    hasher.finalize().into()
}

fn retirement_lot_binding_digest_v1(lot: &pir_service_store::CashuCustodyLotV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BitcoinPIR/admin-cashu-retirement-lot-binding/v1");
    hasher.update(lot.lot_id);
    hasher.update(lot.mint_id);
    hasher.update(lot.manifest_digest);
    hasher.update(lot.active_keyset_digest);
    hasher.update(lot.note_set_digest);
    hasher.update((lot.unit.len() as u32).to_le_bytes());
    hasher.update(lot.unit.as_bytes());
    hasher.update(lot.settlement_value.to_le_bytes());
    hasher.update(lot.note_count.to_le_bytes());
    hasher.update([lot.state as u8]);
    hasher.update(lot.sealed_notes.key_epoch.to_le_bytes());
    hasher.update((lot.sealed_notes.nonce.len() as u32).to_le_bytes());
    hasher.update(&lot.sealed_notes.nonce);
    hasher.update((lot.sealed_notes.ciphertext.len() as u32).to_le_bytes());
    hasher.update(&lot.sealed_notes.ciphertext);
    hasher.finalize().into()
}

fn print_spent_confirm_summary_v1(
    provider_id: [u8; 32],
    cohort: &CashuRetirementCohortV1,
    summary: &SpentConfirmSummaryV1,
    contacted_mint: bool,
) -> Result<(), String> {
    println!("provider_id={}", hex::encode(provider_id));
    println!("mint_id={}", hex::encode(cohort.mint_id));
    println!("unit={}", cohort.unit);
    println!("requested_export_count={}", summary.requested_exports);
    println!("nut07_checked_export_count={}", summary.checked_exports);
    println!(
        "recorded_confirmation_count={}",
        summary.recorded_confirmations
    );
    println!("exact_replay_count={}", summary.exact_replays);
    println!("settlement_value={}", summary.settlement_value);
    println!("note_count={}", summary.note_count);
    println!("mint_contacted={contacted_mint}");
    println!("automatic_polling=false");
    println!("old_exported_notes_spent=true");
    println!("exposure_released=true");
    println!("settlement_proven=false");
    println!("nut05_settlement=false");
    println!("lightning_settlement=false");
    println!("provider_payout_proven=false");
    Ok(())
}

fn load_custody_decryptor(specs: &[String]) -> Result<ChaCha20Poly1305CustodyDecryptorV1, String> {
    let mut loaded = Vec::<(u64, [u8; 32])>::with_capacity(specs.len());
    let mut epochs = std::collections::BTreeSet::new();
    for spec in specs {
        let result = (|| {
            let (epoch, path) = spec.split_once('=').ok_or_else(|| {
                "--custody-key must be EPOCH=RAW_32_BYTE_OWNER_ONLY_PATH".to_owned()
            })?;
            let epoch = epoch
                .parse::<u64>()
                .map_err(|_| "--custody-key epoch must be a non-zero u64".to_owned())?;
            if epoch == 0 || path.is_empty() || !epochs.insert(epoch) {
                return Err(
                    "--custody-key epochs must be unique/non-zero and paths must be non-empty"
                        .to_owned(),
                );
            }
            let key_bytes =
                read_private_bounded(Path::new(path), 32, &format!("custody key epoch {epoch}"))?;
            if key_bytes.len() != 32 {
                return Err(format!(
                    "custody key epoch {epoch} must contain exactly 32 bytes"
                ));
            }
            let mut key = [0_u8; 32];
            key.copy_from_slice(&key_bytes);
            if key.iter().all(|byte| *byte == 0) {
                key.zeroize();
                return Err(format!("custody key epoch {epoch} is all zero"));
            }
            if loaded.iter().any(|(_, existing)| existing == &key) {
                key.zeroize();
                return Err(
                    "the same custody key bytes must not be assigned to multiple epochs".to_owned(),
                );
            }
            loaded.push((epoch, key));
            Ok(())
        })();
        if let Err(error) = result {
            for (_, key) in &mut loaded {
                key.zeroize();
            }
            return Err(error);
        }
    }
    ChaCha20Poly1305CustodyDecryptorV1::new(loaded)
        .map_err(|error| format!("invalid custody decryption keyring: {error:?}"))
}

fn lot_cashu_custody_aad(
    lot: &pir_service_store::CashuCustodyLotV1,
) -> Result<CashuCustodyAadV1, String> {
    CashuCustodyAadV1::from_parts(
        lot.lot_id,
        lot.mint_id,
        lot.manifest_digest,
        &lot.unit,
        lot.active_keyset_digest,
        lot.note_set_digest,
        lot.settlement_value,
        lot.note_count,
    )
    .map_err(|error| format!("reconstruct durable Cashu custody AAD: {error}"))
}

fn merge_cashu_custody_bundles(
    bundles: Vec<CashuCustodyBundleV1>,
) -> Result<Zeroizing<String>, String> {
    encode_cashub_from_custody_bundles_v1(&bundles)
        .map_err(|error| format!("encode canonical Cashu custody cashuB: {error}"))
}

fn open_provider_store(args: &ProviderStoreArgs) -> Result<(ProviderStore, [u8; 32]), String> {
    let provider_id = parse_nonzero_hex::<32>("--provider-id-hex", &args.provider_id_hex)?;
    if !(1..=60_000).contains(&args.busy_timeout_ms) {
        return Err("--busy-timeout-ms must be in 1..=60000".to_owned());
    }
    let store_path = crate::service_store_init::validate_existing_private_file_path(
        &args.store,
        "provider store",
    )?;
    let timeout = Duration::from_millis(args.busy_timeout_ms);
    let authority: Arc<dyn RollbackFloorAuthorityV1> =
        match crate::service_store_init::provider_rollback_authority_source_v1(
            args.rollback_authority.as_deref(),
            args.remote_rollback_authority_config.as_deref(),
        )? {
            crate::service_store_init::ProviderRollbackAuthoritySourceV1::LocalSqlite(path) => {
                eprintln!(
                    "warning: local SQLite provider rollback authority is development/test-only; use --remote-rollback-authority-config for production"
                );
                let authority_path =
                    crate::service_store_init::validate_existing_private_file_path(
                        path,
                        "provider rollback authority",
                    )?;
                if crate::service_store_init::private_database_paths_alias(
                    &store_path,
                    &authority_path,
                )? {
                    return Err(
                        "provider store and rollback authority resolve to the same file/inode"
                            .to_owned(),
                    );
                }
                Arc::new(
                    SqliteRollbackFloorAuthorityV1::open_existing(&authority_path, timeout)
                        .map_err(|error| format!("open provider rollback authority: {error}"))?,
                )
            }
            crate::service_store_init::ProviderRollbackAuthoritySourceV1::RemoteConfig(path) => {
                crate::service_store_init::open_remote_provider_rollback_authority_v1(
                    provider_id,
                    path,
                )?
            }
        };
    let store = ProviderStore::open_existing(
        &store_path,
        provider_id,
        StoreOptions {
            busy_timeout: timeout,
        },
        authority,
    )
    .map_err(|error| format!("open provider store: {error}"))?;
    Ok((store, provider_id))
}

fn validate_export_request(
    batch: &CashuCustodyExportBatchV1,
    export_id: [u8; 16],
    mint_id: [u8; 32],
    unit: &str,
    max_lots: u32,
    recipient_key_id: [u8; 32],
) -> Result<(), String> {
    if batch.export_id != export_id
        || batch.mint_id != mint_id
        || batch.unit != unit
        || batch.requested_max_lots != max_lots
        || batch.recipient_key_id != recipient_key_id
    {
        return Err("durable Cashu export does not match the exact immutable request".to_owned());
    }
    Ok(())
}

fn validate_cashub_for_batch(
    serialized: &str,
    batch: &CashuCustodyExportBatchV1,
) -> Result<(), String> {
    let token = CashuTokenV4V1::decode_cashub(serialized)
        .map_err(|error| format!("validate aggregated Cashu custody cashuB: {error}"))?;
    let canonical = token
        .encode_cashub()
        .map_err(|error| format!("re-encode aggregated Cashu custody cashuB: {error}"))?;
    let mut value = 0_u64;
    let mut note_count = 0_u64;
    for proof in token.groups().iter().flat_map(|group| group.proofs()) {
        value = value
            .checked_add(proof.amount())
            .ok_or_else(|| "aggregated Cashu custody value overflow".to_owned())?;
        note_count = note_count
            .checked_add(1)
            .ok_or_else(|| "aggregated Cashu custody note count overflow".to_owned())?;
    }
    if canonical.as_str() != serialized
        || pir_service_protocol::derive_cashu_mint_id(token.mint_endpoint()) != batch.mint_id
        || token.unit() != batch.unit.as_str()
        || usize::try_from(batch.keyset_group_count).ok() != Some(token.groups().len())
        || note_count != batch.note_count
        || value != batch.settlement_value
    {
        return Err("aggregated Cashu custody cashuB does not match its durable batch".to_owned());
    }
    Ok(())
}

fn validate_batch_artifact(
    batch: &CashuCustodyExportBatchV1,
    provider_id: [u8; 32],
) -> Result<(), String> {
    let artifact = batch
        .artifact
        .as_ref()
        .ok_or_else(|| "Cashu custody export has no persisted artifact to replay".to_owned())?;
    validate_stored_artifact(batch, provider_id, &artifact.bytes)
}

fn validate_stored_artifact(
    batch: &CashuCustodyExportBatchV1,
    provider_id: [u8; 32],
    bytes: &[u8],
) -> Result<(), String> {
    let artifact = batch
        .artifact
        .as_ref()
        .ok_or_else(|| "Cashu custody export artifact metadata is absent".to_owned())?;
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    if digest != artifact.digest || bytes != artifact.bytes {
        return Err("Cashu custody export artifact digest/bytes mismatch".to_owned());
    }
    let envelope = CashuCustodyEnvelopeV1::decode(bytes)
        .map_err(|error| format!("invalid durable Cashu custody envelope: {error}"))?;
    if envelope.export_id() != batch.export_id
        || envelope.provider_id() != provider_id
        || envelope.recipient_key_id() != batch.recipient_key_id
    {
        return Err("durable Cashu custody envelope binding mismatch".to_owned());
    }
    Ok(())
}

fn release_exact_artifact(path: &Path, batch: &CashuCustodyExportBatchV1) -> Result<(), String> {
    let bytes = batch
        .artifact
        .as_ref()
        .ok_or_else(|| "Cashu custody export has no persisted artifact".to_owned())?
        .bytes
        .as_slice();
    write_or_verify_exact_private(path, bytes).map(|_| ())
}

fn print_export_summary(batch: &CashuCustodyExportBatchV1, path: &Path) -> Result<(), String> {
    let artifact = batch
        .artifact
        .as_ref()
        .ok_or_else(|| "Cashu custody export summary has no persisted artifact".to_owned())?;
    println!("export_id={}", hex::encode(batch.export_id));
    println!("mint_id={}", hex::encode(batch.mint_id));
    println!("unit={}", batch.unit);
    println!("lot_count={}", batch.lot_count);
    println!("keyset_group_count={}", batch.keyset_group_count);
    println!("settlement_value={}", batch.settlement_value);
    println!("note_count={}", batch.note_count);
    println!("artifact_digest={}", hex::encode(artifact.digest));
    println!("recipient_key_id={}", hex::encode(batch.recipient_key_id));
    println!("artifact_file={}", path.display());
    println!(
        "custody_state={}",
        match batch.state {
            CashuCustodyExportStateV1::Reserved => "reserved",
            CashuCustodyExportStateV1::ArtifactStored => "artifact-stored",
            CashuCustodyExportStateV1::DeliveryAcknowledged => "delivery-acknowledged",
            CashuCustodyExportStateV1::SpentConfirmed => "spent-confirmed",
        }
    );
    println!(
        "exposure_released={}",
        batch.state == CashuCustodyExportStateV1::SpentConfirmed
    );
    println!("nut05_settlement=false");
    println!("provider_payout_proven=false");
    Ok(())
}

fn encode_recipient_secret_artifact(
    provider_id: [u8; 32],
    secret: &[u8; 32],
    recipient: &CashuCustodyRecipientSecretKeyV1,
) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0u8; RECIPIENT_SECRET_ARTIFACT_BYTES_V1]);
    bytes[..8].copy_from_slice(RECIPIENT_SECRET_MAGIC_V1);
    bytes[8..40].copy_from_slice(&provider_id);
    bytes[40..72].copy_from_slice(secret);
    bytes[72..].copy_from_slice(&recipient_provider_binding_digest(
        &provider_id,
        &recipient.public_key(),
    ));
    bytes
}

fn decode_recipient_secret_artifact(
    bytes: &[u8],
) -> Result<([u8; 32], CashuCustodyRecipientSecretKeyV1), String> {
    if bytes.len() != RECIPIENT_SECRET_ARTIFACT_BYTES_V1 || &bytes[..8] != RECIPIENT_SECRET_MAGIC_V1
    {
        return Err("invalid canonical recipient secret artifact".to_owned());
    }
    let provider_id: [u8; 32] = bytes[8..40]
        .try_into()
        .expect("fixed recipient secret provider slice");
    let mut secret: [u8; 32] = bytes[40..72]
        .try_into()
        .expect("fixed recipient secret key slice");
    let stored_binding: [u8; 32] = bytes[72..]
        .try_into()
        .expect("fixed recipient secret binding slice");
    let result = (|| {
        if provider_id.iter().all(|byte| *byte == 0) || secret.iter().all(|byte| *byte == 0) {
            return Err("recipient secret artifact contains a zero sentinel".to_owned());
        }
        let recipient = CashuCustodyRecipientSecretKeyV1::from_bytes(secret)
            .map_err(|error| format!("invalid recipient secret artifact: {error}"))?;
        if stored_binding.iter().all(|byte| *byte == 0)
            || stored_binding
                != recipient_provider_binding_digest(&provider_id, &recipient.public_key())
        {
            return Err("recipient secret artifact binding checksum mismatch".to_owned());
        }
        Ok((provider_id, recipient))
    })();
    secret.zeroize();
    result
}

fn recipient_provider_binding_digest(
    provider_id: &[u8; 32],
    public: &CashuCustodyRecipientPublicKeyV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BitcoinPIR/cashu-custody/recipient-secret-binding/v1");
    hasher.update(provider_id);
    hasher.update(public.to_bytes());
    hasher.finalize().into()
}

fn encode_recipient_public_artifact(
    provider_id: [u8; 32],
    public: &CashuCustodyRecipientPublicKeyV1,
) -> Vec<u8> {
    let mut bytes = vec![0u8; RECIPIENT_PUBLIC_ARTIFACT_BYTES_V1];
    bytes[..8].copy_from_slice(RECIPIENT_PUBLIC_MAGIC_V1);
    bytes[8..40].copy_from_slice(&provider_id);
    bytes[40..72].copy_from_slice(&public.to_bytes());
    bytes[72..104].copy_from_slice(&public.key_id());
    bytes[104..].copy_from_slice(&recipient_provider_binding_digest(&provider_id, public));
    bytes
}

fn decode_recipient_public_artifact(
    bytes: &[u8],
) -> Result<([u8; 32], CashuCustodyRecipientPublicKeyV1), String> {
    if bytes.len() != RECIPIENT_PUBLIC_ARTIFACT_BYTES_V1 || &bytes[..8] != RECIPIENT_PUBLIC_MAGIC_V1
    {
        return Err("invalid canonical recipient public artifact".to_owned());
    }
    let provider_id: [u8; 32] = bytes[8..40]
        .try_into()
        .expect("fixed recipient public provider slice");
    let public_bytes: [u8; 32] = bytes[40..72]
        .try_into()
        .expect("fixed recipient public key slice");
    let key_id: [u8; 32] = bytes[72..104]
        .try_into()
        .expect("fixed recipient public key ID slice");
    let binding: [u8; 32] = bytes[104..]
        .try_into()
        .expect("fixed recipient public binding slice");
    if provider_id.iter().all(|byte| *byte == 0) {
        return Err("recipient public artifact contains a zero provider".to_owned());
    }
    let public = CashuCustodyRecipientPublicKeyV1::from_bytes(public_bytes)
        .map_err(|error| format!("invalid recipient public key: {error}"))?;
    if public.key_id() != key_id
        || binding != recipient_provider_binding_digest(&provider_id, &public)
    {
        return Err("recipient public artifact key ID/binding mismatch".to_owned());
    }
    Ok((provider_id, public))
}

fn parse_nonzero_hex<const N: usize>(name: &str, value: &str) -> Result<[u8; N], String> {
    let parsed = crate::payment_artifact::parse_hex_exact::<N>(name, value)?;
    if parsed.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} must not be all zero"));
    }
    Ok(parsed)
}

fn validate_unit(unit: &str) -> Result<(), String> {
    pir_service_protocol::validate_cashu_unit_v1(unit)
        .map_err(|error| format!("invalid --unit: {error}"))
}

fn reject_same_output_path(first: &Path, second: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let first = open_private_target(first, "recipient secret output")?;
        let second = open_private_target(second, "recipient public output")?;
        if first.display_path == second.display_path {
            return Err("recipient secret and public outputs must be different paths".to_owned());
        }
        let first_stat = private_target_stat(&first, "recipient secret output")?;
        let second_stat = private_target_stat(&second, "recipient public output")?;
        match (first_stat, second_stat) {
            (Some(first), Some(second))
                if first.st_dev == second.st_dev && first.st_ino == second.st_ino =>
            {
                Err("recipient secret and public outputs resolve to the same inode".to_owned())
            }
            _ => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        if first == second {
            return Err("recipient secret and public outputs must be different paths".to_owned());
        }
        if first.exists()
            && second.exists()
            && crate::service_store_init::private_database_paths_alias(first, second)?
        {
            return Err("recipient secret and public outputs resolve to the same inode".to_owned());
        }
        Ok(())
    }
}

fn path_exists_no_symlink(path: &Path, label: &str) -> Result<bool, String> {
    #[cfg(unix)]
    {
        let target = open_private_target(path, label)?;
        open_private_regular(&target, label).map(|file| file.is_some())
    }
    #[cfg(not(unix))]
    {
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_file() && !metadata.file_type().is_symlink() =>
            {
                Ok(true)
            }
            Ok(_) => Err(format!(
                "{label} must be a non-symlink regular file: {}",
                path.display()
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("inspect {label} {}: {error}", path.display())),
        }
    }
}

#[cfg(unix)]
fn read_private_bounded(
    path: &Path,
    maximum: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let target = open_private_target(path, label)?;
    let mut file = open_private_regular(&target, label)?
        .ok_or_else(|| format!("{label} does not exist: {}", target.display_path.display()))?;
    read_open_private_bounded(&mut file, maximum, label, &target.display_path)
}

#[cfg(not(unix))]
fn read_private_bounded(
    _path: &Path,
    _maximum: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    Err(format!("{label} requires Unix owner and mode enforcement"))
}

#[cfg(unix)]
struct PrivateTarget {
    display_path: PathBuf,
    file_name: OsString,
    parent: fs::File,
}

#[cfg(unix)]
fn open_private_target(path: &Path, label: &str) -> Result<PrivateTarget, String> {
    use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    // Apply the shared production boundary first: every ancestor is pinned
    // without following symlinks, ownership/writability is checked, and the
    // final parent is exact mode 0700 with the platform ACL policy enforced.
    let checked_path = pir_private_files::prepare_private_parent_v1(path, false, label)?;
    let path = checked_path.as_path();
    let file_name = path
        .file_name()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{label} is not a file path: {}", path.display()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect {label} parent {}: {error}", parent.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(format!(
            "{label} parent must be a real directory owned by this user with mode 0700: {}",
            parent.display()
        ));
    }
    let absolute = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("resolve current directory for {label}: {error}"))?
            .join(parent)
    };
    let mut lexical = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => lexical.push(prefix.as_os_str()),
            Component::RootDir => lexical.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "{label} path must not contain a parent-directory component: {}",
                    path.display()
                ));
            }
            Component::Normal(value) => lexical.push(value),
        }
    }
    let canonical = fs::canonicalize(parent)
        .map_err(|error| format!("canonicalize {label} parent {}: {error}", parent.display()))?;
    if canonical != lexical {
        return Err(format!(
            "{label} parent path must not contain intermediate symlinks; use canonical path {}",
            canonical.display()
        ));
    }
    // Walk the canonical spelling one component at a time. Every lookup is
    // relative to the already-open directory and refuses symlinks. All later
    // target operations stay relative to the final fd, so replacing a checked
    // path cannot redirect a secret/token write.
    let root = rustix_fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("open filesystem root for {label}: {error}"))?;
    let mut directory = fs::File::from(root);
    for component in canonical.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => {
                let next = rustix_fs::openat(
                    &directory,
                    value,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| {
                    format!(
                        "open canonical {label} parent component {}: {error}",
                        value.to_string_lossy()
                    )
                })?;
                directory = fs::File::from(next);
            }
            Component::Prefix(_) | Component::ParentDir => {
                return Err(format!(
                    "canonical {label} parent is not an absolute normalized Unix path: {}",
                    canonical.display()
                ));
            }
        }
    }
    let canonical_metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("inspect canonical {label} parent: {error}"))?;
    let current = rustix_fs::stat(&canonical)
        .map_err(|error| format!("stat canonical {label} parent: {error}"))?;
    let opened = rustix_fs::fstat(&directory)
        .map_err(|error| format!("inspect opened canonical {label} parent: {error}"))?;
    if !FileType::from_raw_mode(opened.st_mode).is_dir()
        || opened.st_uid != rustix::process::geteuid().as_raw()
        || opened.st_mode & 0o7777 != 0o700
        || canonical_metadata.file_type().is_symlink()
        || !canonical_metadata.file_type().is_dir()
        || current.st_uid != opened.st_uid
        || current.st_dev != opened.st_dev
        || current.st_ino != opened.st_ino
    {
        return Err(format!(
            "canonical {label} parent must remain the same real owner-only directory: {}",
            canonical.display()
        ));
    }
    pir_private_files::reject_extended_acl_v1(
        &directory,
        &format!("{label} parent {}", canonical.display()),
    )?;
    Ok(PrivateTarget {
        display_path: canonical.join(&file_name),
        file_name,
        parent: directory,
    })
}

#[cfg(unix)]
fn open_private_regular(target: &PrivateTarget, label: &str) -> Result<Option<fs::File>, String> {
    use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};

    let fd = match rustix_fs::openat(
        &target.parent,
        &target.file_name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(format!(
                "open {label} {} without following symlinks: {error}",
                target.display_path.display()
            ));
        }
    };
    let stat = rustix_fs::fstat(&fd).map_err(|error| format!("inspect opened {label}: {error}"))?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_nlink != 1
        || (stat.st_mode & 0o7777 != 0o600 && stat.st_mode & 0o7777 != 0o400)
    {
        return Err(format!(
            "{label} must be a single-link regular file owned by this user with mode 0600/0400: {}",
            target.display_path.display()
        ));
    }
    pir_private_files::reject_extended_acl_v1(
        &fd,
        &format!("{label} file {}", target.display_path.display()),
    )?;
    Ok(Some(fs::File::from(fd)))
}

#[cfg(unix)]
fn private_target_stat(
    target: &PrivateTarget,
    label: &str,
) -> Result<Option<rustix::fs::Stat>, String> {
    use rustix::fs as rustix_fs;

    let Some(file) = open_private_regular(target, label)? else {
        return Ok(None);
    };
    let stat =
        rustix_fs::fstat(&file).map_err(|error| format!("inspect opened {label}: {error}"))?;
    Ok(Some(stat))
}

#[cfg(unix)]
fn read_open_private_bounded(
    file: &mut fs::File,
    maximum: usize,
    label: &str,
    display_path: &Path,
) -> Result<Zeroizing<Vec<u8>>, String> {
    use rustix::fs as rustix_fs;

    let stat = rustix_fs::fstat(&file)
        .map_err(|error| format!("inspect {label} {}: {error}", display_path.display()))?;
    if stat.st_size <= 0
        || match usize::try_from(stat.st_size) {
            Ok(size) => size > maximum,
            Err(_) => true,
        }
    {
        return Err(format!(
            "{label} must be non-empty and no larger than {maximum} bytes: {}",
            display_path.display()
        ));
    }
    let expected = usize::try_from(stat.st_size).expect("positive bounded private file size");
    // Fill one exact allocation. `read_to_end` probes EOF by reserving when a
    // Vec is full, which could abandon an unwiped allocation containing a
    // recipient secret, custody key, or bearer token.
    let mut bytes = Zeroizing::new(vec![0u8; expected]);
    file.read_exact(bytes.as_mut_slice())
        .map_err(|error| format!("read {label} {}: {error}", display_path.display()))?;
    let mut extra = Zeroizing::new([0u8; 1]);
    let extra_len = file
        .read(extra.as_mut_slice())
        .map_err(|error| format!("finish reading {label} {}: {error}", display_path.display()))?;
    extra.zeroize();
    let final_stat = rustix_fs::fstat(&file)
        .map_err(|error| format!("reinspect {label} {}: {error}", display_path.display()))?;
    if extra_len != 0
        || final_stat.st_dev != stat.st_dev
        || final_stat.st_ino != stat.st_ino
        || final_stat.st_uid != stat.st_uid
        || final_stat.st_nlink != stat.st_nlink
        || final_stat.st_mode != stat.st_mode
        || final_stat.st_size != stat.st_size
    {
        return Err(format!("{label} changed while it was read"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn write_or_verify_exact_private(path: &Path, bytes: &[u8]) -> Result<bool, String> {
    use rustix::fs::{self as rustix_fs, AtFlags, Mode, OFlags};

    if bytes.is_empty() {
        return Err("refusing to write an empty private artifact".to_owned());
    }
    let target = open_private_target(path, "private output")?;
    if let Some(mut file) = open_private_regular(&target, "existing private output")? {
        let existing = read_open_private_bounded(
            &mut file,
            bytes.len(),
            "existing private output",
            &target.display_path,
        )?;
        if existing.as_slice() == bytes {
            file.sync_all()
                .map_err(|error| format!("sync existing private output: {error}"))?;
            target
                .parent
                .sync_all()
                .map_err(|error| format!("sync existing private output directory: {error}"))?;
            return Ok(false);
        }
        return Err(format!(
            "{} already exists with different bytes; refusing to overwrite",
            target.display_path.display()
        ));
    }
    let file_name = target
        .file_name
        .to_str()
        .ok_or_else(|| "private output path must have a UTF-8 file name".to_owned())?;
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| format!("OS randomness unavailable for atomic output: {error}"))?;
    let temporary = format!(".{file_name}.{}.tmp", hex::encode(random));
    let result = (|| {
        let fd = rustix_fs::openat(
            &target.parent,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| format!("create private temporary output: {error}"))?;
        rustix_fs::fchmod(&fd, Mode::RUSR | Mode::WUSR)
            .map_err(|error| format!("set private temporary output permissions: {error}"))?;
        pir_private_files::clear_extended_acl_v1(&fd, "Cashu private temporary output")?;
        let mut file = fs::File::from(fd);
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("write private temporary output: {error}"))?;
        let stat = rustix_fs::fstat(&file)
            .map_err(|error| format!("inspect private temporary output: {error}"))?;
        let mode = stat.st_mode & 0o7777;
        if mode != 0o600 || stat.st_nlink != 1 {
            return Err(format!(
                "private temporary output mode/link count is unsafe (mode={mode:o}, nlink={})",
                stat.st_nlink
            ));
        }
        drop(file);
        rustix_fs::linkat(
            &target.parent,
            temporary.as_str(),
            &target.parent,
            &target.file_name,
            AtFlags::empty(),
        )
        .map_err(|error| {
            format!(
                "atomically create {} without replacement: {error}",
                target.display_path.display()
            )
        })?;
        rustix_fs::unlinkat(&target.parent, temporary.as_str(), AtFlags::empty())
            .map_err(|error| format!("remove private temporary link: {error}"))?;
        target
            .parent
            .sync_all()
            .map_err(|error| format!("sync private output directory: {error}"))?;
        Ok(true)
    })();
    if result.is_err() {
        let _ = rustix_fs::unlinkat(&target.parent, temporary.as_str(), AtFlags::empty());
    }
    result
}

#[cfg(unix)]
fn sync_private_file_and_parent(path: &Path) -> Result<(), String> {
    let target = open_private_target(path, "existing private output")?;
    let file = open_private_regular(&target, "existing private output")?
        .ok_or_else(|| "existing private output disappeared before durability sync".to_owned())?;
    file.sync_all()
        .map_err(|error| format!("sync existing private output: {error}"))?;
    target
        .parent
        .sync_all()
        .map_err(|error| format!("sync existing private output directory: {error}"))
}

#[cfg(not(unix))]
fn sync_private_file_and_parent(_path: &Path) -> Result<(), String> {
    Err("Cashu custody keys require Unix durability and owner-only semantics".to_owned())
}

#[cfg(not(unix))]
fn write_or_verify_exact_private(_path: &Path, _bytes: &[u8]) -> Result<bool, String> {
    Err("Cashu custody artifacts require Unix atomic owner-only output semantics".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde::{Deserialize, Serialize};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(unix)]
    fn private_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: CashuCustodyArgs,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TestNut07RequestV1 {
        #[serde(rename = "Ys")]
        ys: Vec<String>,
    }

    #[derive(Serialize)]
    struct TestNut07ResponseV1 {
        states: Vec<TestNut07StateV1>,
    }

    #[derive(Serialize)]
    struct TestNut07StateV1 {
        #[serde(rename = "Y")]
        y: String,
        state: &'static str,
        witness: Option<String>,
    }

    struct TestNut07TransportV1 {
        state: &'static str,
        calls: AtomicUsize,
    }

    impl Default for TestNut07TransportV1 {
        fn default() -> Self {
            Self {
                state: "SPENT",
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl TestNut07TransportV1 {
        fn unspent() -> Self {
            Self {
                state: "UNSPENT",
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl CashuMintTransportV1 for TestNut07TransportV1 {
        fn post_json(
            &self,
            trust: CashuMintTrustV1<'_>,
            route: CashuMintRouteV1,
            request_json: &[u8],
            max_response_bytes: usize,
        ) -> Result<Vec<u8>, CashuMintTransportFailureV1> {
            assert_eq!(trust.mint_endpoint(), "https://mint.example");
            assert_eq!(trust.leaf_spki_sha256_pins(), &[[0x31; 32]]);
            assert_eq!(route, CashuMintRouteV1::CheckState);
            assert!(max_response_bytes >= request_json.len());
            self.calls.fetch_add(1, Ordering::SeqCst);
            let request: TestNut07RequestV1 = serde_json::from_slice(request_json).unwrap();
            assert!(!request.ys.is_empty());
            serde_json::to_vec(&TestNut07ResponseV1 {
                states: request
                    .ys
                    .into_iter()
                    .map(|y| TestNut07StateV1 {
                        y,
                        state: self.state,
                        witness: None,
                    })
                    .collect(),
            })
            .map_err(|_| {
                CashuMintTransportFailureV1::ambiguous(
                    CashuMintTransportFailureKindV1::HttpError,
                    None,
                )
            })
        }
    }

    #[test]
    fn help_contains_all_custody_operations_and_settlement_warning() {
        use clap::CommandFactory;
        TestCli::command().debug_assert();
        let help = TestCli::command().render_long_help().to_string();
        for operation in [
            "recipient-keygen",
            "inventory",
            "export-prepare",
            "export-replay",
            "decrypt",
            "acknowledge",
            "spent-confirm",
        ] {
            assert!(help.contains(operation), "missing {operation}");
        }
        let provider_id = hex::encode([1u8; 32]);
        let export_id = hex::encode([2u8; 16]);
        let artifact_digest = hex::encode([3u8; 32]);
        let parsed = TestCli::try_parse_from([
            "cashu-custody",
            "acknowledge",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
            "--rollback-authority",
            "/independent/floor.sqlite3",
            "--export-id-hex",
            &export_id,
            "--artifact-digest-hex",
            &artifact_digest,
        ])
        .unwrap();
        let CashuCustodyCommand::Acknowledge(args) = parsed.args.command else {
            panic!("wrong subcommand");
        };
        assert!(!args.confirm_external_wallet_took_custody_not_settlement);

        assert!(TestCli::try_parse_from([
            "cashu-custody",
            "acknowledge",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
            "--export-id-hex",
            &export_id,
            "--artifact-digest-hex",
            &artifact_digest,
        ])
        .is_err());
        assert!(TestCli::try_parse_from([
            "cashu-custody",
            "acknowledge",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
            "--rollback-authority",
            "/independent/floor.sqlite3",
            "--remote-rollback-authority-config",
            "/private/remote.toml",
            "--export-id-hex",
            &export_id,
            "--artifact-digest-hex",
            &artifact_digest,
        ])
        .is_err());
        let remote = TestCli::try_parse_from([
            "cashu-custody",
            "acknowledge",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
            "--remote-rollback-authority-config",
            "/private/remote.toml",
            "--export-id-hex",
            &export_id,
            "--artifact-digest-hex",
            &artifact_digest,
        ])
        .unwrap();
        assert!(matches!(
            remote.args.command,
            CashuCustodyCommand::Acknowledge(_)
        ));

        let parsed = TestCli::try_parse_from([
            "cashu-custody",
            "spent-confirm",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
            "--rollback-authority",
            "/independent/floor.sqlite3",
            "--export-id-hex",
            &export_id,
        ])
        .unwrap();
        let CashuCustodyCommand::SpentConfirm(args) = parsed.args.command else {
            panic!("wrong subcommand");
        };
        assert!(args.custody_key_specs.is_empty());
        assert!(!args.confirm_nut07_old_notes_spent_not_settlement_or_payout);
    }

    #[test]
    fn unit_validation_matches_the_shared_cashu_manifest_grammar() {
        for unit in ["sat", "usd1", "usd_1"] {
            validate_unit(unit).unwrap();
        }
        for unit in ["", "USD", "usd-1", "usd 1"] {
            assert!(
                validate_unit(unit).is_err(),
                "accepted invalid unit {unit:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn recipient_keygen_is_provider_bound_owner_only_and_idempotent() {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_tempdir();
        let root = fs::canonicalize(directory.path()).unwrap();
        let secret = root.join("recipient.secret");
        let public = root.join("recipient.public");
        let make_args = || RecipientKeygenArgs {
            provider_id_hex: hex::encode([7u8; 32]),
            secret_out: secret.clone(),
            public_out: public.clone(),
        };
        recipient_keygen(make_args()).unwrap();
        let first_secret = read_private_bounded(
            &secret,
            RECIPIENT_SECRET_ARTIFACT_BYTES_V1,
            "test recipient secret",
        )
        .unwrap();
        let first_public = read_private_bounded(
            &public,
            RECIPIENT_PUBLIC_ARTIFACT_BYTES_V1,
            "test recipient public",
        )
        .unwrap();
        recipient_keygen(make_args()).unwrap();
        assert_eq!(fs::read(&secret).unwrap(), first_secret.as_slice());
        assert_eq!(fs::read(&public).unwrap(), first_public.as_slice());
        fs::remove_file(&public).unwrap();
        recipient_keygen(make_args()).unwrap();
        assert_eq!(fs::read(&public).unwrap(), first_public.as_slice());
        assert_eq!(
            fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&public).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let wrong = RecipientKeygenArgs {
            provider_id_hex: hex::encode([8u8; 32]),
            secret_out: secret,
            public_out: public,
        };
        assert!(recipient_keygen(wrong)
            .unwrap_err()
            .contains("another provider"));
    }

    #[cfg(unix)]
    #[test]
    fn atomic_private_output_never_overwrites_different_bytes() {
        let directory = private_tempdir();
        let root = fs::canonicalize(directory.path()).unwrap();
        let path = root.join("artifact");
        assert!(write_or_verify_exact_private(&path, b"first").unwrap());
        assert!(!write_or_verify_exact_private(&path, b"first").unwrap());
        assert!(write_or_verify_exact_private(&path, b"second")
            .unwrap_err()
            .contains("refusing to overwrite"));
        assert_eq!(fs::read(path).unwrap(), b"first");
    }

    #[cfg(unix)]
    #[test]
    fn private_output_rejects_an_intermediate_parent_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = private_tempdir();
        let root = fs::canonicalize(directory.path()).unwrap();
        let real = root.join("real");
        let private = real.join("private");
        fs::create_dir(&real).unwrap();
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&real, root.join("alias")).unwrap();

        let error = write_or_verify_exact_private(
            &root.join("alias/private/recipient.secret"),
            b"never-follow-this-alias",
        )
        .unwrap_err();
        assert!(!error.is_empty());
        assert!(!private.join("recipient.secret").exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_output_never_follows_a_final_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = private_tempdir();
        let root = fs::canonicalize(directory.path()).unwrap();
        let victim = root.join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
        let output = root.join("recipient.secret");
        symlink(&victim, &output).unwrap();

        assert!(write_or_verify_exact_private(&output, b"replacement").is_err());
        assert_eq!(fs::read(victim).unwrap(), b"unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn private_input_rejects_hardlinks_and_fifo_without_blocking() {
        use std::process::Command;

        let directory = private_tempdir();
        let path = directory.path().join("recipient.secret");
        write_or_verify_exact_private(&path, b"secret bytes").unwrap();
        let hardlink = directory.path().join("recipient-hardlink.secret");
        fs::hard_link(&path, &hardlink).unwrap();
        for candidate in [&path, &hardlink] {
            assert!(read_private_bounded(candidate, 64, "test private input").is_err());
        }

        let fifo = directory.path().join("recipient-fifo.secret");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_private_bounded(&fifo, 64, "test private input").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_output_rejects_a_non_private_parent() {
        let directory = private_tempdir();
        let parent = directory.path().join("unsafe");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o770)).unwrap();
        let output = parent.join("recipient.secret");

        assert!(write_or_verify_exact_private(&output, b"never written").is_err());
        assert!(!output.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_output_rejects_parent_acl_before_creating_a_file() {
        use std::process::Command;

        let directory = private_tempdir();
        assert!(Command::new("chmod")
            .args(["+a", "everyone allow read,file_inherit"])
            .arg(directory.path())
            .status()
            .unwrap()
            .success());
        let output = directory.path().join("recipient.secret");

        assert!(write_or_verify_exact_private(&output, b"never written").is_err());
        assert!(!output.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_input_and_idempotent_output_reject_an_existing_file_acl() {
        use std::process::Command;

        let directory = private_tempdir();
        let path = directory.path().join("recipient.secret");
        write_or_verify_exact_private(&path, b"secret bytes").unwrap();
        assert!(Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .status()
            .unwrap()
            .success());

        assert!(read_private_bounded(&path, 64, "test private input").is_err());
        assert!(write_or_verify_exact_private(&path, b"secret bytes").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"secret bytes");
    }

    #[test]
    fn recipient_secret_artifact_detects_key_corruption_without_public_file() {
        let raw = [0x19_u8; 32];
        let recipient = CashuCustodyRecipientSecretKeyV1::from_bytes(raw).unwrap();
        let mut artifact = encode_recipient_secret_artifact([0x29; 32], &raw, &recipient);
        artifact[41] ^= 1;
        let error = match decode_recipient_secret_artifact(&artifact) {
            Ok(_) => panic!("corrupted recipient secret artifact was accepted"),
            Err(error) => error,
        };
        assert!(error.contains("checksum mismatch"));

        let public = recipient.public_key();
        let mut public_artifact = encode_recipient_public_artifact([0x29; 32], &public);
        public_artifact[8] ^= 1;
        let error = match decode_recipient_public_artifact(&public_artifact) {
            Ok(_) => panic!("corrupted recipient public artifact was accepted"),
            Err(error) => error,
        };
        assert!(error.contains("binding mismatch"));
    }

    #[cfg(unix)]
    #[derive(Serialize)]
    struct TestCustodyNote<'a> {
        amount: u64,
        secret: &'a str,
        c: Vec<u8>,
        y_digest: [u8; 32],
    }

    #[cfg(unix)]
    #[derive(Serialize)]
    struct TestCustodyBundle<'a> {
        version: u8,
        mint_endpoint: &'a str,
        manifest_digest: [u8; 32],
        leaf_spki_sha256_pins: Vec<[u8; 32]>,
        unit: &'a str,
        active_keyset_id: &'a str,
        note_set_digest: [u8; 32],
        notes: Vec<TestCustodyNote<'a>>,
    }

    #[cfg(unix)]
    fn digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(value);
        hasher.finalize().into()
    }

    #[cfg(unix)]
    fn test_custody_bundle_v1(amount: u64, seed: u64) -> CashuCustodyBundleV1 {
        use pir_payment_crypto::cashu_hash_to_curve_v1;

        let mint_endpoint = "https://mint.example";
        let mint_id = pir_service_protocol::derive_cashu_mint_id(mint_endpoint);
        let active_keyset_id = format!("01{}", "11".repeat(32));
        let secret = format!("{seed:064x}");
        let y = cashu_hash_to_curve_v1(secret.as_bytes()).unwrap();
        let mut y_hasher = Sha256::new();
        y_hasher.update(b"BitcoinPIR/cashu-custody-note-y/v1");
        y_hasher.update(mint_id);
        y_hasher.update(y);
        let y_digest: [u8; 32] = y_hasher.finalize().into();
        let mut set_hasher = Sha256::new();
        set_hasher.update(b"BitcoinPIR/cashu-custody-note-set/v1");
        set_hasher.update(1_u32.to_le_bytes());
        set_hasher.update(y_digest);
        let note_set_digest: [u8; 32] = set_hasher.finalize().into();
        let encoded = serde_json::to_vec(&TestCustodyBundle {
            version: 1,
            mint_endpoint,
            manifest_digest: [0x31; 32],
            leaf_spki_sha256_pins: vec![[0x31; 32]],
            unit: "sat",
            active_keyset_id: &active_keyset_id,
            note_set_digest,
            notes: vec![TestCustodyNote {
                amount,
                secret: &secret,
                c: vec![0x02_u8; 33],
                y_digest,
            }],
        })
        .unwrap();
        CashuCustodyBundleV1::decode_canonical(&encoded).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn multi_export_binding_uses_one_nut07_call_and_exact_lot_mapping() {
        let bundles = vec![
            test_custody_bundle_v1(2, 2),
            test_custody_bundle_v1(3, 3),
            test_custody_bundle_v1(5, 5),
        ];
        let note_sets = bundles
            .iter()
            .map(|bundle| *bundle.note_set_digest())
            .collect::<Vec<_>>();
        let prepared = vec![
            PreparedRetirementExportV1 {
                export_id: [0x31; 16],
                artifact_digest: [0x41; 32],
                batch_binding_digest: [0x51; 32],
                member_lot_ids: vec![[0x61; 16], [0x62; 16]],
                lots: vec![
                    PreparedRetirementLotV1 {
                        lot_id: [0x61; 16],
                        note_set_digest: note_sets[2],
                        settlement_value: 5,
                        note_count: 1,
                        binding_digest: [0x71; 32],
                    },
                    PreparedRetirementLotV1 {
                        lot_id: [0x62; 16],
                        note_set_digest: note_sets[0],
                        settlement_value: 2,
                        note_count: 1,
                        binding_digest: [0x72; 32],
                    },
                ],
                settlement_value: 7,
                note_count: 2,
            },
            PreparedRetirementExportV1 {
                export_id: [0x32; 16],
                artifact_digest: [0x42; 32],
                batch_binding_digest: [0x52; 32],
                member_lot_ids: vec![[0x63; 16]],
                lots: vec![PreparedRetirementLotV1 {
                    lot_id: [0x63; 16],
                    note_set_digest: note_sets[1],
                    settlement_value: 3,
                    note_count: 1,
                    binding_digest: [0x73; 32],
                }],
                settlement_value: 3,
                note_count: 1,
            },
        ];
        let transport = TestNut07TransportV1::default();
        let checked = check_cashu_custody_bundles_once_v1(&transport, &bundles).unwrap();
        assert_eq!(transport.calls(), 1);
        let bound = bind_checked_retirement_exports_v1(prepared, checked).unwrap();
        assert_eq!(bound.len(), 2);
        assert_eq!(bound[0].prepared.export_id, [0x31; 16]);
        assert_eq!(bound[1].prepared.export_id, [0x32; 16]);
        assert_eq!(bound[0].lots[0].note_set_digest(), &note_sets[2]);
        assert_eq!(bound[0].lots[1].note_set_digest(), &note_sets[0]);
        assert_eq!(bound[1].lots[0].note_set_digest(), &note_sets[1]);
        assert_ne!(bound[0].observation_digest, bound[1].observation_digest);
    }

    #[cfg(unix)]
    fn initialized_store(root: &Path, provider_id: [u8; 32]) -> (ProviderStoreArgs, ProviderStore) {
        use std::os::unix::fs::PermissionsExt;

        let store_parent = root.join("provider-store");
        let floor_parent = root.join("provider-floor");
        fs::create_dir(&store_parent).unwrap();
        fs::create_dir(&floor_parent).unwrap();
        fs::set_permissions(&store_parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&floor_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let store = store_parent.join("admission.sqlite3");
        let rollback_authority = floor_parent.join("floor.sqlite3");
        crate::service_store_init::run(crate::service_store_init::ServiceStoreInitArgs {
            provider_id_hex: hex::encode(provider_id),
            store: store.clone(),
            rollback_authority: Some(rollback_authority.clone()),
            remote_rollback_authority_config: None,
            store_instance_id_hex: None,
            busy_timeout_ms: 1_000,
        })
        .unwrap();
        let args = ProviderStoreArgs {
            provider_id_hex: hex::encode(provider_id),
            store,
            rollback_authority: Some(rollback_authority),
            remote_rollback_authority_config: None,
            busy_timeout_ms: 1_000,
        };
        let opened = open_provider_store(&args).unwrap().0;
        (args, opened)
    }

    #[cfg(unix)]
    #[test]
    fn full_offline_export_recovery_decrypt_ack_and_spent_confirm_flow() {
        use pir_cashu_client::{CashuCustodyCipherV1, ChaCha20Poly1305CustodyCipherV1};
        use pir_payment_crypto::cashu_hash_to_curve_v1;
        use pir_service_store::{
            CashuCustodyExposureLimitsV1, CashuCustodySealedBlobV1, CashuSwapSealedRecoveryV1,
            NewCashuCustodyLotV1, NewCashuSwapIntentV1,
        };
        use std::os::unix::fs::PermissionsExt;

        let directory = private_tempdir();
        let root = fs::canonicalize(directory.path()).unwrap();
        let provider_id = [0x21_u8; 32];
        let (store_args, store) = initialized_store(&root, provider_id);

        let mint_endpoint = "https://mint.example";
        let mint_id = pir_service_protocol::derive_cashu_mint_id(mint_endpoint);
        let unit = "sat";
        let active_keyset_id = format!("01{}", "11".repeat(32));
        let manifest_digest = [0x31_u8; 32];
        let secret = format!("{}01", "00".repeat(31));
        let y = cashu_hash_to_curve_v1(secret.as_bytes()).unwrap();
        let mut y_hasher = Sha256::new();
        y_hasher.update(b"BitcoinPIR/cashu-custody-note-y/v1");
        y_hasher.update(mint_id);
        y_hasher.update(y);
        let y_digest: [u8; 32] = y_hasher.finalize().into();
        let mut set_hasher = Sha256::new();
        set_hasher.update(b"BitcoinPIR/cashu-custody-note-set/v1");
        set_hasher.update(1_u32.to_le_bytes());
        set_hasher.update(y_digest);
        let note_set_digest: [u8; 32] = set_hasher.finalize().into();
        let unit_digest = digest(b"BitcoinPIR/cashu-unit/v1", unit.as_bytes());
        let active_keyset_digest = digest(
            b"BitcoinPIR/cashu-custody-keyset/v1",
            active_keyset_id.as_bytes(),
        );
        let settlement_value = 1_u64;
        let note_count = 1_u32;
        let mut lot_hasher = Sha256::new();
        lot_hasher.update(b"BitcoinPIR/cashu-custody-lot-id/v1");
        lot_hasher.update(mint_id);
        lot_hasher.update(manifest_digest);
        lot_hasher.update(unit_digest);
        lot_hasher.update(active_keyset_digest);
        lot_hasher.update(note_set_digest);
        lot_hasher.update(settlement_value.to_le_bytes());
        lot_hasher.update(note_count.to_le_bytes());
        let lot_digest: [u8; 32] = lot_hasher.finalize().into();
        let lot_id: [u8; 16] = lot_digest[..16].try_into().unwrap();
        let aad = CashuCustodyAadV1::from_parts(
            lot_id,
            mint_id,
            manifest_digest,
            unit,
            active_keyset_digest,
            note_set_digest,
            settlement_value,
            note_count,
        )
        .unwrap();
        let bundle_json = serde_json::to_vec(&TestCustodyBundle {
            version: 1,
            mint_endpoint,
            manifest_digest,
            leaf_spki_sha256_pins: vec![[0x31; 32]],
            unit,
            active_keyset_id: &active_keyset_id,
            note_set_digest,
            notes: vec![TestCustodyNote {
                amount: settlement_value,
                secret: &secret,
                c: vec![0x02_u8; 33],
                y_digest,
            }],
        })
        .unwrap();
        let bundle = CashuCustodyBundleV1::decode_canonical(&bundle_json).unwrap();
        let canonical_bundle = bundle.encode_canonical().unwrap();
        assert_eq!(canonical_bundle.as_slice(), bundle_json);

        let custody_key = [0x41_u8; 32];
        let custody_cipher = ChaCha20Poly1305CustodyCipherV1::new(7, [(7, custody_key)]).unwrap();
        let mut sealed = custody_cipher.seal(&aad, &canonical_bundle).unwrap();
        let recovery = CashuSwapSealedRecoveryV1 {
            key_epoch: 3,
            nonce: vec![0x51; 24],
            ciphertext: vec![0x52; 32],
        };
        let intent_id = [0x61_u8; 16];
        store
            .insert_cashu_swap_intent_v1(
                &NewCashuSwapIntentV1 {
                    intent_id,
                    mint_id,
                    manifest_digest,
                    unit: unit.to_owned(),
                    input_set_digest: [0x62; 32],
                    request_digest: [0x63; 32],
                    output_set_digest: [0x64; 32],
                    offer_binding_digest: [0x65; 32],
                    settlement_value,
                    expected_output_count: note_count,
                    sealed_recovery: recovery.clone(),
                    created_bucket: 1,
                },
                CashuCustodyExposureLimitsV1 {
                    max_unsettled_value: 10,
                    max_unsettled_notes: 10,
                },
            )
            .unwrap();
        assert!(store.begin_cashu_swap_submission_v1(&intent_id, 2).unwrap());
        assert!(store
            .commit_cashu_swap_wallet_v1(&intent_id, &recovery, 3)
            .unwrap());
        assert!(
            store
                .claim_cashu_swap_grant_once_v1(
                    &intent_id,
                    &NewCashuCustodyLotV1 {
                        lot_id,
                        manifest_digest,
                        active_keyset_digest,
                        note_set_digest,
                        note_ys: vec![y],
                        sealed_notes: CashuCustodySealedBlobV1 {
                            key_epoch: sealed.key_epoch,
                            nonce: std::mem::take(&mut sealed.nonce),
                            ciphertext: std::mem::take(&mut sealed.ciphertext),
                        },
                    },
                    4,
                )
                .unwrap()
                .issued
        );

        let recipient_secret = root.join("recipient.secret");
        let recipient_public = root.join("recipient.public");
        recipient_keygen(RecipientKeygenArgs {
            provider_id_hex: hex::encode(provider_id),
            secret_out: recipient_secret.clone(),
            public_out: recipient_public.clone(),
        })
        .unwrap();
        let custody_key_path = root.join("custody.key");
        write_or_verify_exact_private(&custody_key_path, &custody_key).unwrap();

        let export_id = [0x71_u8; 16];
        let failed_out = root.join("missing-private-parent/export.bin");
        let prepare = |recipient_public: PathBuf, out: PathBuf| ExportPrepareArgs {
            store: store_args.clone(),
            export_id_hex: hex::encode(export_id),
            mint_id_hex: hex::encode(mint_id),
            unit: unit.to_owned(),
            max_lots: 1,
            recipient_public,
            custody_key_specs: vec![format!("7={}", custody_key_path.display())],
            out,
        };
        let release_error =
            export_prepare(prepare(recipient_public.clone(), failed_out)).unwrap_err();
        assert!(release_error.contains("output parent"), "{release_error}");
        let persisted = store.cashu_custody_export_v1(&export_id).unwrap().unwrap();
        assert_eq!(persisted.state, CashuCustodyExportStateV1::ArtifactStored);
        let artifact_digest = persisted.artifact.as_ref().unwrap().digest;
        let envelope =
            CashuCustodyEnvelopeV1::decode(&persisted.artifact.as_ref().unwrap().bytes).unwrap();
        assert_eq!(envelope.recipient_key_id(), persisted.recipient_key_id);

        let other_secret = root.join("other-recipient.secret");
        let other_public = root.join("other-recipient.public");
        recipient_keygen(RecipientKeygenArgs {
            provider_id_hex: hex::encode(provider_id),
            secret_out: other_secret.clone(),
            public_out: other_public.clone(),
        })
        .unwrap();
        let wrong_recipient_out = root.join("wrong-recipient-export.bin");
        let conflict =
            export_prepare(prepare(other_public, wrong_recipient_out.clone())).unwrap_err();
        assert!(conflict.contains("conflict"), "{conflict}");
        assert!(!wrong_recipient_out.exists());

        let artifact_path = root.join("export.bin");
        export_prepare(prepare(recipient_public.clone(), artifact_path.clone())).unwrap();
        assert_eq!(
            fs::read(&artifact_path).unwrap(),
            persisted.artifact.as_ref().unwrap().bytes
        );
        let replay_path = root.join("export-replay.bin");
        export_replay(ExportReplayArgs {
            store: store_args.clone(),
            export_id_hex: hex::encode(export_id),
            out: replay_path.clone(),
        })
        .unwrap();
        assert_eq!(
            fs::read(&artifact_path).unwrap(),
            fs::read(&replay_path).unwrap()
        );
        assert_eq!(
            fs::metadata(&artifact_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&replay_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let wrong_token_path = root.join("wrong-recipient.token");
        let wrong_recipient = decrypt(DecryptArgs {
            artifact: replay_path.clone(),
            recipient_secret: other_secret,
            out: wrong_token_path.clone(),
        })
        .unwrap_err();
        assert!(
            wrong_recipient.contains("recipient key ID"),
            "{wrong_recipient}"
        );
        assert!(!wrong_token_path.exists());

        let token_path = root.join("cashu.token");
        decrypt(DecryptArgs {
            artifact: replay_path,
            recipient_secret,
            out: token_path.clone(),
        })
        .unwrap();
        let token_bytes = Zeroizing::new(fs::read(&token_path).unwrap());
        let token_text = std::str::from_utf8(&token_bytes).unwrap();
        let token = CashuTokenV4V1::decode_cashub(token_text).unwrap();
        assert_eq!(token.mint_endpoint(), mint_endpoint);
        assert_eq!(token.unit(), unit);
        assert_eq!(token.groups().len(), 1);
        assert_eq!(token.groups()[0].proofs().len(), 1);
        assert_eq!(token.groups()[0].proofs()[0].amount(), settlement_value);
        assert_eq!(
            fs::metadata(&token_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let ack = || AcknowledgeArgs {
            store: store_args.clone(),
            export_id_hex: hex::encode(export_id),
            artifact_digest_hex: hex::encode(artifact_digest),
            confirm_external_wallet_took_custody_not_settlement: true,
        };
        let wrong_ack = AcknowledgeArgs {
            store: store_args.clone(),
            export_id_hex: hex::encode(export_id),
            artifact_digest_hex: hex::encode([0x81_u8; 32]),
            confirm_external_wallet_took_custody_not_settlement: true,
        };
        assert!(acknowledge(wrong_ack)
            .unwrap_err()
            .contains("does not match the durable exact artifact"));
        assert_eq!(
            store
                .cashu_custody_export_v1(&export_id)
                .unwrap()
                .unwrap()
                .state,
            CashuCustodyExportStateV1::ArtifactStored
        );
        acknowledge(ack()).unwrap();
        acknowledge(ack()).unwrap();
        let acknowledged = store.cashu_custody_export_v1(&export_id).unwrap().unwrap();
        assert_eq!(
            acknowledged.state,
            CashuCustodyExportStateV1::DeliveryAcknowledged
        );
        let inventory = store.cashu_custody_inventory_v1(&mint_id, unit).unwrap();
        assert_eq!(inventory.available_value, 0);
        assert_eq!(inventory.reserved_value, 0);
        assert_eq!(inventory.acknowledged_lot_count, 1);
        assert_eq!(inventory.acknowledged_export_count, 1);

        let spent_confirm_args =
            |custody_key_specs: Vec<String>, confirmed: bool| SpentConfirmArgs {
                store: store_args.clone(),
                export_id_hexes: vec![hex::encode(export_id)],
                custody_key_specs,
                connect_timeout_ms: 1_000,
                io_timeout_ms: 1_000,
                confirm_nut07_old_notes_spent_not_settlement_or_payout: confirmed,
            };
        let transport = TestNut07TransportV1::default();
        let warning_error = spent_confirm_with_transport(
            spent_confirm_args(vec![format!("7={}", custody_key_path.display())], false),
            &transport,
        )
        .unwrap_err();
        assert!(warning_error.contains("proves only"), "{warning_error}");
        assert_eq!(transport.calls(), 0);

        let missing_key_error =
            spent_confirm_with_transport(spent_confirm_args(Vec::new(), true), &transport)
                .unwrap_err();
        assert!(
            missing_key_error.contains("at least one --custody-key"),
            "{missing_key_error}"
        );
        assert_eq!(transport.calls(), 0);

        let unspent_transport = TestNut07TransportV1::unspent();
        let unspent_error = spent_confirm_with_transport(
            spent_confirm_args(vec![format!("7={}", custody_key_path.display())], true),
            &unspent_transport,
        )
        .unwrap_err();
        assert!(
            unspent_error.contains("did not report all"),
            "{unspent_error}"
        );
        assert_eq!(unspent_transport.calls(), 1);
        assert_eq!(
            store
                .cashu_custody_export_v1(&export_id)
                .unwrap()
                .unwrap()
                .state,
            CashuCustodyExportStateV1::DeliveryAcknowledged
        );

        spent_confirm_with_transport(
            spent_confirm_args(vec![format!("7={}", custody_key_path.display())], true),
            &transport,
        )
        .unwrap();
        assert_eq!(transport.calls(), 1);
        assert_eq!(
            store
                .cashu_custody_export_v1(&export_id)
                .unwrap()
                .unwrap()
                .state,
            CashuCustodyExportStateV1::SpentConfirmed
        );
        let evidence = store
            .cashu_custody_retirement_evidence_v1(&export_id)
            .unwrap()
            .unwrap();
        assert_eq!(evidence.export_id, export_id);
        assert_eq!(evidence.artifact_digest, artifact_digest);
        assert_eq!(evidence.note_count, 1);
        assert_ne!(evidence.nut07_response_digest, [0u8; 32]);
        let inventory = store.cashu_custody_inventory_v1(&mint_id, unit).unwrap();
        assert_eq!(inventory.acknowledged_lot_count, 0);
        assert_eq!(inventory.acknowledged_export_count, 0);
        assert_eq!(inventory.spent_confirmed_lot_count, 1);
        assert_eq!(inventory.spent_confirmed_export_count, 1);

        // Exact terminal replay neither needs custody keys nor contacts the
        // mint again; only the digest-only terminal snapshot is read.
        spent_confirm_with_transport(spent_confirm_args(Vec::new(), true), &transport).unwrap();
        assert_eq!(transport.calls(), 1);
    }
}
