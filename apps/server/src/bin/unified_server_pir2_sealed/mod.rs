//! Measured pir2 sealed-credential startup dispatcher.
//!
//! This module is a directory module so Cargo never discovers it as another
//! binary.  The dispatcher runs before database/ORAM construction and before
//! a listener exists.  Observe never derives a key; enroll/probe always exit
//! inert after writing a current-boot receipt; only Ready transfers the two
//! role-separated signing keys to the server.

use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use pir_identity::IdentityCert;
use pir_runtime_core::snp_sealed_secrets::{
    enroll_new_pir2_sealed_credentials_v1, open_pir2_sealed_credentials_v1,
    Pir2PreReleaseObservationClaimsV1, Pir2PreReleaseObservationReceiptV1,
    Pir2SealedReceiptClaimsV1, Pir2SealedReceiptPhaseV1, Pir2SealedReceiptV1,
    Pir2SealedSigningMaterialV1, SnpDerivedKeyProvider, VerifiedPir2SealedReleaseV1,
};
use pir_service_protocol::{
    IssuerAccountingApprovalV2, ProviderAccountingAuthorizationV2,
    BAT_V2_ISSUER_ACCOUNTING_APPROVAL_LEN_V2, MAX_BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_LEN_V2,
};

use super::read_regular_file_bounded_v1;

const MAX_IDENTITY_CERT_LEN_V1: usize = 4096;
const MAX_RELEASE_LEN_V1: usize = 2048;
pub(super) const PIR2_SEALED_INERT_SUCCESS_EXIT_CODE_V1: i32 = 42;

/// Existing pir2 operator pin compiled into the measured binary. A rotation
/// requires a reviewed source change and a new measured image; there is no CLI
/// escape hatch for substituting this trust root.
const SOURCE_PINNED_PIR2_OPERATOR_KEY_HEX_V1: &str =
    "7ecb7900928f30efbf548a13c8d0b4fff5a580c7a145b003866580e42d9dc9cb";

pub(super) fn source_pinned_pir2_operator_key_v1() -> Result<VerifyingKey, String> {
    let bytes = hex::decode(SOURCE_PINNED_PIR2_OPERATOR_KEY_HEX_V1)
        .map_err(|_| "source-pinned pir2 operator key is not hex".to_owned())?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "source-pinned pir2 operator key has the wrong length".to_owned())?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| "source-pinned pir2 operator key is invalid".to_owned())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Pir2SealedStartupPhaseV1 {
    Observe,
    Enroll,
    Probe,
    Ready,
}

impl Pir2SealedStartupPhaseV1 {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "observe" => Ok(Self::Observe),
            "enroll" => Ok(Self::Enroll),
            "probe" => Ok(Self::Probe),
            "ready" => Ok(Self::Ready),
            _ => Err("--pir2-snp-sealed-phase must be observe, enroll, probe, or ready".to_owned()),
        }
    }

    fn receipt_phase(self) -> Pir2SealedReceiptPhaseV1 {
        match self {
            Self::Observe => Pir2SealedReceiptPhaseV1::Observe,
            Self::Enroll => Pir2SealedReceiptPhaseV1::Enroll,
            Self::Probe => Pir2SealedReceiptPhaseV1::Probe,
            Self::Ready => Pir2SealedReceiptPhaseV1::Ready,
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct Pir2SealedCliV1 {
    pub preflight_only: bool,
    pub require_ready: bool,
    pub release_path: Option<PathBuf>,
    pub envelope_path: Option<PathBuf>,
    pub receipt_path: Option<PathBuf>,
    pub marker_path: Option<PathBuf>,
    pub phase: Option<Pir2SealedStartupPhaseV1>,
    pub ordinal: Option<u64>,
    pub verifier_nonce_hex: Option<String>,
    pub current_boot_id_hex: Option<String>,
    pub current_channel_pubkey_hex: Option<String>,
    pub identity_cert_path: Option<PathBuf>,
    pub accounting_authorization_path: Option<PathBuf>,
    pub issuer_approval_path: Option<PathBuf>,
}

impl Pir2SealedCliV1 {
    pub fn any_configured(&self) -> bool {
        self.preflight_only
            || self.require_ready
            || self.release_path.is_some()
            || self.envelope_path.is_some()
            || self.receipt_path.is_some()
            || self.marker_path.is_some()
            || self.phase.is_some()
            || self.ordinal.is_some()
            || self.verifier_nonce_hex.is_some()
            || self.current_boot_id_hex.is_some()
            || self.current_channel_pubkey_hex.is_some()
            || self.identity_cert_path.is_some()
            || self.accounting_authorization_path.is_some()
            || self.issuer_approval_path.is_some()
    }
}

// This one-shot startup result deliberately owns the non-cloneable keys and
// decoded public artifacts directly. Boxing them would create extra secret-
// bearing allocations for no runtime benefit on this once-per-process path.
#[allow(clippy::large_enum_variant)]
pub(super) enum Pir2SealedStartupV1 {
    Disabled,
    InertSuccess {
        phase: Pir2SealedStartupPhaseV1,
        receipt_digest: [u8; 32],
    },
    Ready {
        identity_key: SigningKey,
        clearing_key: SigningKey,
        identity_cert: IdentityCert,
        accounting_auth: ProviderAccountingAuthorizationV2,
        issuer_approval: IssuerAccountingApprovalV2,
    },
}

struct CompletePir2SealedCliV1<'a> {
    preflight_only: bool,
    require_ready: bool,
    release_path: Option<&'a Path>,
    envelope_path: &'a Path,
    receipt_path: &'a Path,
    marker_path: &'a Path,
    phase: Pir2SealedStartupPhaseV1,
    ordinal: u64,
    verifier_nonce: [u8; 32],
    current_boot_id: [u8; 16],
    expected_current_channel_pubkey: Option<[u8; 32]>,
    identity_cert_path: Option<&'a Path>,
    accounting_authorization_path: Option<&'a Path>,
    issuer_approval_path: Option<&'a Path>,
}

/// Validate the all-or-nothing group and its exclusions without touching a
/// file, SEV device, database, ORAM image, or socket.
pub(super) fn validate_pir2_sealed_cli_v1(
    cli: &Pir2SealedCliV1,
    plaintext_identity_configured: bool,
    plaintext_clearing_configured: bool,
) -> Result<(), String> {
    if !cli.any_configured() {
        return Ok(());
    }
    complete_cli_v1(cli)?;
    if plaintext_identity_configured || plaintext_clearing_configured {
        return Err(
            "pir2 SNP-sealed mode forbids plaintext identity or clearing-key inputs".to_owned(),
        );
    }
    Ok(())
}

fn complete_cli_v1(cli: &Pir2SealedCliV1) -> Result<CompletePir2SealedCliV1<'_>, String> {
    let phase = cli.phase.ok_or_else(|| {
        "pir2 SNP-sealed configuration requires --pir2-snp-sealed-phase".to_owned()
    })?;
    if cli.preflight_only == cli.require_ready {
        return Err(
            "pir2 SNP-sealed configuration requires exactly one of --pir2-snp-sealed-preflight-only or --pir2-snp-sealed-require-ready"
                .to_owned(),
        );
    }
    if phase != Pir2SealedStartupPhaseV1::Ready && cli.require_ready {
        return Err(
            "observe/enroll/probe require preflight-only; only ready may require-ready".to_owned(),
        );
    }
    let ordinal = cli
        .ordinal
        .filter(|value| *value > 0)
        .ok_or_else(|| "--pir2-snp-sealed-ordinal must be non-zero".to_owned())?;
    let ready_paths = (
        cli.identity_cert_path.as_deref(),
        cli.accounting_authorization_path.as_deref(),
        cli.issuer_approval_path.as_deref(),
    );
    if phase == Pir2SealedStartupPhaseV1::Ready {
        if ready_paths.0.is_none() || ready_paths.1.is_none() || ready_paths.2.is_none() {
            return Err("ready sealed mode requires identity cert, accounting authorization, and issuer approval paths".to_owned());
        }
    } else if ready_paths.0.is_some() || ready_paths.1.is_some() || ready_paths.2.is_some() {
        return Err(
            "inert sealed phases forbid premature identity/accounting authorization artifacts"
                .to_owned(),
        );
    }
    let release_path = match phase {
        Pir2SealedStartupPhaseV1::Observe => {
            if cli.release_path.is_some() {
                return Err("pre-release observe forbids --pir2-snp-sealed-release".to_owned());
            }
            None
        }
        Pir2SealedStartupPhaseV1::Enroll
        | Pir2SealedStartupPhaseV1::Probe
        | Pir2SealedStartupPhaseV1::Ready => Some(required_path(
            cli.release_path.as_deref(),
            "--pir2-snp-sealed-release",
        )?),
    };
    Ok(CompletePir2SealedCliV1 {
        preflight_only: cli.preflight_only,
        require_ready: cli.require_ready,
        release_path,
        envelope_path: required_path(cli.envelope_path.as_deref(), "--pir2-snp-sealed-envelope")?,
        receipt_path: required_path(cli.receipt_path.as_deref(), "--pir2-snp-sealed-receipt")?,
        marker_path: required_path(cli.marker_path.as_deref(), "--pir2-snp-sealed-marker")?,
        phase,
        ordinal,
        verifier_nonce: decode_hex_array_v1(
            cli.verifier_nonce_hex.as_deref(),
            "--pir2-snp-sealed-verifier-nonce-hex",
        )?,
        current_boot_id: decode_hex_array_v1(
            cli.current_boot_id_hex.as_deref(),
            "--pir2-snp-sealed-current-boot-id-hex",
        )?,
        expected_current_channel_pubkey: cli
            .current_channel_pubkey_hex
            .as_deref()
            .map(|value| {
                decode_hex_array_v1(Some(value), "--pir2-snp-sealed-current-channel-pubkey-hex")
            })
            .transpose()?,
        identity_cert_path: ready_paths.0,
        accounting_authorization_path: ready_paths.1,
        issuer_approval_path: ready_paths.2,
    })
}

fn required_path<'a>(path: Option<&'a Path>, flag: &str) -> Result<&'a Path, String> {
    path.ok_or_else(|| format!("pir2 SNP-sealed configuration requires {flag}"))
}

fn decode_hex_array_v1<const N: usize>(value: Option<&str>, flag: &str) -> Result<[u8; N], String> {
    let value = value.ok_or_else(|| format!("pir2 SNP-sealed configuration requires {flag}"))?;
    let bytes = hex::decode(value).map_err(|_| format!("{flag} must be exact lowercase hex"))?;
    if hex::encode(&bytes) != value {
        return Err(format!("{flag} must use canonical lowercase hex"));
    }
    let bytes: [u8; N] = bytes
        .try_into()
        .map_err(|_| format!("{flag} has the wrong length"))?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(format!("{flag} must not be all zero"));
    }
    Ok(bytes)
}

/// Run the sealed state machine. Callers must invoke this before loading any
/// database/ORAM input or creating a listener.
pub(super) fn dispatch_pir2_sealed_startup_v1<P: SnpDerivedKeyProvider + ?Sized>(
    cli: &Pir2SealedCliV1,
    source_pinned_operator_key: &VerifyingKey,
    issuer_settlement_key: Option<&VerifyingKey>,
    now_unix: u64,
    current_channel_pubkey: [u8; 32],
    provider: &P,
) -> Result<Pir2SealedStartupV1, String> {
    dispatch_pir2_sealed_startup_with_security_v1(
        cli,
        source_pinned_operator_key,
        issuer_settlement_key,
        now_unix,
        current_channel_pubkey,
        provider,
        enforce_process_secret_controls_v1,
    )
}

fn dispatch_pir2_sealed_startup_with_security_v1<
    P: SnpDerivedKeyProvider + ?Sized,
    F: FnOnce() -> Result<(), String>,
>(
    cli: &Pir2SealedCliV1,
    source_pinned_operator_key: &VerifyingKey,
    issuer_settlement_key: Option<&VerifyingKey>,
    now_unix: u64,
    current_channel_pubkey: [u8; 32],
    provider: &P,
    enforce_security: F,
) -> Result<Pir2SealedStartupV1, String> {
    if !cli.any_configured() {
        return Ok(Pir2SealedStartupV1::Disabled);
    }
    if now_unix == 0 {
        return Err("pir2 sealed startup requires a non-zero current time".to_owned());
    }
    let cli = complete_cli_v1(cli)?;
    if current_channel_pubkey == [0_u8; 32]
        || cli
            .expected_current_channel_pubkey
            .is_some_and(|expected| expected != current_channel_pubkey)
    {
        return Err(
            "generated current channel key does not match the optional sealed CLI assertion"
                .to_owned(),
        );
    }
    enforce_security()?;

    if cli.phase == Pir2SealedStartupPhaseV1::Observe {
        let claims = Pir2PreReleaseObservationClaimsV1::new(
            cli.ordinal,
            cli.verifier_nonce,
            current_channel_pubkey,
            cli.current_boot_id,
        )
        .map_err(|error| error.to_string())?;
        let receipt = Pir2PreReleaseObservationReceiptV1::request(claims, provider)
            .map_err(|error| error.to_string())?;
        let receipt_digest = receipt.digest().map_err(|error| error.to_string())?;
        pir_private_files::write_atomic_noreplace_private_file_v1(
            cli.receipt_path,
            &receipt.encode().map_err(|error| error.to_string())?,
            false,
            "pir2 pre-release observation receipt",
        )?;
        debug_assert!(cli.preflight_only);
        let marker = encode_inert_marker_v1(cli.phase, cli.current_boot_id, receipt_digest);
        pir_private_files::write_atomic_noreplace_private_file_v1(
            cli.marker_path,
            &marker,
            false,
            "pir2 sealed current-boot inert-success marker",
        )?;
        return Ok(Pir2SealedStartupV1::InertSuccess {
            phase: cli.phase,
            receipt_digest,
        });
    }

    let release_bytes = read_regular_file_bounded_v1(
        cli.release_path
            .expect("non-observe release path validated"),
        MAX_RELEASE_LEN_V1,
        "operator-signed pir2 sealed release",
    )?;
    let release =
        VerifiedPir2SealedReleaseV1::decode_and_verify(&release_bytes, source_pinned_operator_key)
            .map_err(|error| error.to_string())?;

    let material = match cli.phase {
        Pir2SealedStartupPhaseV1::Observe => unreachable!("observe returned before release IO"),
        Pir2SealedStartupPhaseV1::Enroll => Some(
            enroll_new_pir2_sealed_credentials_v1(
                cli.envelope_path,
                false,
                release.release(),
                provider,
            )
            .map_err(|error| error.to_string())?,
        ),
        Pir2SealedStartupPhaseV1::Probe | Pir2SealedStartupPhaseV1::Ready => Some(
            open_pir2_sealed_credentials_v1(cli.envelope_path, release.release(), provider)
                .map_err(|error| error.to_string())?,
        ),
    };
    // A Ready receipt is success evidence. Verify every public authority
    // first so a failed ready attempt can never leave a valid-looking receipt.
    let ready_artifacts = if cli.phase == Pir2SealedStartupPhaseV1::Ready {
        Some(load_ready_artifacts_v1(
            &cli,
            &release,
            material.as_ref().expect("ready phase opened material"),
            source_pinned_operator_key,
            issuer_settlement_key,
            now_unix,
        )?)
    } else {
        None
    };
    let claims = Pir2SealedReceiptClaimsV1::for_release(
        &release,
        cli.phase.receipt_phase(),
        cli.ordinal,
        cli.verifier_nonce,
        current_channel_pubkey,
        cli.current_boot_id,
        material.as_ref(),
    )
    .map_err(|error| error.to_string())?;
    let receipt = Pir2SealedReceiptV1::request(&release, claims, provider)
        .map_err(|error| error.to_string())?;
    let receipt_digest = receipt.digest().map_err(|error| error.to_string())?;
    pir_private_files::write_atomic_noreplace_private_file_v1(
        cli.receipt_path,
        &receipt.encode().map_err(|error| error.to_string())?,
        false,
        "pir2 sealed current-boot receipt",
    )?;

    if cli.preflight_only {
        let marker = encode_inert_marker_v1(cli.phase, cli.current_boot_id, receipt_digest);
        pir_private_files::write_atomic_noreplace_private_file_v1(
            cli.marker_path,
            &marker,
            false,
            "pir2 sealed current-boot inert-success marker",
        )?;
        return Ok(Pir2SealedStartupV1::InertSuccess {
            phase: cli.phase,
            receipt_digest,
        });
    }
    debug_assert!(cli.require_ready);
    let material = material.ok_or_else(|| "ready phase did not unseal credentials".to_owned())?;
    let (identity_cert, accounting_auth, issuer_approval) =
        ready_artifacts.expect("ready phase verified public artifacts");
    let keys = material.into_signing_keys();
    Ok(Pir2SealedStartupV1::Ready {
        identity_key: keys.service_identity,
        clearing_key: keys.clearing,
        identity_cert,
        accounting_auth,
        issuer_approval,
    })
}

fn load_ready_artifacts_v1(
    cli: &CompletePir2SealedCliV1<'_>,
    release: &VerifiedPir2SealedReleaseV1,
    material: &Pir2SealedSigningMaterialV1,
    source_pinned_operator_key: &VerifyingKey,
    issuer_settlement_key: Option<&VerifyingKey>,
    now_unix: u64,
) -> Result<
    (
        IdentityCert,
        ProviderAccountingAuthorizationV2,
        IssuerAccountingApprovalV2,
    ),
    String,
> {
    let public_keys = material.public_keys();
    let identity_cert_bytes = read_regular_file_bounded_v1(
        cli.identity_cert_path.expect("ready paths checked"),
        MAX_IDENTITY_CERT_LEN_V1,
        "pir2 operator-signed identity certificate",
    )?;
    let identity_cert = IdentityCert::decode(&identity_cert_bytes)
        .map_err(|error| format!("invalid pir2 identity certificate: {error}"))?;
    identity_cert
        .verify()
        .map_err(|error| format!("invalid pir2 identity certificate signature: {error}"))?;
    identity_cert
        .check_validity(
            i64::try_from(now_unix).map_err(|_| {
                "current time exceeds the identity certificate clock range".to_owned()
            })?,
        )
        .map_err(|error| format!("pir2 identity certificate is not current: {error}"))?;
    if identity_cert.operator_pubkey != source_pinned_operator_key.to_bytes()
        || identity_cert.server_id != release.claims().stable_server_id
        || identity_cert.identity_pubkey != public_keys.service_identity
    {
        return Err(
            "pir2 identity certificate does not match release/operator/sealed key".to_owned(),
        );
    }

    let accounting_bytes = read_regular_file_bounded_v1(
        cli.accounting_authorization_path
            .expect("ready paths checked"),
        MAX_BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_LEN_V2,
        "pir2 BAT V2 accounting authorization",
    )?;
    let accounting_auth = ProviderAccountingAuthorizationV2::decode(&accounting_bytes)
        .map_err(|error| format!("invalid pir2 accounting authorization: {error}"))?;
    if accounting_auth
        .encode()
        .map_err(|error| error.to_string())?
        != accounting_bytes
        || accounting_auth.operator_verifying_key != source_pinned_operator_key.to_bytes()
        || accounting_auth.claims.provider_id != release.claims().provider_id
        || accounting_auth.claims.authorization_epoch
            != release.claims().clearing_authorization_epoch
        || accounting_auth.claims.clearing_verifying_key != public_keys.clearing
    {
        return Err(
            "pir2 accounting authorization does not match release/operator/sealed key".to_owned(),
        );
    }
    accounting_auth
        .verify_for(
            &release.claims().provider_id,
            &accounting_auth.claims.issuer_id,
            source_pinned_operator_key,
            now_unix,
            release.claims().clearing_authorization_epoch,
        )
        .map_err(|error| format!("pir2 accounting authorization is not current: {error}"))?;

    let approval_bytes = read_regular_file_bounded_v1(
        cli.issuer_approval_path.expect("ready paths checked"),
        BAT_V2_ISSUER_ACCOUNTING_APPROVAL_LEN_V2,
        "pir2 BAT V2 issuer accounting approval",
    )?;
    let issuer_approval = IssuerAccountingApprovalV2::decode(&approval_bytes)
        .map_err(|error| format!("invalid pir2 issuer accounting approval: {error}"))?;
    if issuer_approval.encode().as_slice() != approval_bytes.as_slice()
        || issuer_approval.authorization_epoch != release.claims().clearing_authorization_epoch
    {
        return Err("pir2 issuer approval is non-canonical or has the wrong epoch".to_owned());
    }
    issuer_approval
        .verify_for(
            &accounting_auth,
            issuer_settlement_key.ok_or_else(|| {
                "ready sealed mode requires the source-configured issuer settlement key".to_owned()
            })?,
            now_unix,
            release.claims().clearing_authorization_epoch,
        )
        .map_err(|error| format!("pir2 issuer approval is not current: {error}"))?;
    Ok((identity_cert, accounting_auth, issuer_approval))
}

fn encode_inert_marker_v1(
    phase: Pir2SealedStartupPhaseV1,
    boot_id: [u8; 16],
    receipt_digest: [u8; 32],
) -> Vec<u8> {
    format!(
        "schema=bitcoinpir-pir2-sealed-inert-success-v1\nphase={}\nboot_id={}\nreceipt_digest={}\nexit_code={}\n",
        match phase {
            Pir2SealedStartupPhaseV1::Observe => "observe",
            Pir2SealedStartupPhaseV1::Enroll => "enroll",
            Pir2SealedStartupPhaseV1::Probe => "probe",
            Pir2SealedStartupPhaseV1::Ready => "ready",
        },
        hex::encode(boot_id),
        hex::encode(receipt_digest),
        PIR2_SEALED_INERT_SUCCESS_EXIT_CODE_V1,
    )
    .into_bytes()
}

fn enforce_process_secret_controls_v1() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    unsafe {
        let core_limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &core_limit) != 0 {
            return Err("failed to set hard and soft RLIMIT_CORE to zero".to_owned());
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err("failed to make the sealed process non-dumpable".to_owned());
        }
        let swaps = std::fs::read_to_string("/proc/swaps")
            .map_err(|_| "cannot prove that guest swap is disabled".to_owned())?;
        if swaps.lines().skip(1).any(|line| !line.trim().is_empty()) {
            return Err("guest swap is active; refusing to unseal credentials".to_owned());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("pir2 sealed credentials require the measured Linux runtime".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;

    use pir_identity::sign_identity_cert;
    use pir_runtime_core::snp_sealed_secrets::{
        encode_signed_pir2_sealed_release_v1, FreshSnpReportV1, Pir2SealedReleaseClaimsV1,
        SnpDerivedKeyMaterialV1, SnpDerivedKeyProviderErrorV1, SnpDerivedKeyRequestV1,
        SnpTcbVersionV1,
    };
    use pir_service_protocol::{
        ProviderAccountingAuthorizationClaimsV2, ProviderAccountingRuleV2, SettlementUnitV1,
    };

    fn complete(phase: Pir2SealedStartupPhaseV1) -> Pir2SealedCliV1 {
        let ready = phase == Pir2SealedStartupPhaseV1::Ready;
        Pir2SealedCliV1 {
            preflight_only: !ready,
            require_ready: ready,
            release_path: (phase != Pir2SealedStartupPhaseV1::Observe)
                .then(|| "release.bin".into()),
            envelope_path: Some("envelope.bin".into()),
            receipt_path: Some("receipt.bin".into()),
            marker_path: Some("marker".into()),
            phase: Some(phase),
            ordinal: Some(1),
            verifier_nonce_hex: Some("11".repeat(32)),
            current_boot_id_hex: Some("22".repeat(16)),
            current_channel_pubkey_hex: Some("33".repeat(32)),
            identity_cert_path: ready.then(|| "identity.cert".into()),
            accounting_authorization_path: ready.then(|| "accounting.bin".into()),
            issuer_approval_path: ready.then(|| "approval.bin".into()),
        }
    }

    #[test]
    fn cli_is_all_or_nothing_and_plaintext_never_mixes() {
        assert_eq!(
            source_pinned_pir2_operator_key_v1().unwrap().to_bytes(),
            hex::decode(SOURCE_PINNED_PIR2_OPERATOR_KEY_HEX_V1)
                .unwrap()
                .as_slice()
        );
        let disabled = Pir2SealedCliV1::default();
        assert!(validate_pir2_sealed_cli_v1(&disabled, false, false).is_ok());
        let mut partial = Pir2SealedCliV1::default();
        partial.preflight_only = true;
        assert!(validate_pir2_sealed_cli_v1(&partial, false, false).is_err());
        let ready = complete(Pir2SealedStartupPhaseV1::Ready);
        assert!(validate_pir2_sealed_cli_v1(&ready, false, false).is_ok());
        assert!(validate_pir2_sealed_cli_v1(&ready, true, false).is_err());
        assert!(validate_pir2_sealed_cli_v1(&ready, false, true).is_err());

        let mut ready_preflight = complete(Pir2SealedStartupPhaseV1::Ready);
        ready_preflight.preflight_only = true;
        ready_preflight.require_ready = false;
        assert!(validate_pir2_sealed_cli_v1(&ready_preflight, false, false).is_ok());

        let mut invalid_probe = complete(Pir2SealedStartupPhaseV1::Probe);
        invalid_probe.preflight_only = false;
        invalid_probe.require_ready = true;
        assert!(validate_pir2_sealed_cli_v1(&invalid_probe, false, false).is_err());

        let mut observe_with_release = complete(Pir2SealedStartupPhaseV1::Observe);
        observe_with_release.release_path = Some("premature-release.bin".into());
        assert!(validate_pir2_sealed_cli_v1(&observe_with_release, false, false).is_err());

        let mut enroll_without_release = complete(Pir2SealedStartupPhaseV1::Enroll);
        enroll_without_release.release_path = None;
        assert!(validate_pir2_sealed_cli_v1(&enroll_without_release, false, false).is_err());
    }

    #[test]
    fn inert_phases_reject_ready_artifacts_and_ready_requires_them() {
        let mut probe = complete(Pir2SealedStartupPhaseV1::Probe);
        probe.identity_cert_path = Some("too-early.cert".into());
        assert!(complete_cli_v1(&probe).is_err());
        let mut ready = complete(Pir2SealedStartupPhaseV1::Ready);
        ready.issuer_approval_path = None;
        assert!(complete_cli_v1(&ready).is_err());
    }

    #[test]
    fn marker_is_bound_to_boot_receipt_phase_and_dedicated_exit() {
        let marker = String::from_utf8(encode_inert_marker_v1(
            Pir2SealedStartupPhaseV1::Enroll,
            [0x44; 16],
            [0x55; 32],
        ))
        .unwrap();
        assert!(marker.contains("phase=enroll\n"));
        assert!(marker.contains(&format!("boot_id={}\n", "44".repeat(16))));
        assert!(marker.contains(&format!("receipt_digest={}\n", "55".repeat(32))));
        assert!(marker.contains("exit_code=42\n"));
    }

    struct ObserveOnlyProviderV1 {
        report_calls: Cell<u32>,
        derive_calls: Cell<u32>,
    }

    struct ReadyProviderV1 {
        release: pir_runtime_core::snp_sealed_secrets::Pir2SealedReleaseV1,
        derived_key: [u8; 32],
        report_calls: Cell<u32>,
        derive_calls: Cell<u32>,
    }

    impl ReadyProviderV1 {
        fn new(release: &pir_runtime_core::snp_sealed_secrets::Pir2SealedReleaseV1) -> Self {
            Self {
                release: release.clone(),
                derived_key: [0x52; 32],
                report_calls: Cell::new(0),
                derive_calls: Cell::new(0),
            }
        }
    }

    impl SnpDerivedKeyProvider for ReadyProviderV1 {
        fn fresh_report(
            &self,
            report_data: [u8; 64],
        ) -> Result<FreshSnpReportV1, SnpDerivedKeyProviderErrorV1> {
            self.report_calls.set(self.report_calls.get() + 1);
            Ok(FreshSnpReportV1 {
                report_version: 2,
                vmpl: 0,
                guest_policy: self.release.expected_guest_policy,
                measurement: self.release.expected_measurement,
                report_data,
                reported_tcb: self.release.minimum_tcb,
                committed_tcb: self.release.minimum_tcb,
                raw_report: vec![0xB7; 1184],
            })
        }

        fn derive_key(
            &self,
            request: &SnpDerivedKeyRequestV1,
        ) -> Result<SnpDerivedKeyMaterialV1, SnpDerivedKeyProviderErrorV1> {
            self.derive_calls.set(self.derive_calls.get() + 1);
            if request.canonical_evidence()
                != SnpDerivedKeyRequestV1::production().canonical_evidence()
            {
                return Err(SnpDerivedKeyProviderErrorV1::RequestDrift);
            }
            Ok(SnpDerivedKeyMaterialV1::from_bytes(self.derived_key))
        }
    }

    struct ReadyPreflightFixtureV1 {
        _directory: tempfile::TempDir,
        operator: SigningKey,
        issuer_settlement: SigningKey,
        provider: ReadyProviderV1,
        cli: Pir2SealedCliV1,
        accounting_path: PathBuf,
        receipt_path: PathBuf,
        marker_path: PathBuf,
    }

    fn ready_preflight_fixture_v1() -> ReadyPreflightFixtureV1 {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let operator = SigningKey::from_bytes(&[0x61; 32]);
        let issuer_settlement = SigningKey::from_bytes(&[0x62; 32]);
        let claims = Pir2SealedReleaseClaimsV1 {
            provider_id: [0x11; 32],
            stable_server_id: "pir2-mainnet".to_owned(),
            uki_sha256: [0x22; 32],
            expected_measurement: [0x33; 48],
            expected_guest_policy: 1 << 17,
            minimum_tcb: SnpTcbVersionV1 {
                fmc: None,
                bootloader: 1,
                tee: 2,
                snp: 3,
                microcode: 4,
            },
            derived_key_request: SnpDerivedKeyRequestV1::production().canonical_evidence(),
            identity_generation: 7,
            clearing_authorization_epoch: 11,
        };
        let release_bytes = encode_signed_pir2_sealed_release_v1(&claims, &operator).unwrap();
        let release_path = directory.path().join("release.bin");
        std::fs::write(&release_path, &release_bytes).unwrap();
        let verified = VerifiedPir2SealedReleaseV1::decode_and_verify(
            &release_bytes,
            &operator.verifying_key(),
        )
        .unwrap();

        let envelope_path = directory.path().join("envelope.bin");
        let enrollment_provider = ReadyProviderV1::new(verified.release());
        let enrolled = enroll_new_pir2_sealed_credentials_v1(
            &envelope_path,
            false,
            verified.release(),
            &enrollment_provider,
        )
        .unwrap();
        let public_keys = enrolled.public_keys();
        drop(enrolled);
        assert_eq!(enrollment_provider.report_calls.get(), 1);
        assert_eq!(enrollment_provider.derive_calls.get(), 1);

        let identity_cert = sign_identity_cert(
            &operator,
            &claims.stable_server_id,
            public_keys.service_identity,
            100,
            1_000,
        );
        let identity_cert_path = directory.path().join("identity.cert");
        std::fs::write(&identity_cert_path, identity_cert.encode()).unwrap();

        let authorization = ProviderAccountingAuthorizationV2::sign(
            ProviderAccountingAuthorizationClaimsV2 {
                authorization_id: [0x71; 16],
                authorization_epoch: claims.clearing_authorization_epoch,
                provider_id: claims.provider_id,
                issuer_id: [0x72; 32],
                redeem_endpoint: "https://issuer.invalid".to_owned(),
                redeem_leaf_spki_sha256_pins: vec![[0x73; 32]],
                settlement_account_id: [0x74; 32],
                clearing_verifying_key: public_keys.clearing,
                not_before: 100,
                not_after: 1_000,
                rules: vec![ProviderAccountingRuleV2 {
                    class_id: [0x75; 32],
                    policy_digest: [0x76; 32],
                    scope_id: [0x77; 32],
                    offer_id: 1,
                    unit: SettlementUnitV1::AuthCredit,
                    accepted_value: 10,
                    provider_credit: 8,
                    issuer_fee: 2,
                }],
            },
            &operator,
        )
        .unwrap();
        let accounting_path = directory.path().join("accounting.bin");
        std::fs::write(&accounting_path, authorization.encode().unwrap()).unwrap();
        let issuer_approval =
            IssuerAccountingApprovalV2::sign(&authorization, 100, 900, &issuer_settlement).unwrap();
        let issuer_approval_path = directory.path().join("approval.bin");
        std::fs::write(&issuer_approval_path, issuer_approval.encode()).unwrap();

        let receipt_path = directory.path().join("ready-preflight-receipt.bin");
        let marker_path = directory.path().join("ready-preflight.marker");
        let cli = Pir2SealedCliV1 {
            preflight_only: true,
            require_ready: false,
            release_path: Some(release_path),
            envelope_path: Some(envelope_path),
            receipt_path: Some(receipt_path.clone()),
            marker_path: Some(marker_path.clone()),
            phase: Some(Pir2SealedStartupPhaseV1::Ready),
            ordinal: Some(3),
            verifier_nonce_hex: Some("41".repeat(32)),
            current_boot_id_hex: Some("42".repeat(16)),
            current_channel_pubkey_hex: Some("43".repeat(32)),
            identity_cert_path: Some(identity_cert_path),
            accounting_authorization_path: Some(accounting_path.clone()),
            issuer_approval_path: Some(issuer_approval_path),
        };
        let provider = ReadyProviderV1::new(verified.release());

        ReadyPreflightFixtureV1 {
            _directory: directory,
            operator,
            issuer_settlement,
            provider,
            cli,
            accounting_path,
            receipt_path,
            marker_path,
        }
    }

    impl SnpDerivedKeyProvider for ObserveOnlyProviderV1 {
        fn fresh_report(
            &self,
            report_data: [u8; 64],
        ) -> Result<FreshSnpReportV1, SnpDerivedKeyProviderErrorV1> {
            self.report_calls.set(self.report_calls.get() + 1);
            let mut raw_report = vec![0xA7; 1184];
            raw_report[0x50..0x90].copy_from_slice(&report_data);
            Ok(FreshSnpReportV1 {
                report_version: 2,
                vmpl: 0,
                guest_policy: 1 << 17,
                measurement: [0x33; 48],
                report_data,
                reported_tcb: SnpTcbVersionV1 {
                    fmc: None,
                    bootloader: 1,
                    tee: 2,
                    snp: 3,
                    microcode: 4,
                },
                committed_tcb: SnpTcbVersionV1 {
                    fmc: None,
                    bootloader: 1,
                    tee: 2,
                    snp: 3,
                    microcode: 4,
                },
                raw_report,
            })
        }

        fn derive_key(
            &self,
            _request: &SnpDerivedKeyRequestV1,
        ) -> Result<SnpDerivedKeyMaterialV1, SnpDerivedKeyProviderErrorV1> {
            self.derive_calls.set(self.derive_calls.get() + 1);
            Err(SnpDerivedKeyProviderErrorV1::IoctlFailed(
                "observe must never reach derived-key ioctl".to_owned(),
            ))
        }
    }

    #[test]
    fn observation_dispatch_writes_current_boot_evidence_without_deriving_or_enveloping() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let operator = SigningKey::from_bytes(&[0x61; 32]);
        let provider = ObserveOnlyProviderV1 {
            report_calls: Cell::new(0),
            derive_calls: Cell::new(0),
        };
        let envelope_path = directory.path().join("must-not-exist.bin");
        let receipt_path = directory.path().join("receipt.bin");
        let marker_path = directory.path().join("marker");
        let cli = Pir2SealedCliV1 {
            preflight_only: true,
            release_path: None,
            envelope_path: Some(envelope_path.clone()),
            receipt_path: Some(receipt_path.clone()),
            marker_path: Some(marker_path.clone()),
            phase: Some(Pir2SealedStartupPhaseV1::Observe),
            ordinal: Some(1),
            verifier_nonce_hex: Some("41".repeat(32)),
            current_boot_id_hex: Some("42".repeat(16)),
            ..Pir2SealedCliV1::default()
        };
        let outcome = dispatch_pir2_sealed_startup_with_security_v1(
            &cli,
            &operator.verifying_key(),
            None,
            150,
            [0x43; 32],
            &provider,
            || Ok(()),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            Pir2SealedStartupV1::InertSuccess {
                phase: Pir2SealedStartupPhaseV1::Observe,
                ..
            }
        ));
        assert_eq!(provider.report_calls.get(), 1);
        assert_eq!(provider.derive_calls.get(), 0);
        assert!(!envelope_path.exists());
        assert!(receipt_path.exists());
        assert!(marker_path.exists());
        let expected_claims =
            Pir2PreReleaseObservationClaimsV1::new(1, [0x41; 32], [0x43; 32], [0x42; 16]).unwrap();
        Pir2PreReleaseObservationReceiptV1::decode_and_verify(
            &std::fs::read(receipt_path).unwrap(),
            &expected_claims,
        )
        .unwrap();
    }

    #[test]
    fn ready_preflight_verifies_real_artifacts_then_exits_inert_without_keys() {
        let fixture = ready_preflight_fixture_v1();
        let outcome = dispatch_pir2_sealed_startup_with_security_v1(
            &fixture.cli,
            &fixture.operator.verifying_key(),
            Some(&fixture.issuer_settlement.verifying_key()),
            150,
            [0x43; 32],
            &fixture.provider,
            || Ok(()),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            Pir2SealedStartupV1::InertSuccess {
                phase: Pir2SealedStartupPhaseV1::Ready,
                ..
            }
        ));
        assert_eq!(fixture.provider.report_calls.get(), 2);
        assert_eq!(fixture.provider.derive_calls.get(), 1);
        assert!(fixture.receipt_path.exists());
        assert!(fixture.marker_path.exists());
    }

    #[test]
    fn ready_preflight_bad_artifact_writes_neither_receipt_nor_marker() {
        let fixture = ready_preflight_fixture_v1();
        let mut accounting_bytes = std::fs::read(&fixture.accounting_path).unwrap();
        *accounting_bytes.last_mut().unwrap() ^= 0x01;
        std::fs::write(&fixture.accounting_path, accounting_bytes).unwrap();

        let error = match dispatch_pir2_sealed_startup_with_security_v1(
            &fixture.cli,
            &fixture.operator.verifying_key(),
            Some(&fixture.issuer_settlement.verifying_key()),
            150,
            [0x43; 32],
            &fixture.provider,
            || Ok(()),
        ) {
            Ok(_) => panic!("bad Ready artifact unexpectedly passed preflight"),
            Err(error) => error,
        };
        assert!(error.contains("accounting authorization"));
        assert_eq!(fixture.provider.report_calls.get(), 1);
        assert_eq!(fixture.provider.derive_calls.get(), 1);
        assert!(!fixture.receipt_path.exists());
        assert!(!fixture.marker_path.exists());
    }
}
