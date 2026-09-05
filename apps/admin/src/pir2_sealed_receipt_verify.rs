//! `bpir-admin pir2-sealed-receipt-verify` — offline, fail-closed acceptance
//! of one persisted Enroll, Probe, or Ready receipt (or a post-release
//! Observe receipt) against the operator-signed release the guest booted
//! with. Pre-release Observe receipts are verified by `pir2-sealed-release`.
//!
//! This is the reviewed repository command the sealed-release runbook
//! requires before any identity artifact is signed from a receipt. Checks,
//! in order:
//!
//! 1. the release decodes and verifies under the source-pinned operator key;
//! 2. the receipt file is canonical (magic, codec, lengths, claim contract,
//!    `REPORT_DATA` carries the claims digest) and, when given, matches the
//!    receipt hash declared by the phase status JSON;
//! 3. the claims carry the expected phase, ordinal, verifier nonce, and boot
//!    ID, bind this exact release, and repeat its identity generation; for
//!    non-Observe phases the service identity key is a valid Ed25519 point;
//! 4. the AMD ARK pin, ARK → ASK → VCEK chain, and SNP report signature;
//! 5. the report's `REPORT_DATA`, Turin CPUID, measurement, full guest
//!    policy, and TCB floor against the release.
//!
//! Nothing here reads a secret: the operator key is a public pin.

use std::path::PathBuf;

use clap::Args;
use ed25519_dalek::VerifyingKey;
use pir_runtime_core::snp_sealed_secrets::{
    Pir2SealedReceiptClaimsV1, Pir2SealedReceiptFileV1, Pir2SealedReceiptPhaseV1,
    VerifiedPir2SealedReleaseV1, MAX_SEALED_RECEIPT_FILE_LEN_V1,
};
use sha2::{Digest as _, Sha256};

use crate::pir2_sealed_release::{
    parse_fixed_hex, read_public_bounded, validate_report_cpu, validate_signed_report_against_pins,
    verify_offline_report, MAX_RELEASE_LEN,
};

/// Inputs for one offline phase-receipt acceptance.
#[derive(Args, Debug)]
pub struct Pir2SealedReceiptVerifyArgs {
    /// Persisted phase receipt (recovery API download or Flow F copy).
    #[arg(long)]
    pub receipt: PathBuf,
    /// Operator-signed release the guest booted with.
    #[arg(long)]
    pub release: PathBuf,
    /// Source-pinned operator Ed25519 public key (64 hex) the release must
    /// verify under.
    #[arg(long)]
    pub operator_pubkey_hex: String,
    /// Expected phase: observe, enroll, probe, or ready.
    #[arg(long)]
    pub expected_phase: String,
    /// Ordinal written into this boot's startup.env.
    #[arg(long)]
    pub expected_ordinal: u64,
    /// Verifier nonce written into this boot's startup.env (64 hex).
    #[arg(long)]
    pub expected_verifier_nonce_hex: String,
    /// Boot ID declared by the phase status JSON or marker (32 hex).
    #[arg(long)]
    pub expected_boot_id_hex: String,
    /// Receipt SHA-256 declared by the phase status JSON (64 hex). Strongly
    /// recommended: it rejects a cached receipt from an earlier phase.
    #[arg(long)]
    pub expected_receipt_sha256_hex: Option<String>,
    /// AMD ARK PEM for the report's CPU generation.
    #[arg(long)]
    pub ark: PathBuf,
    /// AMD ASK PEM for the report's CPU generation.
    #[arg(long)]
    pub ask: PathBuf,
    /// Chip-specific AMD VCEK PEM.
    #[arg(long)]
    pub vcek: PathBuf,
    /// SHA-256 of the DER-encoded ARK certificate.
    #[arg(long)]
    pub expected_ark_sha256_hex: String,
}

pub fn run(args: Pir2SealedReceiptVerifyArgs) -> Result<(), String> {
    let expected_phase = Pir2SealedReceiptPhaseV1::parse_name(&args.expected_phase)
        .ok_or_else(|| "expected phase must be observe, enroll, probe, or ready".to_owned())?;
    if args.expected_ordinal == 0 {
        return Err("expected ordinal must be non-zero".to_owned());
    }
    let expected_nonce =
        parse_fixed_hex::<32>(&args.expected_verifier_nonce_hex, "expected verifier nonce")?;
    let expected_boot_id = parse_fixed_hex::<16>(&args.expected_boot_id_hex, "expected boot ID")?;
    let operator_pubkey = parse_fixed_hex::<32>(&args.operator_pubkey_hex, "operator public key")?;
    let operator = VerifyingKey::from_bytes(&operator_pubkey)
        .map_err(|_| "operator public key is not a valid Ed25519 point".to_owned())?;
    let expected_ark_sha256 =
        parse_fixed_hex::<32>(&args.expected_ark_sha256_hex, "expected ARK SHA-256")?;
    let expected_receipt_sha256 = args
        .expected_receipt_sha256_hex
        .as_deref()
        .map(|value| parse_fixed_hex::<32>(value, "expected receipt SHA-256"))
        .transpose()?;

    let release_bytes =
        read_public_bounded(&args.release, MAX_RELEASE_LEN, "operator-signed release")?;
    let release = VerifiedPir2SealedReleaseV1::decode_and_verify(&release_bytes, &operator)
        .map_err(|error| format!("verify operator-signed release: {error}"))?;

    let receipt_bytes = read_public_bounded(
        &args.receipt,
        MAX_SEALED_RECEIPT_FILE_LEN_V1,
        "phase receipt",
    )?;
    if let Some(expected) = expected_receipt_sha256 {
        let actual: [u8; 32] = Sha256::digest(&receipt_bytes).into();
        if actual != expected {
            return Err(
                "receipt SHA-256 differs from the phase status declaration; treat the \
                 download as rejecting evidence and recover the receipt through Flow F"
                    .to_owned(),
            );
        }
    }
    let receipt = Pir2SealedReceiptFileV1::decode(&receipt_bytes)
        .map_err(|error| format!("decode phase receipt: {error}"))?;
    check_claims(
        &receipt.claims,
        &release,
        expected_phase,
        args.expected_ordinal,
        expected_nonce,
        expected_boot_id,
    )?;

    // The AMD trust decision comes only after every cheap binding passed.
    let expected_report_data = receipt
        .claims
        .report_data()
        .map_err(|error| format!("derive receipt REPORT_DATA: {error}"))?;
    let report = verify_offline_report(
        &receipt.raw_report,
        &args.ark,
        &args.ask,
        &args.vcek,
        expected_ark_sha256,
        expected_report_data,
    )?;
    validate_report_cpu(&report)?;
    let pinned = release.release();
    validate_signed_report_against_pins(
        &report,
        expected_report_data,
        pinned.expected_measurement,
        pinned.expected_guest_policy,
        pinned.minimum_tcb,
    )?;

    let claims = &receipt.claims;
    println!(
        "PASS pir2_sealed_receipt_verify phase={} ordinal={} identity_generation={} \
         stable_server_id={} boot_id_hex={} current_channel_pubkey_hex={} \
         service_identity_pubkey_hex={} service_identity_fingerprint_hex={} measurement_hex={}",
        claims.phase.name(),
        claims.ordinal,
        claims.identity_generation,
        pinned.stable_server_id,
        hex::encode(claims.boot_id),
        hex::encode(claims.current_channel_pubkey),
        hex::encode(claims.public_keys.service_identity),
        hex::encode(claims.public_fingerprints.service_identity),
        hex::encode(pinned.expected_measurement),
    );
    println!("NEXT_STEP={}", next_step(expected_phase));
    Ok(())
}

/// Bind the decoded claims to the operator's expectations and to the
/// verified release. Runs before any AMD certificate is read.
pub(crate) fn check_claims(
    claims: &Pir2SealedReceiptClaimsV1,
    release: &VerifiedPir2SealedReleaseV1,
    expected_phase: Pir2SealedReceiptPhaseV1,
    expected_ordinal: u64,
    expected_nonce: [u8; 32],
    expected_boot_id: [u8; 16],
) -> Result<(), String> {
    if claims.phase != expected_phase {
        return Err(format!(
            "receipt phase is {}, expected {}",
            claims.phase.name(),
            expected_phase.name()
        ));
    }
    if claims.ordinal != expected_ordinal {
        return Err(format!(
            "receipt ordinal is {}, expected {expected_ordinal}",
            claims.ordinal
        ));
    }
    if claims.verifier_nonce != expected_nonce {
        return Err("receipt verifier nonce differs from the startup nonce".to_owned());
    }
    if claims.boot_id != expected_boot_id {
        return Err("receipt boot ID differs from the phase status boot ID".to_owned());
    }
    if claims.release_artifact_digest != release.artifact_digest() {
        return Err("receipt binds a different release".to_owned());
    }
    if claims.identity_generation != release.release().identity_generation {
        return Err(format!(
            "receipt identity generation is {}, release has {}",
            claims.identity_generation,
            release.release().identity_generation
        ));
    }
    if claims.phase != Pir2SealedReceiptPhaseV1::Observe {
        VerifyingKey::from_bytes(&claims.public_keys.service_identity)
            .map_err(|_| "receipt service identity key is not a valid Ed25519 point".to_owned())?;
    }
    Ok(())
}

fn next_step(phase: Pir2SealedReceiptPhaseV1) -> &'static str {
    match phase {
        Pir2SealedReceiptPhaseV1::Observe => {
            "a post-release Observe is accepted; the pre-release Observe used by \
             pir2-sealed-release is a different receipt"
        }
        Pir2SealedReceiptPhaseV1::Enroll => {
            "sign the runtime identity certificate for service_identity_pubkey_hex with \
             `bpir-admin sign-identity --server-id <stable_server_id>`, place it with Flow F, \
             then run Probe with a fresh ordinal and nonce"
        }
        Pir2SealedReceiptPhaseV1::Probe => {
            "run a second independent Probe, or Ready once two Probe receipts are accepted"
        }
        Pir2SealedReceiptPhaseV1::Ready => "run scripts/pir2-post-switch-check.sh (Flow E step 6)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pir_attest_verify::SNP_REPORT_LEN;
    use pir_runtime_core::snp_sealed_secrets::{
        encode_signed_pir2_sealed_release_v1, FreshSnpReportV1, Pir2SealedReceiptV1,
        Pir2SealedReleaseClaimsV1, Pir2SealedSigningMaterialV1, SnpDerivedKeyMaterialV1,
        SnpDerivedKeyProvider, SnpDerivedKeyProviderErrorV1, SnpDerivedKeyRequestV1,
        SnpTcbVersionV1,
    };
    use std::fs;
    use std::path::Path;

    struct ReportProviderV1;

    impl SnpDerivedKeyProvider for ReportProviderV1 {
        fn fresh_report(
            &self,
            report_data: [u8; 64],
        ) -> Result<FreshSnpReportV1, SnpDerivedKeyProviderErrorV1> {
            let mut raw_report = vec![0xA5; SNP_REPORT_LEN];
            raw_report[0x50..0x90].copy_from_slice(&report_data);
            let tcb = SnpTcbVersionV1 {
                fmc: Some(1),
                bootloader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
            };
            Ok(FreshSnpReportV1 {
                report_version: 3,
                vmpl: 0,
                guest_policy: 1 << 17,
                measurement: [0x33; 48],
                report_data,
                reported_tcb: tcb,
                committed_tcb: tcb,
                raw_report,
            })
        }

        fn derive_key(
            &self,
            _request: &SnpDerivedKeyRequestV1,
        ) -> Result<SnpDerivedKeyMaterialV1, SnpDerivedKeyProviderErrorV1> {
            Err(SnpDerivedKeyProviderErrorV1::RequestDrift)
        }
    }

    fn release_claims() -> Pir2SealedReleaseClaimsV1 {
        Pir2SealedReleaseClaimsV1 {
            provider_id: [0x11; 32],
            stable_server_id: "pir2-test".to_owned(),
            uki_sha256: [0x22; 32],
            expected_measurement: [0x33; 48],
            expected_guest_policy: 1 << 17,
            minimum_tcb: SnpTcbVersionV1 {
                fmc: Some(1),
                bootloader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
            derived_key_request: SnpDerivedKeyRequestV1::production().canonical_evidence(),
            identity_generation: 5,
        }
    }

    const NONCE: [u8; 32] = [0x81; 32];
    const BOOT_ID: [u8; 16] = [0x83; 16];

    fn fixture(dir: &Path) -> (Pir2SealedReceiptVerifyArgs, VerifiedPir2SealedReleaseV1) {
        let operator = SigningKey::from_bytes(&[0x61; 32]);
        let release_bytes =
            encode_signed_pir2_sealed_release_v1(&release_claims(), &operator).unwrap();
        let release = VerifiedPir2SealedReleaseV1::decode_and_verify(
            &release_bytes,
            &operator.verifying_key(),
        )
        .unwrap();
        let material = Pir2SealedSigningMaterialV1::from_seed(&[0x71; 32]);
        let claims = Pir2SealedReceiptClaimsV1::for_release(
            &release,
            Pir2SealedReceiptPhaseV1::Enroll,
            45,
            NONCE,
            [0x82; 32],
            BOOT_ID,
            Some(&material),
        )
        .unwrap();
        let receipt = Pir2SealedReceiptV1::request(&release, claims, &ReportProviderV1).unwrap();
        let receipt_bytes = receipt.encode().unwrap();
        let release_path = dir.join("release.bin");
        let receipt_path = dir.join("enroll.receipt.bin");
        fs::write(&release_path, &release_bytes).unwrap();
        fs::write(&receipt_path, &receipt_bytes).unwrap();
        let args = Pir2SealedReceiptVerifyArgs {
            receipt: receipt_path,
            release: release_path,
            operator_pubkey_hex: hex::encode(operator.verifying_key().to_bytes()),
            expected_phase: "enroll".to_owned(),
            expected_ordinal: 45,
            expected_verifier_nonce_hex: hex::encode(NONCE),
            expected_boot_id_hex: hex::encode(BOOT_ID),
            expected_receipt_sha256_hex: Some(hex::encode(Sha256::digest(&receipt_bytes))),
            ark: dir.join("missing.ark"),
            ask: dir.join("missing.ask"),
            vcek: dir.join("missing.vcek"),
            expected_ark_sha256_hex: hex::encode([3_u8; 32]),
        };
        (args, release)
    }

    #[test]
    fn accepted_bindings_fail_closed_at_the_amd_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (args, _) = fixture(dir.path());
        let error = run(args).unwrap_err();
        assert!(error.contains("AMD ARK"), "{error}");
    }

    #[test]
    fn expectation_mismatches_are_rejected_before_any_certificate_read() {
        let dir = tempfile::tempdir().unwrap();
        type Mutation = fn(&mut Pir2SealedReceiptVerifyArgs);
        let cases: [(&str, Mutation); 6] = [
            ("phase", |a| a.expected_phase = "probe".to_owned()),
            ("ordinal", |a| a.expected_ordinal = 46),
            ("nonce", |a| {
                a.expected_verifier_nonce_hex = hex::encode([0x91_u8; 32])
            }),
            ("boot ID", |a| {
                a.expected_boot_id_hex = hex::encode([0x93_u8; 16])
            }),
            ("receipt SHA-256", |a| {
                a.expected_receipt_sha256_hex = Some(hex::encode([0_u8; 32]))
            }),
            ("operator key", |a| {
                a.operator_pubkey_hex = hex::encode(
                    SigningKey::from_bytes(&[0x62; 32])
                        .verifying_key()
                        .to_bytes(),
                )
            }),
        ];
        for (label, mutate) in cases {
            let (mut args, _) = fixture(dir.path());
            mutate(&mut args);
            let error = run(args).unwrap_err();
            assert!(
                !error.contains("AMD"),
                "{label}: reached the AMD chain: {error}"
            );
            assert!(
                error.contains(label) || error.contains("release"),
                "{label}: unexpected error {error}"
            );
            fs::remove_file(dir.path().join("release.bin")).unwrap();
            fs::remove_file(dir.path().join("enroll.receipt.bin")).unwrap();
        }
    }

    #[test]
    fn claims_must_bind_the_release_and_its_generation() {
        let dir = tempfile::tempdir().unwrap();
        let (_, release) = fixture(dir.path());
        let material = Pir2SealedSigningMaterialV1::from_seed(&[0x71; 32]);
        let claims = Pir2SealedReceiptClaimsV1::for_release(
            &release,
            Pir2SealedReceiptPhaseV1::Probe,
            46,
            NONCE,
            [0x82; 32],
            BOOT_ID,
            Some(&material),
        )
        .unwrap();
        assert!(check_claims(
            &claims,
            &release,
            Pir2SealedReceiptPhaseV1::Probe,
            46,
            NONCE,
            BOOT_ID
        )
        .is_ok());

        let mut other_release = claims.clone();
        other_release.release_artifact_digest[0] ^= 1;
        let error = check_claims(
            &other_release,
            &release,
            Pir2SealedReceiptPhaseV1::Probe,
            46,
            NONCE,
            BOOT_ID,
        )
        .unwrap_err();
        assert!(error.contains("different release"), "{error}");

        let mut other_generation = claims.clone();
        other_generation.identity_generation = 4;
        let error = check_claims(
            &other_generation,
            &release,
            Pir2SealedReceiptPhaseV1::Probe,
            46,
            NONCE,
            BOOT_ID,
        )
        .unwrap_err();
        assert!(error.contains("generation"), "{error}");

        // y = 2 has no square root on the curve, so this is not a point.
        let mut bad_key = claims;
        bad_key.public_keys.service_identity = [0; 32];
        bad_key.public_keys.service_identity[0] = 2;
        let error = check_claims(
            &bad_key,
            &release,
            Pir2SealedReceiptPhaseV1::Probe,
            46,
            NONCE,
            BOOT_ID,
        )
        .unwrap_err();
        assert!(error.contains("Ed25519"), "{error}");
    }
}
