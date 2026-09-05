use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use clap::Args;
use pir_attest_verify::policy::{verify_policy, PolicyRequirements};
use pir_attest_verify::{SnpReport, TcbVersion, SNP_REPORT_LEN};
use pir_private_files::{
    read_private_file_bounded_v1, write_atomic_noreplace_private_file_v1, PrivateFileModeV1,
};
use pir_runtime_core::snp_sealed_secrets::{
    encode_signed_pir2_sealed_release_v1, Pir2PreReleaseObservationClaimsV1,
    Pir2PreReleaseObservationReceiptV1, Pir2SealedReleaseClaimsV1, SnpDerivedKeyRequestV1,
    SnpTcbVersionV1, VerifiedPir2SealedReleaseV1, PIR2_PRE_RELEASE_OBSERVATION_RECEIPT_LEN_V1,
};
use sev::measurement::{
    snp::{snp_calc_launch_digest, SnpMeasurementArgs},
    vcpu_types::CpuType,
    vmsa::{GuestFeatures, VMMType},
};
use sev::parser::ByteParser as _;
use sha2::{Digest as _, Sha256};

const MAX_UKI_LEN: usize = 256 * 1024 * 1024;
const MAX_OVMF_LEN: usize = 64 * 1024 * 1024;
const MAX_CERT_LEN: usize = 128 * 1024;
const MAX_RELEASE_LEN: usize = 4096;

const REQUIRED_VCPUS: u32 = 4;
const REQUIRED_VCPU_SIGNATURE: u32 = 0x00B1_0F10;
const REQUIRED_GUEST_FEATURES: u64 = 0x1;
const REQUIRED_VMM_TYPE: &str = "qemu";
const REQUIRED_CPU_FAMILY: u8 = 26;
const REQUIRED_CPU_MODEL: u8 = 17;
const REQUIRED_CPU_STEPPING: u8 = 0;

/// Inputs for one offline, fail-closed pir2 sealed-release ceremony.
#[derive(Args, Debug)]
pub struct Pir2SealedReleaseArgs {
    /// Exact UKI passed to QEMU as the kernel; read once without following a symlink.
    #[arg(long)]
    pub uki: PathBuf,
    /// Operator-pinned SHA-256 of the exact UKI.
    #[arg(long)]
    pub expected_uki_sha256_hex: String,
    /// Exact pinned OVMF image; read once without following a symlink.
    #[arg(long)]
    pub ovmf: PathBuf,
    /// Operator-pinned SHA-256 of the exact OVMF image.
    #[arg(long)]
    pub expected_ovmf_sha256_hex: String,
    /// Canonical current-boot pre-release observation receipt.
    #[arg(long)]
    pub observation_receipt: PathBuf,
    /// Operator-known current observation ordinal.
    #[arg(long)]
    pub observation_ordinal: u64,
    /// Exact 32-byte fresh verifier nonce committed by the observation.
    #[arg(long)]
    pub observation_verifier_nonce_hex: String,
    /// Exact 32-byte current channel public key committed by the observation.
    #[arg(long)]
    pub observation_current_channel_pubkey_hex: String,
    /// Exact 16-byte current boot ID committed by the observation.
    #[arg(long)]
    pub observation_boot_id_hex: String,
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
    /// Launch vCPU count; the source contract accepts exactly 4.
    #[arg(long)]
    pub vcpus: u32,
    /// Exact QEMU CPUID signature; the source contract accepts 0x00B10F10 only.
    #[arg(long)]
    pub vcpu_sig_hex: String,
    /// VMM implementation; the source contract accepts lowercase `qemu` only.
    #[arg(long)]
    pub vmm_type: String,
    /// Kernel guest features; the source contract accepts 0x1 only.
    #[arg(long)]
    pub guest_features_hex: String,
    /// Full SNP guest policy expected in the signed report and release.
    #[arg(long)]
    pub expected_guest_policy_hex: String,

    /// Provider identifier bound into the release, envelope, and receipts.
    #[arg(long)]
    pub provider_id_hex: String,
    /// Stable server identifier bound into the release.
    #[arg(long)]
    pub stable_server_id: String,
    /// Minimum FMC SVN, if the CPU generation reports one.
    #[arg(long)]
    pub minimum_tcb_fmc: Option<u8>,
    #[arg(long)]
    pub minimum_tcb_bootloader: u8,
    #[arg(long)]
    pub minimum_tcb_tee: u8,
    #[arg(long)]
    pub minimum_tcb_snp: u8,
    #[arg(long)]
    pub minimum_tcb_microcode: u8,
    /// Pre-reserved identity generation (must be nonzero).
    #[arg(long)]
    pub identity_generation: u64,

    /// Owner-only raw 32-byte Ed25519 operator signing key.
    #[arg(long)]
    pub operator_signing_key: PathBuf,
    /// New owner-only canonical release path; existing names are never replaced.
    #[arg(long)]
    pub out: PathBuf,
}

pub fn run(args: Pir2SealedReleaseArgs) -> Result<(), String> {
    let observation_claims = Pir2PreReleaseObservationClaimsV1::new(
        args.observation_ordinal,
        parse_fixed_hex::<32>(
            &args.observation_verifier_nonce_hex,
            "observation verifier nonce",
        )?,
        parse_fixed_hex::<32>(
            &args.observation_current_channel_pubkey_hex,
            "observation current channel public key",
        )?,
        parse_fixed_hex::<16>(&args.observation_boot_id_hex, "observation boot ID")?,
    )
    .map_err(|error| format!("validate expected pre-release observation claims: {error}"))?;
    let observation_receipt_bytes = read_public_bounded(
        &args.observation_receipt,
        PIR2_PRE_RELEASE_OBSERVATION_RECEIPT_LEN_V1,
        "canonical pre-release observation receipt",
    )?;
    let observation_receipt = Pir2PreReleaseObservationReceiptV1::decode_and_verify(
        &observation_receipt_bytes,
        &observation_claims,
    )
    .map_err(|error| format!("verify canonical pre-release observation receipt: {error}"))?;
    let expected_report_data = observation_claims
        .report_data()
        .map_err(|error| format!("derive observation REPORT_DATA: {error}"))?;
    let expected_ark_sha256 =
        parse_fixed_hex::<32>(&args.expected_ark_sha256_hex, "expected ARK SHA-256")?;

    // The AMD trust decision deliberately precedes launch-artifact processing.
    let report = verify_offline_report(
        observation_receipt.raw_report(),
        &args.ark,
        &args.ask,
        &args.vcek,
        expected_ark_sha256,
        expected_report_data,
    )?;

    validate_launch_tuple(
        args.vcpus,
        parse_hex_u64(&args.vcpu_sig_hex, "vCPU signature")?,
        &args.vmm_type,
        parse_hex_u64(&args.guest_features_hex, "guest features")?,
    )?;
    validate_report_cpu(&report)?;

    let uki = read_public_bounded(&args.uki, MAX_UKI_LEN, "exact UKI")?;
    let ovmf = read_public_bounded(&args.ovmf, MAX_OVMF_LEN, "pinned OVMF")?;
    let expected_uki_sha256 =
        parse_fixed_hex::<32>(&args.expected_uki_sha256_hex, "expected UKI SHA-256")?;
    let expected_ovmf_sha256 =
        parse_fixed_hex::<32>(&args.expected_ovmf_sha256_hex, "expected OVMF SHA-256")?;
    let uki_sha256 = verify_exact_sha256(&uki, expected_uki_sha256, "UKI")?;
    verify_exact_sha256(&ovmf, expected_ovmf_sha256, "OVMF")?;

    let measurement = compute_exact_launch_measurement(&uki, &ovmf, args.vcpus)?;
    let expected_guest_policy =
        parse_hex_u64(&args.expected_guest_policy_hex, "expected guest policy")?;
    let minimum_tcb = SnpTcbVersionV1 {
        fmc: args.minimum_tcb_fmc,
        bootloader: args.minimum_tcb_bootloader,
        tee: args.minimum_tcb_tee,
        snp: args.minimum_tcb_snp,
        microcode: args.minimum_tcb_microcode,
    };
    validate_verified_observation(
        &report,
        expected_report_data,
        measurement,
        expected_guest_policy,
        minimum_tcb,
    )?;

    let claims = Pir2SealedReleaseClaimsV1 {
        provider_id: parse_fixed_hex::<32>(&args.provider_id_hex, "provider_id")?,
        stable_server_id: args.stable_server_id,
        uki_sha256,
        expected_measurement: measurement,
        expected_guest_policy,
        minimum_tcb,
        derived_key_request: SnpDerivedKeyRequestV1::production().canonical_evidence(),
        identity_generation: args.identity_generation,
    };

    // This is intentionally the first operator-key access in the command.
    persist_release(&claims, &args.operator_signing_key, &args.out)?;
    println!(
        "pir2 sealed release written: uki_sha256={} measurement={}",
        hex::encode(uki_sha256),
        hex::encode(measurement)
    );
    Ok(())
}

fn verify_offline_report(
    report_bytes: &[u8],
    ark_path: &Path,
    ask_path: &Path,
    vcek_path: &Path,
    expected_ark_sha256: [u8; 32],
    expected_report_data: [u8; 64],
) -> Result<SnpReport, String> {
    if report_bytes.len() != SNP_REPORT_LEN {
        return Err(format!(
            "raw SNP report must contain exactly {SNP_REPORT_LEN} bytes"
        ));
    }
    let ark = read_public_bounded(ark_path, MAX_CERT_LEN, "AMD ARK")?;
    let ask = read_public_bounded(ask_path, MAX_CERT_LEN, "AMD ASK")?;
    let vcek = read_public_bounded(vcek_path, MAX_CERT_LEN, "AMD VCEK")?;

    pir_attest_verify::verify_chain(&ark, &ask, &vcek, Some(expected_ark_sha256))
        .map_err(|error| format!("AMD certificate chain rejected: {error}"))?;
    let report = pir_attest_verify::verify_report_against_vcek(report_bytes, &vcek)
        .map_err(|error| format!("SNP report rejected: {error}"))?;
    if report.report_data != expected_report_data {
        return Err("SNP REPORT_DATA differs from the fresh operator binding".to_owned());
    }
    Ok(report)
}

fn validate_launch_tuple(
    vcpus: u32,
    vcpu_signature: u64,
    vmm_type: &str,
    guest_features: u64,
) -> Result<(), String> {
    if vcpus != REQUIRED_VCPUS
        || vcpu_signature != u64::from(REQUIRED_VCPU_SIGNATURE)
        || vmm_type != REQUIRED_VMM_TYPE
        || guest_features != REQUIRED_GUEST_FEATURES
    {
        return Err(format!(
            "launch tuple drift: require vcpus={REQUIRED_VCPUS}, vcpu_sig=0x{REQUIRED_VCPU_SIGNATURE:08X}, vmm_type={REQUIRED_VMM_TYPE}, guest_features=0x{REQUIRED_GUEST_FEATURES:x}, no external initrd, and no append"
        ));
    }
    Ok(())
}

fn validate_report_cpu(report: &SnpReport) -> Result<(), String> {
    if report.cpuid_fam_id != Some(REQUIRED_CPU_FAMILY)
        || report.cpuid_mod_id != Some(REQUIRED_CPU_MODEL)
        || report.cpuid_step != Some(REQUIRED_CPU_STEPPING)
    {
        return Err(
            "signed report CPUID is not exact Turin 9745 family=26 model=17 stepping=0".to_owned(),
        );
    }
    Ok(())
}

fn verify_exact_sha256(bytes: &[u8], expected: [u8; 32], label: &str) -> Result<[u8; 32], String> {
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if actual != expected {
        return Err(format!("{label} SHA-256 differs from its operator pin"));
    }
    Ok(actual)
}

fn compute_exact_launch_measurement(
    uki: &[u8],
    ovmf: &[u8],
    vcpus: u32,
) -> Result<[u8; 48], String> {
    let mut uki_copy = tempfile::NamedTempFile::new()
        .map_err(|error| format!("create exact UKI measurement copy: {error}"))?;
    uki_copy
        .write_all(uki)
        .and_then(|_| uki_copy.as_file().sync_all())
        .map_err(|error| format!("materialize exact UKI measurement copy: {error}"))?;
    let mut ovmf_copy = tempfile::NamedTempFile::new()
        .map_err(|error| format!("create pinned OVMF measurement copy: {error}"))?;
    ovmf_copy
        .write_all(ovmf)
        .and_then(|_| ovmf_copy.as_file().sync_all())
        .map_err(|error| format!("materialize pinned OVMF measurement copy: {error}"))?;

    let digest = snp_calc_launch_digest(SnpMeasurementArgs {
        vcpus,
        vcpu_type: CpuType::EpycTurin9745,
        ovmf_file: ovmf_copy.path().to_path_buf(),
        guest_features: GuestFeatures(REQUIRED_GUEST_FEATURES),
        kernel_file: Some(uki_copy.path().to_path_buf()),
        initrd_file: None,
        append: None,
        ovmf_hash_str: None,
        vmm_type: Some(VMMType::QEMU),
    })
    .map_err(|error| format!("exact launch measurement failed: {error}"))?;
    let bytes: Vec<u8> = digest
        .try_into()
        .map_err(|error| format!("extract exact launch measurement: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| "exact launch measurement has the wrong length".to_owned())
}

fn validate_verified_observation(
    report: &SnpReport,
    expected_report_data: [u8; 64],
    measurement: [u8; 48],
    expected_guest_policy: u64,
    minimum_tcb: SnpTcbVersionV1,
) -> Result<(), String> {
    if report.report_data != expected_report_data {
        return Err("SNP REPORT_DATA differs from the fresh operator binding".to_owned());
    }
    if report.measurement != measurement {
        return Err("recomputed exact launch measurement differs from signed report".to_owned());
    }
    let raw_guest_policy = u64::from_le_bytes(
        report
            .policy
            .to_bytes()
            .map_err(|error| format!("encode signed guest policy: {error}"))?,
    );
    if raw_guest_policy != expected_guest_policy {
        return Err("full signed guest policy differs from the operator pin".to_owned());
    }
    let requirements = PolicyRequirements {
        min_tcb: Some(TcbVersion {
            fmc: minimum_tcb.fmc,
            bootloader: minimum_tcb.bootloader,
            tee: minimum_tcb.tee,
            snp: minimum_tcb.snp,
            microcode: minimum_tcb.microcode,
        }),
        expected_measurement: Some(measurement),
        ..PolicyRequirements::default()
    };
    verify_policy(report, &requirements)
        .map_err(|error| format!("signed SNP report violates production policy: {error}"))
}

fn persist_release(
    claims: &Pir2SealedReleaseClaimsV1,
    operator_key_path: &Path,
    out: &Path,
) -> Result<(), String> {
    claims
        .validate_for_signing()
        .map_err(|error| format!("validate production release claims: {error}"))?;
    let operator = crate::keygen::read_secret_key(operator_key_path)?;
    let bytes = encode_signed_pir2_sealed_release_v1(claims, &operator)
        .map_err(|error| format!("encode canonical release: {error}"))?;
    let verified =
        VerifiedPir2SealedReleaseV1::decode_and_verify(&bytes, &operator.verifying_key())
            .map_err(|error| format!("self-verify canonical release: {error}"))?;
    if verified.exact_bytes() != bytes {
        return Err("canonical release readback differs before publication".to_owned());
    }

    write_atomic_noreplace_private_file_v1(out, &bytes, false, "pir2 sealed release")?;
    let readback = read_private_file_bounded_v1(
        out,
        MAX_RELEASE_LEN,
        PrivateFileModeV1::ReadOnlyOrReadWrite,
        "pir2 sealed release readback",
    )?;
    if readback.as_slice() != bytes {
        return Err("published release readback differs from signed bytes".to_owned());
    }
    VerifiedPir2SealedReleaseV1::decode_and_verify(&readback, &operator.verifying_key())
        .map_err(|error| format!("verify published release readback: {error}"))?;
    Ok(())
}

fn parse_hex_u64(value: &str, label: &str) -> Result<u64, String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() || value.len() > 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be 1..=16 hexadecimal digits"));
    }
    u64::from_str_radix(value, 16).map_err(|_| format!("{label} is not valid hexadecimal"))
}

fn parse_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != N * 2 {
        return Err(format!("{label} must contain exactly {} hex digits", N * 2));
    }
    let decoded = hex::decode(value).map_err(|_| format!("{label} is not valid hexadecimal"))?;
    decoded
        .try_into()
        .map_err(|_| format!("{label} has the wrong decoded length"))
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicFileSnapshotV1 {
    device: u128,
    inode: u128,
    mode: u64,
    size: i128,
    modified_seconds: i128,
    modified_nanoseconds: i128,
    changed_seconds: i128,
    changed_nanoseconds: i128,
}

#[cfg(unix)]
fn public_file_snapshot_v1(stat: &rustix::fs::Stat) -> PublicFileSnapshotV1 {
    PublicFileSnapshotV1 {
        device: stat.st_dev as u128,
        inode: stat.st_ino as u128,
        mode: stat.st_mode as u64,
        size: stat.st_size as i128,
        modified_seconds: stat.st_mtime as i128,
        modified_nanoseconds: stat.st_mtime_nsec as i128,
        changed_seconds: stat.st_ctime as i128,
        changed_nanoseconds: stat.st_ctime_nsec as i128,
    }
}

#[cfg(unix)]
fn read_public_bounded(path: &Path, max: usize, label: &str) -> Result<Vec<u8>, String> {
    use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};

    let fd = rustix_fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| format!("open {label} {} failed: {error}", path.display()))?;
    let stat = rustix_fs::fstat(&fd)
        .map_err(|error| format!("inspect {label} {} failed: {error}", path.display()))?;
    let snapshot = public_file_snapshot_v1(&stat);
    if !FileType::from_raw_mode(stat.st_mode).is_file() || stat.st_size <= 0 {
        return Err(format!("{label} must be a non-empty regular file"));
    }
    let length = usize::try_from(stat.st_size).map_err(|_| format!("{label} is too large"))?;
    if length > max {
        return Err(format!("{label} exceeds the {max}-byte bound"));
    }
    let file = std::fs::File::from(fd);
    let mut bytes = Vec::with_capacity(length);
    (&file)
        .take((max as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {label} {} failed: {error}", path.display()))?;
    let after = rustix_fs::fstat(&file)
        .map_err(|error| format!("reinspect {label} {} failed: {error}", path.display()))?;
    if bytes.len() != length || bytes.len() > max || public_file_snapshot_v1(&after) != snapshot {
        return Err(format!("{label} changed while it was read"));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_public_bounded(path: &Path, max: usize, label: &str) -> Result<Vec<u8>, String> {
    let _ = (path, max);
    Err(format!(
        "reading {label} requires a local Unix/POSIX filesystem"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pir_runtime_core::snp_sealed_secrets::{
        FreshSnpReportV1, SnpDerivedKeyMaterialV1, SnpDerivedKeyProvider,
        SnpDerivedKeyProviderErrorV1,
    };
    use std::fs;

    struct ObservationProviderV1;

    impl SnpDerivedKeyProvider for ObservationProviderV1 {
        fn fresh_report(
            &self,
            report_data: [u8; 64],
        ) -> Result<FreshSnpReportV1, SnpDerivedKeyProviderErrorV1> {
            let mut raw_report = vec![0xA5; SNP_REPORT_LEN];
            raw_report[0x50..0x90].copy_from_slice(&report_data);
            Ok(FreshSnpReportV1 {
                report_version: 3,
                vmpl: 0,
                guest_policy: 1 << 17,
                measurement: [0x33; 48],
                report_data,
                reported_tcb: SnpTcbVersionV1 {
                    fmc: Some(1),
                    bootloader: 1,
                    tee: 1,
                    snp: 1,
                    microcode: 1,
                },
                committed_tcb: SnpTcbVersionV1 {
                    fmc: Some(1),
                    bootloader: 1,
                    tee: 1,
                    snp: 1,
                    microcode: 1,
                },
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
            identity_generation: 1,
        }
    }

    fn observation_args(dir: &Path) -> Pir2SealedReleaseArgs {
        let claims =
            Pir2PreReleaseObservationClaimsV1::new(1, [0x41; 32], [0x43; 32], [0x42; 16]).unwrap();
        let receipt =
            Pir2PreReleaseObservationReceiptV1::request(claims, &ObservationProviderV1).unwrap();
        let receipt_path = dir.join("observation.bin");
        fs::write(&receipt_path, receipt.encode().unwrap()).unwrap();
        Pir2SealedReleaseArgs {
            uki: dir.join("missing.uki"),
            expected_uki_sha256_hex: hex::encode([1_u8; 32]),
            ovmf: dir.join("missing.ovmf"),
            expected_ovmf_sha256_hex: hex::encode([2_u8; 32]),
            observation_receipt: receipt_path,
            observation_ordinal: 1,
            observation_verifier_nonce_hex: hex::encode([0x41_u8; 32]),
            observation_current_channel_pubkey_hex: hex::encode([0x43_u8; 32]),
            observation_boot_id_hex: hex::encode([0x42_u8; 16]),
            ark: dir.join("missing.ark"),
            ask: dir.join("missing.ask"),
            vcek: dir.join("missing.vcek"),
            expected_ark_sha256_hex: hex::encode([3_u8; 32]),
            vcpus: REQUIRED_VCPUS,
            vcpu_sig_hex: format!("{REQUIRED_VCPU_SIGNATURE:08x}"),
            vmm_type: REQUIRED_VMM_TYPE.to_owned(),
            guest_features_hex: format!("{REQUIRED_GUEST_FEATURES:x}"),
            expected_guest_policy_hex: format!("{:x}", 1_u64 << 17),
            provider_id_hex: hex::encode([4_u8; 32]),
            stable_server_id: "pir2-test".to_owned(),
            minimum_tcb_fmc: Some(1),
            minimum_tcb_bootloader: 1,
            minimum_tcb_tee: 1,
            minimum_tcb_snp: 1,
            minimum_tcb_microcode: 1,
            identity_generation: 1,
            operator_signing_key: dir.join("must-not-read-operator.key"),
            out: dir.join("must-not-create-release.bin"),
        }
    }

    fn verified_report() -> SnpReport {
        let claims = release_claims();
        let tcb = TcbVersion {
            fmc: Some(1),
            bootloader: 1,
            tee: 1,
            snp: 1,
            microcode: 1,
        };
        SnpReport {
            version: 3,
            policy: claims.expected_guest_policy.into(),
            report_data: [0x44; 64],
            measurement: claims.expected_measurement,
            reported_tcb: tcb,
            committed_tcb: tcb,
            cpuid_fam_id: Some(REQUIRED_CPU_FAMILY),
            cpuid_mod_id: Some(REQUIRED_CPU_MODEL),
            cpuid_step: Some(REQUIRED_CPU_STEPPING),
            ..SnpReport::default()
        }
    }

    #[test]
    fn canonical_release_positive_fixture_self_verifies_and_is_noreplace() {
        let dir = crate::keygen::private_tempdir_v1().unwrap();
        let key_path = dir.path().join("operator.key");
        let out = dir.path().join("release.bin");
        let operator = SigningKey::from_bytes(&[0x55; 32]);
        write_atomic_noreplace_private_file_v1(
            &key_path,
            &operator.to_bytes(),
            false,
            "test operator key",
        )
        .unwrap();

        persist_release(&release_claims(), &key_path, &out).unwrap();
        let bytes = fs::read(&out).unwrap();
        let verified =
            VerifiedPir2SealedReleaseV1::decode_and_verify(&bytes, &operator.verifying_key())
                .unwrap();
        assert_eq!(verified.exact_bytes(), bytes);
        assert_eq!(verified.claims(), &release_claims());
        assert!(persist_release(&release_claims(), &key_path, &out).is_err());
    }

    #[test]
    fn invalid_production_claims_fail_before_operator_key_access() {
        let dir = crate::keygen::private_tempdir_v1().unwrap();
        let missing_key = dir.path().join("must-not-read-operator.key");
        let out = dir.path().join("must-not-create-release.bin");

        let mut invalid_claims = Vec::new();

        let mut invalid_policy = release_claims();
        invalid_policy.expected_guest_policy |= 1 << 19;
        invalid_claims.push(invalid_policy);

        let mut empty_tcb = release_claims();
        empty_tcb.minimum_tcb = SnpTcbVersionV1 {
            fmc: None,
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        invalid_claims.push(empty_tcb);

        let mut zero_provider = release_claims();
        zero_provider.provider_id = [0_u8; 32];
        invalid_claims.push(zero_provider);

        let mut zero_generation = release_claims();
        zero_generation.identity_generation = 0;
        invalid_claims.push(zero_generation);

        let mut invalid_server = release_claims();
        invalid_server.stable_server_id = "pir2\nserver".to_owned();
        invalid_claims.push(invalid_server);

        for claims in invalid_claims {
            let error = persist_release(&claims, &missing_key, &out).unwrap_err();
            assert!(error.contains("validate production release claims"));
            assert!(!missing_key.exists());
            assert!(!out.exists());
        }
    }

    #[test]
    fn observation_replay_fields_are_rejected_before_key_or_output_access() {
        let dir = crate::keygen::private_tempdir_v1().unwrap();
        for variant in 0..4 {
            let mut args = observation_args(dir.path());
            match variant {
                0 => args.observation_ordinal += 1,
                1 => args.observation_verifier_nonce_hex = hex::encode([0x51_u8; 32]),
                2 => args.observation_current_channel_pubkey_hex = hex::encode([0x53_u8; 32]),
                3 => args.observation_boot_id_hex = hex::encode([0x52_u8; 16]),
                _ => unreachable!(),
            }
            let out = args.out.clone();
            let key = args.operator_signing_key.clone();
            let error = run(args).unwrap_err();
            assert!(error.contains("claims differ from current boot expectations"));
            assert!(!out.exists());
            assert!(!key.exists());
        }
    }

    #[test]
    fn signed_report_fixture_passes_and_tampering_fails_with_zero_output() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../web/public/proofs/trust-chain/delta_940611_948454/bhtm");
        let report_path = fixture.join("sev-snp-report.bin");
        let ark = fixture.join("ark.pem");
        let ask = fixture.join("ask.pem");
        let vcek = fixture.join("vcek.pem");
        let report_data: [u8; 64] = fs::read(fixture.join("report-data.bin"))
            .unwrap()
            .try_into()
            .unwrap();
        let ark_sha256 = parse_fixed_hex::<32>(
            "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a",
            "fixture ARK",
        )
        .unwrap();

        let report_bytes = fs::read(&report_path).unwrap();
        let report =
            verify_offline_report(&report_bytes, &ark, &ask, &vcek, ark_sha256, report_data)
                .unwrap();
        assert_eq!(report.report_data, report_data);

        let dir = crate::keygen::private_tempdir_v1().unwrap();
        let out = dir.path().join("must-not-create-release.bin");
        let mut tampered = fs::read(report_path).unwrap();
        tampered[144] ^= 1;
        assert!(
            verify_offline_report(&tampered, &ark, &ask, &vcek, ark_sha256, report_data,).is_err()
        );
        assert!(!out.exists());
    }

    #[test]
    fn exact_measurement_matches_independent_python_vector() {
        let ovmf = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../vendor/sev/tests/measurement/ovmf_AmdSev_suffix.bin"),
        )
        .unwrap();

        let measurement = compute_exact_launch_measurement(&[], &ovmf, REQUIRED_VCPUS).unwrap();

        assert_eq!(
            hex::encode(measurement),
            "d380869e4b3b293c55b438f1d744684d8f9ed687aeb0bd69055ff79976973452a335a7cf9973e843f01865b80221590d"
        );
    }

    #[test]
    fn observation_mismatches_fail_before_any_output() {
        let dir = crate::keygen::private_tempdir_v1().unwrap();
        let out = dir.path().join("release.bin");
        let report = verified_report();
        let claims = release_claims();

        assert!(validate_verified_observation(
            &report,
            [0x45; 64],
            claims.expected_measurement,
            claims.expected_guest_policy,
            claims.minimum_tcb,
        )
        .is_err());
        let mut wrong_measurement = claims.expected_measurement;
        wrong_measurement[0] ^= 1;
        assert!(validate_verified_observation(
            &report,
            report.report_data,
            wrong_measurement,
            claims.expected_guest_policy,
            claims.minimum_tcb,
        )
        .is_err());
        assert!(validate_verified_observation(
            &report,
            report.report_data,
            claims.expected_measurement,
            claims.expected_guest_policy ^ (1 << 16),
            claims.minimum_tcb,
        )
        .is_err());
        let mut missing_reserved_one = report;
        missing_reserved_one.policy =
            sev::firmware::guest::GuestPolicy::from_bytes(&0_u64.to_le_bytes()).unwrap();
        assert!(validate_verified_observation(
            &missing_reserved_one,
            missing_reserved_one.report_data,
            claims.expected_measurement,
            claims.expected_guest_policy,
            claims.minimum_tcb,
        )
        .is_err());
        assert!(!out.exists());
    }

    #[test]
    fn uki_ovmf_and_launch_tuple_drift_fail_with_zero_output() {
        let dir = crate::keygen::private_tempdir_v1().unwrap();
        let out = dir.path().join("release.bin");
        let pin: [u8; 32] = Sha256::digest(b"exact").into();
        assert!(verify_exact_sha256(b"different UKI", pin, "UKI").is_err());
        assert!(verify_exact_sha256(b"different OVMF", pin, "OVMF").is_err());
        assert!(validate_launch_tuple(
            REQUIRED_VCPUS + 1,
            u64::from(REQUIRED_VCPU_SIGNATURE),
            REQUIRED_VMM_TYPE,
            REQUIRED_GUEST_FEATURES,
        )
        .is_err());
        assert!(validate_launch_tuple(
            REQUIRED_VCPUS,
            u64::from(REQUIRED_VCPU_SIGNATURE) ^ 1,
            REQUIRED_VMM_TYPE,
            REQUIRED_GUEST_FEATURES,
        )
        .is_err());
        assert!(!out.exists());
    }
}
