//! Measurement-bound persistence for pir2's two long-lived signing roles.
//!
//! This module seals exactly two independently generated Ed25519 seeds: the
//! pir2 service identity seed and the issuer-clearing authentication seed. It
//! does not persist BATs, payment state, ORAM keys, or any plaintext secret.
//! The ciphertext file is intentionally treated as untrusted and does not
//! provide rollback protection by itself; public identity generations and
//! issuer clearing epochs close replay in their respective authorities.
//! Core-dump and swap controls belong to the later measured startup profile;
//! this crypto/IO core neither enables them nor claims to enforce them.

use std::fmt;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey};
use hkdf::Hkdf;
use pir_private_files::{
    prepare_new_private_file_v1, read_private_file_bounded_v1,
    write_atomic_noreplace_private_file_v1, PrivateFileModeV1,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Linux SEV guest message version deliberately pinned for envelope V1.
pub const SNP_DERIVED_KEY_MESSAGE_VERSION_V1: u32 = 1;
/// VCEK root, not VMRK.
pub const SNP_DERIVED_KEY_ROOT_KEY_SELECT_V1: u32 = 0;
/// `GUEST_POLICY | MEASUREMENT` from the AMD SEV-SNP firmware ABI.
pub const SNP_DERIVED_KEY_GUEST_FIELD_SELECT_V1: u64 = 0x9;
/// The measured runtime operates at VMPL 0.
pub const SNP_DERIVED_KEY_VMPL_V1: u32 = 0;
/// V1 deliberately does not opt in to guest-SVN derivation.
pub const SNP_DERIVED_KEY_GUEST_SVN_V1: u32 = 0;
/// V1 deliberately does not opt in to TCB-version derivation.
pub const SNP_DERIVED_KEY_TCB_VERSION_V1: u64 = 0;
/// V1 requests do not carry the message-version-2 mitigation vector.
pub const SNP_DERIVED_KEY_LAUNCH_MIT_VECTOR_V1: u64 = 0;

const DERIVED_KEY_EVIDENCE_LEN_V1: usize = 44;
const ENVELOPE_MAGIC_V1: &[u8; 8] = b"BPIRSLD1";
const ENVELOPE_CODEC_VERSION_V1: u16 = 1;
const ENVELOPE_HEADER_DOMAIN_V1: &[u8] = b"BitcoinPIR/pir2/sealed-header/v1";
const ENVELOPE_PLAINTEXT_DOMAIN_V1: &[u8] = b"BitcoinPIR/pir2/sealed-plaintext/v1";
const ENVELOPE_KDF_SALT_V1: &[u8] = b"BitcoinPIR/pir2/sealed-kek-salt/v1";
const ENVELOPE_KDF_INFO_DOMAIN_V1: &[u8] = b"BitcoinPIR/pir2/sealed-kek-info/v1";
const SERVICE_IDENTITY_FINGERPRINT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/pir2/service-identity-fingerprint/v1";
const CLEARING_FINGERPRINT_DOMAIN_V1: &[u8] = b"BitcoinPIR/pir2/clearing-fingerprint/v1";
const MAX_STABLE_SERVER_ID_LEN_V1: usize = 255;
const MAX_ENVELOPE_HEADER_LEN_V1: usize = 1024;
const MAX_ENVELOPE_FILE_LEN_V1: usize = 4096;
const NONCE_LEN_V1: usize = 24;
const SEED_LEN_V1: usize = 32;
const AEAD_TAG_LEN_V1: usize = 16;

/// Immutable semantic request used for every pir2 envelope V1 derivation.
///
/// Fields are private so callers cannot silently drift away from the
/// source-pinned VCEK/VMPL0/0x9/message-version-1 contract. The canonical
/// evidence bytes are encoded field-by-field in little endian; no ABI padding
/// or in-memory representation is transmuted into evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnpDerivedKeyRequestV1 {
    message_version: u32,
    root_key_select: u32,
    reserved: u32,
    guest_field_select: u64,
    vmpl: u32,
    guest_svn: u32,
    tcb_version: u64,
    launch_mit_vector: u64,
}

impl SnpDerivedKeyRequestV1 {
    /// The only request accepted by this envelope schema.
    pub const fn production() -> Self {
        Self {
            message_version: SNP_DERIVED_KEY_MESSAGE_VERSION_V1,
            root_key_select: SNP_DERIVED_KEY_ROOT_KEY_SELECT_V1,
            reserved: 0,
            guest_field_select: SNP_DERIVED_KEY_GUEST_FIELD_SELECT_V1,
            vmpl: SNP_DERIVED_KEY_VMPL_V1,
            guest_svn: SNP_DERIVED_KEY_GUEST_SVN_V1,
            tcb_version: SNP_DERIVED_KEY_TCB_VERSION_V1,
            launch_mit_vector: SNP_DERIVED_KEY_LAUNCH_MIT_VECTOR_V1,
        }
    }

    /// Kernel/firmware guest-message version, fixed to V1.
    pub const fn message_version(self) -> u32 {
        self.message_version
    }

    /// Root selector, fixed to the VCEK root (`0`).
    pub const fn root_key_select(self) -> u32 {
        self.root_key_select
    }

    /// Selected guest fields, exactly `GUEST_POLICY | MEASUREMENT` (`0x9`).
    pub const fn guest_field_select(self) -> u64 {
        self.guest_field_select
    }

    /// Requested VMPL, exactly zero.
    pub const fn vmpl(self) -> u32 {
        self.vmpl
    }

    /// Canonical complete request evidence, including explicit reserved and
    /// message-version-1-only zero fields.
    pub fn canonical_evidence(self) -> [u8; DERIVED_KEY_EVIDENCE_LEN_V1] {
        let mut out = [0_u8; DERIVED_KEY_EVIDENCE_LEN_V1];
        let mut offset = 0;
        put_fixed(&mut out, &mut offset, &self.message_version.to_le_bytes());
        put_fixed(&mut out, &mut offset, &self.root_key_select.to_le_bytes());
        put_fixed(&mut out, &mut offset, &self.reserved.to_le_bytes());
        put_fixed(
            &mut out,
            &mut offset,
            &self.guest_field_select.to_le_bytes(),
        );
        put_fixed(&mut out, &mut offset, &self.vmpl.to_le_bytes());
        put_fixed(&mut out, &mut offset, &self.guest_svn.to_le_bytes());
        put_fixed(&mut out, &mut offset, &self.tcb_version.to_le_bytes());
        put_fixed(&mut out, &mut offset, &self.launch_mit_vector.to_le_bytes());
        debug_assert_eq!(offset, out.len());
        out
    }
}

impl Default for SnpDerivedKeyRequestV1 {
    fn default() -> Self {
        Self::production()
    }
}

fn put_fixed<const N: usize>(output: &mut [u8; N], offset: &mut usize, bytes: &[u8]) {
    let end = *offset + bytes.len();
    output[*offset..end].copy_from_slice(bytes);
    *offset = end;
}

/// Compact, comparison-safe representation of the SNP TCB fields used by the
/// release floor. Each populated floor component is checked independently.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SnpTcbVersionV1 {
    pub fmc: Option<u8>,
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

impl SnpTcbVersionV1 {
    fn meets_floor(self, floor: Self) -> bool {
        let fmc_meets_floor = match floor.fmc {
            None => true,
            Some(minimum) => self.fmc.is_some_and(|actual| actual >= minimum),
        };
        fmc_meets_floor
            && self.bootloader >= floor.bootloader
            && self.tee >= floor.tee
            && self.snp >= floor.snp
            && self.microcode >= floor.microcode
    }

    fn no_component_exceeds(self, committed: Self) -> bool {
        match (self.fmc, committed.fmc) {
            (Some(actual), Some(maximum)) if actual > maximum => return false,
            (Some(_), None) => return false,
            _ => {}
        }
        self.bootloader <= committed.bootloader
            && self.tee <= committed.tee
            && self.snp <= committed.snp
            && self.microcode <= committed.microcode
    }

    fn encode_into(self, out: &mut Vec<u8>) {
        match self.fmc {
            Some(value) => {
                out.push(1);
                out.push(value);
            }
            None => {
                out.push(0);
                out.push(0);
            }
        }
        out.extend_from_slice(&[self.bootloader, self.tee, self.snp, self.microcode]);
    }

    fn decode(decoder: &mut DecoderV1<'_>) -> Result<Self, SnpSealedSecretsErrorV1> {
        let present = decoder.u8("minimum_tcb.fmc_present")?;
        let value = decoder.u8("minimum_tcb.fmc")?;
        let fmc = match (present, value) {
            (0, 0) => None,
            (1, value) => Some(value),
            _ => {
                return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
                    "non-canonical FMC floor",
                ))
            }
        };
        Ok(Self {
            fmc,
            bootloader: decoder.u8("minimum_tcb.bootloader")?,
            tee: decoder.u8("minimum_tcb.tee")?,
            snp: decoder.u8("minimum_tcb.snp")?,
            microcode: decoder.u8("minimum_tcb.microcode")?,
        })
    }
}

/// Trusted public values taken from a caller-pinned, signature-verified
/// release artifact. None of these values are learned from the ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pir2SealedReleaseV1 {
    pub provider_id: [u8; 32],
    pub stable_server_id: String,
    pub release_artifact_digest: [u8; 32],
    pub expected_measurement: [u8; 48],
    pub expected_guest_policy: u64,
    pub minimum_tcb: SnpTcbVersionV1,
    pub identity_generation: u64,
    pub clearing_authorization_epoch: u64,
}

impl Pir2SealedReleaseV1 {
    fn validate(&self) -> Result<(), SnpSealedSecretsErrorV1> {
        let server_id = self.stable_server_id.as_bytes();
        if server_id.is_empty()
            || server_id.len() > MAX_STABLE_SERVER_ID_LEN_V1
            || server_id.iter().any(|byte| byte.is_ascii_control())
        {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "stable_server_id must be non-empty printable UTF-8 within its bound",
            ));
        }
        if self.provider_id == [0_u8; 32] {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "provider_id must not be all zero",
            ));
        }
        if self.release_artifact_digest == [0_u8; 32] {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "release artifact digest must not be all zero",
            ));
        }
        if self.expected_measurement == [0_u8; 48] {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "expected measurement must not be all zero",
            ));
        }
        if self.identity_generation == 0 || self.clearing_authorization_epoch == 0 {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "identity generation and clearing epoch must be non-zero reservations",
            ));
        }
        if self.minimum_tcb.fmc.unwrap_or(0) == 0
            && self.minimum_tcb.bootloader == 0
            && self.minimum_tcb.tee == 0
            && self.minimum_tcb.snp == 0
            && self.minimum_tcb.microcode == 0
        {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "production TCB floor must not be empty",
            ));
        }
        const POLICY_RESERVED_ONE: u64 = 1 << 17;
        const POLICY_MIGRATE_MA: u64 = 1 << 18;
        const POLICY_DEBUG: u64 = 1 << 19;
        const POLICY_DEFINED_BITS: u64 = (1 << 26) - 1;
        if self.expected_guest_policy & POLICY_RESERVED_ONE == 0
            || self.expected_guest_policy & (POLICY_MIGRATE_MA | POLICY_DEBUG) != 0
            || self.expected_guest_policy & !POLICY_DEFINED_BITS != 0
        {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "expected guest policy is not a production SNP policy",
            ));
        }
        Ok(())
    }
}

/// Fresh report fields needed by the local pre-derivation policy gate.
///
/// The Linux adapter constructs this only from a newly requested typed SNP
/// report. Mock providers can construct it directly for narrow tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshSnpReportV1 {
    pub report_version: u32,
    pub vmpl: u32,
    pub guest_policy: u64,
    pub measurement: [u8; 48],
    pub report_data: [u8; 64],
    pub reported_tcb: SnpTcbVersionV1,
    pub committed_tcb: SnpTcbVersionV1,
}

/// Opaque zeroizing derived-key result. There is deliberately no raw-key
/// accessor or `Debug` implementation.
pub struct SnpDerivedKeyMaterialV1(Zeroizing<[u8; 32]>);

impl SnpDerivedKeyMaterialV1 {
    /// Construct an opaque result in provider implementations and tests.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self::from_zeroizing(Zeroizing::new(bytes))
    }

    fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Failures returned by a derived-key provider. They carry no secret bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnpDerivedKeyProviderErrorV1 {
    DeviceUnavailable,
    IoctlFailed(String),
    MalformedReport(String),
    RequestDrift,
}

impl fmt::Display for SnpDerivedKeyProviderErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceUnavailable => formatter.write_str("SEV guest device unavailable"),
            Self::IoctlFailed(error) => write!(formatter, "SEV guest ioctl failed: {error}"),
            Self::MalformedReport(error) => {
                write!(formatter, "fresh SNP report malformed: {error}")
            }
            Self::RequestDrift => formatter.write_str("derived-key request drifted from V1"),
        }
    }
}

impl std::error::Error for SnpDerivedKeyProviderErrorV1 {}

/// Narrow mockable boundary around fresh report and derived-key ioctls.
pub trait SnpDerivedKeyProvider {
    /// Request a new VMPL0 report carrying the supplied unpredictable data.
    fn fresh_report(
        &self,
        report_data: [u8; 64],
    ) -> Result<FreshSnpReportV1, SnpDerivedKeyProviderErrorV1>;

    /// Derive using exactly the supplied immutable V1 request.
    fn derive_key(
        &self,
        request: &SnpDerivedKeyRequestV1,
    ) -> Result<SnpDerivedKeyMaterialV1, SnpDerivedKeyProviderErrorV1>;
}

/// Production `/dev/sev-guest` adapter backed by the locked typed `sev` API.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxSevSnpDerivedKeyProviderV1;

impl SnpDerivedKeyProvider for LinuxSevSnpDerivedKeyProviderV1 {
    fn fresh_report(
        &self,
        report_data: [u8; 64],
    ) -> Result<FreshSnpReportV1, SnpDerivedKeyProviderErrorV1> {
        #[cfg(target_os = "linux")]
        {
            use sev::firmware::guest::{AttestationReport, Firmware};
            use sev::parser::ByteParser;

            let mut firmware =
                Firmware::open().map_err(|_| SnpDerivedKeyProviderErrorV1::DeviceUnavailable)?;
            let bytes = firmware
                .get_report(
                    Some(SNP_DERIVED_KEY_MESSAGE_VERSION_V1),
                    Some(report_data),
                    Some(SNP_DERIVED_KEY_VMPL_V1),
                )
                .map_err(|error| SnpDerivedKeyProviderErrorV1::IoctlFailed(error.to_string()))?;
            let report = AttestationReport::from_bytes(bytes.as_slice()).map_err(|error| {
                SnpDerivedKeyProviderErrorV1::MalformedReport(error.to_string())
            })?;
            let raw_policy = report.policy.to_bytes().map_err(|error| {
                SnpDerivedKeyProviderErrorV1::MalformedReport(error.to_string())
            })?;
            Ok(FreshSnpReportV1 {
                report_version: report.version,
                vmpl: report.vmpl,
                guest_policy: u64::from_le_bytes(raw_policy),
                measurement: report.measurement,
                report_data: report.report_data,
                reported_tcb: snp_tcb_from_sev_v1(report.reported_tcb),
                committed_tcb: snp_tcb_from_sev_v1(report.committed_tcb),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = report_data;
            Err(SnpDerivedKeyProviderErrorV1::DeviceUnavailable)
        }
    }

    fn derive_key(
        &self,
        request: &SnpDerivedKeyRequestV1,
    ) -> Result<SnpDerivedKeyMaterialV1, SnpDerivedKeyProviderErrorV1> {
        if *request != SnpDerivedKeyRequestV1::production() {
            return Err(SnpDerivedKeyProviderErrorV1::RequestDrift);
        }
        #[cfg(target_os = "linux")]
        {
            use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};

            let mut firmware =
                Firmware::open().map_err(|_| SnpDerivedKeyProviderErrorV1::DeviceUnavailable)?;
            let mut guest_fields = GuestFieldSelect::default();
            guest_fields.set_guest_policy(true);
            guest_fields.set_measurement(true);
            let typed_request = DerivedKey::new(
                false,
                guest_fields,
                SNP_DERIVED_KEY_VMPL_V1,
                SNP_DERIVED_KEY_GUEST_SVN_V1,
                SNP_DERIVED_KEY_TCB_VERSION_V1,
                None,
            );
            let key = Zeroizing::new(
                firmware
                    .get_derived_key(Some(SNP_DERIVED_KEY_MESSAGE_VERSION_V1), typed_request)
                    .map_err(|error| {
                        SnpDerivedKeyProviderErrorV1::IoctlFailed(error.to_string())
                    })?,
            );
            Ok(SnpDerivedKeyMaterialV1::from_zeroizing(key))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(SnpDerivedKeyProviderErrorV1::DeviceUnavailable)
        }
    }
}

#[cfg(target_os = "linux")]
fn snp_tcb_from_sev_v1(value: sev::firmware::host::TcbVersion) -> SnpTcbVersionV1 {
    SnpTcbVersionV1 {
        fmc: value.fmc,
        bootloader: value.bootloader,
        tee: value.tee,
        snp: value.snp,
        microcode: value.microcode,
    }
}

/// Public identifiers for the two independently generated signing roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pir2SealedPublicFingerprintsV1 {
    pub service_identity: [u8; 32],
    pub clearing: [u8; 32],
}

/// Controlled in-memory signing material. The private keys are non-cloneable,
/// have no raw-secret getter or `Debug`, and zeroize on drop in ed25519-dalek.
pub struct Pir2SealedSigningMaterialV1 {
    service_identity: SigningKey,
    clearing: SigningKey,
    fingerprints: Pir2SealedPublicFingerprintsV1,
}

impl Pir2SealedSigningMaterialV1 {
    fn from_seed_pair(
        service_identity_seed: &[u8; 32],
        clearing_seed: &[u8; 32],
    ) -> Result<Self, SnpSealedSecretsErrorV1> {
        if service_identity_seed == clearing_seed {
            return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
                "the two role seeds are equal",
            ));
        }
        let service_identity = SigningKey::from_bytes(service_identity_seed);
        let clearing = SigningKey::from_bytes(clearing_seed);
        let fingerprints = fingerprints_for_keys_v1(&service_identity, &clearing);
        Ok(Self {
            service_identity,
            clearing,
            fingerprints,
        })
    }

    /// Sign only in the service-identity role.
    pub fn sign_service_identity(&self, message: &[u8]) -> Signature {
        self.service_identity.sign(message)
    }

    /// Sign only in the provider-to-issuer clearing-authentication role.
    pub fn sign_clearing_authentication(&self, message: &[u8]) -> Signature {
        self.clearing.sign(message)
    }

    /// Non-secret fingerprints bound into the envelope header and AAD.
    pub const fn public_fingerprints(&self) -> Pir2SealedPublicFingerprintsV1 {
        self.fingerprints
    }
}

/// Fail-closed sealed-envelope errors. No variant includes a secret or key
/// digest.
#[derive(Debug)]
pub enum SnpSealedSecretsErrorV1 {
    InvalidRelease(&'static str),
    ReportPolicy(&'static str),
    Provider(SnpDerivedKeyProviderErrorV1),
    Randomness,
    PrivateFile(String),
    CorruptEnvelope(&'static str),
    EnvelopeDoesNotMatchRelease(&'static str),
    AuthenticationFailed,
}

impl fmt::Display for SnpSealedSecretsErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelease(reason) => write!(formatter, "invalid sealed release: {reason}"),
            Self::ReportPolicy(reason) => write!(formatter, "fresh SNP report rejected: {reason}"),
            Self::Provider(error) => write!(formatter, "{error}"),
            Self::Randomness => formatter.write_str("secure randomness unavailable"),
            Self::PrivateFile(error) => {
                write!(formatter, "sealed envelope private-file error: {error}")
            }
            Self::CorruptEnvelope(reason) => write!(formatter, "sealed envelope corrupt: {reason}"),
            Self::EnvelopeDoesNotMatchRelease(field) => {
                write!(
                    formatter,
                    "sealed envelope does not match pinned release field {field}"
                )
            }
            Self::AuthenticationFailed => {
                formatter.write_str("sealed envelope authentication failed")
            }
        }
    }
}

impl std::error::Error for SnpSealedSecretsErrorV1 {}

impl From<SnpDerivedKeyProviderErrorV1> for SnpSealedSecretsErrorV1 {
    fn from(error: SnpDerivedKeyProviderErrorV1) -> Self {
        Self::Provider(error)
    }
}

/// Enroll an explicitly absent first-generation envelope and return only the
/// controlled in-memory signing handle. Existing paths fail before report or
/// key-derivation calls; the final atomic rename also enforces no replacement.
pub fn enroll_new_pir2_sealed_credentials_v1<P: SnpDerivedKeyProvider + ?Sized>(
    path: &Path,
    create_missing_parent: bool,
    release: &Pir2SealedReleaseV1,
    provider: &P,
) -> Result<Pir2SealedSigningMaterialV1, SnpSealedSecretsErrorV1> {
    release.validate()?;
    prepare_new_private_file_v1(path, create_missing_parent, "pir2 sealed envelope")
        .map_err(SnpSealedSecretsErrorV1::PrivateFile)?;
    validate_fresh_report_v1(release, provider)?;
    let request = SnpDerivedKeyRequestV1::production();
    let derived_key = provider.derive_key(&request)?;

    let mut service_seed = Zeroizing::new([0_u8; SEED_LEN_V1]);
    let mut clearing_seed = Zeroizing::new([0_u8; SEED_LEN_V1]);
    getrandom::getrandom(service_seed.as_mut()).map_err(|_| SnpSealedSecretsErrorV1::Randomness)?;
    getrandom::getrandom(clearing_seed.as_mut())
        .map_err(|_| SnpSealedSecretsErrorV1::Randomness)?;
    if *service_seed == *clearing_seed {
        clearing_seed.zeroize();
        return Err(SnpSealedSecretsErrorV1::Randomness);
    }

    let material = Pir2SealedSigningMaterialV1::from_seed_pair(&service_seed, &clearing_seed)?;
    let header = EnvelopeHeaderV1::from_release(release, material.public_fingerprints());
    let envelope = seal_envelope_v1(
        &header,
        derived_key.as_bytes(),
        &service_seed,
        &clearing_seed,
    )?;
    write_atomic_noreplace_private_file_v1(
        path,
        &envelope,
        create_missing_parent,
        "pir2 sealed envelope",
    )
    .map_err(SnpSealedSecretsErrorV1::PrivateFile)?;
    Ok(material)
}

/// Open an existing envelope. Missing, corrupt, mismatched, undecryptable, or
/// provider-failing inputs return an error and never enter enrollment.
pub fn open_pir2_sealed_credentials_v1<P: SnpDerivedKeyProvider + ?Sized>(
    path: &Path,
    release: &Pir2SealedReleaseV1,
    provider: &P,
) -> Result<Pir2SealedSigningMaterialV1, SnpSealedSecretsErrorV1> {
    release.validate()?;
    let bytes = read_private_file_bounded_v1(
        path,
        MAX_ENVELOPE_FILE_LEN_V1,
        PrivateFileModeV1::ReadOnlyOrReadWrite,
        "pir2 sealed envelope",
    )
    .map_err(SnpSealedSecretsErrorV1::PrivateFile)?;
    let decoded = decode_envelope_v1(bytes.as_slice())?;
    decoded.header.require_release(release)?;
    validate_fresh_report_v1(release, provider)?;
    let request = SnpDerivedKeyRequestV1::production();
    let derived_key = provider.derive_key(&request)?;
    open_decoded_envelope_v1(&decoded, derived_key.as_bytes())
}

/// Open and immediately drop the secret signing handle, returning only the
/// stable non-secret fingerprints used by reboot/enrollment probes.
pub fn probe_pir2_sealed_credentials_v1<P: SnpDerivedKeyProvider + ?Sized>(
    path: &Path,
    release: &Pir2SealedReleaseV1,
    provider: &P,
) -> Result<Pir2SealedPublicFingerprintsV1, SnpSealedSecretsErrorV1> {
    let material = open_pir2_sealed_credentials_v1(path, release, provider)?;
    Ok(material.public_fingerprints())
}

fn validate_fresh_report_v1<P: SnpDerivedKeyProvider + ?Sized>(
    release: &Pir2SealedReleaseV1,
    provider: &P,
) -> Result<(), SnpSealedSecretsErrorV1> {
    let mut challenge = [0_u8; 64];
    getrandom::getrandom(&mut challenge).map_err(|_| SnpSealedSecretsErrorV1::Randomness)?;
    let report = provider.fresh_report(challenge)?;
    if report.report_data != challenge {
        return Err(SnpSealedSecretsErrorV1::ReportPolicy(
            "REPORT_DATA does not match the fresh challenge",
        ));
    }
    if !matches!(report.report_version, 2..=5) {
        return Err(SnpSealedSecretsErrorV1::ReportPolicy(
            "unsupported attestation report version",
        ));
    }
    if report.vmpl != 0 {
        return Err(SnpSealedSecretsErrorV1::ReportPolicy("VMPL is not zero"));
    }
    const POLICY_MIGRATE_MA: u64 = 1 << 18;
    const POLICY_DEBUG: u64 = 1 << 19;
    if report.guest_policy & POLICY_DEBUG != 0 {
        return Err(SnpSealedSecretsErrorV1::ReportPolicy("DEBUG is enabled"));
    }
    if report.guest_policy & POLICY_MIGRATE_MA != 0 {
        return Err(SnpSealedSecretsErrorV1::ReportPolicy(
            "MIGRATE_MA is enabled",
        ));
    }
    if report.measurement != release.expected_measurement {
        return Err(SnpSealedSecretsErrorV1::ReportPolicy(
            "measurement differs from the pinned release",
        ));
    }
    if report.guest_policy != release.expected_guest_policy {
        return Err(SnpSealedSecretsErrorV1::ReportPolicy(
            "full guest policy differs from the pinned release",
        ));
    }
    if !report
        .reported_tcb
        .no_component_exceeds(report.committed_tcb)
    {
        return Err(SnpSealedSecretsErrorV1::ReportPolicy(
            "reported TCB exceeds committed TCB",
        ));
    }
    if !report.reported_tcb.meets_floor(release.minimum_tcb) {
        return Err(SnpSealedSecretsErrorV1::ReportPolicy(
            "reported TCB is below the production floor",
        ));
    }
    Ok(())
}

fn fingerprints_for_keys_v1(
    service_identity: &SigningKey,
    clearing: &SigningKey,
) -> Pir2SealedPublicFingerprintsV1 {
    Pir2SealedPublicFingerprintsV1 {
        service_identity: public_key_fingerprint_v1(
            SERVICE_IDENTITY_FINGERPRINT_DOMAIN_V1,
            service_identity.verifying_key().as_bytes(),
        ),
        clearing: public_key_fingerprint_v1(
            CLEARING_FINGERPRINT_DOMAIN_V1,
            clearing.verifying_key().as_bytes(),
        ),
    }
}

fn public_key_fingerprint_v1(domain: &[u8], public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u32).to_le_bytes());
    hasher.update(domain);
    hasher.update(public_key);
    hasher.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EnvelopeHeaderV1 {
    purpose: u8,
    provider_id: [u8; 32],
    stable_server_id: String,
    derived_key_request: [u8; DERIVED_KEY_EVIDENCE_LEN_V1],
    release_artifact_digest: [u8; 32],
    expected_measurement: [u8; 48],
    expected_guest_policy: u64,
    minimum_tcb: SnpTcbVersionV1,
    identity_generation: u64,
    clearing_authorization_epoch: u64,
    public_fingerprints: Pir2SealedPublicFingerprintsV1,
}

impl EnvelopeHeaderV1 {
    const PURPOSE_PIR2_PRODUCTION_CREDENTIALS: u8 = 1;

    fn from_release(
        release: &Pir2SealedReleaseV1,
        public_fingerprints: Pir2SealedPublicFingerprintsV1,
    ) -> Self {
        Self {
            purpose: Self::PURPOSE_PIR2_PRODUCTION_CREDENTIALS,
            provider_id: release.provider_id,
            stable_server_id: release.stable_server_id.clone(),
            derived_key_request: SnpDerivedKeyRequestV1::production().canonical_evidence(),
            release_artifact_digest: release.release_artifact_digest,
            expected_measurement: release.expected_measurement,
            expected_guest_policy: release.expected_guest_policy,
            minimum_tcb: release.minimum_tcb,
            identity_generation: release.identity_generation,
            clearing_authorization_epoch: release.clearing_authorization_epoch,
            public_fingerprints,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let server_id = self.stable_server_id.as_bytes();
        let mut out = Vec::with_capacity(320 + server_id.len());
        out.extend_from_slice(ENVELOPE_HEADER_DOMAIN_V1);
        out.extend_from_slice(&ENVELOPE_CODEC_VERSION_V1.to_le_bytes());
        out.push(self.purpose);
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&(server_id.len() as u16).to_le_bytes());
        out.extend_from_slice(server_id);
        out.extend_from_slice(&self.derived_key_request);
        out.extend_from_slice(&self.release_artifact_digest);
        out.extend_from_slice(&self.expected_measurement);
        out.extend_from_slice(&self.expected_guest_policy.to_le_bytes());
        self.minimum_tcb.encode_into(&mut out);
        out.extend_from_slice(&self.identity_generation.to_le_bytes());
        out.extend_from_slice(&self.clearing_authorization_epoch.to_le_bytes());
        out.extend_from_slice(&self.public_fingerprints.service_identity);
        out.extend_from_slice(&self.public_fingerprints.clearing);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, SnpSealedSecretsErrorV1> {
        let mut decoder = DecoderV1::new(bytes);
        decoder.exact(ENVELOPE_HEADER_DOMAIN_V1, "header domain")?;
        if decoder.u16("header schema")? != ENVELOPE_CODEC_VERSION_V1 {
            return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
                "unsupported header schema",
            ));
        }
        let purpose = decoder.u8("purpose")?;
        if purpose != Self::PURPOSE_PIR2_PRODUCTION_CREDENTIALS {
            return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
                "unsupported purpose",
            ));
        }
        let provider_id = decoder.array("provider_id")?;
        let server_len = usize::from(decoder.u16("stable_server_id length")?);
        if server_len == 0 || server_len > MAX_STABLE_SERVER_ID_LEN_V1 {
            return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
                "stable_server_id length is invalid",
            ));
        }
        let server_bytes = decoder.bytes(server_len, "stable_server_id")?;
        if server_bytes.iter().any(|byte| byte.is_ascii_control()) {
            return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
                "stable_server_id contains a control byte",
            ));
        }
        let stable_server_id = std::str::from_utf8(server_bytes)
            .map_err(|_| SnpSealedSecretsErrorV1::CorruptEnvelope("stable_server_id is not UTF-8"))?
            .to_owned();
        let derived_key_request = decoder.array("derived_key_request")?;
        if derived_key_request != SnpDerivedKeyRequestV1::production().canonical_evidence() {
            return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
                "derived-key request drift",
            ));
        }
        let header = Self {
            purpose,
            provider_id,
            stable_server_id,
            derived_key_request,
            release_artifact_digest: decoder.array("release_artifact_digest")?,
            expected_measurement: decoder.array("expected_measurement")?,
            expected_guest_policy: decoder.u64("expected_guest_policy")?,
            minimum_tcb: SnpTcbVersionV1::decode(&mut decoder)?,
            identity_generation: decoder.u64("identity_generation")?,
            clearing_authorization_epoch: decoder.u64("clearing_authorization_epoch")?,
            public_fingerprints: Pir2SealedPublicFingerprintsV1 {
                service_identity: decoder.array("service_identity_fingerprint")?,
                clearing: decoder.array("clearing_fingerprint")?,
            },
        };
        decoder.finish()?;
        if header.encode() != bytes {
            return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
                "header is not canonical",
            ));
        }
        Ok(header)
    }

    fn require_release(
        &self,
        release: &Pir2SealedReleaseV1,
    ) -> Result<(), SnpSealedSecretsErrorV1> {
        let expected = Self::from_release(release, self.public_fingerprints);
        if self.purpose != expected.purpose {
            return Err(SnpSealedSecretsErrorV1::EnvelopeDoesNotMatchRelease(
                "purpose",
            ));
        }
        if self.provider_id != expected.provider_id {
            return Err(SnpSealedSecretsErrorV1::EnvelopeDoesNotMatchRelease(
                "provider_id",
            ));
        }
        if self.stable_server_id != expected.stable_server_id {
            return Err(SnpSealedSecretsErrorV1::EnvelopeDoesNotMatchRelease(
                "stable_server_id",
            ));
        }
        if self.derived_key_request != expected.derived_key_request {
            return Err(SnpSealedSecretsErrorV1::EnvelopeDoesNotMatchRelease(
                "derived_key_request",
            ));
        }
        if self.release_artifact_digest != expected.release_artifact_digest {
            return Err(SnpSealedSecretsErrorV1::EnvelopeDoesNotMatchRelease(
                "release_artifact_digest",
            ));
        }
        if self.expected_measurement != expected.expected_measurement {
            return Err(SnpSealedSecretsErrorV1::EnvelopeDoesNotMatchRelease(
                "expected_measurement",
            ));
        }
        if self.expected_guest_policy != expected.expected_guest_policy {
            return Err(SnpSealedSecretsErrorV1::EnvelopeDoesNotMatchRelease(
                "expected_guest_policy",
            ));
        }
        if self.minimum_tcb != expected.minimum_tcb {
            return Err(SnpSealedSecretsErrorV1::EnvelopeDoesNotMatchRelease(
                "minimum_tcb",
            ));
        }
        if self.identity_generation != expected.identity_generation {
            return Err(SnpSealedSecretsErrorV1::EnvelopeDoesNotMatchRelease(
                "identity_generation",
            ));
        }
        if self.clearing_authorization_epoch != expected.clearing_authorization_epoch {
            return Err(SnpSealedSecretsErrorV1::EnvelopeDoesNotMatchRelease(
                "clearing_authorization_epoch",
            ));
        }
        Ok(())
    }
}

struct DecodedEnvelopeV1 {
    header: EnvelopeHeaderV1,
    nonce: [u8; NONCE_LEN_V1],
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
}

fn seal_envelope_v1(
    header: &EnvelopeHeaderV1,
    derived_key: &[u8; 32],
    service_seed: &[u8; 32],
    clearing_seed: &[u8; 32],
) -> Result<Vec<u8>, SnpSealedSecretsErrorV1> {
    if service_seed == clearing_seed {
        return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
            "the two role seeds are equal",
        ));
    }
    let header_bytes = header.encode();
    let aad = envelope_aad_v1(&header_bytes)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        ENVELOPE_PLAINTEXT_DOMAIN_V1.len() + 2 + (2 * SEED_LEN_V1),
    ));
    plaintext.extend_from_slice(ENVELOPE_PLAINTEXT_DOMAIN_V1);
    plaintext.extend_from_slice(&ENVELOPE_CODEC_VERSION_V1.to_le_bytes());
    plaintext.extend_from_slice(service_seed);
    plaintext.extend_from_slice(clearing_seed);

    let kek = derive_envelope_kek_v1(header, derived_key)?;
    let cipher = XChaCha20Poly1305::new_from_slice(kek.as_slice())
        .map_err(|_| SnpSealedSecretsErrorV1::CorruptEnvelope("invalid AEAD key length"))?;
    let mut nonce = [0_u8; NONCE_LEN_V1];
    getrandom::getrandom(&mut nonce).map_err(|_| SnpSealedSecretsErrorV1::Randomness)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| SnpSealedSecretsErrorV1::AuthenticationFailed)?;

    let mut out = aad;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn envelope_aad_v1(header_bytes: &[u8]) -> Result<Vec<u8>, SnpSealedSecretsErrorV1> {
    let header_len = u32::try_from(header_bytes.len())
        .map_err(|_| SnpSealedSecretsErrorV1::CorruptEnvelope("header length overflow"))?;
    if header_bytes.len() > MAX_ENVELOPE_HEADER_LEN_V1 {
        return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
            "header exceeds its bound",
        ));
    }
    let mut aad = Vec::with_capacity(ENVELOPE_MAGIC_V1.len() + 2 + 4 + header_bytes.len());
    aad.extend_from_slice(ENVELOPE_MAGIC_V1);
    aad.extend_from_slice(&ENVELOPE_CODEC_VERSION_V1.to_le_bytes());
    aad.extend_from_slice(&header_len.to_le_bytes());
    aad.extend_from_slice(header_bytes);
    Ok(aad)
}

fn decode_envelope_v1(bytes: &[u8]) -> Result<DecodedEnvelopeV1, SnpSealedSecretsErrorV1> {
    let mut decoder = DecoderV1::new(bytes);
    decoder.exact(ENVELOPE_MAGIC_V1, "envelope magic")?;
    if decoder.u16("envelope codec")? != ENVELOPE_CODEC_VERSION_V1 {
        return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
            "unsupported envelope codec",
        ));
    }
    let header_len = usize::try_from(decoder.u32("header length")?)
        .map_err(|_| SnpSealedSecretsErrorV1::CorruptEnvelope("header length overflow"))?;
    if header_len == 0 || header_len > MAX_ENVELOPE_HEADER_LEN_V1 {
        return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
            "header length is outside its bound",
        ));
    }
    let header_bytes = decoder.bytes(header_len, "header")?;
    let header = EnvelopeHeaderV1::decode(header_bytes)?;
    let aad = envelope_aad_v1(header_bytes)?;
    let nonce = decoder.array("nonce")?;
    let ciphertext_len = usize::try_from(decoder.u32("ciphertext length")?)
        .map_err(|_| SnpSealedSecretsErrorV1::CorruptEnvelope("ciphertext length overflow"))?;
    let expected_plaintext_len = ENVELOPE_PLAINTEXT_DOMAIN_V1.len() + 2 + (2 * SEED_LEN_V1);
    if ciphertext_len != expected_plaintext_len + AEAD_TAG_LEN_V1 {
        return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
            "ciphertext length is not canonical",
        ));
    }
    let ciphertext = decoder.bytes(ciphertext_len, "ciphertext")?.to_vec();
    decoder.finish()?;
    Ok(DecodedEnvelopeV1 {
        header,
        nonce,
        ciphertext,
        aad,
    })
}

fn open_decoded_envelope_v1(
    decoded: &DecodedEnvelopeV1,
    derived_key: &[u8; 32],
) -> Result<Pir2SealedSigningMaterialV1, SnpSealedSecretsErrorV1> {
    let kek = derive_envelope_kek_v1(&decoded.header, derived_key)?;
    let cipher = XChaCha20Poly1305::new_from_slice(kek.as_slice())
        .map_err(|_| SnpSealedSecretsErrorV1::CorruptEnvelope("invalid AEAD key length"))?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&decoded.nonce),
            Payload {
                msg: &decoded.ciphertext,
                aad: &decoded.aad,
            },
        )
        .map_err(|_| SnpSealedSecretsErrorV1::AuthenticationFailed)?;
    let plaintext = Zeroizing::new(plaintext);
    let mut decoder = DecoderV1::new(plaintext.as_slice());
    decoder.exact(ENVELOPE_PLAINTEXT_DOMAIN_V1, "plaintext domain")?;
    if decoder.u16("plaintext schema")? != ENVELOPE_CODEC_VERSION_V1 {
        return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
            "unsupported plaintext schema",
        ));
    }
    let mut service_seed = Zeroizing::new(decoder.array("service identity seed")?);
    let mut clearing_seed = Zeroizing::new(decoder.array("clearing seed")?);
    decoder.finish()?;
    let material = Pir2SealedSigningMaterialV1::from_seed_pair(&service_seed, &clearing_seed)?;
    service_seed.zeroize();
    clearing_seed.zeroize();
    if material.public_fingerprints() != decoded.header.public_fingerprints {
        return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
            "public key fingerprints do not match the decrypted seeds",
        ));
    }
    Ok(material)
}

fn derive_envelope_kek_v1(
    header: &EnvelopeHeaderV1,
    derived_key: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, SnpSealedSecretsErrorV1> {
    let mut info = Vec::with_capacity(256 + header.stable_server_id.len());
    info.extend_from_slice(ENVELOPE_KDF_INFO_DOMAIN_V1);
    info.extend_from_slice(&ENVELOPE_CODEC_VERSION_V1.to_le_bytes());
    info.push(header.purpose);
    info.extend_from_slice(&header.provider_id);
    info.extend_from_slice(&(header.stable_server_id.len() as u16).to_le_bytes());
    info.extend_from_slice(header.stable_server_id.as_bytes());
    info.extend_from_slice(&header.identity_generation.to_le_bytes());
    info.extend_from_slice(&header.clearing_authorization_epoch.to_le_bytes());
    info.extend_from_slice(&header.expected_measurement);
    info.extend_from_slice(&header.expected_guest_policy.to_le_bytes());
    info.extend_from_slice(&header.derived_key_request);
    info.extend_from_slice(&header.release_artifact_digest);
    header.minimum_tcb.encode_into(&mut info);
    info.extend_from_slice(&header.public_fingerprints.service_identity);
    info.extend_from_slice(&header.public_fingerprints.clearing);

    let hkdf = Hkdf::<Sha256>::new(Some(ENVELOPE_KDF_SALT_V1), derived_key);
    let mut kek = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, kek.as_mut())
        .map_err(|_| SnpSealedSecretsErrorV1::CorruptEnvelope("HKDF context is invalid"))?;
    Ok(kek)
}

struct DecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DecoderV1<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(
        &mut self,
        length: usize,
        _field: &'static str,
    ) -> Result<&'a [u8], SnpSealedSecretsErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SnpSealedSecretsErrorV1::CorruptEnvelope("length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SnpSealedSecretsErrorV1::CorruptEnvelope("truncated field"))?;
        self.offset = end;
        Ok(value)
    }

    fn exact(
        &mut self,
        expected: &[u8],
        field: &'static str,
    ) -> Result<(), SnpSealedSecretsErrorV1> {
        if self.bytes(expected.len(), field)? != expected {
            return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
                "domain or magic mismatch",
            ));
        }
        Ok(())
    }

    fn array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], SnpSealedSecretsErrorV1> {
        self.bytes(N, field)?
            .try_into()
            .map_err(|_| SnpSealedSecretsErrorV1::CorruptEnvelope("array length mismatch"))
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, SnpSealedSecretsErrorV1> {
        Ok(self.bytes(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, SnpSealedSecretsErrorV1> {
        Ok(u16::from_le_bytes(self.array(field)?))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, SnpSealedSecretsErrorV1> {
        Ok(u32::from_le_bytes(self.array(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, SnpSealedSecretsErrorV1> {
        Ok(u64::from_le_bytes(self.array(field)?))
    }

    fn finish(self) -> Result<(), SnpSealedSecretsErrorV1> {
        if self.offset != self.bytes.len() {
            return Err(SnpSealedSecretsErrorV1::CorruptEnvelope(
                "trailing bytes are not canonical",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::os::unix::fs::PermissionsExt as _;

    // The real ioctl branch is Linux-only; keep its ownership boundary checked
    // on every test host without attempting to fake `/dev/sev-guest`.
    const _: fn(Zeroizing<[u8; 32]>) -> SnpDerivedKeyMaterialV1 =
        SnpDerivedKeyMaterialV1::from_zeroizing;

    struct MockProviderV1 {
        report: FreshSnpReportV1,
        key: [u8; 32],
        report_failure: Option<SnpDerivedKeyProviderErrorV1>,
        derive_failure: Option<SnpDerivedKeyProviderErrorV1>,
        echo_challenge: bool,
        report_calls: Cell<u32>,
        derive_calls: Cell<u32>,
        last_request: RefCell<Option<[u8; DERIVED_KEY_EVIDENCE_LEN_V1]>>,
    }

    impl MockProviderV1 {
        fn good(release: &Pir2SealedReleaseV1, key: [u8; 32]) -> Self {
            Self {
                report: good_report(release),
                key,
                report_failure: None,
                derive_failure: None,
                echo_challenge: true,
                report_calls: Cell::new(0),
                derive_calls: Cell::new(0),
                last_request: RefCell::new(None),
            }
        }

        fn with_report(release: &Pir2SealedReleaseV1, report: FreshSnpReportV1) -> Self {
            let mut provider = Self::good(release, [0x42; 32]);
            provider.report = report;
            provider
        }
    }

    impl SnpDerivedKeyProvider for MockProviderV1 {
        fn fresh_report(
            &self,
            report_data: [u8; 64],
        ) -> Result<FreshSnpReportV1, SnpDerivedKeyProviderErrorV1> {
            self.report_calls.set(self.report_calls.get() + 1);
            if let Some(error) = &self.report_failure {
                return Err(error.clone());
            }
            let mut report = self.report.clone();
            if self.echo_challenge {
                report.report_data = report_data;
            }
            Ok(report)
        }

        fn derive_key(
            &self,
            request: &SnpDerivedKeyRequestV1,
        ) -> Result<SnpDerivedKeyMaterialV1, SnpDerivedKeyProviderErrorV1> {
            self.derive_calls.set(self.derive_calls.get() + 1);
            self.last_request
                .replace(Some(request.canonical_evidence()));
            if let Some(error) = &self.derive_failure {
                return Err(error.clone());
            }
            Ok(SnpDerivedKeyMaterialV1::from_bytes(self.key))
        }
    }

    fn release() -> Pir2SealedReleaseV1 {
        Pir2SealedReleaseV1 {
            provider_id: [0x11; 32],
            stable_server_id: "pir2-mainnet".to_string(),
            release_artifact_digest: [0x22; 32],
            expected_measurement: [0x33; 48],
            // Bit 17 is the SNP-required fixed-one bit. Debug and MIGRATE_MA
            // remain clear.
            expected_guest_policy: 1 << 17,
            minimum_tcb: SnpTcbVersionV1 {
                fmc: None,
                bootloader: 1,
                tee: 2,
                snp: 3,
                microcode: 4,
            },
            identity_generation: 7,
            clearing_authorization_epoch: 11,
        }
    }

    fn good_report(release: &Pir2SealedReleaseV1) -> FreshSnpReportV1 {
        FreshSnpReportV1 {
            report_version: 2,
            vmpl: 0,
            guest_policy: release.expected_guest_policy,
            measurement: release.expected_measurement,
            report_data: [0_u8; 64],
            reported_tcb: release.minimum_tcb,
            committed_tcb: SnpTcbVersionV1 {
                fmc: None,
                bootloader: 2,
                tee: 3,
                snp: 4,
                microcode: 5,
            },
        }
    }

    fn private_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn enroll_fixture(
        directory: &tempfile::TempDir,
        release: &Pir2SealedReleaseV1,
        key: [u8; 32],
    ) -> (std::path::PathBuf, Pir2SealedPublicFingerprintsV1) {
        let path = directory.path().join("sealed-envelope.bin");
        let provider = MockProviderV1::good(release, key);
        let material =
            enroll_new_pir2_sealed_credentials_v1(&path, false, release, &provider).unwrap();
        assert_eq!(provider.report_calls.get(), 1);
        assert_eq!(provider.derive_calls.get(), 1);
        (path, material.public_fingerprints())
    }

    fn write_ciphertext(path: &Path, bytes: &[u8]) {
        write_atomic_noreplace_private_file_v1(path, bytes, false, "test sealed envelope").unwrap();
    }

    #[test]
    fn derived_key_request_is_source_pinned_and_canonical() {
        let request = SnpDerivedKeyRequestV1::production();
        assert_eq!(request.message_version(), 1);
        assert_eq!(request.root_key_select(), 0);
        assert_eq!(request.guest_field_select(), 0x9);
        assert_eq!(request.vmpl(), 0);
        let evidence = request.canonical_evidence();
        assert_eq!(&evidence[0..4], &1_u32.to_le_bytes());
        assert_eq!(&evidence[4..8], &0_u32.to_le_bytes());
        assert_eq!(&evidence[8..12], &0_u32.to_le_bytes());
        assert_eq!(&evidence[12..20], &0x9_u64.to_le_bytes());
        assert_eq!(&evidence[20..24], &0_u32.to_le_bytes());
        assert_eq!(&evidence[24..28], &0_u32.to_le_bytes());
        assert_eq!(&evidence[28..36], &0_u64.to_le_bytes());
        assert_eq!(&evidence[36..44], &0_u64.to_le_bytes());
    }

    #[test]
    fn enrollment_open_and_probe_round_trip_with_exact_call_counts() {
        let directory = private_tempdir();
        let release = release();
        let key = [0x42; 32];
        let path = directory.path().join("sealed-envelope.bin");
        let enrollment_provider = MockProviderV1::good(&release, key);
        let enrolled =
            enroll_new_pir2_sealed_credentials_v1(&path, false, &release, &enrollment_provider)
                .unwrap();
        assert_eq!(enrollment_provider.report_calls.get(), 1);
        assert_eq!(enrollment_provider.derive_calls.get(), 1);
        assert_eq!(
            enrollment_provider.last_request.borrow().as_ref(),
            Some(&SnpDerivedKeyRequestV1::production().canonical_evidence())
        );
        assert_ne!(
            enrolled.public_fingerprints().service_identity,
            enrolled.public_fingerprints().clearing,
            "the independently generated role keys must differ"
        );
        assert_ne!(
            enrolled
                .sign_service_identity(b"role-separation")
                .to_bytes(),
            enrolled
                .sign_clearing_authentication(b"role-separation")
                .to_bytes()
        );

        let open_provider = MockProviderV1::good(&release, key);
        let opened = open_pir2_sealed_credentials_v1(&path, &release, &open_provider).unwrap();
        assert_eq!(opened.public_fingerprints(), enrolled.public_fingerprints());
        assert_eq!(open_provider.report_calls.get(), 1);
        assert_eq!(open_provider.derive_calls.get(), 1);

        let probe_provider = MockProviderV1::good(&release, key);
        assert_eq!(
            probe_pir2_sealed_credentials_v1(&path, &release, &probe_provider).unwrap(),
            enrolled.public_fingerprints()
        );
        assert_eq!(probe_provider.report_calls.get(), 1);
        assert_eq!(probe_provider.derive_calls.get(), 1);
    }

    #[test]
    fn existing_enrollment_and_missing_or_corrupt_open_never_fallback() {
        let directory = private_tempdir();
        let release = release();
        let (path, expected_fingerprints) = enroll_fixture(&directory, &release, [0x42; 32]);

        let existing_provider = MockProviderV1::good(&release, [0x42; 32]);
        assert!(
            enroll_new_pir2_sealed_credentials_v1(&path, false, &release, &existing_provider)
                .is_err()
        );
        assert_eq!(existing_provider.report_calls.get(), 0);
        assert_eq!(existing_provider.derive_calls.get(), 0);

        let missing_provider = MockProviderV1::good(&release, [0x42; 32]);
        assert!(open_pir2_sealed_credentials_v1(
            &directory.path().join("missing.bin"),
            &release,
            &missing_provider
        )
        .is_err());
        assert_eq!(missing_provider.report_calls.get(), 0);
        assert_eq!(missing_provider.derive_calls.get(), 0);

        let corrupt_path = directory.path().join("corrupt.bin");
        write_ciphertext(&corrupt_path, b"not-an-envelope");
        let corrupt_provider = MockProviderV1::good(&release, [0x42; 32]);
        assert!(
            open_pir2_sealed_credentials_v1(&corrupt_path, &release, &corrupt_provider).is_err()
        );
        assert_eq!(corrupt_provider.report_calls.get(), 0);
        assert_eq!(corrupt_provider.derive_calls.get(), 0);

        let final_provider = MockProviderV1::good(&release, [0x42; 32]);
        assert_eq!(
            probe_pir2_sealed_credentials_v1(&path, &release, &final_provider).unwrap(),
            expected_fingerprints
        );
    }

    #[test]
    fn provider_and_release_context_tamper_fail_closed_before_derivation() {
        let directory = private_tempdir();
        let original = release();
        let (path, _) = enroll_fixture(&directory, &original, [0x42; 32]);

        let mut variants = Vec::new();
        let mut provider = original.clone();
        provider.provider_id[0] ^= 1;
        variants.push(provider);
        let mut server = original.clone();
        server.stable_server_id.push_str("-other");
        variants.push(server);
        let mut generation = original.clone();
        generation.identity_generation += 1;
        variants.push(generation);
        let mut epoch = original.clone();
        epoch.clearing_authorization_epoch += 1;
        variants.push(epoch);
        let mut measurement = original.clone();
        measurement.expected_measurement[0] ^= 1;
        variants.push(measurement);
        let mut policy = original.clone();
        policy.expected_guest_policy ^= 1 << 16;
        variants.push(policy);
        let mut release_digest = original.clone();
        release_digest.release_artifact_digest[0] ^= 1;
        variants.push(release_digest);

        for tampered in variants {
            let provider = MockProviderV1::good(&tampered, [0x42; 32]);
            assert!(matches!(
                open_pir2_sealed_credentials_v1(&path, &tampered, &provider),
                Err(SnpSealedSecretsErrorV1::EnvelopeDoesNotMatchRelease(_))
            ));
            assert_eq!(provider.report_calls.get(), 0);
            assert_eq!(provider.derive_calls.get(), 0);
        }
    }

    #[test]
    fn purpose_header_aad_and_ciphertext_tamper_are_rejected() {
        let directory = private_tempdir();
        let release = release();
        let (path, fingerprints) = enroll_fixture(&directory, &release, [0x42; 32]);
        let original = std::fs::read(&path).unwrap();

        let mut bad_header_len = original.clone();
        bad_header_len[10..14].copy_from_slice(&0_u32.to_le_bytes());
        let bad_header_path = directory.path().join("bad-header.bin");
        write_ciphertext(&bad_header_path, &bad_header_len);
        let provider = MockProviderV1::good(&release, [0x42; 32]);
        assert!(open_pir2_sealed_credentials_v1(&bad_header_path, &release, &provider).is_err());
        assert_eq!(provider.report_calls.get(), 0);

        let mut bad_purpose = original.clone();
        let purpose_offset = 14 + ENVELOPE_HEADER_DOMAIN_V1.len() + 2;
        bad_purpose[purpose_offset] = 2;
        let bad_purpose_path = directory.path().join("bad-purpose.bin");
        write_ciphertext(&bad_purpose_path, &bad_purpose);
        let provider = MockProviderV1::good(&release, [0x42; 32]);
        assert!(open_pir2_sealed_credentials_v1(&bad_purpose_path, &release, &provider).is_err());
        assert_eq!(provider.report_calls.get(), 0);

        let mut bad_aad = original.clone();
        let fingerprint_offset = bad_aad
            .windows(fingerprints.service_identity.len())
            .position(|window| window == fingerprints.service_identity)
            .expect("fingerprint is bound in the canonical header");
        bad_aad[fingerprint_offset] ^= 1;
        let bad_aad_path = directory.path().join("bad-aad.bin");
        write_ciphertext(&bad_aad_path, &bad_aad);
        let provider = MockProviderV1::good(&release, [0x42; 32]);
        assert!(matches!(
            open_pir2_sealed_credentials_v1(&bad_aad_path, &release, &provider),
            Err(SnpSealedSecretsErrorV1::AuthenticationFailed)
        ));
        assert_eq!(provider.report_calls.get(), 1);
        assert_eq!(provider.derive_calls.get(), 1);

        let mut bad_ciphertext = original;
        *bad_ciphertext.last_mut().unwrap() ^= 1;
        let bad_ciphertext_path = directory.path().join("bad-ciphertext.bin");
        write_ciphertext(&bad_ciphertext_path, &bad_ciphertext);
        let provider = MockProviderV1::good(&release, [0x42; 32]);
        assert!(matches!(
            open_pir2_sealed_credentials_v1(&bad_ciphertext_path, &release, &provider),
            Err(SnpSealedSecretsErrorV1::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_derived_key_never_opens_or_reenrolls() {
        let directory = private_tempdir();
        let release = release();
        let (path, expected) = enroll_fixture(&directory, &release, [0x42; 32]);
        let wrong_provider = MockProviderV1::good(&release, [0x43; 32]);
        assert!(matches!(
            open_pir2_sealed_credentials_v1(&path, &release, &wrong_provider),
            Err(SnpSealedSecretsErrorV1::AuthenticationFailed)
        ));
        assert_eq!(wrong_provider.report_calls.get(), 1);
        assert_eq!(wrong_provider.derive_calls.get(), 1);

        let good_provider = MockProviderV1::good(&release, [0x42; 32]);
        assert_eq!(
            probe_pir2_sealed_credentials_v1(&path, &release, &good_provider).unwrap(),
            expected
        );
    }

    #[test]
    fn every_strict_report_policy_field_is_checked_before_derivation() {
        let directory = private_tempdir();
        let release = release();
        let (path, _) = enroll_fixture(&directory, &release, [0x42; 32]);
        let baseline = good_report(&release);
        let mut bad_reports = Vec::new();

        let mut stale = baseline.clone();
        stale.report_data = [0x99; 64];
        bad_reports.push((stale, false));
        let mut version = baseline.clone();
        version.report_version = 6;
        bad_reports.push((version, true));
        let mut vmpl = baseline.clone();
        vmpl.vmpl = 1;
        bad_reports.push((vmpl, true));
        let mut debug = baseline.clone();
        debug.guest_policy |= 1 << 19;
        bad_reports.push((debug, true));
        let mut migrate = baseline.clone();
        migrate.guest_policy |= 1 << 18;
        bad_reports.push((migrate, true));
        let mut measurement = baseline.clone();
        measurement.measurement[0] ^= 1;
        bad_reports.push((measurement, true));
        let mut policy = baseline.clone();
        policy.guest_policy ^= 1 << 16;
        bad_reports.push((policy, true));
        let mut floor = baseline.clone();
        floor.reported_tcb.microcode -= 1;
        bad_reports.push((floor, true));
        let mut impossible = baseline;
        impossible.committed_tcb.microcode = impossible.reported_tcb.microcode - 1;
        bad_reports.push((impossible, true));

        for (report, echo_challenge) in bad_reports {
            let mut provider = MockProviderV1::with_report(&release, report);
            provider.echo_challenge = echo_challenge;
            assert!(matches!(
                open_pir2_sealed_credentials_v1(&path, &release, &provider),
                Err(SnpSealedSecretsErrorV1::ReportPolicy(_))
            ));
            assert_eq!(provider.report_calls.get(), 1);
            assert_eq!(provider.derive_calls.get(), 0);
        }
    }

    #[test]
    fn device_and_ioctl_failures_have_no_plaintext_or_reenrollment_fallback() {
        let directory = private_tempdir();
        let release = release();
        let (path, expected) = enroll_fixture(&directory, &release, [0x42; 32]);

        for failure in [
            SnpDerivedKeyProviderErrorV1::DeviceUnavailable,
            SnpDerivedKeyProviderErrorV1::IoctlFailed("report failure".to_string()),
        ] {
            let mut provider = MockProviderV1::good(&release, [0x42; 32]);
            provider.report_failure = Some(failure);
            assert!(matches!(
                open_pir2_sealed_credentials_v1(&path, &release, &provider),
                Err(SnpSealedSecretsErrorV1::Provider(_))
            ));
            assert_eq!(provider.report_calls.get(), 1);
            assert_eq!(provider.derive_calls.get(), 0);
        }

        let mut derive_failure = MockProviderV1::good(&release, [0x42; 32]);
        derive_failure.derive_failure = Some(SnpDerivedKeyProviderErrorV1::IoctlFailed(
            "derived-key failure".to_string(),
        ));
        assert!(matches!(
            open_pir2_sealed_credentials_v1(&path, &release, &derive_failure),
            Err(SnpSealedSecretsErrorV1::Provider(_))
        ));
        assert_eq!(derive_failure.report_calls.get(), 1);
        assert_eq!(derive_failure.derive_calls.get(), 1);

        let good_provider = MockProviderV1::good(&release, [0x42; 32]);
        assert_eq!(
            probe_pir2_sealed_credentials_v1(&path, &release, &good_provider).unwrap(),
            expected
        );
    }

    #[test]
    fn equal_role_seeds_are_rejected() {
        assert!(matches!(
            Pir2SealedSigningMaterialV1::from_seed_pair(&[7_u8; 32], &[7_u8; 32]),
            Err(SnpSealedSecretsErrorV1::CorruptEnvelope(_))
        ));
    }
}
