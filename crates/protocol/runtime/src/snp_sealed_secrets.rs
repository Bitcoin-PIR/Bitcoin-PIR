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
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
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

pub const SNP_DERIVED_KEY_EVIDENCE_LEN_V1: usize = 44;
const DERIVED_KEY_EVIDENCE_LEN_V1: usize = SNP_DERIVED_KEY_EVIDENCE_LEN_V1;
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
const SEALED_RELEASE_MAGIC_V1: &[u8; 8] = b"BPIRSRL1";
const SEALED_RELEASE_SIGNATURE_DOMAIN_V1: &[u8] = b"BitcoinPIR/pir2/sealed-release-signature/v1";
const SEALED_RELEASE_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/pir2/sealed-release-artifact-digest/v1";
const MAX_SEALED_RELEASE_LEN_V1: usize = 2048;
const SEALED_RECEIPT_MAGIC_V1: &[u8; 8] = b"BPIRSRC1";
const SEALED_RECEIPT_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/pir2/sealed-receipt-digest/v1";
const MAX_FRESH_SNP_REPORT_LEN_V1: usize = 4096;
const PRE_RELEASE_OBSERVATION_MAGIC_V1: &[u8; 8] = b"BPIRPRO1";
const PRE_RELEASE_OBSERVATION_CLAIMS_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/pir2/pre-release-observation-claims/v1";
pub const PIR2_PRE_RELEASE_OBSERVATION_RAW_REPORT_LEN_V1: usize = 1184;
pub const PIR2_PRE_RELEASE_OBSERVATION_RECEIPT_LEN_V1: usize =
    8 + 2 + 8 + 32 + 32 + 16 + PIR2_PRE_RELEASE_OBSERVATION_RAW_REPORT_LEN_V1;

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

/// Canonical public claims signed by the offline pir2 operator.
///
/// The operator public key is deliberately not carried by these claims.  The
/// measured caller must supply the key pinned in its source when it constructs
/// [`VerifiedPir2SealedReleaseV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pir2SealedReleaseClaimsV1 {
    pub provider_id: [u8; 32],
    pub stable_server_id: String,
    pub uki_sha256: [u8; 32],
    pub expected_measurement: [u8; 48],
    pub expected_guest_policy: u64,
    pub minimum_tcb: SnpTcbVersionV1,
    pub derived_key_request: [u8; DERIVED_KEY_EVIDENCE_LEN_V1],
    pub identity_generation: u64,
    pub clearing_authorization_epoch: u64,
}

impl Pir2SealedReleaseClaimsV1 {
    /// Validate every production release invariant before a signing key is
    /// accessed. The canonical encoder repeats this check defensively.
    pub fn validate_for_signing(&self) -> Result<(), SnpSealedSecretsErrorV1> {
        if self.uki_sha256 == [0_u8; 32] {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "UKI SHA-256 must not be all zero",
            ));
        }
        if self.derived_key_request != SnpDerivedKeyRequestV1::production().canonical_evidence() {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "derived-key request differs from the source-pinned V1 request",
            ));
        }
        self.as_release_with_digest([1_u8; 32]).validate()
    }

    fn as_release_with_digest(&self, release_artifact_digest: [u8; 32]) -> Pir2SealedReleaseV1 {
        Pir2SealedReleaseV1 {
            provider_id: self.provider_id,
            stable_server_id: self.stable_server_id.clone(),
            release_artifact_digest,
            expected_measurement: self.expected_measurement,
            expected_guest_policy: self.expected_guest_policy,
            minimum_tcb: self.minimum_tcb,
            identity_generation: self.identity_generation,
            clearing_authorization_epoch: self.clearing_authorization_epoch,
        }
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, SnpSealedSecretsErrorV1> {
        self.validate_for_signing()?;
        let server_id = self.stable_server_id.as_bytes();
        let mut out = Vec::with_capacity(256 + server_id.len());
        out.extend_from_slice(SEALED_RELEASE_MAGIC_V1);
        out.extend_from_slice(&ENVELOPE_CODEC_VERSION_V1.to_le_bytes());
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&(server_id.len() as u16).to_le_bytes());
        out.extend_from_slice(server_id);
        out.extend_from_slice(&self.uki_sha256);
        out.extend_from_slice(&self.expected_measurement);
        out.extend_from_slice(&self.expected_guest_policy.to_le_bytes());
        self.minimum_tcb.encode_into(&mut out);
        out.extend_from_slice(&self.derived_key_request);
        out.extend_from_slice(&self.identity_generation.to_le_bytes());
        out.extend_from_slice(&self.clearing_authorization_epoch.to_le_bytes());
        Ok(out)
    }
}

/// Produce the canonical operator-signed release bytes.  Production runtime
/// code only decodes these bytes; this narrow encoder is shared with the later
/// offline release command and deterministic tests.
pub fn encode_signed_pir2_sealed_release_v1(
    claims: &Pir2SealedReleaseClaimsV1,
    operator_signing_key: &SigningKey,
) -> Result<Vec<u8>, SnpSealedSecretsErrorV1> {
    let mut out = claims.encode_unsigned()?;
    let message = sealed_release_signature_message_v1(&out);
    out.extend_from_slice(&operator_signing_key.sign(&message).to_bytes());
    Ok(out)
}

/// A canonical release whose signature was checked against the operator key
/// pinned by the measured caller.  It cannot be constructed from public
/// fields, preventing unverified claims from reaching envelope operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPir2SealedReleaseV1 {
    claims: Pir2SealedReleaseClaimsV1,
    release: Pir2SealedReleaseV1,
    exact_bytes: Vec<u8>,
}

impl VerifiedPir2SealedReleaseV1 {
    pub fn decode_and_verify(
        exact_bytes: &[u8],
        source_pinned_operator_key: &VerifyingKey,
    ) -> Result<Self, SnpSealedSecretsErrorV1> {
        if exact_bytes.len() > MAX_SEALED_RELEASE_LEN_V1 {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "sealed release exceeds its source bound",
            ));
        }
        let mut decoder = DecoderV1::new(exact_bytes);
        decoder
            .exact(SEALED_RELEASE_MAGIC_V1, "sealed release magic")
            .map_err(|_| SnpSealedSecretsErrorV1::InvalidRelease("invalid release magic"))?;
        if decoder
            .u16("sealed release codec")
            .map_err(|_| SnpSealedSecretsErrorV1::InvalidRelease("truncated release codec"))?
            != ENVELOPE_CODEC_VERSION_V1
        {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "unsupported sealed release codec",
            ));
        }
        let provider_id = decoder
            .array("provider_id")
            .map_err(|_| SnpSealedSecretsErrorV1::InvalidRelease("truncated provider_id"))?;
        let server_len = usize::from(
            decoder
                .u16("stable_server_id length")
                .map_err(|_| SnpSealedSecretsErrorV1::InvalidRelease("truncated server id"))?,
        );
        if server_len == 0 || server_len > MAX_STABLE_SERVER_ID_LEN_V1 {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "stable_server_id length is invalid",
            ));
        }
        let stable_server_id = std::str::from_utf8(
            decoder
                .bytes(server_len, "stable_server_id")
                .map_err(|_| SnpSealedSecretsErrorV1::InvalidRelease("truncated server id"))?,
        )
        .map_err(|_| SnpSealedSecretsErrorV1::InvalidRelease("server id is not UTF-8"))?
        .to_owned();
        let claims = Pir2SealedReleaseClaimsV1 {
            provider_id,
            stable_server_id,
            uki_sha256: decoder
                .array("uki_sha256")
                .map_err(|_| SnpSealedSecretsErrorV1::InvalidRelease("truncated UKI digest"))?,
            expected_measurement: decoder.array("expected_measurement").map_err(|_| {
                SnpSealedSecretsErrorV1::InvalidRelease("truncated expected measurement")
            })?,
            expected_guest_policy: decoder
                .u64("expected_guest_policy")
                .map_err(|_| SnpSealedSecretsErrorV1::InvalidRelease("truncated guest policy"))?,
            minimum_tcb: SnpTcbVersionV1::decode(&mut decoder)
                .map_err(|_| SnpSealedSecretsErrorV1::InvalidRelease("invalid TCB floor"))?,
            derived_key_request: decoder.array("derived_key_request").map_err(|_| {
                SnpSealedSecretsErrorV1::InvalidRelease("truncated derived-key request")
            })?,
            identity_generation: decoder
                .array::<8>("identity_generation")
                .map(u64::from_le_bytes)
                .map_err(|_| {
                    SnpSealedSecretsErrorV1::InvalidRelease("truncated identity generation")
                })?,
            clearing_authorization_epoch: decoder
                .array::<8>("clearing_authorization_epoch")
                .map(u64::from_le_bytes)
                .map_err(|_| SnpSealedSecretsErrorV1::InvalidRelease("truncated clearing epoch"))?,
        };
        claims.validate_for_signing()?;
        let signature_bytes: [u8; 64] = decoder
            .array("operator signature")
            .map_err(|_| SnpSealedSecretsErrorV1::InvalidRelease("truncated operator signature"))?;
        decoder
            .finish()
            .map_err(|_| SnpSealedSecretsErrorV1::InvalidRelease("release has trailing bytes"))?;

        let unsigned = claims.encode_unsigned()?;
        if exact_bytes.get(..unsigned.len()) != Some(unsigned.as_slice()) {
            return Err(SnpSealedSecretsErrorV1::InvalidRelease(
                "sealed release is not canonical",
            ));
        }
        source_pinned_operator_key
            .verify(
                &sealed_release_signature_message_v1(&unsigned),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| {
                SnpSealedSecretsErrorV1::InvalidRelease(
                    "operator signature does not match the source-pinned key",
                )
            })?;
        let digest = sealed_release_artifact_digest_v1(exact_bytes);
        let release = claims.as_release_with_digest(digest);
        Ok(Self {
            claims,
            release,
            exact_bytes: exact_bytes.to_vec(),
        })
    }

    pub const fn release(&self) -> &Pir2SealedReleaseV1 {
        &self.release
    }

    pub const fn claims(&self) -> &Pir2SealedReleaseClaimsV1 {
        &self.claims
    }

    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    pub const fn artifact_digest(&self) -> [u8; 32] {
        self.release.release_artifact_digest
    }
}

fn sealed_release_signature_message_v1(unsigned: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(4 + SEALED_RELEASE_SIGNATURE_DOMAIN_V1.len() + unsigned.len());
    message.extend_from_slice(&(SEALED_RELEASE_SIGNATURE_DOMAIN_V1.len() as u32).to_le_bytes());
    message.extend_from_slice(SEALED_RELEASE_SIGNATURE_DOMAIN_V1);
    message.extend_from_slice(unsigned);
    message
}

fn sealed_release_artifact_digest_v1(exact_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((SEALED_RELEASE_DIGEST_DOMAIN_V1.len() as u32).to_le_bytes());
    hasher.update(SEALED_RELEASE_DIGEST_DOMAIN_V1);
    hasher.update((exact_bytes.len() as u32).to_le_bytes());
    hasher.update(exact_bytes);
    hasher.finalize().into()
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
    /// Exact firmware report bytes delivered on this fresh ioctl channel.
    /// Receipts persist these bytes for the external AMD-chain verifier; the
    /// runtime never reconstructs them from parsed fields.
    pub raw_report: Vec<u8>,
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
                raw_report: bytes,
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

/// Raw non-secret Ed25519 public keys authorized after the enrollment
/// ceremony. Fingerprints alone are insufficient to construct the identity
/// certificate or issuer clearing authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pir2SealedPublicKeysV1 {
    pub service_identity: [u8; 32],
    pub clearing: [u8; 32],
}

/// Owned role-separated signing keys transferred exactly once into the ready
/// server profile. This type intentionally has no `Clone` or `Debug`.
pub struct Pir2SealedSigningKeysV1 {
    pub service_identity: SigningKey,
    pub clearing: SigningKey,
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

    /// Raw public keys for certificate/authorization binding and receipts.
    pub fn public_keys(&self) -> Pir2SealedPublicKeysV1 {
        Pir2SealedPublicKeysV1 {
            service_identity: self.service_identity.verifying_key().to_bytes(),
            clearing: self.clearing.verifying_key().to_bytes(),
        }
    }

    /// Consume the sealed handle and hand each non-cloneable signing key to
    /// its one runtime role without exposing either seed.
    pub fn into_signing_keys(self) -> Pir2SealedSigningKeysV1 {
        Pir2SealedSigningKeysV1 {
            service_identity: self.service_identity,
            clearing: self.clearing,
        }
    }
}

/// Freshness-only claims for the pre-release Observe ceremony.
///
/// This type deliberately cannot carry release, authority, envelope, or key
/// material. Its domain is permanently the pre-release Observe phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pir2PreReleaseObservationClaimsV1 {
    ordinal: u64,
    verifier_nonce: [u8; 32],
    current_channel_pubkey: [u8; 32],
    boot_id: [u8; 16],
}

impl Pir2PreReleaseObservationClaimsV1 {
    pub fn new(
        ordinal: u64,
        verifier_nonce: [u8; 32],
        current_channel_pubkey: [u8; 32],
        boot_id: [u8; 16],
    ) -> Result<Self, SnpSealedSecretsErrorV1> {
        let claims = Self {
            ordinal,
            verifier_nonce,
            current_channel_pubkey,
            boot_id,
        };
        claims.validate()?;
        Ok(claims)
    }

    fn validate(&self) -> Result<(), SnpSealedSecretsErrorV1> {
        if self.ordinal == 0
            || self.verifier_nonce == [0_u8; 32]
            || self.current_channel_pubkey == [0_u8; 32]
            || self.boot_id == [0_u8; 16]
        {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "pre-release observation contains an empty freshness binding",
            ));
        }
        Ok(())
    }

    fn encode_claims(&self) -> Result<Vec<u8>, SnpSealedSecretsErrorV1> {
        self.validate()?;
        let mut out = Vec::with_capacity(88);
        out.extend_from_slice(&self.ordinal.to_le_bytes());
        out.extend_from_slice(&self.verifier_nonce);
        out.extend_from_slice(&self.current_channel_pubkey);
        out.extend_from_slice(&self.boot_id);
        Ok(out)
    }

    pub fn digest(&self) -> Result<[u8; 32], SnpSealedSecretsErrorV1> {
        let encoded = self.encode_claims()?;
        let mut hasher = Sha256::new();
        hasher.update((PRE_RELEASE_OBSERVATION_CLAIMS_DOMAIN_V1.len() as u32).to_le_bytes());
        hasher.update(PRE_RELEASE_OBSERVATION_CLAIMS_DOMAIN_V1);
        hasher.update((encoded.len() as u32).to_le_bytes());
        hasher.update(encoded);
        Ok(hasher.finalize().into())
    }

    pub fn report_data(&self) -> Result<[u8; 64], SnpSealedSecretsErrorV1> {
        let digest = self.digest()?;
        let mut report_data = [0_u8; 64];
        report_data[..32].copy_from_slice(&digest);
        report_data[32..].copy_from_slice(&digest);
        Ok(report_data)
    }
}

/// Canonical pre-release observation receipt containing only the exact raw SNP
/// report and its current-boot freshness claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pir2PreReleaseObservationReceiptV1 {
    claims: Pir2PreReleaseObservationClaimsV1,
    raw_report: [u8; PIR2_PRE_RELEASE_OBSERVATION_RAW_REPORT_LEN_V1],
}

impl Pir2PreReleaseObservationReceiptV1 {
    pub fn request<P: SnpDerivedKeyProvider + ?Sized>(
        claims: Pir2PreReleaseObservationClaimsV1,
        provider: &P,
    ) -> Result<Self, SnpSealedSecretsErrorV1> {
        let expected_report_data = claims.report_data()?;
        let fresh_report = provider.fresh_report(expected_report_data)?;
        if fresh_report.report_data != expected_report_data {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "typed fresh report data does not bind pre-release observation claims",
            ));
        }
        let raw_report: [u8; PIR2_PRE_RELEASE_OBSERVATION_RAW_REPORT_LEN_V1] =
            fresh_report.raw_report.try_into().map_err(|_| {
                SnpSealedSecretsErrorV1::InvalidReceipt(
                    "pre-release observation requires an exact 1184-byte SNP report",
                )
            })?;
        let receipt = Self { claims, raw_report };
        receipt.verify_binding(&receipt.claims)?;
        Ok(receipt)
    }

    pub fn decode_and_verify(
        exact_bytes: &[u8],
        expected_claims: &Pir2PreReleaseObservationClaimsV1,
    ) -> Result<Self, SnpSealedSecretsErrorV1> {
        if exact_bytes.len() != PIR2_PRE_RELEASE_OBSERVATION_RECEIPT_LEN_V1 {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "pre-release observation receipt has a non-canonical length",
            ));
        }
        let mut decoder = DecoderV1::new(exact_bytes);
        decoder
            .exact(
                PRE_RELEASE_OBSERVATION_MAGIC_V1,
                "pre-release observation magic",
            )
            .map_err(|_| {
                SnpSealedSecretsErrorV1::InvalidReceipt(
                    "pre-release observation receipt magic is invalid",
                )
            })?;
        if decoder.u16("pre-release observation codec").map_err(|_| {
            SnpSealedSecretsErrorV1::InvalidReceipt(
                "pre-release observation receipt codec is truncated",
            )
        })? != ENVELOPE_CODEC_VERSION_V1
        {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "pre-release observation receipt codec is unsupported",
            ));
        }
        let claims = Pir2PreReleaseObservationClaimsV1::new(
            decoder.u64("pre-release ordinal").map_err(|_| {
                SnpSealedSecretsErrorV1::InvalidReceipt(
                    "pre-release observation ordinal is truncated",
                )
            })?,
            decoder.array("pre-release verifier nonce").map_err(|_| {
                SnpSealedSecretsErrorV1::InvalidReceipt(
                    "pre-release observation verifier nonce is truncated",
                )
            })?,
            decoder.array("pre-release channel key").map_err(|_| {
                SnpSealedSecretsErrorV1::InvalidReceipt(
                    "pre-release observation channel key is truncated",
                )
            })?,
            decoder.array("pre-release boot id").map_err(|_| {
                SnpSealedSecretsErrorV1::InvalidReceipt(
                    "pre-release observation boot id is truncated",
                )
            })?,
        )?;
        let raw_report = decoder.array("pre-release raw report").map_err(|_| {
            SnpSealedSecretsErrorV1::InvalidReceipt(
                "pre-release observation raw report is truncated",
            )
        })?;
        decoder.finish().map_err(|_| {
            SnpSealedSecretsErrorV1::InvalidReceipt(
                "pre-release observation receipt has trailing bytes",
            )
        })?;
        let receipt = Self { claims, raw_report };
        receipt.verify_binding(expected_claims)?;
        if receipt.encode()? != exact_bytes {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "pre-release observation receipt is not canonical",
            ));
        }
        Ok(receipt)
    }

    pub fn verify_binding(
        &self,
        expected_claims: &Pir2PreReleaseObservationClaimsV1,
    ) -> Result<(), SnpSealedSecretsErrorV1> {
        if &self.claims != expected_claims {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "pre-release observation claims differ from current boot expectations",
            ));
        }
        let embedded_report_data = pir_core::attest::extract_report_data(&self.raw_report).ok_or(
            SnpSealedSecretsErrorV1::InvalidReceipt(
                "pre-release observation report is too short for REPORT_DATA",
            ),
        )?;
        if embedded_report_data != self.claims.report_data()? {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "raw SNP REPORT_DATA does not bind pre-release observation claims",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], SnpSealedSecretsErrorV1> {
        self.claims.digest()
    }

    pub fn claims(&self) -> &Pir2PreReleaseObservationClaimsV1 {
        &self.claims
    }

    pub fn raw_report(&self) -> &[u8; PIR2_PRE_RELEASE_OBSERVATION_RAW_REPORT_LEN_V1] {
        &self.raw_report
    }

    pub fn encode(&self) -> Result<Vec<u8>, SnpSealedSecretsErrorV1> {
        self.verify_binding(&self.claims)?;
        let claims = self.claims.encode_claims()?;
        let mut out = Vec::with_capacity(PIR2_PRE_RELEASE_OBSERVATION_RECEIPT_LEN_V1);
        out.extend_from_slice(PRE_RELEASE_OBSERVATION_MAGIC_V1);
        out.extend_from_slice(&ENVELOPE_CODEC_VERSION_V1.to_le_bytes());
        out.extend_from_slice(&claims);
        out.extend_from_slice(&self.raw_report);
        debug_assert_eq!(out.len(), PIR2_PRE_RELEASE_OBSERVATION_RECEIPT_LEN_V1);
        Ok(out)
    }
}

/// Ceremony phase committed into a current-boot attested receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Pir2SealedReceiptPhaseV1 {
    Observe = 1,
    Enroll = 2,
    Probe = 3,
    Ready = 4,
}

/// Canonical non-secret receipt claims. The verifier nonce, channel key and
/// boot ID jointly prevent a successful receipt from an earlier boot from
/// authorizing this process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pir2SealedReceiptClaimsV1 {
    pub phase: Pir2SealedReceiptPhaseV1,
    pub ordinal: u64,
    pub verifier_nonce: [u8; 32],
    pub current_channel_pubkey: [u8; 32],
    pub boot_id: [u8; 16],
    pub release_artifact_digest: [u8; 32],
    pub public_keys: Pir2SealedPublicKeysV1,
    pub public_fingerprints: Pir2SealedPublicFingerprintsV1,
    pub identity_generation: u64,
    pub clearing_authorization_epoch: u64,
}

impl Pir2SealedReceiptClaimsV1 {
    pub fn for_release(
        release: &VerifiedPir2SealedReleaseV1,
        phase: Pir2SealedReceiptPhaseV1,
        ordinal: u64,
        verifier_nonce: [u8; 32],
        current_channel_pubkey: [u8; 32],
        boot_id: [u8; 16],
        signing_material: Option<&Pir2SealedSigningMaterialV1>,
    ) -> Result<Self, SnpSealedSecretsErrorV1> {
        let (public_keys, public_fingerprints) = match signing_material {
            Some(material) => (material.public_keys(), material.public_fingerprints()),
            None => (
                Pir2SealedPublicKeysV1 {
                    service_identity: [0_u8; 32],
                    clearing: [0_u8; 32],
                },
                Pir2SealedPublicFingerprintsV1 {
                    service_identity: [0_u8; 32],
                    clearing: [0_u8; 32],
                },
            ),
        };
        let claims = Self {
            phase,
            ordinal,
            verifier_nonce,
            current_channel_pubkey,
            boot_id,
            release_artifact_digest: release.artifact_digest(),
            public_keys,
            public_fingerprints,
            identity_generation: release.release.identity_generation,
            clearing_authorization_epoch: release.release.clearing_authorization_epoch,
        };
        claims.validate()?;
        Ok(claims)
    }

    fn validate(&self) -> Result<(), SnpSealedSecretsErrorV1> {
        if self.ordinal == 0
            || self.verifier_nonce == [0_u8; 32]
            || self.current_channel_pubkey == [0_u8; 32]
            || self.boot_id == [0_u8; 16]
            || self.release_artifact_digest == [0_u8; 32]
            || self.identity_generation == 0
            || self.clearing_authorization_epoch == 0
        {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "receipt contains an empty freshness or release binding",
            ));
        }
        let keys_absent = self.public_keys.service_identity == [0_u8; 32]
            && self.public_keys.clearing == [0_u8; 32]
            && self.public_fingerprints.service_identity == [0_u8; 32]
            && self.public_fingerprints.clearing == [0_u8; 32];
        if self.phase == Pir2SealedReceiptPhaseV1::Observe {
            if !keys_absent {
                return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                    "observation receipt must not claim credential keys",
                ));
            }
            return Ok(());
        }
        if keys_absent
            || self.public_keys.service_identity == self.public_keys.clearing
            || public_key_fingerprint_v1(
                SERVICE_IDENTITY_FINGERPRINT_DOMAIN_V1,
                &self.public_keys.service_identity,
            ) != self.public_fingerprints.service_identity
            || public_key_fingerprint_v1(CLEARING_FINGERPRINT_DOMAIN_V1, &self.public_keys.clearing)
                != self.public_fingerprints.clearing
        {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "receipt credential public keys or fingerprints are invalid",
            ));
        }
        Ok(())
    }

    fn encode_claims(&self) -> Result<Vec<u8>, SnpSealedSecretsErrorV1> {
        self.validate()?;
        let mut out = Vec::with_capacity(280);
        out.push(self.phase as u8);
        out.extend_from_slice(&self.ordinal.to_le_bytes());
        out.extend_from_slice(&self.verifier_nonce);
        out.extend_from_slice(&self.current_channel_pubkey);
        out.extend_from_slice(&self.boot_id);
        out.extend_from_slice(&self.release_artifact_digest);
        out.extend_from_slice(&self.public_keys.service_identity);
        out.extend_from_slice(&self.public_keys.clearing);
        out.extend_from_slice(&self.public_fingerprints.service_identity);
        out.extend_from_slice(&self.public_fingerprints.clearing);
        out.extend_from_slice(&self.identity_generation.to_le_bytes());
        out.extend_from_slice(&self.clearing_authorization_epoch.to_le_bytes());
        Ok(out)
    }

    pub fn digest(&self) -> Result<[u8; 32], SnpSealedSecretsErrorV1> {
        let encoded = self.encode_claims()?;
        let mut hasher = Sha256::new();
        hasher.update((SEALED_RECEIPT_DIGEST_DOMAIN_V1.len() as u32).to_le_bytes());
        hasher.update(SEALED_RECEIPT_DIGEST_DOMAIN_V1);
        hasher.update((encoded.len() as u32).to_le_bytes());
        hasher.update(encoded);
        Ok(hasher.finalize().into())
    }

    pub fn report_data(&self) -> Result<[u8; 64], SnpSealedSecretsErrorV1> {
        let digest = self.digest()?;
        let mut report_data = [0_u8; 64];
        report_data[..32].copy_from_slice(&digest);
        report_data[32..].copy_from_slice(&digest);
        Ok(report_data)
    }
}

/// Canonical receipt plus the exact fresh SNP report bytes that carried its
/// digest in `REPORT_DATA`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pir2SealedReceiptV1 {
    pub claims: Pir2SealedReceiptClaimsV1,
    pub fresh_report: FreshSnpReportV1,
}

impl Pir2SealedReceiptV1 {
    pub fn request<P: SnpDerivedKeyProvider + ?Sized>(
        release: &VerifiedPir2SealedReleaseV1,
        claims: Pir2SealedReceiptClaimsV1,
        provider: &P,
    ) -> Result<Self, SnpSealedSecretsErrorV1> {
        if claims.release_artifact_digest != release.artifact_digest()
            || claims.identity_generation != release.release.identity_generation
            || claims.clearing_authorization_epoch != release.release.clearing_authorization_epoch
        {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "receipt does not match the verified release",
            ));
        }
        let report_data = claims.report_data()?;
        let fresh_report =
            request_and_validate_fresh_report_v1(release.release(), provider, report_data)?;
        let receipt = Self {
            claims,
            fresh_report,
        };
        receipt.verify_binding(&receipt.claims)?;
        Ok(receipt)
    }

    pub fn verify_binding(
        &self,
        expected_claims: &Pir2SealedReceiptClaimsV1,
    ) -> Result<(), SnpSealedSecretsErrorV1> {
        if &self.claims != expected_claims {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "receipt claims differ from the expected current-boot claims",
            ));
        }
        if self.fresh_report.raw_report.is_empty()
            || self.fresh_report.raw_report.len() > MAX_FRESH_SNP_REPORT_LEN_V1
        {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "fresh SNP report bytes are absent or oversized",
            ));
        }
        if self.fresh_report.report_data != self.claims.report_data()? {
            return Err(SnpSealedSecretsErrorV1::InvalidReceipt(
                "fresh SNP REPORT_DATA does not bind the receipt digest",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], SnpSealedSecretsErrorV1> {
        self.claims.digest()
    }

    pub fn encode(&self) -> Result<Vec<u8>, SnpSealedSecretsErrorV1> {
        self.verify_binding(&self.claims)?;
        let claims = self.claims.encode_claims()?;
        let report_len = u32::try_from(self.fresh_report.raw_report.len())
            .map_err(|_| SnpSealedSecretsErrorV1::InvalidReceipt("fresh report length overflow"))?;
        let mut out = Vec::with_capacity(18 + claims.len() + self.fresh_report.raw_report.len());
        out.extend_from_slice(SEALED_RECEIPT_MAGIC_V1);
        out.extend_from_slice(&ENVELOPE_CODEC_VERSION_V1.to_le_bytes());
        out.extend_from_slice(&(claims.len() as u32).to_le_bytes());
        out.extend_from_slice(&claims);
        out.extend_from_slice(&report_len.to_le_bytes());
        out.extend_from_slice(&self.fresh_report.raw_report);
        Ok(out)
    }
}

/// Fail-closed sealed-envelope errors. No variant includes a secret or key
/// digest.
#[derive(Debug)]
pub enum SnpSealedSecretsErrorV1 {
    InvalidRelease(&'static str),
    InvalidReceipt(&'static str),
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
            Self::InvalidReceipt(reason) => write!(formatter, "invalid sealed receipt: {reason}"),
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
    request_and_validate_fresh_report_v1(release, provider, challenge).map(|_| ())
}

fn request_and_validate_fresh_report_v1<P: SnpDerivedKeyProvider + ?Sized>(
    release: &Pir2SealedReleaseV1,
    provider: &P,
    expected_report_data: [u8; 64],
) -> Result<FreshSnpReportV1, SnpSealedSecretsErrorV1> {
    let report = provider.fresh_report(expected_report_data)?;
    if report.report_data != expected_report_data {
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
    if report.raw_report.is_empty() || report.raw_report.len() > MAX_FRESH_SNP_REPORT_LEN_V1 {
        return Err(SnpSealedSecretsErrorV1::ReportPolicy(
            "raw fresh report bytes are absent or oversized",
        ));
    }
    Ok(report)
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
                if report.raw_report.len() >= 0x90 {
                    report.raw_report[0x50..0x90].copy_from_slice(&report_data);
                }
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

    fn verified_release() -> (VerifiedPir2SealedReleaseV1, SigningKey) {
        let operator = SigningKey::from_bytes(&[0x61; 32]);
        let baseline = release();
        let claims = Pir2SealedReleaseClaimsV1 {
            provider_id: baseline.provider_id,
            stable_server_id: baseline.stable_server_id,
            uki_sha256: [0x44; 32],
            expected_measurement: baseline.expected_measurement,
            expected_guest_policy: baseline.expected_guest_policy,
            minimum_tcb: baseline.minimum_tcb,
            derived_key_request: SnpDerivedKeyRequestV1::production().canonical_evidence(),
            identity_generation: baseline.identity_generation,
            clearing_authorization_epoch: baseline.clearing_authorization_epoch,
        };
        let bytes = encode_signed_pir2_sealed_release_v1(&claims, &operator).unwrap();
        let verified =
            VerifiedPir2SealedReleaseV1::decode_and_verify(&bytes, &operator.verifying_key())
                .unwrap();
        (verified, operator)
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
            raw_report: vec![0xA5; 1184],
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

    #[test]
    fn signed_release_is_canonical_source_pinned_and_request_exact() {
        let (verified, operator) = verified_release();
        assert_eq!(verified.claims().uki_sha256, [0x44; 32]);
        assert_eq!(
            verified.claims().derived_key_request,
            SnpDerivedKeyRequestV1::production().canonical_evidence()
        );
        assert_eq!(
            verified.artifact_digest(),
            sealed_release_artifact_digest_v1(verified.exact_bytes())
        );

        let wrong = SigningKey::from_bytes(&[0x62; 32]);
        assert!(VerifiedPir2SealedReleaseV1::decode_and_verify(
            verified.exact_bytes(),
            &wrong.verifying_key()
        )
        .is_err());

        let mut tampered = verified.exact_bytes().to_vec();
        tampered[20] ^= 1;
        assert!(VerifiedPir2SealedReleaseV1::decode_and_verify(
            &tampered,
            &operator.verifying_key()
        )
        .is_err());

        let mut trailing = verified.exact_bytes().to_vec();
        trailing.push(0);
        assert!(VerifiedPir2SealedReleaseV1::decode_and_verify(
            &trailing,
            &operator.verifying_key()
        )
        .is_err());
    }

    #[test]
    fn signing_key_handoff_exposes_only_distinct_roles() {
        let material =
            Pir2SealedSigningMaterialV1::from_seed_pair(&[0x71; 32], &[0x72; 32]).unwrap();
        let public = material.public_keys();
        let keys = material.into_signing_keys();
        assert_eq!(
            public.service_identity,
            keys.service_identity.verifying_key().to_bytes()
        );
        assert_eq!(public.clearing, keys.clearing.verifying_key().to_bytes());
        assert_ne!(public.service_identity, public.clearing);
    }

    #[test]
    fn pre_release_observation_receipt_is_canonical_and_rejects_replay() {
        let claims =
            Pir2PreReleaseObservationClaimsV1::new(1, [0x81; 32], [0x82; 32], [0x83; 16]).unwrap();
        let provider = MockProviderV1::good(&release(), [0x42; 32]);
        let receipt =
            Pir2PreReleaseObservationReceiptV1::request(claims.clone(), &provider).unwrap();
        let encoded = receipt.encode().unwrap();
        assert_eq!(encoded.len(), PIR2_PRE_RELEASE_OBSERVATION_RECEIPT_LEN_V1);
        assert_eq!(
            &claims.report_data().unwrap()[..32],
            &claims.report_data().unwrap()[32..]
        );
        assert_eq!(
            Pir2PreReleaseObservationReceiptV1::decode_and_verify(&encoded, &claims).unwrap(),
            receipt
        );
        assert_eq!(provider.report_calls.get(), 1);
        assert_eq!(provider.derive_calls.get(), 0);

        let replay_variants = [
            Pir2PreReleaseObservationClaimsV1::new(2, [0x81; 32], [0x82; 32], [0x83; 16]).unwrap(),
            Pir2PreReleaseObservationClaimsV1::new(1, [0x91; 32], [0x82; 32], [0x83; 16]).unwrap(),
            Pir2PreReleaseObservationClaimsV1::new(1, [0x81; 32], [0x92; 32], [0x83; 16]).unwrap(),
            Pir2PreReleaseObservationClaimsV1::new(1, [0x81; 32], [0x82; 32], [0x93; 16]).unwrap(),
        ];
        for replay in replay_variants {
            assert!(
                Pir2PreReleaseObservationReceiptV1::decode_and_verify(&encoded, &replay).is_err()
            );
        }

        let mut tampered = encoded;
        tampered[10 + 88 + 0x50] ^= 1;
        assert!(Pir2PreReleaseObservationReceiptV1::decode_and_verify(&tampered, &claims).is_err());
    }

    #[test]
    fn receipt_binds_current_boot_channel_nonce_release_and_raw_keys() {
        let (verified, _) = verified_release();
        let material =
            Pir2SealedSigningMaterialV1::from_seed_pair(&[0x71; 32], &[0x72; 32]).unwrap();
        let claims = Pir2SealedReceiptClaimsV1::for_release(
            &verified,
            Pir2SealedReceiptPhaseV1::Probe,
            2,
            [0x81; 32],
            [0x82; 32],
            [0x83; 16],
            Some(&material),
        )
        .unwrap();
        let provider = MockProviderV1::good(verified.release(), [0x42; 32]);
        let receipt = Pir2SealedReceiptV1::request(&verified, claims.clone(), &provider).unwrap();
        assert_eq!(provider.report_calls.get(), 1);
        assert_eq!(provider.derive_calls.get(), 0);
        assert_eq!(
            receipt.fresh_report.report_data,
            claims.report_data().unwrap()
        );
        assert_eq!(
            &receipt.fresh_report.report_data[..32],
            &receipt.fresh_report.report_data[32..]
        );
        assert!(receipt.encode().unwrap().ends_with(&vec![0xA5; 1184]));

        let mut old_channel = claims;
        old_channel.current_channel_pubkey[0] ^= 1;
        assert!(receipt.verify_binding(&old_channel).is_err());
    }

    #[test]
    fn observation_receipt_never_claims_or_derives_credential_keys() {
        let (verified, _) = verified_release();
        let claims = Pir2SealedReceiptClaimsV1::for_release(
            &verified,
            Pir2SealedReceiptPhaseV1::Observe,
            1,
            [0x91; 32],
            [0x92; 32],
            [0x93; 16],
            None,
        )
        .unwrap();
        assert_eq!(claims.public_keys.service_identity, [0_u8; 32]);
        let provider = MockProviderV1::good(verified.release(), [0x42; 32]);
        Pir2SealedReceiptV1::request(&verified, claims, &provider).unwrap();
        assert_eq!(provider.report_calls.get(), 1);
        assert_eq!(provider.derive_calls.get(), 0);
    }
}
