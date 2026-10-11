//! Provider-signed assertions embedded in the untrusted Nostr directory.
//!
//! This module intentionally does not parse or trust a Nostr event. The outer
//! event is a discovery/curation envelope. These canonical inner bytes bind an
//! endpoint hint to an operator identity key and a stable server id. If the
//! caller has no out-of-band operator pin, its pinned directory key is the
//! curatorial/Sybil trust root for the discovered operator and endpoint; the
//! live identity check (REQ_ANNOUNCE: the asserted operator key certifies the
//! server identity for exactly the asserted stable server id) must still close
//! that directory assertion. A manual endpoint with an independent operator
//! pin bypasses that trust.
//!
//! History: the Payment V1 revision of this assertion also bound a
//! service-policy signing key, policy epoch and policy digest. Those fields
//! were removed with the Payment V1 tree before any production publication,
//! so the preimage below is the only v1 layout that was ever signed.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Stable provider audience derived from the operator key and server id.
pub type ProviderId = [u8; 32];

pub const PROVIDER_ID_DOMAIN_V1: &[u8] = b"BitcoinPIR/provider-id/v1";
pub const DIRECTORY_ASSERTION_VERSION_V1: u8 = 1;
pub const DIRECTORY_OPERATOR_ASSERTION_SIGNATURE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/directory-operator-assertion/v1";
pub const DIRECTORY_OPERATOR_ASSERTION_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/directory-operator-assertion-digest/v1";
pub const MAX_DIRECTORY_SERVER_ID_LEN_V1: usize = 256;
pub const MAX_DIRECTORY_ENDPOINTS_V1: usize = 8;
pub const MAX_DIRECTORY_ENDPOINT_LEN_V1: usize = 512;
pub const MAX_DIRECTORY_ASSERTION_LEN_V1: usize = 8 * 1024;
pub const MAX_DIRECTORY_ASSERTION_VALIDITY_SECONDS_V1: u64 = 31 * 24 * 60 * 60;

/// Derive a stable provider audience without using URL, IP, or peer identity.
///
/// The same derivation binds the live REQ_ANNOUNCE identity: the operator key
/// that signs the server's `IdentityCert` and the certificate's `server_id`
/// must derive exactly the directory `provider_id`.
pub fn derive_provider_id(
    operator_ed25519_pubkey: &[u8; 32],
    stable_server_id: &str,
) -> ProviderId {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_ID_DOMAIN_V1);
    hasher.update(operator_ed25519_pubkey);
    hasher.update((stable_server_id.len() as u32).to_le_bytes());
    hasher.update(stable_server_id.as_bytes());
    hasher.finalize().into()
}

/// Wire-format and signature failures of the inner operator assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryAssertionErrorV1 {
    Truncated(&'static str),
    UnknownVersion {
        kind: &'static str,
        version: u8,
    },
    UnknownDiscriminant {
        kind: &'static str,
        value: u8,
    },
    FieldTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    TooManyItems {
        field: &'static str,
        len: usize,
        max: usize,
    },
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
    InvalidUtf8(&'static str),
    TrailingBytes(usize),
    BadSignature,
    BadPublicKey,
}

impl fmt::Display for DirectoryAssertionErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(field) => write!(f, "truncated field: {field}"),
            Self::UnknownVersion { kind, version } => {
                write!(f, "{kind}: unknown version {version}")
            }
            Self::UnknownDiscriminant { kind, value } => {
                write!(f, "{kind}: unknown discriminant {value}")
            }
            Self::FieldTooLong { field, len, max } => {
                write!(f, "field {field} too long: {len} > {max}")
            }
            Self::TooManyItems { field, len, max } => {
                write!(f, "too many {field}: {len} > {max}")
            }
            Self::InvalidValue { field, reason } => write!(f, "invalid {field}: {reason}"),
            Self::InvalidUtf8(field) => write!(f, "field {field} is not UTF-8"),
            Self::TrailingBytes(n) => write!(f, "{n} trailing bytes"),
            Self::BadSignature => f.write_str("signature verification failed"),
            Self::BadPublicKey => f.write_str("invalid Ed25519 public key"),
        }
    }
}

impl std::error::Error for DirectoryAssertionErrorV1 {}

fn put_bytes_u16(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn finish(self) -> Result<(), DirectoryAssertionErrorV1> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(DirectoryAssertionErrorV1::TrailingBytes(
                self.bytes.len() - self.pos,
            ))
        }
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, DirectoryAssertionErrorV1> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, DirectoryAssertionErrorV1> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, DirectoryAssertionErrorV1> {
        let bytes = self.take(8, field)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("checked eight-byte slice"),
        ))
    }

    fn fixed<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], DirectoryAssertionErrorV1> {
        let bytes = self.take(N, field)?;
        Ok(bytes.try_into().expect("checked fixed-size slice"))
    }

    fn string_u16(
        &mut self,
        field: &'static str,
        max: usize,
    ) -> Result<String, DirectoryAssertionErrorV1> {
        let len = self.u16(field)? as usize;
        if len > max {
            return Err(DirectoryAssertionErrorV1::FieldTooLong { field, len, max });
        }
        let bytes = self.take(len, field)?.to_vec();
        String::from_utf8(bytes).map_err(|_| DirectoryAssertionErrorV1::InvalidUtf8(field))
    }

    fn take(
        &mut self,
        len: usize,
        field: &'static str,
    ) -> Result<&'a [u8], DirectoryAssertionErrorV1> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(DirectoryAssertionErrorV1::Truncated(field))?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or(DirectoryAssertionErrorV1::Truncated(field))?;
        self.pos = end;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DirectoryTransportV1 {
    Wss = 1,
}

impl DirectoryTransportV1 {
    fn decode(value: u8) -> Result<Self, DirectoryAssertionErrorV1> {
        match value {
            1 => Ok(Self::Wss),
            value => Err(DirectoryAssertionErrorV1::UnknownDiscriminant {
                kind: "DirectoryTransportV1",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DirectoryEndpointV1 {
    pub transport: DirectoryTransportV1,
    pub url: String,
}

impl DirectoryEndpointV1 {
    fn validate(&self) -> Result<(), DirectoryAssertionErrorV1> {
        if self.url.is_empty() || self.url.len() > MAX_DIRECTORY_ENDPOINT_LEN_V1 {
            return Err(DirectoryAssertionErrorV1::FieldTooLong {
                field: "DirectoryEndpointV1.url",
                len: self.url.len(),
                max: MAX_DIRECTORY_ENDPOINT_LEN_V1,
            });
        }
        match self.transport {
            DirectoryTransportV1::Wss if is_canonical_public_wss_endpoint_v1(&self.url) => Ok(()),
            DirectoryTransportV1::Wss => Err(DirectoryAssertionErrorV1::InvalidValue {
                field: "DirectoryEndpointV1.url",
                reason: "must be a canonical public wss URL",
            }),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), DirectoryAssertionErrorV1> {
        self.validate()?;
        out.push(self.transport as u8);
        put_bytes_u16(out, self.url.as_bytes());
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DirectoryAssertionErrorV1> {
        let value = Self {
            transport: DirectoryTransportV1::decode(decoder.u8("DirectoryEndpointV1.transport")?)?,
            url: decoder.string_u16("DirectoryEndpointV1.url", MAX_DIRECTORY_ENDPOINT_LEN_V1)?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryAssertionRollbackGuardV1 {
    pub highest_assertion_epoch: u64,
    pub digest_at_highest_epoch: [u8; 32],
}

impl DirectoryAssertionRollbackGuardV1 {
    pub const fn initial() -> Self {
        Self {
            highest_assertion_epoch: 0,
            digest_at_highest_epoch: [0; 32],
        }
    }

    pub fn from_verified(value: &VerifiedDirectoryOperatorAssertionV1<'_>) -> Self {
        Self {
            highest_assertion_epoch: value.assertion.assertion_epoch,
            digest_at_highest_epoch: value.assertion_digest,
        }
    }
}

/// Inner assertion signed by the provider's Ed25519 operator key.
///
/// Canonical preimage (little-endian integers, `len_u16` prefixed strings):
///
/// ```text
/// "BitcoinPIR/directory-operator-assertion/v1"
/// || version_u8
/// || operator_pubkey_ed25519_32
/// || len_u16(stable_server_id) || stable_server_id_utf8
/// || provider_id_32
/// || assertion_epoch_u64_le
/// || not_before_u64_le
/// || valid_until_u64_le
/// || endpoint_count_u8
/// || for each endpoint sorted by (transport, url):
///      transport_u8 || len_u16(url) || url_utf8
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryOperatorAssertionV1 {
    pub operator_pubkey_ed25519: [u8; 32],
    pub stable_server_id: String,
    pub provider_id: ProviderId,
    pub assertion_epoch: u64,
    pub not_before: u64,
    pub valid_until: u64,
    pub endpoints: Vec<DirectoryEndpointV1>,
    pub signature_ed25519: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedDirectoryOperatorAssertionV1<'a> {
    assertion: &'a DirectoryOperatorAssertionV1,
    assertion_digest: [u8; 32],
}

impl<'a> VerifiedDirectoryOperatorAssertionV1<'a> {
    pub const fn assertion(&self) -> &'a DirectoryOperatorAssertionV1 {
        self.assertion
    }

    pub const fn assertion_digest(&self) -> [u8; 32] {
        self.assertion_digest
    }
}

impl DirectoryOperatorAssertionV1 {
    pub fn sign(
        stable_server_id: String,
        assertion_epoch: u64,
        not_before: u64,
        valid_until: u64,
        endpoints: Vec<DirectoryEndpointV1>,
        operator_signing_key: &SigningKey,
    ) -> Result<Self, DirectoryAssertionErrorV1> {
        let operator_pubkey_ed25519 = operator_signing_key.verifying_key().to_bytes();
        let provider_id = derive_provider_id(&operator_pubkey_ed25519, &stable_server_id);
        let mut value = Self {
            operator_pubkey_ed25519,
            stable_server_id,
            provider_id,
            assertion_epoch,
            not_before,
            valid_until,
            endpoints,
            signature_ed25519: [0; 64],
        };
        value.validate()?;
        value.signature_ed25519 = operator_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, DirectoryAssertionErrorV1> {
        self.validate()?;
        let mut out = self.unsigned_encoding()?;
        out.extend_from_slice(&self.signature_ed25519);
        if out.len() > MAX_DIRECTORY_ASSERTION_LEN_V1 {
            return Err(DirectoryAssertionErrorV1::FieldTooLong {
                field: "DirectoryOperatorAssertionV1",
                len: out.len(),
                max: MAX_DIRECTORY_ASSERTION_LEN_V1,
            });
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DirectoryAssertionErrorV1> {
        if bytes.len() > MAX_DIRECTORY_ASSERTION_LEN_V1 {
            return Err(DirectoryAssertionErrorV1::FieldTooLong {
                field: "DirectoryOperatorAssertionV1",
                len: bytes.len(),
                max: MAX_DIRECTORY_ASSERTION_LEN_V1,
            });
        }
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("DirectoryOperatorAssertionV1.version")?;
        if version != DIRECTORY_ASSERTION_VERSION_V1 {
            return Err(DirectoryAssertionErrorV1::UnknownVersion {
                kind: "DirectoryOperatorAssertionV1",
                version,
            });
        }
        let operator_pubkey_ed25519 =
            decoder.fixed("DirectoryOperatorAssertionV1.operator_pubkey_ed25519")?;
        let stable_server_id = decoder.string_u16(
            "DirectoryOperatorAssertionV1.stable_server_id",
            MAX_DIRECTORY_SERVER_ID_LEN_V1,
        )?;
        let provider_id = decoder.fixed("DirectoryOperatorAssertionV1.provider_id")?;
        let assertion_epoch = decoder.u64("DirectoryOperatorAssertionV1.assertion_epoch")?;
        let not_before = decoder.u64("DirectoryOperatorAssertionV1.not_before")?;
        let valid_until = decoder.u64("DirectoryOperatorAssertionV1.valid_until")?;
        let endpoint_count = decoder.u8("DirectoryOperatorAssertionV1.endpoint_count")? as usize;
        if endpoint_count == 0 || endpoint_count > MAX_DIRECTORY_ENDPOINTS_V1 {
            return Err(DirectoryAssertionErrorV1::TooManyItems {
                field: "DirectoryOperatorAssertionV1.endpoints",
                len: endpoint_count,
                max: MAX_DIRECTORY_ENDPOINTS_V1,
            });
        }
        let mut endpoints = Vec::with_capacity(endpoint_count);
        for _ in 0..endpoint_count {
            endpoints.push(DirectoryEndpointV1::decode_from(&mut decoder)?);
        }
        let signature_ed25519 = decoder.fixed("DirectoryOperatorAssertionV1.signature_ed25519")?;
        decoder.finish()?;
        let value = Self {
            operator_pubkey_ed25519,
            stable_server_id,
            provider_id,
            assertion_epoch,
            not_before,
            valid_until,
            endpoints,
            signature_ed25519,
        };
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(DirectoryAssertionErrorV1::InvalidValue {
                field: "DirectoryOperatorAssertionV1",
                reason: "encoding is not canonical",
            });
        }
        Ok(value)
    }

    pub fn assertion_digest(&self) -> Result<[u8; 32], DirectoryAssertionErrorV1> {
        let mut hasher = Sha256::new();
        hasher.update(DIRECTORY_OPERATOR_ASSERTION_DIGEST_DOMAIN_V1);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    pub fn verify_current_for<'a>(
        &'a self,
        expected_provider_id: &ProviderId,
        expected_operator_pubkey_ed25519: &[u8; 32],
        now_unix: u64,
        rollback_guard: &DirectoryAssertionRollbackGuardV1,
    ) -> Result<VerifiedDirectoryOperatorAssertionV1<'a>, DirectoryAssertionErrorV1> {
        self.verify_signature_and_binding(expected_provider_id, expected_operator_pubkey_ed25519)?;
        if now_unix < self.not_before || now_unix > self.valid_until {
            return Err(DirectoryAssertionErrorV1::InvalidValue {
                field: "DirectoryOperatorAssertionV1.validity",
                reason: "assertion is not currently valid",
            });
        }
        let initial_guard = rollback_guard.highest_assertion_epoch == 0
            && rollback_guard
                .digest_at_highest_epoch
                .iter()
                .all(|byte| *byte == 0);
        let persisted_guard = rollback_guard.highest_assertion_epoch != 0
            && rollback_guard
                .digest_at_highest_epoch
                .iter()
                .any(|byte| *byte != 0);
        if !initial_guard && !persisted_guard {
            return Err(DirectoryAssertionErrorV1::InvalidValue {
                field: "DirectoryAssertionRollbackGuardV1",
                reason: "initial and persisted rollback states are inconsistent",
            });
        }
        if self.assertion_epoch < rollback_guard.highest_assertion_epoch {
            return Err(DirectoryAssertionErrorV1::InvalidValue {
                field: "DirectoryOperatorAssertionV1.assertion_epoch",
                reason: "operator assertion epoch rollback",
            });
        }
        let assertion_digest = self.assertion_digest()?;
        if self.assertion_epoch == rollback_guard.highest_assertion_epoch
            && self.assertion_epoch != 0
            && assertion_digest != rollback_guard.digest_at_highest_epoch
        {
            return Err(DirectoryAssertionErrorV1::InvalidValue {
                field: "DirectoryOperatorAssertionV1.assertion_digest",
                reason: "different operator assertion at an accepted epoch",
            });
        }
        Ok(VerifiedDirectoryOperatorAssertionV1 {
            assertion: self,
            assertion_digest,
        })
    }

    fn verify_signature_and_binding(
        &self,
        expected_provider_id: &ProviderId,
        expected_operator_pubkey_ed25519: &[u8; 32],
    ) -> Result<(), DirectoryAssertionErrorV1> {
        self.validate()?;
        if &self.provider_id != expected_provider_id
            || &self.operator_pubkey_ed25519 != expected_operator_pubkey_ed25519
        {
            return Err(DirectoryAssertionErrorV1::InvalidValue {
                field: "DirectoryOperatorAssertionV1.identity",
                reason: "does not match the caller-expected provider and operator",
            });
        }
        let verifying_key = VerifyingKey::from_bytes(expected_operator_pubkey_ed25519)
            .map_err(|_| DirectoryAssertionErrorV1::BadPublicKey)?;
        verifying_key
            .verify_strict(
                &self.signing_preimage()?,
                &Signature::from_bytes(&self.signature_ed25519),
            )
            .map_err(|_| DirectoryAssertionErrorV1::BadSignature)
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, DirectoryAssertionErrorV1> {
        let unsigned = self.unsigned_encoding()?;
        let mut out = Vec::with_capacity(
            DIRECTORY_OPERATOR_ASSERTION_SIGNATURE_DOMAIN_V1.len() + unsigned.len(),
        );
        out.extend_from_slice(DIRECTORY_OPERATOR_ASSERTION_SIGNATURE_DOMAIN_V1);
        out.extend_from_slice(&unsigned);
        Ok(out)
    }

    fn unsigned_encoding(&self) -> Result<Vec<u8>, DirectoryAssertionErrorV1> {
        self.validate()?;
        let mut out = Vec::with_capacity(512);
        out.push(DIRECTORY_ASSERTION_VERSION_V1);
        out.extend_from_slice(&self.operator_pubkey_ed25519);
        put_bytes_u16(&mut out, self.stable_server_id.as_bytes());
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.assertion_epoch.to_le_bytes());
        out.extend_from_slice(&self.not_before.to_le_bytes());
        out.extend_from_slice(&self.valid_until.to_le_bytes());
        out.push(self.endpoints.len() as u8);
        for endpoint in &self.endpoints {
            endpoint.encode_into(&mut out)?;
        }
        Ok(out)
    }

    fn validate(&self) -> Result<(), DirectoryAssertionErrorV1> {
        let server_id = self.stable_server_id.as_bytes();
        if server_id.is_empty()
            || server_id.len() > MAX_DIRECTORY_SERVER_ID_LEN_V1
            || server_id.iter().any(|byte| byte.is_ascii_control())
        {
            return Err(DirectoryAssertionErrorV1::InvalidValue {
                field: "DirectoryOperatorAssertionV1.stable_server_id",
                reason: "must be non-empty, bounded UTF-8 without control characters",
            });
        }
        if self.operator_pubkey_ed25519.iter().all(|byte| *byte == 0)
            || self.provider_id.iter().all(|byte| *byte == 0)
            || self.assertion_epoch == 0
            || self.not_before == 0
            || self.valid_until < self.not_before
            || self.valid_until - self.not_before > MAX_DIRECTORY_ASSERTION_VALIDITY_SECONDS_V1
        {
            return Err(DirectoryAssertionErrorV1::InvalidValue {
                field: "DirectoryOperatorAssertionV1",
                reason: "identity, epoch, or validity window is invalid",
            });
        }
        if derive_provider_id(&self.operator_pubkey_ed25519, &self.stable_server_id)
            != self.provider_id
        {
            return Err(DirectoryAssertionErrorV1::InvalidValue {
                field: "DirectoryOperatorAssertionV1.provider_id",
                reason: "does not derive from operator key and stable server id",
            });
        }
        if self.endpoints.is_empty() || self.endpoints.len() > MAX_DIRECTORY_ENDPOINTS_V1 {
            return Err(DirectoryAssertionErrorV1::TooManyItems {
                field: "DirectoryOperatorAssertionV1.endpoints",
                len: self.endpoints.len(),
                max: MAX_DIRECTORY_ENDPOINTS_V1,
            });
        }
        for endpoint in &self.endpoints {
            endpoint.validate()?;
        }
        if !self.endpoints.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(DirectoryAssertionErrorV1::InvalidValue {
                field: "DirectoryOperatorAssertionV1.endpoints",
                reason: "endpoints must be strictly sorted and unique",
            });
        }
        Ok(())
    }
}

/// Return whether `endpoint` is the canonical, credential-free public `wss://`
/// form accepted by the directory protocol.
///
/// Provider discovery endpoints use this broader path-capable grammar. Relay
/// transports use the origin-only predicate below.
pub fn is_canonical_public_wss_endpoint_v1(endpoint: &str) -> bool {
    if endpoint.is_empty()
        || endpoint.len() > MAX_DIRECTORY_ENDPOINT_LEN_V1
        || !endpoint.is_ascii()
        || endpoint
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || endpoint.bytes().any(|byte| byte == 0x7f)
    {
        return false;
    }
    let Some(rest) = endpoint.strip_prefix("wss://") else {
        return false;
    };
    if rest.is_empty() || rest.ends_with('/') || rest.contains(['@', '\\', '?', '#']) {
        return false;
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() {
        return false;
    }
    if authority.starts_with('[') || authority.matches(':').count() > 1 {
        return false;
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if host.is_empty()
        || host.len() > 253
        || !host.contains('.')
        || host.starts_with('.')
        || host.ends_with('.')
        || host
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b'x' | b'X' | b'.'))
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return false;
    }
    if let Some(port) = port {
        let parsed = port.parse::<u16>().ok();
        if port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || parsed.is_none()
            || parsed == Some(0)
            || parsed == Some(443)
            || parsed.is_some_and(|value| value.to_string() != port)
        {
            return false;
        }
    }
    if !path.is_empty()
        && (path.starts_with('/')
            || path.ends_with('/')
            || path.contains("//")
            || path.contains('%')
            || !path.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/')
            })
            || path
                .split('/')
                .any(|segment| segment == "." || segment == ".."))
    {
        return false;
    }
    true
}

/// Canonical directory-relay form: the exact credential-free public WSS
/// origin with no path. Provider service endpoints intentionally retain the
/// broader endpoint grammar above.
pub fn is_canonical_public_wss_origin_v1(origin: &str) -> bool {
    is_canonical_public_wss_endpoint_v1(origin) && !origin["wss://".len()..].contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(url: &str) -> DirectoryEndpointV1 {
        DirectoryEndpointV1 {
            transport: DirectoryTransportV1::Wss,
            url: url.to_owned(),
        }
    }

    fn assertion(epoch: u64, key: &SigningKey) -> DirectoryOperatorAssertionV1 {
        assertion_with_endpoints(
            epoch,
            key,
            vec![
                endpoint("wss://a.example/v1"),
                endpoint("wss://b.example:8443/v1"),
            ],
        )
    }

    fn assertion_with_endpoints(
        epoch: u64,
        key: &SigningKey,
        endpoints: Vec<DirectoryEndpointV1>,
    ) -> DirectoryOperatorAssertionV1 {
        DirectoryOperatorAssertionV1::sign("pir-a".to_owned(), epoch, 1_000, 2_000, endpoints, key)
            .unwrap()
    }

    #[test]
    fn provider_id_derivation_is_domain_separated_and_length_prefixed() {
        let key = [7; 32];
        assert_ne!(derive_provider_id(&key, "a"), derive_provider_id(&key, "b"));
        assert_ne!(
            derive_provider_id(&key, "ab"),
            derive_provider_id(&[8; 32], "ab")
        );
        let mut hasher = Sha256::new();
        hasher.update(PROVIDER_ID_DOMAIN_V1);
        hasher.update(key);
        hasher.update(5u32.to_le_bytes());
        hasher.update(b"pir-a");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(derive_provider_id(&key, "pir-a"), expected);
    }

    #[test]
    fn signed_assertion_roundtrips_and_binds_expected_identity() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let value = assertion(4, &key);
        let bytes = value.encode().unwrap();
        let decoded = DirectoryOperatorAssertionV1::decode(&bytes).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(
            decoded.provider_id,
            derive_provider_id(&key.verifying_key().to_bytes(), "pir-a")
        );

        let verified = decoded
            .verify_current_for(
                &value.provider_id,
                &key.verifying_key().to_bytes(),
                1_500,
                &DirectoryAssertionRollbackGuardV1::initial(),
            )
            .unwrap();
        assert_eq!(verified.assertion(), &value);
        assert_ne!(verified.assertion_digest(), [0; 32]);

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            DirectoryOperatorAssertionV1::decode(&trailing),
            Err(DirectoryAssertionErrorV1::TrailingBytes(1))
        );
    }

    #[test]
    fn expected_key_provider_and_signature_are_not_self_asserted_trust() {
        let key = SigningKey::from_bytes(&[4; 32]);
        let other = SigningKey::from_bytes(&[5; 32]);
        let mut value = assertion(1, &key);
        assert!(value
            .verify_current_for(
                &value.provider_id,
                &other.verifying_key().to_bytes(),
                1_500,
                &DirectoryAssertionRollbackGuardV1::initial(),
            )
            .is_err());
        let mut wrong_provider = value.provider_id;
        wrong_provider[0] ^= 1;
        assert!(value
            .verify_current_for(
                &wrong_provider,
                &key.verifying_key().to_bytes(),
                1_500,
                &DirectoryAssertionRollbackGuardV1::initial(),
            )
            .is_err());
        value.signature_ed25519[0] ^= 1;
        assert!(matches!(
            value.verify_current_for(
                &value.provider_id,
                &key.verifying_key().to_bytes(),
                1_500,
                &DirectoryAssertionRollbackGuardV1::initial(),
            ),
            Err(DirectoryAssertionErrorV1::BadSignature)
        ));

        let mut wrong_endpoint = assertion(2, &key);
        wrong_endpoint.endpoints[0].url = "wss://a.example/v2".to_owned();
        assert!(matches!(
            wrong_endpoint.verify_current_for(
                &wrong_endpoint.provider_id,
                &key.verifying_key().to_bytes(),
                1_500,
                &DirectoryAssertionRollbackGuardV1::initial(),
            ),
            Err(DirectoryAssertionErrorV1::BadSignature)
        ));
    }

    #[test]
    fn assertion_epoch_is_monotonic_and_same_epoch_forks_fail() {
        let key = SigningKey::from_bytes(&[6; 32]);
        let current = assertion(7, &key);
        let current_verified = current
            .verify_current_for(
                &current.provider_id,
                &key.verifying_key().to_bytes(),
                1_500,
                &DirectoryAssertionRollbackGuardV1::initial(),
            )
            .unwrap();
        let guard = DirectoryAssertionRollbackGuardV1::from_verified(&current_verified);
        assert!(current
            .verify_current_for(
                &current.provider_id,
                &key.verifying_key().to_bytes(),
                1_500,
                &guard,
            )
            .is_ok());
        let lower = assertion(6, &key);
        assert!(lower
            .verify_current_for(
                &lower.provider_id,
                &key.verifying_key().to_bytes(),
                1_500,
                &guard,
            )
            .is_err());
        let fork = assertion_with_endpoints(7, &key, vec![endpoint("wss://fork.example/v1")]);
        assert!(fork
            .verify_current_for(
                &fork.provider_id,
                &key.verifying_key().to_bytes(),
                1_500,
                &guard,
            )
            .is_err());
    }

    #[test]
    fn invalid_validity_and_noncanonical_endpoints_fail_closed() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let value = assertion(1, &key);
        for now in [999, 2_001] {
            assert!(value
                .verify_current_for(
                    &value.provider_id,
                    &key.verifying_key().to_bytes(),
                    now,
                    &DirectoryAssertionRollbackGuardV1::initial(),
                )
                .is_err());
        }
        for bad in [
            "ws://a.example/v1",
            "wss://A.example/v1",
            "wss://user@a.example/v1",
            "wss://a.example:443/v1",
            "wss://127.0.0.1/v1",
            "wss://internal/v1",
            "wss://a.example/v1/",
            "wss://a.example/v1?x=1",
            "wss://a.example//query",
            "wss://a.example/v1//query",
            &format!(
                "wss://a.example/{}",
                "x".repeat(MAX_DIRECTORY_ENDPOINT_LEN_V1)
            ),
        ] {
            assert!(!is_canonical_public_wss_endpoint_v1(bad), "accepted {bad}");
        }
        assert!(is_canonical_public_wss_endpoint_v1("wss://a.example/v1"));
        assert!(is_canonical_public_wss_endpoint_v1(
            "wss://a.example:8443/v1"
        ));
        assert!(is_canonical_public_wss_endpoint_v1(
            "wss://weikeng1.bitcoinpir.org"
        ));
        assert!(is_canonical_public_wss_origin_v1("wss://a.example"));
        assert!(is_canonical_public_wss_origin_v1("wss://a.example:8443"));
        assert!(!is_canonical_public_wss_origin_v1("wss://a.example/v1"));
        assert!(!is_canonical_public_wss_origin_v1("wss://a.example/"));
        assert!(!is_canonical_public_wss_origin_v1("wss://a.example:443"));
        assert!(!is_canonical_public_wss_origin_v1("wss://a.example:0"));
        assert!(!is_canonical_public_wss_origin_v1("wss://a.example:08443"));
    }

    #[test]
    fn endpoints_must_be_strictly_sorted_and_unique() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let result = DirectoryOperatorAssertionV1::sign(
            "pir-a".to_owned(),
            1,
            1,
            10,
            vec![
                endpoint("wss://b.example/v1"),
                endpoint("wss://a.example/v1"),
            ],
            &key,
        );
        assert!(result.is_err());
    }

    #[test]
    fn validity_window_and_epoch_must_be_nonzero_and_bounded() {
        let key = SigningKey::from_bytes(&[10; 32]);
        for (epoch, not_before, valid_until) in [
            (0, 1, 10),
            (1, 0, 10),
            (1, 10, 9),
            (1, 1, 1 + MAX_DIRECTORY_ASSERTION_VALIDITY_SECONDS_V1 + 1),
        ] {
            let result = DirectoryOperatorAssertionV1::sign(
                "pir-a".to_owned(),
                epoch,
                not_before,
                valid_until,
                vec![endpoint("wss://a.example/v1")],
                &key,
            );
            assert!(matches!(
                result,
                Err(DirectoryAssertionErrorV1::InvalidValue {
                    field: "DirectoryOperatorAssertionV1",
                    ..
                })
            ));
        }
    }
}
