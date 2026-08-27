//! Provider-signed assertions embedded in the untrusted Nostr directory.
//!
//! This module intentionally does not parse or trust a Nostr event. The outer
//! event is a discovery/curation envelope. These canonical inner bytes bind an
//! endpoint hint, operator identity, distinct policy key, epoch and digest. If
//! the caller has no out-of-band operator pin, its pinned directory key is the
//! curatorial/Sybil trust root for the discovered operator and endpoint; the
//! live identity and policy checks must still close that directory assertion.
//! A manual endpoint with an independent operator pin bypasses that trust.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::codec::{expect_v1, put_bytes_u16, Decoder};
use crate::{derive_provider_id, ProviderId, ServiceProtocolError, SERVICE_PROTOCOL_VERSION};

pub const DIRECTORY_OPERATOR_ASSERTION_SIGNATURE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/directory-operator-assertion/v1";
pub const DIRECTORY_OPERATOR_ASSERTION_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/directory-operator-assertion-digest/v1";
pub const MAX_DIRECTORY_SERVER_ID_LEN_V1: usize = 256;
pub const MAX_DIRECTORY_ENDPOINTS_V1: usize = 8;
pub const MAX_DIRECTORY_ENDPOINT_LEN_V1: usize = 512;
pub const MAX_DIRECTORY_ASSERTION_LEN_V1: usize = 8 * 1024;
pub const MAX_DIRECTORY_ASSERTION_VALIDITY_SECONDS_V1: u64 = 31 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DirectoryTransportV1 {
    Wss = 1,
}

impl DirectoryTransportV1 {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::Wss),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
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
    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.url.is_empty() || self.url.len() > MAX_DIRECTORY_ENDPOINT_LEN_V1 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "DirectoryEndpointV1.url",
                len: self.url.len(),
                max: MAX_DIRECTORY_ENDPOINT_LEN_V1,
            });
        }
        match self.transport {
            DirectoryTransportV1::Wss if is_canonical_public_wss_endpoint_v1(&self.url) => Ok(()),
            DirectoryTransportV1::Wss => Err(ServiceProtocolError::InvalidValue {
                field: "DirectoryEndpointV1.url",
                reason: "must be a canonical public wss URL",
            }),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        out.push(self.transport as u8);
        put_bytes_u16(out, self.url.as_bytes());
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ServiceProtocolError> {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryOperatorAssertionV1 {
    pub operator_pubkey_ed25519: [u8; 32],
    pub stable_server_id: String,
    pub provider_id: ProviderId,
    pub assertion_epoch: u64,
    pub not_before: u64,
    pub valid_until: u64,
    pub endpoints: Vec<DirectoryEndpointV1>,
    pub policy_signing_key_ed25519: [u8; 32],
    pub policy_epoch: u64,
    pub policy_digest: [u8; 32],
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
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        stable_server_id: String,
        assertion_epoch: u64,
        not_before: u64,
        valid_until: u64,
        endpoints: Vec<DirectoryEndpointV1>,
        policy_signing_key_ed25519: [u8; 32],
        policy_epoch: u64,
        policy_digest: [u8; 32],
        operator_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
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
            policy_signing_key_ed25519,
            policy_epoch,
            policy_digest,
            signature_ed25519: [0; 64],
        };
        value.validate()?;
        value.signature_ed25519 = operator_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = self.unsigned_encoding()?;
        out.extend_from_slice(&self.signature_ed25519);
        if out.len() > MAX_DIRECTORY_ASSERTION_LEN_V1 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "DirectoryOperatorAssertionV1",
                len: out.len(),
                max: MAX_DIRECTORY_ASSERTION_LEN_V1,
            });
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_DIRECTORY_ASSERTION_LEN_V1 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "DirectoryOperatorAssertionV1",
                len: bytes.len(),
                max: MAX_DIRECTORY_ASSERTION_LEN_V1,
            });
        }
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("DirectoryOperatorAssertionV1.version")?,
            "DirectoryOperatorAssertionV1",
        )?;
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
            return Err(ServiceProtocolError::TooManyItems {
                field: "DirectoryOperatorAssertionV1.endpoints",
                len: endpoint_count,
                max: MAX_DIRECTORY_ENDPOINTS_V1,
            });
        }
        let mut endpoints = Vec::with_capacity(endpoint_count);
        for _ in 0..endpoint_count {
            endpoints.push(DirectoryEndpointV1::decode_from(&mut decoder)?);
        }
        let policy_signing_key_ed25519 =
            decoder.fixed("DirectoryOperatorAssertionV1.policy_signing_key_ed25519")?;
        let policy_epoch = decoder.u64("DirectoryOperatorAssertionV1.policy_epoch")?;
        let policy_digest = decoder.fixed("DirectoryOperatorAssertionV1.policy_digest")?;
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
            policy_signing_key_ed25519,
            policy_epoch,
            policy_digest,
            signature_ed25519,
        };
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: "DirectoryOperatorAssertionV1",
                reason: "encoding is not canonical",
            });
        }
        Ok(value)
    }

    pub fn assertion_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
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
    ) -> Result<VerifiedDirectoryOperatorAssertionV1<'a>, ServiceProtocolError> {
        self.verify_signature_and_binding(expected_provider_id, expected_operator_pubkey_ed25519)?;
        if now_unix < self.not_before || now_unix > self.valid_until {
            return Err(ServiceProtocolError::InvalidValue {
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
            return Err(ServiceProtocolError::InvalidValue {
                field: "DirectoryAssertionRollbackGuardV1",
                reason: "initial and persisted rollback states are inconsistent",
            });
        }
        if self.assertion_epoch < rollback_guard.highest_assertion_epoch {
            return Err(ServiceProtocolError::InvalidValue {
                field: "DirectoryOperatorAssertionV1.assertion_epoch",
                reason: "operator assertion epoch rollback",
            });
        }
        let assertion_digest = self.assertion_digest()?;
        if self.assertion_epoch == rollback_guard.highest_assertion_epoch
            && self.assertion_epoch != 0
            && assertion_digest != rollback_guard.digest_at_highest_epoch
        {
            return Err(ServiceProtocolError::InvalidValue {
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
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        if &self.provider_id != expected_provider_id
            || &self.operator_pubkey_ed25519 != expected_operator_pubkey_ed25519
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "DirectoryOperatorAssertionV1.identity",
                reason: "does not match the caller-expected provider and operator",
            });
        }
        let verifying_key = VerifyingKey::from_bytes(expected_operator_pubkey_ed25519)
            .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        verifying_key
            .verify_strict(
                &self.signing_preimage()?,
                &Signature::from_bytes(&self.signature_ed25519),
            )
            .map_err(|_| ServiceProtocolError::BadSignature)
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let unsigned = self.unsigned_encoding()?;
        let mut out = Vec::with_capacity(
            DIRECTORY_OPERATOR_ASSERTION_SIGNATURE_DOMAIN_V1.len() + unsigned.len(),
        );
        out.extend_from_slice(DIRECTORY_OPERATOR_ASSERTION_SIGNATURE_DOMAIN_V1);
        out.extend_from_slice(&unsigned);
        Ok(out)
    }

    fn unsigned_encoding(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(512);
        out.push(SERVICE_PROTOCOL_VERSION);
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
        out.extend_from_slice(&self.policy_signing_key_ed25519);
        out.extend_from_slice(&self.policy_epoch.to_le_bytes());
        out.extend_from_slice(&self.policy_digest);
        Ok(out)
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        let server_id = self.stable_server_id.as_bytes();
        if server_id.is_empty()
            || server_id.len() > MAX_DIRECTORY_SERVER_ID_LEN_V1
            || server_id.iter().any(|byte| byte.is_ascii_control())
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "DirectoryOperatorAssertionV1.stable_server_id",
                reason: "must be non-empty, bounded UTF-8 without control characters",
            });
        }
        if self.operator_pubkey_ed25519.iter().all(|byte| *byte == 0)
            || self.provider_id.iter().all(|byte| *byte == 0)
            || self
                .policy_signing_key_ed25519
                .iter()
                .all(|byte| *byte == 0)
            || self.policy_signing_key_ed25519 == self.operator_pubkey_ed25519
            || self.policy_digest.iter().all(|byte| *byte == 0)
            || self.assertion_epoch == 0
            || self.policy_epoch == 0
            || self.not_before == 0
            || self.valid_until < self.not_before
            || self.valid_until - self.not_before > MAX_DIRECTORY_ASSERTION_VALIDITY_SECONDS_V1
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "DirectoryOperatorAssertionV1",
                reason: "identity, separate policy signing key, epochs, digest, or validity window is invalid",
            });
        }
        if derive_provider_id(&self.operator_pubkey_ed25519, &self.stable_server_id)
            != self.provider_id
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "DirectoryOperatorAssertionV1.provider_id",
                reason: "does not derive from operator key and stable server id",
            });
        }
        if self.endpoints.is_empty() || self.endpoints.len() > MAX_DIRECTORY_ENDPOINTS_V1 {
            return Err(ServiceProtocolError::TooManyItems {
                field: "DirectoryOperatorAssertionV1.endpoints",
                len: self.endpoints.len(),
                max: MAX_DIRECTORY_ENDPOINTS_V1,
            });
        }
        for endpoint in &self.endpoints {
            endpoint.validate()?;
        }
        if !self.endpoints.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ServiceProtocolError::InvalidValue {
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
        DirectoryOperatorAssertionV1::sign(
            "pir-a".to_owned(),
            epoch,
            1_000,
            2_000,
            vec![
                endpoint("wss://a.example/v1"),
                endpoint("wss://b.example:8443/v1"),
            ],
            [11; 32],
            9,
            [7; 32],
            key,
        )
        .unwrap()
    }

    #[test]
    fn signed_assertion_roundtrips_and_binds_expected_identity() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let value = assertion(4, &key);
        let bytes = value.encode().unwrap();
        let decoded = DirectoryOperatorAssertionV1::decode(&bytes).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(decoded.policy_signing_key_ed25519, [11; 32]);

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
            Err(ServiceProtocolError::TrailingBytes(1))
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
            Err(ServiceProtocolError::BadSignature)
        ));

        let mut wrong_policy_key = assertion(2, &key);
        wrong_policy_key.policy_signing_key_ed25519[0] ^= 1;
        assert!(matches!(
            wrong_policy_key.verify_current_for(
                &wrong_policy_key.provider_id,
                &key.verifying_key().to_bytes(),
                1_500,
                &DirectoryAssertionRollbackGuardV1::initial(),
            ),
            Err(ServiceProtocolError::BadSignature)
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
        let mut fork = assertion(7, &key);
        fork.policy_digest[0] ^= 1;
        fork.signature_ed25519 = key.sign(&fork.signing_preimage().unwrap()).to_bytes();
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
            [2; 32],
            1,
            [1; 32],
            &key,
        );
        assert!(result.is_err());
    }

    #[test]
    fn policy_signing_key_must_be_nonzero_and_distinct_from_operator_key() {
        let key = SigningKey::from_bytes(&[10; 32]);
        for policy_signing_key_ed25519 in [[0; 32], key.verifying_key().to_bytes()] {
            let result = DirectoryOperatorAssertionV1::sign(
                "pir-a".to_owned(),
                1,
                1,
                10,
                vec![endpoint("wss://a.example/v1")],
                policy_signing_key_ed25519,
                1,
                [1; 32],
                &key,
            );
            assert!(matches!(
                result,
                Err(ServiceProtocolError::InvalidValue {
                    field: "DirectoryOperatorAssertionV1",
                    ..
                })
            ));
        }
    }
}
