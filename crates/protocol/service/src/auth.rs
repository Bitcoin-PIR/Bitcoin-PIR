//! Method-neutral service authorization messages.

use sha2::{Digest, Sha256};

use crate::attach::{HarmonyAttachGrantV1, HarmonyHintSideV1};
use crate::codec::{expect_v1, put_bytes_u32, Decoder};
use crate::{
    AuthPaddingClassV1, AuthScheme, BackendId, ScopeId, ServicePolicyV1, ServiceProtocolError,
    WorkloadId, MAX_SIGNED_POLICY_LEN, SERVICE_PROTOCOL_VERSION,
};

/// Exact V1 authorization body length, excluding the one-byte PIR opcode and
/// outer four-byte record length.
pub const AUTH_FRAME_CLASS_V1: usize = 16 * 1024;
pub const MAX_AUTH_KEY_ID_LEN: usize = 64;
pub const MAX_AUTH_PROOF_LEN: usize = 12 * 1024;
pub const MAX_POLICY_WIRE_LEN: usize = MAX_SIGNED_POLICY_LEN;
pub const OPERATION_START_DIGEST_DOMAIN: &[u8] = b"BitcoinPIR/operation-start/v1";
pub(crate) const MAX_OPERATION_ENCODING_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HintTransport {
    V2Full = 1,
    V2Half = 2,
}

impl HintTransport {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::V2Full),
            2 => Ok(Self::V2Half),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "HintTransport",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationStartV1 {
    DpfQuery {
        db_id: u8,
    },
    HarmonyHint {
        db_id: u8,
        transport: HintTransport,
        session_token: Option<[u8; 16]>,
        primary_side: Option<HarmonyHintSideV1>,
    },
    HarmonyQuery {
        db_id: u8,
    },
    OnionSession {
        db_id: u8,
    },
    TeeOramQuery {
        db_id: u8,
    },
}

impl OperationStartV1 {
    pub fn required_service(&self) -> (BackendId, WorkloadId) {
        match self {
            Self::DpfQuery { .. } => (BackendId::DpfPirV1, WorkloadId::DpfEvaluateJobV1),
            Self::HarmonyHint { .. } => (BackendId::HarmonyPirV2, WorkloadId::HarmonyHintBundleV1),
            Self::HarmonyQuery { .. } => (BackendId::HarmonyPirV2, WorkloadId::HarmonyQueryJobV1),
            Self::OnionSession { .. } => (BackendId::OnionPirV1, WorkloadId::OnionEvaluateJobV1),
            Self::TeeOramQuery { .. } => (BackendId::TeeOramV1, WorkloadId::TeeOramQueryV1),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = Vec::with_capacity(20);
        match self {
            Self::DpfQuery { db_id } => {
                out.push(1);
                out.push(*db_id);
            }
            Self::HarmonyHint {
                db_id,
                transport,
                session_token,
                primary_side,
            } => {
                out.push(2);
                out.push(*db_id);
                out.push(*transport as u8);
                match (transport, session_token, primary_side) {
                    (HintTransport::V2Full, None, None) => {}
                    (HintTransport::V2Half, Some(token), Some(side)) => {
                        if token.iter().all(|byte| *byte == 0) {
                            return Err(ServiceProtocolError::InvalidValue {
                                field: "OperationStartV1.HarmonyHint.session_token",
                                reason: "must be non-zero",
                            });
                        }
                        out.extend_from_slice(token);
                        out.push(*side as u8);
                    }
                    (HintTransport::V2Half, _, _) => {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "OperationStartV1.HarmonyHint",
                            reason: "V2 half transport requires a session token and primary side",
                        })
                    }
                    (HintTransport::V2Full, _, _) => {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "OperationStartV1.HarmonyHint",
                            reason: "V2 full transport must not carry a session token or side",
                        })
                    }
                }
            }
            Self::HarmonyQuery { db_id } => {
                out.push(3);
                out.push(*db_id);
            }
            Self::OnionSession { db_id } => {
                out.push(4);
                out.push(*db_id);
            }
            Self::TeeOramQuery { db_id } => {
                out.push(5);
                out.push(*db_id);
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let value = match decoder.u8("OperationStartV1.type")? {
            1 => Self::DpfQuery {
                db_id: decoder.u8("OperationStartV1.DpfQuery.db_id")?,
            },
            2 => {
                let db_id = decoder.u8("OperationStartV1.HarmonyHint.db_id")?;
                let transport =
                    HintTransport::decode(decoder.u8("OperationStartV1.HarmonyHint.transport")?)?;
                let (session_token, primary_side) = match transport {
                    HintTransport::V2Full => (None, None),
                    HintTransport::V2Half => (
                        Some(decoder.fixed("OperationStartV1.HarmonyHint.session_token")?),
                        Some(HarmonyHintSideV1::decode(
                            decoder.u8("OperationStartV1.HarmonyHint.primary_side")?,
                        )?),
                    ),
                };
                let value = Self::HarmonyHint {
                    db_id,
                    transport,
                    session_token,
                    primary_side,
                };
                value.encode()?;
                value
            }
            3 => Self::HarmonyQuery {
                db_id: decoder.u8("OperationStartV1.HarmonyQuery.db_id")?,
            },
            4 => Self::OnionSession {
                db_id: decoder.u8("OperationStartV1.OnionSession.db_id")?,
            },
            5 => Self::TeeOramQuery {
                db_id: decoder.u8("OperationStartV1.TeeOramQuery.db_id")?,
            },
            value => {
                return Err(ServiceProtocolError::UnknownDiscriminant {
                    kind: "OperationStartV1",
                    value,
                })
            }
        };
        decoder.finish()?;
        Ok(value)
    }

    /// Digest of the canonical operation encoding.  This binds a challenge or
    /// attach continuation without copying a payer, invoice, credential, peer
    /// server, or PIR query payload into the continuation message.
    pub fn digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let encoded = self.encode()?;
        let mut hasher = Sha256::new();
        hasher.update(OPERATION_START_DIGEST_DOMAIN);
        hasher.update((encoded.len() as u32).to_le_bytes());
        hasher.update(encoded);
        Ok(hasher.finalize().into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthBeginV1 {
    pub policy_digest: [u8; 32],
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub scheme: AuthScheme,
    pub key_id: Vec<u8>,
    pub operation: OperationStartV1,
    pub proof: Vec<u8>,
}

impl AuthBeginV1 {
    pub fn encode_padded(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.encode_padded_for(AuthPaddingClassV1::Class16KiB)
    }

    pub fn encode_padded_for(
        &self,
        padding_class: AuthPaddingClassV1,
    ) -> Result<Vec<u8>, ServiceProtocolError> {
        let frame_class = padding_class.body_len();
        if self.key_id.len() > MAX_AUTH_KEY_ID_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "AuthBeginV1.key_id",
                len: self.key_id.len(),
                max: MAX_AUTH_KEY_ID_LEN,
            });
        }
        if self.proof.len() > MAX_AUTH_PROOF_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "AuthBeginV1.proof",
                len: self.proof.len(),
                max: MAX_AUTH_PROOF_LEN,
            });
        }
        if self.offer_id == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "AuthBeginV1.offer_id",
                reason: "must be non-zero",
            });
        }
        let operation = self.operation.encode()?;
        if operation.len() > MAX_OPERATION_ENCODING_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "AuthBeginV1.operation",
                len: operation.len(),
                max: MAX_OPERATION_ENCODING_LEN,
            });
        }
        let mut out = Vec::with_capacity(frame_class);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.scope_id);
        out.extend_from_slice(&self.offer_id.to_le_bytes());
        out.push(self.scheme as u8);
        out.push(self.key_id.len() as u8);
        out.extend_from_slice(&self.key_id);
        out.push(operation.len() as u8);
        out.extend_from_slice(&operation);
        put_bytes_u32(&mut out, &self.proof);
        if out.len() > frame_class {
            return Err(ServiceProtocolError::ProofDoesNotFit {
                encoded: out.len(),
                frame_class,
            });
        }
        out.resize(frame_class, 0);
        Ok(out)
    }

    pub fn decode_padded(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        Self::decode_padded_for(bytes, AuthPaddingClassV1::Class16KiB)
    }

    pub fn decode_padded_for(
        bytes: &[u8],
        padding_class: AuthPaddingClassV1,
    ) -> Result<Self, ServiceProtocolError> {
        let frame_class = padding_class.body_len();
        if bytes.len() != frame_class {
            return Err(ServiceProtocolError::FrameClass {
                expected: frame_class,
                got: bytes.len(),
            });
        }
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("AuthBeginV1.version")?;
        expect_v1(version, "AuthBeginV1")?;
        let policy_digest = decoder.fixed("AuthBeginV1.policy_digest")?;
        let scope_id = decoder.fixed("AuthBeginV1.scope_id")?;
        let offer_id = decoder.u32("AuthBeginV1.offer_id")?;
        if offer_id == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "AuthBeginV1.offer_id",
                reason: "must be non-zero",
            });
        }
        let scheme = AuthScheme::decode(decoder.u8("AuthBeginV1.scheme")?)?;
        let key_id = decoder.bytes_u8("AuthBeginV1.key_id", MAX_AUTH_KEY_ID_LEN)?;
        let operation_bytes =
            decoder.bytes_u8("AuthBeginV1.operation", MAX_OPERATION_ENCODING_LEN)?;
        let operation = OperationStartV1::decode(&operation_bytes)?;
        let proof = decoder.bytes_u32("AuthBeginV1.proof", MAX_AUTH_PROOF_LEN)?;
        let padding = decoder.take_remaining();
        if padding.iter().any(|byte| *byte != 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "AuthBeginV1.padding",
                reason: "padding must be canonical zero bytes",
            });
        }
        Ok(Self {
            policy_digest,
            scope_id,
            offer_id,
            scheme,
            key_id,
            operation,
            proof,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthRejectCode {
    UnsupportedVersion = 1,
    UnsupportedScheme = 2,
    ScopeUnavailable = 3,
    WrongScope = 4,
    InvalidOrSpent = 5,
    ServerBusy = 6,
    SecureChannelRequired = 7,
    PolicyChanged = 8,
    InternalAfterSpend = 9,
}

impl AuthRejectCode {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::UnsupportedVersion),
            2 => Ok(Self::UnsupportedScheme),
            3 => Ok(Self::ScopeUnavailable),
            4 => Ok(Self::WrongScope),
            5 => Ok(Self::InvalidOrSpent),
            6 => Ok(Self::ServerBusy),
            7 => Ok(Self::SecureChannelRequired),
            8 => Ok(Self::PolicyChanged),
            9 => Ok(Self::InternalAfterSpend),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "AuthRejectCode",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthGrantedV1 {
    pub scope_id: ScopeId,
    pub enforced_profile: u16,
    pub expires_in_ms: u32,
    pub harmony_attach: Option<HarmonyAttachGrantV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRejectedV1 {
    pub code: AuthRejectCode,
    pub retry_after_ms: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthResultV1 {
    Granted(AuthGrantedV1),
    Rejected(AuthRejectedV1),
}

impl AuthResultV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = Vec::with_capacity(40);
        out.push(SERVICE_PROTOCOL_VERSION);
        match self {
            Self::Granted(granted) => {
                if granted.expires_in_ms == 0 {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "AuthGrantedV1.expires_in_ms",
                        reason: "must be non-zero",
                    });
                }
                out.push(1);
                out.extend_from_slice(&granted.scope_id);
                out.extend_from_slice(&granted.enforced_profile.to_le_bytes());
                out.extend_from_slice(&granted.expires_in_ms.to_le_bytes());
                match &granted.harmony_attach {
                    Some(attach) => {
                        if attach.expires_in_ms > granted.expires_in_ms {
                            return Err(ServiceProtocolError::InvalidValue {
                                field: "AuthGrantedV1.harmony_attach.expires_in_ms",
                                reason: "must not outlive the authorization grant",
                            });
                        }
                        out.push(1);
                        attach.encode_into(&mut out)?;
                    }
                    None => out.push(0),
                }
            }
            Self::Rejected(rejected) => {
                out.push(2);
                out.push(rejected.code as u8);
                out.extend_from_slice(&rejected.retry_after_ms.to_le_bytes());
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("AuthResultV1.version")?;
        expect_v1(version, "AuthResultV1")?;
        let result = match decoder.u8("AuthResultV1.outcome")? {
            1 => {
                let scope_id = decoder.fixed("AuthGrantedV1.scope_id")?;
                let enforced_profile = decoder.u16("AuthGrantedV1.enforced_profile")?;
                let expires_in_ms = decoder.u32("AuthGrantedV1.expires_in_ms")?;
                if expires_in_ms == 0 {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "AuthGrantedV1.expires_in_ms",
                        reason: "must be non-zero",
                    });
                }
                let harmony_attach = match decoder.u8("AuthGrantedV1.has_harmony_attach")? {
                    0 => None,
                    1 => Some(HarmonyAttachGrantV1::decode_from(&mut decoder)?),
                    value => {
                        return Err(ServiceProtocolError::UnknownDiscriminant {
                            kind: "AuthGrantedV1.has_harmony_attach",
                            value,
                        })
                    }
                };
                if harmony_attach
                    .as_ref()
                    .is_some_and(|attach| attach.expires_in_ms > expires_in_ms)
                {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "AuthGrantedV1.harmony_attach.expires_in_ms",
                        reason: "must not outlive the authorization grant",
                    });
                }
                Self::Granted(AuthGrantedV1 {
                    scope_id,
                    enforced_profile,
                    expires_in_ms,
                    harmony_attach,
                })
            }
            2 => Self::Rejected(AuthRejectedV1 {
                code: AuthRejectCode::decode(decoder.u8("AuthRejectedV1.code")?)?,
                retry_after_ms: decoder.u32("AuthRejectedV1.retry_after_ms")?,
            }),
            value => {
                return Err(ServiceProtocolError::UnknownDiscriminant {
                    kind: "AuthResultV1.outcome",
                    value,
                })
            }
        };
        decoder.finish()?;
        Ok(result)
    }
}

/// Selects the current acquisition policy or one exact retained policy.
///
/// The current-policy form deliberately remains the original one-byte V1
/// encoding.  A retained-policy request adds one non-zero selector byte and
/// one exact policy digest; there is no ambiguous "latest retained" form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServicePolicyRequestV1 {
    Current,
    Retained { policy_digest: [u8; 32] },
}

impl ServicePolicyRequestV1 {
    const RETAINED_EXACT_DIGEST_SELECTOR: u8 = 1;

    pub fn encode(self) -> Vec<u8> {
        match self {
            Self::Current => vec![SERVICE_PROTOCOL_VERSION],
            Self::Retained { policy_digest } => {
                let mut out = Vec::with_capacity(34);
                out.push(SERVICE_PROTOCOL_VERSION);
                out.push(Self::RETAINED_EXACT_DIGEST_SELECTOR);
                out.extend_from_slice(&policy_digest);
                out
            }
        }
    }

    pub fn retained(policy_digest: [u8; 32]) -> Result<Self, ServiceProtocolError> {
        if policy_digest.iter().all(|byte| *byte == 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyRequestV1.policy_digest",
                reason: "must be non-zero",
            });
        }
        Ok(Self::Retained { policy_digest })
    }

    pub const fn exact_policy_digest(self) -> Option<[u8; 32]> {
        match self {
            Self::Current => None,
            Self::Retained { policy_digest } => Some(policy_digest),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("ServicePolicyRequestV1.version")?;
        expect_v1(version, "ServicePolicyRequestV1")?;
        if bytes.len() == 1 {
            return Ok(Self::Current);
        }
        let selector = decoder.u8("ServicePolicyRequestV1.selector")?;
        if selector != Self::RETAINED_EXACT_DIGEST_SELECTOR {
            return Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "ServicePolicyRequestV1.selector",
                value: selector,
            });
        }
        let policy_digest = decoder.fixed("ServicePolicyRequestV1.policy_digest")?;
        decoder.finish()?;
        Self::retained(policy_digest)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServicePolicyResponseV1 {
    pub policy: ServicePolicyV1,
}

impl ServicePolicyResponseV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let policy = self.policy.encode()?;
        if policy.len() > MAX_POLICY_WIRE_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ServicePolicyResponseV1.policy",
                len: policy.len(),
                max: MAX_POLICY_WIRE_LEN,
            });
        }
        let mut out = Vec::with_capacity(5 + policy.len());
        out.push(SERVICE_PROTOCOL_VERSION);
        put_bytes_u32(&mut out, &policy);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("ServicePolicyResponseV1.version")?;
        expect_v1(version, "ServicePolicyResponseV1")?;
        let policy_bytes =
            decoder.bytes_u32("ServicePolicyResponseV1.policy", MAX_POLICY_WIRE_LEN)?;
        decoder.finish()?;
        Ok(Self {
            policy: ServicePolicyV1::decode(&policy_bytes)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(operation: OperationStartV1) -> AuthBeginV1 {
        AuthBeginV1 {
            policy_digest: [1; 32],
            scope_id: [2; 32],
            offer_id: 7,
            scheme: AuthScheme::BitcoinPirCashuBatV1,
            key_id: b"key".to_vec(),
            operation,
            proof: vec![3; 333],
        }
    }

    #[test]
    fn auth_roundtrips_in_exact_frame_class() {
        let original = auth(OperationStartV1::HarmonyHint {
            db_id: 4,
            transport: HintTransport::V2Half,
            session_token: Some([9; 16]),
            primary_side: Some(HarmonyHintSideV1::Index),
        });
        let encoded = original.encode_padded().unwrap();
        assert_eq!(encoded.len(), AUTH_FRAME_CLASS_V1);
        assert_eq!(AuthBeginV1::decode_padded(&encoded).unwrap(), original);
    }

    #[test]
    fn auth_rejects_wrong_class_nonzero_padding_and_oversize_proof() {
        let original = auth(OperationStartV1::DpfQuery { db_id: 0 });
        let mut encoded = original.encode_padded().unwrap();
        assert!(matches!(
            AuthBeginV1::decode_padded(&encoded[..encoded.len() - 1]),
            Err(ServiceProtocolError::FrameClass { .. })
        ));
        *encoded.last_mut().unwrap() = 1;
        assert!(matches!(
            AuthBeginV1::decode_padded(&encoded),
            Err(ServiceProtocolError::InvalidValue {
                field: "AuthBeginV1.padding",
                ..
            })
        ));

        let mut original = original;
        original.proof = vec![0; MAX_AUTH_PROOF_LEN + 1];
        assert!(matches!(
            original.encode_padded(),
            Err(ServiceProtocolError::FieldTooLong {
                field: "AuthBeginV1.proof",
                ..
            })
        ));
    }

    #[test]
    fn harmony_half_requires_token_and_full_forbids_one() {
        let missing = auth(OperationStartV1::HarmonyHint {
            db_id: 1,
            transport: HintTransport::V2Half,
            session_token: None,
            primary_side: Some(HarmonyHintSideV1::Index),
        });
        assert!(missing.encode_padded().is_err());
        let extra = auth(OperationStartV1::HarmonyHint {
            db_id: 1,
            transport: HintTransport::V2Full,
            session_token: Some([1; 16]),
            primary_side: None,
        });
        assert!(extra.encode_padded().is_err());
        let missing_side = auth(OperationStartV1::HarmonyHint {
            db_id: 1,
            transport: HintTransport::V2Half,
            session_token: Some([1; 16]),
            primary_side: None,
        });
        assert!(missing_side.encode_padded().is_err());
        let zero_token = auth(OperationStartV1::HarmonyHint {
            db_id: 1,
            transport: HintTransport::V2Half,
            session_token: Some([0; 16]),
            primary_side: Some(HarmonyHintSideV1::Chunk),
        });
        assert!(zero_token.encode_padded().is_err());
    }

    #[test]
    fn operation_service_mapping_has_no_peer_or_slot() {
        assert_eq!(
            OperationStartV1::DpfQuery { db_id: 1 }.required_service(),
            (BackendId::DpfPirV1, WorkloadId::DpfEvaluateJobV1)
        );
        assert_eq!(
            OperationStartV1::HarmonyQuery { db_id: 1 }.required_service(),
            (BackendId::HarmonyPirV2, WorkloadId::HarmonyQueryJobV1)
        );
    }

    #[test]
    fn auth_results_roundtrip_and_reject_trailing() {
        for result in [
            AuthResultV1::Granted(AuthGrantedV1 {
                scope_id: [4; 32],
                enforced_profile: 8,
                expires_in_ms: 10_000,
                harmony_attach: None,
            }),
            AuthResultV1::Granted(AuthGrantedV1 {
                scope_id: [4; 32],
                enforced_profile: 8,
                expires_in_ms: 10_000,
                harmony_attach: Some(HarmonyAttachGrantV1 {
                    operation_id: [5; 32],
                    attach_secret: [6; 32],
                    primary_side: HarmonyHintSideV1::Index,
                    attach_side: HarmonyHintSideV1::Chunk,
                    expires_in_ms: 9_000,
                }),
            }),
            AuthResultV1::Rejected(AuthRejectedV1 {
                code: AuthRejectCode::InvalidOrSpent,
                retry_after_ms: 0,
            }),
        ] {
            let encoded = result.encode().unwrap();
            assert_eq!(AuthResultV1::decode(&encoded).unwrap(), result);
            let mut trailing = encoded;
            trailing.push(0);
            assert_eq!(
                AuthResultV1::decode(&trailing),
                Err(ServiceProtocolError::TrailingBytes(1))
            );
        }
    }

    #[test]
    fn service_policy_request_is_strict() {
        assert_eq!(ServicePolicyRequestV1::Current.encode(), [1]);
        assert_eq!(
            ServicePolicyRequestV1::decode(&[1]).unwrap(),
            ServicePolicyRequestV1::Current
        );
        let retained = ServicePolicyRequestV1::retained([7; 32]).unwrap();
        let retained_bytes = retained.encode();
        assert_eq!(retained_bytes.len(), 34);
        assert_eq!(retained_bytes[0..2], [1, 1]);
        assert_eq!(
            ServicePolicyRequestV1::decode(&retained_bytes).unwrap(),
            retained
        );
        assert!(matches!(
            ServicePolicyRequestV1::decode(&[2]),
            Err(ServiceProtocolError::UnknownVersion { .. })
        ));
        assert!(matches!(
            ServicePolicyRequestV1::decode(&[1, 0]),
            Err(ServiceProtocolError::UnknownDiscriminant { .. })
        ));
        assert!(ServicePolicyRequestV1::decode(&[1, 1]).is_err());
        assert!(ServicePolicyRequestV1::decode(&[1, 1, 0]).is_err());
        assert!(ServicePolicyRequestV1::decode(&[1, 1, 0, 0, 0]).is_err());
        let mut zero_digest = vec![1, 1];
        zero_digest.extend_from_slice(&[0; 32]);
        assert!(ServicePolicyRequestV1::decode(&zero_digest).is_err());
        let mut trailing = retained_bytes;
        trailing.push(0);
        assert_eq!(
            ServicePolicyRequestV1::decode(&trailing),
            Err(ServiceProtocolError::TrailingBytes(1))
        );
    }
}
