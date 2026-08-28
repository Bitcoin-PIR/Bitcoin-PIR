//! PIR operation-start messages shared by every kept service flow.
//!
//! Extracted from the legacy authorization module: these are the method-neutral
//! operation descriptors (and their frame-class/padding constants) that the
//! Harmony attach path and the query clients use independent of any deleted
//! payment-policy machinery.

use sha2::{Digest, Sha256};

use crate::codec::Decoder;
use crate::{BackendId, ServiceProtocolError, WorkloadId};

/// Which HarmonyPIR hint level (INDEX or CHUNK) an operation-start message
/// refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HarmonyHintSideV1 {
    Index = 0,
    Chunk = 1,
}

impl HarmonyHintSideV1 {
    pub const fn complement(self) -> Self {
        match self {
            Self::Index => Self::Chunk,
            Self::Chunk => Self::Index,
        }
    }

    pub(crate) fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            0 => Ok(Self::Index),
            1 => Ok(Self::Chunk),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "HarmonyHintSideV1",
                value,
            }),
        }
    }
}

/// Exact V1 authorization body length, excluding the one-byte PIR opcode and
/// outer four-byte record length.
pub const AUTH_FRAME_CLASS_V1: usize = 16 * 1024;
pub const MAX_AUTH_PROOF_LEN: usize = 12 * 1024;
pub const OPERATION_START_DIGEST_DOMAIN: &[u8] = b"BitcoinPIR/operation-start/v1";

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
