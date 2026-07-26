//! HarmonyPIR V2 half-stream attachment messages and pure transition logic.
//!
//! The paid authorization is consumed only by the primary half.  A successful
//! authorization grants a short-lived, channel-confined attach secret for the
//! complementary half.  The second connection presents [`HarmonyAttachV1`]
//! under the already authenticated secure channel; it never presents (or
//! spends) the payment capability a second time.

use core::fmt;

use crate::codec::{expect_v1, Decoder};
use crate::{
    ProviderId, ScopeId, ServiceProtocolError, AUTH_FRAME_CLASS_V1, SERVICE_PROTOCOL_VERSION,
};

/// V1 uses the same fixed-size body class as authorization messages so the
/// attach exchange does not create a distinct plaintext length class.
pub const HARMONY_ATTACH_FRAME_CLASS_V1: usize = AUTH_FRAME_CLASS_V1;

/// An attach grant is deliberately short lived.  The protocol cap prevents a
/// provider from accidentally advertising what is effectively a reusable
/// session credential.
pub const MAX_HARMONY_ATTACH_TTL_MS_V1: u32 = 120_000;

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

/// Secret-bearing continuation data returned inside `AuthGrantedV1` for a V2
/// half-stream primary operation.
///
/// `attach_secret` is an opaque, uniformly random bearer secret and MUST NOT be
/// logged.  Its custom `Debug` implementation intentionally redacts the value.
#[derive(Clone, PartialEq, Eq)]
pub struct HarmonyAttachGrantV1 {
    pub operation_id: [u8; 32],
    pub attach_secret: [u8; 32],
    pub primary_side: HarmonyHintSideV1,
    pub attach_side: HarmonyHintSideV1,
    pub expires_in_ms: u32,
}

impl fmt::Debug for HarmonyAttachGrantV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HarmonyAttachGrantV1")
            .field("operation_id", &self.operation_id)
            .field("attach_secret", &"[REDACTED]")
            .field("primary_side", &self.primary_side)
            .field("attach_side", &self.attach_side)
            .field("expires_in_ms", &self.expires_in_ms)
            .finish()
    }
}

impl HarmonyAttachGrantV1 {
    pub fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.operation_id.iter().all(|byte| *byte == 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "HarmonyAttachGrantV1.operation_id",
                reason: "must be non-zero",
            });
        }
        if self.attach_secret.iter().all(|byte| *byte == 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "HarmonyAttachGrantV1.attach_secret",
                reason: "must be non-zero",
            });
        }
        if self.attach_side != self.primary_side.complement() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "HarmonyAttachGrantV1.attach_side",
                reason: "must be the complement of primary_side",
            });
        }
        if self.expires_in_ms == 0 || self.expires_in_ms > MAX_HARMONY_ATTACH_TTL_MS_V1 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "HarmonyAttachGrantV1.expires_in_ms",
                reason: "must be within the V1 attach TTL cap",
            });
        }
        Ok(())
    }

    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        out.extend_from_slice(&self.operation_id);
        out.extend_from_slice(&self.attach_secret);
        out.push(self.primary_side as u8);
        out.push(self.attach_side as u8);
        out.extend_from_slice(&self.expires_in_ms.to_le_bytes());
        Ok(())
    }

    pub(crate) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ServiceProtocolError> {
        let value = Self {
            operation_id: decoder.fixed("HarmonyAttachGrantV1.operation_id")?,
            attach_secret: decoder.fixed("HarmonyAttachGrantV1.attach_secret")?,
            primary_side: HarmonyHintSideV1::decode(
                decoder.u8("HarmonyAttachGrantV1.primary_side")?,
            )?,
            attach_side: HarmonyHintSideV1::decode(
                decoder.u8("HarmonyAttachGrantV1.attach_side")?,
            )?,
            expires_in_ms: decoder.u32("HarmonyAttachGrantV1.expires_in_ms")?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Complementary-half request sent on the second verified secure connection.
///
/// The request deliberately repeats every provider-local operation binding.
/// There is no peer-provider identity, PIR pair identifier, payment identifier,
/// invoice, or credential in this structure.
#[derive(Clone, PartialEq, Eq)]
pub struct HarmonyAttachV1 {
    pub provider_id: ProviderId,
    pub policy_digest: [u8; 32],
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub operation_id: [u8; 32],
    pub operation_digest: [u8; 32],
    pub attach_secret: [u8; 32],
    pub db_id: u8,
    pub session_token: [u8; 16],
    pub primary_side: HarmonyHintSideV1,
    pub attach_side: HarmonyHintSideV1,
    pub operation_profile: u16,
}

impl fmt::Debug for HarmonyAttachV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HarmonyAttachV1")
            .field("provider_id", &self.provider_id)
            .field("policy_digest", &self.policy_digest)
            .field("scope_id", &self.scope_id)
            .field("offer_id", &self.offer_id)
            .field("operation_id", &self.operation_id)
            .field("operation_digest", &self.operation_digest)
            .field("attach_secret", &"[REDACTED]")
            .field("db_id", &self.db_id)
            .field("session_token", &self.session_token)
            .field("primary_side", &self.primary_side)
            .field("attach_side", &self.attach_side)
            .field("operation_profile", &self.operation_profile)
            .finish()
    }
}

impl HarmonyAttachV1 {
    pub fn validate(&self) -> Result<(), ServiceProtocolError> {
        for (field, value) in [
            ("HarmonyAttachV1.provider_id", &self.provider_id),
            ("HarmonyAttachV1.policy_digest", &self.policy_digest),
            ("HarmonyAttachV1.scope_id", &self.scope_id),
            ("HarmonyAttachV1.operation_id", &self.operation_id),
            ("HarmonyAttachV1.operation_digest", &self.operation_digest),
            ("HarmonyAttachV1.attach_secret", &self.attach_secret),
        ] {
            if value.iter().all(|byte| *byte == 0) {
                return Err(ServiceProtocolError::InvalidValue {
                    field,
                    reason: "must be non-zero",
                });
            }
        }
        if self.offer_id == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "HarmonyAttachV1.offer_id",
                reason: "must be non-zero",
            });
        }
        if self.session_token.iter().all(|byte| *byte == 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "HarmonyAttachV1.session_token",
                reason: "must be non-zero",
            });
        }
        if self.attach_side != self.primary_side.complement() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "HarmonyAttachV1.attach_side",
                reason: "must be the complement of primary_side",
            });
        }
        if self.operation_profile == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "HarmonyAttachV1.operation_profile",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    pub fn encode_padded(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(HARMONY_ATTACH_FRAME_CLASS_V1);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.scope_id);
        out.extend_from_slice(&self.offer_id.to_le_bytes());
        out.extend_from_slice(&self.operation_id);
        out.extend_from_slice(&self.operation_digest);
        out.extend_from_slice(&self.attach_secret);
        out.push(self.db_id);
        out.extend_from_slice(&self.session_token);
        out.push(self.primary_side as u8);
        out.push(self.attach_side as u8);
        out.extend_from_slice(&self.operation_profile.to_le_bytes());
        out.resize(HARMONY_ATTACH_FRAME_CLASS_V1, 0);
        Ok(out)
    }

    pub fn decode_padded(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() != HARMONY_ATTACH_FRAME_CLASS_V1 {
            return Err(ServiceProtocolError::FrameClass {
                expected: HARMONY_ATTACH_FRAME_CLASS_V1,
                got: bytes.len(),
            });
        }
        let mut decoder = Decoder::new(bytes);
        expect_v1(decoder.u8("HarmonyAttachV1.version")?, "HarmonyAttachV1")?;
        let value = Self {
            provider_id: decoder.fixed("HarmonyAttachV1.provider_id")?,
            policy_digest: decoder.fixed("HarmonyAttachV1.policy_digest")?,
            scope_id: decoder.fixed("HarmonyAttachV1.scope_id")?,
            offer_id: decoder.u32("HarmonyAttachV1.offer_id")?,
            operation_id: decoder.fixed("HarmonyAttachV1.operation_id")?,
            operation_digest: decoder.fixed("HarmonyAttachV1.operation_digest")?,
            attach_secret: decoder.fixed("HarmonyAttachV1.attach_secret")?,
            db_id: decoder.u8("HarmonyAttachV1.db_id")?,
            session_token: decoder.fixed("HarmonyAttachV1.session_token")?,
            primary_side: HarmonyHintSideV1::decode(decoder.u8("HarmonyAttachV1.primary_side")?)?,
            attach_side: HarmonyHintSideV1::decode(decoder.u8("HarmonyAttachV1.attach_side")?)?,
            operation_profile: decoder.u16("HarmonyAttachV1.operation_profile")?,
        };
        value.validate()?;
        let padding = decoder.take_remaining();
        if padding.iter().any(|byte| *byte != 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "HarmonyAttachV1.padding",
                reason: "padding must be canonical zero bytes",
            });
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HarmonyAttachRejectCodeV1 {
    NoWaitingOperation = 1,
    Expired = 2,
    WrongBinding = 3,
    WrongSide = 4,
    AlreadyAttached = 5,
    SecureChannelRequired = 6,
}

impl HarmonyAttachRejectCodeV1 {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::NoWaitingOperation),
            2 => Ok(Self::Expired),
            3 => Ok(Self::WrongBinding),
            4 => Ok(Self::WrongSide),
            5 => Ok(Self::AlreadyAttached),
            6 => Ok(Self::SecureChannelRequired),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "HarmonyAttachRejectCodeV1",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HarmonyAttachResultV1 {
    Attached { operation_id: [u8; 32] },
    Rejected { code: HarmonyAttachRejectCodeV1 },
}

impl HarmonyAttachResultV1 {
    pub fn encode_padded(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = Vec::with_capacity(HARMONY_ATTACH_FRAME_CLASS_V1);
        out.push(SERVICE_PROTOCOL_VERSION);
        match self {
            Self::Attached { operation_id } => {
                if operation_id.iter().all(|byte| *byte == 0) {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "HarmonyAttachResultV1.operation_id",
                        reason: "must be non-zero",
                    });
                }
                out.push(1);
                out.extend_from_slice(operation_id);
            }
            Self::Rejected { code } => {
                out.push(2);
                out.push(*code as u8);
            }
        }
        out.resize(HARMONY_ATTACH_FRAME_CLASS_V1, 0);
        Ok(out)
    }

    pub fn decode_padded(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() != HARMONY_ATTACH_FRAME_CLASS_V1 {
            return Err(ServiceProtocolError::FrameClass {
                expected: HARMONY_ATTACH_FRAME_CLASS_V1,
                got: bytes.len(),
            });
        }
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("HarmonyAttachResultV1.version")?,
            "HarmonyAttachResultV1",
        )?;
        let value = match decoder.u8("HarmonyAttachResultV1.outcome")? {
            1 => {
                let operation_id = decoder.fixed("HarmonyAttachResultV1.operation_id")?;
                if operation_id.iter().all(|byte| *byte == 0) {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "HarmonyAttachResultV1.operation_id",
                        reason: "must be non-zero",
                    });
                }
                Self::Attached { operation_id }
            }
            2 => Self::Rejected {
                code: HarmonyAttachRejectCodeV1::decode(decoder.u8("HarmonyAttachResultV1.code")?)?,
            },
            value => {
                return Err(ServiceProtocolError::UnknownDiscriminant {
                    kind: "HarmonyAttachResultV1.outcome",
                    value,
                })
            }
        };
        let padding = decoder.take_remaining();
        if padding.iter().any(|byte| *byte != 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "HarmonyAttachResultV1.padding",
                reason: "padding must be canonical zero bytes",
            });
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarmonyAttachTransitionErrorV1 {
    NoWaitingOperation,
    Expired,
    WrongBinding,
    WrongSide,
    AlreadyAttached,
}

/// A single primary operation's `WAITING_COMPLEMENT -> ATTACHED` transition.
///
/// Callers must serialize mutable access to a slot (for example under the
/// connection registry lock or in one database transaction).  This helper does
/// not change state on any error, and changes it exactly once after every field
/// and the secret have matched.
pub struct HarmonyAttachSlotV1 {
    expected: HarmonyAttachV1,
    expires_at_unix_ms: u64,
    attached: bool,
}

impl HarmonyAttachSlotV1 {
    pub fn new(
        expected: HarmonyAttachV1,
        grant: &HarmonyAttachGrantV1,
        now_unix_ms: u64,
    ) -> Result<Self, ServiceProtocolError> {
        expected.validate()?;
        grant.validate()?;
        if expected.operation_id != grant.operation_id
            || !constant_time_eq_32(&expected.attach_secret, &grant.attach_secret)
            || expected.primary_side != grant.primary_side
            || expected.attach_side != grant.attach_side
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "HarmonyAttachSlotV1.binding",
                reason: "expected attach request does not match the grant",
            });
        }
        // Saturation is deliberately fail closed at the representable clock
        // boundary: `try_attach` rejects at (rather than after) the deadline.
        // This also lets a runtime prevalidate every binding before an
        // irreversible credential spend and then start the TTL afterwards
        // without introducing a new fallible transition.
        let expires_at_unix_ms = now_unix_ms.saturating_add(u64::from(grant.expires_in_ms));
        Ok(Self {
            expected,
            expires_at_unix_ms,
            attached: false,
        })
    }

    pub fn try_attach(
        &mut self,
        request: &HarmonyAttachV1,
        now_unix_ms: u64,
    ) -> Result<(), HarmonyAttachTransitionErrorV1> {
        if self.attached {
            return Err(HarmonyAttachTransitionErrorV1::AlreadyAttached);
        }
        if now_unix_ms >= self.expires_at_unix_ms {
            return Err(HarmonyAttachTransitionErrorV1::Expired);
        }
        if request.attach_side != request.primary_side.complement()
            || request.primary_side != self.expected.primary_side
            || request.attach_side != self.expected.attach_side
        {
            return Err(HarmonyAttachTransitionErrorV1::WrongSide);
        }
        let secret_matches =
            constant_time_eq_32(&request.attach_secret, &self.expected.attach_secret);
        let binding_matches = request.provider_id == self.expected.provider_id
            && request.policy_digest == self.expected.policy_digest
            && request.scope_id == self.expected.scope_id
            && request.offer_id == self.expected.offer_id
            && request.operation_id == self.expected.operation_id
            && request.operation_digest == self.expected.operation_digest
            && request.db_id == self.expected.db_id
            && request.session_token == self.expected.session_token
            && request.operation_profile == self.expected.operation_profile;
        if !(secret_matches & binding_matches) {
            return Err(HarmonyAttachTransitionErrorV1::WrongBinding);
        }
        self.attached = true;
        Ok(())
    }

    pub fn is_attached(&self) -> bool {
        self.attached
    }
}

/// Reject attach-before-primary without manufacturing a slot on demand.
pub fn try_attach_waiting_slot(
    slot: Option<&mut HarmonyAttachSlotV1>,
    request: &HarmonyAttachV1,
    now_unix_ms: u64,
) -> Result<(), HarmonyAttachTransitionErrorV1> {
    slot.ok_or(HarmonyAttachTransitionErrorV1::NoWaitingOperation)?
        .try_attach(request, now_unix_ms)
}

fn constant_time_eq_32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> HarmonyAttachGrantV1 {
        HarmonyAttachGrantV1 {
            operation_id: [5; 32],
            attach_secret: [6; 32],
            primary_side: HarmonyHintSideV1::Index,
            attach_side: HarmonyHintSideV1::Chunk,
            expires_in_ms: 30_000,
        }
    }

    fn attach() -> HarmonyAttachV1 {
        HarmonyAttachV1 {
            provider_id: [1; 32],
            policy_digest: [2; 32],
            scope_id: [3; 32],
            offer_id: 4,
            operation_id: [5; 32],
            operation_digest: [7; 32],
            attach_secret: [6; 32],
            db_id: 8,
            session_token: [9; 16],
            primary_side: HarmonyHintSideV1::Index,
            attach_side: HarmonyHintSideV1::Chunk,
            operation_profile: 10,
        }
    }

    #[test]
    fn attach_request_and_both_results_use_exact_padded_class() {
        let request = attach();
        let encoded = request.encode_padded().unwrap();
        assert_eq!(encoded.len(), HARMONY_ATTACH_FRAME_CLASS_V1);
        assert_eq!(HarmonyAttachV1::decode_padded(&encoded).unwrap(), request);

        for result in [
            HarmonyAttachResultV1::Attached {
                operation_id: [5; 32],
            },
            HarmonyAttachResultV1::Rejected {
                code: HarmonyAttachRejectCodeV1::WrongBinding,
            },
        ] {
            let encoded = result.encode_padded().unwrap();
            assert_eq!(encoded.len(), HARMONY_ATTACH_FRAME_CLASS_V1);
            assert_eq!(
                HarmonyAttachResultV1::decode_padded(&encoded).unwrap(),
                result
            );
        }
    }

    #[test]
    fn attach_codec_rejects_wrong_class_nonzero_padding_and_zero_token() {
        let request = attach();
        let mut encoded = request.encode_padded().unwrap();
        assert!(matches!(
            HarmonyAttachV1::decode_padded(&encoded[..encoded.len() - 1]),
            Err(ServiceProtocolError::FrameClass { .. })
        ));
        *encoded.last_mut().unwrap() = 1;
        assert!(matches!(
            HarmonyAttachV1::decode_padded(&encoded),
            Err(ServiceProtocolError::InvalidValue {
                field: "HarmonyAttachV1.padding",
                ..
            })
        ));

        let mut zero_token = request;
        zero_token.session_token = [0; 16];
        assert!(zero_token.encode_padded().is_err());
    }

    #[test]
    fn slot_attaches_exactly_once_and_failures_do_not_consume_it() {
        let expected = attach();
        let mut slot = HarmonyAttachSlotV1::new(expected.clone(), &grant(), 1_000).unwrap();

        let mut wrong = expected.clone();
        wrong.db_id ^= 1;
        assert_eq!(
            slot.try_attach(&wrong, 2_000),
            Err(HarmonyAttachTransitionErrorV1::WrongBinding)
        );
        assert!(!slot.is_attached());

        assert_eq!(slot.try_attach(&expected, 2_000), Ok(()));
        assert!(slot.is_attached());
        assert_eq!(
            slot.try_attach(&expected, 2_001),
            Err(HarmonyAttachTransitionErrorV1::AlreadyAttached)
        );
    }

    #[test]
    fn slot_rejects_missing_expired_wrong_secret_and_same_side() {
        let expected = attach();
        assert_eq!(
            try_attach_waiting_slot(None, &expected, 1_000),
            Err(HarmonyAttachTransitionErrorV1::NoWaitingOperation)
        );

        let mut expired = HarmonyAttachSlotV1::new(expected.clone(), &grant(), 1_000).unwrap();
        assert_eq!(
            expired.try_attach(&expected, 31_001),
            Err(HarmonyAttachTransitionErrorV1::Expired)
        );

        let mut slot = HarmonyAttachSlotV1::new(expected.clone(), &grant(), 1_000).unwrap();
        let mut wrong_secret = expected.clone();
        wrong_secret.attach_secret[0] ^= 1;
        assert_eq!(
            slot.try_attach(&wrong_secret, 2_000),
            Err(HarmonyAttachTransitionErrorV1::WrongBinding)
        );

        let mut same_side = expected;
        same_side.attach_side = same_side.primary_side;
        assert_eq!(
            slot.try_attach(&same_side, 2_000),
            Err(HarmonyAttachTransitionErrorV1::WrongSide)
        );
    }

    #[test]
    fn grant_rejects_invalid_sides_secret_and_ttl() {
        let mut value = grant();
        value.attach_side = value.primary_side;
        assert!(value.validate().is_err());
        value = grant();
        value.attach_secret = [0; 32];
        assert!(value.validate().is_err());
        value = grant();
        value.expires_in_ms = MAX_HARMONY_ATTACH_TTL_MS_V1 + 1;
        assert!(value.validate().is_err());
    }
}
