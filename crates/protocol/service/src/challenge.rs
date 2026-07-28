//! Secure-channel-bound free proof-of-work challenge messages.

use sha2::{Digest, Sha256};

use crate::codec::{expect_v1, Decoder};
use crate::{
    FreePowProofV1, OperationStartV1, ProviderId, ScopeId, ServiceProtocolError,
    AUTH_FRAME_CLASS_V1, SERVICE_PROTOCOL_VERSION,
};

/// V1 challenge requests and responses use the authorization padding class.
pub const POW_CHALLENGE_FRAME_CLASS_V1: usize = AUTH_FRAME_CLASS_V1;
/// Browser-oriented V1 deployments must not demand more than 32 leading bits.
pub const MAX_POW_DIFFICULTY_BITS_V1: u8 = 32;
/// Challenges may live for at most five minutes.
pub const MAX_POW_CHALLENGE_TTL_SECONDS_V1: u64 = 300;
pub const POW_SOLUTION_DOMAIN_V1: &[u8] = b"BitcoinPIR/free-pow-solution/v1";

/// Request for a server-fresh challenge.  This message is valid only after the
/// strict secure-channel upgrade has completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowChallengeRequestV1 {
    pub policy_digest: [u8; 32],
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub operation: OperationStartV1,
}

impl PowChallengeRequestV1 {
    pub fn operation_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        self.operation.digest()
    }

    pub fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.policy_digest.iter().all(|byte| *byte == 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PowChallengeRequestV1.policy_digest",
                reason: "must be non-zero",
            });
        }
        if self.scope_id.iter().all(|byte| *byte == 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PowChallengeRequestV1.scope_id",
                reason: "must be non-zero",
            });
        }
        if self.offer_id == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PowChallengeRequestV1.offer_id",
                reason: "must be non-zero",
            });
        }
        self.operation.encode()?;
        Ok(())
    }

    pub fn encode_padded(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let operation = self.operation.encode()?;
        let operation_len =
            u8::try_from(operation.len()).map_err(|_| ServiceProtocolError::FieldTooLong {
                field: "PowChallengeRequestV1.operation",
                len: operation.len(),
                max: u8::MAX as usize,
            })?;
        let mut out = Vec::with_capacity(POW_CHALLENGE_FRAME_CLASS_V1);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.scope_id);
        out.extend_from_slice(&self.offer_id.to_le_bytes());
        out.push(operation_len);
        out.extend_from_slice(&operation);
        out.resize(POW_CHALLENGE_FRAME_CLASS_V1, 0);
        Ok(out)
    }

    pub fn decode_padded(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() != POW_CHALLENGE_FRAME_CLASS_V1 {
            return Err(ServiceProtocolError::FrameClass {
                expected: POW_CHALLENGE_FRAME_CLASS_V1,
                got: bytes.len(),
            });
        }
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("PowChallengeRequestV1.version")?,
            "PowChallengeRequestV1",
        )?;
        let policy_digest = decoder.fixed("PowChallengeRequestV1.policy_digest")?;
        let scope_id = decoder.fixed("PowChallengeRequestV1.scope_id")?;
        let offer_id = decoder.u32("PowChallengeRequestV1.offer_id")?;
        let operation = OperationStartV1::decode(
            &decoder.bytes_u8("PowChallengeRequestV1.operation", u8::MAX as usize)?,
        )?;
        let value = Self {
            policy_digest,
            scope_id,
            offer_id,
            operation,
        };
        value.validate()?;
        let padding = decoder.take_remaining();
        if padding.iter().any(|byte| *byte != 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PowChallengeRequestV1.padding",
                reason: "padding must be canonical zero bytes",
            });
        }
        Ok(value)
    }
}

/// Server-fresh challenge bound to one provider-local operation and one secure
/// channel exporter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowChallengeResponseV1 {
    pub provider_id: ProviderId,
    pub policy_digest: [u8; 32],
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub operation_digest: [u8; 32],
    pub secure_channel_exporter: [u8; 32],
    pub challenge_id: [u8; 32],
    pub difficulty_bits: u8,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

impl PowChallengeResponseV1 {
    pub fn validate(&self) -> Result<(), ServiceProtocolError> {
        for (field, value) in [
            ("PowChallengeResponseV1.provider_id", &self.provider_id),
            ("PowChallengeResponseV1.policy_digest", &self.policy_digest),
            ("PowChallengeResponseV1.scope_id", &self.scope_id),
            (
                "PowChallengeResponseV1.operation_digest",
                &self.operation_digest,
            ),
            (
                "PowChallengeResponseV1.secure_channel_exporter",
                &self.secure_channel_exporter,
            ),
            ("PowChallengeResponseV1.challenge_id", &self.challenge_id),
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
                field: "PowChallengeResponseV1.offer_id",
                reason: "must be non-zero",
            });
        }
        if self.difficulty_bits == 0 || self.difficulty_bits > MAX_POW_DIFFICULTY_BITS_V1 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PowChallengeResponseV1.difficulty_bits",
                reason: "must be within the V1 difficulty cap",
            });
        }
        let ttl = self
            .expires_at_unix
            .checked_sub(self.issued_at_unix)
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "PowChallengeResponseV1.expires_at_unix",
                reason: "must be later than issued_at_unix",
            })?;
        if self.issued_at_unix == 0 || ttl == 0 || ttl > MAX_POW_CHALLENGE_TTL_SECONDS_V1 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PowChallengeResponseV1.validity",
                reason: "must be non-zero and within the V1 TTL cap",
            });
        }
        Ok(())
    }

    pub fn ttl_seconds(&self) -> Result<u64, ServiceProtocolError> {
        self.validate()?;
        Ok(self.expires_at_unix - self.issued_at_unix)
    }

    pub fn verify_for_request(
        &self,
        expected_provider_id: &ProviderId,
        request: &PowChallengeRequestV1,
        expected_secure_channel_exporter: &[u8; 32],
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        request.validate()?;
        if &self.provider_id != expected_provider_id
            || self.policy_digest != request.policy_digest
            || self.scope_id != request.scope_id
            || self.offer_id != request.offer_id
            || self.operation_digest != request.operation_digest()?
            || !constant_time_eq_32(
                &self.secure_channel_exporter,
                expected_secure_channel_exporter,
            )
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PowChallengeResponseV1.binding",
                reason: "does not match the requested operation and secure channel",
            });
        }
        Ok(())
    }

    pub fn encode_padded(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_core()?;
        out.resize(POW_CHALLENGE_FRAME_CLASS_V1, 0);
        Ok(out)
    }

    pub fn decode_padded(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() != POW_CHALLENGE_FRAME_CLASS_V1 {
            return Err(ServiceProtocolError::FrameClass {
                expected: POW_CHALLENGE_FRAME_CLASS_V1,
                got: bytes.len(),
            });
        }
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("PowChallengeResponseV1.version")?,
            "PowChallengeResponseV1",
        )?;
        let value = Self {
            provider_id: decoder.fixed("PowChallengeResponseV1.provider_id")?,
            policy_digest: decoder.fixed("PowChallengeResponseV1.policy_digest")?,
            scope_id: decoder.fixed("PowChallengeResponseV1.scope_id")?,
            offer_id: decoder.u32("PowChallengeResponseV1.offer_id")?,
            operation_digest: decoder.fixed("PowChallengeResponseV1.operation_digest")?,
            secure_channel_exporter: decoder
                .fixed("PowChallengeResponseV1.secure_channel_exporter")?,
            challenge_id: decoder.fixed("PowChallengeResponseV1.challenge_id")?,
            difficulty_bits: decoder.u8("PowChallengeResponseV1.difficulty_bits")?,
            issued_at_unix: decoder.u64("PowChallengeResponseV1.issued_at_unix")?,
            expires_at_unix: decoder.u64("PowChallengeResponseV1.expires_at_unix")?,
        };
        value.validate()?;
        let padding = decoder.take_remaining();
        if padding.iter().any(|byte| *byte != 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PowChallengeResponseV1.padding",
                reason: "padding must be canonical zero bytes",
            });
        }
        Ok(value)
    }

    fn encode_core(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(214);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.scope_id);
        out.extend_from_slice(&self.offer_id.to_le_bytes());
        out.extend_from_slice(&self.operation_digest);
        out.extend_from_slice(&self.secure_channel_exporter);
        out.extend_from_slice(&self.challenge_id);
        out.push(self.difficulty_bits);
        out.extend_from_slice(&self.issued_at_unix.to_le_bytes());
        out.extend_from_slice(&self.expires_at_unix.to_le_bytes());
        Ok(out)
    }
}

/// The challenge verifier uses the exact same canonical proof type accepted by
/// `AuthBeginV1`; this alias prevents a second PoW proof wire shape.
pub type PowSolutionV1 = FreePowProofV1;

/// Compute `SHA256(domain || canonical_challenge_without_padding || nonce_u64le)`.
pub fn pow_solution_hash_v1(
    challenge: &PowChallengeResponseV1,
    nonce: u64,
) -> Result<[u8; 32], ServiceProtocolError> {
    let challenge_bytes = challenge.encode_core()?;
    let mut hasher = Sha256::new();
    hasher.update(POW_SOLUTION_DOMAIN_V1);
    hasher.update((challenge_bytes.len() as u32).to_le_bytes());
    hasher.update(challenge_bytes);
    hasher.update(nonce.to_le_bytes());
    Ok(hasher.finalize().into())
}

/// Leading-zero comparison is MSB-first within every digest byte.
pub fn pow_solution_meets_difficulty_v1(
    challenge: &PowChallengeResponseV1,
    solution: &PowSolutionV1,
) -> Result<bool, ServiceProtocolError> {
    challenge.validate()?;
    solution.encode()?;
    if solution.challenge_id != challenge.challenge_id {
        return Ok(false);
    }
    let digest = pow_solution_hash_v1(challenge, solution.nonce)?;
    Ok(has_msb_first_leading_zero_bits(
        &digest,
        challenge.difficulty_bits,
    ))
}

fn has_msb_first_leading_zero_bits(digest: &[u8; 32], difficulty_bits: u8) -> bool {
    let full_zero_bytes = usize::from(difficulty_bits / 8);
    let remaining_bits = difficulty_bits % 8;
    if digest[..full_zero_bytes].iter().any(|byte| *byte != 0) {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    let mask = u8::MAX << (8 - remaining_bits);
    digest[full_zero_bytes] & mask == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowChallengeTransitionErrorV1 {
    InvalidChallenge,
    OutstandingExists,
    NoOutstanding,
    AlreadyConsumed,
    NotYetValid,
    Expired,
    WrongBinding,
    WrongChallenge,
    InvalidSolution,
}

/// Pure one-outstanding-challenge state machine for one secure connection.
#[derive(Default)]
pub struct PowChallengeStateV1 {
    outstanding: Option<PowChallengeResponseV1>,
    consumed: bool,
}

impl PowChallengeStateV1 {
    /// Install a server-created challenge.  A still-live challenge cannot be
    /// replaced.  An expired challenge may be replaced; a consumed connection
    /// cannot be reopened for a second authorization.
    pub fn issue(
        &mut self,
        challenge: PowChallengeResponseV1,
        now_unix: u64,
    ) -> Result<(), PowChallengeTransitionErrorV1> {
        challenge
            .validate()
            .map_err(|_| PowChallengeTransitionErrorV1::InvalidChallenge)?;
        if now_unix < challenge.issued_at_unix {
            return Err(PowChallengeTransitionErrorV1::NotYetValid);
        }
        if now_unix > challenge.expires_at_unix {
            return Err(PowChallengeTransitionErrorV1::Expired);
        }
        if self.consumed {
            return Err(PowChallengeTransitionErrorV1::AlreadyConsumed);
        }
        if self
            .outstanding
            .as_ref()
            .is_some_and(|current| now_unix <= current.expires_at_unix)
        {
            return Err(PowChallengeTransitionErrorV1::OutstandingExists);
        }
        self.outstanding = Some(challenge);
        Ok(())
    }

    /// Verify and atomically consume the outstanding challenge.  Failed
    /// attempts leave it outstanding until its absolute expiry.
    pub fn try_consume(
        &mut self,
        expected_provider_id: &ProviderId,
        request: &PowChallengeRequestV1,
        expected_secure_channel_exporter: &[u8; 32],
        solution: &PowSolutionV1,
        now_unix: u64,
    ) -> Result<(), PowChallengeTransitionErrorV1> {
        if self.consumed {
            return Err(PowChallengeTransitionErrorV1::AlreadyConsumed);
        }
        let challenge = self
            .outstanding
            .as_ref()
            .ok_or(PowChallengeTransitionErrorV1::NoOutstanding)?;
        if now_unix < challenge.issued_at_unix {
            return Err(PowChallengeTransitionErrorV1::NotYetValid);
        }
        if now_unix > challenge.expires_at_unix {
            return Err(PowChallengeTransitionErrorV1::Expired);
        }
        challenge
            .verify_for_request(
                expected_provider_id,
                request,
                expected_secure_channel_exporter,
            )
            .map_err(|_| PowChallengeTransitionErrorV1::WrongBinding)?;
        if solution.challenge_id != challenge.challenge_id {
            return Err(PowChallengeTransitionErrorV1::WrongChallenge);
        }
        if !pow_solution_meets_difficulty_v1(challenge, solution)
            .map_err(|_| PowChallengeTransitionErrorV1::InvalidSolution)?
        {
            return Err(PowChallengeTransitionErrorV1::InvalidSolution);
        }
        self.outstanding = None;
        self.consumed = true;
        Ok(())
    }
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
    use crate::{HarmonyHintSideV1, HintTransport};

    fn request() -> PowChallengeRequestV1 {
        PowChallengeRequestV1 {
            policy_digest: [2; 32],
            scope_id: [3; 32],
            offer_id: 4,
            operation: OperationStartV1::HarmonyHint {
                db_id: 5,
                transport: HintTransport::V2Half,
                session_token: Some([6; 16]),
                primary_side: Some(HarmonyHintSideV1::Index),
            },
        }
    }

    fn challenge(difficulty_bits: u8) -> PowChallengeResponseV1 {
        let request = request();
        PowChallengeResponseV1 {
            provider_id: [1; 32],
            policy_digest: request.policy_digest,
            scope_id: request.scope_id,
            offer_id: request.offer_id,
            operation_digest: request.operation_digest().unwrap(),
            secure_channel_exporter: [7; 32],
            challenge_id: [8; 32],
            difficulty_bits,
            issued_at_unix: 1_000,
            expires_at_unix: 1_030,
        }
    }

    fn solve(challenge: &PowChallengeResponseV1) -> PowSolutionV1 {
        for nonce in 0..=u64::MAX {
            let candidate = PowSolutionV1 {
                challenge_id: challenge.challenge_id,
                nonce,
            };
            if pow_solution_meets_difficulty_v1(challenge, &candidate).unwrap() {
                return candidate;
            }
        }
        unreachable!("a low-difficulty SHA256 challenge has a solution")
    }

    #[test]
    fn challenge_request_and_response_use_exact_padded_class() {
        let request = request();
        let encoded = request.encode_padded().unwrap();
        assert_eq!(encoded.len(), POW_CHALLENGE_FRAME_CLASS_V1);
        assert_eq!(
            PowChallengeRequestV1::decode_padded(&encoded).unwrap(),
            request
        );

        let response = challenge(8);
        let encoded = response.encode_padded().unwrap();
        assert_eq!(encoded.len(), POW_CHALLENGE_FRAME_CLASS_V1);
        assert_eq!(
            PowChallengeResponseV1::decode_padded(&encoded).unwrap(),
            response
        );
    }

    #[test]
    fn challenge_codecs_reject_wrong_class_and_nonzero_padding() {
        let mut encoded = challenge(8).encode_padded().unwrap();
        assert!(matches!(
            PowChallengeResponseV1::decode_padded(&encoded[..encoded.len() - 1]),
            Err(ServiceProtocolError::FrameClass { .. })
        ));
        *encoded.last_mut().unwrap() = 1;
        assert!(matches!(
            PowChallengeResponseV1::decode_padded(&encoded),
            Err(ServiceProtocolError::InvalidValue {
                field: "PowChallengeResponseV1.padding",
                ..
            })
        ));
    }

    #[test]
    fn difficulty_cap_ttl_and_binding_are_fail_closed() {
        assert!(challenge(0).validate().is_err());
        assert!(challenge(MAX_POW_DIFFICULTY_BITS_V1 + 1)
            .validate()
            .is_err());
        let mut too_long = challenge(8);
        too_long.expires_at_unix = too_long.issued_at_unix + MAX_POW_CHALLENGE_TTL_SECONDS_V1 + 1;
        assert!(too_long.validate().is_err());

        let response = challenge(8);
        assert!(response
            .verify_for_request(&[1; 32], &request(), &[7; 32])
            .is_ok());
        assert!(response
            .verify_for_request(&[1; 32], &request(), &[9; 32])
            .is_err());
    }

    #[test]
    fn solution_is_nonce_u64le_and_msb_first() {
        let response = challenge(8);
        let solution = solve(&response);
        let encoded = solution.encode().unwrap();
        assert_eq!(&encoded[33..], &solution.nonce.to_le_bytes());
        assert_eq!(PowSolutionV1::decode(&encoded).unwrap(), solution);
        let digest = pow_solution_hash_v1(&response, solution.nonce).unwrap();
        assert_eq!(digest[0], 0, "eight MSB-first bits must be zero");
    }

    #[test]
    fn state_has_one_outstanding_and_consumes_once() {
        let response = challenge(8);
        let solution = solve(&response);
        let mut state = PowChallengeStateV1::default();
        state.issue(response.clone(), 1_000).unwrap();
        assert_eq!(
            state.issue(response, 1_001),
            Err(PowChallengeTransitionErrorV1::OutstandingExists)
        );

        let mut wrong = solution;
        wrong.nonce = wrong.nonce.wrapping_add(1);
        while pow_solution_meets_difficulty_v1(&challenge(8), &wrong).unwrap() {
            wrong.nonce = wrong.nonce.wrapping_add(1);
        }
        assert_eq!(
            state.try_consume(&[1; 32], &request(), &[7; 32], &wrong, 1_010),
            Err(PowChallengeTransitionErrorV1::InvalidSolution)
        );
        state
            .try_consume(&[1; 32], &request(), &[7; 32], &solution, 1_010)
            .unwrap();
        assert_eq!(
            state.try_consume(&[1; 32], &request(), &[7; 32], &solution, 1_010),
            Err(PowChallengeTransitionErrorV1::AlreadyConsumed)
        );
    }

    #[test]
    fn expired_challenge_can_be_replaced_but_not_consumed() {
        let mut state = PowChallengeStateV1::default();
        let first = challenge(8);
        state.issue(first.clone(), 1_000).unwrap();
        let solution = solve(&first);
        assert_eq!(
            state.try_consume(&[1; 32], &request(), &[7; 32], &solution, 1_031),
            Err(PowChallengeTransitionErrorV1::Expired)
        );

        let mut replacement = challenge(8);
        replacement.challenge_id = [9; 32];
        replacement.issued_at_unix = 1_031;
        replacement.expires_at_unix = 1_061;
        state.issue(replacement, 1_031).unwrap();
    }
}
