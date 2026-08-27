//! Canonical HTTP request envelopes for provider settlement operations.
//!
//! The inner request and authentication objects remain independently signed.
//! These envelopes only make their exact ordered transport representation
//! explicit and length bounded; they contain no wallet destination or
//! Lightning payment material.

use core::fmt;

use crate::codec::{expect_v1, put_bytes_u32, Decoder};
use crate::{
    IssuerPayoutIntentResponseV1, IssuerPayoutResponseV1, ProviderBalanceRequestV1,
    ProviderClearingRequestAuthV1, ProviderPayoutIntentRequestV1, ProviderPayoutRequestV1,
    ProviderPayoutStatusRequestV1, ProviderSettlementDepositRequestV1,
    ProviderSettlementRequestAuthV1, ServiceProtocolError, SERVICE_PROTOCOL_VERSION,
};
use zeroize::Zeroizing;

/// Accommodates the bounded 64-note settlement deposit plus framing while
/// placing a hard ceiling on allocation before any signature or DLEQ work.
pub const MAX_SETTLEMENT_HTTP_ENVELOPE_LEN_V1: usize = 320 * 1024;

/// Upper bound for the ledger-only settlement routes served by
/// `payment-issuer`. These V1 envelopes contain only fixed-size request,
/// authentication and signed-response objects; the much larger ceiling above
/// exists solely for the transport-neutral 64-note deposit model.
pub const MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1: usize = 8 * 1024;

fn encode_parts(
    field: &'static str,
    parts: &[&[u8]],
    max_len: usize,
) -> Result<Vec<u8>, ServiceProtocolError> {
    let payload_len = parts.iter().try_fold(1usize, |total, part| {
        total
            .checked_add(4)
            .and_then(|value| value.checked_add(part.len()))
            .ok_or(ServiceProtocolError::FieldTooLong {
                field,
                len: usize::MAX,
                max: max_len,
            })
    })?;
    if payload_len > max_len {
        return Err(ServiceProtocolError::FieldTooLong {
            field,
            len: payload_len,
            max: max_len,
        });
    }
    let mut out = Vec::with_capacity(payload_len);
    out.push(SERVICE_PROTOCOL_VERSION);
    for part in parts {
        put_bytes_u32(&mut out, part);
    }
    Ok(out)
}

fn decode_parts<const N: usize>(
    bytes: &[u8],
    field: &'static str,
    max_len: usize,
) -> Result<[Zeroizing<Vec<u8>>; N], ServiceProtocolError> {
    if bytes.len() > max_len {
        return Err(ServiceProtocolError::FieldTooLong {
            field,
            len: bytes.len(),
            max: max_len,
        });
    }
    let mut decoder = Decoder::new(bytes);
    expect_v1(decoder.u8(field)?, field)?;
    let mut parts = Vec::with_capacity(N);
    for _ in 0..N {
        parts.push(Zeroizing::new(decoder.bytes_u32(field, max_len)?));
    }
    decoder.finish()?;
    parts
        .try_into()
        .map_err(|_| ServiceProtocolError::InvalidValue {
            field,
            reason: "wrong number of nested objects",
        })
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderSettlementDepositEnvelopeV1 {
    pub request: ProviderSettlementDepositRequestV1,
    pub request_auth: ProviderSettlementRequestAuthV1,
}

impl fmt::Debug for ProviderSettlementDepositEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSettlementDepositEnvelopeV1")
            .field("request", &"[REDACTED]")
            .field("request_auth", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ProviderSettlementDepositEnvelopeV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let request = self.request.encode_zeroizing()?;
        let request_auth = Zeroizing::new(self.request_auth.encode()?);
        encode_parts(
            Self::FIELD,
            &[&request, &request_auth],
            MAX_SETTLEMENT_HTTP_ENVELOPE_LEN_V1,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let [request, request_auth] =
            decode_parts::<2>(bytes, Self::FIELD, MAX_SETTLEMENT_HTTP_ENVELOPE_LEN_V1)?;
        let value = Self {
            request: ProviderSettlementDepositRequestV1::decode(&request)?,
            request_auth: ProviderSettlementRequestAuthV1::decode(&request_auth)?,
        };
        let canonical = Zeroizing::new(value.encode()?);
        if canonical.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: Self::FIELD,
                reason: "nested object is not canonical",
            });
        }
        Ok(value)
    }

    const FIELD: &'static str = "ProviderSettlementDepositEnvelopeV1";
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderBalanceEnvelopeV1 {
    pub request: ProviderBalanceRequestV1,
    pub request_auth: ProviderClearingRequestAuthV1,
}

impl fmt::Debug for ProviderBalanceEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderBalanceEnvelopeV1")
            .field("request", &"[REDACTED]")
            .field("request_auth", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ProviderBalanceEnvelopeV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let request = Zeroizing::new(self.request.encode()?);
        let request_auth = Zeroizing::new(self.request_auth.encode());
        encode_parts(
            Self::FIELD,
            &[&request, &request_auth],
            MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let [request, request_auth] = decode_parts::<2>(
            bytes,
            Self::FIELD,
            MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1,
        )?;
        let value = Self {
            request: ProviderBalanceRequestV1::decode(&request)?,
            request_auth: ProviderClearingRequestAuthV1::decode(&request_auth)?,
        };
        let canonical = Zeroizing::new(value.encode()?);
        if canonical.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: Self::FIELD,
                reason: "nested object is not canonical",
            });
        }
        Ok(value)
    }

    const FIELD: &'static str = "ProviderBalanceEnvelopeV1";
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderPayoutIntentEnvelopeV1 {
    pub request: ProviderPayoutIntentRequestV1,
    pub request_auth: ProviderClearingRequestAuthV1,
}

impl fmt::Debug for ProviderPayoutIntentEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderPayoutIntentEnvelopeV1")
            .field("request", &"[REDACTED]")
            .field("request_auth", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ProviderPayoutIntentEnvelopeV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let request = Zeroizing::new(self.request.encode()?);
        let request_auth = Zeroizing::new(self.request_auth.encode());
        encode_parts(
            Self::FIELD,
            &[&request, &request_auth],
            MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let [request, request_auth] = decode_parts::<2>(
            bytes,
            Self::FIELD,
            MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1,
        )?;
        let value = Self {
            request: ProviderPayoutIntentRequestV1::decode(&request)?,
            request_auth: ProviderClearingRequestAuthV1::decode(&request_auth)?,
        };
        let canonical = Zeroizing::new(value.encode()?);
        if canonical.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: Self::FIELD,
                reason: "nested object is not canonical",
            });
        }
        Ok(value)
    }

    const FIELD: &'static str = "ProviderPayoutIntentEnvelopeV1";
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderPayoutEnvelopeV1 {
    pub request: ProviderPayoutRequestV1,
    pub request_auth: ProviderClearingRequestAuthV1,
    pub intent_request: ProviderPayoutIntentRequestV1,
    pub intent_response: IssuerPayoutIntentResponseV1,
}

impl fmt::Debug for ProviderPayoutEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderPayoutEnvelopeV1")
            .field("request", &"[REDACTED]")
            .field("request_auth", &"[REDACTED]")
            .field("intent", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ProviderPayoutEnvelopeV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let request = Zeroizing::new(self.request.encode()?);
        let request_auth = Zeroizing::new(self.request_auth.encode());
        let intent_request = Zeroizing::new(self.intent_request.encode()?);
        let intent_response = Zeroizing::new(self.intent_response.encode()?);
        encode_parts(
            Self::FIELD,
            &[&request, &request_auth, &intent_request, &intent_response],
            MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let [request, request_auth, intent_request, intent_response] = decode_parts::<4>(
            bytes,
            Self::FIELD,
            MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1,
        )?;
        let value = Self {
            request: ProviderPayoutRequestV1::decode(&request)?,
            request_auth: ProviderClearingRequestAuthV1::decode(&request_auth)?,
            intent_request: ProviderPayoutIntentRequestV1::decode(&intent_request)?,
            intent_response: IssuerPayoutIntentResponseV1::decode(&intent_response)?,
        };
        let canonical = Zeroizing::new(value.encode()?);
        if canonical.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: Self::FIELD,
                reason: "nested object is not canonical",
            });
        }
        Ok(value)
    }

    const FIELD: &'static str = "ProviderPayoutEnvelopeV1";
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderPayoutStatusEnvelopeV1 {
    pub request: ProviderPayoutStatusRequestV1,
    pub request_auth: ProviderSettlementRequestAuthV1,
    pub payout_request: ProviderPayoutRequestV1,
    pub initial_payout_response: IssuerPayoutResponseV1,
}

impl fmt::Debug for ProviderPayoutStatusEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderPayoutStatusEnvelopeV1")
            .field("request", &"[REDACTED]")
            .field("request_auth", &"[REDACTED]")
            .field("payout", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ProviderPayoutStatusEnvelopeV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let request = Zeroizing::new(self.request.encode()?);
        let request_auth = Zeroizing::new(self.request_auth.encode()?);
        let payout_request = Zeroizing::new(self.payout_request.encode()?);
        let initial_payout_response = Zeroizing::new(self.initial_payout_response.encode()?);
        encode_parts(
            Self::FIELD,
            &[
                &request,
                &request_auth,
                &payout_request,
                &initial_payout_response,
            ],
            MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let [request, request_auth, payout_request, initial_payout_response] = decode_parts::<4>(
            bytes,
            Self::FIELD,
            MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1,
        )?;
        let value = Self {
            request: ProviderPayoutStatusRequestV1::decode(&request)?,
            request_auth: ProviderSettlementRequestAuthV1::decode(&request_auth)?,
            payout_request: ProviderPayoutRequestV1::decode(&payout_request)?,
            initial_payout_response: IssuerPayoutResponseV1::decode(&initial_payout_response)?,
        };
        let canonical = Zeroizing::new(value.encode()?);
        if canonical.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: Self::FIELD,
                reason: "nested object is not canonical",
            });
        }
        Ok(value)
    }

    const FIELD: &'static str = "ProviderPayoutStatusEnvelopeV1";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_decoder_rejects_oversized_and_trailing_inputs_before_nested_decode() {
        let oversized = vec![0; MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1 + 1];
        assert!(ProviderBalanceEnvelopeV1::decode(&oversized).is_err());
        assert!(ProviderPayoutIntentEnvelopeV1::decode(&oversized).is_err());
        assert!(ProviderPayoutEnvelopeV1::decode(&oversized).is_err());
        assert!(ProviderPayoutStatusEnvelopeV1::decode(&oversized).is_err());

        let mut malformed = vec![SERVICE_PROTOCOL_VERSION];
        malformed.extend_from_slice(&0u32.to_le_bytes());
        malformed.extend_from_slice(&0u32.to_le_bytes());
        malformed.push(0);
        assert!(ProviderBalanceEnvelopeV1::decode(&malformed).is_err());
    }
}
