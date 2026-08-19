//! Restart-safe BOLT11 credential acquisition primitives.
//!
//! HTTP is deliberately left to the caller.  Every request/response body is
//! the protocol's canonical binary encoding, while this module owns the
//! cryptographic checks and the monotonic quote/delegation state.  None of
//! these values are valid PIR-server admission messages.

use core::fmt;

use pir_payment_crypto::{sign_bip340_prehash_v1, verify_quote_claim_v1};
use pir_sdk::{PirError, PirResult};
use pir_service_protocol::{
    ArcIssuanceCanonicalizerV1, Bolt11QuoteClaimEnvelopeV1, Bolt11QuoteClaimV1,
    Bolt11QuoteIntentV1, Bolt11QuoteKeyDelegationV1, Bolt11QuoteKeyRollbackGuardV1,
    Bolt11QuoteStatusRequestV1, Bolt11QuoteStatusV1, Bolt11QuoteV1,
    CheckedCredentialIssuanceResponseV1, CredentialIssuanceRequestItemsV1,
    CredentialIssuanceRequestV1, CredentialIssuanceResponseV1, CredentialKeyBindingV1,
    LightningNetworkV1, ParsedBolt11InvoiceV1, VerifiedServiceOfferV1,
};
use zeroize::{Zeroize, Zeroizing};

const QUOTE_KEY_CHECKPOINT_VERSION_V1: u8 = 1;
const QUOTE_KEY_CHECKPOINT_LEN_V1: usize = 1 + 32 + 1 + 33 + 8 + 32;

/// Durable anti-rollback state for one exact `(issuer, network, payee)` quote
/// signing-key stream.  It contains no invoice, payment hash, query, or peer
/// PIR-provider identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bolt11QuoteKeyCheckpointV1 {
    guard: Bolt11QuoteKeyRollbackGuardV1,
}

impl Bolt11QuoteKeyCheckpointV1 {
    pub fn initial(
        issuer_id: [u8; 32],
        network: LightningNetworkV1,
        expected_payee_pubkey: [u8; 33],
    ) -> PirResult<Self> {
        Bolt11QuoteKeyRollbackGuardV1::initial(issuer_id, network, expected_payee_pubkey)
            .map(|guard| Self { guard })
            .map_err(protocol_verification_error)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(QUOTE_KEY_CHECKPOINT_LEN_V1);
        out.push(QUOTE_KEY_CHECKPOINT_VERSION_V1);
        out.extend_from_slice(&self.guard.issuer_id());
        out.push(self.guard.network() as u8);
        out.extend_from_slice(&self.guard.expected_payee_pubkey());
        out.extend_from_slice(&self.guard.highest_epoch().to_le_bytes());
        out.extend_from_slice(&self.guard.delegation_digest_at_highest_epoch());
        out
    }

    pub fn decode(bytes: &[u8]) -> PirResult<Self> {
        if bytes.len() != QUOTE_KEY_CHECKPOINT_LEN_V1 || bytes[0] != QUOTE_KEY_CHECKPOINT_VERSION_V1
        {
            return Err(PirError::Decode(
                "invalid BOLT11 quote-key checkpoint length or version".into(),
            ));
        }
        let issuer_id = fixed(&bytes[1..33], "quote-key checkpoint issuer")?;
        let network = decode_network(bytes[33])?;
        let expected_payee_pubkey = fixed(&bytes[34..67], "quote-key checkpoint payee")?;
        let highest_epoch = u64::from_le_bytes(
            bytes[67..75]
                .try_into()
                .map_err(|_| PirError::Decode("invalid quote-key checkpoint epoch".into()))?,
        );
        let delegation_digest_at_highest_epoch =
            fixed(&bytes[75..107], "quote-key checkpoint digest")?;
        let guard = Bolt11QuoteKeyRollbackGuardV1::from_persisted(
            issuer_id,
            network,
            expected_payee_pubkey,
            highest_epoch,
            delegation_digest_at_highest_epoch,
        )
        .map_err(protocol_verification_error)?;
        Ok(Self { guard })
    }

    pub const fn issuer_id(&self) -> [u8; 32] {
        self.guard.issuer_id()
    }

    pub const fn network(&self) -> LightningNetworkV1 {
        self.guard.network()
    }

    pub const fn expected_payee_pubkey(&self) -> [u8; 33] {
        self.guard.expected_payee_pubkey()
    }

    pub const fn highest_epoch(&self) -> u64 {
        self.guard.highest_epoch()
    }

    pub(crate) const fn rollback_guard_v1(&self) -> &Bolt11QuoteKeyRollbackGuardV1 {
        &self.guard
    }

    pub(crate) const fn from_rollback_guard_v1(guard: Bolt11QuoteKeyRollbackGuardV1) -> Self {
        Self { guard }
    }

    /// Validate one exact issuer delegation against this durable stream
    /// without constructing an invoice intent. Strict two-provider callers
    /// use this to freeze the payee and delegation before either payment leg
    /// can begin; quote preparation repeats the verification and returns the
    /// checkpoint that must be persisted.
    pub(crate) fn verify_delegation_for_issuer_v1(
        &self,
        expected_issuer_id: &[u8; 32],
        delegation_bytes: &[u8],
        now_unix: u64,
    ) -> PirResult<Bolt11QuoteKeyDelegationV1> {
        if &self.issuer_id() != expected_issuer_id {
            return Err(PirError::VerificationFailed(
                "quote-key checkpoint issuer differs from the signed offer".into(),
            ));
        }
        let delegation =
            Bolt11QuoteKeyDelegationV1::decode(delegation_bytes).map_err(protocol_decode_error)?;
        self.guard
            .verify_and_advance(&delegation, now_unix)
            .map_err(protocol_verification_error)?;
        Ok(delegation)
    }
}

/// A quote intent whose provider policy, commercial terms, issuer delegation,
/// and quote-key rollback state have all been checked.
#[derive(Clone, Debug)]
pub struct PreparedBolt11QuoteV1 {
    intent: Bolt11QuoteIntentV1,
    delegation: Bolt11QuoteKeyDelegationV1,
    credential_binding: CredentialKeyBindingV1,
    advanced_checkpoint: Bolt11QuoteKeyCheckpointV1,
}

impl PreparedBolt11QuoteV1 {
    pub(crate) fn from_verified_offer(
        verified_offer: &VerifiedServiceOfferV1<'_>,
        delegation_bytes: &[u8],
        checkpoint: &Bolt11QuoteKeyCheckpointV1,
        now_unix: u64,
        claim_pubkey_xonly: [u8; 32],
        idempotency_key: [u8; 32],
    ) -> PirResult<Self> {
        let delegation =
            Bolt11QuoteKeyDelegationV1::decode(delegation_bytes).map_err(protocol_decode_error)?;
        let offer = verified_offer.offer();
        if checkpoint.issuer_id() != offer.issuer_id {
            return Err(PirError::VerificationFailed(
                "quote-key checkpoint issuer differs from the signed offer".into(),
            ));
        }
        let credential_binding = offer.credential_binding.clone().ok_or_else(|| {
            PirError::VerificationFailed(
                "BOLT11 offer has no issuer-signed credential binding".into(),
            )
        })?;
        let (intent, advanced_guard) = Bolt11QuoteIntentV1::from_verified_offer_guarded(
            verified_offer,
            &delegation,
            &checkpoint.guard,
            now_unix,
            claim_pubkey_xonly,
            idempotency_key,
        )
        .map_err(protocol_verification_error)?;
        Ok(Self {
            intent,
            delegation,
            credential_binding,
            advanced_checkpoint: Bolt11QuoteKeyCheckpointV1 {
                guard: advanced_guard,
            },
        })
    }

    pub fn intent_bytes(&self) -> PirResult<Vec<u8>> {
        self.intent.encode().map_err(protocol_encode_error)
    }

    pub fn delegation_bytes(&self) -> PirResult<Vec<u8>> {
        self.delegation.encode().map_err(protocol_encode_error)
    }

    pub fn credential_binding_bytes(&self) -> PirResult<Vec<u8>> {
        self.credential_binding
            .encode()
            .map_err(protocol_encode_error)
    }

    pub fn quote_key_checkpoint_bytes(&self) -> Vec<u8> {
        self.advanced_checkpoint.encode()
    }

    /// Restore an encrypted client record without depending on a currently
    /// live PIR connection. Every nested object is decoded canonically and
    /// the issuer delegation, rollback stream, intent, and credential binding
    /// are cross-checked again.
    pub fn restore(
        intent_bytes: &[u8],
        delegation_bytes: &[u8],
        credential_binding_bytes: &[u8],
        checkpoint_bytes: &[u8],
    ) -> PirResult<Self> {
        let intent = Bolt11QuoteIntentV1::decode(intent_bytes).map_err(protocol_decode_error)?;
        let delegation =
            Bolt11QuoteKeyDelegationV1::decode(delegation_bytes).map_err(protocol_decode_error)?;
        let credential_binding = CredentialKeyBindingV1::decode(credential_binding_bytes)
            .map_err(protocol_decode_error)?;
        let advanced_checkpoint = Bolt11QuoteKeyCheckpointV1::decode(checkpoint_bytes)?;
        if advanced_checkpoint.issuer_id() != intent.issuer_id
            || advanced_checkpoint.network() != intent.network
            || advanced_checkpoint.expected_payee_pubkey() != intent.expected_payee_pubkey
            || advanced_checkpoint.highest_epoch() != intent.minimum_quote_key_epoch
            || delegation.key_epoch != intent.minimum_quote_key_epoch
        {
            return Err(PirError::VerificationFailed(
                "restored BOLT11 quote-key stream differs from the intent".into(),
            ));
        }
        let replayed_guard = advanced_checkpoint
            .guard
            .verify_and_advance(&delegation, delegation.not_before)
            .map_err(protocol_verification_error)?;
        if replayed_guard != advanced_checkpoint.guard
            || intent.quote_delegation_digest
                != delegation
                    .delegation_digest()
                    .map_err(protocol_verification_error)?
            || intent.issuer_id != credential_binding.issuer_id
            || intent.provider_id != credential_binding.claims.provider_id
            || intent.scope_id != credential_binding.claims.scope_id
            || intent.offer_id != credential_binding.claims.offer_id
            || intent.authorization != credential_binding.claims.scheme
            || intent.entitlement_profile != credential_binding.claims.entitlement_profile
            || intent.credential_presentation_limit != credential_binding.claims.presentation_limit
            || intent.credential_key_id != credential_binding.claims.credential_key_id
            || intent.credential_binding_digest
                != credential_binding
                    .binding_digest()
                    .map_err(protocol_verification_error)?
        {
            return Err(PirError::VerificationFailed(
                "restored BOLT11 acquisition objects do not share one exact signed binding".into(),
            ));
        }
        Ok(Self {
            intent,
            delegation,
            credential_binding,
            advanced_checkpoint,
        })
    }

    pub const fn intent(&self) -> &Bolt11QuoteIntentV1 {
        &self.intent
    }

    pub const fn delegation(&self) -> &Bolt11QuoteKeyDelegationV1 {
        &self.delegation
    }

    pub const fn credential_binding(&self) -> &CredentialKeyBindingV1 {
        &self.credential_binding
    }

    /// Accept the initial signed quote only if its BOLT11 signature, exact
    /// amount/network/payee, issuer delegation, and payment window all verify.
    pub fn accept_initial_quote_for_payment(
        &self,
        quote_bytes: &[u8],
        now_unix: u64,
    ) -> PirResult<AcceptedBolt11QuoteV1> {
        let quote = Bolt11QuoteV1::decode(quote_bytes).map_err(protocol_decode_error)?;
        let parsed =
            ParsedBolt11InvoiceV1::parse(&quote.invoice).map_err(protocol_verification_error)?;
        quote
            .verify_for_payment(&self.intent, &self.delegation, &parsed, now_unix)
            .map_err(protocol_verification_error)?;
        Ok(AcceptedBolt11QuoteV1 { quote })
    }

    /// Restore a previously accepted signed snapshot. This deliberately does
    /// not assert that it is still payable or claimable.
    pub fn restore_quote_snapshot(
        &self,
        quote_bytes: &[u8],
        now_unix: u64,
    ) -> PirResult<AcceptedBolt11QuoteV1> {
        let quote = Bolt11QuoteV1::decode(quote_bytes).map_err(protocol_decode_error)?;
        let parsed =
            ParsedBolt11InvoiceV1::parse(&quote.invoice).map_err(protocol_verification_error)?;
        quote
            .verify_snapshot(&self.intent, &self.delegation, &parsed, now_unix)
            .map_err(protocol_verification_error)?;
        Ok(AcceptedBolt11QuoteV1 { quote })
    }

    pub fn build_status_request(
        &self,
        quote: &AcceptedBolt11QuoteV1,
        claim_secret_key: &[u8; 32],
        requested_at: u64,
        request_nonce: [u8; 32],
        auxiliary_randomness: [u8; 32],
    ) -> PirResult<Vec<u8>> {
        let mut request = Bolt11QuoteStatusRequestV1 {
            issuer_id: self.intent.issuer_id,
            quote_id: quote.quote.quote_id,
            quote_request_digest: self
                .intent
                .request_digest()
                .map_err(protocol_encode_error)?,
            claim_pubkey_xonly: self.intent.claim_pubkey_xonly,
            requested_at,
            request_nonce,
            // A non-zero placeholder is needed because the protocol type
            // validates complete wire objects before hashing unsigned fields.
            signature: [1; 64],
        };
        let digest = request
            .bip340_signing_digest()
            .map_err(protocol_encode_error)?;
        let (public_key, signature) =
            sign_bip340_prehash_v1(claim_secret_key, &digest, &auxiliary_randomness)
                .map_err(payment_crypto_error)?;
        if public_key != self.intent.claim_pubkey_xonly {
            return Err(PirError::VerificationFailed(
                "claim secret does not match the quote intent".into(),
            ));
        }
        request.signature = signature;
        request.encode().map_err(protocol_encode_error)
    }

    pub fn prepare_claim(
        &self,
        quote: &AcceptedBolt11QuoteV1,
        items: CredentialIssuanceRequestItemsV1,
        claim_secret_key: &[u8; 32],
        auxiliary_randomness: [u8; 32],
        now_unix: u64,
    ) -> PirResult<PreparedBolt11ClaimV1> {
        let parsed = ParsedBolt11InvoiceV1::parse(&quote.quote.invoice)
            .map_err(protocol_verification_error)?;
        let verified_quote = quote
            .quote
            .verify_for_claim_submission(&self.intent, &self.delegation, &parsed, now_unix)
            .map_err(protocol_verification_error)?;
        let request = CredentialIssuanceRequestV1 {
            issuer_id: self.intent.issuer_id,
            quote_id: quote.quote.quote_id,
            quote_request_digest: quote.quote.request_digest,
            authorization: self.intent.authorization,
            credential_binding_digest: self.intent.credential_binding_digest,
            credential_key_id: self.intent.credential_key_id.clone(),
            items,
        };
        let credential_request_digest = request.request_digest().map_err(protocol_encode_error)?;
        let mut claim = Bolt11QuoteClaimV1 {
            issuer_id: self.intent.issuer_id,
            quote_id: quote.quote.quote_id,
            quote_request_digest: quote.quote.request_digest,
            credential_request_digest,
            claim_pubkey_xonly: self.intent.claim_pubkey_xonly,
            idempotency_key: self.intent.idempotency_key,
            signature: [1; 64],
        };
        let digest = claim
            .bip340_signing_digest()
            .map_err(protocol_encode_error)?;
        let (public_key, signature) =
            sign_bip340_prehash_v1(claim_secret_key, &digest, &auxiliary_randomness)
                .map_err(payment_crypto_error)?;
        if public_key != self.intent.claim_pubkey_xonly {
            return Err(PirError::VerificationFailed(
                "claim secret does not match the quote intent".into(),
            ));
        }
        claim.signature = signature;
        let unverified = request
            .verify_for_verified_quote(&claim, &verified_quote, now_unix)
            .map_err(protocol_verification_error)?;
        verify_quote_claim_v1(&unverified).map_err(payment_crypto_error)?;
        let envelope = Bolt11QuoteClaimEnvelopeV1 {
            quote_intent: self.intent.clone(),
            claim,
            credential_request: request.clone(),
        };
        let mut envelope_bytes = Zeroizing::new(envelope.encode().map_err(protocol_encode_error)?);
        Ok(PreparedBolt11ClaimV1 {
            request,
            envelope_bytes: core::mem::take(&mut *envelope_bytes),
        })
    }

    pub fn verify_issuance_response(
        &self,
        quote: &AcceptedBolt11QuoteV1,
        claim: &PreparedBolt11ClaimV1,
        response_bytes: &[u8],
        arc_canonicalizer: Option<&dyn ArcIssuanceCanonicalizerV1>,
        now_unix: u64,
    ) -> PirResult<CheckedCredentialIssuanceResponseV1> {
        let parsed = ParsedBolt11InvoiceV1::parse(&quote.quote.invoice)
            .map_err(protocol_verification_error)?;
        let verified_quote = quote
            .quote
            .verify_snapshot(&self.intent, &self.delegation, &parsed, now_unix)
            .map_err(protocol_verification_error)?;
        let response = CredentialIssuanceResponseV1::decode(response_bytes, arc_canonicalizer)
            .map_err(protocol_decode_error)?;
        response
            .verify_for_verified_quote(&claim.request, &verified_quote, &self.credential_binding)
            .map_err(protocol_verification_error)
    }

    pub fn restore_claim(
        &self,
        envelope_bytes: &[u8],
        arc_canonicalizer: Option<&dyn ArcIssuanceCanonicalizerV1>,
    ) -> PirResult<PreparedBolt11ClaimV1> {
        let envelope = Bolt11QuoteClaimEnvelopeV1::decode(envelope_bytes, arc_canonicalizer)
            .map_err(protocol_decode_error)?;
        if envelope.quote_intent != self.intent
            || envelope.claim.issuer_id != self.intent.issuer_id
            || envelope.claim.quote_request_digest
                != self
                    .intent
                    .request_digest()
                    .map_err(protocol_encode_error)?
            || envelope.claim.claim_pubkey_xonly != self.intent.claim_pubkey_xonly
            || envelope.claim.idempotency_key != self.intent.idempotency_key
        {
            return Err(PirError::VerificationFailed(
                "restored BOLT11 claim differs from the verified quote intent".into(),
            ));
        }
        let mut canonical = Zeroizing::new(envelope.encode().map_err(protocol_encode_error)?);
        if canonical.as_slice() != envelope_bytes {
            return Err(PirError::Decode(
                "restored BOLT11 claim envelope is non-canonical".into(),
            ));
        }
        Ok(PreparedBolt11ClaimV1 {
            request: envelope.credential_request,
            envelope_bytes: core::mem::take(&mut *canonical),
        })
    }
}

#[derive(Clone, Debug)]
pub struct AcceptedBolt11QuoteV1 {
    quote: Bolt11QuoteV1,
}

impl AcceptedBolt11QuoteV1 {
    pub fn bytes(&self) -> PirResult<Vec<u8>> {
        self.quote.encode().map_err(protocol_encode_error)
    }

    pub fn invoice(&self) -> &str {
        &self.quote.invoice
    }

    pub const fn quote_id(&self) -> [u8; 32] {
        self.quote.quote_id
    }

    pub const fn status(&self) -> Bolt11QuoteStatusV1 {
        self.quote.status
    }

    pub const fn state_version(&self) -> u64 {
        self.quote.state_version
    }

    pub const fn invoice_expires_at(&self) -> u64 {
        self.quote.invoice_expires_at
    }

    pub const fn invoice_created_at(&self) -> u64 {
        self.quote.invoice_created_at
    }

    pub const fn claim_deadline(&self) -> u64 {
        self.quote.claim_deadline
    }

    pub fn accept_latest_after(
        &self,
        prepared: &PreparedBolt11QuoteV1,
        response_bytes: &[u8],
        now_unix: u64,
    ) -> PirResult<Self> {
        let next = Bolt11QuoteV1::decode(response_bytes).map_err(protocol_decode_error)?;
        let parsed =
            ParsedBolt11InvoiceV1::parse(&next.invoice).map_err(protocol_verification_error)?;
        next.verify_latest_after(
            &self.quote,
            &prepared.intent,
            &prepared.delegation,
            &parsed,
            now_unix,
        )
        .map_err(protocol_verification_error)?;
        Ok(Self { quote: next })
    }
}

#[derive(Clone)]
pub struct PreparedBolt11ClaimV1 {
    request: CredentialIssuanceRequestV1,
    envelope_bytes: Vec<u8>,
}

impl fmt::Debug for PreparedBolt11ClaimV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedBolt11ClaimV1")
            .field("claim_envelope", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PreparedBolt11ClaimV1 {
    fn drop(&mut self) {
        self.envelope_bytes.zeroize();
    }
}

impl PreparedBolt11ClaimV1 {
    pub fn envelope_bytes(&self) -> &[u8] {
        &self.envelope_bytes
    }

    pub fn credential_request_bytes(&self) -> PirResult<Vec<u8>> {
        self.request.encode().map_err(protocol_encode_error)
    }

    pub const fn credential_request(&self) -> &CredentialIssuanceRequestV1 {
        &self.request
    }
}

fn decode_network(value: u8) -> PirResult<LightningNetworkV1> {
    match value {
        1 => Ok(LightningNetworkV1::Bitcoin),
        2 => Ok(LightningNetworkV1::Testnet),
        3 => Ok(LightningNetworkV1::Signet),
        4 => Ok(LightningNetworkV1::Regtest),
        _ => Err(PirError::Decode(
            "unsupported BOLT11 quote-key checkpoint network".into(),
        )),
    }
}

fn fixed<const N: usize>(bytes: &[u8], field: &'static str) -> PirResult<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| PirError::Decode(format!("invalid {field} length")))
}

fn protocol_decode_error(error: impl core::fmt::Display) -> PirError {
    PirError::Decode(format!("BOLT11 protocol decode failed: {error}"))
}

fn protocol_encode_error(error: impl core::fmt::Display) -> PirError {
    PirError::Encode(format!("BOLT11 protocol encode failed: {error}"))
}

fn protocol_verification_error(error: impl core::fmt::Display) -> PirError {
    PirError::VerificationFailed(format!("BOLT11 verification failed: {error}"))
}

fn payment_crypto_error(error: impl core::fmt::Display) -> PirError {
    PirError::VerificationFailed(format!("BOLT11 client cryptography failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pir_service_protocol::AuthScheme;

    const GENERATOR_COMPRESSED: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    #[test]
    fn quote_key_checkpoint_roundtrips_canonically() {
        let checkpoint = Bolt11QuoteKeyCheckpointV1::initial(
            [7; 32],
            LightningNetworkV1::Bitcoin,
            GENERATOR_COMPRESSED,
        )
        .expect("initial checkpoint");
        let encoded = checkpoint.encode();
        assert_eq!(encoded.len(), QUOTE_KEY_CHECKPOINT_LEN_V1);
        assert_eq!(
            Bolt11QuoteKeyCheckpointV1::decode(&encoded).expect("decode"),
            checkpoint,
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert!(Bolt11QuoteKeyCheckpointV1::decode(&trailing).is_err());
    }

    #[test]
    fn prepared_claim_debug_redacts_replayable_envelope() {
        assert!(core::mem::needs_drop::<PreparedBolt11ClaimV1>());
        let envelope_bytes = b"bolt11-claim-envelope-debug-canary".to_vec();
        let canary = format!("{envelope_bytes:?}");
        let claim = PreparedBolt11ClaimV1 {
            request: CredentialIssuanceRequestV1 {
                issuer_id: [1; 32],
                quote_id: [2; 32],
                quote_request_digest: [3; 32],
                authorization: AuthScheme::Bolt11DirectReceiptV1,
                credential_binding_digest: [4; 32],
                credential_key_id: vec![5; 16],
                items: CredentialIssuanceRequestItemsV1::DirectPaidReceipt,
            },
            envelope_bytes,
        };
        let rendered = format!("{claim:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&canary));
    }
}
