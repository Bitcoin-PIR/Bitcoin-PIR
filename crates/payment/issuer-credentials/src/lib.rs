//! Fail-closed credential signing after a verified BOLT11 settlement.
//!
//! This crate prepares an exact response, but never authorizes its release.
//! The application must commit that response with the issuer store while the
//! quote is in a settled state and release bytes only after the durable commit
//! (or an exact replay) succeeds.

#![forbid(unsafe_code)]

use core::fmt;
use std::collections::HashSet;

use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use pir_arc_adapter::{ArcAdapterErrorV1, ArcSecretKeyringV1};
use pir_payment_crypto::{
    verify_quote_claim_v1, K256CashuDleqVerifierV1, K256CashuMintKeyringV1, PaymentCryptoError,
    VerifiedBip340ClaimV1,
};
use pir_service_protocol::{
    AuthScheme, BitcoinPirCashuBatIssuanceResponseItemV1, Bolt11QuoteClaimV1, Bolt11QuoteStatusV1,
    CheckedCredentialIssuanceResponseV1, CredentialIssuanceRequestItemsV1,
    CredentialIssuanceRequestV1, CredentialIssuanceResponseItemsV1, CredentialIssuanceResponseV1,
    CredentialKeyBindingExpectationV1, CredentialKeyBindingV1, PaidReceiptBindingV1, PaidReceiptV1,
    ServiceProtocolError, VerifiedBolt11QuoteV1,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const DIRECT_SERIAL_DERIVATION_DOMAIN_V1: &[u8] = b"BitcoinPIR/issuer-credential/direct-serial/v1";
const BAT_DLEQ_NONCE_DERIVATION_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-credential/bat-dleq-nonce/v1";
const ARC_RESPONSE_RNG_DERIVATION_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-credential/arc-response-rng/v1";
const MAX_DERIVATION_ATTEMPTS_V1: u32 = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IssuerCredentialErrorV1 {
    Protocol(ServiceProtocolError),
    Crypto(PaymentCryptoError),
    Arc(ArcAdapterErrorV1),
    WrongIssuanceMethod,
    WrongPreparedResponseVariant,
    DerivationKeyIsZero,
    DerivationExhausted,
}

impl fmt::Display for IssuerCredentialErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "credential protocol check failed: {error}"),
            Self::Crypto(error) => write!(formatter, "credential cryptography failed: {error}"),
            Self::Arc(error) => write!(formatter, "experimental ARC issuance failed: {error}"),
            Self::WrongIssuanceMethod => formatter.write_str("wrong credential issuance method"),
            Self::WrongPreparedResponseVariant => {
                formatter.write_str("prepared response has the wrong credential variant")
            }
            Self::DerivationKeyIsZero => formatter.write_str("credential derivation key is zero"),
            Self::DerivationExhausted => {
                formatter.write_str("credential derivation exhausted its safety bound")
            }
        }
    }
}

impl std::error::Error for IssuerCredentialErrorV1 {}

impl From<ServiceProtocolError> for IssuerCredentialErrorV1 {
    fn from(error: ServiceProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<PaymentCryptoError> for IssuerCredentialErrorV1 {
    fn from(error: PaymentCryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<ArcAdapterErrorV1> for IssuerCredentialErrorV1 {
    fn from(error: ArcAdapterErrorV1) -> Self {
        Self::Arc(error)
    }
}

/// Secret PRF key used for response reconstruction without an RNG journal.
///
/// This value is deliberately non-cloneable, zeroized on drop, and redacted
/// from `Debug`. Key custody must treat it like a BAT denomination secret.
pub struct IssuerCredentialDerivationKeyV1 {
    key: Zeroizing<[u8; 32]>,
}

impl IssuerCredentialDerivationKeyV1 {
    pub fn from_bytes(mut key: [u8; 32]) -> Result<Self, IssuerCredentialErrorV1> {
        if key.iter().all(|byte| *byte == 0) {
            key.zeroize();
            return Err(IssuerCredentialErrorV1::DerivationKeyIsZero);
        }
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }

    fn derive(
        &self,
        domain: &[u8],
        quote_id: &[u8; 32],
        credential_request_digest: &[u8; 32],
        item_index: u32,
        item_binding: &[u8],
        attempt: u32,
    ) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.as_ref())
            .expect("HMAC-SHA256 accepts every key length");
        update_len_prefixed(&mut mac, domain);
        update_len_prefixed(&mut mac, quote_id);
        update_len_prefixed(&mut mac, credential_request_digest);
        mac.update(&item_index.to_le_bytes());
        update_len_prefixed(&mut mac, item_binding);
        mac.update(&attempt.to_le_bytes());
        mac.finalize().into_bytes().into()
    }
}

impl fmt::Debug for IssuerCredentialDerivationKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuerCredentialDerivationKeyV1")
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Evidence that the exact claim signature, settled quote, credential key
/// binding, response envelope, and method-specific credentials were checked.
/// Private fields prevent replacing the checks with a caller assertion.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedCredentialClaimV1 {
    bip340: VerifiedBip340ClaimV1,
}

impl VerifiedCredentialClaimV1 {
    pub const fn bip340_message_digest(&self) -> &[u8; 32] {
        self.bip340.message_digest()
    }

    pub const fn claim_pubkey_xonly(&self) -> &[u8; 32] {
        self.bip340.claim_pubkey_xonly()
    }
}

/// Prepared response whose cryptography has been checked, but whose release
/// is not authorized until the issuer store durably commits the exact bytes.
pub struct PreparedCredentialIssuanceV1 {
    response: CredentialIssuanceResponseV1,
    verified_claim: VerifiedCredentialClaimV1,
}

impl PreparedCredentialIssuanceV1 {
    pub const fn response(&self) -> &CredentialIssuanceResponseV1 {
        &self.response
    }

    pub const fn verified_claim(&self) -> &VerifiedCredentialClaimV1 {
        &self.verified_claim
    }

    pub fn encode_response(&self) -> Result<Vec<u8>, IssuerCredentialErrorV1> {
        Ok(self.response.encode()?)
    }
}

impl fmt::Debug for PreparedCredentialIssuanceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedCredentialIssuanceV1")
            .field("authorization", &self.response.authorization)
            .field("item_count", &response_item_count(&self.response.items))
            .finish_non_exhaustive()
    }
}

/// Prepare linkable single-use receipts for a settled direct-BOLT11 quote.
/// No response bytes may be released until the caller commits them durably.
pub fn prepare_direct_receipt_issuance_v1(
    request: &CredentialIssuanceRequestV1,
    claim: &Bolt11QuoteClaimV1,
    verified_quote: &VerifiedBolt11QuoteV1<'_>,
    credential_binding: &CredentialKeyBindingV1,
    signing_key: &SigningKey,
    derivation_key: &IssuerCredentialDerivationKeyV1,
    now_unix: u64,
) -> Result<PreparedCredentialIssuanceV1, IssuerCredentialErrorV1> {
    if request.authorization != AuthScheme::Bolt11DirectReceiptV1
        || !matches!(
            &request.items,
            CredentialIssuanceRequestItemsV1::DirectPaidReceipt
        )
    {
        return Err(IssuerCredentialErrorV1::WrongIssuanceMethod);
    }
    let bip340 = verify_request_claim_v1(request, claim, verified_quote, now_unix)?;
    let quote = verified_quote.quote();
    let intent = verified_quote.intent();
    let request_digest = request.request_digest()?;
    let count = usize::try_from(intent.credential_count)
        .map_err(|_| IssuerCredentialErrorV1::DerivationExhausted)?;
    let mut seen = HashSet::with_capacity(count);
    let mut receipts = Vec::with_capacity(count);
    for index in 0..count {
        let index =
            u32::try_from(index).map_err(|_| IssuerCredentialErrorV1::DerivationExhausted)?;
        let serial = derive_unique_nonzero_v1(
            derivation_key,
            DIRECT_SERIAL_DERIVATION_DOMAIN_V1,
            &quote.quote_id,
            &request_digest,
            index,
            signing_key.verifying_key().as_bytes(),
            &mut seen,
        )?;
        receipts.push(PaidReceiptV1::sign(
            intent.issuer_id,
            serial,
            PaidReceiptBindingV1 {
                scope_id: intent.scope_id,
                offer_id: intent.offer_id,
                policy_digest: intent.policy_digest,
                entitlement_profile: intent.entitlement_profile,
            },
            quote.status_updated_at,
            quote.credential_not_after,
            signing_key,
        )?);
    }
    let response = response_envelope_v1(
        request,
        request_digest,
        CredentialIssuanceResponseItemsV1::DirectPaidReceipts(receipts),
    );
    let verified_claim = verify_prepared_response_v1(
        claim,
        request,
        &response,
        verified_quote,
        credential_binding,
        now_unix,
    )?;
    if verified_claim.bip340_message_digest() != bip340.message_digest() {
        return Err(IssuerCredentialErrorV1::WrongPreparedResponseVariant);
    }
    Ok(PreparedCredentialIssuanceV1 {
        response,
        verified_claim,
    })
}

/// Prepare blind BAT signatures and NUT-12 proofs for a settled quote.
/// The wallet blinding scalar is neither accepted nor derivable by this API.
pub fn prepare_cashu_bat_issuance_v1(
    request: &CredentialIssuanceRequestV1,
    claim: &Bolt11QuoteClaimV1,
    verified_quote: &VerifiedBolt11QuoteV1<'_>,
    credential_binding: &CredentialKeyBindingV1,
    keyring: &K256CashuMintKeyringV1,
    derivation_key: &IssuerCredentialDerivationKeyV1,
    now_unix: u64,
) -> Result<PreparedCredentialIssuanceV1, IssuerCredentialErrorV1> {
    let requests = match &request.items {
        CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(requests)
            if request.authorization == AuthScheme::BitcoinPirCashuBatV1 =>
        {
            requests
        }
        _ => return Err(IssuerCredentialErrorV1::WrongIssuanceMethod),
    };
    let bip340 = verify_request_claim_v1(request, claim, verified_quote, now_unix)?;
    let request_digest = request.request_digest()?;
    let issuer_public_key: [u8; 33] = credential_binding
        .claims
        .verification_key
        .as_slice()
        .try_into()
        .map_err(|_| IssuerCredentialErrorV1::WrongIssuanceMethod)?;
    let mut used_nonce_fingerprints = HashSet::with_capacity(requests.len());
    let mut responses = Vec::with_capacity(requests.len());
    for (index, item) in requests.iter().enumerate() {
        let index =
            u32::try_from(index).map_err(|_| IssuerCredentialErrorV1::DerivationExhausted)?;
        let response = derive_and_blind_sign_v1(
            keyring,
            derivation_key,
            &issuer_public_key,
            &verified_quote.quote().quote_id,
            &request_digest,
            index,
            &item.blinded_message,
            &mut used_nonce_fingerprints,
        )?;
        responses.push(BitcoinPirCashuBatIssuanceResponseItemV1 {
            blinded_message: item.blinded_message,
            blinded_signature: *response.blinded_signature(),
            dleq_e: *response.dleq_e(),
            dleq_s: *response.dleq_s(),
        });
    }
    let response = response_envelope_v1(
        request,
        request_digest,
        CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(responses),
    );
    let verified_claim = verify_prepared_response_v1(
        claim,
        request,
        &response,
        verified_quote,
        credential_binding,
        now_unix,
    )?;
    if verified_claim.bip340_message_digest() != bip340.message_digest() {
        return Err(IssuerCredentialErrorV1::WrongPreparedResponseVariant);
    }
    Ok(PreparedCredentialIssuanceV1 {
        response,
        verified_claim,
    })
}

/// Prepare deterministic experimental ARC responses for a settled quote.
///
/// Deterministic per-item RNG seeds allow exact reconstruction after a crash
/// before the response is durably committed. The seed is domain-separated by
/// quote, exact issuance request, item index, and canonical ARC request. ARC
/// remains experimental regardless of this functional issuance path.
pub fn prepare_arc_issuance_v1(
    request: &CredentialIssuanceRequestV1,
    claim: &Bolt11QuoteClaimV1,
    verified_quote: &VerifiedBolt11QuoteV1<'_>,
    credential_binding: &CredentialKeyBindingV1,
    keyring: &ArcSecretKeyringV1,
    derivation_key: &IssuerCredentialDerivationKeyV1,
    now_unix: u64,
) -> Result<PreparedCredentialIssuanceV1, IssuerCredentialErrorV1> {
    let requests = match &request.items {
        CredentialIssuanceRequestItemsV1::ArcExperimental(requests)
            if request.authorization == AuthScheme::ArcV1Experimental =>
        {
            requests
        }
        _ => return Err(IssuerCredentialErrorV1::WrongIssuanceMethod),
    };
    let bip340 = verify_request_claim_v1(request, claim, verified_quote, now_unix)?;
    let request_digest = request.request_digest()?;
    let quote = verified_quote.quote();
    let intent = verified_quote.intent();
    let expectation = CredentialKeyBindingExpectationV1 {
        issuer_id: &intent.issuer_id,
        provider_id: &intent.provider_id,
        scope_id: &intent.scope_id,
        offer_id: intent.offer_id,
        scheme: AuthScheme::ArcV1Experimental,
        minimum_keyset_epoch: credential_binding.claims.keyset_epoch,
        entitlement_profile: intent.entitlement_profile,
        presentation_limit: intent.credential_presentation_limit,
        credential_key_id: &intent.credential_key_id,
    };
    let mut responses = Vec::with_capacity(requests.len());
    for (index, item) in requests.iter().enumerate() {
        let index =
            u32::try_from(index).map_err(|_| IssuerCredentialErrorV1::DerivationExhausted)?;
        let seed = derivation_key.derive(
            ARC_RESPONSE_RNG_DERIVATION_DOMAIN_V1,
            &quote.quote_id,
            &request_digest,
            index,
            item.as_bytes(),
            0,
        );
        let mut rng = ChaCha20Rng::from_seed(seed);
        responses.push(keyring.issue_credential_response(
            credential_binding,
            &expectation,
            now_unix,
            item,
            &mut rng,
        )?);
    }
    let response = response_envelope_v1(
        request,
        request_digest,
        CredentialIssuanceResponseItemsV1::ArcExperimental(responses),
    );
    match response.verify_for_verified_quote(request, verified_quote, credential_binding)? {
        CheckedCredentialIssuanceResponseV1::ArcExperimental { pending_finalize }
            if pending_finalize.len() == requests.len() => {}
        _ => return Err(IssuerCredentialErrorV1::WrongPreparedResponseVariant),
    }
    Ok(PreparedCredentialIssuanceV1 {
        response,
        verified_claim: VerifiedCredentialClaimV1 { bip340 },
    })
}

/// Verify an exact direct-receipt or BAT claim without access to issuer secret
/// keys. This is suitable for the `IssuerStore::record_claim` verifier
/// callback; the caller must additionally compare the callback's supplied
/// digest with `bip340_message_digest()` before returning `true`.
pub fn verify_prepared_response_v1(
    claim: &Bolt11QuoteClaimV1,
    request: &CredentialIssuanceRequestV1,
    response: &CredentialIssuanceResponseV1,
    verified_quote: &VerifiedBolt11QuoteV1<'_>,
    credential_binding: &CredentialKeyBindingV1,
    now_unix: u64,
) -> Result<VerifiedCredentialClaimV1, IssuerCredentialErrorV1> {
    let bip340 = verify_request_claim_v1(request, claim, verified_quote, now_unix)?;
    match response.verify_for_verified_quote(request, verified_quote, credential_binding)? {
        CheckedCredentialIssuanceResponseV1::DirectPaidReceipts(_)
            if request.authorization == AuthScheme::Bolt11DirectReceiptV1 => {}
        CheckedCredentialIssuanceResponseV1::BitcoinPirCashuBat { unverified_dleq }
            if request.authorization == AuthScheme::BitcoinPirCashuBatV1 =>
        {
            let verifier = K256CashuDleqVerifierV1;
            for tuple in unverified_dleq {
                verifier.verify(
                    &tuple.issuer_public_key,
                    &tuple.blinded_message,
                    &tuple.blinded_signature,
                    &tuple.dleq_e,
                    &tuple.dleq_s,
                )?;
            }
        }
        _ => return Err(IssuerCredentialErrorV1::WrongPreparedResponseVariant),
    }
    Ok(VerifiedCredentialClaimV1 { bip340 })
}

fn verify_request_claim_v1(
    request: &CredentialIssuanceRequestV1,
    claim: &Bolt11QuoteClaimV1,
    verified_quote: &VerifiedBolt11QuoteV1<'_>,
    now_unix: u64,
) -> Result<VerifiedBip340ClaimV1, IssuerCredentialErrorV1> {
    if !matches!(
        verified_quote.quote().status,
        Bolt11QuoteStatusV1::PaymentSettled | Bolt11QuoteStatusV1::LateSettledReconcile
    ) {
        return Err(IssuerCredentialErrorV1::WrongIssuanceMethod);
    }
    verified_quote.ensure_claim_submission_at(now_unix)?;
    let unverified = request.verify_for_verified_quote(claim, verified_quote, now_unix)?;
    Ok(verify_quote_claim_v1(&unverified)?)
}

fn response_envelope_v1(
    request: &CredentialIssuanceRequestV1,
    request_digest: [u8; 32],
    items: CredentialIssuanceResponseItemsV1,
) -> CredentialIssuanceResponseV1 {
    CredentialIssuanceResponseV1 {
        issuer_id: request.issuer_id,
        quote_id: request.quote_id,
        quote_request_digest: request.quote_request_digest,
        credential_request_digest: request_digest,
        authorization: request.authorization,
        credential_binding_digest: request.credential_binding_digest,
        credential_key_id: request.credential_key_id.clone(),
        items,
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_and_blind_sign_v1(
    keyring: &K256CashuMintKeyringV1,
    derivation_key: &IssuerCredentialDerivationKeyV1,
    issuer_public_key: &[u8; 33],
    quote_id: &[u8; 32],
    request_digest: &[u8; 32],
    index: u32,
    blinded_message: &[u8; 33],
    used_nonce_fingerprints: &mut HashSet<[u8; 32]>,
) -> Result<pir_payment_crypto::CashuBlindSignatureWithDleqV1, IssuerCredentialErrorV1> {
    for attempt in 0..MAX_DERIVATION_ATTEMPTS_V1 {
        let mut nonce = derivation_key.derive(
            BAT_DLEQ_NONCE_DERIVATION_DOMAIN_V1,
            quote_id,
            request_digest,
            index,
            blinded_message,
            attempt,
        );
        let nonce_fingerprint: [u8; 32] = Sha256::digest(nonce.as_slice()).into();
        if nonce.iter().all(|byte| *byte == 0)
            || used_nonce_fingerprints.contains(&nonce_fingerprint)
        {
            nonce.zeroize();
            continue;
        }
        let signed = keyring.blind_sign_with_dleq_v1(issuer_public_key, blinded_message, &nonce);
        nonce.zeroize();
        match signed {
            Ok(response) => {
                used_nonce_fingerprints.insert(nonce_fingerprint);
                return Ok(response);
            }
            Err(PaymentCryptoError::InvalidCashuScalar)
            | Err(PaymentCryptoError::CashuDleqResponseScalarInvalid) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(IssuerCredentialErrorV1::DerivationExhausted)
}

#[allow(clippy::too_many_arguments)]
fn derive_unique_nonzero_v1(
    derivation_key: &IssuerCredentialDerivationKeyV1,
    domain: &[u8],
    quote_id: &[u8; 32],
    request_digest: &[u8; 32],
    index: u32,
    item_binding: &[u8],
    seen: &mut HashSet<[u8; 32]>,
) -> Result<[u8; 32], IssuerCredentialErrorV1> {
    for attempt in 0..MAX_DERIVATION_ATTEMPTS_V1 {
        let value = derivation_key.derive(
            domain,
            quote_id,
            request_digest,
            index,
            item_binding,
            attempt,
        );
        if value.iter().any(|byte| *byte != 0) && seen.insert(value) {
            return Ok(value);
        }
    }
    Err(IssuerCredentialErrorV1::DerivationExhausted)
}

fn update_len_prefixed(mac: &mut Hmac<Sha256>, value: &[u8]) {
    mac.update(&(value.len() as u64).to_le_bytes());
    mac.update(value);
}

fn response_item_count(items: &CredentialIssuanceResponseItemsV1) -> usize {
    match items {
        CredentialIssuanceResponseItemsV1::DirectPaidReceipts(items) => items.len(),
        CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(items) => items.len(),
        CredentialIssuanceResponseItemsV1::ArcExperimental(items) => items.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc::group::serialize_scalar;
    use arc::setup_server;
    use pir_arc_adapter::{create_arc_credential_request, ArcSecretKeyV1, ARC_SECRET_KEY_LEN_V1};
    use pir_lightning_backend::{
        CreateInvoiceRequestV1, FakeLightningNodeV1, LightningInvoiceBackendV1,
    };
    use pir_payment_crypto::{
        blind_cashu_message_v1, sign_bip340_prehash_v1, verify_and_unblind_cashu_promise_v1,
    };
    use pir_service_protocol::{
        derive_bat_key_id_v1, paid_receipt_key_id, AcquisitionMethod, AuthPaddingClassV1,
        BackendId, Bolt11QuoteIntentV1, Bolt11QuoteKeyDelegationV1, Bolt11QuoteKeyRollbackGuardV1,
        CredentialIssuanceRequestItemsV1, CredentialKeyBindingClaimsV1, CredentialUnitV1,
        DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, FreeModeV1, LightningNetworkV1,
        ParsedBolt11InvoiceV1, PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1,
        ServicePolicyEpochFloorsV1, ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1,
        VerificationMode, WorkloadId,
    };

    const CREATED_AT: u64 = 1_700_000_000;
    const CLAIM_AT: u64 = CREATED_AT + 10;

    struct Fixture {
        scheme: AuthScheme,
        binding: CredentialKeyBindingV1,
        intent: Bolt11QuoteIntentV1,
        quote: pir_service_protocol::Bolt11QuoteV1,
        delegation: Bolt11QuoteKeyDelegationV1,
        parsed_invoice: ParsedBolt11InvoiceV1,
        direct_key: SigningKey,
        bat_keyring: K256CashuMintKeyringV1,
        arc_keyring: ArcSecretKeyringV1,
        claim_secret: [u8; 32],
        bat_wallet_inputs: Vec<(Vec<u8>, [u8; 32])>,
    }

    impl Fixture {
        fn verified_quote(&self) -> VerifiedBolt11QuoteV1<'_> {
            self.quote
                .verify_for_claim_submission(
                    &self.intent,
                    &self.delegation,
                    &self.parsed_invoice,
                    CLAIM_AT,
                )
                .unwrap()
        }

        fn request(&self) -> CredentialIssuanceRequestV1 {
            let items = match self.scheme {
                AuthScheme::Bolt11DirectReceiptV1 => {
                    CredentialIssuanceRequestItemsV1::DirectPaidReceipt
                }
                AuthScheme::BitcoinPirCashuBatV1 => {
                    CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(
                        self.bat_wallet_inputs
                            .iter()
                            .map(|(secret, scalar)| {
                                pir_service_protocol::BitcoinPirCashuBatIssuanceRequestItemV1 {
                                    blinded_message: blind_cashu_message_v1(secret, scalar)
                                        .unwrap(),
                                }
                            })
                            .collect(),
                    )
                }
                AuthScheme::ArcV1Experimental => unreachable!(
                    "ARC requests retain client finalize state and are constructed by the test"
                ),
                _ => unreachable!(),
            };
            CredentialIssuanceRequestV1 {
                issuer_id: self.intent.issuer_id,
                quote_id: self.quote.quote_id,
                quote_request_digest: self.quote.request_digest,
                authorization: self.scheme,
                credential_binding_digest: self.intent.credential_binding_digest,
                credential_key_id: self.intent.credential_key_id.clone(),
                items,
            }
        }

        fn claim(&self, request: &CredentialIssuanceRequestV1) -> Bolt11QuoteClaimV1 {
            let mut claim = Bolt11QuoteClaimV1 {
                issuer_id: self.intent.issuer_id,
                quote_id: self.quote.quote_id,
                quote_request_digest: self.quote.request_digest,
                credential_request_digest: request.request_digest().unwrap(),
                claim_pubkey_xonly: self.intent.claim_pubkey_xonly,
                idempotency_key: [51; 32],
                // The canonical claim validator rejects an all-zero signature
                // before exposing the signature-independent digest.
                signature: [1; 64],
            };
            let digest = claim.bip340_signing_digest().unwrap();
            let (public_key, signature) =
                sign_bip340_prehash_v1(&self.claim_secret, &digest, &[52; 32]).unwrap();
            assert_eq!(public_key, self.intent.claim_pubkey_xonly);
            claim.signature = signature;
            claim
        }
    }

    fn fixture(scheme: AuthScheme) -> Fixture {
        let provider_id = [2; 32];
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 3,
        };
        let scope_id = scope.scope_id();
        let offer_id = 9;
        let issuer_root = SigningKey::from_bytes(&[7; 32]);
        let direct_key = SigningKey::from_bytes(&[21; 32]);
        let bat_keyring = K256CashuMintKeyringV1::from_secret_keys([[13; 32]]).unwrap();
        let bat_public_key = bat_keyring.denomination_public_keys()[0];
        let mut arc_rng = ChaCha20Rng::from_seed([14; 32]);
        let (arc_secret, arc_public) = setup_server(&mut arc_rng);
        let mut arc_secret_bytes = Zeroizing::new([0u8; ARC_SECRET_KEY_LEN_V1]);
        arc_secret_bytes[0..32].copy_from_slice(&serialize_scalar(&arc_secret.x0));
        arc_secret_bytes[32..64].copy_from_slice(&serialize_scalar(&arc_secret.x1));
        arc_secret_bytes[64..96].copy_from_slice(&serialize_scalar(&arc_secret.x2));
        arc_secret_bytes[96..128].copy_from_slice(&serialize_scalar(&arc_secret.x0_blinding));
        let arc_key_id = vec![0xa7; 16];
        let arc_key =
            ArcSecretKeyV1::from_zeroizing_bytes(arc_key_id.clone(), arc_secret_bytes).unwrap();
        assert_eq!(arc_key.public_key_bytes(), &arc_public.to_bytes());
        let arc_keyring = ArcSecretKeyringV1::new(vec![arc_key]).unwrap();
        let (credential_key_id, verification_key, unit) = match scheme {
            AuthScheme::Bolt11DirectReceiptV1 => (
                paid_receipt_key_id(&direct_key.verifying_key()).to_vec(),
                direct_key.verifying_key().to_bytes().to_vec(),
                CredentialUnitV1::Entitlement,
            ),
            AuthScheme::BitcoinPirCashuBatV1 => (
                derive_bat_key_id_v1(
                    &provider_id,
                    &scope_id,
                    offer_id,
                    scope.entitlement_profile,
                    1,
                    &bat_public_key,
                )
                .to_vec(),
                bat_public_key.to_vec(),
                CredentialUnitV1::Auth,
            ),
            AuthScheme::ArcV1Experimental => (
                arc_key_id,
                arc_public.to_bytes().to_vec(),
                CredentialUnitV1::Auth,
            ),
            _ => unreachable!(),
        };
        let presentation_limit = if scheme == AuthScheme::ArcV1Experimental {
            4
        } else {
            1
        };
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id,
                offer_id,
                scheme,
                keyset_epoch: 1,
                entitlement_profile: scope.entitlement_profile,
                unit,
                amount: 1,
                presentation_limit,
                not_before: CREATED_AT - 100,
                not_after: CREATED_AT + 20_000,
                credential_key_id: credential_key_id.clone(),
                verification_key,
            },
            &issuer_root,
        )
        .unwrap();
        let required_privacy = match scheme {
            AuthScheme::Bolt11DirectReceiptV1 => PrivacyLeakageV1::DIRECT_PAYMENT_TO_SPEND,
            AuthScheme::BitcoinPirCashuBatV1 => {
                PrivacyLeakageV1::PROVIDER_LOCAL_BEARER
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER
                    | PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
            }
            AuthScheme::ArcV1Experimental => {
                PrivacyLeakageV1::PROVIDER_LOCAL_BEARER
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER
                    | PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
            }
            _ => unreachable!(),
        };
        let offer = ServiceOfferV1 {
            offer_id,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: scheme,
            verification: VerificationMode::ProviderLocal,
            deployment_status: if scheme == AuthScheme::ArcV1Experimental {
                DeploymentStatus::Experimental
            } else {
                DeploymentStatus::Stable
            },
            price: PriceV1::MilliSatoshi(100_000),
            issuer_id: binding.issuer_id,
            key_id: credential_key_id,
            credential_binding: Some(binding.clone()),
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".into(),
            invoice_expiry_seconds: 600,
            claim_window_seconds: 900,
            minimum_credential_validity_seconds: 3_600,
            retired_policy_grace_seconds: 20_000,
            credential_count: 2,
            credential_presentation_limit: presentation_limit,
            privacy_leakage: PrivacyLeakageV1::from_bits(required_privacy).unwrap(),
        };
        let provider_policy_key = SigningKey::from_bytes(&[22; 32]);
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            CREATED_AT - 100,
            CREATED_AT + 10_000,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 10,
                    max_request_bytes: 10_000,
                    max_response_bytes: 20_000,
                    max_wall_time_ms: 5_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 100,
                },
                offers: vec![offer],
            }],
            &provider_policy_key,
        )
        .unwrap();
        let verified_policy = policy
            .verify_current_for_acquisition(
                &provider_id,
                CREATED_AT,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &provider_policy_key.verifying_key(),
            )
            .unwrap();
        let verified_offer = verified_policy.offer(&scope_id, offer_id).unwrap();

        let node =
            FakeLightningNodeV1::new(LightningNetworkV1::Bitcoin, [23; 32], [24; 32], CREATED_AT)
                .unwrap();
        let quote_key = SigningKey::from_bytes(&[25; 32]);
        let delegation = Bolt11QuoteKeyDelegationV1::sign(
            LightningNetworkV1::Bitcoin,
            node.payee_pubkey(),
            1,
            CREATED_AT - 100,
            CREATED_AT + 20_000,
            quote_key.verifying_key().to_bytes(),
            &issuer_root,
        )
        .unwrap();
        let rollback = Bolt11QuoteKeyRollbackGuardV1::initial(
            binding.issuer_id,
            LightningNetworkV1::Bitcoin,
            node.payee_pubkey(),
        )
        .unwrap();
        let claim_secret = [26; 32];
        let (claim_pubkey_xonly, _) =
            sign_bip340_prehash_v1(&claim_secret, &[27; 32], &[28; 32]).unwrap();
        let (intent, _) = Bolt11QuoteIntentV1::from_verified_offer_guarded(
            &verified_offer,
            &delegation,
            &rollback,
            CREATED_AT,
            claim_pubkey_xonly,
            [29; 32],
        )
        .unwrap();
        let invoice_request = CreateInvoiceRequestV1 {
            backend_label: format!("bpir-v1-{}", "ab".repeat(32)),
            network: LightningNetworkV1::Bitcoin,
            expected_payee_pubkey: node.payee_pubkey(),
            amount_msat: intent.exact_amount_msat,
            expiry_seconds: intent.invoice_expiry_seconds,
            description_hash: [30; 32],
        };
        let invoice = node.create_or_get_invoice(&invoice_request).unwrap();
        let parsed_invoice = ParsedBolt11InvoiceV1::parse(&invoice.invoice).unwrap();
        let verified_intent = intent
            .verify_for_offer_guarded(&verified_offer, &delegation, &rollback, CREATED_AT)
            .unwrap();
        let open_quote = pir_service_protocol::Bolt11QuoteV1::sign_for_verified_intent(
            &verified_intent,
            [31; 32],
            invoice.invoice,
            &parsed_invoice,
            Bolt11QuoteStatusV1::InvoiceOpen,
            CREATED_AT,
            &quote_key,
        )
        .unwrap();
        let verified_open = open_quote
            .verify_snapshot(&intent, &delegation, &parsed_invoice, CREATED_AT + 1)
            .unwrap();
        let quote = pir_service_protocol::Bolt11QuoteV1::with_status_from_verified_snapshot(
            &verified_open,
            Bolt11QuoteStatusV1::PaymentSettled,
            CREATED_AT + 5,
            &delegation,
            &quote_key,
        )
        .unwrap();

        Fixture {
            scheme,
            binding,
            intent,
            quote,
            delegation,
            parsed_invoice,
            direct_key,
            bat_keyring,
            arc_keyring,
            claim_secret,
            bat_wallet_inputs: vec![
                (b"wallet-secret-one".to_vec(), [32; 32]),
                (b"wallet-secret-two".to_vec(), [33; 32]),
            ],
        }
    }

    #[test]
    fn direct_receipts_are_exact_deterministic_and_claim_bound() {
        let fixture = fixture(AuthScheme::Bolt11DirectReceiptV1);
        let request = fixture.request();
        let claim = fixture.claim(&request);
        let derivation = IssuerCredentialDerivationKeyV1::from_bytes([40; 32]).unwrap();
        let first = prepare_direct_receipt_issuance_v1(
            &request,
            &claim,
            &fixture.verified_quote(),
            &fixture.binding,
            &fixture.direct_key,
            &derivation,
            CLAIM_AT,
        )
        .unwrap();
        let second = prepare_direct_receipt_issuance_v1(
            &request,
            &claim,
            &fixture.verified_quote(),
            &fixture.binding,
            &fixture.direct_key,
            &derivation,
            CLAIM_AT,
        )
        .unwrap();
        assert_eq!(
            first.encode_response().unwrap(),
            second.encode_response().unwrap()
        );
        match &first.response().items {
            CredentialIssuanceResponseItemsV1::DirectPaidReceipts(receipts) => {
                assert_eq!(receipts.len(), 2);
                assert_ne!(receipts[0].serial, receipts[1].serial);
                assert_eq!(receipts[0].not_before, CREATED_AT + 5);
            }
            _ => panic!("wrong response variant"),
        }

        let mut tampered_claim = claim;
        tampered_claim.signature[0] ^= 1;
        assert!(prepare_direct_receipt_issuance_v1(
            &request,
            &tampered_claim,
            &fixture.verified_quote(),
            &fixture.binding,
            &fixture.direct_key,
            &derivation,
            CLAIM_AT,
        )
        .is_err());
        assert!(!format!("{derivation:?}").contains(&"28".repeat(32)));
    }

    #[test]
    fn bat_issuance_is_blind_deterministic_and_wallet_verifiable() {
        let fixture = fixture(AuthScheme::BitcoinPirCashuBatV1);
        let request = fixture.request();
        let claim = fixture.claim(&request);
        let derivation = IssuerCredentialDerivationKeyV1::from_bytes([41; 32]).unwrap();
        let first = prepare_cashu_bat_issuance_v1(
            &request,
            &claim,
            &fixture.verified_quote(),
            &fixture.binding,
            &fixture.bat_keyring,
            &derivation,
            CLAIM_AT,
        )
        .unwrap();
        let second = prepare_cashu_bat_issuance_v1(
            &request,
            &claim,
            &fixture.verified_quote(),
            &fixture.binding,
            &fixture.bat_keyring,
            &derivation,
            CLAIM_AT,
        )
        .unwrap();
        assert_eq!(
            first.encode_response().unwrap(),
            second.encode_response().unwrap()
        );
        let public_key = fixture.bat_keyring.denomination_public_keys()[0];
        let responses = match &first.response().items {
            CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(responses) => responses,
            _ => panic!("wrong response variant"),
        };
        for ((secret, scalar), response) in fixture.bat_wallet_inputs.iter().zip(responses) {
            let unblinded = verify_and_unblind_cashu_promise_v1(
                secret,
                scalar,
                &public_key,
                &response.blinded_message,
                &response.blinded_signature,
                &response.dleq_e,
                &response.dleq_s,
            )
            .unwrap();
            fixture
                .bat_keyring
                .verify_raw_cashu_signature(&public_key, secret, unblinded.unblinded_signature())
                .unwrap();
        }

        let mut tampered = first.response().clone();
        if let CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(items) = &mut tampered.items {
            items[0].dleq_s[0] ^= 1;
        }
        assert!(verify_prepared_response_v1(
            &claim,
            &request,
            &tampered,
            &fixture.verified_quote(),
            &fixture.binding,
            CLAIM_AT,
        )
        .is_err());
    }

    #[test]
    fn arc_issuance_is_deterministic_and_each_wallet_finalizes_experimentally() {
        let fixture = fixture(AuthScheme::ArcV1Experimental);
        let expectation = CredentialKeyBindingExpectationV1 {
            issuer_id: &fixture.binding.issuer_id,
            provider_id: &fixture.binding.claims.provider_id,
            scope_id: &fixture.binding.claims.scope_id,
            offer_id: fixture.binding.claims.offer_id,
            scheme: AuthScheme::ArcV1Experimental,
            minimum_keyset_epoch: fixture.binding.claims.keyset_epoch,
            entitlement_profile: fixture.binding.claims.entitlement_profile,
            presentation_limit: fixture.binding.claims.presentation_limit,
            credential_key_id: &fixture.binding.claims.credential_key_id,
        };
        let mut rng = ChaCha20Rng::from_seed([61; 32]);
        let mut pending = Vec::new();
        let mut requests = Vec::new();
        for _ in 0..fixture.intent.credential_count {
            let (request, state) =
                create_arc_credential_request(&fixture.binding, &expectation, CLAIM_AT, &mut rng)
                    .unwrap();
            requests.push(request);
            pending.push(state);
        }
        let request = CredentialIssuanceRequestV1 {
            issuer_id: fixture.intent.issuer_id,
            quote_id: fixture.quote.quote_id,
            quote_request_digest: fixture.quote.request_digest,
            authorization: AuthScheme::ArcV1Experimental,
            credential_binding_digest: fixture.intent.credential_binding_digest,
            credential_key_id: fixture.intent.credential_key_id.clone(),
            items: CredentialIssuanceRequestItemsV1::ArcExperimental(requests),
        };
        let claim = fixture.claim(&request);
        let derivation = IssuerCredentialDerivationKeyV1::from_bytes([62; 32]).unwrap();
        let first = prepare_arc_issuance_v1(
            &request,
            &claim,
            &fixture.verified_quote(),
            &fixture.binding,
            &fixture.arc_keyring,
            &derivation,
            CLAIM_AT,
        )
        .unwrap();
        let second = prepare_arc_issuance_v1(
            &request,
            &claim,
            &fixture.verified_quote(),
            &fixture.binding,
            &fixture.arc_keyring,
            &derivation,
            CLAIM_AT,
        )
        .unwrap();
        assert_eq!(
            first.encode_response().unwrap(),
            second.encode_response().unwrap()
        );
        let finalize_pairs = match first
            .response()
            .verify_for_verified_quote(&request, &fixture.verified_quote(), &fixture.binding)
            .unwrap()
        {
            CheckedCredentialIssuanceResponseV1::ArcExperimental { pending_finalize } => {
                pending_finalize
            }
            _ => panic!("wrong response variant"),
        };
        assert_eq!(finalize_pairs.len(), pending.len());
        for (state, pair) in pending.into_iter().zip(&finalize_pairs) {
            let credential = state
                .finalize(&fixture.binding, &expectation, CLAIM_AT, pair)
                .unwrap();
            assert_ne!(credential.credential_id(), &[0; 32]);
        }
    }

    #[test]
    fn derivation_key_rejects_zero_and_redacts_debug() {
        assert_eq!(
            IssuerCredentialDerivationKeyV1::from_bytes([0; 32]).unwrap_err(),
            IssuerCredentialErrorV1::DerivationKeyIsZero
        );
        let key = IssuerCredentialDerivationKeyV1::from_bytes([0x5a; 32]).unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains(&"5a".repeat(32)));
    }
}
