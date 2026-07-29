//! Local strict two-provider offer selection.
//!
//! The checks in this module consume only metadata that each provider has
//! already authenticated independently. They perform no network I/O and never
//! disclose a peer provider, pair identifier, offer, issuer, or key to either
//! server.

use pir_arc_adapter::{arc_public_key_fingerprint_v1, ARC_PUBLIC_KEY_LEN_V1};
use pir_sdk::{PirError, PirResult};
use pir_service_protocol::{
    bat_verification_key_fingerprint_v1, is_canonical_public_wss_endpoint_v1, AcquisitionMethod,
    AuthScheme, AuthorizationProofV1, ProviderId, ServiceOfferV1, VerificationMode,
    VerifiedDirectoryOperatorAssertionV1, VerifiedServiceOfferV1,
};

use crate::service::AcceptedServicePolicyV1;

/// Run a native capability retirement only after the caller's current
/// pair/channel readiness check succeeds. The second check narrows the window
/// between a durable vault transition and the authorization send; a transport
/// failure after the producer runs remains an ambiguous spend and must not be
/// retried automatically.
pub(crate) async fn produce_authorization_proof_after_ready_v1<Ready, Producer, Produced>(
    mut verify_ready: Ready,
    produce_after_ready: Producer,
) -> PirResult<AuthorizationProofV1>
where
    Ready: FnMut() -> PirResult<()>,
    Producer: FnOnce() -> Produced,
    Produced: core::future::Future<Output = PirResult<AuthorizationProofV1>>,
{
    verify_ready()?;
    let proof = produce_after_ready().await?;
    verify_ready()?;
    Ok(proof)
}

/// Explicit policy for a strict two-provider selection.
///
/// The default rejects a shared issuer ID or HTTP origin whenever both offers
/// use correlation-capable credential infrastructure. This includes free
/// anonymous tickets and online verification, not only paid acquisition.
/// Setting `allow_shared_issuer_correlation` acknowledges that the common
/// issuer can observe both credential flows; it never relaxes provider,
/// policy-key, operator-key, raw-BAT-key, or raw-ARC-key independence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StrictProviderPairOptionsV1 {
    pub allow_shared_issuer_correlation: bool,
}

/// One exact offer selected from an already accepted provider policy.
///
/// Fields are private and there is no public constructor. Obtain this state
/// only with [`select_strict_provider_offer_v1`], which revalidates policy
/// freshness and, when supplied, binds an already verified directory assertion
/// to the same provider, policy key, epoch, and digest.
#[derive(Clone, Debug)]
pub struct StrictProviderOfferSelectionV1<'policy> {
    accepted_policy: &'policy AcceptedServicePolicyV1,
    verified_offer: VerifiedServiceOfferV1<'policy>,
    directory_operator_key: Option<[u8; 32]>,
    directory_wss_endpoints: Option<Vec<String>>,
}

impl<'policy> StrictProviderOfferSelectionV1<'policy> {
    pub const fn accepted_policy(&self) -> &'policy AcceptedServicePolicyV1 {
        self.accepted_policy
    }

    pub const fn verified_offer(&self) -> &VerifiedServiceOfferV1<'policy> {
        &self.verified_offer
    }

    pub const fn provider_id(&self) -> &ProviderId {
        &self.accepted_policy.policy().provider_id
    }

    pub const fn offer(&self) -> &'policy ServiceOfferV1 {
        self.verified_offer.offer()
    }

    pub const fn directory_operator_key(&self) -> Option<[u8; 32]> {
        self.directory_operator_key
    }

    /// Canonical public WSS endpoints authenticated by the optional verified
    /// directory assertion. `None` means the caller selected this provider
    /// from a separately pinned bootstrap source and must supply the exact
    /// endpoint used by the verified transport when binding payment context.
    pub fn directory_wss_endpoints(&self) -> Option<&[String]> {
        self.directory_wss_endpoints.as_deref()
    }
}

/// A pair that passed every strict local independence check.
///
/// This typestate has private fields and no public constructor. Downstream
/// native clients can require it instead of separately accepting two offers.
/// The object contains no pair identifier and is never serialized or sent.
#[must_use]
#[derive(Clone, Debug)]
pub struct VerifiedStrictTwoProviderOfferPairV1<'first, 'second> {
    first: StrictProviderOfferSelectionV1<'first>,
    second: StrictProviderOfferSelectionV1<'second>,
    shared_issuer_correlation: bool,
}

impl<'first, 'second> VerifiedStrictTwoProviderOfferPairV1<'first, 'second> {
    pub const fn first(&self) -> &StrictProviderOfferSelectionV1<'first> {
        &self.first
    }

    pub const fn second(&self) -> &StrictProviderOfferSelectionV1<'second> {
        &self.second
    }

    /// True only when both selected offers use correlation-capable credential
    /// infrastructure, share an issuer ID or origin, and the caller explicitly
    /// acknowledged that correlation boundary.
    pub const fn shared_issuer_correlation(&self) -> bool {
        self.shared_issuer_correlation
    }

    /// Revalidate the first selected policy and exact offer against a trusted
    /// wall clock. Call this immediately before durably retiring a one-shot
    /// capability; pair-bound send helpers repeat the check at the network
    /// boundary.
    pub fn verify_first_offer_current_v1(&self, now_unix: u64) -> PirResult<()> {
        verify_pair_side_offer_current_v1(&self.first, now_unix)
    }

    /// Revalidate the second selected policy and exact offer against a trusted
    /// wall clock. Call this immediately before durably retiring a one-shot
    /// capability; pair-bound send helpers repeat the check at the network
    /// boundary.
    pub fn verify_second_offer_current_v1(&self, now_unix: u64) -> PirResult<()> {
        verify_pair_side_offer_current_v1(&self.second, now_unix)
    }
}

/// Browser- or application-trusted network and quote-key context for one
/// provider leg. BOLT11 fields must both be present for a BOLT11 offer and both
/// absent for every other acquisition method.
#[derive(Clone, Copy, Debug)]
pub struct StrictProviderPaymentContextInputV1<'input> {
    pub quote_delegation_bytes: Option<&'input [u8]>,
    pub quote_key_checkpoint: Option<&'input crate::bolt11::Bolt11QuoteKeyCheckpointV1>,
}

#[derive(Clone, Debug)]
struct FrozenProviderPaymentContextV1 {
    provider_endpoint: String,
    provider_origin: String,
    quote_delegation_bytes: Option<Vec<u8>>,
    quote_key_checkpoint: Option<crate::bolt11::Bolt11QuoteKeyCheckpointV1>,
    expected_lightning_payee_pubkey: Option<[u8; 33]>,
}

/// A strict offer pair whose two independently trusted provider origins and
/// BOLT11 quote-key streams have also been frozen and cross-checked locally.
///
/// This object is never serialized or sent. Safe quote preparation and
/// capability retirement require it so a caller cannot defer payee/origin
/// independence checks until after an invoice or one-shot token is consumed.
#[must_use]
#[derive(Clone, Debug)]
pub struct VerifiedStrictTwoProviderPaymentContextV1<'first, 'second> {
    pair: VerifiedStrictTwoProviderOfferPairV1<'first, 'second>,
    first: FrozenProviderPaymentContextV1,
    second: FrozenProviderPaymentContextV1,
}

impl<'first, 'second> VerifiedStrictTwoProviderPaymentContextV1<'first, 'second> {
    pub const fn pair(&self) -> &VerifiedStrictTwoProviderOfferPairV1<'first, 'second> {
        &self.pair
    }

    pub fn first_provider_origin(&self) -> &str {
        &self.first.provider_origin
    }

    pub fn second_provider_origin(&self) -> &str {
        &self.second.provider_origin
    }

    pub fn first_provider_endpoint(&self) -> &str {
        &self.first.provider_endpoint
    }

    pub fn second_provider_endpoint(&self) -> &str {
        &self.second.provider_endpoint
    }

    /// Decode the first provider's capability using only the exact method
    /// selected by this payment-bound pair.
    pub fn build_first_authorization_proof(
        &self,
        proof_bytes: &[u8],
    ) -> PirResult<AuthorizationProofV1> {
        build_pair_side_authorization_proof_v1(self.pair.first(), proof_bytes)
    }

    /// Decode the second provider's capability using only the exact method
    /// selected by this payment-bound pair.
    pub fn build_second_authorization_proof(
        &self,
        proof_bytes: &[u8],
    ) -> PirResult<AuthorizationProofV1> {
        build_pair_side_authorization_proof_v1(self.pair.second(), proof_bytes)
    }

    /// Prepare the first provider's independent BOLT11 quote from the
    /// delegation, payee, and rollback stream frozen into this context.
    pub fn prepare_first_bolt11_quote_v1(
        &self,
        now_unix: u64,
        claim_pubkey_xonly: [u8; 32],
        idempotency_key: [u8; 32],
    ) -> PirResult<crate::bolt11::PreparedBolt11QuoteV1> {
        prepare_frozen_pair_side_bolt11_quote_v1(
            self.pair.first(),
            &self.first,
            now_unix,
            claim_pubkey_xonly,
            idempotency_key,
        )
    }

    /// Prepare the second provider's independent BOLT11 quote from the
    /// delegation, payee, and rollback stream frozen into this context.
    pub fn prepare_second_bolt11_quote_v1(
        &self,
        now_unix: u64,
        claim_pubkey_xonly: [u8; 32],
        idempotency_key: [u8; 32],
    ) -> PirResult<crate::bolt11::PreparedBolt11QuoteV1> {
        prepare_frozen_pair_side_bolt11_quote_v1(
            self.pair.second(),
            &self.second,
            now_unix,
            claim_pubkey_xonly,
            idempotency_key,
        )
    }
}

/// Backend clients call this with the exact endpoints held by their connected
/// transports. Keeping it crate-private prevents application code from
/// inventing unrelated endpoint strings merely to satisfy the origin guard.
pub(crate) fn verify_strict_two_provider_payment_context_v1<'first, 'second>(
    pair: VerifiedStrictTwoProviderOfferPairV1<'first, 'second>,
    first_provider_endpoint: &str,
    first: StrictProviderPaymentContextInputV1<'_>,
    second_provider_endpoint: &str,
    second: StrictProviderPaymentContextInputV1<'_>,
    now_unix: u64,
) -> PirResult<VerifiedStrictTwoProviderPaymentContextV1<'first, 'second>> {
    let first =
        freeze_provider_payment_context_v1(pair.first(), first_provider_endpoint, first, now_unix)?;
    let second = freeze_provider_payment_context_v1(
        pair.second(),
        second_provider_endpoint,
        second,
        now_unix,
    )?;
    if first.provider_origin == second.provider_origin {
        return Err(pair_error(
            "strict pair privacy rejects one WebSocket origin serving both PIR roles",
        ));
    }
    if first.expected_lightning_payee_pubkey.is_some()
        && first.expected_lightning_payee_pubkey == second.expected_lightning_payee_pubkey
    {
        return Err(pair_error(
            "strict pair privacy rejects one Lightning payee observing both purchases",
        ));
    }
    Ok(VerifiedStrictTwoProviderPaymentContextV1 {
        pair,
        first,
        second,
    })
}

fn freeze_provider_payment_context_v1(
    selected: &StrictProviderOfferSelectionV1<'_>,
    provider_endpoint: &str,
    input: StrictProviderPaymentContextInputV1<'_>,
    now_unix: u64,
) -> PirResult<FrozenProviderPaymentContextV1> {
    if !is_canonical_public_wss_endpoint_v1(provider_endpoint) {
        return Err(pair_error(
            "provider endpoint is not a canonical credential-free public wss:// URL",
        ));
    }
    if let Some(directory_endpoints) = selected.directory_wss_endpoints() {
        if !directory_endpoints
            .iter()
            .any(|endpoint| endpoint == provider_endpoint)
        {
            return Err(pair_error(
                "provider endpoint is not authenticated by the verified directory assertion",
            ));
        }
    }
    let authority_end = provider_endpoint["wss://".len()..]
        .find('/')
        .map_or(provider_endpoint.len(), |offset| "wss://".len() + offset);
    let provider_origin = provider_endpoint[..authority_end].to_owned();

    let (quote_delegation_bytes, quote_key_checkpoint, expected_lightning_payee_pubkey) =
        match selected.offer().acquisition {
            AcquisitionMethod::Bolt11V1 => {
                let delegation_bytes = input.quote_delegation_bytes.ok_or_else(|| {
                    pair_error("BOLT11 offer is missing its trusted quote-key delegation")
                })?;
                let checkpoint = input.quote_key_checkpoint.ok_or_else(|| {
                    pair_error("BOLT11 offer is missing its durable quote-key checkpoint")
                })?;
                let delegation = checkpoint.verify_delegation_for_issuer_v1(
                    &selected.offer().issuer_id,
                    delegation_bytes,
                    now_unix,
                )?;
                (
                    Some(delegation_bytes.to_vec()),
                    Some(*checkpoint),
                    Some(delegation.expected_payee_pubkey),
                )
            }
            _ => {
                if input.quote_delegation_bytes.is_some() || input.quote_key_checkpoint.is_some() {
                    return Err(pair_error(
                        "non-BOLT11 offer must not carry quote-key payment context",
                    ));
                }
                (None, None, None)
            }
        };

    Ok(FrozenProviderPaymentContextV1 {
        provider_endpoint: provider_endpoint.to_owned(),
        provider_origin,
        quote_delegation_bytes,
        quote_key_checkpoint,
        expected_lightning_payee_pubkey,
    })
}

fn build_pair_side_authorization_proof_v1(
    selected: &StrictProviderOfferSelectionV1<'_>,
    proof_bytes: &[u8],
) -> PirResult<AuthorizationProofV1> {
    crate::service::dangerous_unpaired_build_authorization_proof_v1(
        selected.accepted_policy,
        &selected.verified_offer.scope().scope_id(),
        selected.offer().offer_id,
        proof_bytes,
    )
}

fn prepare_frozen_pair_side_bolt11_quote_v1(
    selected: &StrictProviderOfferSelectionV1<'_>,
    frozen: &FrozenProviderPaymentContextV1,
    now_unix: u64,
    claim_pubkey_xonly: [u8; 32],
    idempotency_key: [u8; 32],
) -> PirResult<crate::bolt11::PreparedBolt11QuoteV1> {
    let delegation = frozen.quote_delegation_bytes.as_deref().ok_or_else(|| {
        pair_error("selected payment context does not contain a BOLT11 delegation")
    })?;
    let checkpoint = frozen.quote_key_checkpoint.as_ref().ok_or_else(|| {
        pair_error("selected payment context does not contain a BOLT11 checkpoint")
    })?;
    prepare_pair_side_bolt11_quote_v1(
        selected,
        delegation,
        checkpoint,
        now_unix,
        claim_pubkey_xonly,
        idempotency_key,
    )
}

fn verify_pair_side_offer_current_v1(
    selected: &StrictProviderOfferSelectionV1<'_>,
    now_unix: u64,
) -> PirResult<()> {
    selected.accepted_policy.verify_current_offer_for_pair_v1(
        &selected.verified_offer.scope().scope_id(),
        selected.offer().offer_id,
        now_unix,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prepare_pair_side_bolt11_quote_v1(
    selected: &StrictProviderOfferSelectionV1<'_>,
    quote_delegation_bytes: &[u8],
    quote_key_checkpoint: &crate::bolt11::Bolt11QuoteKeyCheckpointV1,
    now_unix: u64,
    claim_pubkey_xonly: [u8; 32],
    idempotency_key: [u8; 32],
) -> PirResult<crate::bolt11::PreparedBolt11QuoteV1> {
    selected
        .accepted_policy
        .dangerous_unpaired_prepare_bolt11_quote_v1(
            &selected.verified_offer.scope().scope_id(),
            selected.offer().offer_id,
            quote_delegation_bytes,
            quote_key_checkpoint,
            now_unix,
            claim_pubkey_xonly,
            idempotency_key,
        )
}

/// Select one exact offer and optionally bind its verified directory assertion.
pub fn select_strict_provider_offer_v1<'policy>(
    accepted_policy: &'policy AcceptedServicePolicyV1,
    scope_id: &[u8; 32],
    offer_id: u32,
    now_unix: u64,
    directory_assertion: Option<VerifiedDirectoryOperatorAssertionV1<'_>>,
) -> PirResult<StrictProviderOfferSelectionV1<'policy>> {
    let verified_offer =
        accepted_policy.verify_current_offer_for_pair_v1(scope_id, offer_id, now_unix)?;
    let (directory_operator_key, directory_wss_endpoints) = if let Some(verified) =
        directory_assertion
    {
        let assertion = verified.assertion();
        if assertion.provider_id != accepted_policy.policy().provider_id
            || assertion.policy_signing_key_ed25519 != accepted_policy.policy_signing_key_ed25519()
            || assertion.policy_epoch != accepted_policy.policy().policy_epoch
            || assertion.policy_digest != accepted_policy.policy_digest()
        {
            return Err(pair_error(
                "verified directory assertion does not bind the selected live provider policy",
            ));
        }
        let endpoints = assertion
            .endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.transport == pir_service_protocol::DirectoryTransportV1::Wss
            })
            .map(|endpoint| endpoint.url.clone())
            .collect::<Vec<_>>();
        if endpoints.is_empty() {
            return Err(pair_error(
                "verified directory assertion contains no canonical WSS provider endpoint",
            ));
        }
        (Some(assertion.operator_pubkey_ed25519), Some(endpoints))
    } else {
        (None, None)
    };

    Ok(StrictProviderOfferSelectionV1 {
        accepted_policy,
        verified_offer,
        directory_operator_key,
        directory_wss_endpoints,
    })
}

/// Validate two independently selected provider offers and produce an
/// unforgeable local typestate on success.
pub fn verify_strict_two_provider_offer_pair_v1<'first, 'second>(
    first: StrictProviderOfferSelectionV1<'first>,
    second: StrictProviderOfferSelectionV1<'second>,
    options: StrictProviderPairOptionsV1,
) -> PirResult<VerifiedStrictTwoProviderOfferPairV1<'first, 'second>> {
    if first.provider_id() == second.provider_id() {
        return Err(pair_error(
            "the two PIR selections must use distinct provider IDs",
        ));
    }
    if first.accepted_policy.policy_signing_key_ed25519()
        == second.accepted_policy.policy_signing_key_ed25519()
    {
        return Err(pair_error(
            "the two PIR providers must not reuse one policy signing key",
        ));
    }
    if let (Some(first_operator), Some(second_operator)) =
        (first.directory_operator_key, second.directory_operator_key)
    {
        if first_operator == second_operator {
            return Err(pair_error(
                "the two PIR providers resolve to the same directory operator key",
            ));
        }
    }

    let first_bat = bat_fingerprint(first.offer())?;
    let second_bat = bat_fingerprint(second.offer())?;
    if first_bat.is_some() && first_bat == second_bat {
        return Err(pair_error(
            "the two providers reuse one raw Cashu BAT verification key",
        ));
    }
    let first_arc = arc_fingerprint(first.offer())?;
    let second_arc = arc_fingerprint(second.offer())?;
    if first_arc.is_some() && first_arc == second_arc {
        return Err(pair_error(
            "the two providers reuse one raw ARC verification key",
        ));
    }
    let first_receipt = direct_receipt_key(first.offer())?;
    let second_receipt = direct_receipt_key(second.offer())?;
    if let (Some((first_key_id, first_raw_key)), Some((second_key_id, second_raw_key))) =
        (first_receipt, second_receipt)
    {
        if first_key_id == second_key_id {
            return Err(pair_error(
                "the two providers reuse one direct-receipt verification key ID",
            ));
        }
        if first_raw_key == second_raw_key {
            return Err(pair_error(
                "the two providers reuse one raw direct-receipt verification key",
            ));
        }
    }

    let both_use_correlation_infrastructure = has_correlation_infrastructure(first.offer())
        && has_correlation_infrastructure(second.offer());
    let shared_issuer_id = both_use_correlation_infrastructure
        && first.offer().issuer_id != [0; 32]
        && first.offer().issuer_id == second.offer().issuer_id;
    let first_origin = issuer_origin(first.offer());
    let second_origin = issuer_origin(second.offer());
    let shared_origin = both_use_correlation_infrastructure
        && first_origin.is_some()
        && first_origin == second_origin;
    let shared_issuer_correlation = shared_issuer_id || shared_origin;
    if shared_issuer_correlation && !options.allow_shared_issuer_correlation {
        if shared_issuer_id {
            return Err(pair_error(
                "strict pair privacy rejects one issuer observing both credential flows",
            ));
        }
        return Err(pair_error(
            "strict pair privacy rejects one issuer HTTP origin serving both providers",
        ));
    }

    Ok(VerifiedStrictTwoProviderOfferPairV1 {
        first,
        second,
        shared_issuer_correlation,
    })
}

fn has_correlation_infrastructure(offer: &ServiceOfferV1) -> bool {
    offer.verification != VerificationMode::ProviderLocal
        || offer.acquisition != AcquisitionMethod::FreeV1
        || offer.authorization != AuthScheme::FreeV1
        || !offer.endpoint.is_empty()
        || offer.issuer_id != [0; 32]
}

fn issuer_origin(offer: &ServiceOfferV1) -> Option<&str> {
    let remainder = offer.endpoint.strip_prefix("https://")?;
    let authority_start = "https://".len();
    let origin_end = remainder
        .find('/')
        .map_or(offer.endpoint.len(), |offset| authority_start + offset);
    Some(&offer.endpoint[..origin_end])
}

fn bat_fingerprint(offer: &ServiceOfferV1) -> PirResult<Option<[u8; 32]>> {
    if offer.authorization != AuthScheme::BitcoinPirCashuBatV1 {
        return Ok(None);
    }
    let key: &[u8; 33] = offer
        .credential_binding
        .as_ref()
        .ok_or_else(|| pair_error("Cashu BAT offer is missing its credential binding"))?
        .claims
        .verification_key
        .as_slice()
        .try_into()
        .map_err(|_| pair_error("Cashu BAT offer has an invalid raw verification key"))?;
    bat_verification_key_fingerprint_v1(key)
        .map(Some)
        .map_err(|error| pair_error(format!("Cashu BAT verification key is invalid: {error}")))
}

fn arc_fingerprint(offer: &ServiceOfferV1) -> PirResult<Option<[u8; 32]>> {
    if offer.authorization != AuthScheme::ArcV1Experimental {
        return Ok(None);
    }
    // CredentialKeyBindingClaimsV1 validation already requires exactly 99
    // bytes for ARC. Keep the conversion fallible at this local trust boundary,
    // then reuse the adapter's typed decode and byte-exact re-encode check. That
    // rejects zero/identity, malformed, and non-canonical P-256 points before
    // applying the protocol's domain-separated ARC key fingerprint.
    let key: &[u8; ARC_PUBLIC_KEY_LEN_V1] = offer
        .credential_binding
        .as_ref()
        .ok_or_else(|| pair_error("ARC offer is missing its credential binding"))?
        .claims
        .verification_key
        .as_slice()
        .try_into()
        .map_err(|_| pair_error("ARC offer has an invalid raw verification key length"))?;
    arc_public_key_fingerprint_v1(key)
        .map(Some)
        .map_err(|error| pair_error(format!("ARC verification key is invalid: {error}")))
}

fn direct_receipt_key(offer: &ServiceOfferV1) -> PirResult<Option<(&[u8], &[u8])>> {
    if offer.authorization != AuthScheme::Bolt11DirectReceiptV1 {
        return Ok(None);
    }
    let binding = offer
        .credential_binding
        .as_ref()
        .ok_or_else(|| pair_error("direct-receipt offer is missing its credential binding"))?;
    if offer.key_id.is_empty() || binding.claims.verification_key.is_empty() {
        return Err(pair_error(
            "direct-receipt offer has an empty verification key identity",
        ));
    }
    Ok(Some((
        offer.key_id.as_slice(),
        binding.claims.verification_key.as_slice(),
    )))
}

fn pair_error(message: impl Into<String>) -> PirError {
    PirError::VerificationFailed(format!("strict provider pair: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{accept_service_policy_response_v1, ServicePolicyCheckpointV1};
    use ed25519_dalek::SigningKey;
    use pir_arc_adapter::{ArcSecretKeyV1, ARC_SECRET_KEY_LEN_V1};
    use pir_service_protocol::{
        derive_bat_key_id_v1, derive_provider_id, free_anonymous_ticket_key_id,
        paid_receipt_key_id, AuthPaddingClassV1, BackendId, Bolt11QuoteKeyDelegationV1,
        CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1,
        DeploymentStatus, DirectoryAssertionRollbackGuardV1, DirectoryEndpointV1,
        DirectoryOperatorAssertionV1, DirectoryTransportV1, EntitlementLimitsV1,
        FreeAuthorizationProofV1, FreeModeV1, LightningNetworkV1, PriceV1, PrivacyLeakageV1,
        ServiceOfferV1, ServicePolicyResponseV1, ServicePolicyV1, ServiceScopePolicyV1,
        ServiceScopeV1, VerificationMode, WorkloadId, RESP_SERVICE_POLICY_V1,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use zeroize::Zeroizing;

    const NOW: u64 = 150;
    const OFFER_ID: u32 = 7;

    #[tokio::test]
    async fn readiness_failure_does_not_invoke_deferred_proof_producer() {
        let producer_called = AtomicBool::new(false);
        let error = produce_authorization_proof_after_ready_v1(
            || {
                Err(PirError::VerificationFailed(
                    "stale secure-channel session".into(),
                ))
            },
            || async {
                producer_called.store(true, Ordering::SeqCst);
                Ok(AuthorizationProofV1::Free(
                    FreeAuthorizationProofV1::OpenBestEffort,
                ))
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(error, PirError::VerificationFailed(message) if
            message.contains("stale secure-channel session")));
        assert!(!producer_called.load(Ordering::SeqCst));
    }

    struct Fixture {
        accepted: AcceptedServicePolicyV1,
        scope_id: [u8; 32],
    }

    enum OfferFixture<'a> {
        Free,
        AnonymousTicket {
            issuer_seed: u8,
            endpoint: &'a str,
        },
        Receipt {
            issuer_seed: u8,
            endpoint: &'a str,
        },
        ReceiptWithVerificationSeed {
            issuer_seed: u8,
            endpoint: &'a str,
            verification_seed: u8,
        },
        Bat {
            issuer_seed: u8,
            endpoint: &'a str,
            verification_key: [u8; 33],
        },
        Arc {
            issuer_seed: u8,
            endpoint: &'a str,
            verification_key: Vec<u8>,
        },
    }

    fn limits() -> EntitlementLimitsV1 {
        EntitlementLimitsV1 {
            max_logical_inputs: 1,
            max_frames: 20,
            max_request_bytes: 1_000_000,
            max_response_bytes: 1_000_000,
            max_wall_time_ms: 10_000,
            max_concurrent_sockets: 1,
            max_hint_groups: 0,
            max_work_units: 1_000,
        }
    }

    fn fixture(provider_id: [u8; 32], policy_seed: u8, offer_fixture: OfferFixture<'_>) -> Fixture {
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 2,
        };
        let scope_id = scope.scope_id();
        let offer = match offer_fixture {
            OfferFixture::Free => ServiceOfferV1 {
                offer_id: OFFER_ID,
                acquisition: AcquisitionMethod::FreeV1,
                free_mode: FreeModeV1::OpenBestEffort,
                free_quota: 0,
                free_window_seconds: 0,
                free_pow_difficulty_bits: 0,
                priority_class: 1,
                authorization: AuthScheme::FreeV1,
                verification: VerificationMode::ProviderLocal,
                deployment_status: DeploymentStatus::Stable,
                price: PriceV1::Free,
                issuer_id: [0; 32],
                key_id: Vec::new(),
                credential_binding: None,
                cashu_mint_manifest: None,
                endpoint: String::new(),
                invoice_expiry_seconds: 0,
                claim_window_seconds: 0,
                minimum_credential_validity_seconds: 60,
                retired_policy_grace_seconds: 0,
                credential_count: 1,
                credential_presentation_limit: 1,
                privacy_leakage: PrivacyLeakageV1::NONE,
            },
            OfferFixture::AnonymousTicket {
                issuer_seed,
                endpoint,
            } => anonymous_ticket_offer(provider_id, scope_id, issuer_seed, endpoint),
            OfferFixture::Receipt {
                issuer_seed,
                endpoint,
            } => receipt_offer(provider_id, scope_id, issuer_seed, endpoint),
            OfferFixture::ReceiptWithVerificationSeed {
                issuer_seed,
                endpoint,
                verification_seed,
            } => receipt_offer_with_verification_seed(
                provider_id,
                scope_id,
                issuer_seed,
                endpoint,
                verification_seed,
            ),
            OfferFixture::Bat {
                issuer_seed,
                endpoint,
                verification_key,
            } => bat_offer(
                provider_id,
                scope_id,
                issuer_seed,
                endpoint,
                verification_key,
            ),
            OfferFixture::Arc {
                issuer_seed,
                endpoint,
                verification_key,
            } => arc_offer(
                provider_id,
                scope_id,
                issuer_seed,
                endpoint,
                verification_key,
            ),
        };
        let policy_key = SigningKey::from_bytes(&[policy_seed; 32]);
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: limits(),
                offers: vec![offer],
            }],
            &policy_key,
        )
        .unwrap();
        let encoded = ServicePolicyResponseV1 { policy }.encode().unwrap();
        let mut response = vec![RESP_SERVICE_POLICY_V1];
        response.extend_from_slice(&encoded);
        let accepted = accept_service_policy_response_v1(
            &response,
            provider_id,
            &policy_key.verifying_key(),
            NOW,
            &ServicePolicyCheckpointV1::initial(),
            [policy_seed.wrapping_add(1); 32],
        )
        .unwrap();
        Fixture { accepted, scope_id }
    }

    fn receipt_offer(
        provider_id: [u8; 32],
        scope_id: [u8; 32],
        issuer_seed: u8,
        endpoint: &str,
    ) -> ServiceOfferV1 {
        receipt_offer_with_verification_seed(
            provider_id,
            scope_id,
            issuer_seed,
            endpoint,
            provider_id[0].wrapping_add(90),
        )
    }

    fn receipt_offer_with_verification_seed(
        provider_id: [u8; 32],
        scope_id: [u8; 32],
        issuer_seed: u8,
        endpoint: &str,
        verification_seed: u8,
    ) -> ServiceOfferV1 {
        let receipt_key = SigningKey::from_bytes(&[verification_seed; 32]);
        let credential_key_id = paid_receipt_key_id(&receipt_key.verifying_key()).to_vec();
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id,
                offer_id: OFFER_ID,
                scheme: AuthScheme::Bolt11DirectReceiptV1,
                keyset_epoch: 1,
                entitlement_profile: 2,
                unit: CredentialUnitV1::Entitlement,
                amount: 1,
                presentation_limit: 1,
                not_before: 50,
                not_after: 1_500,
                credential_key_id: credential_key_id.clone(),
                verification_key: receipt_key.verifying_key().to_bytes().to_vec(),
            },
            &SigningKey::from_bytes(&[issuer_seed; 32]),
        )
        .unwrap();
        paid_offer(
            AuthScheme::Bolt11DirectReceiptV1,
            binding,
            credential_key_id,
            endpoint,
            PrivacyLeakageV1::DIRECT_PAYMENT_TO_SPEND,
        )
    }

    fn anonymous_ticket_offer(
        provider_id: [u8; 32],
        scope_id: [u8; 32],
        issuer_seed: u8,
        endpoint: &str,
    ) -> ServiceOfferV1 {
        let ticket_key = SigningKey::from_bytes(&[provider_id[0].wrapping_add(120); 32]);
        let credential_key_id = free_anonymous_ticket_key_id(&ticket_key.verifying_key()).to_vec();
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id,
                offer_id: OFFER_ID,
                scheme: AuthScheme::FreeV1,
                keyset_epoch: 1,
                entitlement_profile: 2,
                unit: CredentialUnitV1::Entitlement,
                amount: 1,
                presentation_limit: 1,
                not_before: 50,
                not_after: 1_500,
                credential_key_id: credential_key_id.clone(),
                verification_key: ticket_key.verifying_key().to_bytes().to_vec(),
            },
            &SigningKey::from_bytes(&[issuer_seed; 32]),
        )
        .unwrap();
        ServiceOfferV1 {
            offer_id: OFFER_ID,
            acquisition: AcquisitionMethod::FreeV1,
            free_mode: FreeModeV1::AnonymousTicket,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::FreeV1,
            verification: VerificationMode::SharedIssuerOnline,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::Free,
            issuer_id: binding.issuer_id,
            key_id: credential_key_id,
            credential_binding: Some(binding),
            cashu_mint_manifest: None,
            endpoint: endpoint.into(),
            invoice_expiry_seconds: 0,
            claim_window_seconds: 0,
            minimum_credential_validity_seconds: 100,
            retired_policy_grace_seconds: 1_300,
            credential_count: 1,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                    | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .unwrap(),
        }
    }

    fn bat_offer(
        provider_id: [u8; 32],
        scope_id: [u8; 32],
        issuer_seed: u8,
        endpoint: &str,
        verification_key: [u8; 33],
    ) -> ServiceOfferV1 {
        let credential_key_id =
            derive_bat_key_id_v1(&provider_id, &scope_id, OFFER_ID, 2, 1, &verification_key)
                .to_vec();
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id,
                offer_id: OFFER_ID,
                scheme: AuthScheme::BitcoinPirCashuBatV1,
                keyset_epoch: 1,
                entitlement_profile: 2,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 1,
                not_before: 50,
                not_after: 1_500,
                credential_key_id: credential_key_id.clone(),
                verification_key: verification_key.to_vec(),
            },
            &SigningKey::from_bytes(&[issuer_seed; 32]),
        )
        .unwrap();
        paid_offer(
            AuthScheme::BitcoinPirCashuBatV1,
            binding,
            credential_key_id,
            endpoint,
            PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                | PrivacyLeakageV1::PROVIDER_LOCAL_BEARER
                | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
        )
    }

    fn paid_offer(
        authorization: AuthScheme,
        binding: CredentialKeyBindingV1,
        credential_key_id: Vec<u8>,
        endpoint: &str,
        leakage: u16,
    ) -> ServiceOfferV1 {
        ServiceOfferV1 {
            offer_id: OFFER_ID,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization,
            verification: VerificationMode::ProviderLocal,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::MilliSatoshi(1_000),
            issuer_id: binding.issuer_id,
            key_id: credential_key_id,
            credential_binding: Some(binding),
            cashu_mint_manifest: None,
            endpoint: endpoint.into(),
            invoice_expiry_seconds: 600,
            claim_window_seconds: 600,
            minimum_credential_validity_seconds: 100,
            retired_policy_grace_seconds: 1_300,
            credential_count: 1,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(leakage).unwrap(),
        }
    }

    fn arc_offer(
        provider_id: [u8; 32],
        scope_id: [u8; 32],
        issuer_seed: u8,
        endpoint: &str,
        verification_key: Vec<u8>,
    ) -> ServiceOfferV1 {
        let credential_key_id = vec![issuer_seed; 16];
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id,
                offer_id: OFFER_ID,
                scheme: AuthScheme::ArcV1Experimental,
                keyset_epoch: 1,
                entitlement_profile: 2,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 10,
                not_before: 50,
                not_after: 1_500,
                credential_key_id: credential_key_id.clone(),
                verification_key,
            },
            &SigningKey::from_bytes(&[issuer_seed; 32]),
        )
        .unwrap();
        ServiceOfferV1 {
            offer_id: OFFER_ID,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::ArcV1Experimental,
            verification: VerificationMode::ProviderLocal,
            deployment_status: DeploymentStatus::Experimental,
            price: PriceV1::MilliSatoshi(1_000),
            issuer_id: binding.issuer_id,
            key_id: credential_key_id,
            credential_binding: Some(binding),
            cashu_mint_manifest: None,
            endpoint: endpoint.into(),
            invoice_expiry_seconds: 600,
            claim_window_seconds: 600,
            minimum_credential_validity_seconds: 100,
            retired_policy_grace_seconds: 1_300,
            credential_count: 1,
            credential_presentation_limit: 10,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                    | PrivacyLeakageV1::PROVIDER_LOCAL_BEARER
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .unwrap(),
        }
    }

    fn arc_public_key(seed: u8) -> [u8; ARC_PUBLIC_KEY_LEN_V1] {
        let mut secret = [0u8; ARC_SECRET_KEY_LEN_V1];
        for component in 0..4 {
            secret[component * 32 + 31] = seed.wrapping_add(component as u8);
        }
        *ArcSecretKeyV1::from_zeroizing_bytes(vec![seed], Zeroizing::new(secret))
            .unwrap()
            .public_key_bytes()
    }

    fn select(fixture: &Fixture) -> StrictProviderOfferSelectionV1<'_> {
        select_strict_provider_offer_v1(&fixture.accepted, &fixture.scope_id, OFFER_ID, NOW, None)
            .unwrap()
    }

    fn select_with_operator<'policy>(
        fixture: &'policy Fixture,
        operator: &SigningKey,
        stable_server_id: &str,
        endpoint: &str,
    ) -> StrictProviderOfferSelectionV1<'policy> {
        let assertion = directory_assertion(fixture, operator, stable_server_id, endpoint);
        let verified = assertion
            .verify_current_for(
                &fixture.accepted.policy().provider_id,
                &operator.verifying_key().to_bytes(),
                NOW,
                &DirectoryAssertionRollbackGuardV1::initial(),
            )
            .unwrap();
        select_strict_provider_offer_v1(
            &fixture.accepted,
            &fixture.scope_id,
            OFFER_ID,
            NOW,
            Some(verified),
        )
        .unwrap()
    }

    fn verify_error(
        first: StrictProviderOfferSelectionV1<'_>,
        second: StrictProviderOfferSelectionV1<'_>,
        options: StrictProviderPairOptionsV1,
    ) -> String {
        verify_strict_two_provider_offer_pair_v1(first, second, options)
            .unwrap_err()
            .to_string()
    }

    fn point(hex_value: &str) -> [u8; 33] {
        hex::decode(hex_value).unwrap().try_into().unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn bolt_payment_context<'first, 'second>(
        pair: VerifiedStrictTwoProviderOfferPairV1<'first, 'second>,
        first_issuer_seed: u8,
        first_payee: [u8; 33],
        first_endpoint: &str,
        second_issuer_seed: u8,
        second_payee: [u8; 33],
        second_endpoint: &str,
    ) -> PirResult<VerifiedStrictTwoProviderPaymentContextV1<'first, 'second>> {
        let first_delegation = Bolt11QuoteKeyDelegationV1::sign(
            LightningNetworkV1::Regtest,
            first_payee,
            1,
            100,
            200,
            SigningKey::from_bytes(&[81; 32]).verifying_key().to_bytes(),
            &SigningKey::from_bytes(&[first_issuer_seed; 32]),
        )
        .unwrap()
        .encode()
        .unwrap();
        let second_delegation = Bolt11QuoteKeyDelegationV1::sign(
            LightningNetworkV1::Regtest,
            second_payee,
            1,
            100,
            200,
            SigningKey::from_bytes(&[82; 32]).verifying_key().to_bytes(),
            &SigningKey::from_bytes(&[second_issuer_seed; 32]),
        )
        .unwrap()
        .encode()
        .unwrap();
        let first_checkpoint = crate::bolt11::Bolt11QuoteKeyCheckpointV1::initial(
            pair.first().offer().issuer_id,
            LightningNetworkV1::Regtest,
            first_payee,
        )?;
        let second_checkpoint = crate::bolt11::Bolt11QuoteKeyCheckpointV1::initial(
            pair.second().offer().issuer_id,
            LightningNetworkV1::Regtest,
            second_payee,
        )?;
        verify_strict_two_provider_payment_context_v1(
            pair,
            first_endpoint,
            StrictProviderPaymentContextInputV1 {
                quote_delegation_bytes: Some(&first_delegation),
                quote_key_checkpoint: Some(&first_checkpoint),
            },
            second_endpoint,
            StrictProviderPaymentContextInputV1 {
                quote_delegation_bytes: Some(&second_delegation),
                quote_key_checkpoint: Some(&second_checkpoint),
            },
            NOW,
        )
    }

    #[test]
    fn accepts_independent_paid_and_free_pairs() {
        let first = fixture(
            [1; 32],
            11,
            OfferFixture::Receipt {
                issuer_seed: 31,
                endpoint: "https://issuer-a.example",
            },
        );
        let second = fixture(
            [2; 32],
            12,
            OfferFixture::Receipt {
                issuer_seed: 32,
                endpoint: "https://issuer-b.example",
            },
        );
        let pair = verify_strict_two_provider_offer_pair_v1(
            select(&first),
            select(&second),
            StrictProviderPairOptionsV1::default(),
        )
        .unwrap();
        assert!(!pair.shared_issuer_correlation());
        assert_eq!(pair.first().provider_id(), &[1; 32]);
        pair.verify_first_offer_current_v1(NOW).unwrap();
        pair.verify_second_offer_current_v1(NOW).unwrap();
        assert!(pair.verify_first_offer_current_v1(201).is_err());
        assert!(pair.verify_second_offer_current_v1(201).is_err());

        let free_first = fixture([3; 32], 13, OfferFixture::Free);
        let free_second = fixture([4; 32], 14, OfferFixture::Free);
        let free_pair = verify_strict_two_provider_offer_pair_v1(
            select(&free_first),
            select(&free_second),
            StrictProviderPairOptionsV1::default(),
        )
        .unwrap();
        assert!(matches!(
            verify_strict_two_provider_payment_context_v1(
                free_pair,
                "wss://free-a.example/v1",
                StrictProviderPaymentContextInputV1 {
                    quote_delegation_bytes: None,
                    quote_key_checkpoint: None,
                },
                "wss://free-b.example/v1",
                StrictProviderPaymentContextInputV1 {
                    quote_delegation_bytes: None,
                    quote_key_checkpoint: None,
                },
                NOW,
            )
            .unwrap()
            .build_first_authorization_proof(&[])
            .unwrap(),
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::OpenBestEffort)
        ));
        let free_pair = verify_strict_two_provider_offer_pair_v1(
            select(&free_first),
            select(&free_second),
            StrictProviderPairOptionsV1::default(),
        )
        .unwrap();
        assert!(matches!(
            verify_strict_two_provider_payment_context_v1(
                free_pair,
                "wss://free-a.example/v1",
                StrictProviderPaymentContextInputV1 {
                    quote_delegation_bytes: None,
                    quote_key_checkpoint: None,
                },
                "wss://free-b.example/v1",
                StrictProviderPaymentContextInputV1 {
                    quote_delegation_bytes: None,
                    quote_key_checkpoint: None,
                },
                NOW,
            )
            .unwrap()
            .build_second_authorization_proof(&[])
            .unwrap(),
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::OpenBestEffort)
        ));
    }

    #[test]
    fn rejects_same_provider_or_policy_signing_key() {
        let first = fixture([1; 32], 11, OfferFixture::Free);
        let same_provider = fixture([1; 32], 12, OfferFixture::Free);
        assert!(verify_error(
            select(&first),
            select(&same_provider),
            StrictProviderPairOptionsV1::default(),
        )
        .contains("distinct provider IDs"));

        let same_policy_key = fixture([2; 32], 11, OfferFixture::Free);
        assert!(verify_error(
            select(&first),
            select(&same_policy_key),
            StrictProviderPairOptionsV1::default(),
        )
        .contains("policy signing key"));
    }

    #[test]
    fn shared_paid_issuer_or_origin_requires_explicit_opt_in() {
        let first = fixture(
            [1; 32],
            11,
            OfferFixture::Receipt {
                issuer_seed: 31,
                endpoint: "https://issuer-a.example",
            },
        );
        let same_issuer = fixture(
            [2; 32],
            12,
            OfferFixture::Receipt {
                issuer_seed: 31,
                endpoint: "https://issuer-b.example",
            },
        );
        assert!(verify_error(
            select(&first),
            select(&same_issuer),
            StrictProviderPairOptionsV1::default(),
        )
        .contains("one issuer"));
        let allowed = verify_strict_two_provider_offer_pair_v1(
            select(&first),
            select(&same_issuer),
            StrictProviderPairOptionsV1 {
                allow_shared_issuer_correlation: true,
            },
        )
        .unwrap();
        assert!(allowed.shared_issuer_correlation());

        let same_origin = fixture(
            [3; 32],
            13,
            OfferFixture::Receipt {
                issuer_seed: 33,
                endpoint: "https://issuer-a.example",
            },
        );
        assert!(verify_error(
            select(&first),
            select(&same_origin),
            StrictProviderPairOptionsV1::default(),
        )
        .contains("HTTP origin"));
        assert!(verify_strict_two_provider_offer_pair_v1(
            select(&first),
            select(&same_origin),
            StrictProviderPairOptionsV1 {
                allow_shared_issuer_correlation: true,
            },
        )
        .is_ok());
    }

    #[test]
    fn shared_free_anonymous_ticket_issuer_or_origin_requires_explicit_opt_in() {
        let first = fixture(
            [1; 32],
            11,
            OfferFixture::AnonymousTicket {
                issuer_seed: 31,
                endpoint: "https://issuer-a.example",
            },
        );
        let same_issuer = fixture(
            [2; 32],
            12,
            OfferFixture::AnonymousTicket {
                issuer_seed: 31,
                endpoint: "https://issuer-b.example",
            },
        );
        assert!(verify_error(
            select(&first),
            select(&same_issuer),
            StrictProviderPairOptionsV1::default(),
        )
        .contains("both credential flows"));

        let same_origin = fixture(
            [3; 32],
            13,
            OfferFixture::AnonymousTicket {
                issuer_seed: 33,
                endpoint: "https://issuer-a.example",
            },
        );
        assert!(verify_error(
            select(&first),
            select(&same_origin),
            StrictProviderPairOptionsV1::default(),
        )
        .contains("HTTP origin"));
    }

    #[test]
    fn paid_and_free_external_flows_share_the_same_pair_guard() {
        let paid = fixture(
            [1; 32],
            11,
            OfferFixture::Receipt {
                issuer_seed: 31,
                endpoint: "https://issuer-a.example",
            },
        );
        let free_same_issuer = fixture(
            [2; 32],
            12,
            OfferFixture::AnonymousTicket {
                issuer_seed: 31,
                endpoint: "https://issuer-b.example",
            },
        );
        assert!(verify_error(
            select(&paid),
            select(&free_same_issuer),
            StrictProviderPairOptionsV1::default(),
        )
        .contains("both credential flows"));

        let free_independent = fixture(
            [3; 32],
            13,
            OfferFixture::AnonymousTicket {
                issuer_seed: 32,
                endpoint: "https://issuer-c.example",
            },
        );
        assert!(verify_strict_two_provider_offer_pair_v1(
            select(&paid),
            select(&free_independent),
            StrictProviderPairOptionsV1::default(),
        )
        .is_ok());
    }

    #[test]
    fn copied_bat_raw_key_is_rejected_even_when_shared_issuer_is_allowed() {
        let raw_key = point("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let first = fixture(
            [1; 32],
            11,
            OfferFixture::Bat {
                issuer_seed: 31,
                endpoint: "https://issuer-a.example",
                verification_key: raw_key,
            },
        );
        let second = fixture(
            [2; 32],
            12,
            OfferFixture::Bat {
                issuer_seed: 32,
                endpoint: "https://issuer-b.example",
                verification_key: raw_key,
            },
        );
        assert!(verify_error(
            select(&first),
            select(&second),
            StrictProviderPairOptionsV1 {
                allow_shared_issuer_correlation: true,
            },
        )
        .contains("raw Cashu BAT verification key"));
    }

    #[test]
    fn copied_direct_receipt_key_is_rejected_even_when_shared_issuer_is_allowed() {
        let first = fixture(
            [1; 32],
            11,
            OfferFixture::ReceiptWithVerificationSeed {
                issuer_seed: 31,
                endpoint: "https://issuer-a.example",
                verification_seed: 91,
            },
        );
        let second = fixture(
            [2; 32],
            12,
            OfferFixture::ReceiptWithVerificationSeed {
                issuer_seed: 32,
                endpoint: "https://issuer-b.example",
                verification_seed: 91,
            },
        );
        assert!(verify_error(
            select(&first),
            select(&second),
            StrictProviderPairOptionsV1 {
                allow_shared_issuer_correlation: true,
            },
        )
        .contains("direct-receipt verification key ID"));
    }

    #[test]
    fn payment_context_rejects_shared_payee_and_provider_origin_even_with_issuer_opt_in() {
        let first = fixture(
            [1; 32],
            11,
            OfferFixture::Receipt {
                issuer_seed: 31,
                endpoint: "https://issuer-a.example",
            },
        );
        let second = fixture(
            [2; 32],
            12,
            OfferFixture::Receipt {
                issuer_seed: 32,
                endpoint: "https://issuer-b.example",
            },
        );
        let generator = point("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let twice_generator =
            point("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        let pair = verify_strict_two_provider_offer_pair_v1(
            select(&first),
            select(&second),
            StrictProviderPairOptionsV1 {
                allow_shared_issuer_correlation: true,
            },
        )
        .unwrap();
        assert!(bolt_payment_context(
            pair.clone(),
            31,
            generator,
            "wss://provider-a.example/v1",
            32,
            generator,
            "wss://provider-b.example/v1",
        )
        .unwrap_err()
        .to_string()
        .contains("Lightning payee"));

        assert!(bolt_payment_context(
            pair,
            31,
            generator,
            "wss://shared-provider.example/first",
            32,
            twice_generator,
            "wss://shared-provider.example/second",
        )
        .unwrap_err()
        .to_string()
        .contains("WebSocket origin"));
    }

    #[test]
    fn independent_payment_context_prepares_quote_from_frozen_payee_stream() {
        let first = fixture(
            [1; 32],
            11,
            OfferFixture::Receipt {
                issuer_seed: 31,
                endpoint: "https://issuer-a.example",
            },
        );
        let second = fixture(
            [2; 32],
            12,
            OfferFixture::Receipt {
                issuer_seed: 32,
                endpoint: "https://issuer-b.example",
            },
        );
        let first_payee =
            point("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let second_payee =
            point("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        let pair = verify_strict_two_provider_offer_pair_v1(
            select(&first),
            select(&second),
            StrictProviderPairOptionsV1::default(),
        )
        .unwrap();
        let context = bolt_payment_context(
            pair,
            31,
            first_payee,
            "wss://provider-a.example/v1",
            32,
            second_payee,
            "wss://provider-b.example/v1",
        )
        .unwrap();
        assert_eq!(context.first_provider_origin(), "wss://provider-a.example");
        assert_eq!(context.second_provider_origin(), "wss://provider-b.example");
        let mut claim = [0u8; 32];
        claim.copy_from_slice(&first_payee[1..]);
        let prepared = context
            .prepare_first_bolt11_quote_v1(NOW, claim, [9; 32])
            .unwrap();
        assert_eq!(prepared.intent().expected_payee_pubkey, first_payee);
    }

    #[test]
    fn accepts_independent_arc_raw_keys_and_operator_keys() {
        let first_operator = SigningKey::from_bytes(&[71; 32]);
        let second_operator = SigningKey::from_bytes(&[72; 32]);
        let first_provider =
            derive_provider_id(&first_operator.verifying_key().to_bytes(), "arc-provider-a");
        let second_provider = derive_provider_id(
            &second_operator.verifying_key().to_bytes(),
            "arc-provider-b",
        );
        let first = fixture(
            first_provider,
            11,
            OfferFixture::Arc {
                issuer_seed: 31,
                endpoint: "https://issuer-a.example",
                verification_key: arc_public_key(1).to_vec(),
            },
        );
        let second = fixture(
            second_provider,
            12,
            OfferFixture::Arc {
                issuer_seed: 32,
                endpoint: "https://issuer-b.example",
                verification_key: arc_public_key(9).to_vec(),
            },
        );

        let pair = verify_strict_two_provider_offer_pair_v1(
            select_with_operator(
                &first,
                &first_operator,
                "arc-provider-a",
                "wss://provider-a.example",
            ),
            select_with_operator(
                &second,
                &second_operator,
                "arc-provider-b",
                "wss://provider-b.example",
            ),
            StrictProviderPairOptionsV1::default(),
        )
        .unwrap();
        assert!(!pair.shared_issuer_correlation());
    }

    #[test]
    fn copied_arc_raw_key_is_rejected_across_independent_operators_and_issuers() {
        let first_operator = SigningKey::from_bytes(&[73; 32]);
        let second_operator = SigningKey::from_bytes(&[74; 32]);
        let first_provider =
            derive_provider_id(&first_operator.verifying_key().to_bytes(), "arc-provider-a");
        let second_provider = derive_provider_id(
            &second_operator.verifying_key().to_bytes(),
            "arc-provider-b",
        );
        let raw_key = arc_public_key(17);
        let first = fixture(
            first_provider,
            11,
            OfferFixture::Arc {
                issuer_seed: 31,
                endpoint: "https://issuer-a.example",
                verification_key: raw_key.to_vec(),
            },
        );
        let second = fixture(
            second_provider,
            12,
            OfferFixture::Arc {
                issuer_seed: 32,
                endpoint: "https://issuer-b.example",
                verification_key: raw_key.to_vec(),
            },
        );

        assert!(verify_error(
            select_with_operator(
                &first,
                &first_operator,
                "arc-provider-a",
                "wss://provider-a.example",
            ),
            select_with_operator(
                &second,
                &second_operator,
                "arc-provider-b",
                "wss://provider-b.example",
            ),
            StrictProviderPairOptionsV1 {
                allow_shared_issuer_correlation: true,
            },
        )
        .contains("raw ARC verification key"));
    }

    #[test]
    fn copied_arc_raw_key_is_rejected_before_shared_issuer_override() {
        let raw_key = arc_public_key(21);
        let first = fixture(
            [1; 32],
            11,
            OfferFixture::Arc {
                issuer_seed: 31,
                endpoint: "https://shared-issuer.example",
                verification_key: raw_key.to_vec(),
            },
        );
        let second = fixture(
            [2; 32],
            12,
            OfferFixture::Arc {
                issuer_seed: 31,
                endpoint: "https://shared-issuer.example",
                verification_key: raw_key.to_vec(),
            },
        );

        assert!(verify_error(
            select(&first),
            select(&second),
            StrictProviderPairOptionsV1 {
                allow_shared_issuer_correlation: true,
            },
        )
        .contains("raw ARC verification key"));
    }

    #[test]
    fn arc_fingerprint_rejects_wrong_length_zero_and_noncanonical_keys() {
        let canonical = arc_public_key(25);
        let mut offer = arc_offer(
            [1; 32],
            [2; 32],
            31,
            "https://issuer-a.example",
            canonical.to_vec(),
        );
        assert!(arc_fingerprint(&offer).unwrap().is_some());

        offer
            .credential_binding
            .as_mut()
            .unwrap()
            .claims
            .verification_key
            .truncate(ARC_PUBLIC_KEY_LEN_V1 - 1);
        assert!(arc_fingerprint(&offer)
            .unwrap_err()
            .to_string()
            .contains("invalid raw verification key length"));

        offer
            .credential_binding
            .as_mut()
            .unwrap()
            .claims
            .verification_key = vec![0; ARC_PUBLIC_KEY_LEN_V1];
        assert!(arc_fingerprint(&offer)
            .unwrap_err()
            .to_string()
            .contains("ARC verification key is invalid"));

        let mut noncanonical = canonical;
        noncanonical[0] = 0x04;
        offer
            .credential_binding
            .as_mut()
            .unwrap()
            .claims
            .verification_key = noncanonical.to_vec();
        assert!(arc_fingerprint(&offer)
            .unwrap_err()
            .to_string()
            .contains("ARC verification key is invalid"));
    }

    #[test]
    fn verified_directory_operator_key_is_compared_only_when_both_are_present() {
        let operator = SigningKey::from_bytes(&[77; 32]);
        let first_provider = derive_provider_id(&operator.verifying_key().to_bytes(), "pir-a");
        let second_provider = derive_provider_id(&operator.verifying_key().to_bytes(), "pir-b");
        let first = fixture(first_provider, 11, OfferFixture::Free);
        let second = fixture(second_provider, 12, OfferFixture::Free);
        let first_assertion = directory_assertion(&first, &operator, "pir-a", "wss://a.example");
        let second_assertion = directory_assertion(&second, &operator, "pir-b", "wss://b.example");
        let first_verified = first_assertion
            .verify_current_for(
                &first_provider,
                &operator.verifying_key().to_bytes(),
                NOW,
                &DirectoryAssertionRollbackGuardV1::initial(),
            )
            .unwrap();
        let second_verified = second_assertion
            .verify_current_for(
                &second_provider,
                &operator.verifying_key().to_bytes(),
                NOW,
                &DirectoryAssertionRollbackGuardV1::initial(),
            )
            .unwrap();
        let selected_first = select_strict_provider_offer_v1(
            &first.accepted,
            &first.scope_id,
            OFFER_ID,
            NOW,
            Some(first_verified),
        )
        .unwrap();
        let selected_second = select_strict_provider_offer_v1(
            &second.accepted,
            &second.scope_id,
            OFFER_ID,
            NOW,
            Some(second_verified),
        )
        .unwrap();
        assert!(verify_error(
            selected_first.clone(),
            selected_second,
            StrictProviderPairOptionsV1::default(),
        )
        .contains("same directory operator key"));

        assert!(verify_strict_two_provider_offer_pair_v1(
            selected_first,
            select(&second),
            StrictProviderPairOptionsV1::default(),
        )
        .is_ok());
    }

    #[test]
    fn payment_context_endpoint_must_be_authenticated_by_bound_directory_assertion() {
        let first_operator = SigningKey::from_bytes(&[75; 32]);
        let second_operator = SigningKey::from_bytes(&[76; 32]);
        let first_provider =
            derive_provider_id(&first_operator.verifying_key().to_bytes(), "provider-a");
        let second_provider =
            derive_provider_id(&second_operator.verifying_key().to_bytes(), "provider-b");
        let first = fixture(first_provider, 11, OfferFixture::Free);
        let second = fixture(second_provider, 12, OfferFixture::Free);
        let pair = verify_strict_two_provider_offer_pair_v1(
            select_with_operator(
                &first,
                &first_operator,
                "provider-a",
                "wss://provider-a.example/v1",
            ),
            select_with_operator(
                &second,
                &second_operator,
                "provider-b",
                "wss://provider-b.example/v1",
            ),
            StrictProviderPairOptionsV1::default(),
        )
        .unwrap();
        let error = verify_strict_two_provider_payment_context_v1(
            pair,
            "wss://forged-a.example/v1",
            StrictProviderPaymentContextInputV1 {
                quote_delegation_bytes: None,
                quote_key_checkpoint: None,
            },
            "wss://provider-b.example/v1",
            StrictProviderPaymentContextInputV1 {
                quote_delegation_bytes: None,
                quote_key_checkpoint: None,
            },
            NOW,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("not authenticated by the verified directory assertion"));
    }

    fn directory_assertion(
        fixture: &Fixture,
        operator: &SigningKey,
        stable_server_id: &str,
        endpoint: &str,
    ) -> DirectoryOperatorAssertionV1 {
        DirectoryOperatorAssertionV1::sign(
            stable_server_id.into(),
            1,
            100,
            200,
            vec![DirectoryEndpointV1 {
                transport: DirectoryTransportV1::Wss,
                url: endpoint.into(),
            }],
            fixture.accepted.policy_signing_key_ed25519(),
            fixture.accepted.policy().policy_epoch,
            fixture.accepted.policy_digest(),
            operator,
        )
        .unwrap()
    }
}
