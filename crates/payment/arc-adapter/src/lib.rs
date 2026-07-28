//! Experimental ARC draft-01 adapters for BitcoinPIR.
//!
//! The protocol crate treats ARC payloads as opaque bytes behind typed
//! canonicalizer traits. This crate is the only place where those bytes are
//! upgraded into objects from the pinned ARC implementation.

#![forbid(unsafe_code)]

use core::fmt;

use arc::group::{deserialize_element, deserialize_scalar, serialize_element, serialize_scalar};
use arc::group::{generator_g, generator_h, hash_to_scalar};
use arc::request::verify_credential_request_proof;
use arc::{
    create_credential_request, create_credential_response, finalize_credential,
    make_presentation_state, present, verify_presentation, ClientSecrets, Credential,
    CredentialRequest, CredentialResponse, Presentation, PresentationState, ServerPrivateKey,
    ServerPublicKey,
};
use pir_service_protocol::{
    arc_provider_global_spend_key_v1, ArcCredentialRequestV1, ArcCredentialResponseV1,
    ArcIssuanceCanonicalizerV1 as ProtocolArcIssuanceCanonicalizerV1,
    ArcPresentationCanonicalizerV1 as ProtocolArcPresentationCanonicalizerV1, ArcPresentationV1,
    AuthScheme, CredentialKeyBindingExpectationV1, CredentialKeyBindingV1,
    PendingArcCredentialFinalizeV1, ServiceProtocolError, MAX_CREDENTIAL_KEY_ID_LEN,
    MAX_CREDENTIAL_PRESENTATIONS_V1,
};
#[cfg(feature = "provider-store")]
use pir_service_protocol::{
    AuthorizationProofV1, BoundAuthAttemptV1, DeploymentStatus, VerificationMode,
    VerifiedServiceOfferV1,
};
#[cfg(feature = "provider-store")]
use pir_service_store::{
    ArcExclusiveKeyLineageVerifierV1, ArcPresentationSpendVerifierV1, ArcVerifiedSpendSinkV1,
    ExclusiveKeyLineage,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const ARC_SECRET_KEY_LEN_V1: usize = 128;
pub const ARC_PUBLIC_KEY_LEN_V1: usize = 99;
pub const ARC_TAG_LEN_V1: usize = pir_service_protocol::ARC_CANONICAL_TAG_LEN_V1;

pub const ARC_PUBLIC_KEY_FINGERPRINT_DOMAIN_V1: &[u8] = b"BitcoinPIR/arc-public-key-fingerprint/v1";
pub const ARC_EXCLUSIVE_KEY_LINEAGE_DOMAIN_V1: &[u8] = b"BitcoinPIR/arc-exclusive-key-lineage/v1";
pub const ARC_SPEND_KEY_DOMAIN_V1: &[u8] =
    pir_service_protocol::ARC_PROVIDER_GLOBAL_SPEND_KEY_DOMAIN_V1;
pub const ARC_CLIENT_CREDENTIAL_ID_DOMAIN_V1: &[u8] = b"BitcoinPIR/arc-client-credential-id/v1";
pub const ARC_CLIENT_STATE_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/arc-client-state-digest/v1";

const ARC_CLIENT_STATE_VERSION_V1: u8 = 1;
const ARC_CLIENT_STATE_LEN_V1: usize = 1 + 32 + 32 + 8 + 8 + 32 + (3 * 33);
const ARC_PENDING_REQUEST_VERSION_V1: u8 = 1;
const ARC_PENDING_REQUEST_LEN_V1: usize =
    1 + 32 + 32 + pir_service_protocol::ARC_CREDENTIAL_REQUEST_LEN_V1 + (4 * 32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArcAdapterErrorV1 {
    InvalidBinding,
    BindingExpired,
    WrongScheme,
    InvalidPublicKey,
    SecretKeyMalformed,
    SecretKeyDoesNotMatchBinding,
    DuplicateKeyId,
    DuplicatePublicKey,
    KeyNotFound,
    InvalidCredentialRequest,
    InvalidCredentialResponse,
    CredentialPairMismatch,
    CredentialFinalizationFailed,
    InvalidPresentation,
    PresentationVerificationFailed,
    UnsupportedPresentationLimit,
    PresentationLimitExceeded,
    InvalidClientState,
    ClientStateBindingMismatch,
    ClientStateRollbackOrFork,
}

impl fmt::Display for ArcAdapterErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidBinding => "invalid ARC credential-key binding",
            Self::BindingExpired => "ARC credential-key binding is not currently valid",
            Self::WrongScheme => "credential-key binding is not experimental ARC",
            Self::InvalidPublicKey => "invalid ARC public key",
            Self::SecretKeyMalformed => "invalid ARC private verification key",
            Self::SecretKeyDoesNotMatchBinding => {
                "ARC private verification key does not match the signed binding"
            }
            Self::DuplicateKeyId => "duplicate ARC key ID",
            Self::DuplicatePublicKey => "duplicate ARC public key",
            Self::KeyNotFound => "ARC private verification key is not retained",
            Self::InvalidCredentialRequest => "invalid ARC credential request",
            Self::InvalidCredentialResponse => "invalid ARC credential response",
            Self::CredentialPairMismatch => "ARC response is not paired with this request",
            Self::CredentialFinalizationFailed => "ARC credential finalization failed",
            Self::InvalidPresentation => "invalid ARC presentation",
            Self::PresentationVerificationFailed => "ARC presentation verification failed",
            Self::UnsupportedPresentationLimit => {
                "ARC draft-01 adapter requires presentation limit in 2..=1024"
            }
            Self::PresentationLimitExceeded => "ARC presentation limit exceeded",
            Self::InvalidClientState => "invalid ARC client state",
            Self::ClientStateBindingMismatch => "ARC client state does not match the binding",
            Self::ClientStateRollbackOrFork => "ARC client state rollback or fork detected",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ArcAdapterErrorV1 {}

/// Stateless strict codec for draft-01 issuance objects.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArcIssuanceCanonicalizerV1;

impl ProtocolArcIssuanceCanonicalizerV1 for ArcIssuanceCanonicalizerV1 {
    fn decode_and_reencode_request(&self, request: &[u8]) -> Result<Vec<u8>, ServiceProtocolError> {
        CredentialRequest::from_bytes(request)
            .map(|value| value.to_bytes().to_vec())
            .map_err(|_| {
                invalid_protocol_value("ArcCredentialRequestV1", "invalid draft-01 ARC request")
            })
    }

    fn decode_and_reencode_response(
        &self,
        response: &[u8],
    ) -> Result<Vec<u8>, ServiceProtocolError> {
        CredentialResponse::from_bytes(response)
            .map(|value| value.to_bytes().to_vec())
            .map_err(|_| {
                invalid_protocol_value("ArcCredentialResponseV1", "invalid draft-01 ARC response")
            })
    }
}

/// Strict presentation codec whose limit can only come from a currently
/// valid, issuer-signed ARC binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArcPresentationCanonicalizerV1 {
    presentation_limit: u64,
    binding_digest: [u8; 32],
}

impl ArcPresentationCanonicalizerV1 {
    pub fn from_verified_binding(
        binding: &CredentialKeyBindingV1,
        expected: &CredentialKeyBindingExpectationV1<'_>,
        now_unix: u64,
    ) -> Result<Self, ArcAdapterErrorV1> {
        let facts = verify_binding(binding, expected, now_unix)?;
        Ok(Self {
            presentation_limit: facts.presentation_limit,
            binding_digest: facts.binding_digest,
        })
    }

    pub const fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }

    /// Construct the strict presentation codec from one exact signed ARC
    /// offer. Callers cannot accidentally supply a context, audience, limit,
    /// key ID, or keyset epoch from a different policy object.
    pub fn from_verified_offer_v1(
        verified_offer: &pir_service_protocol::VerifiedServiceOfferV1<'_>,
        now_unix: u64,
    ) -> Result<Self, ArcAdapterErrorV1> {
        let offer = verified_offer.offer();
        if offer.authorization != AuthScheme::ArcV1Experimental
            || offer.deployment_status != pir_service_protocol::DeploymentStatus::Experimental
        {
            return Err(ArcAdapterErrorV1::WrongScheme);
        }
        let binding = offer
            .credential_binding
            .as_ref()
            .ok_or(ArcAdapterErrorV1::InvalidBinding)?;
        let scope = verified_offer.scope();
        let scope_id = scope.scope_id();
        let expected = CredentialKeyBindingExpectationV1 {
            issuer_id: &offer.issuer_id,
            provider_id: &scope.provider_id,
            scope_id: &scope_id,
            offer_id: offer.offer_id,
            scheme: AuthScheme::ArcV1Experimental,
            minimum_keyset_epoch: binding.claims.keyset_epoch,
            entitlement_profile: scope.entitlement_profile,
            presentation_limit: offer.credential_presentation_limit,
            credential_key_id: &offer.key_id,
        };
        Self::from_verified_binding(binding, &expected, now_unix)
    }
}

impl ProtocolArcPresentationCanonicalizerV1 for ArcPresentationCanonicalizerV1 {
    fn decode_and_reencode(&self, presentation: &[u8]) -> Result<Vec<u8>, ServiceProtocolError> {
        Presentation::from_bytes(presentation, self.presentation_limit)
            .map(|value| value.to_bytes())
            .map_err(|_| {
                invalid_protocol_value(
                    "ArcPresentationV1.presentation",
                    "invalid draft-01 ARC presentation",
                )
            })
    }
}

/// Input for the provider store's permanent raw-key exclusivity guard. The
/// store must atomically enforce `public_key_fingerprint -> lineage_digest`
/// while installing an offer namespace. This value is evidence derived from
/// a currently valid signed binding, not a persistence acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArcExclusiveKeyLineageV1 {
    public_key_fingerprint: [u8; 32],
    lineage_digest: [u8; 32],
    binding_digest: [u8; 32],
}

impl ArcExclusiveKeyLineageV1 {
    pub fn from_verified_binding(
        binding: &CredentialKeyBindingV1,
        expected: &CredentialKeyBindingExpectationV1<'_>,
        now_unix: u64,
    ) -> Result<Self, ArcAdapterErrorV1> {
        let facts = verify_binding(binding, expected, now_unix)?;
        let mut hasher = Sha256::new();
        hasher.update(ARC_EXCLUSIVE_KEY_LINEAGE_DOMAIN_V1);
        hasher.update(facts.public_key_fingerprint);
        hasher.update(facts.binding_digest);
        Ok(Self {
            public_key_fingerprint: facts.public_key_fingerprint,
            lineage_digest: hasher.finalize().into(),
            binding_digest: facts.binding_digest,
        })
    }

    pub const fn public_key_fingerprint(&self) -> &[u8; 32] {
        &self.public_key_fingerprint
    }

    pub const fn lineage_digest(&self) -> &[u8; 32] {
        &self.lineage_digest
    }

    pub const fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }
}

/// One zeroizing ARC private verification key. There is deliberately no
/// private-key export method and no `Clone` implementation.
pub struct ArcSecretKeyV1 {
    key_id: Vec<u8>,
    secret_key: ServerPrivateKey,
    public_key: ServerPublicKey,
    public_key_bytes: [u8; ARC_PUBLIC_KEY_LEN_V1],
    public_key_fingerprint: [u8; 32],
}

impl fmt::Debug for ArcSecretKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArcSecretKeyV1")
            .field("key_id", &self.key_id)
            .field("public_key_fingerprint", &self.public_key_fingerprint)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl ArcSecretKeyV1 {
    pub fn from_zeroizing_bytes(
        key_id: Vec<u8>,
        secret_bytes: Zeroizing<[u8; ARC_SECRET_KEY_LEN_V1]>,
    ) -> Result<Self, ArcAdapterErrorV1> {
        if key_id.is_empty() || key_id.len() > MAX_CREDENTIAL_KEY_ID_LEN {
            return Err(ArcAdapterErrorV1::SecretKeyMalformed);
        }
        let secret_key = ServerPrivateKey {
            x0: deserialize_scalar(&secret_bytes[0..32])
                .map_err(|_| ArcAdapterErrorV1::SecretKeyMalformed)?,
            x1: deserialize_scalar(&secret_bytes[32..64])
                .map_err(|_| ArcAdapterErrorV1::SecretKeyMalformed)?,
            x2: deserialize_scalar(&secret_bytes[64..96])
                .map_err(|_| ArcAdapterErrorV1::SecretKeyMalformed)?,
            x0_blinding: deserialize_scalar(&secret_bytes[96..128])
                .map_err(|_| ArcAdapterErrorV1::SecretKeyMalformed)?,
        };
        let public_key = secret_key.public_key();
        let public_key_bytes = public_key.to_bytes();
        let public_key_fingerprint = arc_public_key_fingerprint_v1(&public_key_bytes)?;
        Ok(Self {
            key_id,
            secret_key,
            public_key,
            public_key_bytes,
            public_key_fingerprint,
        })
    }

    pub fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    pub const fn public_key_bytes(&self) -> &[u8; ARC_PUBLIC_KEY_LEN_V1] {
        &self.public_key_bytes
    }

    pub const fn public_key_fingerprint(&self) -> &[u8; 32] {
        &self.public_key_fingerprint
    }
}

/// A retained-key registry usable either inside a provider-local verifier
/// boundary or inside the shared issuer/clearing boundary.
pub struct ArcSecretKeyringV1 {
    keys: Vec<ArcSecretKeyV1>,
}

impl fmt::Debug for ArcSecretKeyringV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fingerprints: Vec<[u8; 32]> = self
            .keys
            .iter()
            .map(|key| key.public_key_fingerprint)
            .collect();
        formatter
            .debug_struct("ArcSecretKeyringV1")
            .field("key_count", &self.keys.len())
            .field("public_key_fingerprints", &fingerprints)
            .field("secret_keys", &"[REDACTED]")
            .finish()
    }
}

impl ArcSecretKeyringV1 {
    pub fn new(keys: Vec<ArcSecretKeyV1>) -> Result<Self, ArcAdapterErrorV1> {
        if keys.is_empty() {
            return Err(ArcAdapterErrorV1::KeyNotFound);
        }
        for (index, key) in keys.iter().enumerate() {
            if keys[..index].iter().any(|prior| prior.key_id == key.key_id) {
                return Err(ArcAdapterErrorV1::DuplicateKeyId);
            }
            if keys[..index]
                .iter()
                .any(|prior| prior.public_key_bytes == key.public_key_bytes)
            {
                return Err(ArcAdapterErrorV1::DuplicatePublicKey);
            }
        }
        Ok(Self { keys })
    }

    /// Returns whether retained private material exactly matches the public
    /// key ID and canonical ARC public key committed by an issuer binding.
    /// This exposes no secret material and is used for startup fail-closed
    /// coverage checks before an issuer can create a paid quote.
    pub fn contains_credential_key(&self, key_id: &[u8], public_key: &[u8]) -> bool {
        self.keys.iter().any(|candidate| {
            candidate.key_id == key_id && candidate.public_key_bytes.as_slice() == public_key
        })
    }

    /// Create one response for an exact typed request. This method does not
    /// persist issuance or settlement state; the issuer must do that before
    /// returning its enclosing idempotent response.
    pub fn issue_credential_response<R: RngCore + CryptoRng>(
        &self,
        binding: &CredentialKeyBindingV1,
        expected: &CredentialKeyBindingExpectationV1<'_>,
        now_unix: u64,
        request: &ArcCredentialRequestV1,
        rng: &mut R,
    ) -> Result<ArcCredentialResponseV1, ArcAdapterErrorV1> {
        let facts = verify_binding(binding, expected, now_unix)?;
        let key = self.key_for_binding(binding, &facts)?;
        let typed_request = CredentialRequest::from_bytes(request.as_bytes())
            .map_err(|_| ArcAdapterErrorV1::InvalidCredentialRequest)?;
        let response =
            create_credential_response(&key.secret_key, &key.public_key, &typed_request, rng)
                .map_err(|_| ArcAdapterErrorV1::InvalidCredentialRequest)?;
        ArcCredentialResponseV1::decode_canonical(&response.to_bytes(), &ArcIssuanceCanonicalizerV1)
            .map_err(|_| ArcAdapterErrorV1::InvalidCredentialResponse)
    }

    /// Verify a provider-bound presentation and derive the durable spend key.
    /// No in-memory replay set is maintained here.
    pub fn verify_presentation(
        &self,
        binding: &CredentialKeyBindingV1,
        expected: &CredentialKeyBindingExpectationV1<'_>,
        now_unix: u64,
        presentation: &ArcPresentationV1,
    ) -> Result<VerifiedArcSpendV1, ArcAdapterErrorV1> {
        let facts = verify_binding(binding, expected, now_unix)?;
        let key = self.key_for_binding(binding, &facts)?;
        let typed_presentation =
            Presentation::from_bytes(presentation.presentation_bytes(), facts.presentation_limit)
                .map_err(|_| ArcAdapterErrorV1::InvalidPresentation)?;
        if typed_presentation.to_bytes() != presentation.presentation_bytes() {
            return Err(ArcAdapterErrorV1::InvalidPresentation);
        }
        let tag = verify_presentation(
            &key.secret_key,
            &key.public_key,
            &facts.request_context,
            &facts.presentation_context,
            &typed_presentation,
            facts.presentation_limit,
        )
        .map_err(|_| ArcAdapterErrorV1::PresentationVerificationFailed)?;
        let canonical_tag = serialize_element(&tag);
        let spend_key = arc_provider_global_spend_key_v1(
            &facts.public_key_fingerprint,
            &facts.binding_digest,
            &canonical_tag,
        );
        Ok(VerifiedArcSpendV1 {
            canonical_tag,
            spend_key,
            public_key_fingerprint: facts.public_key_fingerprint,
            binding_digest: facts.binding_digest,
        })
    }

    fn key_for_binding<'a>(
        &'a self,
        binding: &CredentialKeyBindingV1,
        facts: &VerifiedBindingFactsV1,
    ) -> Result<&'a ArcSecretKeyV1, ArcAdapterErrorV1> {
        let key = self
            .keys
            .iter()
            .find(|candidate| candidate.key_id == binding.claims.credential_key_id)
            .ok_or(ArcAdapterErrorV1::KeyNotFound)?;
        if key.public_key_bytes != facts.public_key_bytes {
            return Err(ArcAdapterErrorV1::SecretKeyDoesNotMatchBinding);
        }
        Ok(key)
    }
}

/// Cryptographic evidence ready for an authoritative provider or issuer spent
/// store. All fields are private so callers cannot manufacture successful
/// verification by assertion.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VerifiedArcSpendV1 {
    canonical_tag: [u8; ARC_TAG_LEN_V1],
    spend_key: [u8; 32],
    public_key_fingerprint: [u8; 32],
    binding_digest: [u8; 32],
}

impl fmt::Debug for VerifiedArcSpendV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedArcSpendV1")
            .field("canonical_tag", &"[REDACTED]")
            .field("spend_key", &"[REDACTED]")
            .field("public_key_fingerprint", &self.public_key_fingerprint)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

impl VerifiedArcSpendV1 {
    pub const fn canonical_tag(&self) -> &[u8; ARC_TAG_LEN_V1] {
        &self.canonical_tag
    }

    pub const fn spend_key(&self) -> &[u8; 32] {
        &self.spend_key
    }

    pub const fn public_key_fingerprint(&self) -> &[u8; 32] {
        &self.public_key_fingerprint
    }

    pub const fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }
}

#[cfg(feature = "provider-store")]
impl ArcExclusiveKeyLineageVerifierV1 for ArcSecretKeyringV1 {
    fn verify_arc_exclusive_key_lineage_v1(
        &self,
        verified_offer: &VerifiedServiceOfferV1<'_>,
        binding: &CredentialKeyBindingV1,
        now_unix_seconds: u64,
    ) -> Result<ExclusiveKeyLineage, ServiceProtocolError> {
        validate_provider_local_arc_offer(verified_offer, binding, now_unix_seconds)?;
        let offer = verified_offer.offer();
        let scope = verified_offer.scope();
        let scope_id = scope.scope_id();
        let expected = CredentialKeyBindingExpectationV1 {
            issuer_id: &offer.issuer_id,
            provider_id: &scope.provider_id,
            scope_id: &scope_id,
            offer_id: offer.offer_id,
            scheme: AuthScheme::ArcV1Experimental,
            minimum_keyset_epoch: binding.claims.keyset_epoch,
            entitlement_profile: scope.entitlement_profile,
            presentation_limit: offer.credential_presentation_limit,
            credential_key_id: &offer.key_id,
        };
        let facts = verify_binding(binding, &expected, now_unix_seconds)
            .map_err(arc_provider_store_protocol_error)?;
        self.key_for_binding(binding, &facts)
            .map_err(arc_provider_store_protocol_error)?;
        let lineage =
            ArcExclusiveKeyLineageV1::from_verified_binding(binding, &expected, now_unix_seconds)
                .map_err(arc_provider_store_protocol_error)?;
        if lineage.binding_digest()
            != &binding.binding_digest().map_err(|_| {
                invalid_protocol_value(
                    "CredentialKeyBindingV1",
                    "could not derive exact ARC binding digest",
                )
            })?
        {
            return Err(invalid_protocol_value(
                "ArcExclusiveKeyLineageV1.binding_digest",
                "does not match the exact verified offer binding",
            ));
        }
        Ok(ExclusiveKeyLineage {
            key_fingerprint: *lineage.public_key_fingerprint(),
            lineage_digest: *lineage.lineage_digest(),
        })
    }
}

#[cfg(feature = "provider-store")]
impl ArcPresentationSpendVerifierV1 for ArcSecretKeyringV1 {
    fn verify_arc_presentation_spend_v1(
        &self,
        attempt: &BoundAuthAttemptV1<'_>,
        now_unix_seconds: u64,
        sink: &mut dyn ArcVerifiedSpendSinkV1,
    ) -> Result<(), ServiceProtocolError> {
        let verified_offer = attempt.verified_offer();
        let offer = verified_offer.offer();
        let binding = offer.credential_binding.as_ref().ok_or_else(|| {
            invalid_protocol_value(
                "ServiceOfferV1.credential_binding",
                "experimental provider-local ARC binding is missing",
            )
        })?;
        validate_provider_local_arc_offer(verified_offer, binding, now_unix_seconds)?;
        let presentation = match attempt.proof() {
            AuthorizationProofV1::ArcExperimental(presentation) => presentation,
            _ => {
                return Err(invalid_protocol_value(
                    "AuthorizationProofV1",
                    "proof is not experimental ARC",
                ))
            }
        };
        let scope = verified_offer.scope();
        let scope_id = scope.scope_id();
        let expected = CredentialKeyBindingExpectationV1 {
            issuer_id: &offer.issuer_id,
            provider_id: &scope.provider_id,
            scope_id: &scope_id,
            offer_id: offer.offer_id,
            scheme: AuthScheme::ArcV1Experimental,
            minimum_keyset_epoch: binding.claims.keyset_epoch,
            entitlement_profile: scope.entitlement_profile,
            presentation_limit: offer.credential_presentation_limit,
            credential_key_id: &offer.key_id,
        };
        let verified_spend = ArcSecretKeyringV1::verify_presentation(
            self,
            binding,
            &expected,
            now_unix_seconds,
            presentation,
        )
        .map_err(arc_provider_store_protocol_error)?;
        sink.accept_verified_arc_spend_v1(
            verified_spend.canonical_tag(),
            verified_spend.public_key_fingerprint(),
            verified_spend.binding_digest(),
            verified_spend.spend_key(),
        )
    }
}

#[cfg(feature = "provider-store")]
fn validate_provider_local_arc_offer(
    verified_offer: &VerifiedServiceOfferV1<'_>,
    binding: &CredentialKeyBindingV1,
    now_unix_seconds: u64,
) -> Result<(), ServiceProtocolError> {
    let offer = verified_offer.offer();
    if offer.authorization != AuthScheme::ArcV1Experimental
        || offer.verification != VerificationMode::ProviderLocal
        || offer.deployment_status != DeploymentStatus::Experimental
        || offer.credential_presentation_limit < 2
    {
        return Err(invalid_protocol_value(
            "ServiceOfferV1",
            "offer is not supported experimental provider-local ARC",
        ));
    }
    if offer.credential_binding.as_ref() != Some(binding) {
        return Err(invalid_protocol_value(
            "CredentialKeyBindingV1",
            "binding is not the exact verified offer binding",
        ));
    }
    if now_unix_seconds == 0 || now_unix_seconds > verified_offer.redemption_deadline() {
        return Err(invalid_protocol_value(
            "VerifiedServiceOfferV1.redemption_deadline",
            "experimental ARC verification is outside the retained offer horizon",
        ));
    }
    Ok(())
}

#[cfg(feature = "provider-store")]
fn arc_provider_store_protocol_error(_error: ArcAdapterErrorV1) -> ServiceProtocolError {
    invalid_protocol_value(
        "ArcProviderLocalAdapterV1",
        "experimental ARC cryptographic verification failed",
    )
}

/// Client request secrets waiting for the issuer's paired response. `Debug`
/// intentionally reveals only public binding coordinates.
pub struct PendingArcCredentialRequestV1 {
    secrets: ClientSecrets,
    canonical_request: [u8; pir_service_protocol::ARC_CREDENTIAL_REQUEST_LEN_V1],
    binding_digest: [u8; 32],
    public_key_fingerprint: [u8; 32],
}

impl fmt::Debug for PendingArcCredentialRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingArcCredentialRequestV1")
            .field("binding_digest", &self.binding_digest)
            .field("public_key_fingerprint", &self.public_key_fingerprint)
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

impl PendingArcCredentialRequestV1 {
    /// Serialize the client-only issuance state for authenticated encryption
    /// and durable storage before the request is sent. The returned buffer
    /// zeroizes on drop; storage implementations must still encrypt it and
    /// prevent rollback.
    pub fn encode_for_encrypted_storage(&self) -> Result<Zeroizing<Vec<u8>>, ArcAdapterErrorV1> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(ARC_PENDING_REQUEST_LEN_V1));
        bytes.push(ARC_PENDING_REQUEST_VERSION_V1);
        bytes.extend_from_slice(&self.binding_digest);
        bytes.extend_from_slice(&self.public_key_fingerprint);
        bytes.extend_from_slice(&self.canonical_request);
        bytes.extend_from_slice(&serialize_scalar(&self.secrets.m1));
        bytes.extend_from_slice(&serialize_scalar(&self.secrets.m2));
        bytes.extend_from_slice(&serialize_scalar(&self.secrets.r1));
        bytes.extend_from_slice(&serialize_scalar(&self.secrets.r2));
        if bytes.len() != ARC_PENDING_REQUEST_LEN_V1 {
            return Err(ArcAdapterErrorV1::InvalidClientState);
        }
        Ok(bytes)
    }

    /// Finalize only a pair already checked against the exact quote/response
    /// envelope by `pir-service-protocol`.
    pub fn finalize(
        self,
        binding: &CredentialKeyBindingV1,
        expected: &CredentialKeyBindingExpectationV1<'_>,
        now_unix: u64,
        pair: &PendingArcCredentialFinalizeV1,
    ) -> Result<UnpersistedArcClientCredentialV1, ArcAdapterErrorV1> {
        if pair.request().as_bytes() != &self.canonical_request {
            return Err(ArcAdapterErrorV1::CredentialPairMismatch);
        }
        self.finalize_response(binding, expected, now_unix, pair.response())
    }

    fn finalize_response(
        self,
        binding: &CredentialKeyBindingV1,
        expected: &CredentialKeyBindingExpectationV1<'_>,
        now_unix: u64,
        response: &ArcCredentialResponseV1,
    ) -> Result<UnpersistedArcClientCredentialV1, ArcAdapterErrorV1> {
        let facts = verify_binding(binding, expected, now_unix)?;
        if self.binding_digest != facts.binding_digest
            || self.public_key_fingerprint != facts.public_key_fingerprint
        {
            return Err(ArcAdapterErrorV1::CredentialPairMismatch);
        }
        let request = CredentialRequest::from_bytes(&self.canonical_request)
            .map_err(|_| ArcAdapterErrorV1::InvalidCredentialRequest)?;
        let response = CredentialResponse::from_bytes(response.as_bytes())
            .map_err(|_| ArcAdapterErrorV1::InvalidCredentialResponse)?;
        let credential = finalize_credential(&self.secrets, &facts.public_key, &request, &response)
            .map_err(|_| ArcAdapterErrorV1::CredentialFinalizationFailed)?;
        let state = make_presentation_state(
            credential,
            &facts.presentation_context,
            facts.presentation_limit,
        );
        let state = ArcClientCredentialStateV1 {
            state,
            binding_digest: facts.binding_digest,
            public_key_fingerprint: facts.public_key_fingerprint,
        };
        let credential_id = state.credential_id();
        Ok(UnpersistedArcClientCredentialV1 {
            credential_id,
            state,
        })
    }
}

/// Restore client-only issuance state after an invoice/claim response was
/// lost or the page was closed. The exact request and all four secrets are
/// cross-checked against the current signed binding before they are returned.
pub fn restore_arc_credential_request(
    binding: &CredentialKeyBindingV1,
    expected: &CredentialKeyBindingExpectationV1<'_>,
    now_unix: u64,
    encoded: &[u8],
) -> Result<(ArcCredentialRequestV1, PendingArcCredentialRequestV1), ArcAdapterErrorV1> {
    let facts = verify_binding(binding, expected, now_unix)?;
    if encoded.len() != ARC_PENDING_REQUEST_LEN_V1 || encoded[0] != ARC_PENDING_REQUEST_VERSION_V1 {
        return Err(ArcAdapterErrorV1::InvalidClientState);
    }
    let binding_digest: [u8; 32] = encoded[1..33]
        .try_into()
        .map_err(|_| ArcAdapterErrorV1::InvalidClientState)?;
    let public_key_fingerprint: [u8; 32] = encoded[33..65]
        .try_into()
        .map_err(|_| ArcAdapterErrorV1::InvalidClientState)?;
    if binding_digest != facts.binding_digest
        || public_key_fingerprint != facts.public_key_fingerprint
    {
        return Err(ArcAdapterErrorV1::ClientStateBindingMismatch);
    }
    let request_end = 65 + pir_service_protocol::ARC_CREDENTIAL_REQUEST_LEN_V1;
    let canonical_request: [u8; pir_service_protocol::ARC_CREDENTIAL_REQUEST_LEN_V1] = encoded
        [65..request_end]
        .try_into()
        .map_err(|_| ArcAdapterErrorV1::InvalidClientState)?;
    let typed_request = CredentialRequest::from_bytes(&canonical_request)
        .map_err(|_| ArcAdapterErrorV1::InvalidCredentialRequest)?;
    if typed_request.to_bytes() != canonical_request
        || verify_credential_request_proof(&typed_request).is_err()
    {
        return Err(ArcAdapterErrorV1::InvalidCredentialRequest);
    }
    let scalar = |index: usize| {
        let start = request_end + index * 32;
        deserialize_scalar(&encoded[start..start + 32])
            .map_err(|_| ArcAdapterErrorV1::InvalidClientState)
    };
    let secrets = ClientSecrets {
        m1: scalar(0)?,
        m2: scalar(1)?,
        r1: scalar(2)?,
        r2: scalar(3)?,
    };
    if serialize_scalar(&secrets.m2)
        != serialize_scalar(&hash_to_scalar(
            &facts.request_context,
            arc::ciphersuite::INFO_REQUEST_CONTEXT.as_bytes(),
        ))
        || typed_request.m1_enc != generator_g() * secrets.m1 + generator_h() * secrets.r1
        || typed_request.m2_enc != generator_g() * secrets.m2 + generator_h() * secrets.r2
    {
        return Err(ArcAdapterErrorV1::InvalidClientState);
    }
    let request =
        ArcCredentialRequestV1::decode_canonical(&canonical_request, &ArcIssuanceCanonicalizerV1)
            .map_err(|_| ArcAdapterErrorV1::InvalidCredentialRequest)?;
    Ok((
        request,
        PendingArcCredentialRequestV1 {
            secrets,
            canonical_request,
            binding_digest,
            public_key_fingerprint,
        },
    ))
}

/// Create a client request using the request context derived from the complete
/// signed binding. There is no API accepting an arbitrary request context.
pub fn create_arc_credential_request<R: RngCore + CryptoRng>(
    binding: &CredentialKeyBindingV1,
    expected: &CredentialKeyBindingExpectationV1<'_>,
    now_unix: u64,
    rng: &mut R,
) -> Result<(ArcCredentialRequestV1, PendingArcCredentialRequestV1), ArcAdapterErrorV1> {
    let facts = verify_binding(binding, expected, now_unix)?;
    let (secrets, request) = create_credential_request(&facts.request_context, rng)
        .map_err(|_| ArcAdapterErrorV1::InvalidCredentialRequest)?;
    let canonical_request = request.to_bytes();
    let request =
        ArcCredentialRequestV1::decode_canonical(&canonical_request, &ArcIssuanceCanonicalizerV1)
            .map_err(|_| ArcAdapterErrorV1::InvalidCredentialRequest)?;
    Ok((
        request,
        PendingArcCredentialRequestV1 {
            secrets,
            canonical_request,
            binding_digest: facts.binding_digest,
            public_key_fingerprint: facts.public_key_fingerprint,
        },
    ))
}

/// Required durable browser-state boundary. `Ok(())` means the bytes and
/// compare-and-swap metadata are durable; an in-memory acknowledgement does
/// not satisfy this contract.
pub trait ArcClientStateStoreV1 {
    type Error;

    /// Create-if-absent. An exact replay of the same state digest may return
    /// success; a different state for the same credential ID must fail.
    fn persist_initial(
        &mut self,
        credential_id: &[u8; 32],
        state_digest: &[u8; 32],
        encoded_state: &[u8],
    ) -> Result<(), Self::Error>;

    /// Atomically require the current digest to equal
    /// `expected_state_digest`, install the exact successor bytes/digest, and
    /// make that successor durable before returning. An exact already-applied
    /// successor may return success for lost-response recovery; any other
    /// predecessor/successor combination must fail as rollback or fork.
    fn compare_and_swap_successor(
        &mut self,
        credential_id: &[u8; 32],
        expected_state_digest: &[u8; 32],
        successor_state_digest: &[u8; 32],
        encoded_successor_state: &[u8],
    ) -> Result<(), Self::Error>;

    /// Return only the externally anchored current record. A stale local
    /// IndexedDB/backup image must fail closed rather than be returned here.
    fn load_current(
        &mut self,
        credential_id: &[u8; 32],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error>;
}

#[derive(Debug)]
pub enum ArcClientStateErrorV1<E> {
    Adapter(ArcAdapterErrorV1),
    Store(E),
}

impl<E: fmt::Display> fmt::Display for ArcClientStateErrorV1<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adapter(error) => error.fmt(formatter),
            Self::Store(error) => write!(formatter, "ARC client state store failed: {error}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for ArcClientStateErrorV1<E> {}

/// A finalized credential which cannot produce a presentation until its
/// initial state is durably installed.
pub struct UnpersistedArcClientCredentialV1 {
    credential_id: [u8; 32],
    state: ArcClientCredentialStateV1,
}

impl fmt::Debug for UnpersistedArcClientCredentialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnpersistedArcClientCredentialV1")
            .field("credential_id", &"[REDACTED]")
            .field("state", &"[REDACTED]")
            .finish()
    }
}

impl UnpersistedArcClientCredentialV1 {
    pub const fn credential_id(&self) -> &[u8; 32] {
        &self.credential_id
    }

    /// Export the initial client state only for authenticated encryption and
    /// durable storage. This does not release a presentation and does not
    /// claim that persistence has happened; callers must durably install the
    /// exact bytes before constructing any presentation from them.
    pub fn encode_for_encrypted_storage(&self) -> Result<Zeroizing<Vec<u8>>, ArcAdapterErrorV1> {
        self.state.encode()
    }

    pub fn persist_initial<S: ArcClientStateStoreV1>(
        self,
        store: &mut S,
    ) -> Result<ArcClientCredentialV1, ArcClientStateErrorV1<S::Error>> {
        let encoded = self
            .state
            .encode()
            .map_err(ArcClientStateErrorV1::Adapter)?;
        let state_digest = arc_client_state_digest_v1(&encoded);
        store
            .persist_initial(&self.credential_id, &state_digest, &encoded)
            .map_err(ArcClientStateErrorV1::Store)?;
        Ok(ArcClientCredentialV1 {
            credential_id: self.credential_id,
            state_digest,
            state: self.state,
        })
    }
}

/// A persisted current client state. It is move-only: cloning would create an
/// easy stale-nonce fork.
///
/// ```compile_fail
/// use pir_arc_adapter::ArcClientCredentialV1;
/// fn fork_nonce_state(state: ArcClientCredentialV1) {
///     let _stale_copy = state.clone();
/// }
/// ```
pub struct ArcClientCredentialV1 {
    credential_id: [u8; 32],
    state_digest: [u8; 32],
    state: ArcClientCredentialStateV1,
}

impl fmt::Debug for ArcClientCredentialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArcClientCredentialV1")
            .field("credential_id", &"[REDACTED]")
            .field("state_digest", &"[REDACTED]")
            .field("next_nonce", &self.state.state.next_nonce)
            .field("state", &"[REDACTED]")
            .finish()
    }
}

impl ArcClientCredentialV1 {
    pub const fn credential_id(&self) -> &[u8; 32] {
        &self.credential_id
    }

    pub const fn state_digest(&self) -> &[u8; 32] {
        &self.state_digest
    }

    pub const fn remaining_presentations(&self) -> u64 {
        self.state
            .state
            .presentation_limit
            .saturating_sub(self.state.state.next_nonce)
    }

    pub fn load_current<S: ArcClientStateStoreV1>(
        store: &mut S,
        credential_id: [u8; 32],
        binding: &CredentialKeyBindingV1,
        expected: &CredentialKeyBindingExpectationV1<'_>,
        now_unix: u64,
    ) -> Result<Option<Self>, ArcClientStateErrorV1<S::Error>> {
        let Some(encoded) = store
            .load_current(&credential_id)
            .map_err(ArcClientStateErrorV1::Store)?
        else {
            return Ok(None);
        };
        let facts =
            verify_binding(binding, expected, now_unix).map_err(ArcClientStateErrorV1::Adapter)?;
        let state = ArcClientCredentialStateV1::decode(&encoded, &facts)
            .map_err(ArcClientStateErrorV1::Adapter)?;
        if state.credential_id() != credential_id {
            return Err(ArcClientStateErrorV1::Adapter(
                ArcAdapterErrorV1::ClientStateBindingMismatch,
            ));
        }
        let state_digest = arc_client_state_digest_v1(&encoded);
        Ok(Some(Self {
            credential_id,
            state_digest,
            state,
        }))
    }

    /// Consume the current state and build the successor. The returned type
    /// deliberately exposes no presentation bytes.
    pub fn prepare_presentation<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
    ) -> Result<ArcPresentationAwaitingPersistenceV1, ArcAdapterErrorV1> {
        let (successor, _nonce, presentation) =
            present(&self.state.state, rng).map_err(|error| {
                if error == arc::Error::LimitExceeded {
                    ArcAdapterErrorV1::PresentationLimitExceeded
                } else {
                    ArcAdapterErrorV1::PresentationVerificationFailed
                }
            })?;
        let canonical = presentation.to_bytes();
        let checked = Presentation::from_bytes(&canonical, successor.presentation_limit)
            .map_err(|_| ArcAdapterErrorV1::InvalidPresentation)?;
        if checked.to_bytes() != canonical {
            return Err(ArcAdapterErrorV1::InvalidPresentation);
        }
        let presentation = ArcPresentationV1::from_canonical_bytes(canonical)
            .map_err(|_| ArcAdapterErrorV1::InvalidPresentation)?;
        let successor = ArcClientCredentialStateV1 {
            state: successor,
            binding_digest: self.state.binding_digest,
            public_key_fingerprint: self.state.public_key_fingerprint,
        };
        Ok(ArcPresentationAwaitingPersistenceV1 {
            credential_id: self.credential_id,
            predecessor_state_digest: self.state_digest,
            successor,
            presentation,
        })
    }
}

/// A presentation which remains inaccessible until its exact successor state
/// has passed the store's durable compare-and-swap.
///
/// ```compile_fail
/// use pir_arc_adapter::ArcPresentationAwaitingPersistenceV1;
/// fn bypass_persistence(value: ArcPresentationAwaitingPersistenceV1) {
///     let _wire = value.into_presentation();
/// }
/// ```
pub struct ArcPresentationAwaitingPersistenceV1 {
    credential_id: [u8; 32],
    predecessor_state_digest: [u8; 32],
    successor: ArcClientCredentialStateV1,
    presentation: ArcPresentationV1,
}

impl fmt::Debug for ArcPresentationAwaitingPersistenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArcPresentationAwaitingPersistenceV1")
            .field("credential_id", &"[REDACTED]")
            .field("predecessor_state_digest", &"[REDACTED]")
            .field("successor", &"[REDACTED]")
            .field("presentation", &"[WITHHELD]")
            .finish()
    }
}

impl ArcPresentationAwaitingPersistenceV1 {
    pub fn persist_successor<S: ArcClientStateStoreV1>(
        self,
        store: &mut S,
    ) -> Result<(ArcClientCredentialV1, ReadyArcPresentationV1), ArcClientStateErrorV1<S::Error>>
    {
        let encoded = self
            .successor
            .encode()
            .map_err(ArcClientStateErrorV1::Adapter)?;
        let successor_state_digest = arc_client_state_digest_v1(&encoded);
        store
            .compare_and_swap_successor(
                &self.credential_id,
                &self.predecessor_state_digest,
                &successor_state_digest,
                &encoded,
            )
            .map_err(ArcClientStateErrorV1::Store)?;
        Ok((
            ArcClientCredentialV1 {
                credential_id: self.credential_id,
                state_digest: successor_state_digest,
                state: self.successor,
            },
            ReadyArcPresentationV1 {
                presentation: self.presentation,
            },
        ))
    }
}

/// A presentation released only after durable nonce burn. Consuming this
/// wrapper is the intended handoff into wire encoding.
pub struct ReadyArcPresentationV1 {
    presentation: ArcPresentationV1,
}

impl fmt::Debug for ReadyArcPresentationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadyArcPresentationV1")
            .field("presentation", &"[RELEASED]")
            .finish()
    }
}

impl ReadyArcPresentationV1 {
    pub fn into_presentation(self) -> ArcPresentationV1 {
        self.presentation
    }
}

struct ArcClientCredentialStateV1 {
    state: PresentationState,
    binding_digest: [u8; 32],
    public_key_fingerprint: [u8; 32],
}

impl ArcClientCredentialStateV1 {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ArcAdapterErrorV1> {
        if self.state.presentation_context.as_slice()
            != presentation_context_from_binding_digest_v1(&self.binding_digest)
            || self.state.presentation_limit == 0
            || self.state.presentation_limit > u64::from(MAX_CREDENTIAL_PRESENTATIONS_V1)
            || self.state.next_nonce > self.state.presentation_limit
        {
            return Err(ArcAdapterErrorV1::InvalidClientState);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(ARC_CLIENT_STATE_LEN_V1));
        bytes.push(ARC_CLIENT_STATE_VERSION_V1);
        bytes.extend_from_slice(&self.binding_digest);
        bytes.extend_from_slice(&self.public_key_fingerprint);
        bytes.extend_from_slice(&self.state.presentation_limit.to_le_bytes());
        bytes.extend_from_slice(&self.state.next_nonce.to_le_bytes());
        bytes.extend_from_slice(&serialize_scalar(&self.state.credential.m1));
        bytes.extend_from_slice(&serialize_element(&self.state.credential.u));
        bytes.extend_from_slice(&serialize_element(&self.state.credential.u_prime));
        bytes.extend_from_slice(&serialize_element(&self.state.credential.x1));
        if bytes.len() != ARC_CLIENT_STATE_LEN_V1 {
            return Err(ArcAdapterErrorV1::InvalidClientState);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8], facts: &VerifiedBindingFactsV1) -> Result<Self, ArcAdapterErrorV1> {
        if bytes.len() != ARC_CLIENT_STATE_LEN_V1 || bytes[0] != ARC_CLIENT_STATE_VERSION_V1 {
            return Err(ArcAdapterErrorV1::InvalidClientState);
        }
        let binding_digest: [u8; 32] = bytes[1..33]
            .try_into()
            .map_err(|_| ArcAdapterErrorV1::InvalidClientState)?;
        let public_key_fingerprint: [u8; 32] = bytes[33..65]
            .try_into()
            .map_err(|_| ArcAdapterErrorV1::InvalidClientState)?;
        if binding_digest != facts.binding_digest
            || public_key_fingerprint != facts.public_key_fingerprint
        {
            return Err(ArcAdapterErrorV1::ClientStateBindingMismatch);
        }
        let presentation_limit = u64::from_le_bytes(
            bytes[65..73]
                .try_into()
                .map_err(|_| ArcAdapterErrorV1::InvalidClientState)?,
        );
        let next_nonce = u64::from_le_bytes(
            bytes[73..81]
                .try_into()
                .map_err(|_| ArcAdapterErrorV1::InvalidClientState)?,
        );
        if presentation_limit != facts.presentation_limit || next_nonce > presentation_limit {
            return Err(ArcAdapterErrorV1::ClientStateBindingMismatch);
        }
        let m1 = deserialize_scalar(&bytes[81..113])
            .map_err(|_| ArcAdapterErrorV1::InvalidClientState)?;
        let u = deserialize_element(&bytes[113..146])
            .map_err(|_| ArcAdapterErrorV1::InvalidClientState)?;
        let u_prime = deserialize_element(&bytes[146..179])
            .map_err(|_| ArcAdapterErrorV1::InvalidClientState)?;
        let x1 = deserialize_element(&bytes[179..212])
            .map_err(|_| ArcAdapterErrorV1::InvalidClientState)?;
        if serialize_element(&x1) != serialize_element(&facts.public_key.x1) {
            return Err(ArcAdapterErrorV1::ClientStateBindingMismatch);
        }
        let state = PresentationState {
            credential: Credential { m1, u, u_prime, x1 },
            presentation_context: facts.presentation_context.to_vec(),
            next_nonce,
            presentation_limit,
        };
        let value = Self {
            state,
            binding_digest,
            public_key_fingerprint,
        };
        if value.encode()?.as_slice() != bytes {
            return Err(ArcAdapterErrorV1::InvalidClientState);
        }
        Ok(value)
    }

    fn credential_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ARC_CLIENT_CREDENTIAL_ID_DOMAIN_V1);
        hasher.update(self.binding_digest);
        hasher.update(self.public_key_fingerprint);
        hasher.update(serialize_scalar(&self.state.credential.m1));
        hasher.update(serialize_element(&self.state.credential.u));
        hasher.update(serialize_element(&self.state.credential.u_prime));
        hasher.update(serialize_element(&self.state.credential.x1));
        hasher.finalize().into()
    }
}

struct VerifiedBindingFactsV1 {
    public_key: ServerPublicKey,
    public_key_bytes: [u8; ARC_PUBLIC_KEY_LEN_V1],
    public_key_fingerprint: [u8; 32],
    binding_digest: [u8; 32],
    request_context: [u8; 32],
    presentation_context: [u8; 32],
    presentation_limit: u64,
}

fn verify_binding(
    binding: &CredentialKeyBindingV1,
    expected: &CredentialKeyBindingExpectationV1<'_>,
    now_unix: u64,
) -> Result<VerifiedBindingFactsV1, ArcAdapterErrorV1> {
    binding.verify_for(expected, now_unix).map_err(|error| {
        if now_unix < binding.claims.not_before || now_unix > binding.claims.not_after {
            ArcAdapterErrorV1::BindingExpired
        } else {
            let _ = error;
            ArcAdapterErrorV1::InvalidBinding
        }
    })?;
    if binding.claims.scheme != AuthScheme::ArcV1Experimental
        || expected.scheme != AuthScheme::ArcV1Experimental
    {
        return Err(ArcAdapterErrorV1::WrongScheme);
    }
    let public_key_bytes: [u8; ARC_PUBLIC_KEY_LEN_V1] = binding
        .claims
        .verification_key
        .as_slice()
        .try_into()
        .map_err(|_| ArcAdapterErrorV1::InvalidPublicKey)?;
    let public_key = ServerPublicKey::from_bytes(&public_key_bytes)
        .map_err(|_| ArcAdapterErrorV1::InvalidPublicKey)?;
    if public_key.to_bytes() != public_key_bytes {
        return Err(ArcAdapterErrorV1::InvalidPublicKey);
    }
    let binding_digest = binding
        .binding_digest()
        .map_err(|_| ArcAdapterErrorV1::InvalidBinding)?;
    let request_context = binding
        .request_context_digest()
        .map_err(|_| ArcAdapterErrorV1::InvalidBinding)?;
    let presentation_context = binding
        .presentation_context_digest()
        .map_err(|_| ArcAdapterErrorV1::InvalidBinding)?;
    let presentation_limit = u64::from(binding.claims.presentation_limit);
    // The pinned draft-01 implementation represents the range proof with
    // ceil(log2(limit)) bit commitments. At limit=1 that set is empty and its
    // verifier's sum check cannot equal the randomized nonce commitment.
    // Fail closed rather than issue a credential which can never verify.
    if presentation_limit < 2 || presentation_limit > u64::from(MAX_CREDENTIAL_PRESENTATIONS_V1) {
        return Err(ArcAdapterErrorV1::UnsupportedPresentationLimit);
    }
    Ok(VerifiedBindingFactsV1 {
        public_key,
        public_key_bytes,
        public_key_fingerprint: arc_public_key_fingerprint_v1(&public_key_bytes)?,
        binding_digest,
        request_context,
        presentation_context,
        presentation_limit,
    })
}

pub fn arc_public_key_fingerprint_v1(
    public_key: &[u8; ARC_PUBLIC_KEY_LEN_V1],
) -> Result<[u8; 32], ArcAdapterErrorV1> {
    let typed =
        ServerPublicKey::from_bytes(public_key).map_err(|_| ArcAdapterErrorV1::InvalidPublicKey)?;
    if typed.to_bytes() != *public_key {
        return Err(ArcAdapterErrorV1::InvalidPublicKey);
    }
    let mut hasher = Sha256::new();
    hasher.update(ARC_PUBLIC_KEY_FINGERPRINT_DOMAIN_V1);
    hasher.update(public_key);
    Ok(hasher.finalize().into())
}

fn arc_client_state_digest_v1(encoded_state: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ARC_CLIENT_STATE_DIGEST_DOMAIN_V1);
    hasher.update(encoded_state);
    hasher.finalize().into()
}

fn presentation_context_from_binding_digest_v1(binding_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pir_service_protocol::CREDENTIAL_PRESENTATION_CONTEXT_DOMAIN);
    hasher.update(binding_digest);
    hasher.finalize().into()
}

fn invalid_protocol_value(field: &'static str, reason: &'static str) -> ServiceProtocolError {
    ServiceProtocolError::InvalidValue { field, reason }
}

#[cfg(test)]
mod tests;
