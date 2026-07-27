//! Safe derivation of provider-local durable spend namespaces.

use pir_service_protocol::{
    bat_verification_key_fingerprint_v1, AuthScheme, CredentialKeyBindingV1, FreeModeV1,
    ServiceProtocolError, VerificationMode, VerifiedServiceOfferV1,
};
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::{
    ExclusiveKeyLineage, NamespaceInstallOutcome, NamespaceStatus, NewSpendNamespace,
    ProviderStore, StoreError, StoreResult,
};

pub const OFFER_NAMESPACE_ID_DOMAIN_V1: &[u8] = b"BitcoinPIR/provider-spend-namespace-id/v1";
pub const OFFER_NAMESPACE_BINDING_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-spend-namespace-binding/v1";
pub const OFFER_NAMESPACE_LINEAGE_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-exclusive-key-lineage/v1";

/// Reviewed ARC adapter boundary used while deriving a provider-local spend
/// namespace from a verified offer.
///
/// The store deliberately owns [`ExclusiveKeyLineage`] and never accepts a
/// caller-supplied ARC fingerprint or lineage digest. Implementations must
/// strictly decode the exact 99-byte draft-01 public key, verify that
/// `binding` is the offer's complete currently-valid signed binding, and bind
/// the returned lineage to every immutable credential coordinate.
pub trait ArcExclusiveKeyLineageVerifierV1: Send + Sync {
    fn verify_arc_exclusive_key_lineage_v1(
        &self,
        verified_offer: &VerifiedServiceOfferV1<'_>,
        binding: &CredentialKeyBindingV1,
        now_unix_seconds: u64,
    ) -> Result<ExclusiveKeyLineage, ServiceProtocolError>;
}

/// Why a verified offer must not create provider-local bearer spent state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiedOfferNamespaceNotApplicableV1 {
    /// Open, IP-bucketed, and proof-of-work Free grants have no durable bearer.
    NonBearerFree,
    /// The shared issuer owns the authoritative redemption/nullifier state.
    SharedIssuerOnline,
    /// The external mint's atomic NUT-03 invalidation is authoritative.
    StandardCashuMintOnline,
}

/// Result of routing, deriving, and (when required) installing one verified
/// offer's provider-local spend namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "namespace routing must be handled explicitly before serving an offer"]
pub enum VerifiedOfferNamespaceInstallOutcomeV1 {
    Namespace {
        namespace: Box<NewSpendNamespace>,
        install_outcome: NamespaceInstallOutcome,
    },
    NotApplicable(VerifiedOfferNamespaceNotApplicableV1),
    /// No reviewed provider-local ARC adapter was supplied. ARC remains
    /// experimental and must fail closed in that configuration.
    UnsupportedExperimental,
}

/// Read-only startup check for a retained offer's authoritative spend state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "retained namespace readiness must be handled before serving a policy"]
pub enum VerifiedOfferNamespaceReadinessV1 {
    Ready,
    NotApplicable(VerifiedOfferNamespaceNotApplicableV1),
    UnsupportedExperimental,
}

pub(crate) fn verify_existing_verified_offer_namespace_v1(
    store: &ProviderStore,
    verified_offer: &VerifiedServiceOfferV1<'_>,
    now_unix_seconds: u64,
    arc_lineage_verifier: Option<&dyn ArcExclusiveKeyLineageVerifierV1>,
) -> StoreResult<VerifiedOfferNamespaceReadinessV1> {
    if verified_offer.scope().provider_id != store.handle.expected_provider_id {
        return Err(StoreError::ProviderMismatch);
    }
    match derive_verified_offer_namespace_v1(
        verified_offer,
        now_unix_seconds,
        arc_lineage_verifier,
    )? {
        DerivedOfferNamespaceV1::Namespace(expected) => {
            let connection = store.open_checked(false)?;
            let actual = crate::read_namespace(&connection, &expected.namespace_id)?
                .ok_or(StoreError::NamespaceMissing)?;
            if actual.scheme != expected.scheme
                || actual.issuer_id != expected.issuer_id
                || actual.key_id != expected.key_id
                || actual.binding_digest != expected.binding_digest
                || actual.not_after != expected.not_after
            {
                return Err(StoreError::NamespaceConflict);
            }
            if actual.status != NamespaceStatus::Active {
                return Err(StoreError::NamespaceClosed);
            }
            if let Some(lineage) = expected.exclusive_key_lineage {
                let persisted: Option<Vec<u8>> = connection
                    .query_row(
                        "SELECT lineage_digest FROM exclusive_key_lineages \
                         WHERE scheme = ?1 AND key_fingerprint = ?2",
                        params![
                            i64::from(expected.scheme),
                            lineage.key_fingerprint.as_slice()
                        ],
                        |row| row.get(0),
                    )
                    .optional()?;
                let persisted = persisted.ok_or_else(|| {
                    StoreError::SchemaMismatch(
                        "namespace is missing its exclusive key lineage".to_owned(),
                    )
                })?;
                if crate::fixed_blob::<32>(persisted, "invalid exclusive lineage digest")?
                    != lineage.lineage_digest
                {
                    return Err(StoreError::ExclusiveKeyLineageConflict);
                }
            }
            Ok(VerifiedOfferNamespaceReadinessV1::Ready)
        }
        DerivedOfferNamespaceV1::NotApplicable(reason) => {
            Ok(VerifiedOfferNamespaceReadinessV1::NotApplicable(reason))
        }
        DerivedOfferNamespaceV1::UnsupportedExperimental => {
            Ok(VerifiedOfferNamespaceReadinessV1::UnsupportedExperimental)
        }
    }
}

pub(crate) fn install_verified_offer_namespace_v1(
    store: &ProviderStore,
    verified_offer: &VerifiedServiceOfferV1<'_>,
    now_unix_seconds: u64,
    arc_lineage_verifier: Option<&dyn ArcExclusiveKeyLineageVerifierV1>,
) -> StoreResult<VerifiedOfferNamespaceInstallOutcomeV1> {
    if verified_offer.scope().provider_id != store.handle.expected_provider_id {
        return Err(StoreError::ProviderMismatch);
    }

    match derive_verified_offer_namespace_v1(
        verified_offer,
        now_unix_seconds,
        arc_lineage_verifier,
    )? {
        DerivedOfferNamespaceV1::Namespace(namespace) => {
            let install_outcome = store.install_namespace(&namespace)?;
            Ok(VerifiedOfferNamespaceInstallOutcomeV1::Namespace {
                namespace: Box::new(namespace),
                install_outcome,
            })
        }
        DerivedOfferNamespaceV1::NotApplicable(reason) => Ok(
            VerifiedOfferNamespaceInstallOutcomeV1::NotApplicable(reason),
        ),
        DerivedOfferNamespaceV1::UnsupportedExperimental => {
            Ok(VerifiedOfferNamespaceInstallOutcomeV1::UnsupportedExperimental)
        }
    }
}

pub(crate) enum DerivedOfferNamespaceV1 {
    Namespace(NewSpendNamespace),
    NotApplicable(VerifiedOfferNamespaceNotApplicableV1),
    UnsupportedExperimental,
}

pub(crate) fn derive_verified_offer_namespace_v1<A>(
    verified_offer: &VerifiedServiceOfferV1<'_>,
    now_unix_seconds: u64,
    arc_lineage_verifier: Option<&A>,
) -> StoreResult<DerivedOfferNamespaceV1>
where
    A: ArcExclusiveKeyLineageVerifierV1 + ?Sized,
{
    let offer = verified_offer.offer();
    match offer.verification {
        VerificationMode::SharedIssuerOnline => {
            return Ok(DerivedOfferNamespaceV1::NotApplicable(
                VerifiedOfferNamespaceNotApplicableV1::SharedIssuerOnline,
            ))
        }
        VerificationMode::StandardCashuMintOnline => {
            return Ok(DerivedOfferNamespaceV1::NotApplicable(
                VerifiedOfferNamespaceNotApplicableV1::StandardCashuMintOnline,
            ))
        }
        VerificationMode::ProviderLocal => match offer.authorization {
            AuthScheme::FreeV1 if offer.free_mode == FreeModeV1::AnonymousTicket => {}
            AuthScheme::FreeV1 => {
                return Ok(DerivedOfferNamespaceV1::NotApplicable(
                    VerifiedOfferNamespaceNotApplicableV1::NonBearerFree,
                ))
            }
            AuthScheme::Bolt11DirectReceiptV1 | AuthScheme::BitcoinPirCashuBatV1 => {}
            AuthScheme::ArcV1Experimental if arc_lineage_verifier.is_some() => {}
            AuthScheme::ArcV1Experimental => {
                return Ok(DerivedOfferNamespaceV1::UnsupportedExperimental)
            }
            // A verified V1 standard-Cashu offer always uses the mint-online
            // mode, but keep its authoritative-state routing explicit.
            AuthScheme::CashuEcashV1 => {
                return Ok(DerivedOfferNamespaceV1::NotApplicable(
                    VerifiedOfferNamespaceNotApplicableV1::StandardCashuMintOnline,
                ))
            }
        },
    }

    let binding = offer
        .credential_binding
        .as_ref()
        .ok_or(StoreError::InvalidInput(
            "verified bearer offer is missing its credential binding",
        ))?;
    if binding.claims.not_after > verified_offer.redemption_deadline() {
        return Err(StoreError::InvalidInput(
            "credential binding outlives verified offer redemption deadline",
        ));
    }

    let binding_digest = offer_namespace_binding_digest_v1(verified_offer, binding)?;
    let namespace_id = offer_namespace_id_v1(
        &verified_offer.scope().provider_id,
        offer.authorization,
        &offer.issuer_id,
        &offer.key_id,
        &binding_digest,
    );
    let exclusive_key_lineage = match offer.authorization {
        AuthScheme::BitcoinPirCashuBatV1 => {
            Some(derive_bat_exclusive_lineage_v1(verified_offer, binding)?)
        }
        AuthScheme::ArcV1Experimental => {
            if now_unix_seconds == 0 {
                return Err(StoreError::InvalidInput(
                    "ARC namespace verification time is zero",
                ));
            }
            Some(
                arc_lineage_verifier
                    .ok_or(StoreError::InvalidInput(
                        "reviewed ARC lineage verifier is required",
                    ))?
                    .verify_arc_exclusive_key_lineage_v1(
                        verified_offer,
                        binding,
                        now_unix_seconds,
                    )?,
            )
        }
        _ => None,
    };

    Ok(DerivedOfferNamespaceV1::Namespace(NewSpendNamespace {
        namespace_id,
        scheme: offer.authorization as u16,
        issuer_id: offer.issuer_id,
        key_id: offer.key_id.clone(),
        binding_digest,
        // Keep the persisted horizon defensively bounded even though creation
        // of `VerifiedServiceOfferV1` already proves the same relationship.
        not_after: binding
            .claims
            .not_after
            .min(verified_offer.redemption_deadline()),
        exclusive_key_lineage,
    }))
}

fn offer_namespace_binding_digest_v1(
    verified_offer: &VerifiedServiceOfferV1<'_>,
    binding: &CredentialKeyBindingV1,
) -> StoreResult<[u8; 32]> {
    let offer = verified_offer.offer();
    let scope = verified_offer.scope();
    let mut hasher = Sha256::new();
    hasher.update(OFFER_NAMESPACE_BINDING_DIGEST_DOMAIN_V1);
    hasher.update(scope.provider_id);
    hasher.update(scope.scope_id());
    hasher.update(offer.offer_id.to_le_bytes());
    hasher.update((offer.authorization as u16).to_le_bytes());
    hasher.update([offer.verification as u8]);
    hasher.update(offer.issuer_id);
    hasher.update(binding.claims.keyset_epoch.to_le_bytes());
    hasher.update(scope.entitlement_profile.to_le_bytes());
    hash_len_prefixed(&mut hasher, &offer.key_id);
    hasher.update(binding.binding_digest()?);
    Ok(hasher.finalize().into())
}

fn offer_namespace_id_v1(
    provider_id: &[u8; 32],
    scheme: AuthScheme,
    issuer_id: &[u8; 32],
    key_id: &[u8],
    binding_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OFFER_NAMESPACE_ID_DOMAIN_V1);
    hasher.update(provider_id);
    hasher.update((scheme as u16).to_le_bytes());
    hasher.update(issuer_id);
    hash_len_prefixed(&mut hasher, key_id);
    hasher.update(binding_digest);
    hasher.finalize().into()
}

fn derive_bat_exclusive_lineage_v1(
    verified_offer: &VerifiedServiceOfferV1<'_>,
    binding: &CredentialKeyBindingV1,
) -> StoreResult<ExclusiveKeyLineage> {
    let verification_key: [u8; 33] = binding
        .claims
        .verification_key
        .as_slice()
        .try_into()
        .map_err(|_| {
            StoreError::InvalidInput("verified BAT binding key is not exactly 33 bytes")
        })?;
    let key_fingerprint = bat_verification_key_fingerprint_v1(&verification_key)?;
    let offer = verified_offer.offer();
    let scope = verified_offer.scope();
    let claims = &binding.claims;

    let mut hasher = Sha256::new();
    hasher.update(OFFER_NAMESPACE_LINEAGE_DIGEST_DOMAIN_V1);
    hasher.update(scope.provider_id);
    hasher.update(scope.scope_id());
    hasher.update(offer.offer_id.to_le_bytes());
    hasher.update((offer.authorization as u16).to_le_bytes());
    hasher.update(offer.issuer_id);
    hasher.update(scope.entitlement_profile.to_le_bytes());
    hasher.update(claims.keyset_epoch.to_le_bytes());
    hasher.update([claims.unit as u8]);
    hasher.update(claims.amount.to_le_bytes());
    hasher.update(claims.presentation_limit.to_le_bytes());
    hash_len_prefixed(&mut hasher, &claims.credential_key_id);
    hasher.update(key_fingerprint);

    Ok(ExclusiveKeyLineage {
        key_fingerprint,
        lineage_digest: hasher.finalize().into(),
    })
}

fn hash_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    let len = u16::try_from(value.len()).expect("verified V1 key IDs fit in u16");
    hasher.update(len.to_le_bytes());
    hasher.update(value);
}
