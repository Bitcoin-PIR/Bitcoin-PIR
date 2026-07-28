use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use pir_issuer_clearing::RedeemResponseDerivationKeyV1;
use pir_issuer_service::{
    SettlementPayoutPolicyV1, SharedIssuerClearingServiceV1, TrustedClearingProviderV1,
};
use pir_issuer_store::{
    IssuerStore, ProviderSettlementRegistrationWriteV1, SqliteIssuerRollbackFloorAuthorityV1,
    StoreOptions as IssuerStoreOptions,
};
use pir_service_protocol::{
    bind_auth_begin_v1, derive_bat_key_id_v1, derive_issuer_id, free_anonymous_ticket_key_id,
    AcquisitionMethod, ArcPresentationV1, AuthBeginV1, AuthPaddingClassV1, BackendId,
    BitcoinPirCashuBatProofV1, CredentialKeyBindingClaimsV1, CredentialKeyBindingV1,
    CredentialUnitV1, DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1,
    FreeAnonymousTicketV1, FreeModeV1, LightningNetworkV1, OperationStartV1,
    PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1, ProviderClearingAuthorizationClaimsV1,
    ProviderRedeemEnvelopeV1, RedeemSettlementResultV1, ServiceOfferV1,
    ServicePolicyEpochFloorsV1, ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1,
    SettlementModesV1, SettlementRuleV1, TrustedCatalogResolutionV1, VerificationMode,
    VerifiedServiceOfferV1, WorkloadId,
};
use pir_service_store::{
    ProviderStore, RollbackFloorAuthorityV1, SqliteRollbackFloorAuthorityV1, StoreOptions,
};
use tempfile::TempDir;

const NOW: u64 = 1_500;
const PROVIDER_ID: [u8; 32] = [0x31; 32];
const ACCOUNT_ID: [u8; 32] = [0x32; 32];
const GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseModeV1 {
    Good,
    BadSignature,
    OutcomeUnknownOnce,
}

struct SigningRedeemTransportV1 {
    issuer_settlement: SigningKey,
    mode: ResponseModeV1,
    calls: AtomicUsize,
    idempotency_keys: Mutex<Vec<[u8; 32]>>,
}

impl SigningRedeemTransportV1 {
    fn new(issuer_settlement: SigningKey, mode: ResponseModeV1) -> Self {
        Self {
            issuer_settlement,
            mode,
            calls: AtomicUsize::new(0),
            idempotency_keys: Mutex::new(Vec::new()),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn observed_idempotency_keys(&self) -> Vec<[u8; 32]> {
        self.idempotency_keys
            .lock()
            .expect("idempotency-key mutex")
            .clone()
    }
}

impl SharedIssuerRedeemTransportV1 for SigningRedeemTransportV1 {
    fn redeem(
        &self,
        envelope: SharedIssuerRedeemEnvelopeV1<'_>,
        _max_response_bytes: usize,
    ) -> Result<Vec<u8>, SharedIssuerTransportErrorV1> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.idempotency_keys
            .lock()
            .expect("idempotency-key mutex")
            .push(envelope.request.idempotency_key);
        if self.mode == ResponseModeV1::OutcomeUnknownOnce && call == 0 {
            // Model an issuer commit whose HTTP success response was lost. This
            // exercises server-side exact replay for a caller that explicitly
            // retained the identical proof; the Web client intentionally does
            // not treat this as an automatic recovery path.
            return Err(SharedIssuerTransportErrorV1::OutcomeUnknown);
        }
        let account_id = match &envelope.request.destination {
            SettlementDestinationV1::LedgerCredit { account_id } => *account_id,
            SettlementDestinationV1::BlindOutputs { .. } => {
                return Err(SharedIssuerTransportErrorV1::InvalidResponse)
            }
        };
        let response = pir_service_protocol::ProviderRedeemResponseV1::sign(
            pir_service_protocol::ProviderRedeemResponseV1 {
                issuer_settlement_key_id: [1; 16],
                request_digest: envelope
                    .request
                    .request_digest()
                    .map_err(|_| SharedIssuerTransportErrorV1::InvalidResponse)?,
                authorization_digest: envelope.request.authorization_digest,
                issuer_id: envelope.request.issuer_id,
                provider_id: envelope.request.provider_id,
                unit: SettlementUnitV1::AuthCredit,
                accepted_value: envelope.request.accepted_value,
                provider_credit: 9,
                issuer_fee: 1,
                result: RedeemSettlementResultV1::LedgerCredit {
                    account_id,
                    ledger_transaction_id: [0x71; 32],
                },
                signature: [0; 64],
            },
            &self.issuer_settlement,
        )
        .and_then(|response| response.encode())
        .map_err(|_| SharedIssuerTransportErrorV1::InvalidResponse)?;
        let mut response = response;
        if self.mode == ResponseModeV1::BadSignature {
            let last = response
                .last_mut()
                .expect("signed redeem response is non-empty");
            *last ^= 1;
        }
        Ok(response)
    }
}

struct InProcessIssuerTransportV1<'a> {
    service: &'a SharedIssuerClearingServiceV1,
    calls: AtomicUsize,
    lost_response: Mutex<Option<Vec<u8>>>,
}

impl<'a> InProcessIssuerTransportV1<'a> {
    fn new(service: &'a SharedIssuerClearingServiceV1) -> Self {
        Self {
            service,
            calls: AtomicUsize::new(0),
            lost_response: Mutex::new(None),
        }
    }
}

impl SharedIssuerRedeemTransportV1 for InProcessIssuerTransportV1<'_> {
    fn redeem(
        &self,
        envelope: SharedIssuerRedeemEnvelopeV1<'_>,
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, SharedIssuerTransportErrorV1> {
        assert_eq!(envelope.redeem_endpoint, "https://issuer.example");
        assert_eq!(envelope.redeem_leaf_spki_sha256_pins, &[[0x52; 32]]);
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let canonical_envelope = ProviderRedeemEnvelopeV1 {
            request: envelope.request.clone(),
            request_auth: envelope.request_auth.clone(),
            credential_binding: envelope.credential_binding.clone(),
            canonical_credential: envelope.canonical_credential.to_vec(),
        }
        .encode()
        .map_err(|_| SharedIssuerTransportErrorV1::InvalidResponse)?;
        let response = self
            .service
            .redeem(&canonical_envelope, NOW + call as u64)
            .map_err(|_| SharedIssuerTransportErrorV1::InvalidOrSpent)?;
        assert!(response.len() <= max_response_bytes);

        if call == 0 {
            *self
                .lost_response
                .lock()
                .expect("lost-response mutex") = Some(response);
            return Err(SharedIssuerTransportErrorV1::OutcomeUnknown);
        }
        assert_eq!(
            self.lost_response
                .lock()
                .expect("lost-response mutex")
                .as_deref(),
            Some(response.as_slice()),
            "issuer exact replay changed the committed response"
        );
        Ok(response)
    }
}

struct FixtureV1 {
    _directory: TempDir,
    store: ProviderStore,
    policy: ServicePolicyV1,
    policy_key: VerifyingKey,
    authorization: ProviderClearingAuthorizationV1,
    approval: IssuerClearingApprovalV1,
    operator: SigningKey,
    clearing: SigningKey,
    issuer_settlement: SigningKey,
    proof: Vec<u8>,
}

impl FixtureV1 {
    fn new(scheme: AuthScheme) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("bitcoinpir-shared-local-grant-test-")
            .tempdir()
            .expect("create shared local-grant test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("restrict shared local-grant test directory permissions");
        }

        let issuer_root = SigningKey::from_bytes(&[0x21; 32]);
        let issuer_id = derive_issuer_id(&issuer_root.verifying_key().to_bytes());
        let policy_signing = SigningKey::from_bytes(&[0x22; 32]);
        let operator = SigningKey::from_bytes(&[0x23; 32]);
        let clearing = SigningKey::from_bytes(&[0x24; 32]);
        let issuer_settlement = SigningKey::from_bytes(&[0x25; 32]);
        let credential_signing = SigningKey::from_bytes(&[0x26; 32]);
        let scope = ServiceScopeV1 {
            provider_id: PROVIDER_ID,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 7 },
            operation_profile: 3,
            entitlement_profile: 9,
        };
        let scope_id = scope.scope_id();
        let offer_id = match scheme {
            AuthScheme::FreeV1 => 11,
            AuthScheme::BitcoinPirCashuBatV1 => 12,
            AuthScheme::ArcV1Experimental => 13,
            _ => panic!("test helper accepts only shared credential schemes"),
        };
        let (credential_key_id, verification_key, unit, presentation_limit) = match scheme {
            AuthScheme::FreeV1 => (
                free_anonymous_ticket_key_id(&credential_signing.verifying_key()).to_vec(),
                credential_signing.verifying_key().to_bytes().to_vec(),
                CredentialUnitV1::Entitlement,
                1,
            ),
            AuthScheme::BitcoinPirCashuBatV1 => (
                derive_bat_key_id_v1(
                    &PROVIDER_ID,
                    &scope_id,
                    offer_id,
                    scope.entitlement_profile,
                    1,
                    &GENERATOR,
                )
                .to_vec(),
                GENERATOR.to_vec(),
                CredentialUnitV1::Auth,
                1,
            ),
            AuthScheme::ArcV1Experimental => {
                (vec![0x42; 16], vec![0x43; 99], CredentialUnitV1::Auth, 2)
            }
            _ => unreachable!(),
        };
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id: PROVIDER_ID,
                scope_id,
                offer_id,
                scheme,
                keyset_epoch: 1,
                entitlement_profile: scope.entitlement_profile,
                unit,
                amount: 1,
                presentation_limit,
                not_before: 1_000,
                not_after: 2_200,
                credential_key_id: credential_key_id.clone(),
                verification_key,
            },
            &issuer_root,
        )
        .expect("sign credential binding");
        let offer = ServiceOfferV1 {
            offer_id,
            acquisition: if scheme == AuthScheme::FreeV1 {
                AcquisitionMethod::FreeV1
            } else {
                AcquisitionMethod::Bolt11V1
            },
            free_mode: if scheme == AuthScheme::FreeV1 {
                FreeModeV1::AnonymousTicket
            } else {
                FreeModeV1::NotFree
            },
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: scheme,
            verification: VerificationMode::SharedIssuerOnline,
            deployment_status: if scheme == AuthScheme::ArcV1Experimental {
                DeploymentStatus::Experimental
            } else {
                DeploymentStatus::Stable
            },
            price: if scheme == AuthScheme::FreeV1 {
                PriceV1::Free
            } else {
                PriceV1::MilliSatoshi(1_000)
            },
            issuer_id,
            key_id: credential_key_id,
            credential_binding: Some(binding.clone()),
            cashu_mint_manifest: None,
            endpoint: "https://issuer.example".to_owned(),
            invoice_expiry_seconds: if scheme == AuthScheme::FreeV1 { 0 } else { 60 },
            claim_window_seconds: if scheme == AuthScheme::FreeV1 { 0 } else { 60 },
            minimum_credential_validity_seconds: 60,
            retired_policy_grace_seconds: 200,
            credential_count: 1,
            credential_presentation_limit: presentation_limit,
            privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::KNOWN_MASK)
                .expect("known privacy bits"),
        };
        let policy = ServicePolicyV1::sign(
            PROVIDER_ID,
            1,
            1_000,
            2_000,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 8,
                    max_request_bytes: 1_000_000,
                    max_response_bytes: 2_000_000,
                    max_wall_time_ms: 60_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 9_000,
                },
                offers: vec![offer],
            }],
            &policy_signing,
        )
        .expect("sign service policy");
        let authorization = ProviderClearingAuthorizationV1::sign(
            ProviderClearingAuthorizationClaimsV1 {
                authorization_id: [0x51; 16],
                authorization_epoch: 1,
                provider_id: PROVIDER_ID,
                issuer_id,
                redeem_endpoint: "https://issuer.example".to_owned(),
                redeem_leaf_spki_sha256_pins: vec![[0x52; 32]],
                settlement_account_id: ACCOUNT_ID,
                clearing_verifying_key: clearing.verifying_key().to_bytes(),
                not_before: 1_000,
                not_after: 2_000,
                rules: vec![SettlementRuleV1 {
                    credential_binding_digest: binding
                        .binding_digest()
                        .expect("credential binding digest"),
                    unit: SettlementUnitV1::AuthCredit,
                    accepted_value: 10,
                    provider_credit: 9,
                    issuer_fee: 1,
                    denomination_profile: 1,
                    settlement_modes: SettlementModesV1::from_bits(
                        SettlementModesV1::LEDGER_CREDIT,
                    )
                    .expect("ledger settlement mode"),
                    blind_output_minimum_validity_seconds: 0,
                    blind_output_keyset: None,
                }],
            },
            &operator,
        )
        .expect("sign clearing authorization");
        let approval =
            IssuerClearingApprovalV1::sign(&authorization, 1_000, 2_000, &issuer_settlement)
                .expect("sign issuer approval");

        let proof = match scheme {
            AuthScheme::FreeV1 => FreeAnonymousTicketV1::sign(
                PROVIDER_ID,
                scope_id,
                offer_id,
                policy.policy_digest().expect("policy digest"),
                9,
                issuer_id,
                [0x61; 32],
                1_000,
                2_000,
                &credential_signing,
            )
            .and_then(|ticket| ticket.encode())
            .expect("encode free ticket"),
            AuthScheme::BitcoinPirCashuBatV1 => BitcoinPirCashuBatProofV1 {
                secret_raw: [0x62; 32],
                c: GENERATOR,
            }
            .encode()
            .expect("encode BAT proof")
            .to_vec(),
            AuthScheme::ArcV1Experimental => {
                ArcPresentationV1::from_canonical_bytes(vec![0x63, 0x64, 0x65])
                    .and_then(|presentation| presentation.encode())
                    .expect("encode ARC presentation")
            }
            _ => unreachable!(),
        };

        let rollback = Arc::new(
            SqliteRollbackFloorAuthorityV1::create(
                directory.path().join("rollback.sqlite3"),
                Duration::from_secs(1),
            )
            .expect("create rollback authority"),
        );
        let store = ProviderStore::create(
            directory.path().join("provider.sqlite3"),
            [0x71; 16],
            PROVIDER_ID,
            StoreOptions::default(),
            rollback as Arc<dyn RollbackFloorAuthorityV1>,
        )
        .expect("create provider store");
        let verified_offer = verified_offer_v1(&policy, &policy_signing.verifying_key());
        let namespace_outcome = store
            .install_verified_offer_namespace_v1(&verified_offer, NOW, None)
            .expect("install shared local-grant namespace");
        assert!(matches!(
            namespace_outcome,
            pir_service_store::VerifiedOfferNamespaceInstallOutcomeV1::Namespace { .. }
        ));

        Self {
            _directory: directory,
            store,
            policy,
            policy_key: policy_signing.verifying_key(),
            authorization,
            approval,
            operator,
            clearing,
            issuer_settlement,
            proof,
        }
    }

    fn verified_offer(&self) -> VerifiedServiceOfferV1<'_> {
        verified_offer_v1(&self.policy, &self.policy_key)
    }

    fn bound_attempt(&self) -> BoundAuthAttemptV1<'_> {
        let verified_offer = self.verified_offer();
        let request = AuthBeginV1 {
            policy_digest: verified_offer.policy_digest(),
            scope_id: verified_offer.scope().scope_id(),
            offer_id: verified_offer.offer().offer_id,
            scheme: verified_offer.offer().authorization,
            key_id: verified_offer.offer().key_id.clone(),
            operation: OperationStartV1::DpfQuery { db_id: 7 },
            proof: self.proof.clone(),
        };
        let scope = verified_offer.scope().clone();
        let catalog = move |_operation: &OperationStartV1| {
            Some(TrustedCatalogResolutionV1::new(
                7,
                scope.backend,
                scope.workload,
                scope.protocol_version,
                scope.dataset.clone(),
                scope.operation_profile,
            ))
        };
        let canonicalizer = |bytes: &[u8]| Ok(bytes.to_vec());
        bind_auth_begin_v1(&request, verified_offer, &catalog, Some(&canonicalizer))
            .expect("bind shared issuer auth attempt")
    }

    fn committer<'a>(
        &self,
        transport: &'a dyn SharedIssuerRedeemTransportV1,
    ) -> SharedIssuerAdmissionCommitterV1<'a> {
        SharedIssuerAdmissionCommitterV1::new(
            self.authorization.clone(),
            self.approval.clone(),
            self.operator.verifying_key(),
            self.issuer_settlement.verifying_key(),
            self.clearing.clone(),
            1,
            ProviderRedeemIdempotencyKeyV1::from_bytes([0x72; 32]).expect("provider shared secret"),
            self.store.clone(),
            transport,
        )
        .expect("construct shared issuer committer")
    }
}

fn real_issuer_service_v1(fixture: &FixtureV1) -> SharedIssuerClearingServiceV1 {
    let issuer_root = SigningKey::from_bytes(&[0x21; 32]);
    let issuer_id = derive_issuer_id(&issuer_root.verifying_key().to_bytes());
    let rollback = Arc::new(
        SqliteIssuerRollbackFloorAuthorityV1::create(
            fixture._directory.path().join("issuer-rollback.sqlite3"),
            IssuerStoreOptions::default().busy_timeout,
        )
        .expect("create issuer rollback authority"),
    );
    let store = IssuerStore::create(
        fixture._directory.path().join("issuer.sqlite3"),
        [0x75; 16],
        issuer_id,
        LightningNetworkV1::Regtest,
        IssuerStoreOptions::default(),
        rollback,
    )
    .expect("create issuer store");
    let provider_request = SigningKey::from_bytes(&[0x76; 32]);
    let _ = store
        .register_provider_settlement(&ProviderSettlementRegistrationWriteV1 {
            registration_epoch: 1,
            provider_id: PROVIDER_ID,
            settlement_account_id: ACCOUNT_ID,
            provider_request_verifying_key: provider_request.verifying_key().to_bytes(),
            payout_target_id: [0x77; 32],
            not_before: 1_000,
            not_after: 2_000,
        })
        .expect("register provider settlement");
    let _ = store
        .register_clearing_authorization(
            &fixture.authorization,
            &fixture.approval,
            &fixture.operator.verifying_key(),
            &fixture.issuer_settlement.verifying_key(),
            NOW,
        )
        .expect("register clearing authorization");

    SharedIssuerClearingServiceV1::new(
        store,
        vec![TrustedClearingProviderV1 {
            provider_id: PROVIDER_ID,
            operator_key: fixture.operator.verifying_key(),
            minimum_authorization_epoch: 1,
        }],
        None,
        None,
        fixture.issuer_settlement.clone(),
        Vec::new(),
        None,
        Vec::new(),
        RedeemResponseDerivationKeyV1::from_bytes([0x78; 32])
            .expect("redeem response derivation key"),
        SettlementPayoutPolicyV1::new(1, 60).expect("settlement payout policy"),
    )
    .expect("construct real issuer service")
}

fn verified_offer_v1<'a>(
    policy: &'a ServicePolicyV1,
    policy_key: &VerifyingKey,
) -> VerifiedServiceOfferV1<'a> {
    let verified = policy
        .verify_current_for_acquisition(
            &PROVIDER_ID,
            NOW,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::default(),
            policy_key,
        )
        .expect("verify service policy");
    let scope_id = policy.scopes[0].scope.scope_id();
    verified
        .offer(&scope_id, policy.scopes[0].offers[0].offer_id)
        .expect("select verified offer")
}

fn route_for(scheme: AuthScheme) -> AdmissionMethodRouteV1 {
    match scheme {
        AuthScheme::FreeV1 => AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline,
        AuthScheme::BitcoinPirCashuBatV1 => {
            AdmissionMethodRouteV1::BitcoinPirCashuBatSharedIssuerOnline
        }
        AuthScheme::ArcV1Experimental => AdmissionMethodRouteV1::ArcSharedIssuerOnlineExperimental,
        _ => panic!("not a shared issuer route"),
    }
}

#[test]
fn shared_free_bat_and_arc_exact_replay_never_install_a_second_local_grant() {
    for scheme in [
        AuthScheme::FreeV1,
        AuthScheme::BitcoinPirCashuBatV1,
        AuthScheme::ArcV1Experimental,
    ] {
        let fixture = FixtureV1::new(scheme);
        let transport =
            SigningRedeemTransportV1::new(fixture.issuer_settlement.clone(), ResponseModeV1::Good);
        let committer = fixture.committer(&transport);
        assert_eq!(
            committer.verify_and_commit_v1(route_for(scheme), &fixture.bound_attempt(), NOW),
            Ok(())
        );
        assert_eq!(
            committer.verify_and_commit_v1(route_for(scheme), &fixture.bound_attempt(), NOW),
            Err(AdmissionCommitErrorV1::InvalidOrSpent)
        );
        assert_eq!(transport.call_count(), 2);
        assert_eq!(
            fixture
                .store
                .operational_inventory()
                .expect("provider inventory")
                .spent_capability_rows,
            1
        );
    }
}

#[test]
fn concurrent_exact_shared_response_has_exactly_one_local_winner() {
    const WORKERS: usize = 8;
    let fixture = Arc::new(FixtureV1::new(AuthScheme::FreeV1));
    let transport = Arc::new(SigningRedeemTransportV1::new(
        fixture.issuer_settlement.clone(),
        ResponseModeV1::Good,
    ));
    let barrier = Arc::new(Barrier::new(WORKERS));
    let outcomes = (0..WORKERS)
        .map(|_| {
            let fixture = Arc::clone(&fixture);
            let transport = Arc::clone(&transport);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let committer = fixture.committer(transport.as_ref());
                let attempt = fixture.bound_attempt();
                barrier.wait();
                committer.verify_and_commit_v1(
                    AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline,
                    &attempt,
                    NOW,
                )
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|worker| worker.join().expect("shared claim worker"))
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| { **outcome == Err(AdmissionCommitErrorV1::InvalidOrSpent) })
            .count(),
        WORKERS - 1
    );
    assert_eq!(
        fixture
            .store
            .operational_inventory()
            .expect("provider inventory")
            .spent_capability_rows,
        1
    );
}

#[test]
fn server_side_exact_replay_is_safe_when_caller_explicitly_retains_identical_proof() {
    let fixture = FixtureV1::new(AuthScheme::FreeV1);
    let transport = SigningRedeemTransportV1::new(
        fixture.issuer_settlement.clone(),
        ResponseModeV1::OutcomeUnknownOnce,
    );
    let committer = fixture.committer(&transport);
    assert_eq!(
        committer.verify_and_commit_v1(
            AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline,
            &fixture.bound_attempt(),
            NOW,
        ),
        Err(AdmissionCommitErrorV1::InternalAfterSpend)
    );
    assert_eq!(
        fixture
            .store
            .operational_inventory()
            .expect("provider inventory")
            .spent_capability_rows,
        0
    );
    assert_eq!(
        committer.verify_and_commit_v1(
            AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline,
            &fixture.bound_attempt(),
            NOW + 1,
        ),
        Ok(())
    );
    // The provider-local claim key is derived from stable request coordinates,
    // not the retry clock. A later exact issuer replay must therefore hit the
    // same durable local claim instead of yielding a second grant.
    assert_eq!(
        committer.verify_and_commit_v1(
            AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline,
            &fixture.bound_attempt(),
            NOW + 2,
        ),
        Err(AdmissionCommitErrorV1::InvalidOrSpent)
    );
    let keys = transport.observed_idempotency_keys();
    assert_eq!(keys.len(), 3);
    assert!(keys.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn real_issuer_exact_replay_then_provider_local_claim_grants_only_once() {
    let fixture = FixtureV1::new(AuthScheme::FreeV1);
    let issuer = real_issuer_service_v1(&fixture);
    let transport = InProcessIssuerTransportV1::new(&issuer);
    let committer = fixture.committer(&transport);

    assert_eq!(
        committer.verify_and_commit_v1(
            AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline,
            &fixture.bound_attempt(),
            NOW,
        ),
        Err(AdmissionCommitErrorV1::InternalAfterSpend)
    );
    assert_eq!(
        fixture
            .store
            .operational_inventory()
            .expect("provider inventory after lost issuer response")
            .spent_capability_rows,
        0
    );
    assert_eq!(
        committer.verify_and_commit_v1(
            AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline,
            &fixture.bound_attempt(),
            NOW + 1,
        ),
        Ok(())
    );
    assert_eq!(
        committer.verify_and_commit_v1(
            AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline,
            &fixture.bound_attempt(),
            NOW + 2,
        ),
        Err(AdmissionCommitErrorV1::InvalidOrSpent)
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        fixture
            .store
            .operational_inventory()
            .expect("provider inventory after exact issuer replay")
            .spent_capability_rows,
        1
    );
}

#[test]
fn bad_issuer_response_never_creates_a_local_claim() {
    let fixture = FixtureV1::new(AuthScheme::FreeV1);
    let transport = SigningRedeemTransportV1::new(
        fixture.issuer_settlement.clone(),
        ResponseModeV1::BadSignature,
    );
    let committer = fixture.committer(&transport);
    assert_eq!(
        committer.verify_and_commit_v1(
            AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline,
            &fixture.bound_attempt(),
            NOW,
        ),
        Err(AdmissionCommitErrorV1::InternalAfterSpend)
    );
    assert_eq!(
        fixture
            .store
            .operational_inventory()
            .expect("provider inventory")
            .spent_capability_rows,
        0
    );
}

#[test]
fn shared_committer_rejects_a_store_for_another_provider_before_transport() {
    let fixture = FixtureV1::new(AuthScheme::FreeV1);
    let second_directory = tempfile::Builder::new()
        .prefix("bitcoinpir-wrong-provider-store-test-")
        .tempdir()
        .expect("create wrong-provider test directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            second_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("restrict wrong-provider test directory permissions");
    }
    let authority = Arc::new(
        SqliteRollbackFloorAuthorityV1::create(
            second_directory.path().join("rollback.sqlite3"),
            Duration::from_secs(1),
        )
        .expect("create wrong-provider authority"),
    );
    let wrong_store = ProviderStore::create(
        second_directory.path().join("provider.sqlite3"),
        [0x73; 16],
        [0x74; 32],
        StoreOptions::default(),
        authority as Arc<dyn RollbackFloorAuthorityV1>,
    )
    .expect("create wrong-provider store");
    let transport =
        SigningRedeemTransportV1::new(fixture.issuer_settlement.clone(), ResponseModeV1::Good);
    assert!(SharedIssuerAdmissionCommitterV1::new(
        fixture.authorization,
        fixture.approval,
        fixture.operator.verifying_key(),
        fixture.issuer_settlement.verifying_key(),
        fixture.clearing,
        1,
        ProviderRedeemIdempotencyKeyV1::from_bytes([0x72; 32]).unwrap(),
        wrong_store,
        &transport,
    )
    .is_err());
    assert_eq!(transport.call_count(), 0);
}
