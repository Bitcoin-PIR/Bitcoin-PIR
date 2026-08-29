use super::*;
use ed25519_dalek::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use pir_issuer_store::StoreOptions;
use pir_lightning_backend::{
    CreatedInvoiceV1, FakeFailurePointV1, FakeLightningNodeV1, InvoiceObservationV1,
};
use pir_service_protocol::{
    derive_bat_key_id_v1, derive_issuer_id, AcquisitionMethod, AuthPaddingClassV1, AuthScheme,
    BackendId, Bolt11QuoteIntentV1, Bolt11QuoteKeyRollbackGuardV1, CredentialKeyBindingClaimsV1,
    CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1, DeploymentStatus,
    EntitlementLimitsV1, FreeModeV1, LightningNetworkV1, PolicyRollbackGuardV1, PriceV1,
    PrivacyLeakageV1, ServiceOfferV1, ServicePolicyEpochFloorsV1, ServicePolicyV1,
    ServiceScopePolicyV1, ServiceScopeV1, VerificationMode, WorkloadId,
};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use tempfile::{Builder, TempDir};

const NOW: u64 = 1_700_000_000;
const STORE_INSTANCE: [u8; 16] = [0x31; 16];
const EXACT_AMOUNT_MSAT: u64 = 100_000;

#[derive(Debug)]
struct SequentialQuoteIds {
    next: AtomicU8,
    calls: AtomicUsize,
}

impl SequentialQuoteIds {
    fn new(first: u8) -> Self {
        Self {
            next: AtomicU8::new(first),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl QuoteIdSourceV1 for SequentialQuoteIds {
    fn next_quote_id(&self) -> Result<[u8; 32], QuoteIdSourceErrorV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let value = self.next.fetch_add(1, Ordering::SeqCst);
        if value == 0 || value == u8::MAX {
            return Err(QuoteIdSourceErrorV1::Exhausted);
        }
        Ok([value; 32])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum CreatedTamper {
    None = 0,
    PaymentHash = 1,
}

struct RecordingBackend {
    node: FakeLightningNodeV1,
    create_labels: Mutex<Vec<String>>,
    tamper_created: AtomicU8,
    observation_override: Mutex<Option<InvoiceObservationStateV1>>,
}

impl fmt::Debug for RecordingBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingBackend")
            .field("node", &"[redacted]")
            .field("requests", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl RecordingBackend {
    fn new(node_time: u64) -> Self {
        Self {
            node: FakeLightningNodeV1::new(
                LightningNetworkV1::Regtest,
                [3; 32],
                [7; 32],
                node_time,
            )
            .expect("construct fake node"),
            create_labels: Mutex::new(Vec::new()),
            tamper_created: AtomicU8::new(CreatedTamper::None as u8),
            observation_override: Mutex::new(None),
        }
    }

    fn payee_pubkey(&self) -> [u8; 33] {
        self.node.payee_pubkey()
    }

    fn set_created_tamper(&self, value: CreatedTamper) {
        self.tamper_created.store(value as u8, Ordering::SeqCst);
    }

    fn set_observation_override(&self, value: Option<InvoiceObservationStateV1>) {
        *self
            .observation_override
            .lock()
            .expect("observation override mutex") = value;
    }

    fn unique_create_labels(&self) -> usize {
        self.create_labels
            .lock()
            .expect("create labels mutex")
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .len()
    }

    fn create_calls(&self) -> usize {
        self.create_labels
            .lock()
            .expect("create labels mutex")
            .len()
    }
}

impl LightningInvoiceBackendV1 for RecordingBackend {
    fn create_or_get_invoice(
        &self,
        request: &CreateInvoiceRequestV1,
    ) -> Result<CreatedInvoiceV1, LightningBackendErrorV1> {
        self.create_labels
            .lock()
            .map_err(|_| LightningBackendErrorV1::LockPoisoned)?
            .push(request.backend_label.clone());
        let mut created = self.node.create_or_get_invoice(request)?;
        if self.tamper_created.load(Ordering::SeqCst) == CreatedTamper::PaymentHash as u8 {
            created.payment_hash[0] ^= 1;
        }
        Ok(created)
    }

    fn existing_invoice(
        &self,
        backend_label: &str,
    ) -> Result<Option<CreatedInvoiceV1>, LightningBackendErrorV1> {
        let Some(mut created) = self.node.existing_invoice(backend_label)? else {
            return Ok(None);
        };
        if self.tamper_created.load(Ordering::SeqCst) == CreatedTamper::PaymentHash as u8 {
            created.payment_hash[0] ^= 1;
        }
        Ok(Some(created))
    }

    fn lookup_invoice(
        &self,
        backend_label: &str,
        observed_at: u64,
    ) -> Result<InvoiceObservationV1, LightningBackendErrorV1> {
        let mut observation = self.node.lookup_invoice(backend_label, observed_at)?;
        if let Some(override_state) = *self
            .observation_override
            .lock()
            .map_err(|_| LightningBackendErrorV1::LockPoisoned)?
        {
            observation.state = override_state;
        }
        Ok(observation)
    }
}

struct QuoteFixture {
    policy: ServicePolicyV1,
    policy_key: SigningKey,
    delegation: Bolt11QuoteKeyDelegationV1,
    quote_key: SigningKey,
    intent: Bolt11QuoteIntentV1,
    scope_id: [u8; 32],
}

impl QuoteFixture {
    fn new(payee_pubkey: [u8; 33], quote_key_byte: u8, epoch: u64, idempotency: u8) -> Self {
        let issuer_root = SigningKey::from_bytes(&[0x41; 32]);
        let issuer_id = derive_issuer_id(&issuer_root.verifying_key().to_bytes());
        let provider_id = [0x42; 32];
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 2,
            entitlement_profile: 3,
        };
        let scope_id = scope.scope_id();
        let credential_point = compressed_point(11);
        let credential_key_id = derive_bat_key_id_v1(
            &provider_id,
            &scope_id,
            9,
            scope.entitlement_profile,
            1,
            &credential_point,
        )
        .to_vec();
        let credential_binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id,
                offer_id: 9,
                scheme: AuthScheme::BitcoinPirCashuBatV1,
                keyset_epoch: 1,
                entitlement_profile: scope.entitlement_profile,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 1,
                not_before: NOW - 100,
                not_after: NOW + 3_500,
                credential_key_id: credential_key_id.clone(),
                verification_key: credential_point.to_vec(),
            },
            &issuer_root,
        )
        .expect("sign credential binding");
        let offer = ServiceOfferV1 {
            offer_id: 9,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::BitcoinPirCashuBatV1,
            verification: VerificationMode::SharedIssuerOnline,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::MilliSatoshi(EXACT_AMOUNT_MSAT),
            issuer_id,
            key_id: credential_key_id,
            credential_binding: Some(credential_binding),
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".into(),
            invoice_expiry_seconds: 60,
            claim_window_seconds: 120,
            minimum_credential_validity_seconds: 300,
            retired_policy_grace_seconds: 1_000,
            credential_count: 4,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                    | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .expect("privacy flags"),
        };
        let policy_key = SigningKey::from_bytes(&[0x43; 32]);
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            NOW - 100,
            NOW + 3_000,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 10,
                    max_request_bytes: 10_000,
                    max_response_bytes: 20_000,
                    max_wall_time_ms: 1_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 100,
                },
                offers: vec![offer],
            }],
            &policy_key,
        )
        .expect("sign policy");
        let quote_key = SigningKey::from_bytes(&[quote_key_byte; 32]);
        let delegation = Bolt11QuoteKeyDelegationV1::sign(
            LightningNetworkV1::Regtest,
            payee_pubkey,
            epoch,
            NOW - 100,
            NOW + 3_500,
            quote_key.verifying_key().to_bytes(),
            &issuer_root,
        )
        .expect("sign quote delegation");
        let verified_policy = policy
            .verify_current_for_acquisition(
                &provider_id,
                NOW,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &policy_key.verifying_key(),
            )
            .expect("verify policy");
        let verified_offer = verified_policy.offer(&scope_id, 9).expect("find offer");
        let guard = Bolt11QuoteKeyRollbackGuardV1::initial(
            issuer_id,
            LightningNetworkV1::Regtest,
            payee_pubkey,
        )
        .expect("construct quote-key guard");
        let (intent, _) = Bolt11QuoteIntentV1::from_verified_offer_guarded(
            &verified_offer,
            &delegation,
            &guard,
            NOW,
            xonly_point(5),
            [idempotency; 32],
        )
        .expect("construct quote intent");
        Self {
            policy,
            policy_key,
            delegation,
            quote_key,
            intent,
            scope_id,
        }
    }

    fn verified_intent(&self, now_unix: u64) -> VerifiedBolt11QuoteIntentV1<'_> {
        let verified_policy = self
            .policy
            .verify_current_for_acquisition(
                &self.policy.provider_id,
                now_unix,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &self.policy_key.verifying_key(),
            )
            .expect("verify policy");
        let verified_offer = verified_policy
            .offer(&self.scope_id, 9)
            .expect("find offer");
        let guard = Bolt11QuoteKeyRollbackGuardV1::initial(
            self.delegation.issuer_id,
            LightningNetworkV1::Regtest,
            self.delegation.expected_payee_pubkey,
        )
        .expect("construct quote-key guard");
        self.intent
            .verify_for_offer_guarded(&verified_offer, &self.delegation, &guard, now_unix)
            .expect("verify quote intent")
    }

    fn issuer_id(&self) -> [u8; 32] {
        self.delegation.issuer_id
    }
}

type TestCore = Bolt11IssuerCoreV1<RecordingBackend, SequentialQuoteIds>;

struct Harness {
    _directory: TempDir,
    database: PathBuf,
    backend: Arc<RecordingBackend>,
    quote_ids: Arc<SequentialQuoteIds>,
    fixture: QuoteFixture,
    store: IssuerStore,
    core: Arc<TestCore>,
}

impl Harness {
    fn new(node_time: u64) -> Self {
        let directory = Builder::new()
            .prefix("bitcoinpir-issuer-core-test-")
            .tempdir()
            .expect("create temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("restrict temporary directory permissions");
        }
        let database = directory.path().join("issuer.sqlite3");
        let backend = Arc::new(RecordingBackend::new(node_time));
        let fixture = QuoteFixture::new(backend.payee_pubkey(), 0x44, 4, 0x45);
        let store = IssuerStore::create(
            &database,
            STORE_INSTANCE,
            fixture.issuer_id(),
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
        )
        .expect("create issuer store");
        let quote_ids = Arc::new(SequentialQuoteIds::new(0x51));
        let core = Arc::new(Bolt11IssuerCoreV1::new(
            store.clone(),
            backend.clone(),
            quote_ids.clone(),
        ));
        Self {
            _directory: directory,
            database,
            backend,
            quote_ids,
            fixture,
            store,
            core,
        }
    }

    fn reopen_core(&self) -> Arc<TestCore> {
        let store = IssuerStore::open_existing(
            &self.database,
            self.fixture.issuer_id(),
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
        )
        .expect("reopen issuer store");
        Arc::new(Bolt11IssuerCoreV1::new(
            store,
            self.backend.clone(),
            self.quote_ids.clone(),
        ))
    }

    fn create_quote(&self) -> QuoteCreateResultV1 {
        self.core
            .create_or_recover_quote(
                &self.fixture.verified_intent(NOW),
                &self.fixture.quote_key,
                NOW,
            )
            .expect("create quote")
    }

    fn record(&self) -> QuoteRecord {
        self.store
            .quote_by_creation_idempotency_key(&self.fixture.intent.idempotency_key)
            .expect("read quote")
            .expect("quote exists")
    }
}

fn compressed_point(multiplier: u64) -> [u8; 33] {
    let encoded = (ProjectivePoint::GENERATOR * Scalar::from(multiplier))
        .to_affine()
        .to_encoded_point(true);
    encoded.as_bytes().try_into().expect("compressed point")
}

fn xonly_point(multiplier: u64) -> [u8; 32] {
    compressed_point(multiplier)[1..]
        .try_into()
        .expect("x-only point")
}

fn expect_core_error<T>(result: Result<T, IssuerCoreErrorV1>) -> IssuerCoreErrorV1 {
    match result {
        Ok(_) => panic!("expected issuer-core failure"),
        Err(error) => error,
    }
}

#[test]
fn invoice_description_hash_is_public_fixed_and_query_independent() {
    let expected = pir_lightning_backend::anonymous_invoice_description_hash_v1();
    assert!(expected.iter().any(|byte| *byte != 0));
    assert_eq!(
        expected,
        pir_lightning_backend::anonymous_invoice_description_hash_v1()
    );
}

#[test]
fn concurrent_same_idempotency_key_produces_one_invoice_identity() {
    let harness = Harness::new(NOW);
    let barrier = Arc::new(Barrier::new(3));
    let mut responses = Vec::new();
    std::thread::scope(|scope| {
        let first = {
            let core = harness.core.clone();
            let barrier = barrier.clone();
            let fixture = &harness.fixture;
            scope.spawn(move || {
                barrier.wait();
                core.create_or_recover_quote(&fixture.verified_intent(NOW), &fixture.quote_key, NOW)
                    .expect("first concurrent create")
                    .into_exact_signed_quote_response()
            })
        };
        let second = {
            let core = harness.core.clone();
            let barrier = barrier.clone();
            let fixture = &harness.fixture;
            scope.spawn(move || {
                barrier.wait();
                core.create_or_recover_quote(&fixture.verified_intent(NOW), &fixture.quote_key, NOW)
                    .expect("second concurrent create")
                    .into_exact_signed_quote_response()
            })
        };
        barrier.wait();
        responses.push(first.join().expect("first thread"));
        responses.push(second.join().expect("second thread"));
    });
    assert_eq!(responses[0], responses[1]);
    assert_eq!(harness.backend.unique_create_labels(), 1);
    assert_eq!(harness.record().state, QuoteState::InvoiceOpen);
}

#[test]
fn lost_backend_create_response_recovers_exact_bytes_without_new_label() {
    let harness = Harness::new(NOW);
    harness
        .backend
        .node
        .fail_once(FakeFailurePointV1::CreateAfterCommitOnce)
        .expect("inject failure");
    let first = expect_core_error(harness.core.create_or_recover_quote(
        &harness.fixture.verified_intent(NOW),
        &harness.fixture.quote_key,
        NOW,
    ));
    assert_eq!(first, IssuerCoreErrorV1::OutcomeUnknown);
    assert_eq!(harness.record().state, QuoteState::Reserved);

    let recovered = harness.create_quote();
    assert_eq!(
        recovered.disposition(),
        QuoteCreateDispositionV1::RecoveredReserved
    );
    let exact = recovered.into_exact_signed_quote_response();
    let replay = harness.create_quote().into_exact_signed_quote_response();
    assert_eq!(replay, exact);
    assert_eq!(harness.backend.unique_create_labels(), 1);
    assert_eq!(harness.backend.create_calls(), 1);
}

#[test]
fn restart_recovers_reserved_backend_commit_with_original_timestamp_window() {
    let harness = Harness::new(NOW);
    harness
        .backend
        .node
        .fail_once(FakeFailurePointV1::CreateAfterCommitOnce)
        .expect("inject failure");
    assert_eq!(
        expect_core_error(harness.core.create_or_recover_quote(
            &harness.fixture.verified_intent(NOW),
            &harness.fixture.quote_key,
            NOW,
        )),
        IssuerCoreErrorV1::OutcomeUnknown
    );
    harness
        .backend
        .node
        .set_time(NOW + 20)
        .expect("advance fake clock");
    let restarted = harness.reopen_core();
    let result = restarted
        .create_or_recover_quote(
            &harness.fixture.verified_intent(NOW + 20),
            &harness.fixture.quote_key,
            NOW + 20,
        )
        .expect("restart recovery");
    assert_eq!(
        result.disposition(),
        QuoteCreateDispositionV1::RecoveredReserved
    );
    let quote = Bolt11QuoteV1::decode(result.exact_signed_quote_response()).expect("decode quote");
    assert_eq!(quote.invoice_created_at, NOW);
    assert_eq!(harness.backend.unique_create_labels(), 1);
}

#[test]
fn background_reconciliation_recovers_reserved_without_raw_idempotency_key() {
    let harness = Harness::new(NOW);
    harness
        .backend
        .node
        .fail_once(FakeFailurePointV1::CreateAfterCommitOnce)
        .expect("inject failure");
    assert_eq!(
        expect_core_error(harness.core.create_or_recover_quote(
            &harness.fixture.verified_intent(NOW),
            &harness.fixture.quote_key,
            NOW,
        )),
        IssuerCoreErrorV1::OutcomeUnknown
    );
    let reserved = harness.record();
    harness
        .backend
        .node
        .set_time(NOW + INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1 + 1)
        .expect("advance beyond reservation creation window");
    let restarted = harness.reopen_core();
    let recovered = restarted
        .reconcile_by_backend_label(
            &reserved.backend_label,
            &harness.fixture.quote_key,
            NOW + INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1 + 1,
        )
        .expect("background recovery");
    assert_eq!(recovered.durable_state(), QuoteState::InvoiceOpen);
    assert_eq!(
        recovered.disposition(),
        QuoteReconcileDispositionV1::Transitioned
    );
    let quote = Bolt11QuoteV1::decode(recovered.exact_signed_quote_response())
        .expect("decode recovered quote");
    assert_eq!(
        quote.request_digest,
        harness.fixture.intent.request_digest().unwrap()
    );
    assert_eq!(quote.invoice_created_at, NOW);
    let parsed = ParsedBolt11InvoiceV1::parse(&quote.invoice).expect("parse recovered invoice");
    quote
        .verify_snapshot(
            &harness.fixture.intent,
            &harness.fixture.delegation,
            &parsed,
            NOW + INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1 + 1,
        )
        .expect("recovered snapshot verifies against the original client intent");
    assert_eq!(harness.backend.create_calls(), 1);
}

#[test]
fn stale_reserved_reconciliation_never_creates_a_new_orphan_invoice() {
    let harness = Harness::new(NOW);
    harness
        .backend
        .node
        .fail_once(FakeFailurePointV1::CreateBeforeCommitOnce)
        .expect("inject precommit failure");
    assert_eq!(
        expect_core_error(harness.core.create_or_recover_quote(
            &harness.fixture.verified_intent(NOW),
            &harness.fixture.quote_key,
            NOW,
        )),
        IssuerCoreErrorV1::RetryableUnavailable
    );
    let reserved = harness.record();
    harness
        .backend
        .node
        .set_time(NOW + INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1 + 1)
        .expect("advance beyond reservation creation window");
    assert_eq!(
        expect_core_error(harness.core.reconcile_by_backend_label(
            &reserved.backend_label,
            &harness.fixture.quote_key,
            NOW + INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1 + 1,
        )),
        IssuerCoreErrorV1::InvalidState
    );
    assert_eq!(
        expect_core_error(
            harness.core.create_or_recover_quote(
                &harness
                    .fixture
                    .verified_intent(NOW + INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1 + 1),
                &harness.fixture.quote_key,
                NOW + INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1 + 1,
            )
        ),
        IssuerCoreErrorV1::InvalidState
    );
    assert_eq!(harness.backend.create_calls(), 1);
    assert!(harness
        .backend
        .existing_invoice(&reserved.backend_label)
        .unwrap()
        .is_none());
    assert_eq!(harness.record().state, QuoteState::Reserved);
}

#[test]
fn restart_reconciles_open_quote_to_exact_settlement() {
    let harness = Harness::new(NOW);
    let initial = harness.create_quote();
    let record = harness.record();
    harness
        .backend
        .node
        .observe_settlement(&record.backend_label, EXACT_AMOUNT_MSAT, NOW + 10)
        .expect("observe settlement");
    let restarted = harness.reopen_core();
    let settled = restarted
        .reconcile_by_backend_label(&record.backend_label, &harness.fixture.quote_key, NOW + 11)
        .expect("reconcile settlement");
    assert_eq!(settled.durable_state(), QuoteState::PaymentSettled);
    assert_eq!(
        settled.disposition(),
        QuoteReconcileDispositionV1::Transitioned
    );
    let quote = Bolt11QuoteV1::decode(settled.exact_signed_quote_response()).expect("decode quote");
    assert_eq!(quote.status, Bolt11QuoteStatusV1::PaymentSettled);
    assert_ne!(
        initial.exact_signed_quote_response(),
        settled.exact_signed_quote_response()
    );
}

#[test]
fn same_second_settlement_retries_then_preserves_paid_and_transition_times() {
    let harness = Harness::new(NOW);
    harness.create_quote();
    let record = harness.record();
    harness
        .backend
        .node
        .observe_settlement(&record.backend_label, EXACT_AMOUNT_MSAT, NOW)
        .expect("observe same-second settlement");

    assert_eq!(
        expect_core_error(harness.core.reconcile_by_backend_label(
            &record.backend_label,
            &harness.fixture.quote_key,
            NOW,
        )),
        IssuerCoreErrorV1::RetryableUnavailable
    );
    let still_open = harness.record();
    assert_eq!(still_open.state, QuoteState::InvoiceOpen);
    assert!(still_open.settlement_commit.is_none());

    let settled = harness
        .core
        .reconcile_by_backend_label(&record.backend_label, &harness.fixture.quote_key, NOW + 1)
        .expect("later observation commits same-second payment");
    assert_eq!(settled.durable_state(), QuoteState::PaymentSettled);
    let quote = Bolt11QuoteV1::decode(settled.exact_signed_quote_response()).expect("decode quote");
    assert_eq!(quote.status_updated_at, NOW + 1);

    let persisted = harness.record();
    assert_eq!(persisted.settled_at, Some(NOW));
    assert_eq!(persisted.settlement_observed_at, Some(NOW + 1));
}

#[test]
fn on_time_settlement_first_observed_after_expiry_keeps_payment_time_on_wire() {
    let harness = Harness::new(NOW);
    harness.create_quote();
    let record = harness.record();
    let expiry = record.invoice_expires_at.expect("invoice expiry");
    let settled_at = expiry - 1;
    let observed_at = expiry + 100;
    harness
        .backend
        .node
        .observe_settlement(&record.backend_label, EXACT_AMOUNT_MSAT, settled_at)
        .expect("observe on-time settlement after issuer outage");

    let settled = harness
        .core
        .reconcile_by_backend_label(
            &record.backend_label,
            &harness.fixture.quote_key,
            observed_at,
        )
        .expect("late observation preserves on-time settlement classification");
    assert_eq!(settled.durable_state(), QuoteState::PaymentSettled);
    let quote = Bolt11QuoteV1::decode(settled.exact_signed_quote_response()).expect("decode quote");
    assert_eq!(quote.status, Bolt11QuoteStatusV1::PaymentSettled);
    assert_eq!(quote.status_updated_at, settled_at);
    assert!(quote.status_updated_at <= quote.invoice_expires_at);

    let persisted = harness.record();
    assert_eq!(persisted.settled_at, Some(settled_at));
    assert_eq!(persisted.settlement_observed_at, Some(settled_at));
}

#[test]
fn expiry_then_late_settlement_is_two_durable_transitions() {
    let harness = Harness::new(NOW);
    harness.create_quote();
    let record = harness.record();
    let expiry = record.invoice_expires_at.expect("invoice expiry");
    let expired = harness
        .core
        .reconcile_by_backend_label(&record.backend_label, &harness.fixture.quote_key, expiry)
        .expect("reconcile expiry");
    assert_eq!(
        expired.durable_state(),
        QuoteState::InvoiceExpiredPendingReconcile
    );
    let expired_record = harness.record();
    assert!(expired_record.expiry_commit.is_some());
    assert!(expired_record.settlement_commit.is_none());

    harness
        .backend
        .node
        .observe_settlement(&record.backend_label, EXACT_AMOUNT_MSAT, expiry + 10)
        .expect("observe late settlement");
    let late = harness
        .core
        .reconcile_by_backend_label(
            &record.backend_label,
            &harness.fixture.quote_key,
            expiry + 11,
        )
        .expect("reconcile late settlement");
    assert_eq!(late.durable_state(), QuoteState::LateSettledReconcile);
    let late_record = harness.record();
    assert!(late_record.expiry_commit.is_some());
    assert!(late_record.settlement_commit.is_some());
    assert!(
        late_record.expiry_commit.expect("expiry commit").commit_seq
            < late_record
                .settlement_commit
                .expect("settlement commit")
                .commit_seq
    );
}

#[test]
fn long_outage_still_releases_an_expired_open_quote_at_its_exact_expiry() {
    let harness = Harness::new(NOW);
    harness.create_quote();
    let record = harness.record();
    let expiry = record.invoice_expires_at.expect("invoice expiry");
    let after_delegation_expiry = NOW + 3_501;
    harness
        .backend
        .node
        .set_time(after_delegation_expiry)
        .expect("advance beyond quote-key delegation");

    let restarted = harness.reopen_core();
    let expired = restarted
        .reconcile_by_backend_label(
            &record.backend_label,
            &harness.fixture.quote_key,
            after_delegation_expiry,
        )
        .expect("deterministic expiry remains recoverable after a long outage");
    assert_eq!(
        expired.durable_state(),
        QuoteState::InvoiceExpiredPendingReconcile
    );
    let quote =
        Bolt11QuoteV1::decode(expired.exact_signed_quote_response()).expect("decode expired quote");
    assert_eq!(quote.status_updated_at, expiry);
    let persisted = harness.record();
    assert_eq!(persisted.expiry_observed_at, Some(expiry));
}

#[test]
fn late_settlement_seen_while_open_commits_expiry_before_settlement() {
    let harness = Harness::new(NOW);
    harness.create_quote();
    let record = harness.record();
    let expiry = record.invoice_expires_at.expect("invoice expiry");
    harness
        .backend
        .node
        .observe_settlement(&record.backend_label, EXACT_AMOUNT_MSAT, expiry + 10)
        .expect("observe late settlement");
    let late = harness
        .core
        .reconcile_by_backend_label(
            &record.backend_label,
            &harness.fixture.quote_key,
            expiry + 11,
        )
        .expect("reconcile direct late settlement");
    assert_eq!(late.durable_state(), QuoteState::LateSettledReconcile);
    let persisted = harness.record();
    let expiry_commit = persisted.expiry_commit.expect("durable expiry commit");
    let settlement_commit = persisted
        .settlement_commit
        .expect("durable settlement commit");
    assert!(expiry_commit.commit_seq < settlement_commit.commit_seq);
    assert_eq!(persisted.expiry_observed_at, Some(expiry));
    assert_eq!(persisted.settled_at, Some(expiry + 10));
}

#[test]
fn underpaid_settlement_fails_closed_without_state_change() {
    let harness = Harness::new(NOW);
    harness.create_quote();
    let record = harness.record();
    harness
        .backend
        .node
        .observe_settlement(&record.backend_label, EXACT_AMOUNT_MSAT - 1, NOW + 10)
        .expect("observe wrong amount");
    assert_eq!(
        expect_core_error(harness.core.reconcile_by_backend_label(
            &record.backend_label,
            &harness.fixture.quote_key,
            NOW + 11,
        )),
        IssuerCoreErrorV1::PermanentMismatch
    );
    assert_eq!(harness.record().state, QuoteState::InvoiceOpen);
}

#[test]
fn overpaid_settlement_grants_only_the_fixed_quote_entitlement() {
    let harness = Harness::new(NOW);
    harness.create_quote();
    let record = harness.record();
    harness
        .backend
        .node
        .observe_settlement(&record.backend_label, EXACT_AMOUNT_MSAT + 1_000, NOW + 10)
        .expect("observe overpayment");
    let reconciled = harness
        .core
        .reconcile_by_backend_label(&record.backend_label, &harness.fixture.quote_key, NOW + 11)
        .expect("overpayment settles the fixed quote");
    assert_eq!(reconciled.durable_state(), QuoteState::PaymentSettled);
    let persisted = harness.record();
    assert_eq!(
        persisted.settled_amount_msat,
        Some(EXACT_AMOUNT_MSAT + 1_000)
    );
    assert_eq!(persisted.exact_amount_msat, record.exact_amount_msat);
    assert_eq!(
        persisted.intent_digest, record.intent_digest,
        "received amount never rewrites the signed offer entitlement"
    );
}

#[test]
fn tampered_backend_response_never_finalizes_reserved_quote() {
    let harness = Harness::new(NOW);
    harness
        .backend
        .set_created_tamper(CreatedTamper::PaymentHash);
    assert_eq!(
        expect_core_error(harness.core.create_or_recover_quote(
            &harness.fixture.verified_intent(NOW),
            &harness.fixture.quote_key,
            NOW,
        )),
        IssuerCoreErrorV1::PermanentMismatch
    );
    assert_eq!(harness.record().state, QuoteState::Reserved);
}

#[test]
fn wrong_signer_and_conflicting_verified_delegation_fail_before_rebinding() {
    let harness = Harness::new(NOW);
    let wrong_signer = SigningKey::from_bytes(&[0x77; 32]);
    assert_eq!(
        expect_core_error(harness.core.create_or_recover_quote(
            &harness.fixture.verified_intent(NOW),
            &wrong_signer,
            NOW,
        )),
        IssuerCoreErrorV1::PermanentMismatch
    );
    assert!(harness
        .store
        .quote_by_creation_idempotency_key(&harness.fixture.intent.idempotency_key)
        .expect("read absent quote")
        .is_none());

    harness.create_quote();
    let conflicting = QuoteFixture::new(harness.backend.payee_pubkey(), 0x55, 5, 0x45);
    assert_eq!(
        expect_core_error(harness.core.create_or_recover_quote(
            &conflicting.verified_intent(NOW),
            &conflicting.quote_key,
            NOW,
        )),
        IssuerCoreErrorV1::PermanentMismatch
    );
    assert_eq!(harness.record().delegation_epoch, 4);
}

#[test]
fn exact_replay_returns_identical_bytes_without_backend_or_id_source_call() {
    let harness = Harness::new(NOW);
    let first = harness.create_quote().into_exact_signed_quote_response();
    let source_calls = harness.quote_ids.calls();
    let backend_calls = harness.backend.create_calls();
    harness
        .backend
        .node
        .set_time(NOW + 20)
        .expect("advance fake clock");
    let second = harness
        .core
        .create_or_recover_quote(
            &harness.fixture.verified_intent(NOW + 20),
            &harness.fixture.quote_key,
            NOW + 20,
        )
        .expect("exact replay");
    assert_eq!(second.disposition(), QuoteCreateDispositionV1::ExactReplay);
    assert_eq!(second.exact_signed_quote_response(), first);
    assert_eq!(harness.quote_ids.calls(), source_calls);
    assert_eq!(harness.backend.create_calls(), backend_calls);
}

#[test]
fn contradictory_terminal_backend_evidence_is_never_persisted() {
    let harness = Harness::new(NOW);
    harness.create_quote();
    let record = harness.record();
    harness
        .backend
        .node
        .observe_settlement(&record.backend_label, EXACT_AMOUNT_MSAT, NOW + 10)
        .expect("observe settlement");
    harness
        .core
        .reconcile_by_backend_label(&record.backend_label, &harness.fixture.quote_key, NOW + 11)
        .expect("settle quote");
    harness
        .backend
        .set_observation_override(Some(InvoiceObservationStateV1::Expired));
    assert_eq!(
        expect_core_error(harness.core.reconcile_by_backend_label(
            &record.backend_label,
            &harness.fixture.quote_key,
            NOW + 12,
        )),
        IssuerCoreErrorV1::PermanentMismatch
    );
    assert_eq!(harness.record().state, QuoteState::PaymentSettled);
}

#[test]
fn invoice_timestamp_window_accepts_boundaries_and_rejects_old_or_future() {
    for timestamp in [
        NOW - INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1,
        NOW + INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1,
    ] {
        let harness = Harness::new(timestamp);
        let quote = harness.create_quote();
        let decoded =
            Bolt11QuoteV1::decode(quote.exact_signed_quote_response()).expect("decode quote");
        assert_eq!(decoded.invoice_created_at, timestamp);
    }

    for timestamp in [
        NOW - INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1 - 1,
        NOW + INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1 + 1,
    ] {
        let harness = Harness::new(timestamp);
        assert_eq!(
            expect_core_error(harness.core.create_or_recover_quote(
                &harness.fixture.verified_intent(NOW),
                &harness.fixture.quote_key,
                NOW,
            )),
            IssuerCoreErrorV1::PermanentMismatch
        );
        assert_eq!(harness.record().state, QuoteState::Reserved);
    }
}

#[test]
fn errors_and_public_results_have_no_preimage_or_backend_secret_surface() {
    let harness = Harness::new(NOW);
    let response = harness.create_quote();
    assert!(!response.exact_signed_quote_response().is_empty());
    let record = harness.record();
    harness
        .backend
        .node
        .fail_once(FakeFailurePointV1::LookupOnce)
        .expect("inject lookup outage");
    let error = expect_core_error(harness.core.reconcile_by_backend_label(
        &record.backend_label,
        &harness.fixture.quote_key,
        NOW + 1,
    ));
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(&record.backend_label));
    assert!(!rendered.contains(record.invoice.as_deref().expect("invoice")));
    let payment_hash = record.payment_hash.expect("payment hash");
    let payment_hash_hex = payment_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(!rendered.contains(&payment_hash_hex));

    let public_source = include_str!("lib.rs");
    assert!(!public_source.contains("pub payment_preimage"));
    assert!(!public_source.contains("fn payment_preimage"));
    assert!(!public_source.contains("payment_preimage:"));
}
