use ed25519_dalek::{Signer, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use pir_issuer_store::{
    BatKeyLineageRegistration, ClaimCryptographicVerificationInput, ClaimWrite, DelegationAdvance,
    IssuerRollbackFloorAuthorityErrorV1, IssuerRollbackFloorAuthorityV1, IssuerRollbackFloorV1,
    IssuerStore, QuoteCapacityV1, QuoteExpiry, QuoteFinalization, QuoteReservation,
    QuoteSettlement, QuoteState, QuoteStatusBip340Input, SettlementKeyLineageRegistration,
    StoreError, StoreOptions, WriteDisposition, SCHEMA_VERSION,
};
use pir_service_protocol::{
    derive_bat_key_id_v1, derive_cashu_keyset_id_v2, derive_issuer_id, paid_receipt_key_id,
    AuthScheme, Bolt11QuoteClaimV1, Bolt11QuoteIntentV1, Bolt11QuoteKeyDelegationV1,
    Bolt11QuoteStatusRequestV1, Bolt11QuoteStatusV1, Bolt11QuoteV1, CashuDenominationKeyV1,
    CredentialIssuanceRequestItemsV1, CredentialIssuanceRequestV1,
    CredentialIssuanceResponseItemsV1, CredentialIssuanceResponseV1, LightningNetworkV1,
    PaidReceiptBindingV1, PaidReceiptV1, BOLT11_QUOTE_SIGNATURE_DOMAIN,
};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use tempfile::{Builder, TempDir};

const STORE_INSTANCE: [u8; 16] = [0x11; 16];

#[derive(Debug, Default)]
struct MemoryRollbackAuthority {
    floor: Mutex<Option<IssuerRollbackFloorV1>>,
    unavailable: AtomicBool,
    lose_next_advance_response: AtomicBool,
    reject_next_advance: AtomicBool,
    load_calls: AtomicUsize,
    fail_on_load_call: AtomicUsize,
    compare_and_advance_calls: AtomicUsize,
}

impl MemoryRollbackAuthority {
    fn floor(&self) -> Option<IssuerRollbackFloorV1> {
        *self.floor.lock().expect("rollback floor mutex")
    }

    fn set_floor(&self, floor: IssuerRollbackFloorV1) {
        *self.floor.lock().expect("rollback floor mutex") = Some(floor);
    }

    fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::SeqCst);
    }

    fn lose_next_advance_response(&self) {
        self.lose_next_advance_response
            .store(true, Ordering::SeqCst);
    }

    fn reject_next_advance(&self) {
        self.reject_next_advance.store(true, Ordering::SeqCst);
    }

    fn compare_and_advance_calls(&self) -> usize {
        self.compare_and_advance_calls.load(Ordering::SeqCst)
    }

    fn fail_load_after(&self, successful_loads: usize) {
        let target = self
            .load_calls
            .load(Ordering::SeqCst)
            .checked_add(successful_loads)
            .and_then(|value| value.checked_add(1))
            .expect("load-call target");
        self.fail_on_load_call.store(target, Ordering::SeqCst);
    }

    fn check_available(&self) -> Result<(), IssuerRollbackFloorAuthorityErrorV1> {
        if self.unavailable.load(Ordering::SeqCst) {
            Err(IssuerRollbackFloorAuthorityErrorV1::new(
                "injected authority outage",
            ))
        } else {
            Ok(())
        }
    }
}

impl IssuerRollbackFloorAuthorityV1 for MemoryRollbackAuthority {
    fn load(
        &self,
        _issuer_id: &[u8; 32],
        _network: LightningNetworkV1,
    ) -> Result<Option<IssuerRollbackFloorV1>, IssuerRollbackFloorAuthorityErrorV1> {
        self.check_available()?;
        let call = self.load_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self
            .fail_on_load_call
            .compare_exchange(call, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Err(IssuerRollbackFloorAuthorityErrorV1::new(
                "injected load failure",
            ));
        }
        Ok(self.floor())
    }

    fn initialize(
        &self,
        initial: &IssuerRollbackFloorV1,
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1> {
        self.check_available()?;
        let mut floor = self.floor.lock().expect("rollback floor mutex");
        if floor.is_none() {
            *floor = Some(*initial);
        }
        floor.ok_or_else(|| {
            IssuerRollbackFloorAuthorityErrorV1::new("floor disappeared during initialize")
        })
    }

    fn compare_and_advance(
        &self,
        expected: &IssuerRollbackFloorV1,
        next: &IssuerRollbackFloorV1,
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1> {
        self.check_available()?;
        self.compare_and_advance_calls
            .fetch_add(1, Ordering::SeqCst);
        if self.reject_next_advance.swap(false, Ordering::SeqCst) {
            return Err(IssuerRollbackFloorAuthorityErrorV1::new(
                "injected pre-advance CAS failure",
            ));
        }
        if next.store_generation != expected.store_generation.saturating_add(1)
            || next.store_instance_id != expected.store_instance_id
            || next.issuer_id != expected.issuer_id
            || next.network != expected.network
            || next.schema_version != expected.schema_version
        {
            return Err(IssuerRollbackFloorAuthorityErrorV1::new(
                "invalid authority CAS transition",
            ));
        }
        let mut floor = self.floor.lock().expect("rollback floor mutex");
        if floor.as_ref() == Some(expected) {
            *floor = Some(*next);
        }
        let current = floor.ok_or_else(|| {
            IssuerRollbackFloorAuthorityErrorV1::new("floor disappeared during CAS")
        })?;
        if self
            .lose_next_advance_response
            .swap(false, Ordering::SeqCst)
        {
            return Err(IssuerRollbackFloorAuthorityErrorV1::new(
                "injected lost CAS response",
            ));
        }
        Ok(current)
    }
}

struct TestPath {
    _directory: TempDir,
    database: PathBuf,
    backup: PathBuf,
    authority: Arc<MemoryRollbackAuthority>,
}

impl TestPath {
    fn new() -> Self {
        let directory = Builder::new()
            .prefix("bitcoinpir-issuer-store-test-")
            .tempdir()
            .expect("create task-specific temporary directory");
        let database = directory.path().join("issuer.sqlite3");
        Self {
            backup: directory.path().join("issuer-backup.sqlite3"),
            authority: Arc::new(MemoryRollbackAuthority::default()),
            _directory: directory,
            database,
        }
    }
}

fn root_key() -> SigningKey {
    SigningKey::from_bytes(&[0x21; 32])
}

fn quote_key() -> SigningKey {
    SigningKey::from_bytes(&[0x22; 32])
}

fn receipt_key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn issuer_id() -> [u8; 32] {
    derive_issuer_id(&root_key().verifying_key().to_bytes())
}

fn point(multiplier: u64) -> [u8; 33] {
    let encoded = (ProjectivePoint::GENERATOR * Scalar::from(multiplier))
        .to_affine()
        .to_encoded_point(true);
    encoded.as_bytes().try_into().expect("compressed point")
}

fn xonly(multiplier: u64) -> [u8; 32] {
    point(multiplier)[1..].try_into().expect("x-only point")
}

fn create_store(path: &TestPath) -> IssuerStore {
    IssuerStore::create(
        &path.database,
        STORE_INSTANCE,
        issuer_id(),
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        path.authority.clone(),
    )
    .expect("create issuer store")
}

fn open_store(path: &TestPath) -> Result<IssuerStore, StoreError> {
    IssuerStore::open_existing(
        &path.database,
        issuer_id(),
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        path.authority.clone(),
    )
}

fn copy_database_without_wal(source: &Path, destination: &Path) {
    let connection = Connection::open(source).expect("open backup source");
    connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_row| Ok(()))
        .expect("checkpoint backup source");
    drop(connection);
    std::fs::copy(source, destination).expect("copy database");
}

fn remove_sqlite_sidecars(path: &Path) {
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
        if sidecar.exists() {
            std::fs::remove_file(sidecar).expect("remove SQLite sidecar");
        }
    }
}

fn delegation(epoch: u64, quote_key_byte: u8) -> Bolt11QuoteKeyDelegationV1 {
    let quote_key = SigningKey::from_bytes(&[quote_key_byte; 32]);
    Bolt11QuoteKeyDelegationV1::sign(
        LightningNetworkV1::Regtest,
        point(2),
        epoch,
        100,
        10_000,
        quote_key.verifying_key().to_bytes(),
        &root_key(),
    )
    .expect("sign delegation")
}

fn reservation_with_receipt_key(
    quote_id_byte: u8,
    idempotency_byte: u8,
    delegation: &Bolt11QuoteKeyDelegationV1,
    receipt_key_byte: u8,
) -> QuoteReservation {
    let idempotency_key = [idempotency_byte; 32];
    let intent = Bolt11QuoteIntentV1 {
        issuer_id: issuer_id(),
        provider_id: [0x31; 32],
        policy_digest: [0x32; 32],
        scope_id: [0x33; 32],
        offer_id: 7,
        network: LightningNetworkV1::Regtest,
        expected_payee_pubkey: point(2),
        minimum_quote_key_epoch: delegation.key_epoch,
        quote_delegation_digest: delegation.delegation_digest().expect("delegation digest"),
        authorization: AuthScheme::Bolt11DirectReceiptV1,
        credential_binding_digest: [0x34; 32],
        credential_key_id: paid_receipt_key_id(&receipt_key(receipt_key_byte).verifying_key())
            .to_vec(),
        exact_amount_msat: 1_000,
        entitlement_profile: 3,
        credential_count: 1,
        credential_presentation_limit: 1,
        invoice_expiry_seconds: 60,
        claim_window_seconds: 120,
        minimum_credential_validity_seconds: 300,
        claim_pubkey_xonly: xonly(3),
        idempotency_key,
    };
    let exact_intent = intent.encode().expect("encode intent");
    QuoteReservation {
        quote_id: [quote_id_byte; 32],
        creation_idempotency_key: idempotency_key,
        intent_digest: intent.request_digest().expect("intent digest"),
        exact_intent,
        payee_pubkey: delegation.expected_payee_pubkey,
        delegation_epoch: delegation.key_epoch,
        delegation_digest: delegation.delegation_digest().expect("delegation digest"),
        exact_delegation: delegation.encode().expect("encode delegation"),
        exact_amount_msat: 1_000,
        invoice_created_not_before: 250,
        invoice_created_not_after: 350,
        now_unix: 200,
    }
}

fn reservation(
    quote_id_byte: u8,
    idempotency_byte: u8,
    delegation: &Bolt11QuoteKeyDelegationV1,
) -> QuoteReservation {
    reservation_with_receipt_key(quote_id_byte, idempotency_byte, delegation, 0x25)
}

fn signed_quote(
    quote_id_byte: u8,
    quote_request_digest: [u8; 32],
    invoice_suffix: u8,
    status: Bolt11QuoteStatusV1,
    state_version: u64,
    status_updated_at: u64,
) -> Vec<u8> {
    let delegation = delegation(1, 0x22);
    let mut snapshot = Bolt11QuoteV1 {
        request_digest: quote_request_digest,
        quote_id: [quote_id_byte; 32],
        quote_key_id: delegation.quote_key_id,
        invoice: format!("lnbcrt1bitcoinpirfixture{invoice_suffix}"),
        network: LightningNetworkV1::Regtest,
        payee_pubkey: point(2),
        amount_msat: 1_000,
        invoice_created_at: 300,
        invoice_expires_at: 360,
        claim_deadline: 480,
        credential_not_after: 780,
        status,
        state_version,
        status_updated_at,
        signature: [1; 64],
    };
    let placeholder = snapshot.encode().expect("encode quote placeholder");
    let mut preimage = Vec::new();
    preimage.extend_from_slice(BOLT11_QUOTE_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(&placeholder[..placeholder.len() - 64]);
    snapshot.signature = quote_key().sign(&preimage).to_bytes();
    snapshot.encode().expect("encode signed quote")
}

fn finalization(
    quote_id_byte: u8,
    invoice_suffix: u8,
    quote_request_digest: [u8; 32],
) -> QuoteFinalization {
    QuoteFinalization {
        quote_id: [quote_id_byte; 32],
        invoice: format!("lnbcrt1bitcoinpirfixture{invoice_suffix}"),
        payment_hash: [invoice_suffix; 32],
        invoice_created_at: 300,
        invoice_expires_at: 360,
        claim_deadline: 480,
        credential_not_after: 780,
        exact_signed_quote_response: signed_quote(
            quote_id_byte,
            quote_request_digest,
            invoice_suffix,
            Bolt11QuoteStatusV1::InvoiceOpen,
            1,
            300,
        ),
    }
}

fn settlement(
    quote_id_byte: u8,
    quote_request_digest: [u8; 32],
    settled_at: u64,
    observed_at: u64,
    response_byte: u8,
    late: bool,
) -> QuoteSettlement {
    QuoteSettlement {
        quote_id: [quote_id_byte; 32],
        settled_at,
        observed_at,
        settled_amount_msat: 1_000,
        settlement_evidence_digest: [response_byte; 32],
        exact_signed_quote_response: signed_quote(
            quote_id_byte,
            quote_request_digest,
            response_byte,
            if late {
                Bolt11QuoteStatusV1::LateSettledReconcile
            } else {
                Bolt11QuoteStatusV1::PaymentSettled
            },
            if late { 3 } else { 2 },
            observed_at,
        ),
    }
}

fn claim(
    quote_id_byte: u8,
    quote_request_digest: [u8; 32],
    idempotency_byte: u8,
    invoice_suffix: u8,
    serial_byte: u8,
    receipt_key_byte: u8,
    claimed_state_version: u64,
) -> ClaimWrite {
    let key_id = paid_receipt_key_id(&receipt_key(receipt_key_byte).verifying_key());
    let issuance_request = CredentialIssuanceRequestV1 {
        issuer_id: issuer_id(),
        quote_id: [quote_id_byte; 32],
        quote_request_digest,
        authorization: AuthScheme::Bolt11DirectReceiptV1,
        credential_binding_digest: [0x34; 32],
        credential_key_id: key_id.to_vec(),
        items: CredentialIssuanceRequestItemsV1::DirectPaidReceipt,
    };
    let exact_credential_request = issuance_request.encode().expect("encode issuance request");
    let credential_request_digest = issuance_request
        .request_digest()
        .expect("issuance request digest");
    let claim = Bolt11QuoteClaimV1 {
        issuer_id: issuer_id(),
        quote_id: [quote_id_byte; 32],
        quote_request_digest,
        credential_request_digest,
        claim_pubkey_xonly: xonly(3),
        idempotency_key: [idempotency_byte; 32],
        signature: [0x62; 64],
    };
    let exact_claim_request = claim.encode().expect("encode claim");
    let paid_receipt = PaidReceiptV1::sign(
        issuer_id(),
        [serial_byte; 32],
        PaidReceiptBindingV1 {
            scope_id: [0x33; 32],
            offer_id: 7,
            policy_digest: [0x32; 32],
            entitlement_profile: 3,
        },
        400,
        780,
        &receipt_key(receipt_key_byte),
    )
    .expect("sign paid receipt");
    let issuance_response = CredentialIssuanceResponseV1 {
        issuer_id: issuer_id(),
        quote_id: [quote_id_byte; 32],
        quote_request_digest,
        credential_request_digest,
        authorization: AuthScheme::Bolt11DirectReceiptV1,
        credential_binding_digest: [0x34; 32],
        credential_key_id: key_id.to_vec(),
        items: CredentialIssuanceResponseItemsV1::DirectPaidReceipts(vec![paid_receipt]),
    };
    ClaimWrite {
        quote_id: [quote_id_byte; 32],
        claim_idempotency_key: [idempotency_byte; 32],
        claim_request_digest: claim.claim_request_digest().expect("claim digest"),
        exact_claim_request,
        exact_credential_request,
        exact_claim_response: issuance_response
            .encode()
            .expect("encode issuance response"),
        exact_signed_quote_response: signed_quote(
            quote_id_byte,
            quote_request_digest,
            invoice_suffix,
            Bolt11QuoteStatusV1::CredentialClaimed,
            claimed_state_version,
            400,
        ),
        now_unix: 400,
    }
}

fn accept_claim_crypto(_input: ClaimCryptographicVerificationInput<'_>) -> bool {
    true
}

fn reject_claim_crypto(_input: ClaimCryptographicVerificationInput<'_>) -> bool {
    false
}

fn accept_status_signature(_input: QuoteStatusBip340Input<'_>) -> bool {
    true
}

fn reject_status_signature(_input: QuoteStatusBip340Input<'_>) -> bool {
    false
}

fn status_request(
    quote_id_byte: u8,
    quote_request_digest: [u8; 32],
    requested_at: u64,
    nonce_byte: u8,
) -> Bolt11QuoteStatusRequestV1 {
    Bolt11QuoteStatusRequestV1 {
        issuer_id: issuer_id(),
        quote_id: [quote_id_byte; 32],
        quote_request_digest,
        claim_pubkey_xonly: xonly(3),
        requested_at,
        request_nonce: [nonce_byte; 32],
        signature: [0x91; 64],
    }
}

fn reserve_finalize_settle(
    store: &IssuerStore,
    quote_byte: u8,
    idempotency_byte: u8,
    invoice_byte: u8,
) -> QuoteReservation {
    reserve_finalize_settle_with_receipt_key(
        store,
        quote_byte,
        idempotency_byte,
        invoice_byte,
        0x25,
    )
}

fn reserve_finalize_settle_with_receipt_key(
    store: &IssuerStore,
    quote_byte: u8,
    idempotency_byte: u8,
    invoice_byte: u8,
    receipt_key_byte: u8,
) -> QuoteReservation {
    let delegation = delegation(1, 0x22);
    let reservation =
        reservation_with_receipt_key(quote_byte, idempotency_byte, &delegation, receipt_key_byte);
    let _ = store.reserve_quote(&reservation).expect("reserve quote");
    let _ = store
        .finalize_quote(&finalization(
            quote_byte,
            invoice_byte,
            reservation.intent_digest,
        ))
        .expect("finalize quote");
    let _ = store
        .record_settlement(&settlement(
            quote_byte,
            reservation.intent_digest,
            350,
            350,
            invoice_byte,
            false,
        ))
        .expect("record settlement");
    reservation
}

#[test]
fn quote_signing_material_requirements_follow_recovery_horizon_and_claim_state() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let first_delegation = delegation(1, 0x22);
    let digest = first_delegation
        .delegation_digest()
        .expect("delegation digest");
    let first_reservation = reservation(0x5e, 0xd0, &first_delegation);
    let _ = store
        .reserve_quote(&first_reservation)
        .expect("reserve quote");

    assert_eq!(
        store
            .quote_delegation_digests_requiring_signing_material(530)
            .expect("reserved requirements"),
        vec![digest]
    );
    assert!(store
        .quote_delegation_digests_requiring_signing_material(531)
        .expect("expired reservation requirements")
        .is_empty());

    let _ = store
        .finalize_quote(&finalization(0x5e, 0xde, first_reservation.intent_digest))
        .expect("finalize quote");
    assert_eq!(
        store
            .quote_delegation_digests_requiring_signing_material(480)
            .expect("open requirements"),
        vec![digest]
    );
    assert!(store
        .quote_delegation_digests_requiring_signing_material(481)
        .expect("past-claim requirements")
        .is_empty());

    let _ = store
        .record_settlement(&settlement(
            0x5e,
            first_reservation.intent_digest,
            350,
            350,
            0xde,
            false,
        ))
        .expect("settle quote");
    let claim = claim(
        0x5e,
        first_reservation.intent_digest,
        0xcf,
        0xde,
        0xce,
        0x25,
        3,
    );
    let _ = store
        .record_claim(&claim, &accept_claim_crypto, None)
        .expect("claim quote");
    assert!(store
        .quote_delegation_digests_requiring_signing_material(400)
        .expect("claimed requirements")
        .is_empty());

    let live_delegation = delegation(2, 0x23);
    let live_digest = live_delegation
        .delegation_digest()
        .expect("live delegation digest");
    let mut live = reservation(0x5d, 0xcf, &live_delegation);
    live.invoice_created_not_before = 570;
    live.invoice_created_not_after = 630;
    live.now_unix = 600;
    let _ = store
        .reserve_quote(&live)
        .expect("reserve later live quote");
    assert_eq!(
        store
            .quote_delegation_digests_requiring_signing_material(600)
            .expect("only live material requirement"),
        vec![live_digest],
        "stale historical rows must be filtered before readiness decoding"
    );
}

#[test]
fn material_readiness_filters_expired_quotes_before_replay_decode() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let quote = reservation(0x5c, 0xce, &delegation(1, 0x22));
    let _ = store.reserve_quote(&quote).expect("reserve quote");

    let connection = Connection::open(&test_path.database).expect("open issuer database");
    connection
        .execute(
            "UPDATE quotes SET intent_replay_image = ?1 WHERE quote_id = ?2",
            rusqlite::params![vec![0xff_u8], quote.quote_id.as_slice()],
        )
        .expect("install schema-valid non-canonical replay image");
    drop(connection);

    assert!(store
        .quote_delegation_digests_requiring_signing_material(531)
        .expect("expired signer readiness")
        .is_empty());
    assert!(store
        .service_policies_requiring_credential_material(531)
        .expect("expired credential readiness")
        .is_empty());

    assert!(matches!(
        store.quote_delegation_digests_requiring_signing_material(530),
        Err(StoreError::SchemaMismatch(_))
    ));
    assert!(matches!(
        store.service_policies_requiring_credential_material(530),
        Err(StoreError::SchemaMismatch(_))
    ));
}

#[test]
fn invoice_creation_window_is_durable_and_part_of_exact_reservation_identity() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let original = reservation(0x5f, 0xd1, &delegation(1, 0x22));
    let first = store.reserve_quote(&original).unwrap();
    assert_eq!(first.value.invoice_created_not_before, 250);
    assert_eq!(first.value.invoice_created_not_after, 350);

    let reopened = open_store(&test_path).unwrap();
    let recovered = reopened.quote(&original.quote_id).unwrap().unwrap();
    assert_eq!(recovered.invoice_created_not_before, 250);
    assert_eq!(recovered.invoice_created_not_after, 350);

    let mut changed = original.clone();
    changed.invoice_created_not_before = 249;
    assert!(matches!(
        reopened.reserve_quote(&changed),
        Err(StoreError::CreationIdempotencyConflict)
    ));

    let mut invalid = reservation(0x60, 0xd2, &delegation(1, 0x22));
    invalid.invoice_created_not_after = invalid.invoice_created_not_before - 1;
    assert!(matches!(
        reopened.reserve_quote(&invalid),
        Err(StoreError::InvalidInput(_))
    ));

    let mut outside = reservation(0x61, 0xd3, &delegation(1, 0x22));
    outside.invoice_created_not_before = 301;
    let _ = reopened.reserve_quote(&outside).unwrap();
    let outside_finalization = finalization(0x61, 0xd4, outside.intent_digest);
    // The finalization and signed snapshot agree on timestamp 300, but it is
    // outside the immutable reservation window and therefore fails closed.
    assert!(matches!(
        reopened.finalize_quote(&outside_finalization),
        Err(StoreError::SignedQuoteMismatch)
    ));
}

#[test]
fn quote_capacity_is_atomic_and_never_blocks_exact_recovery() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let capacity = QuoteCapacityV1::new(1, 2).unwrap();
    let first = reservation(0x62, 0xd4, &delegation(1, 0x22));
    let first_write = store.reserve_quote_with_capacity(&first, capacity).unwrap();
    assert_eq!(first_write.disposition, WriteDisposition::Committed);
    assert_eq!(
        store
            .reserve_quote_with_capacity(&first, capacity)
            .unwrap()
            .disposition,
        WriteDisposition::ExactReplay
    );

    let second = reservation(0x63, 0xd5, &delegation(1, 0x22));
    assert!(matches!(
        store.reserve_quote_with_capacity(&second, capacity),
        Err(StoreError::QuoteCapacityExceeded)
    ));

    let _ = store
        .finalize_quote(&finalization(0x62, 0xe4, first.intent_digest))
        .unwrap();
    let _ = store
        .record_settlement(&settlement(
            0x62,
            first.intent_digest,
            350,
            350,
            0xe4,
            false,
        ))
        .unwrap();
    let _ = store
        .reserve_quote_with_capacity(&second, capacity)
        .unwrap();

    let third = reservation(0x64, 0xd6, &delegation(1, 0x22));
    assert!(matches!(
        store.reserve_quote_with_capacity(&third, capacity),
        Err(StoreError::QuoteCapacityExceeded)
    ));
    assert_eq!(
        store
            .reserve_quote_with_capacity(&first, capacity)
            .unwrap()
            .disposition,
        WriteDisposition::ExactReplay
    );
}

#[test]
fn stale_reserved_rows_do_not_permanently_consume_outstanding_capacity() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let capacity = QuoteCapacityV1::new(1, 1).unwrap();
    let first = reservation(0x67, 0xd9, &delegation(1, 0x22));
    let _ = store
        .reserve_quote_with_capacity(&first, capacity)
        .expect("reserve first quote");

    let mut second = reservation(0x68, 0xda, &delegation(1, 0x22));
    second.invoice_created_not_before = 570;
    second.invoice_created_not_after = 630;
    second.now_unix = 600;
    let _ = store
        .reserve_quote_with_capacity(&second, capacity)
        .expect("stale reservation no longer blocks a new bounded window");

    let first_page = store
        .quote_reconciliation_candidates_after(None, 1, 600)
        .expect("first reconciliation page");
    assert_eq!(first_page.len(), 1);
    assert_eq!(first_page[0].quote_id(), &second.quote_id);
    assert!(store
        .quote_reconciliation_candidates_after(Some(first_page[0].quote_id()), 1, 600)
        .expect("end reconciliation page")
        .is_empty());
}

#[test]
fn paid_quote_releases_active_capacity_without_deleting_audit_row() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let capacity = QuoteCapacityV1::new(1, 1).unwrap();

    let first = reservation(0x69, 0xdb, &delegation(1, 0x22));
    let _ = store.reserve_quote_with_capacity(&first, capacity).unwrap();
    let second = reservation(0x6a, 0xdc, &delegation(1, 0x22));
    assert!(matches!(
        store.reserve_quote_with_capacity(&second, capacity),
        Err(StoreError::QuoteCapacityExceeded)
    ));

    let _ = store
        .finalize_quote(&finalization(0x69, 0xe9, first.intent_digest))
        .unwrap();
    let _ = store
        .record_settlement(&settlement(
            0x69,
            first.intent_digest,
            350,
            350,
            0xe9,
            false,
        ))
        .unwrap();
    let _ = store
        .reserve_quote_with_capacity(&second, capacity)
        .unwrap();

    assert_eq!(
        store.quote(&first.quote_id).unwrap().unwrap().state,
        QuoteState::PaymentSettled
    );
}

#[test]
fn expired_pending_quote_holds_capacity_through_recovery_horizon_then_releases_it() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let capacity = QuoteCapacityV1::new(1, 1).unwrap();

    let first = reservation(0x6b, 0xdd, &delegation(1, 0x22));
    let _ = store.reserve_quote_with_capacity(&first, capacity).unwrap();
    let _ = store
        .finalize_quote(&finalization(0x6b, 0xeb, first.intent_digest))
        .unwrap();
    let _ = store
        .mark_invoice_expired(&QuoteExpiry {
            quote_id: first.quote_id,
            observed_at: 361,
            exact_signed_quote_response: signed_quote(
                0x6b,
                first.intent_digest,
                0xeb,
                Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile,
                2,
                361,
            ),
        })
        .unwrap();
    let mut before_deadline = reservation(0x6c, 0xde, &delegation(1, 0x22));
    before_deadline.invoice_created_not_before = 400;
    before_deadline.invoice_created_not_after = 450;
    before_deadline.now_unix = 400;
    assert!(matches!(
        store.reserve_quote_with_capacity(&before_deadline, capacity),
        Err(StoreError::QuoteCapacityExceeded)
    ));

    let mut after_deadline = reservation(0x6d, 0xdf, &delegation(1, 0x22));
    after_deadline.invoice_created_not_before = 481;
    after_deadline.invoice_created_not_after = 550;
    after_deadline.now_unix = 481;
    let _ = store
        .reserve_quote_with_capacity(&after_deadline, capacity)
        .unwrap();

    assert_eq!(
        store.quote(&first.quote_id).unwrap().unwrap().state,
        QuoteState::InvoiceExpiredPendingReconcile
    );
}

#[test]
fn concurrent_distinct_quote_reservations_cannot_oversubscribe_capacity() {
    let test_path = TestPath::new();
    let store = Arc::new(create_store(&test_path));
    let capacity = QuoteCapacityV1::new(1, 10).unwrap();
    let reservations = [
        reservation(0x65, 0xd7, &delegation(1, 0x22)),
        reservation(0x66, 0xd8, &delegation(1, 0x22)),
    ];
    let barrier = Arc::new(Barrier::new(2));
    let workers = reservations.clone().map(|reservation| {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            store.reserve_quote_with_capacity(&reservation, capacity)
        })
    });
    let outcomes = workers.map(|worker| worker.join().unwrap());
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(StoreError::QuoteCapacityExceeded)))
            .count(),
        1
    );

    let winner = outcomes
        .into_iter()
        .find_map(Result::ok)
        .expect("one reservation wins");
    let original = reservations
        .iter()
        .find(|reservation| reservation.quote_id == winner.value.quote_id)
        .expect("winner corresponds to an input");
    assert_eq!(
        store
            .reserve_quote_with_capacity(original, capacity)
            .unwrap()
            .disposition,
        WriteDisposition::ExactReplay
    );
}

#[test]
fn explicit_create_open_identity_schema_and_privacy_boundary() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let identity = store.identity().unwrap();
    assert_eq!(identity.store_instance_id, STORE_INSTANCE);
    assert_eq!(identity.issuer_id, issuer_id());
    assert_eq!(identity.network, LightningNetworkV1::Regtest);
    assert_eq!(identity.schema_version, SCHEMA_VERSION);
    assert_eq!(identity.commit_seq, 0);
    let floor = test_path.authority.floor().unwrap();
    assert_eq!(floor.store_instance_id, identity.store_instance_id);
    assert_eq!(floor.issuer_id, identity.issuer_id);
    assert_eq!(floor.network, identity.network);
    assert_eq!(floor.store_generation, identity.commit_seq);
    assert_eq!(floor.rollback_commitment, identity.rollback_commitment);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&test_path.database)
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    assert!(IssuerStore::create(
        &test_path.database,
        [0x12; 16],
        issuer_id(),
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        test_path.authority.clone(),
    )
    .is_err());

    let connection = Connection::open(&test_path.database).unwrap();
    let all_columns: Vec<String> = connection
        .prepare(
            "SELECT name FROM pragma_table_info('store_identity') \
             UNION ALL SELECT name FROM pragma_table_info('quotes') \
             UNION ALL SELECT name FROM pragma_table_info('claims') \
             UNION ALL SELECT name FROM pragma_table_info('receipt_serials') \
             UNION ALL SELECT name FROM pragma_table_info('quote_delegation_heads') \
             UNION ALL SELECT name FROM pragma_table_info('quote_status_nonces') \
             UNION ALL SELECT name FROM pragma_table_info('bat_key_lineages') \
             UNION ALL SELECT name FROM pragma_table_info('settlement_key_lineages')",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for forbidden in [
        "creation_idempotency_key",
        "claim_idempotency_key",
        "payer",
        "payer_id",
        "browser_ip",
        "client_ip",
        "query_id",
        "bitcoin_address",
        "pir_share",
        "peer_provider",
        "route",
        "payment_preimage",
        "preimage",
        "request_nonce",
        "status_request_signature",
        "claim_pubkey_xonly",
    ] {
        assert!(!all_columns.iter().any(|column| column == forbidden));
    }
    assert!(all_columns
        .iter()
        .any(|column| column == "creation_idempotency_digest"));
    assert!(all_columns
        .iter()
        .any(|column| column == "claim_idempotency_digest"));
}

#[test]
fn authenticated_status_reads_consume_only_nonce_digests_and_reject_replay_or_rollback() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let reservation = reservation(0x39, 0x81, &delegation(1, 0x22));
    let _ = store.reserve_quote(&reservation).unwrap();
    let finalization = finalization(0x39, 0x49, reservation.intent_digest);
    let _ = store.finalize_quote(&finalization).unwrap();

    let first_request = status_request(0x39, reservation.intent_digest, 320, 0x82);
    let first = store
        .consume_quote_status_request(&first_request, 320, &accept_status_signature)
        .unwrap();
    assert_eq!(first.value.state, QuoteState::InvoiceOpen);
    assert_eq!(first.value.state_version, 1);
    assert_eq!(
        first.value.exact_signed_quote_response,
        finalization.exact_signed_quote_response
    );
    assert_eq!(store.identity().unwrap().status_time_floor, 320);
    assert!(matches!(
        store.consume_quote_status_request(&first_request, 320, &accept_status_signature),
        Err(StoreError::StatusNonceReplay)
    ));

    let connection = Connection::open(&test_path.database).unwrap();
    let stored_nonce_digest: Vec<u8> = connection
        .query_row("SELECT nonce_digest FROM quote_status_nonces", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_ne!(stored_nonce_digest, first_request.request_nonce);
    assert!(!stored_nonce_digest
        .windows(32)
        .any(|window| window == first_request.request_nonce));
    drop(connection);

    let bad_signature = status_request(0x39, reservation.intent_digest, 321, 0x83);
    let before_bad_signature = store.identity().unwrap().commit_seq;
    assert!(matches!(
        store.consume_quote_status_request(&bad_signature, 321, &reject_status_signature),
        Err(StoreError::BadStatusRequestSignature)
    ));
    assert_eq!(store.identity().unwrap().commit_seq, before_bad_signature);
    // A rejected signature did not consume the nonce.
    let _ = store
        .consume_quote_status_request(&bad_signature, 321, &accept_status_signature)
        .unwrap();

    let mut wrong_binding = status_request(0x39, reservation.intent_digest, 322, 0x84);
    wrong_binding.quote_request_digest[0] ^= 1;
    assert!(matches!(
        store.consume_quote_status_request(&wrong_binding, 322, &accept_status_signature),
        Err(StoreError::StatusRequestBindingMismatch)
    ));
    let stale = status_request(0x39, reservation.intent_digest, 100, 0x85);
    assert!(matches!(
        store.consume_quote_status_request(&stale, 1_000, &accept_status_signature),
        Err(StoreError::StatusRequestStale)
    ));
    let clock_rollback = status_request(0x39, reservation.intent_digest, 319, 0x86);
    assert!(matches!(
        store.consume_quote_status_request(&clock_rollback, 319, &accept_status_signature),
        Err(StoreError::StatusTimeRollback)
    ));
}

#[test]
fn concurrent_authenticated_status_nonce_is_consumed_once() {
    let test_path = TestPath::new();
    let store = Arc::new(create_store(&test_path));
    let reservation = reservation(0x38, 0x80, &delegation(1, 0x22));
    let _ = store.reserve_quote(&reservation).unwrap();
    let _ = store
        .finalize_quote(&finalization(0x38, 0x48, reservation.intent_digest))
        .unwrap();
    let request = Arc::new(status_request(0x38, reservation.intent_digest, 320, 0x81));
    let barrier = Arc::new(Barrier::new(2));
    let workers = [0, 1].map(|_| {
        let store = Arc::clone(&store);
        let request = Arc::clone(&request);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            store.consume_quote_status_request(&request, 320, &accept_status_signature)
        })
    });
    let outcomes = workers.map(|worker| worker.join().unwrap());
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(StoreError::StatusNonceReplay)))
            .count(),
        1
    );
}

#[test]
fn authenticated_status_nonce_window_is_bounded_per_quote_and_recovers_after_expiry() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let reservation = reservation(0x37, 0x7f, &delegation(1, 0x22));
    let _ = store.reserve_quote(&reservation).unwrap();
    let _ = store
        .finalize_quote(&finalization(0x37, 0x47, reservation.intent_digest))
        .unwrap();

    for nonce in 1..=64u8 {
        let request = status_request(0x37, reservation.intent_digest, 320, nonce);
        let _ = store
            .consume_quote_status_request(&request, 320, &accept_status_signature)
            .unwrap();
    }
    let saturated = status_request(0x37, reservation.intent_digest, 320, 65);
    assert!(matches!(
        store.consume_quote_status_request(&saturated, 320, &accept_status_signature),
        Err(StoreError::StatusNonceCapacityExceeded)
    ));

    // The V1 status freshness horizon is five minutes. Once those nonces are
    // expired, deterministic cleanup and a fresh authenticated read can
    // commit in the same transaction.
    let recovered = status_request(0x37, reservation.intent_digest, 621, 66);
    assert!(store
        .consume_quote_status_request(&recovered, 621, &accept_status_signature)
        .is_ok());
}

#[test]
fn stale_backup_restore_is_rejected_by_the_independent_authority() {
    let live = TestPath::new();
    let store = create_store(&live);
    let reservation = reservation(0x3a, 0x87, &delegation(1, 0x22));
    let _ = store.reserve_quote(&reservation).unwrap();
    copy_database_without_wal(&live.database, &live.backup);

    let _ = store
        .finalize_quote(&finalization(0x3a, 0x4a, reservation.intent_digest))
        .unwrap();
    assert_eq!(live.authority.floor().unwrap().store_generation, 2);
    drop(store);

    remove_sqlite_sidecars(&live.database);
    std::fs::copy(&live.backup, &live.database).unwrap();
    assert!(matches!(
        open_store(&live),
        Err(StoreError::RollbackDetected {
            database_generation: 1,
            authority_generation: 2,
        })
    ));
}

#[test]
fn missing_or_wrong_external_floor_fails_closed() {
    let path = TestPath::new();
    let store = create_store(&path);
    drop(store);

    let missing = Arc::new(MemoryRollbackAuthority::default());
    assert!(matches!(
        IssuerStore::open_existing(
            &path.database,
            issuer_id(),
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
            missing,
        ),
        Err(StoreError::RollbackFloorMissing)
    ));

    let wrong = Arc::new(MemoryRollbackAuthority::default());
    wrong.set_floor(IssuerRollbackFloorV1 {
        store_instance_id: [0x99; 16],
        issuer_id: issuer_id(),
        network: LightningNetworkV1::Regtest,
        store_generation: 0,
        rollback_commitment: [0x88; 32],
        schema_version: SCHEMA_VERSION,
    });
    assert!(matches!(
        IssuerStore::open_existing(
            &path.database,
            issuer_id(),
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
            wrong,
        ),
        Err(StoreError::RollbackFloorIdentityMismatch)
    ));
}

#[test]
fn committed_but_unanchored_write_recovers_once_and_replays_without_advancing() {
    let path = TestPath::new();
    let store = create_store(&path);
    let reservation = reservation(0x3d, 0x8b, &delegation(1, 0x22));
    path.authority.reject_next_advance();

    assert!(matches!(
        store.reserve_quote(&reservation),
        Err(StoreError::UnanchoredCommit {
            store_generation: 1,
            ..
        })
    ));
    assert_eq!(path.authority.floor().unwrap().store_generation, 0);
    let database_generation: i64 = Connection::open(&path.database)
        .unwrap()
        .query_row("SELECT commit_seq FROM store_identity", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(database_generation, 1);
    assert_eq!(path.authority.compare_and_advance_calls(), 1);
    drop(store);

    let recovered = open_store(&path).unwrap();
    assert_eq!(recovered.identity().unwrap().commit_seq, 1);
    assert_eq!(path.authority.floor().unwrap().store_generation, 1);
    assert_eq!(path.authority.compare_and_advance_calls(), 2);
    let replay = recovered.reserve_quote(&reservation).unwrap();
    assert_eq!(replay.disposition, WriteDisposition::ExactReplay);
    assert_eq!(recovered.identity().unwrap().commit_seq, 1);
    assert_eq!(path.authority.compare_and_advance_calls(), 2);
}

#[test]
fn lost_cas_response_recovers_without_a_second_generation() {
    let path = TestPath::new();
    let store = create_store(&path);
    let reservation = reservation(0x3e, 0x8c, &delegation(1, 0x22));
    path.authority.lose_next_advance_response();

    assert!(matches!(
        store.reserve_quote(&reservation),
        Err(StoreError::UnanchoredCommit {
            store_generation: 1,
            ..
        })
    ));
    assert_eq!(path.authority.floor().unwrap().store_generation, 1);
    assert_eq!(path.authority.compare_and_advance_calls(), 1);
    drop(store);

    let recovered = open_store(&path).unwrap();
    assert_eq!(recovered.identity().unwrap().commit_seq, 1);
    assert_eq!(path.authority.compare_and_advance_calls(), 1);
    assert_eq!(
        recovered.reserve_quote(&reservation).unwrap().disposition,
        WriteDisposition::ExactReplay
    );
    assert_eq!(recovered.identity().unwrap().commit_seq, 1);
}

#[test]
fn same_generation_fork_and_two_step_unanchored_advance_are_rejected() {
    let same_generation = TestPath::new();
    let store = create_store(&same_generation);
    let _ = store
        .reserve_quote(&reservation(0x3f, 0x8d, &delegation(1, 0x22)))
        .unwrap();
    drop(store);
    Connection::open(&same_generation.database)
        .unwrap()
        .execute(
            "UPDATE store_identity SET rollback_commitment = ?1 WHERE singleton = 1",
            [[0xa5_u8; 32].as_slice()],
        )
        .unwrap();
    assert!(matches!(
        open_store(&same_generation),
        Err(StoreError::RollbackFork)
    ));

    let two_step = TestPath::new();
    let store = create_store(&two_step);
    drop(store);
    let initial = two_step.authority.floor().unwrap();
    Connection::open(&two_step.database)
        .unwrap()
        .execute(
            "UPDATE store_identity SET commit_seq = 2, rollback_parent_commitment = ?1, \
             rollback_commitment = ?2 WHERE singleton = 1",
            rusqlite::params![
                initial.rollback_commitment.as_slice(),
                [0xa6_u8; 32].as_slice()
            ],
        )
        .unwrap();
    assert!(matches!(
        open_store(&two_step),
        Err(StoreError::RollbackFork)
    ));
    assert_eq!(two_step.authority.floor().unwrap(), initial);
}

#[test]
fn authority_outage_blocks_open_writes_reads_and_exact_replay() {
    let path = TestPath::new();
    let store = create_store(&path);
    let reservation = reservation(0x40, 0x8e, &delegation(1, 0x22));
    let _ = store.reserve_quote(&reservation).unwrap();
    let generation = store.identity().unwrap().commit_seq;

    path.authority.set_unavailable(true);
    assert!(matches!(
        open_store(&path),
        Err(StoreError::RollbackAuthorityUnavailable(_))
    ));
    assert!(matches!(
        store.quote(&reservation.quote_id),
        Err(StoreError::RollbackAuthorityUnavailable(_))
    ));
    assert!(matches!(
        store.reserve_quote(&reservation),
        Err(StoreError::RollbackAuthorityUnavailable(_))
    ));
    path.authority.set_unavailable(false);
    assert_eq!(store.identity().unwrap().commit_seq, generation);
    assert_eq!(
        store.reserve_quote(&reservation).unwrap().disposition,
        WriteDisposition::ExactReplay
    );
}

#[test]
fn read_result_is_discarded_when_the_post_read_authority_check_fails() {
    let path = TestPath::new();
    let store = create_store(&path);
    let reservation = reservation(0x49, 0x8f, &delegation(1, 0x22));
    let _ = store.reserve_quote(&reservation).unwrap();

    // A quote read performs two authority loads before its SELECT and two
    // more before returning. Fail the first post-SELECT load.
    path.authority.fail_load_after(2);
    assert!(matches!(
        store.quote(&reservation.quote_id),
        Err(StoreError::RollbackAuthorityUnavailable(_))
    ));
    assert!(store.quote(&reservation.quote_id).unwrap().is_some());
}

#[test]
fn serve_mode_rejects_missing_corrupt_wrong_identity_network_schema_and_symlink() {
    let missing = TestPath::new();
    assert!(matches!(
        IssuerStore::open_existing(
            &missing.database,
            issuer_id(),
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
            missing.authority.clone(),
        ),
        Err(StoreError::MissingDatabase(_))
    ));
    assert!(!missing.database.exists());

    let corrupt = TestPath::new();
    std::fs::write(&corrupt.database, b"not sqlite").unwrap();
    assert!(IssuerStore::open_existing(
        &corrupt.database,
        issuer_id(),
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        corrupt.authority.clone(),
    )
    .is_err());

    let wrong = TestPath::new();
    let _store = create_store(&wrong);
    assert!(matches!(
        IssuerStore::open_existing(
            &wrong.database,
            [0x99; 32],
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
            wrong.authority.clone(),
        ),
        Err(StoreError::IssuerMismatch)
    ));
    assert!(matches!(
        IssuerStore::open_existing(
            &wrong.database,
            issuer_id(),
            LightningNetworkV1::Bitcoin,
            StoreOptions::default(),
            wrong.authority.clone(),
        ),
        Err(StoreError::NetworkMismatch)
    ));

    let schema = TestPath::new();
    let store = create_store(&schema);
    drop(store);
    let connection = Connection::open(&schema.database).unwrap();
    connection.pragma_update(None, "user_version", 999).unwrap();
    drop(connection);
    assert!(matches!(
        IssuerStore::open_existing(
            &schema.database,
            issuer_id(),
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
            schema.authority.clone(),
        ),
        Err(StoreError::SchemaMismatch(_))
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = TestPath::new();
        let _store = create_store(&target);
        let link = target._directory.path().join("issuer-link.sqlite3");
        symlink(&target.database, &link).unwrap();
        assert!(matches!(
            IssuerStore::open_existing(
                &link,
                issuer_id(),
                LightningNetworkV1::Regtest,
                StoreOptions::default(),
                target.authority.clone(),
            ),
            Err(StoreError::NotRegularDatabase(_))
        ));
    }
}

#[test]
fn quote_claim_exact_replay_state_versions_and_no_raw_idempotency_persistence() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let delegation = delegation(1, 0x22);
    let reservation = reservation(0x41, 0xa1, &delegation);

    let first = store.reserve_quote(&reservation).unwrap();
    assert_eq!(first.disposition, WriteDisposition::Committed);
    assert_eq!(first.value.state, QuoteState::Reserved);
    assert_eq!(first.value.state_version, 0);
    assert_ne!(
        first.value.creation_idempotency_digest,
        reservation.creation_idempotency_key
    );
    assert!(!first
        .value
        .intent_replay_image
        .windows(32)
        .any(|window| window == reservation.creation_idempotency_key));

    let replay = store.reserve_quote(&reservation).unwrap();
    assert_eq!(replay.disposition, WriteDisposition::ExactReplay);
    assert_eq!(replay.commit, first.commit);
    assert_eq!(replay.value.state_version, 0);

    let mut conflict = reservation.clone();
    conflict.quote_id = [0x42; 32];
    assert!(matches!(
        store.reserve_quote(&conflict),
        Err(StoreError::CreationIdempotencyConflict)
    ));

    let finalization = finalization(0x41, 0x51, reservation.intent_digest);
    let finalized = store.finalize_quote(&finalization).unwrap();
    assert_eq!(finalized.value.state, QuoteState::InvoiceOpen);
    assert_eq!(finalized.value.state_version, 1);
    let final_replay = store.finalize_quote(&finalization).unwrap();
    assert_eq!(final_replay.disposition, WriteDisposition::ExactReplay);
    assert_eq!(final_replay.commit, finalized.commit);
    assert_eq!(final_replay.value.state_version, 1);

    let paid = store
        .record_settlement(&settlement(
            0x41,
            reservation.intent_digest,
            350,
            350,
            0x51,
            false,
        ))
        .unwrap();
    assert_eq!(paid.value.state, QuoteState::PaymentSettled);
    assert_eq!(paid.value.state_version, 2);

    // Claim and creation keys may be equal: their persisted digests are in
    // independent endpoint domains.
    let claim = claim(0x41, reservation.intent_digest, 0xa1, 0x51, 0x71, 0x25, 3);
    let claimed = store
        .record_claim(&claim, &accept_claim_crypto, None)
        .unwrap();
    assert_eq!(claimed.disposition, WriteDisposition::Committed);
    assert_ne!(
        claimed.value.claim_idempotency_digest,
        claim.claim_idempotency_key
    );
    assert_ne!(
        claimed.value.claim_idempotency_digest,
        first.value.creation_idempotency_digest
    );
    assert!(!claimed
        .value
        .claim_request_replay_image
        .windows(32)
        .any(|window| window == claim.claim_idempotency_key));
    assert_eq!(store.quote(&[0x41; 32]).unwrap().unwrap().state_version, 3);

    drop(store);
    let store = IssuerStore::open_existing(
        &test_path.database,
        issuer_id(),
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        test_path.authority.clone(),
    )
    .unwrap();
    let mut late_replay = claim.clone();
    late_replay.now_unix = 999_999;
    let recovered = store
        .record_claim(&late_replay, &reject_claim_crypto, None)
        .unwrap();
    assert_eq!(recovered.disposition, WriteDisposition::ExactReplay);
    assert_eq!(recovered.commit, claimed.commit);
    assert_eq!(
        recovered.value.exact_claim_response,
        claim.exact_claim_response
    );

    let connection = Connection::open(&test_path.database).unwrap();
    let stored_intent: Vec<u8> = connection
        .query_row("SELECT intent_replay_image FROM quotes", [], |row| {
            row.get(0)
        })
        .unwrap();
    let stored_claim: Vec<u8> = connection
        .query_row("SELECT claim_request_replay_image FROM claims", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(!stored_intent
        .windows(32)
        .any(|window| window == reservation.creation_idempotency_key));
    assert!(!stored_claim
        .windows(32)
        .any(|window| window == claim.claim_idempotency_key));
}

#[test]
fn signed_lifecycle_and_mandatory_claim_crypto_fail_closed_before_commit() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let reservation = reservation(0x3b, 0x88, &delegation(1, 0x22));
    let _ = store.reserve_quote(&reservation).unwrap();

    let valid_finalization = finalization(0x3b, 0x4b, reservation.intent_digest);
    let mut bad_signature = valid_finalization.clone();
    let last = bad_signature.exact_signed_quote_response.len() - 1;
    bad_signature.exact_signed_quote_response[last] ^= 1;
    assert!(matches!(
        store.finalize_quote(&bad_signature),
        Err(StoreError::SignedQuoteMismatch)
    ));
    assert_eq!(store.identity().unwrap().commit_seq, 1);
    assert_eq!(
        store.quote(&[0x3b; 32]).unwrap().unwrap().state,
        QuoteState::Reserved
    );
    let _ = store.finalize_quote(&valid_finalization).unwrap();

    let mut wrong_transition = settlement(0x3b, reservation.intent_digest, 350, 350, 0x4b, false);
    wrong_transition.exact_signed_quote_response =
        valid_finalization.exact_signed_quote_response.clone();
    assert!(matches!(
        store.record_settlement(&wrong_transition),
        Err(StoreError::SignedQuoteMismatch)
    ));
    let _ = store
        .record_settlement(&settlement(
            0x3b,
            reservation.intent_digest,
            350,
            350,
            0x4b,
            false,
        ))
        .unwrap();

    let valid_claim = claim(0x3b, reservation.intent_digest, 0x89, 0x4b, 0x75, 0x25, 3);
    let mut envelope_mismatch = valid_claim.clone();
    let mut parsed_response =
        CredentialIssuanceResponseV1::decode(&envelope_mismatch.exact_claim_response, None)
            .unwrap();
    parsed_response.credential_binding_digest[0] ^= 1;
    envelope_mismatch.exact_claim_response = parsed_response.encode().unwrap();
    assert!(matches!(
        store.record_claim(&envelope_mismatch, &accept_claim_crypto, None),
        Err(StoreError::ClaimProtocolMismatch)
    ));
    assert!(matches!(
        store.record_claim(&valid_claim, &reject_claim_crypto, None),
        Err(StoreError::BadClaimCryptography)
    ));
    assert_eq!(store.identity().unwrap().commit_seq, 3);
    assert!(store.claim(&[0x3b; 32]).unwrap().is_none());

    let mut wrong_claim_snapshot = valid_claim.clone();
    wrong_claim_snapshot.exact_signed_quote_response =
        valid_finalization.exact_signed_quote_response.clone();
    assert!(matches!(
        store.record_claim(&wrong_claim_snapshot, &accept_claim_crypto, None),
        Err(StoreError::SignedQuoteMismatch)
    ));
    let committed = store
        .record_claim(&valid_claim, &accept_claim_crypto, None)
        .unwrap();
    assert_eq!(committed.value.receipt_serials.len(), 1);
    assert_eq!(committed.value.receipt_serials[0].serial, [0x75; 32]);
}

#[test]
fn signed_quote_corruption_is_rejected_on_restart_integrity_check() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let reservation = reservation(0x3c, 0x8a, &delegation(1, 0x22));
    let _ = store.reserve_quote(&reservation).unwrap();
    let _ = store
        .finalize_quote(&finalization(0x3c, 0x4c, reservation.intent_digest))
        .unwrap();
    drop(store);

    let connection = Connection::open(&test_path.database).unwrap();
    let quote_id = [0x3c_u8; 32];
    let mut exact: Vec<u8> = connection
        .query_row(
            "SELECT initial_signed_quote_response FROM quotes WHERE quote_id = ?1",
            [quote_id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let last = exact.len() - 1;
    exact[last] ^= 1;
    connection
        .execute(
            "UPDATE quotes SET initial_signed_quote_response = ?1 WHERE quote_id = ?2",
            rusqlite::params![exact, quote_id.as_slice()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        IssuerStore::open_existing(
            &test_path.database,
            issuer_id(),
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
            test_path.authority.clone(),
        ),
        Err(StoreError::SignedQuoteMismatch)
    ));
}

#[test]
fn full_request_conflicts_are_not_hidden_by_idempotency_digest() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let delegation = delegation(1, 0x22);
    let reservation = reservation(0x43, 0xa2, &delegation);
    let _ = store.reserve_quote(&reservation).unwrap();

    let mut changed_intent = reservation.clone();
    let mut parsed = Bolt11QuoteIntentV1::decode(&changed_intent.exact_intent).unwrap();
    parsed.provider_id[0] ^= 1;
    changed_intent.intent_digest = parsed.request_digest().unwrap();
    changed_intent.exact_intent = parsed.encode().unwrap();
    assert!(matches!(
        store.reserve_quote(&changed_intent),
        Err(StoreError::CreationIdempotencyConflict)
    ));

    let _ = store
        .finalize_quote(&finalization(0x43, 0x52, reservation.intent_digest))
        .unwrap();
    let _ = store
        .record_settlement(&settlement(
            0x43,
            reservation.intent_digest,
            350,
            350,
            0x52,
            false,
        ))
        .unwrap();
    let claim = claim(0x43, reservation.intent_digest, 0xa3, 0x52, 0x72, 0x25, 3);
    let _ = store
        .record_claim(&claim, &accept_claim_crypto, None)
        .unwrap();
    let mut changed_claim = claim.clone();
    changed_claim.exact_claim_response.push(0xff);
    assert!(matches!(
        store.record_claim(&changed_claim, &accept_claim_crypto, None),
        Err(StoreError::ClaimIdempotencyConflict)
    ));
}

#[test]
fn late_settlement_requires_expiry_transition_and_remains_claimable() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let delegation = delegation(1, 0x22);
    let reservation = reservation(0x44, 0xa4, &delegation);
    let _ = store.reserve_quote(&reservation).unwrap();
    let _ = store
        .finalize_quote(&finalization(0x44, 0x53, reservation.intent_digest))
        .unwrap();

    assert!(matches!(
        store.record_settlement(&settlement(
            0x44,
            reservation.intent_digest,
            361,
            361,
            0x53,
            true,
        )),
        Err(StoreError::RequiresExpiryReconcile)
    ));
    let expiry = QuoteExpiry {
        quote_id: [0x44; 32],
        observed_at: 361,
        exact_signed_quote_response: signed_quote(
            0x44,
            reservation.intent_digest,
            0x53,
            Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile,
            2,
            361,
        ),
    };
    let expired = store.mark_invoice_expired(&expiry).unwrap();
    assert_eq!(
        expired.value.state,
        QuoteState::InvoiceExpiredPendingReconcile
    );
    assert_eq!(expired.value.state_version, 2);
    let expiry_replay = store.mark_invoice_expired(&expiry).unwrap();
    assert_eq!(expiry_replay.commit, expired.commit);

    let late = store
        .record_settlement(&settlement(
            0x44,
            reservation.intent_digest,
            350,
            362,
            0x53,
            true,
        ))
        .unwrap();
    assert_eq!(late.value.state, QuoteState::LateSettledReconcile);
    assert_eq!(late.value.state_version, 3);
    let _ = store
        .record_claim(
            &claim(0x44, reservation.intent_digest, 0xa5, 0x53, 0x73, 0x25, 4),
            &accept_claim_crypto,
            None,
        )
        .unwrap();
    assert_eq!(store.quote(&[0x44; 32]).unwrap().unwrap().state_version, 4);
}

#[test]
fn delegation_guard_rejects_rollback_and_same_epoch_fork_across_restart() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let first = delegation(1, 0x22);
    let first_input = DelegationAdvance {
        payee_pubkey: first.expected_payee_pubkey,
        delegation_epoch: first.key_epoch,
        delegation_digest: first.delegation_digest().unwrap(),
        exact_delegation: first.encode().unwrap(),
        now_unix: 200,
    };
    let installed = store.advance_delegation(&first_input).unwrap();
    assert_eq!(installed.disposition, WriteDisposition::Committed);
    assert_eq!(
        store.advance_delegation(&first_input).unwrap().disposition,
        WriteDisposition::ExactReplay
    );

    let second = delegation(2, 0x23);
    let second_input = DelegationAdvance {
        payee_pubkey: second.expected_payee_pubkey,
        delegation_epoch: second.key_epoch,
        delegation_digest: second.delegation_digest().unwrap(),
        exact_delegation: second.encode().unwrap(),
        now_unix: 200,
    };
    let _ = store.advance_delegation(&second_input).unwrap();
    assert!(matches!(
        store.advance_delegation(&first_input),
        Err(StoreError::DelegationRollback)
    ));

    let fork = delegation(2, 0x24);
    let fork_input = DelegationAdvance {
        payee_pubkey: fork.expected_payee_pubkey,
        delegation_epoch: fork.key_epoch,
        delegation_digest: fork.delegation_digest().unwrap(),
        exact_delegation: fork.encode().unwrap(),
        now_unix: 200,
    };
    assert!(matches!(
        store.advance_delegation(&fork_input),
        Err(StoreError::DelegationFork)
    ));
    drop(store);

    let reopened = IssuerStore::open_existing(
        &test_path.database,
        issuer_id(),
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        test_path.authority.clone(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .delegation_head(&point(2))
            .unwrap()
            .unwrap()
            .highest_epoch,
        2
    );
    assert!(matches!(
        reopened.advance_delegation(&first_input),
        Err(StoreError::DelegationRollback)
    ));
}

#[test]
fn concurrent_exact_quote_reservation_commits_once() {
    const THREADS: usize = 10;
    let test_path = TestPath::new();
    let store = Arc::new(create_store(&test_path));
    let reservation = Arc::new(reservation(0x45, 0xa6, &delegation(1, 0x22)));
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut workers = Vec::new();
    for _ in 0..THREADS {
        let store = Arc::clone(&store);
        let reservation = Arc::clone(&reservation);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            store
                .reserve_quote(&reservation)
                .map(|outcome| outcome.disposition)
        }));
    }
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == WriteDisposition::Committed)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == WriteDisposition::ExactReplay)
            .count(),
        THREADS - 1
    );
    assert_eq!(store.identity().unwrap().commit_seq, 1);
    assert_eq!(test_path.authority.floor().unwrap().store_generation, 1);
    // A replaying thread may observe the committed SQLite generation before
    // the committing thread anchors it and legitimately help complete that
    // same CAS. The original writer then performs an idempotent CAS, so both
    // one and two authority calls preserve a single durable generation.
    assert!(matches!(
        test_path.authority.compare_and_advance_calls(),
        1 | 2
    ));
}

#[test]
fn receipt_serial_is_global_per_issuer_across_key_ids_and_claims_are_concurrent_safe() {
    let test_path = TestPath::new();
    let store = Arc::new(create_store(&test_path));
    let first = reserve_finalize_settle(&store, 0x46, 0xa7, 0x54);
    let second = reserve_finalize_settle_with_receipt_key(&store, 0x47, 0xa8, 0x55, 0x26);
    let claims = [
        claim(0x46, first.intent_digest, 0xa9, 0x54, 0x74, 0x25, 3),
        claim(0x47, second.intent_digest, 0xaa, 0x55, 0x74, 0x26, 3),
    ];
    let barrier = Arc::new(Barrier::new(2));
    let workers = claims.map(|claim| {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            store.record_claim(&claim, &accept_claim_crypto, None)
        })
    });
    let outcomes = workers.map(|worker| worker.join().unwrap());
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(StoreError::ReceiptSerialConflict)))
            .count(),
        1
    );
}

#[test]
fn bat_and_settlement_key_lineages_are_immutable_and_survive_restart() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let bat_key = point(4);
    let bat = BatKeyLineageRegistration {
        raw_public_key: bat_key,
        provider_id: [0xb1; 32],
        scope_id: [0xb2; 32],
        offer_id: 9,
        entitlement_profile: 4,
        keyset_epoch: 3,
        credential_key_id: derive_bat_key_id_v1(&[0xb1; 32], &[0xb2; 32], 9, 4, 3, &bat_key),
    };
    let installed = store.register_bat_key_lineage(&bat).unwrap();
    assert_eq!(installed.disposition, WriteDisposition::Committed);
    assert_eq!(
        store.register_bat_key_lineage(&bat).unwrap().disposition,
        WriteDisposition::ExactReplay
    );
    let mut rebound = bat.clone();
    rebound.provider_id = [0xb3; 32];
    rebound.credential_key_id = derive_bat_key_id_v1(
        &rebound.provider_id,
        &rebound.scope_id,
        rebound.offer_id,
        rebound.entitlement_profile,
        rebound.keyset_epoch,
        &rebound.raw_public_key,
    );
    assert!(matches!(
        store.register_bat_key_lineage(&rebound),
        Err(StoreError::BatKeyLineageConflict)
    ));

    let settlement_key = point(5);
    let keyset_id = derive_cashu_keyset_id_v2(
        &[CashuDenominationKeyV1 {
            amount: 1,
            public_key: settlement_key,
        }],
        "sat",
        0,
        Some(20_000),
    )
    .unwrap();
    let settlement = SettlementKeyLineageRegistration {
        raw_public_key: settlement_key,
        keyset_id,
        unit: "sat".to_owned(),
        keyset_epoch: 8,
        denomination: 1,
        manifest_digest: [0xc1; 32],
        final_expiry: Some(20_000),
    };
    let _ = store.register_settlement_key_lineage(&settlement).unwrap();
    assert_eq!(
        store
            .register_settlement_key_lineage(&settlement)
            .unwrap()
            .disposition,
        WriteDisposition::ExactReplay
    );
    let mut changed = settlement.clone();
    changed.manifest_digest = [0xc2; 32];
    assert!(matches!(
        store.register_settlement_key_lineage(&changed),
        Err(StoreError::SettlementKeyLineageConflict)
    ));
    drop(store);

    let reopened = IssuerStore::open_existing(
        &test_path.database,
        issuer_id(),
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        test_path.authority.clone(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .bat_key_lineage(&bat.raw_public_key)
            .unwrap()
            .unwrap()
            .lineage_digest,
        installed.value.lineage_digest
    );
    assert_eq!(
        reopened
            .settlement_key_lineage(&settlement.raw_public_key)
            .unwrap()
            .unwrap()
            .manifest_digest,
        settlement.manifest_digest
    );
}

#[test]
fn schema_extension_and_semantic_backend_label_corruption_fail_closed() {
    let extra = TestPath::new();
    let store = create_store(&extra);
    drop(store);
    let connection = Connection::open(&extra.database).unwrap();
    connection
        .execute("CREATE TABLE unexpected (value INTEGER)", [])
        .unwrap();
    drop(connection);
    assert!(matches!(
        IssuerStore::open_existing(
            &extra.database,
            issuer_id(),
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
            extra.authority.clone(),
        ),
        Err(StoreError::SchemaMismatch(_))
    ));

    let semantic = TestPath::new();
    let store = create_store(&semantic);
    let _ = store
        .reserve_quote(&reservation(0x48, 0xab, &delegation(1, 0x22)))
        .unwrap();
    drop(store);
    let connection = Connection::open(&semantic.database).unwrap();
    connection
        .execute("UPDATE quotes SET backend_label = 'attacker-label'", [])
        .unwrap();
    drop(connection);
    assert!(matches!(
        IssuerStore::open_existing(
            &semantic.database,
            issuer_id(),
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
            semantic.authority.clone(),
        ),
        Err(StoreError::SchemaMismatch(_))
    ));
}
