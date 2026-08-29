use ed25519_dalek::{Signer, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use pir_issuer_store::{
    BatKeyLineageRegistration, BatV2ClaimCryptographicVerificationInputV2, BatV2ClaimWrite,
    BatV2ClearingEpochReservationV2, BatV2QuoteReservation, ClaimCryptographicVerificationInput,
    ClaimWrite, DelegationAdvance, IssuerStore, ProviderSettlementRegistrationWriteV1,
    QuoteCapacityV1, QuoteExpiry, QuoteFinalization, QuoteReservation, QuoteSettlement, QuoteState,
    QuoteStatusBip340Input, SettlementKeyLineageRegistration, StoreError, StoreOptions,
    WriteDisposition, SCHEMA_VERSION,
};
use pir_service_protocol::{
    derive_bat_key_id_v1, derive_cashu_keyset_id_v2, derive_issuer_id, paid_receipt_key_id,
    precheck_bat_v2_redeem_v2, sign_and_commit_grantable_success_v2,
    verify_bat_v2_credential_for_commit_v2, AcquisitionMethod, AuthPaddingClassV1, AuthScheme,
    BackendId, BatAcceptanceClassV2, BatAcceptanceMemberV2, BatAcceptanceTermsV2,
    BatV2CredentialCheckV2, BatV2IssuanceRequestV2, BatV2IssuanceResponseV2,
    BatV2ProofVerificationInputV2, BatV2RedeemCommitResultV2, BatV2RedeemPrecheckV2,
    BitcoinPirCashuBatIssuanceRequestItemV1, BitcoinPirCashuBatIssuanceResponseItemV1,
    BitcoinPirCashuBatProofV2, Bolt11BatV2ClaimEnvelopeV2, Bolt11BatV2QuoteIntentV2,
    Bolt11QuoteClaimV1, Bolt11QuoteIntentV1, Bolt11QuoteKeyDelegationV1,
    Bolt11QuoteStatusRequestV1, Bolt11QuoteStatusV1, Bolt11QuoteV1, CashuDenominationKeyV1,
    CredentialIssuanceRequestItemsV1, CredentialIssuanceRequestV1,
    CredentialIssuanceResponseItemsV1, CredentialIssuanceResponseV1, DatasetBindingV1,
    DeploymentStatus, EntitlementLimitsV1, FreeModeV1, IssuerAccountingApprovalV2,
    LightningNetworkV1, PaidReceiptBindingV1, PaidReceiptV1, PriceV1, PrivacyLeakageV1,
    ProviderAccountingAuthorizationClaimsV2, ProviderAccountingAuthorizationV2,
    ProviderAccountingExpectationV2, ProviderAccountingRuleV2, ProviderRedeemEnvelopeV2,
    ProviderRedeemRequestAuthV2, ServiceOfferV1, ServicePolicyV1, ServiceScopePolicyV1,
    ServiceScopeV1, SettlementUnitV1, VerificationMode, VerifiedBatAcceptanceMemberV2,
    VerifiedBatV2RedeemCommitV2, WorkloadId, BOLT11_QUOTE_SIGNATURE_DOMAIN,
};
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use tempfile::{Builder, TempDir};

const STORE_INSTANCE: [u8; 16] = [0x11; 16];

struct TestPath {
    _directory: TempDir,
    database: PathBuf,
}

impl TestPath {
    fn new() -> Self {
        let directory = Builder::new()
            .prefix("bitcoinpir-issuer-store-test-")
            .tempdir()
            .expect("create task-specific temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("restrict task-specific temporary directory permissions");
        }
        let database = directory.path().join("issuer.sqlite3");
        Self {
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

fn scalar(multiplier: u64) -> [u8; 32] {
    Scalar::from(multiplier).to_bytes().into()
}

fn bat_v2_limits() -> EntitlementLimitsV1 {
    EntitlementLimitsV1 {
        max_logical_inputs: 4,
        max_frames: 200,
        max_request_bytes: 1_000_000,
        max_response_bytes: 2_000_000,
        max_wall_time_ms: 60_000,
        max_concurrent_sockets: 1,
        max_hint_groups: 0,
        max_work_units: 9_000,
    }
}

fn bat_v2_privacy() -> PrivacyLeakageV1 {
    PrivacyLeakageV1::from_bits(
        PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
            | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
            | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
    )
    .expect("BAT V2 privacy flags")
}

fn bat_v2_scope(provider_id: [u8; 32]) -> ServiceScopeV1 {
    ServiceScopeV1 {
        provider_id,
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        protocol_version: 1,
        dataset: DatasetBindingV1::Class { class_id: 1 },
        operation_profile: 1,
        entitlement_profile: 2,
    }
}

fn bat_v2_offer(class_id: [u8; 32]) -> ServiceOfferV1 {
    ServiceOfferV1 {
        offer_id: 7,
        acquisition: AcquisitionMethod::Bolt11V1,
        free_mode: FreeModeV1::NotFree,
        free_quota: 0,
        free_window_seconds: 0,
        free_pow_difficulty_bits: 0,
        priority_class: 1,
        authorization: AuthScheme::BitcoinPirCashuBatV2,
        verification: VerificationMode::SharedIssuerOnline,
        deployment_status: DeploymentStatus::Stable,
        price: PriceV1::MilliSatoshi(2_000),
        issuer_id: issuer_id(),
        key_id: class_id.to_vec(),
        credential_binding: None,
        cashu_mint_manifest: None,
        endpoint: "https://issuer.invalid".to_owned(),
        invoice_expiry_seconds: 60,
        claim_window_seconds: 120,
        minimum_credential_validity_seconds: 300,
        retired_policy_grace_seconds: 480,
        credential_count: 2,
        credential_presentation_limit: 1,
        privacy_leakage: bat_v2_privacy(),
    }
}

fn bat_v2_terms() -> BatAcceptanceTermsV2 {
    BatAcceptanceTermsV2 {
        auth_padding_class: AuthPaddingClassV1::Class16KiB,
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        protocol_version: 1,
        dataset: DatasetBindingV1::Class { class_id: 1 },
        operation_profile: 1,
        entitlement_profile: 2,
        limits: bat_v2_limits(),
        priority_class: 1,
        deployment_status: DeploymentStatus::Stable,
        price_msat: 2_000,
        issuer_endpoint: "https://issuer.invalid".to_owned(),
        invoice_expiry_seconds: 60,
        claim_window_seconds: 120,
        minimum_credential_validity_seconds: 300,
        retired_policy_grace_seconds: 480,
        credential_count: 2,
        credential_presentation_limit: 1,
        privacy_leakage: bat_v2_privacy(),
    }
}

fn register_bat_v2_member_policy(
    store: &IssuerStore,
    provider_byte: u8,
    signing_key_byte: u8,
    class_id: [u8; 32],
    policy_epoch: u64,
) -> BatAcceptanceMemberV2 {
    let provider_id = [provider_byte; 32];
    let scope = bat_v2_scope(provider_id);
    let scope_id = scope.scope_id();
    let signing_key = SigningKey::from_bytes(&[signing_key_byte; 32]);
    let policy = ServicePolicyV1::sign(
        provider_id,
        policy_epoch,
        100,
        1_000,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope,
            limits: bat_v2_limits(),
            offers: vec![bat_v2_offer(class_id)],
        }],
        &signing_key,
    )
    .expect("sign BAT V2 member policy");
    let policy_digest = policy.policy_digest().expect("BAT V2 policy digest");
    let _ = store
        .register_service_policy(&policy, &signing_key.verifying_key(), 200)
        .expect("register BAT V2 member policy");
    BatAcceptanceMemberV2 {
        provider_id,
        policy_digest,
        scope_id,
        offer_id: 7,
    }
}

fn register_bat_v2_members(
    store: &IssuerStore,
    class_id: [u8; 32],
    policy_epoch: u64,
) -> Vec<BatAcceptanceMemberV2> {
    vec![
        register_bat_v2_member_policy(store, 0xa1, 0xb1, class_id, policy_epoch),
        register_bat_v2_member_policy(store, 0xa2, 0xb2, class_id, policy_epoch),
    ]
}

fn bat_v2_class(
    class_id: [u8; 32],
    key_epoch: u64,
    raw_key_multiplier: u64,
    terms: BatAcceptanceTermsV2,
    members: Vec<BatAcceptanceMemberV2>,
) -> BatAcceptanceClassV2 {
    bat_v2_class_with_validity(
        class_id,
        key_epoch,
        raw_key_multiplier,
        100,
        1_480,
        terms,
        members,
    )
}

#[allow(clippy::too_many_arguments)]
fn bat_v2_class_with_validity(
    class_id: [u8; 32],
    key_epoch: u64,
    raw_key_multiplier: u64,
    key_not_before: u64,
    key_not_after: u64,
    terms: BatAcceptanceTermsV2,
    members: Vec<BatAcceptanceMemberV2>,
) -> BatAcceptanceClassV2 {
    BatAcceptanceClassV2::sign(
        class_id,
        key_epoch,
        key_not_before,
        key_not_after,
        point(raw_key_multiplier),
        terms,
        members,
        &root_key(),
    )
    .expect("sign BAT V2 class")
}

#[derive(Clone)]
struct BatV2RedemptionAuthorityFixture {
    authorization: ProviderAccountingAuthorizationV2,
    approval: IssuerAccountingApprovalV2,
    operator_key: SigningKey,
    clearing_key: SigningKey,
    settlement_key: SigningKey,
}

fn bat_v2_verified_member(
    class: &BatAcceptanceClassV2,
    member: &BatAcceptanceMemberV2,
) -> VerifiedBatAcceptanceMemberV2 {
    VerifiedBatAcceptanceMemberV2 {
        issuer_id: class.issuer_id,
        class_id: class.class_id,
        member: member.clone(),
        common_terms: class.common_terms.clone(),
        policy_issued_at: 100,
        policy_expires_at: 1_000,
        redemption_deadline: 1_480,
    }
}

fn make_bat_v2_redemption_authority(
    class: &BatAcceptanceClassV2,
    member: &BatAcceptanceMemberV2,
    account_byte: u8,
    key_byte: u8,
    epoch: u64,
) -> BatV2RedemptionAuthorityFixture {
    let operator_key = SigningKey::from_bytes(&[key_byte; 32]);
    let clearing_key = SigningKey::from_bytes(&[key_byte.wrapping_add(1); 32]);
    let settlement_key = SigningKey::from_bytes(&[0xd1; 32]);
    let authorization = ProviderAccountingAuthorizationV2::sign(
        ProviderAccountingAuthorizationClaimsV2 {
            authorization_id: [key_byte.wrapping_add(2); 16],
            authorization_epoch: epoch,
            provider_id: member.provider_id,
            issuer_id: issuer_id(),
            redeem_endpoint: "https://issuer.invalid".to_owned(),
            redeem_leaf_spki_sha256_pins: vec![[key_byte.wrapping_add(3); 32]],
            settlement_account_id: [account_byte; 32],
            clearing_verifying_key: clearing_key.verifying_key().to_bytes(),
            not_before: 100,
            not_after: 2_000,
            rules: vec![ProviderAccountingRuleV2 {
                class_id: class.class_id,
                policy_digest: member.policy_digest,
                scope_id: member.scope_id,
                offer_id: member.offer_id,
                unit: SettlementUnitV1::AuthCredit,
                accepted_value: 10,
                provider_credit: 7,
                issuer_fee: 3,
            }],
        },
        &operator_key,
    )
    .expect("sign BAT V2 accounting authorization");
    let approval = IssuerAccountingApprovalV2::sign(&authorization, 200, 2_000, &settlement_key)
        .expect("sign BAT V2 issuer approval");
    BatV2RedemptionAuthorityFixture {
        authorization,
        approval,
        operator_key,
        clearing_key,
        settlement_key,
    }
}

fn bat_v2_redemption_authority(
    store: &IssuerStore,
    class: &BatAcceptanceClassV2,
    member: &BatAcceptanceMemberV2,
    account_byte: u8,
    key_byte: u8,
    epoch: u64,
) -> BatV2RedemptionAuthorityFixture {
    let fixture = make_bat_v2_redemption_authority(class, member, account_byte, key_byte, epoch);
    let _ = store
        .reserve_bat_v2_clearing_epoch(BatV2ClearingEpochReservationV2 {
            provider_id: member.provider_id,
            authorization_epoch: epoch,
        })
        .expect("reserve BAT V2 clearing epoch");
    let _ = store
        .register_bat_v2_accounting_authorization(
            &fixture.authorization,
            &fixture.approval,
            &fixture.operator_key.verifying_key(),
            &fixture.settlement_key.verifying_key(),
            200,
        )
        .expect("register BAT V2 accounting authorization");
    fixture
}

fn bat_v2_redemption_precheck(
    class: &BatAcceptanceClassV2,
    member: &VerifiedBatAcceptanceMemberV2,
    authority: &BatV2RedemptionAuthorityFixture,
    attempt_byte: u8,
    secret_byte: u8,
    now_unix: u64,
) -> BatV2RedeemPrecheckV2 {
    let proof = BitcoinPirCashuBatProofV2::from_class(
        class,
        [secret_byte; 32],
        point(u64::from(secret_byte) + 100),
    )
    .expect("construct BAT V2 proof");
    let (request, _) = pir_service_protocol::ProviderRedeemRequestV2::prepare(
        &authority.authorization,
        member,
        class,
        &proof,
        [attempt_byte; 32],
    )
    .expect("prepare BAT V2 redeem request")
    .into_parts();
    let request_auth = ProviderRedeemRequestAuthV2::sign(&request, &authority.clearing_key)
        .expect("sign BAT V2 request");
    precheck_bat_v2_redeem_v2(
        ProviderRedeemEnvelopeV2 {
            request,
            request_auth,
            credential: proof,
        },
        &authority.authorization,
        &authority.approval,
        class,
        member,
        ProviderAccountingExpectationV2 {
            provider_id: member.member.provider_id,
            issuer_id: issuer_id(),
            operator_verifying_key: &authority.operator_key.verifying_key(),
            issuer_settlement_verifying_key: &authority.settlement_key.verifying_key(),
            now_unix,
            minimum_authorization_epoch: authority.authorization.claims.authorization_epoch,
        },
    )
    .expect("precheck BAT V2 redeem")
}

fn bat_v2_verified_redeem(
    class: &BatAcceptanceClassV2,
    member: &VerifiedBatAcceptanceMemberV2,
    authority: &BatV2RedemptionAuthorityFixture,
    attempt_byte: u8,
    secret_byte: u8,
    now_unix: u64,
) -> VerifiedBatV2RedeemCommitV2 {
    let BatV2RedeemPrecheckV2::Authorized(authorized) = bat_v2_redemption_precheck(
        class,
        member,
        authority,
        attempt_byte,
        secret_byte,
        now_unix,
    ) else {
        panic!("BAT V2 redeem should be authorized")
    };
    fn accept_bat_v2_proof(_input: BatV2ProofVerificationInputV2<'_>) -> Result<bool, ()> {
        Ok(true)
    }
    let verified = verify_bat_v2_credential_for_commit_v2(*authorized, &accept_bat_v2_proof)
        .expect("verify BAT V2 credential");
    let BatV2CredentialCheckV2::Verified(verified) = verified else {
        panic!("BAT V2 credential should be valid")
    };
    verified
}

fn install_bat_v2_redemption_class(
    store: &IssuerStore,
    class_id: [u8; 32],
    key_epoch: u64,
    raw_key_multiplier: u64,
    policy_epoch: u64,
) -> (BatAcceptanceClassV2, Vec<VerifiedBatAcceptanceMemberV2>) {
    let members = register_bat_v2_members(store, class_id, policy_epoch);
    let class = bat_v2_class(
        class_id,
        key_epoch,
        raw_key_multiplier,
        bat_v2_terms(),
        members.clone(),
    );
    let _ = store
        .register_bat_acceptance_class_v2(&class, 200)
        .expect("register BAT V2 redemption class");
    let verified = members
        .iter()
        .map(|member| bat_v2_verified_member(&class, member))
        .collect();
    (class, verified)
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
    )
    .expect("create issuer store")
}

fn open_store(path: &TestPath) -> Result<IssuerStore, StoreError> {
    IssuerStore::open_existing(
        &path.database,
        issuer_id(),
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
    )
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

fn bat_v2_reservation(
    quote_id_byte: u8,
    idempotency_byte: u8,
    class: &BatAcceptanceClassV2,
    delegation: &Bolt11QuoteKeyDelegationV1,
) -> (BatV2QuoteReservation, Bolt11BatV2QuoteIntentV2) {
    let intent = Bolt11BatV2QuoteIntentV2 {
        issuer_id: issuer_id(),
        class_id: class.class_id,
        class_digest: class.class_digest().expect("BAT V2 class digest"),
        class_key_epoch: class.key_epoch,
        bat_key_id: class.bat_key_id(),
        network: LightningNetworkV1::Regtest,
        expected_payee_pubkey: delegation.expected_payee_pubkey,
        minimum_quote_key_epoch: delegation.key_epoch,
        quote_delegation_digest: delegation
            .delegation_digest()
            .expect("BAT V2 delegation digest"),
        exact_amount_msat: class.common_terms.price_msat,
        credential_count: class.common_terms.credential_count,
        invoice_expiry_seconds: class.common_terms.invoice_expiry_seconds,
        claim_window_seconds: class.common_terms.claim_window_seconds,
        minimum_credential_validity_seconds: class.common_terms.minimum_credential_validity_seconds,
        claim_pubkey_xonly: xonly(3),
        idempotency_key: [idempotency_byte; 32],
    };
    let reservation = BatV2QuoteReservation {
        quote_id: [quote_id_byte; 32],
        exact_intent: intent.encode().expect("encode BAT V2 intent"),
        exact_delegation: delegation.encode().expect("encode BAT V2 delegation"),
        invoice_created_not_before: 250,
        invoice_created_not_after: 350,
        now_unix: 200,
    };
    (reservation, intent)
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

fn bat_v2_signed_quote(
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
        invoice: format!("lnbcrt1bitcoinpirbatv2fixture{invoice_suffix}"),
        network: LightningNetworkV1::Regtest,
        payee_pubkey: point(2),
        amount_msat: 2_000,
        invoice_created_at: 300,
        invoice_expires_at: 360,
        claim_deadline: 480,
        credential_not_after: 780,
        status,
        state_version,
        status_updated_at,
        signature: [1; 64],
    };
    let placeholder = snapshot.encode().expect("encode BAT V2 quote placeholder");
    let mut preimage = Vec::new();
    preimage.extend_from_slice(BOLT11_QUOTE_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(&placeholder[..placeholder.len() - 64]);
    snapshot.signature = quote_key().sign(&preimage).to_bytes();
    snapshot.encode().expect("encode signed BAT V2 quote")
}

fn bat_v2_finalization(
    quote_id_byte: u8,
    invoice_suffix: u8,
    quote_request_digest: [u8; 32],
) -> QuoteFinalization {
    QuoteFinalization {
        quote_id: [quote_id_byte; 32],
        invoice: format!("lnbcrt1bitcoinpirbatv2fixture{invoice_suffix}"),
        payment_hash: [invoice_suffix; 32],
        invoice_created_at: 300,
        invoice_expires_at: 360,
        claim_deadline: 480,
        credential_not_after: 780,
        exact_signed_quote_response: bat_v2_signed_quote(
            quote_id_byte,
            quote_request_digest,
            invoice_suffix,
            Bolt11QuoteStatusV1::InvoiceOpen,
            1,
            300,
        ),
    }
}

fn bat_v2_settlement(
    quote_id_byte: u8,
    quote_request_digest: [u8; 32],
    invoice_suffix: u8,
) -> QuoteSettlement {
    QuoteSettlement {
        quote_id: [quote_id_byte; 32],
        settled_at: 350,
        observed_at: 350,
        settled_amount_msat: 2_000,
        settlement_evidence_digest: [invoice_suffix; 32],
        exact_signed_quote_response: bat_v2_signed_quote(
            quote_id_byte,
            quote_request_digest,
            invoice_suffix,
            Bolt11QuoteStatusV1::PaymentSettled,
            2,
            350,
        ),
    }
}

fn bat_v2_claim_write(
    quote_id_byte: u8,
    intent: &Bolt11BatV2QuoteIntentV2,
    claim_idempotency_byte: u8,
    invoice_suffix: u8,
) -> BatV2ClaimWrite {
    let quote_request_digest = intent.request_digest().expect("BAT V2 intent digest");
    let credential_request = BatV2IssuanceRequestV2 {
        issuer_id: issuer_id(),
        quote_id: [quote_id_byte; 32],
        quote_request_digest,
        class_id: intent.class_id,
        class_digest: intent.class_digest,
        class_key_epoch: intent.class_key_epoch,
        bat_key_id: intent.bat_key_id,
        items: vec![
            BitcoinPirCashuBatIssuanceRequestItemV1 {
                blinded_message: point(70),
            },
            BitcoinPirCashuBatIssuanceRequestItemV1 {
                blinded_message: point(71),
            },
        ],
    };
    let credential_request_digest = credential_request
        .request_digest()
        .expect("BAT V2 issuance request digest");
    let claim = Bolt11QuoteClaimV1 {
        issuer_id: issuer_id(),
        quote_id: [quote_id_byte; 32],
        quote_request_digest,
        credential_request_digest,
        claim_pubkey_xonly: intent.claim_pubkey_xonly,
        idempotency_key: [claim_idempotency_byte; 32],
        signature: [0x62; 64],
    };
    let envelope = Bolt11BatV2ClaimEnvelopeV2 {
        quote_intent: intent.clone(),
        claim,
        credential_request: credential_request.clone(),
    };
    let response = BatV2IssuanceResponseV2 {
        issuer_id: issuer_id(),
        quote_id: [quote_id_byte; 32],
        quote_request_digest,
        credential_request_digest,
        class_id: intent.class_id,
        class_digest: intent.class_digest,
        class_key_epoch: intent.class_key_epoch,
        bat_key_id: intent.bat_key_id,
        items: vec![
            BitcoinPirCashuBatIssuanceResponseItemV1 {
                blinded_message: point(70),
                blinded_signature: point(72),
                dleq_e: scalar(1),
                dleq_s: scalar(2),
            },
            BitcoinPirCashuBatIssuanceResponseItemV1 {
                blinded_message: point(71),
                blinded_signature: point(73),
                dleq_e: scalar(3),
                dleq_s: scalar(4),
            },
        ],
    };
    BatV2ClaimWrite {
        exact_claim_envelope: envelope.encode().expect("encode BAT V2 claim envelope"),
        exact_claim_response: response.encode().expect("encode BAT V2 issuance response"),
        exact_signed_quote_response: bat_v2_signed_quote(
            quote_id_byte,
            quote_request_digest,
            invoice_suffix,
            Bolt11QuoteStatusV1::CredentialClaimed,
            3,
            400,
        ),
        now_unix: 400,
    }
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

fn accept_bat_v2_claim_crypto(_input: BatV2ClaimCryptographicVerificationInputV2<'_>) -> bool {
    true
}

fn reject_bat_v2_claim_crypto(_input: BatV2ClaimCryptographicVerificationInputV2<'_>) -> bool {
    false
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
    let inventory = store.operational_inventory().unwrap();
    assert_eq!(inventory.observed_commit_seq, 0);
    assert_eq!(inventory.quote_rows, 0);
    assert_eq!(inventory.claim_rows, 0);
    assert_eq!(inventory.retained_policy_rows, 0);
    assert_eq!(inventory.bat_v2_class_rows, 0);
    assert_eq!(inventory.bat_v2_class_head_rows, 0);
    assert_eq!(inventory.bat_v2_class_member_rows, 0);
    assert_eq!(inventory.redemption_rows, 0);
    assert_eq!(inventory.payout_rows, 0);
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
             UNION ALL SELECT name FROM pragma_table_info('settlement_key_lineages') \
             UNION ALL SELECT name FROM pragma_table_info('provider_registration_history')",
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
fn provider_registration_rotation_retains_digest_addressed_history() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let provider_id = [0x31; 32];
    let account_id = [0x33; 32];
    let payout_target_id = [0x34; 32];
    let first_key = SigningKey::from_bytes(&[0x22; 32]);
    let second_key = SigningKey::from_bytes(&[0x23; 32]);
    let first_registration = ProviderSettlementRegistrationWriteV1 {
        registration_epoch: 1,
        provider_id,
        settlement_account_id: account_id,
        provider_request_verifying_key: first_key.verifying_key().to_bytes(),
        payout_target_id,
        not_before: 1_000,
        not_after: 5_000,
    };
    let first = store
        .register_provider_settlement(&first_registration)
        .expect("register first provider key");
    assert_eq!(first.disposition, WriteDisposition::Committed);
    assert_eq!(first.commit.commit_seq, 1);
    assert!(
        store
            .historical_provider_settlement_registration(
                &provider_id,
                &first.value.registration_digest,
            )
            .expect("read first registration history")
            == Some(first.value.clone())
    );

    let replay = store
        .register_provider_settlement(&first_registration)
        .expect("replay first provider key");
    assert_eq!(replay.disposition, WriteDisposition::ExactReplay);
    assert_eq!(store.identity().expect("identity").commit_seq, 1);

    let second_registration = ProviderSettlementRegistrationWriteV1 {
        registration_epoch: 2,
        provider_id,
        settlement_account_id: account_id,
        provider_request_verifying_key: second_key.verifying_key().to_bytes(),
        payout_target_id,
        not_before: 1_500,
        not_after: 7_000,
    };
    let second = store
        .register_provider_settlement(&second_registration)
        .expect("rotate provider key");
    assert_eq!(second.disposition, WriteDisposition::Committed);
    assert_eq!(second.commit.commit_seq, 2);
    assert!(
        store
            .provider_settlement_registration(&provider_id)
            .expect("read current registration")
            == Some(second.value.clone())
    );
    assert!(
        store
            .historical_provider_settlement_registration(
                &provider_id,
                &first.value.registration_digest,
            )
            .expect("read retained first registration")
            == Some(first.value.clone())
    );
    assert!(
        store
            .historical_provider_settlement_registration(
                &provider_id,
                &second.value.registration_digest,
            )
            .expect("read retained current registration")
            == Some(second.value.clone())
    );
    assert!(store
        .historical_provider_settlement_registration(&[0x41; 32], &first.value.registration_digest)
        .expect("wrong provider history lookup")
        .is_none());
    assert!(store
        .historical_provider_settlement_registration(&provider_id, &[0x42; 32])
        .expect("wrong digest history lookup")
        .is_none());

    let mut rollback = first_registration.clone();
    rollback.registration_epoch = 1;
    rollback.provider_request_verifying_key = second_key.verifying_key().to_bytes();
    assert!(matches!(
        store.register_provider_settlement(&rollback),
        Err(StoreError::ProviderRegistrationRollback)
    ));
    let mut account_fork = second_registration.clone();
    account_fork.registration_epoch = 3;
    account_fork.settlement_account_id = [0x43; 32];
    assert!(matches!(
        store.register_provider_settlement(&account_fork),
        Err(StoreError::ProviderRegistrationFork)
    ));
    let mut target_fork = second_registration;
    target_fork.registration_epoch = 3;
    target_fork.payout_target_id = [0x44; 32];
    assert!(matches!(
        store.register_provider_settlement(&target_fork),
        Err(StoreError::ProviderRegistrationFork)
    ));
    assert_eq!(store.identity().expect("identity").commit_seq, 2);

    drop(store);
    let reopened = open_store(&test_path).expect("reopen issuer store");
    assert!(
        reopened
            .historical_provider_settlement_registration(
                &provider_id,
                &first.value.registration_digest,
            )
            .expect("read history after restart")
            == Some(first.value)
    );
}

#[test]
fn provider_registration_history_digest_corruption_fails_closed() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let provider_id = [0x31; 32];
    let registration = store
        .register_provider_settlement(&ProviderSettlementRegistrationWriteV1 {
            registration_epoch: 1,
            provider_id,
            settlement_account_id: [0x33; 32],
            provider_request_verifying_key: SigningKey::from_bytes(&[0x22; 32])
                .verifying_key()
                .to_bytes(),
            payout_target_id: [0x34; 32],
            not_before: 1_000,
            not_after: 5_000,
        })
        .expect("register provider");
    let rotated = store
        .register_provider_settlement(&ProviderSettlementRegistrationWriteV1 {
            registration_epoch: 2,
            provider_id,
            settlement_account_id: [0x33; 32],
            provider_request_verifying_key: SigningKey::from_bytes(&[0x23; 32])
                .verifying_key()
                .to_bytes(),
            payout_target_id: [0x34; 32],
            not_before: 1_500,
            not_after: 7_000,
        })
        .expect("rotate provider");
    assert_eq!(rotated.disposition, WriteDisposition::Committed);
    let connection = Connection::open(&test_path.database).expect("open database");
    connection
        .execute(
            "UPDATE provider_registration_history SET provider_request_verifying_key = ?1 \
             WHERE registration_digest = ?2",
            rusqlite::params![
                SigningKey::from_bytes(&[0x24; 32])
                    .verifying_key()
                    .to_bytes()
                    .as_slice(),
                registration.value.registration_digest.as_slice(),
            ],
        )
        .expect("tamper retained registration");
    drop(connection);
    assert!(matches!(
        store.historical_provider_settlement_registration(
            &provider_id,
            &registration.value.registration_digest,
        ),
        Err(StoreError::SchemaMismatch(_))
    ));
    assert!(store
        .provider_settlement_registration(&provider_id)
        .expect("current registration remains readable")
        .is_some());
    drop(store);
    assert!(matches!(
        open_store(&test_path),
        Err(StoreError::SchemaMismatch(_))
    ));
}

#[test]
fn current_provider_registration_must_match_its_history_commit() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let provider_id = [0x31; 32];
    let account_id = [0x33; 32];
    let payout_target_id = [0x34; 32];
    for (registration_epoch, seed) in [(1, 0x22), (2, 0x23)] {
        let write = store
            .register_provider_settlement(&ProviderSettlementRegistrationWriteV1 {
                registration_epoch,
                provider_id,
                settlement_account_id: account_id,
                provider_request_verifying_key: SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .to_bytes(),
                payout_target_id,
                not_before: 1_000 + registration_epoch,
                not_after: 5_000 + registration_epoch,
            })
            .expect("register provider epoch");
        assert_eq!(write.disposition, WriteDisposition::Committed);
    }
    let connection = Connection::open(&test_path.database).expect("open database");
    connection
        .execute(
            "UPDATE provider_registration_history SET commit_seq = 1 \
             WHERE provider_id = ?1 AND registration_epoch = 2",
            rusqlite::params![provider_id.as_slice()],
        )
        .expect("tamper current history commit marker");
    drop(connection);
    drop(store);
    assert!(matches!(
        open_store(&test_path),
        Err(StoreError::SchemaMismatch(_))
    ));
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
fn serve_mode_rejects_missing_corrupt_wrong_identity_network_schema_and_symlink() {
    let missing = TestPath::new();
    assert!(matches!(
        IssuerStore::open_existing(
            &missing.database,
            issuer_id(),
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
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
        ),
        Err(StoreError::IssuerMismatch)
    ));
    assert!(matches!(
        IssuerStore::open_existing(
            &wrong.database,
            issuer_id(),
            LightningNetworkV1::Bitcoin,
            StoreOptions::default(),
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
            ),
            Err(StoreError::NotRegularDatabase(_))
        ));

        let hardlink = target._directory.path().join("issuer-hardlink.sqlite3");
        std::fs::hard_link(&target.database, &hardlink).unwrap();
        assert!(matches!(
            IssuerStore::open_existing(
                &hardlink,
                issuer_id(),
                LightningNetworkV1::Regtest,
                StoreOptions::default(),
            ),
            Err(StoreError::NotRegularDatabase(_))
        ));
        assert!(matches!(
            IssuerStore::open_existing(
                &target.database,
                issuer_id(),
                LightningNetworkV1::Regtest,
                StoreOptions::default(),
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
fn bat_v2_acquisition_reservation_is_current_head_only_but_old_exact_replay_survives() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let class_id = [0x70; 32];
    let first_members = register_bat_v2_members(&store, class_id, 1);
    let first_class = bat_v2_class(class_id, 1, 70, bat_v2_terms(), first_members);
    let _ = store
        .register_bat_acceptance_class_v2(&first_class, 200)
        .unwrap();
    let live_head_only = store.bat_v2_credential_material_requirements(200).unwrap();
    assert_eq!(live_head_only.len(), 1);
    assert_eq!(live_head_only[0].class_key_epoch, 1);
    assert_eq!(live_head_only[0].raw_public_key, point(70));
    let first_delegation = delegation(1, 0x22);
    let (first_reservation, _) = bat_v2_reservation(0x70, 0x71, &first_class, &first_delegation);
    let committed = store.reserve_bat_v2_quote(&first_reservation).unwrap();
    assert_eq!(committed.disposition, WriteDisposition::Committed);
    assert_eq!(
        store
            .reserve_bat_v2_quote(&first_reservation)
            .unwrap()
            .disposition,
        WriteDisposition::ExactReplay
    );
    assert!(matches!(
        store.quote(&first_reservation.quote_id),
        Err(StoreError::QuoteProtocolMismatch)
    ));

    let requirements = store.bat_v2_credential_material_requirements(400).unwrap();
    assert_eq!(requirements.len(), 1);
    assert_eq!(requirements[0].class_id, class_id);
    assert_eq!(requirements[0].class_key_epoch, 1);
    assert_eq!(
        requirements[0].raw_public_key,
        first_class.bat_verification_key
    );
    assert_eq!(requirements[0].bat_key_id, first_class.bat_key_id());

    let second_members = register_bat_v2_members(&store, class_id, 2);
    let second_class = bat_v2_class(class_id, 2, 71, bat_v2_terms(), second_members);
    let _ = store
        .register_bat_acceptance_class_v2(&second_class, 200)
        .unwrap();
    let rotated_requirements = store.bat_v2_credential_material_requirements(400).unwrap();
    assert_eq!(rotated_requirements.len(), 2);
    assert_eq!(rotated_requirements[0].class_key_epoch, 1);
    assert_eq!(rotated_requirements[1].class_key_epoch, 2);
    assert_eq!(
        store
            .reserve_bat_v2_quote(&first_reservation)
            .unwrap()
            .disposition,
        WriteDisposition::ExactReplay,
        "an already durable historical quote must recover after class rotation"
    );
    let (fresh_old_epoch, _) = bat_v2_reservation(0x72, 0x73, &first_class, &first_delegation);
    assert!(matches!(
        store.reserve_bat_v2_quote(&fresh_old_epoch),
        Err(StoreError::BatV2ClassMemberMismatch)
    ));

    let conflicting_v1 = reservation(0x73, 0x71, &first_delegation);
    assert!(matches!(
        store.reserve_quote(&conflicting_v1),
        Err(StoreError::QuoteProtocolMismatch)
    ));
    let v1_first = reservation(0x74, 0x75, &first_delegation);
    let _ = store.reserve_quote(&v1_first).unwrap();
    let (conflicting_v2, _) = bat_v2_reservation(0x75, 0x75, &second_class, &first_delegation);
    assert!(matches!(
        store.reserve_bat_v2_quote(&conflicting_v2),
        Err(StoreError::QuoteProtocolMismatch)
    ));
    drop(store);

    let reopened = open_store(&test_path).unwrap();
    let mut historical_recovery = first_reservation.clone();
    historical_recovery.now_unix = 2_000;
    assert_eq!(
        reopened
            .reserve_bat_v2_quote(&historical_recovery)
            .unwrap()
            .disposition,
        WriteDisposition::ExactReplay
    );
    assert_eq!(
        reopened
            .bat_v2_quote_by_creation_idempotency_key(&[0x71; 32])
            .unwrap()
            .unwrap()
            .quote_id,
        first_reservation.quote_id
    );
    let current_only = reopened
        .bat_v2_credential_material_requirements(531)
        .unwrap();
    assert_eq!(current_only.len(), 1);
    assert_eq!(current_only[0].class_key_epoch, 2);
    assert_eq!(current_only[0].raw_public_key, point(71));
    assert!(reopened
        .bat_v2_credential_material_requirements(1_001)
        .unwrap()
        .is_empty());
}

#[test]
fn bat_v2_acquisition_claim_status_and_restart_are_protocol_isolated() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let class_id = [0x76; 32];
    let members = register_bat_v2_members(&store, class_id, 1);
    let mixed_v1_member = members[0].clone();
    let class = bat_v2_class(class_id, 1, 76, bat_v2_terms(), members);
    let _ = store.register_bat_acceptance_class_v2(&class, 200).unwrap();
    let (reservation, intent) = bat_v2_reservation(0x76, 0x77, &class, &delegation(1, 0x22));
    let intent_digest = intent.request_digest().unwrap();
    let _ = store.reserve_bat_v2_quote(&reservation).unwrap();
    let _ = store
        .finalize_bat_v2_quote(&bat_v2_finalization(0x76, 0x78, intent_digest))
        .unwrap();

    let mut mixed_v1 = reservation_with_receipt_key(0x79, 0x80, &delegation(1, 0x22), 0x25);
    let mut mixed_v1_intent = Bolt11QuoteIntentV1::decode(&mixed_v1.exact_intent).unwrap();
    mixed_v1_intent.provider_id = mixed_v1_member.provider_id;
    mixed_v1_intent.policy_digest = mixed_v1_member.policy_digest;
    mixed_v1.intent_digest = mixed_v1_intent.request_digest().unwrap();
    mixed_v1.exact_intent = mixed_v1_intent.encode().unwrap();
    let _ = store.reserve_quote(&mixed_v1).unwrap();
    drop(store);

    let store = open_store(&test_path).unwrap();
    let v1_requirements = store
        .service_policies_requiring_credential_material(320)
        .expect("mixed V1 plus open BAT V2 readiness must decode only V1 intents");
    assert!(v1_requirements.iter().any(|record| {
        record.provider_id == mixed_v1_member.provider_id
            && record.policy_digest == mixed_v1_member.policy_digest
    }));
    assert_eq!(
        store
            .quote_delegation_digests_requiring_signing_material(320)
            .expect("mixed V1 plus open BAT V2 signer readiness"),
        vec![delegation(1, 0x22).delegation_digest().unwrap()]
    );

    let status = status_request(0x76, intent_digest, 320, 0x79);
    let authenticated = store
        .consume_bat_v2_quote_status_request(&status, 320, &accept_status_signature)
        .unwrap();
    assert_eq!(authenticated.value.state, QuoteState::InvoiceOpen);
    assert!(matches!(
        store.consume_bat_v2_quote_status_request(&status, 320, &accept_status_signature),
        Err(StoreError::StatusNonceReplay)
    ));
    assert!(matches!(
        store.consume_quote_status_request(&status, 320, &accept_status_signature),
        Err(StoreError::QuoteProtocolMismatch)
    ));

    let _ = store
        .record_bat_v2_settlement(&bat_v2_settlement(0x76, intent_digest, 0x78))
        .unwrap();
    let v2_claim = bat_v2_claim_write(0x76, &intent, 0x7a, 0x78);
    let committed = store
        .record_bat_v2_claim(&v2_claim, &accept_bat_v2_claim_crypto)
        .unwrap();
    assert_eq!(committed.disposition, WriteDisposition::Committed);
    assert!(committed.value.receipt_serials.is_empty());
    assert!(matches!(
        store.claim(&reservation.quote_id),
        Err(StoreError::QuoteProtocolMismatch)
    ));

    let mut replay_after_deadline = v2_claim.clone();
    replay_after_deadline.now_unix = 999;
    let replay = store
        .record_bat_v2_claim(&replay_after_deadline, &reject_bat_v2_claim_crypto)
        .unwrap();
    assert_eq!(replay.disposition, WriteDisposition::ExactReplay);
    assert!(replay.value == committed.value);

    let connection = Connection::open(&test_path.database).unwrap();
    let receipt_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM receipt_serials r JOIN quotes q ON q.quote_id = r.quote_id \
             WHERE q.quote_protocol = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(receipt_rows, 0);
    drop(connection);
    drop(store);

    let reopened = open_store(&test_path).unwrap();
    assert!(
        reopened
            .bat_v2_claim_by_idempotency_key(&[0x7a; 32])
            .unwrap()
            .unwrap()
            == committed.value
    );
    let second_members = register_bat_v2_members(&reopened, class_id, 2);
    let second_class = bat_v2_class(class_id, 2, 77, bat_v2_terms(), second_members);
    let _ = reopened
        .register_bat_acceptance_class_v2(&second_class, 400)
        .unwrap();
    let issued_old_epoch_remains_pinned = reopened
        .bat_v2_credential_material_requirements(400)
        .unwrap();
    assert_eq!(issued_old_epoch_remains_pinned.len(), 2);
    assert_eq!(issued_old_epoch_remains_pinned[0].class_key_epoch, 1);
    assert_eq!(issued_old_epoch_remains_pinned[0].raw_public_key, point(76));
    assert_eq!(issued_old_epoch_remains_pinned[1].class_key_epoch, 2);
    assert_eq!(issued_old_epoch_remains_pinned[1].raw_public_key, point(77));
    let at_redemption_deadline = reopened
        .bat_v2_credential_material_requirements(1_480)
        .unwrap();
    assert_eq!(at_redemption_deadline.len(), 1);
    assert_eq!(at_redemption_deadline[0].class_key_epoch, 1);
    assert_eq!(at_redemption_deadline[0].raw_public_key, point(76));
    assert!(reopened
        .bat_v2_credential_material_requirements(1_481)
        .unwrap()
        .is_empty());

    let v1 = reserve_finalize_settle(&reopened, 0x7b, 0x7c, 0x7d);
    let v1_claim = claim(0x7b, v1.intent_digest, 0x7e, 0x7d, 0x7f, 0x25, 3);
    let _ = reopened
        .record_claim(&v1_claim, &accept_claim_crypto, None)
        .unwrap();
    assert!(matches!(
        reopened.bat_v2_claim(&v1.quote_id),
        Err(StoreError::QuoteProtocolMismatch)
    ));
}

#[test]
fn bat_v2_registry_accepts_two_provider_epochs_and_survives_restart() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let class_id = [0x42; 32];
    let first_members = register_bat_v2_members(&store, class_id, 1);
    let first = bat_v2_class(class_id, 1, 40, bat_v2_terms(), first_members);
    let installed = store.register_bat_acceptance_class_v2(&first, 200).unwrap();
    assert_eq!(installed.disposition, WriteDisposition::Committed);
    assert_eq!(installed.value.members.len(), 2);
    assert_eq!(
        store
            .register_bat_acceptance_class_v2(&first, 200)
            .unwrap()
            .disposition,
        WriteDisposition::ExactReplay
    );

    let second_members = register_bat_v2_members(&store, class_id, 2);
    let second = bat_v2_class(class_id, 2, 41, bat_v2_terms(), second_members);
    let _ = store
        .register_bat_acceptance_class_v2(&second, 200)
        .unwrap();
    assert!(matches!(
        store.register_bat_acceptance_class_v2(&first, 200),
        Err(StoreError::BatV2ClassRollback)
    ));
    assert_eq!(
        store
            .current_bat_acceptance_class_v2(&class_id)
            .unwrap()
            .unwrap()
            .key_epoch,
        2
    );
    assert_eq!(
        store
            .bat_acceptance_class_v2(&class_id, 1)
            .unwrap()
            .unwrap()
            .exact_artifact,
        first.encode().unwrap()
    );
    let inventory = store.operational_inventory().unwrap();
    assert_eq!(inventory.bat_v2_class_rows, 2);
    assert_eq!(inventory.bat_v2_class_head_rows, 1);
    assert_eq!(inventory.bat_v2_class_member_rows, 4);
    drop(store);

    let reopened = open_store(&test_path).unwrap();
    assert_eq!(
        reopened
            .current_bat_acceptance_class_v2(&class_id)
            .unwrap()
            .unwrap()
            .exact_artifact,
        second.encode().unwrap()
    );
    assert!(reopened
        .bat_acceptance_class_v2(&class_id, 1)
        .unwrap()
        .is_some());
}

#[test]
fn bat_v2_registry_rejects_member_terms_epoch_and_cross_class_conflicts() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let class_id = [0x43; 32];
    let members = register_bat_v2_members(&store, class_id, 1);

    let mut changed_terms = bat_v2_terms();
    changed_terms.price_msat += 1;
    let terms_mismatch = bat_v2_class(class_id, 1, 50, changed_terms.clone(), members.clone());
    assert!(matches!(
        store.register_bat_acceptance_class_v2(&terms_mismatch, 200),
        Err(StoreError::BatV2ClassTermsConflict)
    ));

    let mut wrong_members = members.clone();
    wrong_members[0].offer_id += 1;
    let wrong_member = bat_v2_class(class_id, 1, 50, bat_v2_terms(), wrong_members);
    assert!(matches!(
        store.register_bat_acceptance_class_v2(&wrong_member, 200),
        Err(StoreError::BatV2ClassMemberMismatch)
    ));

    let late_not_before =
        bat_v2_class_with_validity(class_id, 1, 52, 101, 1_480, bat_v2_terms(), members.clone());
    assert!(matches!(
        store.register_bat_acceptance_class_v2(&late_not_before, 200),
        Err(StoreError::BatV2ClassMemberMismatch)
    ));
    let short_not_after =
        bat_v2_class_with_validity(class_id, 1, 53, 100, 1_479, bat_v2_terms(), members.clone());
    assert!(matches!(
        store.register_bat_acceptance_class_v2(&short_not_after, 200),
        Err(StoreError::BatV2ClassMemberMismatch)
    ));
    let long_not_after =
        bat_v2_class_with_validity(class_id, 1, 54, 100, 1_481, bat_v2_terms(), members.clone());
    assert!(matches!(
        store.register_bat_acceptance_class_v2(&long_not_after, 200),
        Err(StoreError::BatV2ClassMemberMismatch)
    ));

    let accepted = bat_v2_class(class_id, 1, 50, bat_v2_terms(), members.clone());
    let _ = store
        .register_bat_acceptance_class_v2(&accepted, 200)
        .unwrap();
    let same_epoch_fork = bat_v2_class(class_id, 1, 51, bat_v2_terms(), members.clone());
    assert!(matches!(
        store.register_bat_acceptance_class_v2(&same_epoch_fork, 200),
        Err(StoreError::BatV2ClassFork)
    ));
    let changed_terms_epoch = bat_v2_class(class_id, 2, 51, changed_terms, members.clone());
    assert!(matches!(
        store.register_bat_acceptance_class_v2(&changed_terms_epoch, 200),
        Err(StoreError::BatV2ClassTermsConflict)
    ));
    let reused_epoch_key = bat_v2_class(class_id, 2, 50, bat_v2_terms(), members);
    assert!(matches!(
        store.register_bat_acceptance_class_v2(&reused_epoch_key, 200),
        Err(StoreError::BatV2RawKeyConflict)
    ));

    let other_class_id = [0x44; 32];
    let other_members = register_bat_v2_members(&store, other_class_id, 2);
    let cross_class_reuse = bat_v2_class(other_class_id, 1, 50, bat_v2_terms(), other_members);
    assert!(matches!(
        store.register_bat_acceptance_class_v2(&cross_class_reuse, 200),
        Err(StoreError::BatV2RawKeyConflict)
    ));
}

fn bat_v2_legacy_lineage(raw_public_key: [u8; 33]) -> BatKeyLineageRegistration {
    let provider_id = [0xd1; 32];
    let scope_id = [0xd2; 32];
    BatKeyLineageRegistration {
        raw_public_key,
        provider_id,
        scope_id,
        offer_id: 9,
        entitlement_profile: 4,
        keyset_epoch: 3,
        credential_key_id: derive_bat_key_id_v1(&provider_id, &scope_id, 9, 4, 3, &raw_public_key),
    }
}

#[test]
fn bat_v2_registry_rejects_bidirectional_legacy_raw_key_reuse() {
    let legacy_first_path = TestPath::new();
    let legacy_first = create_store(&legacy_first_path);
    let class_id = [0x45; 32];
    let members = register_bat_v2_members(&legacy_first, class_id, 1);
    let artifact = bat_v2_class(class_id, 1, 60, bat_v2_terms(), members);
    let lineage = bat_v2_legacy_lineage(point(60));
    let _ = legacy_first.register_bat_key_lineage(&lineage).unwrap();
    assert!(matches!(
        legacy_first.register_bat_acceptance_class_v2(&artifact, 200),
        Err(StoreError::BatV2RawKeyConflict)
    ));

    let v2_first_path = TestPath::new();
    let v2_first = create_store(&v2_first_path);
    let class_id = [0x46; 32];
    let members = register_bat_v2_members(&v2_first, class_id, 1);
    let artifact = bat_v2_class(class_id, 1, 61, bat_v2_terms(), members);
    let _ = v2_first
        .register_bat_acceptance_class_v2(&artifact, 200)
        .unwrap();
    let lineage = bat_v2_legacy_lineage(point(61));
    assert!(matches!(
        v2_first.register_bat_key_lineage(&lineage),
        Err(StoreError::BatV2RawKeyConflict)
    ));
}

#[test]
fn bat_v2_clearing_reservation_schema_v9_rejects_implicit_v8_open() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    drop(store);
    let connection = Connection::open(&test_path.database).unwrap();
    connection.pragma_update(None, "user_version", 8).unwrap();
    drop(connection);
    assert!(matches!(
        open_store(&test_path),
        Err(StoreError::SchemaMismatch(_))
    ));
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
        ),
        Err(StoreError::SchemaMismatch(_))
    ));
}

#[test]
fn bat_v2_redemption_v1_registration_uses_neutral_binding_and_reopens() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let provider_id = [0x31; 32];
    let account_id = [0x32; 32];
    let _ = store
        .register_provider_settlement(&ProviderSettlementRegistrationWriteV1 {
            registration_epoch: 1,
            provider_id,
            settlement_account_id: account_id,
            provider_request_verifying_key: SigningKey::from_bytes(&[0x33; 32])
                .verifying_key()
                .to_bytes(),
            payout_target_id: [0x34; 32],
            not_before: 100,
            not_after: 2_000,
        })
        .expect("register V1 provider through neutral account binding");
    let inventory = store.operational_inventory().unwrap();
    assert_eq!(inventory.provider_account_binding_rows, 1);
    assert_eq!(inventory.bat_v2_accounting_authorization_rows, 0);
    assert_eq!(inventory.bat_v2_redemption_rows, 0);
    assert_eq!(
        store
            .provider_ledger_balance(&provider_id)
            .unwrap()
            .unwrap()
            .account_id,
        account_id
    );
    drop(store);

    let reopened = open_store(&test_path).expect("reopen v9 store with V1 registration");
    assert_eq!(
        reopened
            .provider_settlement_registration(&provider_id)
            .unwrap()
            .unwrap()
            .settlement_account_id,
        account_id
    );
    assert_eq!(
        reopened
            .operational_inventory()
            .unwrap()
            .provider_account_binding_rows,
        1
    );
}

#[test]
fn bat_v2_redemption_authorization_replay_epoch_fork_and_account_mismatch() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let (class, members) = install_bat_v2_redemption_class(&store, [0x81; 32], 1, 81, 1);
    let first = bat_v2_redemption_authority(&store, &class, &members[0].member, 0x82, 0x83, 1);
    drop(store);
    let store = open_store(&test_path).expect("reopen clearing reservation before exact replay");
    let replay = store
        .register_bat_v2_accounting_authorization(
            &first.authorization,
            &first.approval,
            &first.operator_key.verifying_key(),
            &first.settlement_key.verifying_key(),
            200,
        )
        .unwrap();
    assert_eq!(replay.disposition, WriteDisposition::ExactReplay);

    let fork = ProviderAccountingAuthorizationV2::sign(
        ProviderAccountingAuthorizationClaimsV2 {
            authorization_id: [0x84; 16],
            ..first.authorization.claims.clone()
        },
        &first.operator_key,
    )
    .unwrap();
    let fork_approval =
        IssuerAccountingApprovalV2::sign(&fork, 200, 2_000, &first.settlement_key).unwrap();
    assert!(matches!(
        store.register_bat_v2_accounting_authorization(
            &fork,
            &fork_approval,
            &first.operator_key.verifying_key(),
            &first.settlement_key.verifying_key(),
            200,
        ),
        Err(StoreError::BatV2ClearingAuthorizationFork)
    ));

    let second = make_bat_v2_redemption_authority(&class, &members[0].member, 0x82, 0x89, 2);
    let _ = store
        .reserve_bat_v2_clearing_epoch(BatV2ClearingEpochReservationV2 {
            provider_id: second.authorization.claims.provider_id,
            authorization_epoch: second.authorization.claims.authorization_epoch,
        })
        .unwrap();
    let _ = store
        .register_bat_v2_accounting_authorization(
            &second.authorization,
            &second.approval,
            &second.operator_key.verifying_key(),
            &second.settlement_key.verifying_key(),
            200,
        )
        .expect("append BAT V2 authorization epoch");
    assert_eq!(
        store
            .current_bat_v2_accounting_authorization(&members[0].member.provider_id)
            .unwrap()
            .unwrap()
            .authorization_epoch,
        2
    );

    let rollback = ProviderAccountingAuthorizationV2::sign(
        ProviderAccountingAuthorizationClaimsV2 {
            authorization_id: [0x86; 16],
            ..first.authorization.claims.clone()
        },
        &first.operator_key,
    )
    .unwrap();
    let rollback_approval =
        IssuerAccountingApprovalV2::sign(&rollback, 200, 2_000, &first.settlement_key).unwrap();
    assert!(matches!(
        store.register_bat_v2_accounting_authorization(
            &rollback,
            &rollback_approval,
            &first.operator_key.verifying_key(),
            &first.settlement_key.verifying_key(),
            200,
        ),
        Err(StoreError::BatV2ClearingAuthorizationRollback)
    ));

    let account_fork = make_bat_v2_redemption_authority(&class, &members[0].member, 0x88, 0x8c, 3);
    let _ = store
        .reserve_bat_v2_clearing_epoch(BatV2ClearingEpochReservationV2 {
            provider_id: account_fork.authorization.claims.provider_id,
            authorization_epoch: account_fork.authorization.claims.authorization_epoch,
        })
        .unwrap();
    let before_account_fork = store.identity().unwrap().commit_seq;
    assert!(matches!(
        store.register_bat_v2_accounting_authorization(
            &account_fork.authorization,
            &account_fork.approval,
            &account_fork.operator_key.verifying_key(),
            &account_fork.settlement_key.verifying_key(),
            200,
        ),
        Err(StoreError::ProviderAccountBindingConflict)
    ));
    assert_eq!(store.identity().unwrap().commit_seq, before_account_fork);
}

#[test]
fn bat_v2_redemption_same_proof_two_providers_has_one_global_winner_and_no_restart_grant() {
    let test_path = TestPath::new();
    let store = Arc::new(create_store(&test_path));
    let (class, members) = install_bat_v2_redemption_class(store.as_ref(), [0x91; 32], 1, 91, 1);
    let authorities = [
        bat_v2_redemption_authority(store.as_ref(), &class, &members[0].member, 0x92, 0x93, 1),
        bat_v2_redemption_authority(store.as_ref(), &class, &members[1].member, 0x94, 0x95, 1),
    ];
    let verified = [
        bat_v2_verified_redeem(&class, &members[0], &authorities[0], 0x96, 0x97, 400),
        bat_v2_verified_redeem(&class, &members[1], &authorities[1], 0x98, 0x97, 400),
    ];
    let barrier = Arc::new(Barrier::new(2));
    let workers = verified
        .into_iter()
        .zip(authorities.clone())
        .map(|(verified, authority)| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let mut committer = store.bat_v2_redeem_committer(400).unwrap();
                sign_and_commit_grantable_success_v2(
                    verified,
                    &authority.settlement_key,
                    &mut committer,
                )
                .expect("commit or classify globally spent BAT V2 proof")
            })
        })
        .collect::<Vec<_>>();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, BatV2RedeemCommitResultV2::FreshCommitted(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                BatV2RedeemCommitResultV2::TerminalInvalidOrSpent(_)
            ))
            .count(),
        1
    );
    assert_eq!(
        members
            .iter()
            .map(|member| {
                store
                    .provider_ledger_balance(&member.member.provider_id)
                    .unwrap()
                    .unwrap()
                    .available_value
            })
            .sum::<u64>(),
        7
    );
    assert_eq!(
        store
            .operational_inventory()
            .unwrap()
            .bat_v2_redemption_rows,
        1
    );
    let ledger_rows: i64 = Connection::open(&test_path.database)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM ledger_transactions WHERE kind = 7",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ledger_rows, 1);
    let redemption_columns: Vec<String> = Connection::open(&test_path.database)
        .unwrap()
        .prepare("SELECT name FROM pragma_table_info('bat_v2_redemptions')")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for forbidden in [
        "raw_proof",
        "proof",
        "secret_raw",
        "quote_id",
        "request_replay_image",
        "rejection_reason",
    ] {
        assert!(!redemption_columns.iter().any(|column| column == forbidden));
    }
    assert!(redemption_columns
        .iter()
        .any(|column| column == "exact_initial_success"));
    drop(store);

    let reopened = open_store(&test_path).expect("reopen committed BAT V2 redemption");
    let replay = bat_v2_verified_redeem(&class, &members[0], &authorities[0], 0x96, 0x97, 400);
    let mut committer = reopened.bat_v2_redeem_committer(400).unwrap();
    assert!(matches!(
        sign_and_commit_grantable_success_v2(
            replay,
            &authorities[0].settlement_key,
            &mut committer,
        )
        .unwrap(),
        BatV2RedeemCommitResultV2::TerminalInvalidOrSpent(_)
    ));
}

#[test]
fn bat_v2_redemption_bad_auth_account_and_member_are_zero_mutation_then_valid_succeeds() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let (class, members) = install_bat_v2_redemption_class(&store, [0xa1; 32], 1, 101, 1);
    let authority = bat_v2_redemption_authority(&store, &class, &members[0].member, 0xa2, 0xa3, 1);
    let baseline = store.identity().unwrap().commit_seq;

    let proof = BitcoinPirCashuBatProofV2::from_class(&class, [0xa4; 32], point(204)).unwrap();
    let (base_request, _) = pir_service_protocol::ProviderRedeemRequestV2::prepare(
        &authority.authorization,
        &members[0],
        &class,
        &proof,
        [0xa5; 32],
    )
    .unwrap()
    .into_parts();
    let classify = |request: pir_service_protocol::ProviderRedeemRequestV2,
                    signing_key: &SigningKey| {
        let request_auth = ProviderRedeemRequestAuthV2::sign(&request, signing_key).unwrap();
        precheck_bat_v2_redeem_v2(
            ProviderRedeemEnvelopeV2 {
                request,
                request_auth,
                credential: proof.clone(),
            },
            &authority.authorization,
            &authority.approval,
            &class,
            &members[0],
            ProviderAccountingExpectationV2 {
                provider_id: members[0].member.provider_id,
                issuer_id: issuer_id(),
                operator_verifying_key: &authority.operator_key.verifying_key(),
                issuer_settlement_verifying_key: &authority.settlement_key.verifying_key(),
                now_unix: 400,
                minimum_authorization_epoch: 1,
            },
        )
        .unwrap()
    };
    assert!(matches!(
        classify(base_request.clone(), &SigningKey::from_bytes(&[0xa6; 32])),
        BatV2RedeemPrecheckV2::RetrySafeNonConsuming(_)
    ));
    let mut wrong_account = base_request.clone();
    wrong_account.settlement_account_id = [0xa7; 32];
    assert!(matches!(
        classify(wrong_account, &authority.clearing_key),
        BatV2RedeemPrecheckV2::RetrySafeNonConsuming(_)
    ));
    let mut wrong_member = base_request;
    wrong_member.policy_digest = [0xa8; 32];
    assert!(matches!(
        classify(wrong_member, &authority.clearing_key),
        BatV2RedeemPrecheckV2::RetrySafeNonConsuming(_)
    ));
    assert_eq!(store.identity().unwrap().commit_seq, baseline);
    assert_eq!(
        store
            .operational_inventory()
            .unwrap()
            .bat_v2_redemption_rows,
        0
    );

    let verified = bat_v2_verified_redeem(&class, &members[0], &authority, 0xa9, 0xaa, 400);
    let mut committer = store.bat_v2_redeem_committer(400).unwrap();
    assert!(matches!(
        sign_and_commit_grantable_success_v2(verified, &authority.settlement_key, &mut committer,)
            .unwrap(),
        BatV2RedeemCommitResultV2::FreshCommitted(_)
    ));
    assert_eq!(store.identity().unwrap().commit_seq, baseline + 1);
}

#[test]
fn bat_v2_redemption_retained_member_works_until_exact_deadline_then_is_terminal() {
    let test_path = TestPath::new();
    let store = create_store(&test_path);
    let class_id = [0xb1; 32];
    let (first_class, first_members) = install_bat_v2_redemption_class(&store, class_id, 1, 111, 1);
    let authority = bat_v2_redemption_authority(
        &store,
        &first_class,
        &first_members[0].member,
        0xb2,
        0xb3,
        1,
    );
    let _ = install_bat_v2_redemption_class(&store, class_id, 2, 112, 2);

    let within = bat_v2_verified_redeem(
        &first_class,
        &first_members[0],
        &authority,
        0xb4,
        0xb5,
        1_480,
    );
    let mut committer = store.bat_v2_redeem_committer(1_480).unwrap();
    assert!(matches!(
        sign_and_commit_grantable_success_v2(within, &authority.settlement_key, &mut committer,)
            .unwrap(),
        BatV2RedeemCommitResultV2::FreshCommitted(_)
    ));
    let before_expired = store.identity().unwrap().commit_seq;
    assert!(matches!(
        bat_v2_redemption_precheck(
            &first_class,
            &first_members[0],
            &authority,
            0xb6,
            0xb7,
            1_481,
        ),
        BatV2RedeemPrecheckV2::TerminalInvalidOrSpent(_)
    ));
    assert_eq!(store.identity().unwrap().commit_seq, before_expired);
}
