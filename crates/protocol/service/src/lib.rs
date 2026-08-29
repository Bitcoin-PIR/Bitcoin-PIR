//! Canonical BitcoinPIR service-policy and authorization protocol.
//!
//! This crate is intentionally pure: it owns identifiers, signed policy
//! encoding, authorization messages, opcodes, hashing, and strict decoding. It
//! does not verify payment proofs, perform I/O, or maintain spent state.

#[path = "legacy/auth.rs"]
mod auth;
#[path = "legacy/auth_verify.rs"]
mod auth_verify;
#[path = "legacy/bat_v2.rs"]
mod bat_v2;
#[path = "legacy/bat_v2_acquisition.rs"]
mod bat_v2_acquisition;
#[path = "legacy/bat_v2_redemption.rs"]
mod bat_v2_redemption;
#[path = "legacy/binding.rs"]
mod binding;
#[path = "legacy/cashu_manifest.rs"]
mod cashu_manifest;
#[path = "legacy/challenge.rs"]
mod challenge;
#[path = "legacy/clearing.rs"]
mod clearing;
mod codec;
#[path = "legacy/directory.rs"]
mod directory;
mod error;
#[path = "legacy/grant_claim.rs"]
mod grant_claim;
#[path = "legacy/issuance.rs"]
mod issuance;
mod operation;
#[path = "legacy/policy.rs"]
mod policy;
mod proof;
#[path = "legacy/quote.rs"]
mod quote;
#[path = "legacy/quote_wasm.rs"]
mod quote_wasm;
#[path = "legacy/receipt.rs"]
mod receipt;
mod scope;
#[path = "legacy/settlement.rs"]
mod settlement;
#[path = "legacy/settlement_http.rs"]
mod settlement_http;

pub use auth::{
    AuthBeginV1, AuthGrantedV1, AuthRejectCode, AuthRejectedV1, AuthResultV1, HarmonyHintSideV1,
    HintTransport, OperationStartV1, ServicePolicyRequestV1, ServicePolicyResponseV1,
    AUTH_FRAME_CLASS_V1, MAX_AUTH_KEY_ID_LEN, MAX_AUTH_PROOF_LEN, MAX_POLICY_WIRE_LEN,
    OPERATION_START_DIGEST_DOMAIN,
};
pub use auth_verify::{
    bind_auth_begin_v1, BoundAuthAttemptV1, TrustedCatalogResolutionV1, TrustedServiceCatalogV1,
};
pub use bat_v2::{
    bat_acceptance_member_from_retained_policy_v2, bat_acceptance_member_from_verified_policy_v2,
    derive_bat_acceptance_key_id_v2, validate_bat_acceptance_class_id_v2,
    verify_bat_acceptance_class_member_projection_v2, BatAcceptanceClassIdV2, BatAcceptanceClassV2,
    BatAcceptanceMemberV2, BatAcceptanceTermsV2, VerifiedBatAcceptanceMemberV2,
    BAT_ACCEPTANCE_CLASS_CODEC_MAGIC_V2, BAT_ACCEPTANCE_CLASS_DIGEST_DOMAIN_V2,
    BAT_ACCEPTANCE_CLASS_SIGNATURE_DOMAIN_V2, BAT_ACCEPTANCE_CLASS_WIRE_VERSION_V2,
    BAT_ACCEPTANCE_KEY_ID_DOMAIN_V2, BAT_ACCEPTANCE_TERMS_DIGEST_DOMAIN_V2,
    MAX_BAT_ACCEPTANCE_CLASS_LEN_V2, MAX_BAT_ACCEPTANCE_CLASS_MEMBERS_V2,
    MAX_BAT_ACCEPTANCE_TERMS_LEN_V2,
};
pub use bat_v2_acquisition::{
    BatV2IssuanceRequestV2, BatV2IssuanceResponseV2, Bolt11BatV2ClaimEnvelopeV2,
    Bolt11BatV2QuoteIntentV2, CheckedBatV2IssuanceResponseV2,
    PersistedBolt11BatV2QuoteExpectationV2, VerifiedBolt11BatV2QuoteIntentV2,
    VerifiedBolt11BatV2QuoteV2, BAT_V2_CLAIM_ENVELOPE_CODEC_MAGIC,
    BAT_V2_CLAIM_ENVELOPE_WIRE_VERSION, BAT_V2_ISSUANCE_REQUEST_CODEC_MAGIC,
    BAT_V2_ISSUANCE_REQUEST_DIGEST_DOMAIN, BAT_V2_ISSUANCE_REQUEST_WIRE_VERSION,
    BAT_V2_ISSUANCE_RESPONSE_CODEC_MAGIC, BAT_V2_ISSUANCE_RESPONSE_WIRE_VERSION,
    BAT_V2_QUOTE_INTENT_CODEC_MAGIC, BAT_V2_QUOTE_INTENT_DIGEST_DOMAIN,
    BAT_V2_QUOTE_INTENT_WIRE_VERSION, MAX_BAT_V2_CLAIM_ENVELOPE_LEN,
    MAX_BAT_V2_ISSUANCE_REQUEST_LEN, MAX_BAT_V2_ISSUANCE_RESPONSE_LEN, MAX_BAT_V2_QUOTE_INTENT_LEN,
};
pub use bat_v2_redemption::{
    bat_v2_redeem_ledger_transaction_id_v2, precheck_bat_v2_redeem_v2,
    sign_and_commit_grantable_success_v2, sign_retry_safe_non_consuming_v2,
    sign_terminal_if_attempt_committed_v2, sign_terminal_invalid_or_spent_v2,
    verify_bat_v2_credential_for_commit_v2, verify_grantable_success_for_inflight_attempt_v2,
    BatV2CredentialCheckV2, BatV2CredentialVerificationErrorV2, BatV2ProofVerificationInputV2,
    BatV2ProofVerifierV2, BatV2RedeemCommitErrorV2, BatV2RedeemCommitResultV2,
    BatV2RedeemCommitStoreV2, BatV2RedeemPrecheckV2, BitcoinPirCashuBatProofV2,
    FreshCommittedProviderRedeemV2, IssuerAccountingApprovalV2, PreparedProviderRedeemRequestV2,
    ProviderAccountingAuthorizationClaimsV2, ProviderAccountingAuthorizationV2,
    ProviderAccountingExpectationV2, ProviderAccountingRuleV2, ProviderInFlightRedeemAttemptV2,
    ProviderRedeemEnvelopeV2, ProviderRedeemOutcomeV2, ProviderRedeemRequestAuthV2,
    ProviderRedeemRequestV2, ProviderRedeemResponseV2, RetrySafeNonConsumingReasonV2,
    VerifiedBatV2RedeemCommitV2, VerifiedGrantableProviderRedeemSuccessV2,
    VerifiedProviderRedeemAuthorizationV2, VerifiedRetrySafeNonConsumingV2,
    VerifiedTerminalInvalidOrSpentV2, BAT_V2_CREDENTIAL_PRESENTATION_DIGEST_DOMAIN_V2,
    BAT_V2_ISSUER_ACCOUNTING_APPROVAL_CODEC_MAGIC_V2, BAT_V2_ISSUER_ACCOUNTING_APPROVAL_LEN_V2,
    BAT_V2_ISSUER_ACCOUNTING_APPROVAL_SIGNATURE_DOMAIN_V2, BAT_V2_PROOF_CODEC_MAGIC_V2,
    BAT_V2_PROOF_LEN_V2, BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_CODEC_MAGIC_V2,
    BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_DIGEST_DOMAIN_V2,
    BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_SIGNATURE_DOMAIN_V2,
    BAT_V2_PROVIDER_REDEEM_ENVELOPE_CODEC_MAGIC_V2, BAT_V2_PROVIDER_REDEEM_ENVELOPE_LEN_V2,
    BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_CODEC_MAGIC_V2, BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_LEN_V2,
    BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_SIGNATURE_DOMAIN_V2,
    BAT_V2_PROVIDER_REDEEM_REQUEST_CODEC_MAGIC_V2, BAT_V2_PROVIDER_REDEEM_REQUEST_DIGEST_DOMAIN_V2,
    BAT_V2_PROVIDER_REDEEM_REQUEST_LEN_V2, BAT_V2_PROVIDER_REDEEM_RESPONSE_CODEC_MAGIC_V2,
    BAT_V2_PROVIDER_REDEEM_RESPONSE_SIGNATURE_DOMAIN_V2,
    BAT_V2_REDEEM_LEDGER_TRANSACTION_ID_DOMAIN_V2, BAT_V2_REDEMPTION_WIRE_VERSION_V2,
    MAX_BAT_V2_ACCOUNTING_RULES_V2, MAX_BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_LEN_V2,
    MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2,
};
pub use binding::{
    derive_bat_key_id_v1, derive_issuer_id, CredentialKeyBindingClaimsV1,
    CredentialKeyBindingExpectationV1, CredentialKeyBindingV1, CredentialUnitV1, BAT_KEY_ID_DOMAIN,
    CREDENTIAL_BINDING_DIGEST_DOMAIN, CREDENTIAL_BINDING_SIGNATURE_DOMAIN,
    CREDENTIAL_PRESENTATION_CONTEXT_DOMAIN, CREDENTIAL_REQUEST_CONTEXT_DOMAIN, ISSUER_ID_DOMAIN,
    MAX_CREDENTIAL_BINDING_LEN, MAX_CREDENTIAL_KEY_ID_LEN, MAX_CREDENTIAL_VERIFICATION_KEY_LEN,
};
pub use cashu_manifest::{
    derive_cashu_keyset_id_v2, derive_cashu_mint_id, is_canonical_cashu_keyset_id_v2,
    validate_cashu_unit_v1, validate_leaf_spki_sha256_pins_v1, CashuDenominationKeyV1,
    CashuKeysetBindingV1, CashuRequiredNutsV1, StandardCashuMintExpectationV1,
    StandardCashuMintManifestV1, CASHU_KEYSET_ID_V2_LEN, CASHU_MINT_ID_DOMAIN,
    CASHU_MINT_MANIFEST_DIGEST_DOMAIN, MAX_CASHU_DENOMINATION_KEYS, MAX_CASHU_INPUT_KEYSETS,
    MAX_CASHU_KEYSET_ENCODING_LEN, MAX_CASHU_KEYSET_ID_LEN, MAX_CASHU_MINT_MANIFEST_LEN,
    MAX_LEAF_SPKI_SHA256_PINS_V1,
};
pub use challenge::{
    pow_solution_hash_v1, pow_solution_meets_difficulty_v1, PowChallengeRequestV1,
    PowChallengeResponseV1, PowChallengeStateV1, PowChallengeTransitionErrorV1, PowSolutionV1,
    MAX_POW_CHALLENGE_TTL_SECONDS_V1, MAX_POW_DIFFICULTY_BITS_V1, POW_CHALLENGE_FRAME_CLASS_V1,
    POW_SOLUTION_DOMAIN_V1,
};
pub use clearing::{
    credential_presentation_digest, issuer_settlement_key_id,
    verify_committed_clearing_request_auth_v1, verify_committed_redeem_replay_auth_v1,
    verify_new_redeem_request_for, BlindSettlementOutputV1, CommittedRedeemReplayExpectationV1,
    IssuerClearingApprovalV1, ProviderClearingAuthorizationClaimsV1,
    ProviderClearingAuthorizationV1, ProviderClearingExpectationV1, ProviderClearingRequestAuthV1,
    ProviderRedeemEnvelopeV1, ProviderRedeemRequestV1, SettlementDestinationV1, SettlementModesV1,
    SettlementRuleV1, SettlementUnitV1, CLEARING_AUTH_DIGEST_DOMAIN,
    CLEARING_AUTH_SIGNATURE_DOMAIN, CLEARING_REQUEST_SIGNATURE_DOMAIN,
    CREDENTIAL_PRESENTATION_DIGEST_DOMAIN, ISSUER_CLEARING_APPROVAL_SIGNATURE_DOMAIN,
    ISSUER_SETTLEMENT_KEY_ID_DOMAIN, MAX_PROVIDER_REDEEM_CREDENTIAL_LEN_V1,
    MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1, MAX_SETTLEMENT_DENOMINATIONS, MAX_SETTLEMENT_OUTPUTS,
    MAX_SETTLEMENT_RULES, PROVIDER_REDEEM_REQUEST_DIGEST_DOMAIN,
};
pub use directory::{
    is_canonical_public_wss_endpoint_v1, is_canonical_public_wss_origin_v1,
    DirectoryAssertionRollbackGuardV1, DirectoryEndpointV1, DirectoryOperatorAssertionV1,
    DirectoryTransportV1, VerifiedDirectoryOperatorAssertionV1,
    DIRECTORY_OPERATOR_ASSERTION_DIGEST_DOMAIN_V1,
    DIRECTORY_OPERATOR_ASSERTION_SIGNATURE_DOMAIN_V1, MAX_DIRECTORY_ASSERTION_LEN_V1,
    MAX_DIRECTORY_ASSERTION_VALIDITY_SECONDS_V1, MAX_DIRECTORY_ENDPOINTS_V1,
    MAX_DIRECTORY_ENDPOINT_LEN_V1, MAX_DIRECTORY_SERVER_ID_LEN_V1,
};
pub use error::ServiceProtocolError;
pub use grant_claim::{
    derive_shared_issuer_local_grant_namespace_v1, verify_shared_issuer_local_grant_claim_v1,
    SharedIssuerLocalGrantNamespaceV1, SharedIssuerProviderSecretV1,
    VerifiedSharedIssuerLocalGrantClaimV1, SHARED_ISSUER_LOCAL_GRANT_BINDING_DOMAIN_V1,
    SHARED_ISSUER_LOCAL_GRANT_CLAIM_KEY_DOMAIN_V1, SHARED_ISSUER_LOCAL_GRANT_KEY_ID_DOMAIN_V1,
    SHARED_ISSUER_LOCAL_GRANT_NAMESPACE_DOMAIN_V1, SHARED_ISSUER_LOCAL_GRANT_NAMESPACE_SCHEME_V1,
    SHARED_ISSUER_WIRE_IDEMPOTENCY_DOMAIN_V1,
};
pub use issuance::{
    ArcCredentialRequestV1, ArcCredentialResponseV1, ArcIssuanceCanonicalizerV1,
    BitcoinPirCashuBatIssuanceRequestItemV1, BitcoinPirCashuBatIssuanceResponseItemV1,
    Bolt11QuoteClaimEnvelopeV1, CheckedCredentialIssuanceResponseV1,
    CredentialIssuanceRequestItemsV1, CredentialIssuanceRequestV1,
    CredentialIssuanceResponseItemsV1, CredentialIssuanceResponseV1,
    PendingArcCredentialFinalizeV1, UnverifiedCashuBatDleqTupleV1, ARC_CREDENTIAL_REQUEST_LEN_V1,
    ARC_CREDENTIAL_RESPONSE_LEN_V1, CREDENTIAL_ISSUANCE_REQUEST_DIGEST_DOMAIN_V1,
    MAX_BOLT11_QUOTE_CLAIM_ENVELOPE_LEN_V1, MAX_CREDENTIAL_ISSUANCE_REQUEST_LEN_V1,
    MAX_CREDENTIAL_ISSUANCE_RESPONSE_LEN_V1, PAID_RECEIPT_WIRE_LEN_V1,
};
pub use policy::{
    is_canonical_service_https_endpoint_v1, is_canonical_service_https_origin_v1,
    policy_signing_key_id, AcquisitionMethod, AuthPaddingClassV1, CashuManifestEpochFloorV1,
    CredentialKeysetEpochFloorV1, DeploymentStatus, EntitlementLimitsV1, FreeModeV1,
    PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1, ServicePolicyEpochFloorsV1,
    ServicePolicyV1, ServiceScopePolicyV1, VerificationMode, VerifiedCurrentPolicyV1,
    VerifiedRetiredOfferV1, VerifiedServiceOfferV1, MAX_BITCOIN_MSAT_V1,
    MAX_CREDENTIALS_PER_ACQUISITION_V1, MAX_CREDENTIAL_PRESENTATIONS_V1, MAX_ENDPOINT_LEN,
    MAX_KEY_ID_LEN, MAX_OFFERS_PER_SCOPE, MAX_OFFER_ENCODING_LEN, MAX_POLICY_SCOPES,
    MAX_PRICE_UNIT_LEN, MAX_SERVICE_VALUE_V1, MAX_SIGNED_POLICY_LEN,
    MAX_TOTAL_PRESENTATIONS_PER_ACQUISITION_V1, POLICY_DIGEST_DOMAIN, POLICY_SIGNATURE_DOMAIN,
};
pub use proof::{
    arc_provider_global_spend_key_v1, bat_verification_key_fingerprint_v1,
    check_standard_cashu_spend_for_offer, free_anonymous_ticket_key_id,
    verify_free_anonymous_ticket_for_offer, ArcPresentationCanonicalizerV1, ArcPresentationV1,
    AuthorizationProofV1, BitcoinPirCashuBatProofV1, FreeAnonymousTicketExpectationV1,
    FreeAnonymousTicketV1, FreeAuthorizationProofV1, FreePowProofV1, StandardCashuProofV1,
    StandardCashuSpendCheckV1, StandardCashuSpendV1, ARC_CANONICAL_TAG_LEN_V1,
    ARC_PROVIDER_GLOBAL_SPEND_KEY_DOMAIN_V1, BAT_PROOF_LEN_V1, BAT_SPEND_DOMAIN,
    BAT_VERIFICATION_KEY_FINGERPRINT_DOMAIN_V1, FREE_ANONYMOUS_TICKET_KEY_ID_DOMAIN,
    FREE_ANONYMOUS_TICKET_SIGNATURE_DOMAIN, FREE_ANONYMOUS_TICKET_SPEND_DOMAIN,
    FREE_POW_PROOF_LEN_V1, MAX_ARC_PRESENTATION_LEN_V1, MAX_STANDARD_CASHU_PROOFS_V1,
    MAX_STANDARD_CASHU_SECRET_LEN_V1,
};
pub use quote::{
    bolt11_invoice_text_digest_v1, bolt11_quote_key_id_v1, Bolt11QuoteClaimV1,
    Bolt11QuoteHorizonsV1, Bolt11QuoteIntentV1, Bolt11QuoteKeyDelegationV1,
    Bolt11QuoteKeyRollbackGuardV1, Bolt11QuoteStatusRequestV1, Bolt11QuoteStatusV1, Bolt11QuoteV1,
    LightningNetworkV1, ParsedBolt11InvoiceV1, PersistedBolt11QuoteExpectationV1,
    UnverifiedBip340ClaimV1, UnverifiedBip340QuoteStatusRequestV1, VerifiedBolt11QuoteIntentV1,
    VerifiedBolt11QuoteV1, VerifiedPersistedBolt11QuoteV1, BOLT11_INVOICE_TEXT_DIGEST_DOMAIN,
    BOLT11_QUOTE_CLAIM_REQUEST_DIGEST_DOMAIN, BOLT11_QUOTE_CLAIM_SIGNATURE_DOMAIN,
    BOLT11_QUOTE_INTENT_DIGEST_DOMAIN, BOLT11_QUOTE_KEY_DELEGATION_DIGEST_DOMAIN_V1,
    BOLT11_QUOTE_KEY_DELEGATION_SIGNATURE_DOMAIN, BOLT11_QUOTE_KEY_ID_DOMAIN,
    BOLT11_QUOTE_SIGNATURE_DOMAIN, BOLT11_QUOTE_STATUS_REQUEST_SIGNATURE_DOMAIN_V1,
    MAX_BOLT11_CLAIM_WINDOW_SECONDS_V1, MAX_BOLT11_CREDENTIAL_VALIDITY_SECONDS_V1,
    MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1, MAX_BOLT11_INVOICE_LEN, MAX_BOLT11_QUOTE_CLAIM_LEN,
    MAX_BOLT11_QUOTE_INTENT_LEN, MAX_BOLT11_QUOTE_KEY_DELEGATION_LEN, MAX_BOLT11_QUOTE_LEN,
    MAX_BOLT11_QUOTE_STATUS_REQUEST_AGE_SECONDS_V1, MAX_BOLT11_QUOTE_STATUS_REQUEST_LEN,
};
pub use receipt::{
    paid_receipt_key_id, verify_paid_receipt_for_offer, PaidReceiptBindingV1, PaidReceiptV1,
    PAID_RECEIPT_KEY_ID_DOMAIN, PAID_RECEIPT_SIGNATURE_DOMAIN, PAID_RECEIPT_SPEND_DOMAIN,
};
pub use scope::{
    derive_provider_id, AuthScheme, BackendId, DatasetBindingV1, ProviderId, ScopeId,
    ServiceScopeV1, WorkloadId, PROVIDER_ID_DOMAIN, SCOPE_ID_DOMAIN,
};
pub use settlement::{
    settlement_denomination_key_fingerprint_v1, settlement_note_presentation_digest,
    settlement_note_spend_key_v1, verify_committed_payout_status_replay_auth_v1,
    verify_ledger_redeem_response_for_exact_request_v1, verify_new_balance_request_for,
    verify_new_balance_response_for, verify_new_payout_intent_request_for,
    verify_new_payout_intent_response_for, verify_new_payout_request_for,
    verify_new_payout_response_for, verify_new_payout_status_request_for,
    verify_new_payout_status_response_for, verify_new_redeem_response_for,
    verify_new_settlement_deposit_request_for, verify_new_settlement_deposit_response_for,
    verify_payout_initial_response_for_exact_request, verify_payout_status_successor_for_store_v1,
    verify_persisted_payout_snapshot_for_store_v1,
    verify_persisted_payout_snapshot_from_store_record_v1,
    verify_redeem_response_for_exact_request, BlindSettlementSignatureV1,
    CashuDleqVerificationInputV1, CashuDleqVerifierV1, CashuSettlementNoteVerificationInputV1,
    CashuSettlementNoteVerifierV1, IssuerBalanceResponseV1, IssuerPayoutIntentResponseV1,
    IssuerPayoutResponseV1, IssuerPayoutStatusResponseV1, IssuerSettlementKeyringExpectationV1,
    PayoutCommitErrorV1, PayoutExecutionCommitStoreV1, PayoutExecutionContextV1, PayoutStateV1,
    PayoutStatusCasExpectationV1, PayoutStatusCompareAndSwapStoreV1, PayoutStatusContextV1,
    PayoutTargetIdV1, ProviderBalanceRequestV1, ProviderPayoutIntentRequestV1,
    ProviderPayoutRequestV1, ProviderPayoutStatusRequestV1, ProviderRedeemResponseV1,
    ProviderSettlementDepositRequestV1, ProviderSettlementDepositResponseV1,
    ProviderSettlementRegistrationExpectationV1, ProviderSettlementRequestAuthV1,
    RedeemResponseCryptoExpectationV1, RedeemSettlementResultV1,
    RetainedSettlementKeysetExpectationV1, RetainedSettlementKeysetV1, SettlementNoteV1,
    VerifiedBlindSettlementPromiseV1, VerifiedPayoutExecutionV1, VerifiedPayoutSnapshotV1,
    VerifiedProviderRedeemResponseV1, VerifiedRedeemSettlementResultV1,
    VerifiedSettlementDepositV1, VerifiedSettlementNoteV1,
    ISSUER_BALANCE_RESPONSE_SIGNATURE_DOMAIN_V1, ISSUER_PAYOUT_INTENT_RESPONSE_SIGNATURE_DOMAIN_V1,
    ISSUER_PAYOUT_RESPONSE_SIGNATURE_DOMAIN_V1, ISSUER_PAYOUT_STATUS_RESPONSE_SIGNATURE_DOMAIN_V1,
    MAX_SETTLEMENT_NOTES_V1, MAX_SETTLEMENT_SECRET_LEN_V1, MAX_SETTLEMENT_WITNESS_LEN_V1,
    PAYOUT_INTENT_DIGEST_DOMAIN_V1, PROVIDER_BALANCE_REQUEST_DIGEST_DOMAIN_V1,
    PROVIDER_PAYOUT_INTENT_REQUEST_DIGEST_DOMAIN_V1, PROVIDER_PAYOUT_REQUEST_DIGEST_DOMAIN_V1,
    PROVIDER_PAYOUT_STATUS_REQUEST_DIGEST_DOMAIN_V1, PROVIDER_REDEEM_RESPONSE_SIGNATURE_DOMAIN_V1,
    PROVIDER_SETTLEMENT_DEPOSIT_REQUEST_DIGEST_DOMAIN_V1,
    PROVIDER_SETTLEMENT_DEPOSIT_RESPONSE_SIGNATURE_DOMAIN_V1,
    PROVIDER_SETTLEMENT_REQUEST_SIGNATURE_DOMAIN_V1,
    SETTLEMENT_DENOMINATION_KEY_FINGERPRINT_DOMAIN_V1,
    SETTLEMENT_NOTE_PRESENTATION_DIGEST_DOMAIN_V1, SETTLEMENT_NOTE_SPEND_KEY_DOMAIN_V1,
};
pub use settlement_http::{
    ProviderBalanceEnvelopeV1, ProviderPayoutEnvelopeV1, ProviderPayoutIntentEnvelopeV1,
    ProviderPayoutStatusEnvelopeV1, ProviderSettlementDepositEnvelopeV1,
    MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1, MAX_SETTLEMENT_HTTP_ENVELOPE_LEN_V1,
};

/// Current version of all V1 structures in this crate.
pub const SERVICE_PROTOCOL_VERSION: u8 = 1;

/// Length of provider, scope, and policy digests.
pub const HASH_LEN: usize = 32;
