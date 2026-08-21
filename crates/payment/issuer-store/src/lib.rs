//! Fail-closed issuer persistence for BitcoinPIR paid capabilities.
//!
//! This crate owns durable quote/claim recovery and cryptographic key-lineage
//! registries. It deliberately has no HTTP, Lightning RPC, wallet, balance,
//! payout, PIR query, or provider-server networking code.

#![forbid(unsafe_code)]

mod bat_v2_clearing_ops;
mod bat_v2_ops;
mod clearing_ops;
mod db;
mod error;
mod payout_ops;
mod policy_ops;
mod quote_ops;
mod registry_ops;
mod rollback;
mod schema;
mod types;

pub use error::{StoreError, StoreResult};
pub use types::{
    ArcKeyLineageV1, AuthenticatedQuoteStatus, BatAcceptanceClassMemberRecordV2,
    BatAcceptanceClassRecordV2, BatKeyLineage, BatKeyLineageRegistration,
    BatV2AccountingAuthorizationRecordV2, BatV2ClaimCryptographicVerificationInputV2,
    BatV2ClaimCryptographicVerifierV2, BatV2ClaimWrite, BatV2ClearingEpochReservationRecordV2,
    BatV2ClearingEpochReservationStateV2, BatV2ClearingEpochReservationV2,
    BatV2CredentialMaterialRequirementV2, BatV2QuoteReservation,
    ClaimCryptographicVerificationInput, ClaimCryptographicVerifier, ClaimRecord, ClaimWrite,
    ClearingAuthorizationRecordV1, CommitMarker, DelegationAdvance, DelegationHead, DurableWrite,
    IssuerServicePolicyRecordV1, IssuerStoreOperationalInventoryV1, LedgerTransactionKindV1,
    PayoutIntentRecordV1, PayoutOutboxCommandV1, PayoutOutboxStateV1, PayoutRecordV1,
    ProviderAccountBindingRecordV2, ProviderLedgerBalanceV1,
    ProviderSettlementRegistrationRecordV1, ProviderSettlementRegistrationWriteV1, QuoteCapacityV1,
    QuoteExpiry, QuoteFinalization, QuoteReconciliationCandidateV1, QuoteRecord, QuoteReservation,
    QuoteSettlement, QuoteState, QuoteStatusBip340Input, QuoteStatusBip340Verifier, ReceiptSerial,
    RedeemRecordV1, SettlementDepositRecordV1, SettlementKeyLineage,
    SettlementKeyLineageRegistration, SharedCredentialCryptographicVerifierV1,
    SharedCredentialSpendSinkV1, SharedCredentialVerificationInputV1, StoreIdentity, StoreOptions,
    VerifiedRedeemCommitV1, VerifiedSharedIssuerRedeemV1, WriteDisposition,
    MAX_EXACT_BAT_V2_ACCOUNTING_APPROVAL_BYTES, MAX_EXACT_BAT_V2_ACCOUNTING_AUTHORIZATION_BYTES,
    MAX_EXACT_BAT_V2_CLASS_BYTES, MAX_EXACT_BAT_V2_REDEEM_SUCCESS_BYTES,
    MAX_EXACT_CLAIM_REQUEST_BYTES, MAX_EXACT_CLAIM_RESPONSE_BYTES,
    MAX_EXACT_CLEARING_APPROVAL_BYTES, MAX_EXACT_CLEARING_AUTHORIZATION_BYTES,
    MAX_EXACT_DELEGATION_BYTES, MAX_EXACT_INTENT_BYTES, MAX_EXACT_PAYOUT_INTENT_REQUEST_BYTES,
    MAX_EXACT_PAYOUT_INTENT_RESPONSE_BYTES, MAX_EXACT_PAYOUT_REQUEST_BYTES,
    MAX_EXACT_PAYOUT_RESPONSE_BYTES, MAX_EXACT_PAYOUT_STATUS_RESPONSE_BYTES,
    MAX_EXACT_REDEEM_REQUEST_BYTES, MAX_EXACT_REDEEM_RESPONSE_BYTES,
    MAX_EXACT_SERVICE_POLICY_BYTES, MAX_EXACT_SETTLEMENT_DEPOSIT_REQUEST_BYTES,
    MAX_EXACT_SETTLEMENT_DEPOSIT_RESPONSE_BYTES, MAX_INVOICE_BYTES, MAX_RECEIPT_SERIALS_PER_CLAIM,
    MAX_SIGNED_QUOTE_BYTES, SCHEMA_VERSION,
};

pub use bat_v2_clearing_ops::IssuerBatV2RedeemCommitterV2;

pub use clearing_ops::{
    issuer_redeem_ledger_transaction_id_v1, issuer_settlement_deposit_transaction_id_v1,
    verify_shared_issuer_redeem_v1,
};
pub use quote_ops::MAX_QUOTE_RECONCILIATION_BATCH_V1;

pub use payout_ops::{
    issuer_payout_id_v1, issuer_payout_intent_id_v1, issuer_payout_ledger_transaction_id_v1,
    issuer_payout_outbox_command_id_v1, IssuerPayoutExecutionCommitterV1,
    IssuerPayoutStatusCommitterV1,
};

use crate::db::{
    checkpoint_new_store, configure_connection, create_file, network_code, open_checked,
    open_raw_existing, read_identity, sync_database_and_parent, validate_options, validate_schema,
    verify_expected_identity,
};
use crate::schema::{indexes, schema, APPLICATION_ID};
use crate::types::StoreHandle;
use pir_service_protocol::LightningNetworkV1;
use rusqlite::{params, TransactionBehavior};
use std::path::Path;

/// Handle to exactly one issuer and Lightning network's durable authority.
///
/// Each operation opens the existing file without `CREATE`, reapplies and
/// checks safety pragmas, and rechecks store/issuer/network identity. Clones
/// share one configured external authority; SQLite mutations serialize through
/// `BEGIN IMMEDIATE`, and every process must use the same linearizable,
/// independently durable authority.
#[derive(Clone, Debug)]
pub struct IssuerStore {
    pub(crate) handle: StoreHandle,
}

impl IssuerStore {
    /// Explicitly creates a new store and refuses an existing path.
    ///
    /// An incomplete file is deliberately left in place on failure so serve
    /// mode cannot silently replace or reinterpret it.
    pub fn create(
        path: impl AsRef<Path>,
        store_instance_id: [u8; 16],
        issuer_id: [u8; 32],
        network: LightningNetworkV1,
        options: StoreOptions,
    ) -> StoreResult<Self> {
        validate_options(options)?;
        if db::is_zero(&store_instance_id) {
            return Err(StoreError::InvalidInput("store instance id is all zero"));
        }
        if db::is_zero(&issuer_id) {
            return Err(StoreError::InvalidInput("issuer id is all zero"));
        }
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "issuer database path already exists",
            )));
        }
        let initial_commitment =
            rollback::initial_commitment(&store_instance_id, &issuer_id, network);
        create_file(&path)?;

        let mut connection = open_raw_existing(&path)?;
        configure_connection(&connection, options)?;
        {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            for (_, statement) in schema() {
                transaction.execute_batch(&statement)?;
            }
            for (_, statement) in indexes() {
                transaction.execute_batch(&statement)?;
            }
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.execute(
                "INSERT INTO store_identity \
                 (singleton, store_instance_id, issuer_id, network, commit_seq, \
                  rollback_parent_commitment, rollback_commitment, status_time_floor, schema_version) \
                 VALUES (1, ?1, ?2, ?3, 0, zeroblob(32), ?4, 0, ?5)",
                params![
                    store_instance_id.as_slice(),
                    issuer_id.as_slice(),
                    network_code(network),
                    initial_commitment.as_slice(),
                    i64::from(SCHEMA_VERSION),
                ],
            )?;
            db::commit(transaction)?;
        }
        checkpoint_new_store(&connection)?;
        drop(connection);
        sync_database_and_parent(&path)?;

        let store = Self {
            handle: StoreHandle {
                path,
                expected_store_instance_id: store_instance_id,
                expected_issuer_id: issuer_id,
                expected_network: network,
                options,
            },
        };
        let _ = store.open_checked(true)?;
        Ok(store)
    }

    /// Opens and fully validates an existing store. It never creates a file
    /// or performs a schema migration.
    pub fn open_existing(
        path: impl AsRef<Path>,
        expected_issuer_id: [u8; 32],
        expected_network: LightningNetworkV1,
        options: StoreOptions,
    ) -> StoreResult<Self> {
        validate_options(options)?;
        if db::is_zero(&expected_issuer_id) {
            return Err(StoreError::InvalidInput("issuer id is all zero"));
        }
        let path = path.as_ref().to_path_buf();
        let connection = open_raw_existing(&path)?;
        configure_connection(&connection, options)?;
        validate_schema(&connection)?;
        let identity = read_identity(&connection)?;
        if identity.issuer_id != expected_issuer_id {
            return Err(StoreError::IssuerMismatch);
        }
        if identity.network != expected_network {
            return Err(StoreError::NetworkMismatch);
        }
        drop(connection);
        let store = Self {
            handle: StoreHandle {
                path,
                expected_store_instance_id: identity.store_instance_id,
                expected_issuer_id,
                expected_network,
                options,
            },
        };
        let _ = store.open_checked(true)?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.handle.path
    }

    pub fn identity(&self) -> StoreResult<StoreIdentity> {
        let connection = self.open_checked(false)?;
        read_identity(&connection)
    }

    /// Returns aggregate row counts. This is intended for startup SLO and
    /// capacity observation; it never returns row identifiers or payment
    /// material.
    pub fn operational_inventory(&self) -> StoreResult<IssuerStoreOperationalInventoryV1> {
        let connection = self.open_checked(false)?;
        type RawInventory = (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64);
        let raw: RawInventory = connection.query_row(
            "SELECT (SELECT commit_seq FROM store_identity WHERE singleton = 1), \
                    (SELECT COUNT(*) FROM quotes), \
                    (SELECT COUNT(*) FROM claims), \
                    (SELECT COUNT(*) FROM issuer_service_policies), \
                    (SELECT COUNT(*) FROM bat_v2_class_artifacts), \
                    (SELECT COUNT(*) FROM bat_v2_class_heads), \
                    (SELECT COUNT(*) FROM bat_v2_class_members), \
                    (SELECT COUNT(*) FROM provider_account_bindings), \
                    (SELECT COUNT(*) FROM bat_v2_clearing_authorizations), \
                    (SELECT COUNT(*) FROM redemptions), \
                    (SELECT COUNT(*) FROM bat_v2_redemptions), \
                    (SELECT COUNT(*) FROM payouts)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            },
        )?;
        let inventory = IssuerStoreOperationalInventoryV1 {
            observed_commit_seq: db::db_u64(raw.0, "negative observed commit sequence")?,
            quote_rows: db::db_u64(raw.1, "negative quote row count")?,
            claim_rows: db::db_u64(raw.2, "negative claim row count")?,
            retained_policy_rows: db::db_u64(raw.3, "negative retained policy row count")?,
            bat_v2_class_rows: db::db_u64(raw.4, "negative BAT V2 class row count")?,
            bat_v2_class_head_rows: db::db_u64(raw.5, "negative BAT V2 class head row count")?,
            bat_v2_class_member_rows: db::db_u64(raw.6, "negative BAT V2 class member row count")?,
            provider_account_binding_rows: db::db_u64(
                raw.7,
                "negative provider account binding row count",
            )?,
            bat_v2_accounting_authorization_rows: db::db_u64(
                raw.8,
                "negative BAT V2 accounting authorization row count",
            )?,
            redemption_rows: db::db_u64(raw.9, "negative redemption row count")?,
            bat_v2_redemption_rows: db::db_u64(raw.10, "negative BAT V2 redemption row count")?,
            payout_rows: db::db_u64(raw.11, "negative payout row count")?,
        };
        Ok(inventory)
    }

    /// Stable Lightning-backend idempotency label for one quote id.
    pub fn backend_label_for_quote(&self, quote_id: &[u8; 32]) -> StoreResult<String> {
        if db::is_zero(quote_id) {
            return Err(StoreError::InvalidInput("quote id is all zero"));
        }
        Ok(db::derive_backend_label(
            &self.handle.expected_issuer_id,
            self.handle.expected_network,
            quote_id,
        ))
    }

    pub(crate) fn open_checked(
        &self,
        run_integrity_check: bool,
    ) -> StoreResult<rusqlite::Connection> {
        let connection = open_checked(&self.handle, run_integrity_check)?;
        let _ = verify_expected_identity(&connection, &self.handle)?;
        if run_integrity_check {
            quote_ops::verify_all_quote_histories(self, &connection)?;
            clearing_ops::verify_all_provider_registration_histories(self, &connection)?;
            bat_v2_ops::verify_all_bat_acceptance_classes_v2(self, &connection)?;
            bat_v2_clearing_ops::verify_all_bat_v2_clearing(self, &connection)?;
        }
        Ok(connection)
    }
}
