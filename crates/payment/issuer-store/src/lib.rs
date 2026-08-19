//! Fail-closed issuer persistence for BitcoinPIR paid capabilities.
//!
//! This crate owns durable quote/claim recovery and cryptographic key-lineage
//! registries. It deliberately has no HTTP, Lightning RPC, wallet, balance,
//! payout, PIR query, or provider-server networking code.

#![forbid(unsafe_code)]

mod bat_v2_ops;
mod clearing_ops;
mod db;
mod error;
mod payout_ops;
mod policy_ops;
mod quote_ops;
mod registry_ops;
mod remote_rollback;
mod rollback;
mod schema;
mod sqlite_rollback;
mod types;

pub use error::{StoreError, StoreResult};
pub use remote_rollback::RemoteIssuerRollbackFloorAuthorityV1;
pub use rollback::{
    IssuerRollbackFloorAuthorityErrorV1, IssuerRollbackFloorAuthorityV1, IssuerRollbackFloorV1,
    ISSUER_ROLLBACK_INITIAL_COMMITMENT_DOMAIN_V1, ISSUER_ROLLBACK_MUTATION_COMMITMENT_DOMAIN_V1,
};
pub use sqlite_rollback::SqliteIssuerRollbackFloorAuthorityV1;
pub use types::{
    ArcKeyLineageV1, AuthenticatedQuoteStatus, BatAcceptanceClassMemberRecordV2,
    BatAcceptanceClassRecordV2, BatKeyLineage, BatKeyLineageRegistration,
    ClaimCryptographicVerificationInput, ClaimCryptographicVerifier, ClaimRecord, ClaimWrite,
    ClearingAuthorizationRecordV1, CommitMarker, DelegationAdvance, DelegationHead, DurableWrite,
    IssuerServicePolicyRecordV1, IssuerStoreOperationalInventoryV1, LedgerTransactionKindV1,
    PayoutIntentRecordV1, PayoutOutboxCommandV1, PayoutOutboxStateV1, PayoutRecordV1,
    ProviderLedgerBalanceV1, ProviderSettlementRegistrationRecordV1,
    ProviderSettlementRegistrationWriteV1, QuoteCapacityV1, QuoteExpiry, QuoteFinalization,
    QuoteReconciliationCandidateV1, QuoteRecord, QuoteReservation, QuoteSettlement, QuoteState,
    QuoteStatusBip340Input, QuoteStatusBip340Verifier, ReceiptSerial, RedeemRecordV1,
    SettlementDepositRecordV1, SettlementKeyLineage, SettlementKeyLineageRegistration,
    SharedCredentialCryptographicVerifierV1, SharedCredentialSpendSinkV1,
    SharedCredentialVerificationInputV1, StoreIdentity, StoreOptions, VerifiedRedeemCommitV1,
    VerifiedSharedIssuerRedeemV1, WriteDisposition, MAX_EXACT_BAT_V2_CLASS_BYTES,
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
use std::sync::Arc;

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
        rollback_authority: Arc<dyn IssuerRollbackFloorAuthorityV1>,
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
        let expected_floor = IssuerRollbackFloorV1 {
            store_instance_id,
            issuer_id,
            network,
            store_generation: 0,
            rollback_commitment: initial_commitment,
            schema_version: SCHEMA_VERSION,
        };
        let initialized = rollback_authority
            .initialize(&expected_floor)
            .map_err(|error| StoreError::RollbackAuthorityUnavailable(error.to_string()))?;
        validate_exact_floor(&initialized, &expected_floor)?;
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
                rollback_authority,
                options,
            },
        };
        let _ = store.open_checked(true)?;
        Ok(store)
    }

    /// Opens and fully validates an existing store against the independently
    /// durable rollback authority. A missing authority record is fatal and is
    /// never reconstructed from SQLite.
    pub fn open_existing(
        path: impl AsRef<Path>,
        expected_issuer_id: [u8; 32],
        expected_network: LightningNetworkV1,
        options: StoreOptions,
        rollback_authority: Arc<dyn IssuerRollbackFloorAuthorityV1>,
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
                rollback_authority,
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
        let identity = read_identity(&connection)?;
        self.confirm_anchored_read(&connection, identity)
    }

    /// Returns aggregate row counts after rechecking the external rollback
    /// authority on both sides of the read. This is intended for startup SLO
    /// and capacity observation; it never returns row identifiers or payment
    /// material.
    pub fn operational_inventory(&self) -> StoreResult<IssuerStoreOperationalInventoryV1> {
        let connection = self.open_checked(false)?;
        type RawInventory = (i64, i64, i64, i64, i64, i64, i64, i64, i64);
        let raw: RawInventory = connection.query_row(
            "SELECT (SELECT commit_seq FROM store_identity WHERE singleton = 1), \
                    (SELECT COUNT(*) FROM quotes), \
                    (SELECT COUNT(*) FROM claims), \
                    (SELECT COUNT(*) FROM issuer_service_policies), \
                    (SELECT COUNT(*) FROM bat_v2_class_artifacts), \
                    (SELECT COUNT(*) FROM bat_v2_class_heads), \
                    (SELECT COUNT(*) FROM bat_v2_class_members), \
                    (SELECT COUNT(*) FROM redemptions), \
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
            redemption_rows: db::db_u64(raw.7, "negative redemption row count")?,
            payout_rows: db::db_u64(raw.8, "negative payout row count")?,
        };
        self.confirm_anchored_read(&connection, inventory)
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
        self.reconcile_rollback_floor(&connection)?;
        if run_integrity_check {
            quote_ops::verify_all_quote_histories(self, &connection)?;
            clearing_ops::verify_all_provider_registration_histories(self, &connection)?;
            bat_v2_ops::verify_all_bat_acceptance_classes_v2(self, &connection)?;
        }
        Ok(connection)
    }

    fn reconcile_rollback_floor(&self, connection: &rusqlite::Connection) -> StoreResult<()> {
        // Double-collect the external record around SQLite. A concurrent
        // writer may commit and anchor between reads; retry instead of
        // misclassifying that healthy transition as rollback.
        for _ in 0..8 {
            let authority_before = self
                .handle
                .rollback_authority
                .load(
                    &self.handle.expected_issuer_id,
                    self.handle.expected_network,
                )
                .map_err(|error| StoreError::RollbackAuthorityUnavailable(error.to_string()))?
                .ok_or(StoreError::RollbackFloorMissing)?;
            let identity = read_identity(connection)?;
            let database_floor = IssuerRollbackFloorV1::from_identity(&identity);
            let authority_after = self
                .handle
                .rollback_authority
                .load(
                    &self.handle.expected_issuer_id,
                    self.handle.expected_network,
                )
                .map_err(|error| StoreError::RollbackAuthorityUnavailable(error.to_string()))?
                .ok_or(StoreError::RollbackFloorMissing)?;
            if authority_before != authority_after {
                continue;
            }
            validate_floor_identity(&authority_after, &database_floor)?;
            return match database_floor
                .store_generation
                .cmp(&authority_after.store_generation)
            {
                std::cmp::Ordering::Less => Err(StoreError::RollbackDetected {
                    database_generation: database_floor.store_generation,
                    authority_generation: authority_after.store_generation,
                }),
                std::cmp::Ordering::Equal => {
                    validate_exact_floor(&authority_after, &database_floor)
                }
                std::cmp::Ordering::Greater => {
                    if database_floor.store_generation
                        != authority_after.store_generation.saturating_add(1)
                        || identity.rollback_parent_commitment
                            != authority_after.rollback_commitment
                    {
                        return Err(StoreError::RollbackFork);
                    }
                    let anchored = self
                        .handle
                        .rollback_authority
                        .compare_and_advance(&authority_after, &database_floor)
                        .map_err(|error| {
                            StoreError::RollbackAuthorityUnavailable(error.to_string())
                        })?;
                    validate_exact_floor(&anchored, &database_floor)
                }
            };
        }
        Err(StoreError::RollbackAuthorityUnavailable(
            "rollback floor changed continuously during checked open".to_owned(),
        ))
    }

    /// Confirms the external authority again after a read has materialized its
    /// result. This closes the commit-before-CAS race in which another process
    /// could commit an unanchored successor between the initial checked open
    /// and the actual SELECT. The value remains local until this succeeds.
    pub(crate) fn confirm_anchored_read<T>(
        &self,
        connection: &rusqlite::Connection,
        value: T,
    ) -> StoreResult<T> {
        self.reconcile_rollback_floor(connection)?;
        Ok(value)
    }

    pub(crate) fn require_exact_rollback_floor(
        &self,
        identity: &StoreIdentity,
    ) -> StoreResult<IssuerRollbackFloorV1> {
        let database_floor = IssuerRollbackFloorV1::from_identity(identity);
        let current = self
            .handle
            .rollback_authority
            .load(
                &self.handle.expected_issuer_id,
                self.handle.expected_network,
            )
            .map_err(|error| StoreError::RollbackAuthorityUnavailable(error.to_string()))?
            .ok_or(StoreError::RollbackFloorMissing)?;
        validate_floor_identity(&current, &database_floor)?;
        if current == database_floor {
            return Ok(current);
        }
        if database_floor.store_generation == current.store_generation.saturating_add(1)
            && identity.rollback_parent_commitment == current.rollback_commitment
        {
            let anchored = self
                .handle
                .rollback_authority
                .compare_and_advance(&current, &database_floor)
                .map_err(|error| StoreError::RollbackAuthorityUnavailable(error.to_string()))?;
            validate_exact_floor(&anchored, &database_floor)?;
            return Ok(database_floor);
        }
        validate_exact_floor(&current, &database_floor)?;
        Ok(current)
    }

    pub(crate) fn anchor_committed_identity(
        &self,
        expected: &IssuerRollbackFloorV1,
        committed: &StoreIdentity,
    ) -> StoreResult<()> {
        let next = IssuerRollbackFloorV1::from_identity(committed);
        let current = self
            .handle
            .rollback_authority
            .compare_and_advance(expected, &next)
            .map_err(|error| StoreError::UnanchoredCommit {
                store_generation: next.store_generation,
                authority_error: error.to_string(),
            })?;
        validate_exact_floor(&current, &next).map_err(|error| StoreError::UnanchoredCommit {
            store_generation: next.store_generation,
            authority_error: error.to_string(),
        })
    }
}

fn validate_floor_identity(
    actual: &IssuerRollbackFloorV1,
    expected: &IssuerRollbackFloorV1,
) -> StoreResult<()> {
    actual.validate()?;
    expected.validate()?;
    if actual.issuer_id != expected.issuer_id
        || actual.network != expected.network
        || actual.store_instance_id != expected.store_instance_id
        || actual.schema_version != expected.schema_version
    {
        return Err(StoreError::RollbackFloorIdentityMismatch);
    }
    Ok(())
}

fn validate_exact_floor(
    actual: &IssuerRollbackFloorV1,
    expected: &IssuerRollbackFloorV1,
) -> StoreResult<()> {
    validate_floor_identity(actual, expected)?;
    if actual == expected {
        return Ok(());
    }
    if actual.store_generation > expected.store_generation {
        return Err(StoreError::RollbackDetected {
            database_generation: expected.store_generation,
            authority_generation: actual.store_generation,
        });
    }
    Err(StoreError::RollbackFork)
}
