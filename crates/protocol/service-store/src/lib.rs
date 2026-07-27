//! Provider-local, fail-closed persistence for BitcoinPIR admission state.
//!
//! This crate intentionally does not contain issuer, invoice, payer, or query
//! data. See `docs/payment/PERSISTENCE.md` for the normative storage contract.
//! A [`SpendCommit`] is returned only after SQLite reports that `COMMIT`
//! succeeded. All proof verification belongs outside this crate and outside the
//! short write transaction.

#![forbid(unsafe_code)]

mod admission;
mod cashu_swap;
mod error;
mod offer_namespace;
mod rollback;
mod schema;
mod sqlite_rollback;
mod types;

pub use admission::{
    arc_provider_global_spend_key_v1, verify_provider_local_arc_spend_v1,
    verify_provider_local_bearer_spend_v1, ArcPresentationSpendVerifierV1,
    ArcProviderLocalAdapterV1, ArcVerifiedSpendSinkV1, CashuBatProofVerifierV1,
    VerifiedArcProviderLocalSpendV1, VerifiedProviderLocalSpendV1, ARC_CANONICAL_TAG_LEN_V1,
    ARC_PROVIDER_GLOBAL_SPEND_KEY_DOMAIN_V1,
};
pub use error::{StoreError, StoreResult};
pub use offer_namespace::{
    ArcExclusiveKeyLineageVerifierV1, VerifiedOfferNamespaceInstallOutcomeV1,
    VerifiedOfferNamespaceNotApplicableV1, VerifiedOfferNamespaceReadinessV1,
    OFFER_NAMESPACE_BINDING_DIGEST_DOMAIN_V1, OFFER_NAMESPACE_ID_DOMAIN_V1,
    OFFER_NAMESPACE_LINEAGE_DIGEST_DOMAIN_V1,
};
pub use rollback::{
    RollbackFloorAuthorityErrorV1, RollbackFloorAuthorityV1, RollbackFloorV1,
    ROLLBACK_INITIAL_COMMITMENT_DOMAIN_V1, ROLLBACK_MUTATION_COMMITMENT_DOMAIN_V1,
};
pub use sqlite_rollback::SqliteRollbackFloorAuthorityV1;
pub use types::{
    CashuCustodyExportArtifactPersistV1, CashuCustodyExportArtifactV1, CashuCustodyExportBatchV1,
    CashuCustodyExportReservationV1, CashuCustodyExportStateV1, CashuCustodyExposureLimitsV1,
    CashuCustodyInventoryV1, CashuCustodyLotStateV1, CashuCustodyLotV1,
    CashuCustodyRetirementCheckableSnapshotV1, CashuCustodyRetirementCompletedSnapshotV1,
    CashuCustodyRetirementEvidenceV1, CashuCustodyRetirementNoteCheckV1,
    CashuCustodyRetirementNoteStateV1, CashuCustodyRetirementSnapshotRequestV1,
    CashuCustodyRetirementSnapshotV1, CashuCustodySealedBlobV1,
    CashuCustodySpentConfirmationRequestV1, CashuCustodySpentConfirmationV1,
    CashuManifestEpochFloor, CashuSwapGrantClaimV1, CashuSwapIntentInsertV1,
    CashuSwapIntentStateV1, CashuSwapIntentV1, CashuSwapSealedRecoveryV1, CredentialEpochFloor,
    ExclusiveKeyLineage, FreeIpRateLimitRequestV1, NamespaceCloseOutcome, NamespaceInstallOutcome,
    NamespaceStatus, NewCashuCustodyExportV1, NewCashuCustodyLotV1, NewCashuSwapIntentV1,
    NewSpendNamespace, PolicyHead, PolicyStateUpdate, PolicyUpdateOutcome,
    ProviderStoreOperationalInventoryV1, SpendCommit, SpendNamespace, SpendReadBack, SpendRequest,
    StoreIdentity, StoreOptions, MAX_CASHU_CUSTODY_EXPORT_ARTIFACT_BYTES_V1,
    MAX_CASHU_CUSTODY_EXPORT_KEYSET_GROUPS_V1, MAX_CASHU_CUSTODY_EXPORT_LOTS_V1,
    MAX_CASHU_CUSTODY_EXPORT_NOTES_V1, MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1,
    MAX_CASHU_RECOVERY_CIPHERTEXT_BYTES_V1, MAX_CASHU_RECOVERY_NONCE_BYTES_V1, MAX_FLOOR_UPDATES,
    MAX_SIGNED_POLICY_BYTES, SCHEMA_VERSION,
};

use crate::schema::{APPLICATION_ID, SCHEMA};
use crate::types::StoreHandle;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::sync::Arc;

const MAX_BUSY_TIMEOUT_MILLIS: u128 = 60_000;
const MAX_KEY_ID_BYTES: usize = 66;

/// Handle to exactly one provider's SQLite spend authority.
///
/// The handle is cheap to clone. Every operation opens the file read/write
/// without `SQLITE_OPEN_CREATE`, verifies the checked connection pragmas and
/// schema, and repeats the provider identity check. Independent handles and
/// processes coordinate through `BEGIN IMMEDIATE` plus SQLite's unique key.
#[derive(Clone, Debug)]
pub struct ProviderStore {
    handle: StoreHandle,
}

impl ProviderStore {
    /// Explicitly creates a new provider store and refuses an existing path.
    ///
    /// The independently durable generation-zero floor is initialized before
    /// the SQLite file is created. If filesystem initialization then fails,
    /// the exact same store identity may retry; the authority record is never
    /// silently rebound or lowered. If failure occurs after file creation, the
    /// incomplete file remains for explicit operator inspection.
    pub fn create(
        path: impl AsRef<Path>,
        store_instance_id: [u8; 16],
        provider_id: [u8; 32],
        options: StoreOptions,
        rollback_authority: Arc<dyn RollbackFloorAuthorityV1>,
    ) -> StoreResult<Self> {
        Self::create_internal(
            path,
            store_instance_id,
            provider_id,
            options,
            Some(rollback_authority),
        )
    }

    fn create_internal(
        path: impl AsRef<Path>,
        store_instance_id: [u8; 16],
        provider_id: [u8; 32],
        options: StoreOptions,
        rollback_authority: Option<Arc<dyn RollbackFloorAuthorityV1>>,
    ) -> StoreResult<Self> {
        validate_options(options)?;
        if is_zero(&store_instance_id) {
            return Err(StoreError::InvalidInput("store instance id is all zero"));
        }
        if is_zero(&provider_id) {
            return Err(StoreError::InvalidInput("provider id is all zero"));
        }
        let path = path.as_ref().to_path_buf();
        if path.as_os_str().is_empty() {
            return Err(StoreError::InvalidInput("database path is empty"));
        }

        let initial_commitment = rollback::initial_commitment(&store_instance_id, &provider_id);
        if let Some(authority) = rollback_authority.as_ref() {
            if path.exists() {
                return Err(StoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "provider database path already exists",
                )));
            }
            let expected = RollbackFloorV1 {
                store_instance_id,
                provider_id,
                store_generation: 0,
                spend_commit_seq: 0,
                rollback_commitment: initial_commitment,
                schema_version: SCHEMA_VERSION,
            };
            let initialized = authority
                .initialize(&expected)
                .map_err(|error| StoreError::RollbackAuthorityUnavailable(error.to_string()))?;
            validate_exact_floor(&initialized, &expected)?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.sync_all()?;
        drop(file);
        sync_parent_directory(&path)?;

        let handle = StoreHandle {
            path,
            expected_provider_id: provider_id,
            options,
            rollback_authority,
        };
        let mut connection = open_raw_existing(&handle.path)?;
        configure_connection(&connection, options)?;

        {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            for (_, statement) in SCHEMA {
                transaction.execute_batch(statement)?;
            }
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.execute(
                "INSERT INTO store_identity \
                 (singleton, store_instance_id, provider_id, store_generation, spend_commit_seq, \
                  rollback_parent_commitment, rollback_commitment, schema_version) \
                 VALUES (1, ?1, ?2, 0, 0, zeroblob(32), ?3, ?4)",
                params![
                    store_instance_id.as_slice(),
                    provider_id.as_slice(),
                    initial_commitment.as_slice(),
                    i64::from(SCHEMA_VERSION)
                ],
            )?;
            transaction.execute(
                "INSERT INTO free_ip_rate_limit_clock (singleton, highest_now) VALUES (1, 0)",
                [],
            )?;
            transaction.commit()?;
        }
        checkpoint_new_store(&connection)?;
        drop(connection);
        OpenOptions::new()
            .read(true)
            .open(&handle.path)?
            .sync_all()?;
        sync_parent_directory(&handle.path)?;

        let store = Self { handle };
        let _ = store.open_checked(true)?;
        Ok(store)
    }

    /// Opens and fully validates an existing store. It never creates a file or
    /// performs a schema migration. A missing authority record is fatal and is
    /// never reconstructed from this database.
    pub fn open_existing(
        path: impl AsRef<Path>,
        expected_provider_id: [u8; 32],
        options: StoreOptions,
        rollback_authority: Arc<dyn RollbackFloorAuthorityV1>,
    ) -> StoreResult<Self> {
        Self::open_existing_internal(
            path,
            expected_provider_id,
            options,
            Some(rollback_authority),
        )
    }

    fn open_existing_internal(
        path: impl AsRef<Path>,
        expected_provider_id: [u8; 32],
        options: StoreOptions,
        rollback_authority: Option<Arc<dyn RollbackFloorAuthorityV1>>,
    ) -> StoreResult<Self> {
        validate_options(options)?;
        if is_zero(&expected_provider_id) {
            return Err(StoreError::InvalidInput("provider id is all zero"));
        }
        let store = Self {
            handle: StoreHandle {
                path: path.as_ref().to_path_buf(),
                expected_provider_id,
                options,
                rollback_authority,
            },
        };
        let _ = store.open_checked(true)?;
        Ok(store)
    }

    #[cfg(test)]
    fn create_unprotected_for_tests(
        path: impl AsRef<Path>,
        store_instance_id: [u8; 16],
        provider_id: [u8; 32],
        options: StoreOptions,
    ) -> StoreResult<Self> {
        Self::create_internal(path, store_instance_id, provider_id, options, None)
    }

    #[cfg(test)]
    fn open_existing_unprotected_for_tests(
        path: impl AsRef<Path>,
        expected_provider_id: [u8; 32],
        options: StoreOptions,
    ) -> StoreResult<Self> {
        Self::open_existing_internal(path, expected_provider_id, options, None)
    }

    pub fn path(&self) -> &Path {
        &self.handle.path
    }

    pub fn identity(&self) -> StoreResult<StoreIdentity> {
        let connection = self.open_checked(false)?;
        read_identity(&connection)
    }

    /// Returns aggregate row counts after rechecking the independent rollback
    /// authority. This supports startup SLO/capacity observation without
    /// exposing spend keys, subjects, namespaces, or protocol transcripts.
    pub fn operational_inventory(&self) -> StoreResult<ProviderStoreOperationalInventoryV1> {
        let connection = self.open_checked(false)?;
        let raw: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = connection.query_row(
            "SELECT (SELECT store_generation FROM store_identity WHERE singleton = 1), \
                    (SELECT spend_commit_seq FROM store_identity WHERE singleton = 1), \
                    (SELECT COUNT(*) FROM spend_namespaces), \
                    (SELECT COUNT(*) FROM spent_capabilities), \
                    (SELECT COUNT(*) FROM free_ip_rate_limit_buckets), \
                    (SELECT COUNT(*) FROM cashu_swap_intents), \
                    (SELECT COUNT(*) FROM cashu_custody_lots), \
                    (SELECT COUNT(*) FROM cashu_custody_notes), \
                    (SELECT COUNT(*) FROM cashu_custody_export_batches), \
                    (SELECT COUNT(*) FROM cashu_custody_retirement_evidence)",
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
                ))
            },
        )?;
        let inventory = ProviderStoreOperationalInventoryV1 {
            observed_store_generation: db_u64(raw.0, "negative observed store generation")?,
            observed_spend_commit_seq: db_u64(raw.1, "negative observed spend commit sequence")?,
            namespace_rows: db_u64(raw.2, "negative namespace row count")?,
            spent_capability_rows: db_u64(raw.3, "negative spent capability row count")?,
            free_rate_limit_bucket_rows: db_u64(raw.4, "negative Free bucket row count")?,
            cashu_swap_intent_rows: db_u64(raw.5, "negative Cashu swap intent row count")?,
            cashu_custody_lot_rows: db_u64(raw.6, "negative Cashu custody lot row count")?,
            cashu_custody_note_rows: db_u64(raw.7, "negative Cashu custody note row count")?,
            cashu_custody_export_batch_rows: db_u64(
                raw.8,
                "negative Cashu custody export batch row count",
            )?,
            cashu_custody_retirement_evidence_rows: db_u64(
                raw.9,
                "negative Cashu custody retirement evidence row count",
            )?,
        };
        self.reconcile_rollback_floor(&connection)?;
        Ok(inventory)
    }

    /// Recommended and only high-level namespace installation path.
    ///
    /// The input can only be constructed by successfully verifying a signed
    /// service policy. This method also binds it to this store's provider,
    /// routes schemes which do not use a provider-local bearer spent-set, and
    /// installs the required BAT/ARC raw-key lineage guard atomically with the
    /// derived namespace. Provider-local experimental ARC returns
    /// [`VerifiedOfferNamespaceInstallOutcomeV1::UnsupportedExperimental`]
    /// unless a reviewed adapter is supplied; shared-issuer ARC never creates
    /// provider-local state.
    pub fn install_verified_offer_namespace_v1(
        &self,
        verified_offer: &pir_service_protocol::VerifiedServiceOfferV1<'_>,
        now_unix_seconds: u64,
        arc_lineage_verifier: Option<&dyn ArcExclusiveKeyLineageVerifierV1>,
    ) -> StoreResult<VerifiedOfferNamespaceInstallOutcomeV1> {
        offer_namespace::install_verified_offer_namespace_v1(
            self,
            verified_offer,
            now_unix_seconds,
            arc_lineage_verifier,
        )
    }

    /// Read-only retained-policy startup check. Unlike installation, this
    /// fails if required provider-local spend state was not durably installed
    /// while the policy was current, or if that namespace was closed.
    pub fn verify_existing_verified_offer_namespace_v1(
        &self,
        verified_offer: &pir_service_protocol::VerifiedServiceOfferV1<'_>,
        now_unix_seconds: u64,
        arc_lineage_verifier: Option<&dyn ArcExclusiveKeyLineageVerifierV1>,
    ) -> StoreResult<VerifiedOfferNamespaceReadinessV1> {
        offer_namespace::verify_existing_verified_offer_namespace_v1(
            self,
            verified_offer,
            now_unix_seconds,
            arc_lineage_verifier,
        )
    }

    /// Crate-private low-level installation primitive.
    ///
    /// Production integration SHOULD use
    /// [`Self::install_verified_offer_namespace_v1`]. This primitive cannot
    /// prove that a caller derived the namespace from a verified policy and
    /// cannot know whether an omitted exclusive-key lineage was required, so
    /// it is inaccessible to downstream crates. Repeating the exact row is
    /// idempotent; a closed row remains closed and is never reopened.
    pub(crate) fn install_namespace(
        &self,
        namespace: &NewSpendNamespace,
    ) -> StoreResult<NamespaceInstallOutcome> {
        validate_new_namespace(namespace)?;
        let not_after = sql_integer(namespace.not_after, "namespace not_after exceeds i64::MAX")?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;

        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        if let Some(existing) = read_namespace(&transaction, &namespace.namespace_id)? {
            if existing.scheme != namespace.scheme
                || existing.issuer_id != namespace.issuer_id
                || existing.key_id != namespace.key_id
                || existing.binding_digest != namespace.binding_digest
                || existing.not_after != namespace.not_after
            {
                return Err(StoreError::NamespaceConflict);
            }
            if let Some(lineage) = namespace.exclusive_key_lineage {
                let persisted: Option<Vec<u8>> = transaction
                    .query_row(
                        "SELECT lineage_digest FROM exclusive_key_lineages \
                         WHERE scheme = ?1 AND key_fingerprint = ?2",
                        params![
                            i64::from(namespace.scheme),
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
                if fixed_blob::<32>(persisted, "invalid exclusive lineage digest")?
                    != lineage.lineage_digest
                {
                    return Err(StoreError::ExclusiveKeyLineageConflict);
                }
            }
            return Ok(NamespaceInstallOutcome::AlreadyPresent(existing.status));
        }

        if let Some(lineage) = namespace.exclusive_key_lineage {
            let existing: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT lineage_digest FROM exclusive_key_lineages \
                     WHERE scheme = ?1 AND key_fingerprint = ?2",
                    params![
                        i64::from(namespace.scheme),
                        lineage.key_fingerprint.as_slice()
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            match existing {
                Some(existing) => {
                    let existing = fixed_blob(existing, "invalid exclusive lineage digest")?;
                    if is_zero(&existing) {
                        return Err(StoreError::SchemaMismatch(
                            "exclusive lineage digest is all zero".to_owned(),
                        ));
                    }
                    if existing != lineage.lineage_digest {
                        return Err(StoreError::ExclusiveKeyLineageConflict);
                    }
                }
                None => {
                    transaction.execute(
                        "INSERT INTO exclusive_key_lineages \
                         (scheme, key_fingerprint, lineage_digest) VALUES (?1, ?2, ?3)",
                        params![
                            i64::from(namespace.scheme),
                            lineage.key_fingerprint.as_slice(),
                            lineage.lineage_digest.as_slice(),
                        ],
                    )?;
                }
            }
        }

        let tuple_owner: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT namespace_id FROM spend_namespaces \
                 WHERE scheme = ?1 AND issuer_id = ?2 AND key_id = ?3",
                params![
                    i64::from(namespace.scheme),
                    namespace.issuer_id.as_slice(),
                    namespace.key_id.as_slice()
                ],
                |row| row.get(0),
            )
            .optional()?;
        if tuple_owner.is_some() {
            return Err(StoreError::NamespaceConflict);
        }

        transaction.execute(
            "INSERT INTO spend_namespaces \
             (namespace_id, scheme, issuer_id, key_id, binding_digest, not_after, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                namespace.namespace_id.as_slice(),
                i64::from(namespace.scheme),
                namespace.issuer_id.as_slice(),
                namespace.key_id.as_slice(),
                namespace.binding_digest.as_slice(),
                not_after,
                NamespaceStatus::Active as i64,
            ],
        )?;
        let scheme = namespace.scheme.to_le_bytes();
        let not_after_bytes = namespace.not_after.to_le_bytes();
        let lineage_fingerprint = namespace
            .exclusive_key_lineage
            .map(|lineage| lineage.key_fingerprint)
            .unwrap_or([0; 32]);
        let lineage_digest = namespace
            .exclusive_key_lineage
            .map(|lineage| lineage.lineage_digest)
            .unwrap_or([0; 32]);
        let digest = mutation_digest(
            b"install-namespace-v1",
            &[
                &namespace.namespace_id,
                &scheme,
                &namespace.issuer_id,
                &namespace.key_id,
                &namespace.binding_digest,
                &not_after_bytes,
                &lineage_fingerprint,
                &lineage_digest,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            b"install-namespace-v1",
            &digest,
            false,
        )?;
        transaction.commit()?;
        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)?;
        Ok(NamespaceInstallOutcome::Installed)
    }

    /// Irreversibly closes a namespace. Missing namespaces fail closed.
    pub fn close_namespace(&self, namespace_id: &[u8; 32]) -> StoreResult<NamespaceCloseOutcome> {
        if is_zero(namespace_id) {
            return Err(StoreError::InvalidInput("namespace id is all zero"));
        }
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;
        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        let namespace =
            read_namespace(&transaction, namespace_id)?.ok_or(StoreError::NamespaceMissing)?;
        if namespace.status == NamespaceStatus::Closed {
            return Ok(NamespaceCloseOutcome::AlreadyClosed);
        }
        transaction.execute(
            "UPDATE spend_namespaces SET status = ?1 WHERE namespace_id = ?2",
            params![NamespaceStatus::Closed as i64, namespace_id.as_slice()],
        )?;
        let digest = mutation_digest(b"close-namespace-v1", &[namespace_id]);
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            b"close-namespace-v1",
            &digest,
            false,
        )?;
        transaction.commit()?;
        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)?;
        Ok(NamespaceCloseOutcome::Closed)
    }

    pub fn namespace(&self, namespace_id: &[u8; 32]) -> StoreResult<Option<SpendNamespace>> {
        if is_zero(namespace_id) {
            return Err(StoreError::InvalidInput("namespace id is all zero"));
        }
        let connection = self.open_checked(false)?;
        read_namespace(&connection, namespace_id)
    }

    /// Atomically consumes a previously verified capability.
    ///
    /// The caller may install a connection-local grant only from `Ok`. A
    /// SQLite `COMMIT` error is returned as
    /// [`StoreError::InternalAfterSpend`] after read-back; failure to confirm
    /// the independent anchor is [`StoreError::UnanchoredCommit`]. Neither
    /// case grants the connection, even when the spend is later observable.
    pub fn spend_verified_provider_local_v1(
        &self,
        verified: VerifiedProviderLocalSpendV1,
    ) -> StoreResult<SpendCommit> {
        self.spend(verified.into())
    }

    /// Atomically consumes a cryptographically verified experimental ARC
    /// presentation. The sealed input can only be created by
    /// [`verify_provider_local_arc_spend_v1`].
    pub fn spend_verified_arc_provider_local_v1(
        &self,
        verified: VerifiedArcProviderLocalSpendV1,
    ) -> StoreResult<SpendCommit> {
        self.spend(verified.into())
    }

    /// Low-level primitive deliberately inaccessible to runtime crates. Public
    /// handlers must use [`Self::spend_verified_provider_local_v1`].
    ///
    /// ```compile_fail
    /// use pir_service_store::{ProviderStore, SpendRequest};
    /// fn bypass(store: &ProviderStore, request: SpendRequest) {
    ///     store.spend(request);
    /// }
    /// ```
    pub(crate) fn spend(&self, request: SpendRequest) -> StoreResult<SpendCommit> {
        if is_zero(&request.namespace_id) {
            return Err(StoreError::InvalidInput("namespace id is all zero"));
        }
        if is_zero(&request.spend_key) {
            return Err(StoreError::InvalidInput("spend key is all zero"));
        }
        if request.now_unix_seconds == 0 {
            return Err(StoreError::InvalidInput("spend time is zero"));
        }
        let now = sql_integer(
            request.now_unix_seconds,
            "spend time exceeds SQLite integer range",
        )?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;
        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        let (status, not_after): (i64, i64) = transaction
            .query_row(
                "SELECT status, not_after FROM spend_namespaces WHERE namespace_id = ?1",
                [request.namespace_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NamespaceMissing)?;
        match NamespaceStatus::from_db(status) {
            Some(NamespaceStatus::Active) => {}
            Some(NamespaceStatus::Closed) => return Err(StoreError::NamespaceClosed),
            None => {
                return Err(StoreError::SchemaMismatch(
                    "namespace contains an unknown status".to_owned(),
                ))
            }
        }
        if now > not_after {
            return Err(StoreError::NamespaceExpired);
        }

        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM spent_capabilities \
             WHERE spend_key = ?1)",
            [request.spend_key.as_slice()],
            |row| row.get(0),
        )?;
        if exists {
            return Err(StoreError::AlreadySpent);
        }

        transaction.execute(
            "INSERT INTO spent_capabilities (namespace_id, spend_key) VALUES (?1, ?2)",
            params![
                request.namespace_id.as_slice(),
                request.spend_key.as_slice()
            ],
        )?;
        let now_bytes = request.now_unix_seconds.to_le_bytes();
        let digest = mutation_digest(
            b"spend-capability-v1",
            &[&request.namespace_id, &request.spend_key, &now_bytes],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            b"spend-capability-v1",
            &digest,
            true,
        )?;

        if let Err(error) = transaction.commit() {
            let database_error = error.to_string();
            drop(connection);
            let read_back = self.inspect_spend_after_failed_commit(&request);
            return Err(StoreError::InternalAfterSpend {
                read_back,
                database_error,
            });
        }

        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)?;

        Ok(SpendCommit {
            spend_commit_seq: committed_identity.spend_commit_seq,
        })
    }

    /// Atomically consumes one provider-local fixed-window IP quota bucket.
    /// The only durable subject is the caller-supplied 32-byte HMAC cohort.
    /// A lower window than the persisted high-water mark fails closed.
    pub fn consume_free_ip_rate_limit_v1(
        &self,
        request: FreeIpRateLimitRequestV1,
    ) -> StoreResult<()> {
        if request.subject.iter().all(|byte| *byte == 0)
            || request.policy_digest.iter().all(|byte| *byte == 0)
            || request.scope_id.iter().all(|byte| *byte == 0)
            || request.offer_id == 0
            || request.quota == 0
            || request.window_seconds == 0
            || request.max_buckets == 0
            || request.now_unix_seconds == 0
        {
            return Err(StoreError::InvalidInput("invalid free IP quota request"));
        }
        let window_end = (request.now_unix_seconds / u64::from(request.window_seconds))
            .checked_add(1)
            .and_then(|window| window.checked_mul(u64::from(request.window_seconds)))
            .ok_or(StoreError::InvalidInput("free IP window expiry overflow"))?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;
        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        let highest_now: i64 = transaction.query_row(
            "SELECT highest_now FROM free_ip_rate_limit_clock WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if request.now_unix_seconds < db_u64(highest_now, "negative free IP clock")? {
            return Err(StoreError::FreeIpClockRollback);
        }
        transaction.execute(
            "DELETE FROM free_ip_rate_limit_buckets WHERE expires_at <= ?1",
            [sql_integer(
                request.now_unix_seconds,
                "free IP time exceeds SQLite integer range",
            )?],
        )?;
        let existing: Option<i64> = transaction
            .query_row(
                "SELECT count FROM free_ip_rate_limit_buckets \
                 WHERE subject = ?1 AND policy_digest = ?2 AND scope_id = ?3 AND offer_id = ?4",
                params![
                    request.subject.as_slice(),
                    request.policy_digest.as_slice(),
                    request.scope_id.as_slice(),
                    i64::from(request.offer_id),
                ],
                |row| row.get(0),
            )
            .optional()?;
        let next_count = match existing {
            None => {
                let bucket_count: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM free_ip_rate_limit_buckets",
                    [],
                    |row| row.get(0),
                )?;
                if u64::try_from(bucket_count).map_err(|_| {
                    StoreError::SchemaMismatch("negative free IP bucket count".to_owned())
                })? >= u64::try_from(request.max_buckets)
                    .map_err(|_| StoreError::InvalidInput("free IP bucket capacity exceeds u64"))?
                {
                    return Err(StoreError::FreeIpQuotaExhausted);
                }
                transaction.execute(
                    "INSERT INTO free_ip_rate_limit_buckets \
                     (subject, policy_digest, scope_id, offer_id, expires_at, count) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
                    params![
                        request.subject.as_slice(), request.policy_digest.as_slice(), request.scope_id.as_slice(),
                        i64::from(request.offer_id), sql_integer(window_end, "free IP expiry exceeds SQLite integer range")?,
                    ],
                )?;
                1u32
            }
            Some(count) => {
                let count = db_u64(count, "negative free IP count")?;
                if count >= u64::from(request.quota) {
                    return Err(StoreError::FreeIpQuotaExhausted);
                }
                let next = count
                    .checked_add(1)
                    .ok_or(StoreError::FreeIpQuotaExhausted)?;
                transaction.execute(
                    "UPDATE free_ip_rate_limit_buckets SET count = ?1 \
                     WHERE subject = ?2 AND policy_digest = ?3 AND scope_id = ?4 AND offer_id = ?5",
                    params![
                        sql_integer(next, "free IP count exceeds SQLite integer range")?,
                        request.subject.as_slice(),
                        request.policy_digest.as_slice(),
                        request.scope_id.as_slice(),
                        i64::from(request.offer_id)
                    ],
                )?;
                u32::try_from(next).map_err(|_| StoreError::FreeIpQuotaExhausted)?
            }
        };
        transaction.execute(
            "UPDATE free_ip_rate_limit_clock SET highest_now = ?1 WHERE singleton = 1 AND highest_now <= ?1",
            [sql_integer(request.now_unix_seconds, "free IP time exceeds SQLite integer range")?],
        )?;
        let digest = mutation_digest(
            b"consume-free-ip-rate-limit-v1",
            &[
                &request.subject,
                &request.policy_digest,
                &request.scope_id,
                &request.offer_id.to_le_bytes(),
                &window_end.to_le_bytes(),
                &next_count.to_le_bytes(),
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            b"consume-free-ip-rate-limit-v1",
            &digest,
            false,
        )?;
        transaction.commit()?;
        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)
    }

    /// Checks the provider-global spend key. Namespace is deliberately not part
    /// of replay identity, so a serial cannot be consumed again under a second
    /// scope or retired namespace.
    pub fn is_spent(&self, spend_key: &[u8; 32]) -> StoreResult<bool> {
        if is_zero(spend_key) {
            return Err(StoreError::InvalidInput("spend key is all zero"));
        }
        let connection = self.open_checked(false)?;
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM spent_capabilities \
             WHERE spend_key = ?1)",
            [spend_key.as_slice()],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    /// Atomically advances the signed policy head and every derived monotonic
    /// floor supplied by the caller. Any rollback aborts the whole transaction.
    /// ```compile_fail
    /// use pir_service_store::{PolicyStateUpdate, ProviderStore};
    /// fn bypass(store: &ProviderStore, update: &PolicyStateUpdate) {
    ///     store.apply_policy_state(update);
    /// }
    /// ```
    pub(crate) fn apply_policy_state(
        &self,
        update: &PolicyStateUpdate,
    ) -> StoreResult<PolicyUpdateOutcome> {
        validate_policy_update(update)?;
        let policy_epoch = sql_integer(
            update.head.highest_policy_epoch,
            "policy epoch exceeds SQLite integer range",
        )?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;
        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        let current = read_policy_head(&transaction, &self.handle.expected_provider_id)?;
        let outcome = match &current {
            Some(head) if update.head.highest_policy_epoch < head.highest_policy_epoch => {
                return Err(StoreError::PolicyRollback)
            }
            Some(head)
                if update.head.highest_policy_epoch == head.highest_policy_epoch
                    && update.head.policy_digest != head.policy_digest =>
            {
                return Err(StoreError::PolicyFork)
            }
            Some(head)
                if update.head.highest_policy_epoch == head.highest_policy_epoch
                    && update.head.signed_policy != head.signed_policy =>
            {
                return Err(StoreError::PolicyFork)
            }
            Some(head) if update.head.highest_policy_epoch == head.highest_policy_epoch => {
                PolicyUpdateOutcome::AlreadyCurrent
            }
            _ => PolicyUpdateOutcome::Advanced,
        };
        let mut state_changed = outcome == PolicyUpdateOutcome::Advanced;

        for floor in &update.credential_floors {
            let old: Option<i64> = transaction
                .query_row(
                    "SELECT minimum_epoch FROM credential_epoch_floors \
                     WHERE scope_id = ?1 AND scheme = ?2 AND issuer_id = ?3",
                    params![
                        floor.scope_id.as_slice(),
                        i64::from(floor.scheme),
                        floor.issuer_id.as_slice()
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(value) = old {
                let value = db_u64(value, "negative credential epoch floor")?;
                if floor.minimum_epoch < value {
                    return Err(StoreError::CredentialFloorRollback);
                }
                state_changed |= floor.minimum_epoch > value;
            } else {
                state_changed = true;
            }
        }
        for floor in &update.cashu_manifest_floors {
            let old: Option<i64> = transaction
                .query_row(
                    "SELECT minimum_epoch FROM cashu_manifest_epoch_floors \
                     WHERE mint_id = ?1 AND unit = ?2",
                    params![floor.mint_id.as_slice(), floor.unit],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(value) = old {
                let value = db_u64(value, "negative Cashu manifest epoch floor")?;
                if floor.minimum_epoch < value {
                    return Err(StoreError::CashuFloorRollback);
                }
                state_changed |= floor.minimum_epoch > value;
            } else {
                state_changed = true;
            }
        }

        if !state_changed {
            return Ok(PolicyUpdateOutcome::AlreadyCurrent);
        }

        transaction.execute(
            "INSERT INTO policy_heads \
             (provider_id, highest_policy_epoch, policy_digest, signed_policy) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(provider_id) DO UPDATE SET \
               highest_policy_epoch = excluded.highest_policy_epoch, \
               policy_digest = excluded.policy_digest, \
               signed_policy = excluded.signed_policy",
            params![
                self.handle.expected_provider_id.as_slice(),
                policy_epoch,
                update.head.policy_digest.as_slice(),
                update.head.signed_policy.as_slice(),
            ],
        )?;
        for floor in &update.credential_floors {
            transaction.execute(
                "INSERT INTO credential_epoch_floors \
                 (scope_id, scheme, issuer_id, minimum_epoch) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(scope_id, scheme, issuer_id) DO UPDATE SET \
                   minimum_epoch = excluded.minimum_epoch",
                params![
                    floor.scope_id.as_slice(),
                    i64::from(floor.scheme),
                    floor.issuer_id.as_slice(),
                    sql_integer(
                        floor.minimum_epoch,
                        "credential epoch exceeds SQLite integer range"
                    )?,
                ],
            )?;
        }
        for floor in &update.cashu_manifest_floors {
            transaction.execute(
                "INSERT INTO cashu_manifest_epoch_floors \
                 (mint_id, unit, minimum_epoch) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(mint_id, unit) DO UPDATE SET \
                   minimum_epoch = excluded.minimum_epoch",
                params![
                    floor.mint_id.as_slice(),
                    floor.unit,
                    sql_integer(
                        floor.minimum_epoch,
                        "Cashu manifest epoch exceeds SQLite integer range"
                    )?,
                ],
            )?;
        }
        let digest = policy_update_mutation_digest(update);
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            b"apply-policy-state-v1",
            &digest,
            false,
        )?;
        transaction.commit()?;
        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)?;
        Ok(outcome)
    }

    /// Production entry point for durable policy/floor advancement. Every
    /// persisted field is derived from a successfully verified current signed
    /// policy; downstream handlers cannot provide raw floor values.
    pub fn apply_verified_policy_state_v1(
        &self,
        verified_policy: &pir_service_protocol::VerifiedCurrentPolicyV1<'_>,
    ) -> StoreResult<PolicyUpdateOutcome> {
        let policy = verified_policy.policy();
        if policy.provider_id != self.handle.expected_provider_id {
            return Err(StoreError::ProviderMismatch);
        }

        let mut credential_floors = BTreeMap::new();
        let mut cashu_manifest_floors = BTreeMap::new();
        for scope_policy in &policy.scopes {
            let scope_id = scope_policy.scope.scope_id();
            for offer in &scope_policy.offers {
                if let Some(binding) = &offer.credential_binding {
                    credential_floors
                        .entry((scope_id, offer.authorization as u16, offer.issuer_id))
                        .and_modify(|epoch: &mut u64| {
                            *epoch = (*epoch).max(binding.claims.keyset_epoch)
                        })
                        .or_insert(binding.claims.keyset_epoch);
                }
                if let Some(manifest) = &offer.cashu_mint_manifest {
                    cashu_manifest_floors
                        .entry((offer.issuer_id, manifest.unit.clone()))
                        .and_modify(|epoch: &mut u64| {
                            *epoch = (*epoch).max(manifest.manifest_epoch)
                        })
                        .or_insert(manifest.manifest_epoch);
                }
            }
        }

        let update = PolicyStateUpdate {
            head: PolicyHead {
                highest_policy_epoch: policy.policy_epoch,
                policy_digest: verified_policy.policy_digest(),
                signed_policy: policy.encode()?,
            },
            credential_floors: credential_floors
                .into_iter()
                .map(
                    |((scope_id, scheme, issuer_id), minimum_epoch)| CredentialEpochFloor {
                        scope_id,
                        scheme,
                        issuer_id,
                        minimum_epoch,
                    },
                )
                .collect(),
            cashu_manifest_floors: cashu_manifest_floors
                .into_iter()
                .map(|((mint_id, unit), minimum_epoch)| CashuManifestEpochFloor {
                    mint_id,
                    unit,
                    minimum_epoch,
                })
                .collect(),
        };
        self.apply_policy_state(&update)
    }

    pub fn policy_head(&self) -> StoreResult<Option<PolicyHead>> {
        let connection = self.open_checked(false)?;
        read_policy_head(&connection, &self.handle.expected_provider_id)
    }

    pub fn credential_epoch_floor(
        &self,
        scope_id: &[u8; 32],
        scheme: u16,
        issuer_id: &[u8; 32],
    ) -> StoreResult<Option<u64>> {
        if is_zero(scope_id) || is_zero(issuer_id) || scheme == 0 {
            return Err(StoreError::InvalidInput(
                "credential floor identity contains a zero sentinel",
            ));
        }
        let connection = self.open_checked(false)?;
        let value: Option<i64> = connection
            .query_row(
                "SELECT minimum_epoch FROM credential_epoch_floors \
                 WHERE scope_id = ?1 AND scheme = ?2 AND issuer_id = ?3",
                params![scope_id.as_slice(), i64::from(scheme), issuer_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| db_u64(value, "negative credential epoch floor"))
            .transpose()
    }

    pub fn cashu_manifest_epoch_floor(
        &self,
        mint_id: &[u8; 32],
        unit: &str,
    ) -> StoreResult<Option<u64>> {
        if is_zero(mint_id) {
            return Err(StoreError::InvalidInput("Cashu mint id is all zero"));
        }
        validate_cashu_unit(unit)?;
        let connection = self.open_checked(false)?;
        let value: Option<i64> = connection
            .query_row(
                "SELECT minimum_epoch FROM cashu_manifest_epoch_floors \
                 WHERE mint_id = ?1 AND unit = ?2",
                params![mint_id.as_slice(), unit],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| db_u64(value, "negative Cashu manifest epoch floor"))
            .transpose()
    }

    fn inspect_spend_after_failed_commit(&self, request: &SpendRequest) -> SpendReadBack {
        let result = self.open_checked(false).and_then(|connection| {
            connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM spent_capabilities \
                     WHERE spend_key = ?1)",
                    [request.spend_key.as_slice()],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(StoreError::from)
        });
        match result {
            Ok(true) => SpendReadBack::Present,
            Ok(false) => SpendReadBack::Absent,
            Err(_) => SpendReadBack::Unavailable,
        }
    }

    fn open_checked(&self, run_integrity_check: bool) -> StoreResult<Connection> {
        let connection = open_raw_existing(&self.handle.path)?;
        configure_connection(&connection, self.handle.options)?;
        validate_schema(&connection)?;
        verify_expected_provider(&connection, &self.handle.expected_provider_id)?;
        self.reconcile_rollback_floor(&connection)?;
        if run_integrity_check {
            let result: String =
                connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
            if result != "ok" {
                return Err(StoreError::IntegrityCheckFailed(result));
            }
            let mut foreign_key_check = connection.prepare("PRAGMA foreign_key_check")?;
            if foreign_key_check.query([])?.next()?.is_some() {
                return Err(StoreError::IntegrityCheckFailed(
                    "foreign key check reported a violation".to_owned(),
                ));
            }
        }
        Ok(connection)
    }

    fn reconcile_rollback_floor(&self, connection: &Connection) -> StoreResult<()> {
        let Some(authority) = self.handle.rollback_authority.as_ref() else {
            return Ok(());
        };
        // Double-collect the external record around the SQLite read. Without
        // this, a healthy concurrent writer can commit and anchor between a
        // stale DB read and the authority read, which resembles a rollback.
        for _ in 0..8 {
            let authority_before = authority
                .load(&self.handle.expected_provider_id)
                .map_err(|error| StoreError::RollbackAuthorityUnavailable(error.to_string()))?
                .ok_or(StoreError::RollbackFloorMissing)?;
            let identity = read_identity(connection)?;
            let database_floor = RollbackFloorV1::from_identity(&identity);
            let authority_after = authority
                .load(&self.handle.expected_provider_id)
                .map_err(|error| StoreError::RollbackAuthorityUnavailable(error.to_string()))?
                .ok_or(StoreError::RollbackFloorMissing)?;
            if authority_before != authority_after {
                continue;
            }
            let authority_floor = authority_after;
            authority_floor.validate()?;
            validate_floor_identity(&authority_floor, &database_floor)?;

            return match database_floor
                .store_generation
                .cmp(&authority_floor.store_generation)
            {
                std::cmp::Ordering::Less => Err(StoreError::RollbackDetected {
                    database_generation: database_floor.store_generation,
                    authority_generation: authority_floor.store_generation,
                }),
                std::cmp::Ordering::Equal => {
                    validate_exact_floor(&authority_floor, &database_floor)
                }
                std::cmp::Ordering::Greater => {
                    if database_floor.store_generation
                        != authority_floor.store_generation.saturating_add(1)
                        || identity.rollback_parent_commitment
                            != authority_floor.rollback_commitment
                        || database_floor.spend_commit_seq < authority_floor.spend_commit_seq
                    {
                        return Err(StoreError::RollbackFork);
                    }
                    let current = authority
                        .compare_and_advance(&authority_floor, &database_floor)
                        .map_err(|error| {
                            StoreError::RollbackAuthorityUnavailable(error.to_string())
                        })?;
                    validate_exact_floor(&current, &database_floor)
                }
            };
        }
        Err(StoreError::RollbackAuthorityUnavailable(
            "rollback floor changed continuously during checked open".to_owned(),
        ))
    }

    /// Must run while the SQLite `BEGIN IMMEDIATE` write lock is held. This
    /// closes the race between the checked open and a concurrent writer.
    fn require_exact_rollback_floor(
        &self,
        identity: &StoreIdentity,
    ) -> StoreResult<RollbackFloorV1> {
        let database_floor = RollbackFloorV1::from_identity(identity);
        let Some(authority) = self.handle.rollback_authority.as_ref() else {
            return Ok(database_floor);
        };
        let current = authority
            .load(&self.handle.expected_provider_id)
            .map_err(|error| StoreError::RollbackAuthorityUnavailable(error.to_string()))?
            .ok_or(StoreError::RollbackFloorMissing)?;
        validate_floor_identity(&current, &database_floor)?;
        if current == database_floor {
            return Ok(current);
        }
        if database_floor.store_generation == current.store_generation.saturating_add(1)
            && identity.rollback_parent_commitment == current.rollback_commitment
            && database_floor.spend_commit_seq >= current.spend_commit_seq
        {
            let anchored = authority
                .compare_and_advance(&current, &database_floor)
                .map_err(|error| StoreError::RollbackAuthorityUnavailable(error.to_string()))?;
            validate_exact_floor(&anchored, &database_floor)?;
            return Ok(database_floor);
        }
        validate_exact_floor(&current, &database_floor)?;
        Ok(current)
    }

    fn anchor_committed_identity(
        &self,
        connection: &Connection,
        expected: &RollbackFloorV1,
        committed: &StoreIdentity,
    ) -> StoreResult<()> {
        let Some(authority) = self.handle.rollback_authority.as_ref() else {
            return Ok(());
        };
        let next = RollbackFloorV1::from_identity(committed);
        let current = authority
            .compare_and_advance(expected, &next)
            .map_err(|error| StoreError::UnanchoredCommit {
                store_generation: next.store_generation,
                authority_error: error.to_string(),
            })?;
        if current == next {
            return Ok(());
        }
        validate_floor_identity(&current, &next).map_err(|error| StoreError::UnanchoredCommit {
            store_generation: next.store_generation,
            authority_error: error.to_string(),
        })?;

        // A later writer on this exact SQLite file may reconcile and advance
        // the linearizable floor after our COMMIT but before our CAS response.
        // Confirm that superseding floor against the same still-open
        // connection which committed `next`. Accepting an arbitrary higher
        // authority floor would be unsafe: a cloned fork could have won and
        // advanced instead.
        if current.store_generation > next.store_generation
            && current.spend_commit_seq >= next.spend_commit_seq
        {
            return self.reconcile_rollback_floor(connection).map_err(|error| {
                StoreError::UnanchoredCommit {
                    store_generation: next.store_generation,
                    authority_error: error.to_string(),
                }
            });
        }

        validate_exact_floor(&current, &next).map_err(|error| StoreError::UnanchoredCommit {
            store_generation: next.store_generation,
            authority_error: error.to_string(),
        })
    }
}

fn validate_floor_identity(
    actual: &RollbackFloorV1,
    expected: &RollbackFloorV1,
) -> StoreResult<()> {
    actual.validate()?;
    expected.validate()?;
    if actual.provider_id != expected.provider_id
        || actual.store_instance_id != expected.store_instance_id
        || actual.schema_version != expected.schema_version
    {
        return Err(StoreError::RollbackFloorIdentityMismatch);
    }
    Ok(())
}

fn validate_exact_floor(actual: &RollbackFloorV1, expected: &RollbackFloorV1) -> StoreResult<()> {
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

fn open_raw_existing(path: &Path) -> StoreResult<Connection> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(StoreError::MissingDatabase(path.to_path_buf()))
        }
        Err(error) => return Err(StoreError::Io(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(StoreError::NotRegularDatabase(path.to_path_buf()));
    }
    // macOS commonly spells its temporary directory through `/var`, which is
    // itself a symlink. SQLite's NOFOLLOW rejects symlinks in any path
    // component, so resolve only the operator-controlled parent and preserve
    // the final filename. The final component is checked above and NOFOLLOW
    // checks it again at sqlite3_open_v2 time.
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or(StoreError::InvalidInput("database path has no filename"))?;
    let open_path = parent.canonicalize()?.join(file_name);
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    Ok(Connection::open_with_flags(open_path, flags)?)
}

fn validate_options(options: StoreOptions) -> StoreResult<()> {
    let milliseconds = options.busy_timeout.as_millis();
    if milliseconds == 0 || milliseconds > MAX_BUSY_TIMEOUT_MILLIS {
        return Err(StoreError::InvalidInput(
            "busy timeout must be in 1ms..=60s",
        ));
    }
    Ok(())
}

fn configure_connection(connection: &Connection, options: StoreOptions) -> StoreResult<()> {
    validate_options(options)?;
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::SchemaMismatch(
            "journal_mode is not WAL".to_owned(),
        ));
    }

    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.busy_timeout(options.busy_timeout)?;

    check_pragma_i64(connection, "synchronous", 2)?;
    check_pragma_i64(connection, "foreign_keys", 1)?;
    check_pragma_i64(connection, "trusted_schema", 0)?;
    check_pragma_i64(connection, "temp_store", 2)?;
    check_pragma_i64(
        connection,
        "busy_timeout",
        i64::try_from(options.busy_timeout.as_millis())
            .map_err(|_| StoreError::InvalidInput("busy timeout exceeds SQLite range"))?,
    )?;
    Ok(())
}

fn check_pragma_i64(connection: &Connection, name: &'static str, expected: i64) -> StoreResult<()> {
    let statement = format!("PRAGMA {name}");
    let actual: i64 = connection.query_row(&statement, [], |row| row.get(0))?;
    if actual != expected {
        return Err(StoreError::SchemaMismatch(format!(
            "checked pragma {name} has unexpected value"
        )));
    }
    Ok(())
}

fn validate_schema(connection: &Connection) -> StoreResult<()> {
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != APPLICATION_ID {
        return Err(StoreError::SchemaMismatch(
            "application_id is unknown".to_owned(),
        ));
    }
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if user_version != i64::from(SCHEMA_VERSION) {
        return Err(StoreError::SchemaMismatch(
            "user_version is unsupported".to_owned(),
        ));
    }

    let mut statement = connection.prepare(
        "SELECT name, sql FROM sqlite_schema \
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != SCHEMA.len() {
        return Err(StoreError::SchemaMismatch(
            "unexpected table set".to_owned(),
        ));
    }
    for ((actual_name, actual_sql), (expected_name, expected_sql)) in rows.iter().zip(SCHEMA) {
        if actual_name != expected_name || normalize_sql(actual_sql) != normalize_sql(expected_sql)
        {
            return Err(StoreError::SchemaMismatch(format!(
                "table {expected_name} does not match schema v{SCHEMA_VERSION}"
            )));
        }
    }

    let explicit_schema_objects: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema \
         WHERE type IN ('index', 'trigger', 'view') AND sql IS NOT NULL",
        [],
        |row| row.get(0),
    )?;
    if explicit_schema_objects != 0 {
        return Err(StoreError::SchemaMismatch(
            "unexpected index, trigger, or view".to_owned(),
        ));
    }

    let identity = read_identity(connection)?;
    if identity.schema_version != SCHEMA_VERSION {
        return Err(StoreError::SchemaMismatch(
            "identity schema_version is unsupported".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_identity(connection: &Connection) -> StoreResult<StoreIdentity> {
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM store_identity", [], |row| row.get(0))?;
    if count != 1 {
        return Err(StoreError::SchemaMismatch(
            "store_identity must contain exactly one row".to_owned(),
        ));
    }
    type RawIdentity = (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, Vec<u8>, i64);
    let raw: RawIdentity = connection.query_row(
        "SELECT store_instance_id, provider_id, store_generation, spend_commit_seq, \
                rollback_parent_commitment, rollback_commitment, schema_version \
         FROM store_identity WHERE singleton = 1",
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
            ))
        },
    )?;
    let identity = StoreIdentity {
        store_instance_id: fixed_blob(raw.0, "invalid store instance id")?,
        provider_id: fixed_blob(raw.1, "invalid provider id")?,
        store_generation: db_u64(raw.2, "negative store generation")?,
        spend_commit_seq: db_u64(raw.3, "negative spend commit sequence")?,
        rollback_parent_commitment: fixed_blob(raw.4, "invalid rollback parent commitment")?,
        rollback_commitment: fixed_blob(raw.5, "invalid rollback commitment")?,
        schema_version: u32::try_from(raw.6).map_err(|_| {
            StoreError::SchemaMismatch("invalid identity schema version".to_owned())
        })?,
    };
    if is_zero(&identity.store_instance_id) {
        return Err(StoreError::SchemaMismatch(
            "store instance id is all zero".to_owned(),
        ));
    }
    if is_zero(&identity.provider_id) {
        return Err(StoreError::SchemaMismatch(
            "provider id is all zero".to_owned(),
        ));
    }
    if identity.spend_commit_seq > identity.store_generation {
        return Err(StoreError::SchemaMismatch(
            "spend sequence exceeds store generation".to_owned(),
        ));
    }
    if is_zero(&identity.rollback_commitment)
        || (identity.store_generation == 0 && !is_zero(&identity.rollback_parent_commitment))
        || (identity.store_generation != 0 && is_zero(&identity.rollback_parent_commitment))
    {
        return Err(StoreError::SchemaMismatch(
            "invalid rollback commitment lineage".to_owned(),
        ));
    }
    Ok(identity)
}

fn verify_expected_provider(
    connection: &Connection,
    expected_provider_id: &[u8; 32],
) -> StoreResult<()> {
    let identity = read_identity(connection)?;
    if &identity.provider_id != expected_provider_id {
        return Err(StoreError::ProviderMismatch);
    }
    let foreign_heads: i64 = connection.query_row(
        "SELECT COUNT(*) FROM policy_heads WHERE provider_id != ?1",
        [expected_provider_id.as_slice()],
        |row| row.get(0),
    )?;
    if foreign_heads != 0 {
        return Err(StoreError::ProviderMismatch);
    }
    Ok(())
}

fn validate_new_namespace(namespace: &NewSpendNamespace) -> StoreResult<()> {
    if is_zero(&namespace.namespace_id) {
        return Err(StoreError::InvalidInput("namespace id is all zero"));
    }
    if is_zero(&namespace.issuer_id) {
        return Err(StoreError::InvalidInput("namespace issuer id is all zero"));
    }
    if is_zero(&namespace.binding_digest) {
        return Err(StoreError::InvalidInput(
            "namespace binding digest is all zero",
        ));
    }
    if namespace.scheme == 0 {
        return Err(StoreError::InvalidInput("namespace scheme is zero"));
    }
    if namespace.key_id.is_empty()
        || namespace.key_id.len() > MAX_KEY_ID_BYTES
        || is_zero(&namespace.key_id)
    {
        return Err(StoreError::InvalidInput(
            "namespace key id must contain 1..=66 bytes",
        ));
    }
    let _ = sql_integer(namespace.not_after, "namespace not_after exceeds i64::MAX")?;
    if let Some(lineage) = namespace.exclusive_key_lineage {
        if is_zero(&lineage.key_fingerprint) {
            return Err(StoreError::InvalidInput(
                "exclusive key fingerprint is all zero",
            ));
        }
        if is_zero(&lineage.lineage_digest) {
            return Err(StoreError::InvalidInput(
                "exclusive key lineage digest is all zero",
            ));
        }
    }
    Ok(())
}

fn read_namespace(
    connection: &Connection,
    namespace_id: &[u8; 32],
) -> StoreResult<Option<SpendNamespace>> {
    type RawNamespace = (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64);
    let raw: Option<RawNamespace> = connection
        .query_row(
            "SELECT scheme, issuer_id, key_id, binding_digest, not_after, status \
             FROM spend_namespaces WHERE namespace_id = ?1",
            [namespace_id.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let scheme = u16::try_from(raw.0)
            .map_err(|_| StoreError::SchemaMismatch("invalid namespace scheme".to_owned()))?;
        if scheme == 0 {
            return Err(StoreError::SchemaMismatch(
                "namespace scheme is zero".to_owned(),
            ));
        }
        let status = NamespaceStatus::from_db(raw.5)
            .ok_or_else(|| StoreError::SchemaMismatch("invalid namespace status".to_owned()))?;
        if raw.2.is_empty() || raw.2.len() > MAX_KEY_ID_BYTES || is_zero(&raw.2) {
            return Err(StoreError::SchemaMismatch(
                "invalid namespace key id".to_owned(),
            ));
        }
        let issuer_id = fixed_blob(raw.1, "invalid namespace issuer id")?;
        let binding_digest = fixed_blob(raw.3, "invalid namespace binding digest")?;
        if is_zero(&issuer_id) || is_zero(&binding_digest) {
            return Err(StoreError::SchemaMismatch(
                "namespace contains an all-zero identity".to_owned(),
            ));
        }
        Ok(SpendNamespace {
            namespace_id: *namespace_id,
            scheme,
            issuer_id,
            key_id: raw.2,
            binding_digest,
            not_after: db_u64(raw.4, "negative namespace expiry")?,
            status,
        })
    })
    .transpose()
}

fn validate_policy_update(update: &PolicyStateUpdate) -> StoreResult<()> {
    if update.head.highest_policy_epoch == 0 {
        return Err(StoreError::InvalidInput("policy epoch is zero"));
    }
    if is_zero(&update.head.policy_digest) {
        return Err(StoreError::InvalidInput("policy digest is all zero"));
    }
    let _ = sql_integer(
        update.head.highest_policy_epoch,
        "policy epoch exceeds SQLite integer range",
    )?;
    if update.head.signed_policy.is_empty()
        || update.head.signed_policy.len() > MAX_SIGNED_POLICY_BYTES
    {
        return Err(StoreError::InvalidInput(
            "signed policy size is outside 1..=64KiB",
        ));
    }
    if update.credential_floors.len() + update.cashu_manifest_floors.len() > MAX_FLOOR_UPDATES {
        return Err(StoreError::InvalidInput("too many epoch floor updates"));
    }

    let mut credential_keys = BTreeSet::new();
    for floor in &update.credential_floors {
        if is_zero(&floor.scope_id) || is_zero(&floor.issuer_id) {
            return Err(StoreError::InvalidInput(
                "credential floor identity is all zero",
            ));
        }
        if floor.scheme == 0 || floor.minimum_epoch == 0 {
            return Err(StoreError::InvalidInput(
                "credential floor scheme and epoch must be nonzero",
            ));
        }
        let _ = sql_integer(
            floor.minimum_epoch,
            "credential epoch exceeds SQLite integer range",
        )?;
        if !credential_keys.insert((floor.scope_id, floor.scheme, floor.issuer_id)) {
            return Err(StoreError::InvalidInput(
                "duplicate credential floor key in one update",
            ));
        }
    }

    let mut cashu_keys = BTreeSet::new();
    for floor in &update.cashu_manifest_floors {
        if is_zero(&floor.mint_id) {
            return Err(StoreError::InvalidInput("Cashu mint id is all zero"));
        }
        validate_cashu_unit(&floor.unit)?;
        if floor.minimum_epoch == 0 {
            return Err(StoreError::InvalidInput(
                "Cashu manifest floor epoch is zero",
            ));
        }
        let _ = sql_integer(
            floor.minimum_epoch,
            "Cashu manifest epoch exceeds SQLite integer range",
        )?;
        if !cashu_keys.insert((floor.mint_id, floor.unit.clone())) {
            return Err(StoreError::InvalidInput(
                "duplicate Cashu floor key in one update",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_cashu_unit(unit: &str) -> StoreResult<()> {
    if pir_service_protocol::validate_cashu_unit_v1(unit).is_err() {
        return Err(StoreError::InvalidInput(
            "Cashu unit must match the canonical V1 unit alphabet",
        ));
    }
    Ok(())
}

fn read_policy_head(
    connection: &Connection,
    provider_id: &[u8; 32],
) -> StoreResult<Option<PolicyHead>> {
    let raw: Option<(i64, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT highest_policy_epoch, policy_digest, signed_policy \
             FROM policy_heads WHERE provider_id = ?1",
            [provider_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    raw.map(|raw| {
        if raw.2.is_empty() || raw.2.len() > MAX_SIGNED_POLICY_BYTES {
            return Err(StoreError::SchemaMismatch(
                "invalid persisted signed policy length".to_owned(),
            ));
        }
        let highest_policy_epoch = db_u64(raw.0, "invalid policy epoch")?;
        let policy_digest = fixed_blob(raw.1, "invalid policy digest")?;
        if highest_policy_epoch == 0 || is_zero(&policy_digest) {
            return Err(StoreError::SchemaMismatch(
                "persisted policy head contains a zero sentinel".to_owned(),
            ));
        }
        Ok(PolicyHead {
            highest_policy_epoch,
            policy_digest,
            signed_policy: raw.2,
        })
    })
    .transpose()
}

fn sql_integer(value: u64, reason: &'static str) -> StoreResult<i64> {
    i64::try_from(value).map_err(|_| StoreError::InvalidInput(reason))
}

fn db_u64(value: i64, reason: &'static str) -> StoreResult<u64> {
    u64::try_from(value).map_err(|_| StoreError::SchemaMismatch(reason.to_owned()))
}

fn fixed_blob<const N: usize>(value: Vec<u8>, reason: &'static str) -> StoreResult<[u8; N]> {
    value
        .try_into()
        .map_err(|_| StoreError::SchemaMismatch(reason.to_owned()))
}

fn is_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn mutation_digest(kind: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BitcoinPIR/provider-store-mutation-payload/v1");
    hasher.update((kind.len() as u16).to_le_bytes());
    hasher.update(kind);
    hasher.update((parts.len() as u16).to_le_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn policy_update_mutation_digest(update: &PolicyStateUpdate) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BitcoinPIR/provider-store-policy-update/v1");
    hasher.update(update.head.highest_policy_epoch.to_le_bytes());
    hasher.update(update.head.policy_digest);
    hasher.update((update.head.signed_policy.len() as u64).to_le_bytes());
    hasher.update(&update.head.signed_policy);
    hasher.update((update.credential_floors.len() as u64).to_le_bytes());
    for floor in &update.credential_floors {
        hasher.update(floor.scope_id);
        hasher.update(floor.scheme.to_le_bytes());
        hasher.update(floor.issuer_id);
        hasher.update(floor.minimum_epoch.to_le_bytes());
    }
    hasher.update((update.cashu_manifest_floors.len() as u64).to_le_bytes());
    for floor in &update.cashu_manifest_floors {
        hasher.update(floor.mint_id);
        hasher.update((floor.unit.len() as u64).to_le_bytes());
        hasher.update(floor.unit.as_bytes());
        hasher.update(floor.minimum_epoch.to_le_bytes());
    }
    hasher.finalize().into()
}

fn advance_store_generation(
    connection: &Connection,
    expected_provider_id: &[u8; 32],
    previous: &StoreIdentity,
    mutation_kind: &[u8],
    mutation_digest: &[u8; 32],
    increment_spend_sequence: bool,
) -> StoreResult<StoreIdentity> {
    let next_generation = previous
        .store_generation
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(StoreError::StoreGenerationExhausted)?;
    let next_spend_sequence = if increment_spend_sequence {
        previous
            .spend_commit_seq
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(StoreError::SpendSequenceExhausted)?
    } else {
        previous.spend_commit_seq
    };
    let next_commitment = rollback::next_commitment(
        &previous.rollback_commitment,
        next_generation,
        mutation_kind,
        mutation_digest,
    );
    let updated = connection.execute(
        "UPDATE store_identity SET \
           store_generation = ?1, spend_commit_seq = ?2, \
           rollback_parent_commitment = ?3, rollback_commitment = ?4 \
         WHERE singleton = 1 AND provider_id = ?5 AND store_generation = ?6 \
           AND spend_commit_seq = ?7 AND rollback_commitment = ?8",
        params![
            sql_integer(
                next_generation,
                "store generation exceeds SQLite integer range"
            )?,
            sql_integer(
                next_spend_sequence,
                "spend sequence exceeds SQLite integer range"
            )?,
            previous.rollback_commitment.as_slice(),
            next_commitment.as_slice(),
            expected_provider_id.as_slice(),
            sql_integer(
                previous.store_generation,
                "store generation exceeds SQLite integer range"
            )?,
            sql_integer(
                previous.spend_commit_seq,
                "spend sequence exceeds SQLite integer range"
            )?,
            previous.rollback_commitment.as_slice(),
        ],
    )?;
    if updated != 1 {
        return Err(StoreError::RollbackFork);
    }
    Ok(StoreIdentity {
        store_instance_id: previous.store_instance_id,
        provider_id: previous.provider_id,
        store_generation: next_generation,
        spend_commit_seq: next_spend_sequence,
        rollback_parent_commitment: previous.rollback_commitment,
        rollback_commitment: next_commitment,
        schema_version: previous.schema_version,
    })
}

fn checkpoint_new_store(connection: &Connection) -> StoreResult<()> {
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) =
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    if busy != 0 || log_frames != checkpointed_frames {
        return Err(StoreError::IntegrityCheckFailed(
            "new store WAL checkpoint did not complete".to_owned(),
        ));
    }
    Ok(())
}

fn sync_parent_directory(path: &Path) -> StoreResult<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

// These low-level persistence tests deliberately exercise malformed and
// synthetic namespaces. Keep them as crate unit tests so the dangerous
// installer is never part of the downstream API.
#[cfg(test)]
extern crate self as pir_service_store;

#[cfg(test)]
mod low_level_store_tests {
    include!("../tests/provider_store.rs");
}

#[cfg(test)]
mod verified_offer_namespace_tests {
    include!("../tests/verified_offer_namespace.rs");
}

#[cfg(test)]
mod rollback_floor_tests {
    include!("../tests/rollback_floor.rs");
}

#[cfg(test)]
mod cashu_swap_v4_tests {
    include!("../tests/cashu_swap_v4.rs");
}

#[cfg(test)]
mod cashu_custody_v7_tests {
    include!("../tests/cashu_custody_v7.rs");
}

#[cfg(test)]
mod free_ip_rate_limit_v5_tests {
    include!("../tests/free_ip_rate_limit_v5.rs");
}
