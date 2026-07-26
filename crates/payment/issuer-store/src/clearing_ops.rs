use crate::db::{
    advance_store_generation, commit, db_u64, fixed_blob, is_zero, sql_integer,
    verify_expected_identity,
};
use crate::rollback::mutation_digest;
use crate::{
    ClearingAuthorizationRecordV1, CommitMarker, DurableWrite, IssuerStore,
    LedgerTransactionKindV1, ProviderLedgerBalanceV1, ProviderSettlementRegistrationRecordV1,
    ProviderSettlementRegistrationWriteV1, RedeemRecordV1, SettlementDepositRecordV1,
    SharedCredentialCryptographicVerifierV1, SharedCredentialSpendSinkV1,
    SharedCredentialVerificationInputV1, StoreError, StoreResult, VerifiedRedeemCommitV1,
    VerifiedSharedIssuerRedeemV1, WriteDisposition, MAX_EXACT_CLEARING_APPROVAL_BYTES,
    MAX_EXACT_CLEARING_AUTHORIZATION_BYTES, MAX_EXACT_REDEEM_REQUEST_BYTES,
    MAX_EXACT_REDEEM_RESPONSE_BYTES, MAX_EXACT_SETTLEMENT_DEPOSIT_REQUEST_BYTES,
    MAX_EXACT_SETTLEMENT_DEPOSIT_RESPONSE_BYTES,
};
use ed25519_dalek::VerifyingKey;
use pir_service_protocol::{
    verify_new_redeem_request_for, AuthScheme, IssuerClearingApprovalV1,
    ProviderClearingAuthorizationV1, ProviderClearingExpectationV1, ProviderClearingRequestAuthV1,
    ProviderRedeemRequestV1, ProviderSettlementDepositRequestV1,
    ProviderSettlementDepositResponseV1, RedeemSettlementResultV1, ServiceProtocolError,
    SettlementDestinationV1, SettlementUnitV1, VerifiedSettlementDepositV1,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

const PROVIDER_REGISTRATION_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/provider-settlement-registration/v1";
const REDEEM_IDEMPOTENCY_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/idempotency/POST-/v1/redeems/v1";
const REDEEM_LEDGER_TRANSACTION_ID_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/redeem-ledger-transaction-id/v1";
const SETTLEMENT_DEPOSIT_IDEMPOTENCY_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/idempotency/POST-/v1/settlement/deposits/v1";
const SETTLEMENT_DEPOSIT_TRANSACTION_ID_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/settlement-deposit-transaction-id/v1";
const SYSTEM_LEDGER_ACCOUNT_ID_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/system-ledger-account-id/v1";

const ACCOUNT_KIND_PROVIDER: i64 = 1;
const ACCOUNT_KIND_CREDENTIAL_SOURCE: i64 = 2;
const ACCOUNT_KIND_ISSUER_FEE: i64 = 3;
const ACCOUNT_KIND_BLIND_LIABILITY: i64 = 4;

const SYSTEM_ACCOUNT_CREDENTIAL_SOURCE: u8 = 1;
const SYSTEM_ACCOUNT_ISSUER_FEE: u8 = 2;
const SYSTEM_ACCOUNT_BLIND_LIABILITY: u8 = 3;

type RawProviderRegistration = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64);

/// Deterministic transaction identity used both when constructing the signed
/// redeem response and when atomically committing its ledger postings.
pub fn issuer_redeem_ledger_transaction_id_v1(
    issuer_id: &[u8; 32],
    request_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REDEEM_LEDGER_TRANSACTION_ID_DOMAIN_V1);
    hasher.update(issuer_id);
    hasher.update(request_digest);
    hasher.finalize().into()
}

pub fn issuer_settlement_deposit_transaction_id_v1(
    issuer_id: &[u8; 32],
    request_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SETTLEMENT_DEPOSIT_TRANSACTION_ID_DOMAIN_V1);
    hasher.update(issuer_id);
    hasher.update(request_digest);
    hasher.finalize().into()
}

/// Composite live verification for a new shared-issuer redemption. Exact
/// committed replays must be looked up before calling this function.
#[allow(clippy::too_many_arguments)]
pub fn verify_shared_issuer_redeem_v1<'a>(
    request: &'a ProviderRedeemRequestV1,
    canonical_credential: &[u8],
    credential_binding: &'a pir_service_protocol::CredentialKeyBindingV1,
    authorization: &'a ProviderClearingAuthorizationV1,
    issuer_approval: &'a IssuerClearingApprovalV1,
    request_auth: &ProviderClearingRequestAuthV1,
    expectation: &ProviderClearingExpectationV1<'_>,
    credential_verifier: &dyn SharedCredentialCryptographicVerifierV1,
) -> StoreResult<VerifiedSharedIssuerRedeemV1<'a>> {
    verify_new_redeem_request_for(
        request,
        canonical_credential,
        credential_binding,
        authorization,
        issuer_approval,
        request_auth,
        expectation,
    )?;
    if expectation.now_unix == 0 {
        return Err(StoreError::InvalidInput(
            "clearing verification time is zero",
        ));
    }
    let binding_digest = credential_binding.binding_digest()?;
    let mut sink = CapturingSpendSinkV1 {
        expected_scheme: request.scheme,
        expected_binding_digest: binding_digest,
        spend_key: None,
    };
    credential_verifier.verify_shared_credential_v1(
        SharedCredentialVerificationInputV1 {
            request,
            canonical_credential,
            credential_binding,
            now_unix: expectation.now_unix,
        },
        &mut sink,
    )?;
    let spend_key = sink.spend_key.ok_or(StoreError::InvalidInput(
        "shared credential verifier did not return a verified spend",
    ))?;
    let rule = authorization
        .rule_for_binding(&request.credential_binding_digest)
        .ok_or(StoreError::InvalidInput(
            "verified clearing authorization lost its settlement rule",
        ))?;
    Ok(VerifiedSharedIssuerRedeemV1 {
        request,
        credential_binding,
        authorization,
        issuer_approval,
        spend_key,
        unit: rule.unit,
        provider_credit: rule.provider_credit,
        issuer_fee: rule.issuer_fee,
        now_unix: expectation.now_unix,
    })
}

struct CapturingSpendSinkV1 {
    expected_scheme: AuthScheme,
    expected_binding_digest: [u8; 32],
    spend_key: Option<[u8; 32]>,
}

impl SharedCredentialSpendSinkV1 for CapturingSpendSinkV1 {
    fn accept_verified_spend_v1(
        &mut self,
        scheme: AuthScheme,
        credential_binding_digest: &[u8; 32],
        spend_key: &[u8; 32],
    ) -> Result<(), ServiceProtocolError> {
        if self.spend_key.is_some() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "SharedCredentialCryptographicVerifierV1",
                reason: "verifier called the verified-spend sink more than once",
            });
        }
        if scheme != self.expected_scheme
            || credential_binding_digest != &self.expected_binding_digest
            || is_zero(spend_key)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "SharedCredentialCryptographicVerifierV1",
                reason: "verifier returned a mismatched scheme, binding, or zero spend key",
            });
        }
        self.spend_key = Some(*spend_key);
        Ok(())
    }
}

impl IssuerStore {
    /// Installs or rotates trusted provider settlement configuration. Account
    /// and payout target identities are immutable; only the request key and
    /// validity window may rotate at a strictly increasing epoch.
    pub fn register_provider_settlement(
        &self,
        registration: &ProviderSettlementRegistrationWriteV1,
    ) -> StoreResult<DurableWrite<ProviderSettlementRegistrationRecordV1>> {
        let candidate = build_provider_registration(self, registration)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        if let Some(existing) =
            read_provider_registration(&transaction, self, &candidate.provider_id)?
        {
            if provider_registration_matches(&existing, &candidate) {
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.commit,
                    value: existing,
                });
            }
            if registration.registration_epoch < existing.registration_epoch {
                return Err(StoreError::ProviderRegistrationRollback);
            }
            if registration.registration_epoch == existing.registration_epoch
                || registration.settlement_account_id != existing.settlement_account_id
                || registration.payout_target_id != existing.payout_target_id
            {
                return Err(StoreError::ProviderRegistrationFork);
            }
        }

        let digest = mutation_digest(
            b"register-provider-settlement-v1",
            &[
                &candidate.provider_id,
                &candidate.registration_digest,
                &candidate.registration_epoch.to_le_bytes(),
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"register-provider-settlement-v1",
            &digest,
        )?;
        let sequence = committed_identity.commit_seq;
        transaction.execute(
            "INSERT INTO provider_registrations (issuer_id, provider_id, registration_epoch, \
             registration_digest, settlement_account_id, provider_request_verifying_key, \
             payout_target_id, not_before, not_after, commit_seq) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
             ON CONFLICT(provider_id) DO UPDATE SET registration_epoch = excluded.registration_epoch, \
             registration_digest = excluded.registration_digest, \
             provider_request_verifying_key = excluded.provider_request_verifying_key, \
             not_before = excluded.not_before, not_after = excluded.not_after, \
             commit_seq = excluded.commit_seq",
            params![
                self.handle.expected_issuer_id.as_slice(),
                candidate.provider_id.as_slice(),
                sql_integer(candidate.registration_epoch, "registration epoch exceeds SQLite range")?,
                candidate.registration_digest.as_slice(),
                candidate.settlement_account_id.as_slice(),
                candidate.provider_request_verifying_key.as_slice(),
                candidate.payout_target_id.as_slice(),
                sql_integer(candidate.not_before, "registration not_before exceeds SQLite range")?,
                sql_integer(candidate.not_after, "registration not_after exceeds SQLite range")?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO provider_registration_history (issuer_id, provider_id, \
             registration_epoch, registration_digest, settlement_account_id, \
             provider_request_verifying_key, payout_target_id, not_before, not_after, \
             commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                self.handle.expected_issuer_id.as_slice(),
                candidate.provider_id.as_slice(),
                sql_integer(
                    candidate.registration_epoch,
                    "registration epoch exceeds SQLite range"
                )?,
                candidate.registration_digest.as_slice(),
                candidate.settlement_account_id.as_slice(),
                candidate.provider_request_verifying_key.as_slice(),
                candidate.payout_target_id.as_slice(),
                sql_integer(
                    candidate.not_before,
                    "registration not_before exceeds SQLite range"
                )?,
                sql_integer(
                    candidate.not_after,
                    "registration not_after exceeds SQLite range"
                )?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO ledger_accounts (account_id, issuer_id, provider_id, unit, \
             available_value, reserved_value, ledger_sequence, commit_seq) \
             VALUES (?1, ?2, ?3, ?4, 0, 0, 0, ?5) \
             ON CONFLICT(account_id) DO UPDATE SET commit_seq = excluded.commit_seq",
            params![
                candidate.settlement_account_id.as_slice(),
                self.handle.expected_issuer_id.as_slice(),
                candidate.provider_id.as_slice(),
                SettlementUnitV1::AuthCredit as u8,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let value = self
            .provider_settlement_registration(&candidate.provider_id)?
            .ok_or_else(|| {
                StoreError::SchemaMismatch("committed provider registration missing".to_owned())
            })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value,
        })
    }

    pub fn provider_settlement_registration(
        &self,
        provider_id: &[u8; 32],
    ) -> StoreResult<Option<ProviderSettlementRegistrationRecordV1>> {
        if is_zero(provider_id) {
            return Err(StoreError::InvalidInput("provider id is all zero"));
        }
        let connection = self.open_checked(false)?;
        let value = read_provider_registration(&connection, self, provider_id)?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Reads one retained provider registration by its canonical digest.
    ///
    /// This history is recovery-only trust state. Callers must not use it for
    /// a fresh request or any new ledger/payout mutation; the settlement
    /// service consults it only after proving that the exact status response
    /// bytes for the same request digest are already durable.
    pub fn historical_provider_settlement_registration(
        &self,
        provider_id: &[u8; 32],
        registration_digest: &[u8; 32],
    ) -> StoreResult<Option<ProviderSettlementRegistrationRecordV1>> {
        if is_zero(provider_id) || is_zero(registration_digest) {
            return Err(StoreError::InvalidInput(
                "provider id or registration digest is all zero",
            ));
        }
        let connection = self.open_checked(false)?;
        let value = read_provider_registration_history(
            &connection,
            self,
            provider_id,
            registration_digest,
        )?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Persists the operator authorization and issuer countersignature. An
    /// exact historical replay is recoverable; new debt can only use the
    /// highest registered epoch for that provider.
    pub fn register_clearing_authorization(
        &self,
        authorization: &ProviderClearingAuthorizationV1,
        approval: &IssuerClearingApprovalV1,
        expected_operator_key: &VerifyingKey,
        issuer_settlement_key: &VerifyingKey,
        now_unix: u64,
    ) -> StoreResult<DurableWrite<ClearingAuthorizationRecordV1>> {
        if now_unix == 0 {
            return Err(StoreError::InvalidInput(
                "clearing registration time is zero",
            ));
        }
        let exact_authorization = authorization.encode()?;
        let exact_approval = approval.encode();
        if exact_authorization.len() > MAX_EXACT_CLEARING_AUTHORIZATION_BYTES
            || exact_approval.len() > MAX_EXACT_CLEARING_APPROVAL_BYTES
        {
            return Err(StoreError::InvalidInput(
                "clearing authorization encoding exceeds store bound",
            ));
        }
        let authorization_digest = authorization.authorization_digest()?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        if let Some(existing) =
            read_clearing_authorization(&transaction, self, &authorization_digest)?
        {
            if existing.exact_authorization == exact_authorization
                && existing.exact_approval == exact_approval
            {
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.commit,
                    value: existing,
                });
            }
            return Err(StoreError::ClearingAuthorizationFork);
        }
        let highest_epoch: Option<i64> = transaction.query_row(
            "SELECT MAX(authorization_epoch) FROM clearing_authorizations \
             WHERE issuer_id = ?1 AND provider_id = ?2",
            params![
                self.handle.expected_issuer_id.as_slice(),
                authorization.claims.provider_id.as_slice(),
            ],
            |row| row.get(0),
        )?;
        let highest_epoch = highest_epoch
            .map(|value| db_u64(value, "negative clearing authorization epoch"))
            .transpose()?
            .unwrap_or(0);
        if authorization.claims.authorization_epoch < highest_epoch {
            return Err(StoreError::ClearingAuthorizationRollback);
        }
        if authorization.claims.authorization_epoch == highest_epoch && highest_epoch != 0 {
            return Err(StoreError::ClearingAuthorizationFork);
        }
        authorization.verify_for(
            &authorization.claims.provider_id,
            &self.handle.expected_issuer_id,
            expected_operator_key,
            now_unix,
            highest_epoch,
        )?;
        approval.verify_for(
            authorization,
            issuer_settlement_key,
            now_unix,
            highest_epoch,
        )?;

        let digest = mutation_digest(
            b"register-clearing-authorization-v1",
            &[
                &authorization_digest,
                &authorization.claims.provider_id,
                &authorization.claims.authorization_epoch.to_le_bytes(),
                &exact_approval,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"register-clearing-authorization-v1",
            &digest,
        )?;
        let sequence = committed_identity.commit_seq;
        transaction.execute(
            "INSERT INTO clearing_authorizations (authorization_digest, issuer_id, provider_id, \
             authorization_epoch, exact_authorization, exact_approval, not_after, commit_seq) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                authorization_digest.as_slice(),
                self.handle.expected_issuer_id.as_slice(),
                authorization.claims.provider_id.as_slice(),
                sql_integer(
                    authorization.claims.authorization_epoch,
                    "clearing authorization epoch exceeds SQLite range",
                )?,
                exact_authorization.as_slice(),
                exact_approval.as_slice(),
                sql_integer(
                    approval.not_after,
                    "clearing approval expiry exceeds SQLite range"
                )?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let value = self
            .clearing_authorization(&authorization_digest)?
            .ok_or_else(|| {
                StoreError::SchemaMismatch("committed clearing authorization missing".to_owned())
            })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value,
        })
    }

    pub fn clearing_authorization(
        &self,
        authorization_digest: &[u8; 32],
    ) -> StoreResult<Option<ClearingAuthorizationRecordV1>> {
        if is_zero(authorization_digest) {
            return Err(StoreError::InvalidInput(
                "clearing authorization digest is all zero",
            ));
        }
        let connection = self.open_checked(false)?;
        let value = read_clearing_authorization(&connection, self, authorization_digest)?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Read-before-live-verification path for exact HTTP recovery. A reused
    /// idempotency key with different request bytes fails; a committed exact
    /// replay remains available after credential/auth expiry.
    pub fn redeem_by_idempotency(
        &self,
        request: &ProviderRedeemRequestV1,
    ) -> StoreResult<Option<RedeemRecordV1>> {
        let idempotency_digest = redeem_idempotency_digest(self, &request.idempotency_key);
        let request_digest = request.request_digest()?;
        let replay_image = redeem_request_replay_image(self, request)?;
        let connection = self.open_checked(false)?;
        let value = read_redeem(&connection, self, &idempotency_digest)?;
        if let Some(record) = &value {
            if record.request_digest != request_digest
                || record.exact_request_replay_image != replay_image
            {
                return Err(StoreError::RedeemIdempotencyConflict);
            }
        }
        self.confirm_anchored_read(&connection, value)
    }

    /// Atomically marks the credential globally spent, writes a balanced
    /// ledger transaction, updates provider credit when applicable, and
    /// stores the exact signed response before it can be released.
    pub fn commit_redeem(
        &self,
        verified: &VerifiedRedeemCommitV1<'_, '_>,
    ) -> StoreResult<DurableWrite<RedeemRecordV1>> {
        let redeem = &verified.redeem;
        let request = redeem.request;
        let response = verified.response.response();
        validate_redeem_pair(self, redeem, response)?;
        let idempotency_digest = redeem_idempotency_digest(self, &request.idempotency_key);
        let request_digest = request.request_digest()?;
        let replay_image = redeem_request_replay_image(self, request)?;
        let exact_response = response.encode()?;
        if replay_image.len() > MAX_EXACT_REDEEM_REQUEST_BYTES
            || exact_response.len() > MAX_EXACT_REDEEM_RESPONSE_BYTES
        {
            return Err(StoreError::InvalidInput(
                "redeem encoding exceeds store bound",
            ));
        }
        let ledger_transaction_id = issuer_redeem_ledger_transaction_id_v1(
            &self.handle.expected_issuer_id,
            &request_digest,
        );

        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        if let Some(existing) = read_redeem(&transaction, self, &idempotency_digest)? {
            if existing.request_digest == request_digest
                && existing.exact_request_replay_image == replay_image
                && existing.exact_response == exact_response
            {
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.commit,
                    value: existing,
                });
            }
            return Err(StoreError::RedeemIdempotencyConflict);
        }
        let spent: Option<i64> = transaction
            .query_row(
                "SELECT 1 FROM redemptions WHERE credential_spend_key = ?1",
                params![redeem.spend_key.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if spent.is_some() {
            return Err(StoreError::CredentialAlreadySpent);
        }
        require_current_registered_authorization(&transaction, self, redeem)?;
        require_registered_credential_lineage(&transaction, self, redeem)?;
        require_registered_redeem_settlement_lineage(&transaction, self, redeem)?;
        let registration = read_provider_registration(&transaction, self, &request.provider_id)?
            .ok_or(StoreError::InvalidInput(
                "provider settlement registration is missing",
            ))?;
        if registration.settlement_account_id != redeem.authorization.claims.settlement_account_id {
            return Err(StoreError::InvalidInput(
                "clearing authorization account differs from provider registration",
            ));
        }

        let mutation = mutation_digest(
            b"commit-shared-redeem-v1",
            &[
                &idempotency_digest,
                &request_digest,
                &redeem.spend_key,
                &ledger_transaction_id,
                &exact_response,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"commit-shared-redeem-v1",
            &mutation,
        )?;
        let sequence = committed_identity.commit_seq;
        let (destination_kind, transaction_kind) = match &request.destination {
            SettlementDestinationV1::LedgerCredit { account_id } => {
                if account_id != &registration.settlement_account_id {
                    return Err(StoreError::InvalidInput(
                        "redeem ledger destination is not the registered account",
                    ));
                }
                let _ledger_sequence = credit_provider_account(
                    &transaction,
                    self,
                    &registration,
                    redeem.provider_credit,
                    sequence,
                )?;
                (1i64, LedgerTransactionKindV1::RedeemLedgerCredit)
            }
            SettlementDestinationV1::BlindOutputs { .. } => {
                (2i64, LedgerTransactionKindV1::RedeemBlindLiability)
            }
        };
        insert_redeem_ledger_transaction(
            &transaction,
            self,
            redeem,
            &registration,
            transaction_kind,
            &ledger_transaction_id,
            &request_digest,
            sequence,
        )?;
        transaction.execute(
            "INSERT INTO redemptions (idempotency_digest, request_digest, issuer_id, provider_id, \
             authorization_digest, credential_binding_digest, scheme, credential_digest, \
             credential_spend_key, accepted_value, provider_credit, issuer_fee, unit, \
             destination_kind, ledger_transaction_id, request_replay_image, exact_response, \
             redeemed_at, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, \
             ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                idempotency_digest.as_slice(),
                request_digest.as_slice(),
                self.handle.expected_issuer_id.as_slice(),
                request.provider_id.as_slice(),
                request.authorization_digest.as_slice(),
                request.credential_binding_digest.as_slice(),
                request.scheme as u8,
                request.credential_digest.as_slice(),
                redeem.spend_key.as_slice(),
                sql_integer(
                    request.accepted_value,
                    "accepted value exceeds SQLite range"
                )?,
                sql_integer(
                    redeem.provider_credit,
                    "provider credit exceeds SQLite range"
                )?,
                sql_integer(redeem.issuer_fee, "issuer fee exceeds SQLite range")?,
                redeem.unit as u8,
                destination_kind,
                ledger_transaction_id.as_slice(),
                replay_image.as_slice(),
                exact_response.as_slice(),
                sql_integer(redeem.now_unix, "redeem time exceeds SQLite range")?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let value = self
            .redeem_by_idempotency(request)?
            .ok_or_else(|| StoreError::SchemaMismatch("committed redeem missing".to_owned()))?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value,
        })
    }

    pub fn provider_ledger_balance(
        &self,
        provider_id: &[u8; 32],
    ) -> StoreResult<Option<ProviderLedgerBalanceV1>> {
        if is_zero(provider_id) {
            return Err(StoreError::InvalidInput("provider id is all zero"));
        }
        let connection = self.open_checked(false)?;
        let value = read_provider_balance(&connection, self, provider_id)?;
        self.confirm_anchored_read(&connection, value)
    }

    pub fn settlement_deposit_by_idempotency(
        &self,
        request: &ProviderSettlementDepositRequestV1,
    ) -> StoreResult<Option<SettlementDepositRecordV1>> {
        let idempotency_digest =
            settlement_deposit_idempotency_digest(self, &request.idempotency_key);
        let request_digest = request.request_digest()?;
        let replay_image = settlement_deposit_replay_image(self, request)?;
        let connection = self.open_checked(false)?;
        let value = read_settlement_deposit(&connection, self, &idempotency_digest)?;
        if let Some(record) = &value {
            if record.request_digest != request_digest
                || record.exact_request_replay_image != replay_image
            {
                return Err(StoreError::SettlementDepositIdempotencyConflict);
            }
        }
        self.confirm_anchored_read(&connection, value)
    }

    /// Atomically consumes every verified blind settlement note and transfers
    /// the corresponding blind liability into the provider's identified
    /// ledger account. No partial note insertion or credit is possible.
    pub fn commit_settlement_deposit(
        &self,
        verified: &VerifiedSettlementDepositV1<'_>,
        response: &ProviderSettlementDepositResponseV1,
        issuer_settlement_key: &VerifyingKey,
        now_unix: u64,
    ) -> StoreResult<DurableWrite<SettlementDepositRecordV1>> {
        if now_unix == 0 {
            return Err(StoreError::InvalidInput("settlement deposit time is zero"));
        }
        let request = verified.request();
        response.verify_for_exact_request(request, issuer_settlement_key)?;
        let request_digest = request.request_digest()?;
        let transaction_id = issuer_settlement_deposit_transaction_id_v1(
            &self.handle.expected_issuer_id,
            &request_digest,
        );
        if response.ledger_transaction_id != transaction_id {
            return Err(StoreError::InvalidInput(
                "settlement deposit response has a non-deterministic transaction id",
            ));
        }
        let idempotency_digest =
            settlement_deposit_idempotency_digest(self, &request.idempotency_key);
        let replay_image = settlement_deposit_replay_image(self, request)?;
        let exact_response = response.encode()?;
        if replay_image.len() > MAX_EXACT_SETTLEMENT_DEPOSIT_REQUEST_BYTES
            || exact_response.len() > MAX_EXACT_SETTLEMENT_DEPOSIT_RESPONSE_BYTES
        {
            return Err(StoreError::InvalidInput(
                "settlement deposit encoding exceeds store bound",
            ));
        }

        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        if let Some(existing) = read_settlement_deposit(&transaction, self, &idempotency_digest)? {
            if existing.request_digest == request_digest
                && existing.exact_request_replay_image == replay_image
                && existing.exact_response == exact_response
            {
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.commit,
                    value: existing,
                });
            }
            return Err(StoreError::SettlementDepositIdempotencyConflict);
        }
        let registration = read_provider_registration(&transaction, self, &request.provider_id)?
            .ok_or(StoreError::InvalidInput(
                "provider settlement registration is missing",
            ))?;
        if request.issuer_id != self.handle.expected_issuer_id
            || request.registration_digest != registration.registration_digest
            || request.account_id != registration.settlement_account_id
            || request.unit != SettlementUnitV1::AuthCredit
        {
            return Err(StoreError::InvalidInput(
                "settlement deposit does not match current provider registration",
            ));
        }
        for note in verified.notes() {
            let spent: Option<i64> = transaction
                .query_row(
                    "SELECT 1 FROM settlement_note_spends WHERE spend_key = ?1",
                    params![note.spend_key().as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            if spent.is_some() {
                return Err(StoreError::SettlementNoteAlreadySpent);
            }
            require_settlement_key_lineage_row(
                &transaction,
                self,
                verified.keyset_id(),
                note.denomination(),
                note.denomination_public_key(),
            )?;
        }

        let mutation = mutation_digest(
            b"commit-settlement-deposit-v1",
            &[
                &idempotency_digest,
                &request_digest,
                &transaction_id,
                &exact_response,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"commit-settlement-deposit-v1",
            &mutation,
        )?;
        let sequence = committed_identity.commit_seq;
        let ledger_sequence = credit_provider_account(
            &transaction,
            self,
            &registration,
            request.total_value,
            sequence,
        )?;
        if ledger_sequence != response.ledger_sequence {
            return Err(StoreError::SettlementLedgerSequenceConflict);
        }
        insert_deposit_ledger_transaction(
            &transaction,
            self,
            request,
            &registration,
            &transaction_id,
            &request_digest,
            now_unix,
            sequence,
        )?;
        transaction.execute(
            "INSERT INTO settlement_deposits (idempotency_digest, request_digest, issuer_id, \
             registration_digest, provider_id, account_id, unit, settlement_keyset_id, \
             total_value, ledger_transaction_id, ledger_sequence, request_replay_image, \
             exact_response, deposited_at, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, \
             ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                idempotency_digest.as_slice(),
                request_digest.as_slice(),
                self.handle.expected_issuer_id.as_slice(),
                request.registration_digest.as_slice(),
                request.provider_id.as_slice(),
                request.account_id.as_slice(),
                request.unit as u8,
                &request.settlement_keyset_id,
                sql_integer(request.total_value, "deposit value exceeds SQLite range")?,
                transaction_id.as_slice(),
                sql_integer(ledger_sequence, "ledger sequence exceeds SQLite range")?,
                replay_image.as_slice(),
                exact_response.as_slice(),
                sql_integer(now_unix, "deposit time exceeds SQLite range")?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        for note in verified.notes() {
            transaction.execute(
                "INSERT INTO settlement_note_spends (spend_key, issuer_id, settlement_keyset_id, \
                 denomination, presentation_digest, deposit_idempotency_digest, commit_seq) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    note.spend_key().as_slice(),
                    self.handle.expected_issuer_id.as_slice(),
                    verified.keyset_id(),
                    sql_integer(
                        note.denomination(),
                        "note denomination exceeds SQLite range"
                    )?,
                    note.presentation_digest().as_slice(),
                    idempotency_digest.as_slice(),
                    sql_integer(sequence, "commit sequence exceeds SQLite range")?,
                ],
            )?;
        }
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let value = self
            .settlement_deposit_by_idempotency(request)?
            .ok_or_else(|| {
                StoreError::SchemaMismatch("committed settlement deposit missing".to_owned())
            })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value,
        })
    }
}

fn build_provider_registration(
    store: &IssuerStore,
    value: &ProviderSettlementRegistrationWriteV1,
) -> StoreResult<ProviderSettlementRegistrationRecordV1> {
    if value.registration_epoch == 0
        || is_zero(&value.provider_id)
        || is_zero(&value.settlement_account_id)
        || is_zero(&value.provider_request_verifying_key)
        || is_zero(&value.payout_target_id)
        || value.not_before == 0
        || value.not_after < value.not_before
    {
        return Err(StoreError::InvalidInput(
            "invalid provider settlement registration",
        ));
    }
    VerifyingKey::from_bytes(&value.provider_request_verifying_key)
        .map_err(|_| StoreError::InvalidInput("invalid provider settlement request key"))?;
    let _ = sql_integer(
        value.registration_epoch,
        "registration epoch exceeds SQLite range",
    )?;
    let _ = sql_integer(
        value.not_before,
        "registration not_before exceeds SQLite range",
    )?;
    let _ = sql_integer(
        value.not_after,
        "registration not_after exceeds SQLite range",
    )?;
    let registration_digest = provider_registration_digest(store, value);
    Ok(ProviderSettlementRegistrationRecordV1 {
        registration_epoch: value.registration_epoch,
        registration_digest,
        provider_id: value.provider_id,
        settlement_account_id: value.settlement_account_id,
        provider_request_verifying_key: value.provider_request_verifying_key,
        payout_target_id: value.payout_target_id,
        not_before: value.not_before,
        not_after: value.not_after,
        commit: marker(store, 1),
    })
}

fn provider_registration_digest(
    store: &IssuerStore,
    value: &ProviderSettlementRegistrationWriteV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_REGISTRATION_DIGEST_DOMAIN_V1);
    hasher.update(store.handle.expected_issuer_id);
    hasher.update(value.registration_epoch.to_le_bytes());
    hasher.update(value.provider_id);
    hasher.update(value.settlement_account_id);
    hasher.update(value.provider_request_verifying_key);
    hasher.update(value.payout_target_id);
    hasher.update(value.not_before.to_le_bytes());
    hasher.update(value.not_after.to_le_bytes());
    hasher.finalize().into()
}

fn read_provider_registration(
    connection: &Connection,
    store: &IssuerStore,
    provider_id: &[u8; 32],
) -> StoreResult<Option<ProviderSettlementRegistrationRecordV1>> {
    let raw: Option<RawProviderRegistration> = connection
        .query_row(
            "SELECT registration_epoch, registration_digest, settlement_account_id, \
             provider_request_verifying_key, payout_target_id, not_before, not_after, commit_seq \
             FROM provider_registrations WHERE issuer_id = ?1 AND provider_id = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                provider_id.as_slice(),
            ],
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
                ))
            },
        )
        .optional()?;
    let record = raw
        .map(|raw| decode_provider_registration(store, *provider_id, raw))
        .transpose()?;
    if let Some(record) = &record {
        let historical = read_provider_registration_history(
            connection,
            store,
            provider_id,
            &record.registration_digest,
        )?;
        if historical.as_ref() != Some(record) {
            return Err(StoreError::SchemaMismatch(
                "current provider registration is missing from retained history".to_owned(),
            ));
        }
    }
    Ok(record)
}

fn read_provider_registration_history(
    connection: &Connection,
    store: &IssuerStore,
    provider_id: &[u8; 32],
    registration_digest: &[u8; 32],
) -> StoreResult<Option<ProviderSettlementRegistrationRecordV1>> {
    let raw: Option<RawProviderRegistration> = connection
        .query_row(
            "SELECT registration_epoch, registration_digest, settlement_account_id, \
             provider_request_verifying_key, payout_target_id, not_before, not_after, commit_seq \
             FROM provider_registration_history WHERE issuer_id = ?1 AND provider_id = ?2 \
             AND registration_digest = ?3",
            params![
                store.handle.expected_issuer_id.as_slice(),
                provider_id.as_slice(),
                registration_digest.as_slice(),
            ],
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
                ))
            },
        )
        .optional()?;
    raw.map(|raw| decode_provider_registration(store, *provider_id, raw))
        .transpose()
}

fn decode_provider_registration(
    store: &IssuerStore,
    provider_id: [u8; 32],
    raw: RawProviderRegistration,
) -> StoreResult<ProviderSettlementRegistrationRecordV1> {
    let record = ProviderSettlementRegistrationRecordV1 {
        registration_epoch: db_u64(raw.0, "negative registration epoch")?,
        registration_digest: fixed_blob(raw.1, "invalid registration digest")?,
        provider_id,
        settlement_account_id: fixed_blob(raw.2, "invalid settlement account id")?,
        provider_request_verifying_key: fixed_blob(raw.3, "invalid provider request key")?,
        payout_target_id: fixed_blob(raw.4, "invalid payout target id")?,
        not_before: db_u64(raw.5, "negative registration not_before")?,
        not_after: db_u64(raw.6, "negative registration not_after")?,
        commit: marker(store, db_u64(raw.7, "negative registration commit")?),
    };
    let rebuilt = build_provider_registration(
        store,
        &ProviderSettlementRegistrationWriteV1 {
            registration_epoch: record.registration_epoch,
            provider_id: record.provider_id,
            settlement_account_id: record.settlement_account_id,
            provider_request_verifying_key: record.provider_request_verifying_key,
            payout_target_id: record.payout_target_id,
            not_before: record.not_before,
            not_after: record.not_after,
        },
    )?;
    if !provider_registration_matches(&record, &rebuilt) {
        return Err(StoreError::SchemaMismatch(
            "provider settlement registration digest mismatch".to_owned(),
        ));
    }
    Ok(record)
}

fn provider_registration_matches(
    left: &ProviderSettlementRegistrationRecordV1,
    right: &ProviderSettlementRegistrationRecordV1,
) -> bool {
    left.registration_epoch == right.registration_epoch
        && left.registration_digest == right.registration_digest
        && left.provider_id == right.provider_id
        && left.settlement_account_id == right.settlement_account_id
        && left.provider_request_verifying_key == right.provider_request_verifying_key
        && left.payout_target_id == right.payout_target_id
        && left.not_before == right.not_before
        && left.not_after == right.not_after
}

pub(crate) fn verify_all_provider_registration_histories(
    store: &IssuerStore,
    connection: &Connection,
) -> StoreResult<()> {
    let mut statement = connection.prepare(
        "SELECT provider_id, registration_digest FROM provider_registration_history \
         ORDER BY provider_id, registration_epoch",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (provider_id, registration_digest) in rows {
        let provider_id = fixed_blob(provider_id, "invalid historical provider id")?;
        let registration_digest = fixed_blob(
            registration_digest,
            "invalid historical provider registration digest",
        )?;
        if read_provider_registration_history(
            connection,
            store,
            &provider_id,
            &registration_digest,
        )?
        .is_none()
        {
            return Err(StoreError::SchemaMismatch(
                "retained provider registration disappeared during integrity check".to_owned(),
            ));
        }
    }
    Ok(())
}

fn read_clearing_authorization(
    connection: &Connection,
    store: &IssuerStore,
    digest: &[u8; 32],
) -> StoreResult<Option<ClearingAuthorizationRecordV1>> {
    type Raw = (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, i64);
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT provider_id, authorization_epoch, exact_authorization, exact_approval, \
             not_after, commit_seq FROM clearing_authorizations \
             WHERE issuer_id = ?1 AND authorization_digest = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                digest.as_slice(),
            ],
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
        let exact_authorization: Vec<u8> = raw.2;
        let exact_approval: Vec<u8> = raw.3;
        let authorization = ProviderClearingAuthorizationV1::decode(&exact_authorization)?;
        let approval = IssuerClearingApprovalV1::decode(&exact_approval)?;
        if authorization.encode()? != exact_authorization
            || approval.encode() != exact_approval
            || authorization.authorization_digest()? != *digest
            || authorization.claims.issuer_id != store.handle.expected_issuer_id
            || authorization.claims.provider_id.as_slice() != raw.0.as_slice()
            || authorization.claims.authorization_epoch
                != db_u64(raw.1, "negative clearing authorization epoch")?
            || approval.authorization_digest != *digest
            || approval.not_after != db_u64(raw.4, "negative clearing approval expiry")?
        {
            return Err(StoreError::SchemaMismatch(
                "clearing authorization row is not canonical or self-consistent".to_owned(),
            ));
        }
        Ok(ClearingAuthorizationRecordV1 {
            authorization_digest: *digest,
            provider_id: fixed_blob(raw.0, "invalid clearing provider id")?,
            authorization_epoch: authorization.claims.authorization_epoch,
            exact_authorization,
            exact_approval,
            not_after: approval.not_after,
            commit: marker(
                store,
                db_u64(raw.5, "negative clearing authorization commit")?,
            ),
        })
    })
    .transpose()
}

fn redeem_idempotency_digest(store: &IssuerStore, key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REDEEM_IDEMPOTENCY_DOMAIN_V1);
    hasher.update(store.handle.expected_issuer_id);
    hasher.update(key);
    hasher.finalize().into()
}

fn redeem_request_replay_image(
    store: &IssuerStore,
    request: &ProviderRedeemRequestV1,
) -> StoreResult<Vec<u8>> {
    let mut sanitized = request.clone();
    sanitized.idempotency_key = redeem_idempotency_digest(store, &request.idempotency_key);
    Ok(sanitized.encode()?)
}

fn validate_redeem_pair(
    store: &IssuerStore,
    redeem: &VerifiedSharedIssuerRedeemV1<'_>,
    response: &pir_service_protocol::ProviderRedeemResponseV1,
) -> StoreResult<()> {
    let request = redeem.request;
    let request_digest = request.request_digest()?;
    let expected_transaction_id =
        issuer_redeem_ledger_transaction_id_v1(&store.handle.expected_issuer_id, &request_digest);
    if request.issuer_id != store.handle.expected_issuer_id
        || response.request_digest != request_digest
        || response.authorization_digest != request.authorization_digest
        || response.issuer_id != request.issuer_id
        || response.provider_id != request.provider_id
        || response.unit != redeem.unit
        || response.accepted_value != request.accepted_value
        || response.provider_credit != redeem.provider_credit
        || response.issuer_fee != redeem.issuer_fee
    {
        return Err(StoreError::InvalidInput(
            "verified redeem request and response typestates do not match",
        ));
    }
    match (&request.destination, &response.result) {
        (
            SettlementDestinationV1::LedgerCredit { account_id },
            RedeemSettlementResultV1::LedgerCredit {
                account_id: response_account,
                ledger_transaction_id,
            },
        ) if account_id == response_account
            && ledger_transaction_id == &expected_transaction_id =>
        {
            Ok(())
        }
        (
            SettlementDestinationV1::BlindOutputs {
                settlement_keyset_id,
                outputs,
            },
            RedeemSettlementResultV1::BlindOutputs {
                settlement_keyset_id: response_keyset,
                signatures,
            },
        ) if settlement_keyset_id == response_keyset
            && outputs.len() == signatures.len()
            && outputs.iter().zip(signatures).all(|(output, signature)| {
                output.denomination == signature.denomination
                    && output.blinded_message == signature.blinded_message
            }) =>
        {
            Ok(())
        }
        _ => Err(StoreError::InvalidInput(
            "verified redeem response changed its exact settlement destination",
        )),
    }
}

fn require_current_registered_authorization(
    transaction: &Connection,
    store: &IssuerStore,
    redeem: &VerifiedSharedIssuerRedeemV1<'_>,
) -> StoreResult<()> {
    let digest = redeem.authorization.authorization_digest()?;
    let record = read_clearing_authorization(transaction, store, &digest)?.ok_or(
        StoreError::InvalidInput("clearing authorization is not issuer-registered"),
    )?;
    if record.exact_authorization != redeem.authorization.encode()?
        || record.exact_approval != redeem.issuer_approval.encode()
    {
        return Err(StoreError::ClearingAuthorizationFork);
    }
    let highest: i64 = transaction.query_row(
        "SELECT MAX(authorization_epoch) FROM clearing_authorizations \
         WHERE issuer_id = ?1 AND provider_id = ?2",
        params![
            store.handle.expected_issuer_id.as_slice(),
            redeem.request.provider_id.as_slice(),
        ],
        |row| row.get(0),
    )?;
    if db_u64(highest, "negative clearing authorization epoch")?
        != redeem.authorization.claims.authorization_epoch
    {
        return Err(StoreError::ClearingAuthorizationRollback);
    }
    Ok(())
}

fn require_registered_credential_lineage(
    transaction: &Connection,
    store: &IssuerStore,
    redeem: &VerifiedSharedIssuerRedeemV1<'_>,
) -> StoreResult<()> {
    if redeem.request.scheme == AuthScheme::ArcV1Experimental {
        let binding = redeem.credential_binding;
        let raw_public_key: [u8; 99] = binding
            .claims
            .verification_key
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::InvalidInput("ARC binding key is not 99 bytes"))?;
        let fingerprint = pir_arc_adapter::arc_public_key_fingerprint_v1(&raw_public_key)
            .map_err(|_| StoreError::InvalidInput("ARC binding key is invalid"))?;
        type RawArc = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64, Vec<u8>);
        let raw: Option<RawArc> = transaction
            .query_row(
                "SELECT raw_public_key, binding_digest, provider_id, scope_id, offer_id, \
                 entitlement_profile, keyset_epoch, credential_key_id FROM arc_key_lineages \
                 WHERE issuer_id = ?1 AND key_fingerprint = ?2",
                params![
                    store.handle.expected_issuer_id.as_slice(),
                    fingerprint.as_slice(),
                ],
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
                    ))
                },
            )
            .optional()?;
        let Some(raw) = raw else {
            return Err(StoreError::InvalidInput(
                "experimental ARC key lineage is not issuer-registered",
            ));
        };
        if raw.0.as_slice() != raw_public_key.as_slice()
            || raw.1.as_slice() != binding.binding_digest()?.as_slice()
            || raw.2.as_slice() != binding.claims.provider_id.as_slice()
            || raw.3.as_slice() != binding.claims.scope_id.as_slice()
            || u32::try_from(raw.4).ok() != Some(binding.claims.offer_id)
            || u16::try_from(raw.5).ok() != Some(binding.claims.entitlement_profile)
            || db_u64(raw.6, "negative ARC keyset epoch")? != binding.claims.keyset_epoch
            || raw.7.as_slice() != binding.claims.credential_key_id.as_slice()
        {
            return Err(StoreError::ArcKeyLineageConflict);
        }
        return Ok(());
    }
    if redeem.request.scheme != AuthScheme::BitcoinPirCashuBatV1 {
        return Ok(());
    }
    let binding = redeem.credential_binding;
    let raw_public_key: [u8; 33] = binding
        .claims
        .verification_key
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::InvalidInput("BAT binding key is not 33 bytes"))?;
    let fingerprint = pir_service_protocol::bat_verification_key_fingerprint_v1(&raw_public_key)
        .map_err(|_| StoreError::InvalidInput("BAT binding key is invalid"))?;
    type Raw = (Vec<u8>, Vec<u8>, i64, i64, i64, Vec<u8>);
    let raw: Option<Raw> = transaction
        .query_row(
            "SELECT provider_id, scope_id, offer_id, entitlement_profile, keyset_epoch, \
             credential_key_id FROM bat_key_lineages WHERE issuer_id = ?1 AND key_fingerprint = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                fingerprint.as_slice(),
            ],
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
    let Some(raw) = raw else {
        return Err(StoreError::InvalidInput(
            "BAT key lineage is not issuer-registered",
        ));
    };
    if raw.0.as_slice() != binding.claims.provider_id.as_slice()
        || raw.1.as_slice() != binding.claims.scope_id.as_slice()
        || u32::try_from(raw.2).ok() != Some(binding.claims.offer_id)
        || u16::try_from(raw.3).ok() != Some(binding.claims.entitlement_profile)
        || db_u64(raw.4, "negative BAT keyset epoch")? != binding.claims.keyset_epoch
        || raw.5.as_slice() != binding.claims.credential_key_id.as_slice()
    {
        return Err(StoreError::BatKeyLineageConflict);
    }
    Ok(())
}

fn require_registered_redeem_settlement_lineage(
    transaction: &Connection,
    store: &IssuerStore,
    redeem: &VerifiedSharedIssuerRedeemV1<'_>,
) -> StoreResult<()> {
    let SettlementDestinationV1::BlindOutputs {
        settlement_keyset_id,
        outputs,
    } = &redeem.request.destination
    else {
        return Ok(());
    };
    let rule = redeem
        .authorization
        .rule_for_binding(&redeem.request.credential_binding_digest)
        .ok_or(StoreError::InvalidInput("blind settlement rule is missing"))?;
    let keyset = rule
        .blind_output_keyset
        .as_ref()
        .ok_or(StoreError::InvalidInput(
            "blind settlement keyset is missing",
        ))?;
    if &keyset.keyset_id != settlement_keyset_id {
        return Err(StoreError::SettlementKeyLineageConflict);
    }
    for output in outputs {
        let public_key = keyset
            .keys
            .iter()
            .find(|key| key.amount == output.denomination)
            .map(|key| key.public_key)
            .ok_or(StoreError::SettlementKeyLineageConflict)?;
        require_settlement_key_lineage_row(
            transaction,
            store,
            settlement_keyset_id,
            output.denomination,
            &public_key,
        )?;
    }
    Ok(())
}

fn require_settlement_key_lineage_row(
    transaction: &Connection,
    store: &IssuerStore,
    keyset_id: &str,
    denomination: u64,
    public_key: &[u8; 33],
) -> StoreResult<()> {
    let fingerprint = pir_service_protocol::settlement_denomination_key_fingerprint_v1(public_key)?;
    let raw: Option<(String, i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT keyset_id, denomination, raw_public_key FROM settlement_key_lineages \
             WHERE issuer_id = ?1 AND key_fingerprint = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                fingerprint.as_slice(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((stored_keyset, stored_denomination, stored_public_key)) = raw else {
        return Err(StoreError::InvalidInput(
            "settlement denomination key lineage is not issuer-registered",
        ));
    };
    if stored_keyset != keyset_id
        || db_u64(stored_denomination, "negative settlement denomination")? != denomination
        || stored_public_key.as_slice() != public_key.as_slice()
    {
        return Err(StoreError::SettlementKeyLineageConflict);
    }
    Ok(())
}

fn credit_provider_account(
    transaction: &Connection,
    store: &IssuerStore,
    registration: &ProviderSettlementRegistrationRecordV1,
    credit: u64,
    sequence: u64,
) -> StoreResult<u64> {
    let current: (i64, i64, i64) = transaction.query_row(
        "SELECT available_value, reserved_value, ledger_sequence FROM ledger_accounts \
         WHERE issuer_id = ?1 AND provider_id = ?2 AND account_id = ?3 AND unit = ?4",
        params![
            store.handle.expected_issuer_id.as_slice(),
            registration.provider_id.as_slice(),
            registration.settlement_account_id.as_slice(),
            SettlementUnitV1::AuthCredit as u8,
        ],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let available = db_u64(current.0, "negative available ledger balance")?;
    let next = available
        .checked_add(credit)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(StoreError::LedgerBalanceOverflow)?;
    let ledger_sequence = db_u64(current.2, "negative ledger sequence")?
        .checked_add(1)
        .ok_or(StoreError::LedgerBalanceOverflow)?;
    let changed = transaction.execute(
        "UPDATE ledger_accounts SET available_value = ?1, ledger_sequence = ?2, commit_seq = ?3 \
         WHERE account_id = ?4 AND available_value = ?5 AND reserved_value = ?6 \
         AND ledger_sequence = ?7",
        params![
            sql_integer(next, "available ledger balance exceeds SQLite range")?,
            sql_integer(ledger_sequence, "ledger sequence exceeds SQLite range")?,
            sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            registration.settlement_account_id.as_slice(),
            current.0,
            current.1,
            current.2,
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::SchemaMismatch(
            "provider ledger compare-and-set failed".to_owned(),
        ));
    }
    Ok(ledger_sequence)
}

#[allow(clippy::too_many_arguments)]
fn insert_redeem_ledger_transaction(
    transaction: &Connection,
    store: &IssuerStore,
    redeem: &VerifiedSharedIssuerRedeemV1<'_>,
    registration: &ProviderSettlementRegistrationRecordV1,
    kind: LedgerTransactionKindV1,
    transaction_id: &[u8; 32],
    request_digest: &[u8; 32],
    sequence: u64,
) -> StoreResult<()> {
    transaction.execute(
        "INSERT INTO ledger_transactions (transaction_id, issuer_id, provider_id, kind, \
         reference_digest, unit, created_at, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            transaction_id.as_slice(),
            store.handle.expected_issuer_id.as_slice(),
            registration.provider_id.as_slice(),
            kind as i64,
            request_digest.as_slice(),
            redeem.unit as u8,
            sql_integer(
                redeem.now_unix,
                "ledger transaction time exceeds SQLite range"
            )?,
            sql_integer(sequence, "commit sequence exceeds SQLite range")?,
        ],
    )?;
    let provider_account_kind = if kind == LedgerTransactionKindV1::RedeemLedgerCredit {
        ACCOUNT_KIND_PROVIDER
    } else {
        ACCOUNT_KIND_BLIND_LIABILITY
    };
    let provider_account_id = if kind == LedgerTransactionKindV1::RedeemLedgerCredit {
        registration.settlement_account_id
    } else {
        system_account_id(store, SYSTEM_ACCOUNT_BLIND_LIABILITY)
    };
    let credential_source = system_account_id(store, SYSTEM_ACCOUNT_CREDENTIAL_SOURCE);
    let fee_account = system_account_id(store, SYSTEM_ACCOUNT_ISSUER_FEE);
    let credit =
        i64::try_from(redeem.provider_credit).map_err(|_| StoreError::LedgerBalanceOverflow)?;
    let accepted = i64::try_from(redeem.request.accepted_value)
        .map_err(|_| StoreError::LedgerBalanceOverflow)?;
    transaction.execute(
        "INSERT INTO ledger_postings (transaction_id, line_no, account_kind, account_id, signed_amount) \
         VALUES (?1, 1, ?2, ?3, ?4)",
        params![
            transaction_id.as_slice(),
            provider_account_kind,
            provider_account_id.as_slice(),
            credit,
        ],
    )?;
    let mut source_line = 2i64;
    if redeem.issuer_fee != 0 {
        let fee =
            i64::try_from(redeem.issuer_fee).map_err(|_| StoreError::LedgerBalanceOverflow)?;
        transaction.execute(
            "INSERT INTO ledger_postings (transaction_id, line_no, account_kind, account_id, signed_amount) \
             VALUES (?1, 2, ?2, ?3, ?4)",
            params![
                transaction_id.as_slice(),
                ACCOUNT_KIND_ISSUER_FEE,
                fee_account.as_slice(),
                fee,
            ],
        )?;
        source_line = 3;
    }
    transaction.execute(
        "INSERT INTO ledger_postings (transaction_id, line_no, account_kind, account_id, signed_amount) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            transaction_id.as_slice(),
            source_line,
            ACCOUNT_KIND_CREDENTIAL_SOURCE,
            credential_source.as_slice(),
            -accepted,
        ],
    )?;
    Ok(())
}

fn system_account_id(store: &IssuerStore, kind: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SYSTEM_LEDGER_ACCOUNT_ID_DOMAIN_V1);
    hasher.update(store.handle.expected_issuer_id);
    hasher.update([kind]);
    hasher.finalize().into()
}

fn settlement_deposit_idempotency_digest(store: &IssuerStore, key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SETTLEMENT_DEPOSIT_IDEMPOTENCY_DOMAIN_V1);
    hasher.update(store.handle.expected_issuer_id);
    hasher.update(key);
    hasher.finalize().into()
}

fn settlement_deposit_replay_image(
    store: &IssuerStore,
    request: &ProviderSettlementDepositRequestV1,
) -> StoreResult<Vec<u8>> {
    let mut sanitized = request.clone();
    sanitized.idempotency_key =
        settlement_deposit_idempotency_digest(store, &request.idempotency_key);
    Ok(sanitized.encode()?)
}

#[allow(clippy::too_many_arguments)]
fn insert_deposit_ledger_transaction(
    transaction: &Connection,
    store: &IssuerStore,
    request: &ProviderSettlementDepositRequestV1,
    registration: &ProviderSettlementRegistrationRecordV1,
    transaction_id: &[u8; 32],
    request_digest: &[u8; 32],
    now_unix: u64,
    sequence: u64,
) -> StoreResult<()> {
    transaction.execute(
        "INSERT INTO ledger_transactions (transaction_id, issuer_id, provider_id, kind, \
         reference_digest, unit, created_at, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            transaction_id.as_slice(),
            store.handle.expected_issuer_id.as_slice(),
            registration.provider_id.as_slice(),
            LedgerTransactionKindV1::BlindSettlementDeposit as i64,
            request_digest.as_slice(),
            request.unit as u8,
            sql_integer(now_unix, "deposit ledger time exceeds SQLite range")?,
            sql_integer(sequence, "commit sequence exceeds SQLite range")?,
        ],
    )?;
    let blind_liability = system_account_id(store, SYSTEM_ACCOUNT_BLIND_LIABILITY);
    let value =
        i64::try_from(request.total_value).map_err(|_| StoreError::LedgerBalanceOverflow)?;
    transaction.execute(
        "INSERT INTO ledger_postings (transaction_id, line_no, account_kind, account_id, signed_amount) \
         VALUES (?1, 1, ?2, ?3, ?4)",
        params![
            transaction_id.as_slice(),
            ACCOUNT_KIND_PROVIDER,
            registration.settlement_account_id.as_slice(),
            value,
        ],
    )?;
    transaction.execute(
        "INSERT INTO ledger_postings (transaction_id, line_no, account_kind, account_id, signed_amount) \
         VALUES (?1, 2, ?2, ?3, ?4)",
        params![
            transaction_id.as_slice(),
            ACCOUNT_KIND_BLIND_LIABILITY,
            blind_liability.as_slice(),
            -value,
        ],
    )?;
    Ok(())
}

fn read_settlement_deposit(
    connection: &Connection,
    store: &IssuerStore,
    idempotency_digest: &[u8; 32],
) -> StoreResult<Option<SettlementDepositRecordV1>> {
    type Raw = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        String,
        i64,
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
    );
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT request_digest, registration_digest, provider_id, account_id, unit, \
             settlement_keyset_id, total_value, ledger_transaction_id, ledger_sequence, \
             request_replay_image, exact_response, deposited_at, commit_seq \
             FROM settlement_deposits WHERE issuer_id = ?1 AND idempotency_digest = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                idempotency_digest.as_slice(),
            ],
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
                    row.get(12)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let request_digest = fixed_blob(raw.0, "invalid deposit request digest")?;
        let registration_digest = fixed_blob(raw.1, "invalid deposit registration digest")?;
        let provider_id = fixed_blob(raw.2, "invalid deposit provider id")?;
        let account_id = fixed_blob(raw.3, "invalid deposit account id")?;
        let unit = settlement_unit_from_db(raw.4)?;
        let total_value = db_u64(raw.6, "negative deposit value")?;
        let ledger_transaction_id = fixed_blob(raw.7, "invalid deposit transaction id")?;
        let ledger_sequence = db_u64(raw.8, "negative deposit ledger sequence")?;
        let exact_response: Vec<u8> = raw.10;
        let response = ProviderSettlementDepositResponseV1::decode(&exact_response)?;
        if response.encode()? != exact_response
            || response.request_digest != request_digest
            || response.registration_digest != registration_digest
            || response.issuer_id != store.handle.expected_issuer_id
            || response.provider_id != provider_id
            || response.account_id != account_id
            || response.unit != unit
            || response.settlement_keyset_id != raw.5
            || response.total_value != total_value
            || response.ledger_transaction_id != ledger_transaction_id
            || response.ledger_sequence != ledger_sequence
        {
            return Err(StoreError::SchemaMismatch(
                "settlement deposit response is not canonical or row-bound".to_owned(),
            ));
        }
        Ok(SettlementDepositRecordV1 {
            idempotency_digest: *idempotency_digest,
            request_digest,
            registration_digest,
            provider_id,
            account_id,
            unit,
            settlement_keyset_id: raw.5,
            total_value,
            ledger_transaction_id,
            ledger_sequence,
            exact_request_replay_image: raw.9,
            exact_response,
            deposited_at: db_u64(raw.11, "negative deposit time")?,
            commit: marker(store, db_u64(raw.12, "negative deposit commit")?),
        })
    })
    .transpose()
}

fn read_redeem(
    connection: &Connection,
    store: &IssuerStore,
    idempotency_digest: &[u8; 32],
) -> StoreResult<Option<RedeemRecordV1>> {
    type Raw = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        Vec<u8>,
        i64,
        i64,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
    );
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT request_digest, provider_id, authorization_digest, credential_binding_digest, \
             scheme, credential_digest, accepted_value, provider_credit, issuer_fee, unit, \
             ledger_transaction_id, request_replay_image, exact_response, redeemed_at, commit_seq \
             FROM redemptions WHERE issuer_id = ?1 AND idempotency_digest = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                idempotency_digest.as_slice(),
            ],
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
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let scheme = auth_scheme_from_db(raw.4)?;
        let unit = settlement_unit_from_db(raw.9)?;
        let exact_response: Vec<u8> = raw.12;
        let response = pir_service_protocol::ProviderRedeemResponseV1::decode(&exact_response)?;
        let request_digest = fixed_blob(raw.0, "invalid redeem request digest")?;
        let provider_id = fixed_blob(raw.1, "invalid redeem provider id")?;
        let authorization_digest = fixed_blob(raw.2, "invalid redeem authorization digest")?;
        let credential_binding_digest =
            fixed_blob(raw.3, "invalid redeem credential binding digest")?;
        let credential_digest = fixed_blob(raw.5, "invalid redeem credential digest")?;
        let accepted_value = db_u64(raw.6, "negative redeem accepted value")?;
        let provider_credit = db_u64(raw.7, "negative redeem provider credit")?;
        let issuer_fee = db_u64(raw.8, "negative redeem issuer fee")?;
        let ledger_transaction_id = fixed_blob(raw.10, "invalid ledger transaction id")?;
        if response.encode()? != exact_response
            || response.request_digest != request_digest
            || response.authorization_digest != authorization_digest
            || response.issuer_id != store.handle.expected_issuer_id
            || response.provider_id != provider_id
            || response.unit != unit
            || response.accepted_value != accepted_value
            || response.provider_credit != provider_credit
            || response.issuer_fee != issuer_fee
        {
            return Err(StoreError::SchemaMismatch(
                "redeem response is not canonical or row-bound".to_owned(),
            ));
        }
        Ok(RedeemRecordV1 {
            idempotency_digest: *idempotency_digest,
            request_digest,
            provider_id,
            authorization_digest,
            credential_binding_digest,
            scheme,
            credential_digest,
            accepted_value,
            provider_credit,
            issuer_fee,
            unit,
            ledger_transaction_id,
            exact_request_replay_image: raw.11,
            exact_response,
            redeemed_at: db_u64(raw.13, "negative redeem time")?,
            commit: marker(store, db_u64(raw.14, "negative redeem commit")?),
        })
    })
    .transpose()
}

fn read_provider_balance(
    connection: &Connection,
    store: &IssuerStore,
    provider_id: &[u8; 32],
) -> StoreResult<Option<ProviderLedgerBalanceV1>> {
    type Raw = (Vec<u8>, i64, i64, i64, i64, i64);
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT account_id, unit, available_value, reserved_value, ledger_sequence, commit_seq \
             FROM ledger_accounts WHERE issuer_id = ?1 AND provider_id = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                provider_id.as_slice(),
            ],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        Ok(ProviderLedgerBalanceV1 {
            provider_id: *provider_id,
            account_id: fixed_blob(raw.0, "invalid ledger account id")?,
            unit: settlement_unit_from_db(raw.1)?,
            available_value: db_u64(raw.2, "negative available ledger balance")?,
            reserved_value: db_u64(raw.3, "negative reserved ledger balance")?,
            ledger_sequence: db_u64(raw.4, "negative ledger sequence")?,
            commit: marker(store, db_u64(raw.5, "negative ledger account commit")?),
        })
    })
    .transpose()
}

fn auth_scheme_from_db(value: i64) -> StoreResult<AuthScheme> {
    match value {
        1 => Ok(AuthScheme::FreeV1),
        4 => Ok(AuthScheme::BitcoinPirCashuBatV1),
        5 => Ok(AuthScheme::ArcV1Experimental),
        _ => Err(StoreError::SchemaMismatch(
            "invalid shared redeem auth scheme".to_owned(),
        )),
    }
}

fn settlement_unit_from_db(value: i64) -> StoreResult<SettlementUnitV1> {
    match value {
        1 => Ok(SettlementUnitV1::MilliSatoshi),
        2 => Ok(SettlementUnitV1::Satoshi),
        3 => Ok(SettlementUnitV1::AuthCredit),
        _ => Err(StoreError::SchemaMismatch(
            "invalid settlement ledger unit".to_owned(),
        )),
    }
}

fn marker(store: &IssuerStore, sequence: u64) -> CommitMarker {
    CommitMarker {
        store_instance_id: store.handle.expected_store_instance_id,
        commit_seq: sequence,
    }
}
