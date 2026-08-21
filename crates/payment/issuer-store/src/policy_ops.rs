use crate::db::{
    advance_store_generation, commit, db_u64, fixed_blob, sql_integer, verify_expected_identity,
};
use crate::rollback::mutation_digest;
use crate::{
    CommitMarker, DurableWrite, IssuerServicePolicyRecordV1, IssuerStore, StoreError, StoreResult,
    WriteDisposition, MAX_EXACT_SERVICE_POLICY_BYTES,
};
use ed25519_dalek::VerifyingKey;
use pir_service_protocol::{
    bat_acceptance_member_from_verified_policy_v2, AuthScheme, BatAcceptanceMemberV2,
    Bolt11BatV2QuoteIntentV2, Bolt11QuoteIntentV1, CashuManifestEpochFloorV1,
    CredentialKeyBindingExpectationV1, CredentialKeyBindingV1, CredentialKeysetEpochFloorV1,
    PolicyRollbackGuardV1, ProviderClearingAuthorizationV1, ServicePolicyEpochFloorsV1,
    ServicePolicyV1, VerifiedBatAcceptanceMemberV2,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const POLICY_FLOOR_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/issuer-store/service-policy-floors/v1";

impl IssuerStore {
    /// Installs a currently valid provider policy into the issuer's durable
    /// acquisition catalog. Epoch, same-epoch fork, signing-key, credential
    /// keyset, and Cashu-manifest rollback checks all occur before the exact
    /// policy becomes eligible for new quotes.
    ///
    /// Every accepted policy is retained for paid-claim recovery. A signing
    /// key rotation requires a future explicitly authorized rotation record;
    /// merely supplying a different key here fails closed.
    pub fn register_service_policy(
        &self,
        policy: &ServicePolicyV1,
        policy_verifying_key: &VerifyingKey,
        now_unix: u64,
    ) -> StoreResult<DurableWrite<IssuerServicePolicyRecordV1>> {
        if now_unix == 0 {
            return Err(StoreError::InvalidInput("service policy time is zero"));
        }
        let exact_policy = policy.encode()?;
        if exact_policy.is_empty() || exact_policy.len() > MAX_EXACT_SERVICE_POLICY_BYTES {
            return Err(StoreError::InvalidInput(
                "service policy exceeds issuer-store bound",
            ));
        }
        let provider_id = policy.provider_id;
        let policy_digest = policy.policy_digest()?;
        let policy_verifying_key_bytes = policy_verifying_key.to_bytes();

        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let existing_head = read_policy_head(&transaction, self, &provider_id)?;
        if let Some(head) = &existing_head {
            if head.policy_verifying_key != policy_verifying_key_bytes {
                return Err(StoreError::ServicePolicySigningKeyConflict);
            }
            if policy.policy_epoch < head.policy_epoch {
                return Err(StoreError::ServicePolicyRollback);
            }
            if policy.policy_epoch == head.policy_epoch && policy_digest != head.policy_digest {
                return Err(StoreError::ServicePolicyFork);
            }
        }

        let rollback_guard =
            existing_head
                .as_ref()
                .map_or_else(PolicyRollbackGuardV1::initial, |head| {
                    PolicyRollbackGuardV1 {
                        highest_epoch: head.policy_epoch,
                        digest_at_highest_epoch: head.policy_digest,
                    }
                });
        let current_floors = read_policy_floors(&transaction, &provider_id)?;
        let verified = policy
            .verify_current_for_acquisition(
                &provider_id,
                now_unix,
                &rollback_guard,
                &current_floors,
                policy_verifying_key,
            )
            .map_err(StoreError::Protocol)?;
        let updated_floors = current_floors
            .updated_from_verified(&verified)
            .map_err(StoreError::Protocol)?;

        if let Some(head) = existing_head {
            if head.policy_epoch == policy.policy_epoch {
                if head.exact_policy != exact_policy
                    || head.expires_at != policy.expires_at
                    || head.policy_verifying_key != policy_verifying_key_bytes
                {
                    return Err(StoreError::ServicePolicyFork);
                }
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: head.commit,
                    value: head,
                });
            }
        }

        let floor_digest = policy_floor_digest(&updated_floors);
        let epoch = policy.policy_epoch.to_le_bytes();
        let expires_at = policy.expires_at.to_le_bytes();
        let mutation = mutation_digest(
            b"register-service-policy-v1",
            &[
                &provider_id,
                &epoch,
                &policy_digest,
                &policy_verifying_key_bytes,
                &expires_at,
                &floor_digest,
                &exact_policy,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"register-service-policy-v1",
            &mutation,
        )?;
        let sequence = committed_identity.commit_seq;
        transaction.execute(
            "INSERT INTO issuer_service_policies (provider_id, policy_epoch, policy_digest, \
             policy_verifying_key, exact_policy, expires_at, commit_seq) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                provider_id.as_slice(),
                sql_integer(policy.policy_epoch, "policy epoch exceeds SQLite range")?,
                policy_digest.as_slice(),
                policy_verifying_key_bytes.as_slice(),
                exact_policy.as_slice(),
                sql_integer(policy.expires_at, "policy expiry exceeds SQLite range")?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO issuer_service_policy_heads (provider_id, highest_epoch, policy_digest, \
             policy_verifying_key, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(provider_id) DO UPDATE SET highest_epoch = excluded.highest_epoch, \
             policy_digest = excluded.policy_digest, \
             policy_verifying_key = excluded.policy_verifying_key, commit_seq = excluded.commit_seq",
            params![
                provider_id.as_slice(),
                sql_integer(policy.policy_epoch, "policy epoch exceeds SQLite range")?,
                policy_digest.as_slice(),
                policy_verifying_key_bytes.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        write_policy_floors(&transaction, &provider_id, &updated_floors, sequence)?;
        commit(transaction)?;
        let value = self
            .service_policy(&provider_id, &policy_digest)?
            .ok_or_else(|| {
                StoreError::SchemaMismatch("committed service policy is missing".to_owned())
            })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value,
        })
    }

    /// Loads one exact policy from the issuer-retained allowlist. This does
    /// not assert that it is current; callers use current policies only for
    /// acquisition and retained policies only for already-created claims.
    pub fn service_policy(
        &self,
        provider_id: &[u8; 32],
        policy_digest: &[u8; 32],
    ) -> StoreResult<Option<IssuerServicePolicyRecordV1>> {
        let connection = self.open_checked(false)?;
        let value = read_policy_by_digest(&connection, self, provider_id, policy_digest)?;
        Ok(value)
    }

    pub fn current_service_policy(
        &self,
        provider_id: &[u8; 32],
    ) -> StoreResult<Option<IssuerServicePolicyRecordV1>> {
        let connection = self.open_checked(false)?;
        let value = read_policy_head(&connection, self, provider_id)?;
        Ok(value)
    }

    /// Loads the exact policies whose issuer credential private material is
    /// needed now: every live acquisition head plus every durable quote that
    /// can still be recovered, paid, or claimed. Historical terminal rows are
    /// retained but deliberately do not force obsolete private keys to remain
    /// online forever.
    pub fn service_policies_requiring_credential_material(
        &self,
        now_unix: u64,
    ) -> StoreResult<Vec<IssuerServicePolicyRecordV1>> {
        if now_unix == 0 {
            return Err(StoreError::InvalidInput(
                "credential material observation time is zero",
            ));
        }
        let connection = self.open_checked(false)?;
        let mut required = BTreeSet::new();

        let mut head_statement = connection.prepare(
            "SELECT h.provider_id, h.policy_digest, p.exact_policy
             FROM issuer_service_policy_heads h
             JOIN issuer_service_policies p
               ON p.provider_id = h.provider_id AND p.policy_digest = h.policy_digest
             ORDER BY h.provider_id",
        )?;
        let heads = head_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (provider_id, policy_digest, exact_policy) in heads {
            let provider_id = fixed_blob(provider_id, "invalid policy head provider ID")?;
            let policy_digest = fixed_blob(policy_digest, "invalid policy head digest")?;
            let policy = ServicePolicyV1::decode(&exact_policy).map_err(|_| {
                StoreError::SchemaMismatch("current service policy is not canonical".to_owned())
            })?;
            if policy.encode()? != exact_policy {
                return Err(StoreError::SchemaMismatch(
                    "current service policy is non-canonical".to_owned(),
                ));
            }
            if policy.issued_at <= now_unix && now_unix <= policy.expires_at {
                required.insert((provider_id, policy_digest));
            }
        }

        let mut quote_statement = connection.prepare(
            "SELECT state, intent_replay_image, invoice_created_not_after, claim_deadline
             FROM quotes
             WHERE quote_protocol = 1 AND (
                    (state = 0 AND reservation_recovery_deadline >= ?1)
                    OR (state IN (1, 2, 4, 5) AND claim_deadline >= ?1)
             )
             ORDER BY quote_id",
        )?;
        let quotes = quote_statement
            .query_map(
                [sql_integer(
                    now_unix,
                    "credential material observation time exceeds SQLite range",
                )?],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        for (state, exact_intent, invoice_created_not_after, claim_deadline) in quotes {
            let state = crate::QuoteState::from_db(state)
                .ok_or_else(|| StoreError::SchemaMismatch("quote has invalid state".to_owned()))?;
            let intent = Bolt11QuoteIntentV1::decode(&exact_intent).map_err(|_| {
                StoreError::SchemaMismatch("quote intent replay image is not canonical".to_owned())
            })?;
            if intent.encode()? != exact_intent {
                return Err(StoreError::SchemaMismatch(
                    "quote intent replay image is non-canonical".to_owned(),
                ));
            }
            if intent.issuer_id != self.handle.expected_issuer_id
                || intent.network != self.handle.expected_network
            {
                return Err(StoreError::SchemaMismatch(
                    "quote intent replay image has the wrong issuer or network".to_owned(),
                ));
            }
            let still_requires_material = match state {
                crate::QuoteState::Reserved => {
                    let latest_creation = db_u64(
                        invoice_created_not_after,
                        "negative invoice creation deadline",
                    )?;
                    let deadline = latest_creation
                        .checked_add(u64::from(intent.invoice_expiry_seconds))
                        .and_then(|value| value.checked_add(u64::from(intent.claim_window_seconds)))
                        .ok_or_else(|| {
                            StoreError::SchemaMismatch(
                                "reserved quote recovery horizon overflows Unix time".to_owned(),
                            )
                        })?;
                    now_unix <= deadline
                }
                crate::QuoteState::InvoiceOpen
                | crate::QuoteState::PaymentSettled
                | crate::QuoteState::InvoiceExpiredPendingReconcile
                | crate::QuoteState::LateSettledReconcile => claim_deadline
                    .map(|value| db_u64(value, "negative quote claim deadline"))
                    .transpose()?
                    .is_some_and(|deadline| now_unix <= deadline),
                crate::QuoteState::CredentialClaimed => false,
            };
            if still_requires_material {
                required.insert((intent.provider_id, intent.policy_digest));
            }
        }

        let mut policies = Vec::with_capacity(required.len());
        for (provider_id, policy_digest) in required {
            policies.push(
                read_policy_by_digest(&connection, self, &provider_id, &policy_digest)?
                    .ok_or_else(|| {
                        StoreError::SchemaMismatch(
                            "required quote policy is not retained".to_owned(),
                        )
                    })?,
            );
        }
        Ok(policies)
    }

    /// Returns every quote delegation digest whose private signing key is
    /// still needed for durable quote creation recovery, reconciliation,
    /// status, or claim. A claimed quote is exact-response recoverable and no
    /// longer needs its quote signer; a historical quote past its immutable
    /// recovery horizon remains retained but does not pin a key online.
    pub fn quote_delegation_digests_requiring_signing_material(
        &self,
        now_unix: u64,
    ) -> StoreResult<Vec<[u8; 32]>> {
        if now_unix == 0 {
            return Err(StoreError::InvalidInput(
                "quote material observation time is zero",
            ));
        }
        let connection = self.open_checked(false)?;
        let mut statement = connection.prepare(
            "SELECT quote_protocol, state, delegation_digest, intent_replay_image, \
                    invoice_created_not_after, claim_deadline
             FROM quotes
             WHERE (state = 0 AND reservation_recovery_deadline >= ?1)
                OR (state IN (1, 2, 4, 5) AND claim_deadline >= ?1)
             ORDER BY quote_id",
        )?;
        let rows = statement
            .query_map(
                [sql_integer(
                    now_unix,
                    "quote material observation time exceeds SQLite range",
                )?],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let mut required = BTreeSet::new();
        for (
            quote_protocol,
            state,
            delegation_digest,
            exact_intent,
            create_deadline,
            claim_deadline,
        ) in rows
        {
            let state = crate::QuoteState::from_db(state)
                .ok_or_else(|| StoreError::SchemaMismatch("quote has invalid state".to_owned()))?;
            let delegation_digest =
                fixed_blob(delegation_digest, "invalid quote delegation digest")?;
            let (intent_issuer_id, intent_network, intent_delegation_digest, expiry, claim) =
                match quote_protocol {
                    1 => {
                        let intent = Bolt11QuoteIntentV1::decode(&exact_intent).map_err(|_| {
                            StoreError::SchemaMismatch(
                                "V1 quote intent replay image is not canonical".to_owned(),
                            )
                        })?;
                        if intent.encode()? != exact_intent {
                            return Err(StoreError::SchemaMismatch(
                                "V1 quote intent replay image is non-canonical".to_owned(),
                            ));
                        }
                        (
                            intent.issuer_id,
                            intent.network,
                            intent.quote_delegation_digest,
                            intent.invoice_expiry_seconds,
                            intent.claim_window_seconds,
                        )
                    }
                    2 => {
                        let intent =
                            Bolt11BatV2QuoteIntentV2::decode(&exact_intent).map_err(|_| {
                                StoreError::SchemaMismatch(
                                    "BAT V2 quote intent replay image is not canonical".to_owned(),
                                )
                            })?;
                        if intent.encode()? != exact_intent {
                            return Err(StoreError::SchemaMismatch(
                                "BAT V2 quote intent replay image is non-canonical".to_owned(),
                            ));
                        }
                        (
                            intent.issuer_id,
                            intent.network,
                            intent.quote_delegation_digest,
                            intent.invoice_expiry_seconds,
                            intent.claim_window_seconds,
                        )
                    }
                    _ => {
                        return Err(StoreError::SchemaMismatch(
                            "quote has an unknown acquisition protocol".to_owned(),
                        ))
                    }
                };
            if intent_issuer_id != self.handle.expected_issuer_id
                || intent_network != self.handle.expected_network
                || intent_delegation_digest != delegation_digest
            {
                return Err(StoreError::SchemaMismatch(
                    "quote intent does not match its durable delegation".to_owned(),
                ));
            }
            let still_required = match state {
                crate::QuoteState::Reserved => {
                    let deadline = db_u64(create_deadline, "negative invoice creation deadline")?
                        .checked_add(u64::from(expiry))
                        .and_then(|value| value.checked_add(u64::from(claim)))
                        .ok_or_else(|| {
                            StoreError::SchemaMismatch(
                                "reserved quote recovery horizon overflows Unix time".to_owned(),
                            )
                        })?;
                    now_unix <= deadline
                }
                crate::QuoteState::InvoiceOpen
                | crate::QuoteState::PaymentSettled
                | crate::QuoteState::InvoiceExpiredPendingReconcile
                | crate::QuoteState::LateSettledReconcile => claim_deadline
                    .map(|value| db_u64(value, "negative quote claim deadline"))
                    .transpose()?
                    .is_some_and(|deadline| now_unix <= deadline),
                crate::QuoteState::CredentialClaimed => false,
            };
            if still_required {
                required.insert(delegation_digest);
            }
        }
        Ok(required.into_iter().collect())
    }

    /// Resolves every settlement-rule binding in one current clearing
    /// authorization against the issuer's immutable retained policy catalog
    /// and registered BAT/ARC key lineage. The returned bindings are exact,
    /// canonical issuer-signed objects. Callers may retire private verifier
    /// material only after a returned binding's `not_after` has passed.
    pub fn credential_bindings_for_clearing_authorization(
        &self,
        authorization: &ProviderClearingAuthorizationV1,
        now_unix: u64,
    ) -> StoreResult<Vec<CredentialKeyBindingV1>> {
        if now_unix == 0 {
            return Err(StoreError::InvalidInput(
                "clearing material observation time is zero",
            ));
        }
        if authorization.claims.issuer_id != self.handle.expected_issuer_id
            || now_unix < authorization.claims.not_before
            || now_unix > authorization.claims.not_after
        {
            return Err(StoreError::InvalidInput(
                "clearing authorization is not current for this issuer",
            ));
        }

        let connection = self.open_checked(false)?;
        let mut statement = connection.prepare(
            "SELECT provider_id, policy_digest, exact_policy
             FROM issuer_service_policies ORDER BY provider_id, policy_epoch",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let wanted = authorization
            .claims
            .rules
            .iter()
            .map(|rule| rule.credential_binding_digest)
            .collect::<BTreeSet<_>>();
        let mut found = std::collections::BTreeMap::new();
        for (provider_id, policy_digest, exact_policy) in rows {
            let provider_id = fixed_blob(provider_id, "invalid retained policy provider ID")?;
            let policy_digest = fixed_blob(policy_digest, "invalid retained policy digest")?;
            let policy = ServicePolicyV1::decode(&exact_policy).map_err(|_| {
                StoreError::SchemaMismatch("retained service policy is not canonical".to_owned())
            })?;
            if policy.encode()? != exact_policy
                || policy.provider_id != provider_id
                || policy.policy_digest()? != policy_digest
            {
                return Err(StoreError::SchemaMismatch(
                    "retained service policy row is not self-consistent".to_owned(),
                ));
            }
            for scope in &policy.scopes {
                for offer in &scope.offers {
                    let Some(binding) = &offer.credential_binding else {
                        continue;
                    };
                    let digest = binding.binding_digest()?;
                    if !wanted.contains(&digest) {
                        continue;
                    }
                    if binding.issuer_id != self.handle.expected_issuer_id
                        || binding.claims.provider_id != authorization.claims.provider_id
                        || binding.claims.scope_id != scope.scope.scope_id()
                        || binding.claims.offer_id != offer.offer_id
                        || binding.claims.scheme != offer.authorization
                    {
                        return Err(StoreError::SchemaMismatch(
                            "clearing binding does not match its retained policy offer".to_owned(),
                        ));
                    }
                    let expectation = CredentialKeyBindingExpectationV1 {
                        issuer_id: &self.handle.expected_issuer_id,
                        provider_id: &binding.claims.provider_id,
                        scope_id: &binding.claims.scope_id,
                        offer_id: binding.claims.offer_id,
                        scheme: binding.claims.scheme,
                        minimum_keyset_epoch: binding.claims.keyset_epoch,
                        entitlement_profile: binding.claims.entitlement_profile,
                        presentation_limit: binding.claims.presentation_limit,
                        credential_key_id: &binding.claims.credential_key_id,
                    };
                    binding
                        .verify_for(&expectation, binding.claims.not_before)
                        .map_err(StoreError::Protocol)?;
                    if let Some(previous) = found.insert(digest, binding.clone()) {
                        if previous != *binding {
                            return Err(StoreError::SchemaMismatch(
                                "clearing binding digest maps to different retained bindings"
                                    .to_owned(),
                            ));
                        }
                    }
                }
            }
        }

        let mut resolved = Vec::with_capacity(authorization.claims.rules.len());
        for rule in &authorization.claims.rules {
            let binding =
                found
                    .get(&rule.credential_binding_digest)
                    .ok_or(StoreError::InvalidInput(
                        "clearing rule binding is not retained by this issuer",
                    ))?;
            match binding.claims.scheme {
                AuthScheme::FreeV1 => {}
                AuthScheme::BitcoinPirCashuBatV1 => {
                    let raw_public_key: [u8; 33] = binding
                        .claims
                        .verification_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| {
                            StoreError::SchemaMismatch(
                                "BAT clearing binding key is not 33 bytes".to_owned(),
                            )
                        })?;
                    let lineage = crate::registry_ops::read_bat_lineage(
                        &connection,
                        self,
                        &pir_service_protocol::bat_verification_key_fingerprint_v1(&raw_public_key)
                            .map_err(StoreError::Protocol)?,
                    )?
                    .ok_or(StoreError::InvalidInput(
                        "BAT clearing binding has no immutable issuer lineage",
                    ))?;
                    if lineage.raw_public_key != raw_public_key
                        || lineage.provider_id != binding.claims.provider_id
                        || lineage.scope_id != binding.claims.scope_id
                        || lineage.offer_id != binding.claims.offer_id
                        || lineage.entitlement_profile != binding.claims.entitlement_profile
                        || lineage.keyset_epoch != binding.claims.keyset_epoch
                        || lineage.credential_key_id.as_slice()
                            != binding.claims.credential_key_id.as_slice()
                    {
                        return Err(StoreError::SchemaMismatch(
                            "BAT clearing binding conflicts with immutable issuer lineage"
                                .to_owned(),
                        ));
                    }
                }
                AuthScheme::ArcV1Experimental => {
                    let raw_public_key: [u8; 99] = binding
                        .claims
                        .verification_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| {
                            StoreError::SchemaMismatch(
                                "ARC clearing binding key is not 99 bytes".to_owned(),
                            )
                        })?;
                    let lineage = crate::registry_ops::read_arc_lineage(
                        &connection,
                        self,
                        &pir_arc_adapter::arc_public_key_fingerprint_v1(&raw_public_key)
                            .map_err(|_| StoreError::InvalidInput("invalid ARC clearing key"))?,
                    )?
                    .ok_or(StoreError::InvalidInput(
                        "ARC clearing binding has no immutable issuer lineage",
                    ))?;
                    if lineage.raw_public_key != raw_public_key
                        || lineage.binding_digest != rule.credential_binding_digest
                        || lineage.provider_id != binding.claims.provider_id
                        || lineage.scope_id != binding.claims.scope_id
                        || lineage.offer_id != binding.claims.offer_id
                        || lineage.entitlement_profile != binding.claims.entitlement_profile
                        || lineage.keyset_epoch != binding.claims.keyset_epoch
                        || lineage.credential_key_id != binding.claims.credential_key_id
                    {
                        return Err(StoreError::SchemaMismatch(
                            "ARC clearing binding conflicts with immutable issuer lineage"
                                .to_owned(),
                        ));
                    }
                }
                AuthScheme::Bolt11DirectReceiptV1 | AuthScheme::CashuEcashV1 => {
                    return Err(StoreError::InvalidInput(
                        "clearing rule references a non-shared credential scheme",
                    ));
                }
                AuthScheme::BitcoinPirCashuBatV2 => {
                    return Err(StoreError::InvalidInput(
                        "BAT V2 has no V1 credential binding or clearing-rule path",
                    ));
                }
            }
            resolved.push(binding.clone());
        }
        Ok(resolved)
    }
}

pub(crate) fn read_policy_head(
    connection: &Connection,
    store: &IssuerStore,
    provider_id: &[u8; 32],
) -> StoreResult<Option<IssuerServicePolicyRecordV1>> {
    type RawHead = (i64, Vec<u8>, Vec<u8>, i64);
    let head: Option<RawHead> = connection
        .query_row(
            "SELECT highest_epoch, policy_digest, policy_verifying_key, commit_seq \
             FROM issuer_service_policy_heads WHERE provider_id = ?1",
            [provider_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    head.map(|(highest_epoch, digest, verifying_key, commit_seq)| {
        let highest_epoch = db_u64(highest_epoch, "negative service policy head epoch")?;
        let digest = fixed_blob(digest, "invalid service policy head digest")?;
        let verifying_key = fixed_blob(verifying_key, "invalid service policy head verifying key")?;
        let commit_seq = db_u64(commit_seq, "negative service policy head commit")?;
        let record =
            read_policy_by_digest(connection, store, provider_id, &digest)?.ok_or_else(|| {
                StoreError::SchemaMismatch(
                    "service policy head points to a missing retained policy".to_owned(),
                )
            })?;
        if record.policy_epoch != highest_epoch
            || record.policy_verifying_key != verifying_key
            || record.commit.commit_seq != commit_seq
        {
            return Err(StoreError::SchemaMismatch(
                "service policy head metadata points to different retained rows".to_owned(),
            ));
        }
        Ok(record)
    })
    .transpose()
}

pub(crate) fn read_policy_by_digest(
    connection: &Connection,
    store: &IssuerStore,
    provider_id: &[u8; 32],
    policy_digest: &[u8; 32],
) -> StoreResult<Option<IssuerServicePolicyRecordV1>> {
    if provider_id.iter().all(|byte| *byte == 0) || policy_digest.iter().all(|byte| *byte == 0) {
        return Err(StoreError::InvalidInput("invalid service policy lookup"));
    }
    type Raw = (i64, Vec<u8>, Vec<u8>, i64, i64);
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT policy_epoch, policy_verifying_key, exact_policy, expires_at, commit_seq \
             FROM issuer_service_policies WHERE provider_id = ?1 AND policy_digest = ?2",
            params![provider_id.as_slice(), policy_digest.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let policy_epoch = db_u64(raw.0, "negative service policy epoch")?;
        let policy_verifying_key: [u8; 32] =
            fixed_blob(raw.1, "invalid service policy verifying key")?;
        let exact_policy = raw.2;
        let expires_at = db_u64(raw.3, "negative service policy expiry")?;
        let commit_seq = db_u64(raw.4, "negative service policy commit")?;
        let policy = ServicePolicyV1::decode(&exact_policy).map_err(|_| {
            StoreError::SchemaMismatch("retained service policy is not canonical".to_owned())
        })?;
        let key = VerifyingKey::from_bytes(&policy_verifying_key).map_err(|_| {
            StoreError::SchemaMismatch("retained service policy key is malformed".to_owned())
        })?;
        if policy.encode()? != exact_policy
            || policy.provider_id != *provider_id
            || policy.policy_epoch != policy_epoch
            || policy.expires_at != expires_at
            || policy.policy_digest()? != *policy_digest
            || policy
                .verify_signature_and_identity(provider_id, &key)
                .is_err()
        {
            return Err(StoreError::SchemaMismatch(
                "retained service policy metadata or signature mismatches".to_owned(),
            ));
        }
        Ok(IssuerServicePolicyRecordV1 {
            provider_id: *provider_id,
            policy_epoch,
            policy_digest: *policy_digest,
            policy_verifying_key,
            exact_policy,
            expires_at,
            commit: marker(store, commit_seq),
        })
    })
    .transpose()
}

/// Resolves a BAT V2 member only through the provider's currently registered
/// policy head. This is used inside the class-registration transaction so a
/// retained but superseded policy can never activate a new class epoch.
pub(crate) fn project_current_bat_acceptance_member_v2(
    connection: &Connection,
    store: &IssuerStore,
    member: &BatAcceptanceMemberV2,
    now_unix: u64,
) -> StoreResult<(VerifiedBatAcceptanceMemberV2, IssuerServicePolicyRecordV1)> {
    let record = read_policy_head(connection, store, &member.provider_id)?
        .ok_or(StoreError::BatV2ClassMemberMismatch)?;
    if record.policy_digest != member.policy_digest {
        return Err(StoreError::BatV2ClassMemberMismatch);
    }
    let floors = read_policy_floors(connection, &member.provider_id)?;
    project_bat_acceptance_member_from_record_v2(record, member, now_unix, &floors)
}

/// Rebuilds the BAT V2 projection from one retained exact signed policy at its
/// original issuance time. It is readback/integrity-only and therefore never
/// makes an expired policy eligible for a new class registration.
pub(crate) fn project_retained_bat_acceptance_member_v2(
    connection: &Connection,
    store: &IssuerStore,
    member: &BatAcceptanceMemberV2,
) -> StoreResult<(VerifiedBatAcceptanceMemberV2, IssuerServicePolicyRecordV1)> {
    let record = read_policy_by_digest(
        connection,
        store,
        &member.provider_id,
        &member.policy_digest,
    )?
    .ok_or_else(|| StoreError::SchemaMismatch("BAT V2 member policy is not retained".to_owned()))?;
    let policy = ServicePolicyV1::decode(&record.exact_policy).map_err(|_| {
        StoreError::SchemaMismatch("retained BAT V2 member policy is not canonical".to_owned())
    })?;
    project_bat_acceptance_member_from_record_v2(
        record,
        member,
        policy.issued_at,
        &ServicePolicyEpochFloorsV1::initial(),
    )
}

fn project_bat_acceptance_member_from_record_v2(
    record: IssuerServicePolicyRecordV1,
    member: &BatAcceptanceMemberV2,
    verification_time: u64,
    floors: &ServicePolicyEpochFloorsV1,
) -> StoreResult<(VerifiedBatAcceptanceMemberV2, IssuerServicePolicyRecordV1)> {
    let policy = ServicePolicyV1::decode(&record.exact_policy).map_err(|_| {
        StoreError::SchemaMismatch("retained BAT V2 member policy is not canonical".to_owned())
    })?;
    let key = VerifyingKey::from_bytes(&record.policy_verifying_key).map_err(|_| {
        StoreError::SchemaMismatch("retained BAT V2 policy key is malformed".to_owned())
    })?;
    let guard = PolicyRollbackGuardV1 {
        highest_epoch: record.policy_epoch,
        digest_at_highest_epoch: record.policy_digest,
    };
    let verified = policy
        .verify_current_for_acquisition(
            &member.provider_id,
            verification_time,
            &guard,
            floors,
            &key,
        )
        .map_err(|_| StoreError::BatV2ClassMemberMismatch)?;
    let projection =
        bat_acceptance_member_from_verified_policy_v2(&verified, &member.scope_id, member.offer_id)
            .map_err(|_| StoreError::BatV2ClassMemberMismatch)?;
    if projection.member != *member {
        return Err(StoreError::BatV2ClassMemberMismatch);
    }
    Ok((projection, record))
}

fn read_policy_floors(
    connection: &Connection,
    provider_id: &[u8; 32],
) -> StoreResult<ServicePolicyEpochFloorsV1> {
    let mut credential_statement = connection.prepare(
        "SELECT scope_id, scheme, credential_issuer_id, minimum_epoch \
         FROM issuer_credential_keyset_floors WHERE provider_id = ?1 \
         ORDER BY scope_id, scheme, credential_issuer_id",
    )?;
    let credential_rows = credential_statement.query_map([provider_id.as_slice()], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let mut credential_keysets = Vec::new();
    for row in credential_rows {
        let (scope_id, scheme, issuer_id, minimum_epoch) = row?;
        credential_keysets.push(CredentialKeysetEpochFloorV1 {
            scope_id: fixed_blob(scope_id, "invalid credential floor scope")?,
            scheme: decode_scheme(scheme)?,
            issuer_id: fixed_blob(issuer_id, "invalid credential floor issuer")?,
            minimum_epoch: db_u64(minimum_epoch, "negative credential floor epoch")?,
        });
    }

    let mut cashu_statement = connection.prepare(
        "SELECT mint_id, unit, minimum_epoch FROM issuer_cashu_manifest_floors \
         WHERE provider_id = ?1 ORDER BY mint_id, unit",
    )?;
    let cashu_rows = cashu_statement.query_map([provider_id.as_slice()], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    let mut cashu_manifests = Vec::new();
    for row in cashu_rows {
        let (mint_id, unit, minimum_epoch) = row?;
        cashu_manifests.push(CashuManifestEpochFloorV1 {
            mint_id: fixed_blob(mint_id, "invalid Cashu floor mint")?,
            unit,
            minimum_epoch: db_u64(minimum_epoch, "negative Cashu floor epoch")?,
        });
    }
    Ok(ServicePolicyEpochFloorsV1 {
        credential_keysets,
        cashu_manifests,
    })
}

fn write_policy_floors(
    transaction: &rusqlite::Transaction<'_>,
    provider_id: &[u8; 32],
    floors: &ServicePolicyEpochFloorsV1,
    sequence: u64,
) -> StoreResult<()> {
    for floor in &floors.credential_keysets {
        transaction.execute(
            "INSERT INTO issuer_credential_keyset_floors (provider_id, scope_id, scheme, \
             credential_issuer_id, minimum_epoch, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(provider_id, scope_id, scheme, credential_issuer_id) DO UPDATE SET \
             minimum_epoch = excluded.minimum_epoch, commit_seq = excluded.commit_seq",
            params![
                provider_id.as_slice(),
                floor.scope_id.as_slice(),
                floor.scheme as u8,
                floor.issuer_id.as_slice(),
                sql_integer(floor.minimum_epoch, "credential floor exceeds SQLite range")?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
    }
    for floor in &floors.cashu_manifests {
        transaction.execute(
            "INSERT INTO issuer_cashu_manifest_floors (provider_id, mint_id, unit, \
             minimum_epoch, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(provider_id, mint_id, unit) DO UPDATE SET \
             minimum_epoch = excluded.minimum_epoch, commit_seq = excluded.commit_seq",
            params![
                provider_id.as_slice(),
                floor.mint_id.as_slice(),
                &floor.unit,
                sql_integer(floor.minimum_epoch, "Cashu floor exceeds SQLite range")?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
    }
    Ok(())
}

fn policy_floor_digest(floors: &ServicePolicyEpochFloorsV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_FLOOR_DIGEST_DOMAIN_V1);
    hasher.update((floors.credential_keysets.len() as u32).to_le_bytes());
    for floor in &floors.credential_keysets {
        hasher.update(floor.scope_id);
        hasher.update([floor.scheme as u8]);
        hasher.update(floor.issuer_id);
        hasher.update(floor.minimum_epoch.to_le_bytes());
    }
    hasher.update((floors.cashu_manifests.len() as u32).to_le_bytes());
    for floor in &floors.cashu_manifests {
        hasher.update(floor.mint_id);
        hasher.update((floor.unit.len() as u16).to_le_bytes());
        hasher.update(floor.unit.as_bytes());
        hasher.update(floor.minimum_epoch.to_le_bytes());
    }
    hasher.finalize().into()
}

fn decode_scheme(value: i64) -> StoreResult<AuthScheme> {
    match value {
        1 => Ok(AuthScheme::FreeV1),
        2 => Ok(AuthScheme::Bolt11DirectReceiptV1),
        3 => Ok(AuthScheme::CashuEcashV1),
        4 => Ok(AuthScheme::BitcoinPirCashuBatV1),
        5 => Ok(AuthScheme::ArcV1Experimental),
        _ => Err(StoreError::SchemaMismatch(
            "invalid credential floor scheme".to_owned(),
        )),
    }
}

fn marker(store: &IssuerStore, sequence: u64) -> CommitMarker {
    CommitMarker {
        store_instance_id: store.handle.expected_store_instance_id,
        commit_seq: sequence,
    }
}
