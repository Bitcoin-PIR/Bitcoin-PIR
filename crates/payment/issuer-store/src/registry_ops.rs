use crate::db::{
    advance_store_generation, commit, db_u64, fixed_blob, is_zero, sql_integer,
    verify_expected_identity,
};
use crate::rollback::mutation_digest;
use crate::{
    ArcKeyLineageV1, BatKeyLineage, BatKeyLineageRegistration, CommitMarker, DurableWrite,
    IssuerStore, SettlementKeyLineage, SettlementKeyLineageRegistration, StoreError, StoreResult,
    WriteDisposition,
};
use pir_service_protocol::{
    bat_verification_key_fingerprint_v1, derive_bat_key_id_v1, is_canonical_cashu_keyset_id_v2,
    settlement_denomination_key_fingerprint_v1, AuthScheme, CredentialKeyBindingExpectationV1,
    CredentialKeyBindingV1,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

const BAT_KEY_LINEAGE_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/issuer-store/bat-key-lineage/v1";
const SETTLEMENT_KEY_LINEAGE_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/settlement-key-lineage/v1";

impl IssuerStore {
    /// Permanently binds one draft-01 ARC raw public key to one complete,
    /// issuer-signed audience lineage. ARC remains experimental; registration
    /// is necessary for redemption but does not activate it in policy/runtime.
    pub fn register_arc_key_lineage_experimental(
        &self,
        binding: &CredentialKeyBindingV1,
        now_unix: u64,
    ) -> StoreResult<DurableWrite<ArcKeyLineageV1>> {
        let candidate = build_arc_lineage(self, binding, now_unix)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        if let Some(existing) = read_arc_lineage(&transaction, self, &candidate.key_fingerprint)? {
            if arc_lineage_matches(&existing, &candidate) {
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.commit,
                    value: existing,
                });
            }
            return Err(StoreError::ArcKeyLineageConflict);
        }
        let owner: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT key_fingerprint FROM arc_key_lineages WHERE issuer_id = ?1 AND (\
                 binding_digest = ?2 OR credential_key_id = ?3 OR lineage_digest = ?4 OR \
                 (provider_id = ?5 AND scope_id = ?6 AND offer_id = ?7 AND \
                  entitlement_profile = ?8 AND keyset_epoch = ?9))",
                params![
                    self.handle.expected_issuer_id.as_slice(),
                    candidate.binding_digest.as_slice(),
                    candidate.credential_key_id.as_slice(),
                    candidate.lineage_digest.as_slice(),
                    candidate.provider_id.as_slice(),
                    candidate.scope_id.as_slice(),
                    i64::from(candidate.offer_id),
                    i64::from(candidate.entitlement_profile),
                    sql_integer(
                        candidate.keyset_epoch,
                        "ARC keyset epoch exceeds SQLite range"
                    )?,
                ],
                |row| row.get(0),
            )
            .optional()?;
        if owner.is_some() {
            return Err(StoreError::ArcKeyLineageConflict);
        }
        let digest = mutation_digest(
            b"register-arc-lineage-experimental-v1",
            &[
                &candidate.key_fingerprint,
                &candidate.binding_digest,
                &candidate.lineage_digest,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"register-arc-lineage-experimental-v1",
            &digest,
        )?;
        let sequence = committed_identity.commit_seq;
        transaction.execute(
            "INSERT INTO arc_key_lineages (issuer_id, key_fingerprint, raw_public_key, \
             binding_digest, provider_id, scope_id, offer_id, entitlement_profile, keyset_epoch, \
             credential_key_id, exact_binding, lineage_digest, commit_seq) VALUES (?1, ?2, ?3, \
             ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                self.handle.expected_issuer_id.as_slice(),
                candidate.key_fingerprint.as_slice(),
                candidate.raw_public_key.as_slice(),
                candidate.binding_digest.as_slice(),
                candidate.provider_id.as_slice(),
                candidate.scope_id.as_slice(),
                i64::from(candidate.offer_id),
                i64::from(candidate.entitlement_profile),
                sql_integer(
                    candidate.keyset_epoch,
                    "ARC keyset epoch exceeds SQLite range"
                )?,
                candidate.credential_key_id.as_slice(),
                candidate.exact_binding.as_slice(),
                candidate.lineage_digest.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let value = self
            .arc_key_lineage_experimental(&candidate.raw_public_key)?
            .ok_or_else(|| {
                StoreError::SchemaMismatch("committed ARC lineage missing".to_owned())
            })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value,
        })
    }

    pub fn arc_key_lineage_experimental(
        &self,
        raw_public_key: &[u8; 99],
    ) -> StoreResult<Option<ArcKeyLineageV1>> {
        let fingerprint = pir_arc_adapter::arc_public_key_fingerprint_v1(raw_public_key)
            .map_err(|_| StoreError::InvalidInput("invalid ARC public key"))?;
        let connection = self.open_checked(false)?;
        let value = read_arc_lineage(&connection, self, &fingerprint)?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Registers one raw BAT verification key in exactly one audience lineage.
    /// The mapping remains immutable after policies or credentials expire.
    pub fn register_bat_key_lineage(
        &self,
        registration: &BatKeyLineageRegistration,
    ) -> StoreResult<DurableWrite<BatKeyLineage>> {
        let candidate = build_bat_lineage(self, registration)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        if let Some(existing) = read_bat_lineage(&transaction, self, &candidate.key_fingerprint)? {
            if bat_lineage_matches(&existing, &candidate) {
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.commit,
                    value: existing,
                });
            }
            return Err(StoreError::BatKeyLineageConflict);
        }
        let tuple_owner: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT key_fingerprint FROM bat_key_lineages WHERE issuer_id = ?1 AND (\
                    credential_key_id = ?2 OR \
                    (provider_id = ?3 AND scope_id = ?4 AND offer_id = ?5 AND \
                     entitlement_profile = ?6 AND keyset_epoch = ?7) OR lineage_digest = ?8)",
                params![
                    self.handle.expected_issuer_id.as_slice(),
                    candidate.credential_key_id.as_slice(),
                    candidate.provider_id.as_slice(),
                    candidate.scope_id.as_slice(),
                    i64::from(candidate.offer_id),
                    i64::from(candidate.entitlement_profile),
                    sql_integer(candidate.keyset_epoch, "BAT epoch exceeds SQLite range")?,
                    candidate.lineage_digest.as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()?;
        if tuple_owner.is_some() {
            return Err(StoreError::BatKeyLineageConflict);
        }

        let digest = mutation_digest(
            b"register-bat-lineage-v1",
            &[
                &candidate.key_fingerprint,
                &candidate.raw_public_key,
                &candidate.lineage_digest,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"register-bat-lineage-v1",
            &digest,
        )?;
        let sequence = committed_identity.commit_seq;
        transaction.execute(
            "INSERT INTO bat_key_lineages (issuer_id, key_fingerprint, raw_public_key, \
             provider_id, scope_id, offer_id, entitlement_profile, keyset_epoch, \
             credential_key_id, lineage_digest, commit_seq) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                self.handle.expected_issuer_id.as_slice(),
                candidate.key_fingerprint.as_slice(),
                candidate.raw_public_key.as_slice(),
                candidate.provider_id.as_slice(),
                candidate.scope_id.as_slice(),
                i64::from(candidate.offer_id),
                i64::from(candidate.entitlement_profile),
                sql_integer(candidate.keyset_epoch, "BAT epoch exceeds SQLite range")?,
                candidate.credential_key_id.as_slice(),
                candidate.lineage_digest.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let value = self
            .bat_key_lineage(&registration.raw_public_key)?
            .ok_or_else(|| {
                StoreError::SchemaMismatch("committed BAT lineage missing".to_owned())
            })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value,
        })
    }

    pub fn bat_key_lineage(&self, raw_public_key: &[u8; 33]) -> StoreResult<Option<BatKeyLineage>> {
        let fingerprint = bat_verification_key_fingerprint_v1(raw_public_key)
            .map_err(|_| StoreError::InvalidInput("invalid BAT public key"))?;
        let connection = self.open_checked(false)?;
        let value = read_bat_lineage(&connection, self, &fingerprint)?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Registers one settlement denomination key in one immutable Cashu
    /// keyset/denomination lineage.
    pub fn register_settlement_key_lineage(
        &self,
        registration: &SettlementKeyLineageRegistration,
    ) -> StoreResult<DurableWrite<SettlementKeyLineage>> {
        let candidate = build_settlement_lineage(self, registration)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        if let Some(existing) =
            read_settlement_lineage(&transaction, self, &candidate.key_fingerprint)?
        {
            if settlement_lineage_matches(&existing, &candidate) {
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.commit,
                    value: existing,
                });
            }
            return Err(StoreError::SettlementKeyLineageConflict);
        }
        let tuple_owner: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT key_fingerprint FROM settlement_key_lineages \
                 WHERE issuer_id = ?1 AND ((keyset_id = ?2 AND denomination = ?3) \
                 OR lineage_digest = ?4)",
                params![
                    self.handle.expected_issuer_id.as_slice(),
                    &candidate.keyset_id,
                    sql_integer(candidate.denomination, "denomination exceeds SQLite range")?,
                    candidate.lineage_digest.as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()?;
        if tuple_owner.is_some() {
            return Err(StoreError::SettlementKeyLineageConflict);
        }

        let digest = mutation_digest(
            b"register-settlement-lineage-v1",
            &[
                &candidate.key_fingerprint,
                &candidate.raw_public_key,
                &candidate.lineage_digest,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"register-settlement-lineage-v1",
            &digest,
        )?;
        let sequence = committed_identity.commit_seq;
        transaction.execute(
            "INSERT INTO settlement_key_lineages (issuer_id, key_fingerprint, raw_public_key, \
             keyset_id, unit, keyset_epoch, denomination, manifest_digest, final_expiry, \
             lineage_digest, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                self.handle.expected_issuer_id.as_slice(),
                candidate.key_fingerprint.as_slice(),
                candidate.raw_public_key.as_slice(),
                &candidate.keyset_id,
                &candidate.unit,
                sql_integer(
                    candidate.keyset_epoch,
                    "settlement keyset epoch exceeds SQLite range"
                )?,
                sql_integer(candidate.denomination, "denomination exceeds SQLite range")?,
                candidate.manifest_digest.as_slice(),
                candidate
                    .final_expiry
                    .map(|value| sql_integer(value, "settlement final expiry exceeds SQLite range"))
                    .transpose()?,
                candidate.lineage_digest.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let value = self
            .settlement_key_lineage(&registration.raw_public_key)?
            .ok_or_else(|| {
                StoreError::SchemaMismatch("committed settlement lineage missing".to_owned())
            })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value,
        })
    }

    pub fn settlement_key_lineage(
        &self,
        raw_public_key: &[u8; 33],
    ) -> StoreResult<Option<SettlementKeyLineage>> {
        let fingerprint = settlement_denomination_key_fingerprint_v1(raw_public_key)
            .map_err(|_| StoreError::InvalidInput("invalid settlement public key"))?;
        let connection = self.open_checked(false)?;
        let value = read_settlement_lineage(&connection, self, &fingerprint)?;
        self.confirm_anchored_read(&connection, value)
    }
}

fn build_arc_lineage(
    store: &IssuerStore,
    binding: &CredentialKeyBindingV1,
    now_unix: u64,
) -> StoreResult<ArcKeyLineageV1> {
    if binding.issuer_id != store.handle.expected_issuer_id
        || binding.claims.scheme != AuthScheme::ArcV1Experimental
        || now_unix == 0
    {
        return Err(StoreError::InvalidInput("invalid experimental ARC lineage"));
    }
    let expected = CredentialKeyBindingExpectationV1 {
        issuer_id: &store.handle.expected_issuer_id,
        provider_id: &binding.claims.provider_id,
        scope_id: &binding.claims.scope_id,
        offer_id: binding.claims.offer_id,
        scheme: AuthScheme::ArcV1Experimental,
        minimum_keyset_epoch: binding.claims.keyset_epoch,
        entitlement_profile: binding.claims.entitlement_profile,
        presentation_limit: binding.claims.presentation_limit,
        credential_key_id: &binding.claims.credential_key_id,
    };
    let lineage = pir_arc_adapter::ArcExclusiveKeyLineageV1::from_verified_binding(
        binding, &expected, now_unix,
    )
    .map_err(|_| StoreError::InvalidInput("ARC binding or public key is invalid"))?;
    let raw_public_key: [u8; 99] = binding
        .claims
        .verification_key
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::InvalidInput("ARC public key is not 99 bytes"))?;
    Ok(ArcKeyLineageV1 {
        key_fingerprint: *lineage.public_key_fingerprint(),
        raw_public_key,
        binding_digest: binding.binding_digest()?,
        provider_id: binding.claims.provider_id,
        scope_id: binding.claims.scope_id,
        offer_id: binding.claims.offer_id,
        entitlement_profile: binding.claims.entitlement_profile,
        keyset_epoch: binding.claims.keyset_epoch,
        credential_key_id: binding.claims.credential_key_id.clone(),
        exact_binding: binding.encode()?,
        lineage_digest: *lineage.lineage_digest(),
        commit: marker(store, 1),
    })
}

fn arc_lineage_matches(left: &ArcKeyLineageV1, right: &ArcKeyLineageV1) -> bool {
    left.key_fingerprint == right.key_fingerprint
        && left.raw_public_key == right.raw_public_key
        && left.binding_digest == right.binding_digest
        && left.provider_id == right.provider_id
        && left.scope_id == right.scope_id
        && left.offer_id == right.offer_id
        && left.entitlement_profile == right.entitlement_profile
        && left.keyset_epoch == right.keyset_epoch
        && left.credential_key_id == right.credential_key_id
        && left.exact_binding == right.exact_binding
        && left.lineage_digest == right.lineage_digest
}

pub(crate) fn read_arc_lineage(
    connection: &Connection,
    store: &IssuerStore,
    fingerprint: &[u8; 32],
) -> StoreResult<Option<ArcKeyLineageV1>> {
    type Raw = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
    );
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT raw_public_key, binding_digest, provider_id, scope_id, offer_id, \
             entitlement_profile, keyset_epoch, credential_key_id, exact_binding, \
             lineage_digest, commit_seq FROM arc_key_lineages WHERE issuer_id = ?1 \
             AND key_fingerprint = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                fingerprint.as_slice()
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
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let exact_binding: Vec<u8> = raw.8;
        let binding = CredentialKeyBindingV1::decode(&exact_binding)?;
        if binding.encode()? != exact_binding {
            return Err(StoreError::SchemaMismatch(
                "ARC binding is not canonical".to_owned(),
            ));
        }
        let value = ArcKeyLineageV1 {
            key_fingerprint: *fingerprint,
            raw_public_key: fixed_blob(raw.0, "invalid ARC raw public key")?,
            binding_digest: fixed_blob(raw.1, "invalid ARC binding digest")?,
            provider_id: fixed_blob(raw.2, "invalid ARC provider id")?,
            scope_id: fixed_blob(raw.3, "invalid ARC scope id")?,
            offer_id: u32::try_from(raw.4)
                .map_err(|_| StoreError::SchemaMismatch("invalid ARC offer id".to_owned()))?,
            entitlement_profile: u16::try_from(raw.5)
                .map_err(|_| StoreError::SchemaMismatch("invalid ARC profile".to_owned()))?,
            keyset_epoch: db_u64(raw.6, "negative ARC keyset epoch")?,
            credential_key_id: raw.7,
            exact_binding,
            lineage_digest: fixed_blob(raw.9, "invalid ARC lineage digest")?,
            commit: marker(store, db_u64(raw.10, "negative ARC commit")?),
        };
        let rebuilt = build_arc_lineage(store, &binding, binding.claims.not_before)?;
        if !arc_lineage_matches(&value, &rebuilt) {
            return Err(StoreError::SchemaMismatch(
                "ARC lineage digest or binding mismatch".to_owned(),
            ));
        }
        Ok(value)
    })
    .transpose()
}

fn build_bat_lineage(
    store: &IssuerStore,
    value: &BatKeyLineageRegistration,
) -> StoreResult<BatKeyLineage> {
    if is_zero(&value.provider_id)
        || is_zero(&value.scope_id)
        || value.offer_id == 0
        || value.entitlement_profile == 0
        || value.keyset_epoch == 0
    {
        return Err(StoreError::InvalidInput("invalid BAT key lineage"));
    }
    let key_fingerprint = bat_verification_key_fingerprint_v1(&value.raw_public_key)
        .map_err(|_| StoreError::InvalidInput("invalid BAT public key"))?;
    let expected_key_id = derive_bat_key_id_v1(
        &value.provider_id,
        &value.scope_id,
        value.offer_id,
        value.entitlement_profile,
        value.keyset_epoch,
        &value.raw_public_key,
    );
    if value.credential_key_id != expected_key_id {
        return Err(StoreError::InvalidInput(
            "BAT credential key id is not audience-derived",
        ));
    }
    let _ = sql_integer(value.keyset_epoch, "BAT epoch exceeds SQLite range")?;
    let mut hasher = Sha256::new();
    hasher.update(BAT_KEY_LINEAGE_DIGEST_DOMAIN_V1);
    hasher.update(store.handle.expected_issuer_id);
    hasher.update(key_fingerprint);
    hasher.update(value.provider_id);
    hasher.update(value.scope_id);
    hasher.update(value.offer_id.to_le_bytes());
    hasher.update(value.entitlement_profile.to_le_bytes());
    hasher.update(value.keyset_epoch.to_le_bytes());
    hasher.update(value.credential_key_id);
    let lineage_digest = hasher.finalize().into();
    Ok(BatKeyLineage {
        key_fingerprint,
        raw_public_key: value.raw_public_key,
        provider_id: value.provider_id,
        scope_id: value.scope_id,
        offer_id: value.offer_id,
        entitlement_profile: value.entitlement_profile,
        keyset_epoch: value.keyset_epoch,
        credential_key_id: value.credential_key_id,
        lineage_digest,
        commit: marker(store, 1),
    })
}

fn build_settlement_lineage(
    store: &IssuerStore,
    value: &SettlementKeyLineageRegistration,
) -> StoreResult<SettlementKeyLineage> {
    if !is_canonical_cashu_keyset_id_v2(&value.keyset_id)
        || value.unit.is_empty()
        || value.unit.len() > 64
        || !value.unit.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        || value.keyset_epoch == 0
        || value.denomination == 0
        || is_zero(&value.manifest_digest)
        || value.final_expiry == Some(0)
    {
        return Err(StoreError::InvalidInput("invalid settlement key lineage"));
    }
    let key_fingerprint = settlement_denomination_key_fingerprint_v1(&value.raw_public_key)
        .map_err(|_| StoreError::InvalidInput("invalid settlement public key"))?;
    let _ = sql_integer(
        value.keyset_epoch,
        "settlement keyset epoch exceeds SQLite range",
    )?;
    let _ = sql_integer(value.denomination, "denomination exceeds SQLite range")?;
    if let Some(expiry) = value.final_expiry {
        let _ = sql_integer(expiry, "settlement final expiry exceeds SQLite range")?;
    }
    let mut hasher = Sha256::new();
    hasher.update(SETTLEMENT_KEY_LINEAGE_DIGEST_DOMAIN_V1);
    hasher.update(store.handle.expected_issuer_id);
    hasher.update(key_fingerprint);
    hasher.update((value.keyset_id.len() as u16).to_le_bytes());
    hasher.update(value.keyset_id.as_bytes());
    hasher.update((value.unit.len() as u16).to_le_bytes());
    hasher.update(value.unit.as_bytes());
    hasher.update(value.keyset_epoch.to_le_bytes());
    hasher.update(value.denomination.to_le_bytes());
    hasher.update(value.manifest_digest);
    match value.final_expiry {
        Some(expiry) => {
            hasher.update([1]);
            hasher.update(expiry.to_le_bytes());
        }
        None => hasher.update([0]),
    }
    let lineage_digest = hasher.finalize().into();
    Ok(SettlementKeyLineage {
        key_fingerprint,
        raw_public_key: value.raw_public_key,
        keyset_id: value.keyset_id.clone(),
        unit: value.unit.clone(),
        keyset_epoch: value.keyset_epoch,
        denomination: value.denomination,
        manifest_digest: value.manifest_digest,
        final_expiry: value.final_expiry,
        lineage_digest,
        commit: marker(store, 1),
    })
}

fn bat_lineage_matches(left: &BatKeyLineage, right: &BatKeyLineage) -> bool {
    left.key_fingerprint == right.key_fingerprint
        && left.raw_public_key == right.raw_public_key
        && left.provider_id == right.provider_id
        && left.scope_id == right.scope_id
        && left.offer_id == right.offer_id
        && left.entitlement_profile == right.entitlement_profile
        && left.keyset_epoch == right.keyset_epoch
        && left.credential_key_id == right.credential_key_id
        && left.lineage_digest == right.lineage_digest
}

fn settlement_lineage_matches(left: &SettlementKeyLineage, right: &SettlementKeyLineage) -> bool {
    left.key_fingerprint == right.key_fingerprint
        && left.raw_public_key == right.raw_public_key
        && left.keyset_id == right.keyset_id
        && left.unit == right.unit
        && left.keyset_epoch == right.keyset_epoch
        && left.denomination == right.denomination
        && left.manifest_digest == right.manifest_digest
        && left.final_expiry == right.final_expiry
        && left.lineage_digest == right.lineage_digest
}

pub(crate) fn read_bat_lineage(
    connection: &Connection,
    store: &IssuerStore,
    fingerprint: &[u8; 32],
) -> StoreResult<Option<BatKeyLineage>> {
    type Raw = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        i64,
    );
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT raw_public_key, provider_id, scope_id, offer_id, entitlement_profile, \
             keyset_epoch, credential_key_id, lineage_digest, commit_seq \
             FROM bat_key_lineages WHERE issuer_id = ?1 AND key_fingerprint = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                fingerprint.as_slice()
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
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let value = BatKeyLineage {
            key_fingerprint: *fingerprint,
            raw_public_key: fixed_blob(raw.0, "invalid BAT raw public key")?,
            provider_id: fixed_blob(raw.1, "invalid BAT provider id")?,
            scope_id: fixed_blob(raw.2, "invalid BAT scope id")?,
            offer_id: u32::try_from(raw.3)
                .map_err(|_| StoreError::SchemaMismatch("invalid BAT offer id".to_owned()))?,
            entitlement_profile: u16::try_from(raw.4).map_err(|_| {
                StoreError::SchemaMismatch("invalid BAT entitlement profile".to_owned())
            })?,
            keyset_epoch: db_u64(raw.5, "negative BAT epoch")?,
            credential_key_id: fixed_blob(raw.6, "invalid BAT credential key id")?,
            lineage_digest: fixed_blob(raw.7, "invalid BAT lineage digest")?,
            commit: marker(store, db_u64(raw.8, "negative BAT commit")?),
        };
        let rebuilt = build_bat_lineage(
            store,
            &BatKeyLineageRegistration {
                raw_public_key: value.raw_public_key,
                provider_id: value.provider_id,
                scope_id: value.scope_id,
                offer_id: value.offer_id,
                entitlement_profile: value.entitlement_profile,
                keyset_epoch: value.keyset_epoch,
                credential_key_id: value.credential_key_id,
            },
        )?;
        if !bat_lineage_matches(&value, &rebuilt) {
            return Err(StoreError::SchemaMismatch(
                "BAT key lineage digest or fingerprint mismatch".to_owned(),
            ));
        }
        Ok(value)
    })
    .transpose()
}

fn read_settlement_lineage(
    connection: &Connection,
    store: &IssuerStore,
    fingerprint: &[u8; 32],
) -> StoreResult<Option<SettlementKeyLineage>> {
    type Raw = (
        Vec<u8>,
        String,
        String,
        i64,
        i64,
        Vec<u8>,
        Option<i64>,
        Vec<u8>,
        i64,
    );
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT raw_public_key, keyset_id, unit, keyset_epoch, denomination, \
             manifest_digest, final_expiry, lineage_digest, commit_seq \
             FROM settlement_key_lineages WHERE issuer_id = ?1 AND key_fingerprint = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                fingerprint.as_slice()
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
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let value = SettlementKeyLineage {
            key_fingerprint: *fingerprint,
            raw_public_key: fixed_blob(raw.0, "invalid settlement raw public key")?,
            keyset_id: raw.1,
            unit: raw.2,
            keyset_epoch: db_u64(raw.3, "negative settlement epoch")?,
            denomination: db_u64(raw.4, "negative settlement denomination")?,
            manifest_digest: fixed_blob(raw.5, "invalid settlement manifest digest")?,
            final_expiry: raw
                .6
                .map(|value| db_u64(value, "negative settlement final expiry"))
                .transpose()?,
            lineage_digest: fixed_blob(raw.7, "invalid settlement lineage digest")?,
            commit: marker(store, db_u64(raw.8, "negative settlement commit")?),
        };
        let rebuilt = build_settlement_lineage(
            store,
            &SettlementKeyLineageRegistration {
                raw_public_key: value.raw_public_key,
                keyset_id: value.keyset_id.clone(),
                unit: value.unit.clone(),
                keyset_epoch: value.keyset_epoch,
                denomination: value.denomination,
                manifest_digest: value.manifest_digest,
                final_expiry: value.final_expiry,
            },
        )?;
        if !settlement_lineage_matches(&value, &rebuilt) {
            return Err(StoreError::SchemaMismatch(
                "settlement key lineage digest or fingerprint mismatch".to_owned(),
            ));
        }
        Ok(value)
    })
    .transpose()
}

fn marker(store: &IssuerStore, sequence: u64) -> CommitMarker {
    CommitMarker {
        store_instance_id: store.handle.expected_store_instance_id,
        commit_seq: sequence,
    }
}
