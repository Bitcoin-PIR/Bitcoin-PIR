use crate::db::{
    advance_store_generation, commit, db_u64, fixed_blob, sql_integer, verify_expected_identity,
};
use crate::policy_ops::{
    project_current_bat_acceptance_member_v2, project_retained_bat_acceptance_member_v2,
};
use crate::rollback::mutation_digest;
use crate::{
    BatAcceptanceClassMemberRecordV2, BatAcceptanceClassRecordV2, CommitMarker, DurableWrite,
    IssuerStore, StoreError, StoreResult, WriteDisposition, MAX_EXACT_BAT_V2_CLASS_BYTES,
};
use pir_service_protocol::{
    bat_verification_key_fingerprint_v1, verify_bat_acceptance_class_member_projection_v2,
    BatAcceptanceClassV2, BatAcceptanceMemberV2, VerifiedBatAcceptanceMemberV2,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

const REGISTER_BAT_V2_CLASS_MUTATION: &[u8] = b"register-bat-acceptance-class-v2";

struct CandidateClassV2 {
    exact_artifact: Vec<u8>,
    artifact_digest: [u8; 32],
    common_terms_digest: [u8; 32],
    key_fingerprint: [u8; 32],
    bat_key_id: [u8; 32],
}

struct RawArtifactRow {
    artifact_digest: Vec<u8>,
    common_terms_digest: Vec<u8>,
    issuer_verifying_key: Vec<u8>,
    raw_public_key: Vec<u8>,
    key_fingerprint: Vec<u8>,
    bat_key_id: Vec<u8>,
    key_not_before: i64,
    key_not_after: i64,
    member_count: i64,
    exact_artifact: Vec<u8>,
    commit_seq: i64,
}

struct RawMemberRow {
    member_index: i64,
    provider_id: Vec<u8>,
    policy_digest: Vec<u8>,
    scope_id: Vec<u8>,
    offer_id: i64,
    redemption_deadline: i64,
    commit_seq: i64,
}

impl IssuerStore {
    /// Registers one complete issuer-signed BAT V2 class/key-epoch snapshot.
    ///
    /// Every member must resolve to that provider's exact current policy head
    /// in this same `BEGIN IMMEDIATE` transaction. Older epochs remain
    /// append-only for later redemption, while the head advances atomically
    /// with the complete canonical member set.
    pub fn register_bat_acceptance_class_v2(
        &self,
        artifact: &BatAcceptanceClassV2,
        now_unix: u64,
    ) -> StoreResult<DurableWrite<BatAcceptanceClassRecordV2>> {
        if now_unix == 0 {
            return Err(StoreError::InvalidInput(
                "BAT V2 class registration time is zero",
            ));
        }
        let candidate = build_candidate(self, artifact)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;

        let head: Option<(i64, Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT highest_key_epoch, artifact_digest, common_terms_digest \
                 FROM bat_v2_class_heads WHERE issuer_id = ?1 AND class_id = ?2",
                params![
                    self.handle.expected_issuer_id.as_slice(),
                    artifact.class_id.as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((head_epoch_raw, head_digest_raw, head_terms_raw)) = head {
            let head_epoch = db_u64(head_epoch_raw, "negative BAT V2 class head epoch")?;
            let head_digest: [u8; 32] =
                fixed_blob(head_digest_raw, "invalid BAT V2 class head digest")?;
            let head_terms: [u8; 32] =
                fixed_blob(head_terms_raw, "invalid BAT V2 class head terms digest")?;
            let existing =
                read_bat_acceptance_class_v2(&transaction, self, &artifact.class_id, head_epoch)?
                    .ok_or_else(|| {
                    StoreError::SchemaMismatch("BAT V2 class head artifact is missing".to_owned())
                })?;
            if artifact.key_epoch < head_epoch {
                return Err(StoreError::BatV2ClassRollback);
            }
            if artifact.key_epoch == head_epoch {
                if candidate.artifact_digest != head_digest
                    || existing.exact_artifact != candidate.exact_artifact
                {
                    return Err(StoreError::BatV2ClassFork);
                }
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.commit,
                    value: existing,
                });
            }
            if head_terms != candidate.common_terms_digest
                || existing.common_terms_digest != candidate.common_terms_digest
            {
                return Err(StoreError::BatV2ClassTermsConflict);
            }
        }

        reject_owned_raw_key(&transaction, self, artifact, &candidate)?;

        let mut verified_members = Vec::with_capacity(artifact.members.len());
        for member in &artifact.members {
            let (projection, _) =
                project_current_bat_acceptance_member_v2(&transaction, self, member, now_unix)?;
            if !projection_matches_artifact(artifact, member, &projection) {
                return Err(
                    if !projection
                        .common_terms
                        .commercially_equivalent_to(&artifact.common_terms)
                    {
                        StoreError::BatV2ClassTermsConflict
                    } else {
                        StoreError::BatV2ClassMemberMismatch
                    },
                );
            }
            verified_members.push(projection);
        }

        let member_material = encode_member_commitment_material(&verified_members);
        let mutation = mutation_digest(
            REGISTER_BAT_V2_CLASS_MUTATION,
            &[
                &candidate.exact_artifact,
                &candidate.artifact_digest,
                &candidate.common_terms_digest,
                &candidate.key_fingerprint,
                &candidate.bat_key_id,
                &member_material,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            REGISTER_BAT_V2_CLASS_MUTATION,
            &mutation,
        )?;
        let sequence = committed_identity.commit_seq;
        transaction.execute(
            "INSERT INTO bat_v2_class_artifacts (issuer_id, class_id, key_epoch, \
             artifact_digest, common_terms_digest, issuer_verifying_key, raw_public_key, \
             key_fingerprint, bat_key_id, key_not_before, key_not_after, member_count, \
             exact_artifact, commit_seq) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                self.handle.expected_issuer_id.as_slice(),
                artifact.class_id.as_slice(),
                sql_integer(artifact.key_epoch, "BAT V2 key epoch exceeds SQLite range")?,
                candidate.artifact_digest.as_slice(),
                candidate.common_terms_digest.as_slice(),
                artifact.issuer_verifying_key.as_slice(),
                artifact.bat_verification_key.as_slice(),
                candidate.key_fingerprint.as_slice(),
                candidate.bat_key_id.as_slice(),
                sql_integer(
                    artifact.key_not_before,
                    "BAT V2 not-before exceeds SQLite range"
                )?,
                sql_integer(
                    artifact.key_not_after,
                    "BAT V2 not-after exceeds SQLite range"
                )?,
                i64::try_from(artifact.members.len()).map_err(|_| {
                    StoreError::InvalidInput("BAT V2 member count exceeds SQLite range")
                })?,
                candidate.exact_artifact.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        for (member_index, projection) in verified_members.iter().enumerate() {
            transaction.execute(
                "INSERT INTO bat_v2_class_members (issuer_id, class_id, key_epoch, member_index, \
                 provider_id, policy_digest, scope_id, offer_id, redemption_deadline, commit_seq) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    self.handle.expected_issuer_id.as_slice(),
                    artifact.class_id.as_slice(),
                    sql_integer(artifact.key_epoch, "BAT V2 key epoch exceeds SQLite range")?,
                    i64::try_from(member_index).map_err(|_| {
                        StoreError::InvalidInput("BAT V2 member index exceeds SQLite range")
                    })?,
                    projection.member.provider_id.as_slice(),
                    projection.member.policy_digest.as_slice(),
                    projection.member.scope_id.as_slice(),
                    i64::from(projection.member.offer_id),
                    sql_integer(
                        projection.redemption_deadline,
                        "BAT V2 redemption deadline exceeds SQLite range"
                    )?,
                    sql_integer(sequence, "commit sequence exceeds SQLite range")?,
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO bat_v2_class_heads (issuer_id, class_id, highest_key_epoch, \
             artifact_digest, common_terms_digest, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(issuer_id, class_id) DO UPDATE SET \
             highest_key_epoch = excluded.highest_key_epoch, \
             artifact_digest = excluded.artifact_digest, \
             common_terms_digest = excluded.common_terms_digest, \
             commit_seq = excluded.commit_seq",
            params![
                self.handle.expected_issuer_id.as_slice(),
                artifact.class_id.as_slice(),
                sql_integer(artifact.key_epoch, "BAT V2 key epoch exceeds SQLite range")?,
                candidate.artifact_digest.as_slice(),
                candidate.common_terms_digest.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        let value = self
            .bat_acceptance_class_v2(&artifact.class_id, artifact.key_epoch)?
            .ok_or_else(|| {
                StoreError::SchemaMismatch("committed BAT V2 class is missing".to_owned())
            })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value,
        })
    }

    /// Reads one retained class/key epoch. Historical epochs remain available
    /// after the current head advances.
    pub fn bat_acceptance_class_v2(
        &self,
        class_id: &[u8; 32],
        key_epoch: u64,
    ) -> StoreResult<Option<BatAcceptanceClassRecordV2>> {
        let connection = self.open_checked(false)?;
        let value = read_bat_acceptance_class_v2(&connection, self, class_id, key_epoch)?;
        Ok(value)
    }

    /// Reads the issuer-authoritative current key epoch for one stable class
    /// ID without discarding any retained older epoch.
    pub fn current_bat_acceptance_class_v2(
        &self,
        class_id: &[u8; 32],
    ) -> StoreResult<Option<BatAcceptanceClassRecordV2>> {
        if class_id.iter().all(|byte| *byte == 0) {
            return Err(StoreError::InvalidInput("BAT V2 class ID is all zero"));
        }
        let connection = self.open_checked(false)?;
        let epoch: Option<i64> = connection
            .query_row(
                "SELECT highest_key_epoch FROM bat_v2_class_heads \
                 WHERE issuer_id = ?1 AND class_id = ?2",
                params![
                    self.handle.expected_issuer_id.as_slice(),
                    class_id.as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()?;
        let value = epoch
            .map(|epoch| {
                let epoch = db_u64(epoch, "negative BAT V2 class head epoch")?;
                read_bat_acceptance_class_v2(&connection, self, class_id, epoch)?.ok_or_else(|| {
                    StoreError::SchemaMismatch("BAT V2 class head is missing".to_owned())
                })
            })
            .transpose()?;
        Ok(value)
    }
}

fn build_candidate(
    store: &IssuerStore,
    artifact: &BatAcceptanceClassV2,
) -> StoreResult<CandidateClassV2> {
    artifact.verify().map_err(StoreError::Protocol)?;
    if artifact.issuer_id != store.handle.expected_issuer_id {
        return Err(StoreError::IssuerMismatch);
    }
    let exact_artifact = artifact.encode().map_err(StoreError::Protocol)?;
    if exact_artifact.is_empty() || exact_artifact.len() > MAX_EXACT_BAT_V2_CLASS_BYTES {
        return Err(StoreError::InvalidInput(
            "BAT V2 class artifact exceeds issuer-store bound",
        ));
    }
    let artifact_digest = artifact.class_digest().map_err(StoreError::Protocol)?;
    let common_terms_digest = artifact
        .common_terms
        .terms_digest()
        .map_err(StoreError::Protocol)?;
    let key_fingerprint = bat_verification_key_fingerprint_v1(&artifact.bat_verification_key)
        .map_err(StoreError::Protocol)?;
    Ok(CandidateClassV2 {
        exact_artifact,
        artifact_digest,
        common_terms_digest,
        key_fingerprint,
        bat_key_id: artifact.bat_key_id(),
    })
}

fn reject_owned_raw_key(
    connection: &Connection,
    store: &IssuerStore,
    artifact: &BatAcceptanceClassV2,
    candidate: &CandidateClassV2,
) -> StoreResult<()> {
    let legacy_owner: Option<Vec<u8>> = connection
        .query_row(
            "SELECT key_fingerprint FROM bat_key_lineages \
             WHERE issuer_id = ?1 AND (raw_public_key = ?2 OR key_fingerprint = ?3) LIMIT 1",
            params![
                store.handle.expected_issuer_id.as_slice(),
                artifact.bat_verification_key.as_slice(),
                candidate.key_fingerprint.as_slice(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    let v2_owner: Option<Vec<u8>> = connection
        .query_row(
            "SELECT class_id FROM bat_v2_class_artifacts WHERE issuer_id = ?1 AND \
             (raw_public_key = ?2 OR key_fingerprint = ?3 OR bat_key_id = ?4) LIMIT 1",
            params![
                store.handle.expected_issuer_id.as_slice(),
                artifact.bat_verification_key.as_slice(),
                candidate.key_fingerprint.as_slice(),
                candidate.bat_key_id.as_slice(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    if legacy_owner.is_some() || v2_owner.is_some() {
        return Err(StoreError::BatV2RawKeyConflict);
    }
    Ok(())
}

fn projection_matches_artifact(
    artifact: &BatAcceptanceClassV2,
    member: &BatAcceptanceMemberV2,
    projection: &VerifiedBatAcceptanceMemberV2,
) -> bool {
    projection.member == *member
        && verify_bat_acceptance_class_member_projection_v2(artifact, projection).is_ok()
}

fn encode_member_commitment_material(members: &[VerifiedBatAcceptanceMemberV2]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + members.len() * 116);
    out.extend_from_slice(&(members.len() as u32).to_le_bytes());
    for (index, member) in members.iter().enumerate() {
        out.extend_from_slice(&(index as u32).to_le_bytes());
        out.extend_from_slice(&member.member.provider_id);
        out.extend_from_slice(&member.member.policy_digest);
        out.extend_from_slice(&member.member.scope_id);
        out.extend_from_slice(&member.member.offer_id.to_le_bytes());
        out.extend_from_slice(&member.redemption_deadline.to_le_bytes());
    }
    out
}

pub(crate) fn read_bat_acceptance_class_v2(
    connection: &Connection,
    store: &IssuerStore,
    class_id: &[u8; 32],
    key_epoch: u64,
) -> StoreResult<Option<BatAcceptanceClassRecordV2>> {
    if class_id.iter().all(|byte| *byte == 0) || key_epoch == 0 {
        return Err(StoreError::InvalidInput("invalid BAT V2 class lookup"));
    }
    let raw: Option<RawArtifactRow> = connection
        .query_row(
            "SELECT artifact_digest, common_terms_digest, issuer_verifying_key, raw_public_key, \
             key_fingerprint, bat_key_id, key_not_before, key_not_after, member_count, \
             exact_artifact, commit_seq FROM bat_v2_class_artifacts \
             WHERE issuer_id = ?1 AND class_id = ?2 AND key_epoch = ?3",
            params![
                store.handle.expected_issuer_id.as_slice(),
                class_id.as_slice(),
                sql_integer(key_epoch, "BAT V2 key epoch exceeds SQLite range")?,
            ],
            |row| {
                Ok(RawArtifactRow {
                    artifact_digest: row.get(0)?,
                    common_terms_digest: row.get(1)?,
                    issuer_verifying_key: row.get(2)?,
                    raw_public_key: row.get(3)?,
                    key_fingerprint: row.get(4)?,
                    bat_key_id: row.get(5)?,
                    key_not_before: row.get(6)?,
                    key_not_after: row.get(7)?,
                    member_count: row.get(8)?,
                    exact_artifact: row.get(9)?,
                    commit_seq: row.get(10)?,
                })
            },
        )
        .optional()?;
    raw.map(|raw| rebuild_record(connection, store, class_id, key_epoch, raw))
        .transpose()
}

fn rebuild_record(
    connection: &Connection,
    store: &IssuerStore,
    class_id: &[u8; 32],
    key_epoch: u64,
    raw: RawArtifactRow,
) -> StoreResult<BatAcceptanceClassRecordV2> {
    let artifact_digest = fixed_blob(raw.artifact_digest, "invalid BAT V2 artifact digest")?;
    let common_terms_digest = fixed_blob(
        raw.common_terms_digest,
        "invalid BAT V2 common terms digest",
    )?;
    let issuer_verifying_key = fixed_blob(
        raw.issuer_verifying_key,
        "invalid BAT V2 issuer verifying key",
    )?;
    let raw_public_key = fixed_blob(raw.raw_public_key, "invalid BAT V2 raw public key")?;
    let key_fingerprint = fixed_blob(raw.key_fingerprint, "invalid BAT V2 key fingerprint")?;
    let bat_key_id = fixed_blob(raw.bat_key_id, "invalid BAT V2 key ID")?;
    let key_not_before = db_u64(raw.key_not_before, "negative BAT V2 not-before")?;
    let key_not_after = db_u64(raw.key_not_after, "negative BAT V2 not-after")?;
    let member_count = usize::try_from(raw.member_count)
        .map_err(|_| StoreError::SchemaMismatch("invalid BAT V2 member count".to_owned()))?;
    let commit_seq = db_u64(raw.commit_seq, "negative BAT V2 artifact commit")?;
    let artifact = BatAcceptanceClassV2::decode(&raw.exact_artifact)
        .map_err(|_| StoreError::SchemaMismatch("BAT V2 artifact is not canonical".to_owned()))?;
    if artifact.encode().map_err(StoreError::Protocol)? != raw.exact_artifact
        || artifact
            .verify_for(&store.handle.expected_issuer_id, class_id)
            .is_err()
        || artifact.key_epoch != key_epoch
        || artifact.class_digest().map_err(StoreError::Protocol)? != artifact_digest
        || artifact
            .common_terms
            .terms_digest()
            .map_err(StoreError::Protocol)?
            != common_terms_digest
        || artifact.issuer_verifying_key != issuer_verifying_key
        || artifact.bat_verification_key != raw_public_key
        || bat_verification_key_fingerprint_v1(&artifact.bat_verification_key)
            .map_err(StoreError::Protocol)?
            != key_fingerprint
        || artifact.bat_key_id() != bat_key_id
        || artifact.key_not_before != key_not_before
        || artifact.key_not_after != key_not_after
        || artifact.members.len() != member_count
    {
        return Err(StoreError::SchemaMismatch(
            "BAT V2 artifact metadata, digest, signature, or key identity mismatches".to_owned(),
        ));
    }

    let mut statement = connection.prepare(
        "SELECT member_index, provider_id, policy_digest, scope_id, offer_id, \
         redemption_deadline, commit_seq FROM bat_v2_class_members \
         WHERE issuer_id = ?1 AND class_id = ?2 AND key_epoch = ?3 ORDER BY member_index",
    )?;
    let rows = statement.query_map(
        params![
            store.handle.expected_issuer_id.as_slice(),
            class_id.as_slice(),
            sql_integer(key_epoch, "BAT V2 key epoch exceeds SQLite range")?,
        ],
        |row| {
            Ok(RawMemberRow {
                member_index: row.get(0)?,
                provider_id: row.get(1)?,
                policy_digest: row.get(2)?,
                scope_id: row.get(3)?,
                offer_id: row.get(4)?,
                redemption_deadline: row.get(5)?,
                commit_seq: row.get(6)?,
            })
        },
    )?;
    let raw_members = rows.collect::<Result<Vec<_>, _>>()?;
    if raw_members.len() != member_count {
        return Err(StoreError::SchemaMismatch(
            "BAT V2 artifact member count mismatches retained rows".to_owned(),
        ));
    }
    let mut members = Vec::with_capacity(member_count);
    for (expected_index, (raw_member, signed_member)) in
        raw_members.into_iter().zip(&artifact.members).enumerate()
    {
        let member_index = u16::try_from(raw_member.member_index)
            .map_err(|_| StoreError::SchemaMismatch("invalid BAT V2 member index".to_owned()))?;
        let member = BatAcceptanceMemberV2 {
            provider_id: fixed_blob(raw_member.provider_id, "invalid BAT V2 member provider ID")?,
            policy_digest: fixed_blob(
                raw_member.policy_digest,
                "invalid BAT V2 member policy digest",
            )?,
            scope_id: fixed_blob(raw_member.scope_id, "invalid BAT V2 member scope ID")?,
            offer_id: u32::try_from(raw_member.offer_id)
                .map_err(|_| StoreError::SchemaMismatch("invalid BAT V2 offer ID".to_owned()))?,
        };
        let redemption_deadline = db_u64(
            raw_member.redemption_deadline,
            "negative BAT V2 redemption deadline",
        )?;
        let member_commit = db_u64(raw_member.commit_seq, "negative BAT V2 member commit")?;
        if usize::from(member_index) != expected_index
            || member != *signed_member
            || member_commit != commit_seq
        {
            return Err(StoreError::SchemaMismatch(
                "BAT V2 member rows do not match the signed canonical set".to_owned(),
            ));
        }
        let (projection, policy_record) = project_retained_bat_acceptance_member_v2(
            connection, store, &member,
        )
        .map_err(|error| match error {
            StoreError::BatV2ClassMemberMismatch => StoreError::SchemaMismatch(
                "BAT V2 member no longer projects from its retained signed policy".to_owned(),
            ),
            error => error,
        })?;
        let later_policy_at_commit: i64 = connection.query_row(
            "SELECT COUNT(*) FROM issuer_service_policies WHERE provider_id = ?1 \
             AND commit_seq <= ?2 AND policy_epoch > ?3",
            params![
                member.provider_id.as_slice(),
                sql_integer(commit_seq, "BAT V2 commit exceeds SQLite range")?,
                sql_integer(
                    policy_record.policy_epoch,
                    "BAT V2 member policy epoch exceeds SQLite range"
                )?,
            ],
            |row| row.get(0),
        )?;
        if policy_record.commit.commit_seq > commit_seq
            || later_policy_at_commit != 0
            || projection.redemption_deadline != redemption_deadline
            || !projection_matches_artifact(&artifact, &member, &projection)
        {
            return Err(StoreError::SchemaMismatch(
                "BAT V2 member policy, validity, or historical-head linkage mismatches".to_owned(),
            ));
        }
        members.push(BatAcceptanceClassMemberRecordV2 {
            member_index,
            provider_id: member.provider_id,
            policy_digest: member.policy_digest,
            scope_id: member.scope_id,
            offer_id: member.offer_id,
            redemption_deadline,
        });
    }
    Ok(BatAcceptanceClassRecordV2 {
        class_id: *class_id,
        key_epoch,
        artifact_digest,
        common_terms_digest,
        issuer_verifying_key,
        raw_public_key,
        key_fingerprint,
        bat_key_id,
        key_not_before,
        key_not_after,
        exact_artifact: raw.exact_artifact,
        members,
        commit: marker(store, commit_seq),
    })
}

pub(crate) fn verify_all_bat_acceptance_classes_v2(
    store: &IssuerStore,
    connection: &Connection,
) -> StoreResult<()> {
    let mut statement = connection.prepare(
        "SELECT class_id, key_epoch FROM bat_v2_class_artifacts \
         WHERE issuer_id = ?1 ORDER BY class_id, key_epoch",
    )?;
    let rows = statement
        .query_map([store.handle.expected_issuer_id.as_slice()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (class_id, key_epoch) in rows {
        let class_id = fixed_blob(class_id, "invalid BAT V2 class ID")?;
        let key_epoch = db_u64(key_epoch, "negative BAT V2 key epoch")?;
        if read_bat_acceptance_class_v2(connection, store, &class_id, key_epoch)?.is_none() {
            return Err(StoreError::SchemaMismatch(
                "BAT V2 inventory row disappeared during integrity read".to_owned(),
            ));
        }
    }
    Ok(())
}

fn marker(store: &IssuerStore, sequence: u64) -> CommitMarker {
    CommitMarker {
        store_instance_id: store.handle.expected_store_instance_id,
        commit_seq: sequence,
    }
}
