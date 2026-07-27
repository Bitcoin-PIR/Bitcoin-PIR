pub(crate) const APPLICATION_ID: i64 = 0x4250_4952;

pub(crate) const STORE_IDENTITY_SQL: &str = r#"CREATE TABLE store_identity (
    singleton                  INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    store_instance_id          BLOB NOT NULL UNIQUE CHECK (length(store_instance_id) = 16),
    provider_id                BLOB NOT NULL UNIQUE CHECK (length(provider_id) = 32),
    store_generation           INTEGER NOT NULL CHECK (store_generation >= 0),
    spend_commit_seq           INTEGER NOT NULL CHECK (
        spend_commit_seq >= 0 AND spend_commit_seq <= store_generation
    ),
    rollback_parent_commitment BLOB NOT NULL CHECK (
        length(rollback_parent_commitment) = 32
        AND (
            (store_generation = 0 AND rollback_parent_commitment = zeroblob(32))
            OR (store_generation > 0 AND rollback_parent_commitment != zeroblob(32))
        )
    ),
    rollback_commitment        BLOB NOT NULL CHECK (
        length(rollback_commitment) = 32 AND rollback_commitment != zeroblob(32)
    ),
    schema_version             INTEGER NOT NULL CHECK (schema_version > 0)
) STRICT, WITHOUT ROWID"#;

pub(crate) const SPEND_NAMESPACES_SQL: &str = r#"CREATE TABLE spend_namespaces (
    namespace_id   BLOB NOT NULL PRIMARY KEY CHECK (length(namespace_id) = 32),
    scheme         INTEGER NOT NULL,
    issuer_id      BLOB NOT NULL CHECK (length(issuer_id) = 32),
    key_id         BLOB NOT NULL CHECK (length(key_id) BETWEEN 1 AND 66),
    binding_digest BLOB NOT NULL CHECK (length(binding_digest) = 32),
    not_after      INTEGER NOT NULL CHECK (not_after >= 0),
    status         INTEGER NOT NULL CHECK (status IN (1, 2)),
    UNIQUE (scheme, issuer_id, key_id)
) STRICT, WITHOUT ROWID"#;

pub(crate) const SPENT_CAPABILITIES_SQL: &str = r#"CREATE TABLE spent_capabilities (
    namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 32),
    spend_key    BLOB NOT NULL PRIMARY KEY CHECK (length(spend_key) = 32),
    FOREIGN KEY (namespace_id)
        REFERENCES spend_namespaces(namespace_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

pub(crate) const EXCLUSIVE_KEY_LINEAGES_SQL: &str = r#"CREATE TABLE exclusive_key_lineages (
    scheme          INTEGER NOT NULL CHECK (scheme BETWEEN 1 AND 65535),
    key_fingerprint BLOB NOT NULL CHECK (
        length(key_fingerprint) = 32 AND key_fingerprint != zeroblob(32)
    ),
    lineage_digest  BLOB NOT NULL CHECK (
        length(lineage_digest) = 32 AND lineage_digest != zeroblob(32)
    ),
    PRIMARY KEY (scheme, key_fingerprint)
) STRICT, WITHOUT ROWID"#;

pub(crate) const FREE_IP_RATE_LIMIT_BUCKETS_SQL: &str = r#"CREATE TABLE free_ip_rate_limit_buckets (
    subject        BLOB NOT NULL CHECK (length(subject) = 32),
    policy_digest  BLOB NOT NULL CHECK (length(policy_digest) = 32),
    scope_id       BLOB NOT NULL CHECK (length(scope_id) = 32),
    offer_id       INTEGER NOT NULL CHECK (offer_id > 0),
    expires_at     INTEGER NOT NULL CHECK (expires_at > 0),
    count          INTEGER NOT NULL CHECK (count > 0),
    PRIMARY KEY (subject, policy_digest, scope_id, offer_id)
) STRICT, WITHOUT ROWID"#;

pub(crate) const FREE_IP_RATE_LIMIT_CLOCK_SQL: &str = r#"CREATE TABLE free_ip_rate_limit_clock (
    singleton   INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    highest_now INTEGER NOT NULL CHECK (highest_now >= 0)
) STRICT, WITHOUT ROWID"#;

pub(crate) const POLICY_HEADS_SQL: &str = r#"CREATE TABLE policy_heads (
    provider_id          BLOB NOT NULL PRIMARY KEY CHECK (length(provider_id) = 32),
    highest_policy_epoch INTEGER NOT NULL CHECK (highest_policy_epoch > 0),
    policy_digest        BLOB NOT NULL CHECK (length(policy_digest) = 32),
    signed_policy        BLOB NOT NULL
) STRICT, WITHOUT ROWID"#;

pub(crate) const CREDENTIAL_EPOCH_FLOORS_SQL: &str = r#"CREATE TABLE credential_epoch_floors (
    scope_id      BLOB NOT NULL CHECK (length(scope_id) = 32),
    scheme        INTEGER NOT NULL,
    issuer_id     BLOB NOT NULL CHECK (length(issuer_id) = 32),
    minimum_epoch INTEGER NOT NULL CHECK (minimum_epoch > 0),
    PRIMARY KEY (scope_id, scheme, issuer_id)
) STRICT, WITHOUT ROWID"#;

pub(crate) const CASHU_MANIFEST_EPOCH_FLOORS_SQL: &str = r#"CREATE TABLE cashu_manifest_epoch_floors (
    mint_id       BLOB NOT NULL CHECK (length(mint_id) = 32),
    unit          TEXT NOT NULL,
    minimum_epoch INTEGER NOT NULL CHECK (minimum_epoch > 0),
    PRIMARY KEY (mint_id, unit)
) STRICT, WITHOUT ROWID"#;

pub(crate) const CASHU_CUSTODY_LOTS_SQL: &str = r#"CREATE TABLE cashu_custody_lots (
    lot_id               BLOB NOT NULL PRIMARY KEY CHECK (
        length(lot_id) = 16 AND lot_id != zeroblob(16)
    ),
    intent_id            BLOB NOT NULL UNIQUE CHECK (
        length(intent_id) = 16 AND intent_id != zeroblob(16)
    ),
    mint_id              BLOB NOT NULL CHECK (
        length(mint_id) = 32 AND mint_id != zeroblob(32)
    ),
    manifest_digest      BLOB NOT NULL CHECK (
        length(manifest_digest) = 32 AND manifest_digest != zeroblob(32)
    ),
    active_keyset_digest BLOB NOT NULL CHECK (
        length(active_keyset_digest) = 32 AND active_keyset_digest != zeroblob(32)
    ),
    note_set_digest      BLOB NOT NULL CHECK (
        length(note_set_digest) = 32 AND note_set_digest != zeroblob(32)
    ),
    unit                 TEXT NOT NULL CHECK (length(unit) BETWEEN 1 AND 64),
    settlement_value     INTEGER NOT NULL CHECK (settlement_value > 0),
    note_count           INTEGER NOT NULL CHECK (note_count BETWEEN 1 AND 64),
    state                INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    sealed_key_epoch     INTEGER NOT NULL CHECK (sealed_key_epoch > 0),
    sealed_nonce         BLOB NOT NULL CHECK (length(sealed_nonce) BETWEEN 1 AND 64),
    sealed_ciphertext    BLOB NOT NULL CHECK (
        length(sealed_ciphertext) BETWEEN 1 AND 262144
    ),
    FOREIGN KEY (intent_id) REFERENCES cashu_swap_intents(intent_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

pub(crate) const CASHU_CUSTODY_NOTES_SQL: &str = r#"CREATE TABLE cashu_custody_notes (
    note_fingerprint BLOB NOT NULL PRIMARY KEY CHECK (
        length(note_fingerprint) = 32 AND note_fingerprint != zeroblob(32)
    ),
    lot_id           BLOB NOT NULL CHECK (
        length(lot_id) = 16 AND lot_id != zeroblob(16)
    ),
    FOREIGN KEY (lot_id) REFERENCES cashu_custody_lots(lot_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

pub(crate) const CASHU_CUSTODY_EXPORT_BATCHES_SQL: &str = r#"CREATE TABLE cashu_custody_export_batches (
    export_id             BLOB NOT NULL PRIMARY KEY CHECK (
        length(export_id) = 16 AND export_id != zeroblob(16)
    ),
    mint_id               BLOB NOT NULL CHECK (
        length(mint_id) = 32 AND mint_id != zeroblob(32)
    ),
    unit                  TEXT NOT NULL CHECK (length(unit) BETWEEN 1 AND 64),
    recipient_key_id      BLOB NOT NULL CHECK (
        length(recipient_key_id) = 32 AND recipient_key_id != zeroblob(32)
    ),
    requested_max_lots    INTEGER NOT NULL CHECK (requested_max_lots BETWEEN 1 AND 4096),
    lot_count             INTEGER NOT NULL CHECK (lot_count BETWEEN 1 AND requested_max_lots),
    keyset_group_count    INTEGER NOT NULL CHECK (keyset_group_count BETWEEN 1 AND 16),
    settlement_value      INTEGER NOT NULL CHECK (settlement_value > 0),
    note_count            INTEGER NOT NULL CHECK (note_count BETWEEN 1 AND 512),
    state                 INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    artifact_digest       BLOB,
    artifact              BLOB,
    CHECK (
        (
            state = 1 AND artifact_digest IS NULL AND artifact IS NULL
        ) OR (
            state IN (2, 3, 4) AND length(artifact_digest) = 32
            AND artifact_digest != zeroblob(32)
            AND length(artifact) BETWEEN 1 AND 262144
        )
    )
) STRICT, WITHOUT ROWID"#;

pub(crate) const CASHU_CUSTODY_EXPORT_MEMBERS_SQL: &str = r#"CREATE TABLE cashu_custody_export_members (
    export_id    BLOB NOT NULL CHECK (
        length(export_id) = 16 AND export_id != zeroblob(16)
    ),
    member_index INTEGER NOT NULL CHECK (member_index >= 0),
    lot_id       BLOB NOT NULL UNIQUE CHECK (
        length(lot_id) = 16 AND lot_id != zeroblob(16)
    ),
    PRIMARY KEY (export_id, member_index),
    FOREIGN KEY (export_id) REFERENCES cashu_custody_export_batches(export_id) ON DELETE RESTRICT,
    FOREIGN KEY (lot_id) REFERENCES cashu_custody_lots(lot_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

/// Durable, digest-only evidence for the sole custody-exposure retirement
/// transition. The checked NUT-07 Y values and states are transient inputs and
/// are deliberately not persisted.
pub(crate) const CASHU_CUSTODY_RETIREMENT_EVIDENCE_SQL: &str = r#"CREATE TABLE cashu_custody_retirement_evidence (
    export_id                       BLOB NOT NULL PRIMARY KEY CHECK (
        length(export_id) = 16 AND export_id != zeroblob(16)
    ),
    provider_id                     BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    store_instance_id               BLOB NOT NULL CHECK (
        length(store_instance_id) = 16 AND store_instance_id != zeroblob(16)
    ),
    precondition_store_generation   INTEGER NOT NULL CHECK (
        precondition_store_generation >= 0
        AND precondition_store_generation < 9223372036854775807
    ),
    precondition_spend_commit_seq   INTEGER NOT NULL CHECK (
        precondition_spend_commit_seq >= 0
        AND precondition_spend_commit_seq <= precondition_store_generation
    ),
    precondition_rollback_commitment BLOB NOT NULL CHECK (
        length(precondition_rollback_commitment) = 32
        AND precondition_rollback_commitment != zeroblob(32)
    ),
    confirmed_store_generation      INTEGER NOT NULL CHECK (
        confirmed_store_generation = precondition_store_generation + 1
    ),
    confirmed_spend_commit_seq      INTEGER NOT NULL CHECK (
        confirmed_spend_commit_seq = precondition_spend_commit_seq
    ),
    confirmed_rollback_commitment   BLOB NOT NULL CHECK (
        length(confirmed_rollback_commitment) = 32
        AND confirmed_rollback_commitment != zeroblob(32)
        AND confirmed_rollback_commitment != precondition_rollback_commitment
    ),
    artifact_digest                 BLOB NOT NULL CHECK (
        length(artifact_digest) = 32 AND artifact_digest != zeroblob(32)
    ),
    member_set_digest               BLOB NOT NULL CHECK (
        length(member_set_digest) = 32 AND member_set_digest != zeroblob(32)
    ),
    note_fingerprint_set_digest     BLOB NOT NULL CHECK (
        length(note_fingerprint_set_digest) = 32
        AND note_fingerprint_set_digest != zeroblob(32)
    ),
    y_set_digest                    BLOB NOT NULL CHECK (
        length(y_set_digest) = 32 AND y_set_digest != zeroblob(32)
    ),
    nut07_response_digest           BLOB NOT NULL CHECK (
        length(nut07_response_digest) = 32
        AND nut07_response_digest != zeroblob(32)
    ),
    note_count                      INTEGER NOT NULL CHECK (note_count BETWEEN 1 AND 512),
    evidence_digest                 BLOB NOT NULL CHECK (
        length(evidence_digest) = 32 AND evidence_digest != zeroblob(32)
    ),
    FOREIGN KEY (export_id)
        REFERENCES cashu_custody_export_batches(export_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

pub(crate) const CASHU_SWAP_INTENTS_SQL: &str = r#"CREATE TABLE cashu_swap_intents (
    intent_id               BLOB NOT NULL PRIMARY KEY CHECK (
        length(intent_id) = 16 AND intent_id != zeroblob(16)
    ),
    mint_id                 BLOB NOT NULL CHECK (
        length(mint_id) = 32 AND mint_id != zeroblob(32)
    ),
    manifest_digest         BLOB NOT NULL CHECK (
        length(manifest_digest) = 32 AND manifest_digest != zeroblob(32)
    ),
    unit                    TEXT NOT NULL CHECK (length(unit) BETWEEN 1 AND 64),
    input_set_digest        BLOB NOT NULL CHECK (
        length(input_set_digest) = 32 AND input_set_digest != zeroblob(32)
    ),
    request_digest          BLOB NOT NULL CHECK (
        length(request_digest) = 32 AND request_digest != zeroblob(32)
    ),
    output_set_digest       BLOB NOT NULL CHECK (
        length(output_set_digest) = 32 AND output_set_digest != zeroblob(32)
    ),
    offer_binding_digest    BLOB NOT NULL CHECK (
        length(offer_binding_digest) = 32 AND offer_binding_digest != zeroblob(32)
    ),
    settlement_value        INTEGER NOT NULL CHECK (settlement_value > 0),
    expected_output_count   INTEGER NOT NULL CHECK (expected_output_count BETWEEN 1 AND 64),
    state                   INTEGER NOT NULL CHECK (state BETWEEN 0 AND 4),
    recovery_key_epoch      INTEGER NOT NULL CHECK (recovery_key_epoch > 0),
    recovery_nonce          BLOB NOT NULL CHECK (length(recovery_nonce) BETWEEN 1 AND 64),
    recovery_ciphertext     BLOB NOT NULL CHECK (
        length(recovery_ciphertext) BETWEEN 1 AND 262144
    ),
    created_bucket          INTEGER NOT NULL CHECK (created_bucket >= 0),
    updated_bucket          INTEGER NOT NULL CHECK (updated_bucket >= created_bucket),
    UNIQUE (mint_id, input_set_digest)
) STRICT, WITHOUT ROWID"#;

pub(crate) const SCHEMA: [(&str, &str); 15] = [
    (
        "cashu_custody_export_batches",
        CASHU_CUSTODY_EXPORT_BATCHES_SQL,
    ),
    (
        "cashu_custody_export_members",
        CASHU_CUSTODY_EXPORT_MEMBERS_SQL,
    ),
    ("cashu_custody_lots", CASHU_CUSTODY_LOTS_SQL),
    ("cashu_custody_notes", CASHU_CUSTODY_NOTES_SQL),
    (
        "cashu_custody_retirement_evidence",
        CASHU_CUSTODY_RETIREMENT_EVIDENCE_SQL,
    ),
    (
        "cashu_manifest_epoch_floors",
        CASHU_MANIFEST_EPOCH_FLOORS_SQL,
    ),
    ("cashu_swap_intents", CASHU_SWAP_INTENTS_SQL),
    ("credential_epoch_floors", CREDENTIAL_EPOCH_FLOORS_SQL),
    ("exclusive_key_lineages", EXCLUSIVE_KEY_LINEAGES_SQL),
    ("free_ip_rate_limit_buckets", FREE_IP_RATE_LIMIT_BUCKETS_SQL),
    ("free_ip_rate_limit_clock", FREE_IP_RATE_LIMIT_CLOCK_SQL),
    ("policy_heads", POLICY_HEADS_SQL),
    ("spend_namespaces", SPEND_NAMESPACES_SQL),
    ("spent_capabilities", SPENT_CAPABILITIES_SQL),
    ("store_identity", STORE_IDENTITY_SQL),
];
