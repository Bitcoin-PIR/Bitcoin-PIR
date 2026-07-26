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

pub(crate) const CASHU_SWAP_INTENTS_SQL: &str = r#"CREATE TABLE cashu_swap_intents (
    intent_id               BLOB NOT NULL PRIMARY KEY CHECK (length(intent_id) = 16),
    mint_id                 BLOB NOT NULL CHECK (length(mint_id) = 32),
    input_set_digest        BLOB NOT NULL CHECK (length(input_set_digest) = 32),
    request_digest          BLOB NOT NULL CHECK (length(request_digest) = 32),
    output_set_digest       BLOB NOT NULL CHECK (length(output_set_digest) = 32),
    offer_binding_digest    BLOB NOT NULL CHECK (length(offer_binding_digest) = 32),
    settlement_value        INTEGER NOT NULL CHECK (settlement_value > 0),
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

pub(crate) const SCHEMA: [(&str, &str); 10] = [
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
