use crate::{
    MAX_EXACT_BAT_V2_ACCOUNTING_APPROVAL_BYTES, MAX_EXACT_BAT_V2_ACCOUNTING_AUTHORIZATION_BYTES,
    MAX_EXACT_BAT_V2_CLASS_BYTES, MAX_EXACT_BAT_V2_REDEEM_SUCCESS_BYTES,
    MAX_EXACT_CLAIM_REQUEST_BYTES, MAX_EXACT_CLAIM_RESPONSE_BYTES,
    MAX_EXACT_CLEARING_APPROVAL_BYTES, MAX_EXACT_CLEARING_AUTHORIZATION_BYTES,
    MAX_EXACT_DELEGATION_BYTES, MAX_EXACT_INTENT_BYTES, MAX_EXACT_PAYOUT_INTENT_REQUEST_BYTES,
    MAX_EXACT_PAYOUT_INTENT_RESPONSE_BYTES, MAX_EXACT_PAYOUT_REQUEST_BYTES,
    MAX_EXACT_PAYOUT_RESPONSE_BYTES, MAX_EXACT_PAYOUT_STATUS_RESPONSE_BYTES,
    MAX_EXACT_REDEEM_REQUEST_BYTES, MAX_EXACT_REDEEM_RESPONSE_BYTES,
    MAX_EXACT_SERVICE_POLICY_BYTES, MAX_EXACT_SETTLEMENT_DEPOSIT_REQUEST_BYTES,
    MAX_EXACT_SETTLEMENT_DEPOSIT_RESPONSE_BYTES, MAX_INVOICE_BYTES, MAX_SIGNED_QUOTE_BYTES,
};
use pir_service_protocol::MAX_BAT_ACCEPTANCE_CLASS_MEMBERS_V2;

pub(crate) const APPLICATION_ID: i64 = 0x4250_4949;

pub(crate) const STORE_IDENTITY_SQL: &str = r#"CREATE TABLE store_identity (
    singleton         INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    store_instance_id BLOB NOT NULL UNIQUE CHECK (
        length(store_instance_id) = 16 AND store_instance_id != zeroblob(16)
    ),
    issuer_id         BLOB NOT NULL UNIQUE CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    network           INTEGER NOT NULL CHECK (network BETWEEN 1 AND 4),
    commit_seq        INTEGER NOT NULL CHECK (commit_seq >= 0),
    rollback_parent_commitment BLOB NOT NULL CHECK (
        length(rollback_parent_commitment) = 32 AND (
            (commit_seq = 0 AND rollback_parent_commitment = zeroblob(32)) OR
            (commit_seq > 0 AND rollback_parent_commitment != zeroblob(32))
        )
    ),
    rollback_commitment BLOB NOT NULL CHECK (
        length(rollback_commitment) = 32 AND rollback_commitment != zeroblob(32)
    ),
    status_time_floor INTEGER NOT NULL CHECK (status_time_floor >= 0),
    schema_version    INTEGER NOT NULL CHECK (schema_version > 0)
) STRICT, WITHOUT ROWID"#;

pub(crate) fn quotes_sql() -> String {
    format!(
        r#"CREATE TABLE quotes (
    quote_id                       BLOB NOT NULL PRIMARY KEY CHECK (
        length(quote_id) = 32 AND quote_id != zeroblob(32)
    ),
    issuer_id                      BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    network                        INTEGER NOT NULL CHECK (network BETWEEN 1 AND 4),
    quote_protocol                 INTEGER NOT NULL CHECK (quote_protocol IN (1, 2)),
    creation_idempotency_digest    BLOB NOT NULL UNIQUE CHECK (
        length(creation_idempotency_digest) = 32 AND
        creation_idempotency_digest != zeroblob(32)
    ),
    backend_label                  TEXT NOT NULL UNIQUE CHECK (
        length(backend_label) BETWEEN 1 AND 96
    ),
    intent_digest                  BLOB NOT NULL CHECK (
        length(intent_digest) = 32 AND intent_digest != zeroblob(32)
    ),
    intent_replay_image            BLOB NOT NULL CHECK (
        length(intent_replay_image) BETWEEN 1 AND {max_intent}
    ),
    payee_pubkey                   BLOB NOT NULL CHECK (length(payee_pubkey) = 33),
    delegation_epoch              INTEGER NOT NULL CHECK (delegation_epoch > 0),
    delegation_digest             BLOB NOT NULL CHECK (
        length(delegation_digest) = 32 AND delegation_digest != zeroblob(32)
    ),
    exact_delegation               BLOB NOT NULL CHECK (
        length(exact_delegation) BETWEEN 1 AND {max_delegation}
    ),
    exact_amount_msat              INTEGER NOT NULL CHECK (exact_amount_msat > 0),
    invoice_created_not_before     INTEGER NOT NULL CHECK (invoice_created_not_before > 0),
    invoice_created_not_after      INTEGER NOT NULL CHECK (
        invoice_created_not_after >= invoice_created_not_before
    ),
    reservation_recovery_deadline INTEGER NOT NULL CHECK (
        reservation_recovery_deadline >= invoice_created_not_after
    ),
    state                          INTEGER NOT NULL CHECK (state BETWEEN 0 AND 5),
    state_version                  INTEGER NOT NULL CHECK (state_version >= 0),
    invoice                        TEXT UNIQUE CHECK (
        invoice IS NULL OR length(invoice) BETWEEN 1 AND {max_invoice}
    ),
    payment_hash                   BLOB UNIQUE CHECK (
        payment_hash IS NULL OR (
            length(payment_hash) = 32 AND payment_hash != zeroblob(32)
        )
    ),
    invoice_created_at             INTEGER CHECK (invoice_created_at IS NULL OR invoice_created_at > 0),
    invoice_expires_at             INTEGER CHECK (invoice_expires_at IS NULL OR invoice_expires_at > 0),
    claim_deadline                 INTEGER CHECK (claim_deadline IS NULL OR claim_deadline > 0),
    credential_not_after           INTEGER CHECK (credential_not_after IS NULL OR credential_not_after > 0),
    initial_signed_quote_response  BLOB CHECK (
        initial_signed_quote_response IS NULL OR
        length(initial_signed_quote_response) BETWEEN 1 AND {max_quote}
    ),
    expiry_observed_at             INTEGER CHECK (expiry_observed_at IS NULL OR expiry_observed_at > 0),
    expired_signed_quote_response  BLOB CHECK (
        expired_signed_quote_response IS NULL OR
        length(expired_signed_quote_response) BETWEEN 1 AND {max_quote}
    ),
    settled_at                     INTEGER CHECK (settled_at IS NULL OR settled_at > 0),
    settlement_observed_at         INTEGER CHECK (settlement_observed_at IS NULL OR settlement_observed_at > 0),
    settled_amount_msat            INTEGER CHECK (settled_amount_msat IS NULL OR settled_amount_msat > 0),
    settlement_evidence_digest     BLOB CHECK (
        settlement_evidence_digest IS NULL OR (
            length(settlement_evidence_digest) = 32 AND
            settlement_evidence_digest != zeroblob(32)
        )
    ),
    settled_signed_quote_response  BLOB CHECK (
        settled_signed_quote_response IS NULL OR
        length(settled_signed_quote_response) BETWEEN 1 AND {max_quote}
    ),
    reservation_commit_seq         INTEGER NOT NULL CHECK (reservation_commit_seq > 0),
    finalization_commit_seq         INTEGER CHECK (finalization_commit_seq IS NULL OR finalization_commit_seq > 0),
    expiry_commit_seq               INTEGER CHECK (expiry_commit_seq IS NULL OR expiry_commit_seq > 0),
    settlement_commit_seq           INTEGER CHECK (settlement_commit_seq IS NULL OR settlement_commit_seq > 0),
    UNIQUE (issuer_id, network, quote_id),
    CHECK (
        (invoice IS NULL AND payment_hash IS NULL AND invoice_created_at IS NULL AND
         invoice_expires_at IS NULL AND claim_deadline IS NULL AND
         credential_not_after IS NULL AND initial_signed_quote_response IS NULL AND
         finalization_commit_seq IS NULL)
        OR
        (invoice IS NOT NULL AND payment_hash IS NOT NULL AND invoice_created_at IS NOT NULL AND
         invoice_expires_at IS NOT NULL AND claim_deadline IS NOT NULL AND
         credential_not_after IS NOT NULL AND initial_signed_quote_response IS NOT NULL AND
         finalization_commit_seq IS NOT NULL AND
         invoice_created_at <= invoice_expires_at AND
         invoice_expires_at <= claim_deadline AND
         claim_deadline <= credential_not_after)
    ),
    CHECK (
        (expiry_observed_at IS NULL AND expired_signed_quote_response IS NULL AND expiry_commit_seq IS NULL)
        OR
        (expiry_observed_at IS NOT NULL AND expired_signed_quote_response IS NOT NULL AND
         expiry_commit_seq IS NOT NULL AND expiry_observed_at >= invoice_expires_at)
    ),
    CHECK (
        (settled_at IS NULL AND settlement_observed_at IS NULL AND settled_amount_msat IS NULL AND
         settlement_evidence_digest IS NULL AND settled_signed_quote_response IS NULL AND
         settlement_commit_seq IS NULL)
        OR
        (settled_at IS NOT NULL AND settlement_observed_at IS NOT NULL AND settled_amount_msat IS NOT NULL AND
         settlement_evidence_digest IS NOT NULL AND settled_signed_quote_response IS NOT NULL AND
         settlement_commit_seq IS NOT NULL AND settled_amount_msat >= exact_amount_msat)
    ),
    CHECK (
        (state = 0 AND state_version = 0 AND invoice IS NULL AND expiry_commit_seq IS NULL AND settlement_commit_seq IS NULL)
        OR (state = 1 AND state_version = 1 AND invoice IS NOT NULL AND expiry_commit_seq IS NULL AND settlement_commit_seq IS NULL)
        OR (state = 2 AND state_version = 2 AND invoice IS NOT NULL AND expiry_commit_seq IS NULL AND settlement_commit_seq IS NOT NULL)
        OR (state = 3 AND state_version IN (3, 4) AND invoice IS NOT NULL AND settlement_commit_seq IS NOT NULL)
        OR (state = 4 AND state_version = 2 AND invoice IS NOT NULL AND expiry_commit_seq IS NOT NULL AND settlement_commit_seq IS NULL)
        OR (state = 5 AND state_version = 3 AND invoice IS NOT NULL AND expiry_commit_seq IS NOT NULL AND settlement_commit_seq IS NOT NULL)
    )
) STRICT, WITHOUT ROWID"#,
        max_intent = MAX_EXACT_INTENT_BYTES,
        max_delegation = MAX_EXACT_DELEGATION_BYTES,
        max_invoice = MAX_INVOICE_BYTES,
        max_quote = MAX_SIGNED_QUOTE_BYTES,
    )
}

pub(crate) const QUOTES_ACTIVE_CAPACITY_INDEX_SQL: &str =
    "CREATE INDEX quotes_active_capacity_v1 ON quotes (state, reservation_recovery_deadline, claim_deadline, quote_id) WHERE state IN (0, 1, 4)";
pub(crate) const QUOTES_MATERIAL_HORIZON_INDEX_SQL: &str =
    "CREATE INDEX quotes_material_horizon_v1 ON quotes (state, reservation_recovery_deadline, claim_deadline, quote_id) WHERE state != 3";

pub(crate) fn claims_sql() -> String {
    format!(
        r#"CREATE TABLE claims (
    quote_id                    BLOB NOT NULL PRIMARY KEY CHECK (
        length(quote_id) = 32 AND quote_id != zeroblob(32)
    ),
    issuer_id                   BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    claim_idempotency_digest    BLOB NOT NULL UNIQUE CHECK (
        length(claim_idempotency_digest) = 32 AND
        claim_idempotency_digest != zeroblob(32)
    ),
    claim_request_digest        BLOB NOT NULL CHECK (
        length(claim_request_digest) = 32 AND claim_request_digest != zeroblob(32)
    ),
    claim_request_replay_image  BLOB NOT NULL CHECK (
        length(claim_request_replay_image) BETWEEN 1 AND {max_request}
    ),
    exact_credential_request    BLOB NOT NULL CHECK (
        length(exact_credential_request) BETWEEN 1 AND {max_request}
    ),
    exact_claim_response        BLOB NOT NULL CHECK (
        length(exact_claim_response) BETWEEN 1 AND {max_response}
    ),
    exact_signed_quote_response BLOB NOT NULL CHECK (
        length(exact_signed_quote_response) BETWEEN 1 AND {max_quote}
    ),
    claimed_at                  INTEGER NOT NULL CHECK (claimed_at > 0),
    claim_commit_seq            INTEGER NOT NULL CHECK (claim_commit_seq > 0),
    FOREIGN KEY (quote_id) REFERENCES quotes(quote_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#,
        max_request = MAX_EXACT_CLAIM_REQUEST_BYTES,
        max_response = MAX_EXACT_CLAIM_RESPONSE_BYTES,
        max_quote = MAX_SIGNED_QUOTE_BYTES,
    )
}

pub(crate) fn delegation_heads_sql() -> String {
    format!(
        r#"CREATE TABLE quote_delegation_heads (
    issuer_id          BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    network            INTEGER NOT NULL CHECK (network BETWEEN 1 AND 4),
    payee_pubkey       BLOB NOT NULL CHECK (length(payee_pubkey) = 33),
    highest_epoch      INTEGER NOT NULL CHECK (highest_epoch > 0),
    delegation_digest BLOB NOT NULL CHECK (
        length(delegation_digest) = 32 AND delegation_digest != zeroblob(32)
    ),
    exact_delegation   BLOB NOT NULL CHECK (
        length(exact_delegation) BETWEEN 1 AND {max_delegation}
    ),
    commit_seq         INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (issuer_id, network, payee_pubkey)
) STRICT, WITHOUT ROWID"#,
        max_delegation = MAX_EXACT_DELEGATION_BYTES,
    )
}

pub(crate) const QUOTE_STATUS_NONCES_SQL: &str = r#"CREATE TABLE quote_status_nonces (
    quote_id     BLOB NOT NULL CHECK (
        length(quote_id) = 32 AND quote_id != zeroblob(32)
    ),
    nonce_digest BLOB NOT NULL CHECK (
        length(nonce_digest) = 32 AND nonce_digest != zeroblob(32)
    ),
    expires_at   INTEGER NOT NULL CHECK (expires_at > 0),
    commit_seq   INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (quote_id, nonce_digest),
    FOREIGN KEY (quote_id) REFERENCES quotes(quote_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

pub(crate) const RECEIPT_SERIALS_SQL: &str = r#"CREATE TABLE receipt_serials (
    issuer_id BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    key_id    BLOB NOT NULL CHECK (
        length(key_id) = 16 AND key_id != zeroblob(16)
    ),
    serial    BLOB NOT NULL CHECK (
        length(serial) = 32 AND serial != zeroblob(32)
    ),
    quote_id  BLOB NOT NULL CHECK (
        length(quote_id) = 32 AND quote_id != zeroblob(32)
    ),
    PRIMARY KEY (issuer_id, serial),
    FOREIGN KEY (quote_id) REFERENCES claims(quote_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

pub(crate) fn issuer_service_policies_sql() -> String {
    format!(
        r#"CREATE TABLE issuer_service_policies (
    provider_id          BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    policy_epoch         INTEGER NOT NULL CHECK (policy_epoch > 0),
    policy_digest        BLOB NOT NULL UNIQUE CHECK (
        length(policy_digest) = 32 AND policy_digest != zeroblob(32)
    ),
    policy_verifying_key BLOB NOT NULL CHECK (length(policy_verifying_key) = 32),
    exact_policy         BLOB NOT NULL CHECK (
        length(exact_policy) BETWEEN 1 AND {max_policy}
    ),
    expires_at           INTEGER NOT NULL CHECK (expires_at > 0),
    commit_seq           INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (provider_id, policy_epoch)
) STRICT, WITHOUT ROWID"#,
        max_policy = MAX_EXACT_SERVICE_POLICY_BYTES,
    )
}

pub(crate) const ISSUER_SERVICE_POLICY_HEADS_SQL: &str = r#"CREATE TABLE issuer_service_policy_heads (
    provider_id          BLOB NOT NULL PRIMARY KEY CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    highest_epoch        INTEGER NOT NULL CHECK (highest_epoch > 0),
    policy_digest        BLOB NOT NULL CHECK (
        length(policy_digest) = 32 AND policy_digest != zeroblob(32)
    ),
    policy_verifying_key BLOB NOT NULL CHECK (length(policy_verifying_key) = 32),
    commit_seq           INTEGER NOT NULL CHECK (commit_seq > 0),
    FOREIGN KEY (provider_id, highest_epoch)
        REFERENCES issuer_service_policies(provider_id, policy_epoch) ON DELETE RESTRICT,
    FOREIGN KEY (policy_digest)
        REFERENCES issuer_service_policies(policy_digest) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

pub(crate) const ISSUER_CREDENTIAL_KEYSET_FLOORS_SQL: &str = r#"CREATE TABLE issuer_credential_keyset_floors (
    provider_id    BLOB NOT NULL CHECK (length(provider_id) = 32),
    scope_id       BLOB NOT NULL CHECK (length(scope_id) = 32),
    scheme         INTEGER NOT NULL CHECK (scheme BETWEEN 1 AND 5),
    credential_issuer_id BLOB NOT NULL CHECK (length(credential_issuer_id) = 32),
    minimum_epoch  INTEGER NOT NULL CHECK (minimum_epoch > 0),
    commit_seq     INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (provider_id, scope_id, scheme, credential_issuer_id)
) STRICT, WITHOUT ROWID"#;

pub(crate) const ISSUER_CASHU_MANIFEST_FLOORS_SQL: &str = r#"CREATE TABLE issuer_cashu_manifest_floors (
    provider_id    BLOB NOT NULL CHECK (length(provider_id) = 32),
    mint_id        BLOB NOT NULL CHECK (length(mint_id) = 32),
    unit           TEXT NOT NULL CHECK (length(unit) BETWEEN 1 AND 64),
    minimum_epoch  INTEGER NOT NULL CHECK (minimum_epoch > 0),
    commit_seq     INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (provider_id, mint_id, unit)
) STRICT, WITHOUT ROWID"#;

pub(crate) const BAT_KEY_LINEAGES_SQL: &str = r#"CREATE TABLE bat_key_lineages (
    issuer_id           BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    key_fingerprint     BLOB NOT NULL CHECK (
        length(key_fingerprint) = 32 AND key_fingerprint != zeroblob(32)
    ),
    raw_public_key      BLOB NOT NULL CHECK (length(raw_public_key) = 33),
    provider_id         BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    scope_id            BLOB NOT NULL CHECK (
        length(scope_id) = 32 AND scope_id != zeroblob(32)
    ),
    offer_id            INTEGER NOT NULL CHECK (offer_id > 0),
    entitlement_profile INTEGER NOT NULL CHECK (entitlement_profile > 0),
    keyset_epoch        INTEGER NOT NULL CHECK (keyset_epoch > 0),
    credential_key_id   BLOB NOT NULL CHECK (
        length(credential_key_id) = 32 AND credential_key_id != zeroblob(32)
    ),
    lineage_digest      BLOB NOT NULL CHECK (
        length(lineage_digest) = 32 AND lineage_digest != zeroblob(32)
    ),
    commit_seq          INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (issuer_id, key_fingerprint),
    UNIQUE (issuer_id, credential_key_id),
    UNIQUE (issuer_id, lineage_digest),
    UNIQUE (issuer_id, provider_id, scope_id, offer_id, entitlement_profile, keyset_epoch)
) STRICT, WITHOUT ROWID"#;

pub(crate) fn bat_v2_class_artifacts_sql() -> String {
    format!(
        r#"CREATE TABLE bat_v2_class_artifacts (
    issuer_id             BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    class_id              BLOB NOT NULL CHECK (
        length(class_id) = 32 AND class_id != zeroblob(32)
    ),
    key_epoch             INTEGER NOT NULL CHECK (key_epoch > 0),
    artifact_digest       BLOB NOT NULL CHECK (
        length(artifact_digest) = 32 AND artifact_digest != zeroblob(32)
    ),
    common_terms_digest   BLOB NOT NULL CHECK (
        length(common_terms_digest) = 32 AND common_terms_digest != zeroblob(32)
    ),
    issuer_verifying_key  BLOB NOT NULL CHECK (
        length(issuer_verifying_key) = 32 AND issuer_verifying_key != zeroblob(32)
    ),
    raw_public_key        BLOB NOT NULL CHECK (
        length(raw_public_key) = 33 AND raw_public_key != zeroblob(33)
    ),
    key_fingerprint       BLOB NOT NULL CHECK (
        length(key_fingerprint) = 32 AND key_fingerprint != zeroblob(32)
    ),
    bat_key_id            BLOB NOT NULL CHECK (
        length(bat_key_id) = 32 AND bat_key_id != zeroblob(32)
    ),
    key_not_before        INTEGER NOT NULL CHECK (key_not_before >= 0),
    key_not_after         INTEGER NOT NULL CHECK (key_not_after >= key_not_before),
    member_count          INTEGER NOT NULL CHECK (
        member_count BETWEEN 1 AND {max_members}
    ),
    exact_artifact        BLOB NOT NULL CHECK (
        length(exact_artifact) BETWEEN 1 AND {max_artifact}
    ),
    commit_seq            INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (issuer_id, class_id, key_epoch),
    UNIQUE (issuer_id, artifact_digest),
    UNIQUE (issuer_id, class_id, key_epoch, artifact_digest),
    UNIQUE (issuer_id, raw_public_key),
    UNIQUE (issuer_id, key_fingerprint),
    UNIQUE (issuer_id, bat_key_id)
) STRICT, WITHOUT ROWID"#,
        max_artifact = MAX_EXACT_BAT_V2_CLASS_BYTES,
        max_members = MAX_BAT_ACCEPTANCE_CLASS_MEMBERS_V2,
    )
}

pub(crate) const BAT_V2_CLASS_HEADS_SQL: &str = r#"CREATE TABLE bat_v2_class_heads (
    issuer_id           BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    class_id            BLOB NOT NULL CHECK (
        length(class_id) = 32 AND class_id != zeroblob(32)
    ),
    highest_key_epoch   INTEGER NOT NULL CHECK (highest_key_epoch > 0),
    artifact_digest     BLOB NOT NULL CHECK (
        length(artifact_digest) = 32 AND artifact_digest != zeroblob(32)
    ),
    common_terms_digest BLOB NOT NULL CHECK (
        length(common_terms_digest) = 32 AND common_terms_digest != zeroblob(32)
    ),
    commit_seq          INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (issuer_id, class_id),
    FOREIGN KEY (issuer_id, class_id, highest_key_epoch)
        REFERENCES bat_v2_class_artifacts(issuer_id, class_id, key_epoch) ON DELETE RESTRICT,
    FOREIGN KEY (issuer_id, artifact_digest)
        REFERENCES bat_v2_class_artifacts(issuer_id, artifact_digest) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

pub(crate) fn bat_v2_class_members_sql() -> String {
    format!(
        r#"CREATE TABLE bat_v2_class_members (
    issuer_id           BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    class_id            BLOB NOT NULL CHECK (
        length(class_id) = 32 AND class_id != zeroblob(32)
    ),
    key_epoch           INTEGER NOT NULL CHECK (key_epoch > 0),
    member_index        INTEGER NOT NULL CHECK (
        member_index BETWEEN 0 AND {max_member_index}
    ),
    provider_id         BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    policy_digest       BLOB NOT NULL CHECK (
        length(policy_digest) = 32 AND policy_digest != zeroblob(32)
    ),
    scope_id            BLOB NOT NULL CHECK (
        length(scope_id) = 32 AND scope_id != zeroblob(32)
    ),
    offer_id            INTEGER NOT NULL CHECK (offer_id > 0),
    redemption_deadline INTEGER NOT NULL CHECK (redemption_deadline > 0),
    commit_seq          INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (issuer_id, class_id, key_epoch, member_index),
    UNIQUE (issuer_id, class_id, key_epoch, provider_id, policy_digest, scope_id, offer_id),
    FOREIGN KEY (issuer_id, class_id, key_epoch)
        REFERENCES bat_v2_class_artifacts(issuer_id, class_id, key_epoch) ON DELETE RESTRICT,
    FOREIGN KEY (policy_digest)
        REFERENCES issuer_service_policies(policy_digest) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#,
        max_member_index = MAX_BAT_ACCEPTANCE_CLASS_MEMBERS_V2 - 1,
    )
}

pub(crate) const ARC_KEY_LINEAGES_SQL: &str = r#"CREATE TABLE arc_key_lineages (
    issuer_id           BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    key_fingerprint     BLOB NOT NULL CHECK (
        length(key_fingerprint) = 32 AND key_fingerprint != zeroblob(32)
    ),
    raw_public_key      BLOB NOT NULL CHECK (length(raw_public_key) = 99),
    binding_digest      BLOB NOT NULL UNIQUE CHECK (
        length(binding_digest) = 32 AND binding_digest != zeroblob(32)
    ),
    provider_id         BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    scope_id            BLOB NOT NULL CHECK (
        length(scope_id) = 32 AND scope_id != zeroblob(32)
    ),
    offer_id            INTEGER NOT NULL CHECK (offer_id > 0),
    entitlement_profile INTEGER NOT NULL CHECK (entitlement_profile > 0),
    keyset_epoch        INTEGER NOT NULL CHECK (keyset_epoch > 0),
    credential_key_id   BLOB NOT NULL CHECK (length(credential_key_id) BETWEEN 1 AND 64),
    exact_binding       BLOB NOT NULL CHECK (length(exact_binding) BETWEEN 1 AND 1024),
    lineage_digest      BLOB NOT NULL UNIQUE CHECK (
        length(lineage_digest) = 32 AND lineage_digest != zeroblob(32)
    ),
    commit_seq          INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (issuer_id, key_fingerprint),
    UNIQUE (issuer_id, credential_key_id),
    UNIQUE (issuer_id, provider_id, scope_id, offer_id, entitlement_profile, keyset_epoch)
) STRICT, WITHOUT ROWID"#;

pub(crate) const SETTLEMENT_KEY_LINEAGES_SQL: &str = r#"CREATE TABLE settlement_key_lineages (
    issuer_id       BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    key_fingerprint BLOB NOT NULL CHECK (
        length(key_fingerprint) = 32 AND key_fingerprint != zeroblob(32)
    ),
    raw_public_key  BLOB NOT NULL CHECK (length(raw_public_key) = 33),
    keyset_id       TEXT NOT NULL CHECK (length(keyset_id) = 66),
    unit            TEXT NOT NULL CHECK (length(unit) BETWEEN 1 AND 64),
    keyset_epoch    INTEGER NOT NULL CHECK (keyset_epoch > 0),
    denomination    INTEGER NOT NULL CHECK (denomination > 0),
    manifest_digest BLOB NOT NULL CHECK (
        length(manifest_digest) = 32 AND manifest_digest != zeroblob(32)
    ),
    final_expiry    INTEGER CHECK (final_expiry IS NULL OR final_expiry > 0),
    lineage_digest  BLOB NOT NULL CHECK (
        length(lineage_digest) = 32 AND lineage_digest != zeroblob(32)
    ),
    commit_seq      INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (issuer_id, key_fingerprint),
    UNIQUE (issuer_id, lineage_digest),
    UNIQUE (issuer_id, keyset_id, denomination)
) STRICT, WITHOUT ROWID"#;

pub(crate) fn clearing_authorizations_sql() -> String {
    format!(
        r#"CREATE TABLE clearing_authorizations (
    authorization_digest BLOB NOT NULL PRIMARY KEY CHECK (
        length(authorization_digest) = 32 AND authorization_digest != zeroblob(32)
    ),
    issuer_id             BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    provider_id           BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    authorization_epoch   INTEGER NOT NULL CHECK (authorization_epoch > 0),
    exact_authorization   BLOB NOT NULL CHECK (
        length(exact_authorization) BETWEEN 1 AND {max_authorization}
    ),
    exact_approval        BLOB NOT NULL CHECK (
        length(exact_approval) BETWEEN 1 AND {max_approval}
    ),
    not_after             INTEGER NOT NULL CHECK (not_after > 0),
    commit_seq            INTEGER NOT NULL CHECK (commit_seq > 0),
    UNIQUE (issuer_id, provider_id, authorization_epoch)
) STRICT, WITHOUT ROWID"#,
        max_authorization = MAX_EXACT_CLEARING_AUTHORIZATION_BYTES,
        max_approval = MAX_EXACT_CLEARING_APPROVAL_BYTES,
    )
}

pub(crate) const PROVIDER_REGISTRATIONS_SQL: &str = r#"CREATE TABLE provider_registrations (
    issuer_id                     BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    provider_id                   BLOB NOT NULL PRIMARY KEY CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    registration_epoch            INTEGER NOT NULL CHECK (registration_epoch > 0),
    registration_digest           BLOB NOT NULL UNIQUE CHECK (
        length(registration_digest) = 32 AND registration_digest != zeroblob(32)
    ),
    settlement_account_id         BLOB NOT NULL UNIQUE CHECK (
        length(settlement_account_id) = 32 AND settlement_account_id != zeroblob(32)
    ),
    provider_request_verifying_key BLOB NOT NULL CHECK (
        length(provider_request_verifying_key) = 32 AND
        provider_request_verifying_key != zeroblob(32)
    ),
    payout_target_id              BLOB NOT NULL CHECK (
        length(payout_target_id) = 32 AND payout_target_id != zeroblob(32)
    ),
    not_before                    INTEGER NOT NULL CHECK (not_before > 0),
    not_after                     INTEGER NOT NULL CHECK (not_after >= not_before),
    commit_seq                    INTEGER NOT NULL CHECK (commit_seq > 0),
    FOREIGN KEY (issuer_id, provider_id, settlement_account_id)
        REFERENCES provider_account_bindings(issuer_id, provider_id, settlement_account_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

/// Append-only provider request-key history used only to authenticate an
/// exact payout-status response replay after the current registration rotates.
/// Fresh requests and payout mutations continue to consult
/// `provider_registrations` exclusively.
pub(crate) const PROVIDER_REGISTRATION_HISTORY_SQL: &str = r#"CREATE TABLE provider_registration_history (
    issuer_id                     BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    provider_id                   BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    registration_epoch            INTEGER NOT NULL CHECK (registration_epoch > 0),
    registration_digest           BLOB NOT NULL PRIMARY KEY CHECK (
        length(registration_digest) = 32 AND registration_digest != zeroblob(32)
    ),
    settlement_account_id         BLOB NOT NULL CHECK (
        length(settlement_account_id) = 32 AND settlement_account_id != zeroblob(32)
    ),
    provider_request_verifying_key BLOB NOT NULL CHECK (
        length(provider_request_verifying_key) = 32 AND
        provider_request_verifying_key != zeroblob(32)
    ),
    payout_target_id              BLOB NOT NULL CHECK (
        length(payout_target_id) = 32 AND payout_target_id != zeroblob(32)
    ),
    not_before                    INTEGER NOT NULL CHECK (not_before > 0),
    not_after                     INTEGER NOT NULL CHECK (not_after >= not_before),
    commit_seq                    INTEGER NOT NULL CHECK (commit_seq > 0),
    UNIQUE (issuer_id, provider_id, registration_epoch)
) STRICT, WITHOUT ROWID"#;

/// Immutable account ownership shared by V1 and V2 clearing. Neither protocol
/// is allowed to manufacture a registration row in the other's namespace.
pub(crate) const PROVIDER_ACCOUNT_BINDINGS_SQL: &str = r#"CREATE TABLE provider_account_bindings (
    issuer_id            BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    provider_id          BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    settlement_account_id BLOB NOT NULL CHECK (
        length(settlement_account_id) = 32 AND settlement_account_id != zeroblob(32)
    ),
    unit                 INTEGER NOT NULL CHECK (unit BETWEEN 1 AND 3),
    commit_seq           INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (issuer_id, provider_id),
    UNIQUE (issuer_id, settlement_account_id),
    UNIQUE (issuer_id, provider_id, settlement_account_id),
    UNIQUE (provider_id),
    UNIQUE (settlement_account_id)
) STRICT, WITHOUT ROWID"#;

pub(crate) fn bat_v2_clearing_authorizations_sql() -> String {
    format!(
        r#"CREATE TABLE bat_v2_clearing_authorizations (
    authorization_digest          BLOB NOT NULL PRIMARY KEY CHECK (
        length(authorization_digest) = 32 AND authorization_digest != zeroblob(32)
    ),
    issuer_id                     BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    authorization_id              BLOB NOT NULL CHECK (
        length(authorization_id) = 16 AND authorization_id != zeroblob(16)
    ),
    authorization_epoch           INTEGER NOT NULL CHECK (authorization_epoch > 0),
    provider_id                   BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    settlement_account_id         BLOB NOT NULL CHECK (
        length(settlement_account_id) = 32 AND settlement_account_id != zeroblob(32)
    ),
    operator_verifying_key        BLOB NOT NULL CHECK (
        length(operator_verifying_key) = 32 AND operator_verifying_key != zeroblob(32)
    ),
    issuer_settlement_verifying_key BLOB NOT NULL CHECK (
        length(issuer_settlement_verifying_key) = 32 AND
        issuer_settlement_verifying_key != zeroblob(32)
    ),
    not_before                    INTEGER NOT NULL CHECK (not_before > 0),
    not_after                     INTEGER NOT NULL CHECK (not_after >= not_before),
    exact_authorization           BLOB NOT NULL CHECK (
        length(exact_authorization) BETWEEN 1 AND {max_authorization}
    ),
    exact_approval                BLOB NOT NULL CHECK (
        length(exact_approval) BETWEEN 1 AND {max_approval}
    ),
    commit_seq                    INTEGER NOT NULL CHECK (commit_seq > 0),
    UNIQUE (issuer_id, authorization_digest),
    UNIQUE (issuer_id, provider_id, authorization_epoch),
    FOREIGN KEY (issuer_id, provider_id, settlement_account_id)
        REFERENCES provider_account_bindings(issuer_id, provider_id, settlement_account_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#,
        max_authorization = MAX_EXACT_BAT_V2_ACCOUNTING_AUTHORIZATION_BYTES,
        max_approval = MAX_EXACT_BAT_V2_ACCOUNTING_APPROVAL_BYTES,
    )
}

pub(crate) const BAT_V2_CLEARING_EPOCH_RESERVATIONS_SQL: &str = r#"CREATE TABLE bat_v2_clearing_epoch_reservations (
    issuer_id                     BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    provider_id                   BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    authorization_epoch           INTEGER NOT NULL CHECK (authorization_epoch > 0),
    clearing_verifying_key          BLOB CHECK (
        clearing_verifying_key IS NULL OR
        (length(clearing_verifying_key) = 32 AND clearing_verifying_key != zeroblob(32))
    ),
    state                         INTEGER NOT NULL CHECK (state IN (0, 1)),
    authorization_digest          BLOB CHECK (
        authorization_digest IS NULL OR
        (length(authorization_digest) = 32 AND authorization_digest != zeroblob(32))
    ),
    reservation_commit_seq        INTEGER NOT NULL CHECK (reservation_commit_seq > 0),
    activation_commit_seq         INTEGER CHECK (
        activation_commit_seq IS NULL OR activation_commit_seq > reservation_commit_seq
    ),
    PRIMARY KEY (issuer_id, provider_id, authorization_epoch),
    UNIQUE (issuer_id, clearing_verifying_key),
    CHECK ((state = 0 AND clearing_verifying_key IS NULL AND authorization_digest IS NULL AND activation_commit_seq IS NULL) OR
           (state = 1 AND clearing_verifying_key IS NOT NULL AND authorization_digest IS NOT NULL AND activation_commit_seq IS NOT NULL)),
    FOREIGN KEY (issuer_id, authorization_digest)
        REFERENCES bat_v2_clearing_authorizations(issuer_id, authorization_digest)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

pub(crate) fn redemptions_sql() -> String {
    format!(
        r#"CREATE TABLE redemptions (
    idempotency_digest       BLOB NOT NULL PRIMARY KEY CHECK (
        length(idempotency_digest) = 32 AND idempotency_digest != zeroblob(32)
    ),
    request_digest           BLOB NOT NULL UNIQUE CHECK (
        length(request_digest) = 32 AND request_digest != zeroblob(32)
    ),
    issuer_id                BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    provider_id              BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    authorization_digest     BLOB NOT NULL CHECK (
        length(authorization_digest) = 32 AND authorization_digest != zeroblob(32)
    ),
    credential_binding_digest BLOB NOT NULL CHECK (
        length(credential_binding_digest) = 32 AND credential_binding_digest != zeroblob(32)
    ),
    scheme                   INTEGER NOT NULL CHECK (scheme IN (1, 4, 5)),
    credential_digest        BLOB NOT NULL CHECK (
        length(credential_digest) = 32 AND credential_digest != zeroblob(32)
    ),
    credential_spend_key     BLOB NOT NULL UNIQUE CHECK (
        length(credential_spend_key) = 32 AND credential_spend_key != zeroblob(32)
    ),
    accepted_value           INTEGER NOT NULL CHECK (accepted_value > 0),
    provider_credit          INTEGER NOT NULL CHECK (provider_credit > 0),
    issuer_fee               INTEGER NOT NULL CHECK (issuer_fee >= 0),
    unit                     INTEGER NOT NULL CHECK (unit BETWEEN 1 AND 3),
    destination_kind         INTEGER NOT NULL CHECK (destination_kind IN (1, 2)),
    ledger_transaction_id    BLOB NOT NULL UNIQUE CHECK (
        length(ledger_transaction_id) = 32 AND ledger_transaction_id != zeroblob(32)
    ),
    request_replay_image     BLOB NOT NULL CHECK (
        length(request_replay_image) BETWEEN 1 AND {max_request}
    ),
    exact_response           BLOB NOT NULL CHECK (
        length(exact_response) BETWEEN 1 AND {max_response}
    ),
    redeemed_at              INTEGER NOT NULL CHECK (redeemed_at > 0),
    commit_seq               INTEGER NOT NULL CHECK (commit_seq > 0),
    FOREIGN KEY (authorization_digest) REFERENCES clearing_authorizations(authorization_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (ledger_transaction_id) REFERENCES ledger_transactions(transaction_id)
        ON DELETE RESTRICT,
    CHECK (provider_credit + issuer_fee = accepted_value)
) STRICT, WITHOUT ROWID"#,
        max_request = MAX_EXACT_REDEEM_REQUEST_BYTES,
        max_response = MAX_EXACT_REDEEM_RESPONSE_BYTES,
    )
}

pub(crate) fn bat_v2_redemptions_sql() -> String {
    format!(
        r#"CREATE TABLE bat_v2_redemptions (
    issuer_id                    BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    provider_id                  BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    attempt_id                   BLOB NOT NULL CHECK (
        length(attempt_id) = 32 AND attempt_id != zeroblob(32)
    ),
    request_digest               BLOB NOT NULL UNIQUE CHECK (
        length(request_digest) = 32 AND request_digest != zeroblob(32)
    ),
    authorization_digest         BLOB NOT NULL CHECK (
        length(authorization_digest) = 32 AND authorization_digest != zeroblob(32)
    ),
    settlement_account_id        BLOB NOT NULL CHECK (
        length(settlement_account_id) = 32 AND settlement_account_id != zeroblob(32)
    ),
    class_id                     BLOB NOT NULL CHECK (
        length(class_id) = 32 AND class_id != zeroblob(32)
    ),
    class_key_epoch              INTEGER NOT NULL CHECK (class_key_epoch > 0),
    class_digest                 BLOB NOT NULL CHECK (
        length(class_digest) = 32 AND class_digest != zeroblob(32)
    ),
    member_index                 INTEGER NOT NULL CHECK (
        member_index BETWEEN 0 AND {max_member_index}
    ),
    credential_digest            BLOB NOT NULL CHECK (
        length(credential_digest) = 32 AND credential_digest != zeroblob(32)
    ),
    global_spend_key             BLOB NOT NULL UNIQUE CHECK (
        length(global_spend_key) = 32 AND global_spend_key != zeroblob(32)
    ),
    accepted_value               INTEGER NOT NULL CHECK (accepted_value > 0),
    provider_credit              INTEGER NOT NULL CHECK (provider_credit > 0),
    issuer_fee                   INTEGER NOT NULL CHECK (issuer_fee >= 0),
    unit                         INTEGER NOT NULL CHECK (unit BETWEEN 1 AND 3),
    ledger_transaction_id        BLOB NOT NULL UNIQUE CHECK (
        length(ledger_transaction_id) = 32 AND ledger_transaction_id != zeroblob(32)
    ),
    exact_initial_success        BLOB NOT NULL CHECK (
        length(exact_initial_success) BETWEEN 1 AND {max_success}
    ),
    redeemed_at                  INTEGER NOT NULL CHECK (redeemed_at > 0),
    commit_seq                   INTEGER NOT NULL CHECK (commit_seq > 0),
    PRIMARY KEY (issuer_id, provider_id, attempt_id),
    FOREIGN KEY (issuer_id, authorization_digest)
        REFERENCES bat_v2_clearing_authorizations(issuer_id, authorization_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (issuer_id, provider_id, settlement_account_id)
        REFERENCES provider_account_bindings(issuer_id, provider_id, settlement_account_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (issuer_id, class_id, class_key_epoch, class_digest)
        REFERENCES bat_v2_class_artifacts(issuer_id, class_id, key_epoch, artifact_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (issuer_id, class_id, class_key_epoch, member_index)
        REFERENCES bat_v2_class_members(issuer_id, class_id, key_epoch, member_index)
        ON DELETE RESTRICT,
    FOREIGN KEY (ledger_transaction_id)
        REFERENCES ledger_transactions(transaction_id) ON DELETE RESTRICT,
    CHECK (provider_credit + issuer_fee = accepted_value)
) STRICT, WITHOUT ROWID"#,
        max_member_index = MAX_BAT_ACCEPTANCE_CLASS_MEMBERS_V2 - 1,
        max_success = MAX_EXACT_BAT_V2_REDEEM_SUCCESS_BYTES,
    )
}

pub(crate) const LEDGER_ACCOUNTS_SQL: &str = r#"CREATE TABLE ledger_accounts (
    account_id       BLOB NOT NULL PRIMARY KEY CHECK (
        length(account_id) = 32 AND account_id != zeroblob(32)
    ),
    issuer_id        BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    provider_id      BLOB NOT NULL UNIQUE CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    unit             INTEGER NOT NULL CHECK (unit BETWEEN 1 AND 3),
    available_value  INTEGER NOT NULL CHECK (available_value >= 0),
    reserved_value   INTEGER NOT NULL CHECK (reserved_value >= 0),
    ledger_sequence  INTEGER NOT NULL CHECK (ledger_sequence >= 0),
    commit_seq       INTEGER NOT NULL CHECK (commit_seq > 0),
    FOREIGN KEY (issuer_id, provider_id, account_id)
        REFERENCES provider_account_bindings(issuer_id, provider_id, settlement_account_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

pub(crate) const LEDGER_TRANSACTIONS_SQL: &str = r#"CREATE TABLE ledger_transactions (
    transaction_id  BLOB NOT NULL PRIMARY KEY CHECK (
        length(transaction_id) = 32 AND transaction_id != zeroblob(32)
    ),
    issuer_id       BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    provider_id     BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    kind            INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 7),
    reference_digest BLOB NOT NULL UNIQUE CHECK (
        length(reference_digest) = 32 AND reference_digest != zeroblob(32)
    ),
    unit            INTEGER NOT NULL CHECK (unit BETWEEN 1 AND 3),
    created_at      INTEGER NOT NULL CHECK (created_at > 0),
    commit_seq      INTEGER NOT NULL CHECK (commit_seq > 0)
) STRICT, WITHOUT ROWID"#;

pub(crate) const LEDGER_POSTINGS_SQL: &str = r#"CREATE TABLE ledger_postings (
    transaction_id BLOB NOT NULL CHECK (
        length(transaction_id) = 32 AND transaction_id != zeroblob(32)
    ),
    line_no        INTEGER NOT NULL CHECK (line_no BETWEEN 1 AND 8),
    account_kind   INTEGER NOT NULL CHECK (account_kind BETWEEN 1 AND 6),
    account_id     BLOB NOT NULL CHECK (
        length(account_id) = 32 AND account_id != zeroblob(32)
    ),
    signed_amount  INTEGER NOT NULL CHECK (signed_amount != 0),
    PRIMARY KEY (transaction_id, line_no),
    FOREIGN KEY (transaction_id) REFERENCES ledger_transactions(transaction_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

pub(crate) fn payout_intents_sql() -> String {
    format!(
        r#"CREATE TABLE payout_intents (
    idempotency_digest       BLOB NOT NULL PRIMARY KEY CHECK (
        length(idempotency_digest) = 32 AND idempotency_digest != zeroblob(32)
    ),
    request_digest           BLOB NOT NULL UNIQUE CHECK (
        length(request_digest) = 32 AND request_digest != zeroblob(32)
    ),
    issuer_id                BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    provider_id              BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    account_id               BLOB NOT NULL CHECK (
        length(account_id) = 32 AND account_id != zeroblob(32)
    ),
    payout_target_id         BLOB NOT NULL CHECK (
        length(payout_target_id) = 32 AND payout_target_id != zeroblob(32)
    ),
    unit                     INTEGER NOT NULL CHECK (unit BETWEEN 1 AND 3),
    payout_value             INTEGER NOT NULL CHECK (payout_value > 0),
    issuer_fee               INTEGER NOT NULL CHECK (issuer_fee >= 0),
    total_debit              INTEGER NOT NULL CHECK (total_debit > 0),
    payout_intent_id         BLOB NOT NULL UNIQUE CHECK (
        length(payout_intent_id) = 32 AND payout_intent_id != zeroblob(32)
    ),
    expires_at               INTEGER NOT NULL CHECK (expires_at > 0),
    consumed_by_payout_id    BLOB UNIQUE CHECK (
        consumed_by_payout_id IS NULL OR (
            length(consumed_by_payout_id) = 32 AND consumed_by_payout_id != zeroblob(32)
        )
    ),
    request_replay_image     BLOB NOT NULL CHECK (
        length(request_replay_image) BETWEEN 1 AND {max_request}
    ),
    exact_response           BLOB NOT NULL CHECK (
        length(exact_response) BETWEEN 1 AND {max_response}
    ),
    commit_seq               INTEGER NOT NULL CHECK (commit_seq > 0),
    FOREIGN KEY (provider_id) REFERENCES provider_registrations(provider_id)
        ON DELETE RESTRICT,
    CHECK (payout_value + issuer_fee = total_debit)
) STRICT, WITHOUT ROWID"#,
        max_request = MAX_EXACT_PAYOUT_INTENT_REQUEST_BYTES,
        max_response = MAX_EXACT_PAYOUT_INTENT_RESPONSE_BYTES,
    )
}

pub(crate) const PAYOUT_OUTBOX_SQL: &str = r#"CREATE TABLE payout_outbox (
    command_id          BLOB NOT NULL PRIMARY KEY CHECK (
        length(command_id) = 32 AND command_id != zeroblob(32)
    ),
    issuer_id           BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    payout_id           BLOB NOT NULL UNIQUE CHECK (
        length(payout_id) = 32 AND payout_id != zeroblob(32)
    ),
    payout_target_id    BLOB NOT NULL CHECK (
        length(payout_target_id) = 32 AND payout_target_id != zeroblob(32)
    ),
    unit                INTEGER NOT NULL CHECK (unit BETWEEN 1 AND 3),
    payout_value        INTEGER NOT NULL CHECK (payout_value > 0),
    state               INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    attempt_count       INTEGER NOT NULL CHECK (attempt_count >= 0),
    lease_owner_digest  BLOB CHECK (
        lease_owner_digest IS NULL OR (
            length(lease_owner_digest) = 32 AND lease_owner_digest != zeroblob(32)
        )
    ),
    lease_until         INTEGER CHECK (lease_until IS NULL OR lease_until > 0),
    commit_seq          INTEGER NOT NULL CHECK (commit_seq > 0),
    FOREIGN KEY (payout_id) REFERENCES payouts(payout_id) ON DELETE RESTRICT,
    CHECK (
        (state = 1 AND lease_owner_digest IS NULL AND lease_until IS NULL) OR
        (state = 2 AND lease_owner_digest IS NOT NULL AND lease_until IS NOT NULL) OR
        (state = 3 AND lease_owner_digest IS NULL AND lease_until IS NULL)
    )
) STRICT, WITHOUT ROWID"#;

pub(crate) fn payouts_sql() -> String {
    format!(
        r#"CREATE TABLE payouts (
    idempotency_digest          BLOB NOT NULL PRIMARY KEY CHECK (
        length(idempotency_digest) = 32 AND idempotency_digest != zeroblob(32)
    ),
    request_digest              BLOB NOT NULL UNIQUE CHECK (
        length(request_digest) = 32 AND request_digest != zeroblob(32)
    ),
    issuer_id                   BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    provider_id                 BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    account_id                  BLOB NOT NULL CHECK (
        length(account_id) = 32 AND account_id != zeroblob(32)
    ),
    payout_target_id            BLOB NOT NULL CHECK (
        length(payout_target_id) = 32 AND payout_target_id != zeroblob(32)
    ),
    payout_intent_id            BLOB NOT NULL UNIQUE CHECK (
        length(payout_intent_id) = 32 AND payout_intent_id != zeroblob(32)
    ),
    payout_id                   BLOB NOT NULL UNIQUE CHECK (
        length(payout_id) = 32 AND payout_id != zeroblob(32)
    ),
    unit                        INTEGER NOT NULL CHECK (unit BETWEEN 1 AND 3),
    payout_value                INTEGER NOT NULL CHECK (payout_value > 0),
    total_debit                 INTEGER NOT NULL CHECK (total_debit >= payout_value),
    state                       INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    ledger_transaction_id       BLOB NOT NULL UNIQUE CHECK (
        length(ledger_transaction_id) = 32 AND ledger_transaction_id != zeroblob(32)
    ),
    terminal_ledger_transaction_id BLOB UNIQUE CHECK (
        terminal_ledger_transaction_id IS NULL OR (
            length(terminal_ledger_transaction_id) = 32 AND
            terminal_ledger_transaction_id != zeroblob(32)
        )
    ),
    state_version               INTEGER NOT NULL CHECK (state_version > 0),
    updated_at                  INTEGER NOT NULL CHECK (updated_at > 0),
    request_replay_image        BLOB NOT NULL CHECK (
        length(request_replay_image) BETWEEN 1 AND {max_request}
    ),
    exact_initial_response      BLOB NOT NULL CHECK (
        length(exact_initial_response) BETWEEN 1 AND {max_response}
    ),
    exact_latest_status_response BLOB CHECK (
        exact_latest_status_response IS NULL OR
        length(exact_latest_status_response) BETWEEN 1 AND {max_status}
    ),
    commit_seq                  INTEGER NOT NULL CHECK (commit_seq > 0),
    FOREIGN KEY (payout_intent_id) REFERENCES payout_intents(payout_intent_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (ledger_transaction_id) REFERENCES ledger_transactions(transaction_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (terminal_ledger_transaction_id) REFERENCES ledger_transactions(transaction_id)
        ON DELETE RESTRICT,
    CHECK (
        (state = 1 AND terminal_ledger_transaction_id IS NULL AND (
            (state_version = 1 AND exact_latest_status_response IS NULL) OR
            (state_version >= 2 AND exact_latest_status_response IS NOT NULL)
        )) OR
        (state = 2 AND state_version >= 2 AND exact_latest_status_response IS NOT NULL AND
         terminal_ledger_transaction_id IS NULL) OR
        (state IN (3, 4) AND state_version >= 3 AND exact_latest_status_response IS NOT NULL AND
         terminal_ledger_transaction_id IS NOT NULL)
    )
) STRICT, WITHOUT ROWID"#,
        max_request = MAX_EXACT_PAYOUT_REQUEST_BYTES,
        max_response = MAX_EXACT_PAYOUT_RESPONSE_BYTES,
        max_status = MAX_EXACT_PAYOUT_STATUS_RESPONSE_BYTES,
    )
}

pub(crate) fn settlement_deposits_sql() -> String {
    format!(
        r#"CREATE TABLE settlement_deposits (
    idempotency_digest    BLOB NOT NULL PRIMARY KEY CHECK (
        length(idempotency_digest) = 32 AND idempotency_digest != zeroblob(32)
    ),
    request_digest        BLOB NOT NULL UNIQUE CHECK (
        length(request_digest) = 32 AND request_digest != zeroblob(32)
    ),
    issuer_id             BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    registration_digest   BLOB NOT NULL CHECK (
        length(registration_digest) = 32 AND registration_digest != zeroblob(32)
    ),
    provider_id           BLOB NOT NULL CHECK (
        length(provider_id) = 32 AND provider_id != zeroblob(32)
    ),
    account_id            BLOB NOT NULL CHECK (
        length(account_id) = 32 AND account_id != zeroblob(32)
    ),
    unit                  INTEGER NOT NULL CHECK (unit BETWEEN 1 AND 3),
    settlement_keyset_id  TEXT NOT NULL CHECK (length(settlement_keyset_id) = 66),
    total_value           INTEGER NOT NULL CHECK (total_value > 0),
    ledger_transaction_id BLOB NOT NULL UNIQUE CHECK (
        length(ledger_transaction_id) = 32 AND ledger_transaction_id != zeroblob(32)
    ),
    ledger_sequence       INTEGER NOT NULL CHECK (ledger_sequence > 0),
    request_replay_image  BLOB NOT NULL CHECK (
        length(request_replay_image) BETWEEN 1 AND {max_request}
    ),
    exact_response        BLOB NOT NULL CHECK (
        length(exact_response) BETWEEN 1 AND {max_response}
    ),
    deposited_at          INTEGER NOT NULL CHECK (deposited_at > 0),
    commit_seq            INTEGER NOT NULL CHECK (commit_seq > 0),
    FOREIGN KEY (ledger_transaction_id) REFERENCES ledger_transactions(transaction_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#,
        max_request = MAX_EXACT_SETTLEMENT_DEPOSIT_REQUEST_BYTES,
        max_response = MAX_EXACT_SETTLEMENT_DEPOSIT_RESPONSE_BYTES,
    )
}

pub(crate) const SETTLEMENT_NOTE_SPENDS_SQL: &str = r#"CREATE TABLE settlement_note_spends (
    spend_key             BLOB NOT NULL PRIMARY KEY CHECK (
        length(spend_key) = 32 AND spend_key != zeroblob(32)
    ),
    issuer_id             BLOB NOT NULL CHECK (
        length(issuer_id) = 32 AND issuer_id != zeroblob(32)
    ),
    settlement_keyset_id  TEXT NOT NULL CHECK (length(settlement_keyset_id) = 66),
    denomination          INTEGER NOT NULL CHECK (denomination > 0),
    presentation_digest   BLOB NOT NULL CHECK (
        length(presentation_digest) = 32 AND presentation_digest != zeroblob(32)
    ),
    deposit_idempotency_digest BLOB NOT NULL CHECK (
        length(deposit_idempotency_digest) = 32 AND
        deposit_idempotency_digest != zeroblob(32)
    ),
    commit_seq            INTEGER NOT NULL CHECK (commit_seq > 0),
    FOREIGN KEY (deposit_idempotency_digest) REFERENCES settlement_deposits(idempotency_digest)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID"#;

pub(crate) fn schema() -> Vec<(&'static str, String)> {
    vec![
        ("arc_key_lineages", ARC_KEY_LINEAGES_SQL.to_owned()),
        ("bat_key_lineages", BAT_KEY_LINEAGES_SQL.to_owned()),
        ("bat_v2_class_artifacts", bat_v2_class_artifacts_sql()),
        ("bat_v2_class_heads", BAT_V2_CLASS_HEADS_SQL.to_owned()),
        ("bat_v2_class_members", bat_v2_class_members_sql()),
        (
            "bat_v2_clearing_authorizations",
            bat_v2_clearing_authorizations_sql(),
        ),
        (
            "bat_v2_clearing_epoch_reservations",
            BAT_V2_CLEARING_EPOCH_RESERVATIONS_SQL.to_owned(),
        ),
        ("bat_v2_redemptions", bat_v2_redemptions_sql()),
        ("claims", claims_sql()),
        ("clearing_authorizations", clearing_authorizations_sql()),
        (
            "issuer_cashu_manifest_floors",
            ISSUER_CASHU_MANIFEST_FLOORS_SQL.to_owned(),
        ),
        (
            "issuer_credential_keyset_floors",
            ISSUER_CREDENTIAL_KEYSET_FLOORS_SQL.to_owned(),
        ),
        ("issuer_service_policies", issuer_service_policies_sql()),
        (
            "issuer_service_policy_heads",
            ISSUER_SERVICE_POLICY_HEADS_SQL.to_owned(),
        ),
        ("ledger_accounts", LEDGER_ACCOUNTS_SQL.to_owned()),
        ("ledger_postings", LEDGER_POSTINGS_SQL.to_owned()),
        ("ledger_transactions", LEDGER_TRANSACTIONS_SQL.to_owned()),
        ("payout_intents", payout_intents_sql()),
        ("payout_outbox", PAYOUT_OUTBOX_SQL.to_owned()),
        ("payouts", payouts_sql()),
        (
            "provider_account_bindings",
            PROVIDER_ACCOUNT_BINDINGS_SQL.to_owned(),
        ),
        (
            "provider_registration_history",
            PROVIDER_REGISTRATION_HISTORY_SQL.to_owned(),
        ),
        (
            "provider_registrations",
            PROVIDER_REGISTRATIONS_SQL.to_owned(),
        ),
        ("quote_delegation_heads", delegation_heads_sql()),
        ("quote_status_nonces", QUOTE_STATUS_NONCES_SQL.to_owned()),
        ("quotes", quotes_sql()),
        ("receipt_serials", RECEIPT_SERIALS_SQL.to_owned()),
        ("redemptions", redemptions_sql()),
        ("settlement_deposits", settlement_deposits_sql()),
        (
            "settlement_key_lineages",
            SETTLEMENT_KEY_LINEAGES_SQL.to_owned(),
        ),
        (
            "settlement_note_spends",
            SETTLEMENT_NOTE_SPENDS_SQL.to_owned(),
        ),
        ("store_identity", STORE_IDENTITY_SQL.to_owned()),
    ]
}

pub(crate) fn indexes() -> Vec<(&'static str, String)> {
    vec![
        (
            "quotes_active_capacity_v1",
            QUOTES_ACTIVE_CAPACITY_INDEX_SQL.to_owned(),
        ),
        (
            "quotes_material_horizon_v1",
            QUOTES_MATERIAL_HORIZON_INDEX_SQL.to_owned(),
        ),
    ]
}
