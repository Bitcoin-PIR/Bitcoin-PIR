pub(crate) const APPLICATION_ID_V1: i32 = 0x4252_4155; // "BRAU"
                                                       // This is the second on-disk schema used by the V1 wire protocol. The first
                                                       // development-only schema did not persist per-call replay snapshots and must
                                                       // never be opened or migrated in place.
pub(crate) const SCHEMA_VERSION_V1: u32 = 2;

pub(crate) const AUTHORITY_IDENTITY_SCHEMA_V1: &str = r#"
CREATE TABLE authority_identity (
    singleton              INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1),
    authority_instance_id  BLOB NOT NULL UNIQUE
        CHECK(length(authority_instance_id) = 32)
        CHECK(authority_instance_id != zeroblob(32)),
    schema_version         INTEGER NOT NULL CHECK(schema_version = 2)
) STRICT, WITHOUT ROWID
"#;

pub(crate) const PROVISIONED_NAMESPACES_SCHEMA_V1: &str = r#"
CREATE TABLE provisioned_namespaces (
    authority_instance_id  BLOB NOT NULL CHECK(length(authority_instance_id) = 32),
    namespace              BLOB NOT NULL
        CHECK(length(namespace) = 32)
        CHECK(namespace != zeroblob(32)),
    client_key_id          BLOB NOT NULL
        CHECK(length(client_key_id) = 32)
        CHECK(client_key_id != zeroblob(32)),
    client_verifying_key   BLOB NOT NULL CHECK(length(client_verifying_key) = 32),
    max_operation_rows     INTEGER NOT NULL
        CHECK(max_operation_rows BETWEEN 1 AND 100000000),
    operation_rows         INTEGER NOT NULL
        CHECK(operation_rows BETWEEN 0 AND max_operation_rows),
    max_call_rows          INTEGER NOT NULL
        CHECK(max_call_rows BETWEEN 1 AND 100000000),
    call_rows              INTEGER NOT NULL
        CHECK(call_rows BETWEEN 0 AND max_call_rows),
    PRIMARY KEY (authority_instance_id, namespace, client_key_id),
    UNIQUE (authority_instance_id),
    UNIQUE (authority_instance_id, namespace),
    FOREIGN KEY (authority_instance_id)
        REFERENCES authority_identity(authority_instance_id)
) STRICT, WITHOUT ROWID
"#;

pub(crate) const CALL_LOG_SCHEMA_V1: &str = r#"
CREATE TABLE call_log (
    authority_instance_id  BLOB NOT NULL CHECK(length(authority_instance_id) = 32),
    namespace              BLOB NOT NULL CHECK(length(namespace) = 32),
    client_key_id          BLOB NOT NULL CHECK(length(client_key_id) = 32),
    call_nonce             BLOB NOT NULL
        CHECK(length(call_nonce) = 32)
        CHECK(call_nonce != zeroblob(32)),
    operation_id           BLOB NOT NULL
        CHECK(length(operation_id) = 32)
        CHECK(operation_id != zeroblob(32)),
    operation_digest       BLOB NOT NULL CHECK(length(operation_digest) = 32),
    request_digest         BLOB NOT NULL CHECK(length(request_digest) = 32),
    operation_kind         INTEGER NOT NULL CHECK(operation_kind IN (1, 2)),
    cas_disposition        INTEGER CHECK(cas_disposition IN (1, 2)),
    observed_record        BLOB CHECK(observed_record IS NULL OR length(observed_record) = 552),
    CHECK(
        (operation_kind = 1 AND cas_disposition IS NULL) OR
        (operation_kind = 2 AND cas_disposition IN (1, 2))
    ),
    PRIMARY KEY (
        authority_instance_id, namespace, client_key_id, call_nonce
    ),
    FOREIGN KEY (authority_instance_id, namespace, client_key_id)
        REFERENCES provisioned_namespaces(authority_instance_id, namespace, client_key_id)
) STRICT, WITHOUT ROWID
"#;

pub(crate) const CURRENT_RECORDS_SCHEMA_V1: &str = r#"
CREATE TABLE current_records (
    authority_instance_id  BLOB NOT NULL CHECK(length(authority_instance_id) = 32),
    namespace              BLOB NOT NULL CHECK(length(namespace) = 32),
    client_key_id          BLOB NOT NULL CHECK(length(client_key_id) = 32),
    opaque_record          BLOB NOT NULL CHECK(length(opaque_record) = 552),
    PRIMARY KEY (authority_instance_id, namespace, client_key_id),
    FOREIGN KEY (authority_instance_id, namespace, client_key_id)
        REFERENCES provisioned_namespaces(authority_instance_id, namespace, client_key_id)
) STRICT, WITHOUT ROWID
"#;

pub(crate) const OPERATION_LOG_SCHEMA_V1: &str = r#"
CREATE TABLE operation_log (
    authority_instance_id  BLOB NOT NULL CHECK(length(authority_instance_id) = 32),
    namespace              BLOB NOT NULL CHECK(length(namespace) = 32),
    client_key_id          BLOB NOT NULL CHECK(length(client_key_id) = 32),
    operation_id           BLOB NOT NULL
        CHECK(length(operation_id) = 32)
        CHECK(operation_id != zeroblob(32)),
    operation_digest       BLOB NOT NULL CHECK(length(operation_digest) = 32),
    first_outcome          INTEGER NOT NULL CHECK(first_outcome IN (0, 1, 3)),
    first_record           BLOB,
    CHECK(
        (first_outcome = 0 AND first_record IS NULL) OR
        (first_outcome IN (1, 3) AND length(first_record) = 552)
    ),
    PRIMARY KEY (
        authority_instance_id, namespace, client_key_id, operation_id
    ),
    FOREIGN KEY (authority_instance_id, namespace, client_key_id)
        REFERENCES provisioned_namespaces(authority_instance_id, namespace, client_key_id)
) STRICT, WITHOUT ROWID
"#;

pub(crate) const SCHEMA_STATEMENTS_V1: [&str; 5] = [
    AUTHORITY_IDENTITY_SCHEMA_V1,
    PROVISIONED_NAMESPACES_SCHEMA_V1,
    CURRENT_RECORDS_SCHEMA_V1,
    OPERATION_LOG_SCHEMA_V1,
    CALL_LOG_SCHEMA_V1,
];

pub(crate) const EXPECTED_TABLES_V1: [(&str, &str); 5] = [
    ("authority_identity", AUTHORITY_IDENTITY_SCHEMA_V1),
    ("call_log", CALL_LOG_SCHEMA_V1),
    ("current_records", CURRENT_RECORDS_SCHEMA_V1),
    ("operation_log", OPERATION_LOG_SCHEMA_V1),
    ("provisioned_namespaces", PROVISIONED_NAMESPACES_SCHEMA_V1),
];
