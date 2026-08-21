use pir_service_store::{
    CashuManifestEpochFloor, CredentialEpochFloor, ExclusiveKeyLineage, FreeIpRateLimitRequestV1,
    NamespaceCloseOutcome, NamespaceInstallOutcome, NamespaceStatus, NewSpendNamespace, PolicyHead,
    PolicyStateUpdate, PolicyUpdateOutcome, ProviderStore, SpendRequest, StoreError, StoreOptions,
    SCHEMA_VERSION,
};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use tempfile::{Builder, TempDir};

#[test]
fn sensitive_admission_request_debug_is_fully_redacted() {
    let spend = SpendRequest {
        namespace_id: [0x61; 32],
        spend_key: [0x62; 32],
        now_unix_seconds: 1_234_567,
    };
    assert_eq!(
        format!("{spend:?}"),
        "SpendRequest { request: \"[REDACTED]\" }"
    );

    let free = FreeIpRateLimitRequestV1 {
        subject: [0x63; 32],
        policy_digest: [0x64; 32],
        scope_id: [0x65; 32],
        offer_id: 67,
        quota: 68,
        window_seconds: 69,
        max_buckets: 70,
        now_unix_seconds: 7_654_321,
    };
    assert_eq!(
        format!("{free:?}"),
        "FreeIpRateLimitRequestV1 { request: \"[REDACTED]\" }"
    );
}

const PROVIDER: [u8; 32] = [0x11; 32];
const STORE_INSTANCE: [u8; 16] = [0x22; 16];
const NAMESPACE: [u8; 32] = [0x33; 32];
const ISSUER: [u8; 32] = [0x44; 32];
const BINDING: [u8; 32] = [0x55; 32];
const KEY_FINGERPRINT: [u8; 32] = [0x77; 32];
const KEY_LINEAGE: [u8; 32] = [0x88; 32];

struct TestPath {
    _directory: TempDir,
    database: PathBuf,
}

impl TestPath {
    fn new() -> Self {
        let directory = Builder::new()
            .prefix("bitcoinpir-provider-store-test-")
            .tempdir()
            .expect("create task-specific temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("restrict provider-store test directory permissions");
        }
        let database = directory.path().join("provider.sqlite3");
        Self {
            _directory: directory,
            database,
        }
    }
}

fn create_store(path: &Path) -> ProviderStore {
    ProviderStore::create(
        path,
        STORE_INSTANCE,
        PROVIDER,
        StoreOptions::default(),
    )
    .expect("create provider store")
}

fn namespace(not_after: u64) -> NewSpendNamespace {
    NewSpendNamespace {
        namespace_id: NAMESPACE,
        scheme: 4,
        issuer_id: ISSUER,
        key_id: vec![0x66; 16],
        binding_digest: BINDING,
        not_after,
        exclusive_key_lineage: None,
    }
}

fn namespace_with_lineage(
    namespace_id: [u8; 32],
    key_id_byte: u8,
    lineage_digest: [u8; 32],
) -> NewSpendNamespace {
    NewSpendNamespace {
        namespace_id,
        scheme: 4,
        issuer_id: ISSUER,
        key_id: vec![key_id_byte; 16],
        binding_digest: [key_id_byte.wrapping_add(1); 32],
        not_after: 1_000,
        exclusive_key_lineage: Some(ExclusiveKeyLineage {
            key_fingerprint: KEY_FINGERPRINT,
            lineage_digest,
        }),
    }
}

fn create_store_with_namespace(path: &Path, not_after: u64) -> ProviderStore {
    let store = create_store(path);
    assert_eq!(
        store.install_namespace(&namespace(not_after)).unwrap(),
        NamespaceInstallOutcome::Installed
    );
    store
}

fn spend_request(spend_key: [u8; 32], now_unix_seconds: u64) -> SpendRequest {
    SpendRequest {
        namespace_id: NAMESPACE,
        spend_key,
        now_unix_seconds,
    }
}

#[test]
fn create_is_explicit_and_schema_has_no_linkage_columns() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database);
    let identity = store.identity().unwrap();
    assert_eq!(identity.store_instance_id, STORE_INSTANCE);
    assert_eq!(identity.provider_id, PROVIDER);
    assert_eq!(identity.store_generation, 0);
    assert_eq!(identity.spend_commit_seq, 0);
    assert_eq!(identity.rollback_parent_commitment, [0; 32]);
    assert_ne!(identity.rollback_commitment, [0; 32]);
    assert_eq!(identity.schema_version, SCHEMA_VERSION);

    assert!(ProviderStore::create(
        &test_path.database,
        [1; 16],
        PROVIDER,
        StoreOptions::default()
    )
    .is_err());

    let connection = Connection::open(&test_path.database).unwrap();
    let spent_columns = table_columns(&connection, "spent_capabilities");
    assert_eq!(spent_columns, vec!["namespace_id", "spend_key"]);
    assert_eq!(
        table_columns(&connection, "exclusive_key_lineages"),
        vec!["scheme", "key_fingerprint", "lineage_digest"]
    );
    assert_eq!(
        table_columns(&connection, "store_identity"),
        vec![
            "singleton",
            "store_instance_id",
            "provider_id",
            "store_generation",
            "spend_commit_seq",
            "rollback_parent_commitment",
            "rollback_commitment",
            "schema_version",
        ]
    );
    let all_columns: Vec<String> = connection
        .prepare(
            "SELECT name FROM pragma_table_info('store_identity') \
             UNION ALL SELECT name FROM pragma_table_info('spend_namespaces') \
             UNION ALL SELECT name FROM pragma_table_info('spent_capabilities') \
             UNION ALL SELECT name FROM pragma_table_info('policy_heads') \
             UNION ALL SELECT name FROM pragma_table_info('credential_epoch_floors') \
             UNION ALL SELECT name FROM pragma_table_info('cashu_manifest_epoch_floors') \
             UNION ALL SELECT name FROM pragma_table_info('exclusive_key_lineages')",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for forbidden in [
        "timestamp",
        "created_at",
        "ip",
        "query_id",
        "payment_hash",
        "invoice",
        "preimage",
        "raw_capability",
    ] {
        assert!(!all_columns.iter().any(|column| column == forbidden));
    }
}

#[test]
fn missing_exclusive_key_lineage_table_is_rejected_as_schema_drift() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database);
    drop(store);
    let connection = Connection::open(&test_path.database).unwrap();
    connection
        .execute("DROP TABLE exclusive_key_lineages", [])
        .unwrap();
    drop(connection);

    assert!(matches!(
        ProviderStore::open_existing(
            &test_path.database,
            PROVIDER,
            StoreOptions::default()
        ),
        Err(StoreError::SchemaMismatch(_))
    ));
}

#[test]
fn serve_mode_rejects_missing_corrupt_wrong_provider_and_unknown_schema() {
    let missing = TestPath::new();
    assert!(matches!(
        ProviderStore::open_existing(
            &missing.database,
            PROVIDER,
            StoreOptions::default()
        ),
        Err(StoreError::MissingDatabase(_))
    ));
    assert!(!missing.database.exists());

    let corrupt = TestPath::new();
    std::fs::write(&corrupt.database, b"not a sqlite database").unwrap();
    assert!(ProviderStore::open_existing(
        &corrupt.database,
        PROVIDER,
        StoreOptions::default()
    )
    .is_err());

    let wrong_provider = TestPath::new();
    let _store = create_store(&wrong_provider.database);
    assert!(matches!(
        ProviderStore::open_existing(
            &wrong_provider.database,
            [0x99; 32],
            StoreOptions::default()
        ),
        Err(StoreError::ProviderMismatch)
    ));

    let wrong_schema = TestPath::new();
    let store = create_store(&wrong_schema.database);
    drop(store);
    let connection = Connection::open(&wrong_schema.database).unwrap();
    connection.pragma_update(None, "user_version", 999).unwrap();
    drop(connection);
    assert!(matches!(
        ProviderStore::open_existing(
            &wrong_schema.database,
            PROVIDER,
            StoreOptions::default()
        ),
        Err(StoreError::SchemaMismatch(_))
    ));
}

#[test]
fn schema_extensions_and_symlink_paths_fail_closed() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database);
    drop(store);
    let connection = Connection::open(&test_path.database).unwrap();
    connection
        .execute("CREATE TABLE unexpected (value INTEGER)", [])
        .unwrap();
    drop(connection);
    assert!(matches!(
        ProviderStore::open_existing(
            &test_path.database,
            PROVIDER,
            StoreOptions::default()
        ),
        Err(StoreError::SchemaMismatch(_))
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = TestPath::new();
        let _store = create_store(&target.database);
        let link = target._directory.path().join("provider-link.sqlite3");
        symlink(&target.database, &link).unwrap();
        assert!(matches!(
            ProviderStore::open_existing(
                &link,
                PROVIDER,
                StoreOptions::default()
            ),
            Err(StoreError::NotRegularDatabase(_))
        ));

        let hardlink = target._directory.path().join("provider-hardlink.sqlite3");
        std::fs::hard_link(&target.database, &hardlink).unwrap();
        assert!(matches!(
            ProviderStore::open_existing(
                &hardlink,
                PROVIDER,
                StoreOptions::default()
            ),
            Err(StoreError::NotRegularDatabase(_))
        ));
        assert!(matches!(
            ProviderStore::open_existing(
                &target.database,
                PROVIDER,
                StoreOptions::default()
            ),
            Err(StoreError::NotRegularDatabase(_))
        ));
    }
}

#[test]
fn namespace_missing_closed_and_expired_are_distinct_and_closed_never_reopens() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database);
    assert!(matches!(
        store.spend(spend_request([1; 32], 50)),
        Err(StoreError::NamespaceMissing)
    ));

    let expiring = namespace(100);
    assert_eq!(
        store.install_namespace(&expiring).unwrap(),
        NamespaceInstallOutcome::Installed
    );
    assert!(matches!(
        store.spend(spend_request([2; 32], 101)),
        Err(StoreError::NamespaceExpired)
    ));
    assert_eq!(
        store
            .spend(spend_request([3; 32], 100))
            .unwrap()
            .spend_commit_seq,
        1
    );

    assert_eq!(
        store.close_namespace(&NAMESPACE).unwrap(),
        NamespaceCloseOutcome::Closed
    );
    assert_eq!(
        store.close_namespace(&NAMESPACE).unwrap(),
        NamespaceCloseOutcome::AlreadyClosed
    );
    assert!(matches!(
        store.spend(spend_request([4; 32], 50)),
        Err(StoreError::NamespaceClosed)
    ));
    assert_eq!(
        store.install_namespace(&expiring).unwrap(),
        NamespaceInstallOutcome::AlreadyPresent(NamespaceStatus::Closed)
    );
    assert_eq!(
        store.namespace(&NAMESPACE).unwrap().unwrap().status,
        NamespaceStatus::Closed
    );
}

#[test]
fn every_security_mutation_advances_generation_but_exact_replays_do_not() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database);
    assert_eq!(store.identity().unwrap().store_generation, 0);

    let durable_namespace = namespace(1_000);
    store.install_namespace(&durable_namespace).unwrap();
    assert_eq!(store.identity().unwrap().store_generation, 1);
    store.install_namespace(&durable_namespace).unwrap();
    assert_eq!(store.identity().unwrap().store_generation, 1);

    store
        .spend(spend_request([0x91; 32], 100))
        .expect("spend commits");
    let after_spend = store.identity().unwrap();
    assert_eq!(after_spend.store_generation, 2);
    assert_eq!(after_spend.spend_commit_seq, 1);

    store.close_namespace(&NAMESPACE).unwrap();
    assert_eq!(store.identity().unwrap().store_generation, 3);
    store.close_namespace(&NAMESPACE).unwrap();
    assert_eq!(store.identity().unwrap().store_generation, 3);

    let policy = policy_update(1, [0x92; 32], 1, 1);
    store.apply_policy_state(&policy).unwrap();
    assert_eq!(store.identity().unwrap().store_generation, 4);
    store.apply_policy_state(&policy).unwrap();
    let final_identity = store.identity().unwrap();
    assert_eq!(final_identity.store_generation, 4);
    assert_eq!(final_identity.spend_commit_seq, 1);
}

#[test]
fn conflicting_namespace_identity_or_binding_is_rejected() {
    let test_path = TestPath::new();
    let store = create_store_with_namespace(&test_path.database, 1_000);

    let mut changed_binding = namespace(1_000);
    changed_binding.binding_digest = [0x77; 32];
    assert!(matches!(
        store.install_namespace(&changed_binding),
        Err(StoreError::NamespaceConflict)
    ));

    let mut same_key_tuple = namespace(1_000);
    same_key_tuple.namespace_id = [0x88; 32];
    assert!(matches!(
        store.install_namespace(&same_key_tuple),
        Err(StoreError::NamespaceConflict)
    ));
}

#[test]
fn exclusive_key_lineage_survives_close_reopen_and_restart() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database);
    let first = namespace_with_lineage([0x81; 32], 0x91, KEY_LINEAGE);
    assert_eq!(
        store.install_namespace(&first).unwrap(),
        NamespaceInstallOutcome::Installed
    );
    assert_eq!(
        store.install_namespace(&first).unwrap(),
        NamespaceInstallOutcome::AlreadyPresent(NamespaceStatus::Active)
    );
    assert_eq!(
        store.close_namespace(&first.namespace_id).unwrap(),
        NamespaceCloseOutcome::Closed
    );

    let same_lineage = namespace_with_lineage([0x82; 32], 0x92, KEY_LINEAGE);
    assert_eq!(
        store.install_namespace(&same_lineage).unwrap(),
        NamespaceInstallOutcome::Installed
    );
    store.close_namespace(&same_lineage.namespace_id).unwrap();
    drop(store);

    let reopened = ProviderStore::open_existing(
        &test_path.database,
        PROVIDER,
        StoreOptions::default(),
    )
    .unwrap();
    let conflicting = namespace_with_lineage([0x83; 32], 0x93, [0x89; 32]);
    assert!(matches!(
        reopened.install_namespace(&conflicting),
        Err(StoreError::ExclusiveKeyLineageConflict)
    ));
    drop(reopened);

    let restarted = ProviderStore::open_existing(
        &test_path.database,
        PROVIDER,
        StoreOptions::default(),
    )
    .unwrap();
    assert!(matches!(
        restarted.install_namespace(&conflicting),
        Err(StoreError::ExclusiveKeyLineageConflict)
    ));
    let connection = Connection::open(&test_path.database).unwrap();
    let rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM exclusive_key_lineages \
             WHERE scheme = 4 AND key_fingerprint = ?1 AND lineage_digest = ?2",
            rusqlite::params![KEY_FINGERPRINT.as_slice(), KEY_LINEAGE.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn lineage_registration_and_namespace_install_are_one_atomic_transaction() {
    let test_path = TestPath::new();
    let store = create_store_with_namespace(&test_path.database, 1_000);
    let mut conflicting = namespace(1_000);
    conflicting.binding_digest = [0x99; 32];
    conflicting.exclusive_key_lineage = Some(ExclusiveKeyLineage {
        key_fingerprint: KEY_FINGERPRINT,
        lineage_digest: KEY_LINEAGE,
    });
    assert!(matches!(
        store.install_namespace(&conflicting),
        Err(StoreError::NamespaceConflict)
    ));

    let connection = Connection::open(&test_path.database).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM exclusive_key_lineages", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn concurrent_conflicting_key_lineages_commit_exactly_one_mapping() {
    let test_path = TestPath::new();
    let store = Arc::new(create_store(&test_path.database));
    let barrier = Arc::new(Barrier::new(2));
    let candidates = [
        namespace_with_lineage([0xa1; 32], 0xb1, [0xc1; 32]),
        namespace_with_lineage([0xa2; 32], 0xb2, [0xc2; 32]),
    ];
    let workers = candidates.map(|candidate| {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            store.install_namespace(&candidate)
        })
    });

    let outcomes = workers.map(|worker| worker.join().unwrap());
    let installed = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Ok(NamespaceInstallOutcome::Installed)))
        .count();
    let conflicts = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Err(StoreError::ExclusiveKeyLineageConflict)))
        .count();
    assert_eq!(installed, 1);
    assert_eq!(conflicts, 1);

    let connection = Connection::open(&test_path.database).unwrap();
    let lineage_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM exclusive_key_lineages", [], |row| {
            row.get(0)
        })
        .unwrap();
    let namespace_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM spend_namespaces", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(lineage_rows, 1);
    assert_eq!(namespace_rows, 1);
}

#[test]
fn committed_spend_survives_reopen_and_duplicate_is_rejected() {
    let test_path = TestPath::new();
    let store = create_store_with_namespace(&test_path.database, 1_000);
    let request = spend_request([0xaa; 32], 10);
    assert_eq!(store.spend(request).unwrap().spend_commit_seq, 1);
    drop(store);

    let reopened = ProviderStore::open_existing(
        &test_path.database,
        PROVIDER,
        StoreOptions::default(),
    )
    .unwrap();
    assert!(reopened.is_spent(&[0xaa; 32]).unwrap());
    assert!(matches!(
        reopened.spend(request),
        Err(StoreError::AlreadySpent)
    ));
    assert_eq!(reopened.identity().unwrap().spend_commit_seq, 1);
}

#[test]
fn wal_commit_is_visible_while_an_older_reader_remains_open() {
    let test_path = TestPath::new();
    let store = create_store_with_namespace(&test_path.database, 1_000);
    let reader = Connection::open(&test_path.database).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let before: i64 = reader
        .query_row("SELECT spend_commit_seq FROM store_identity", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(before, 0);

    let request = spend_request([0xbb; 32], 10);
    assert_eq!(store.spend(request).unwrap().spend_commit_seq, 1);
    drop(store);

    let reopened = ProviderStore::open_existing(
        &test_path.database,
        PROVIDER,
        StoreOptions::default(),
    )
    .unwrap();
    assert!(matches!(
        reopened.spend(request),
        Err(StoreError::AlreadySpent)
    ));
    reader.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn concurrent_duplicate_spends_have_exactly_one_commit() {
    const THREADS: usize = 12;
    let test_path = TestPath::new();
    let store = Arc::new(create_store_with_namespace(&test_path.database, 1_000));
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut workers = Vec::new();
    for _ in 0..THREADS {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            match store.spend(spend_request([0xcc; 32], 10)) {
                Ok(_) => 1,
                Err(StoreError::AlreadySpent) => 0,
                Err(error) => panic!("unexpected concurrent spend error: {error}"),
            }
        }));
    }
    let committed: i32 = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .sum();
    assert_eq!(committed, 1);
    assert_eq!(store.identity().unwrap().spend_commit_seq, 1);
}

#[test]
fn grant_nonce_failure_rolls_back_spend_before_authorization() {
    let test_path = TestPath::new();
    let store = create_store_with_namespace(&test_path.database, 1_000);
    let before = store.identity().unwrap();
    let request = spend_request([0xce; 32], 10);

    crate::fail_next_grant_transition_nonce_for_current_thread_v1();
    assert!(matches!(store.spend(request), Err(StoreError::Io(_))));
    assert_eq!(store.identity().unwrap(), before);
    assert!(!store.is_spent(&request.spend_key).unwrap());
    assert_eq!(
        store.operational_inventory().unwrap().spent_capability_rows,
        0
    );

    assert_eq!(store.spend(request).unwrap().spend_commit_seq, 1);
}

#[test]
fn spend_key_is_provider_global_across_namespaces() {
    let test_path = TestPath::new();
    let store = create_store_with_namespace(&test_path.database, 1_000);
    let second_namespace_id = [0x34; 32];
    let second = NewSpendNamespace {
        namespace_id: second_namespace_id,
        scheme: 5,
        issuer_id: ISSUER,
        key_id: vec![0x67; 16],
        binding_digest: [0x56; 32],
        not_after: 1_000,
        exclusive_key_lineage: None,
    };
    store.install_namespace(&second).unwrap();

    let spend_key = [0xcd; 32];
    store.spend(spend_request(spend_key, 10)).unwrap();
    assert!(store.is_spent(&spend_key).unwrap());
    assert!(matches!(
        store.spend(SpendRequest {
            namespace_id: second_namespace_id,
            spend_key,
            now_unix_seconds: 10,
        }),
        Err(StoreError::AlreadySpent)
    ));
    assert_eq!(store.identity().unwrap().spend_commit_seq, 1);
}

#[test]
fn policy_head_and_epoch_floors_survive_reopen_and_reject_rollback_atomically() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database);
    let initial = policy_update(5, [0x10; 32], 7, 8);
    assert_eq!(
        store.apply_policy_state(&initial).unwrap(),
        PolicyUpdateOutcome::Advanced
    );
    assert_eq!(
        store.apply_policy_state(&initial).unwrap(),
        PolicyUpdateOutcome::AlreadyCurrent
    );
    drop(store);

    let store = ProviderStore::open_existing(
        &test_path.database,
        PROVIDER,
        StoreOptions::default(),
    )
    .unwrap();
    assert_eq!(store.policy_head().unwrap(), Some(initial.head.clone()));
    assert_eq!(
        store
            .credential_epoch_floor(&[0x20; 32], 4, &[0x30; 32])
            .unwrap(),
        Some(7)
    );
    assert_eq!(
        store
            .cashu_manifest_epoch_floor(&[0x40; 32], "sat")
            .unwrap(),
        Some(8)
    );

    assert!(matches!(
        store.apply_policy_state(&policy_update(4, [0x09; 32], 7, 8)),
        Err(StoreError::PolicyRollback)
    ));
    assert!(matches!(
        store.apply_policy_state(&policy_update(5, [0x99; 32], 7, 8)),
        Err(StoreError::PolicyFork)
    ));
    let mut same_digest_different_envelope = initial.clone();
    same_digest_different_envelope.head.signed_policy.push(0xff);
    assert!(matches!(
        store.apply_policy_state(&same_digest_different_envelope),
        Err(StoreError::PolicyFork)
    ));

    let credential_rollback = policy_update(6, [0x11; 32], 6, 9);
    assert!(matches!(
        store.apply_policy_state(&credential_rollback),
        Err(StoreError::CredentialFloorRollback)
    ));
    assert_eq!(store.policy_head().unwrap(), Some(initial.head.clone()));

    let cashu_rollback = policy_update(6, [0x11; 32], 8, 7);
    assert!(matches!(
        store.apply_policy_state(&cashu_rollback),
        Err(StoreError::CashuFloorRollback)
    ));
    assert_eq!(store.policy_head().unwrap(), Some(initial.head));

    let advanced = policy_update(6, [0x11; 32], 8, 9);
    assert_eq!(
        store.apply_policy_state(&advanced).unwrap(),
        PolicyUpdateOutcome::Advanced
    );
    assert_eq!(store.policy_head().unwrap(), Some(advanced.head));
}

#[test]
fn zero_sentinels_are_rejected_before_persistence() {
    let zero_provider_path = TestPath::new();
    assert!(matches!(
        ProviderStore::create(
            &zero_provider_path.database,
            STORE_INSTANCE,
            [0; 32],
            StoreOptions::default()
        ),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(!zero_provider_path.database.exists());

    let zero_instance_path = TestPath::new();
    assert!(matches!(
        ProviderStore::create(
            &zero_instance_path.database,
            [0; 16],
            PROVIDER,
            StoreOptions::default()
        ),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(!zero_instance_path.database.exists());

    let test_path = TestPath::new();
    let store = create_store(&test_path.database);
    let mut invalid_namespace = namespace(1_000);
    invalid_namespace.namespace_id = [0; 32];
    assert!(matches!(
        store.install_namespace(&invalid_namespace),
        Err(StoreError::InvalidInput(_))
    ));
    invalid_namespace = namespace(1_000);
    invalid_namespace.issuer_id = [0; 32];
    assert!(matches!(
        store.install_namespace(&invalid_namespace),
        Err(StoreError::InvalidInput(_))
    ));
    invalid_namespace = namespace(1_000);
    invalid_namespace.binding_digest = [0; 32];
    assert!(matches!(
        store.install_namespace(&invalid_namespace),
        Err(StoreError::InvalidInput(_))
    ));
    invalid_namespace = namespace(1_000);
    invalid_namespace.key_id.fill(0);
    assert!(matches!(
        store.install_namespace(&invalid_namespace),
        Err(StoreError::InvalidInput(_))
    ));
    invalid_namespace = namespace(1_000);
    invalid_namespace.exclusive_key_lineage = Some(ExclusiveKeyLineage {
        key_fingerprint: [0; 32],
        lineage_digest: KEY_LINEAGE,
    });
    assert!(matches!(
        store.install_namespace(&invalid_namespace),
        Err(StoreError::InvalidInput(_))
    ));
    invalid_namespace = namespace(1_000);
    invalid_namespace.exclusive_key_lineage = Some(ExclusiveKeyLineage {
        key_fingerprint: KEY_FINGERPRINT,
        lineage_digest: [0; 32],
    });
    assert!(matches!(
        store.install_namespace(&invalid_namespace),
        Err(StoreError::InvalidInput(_))
    ));
    let connection = Connection::open(&test_path.database).unwrap();
    let lineage_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM exclusive_key_lineages", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(lineage_rows, 0);
    drop(connection);
    store.install_namespace(&namespace(1_000)).unwrap();
    for request in [
        SpendRequest {
            namespace_id: [0; 32],
            spend_key: [1; 32],
            now_unix_seconds: 1,
        },
        SpendRequest {
            namespace_id: NAMESPACE,
            spend_key: [0; 32],
            now_unix_seconds: 1,
        },
        SpendRequest {
            namespace_id: NAMESPACE,
            spend_key: [1; 32],
            now_unix_seconds: 0,
        },
    ] {
        assert!(matches!(
            store.spend(request),
            Err(StoreError::InvalidInput(_))
        ));
    }
    assert_eq!(store.identity().unwrap().spend_commit_seq, 0);
}

#[test]
fn foreign_key_violation_fails_full_open_integrity_check() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database);
    drop(store);
    let connection = Connection::open(&test_path.database).unwrap();
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection
        .execute(
            "INSERT INTO spent_capabilities (namespace_id, spend_key) VALUES (?1, ?2)",
            rusqlite::params![[0x91_u8; 32].as_slice(), [0x92_u8; 32].as_slice()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        ProviderStore::open_existing(
            &test_path.database,
            PROVIDER,
            StoreOptions::default()
        ),
        Err(StoreError::IntegrityCheckFailed(_))
    ));
}

fn policy_update(
    epoch: u64,
    digest: [u8; 32],
    credential_floor: u64,
    cashu_floor: u64,
) -> PolicyStateUpdate {
    PolicyStateUpdate {
        head: PolicyHead {
            highest_policy_epoch: epoch,
            policy_digest: digest,
            signed_policy: vec![epoch as u8, 0xa5],
        },
        credential_floors: vec![CredentialEpochFloor {
            scope_id: [0x20; 32],
            scheme: 4,
            issuer_id: [0x30; 32],
            minimum_epoch: credential_floor,
        }],
        cashu_manifest_floors: vec![CashuManifestEpochFloor {
            mint_id: [0x40; 32],
            unit: "sat".to_owned(),
            minimum_epoch: cashu_floor,
        }],
    }
}

fn table_columns(connection: &Connection, table: &str) -> Vec<String> {
    let sql = format!("PRAGMA table_info({table})");
    connection
        .prepare(&sql)
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}
