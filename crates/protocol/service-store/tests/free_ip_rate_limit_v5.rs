use pir_service_store::{
    FreeIpRateLimitRequestV1, ProviderStore, RollbackFloorAuthorityV1,
    SqliteRollbackFloorAuthorityV1, StoreError, StoreOptions, SCHEMA_VERSION,
};
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::tempdir;

const PROVIDER: [u8; 32] = [0x11; 32];
const STORE_INSTANCE: [u8; 16] = [0x22; 16];
const SUBJECT: [u8; 32] = [0x33; 32];
const SCOPE: [u8; 32] = [0x44; 32];

fn private_tempdir_v1() -> tempfile::TempDir {
    let directory = tempdir().expect("create free-IP test directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restrict free-IP test directory permissions");
    }
    directory
}

fn request(now_unix_seconds: u64) -> FreeIpRateLimitRequestV1 {
    FreeIpRateLimitRequestV1 {
        subject: SUBJECT,
        policy_digest: [0x55; 32],
        scope_id: SCOPE,
        offer_id: 7,
        quota: 2,
        window_seconds: 60,
        max_buckets: 16,
        now_unix_seconds,
    }
}

fn create_store(path: &Path, authority: Arc<dyn RollbackFloorAuthorityV1>) -> ProviderStore {
    ProviderStore::create(
        path,
        STORE_INSTANCE,
        PROVIDER,
        StoreOptions::default(),
        authority,
    )
    .unwrap()
}

#[test]
fn quota_survives_restart_and_clock_rollback_fails_closed() {
    let dir = private_tempdir_v1();
    let authority: Arc<dyn RollbackFloorAuthorityV1> = Arc::new(
        SqliteRollbackFloorAuthorityV1::create(
            dir.path().join("authority.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .unwrap(),
    );
    let path = dir.path().join("provider.sqlite3");
    let store = create_store(&path, Arc::clone(&authority));
    store.consume_free_ip_rate_limit_v1(request(180)).unwrap();
    store.consume_free_ip_rate_limit_v1(request(181)).unwrap();
    assert_eq!(store.identity().unwrap().spend_commit_seq, 2);
    drop(store);

    let reopened = ProviderStore::open_existing(
        &path,
        PROVIDER,
        StoreOptions::default(),
        Arc::clone(&authority),
    )
    .unwrap();
    assert!(matches!(
        reopened.consume_free_ip_rate_limit_v1(request(182)),
        Err(StoreError::FreeIpQuotaExhausted)
    ));
    assert!(matches!(
        reopened.consume_free_ip_rate_limit_v1(request(120)),
        Err(StoreError::FreeIpClockRollback)
    ));
}

#[test]
fn quota_is_exactly_bounded_under_concurrency() {
    let dir = private_tempdir_v1();
    let authority: Arc<dyn RollbackFloorAuthorityV1> = Arc::new(
        SqliteRollbackFloorAuthorityV1::create(
            dir.path().join("authority.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .unwrap(),
    );
    let path = dir.path().join("provider.sqlite3");
    let store = create_store(&path, Arc::clone(&authority));
    let barrier = Arc::new(Barrier::new(9));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            store.consume_free_ip_rate_limit_v1(FreeIpRateLimitRequestV1 {
                quota: 3,
                now_unix_seconds: 240,
                ..request(240)
            })
        }));
    }
    barrier.wait();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    let successes = outcomes.iter().filter(|result| result.is_ok()).count();
    assert_eq!(successes, 3, "unexpected outcomes: {outcomes:?}");
    assert_eq!(store.identity().unwrap().spend_commit_seq, 3);
}

#[test]
fn grant_nonce_failure_rolls_back_free_ip_bucket_and_clock() {
    let dir = private_tempdir_v1();
    let authority: Arc<dyn RollbackFloorAuthorityV1> = Arc::new(
        SqliteRollbackFloorAuthorityV1::create(
            dir.path().join("authority.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .unwrap(),
    );
    let store = create_store(&dir.path().join("provider.sqlite3"), authority);
    let before = store.identity().unwrap();

    crate::fail_next_grant_transition_nonce_for_current_thread_v1();
    assert!(matches!(
        store.consume_free_ip_rate_limit_v1(request(180)),
        Err(StoreError::Io(_))
    ));
    assert_eq!(store.identity().unwrap(), before);
    assert_eq!(
        store
            .operational_inventory()
            .unwrap()
            .free_rate_limit_bucket_rows,
        0
    );

    // A lower timestamp remains admissible only if the failed transaction also
    // rolled the provider-local clock update back.
    store.consume_free_ip_rate_limit_v1(request(120)).unwrap();
    assert_eq!(store.identity().unwrap().spend_commit_seq, 1);
}

#[test]
fn schema_contains_only_hmac_subject_and_public_bucket_fields() {
    let dir = private_tempdir_v1();
    let authority: Arc<dyn RollbackFloorAuthorityV1> = Arc::new(
        SqliteRollbackFloorAuthorityV1::create(
            dir.path().join("authority.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .unwrap(),
    );
    let path = dir.path().join("provider.sqlite3");
    let store = create_store(&path, authority);
    assert_eq!(store.identity().unwrap().schema_version, SCHEMA_VERSION);
    let connection = Connection::open(&path).unwrap();
    let columns = connection
        .prepare("SELECT name FROM pragma_table_info('free_ip_rate_limit_buckets')")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        columns,
        vec![
            "subject",
            "policy_digest",
            "scope_id",
            "offer_id",
            "expires_at",
            "count"
        ]
    );
    assert!(!columns
        .iter()
        .any(|name| name.contains("ip") || name.contains("address")));
}

#[test]
fn policy_digest_prevents_offer_id_reuse_from_sharing_quota() {
    let dir = private_tempdir_v1();
    let authority: Arc<dyn RollbackFloorAuthorityV1> = Arc::new(
        SqliteRollbackFloorAuthorityV1::create(
            dir.path().join("authority.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .unwrap(),
    );
    let store = create_store(&dir.path().join("provider.sqlite3"), authority);
    let first = FreeIpRateLimitRequestV1 {
        quota: 1,
        ..request(120)
    };
    store.consume_free_ip_rate_limit_v1(first).unwrap();
    assert!(matches!(
        store.consume_free_ip_rate_limit_v1(first),
        Err(StoreError::FreeIpQuotaExhausted)
    ));
    store
        .consume_free_ip_rate_limit_v1(FreeIpRateLimitRequestV1 {
            policy_digest: [0x56; 32],
            ..first
        })
        .unwrap();
}

#[test]
fn expired_buckets_are_collected_before_capacity_and_clock_remains_high() {
    let dir = private_tempdir_v1();
    let authority: Arc<dyn RollbackFloorAuthorityV1> = Arc::new(
        SqliteRollbackFloorAuthorityV1::create(
            dir.path().join("authority.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .unwrap(),
    );
    let store = create_store(&dir.path().join("provider.sqlite3"), authority);
    let first = FreeIpRateLimitRequestV1 {
        max_buckets: 1,
        now_unix_seconds: 120,
        ..request(120)
    };
    store.consume_free_ip_rate_limit_v1(first).unwrap();
    let second = FreeIpRateLimitRequestV1 {
        subject: [0x34; 32],
        max_buckets: 1,
        now_unix_seconds: 180,
        ..request(180)
    };
    store.consume_free_ip_rate_limit_v1(second).unwrap();
    assert!(matches!(
        store.consume_free_ip_rate_limit_v1(FreeIpRateLimitRequestV1 {
            now_unix_seconds: 120,
            ..second
        }),
        Err(StoreError::FreeIpClockRollback)
    ));
}

#[test]
fn capacity_rejects_new_subject_without_eviction() {
    let dir = private_tempdir_v1();
    let authority: Arc<dyn RollbackFloorAuthorityV1> = Arc::new(
        SqliteRollbackFloorAuthorityV1::create(
            dir.path().join("authority.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .unwrap(),
    );
    let store = create_store(&dir.path().join("provider.sqlite3"), authority);
    let first = FreeIpRateLimitRequestV1 {
        max_buckets: 1,
        ..request(120)
    };
    store.consume_free_ip_rate_limit_v1(first).unwrap();
    assert!(matches!(
        store.consume_free_ip_rate_limit_v1(FreeIpRateLimitRequestV1 {
            subject: [0x34; 32],
            ..first
        }),
        Err(StoreError::FreeIpQuotaExhausted)
    ));
}

#[test]
fn prior_v4_schema_is_strictly_rejected_without_migration() {
    let dir = private_tempdir_v1();
    let authority: Arc<dyn RollbackFloorAuthorityV1> = Arc::new(
        SqliteRollbackFloorAuthorityV1::create(
            dir.path().join("authority.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .unwrap(),
    );
    let path = dir.path().join("provider.sqlite3");
    let store = create_store(&path, Arc::clone(&authority));
    drop(store);
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 4i64)
        .unwrap();

    assert!(matches!(
        ProviderStore::open_existing(&path, PROVIDER, StoreOptions::default(), authority),
        Err(StoreError::SchemaMismatch(_))
    ));
}
