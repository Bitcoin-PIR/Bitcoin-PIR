use pir_service_store::{
    CashuCustodyExposureLimitsV1, CashuCustodySealedBlobV1, CashuSwapIntentStateV1,
    CashuSwapSealedRecoveryV1, NewCashuCustodyLotV1, NewCashuSwapIntentV1, ProviderStore,
    RollbackFloorAuthorityErrorV1, RollbackFloorAuthorityV1, RollbackFloorV1, StoreError,
    StoreOptions, SCHEMA_VERSION,
};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use tempfile::{Builder, TempDir};

const PROVIDER: [u8; 32] = [0x91; 32];
const STORE_INSTANCE: [u8; 16] = [0x92; 16];
const WORKERS: usize = 8;

#[derive(Debug, Default)]
struct MemoryRollbackAuthority {
    floor: Mutex<Option<RollbackFloorV1>>,
    /// If non-zero, durably apply this generation and then lose its response.
    lose_response_at_generation: AtomicU64,
}

impl MemoryRollbackAuthority {
    fn floor(&self) -> RollbackFloorV1 {
        self.floor.lock().unwrap().unwrap()
    }

    fn lose_response_at(&self, generation: u64) {
        self.lose_response_at_generation
            .store(generation, Ordering::SeqCst);
    }
}

impl RollbackFloorAuthorityV1 for MemoryRollbackAuthority {
    fn load(
        &self,
        _provider_id: &[u8; 32],
    ) -> Result<Option<RollbackFloorV1>, RollbackFloorAuthorityErrorV1> {
        Ok(*self.floor.lock().unwrap())
    }

    fn initialize(
        &self,
        initial: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        let mut floor = self.floor.lock().unwrap();
        if floor.is_none() {
            *floor = Some(*initial);
        }
        Ok(floor.unwrap())
    }

    fn compare_and_advance(
        &self,
        expected: &RollbackFloorV1,
        next: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        let mut floor = self.floor.lock().unwrap();
        if floor.as_ref() == Some(expected) {
            *floor = Some(*next);
        }
        let current = floor
            .ok_or_else(|| RollbackFloorAuthorityErrorV1::new("rollback floor disappeared"))?;
        if next.store_generation != 0
            && self
                .lose_response_at_generation
                .compare_exchange(next.store_generation, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            return Err(RollbackFloorAuthorityErrorV1::new(
                "injected lost CAS response",
            ));
        }
        Ok(current)
    }
}

struct TestPath {
    _directory: TempDir,
    database: PathBuf,
    backup: PathBuf,
}

impl TestPath {
    fn new() -> Self {
        let directory = Builder::new()
            .prefix("bitcoinpir-cashu-swap-v4-test-")
            .tempdir()
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("restrict Cashu swap test directory permissions");
        }
        Self {
            database: directory.path().join("provider.sqlite3"),
            backup: directory.path().join("provider-backup.sqlite3"),
            _directory: directory,
        }
    }
}

fn create_store(path: &Path, authority: Arc<MemoryRollbackAuthority>) -> ProviderStore {
    ProviderStore::create(
        path,
        STORE_INSTANCE,
        PROVIDER,
        StoreOptions::default(),
        authority,
    )
    .unwrap()
}

fn intent() -> NewCashuSwapIntentV1 {
    NewCashuSwapIntentV1 {
        intent_id: [0xa1; 16],
        mint_id: [0xa2; 32],
        manifest_digest: [0xa9; 32],
        unit: "sat".to_owned(),
        input_set_digest: [0xa3; 32],
        request_digest: [0xa4; 32],
        output_set_digest: [0xa5; 32],
        offer_binding_digest: [0xa6; 32],
        settlement_value: 7,
        expected_output_count: 2,
        sealed_recovery: CashuSwapSealedRecoveryV1 {
            key_epoch: 3,
            nonce: vec![0xa7; 24],
            ciphertext: vec![0xa8; 128],
        },
        created_bucket: 100,
    }
}

fn limits() -> CashuCustodyExposureLimitsV1 {
    CashuCustodyExposureLimitsV1 {
        max_unsettled_value: 1_000,
        max_unsettled_notes: 100,
    }
}

fn limits_below_existing_exposure() -> CashuCustodyExposureLimitsV1 {
    CashuCustodyExposureLimitsV1 {
        max_unsettled_value: 1,
        max_unsettled_notes: 1,
    }
}

fn custody_y(prefix: u8, fill: u8) -> [u8; 33] {
    let mut value = [fill; 33];
    value[0] = prefix;
    value
}

fn custody_lot() -> NewCashuCustodyLotV1 {
    NewCashuCustodyLotV1 {
        lot_id: [0xc1; 16],
        manifest_digest: [0xa9; 32],
        active_keyset_digest: [0xca; 32],
        note_set_digest: [0xcb; 32],
        note_ys: vec![custody_y(0x02, 0xc2), custody_y(0x03, 0xc3)],
        sealed_notes: CashuCustodySealedBlobV1 {
            key_epoch: 5,
            nonce: vec![0xc4; 24],
            ciphertext: vec![0xc5; 96],
        },
    }
}

fn replacement_recovery() -> CashuSwapSealedRecoveryV1 {
    CashuSwapSealedRecoveryV1 {
        key_epoch: 4,
        nonce: vec![0xb7; 24],
        ciphertext: vec![0xb8; 192],
    }
}

fn copy_database_without_wal(source: &Path, destination: &Path) {
    let connection = Connection::open(source).unwrap();
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(busy, 0);
    assert_eq!(log_frames, checkpointed_frames);
    drop(connection);
    std::fs::copy(source, destination).unwrap();
}

fn remove_sqlite_sidecars(path: &Path) {
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
        if sidecar.exists() {
            std::fs::remove_file(sidecar).unwrap();
        }
    }
}

#[test]
fn schema_v7_exact_replay_is_idempotent_and_conflicts_fail_closed() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    assert_eq!(SCHEMA_VERSION, 7);

    let proposed = intent();
    let inserted = store
        .insert_cashu_swap_intent_v1(&proposed, limits())
        .unwrap();
    assert!(inserted.inserted);
    assert_eq!(inserted.intent.state, CashuSwapIntentStateV1::Prepared);
    assert_eq!(store.identity().unwrap().store_generation, 1);

    // A fresh AEAD nonce/ciphertext is an exact semantic replay. The first
    // durable envelope wins and no second generation is written.
    let mut replay = proposed.clone();
    replay.sealed_recovery = CashuSwapSealedRecoveryV1 {
        key_epoch: 9,
        nonce: vec![0xc7; 24],
        ciphertext: vec![0xc8; 64],
    };
    let replayed = store
        .insert_cashu_swap_intent_v1(&replay, limits())
        .unwrap();
    assert!(!replayed.inserted);
    assert_eq!(replayed.intent.sealed_recovery, proposed.sealed_recovery);
    assert_eq!(store.identity().unwrap().store_generation, 1);
    let replayed_while_admission_is_closed = store
        .insert_cashu_swap_intent_v1(&proposed, limits_below_existing_exposure())
        .unwrap();
    assert!(!replayed_while_admission_is_closed.inserted);

    for conflicting in [
        {
            let mut value = proposed.clone();
            value.manifest_digest[0] ^= 1;
            value
        },
        {
            let mut value = proposed.clone();
            value.unit = "msat".to_owned();
            value
        },
        {
            let mut value = proposed.clone();
            value.request_digest[0] ^= 1;
            value
        },
        {
            let mut value = proposed.clone();
            value.output_set_digest[0] ^= 1;
            value
        },
        {
            let mut value = proposed.clone();
            value.offer_binding_digest[0] ^= 1;
            value
        },
        {
            let mut value = proposed.clone();
            value.settlement_value += 1;
            value
        },
        {
            let mut value = proposed.clone();
            value.expected_output_count += 1;
            value
        },
        {
            let mut value = proposed.clone();
            value.intent_id[0] ^= 1;
            value
        },
    ] {
        assert!(matches!(
            store.insert_cashu_swap_intent_v1(&conflicting, limits()),
            Err(StoreError::CashuSwapIntentConflict)
        ));
    }
    let mut reused_intent_id = proposed.clone();
    reused_intent_id.input_set_digest[0] ^= 1;
    assert!(matches!(
        store.insert_cashu_swap_intent_v1(&reused_intent_id, limits()),
        Err(StoreError::CashuSwapIntentConflict)
    ));
    assert_eq!(store.identity().unwrap().store_generation, 1);
    assert_eq!(authority.floor().store_generation, 1);

    let connection = Connection::open(&path.database).unwrap();
    let columns = connection
        .prepare("PRAGMA table_info(cashu_swap_intents)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        columns,
        [
            "intent_id",
            "mint_id",
            "manifest_digest",
            "unit",
            "input_set_digest",
            "request_digest",
            "output_set_digest",
            "offer_binding_digest",
            "settlement_value",
            "expected_output_count",
            "state",
            "recovery_key_epoch",
            "recovery_nonce",
            "recovery_ciphertext",
            "created_bucket",
            "updated_bucket",
        ]
    );
    for forbidden in [
        "invoice",
        "payment_hash",
        "preimage",
        "payer",
        "query",
        "proof_secret",
        "blinding_factor",
    ] {
        assert!(!columns.iter().any(|column| column.contains(forbidden)));
    }
}

#[test]
fn dfa_is_monotonic_across_restart_and_grant_is_claimed_once() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    let proposed = intent();
    store
        .insert_cashu_swap_intent_v1(&proposed, limits())
        .unwrap();

    assert!(matches!(
        store.commit_cashu_swap_wallet_v1(&proposed.intent_id, &replacement_recovery(), 101),
        Err(StoreError::CashuSwapStateConflict)
    ));
    assert!(matches!(
        store.mark_cashu_swap_attention_v1(&proposed.intent_id, 101),
        Err(StoreError::CashuSwapStateConflict)
    ));
    assert!(matches!(
        store.claim_cashu_swap_grant_once_v1(&proposed.intent_id, &custody_lot(), 101),
        Err(StoreError::CashuSwapStateConflict)
    ));
    assert_eq!(store.identity().unwrap().store_generation, 1);

    assert!(store
        .begin_cashu_swap_submission_v1(&proposed.intent_id, 101)
        .unwrap());
    assert!(!store
        .begin_cashu_swap_submission_v1(&proposed.intent_id, 101)
        .unwrap());
    assert_eq!(store.identity().unwrap().store_generation, 2);
    drop(store);

    let reopened = ProviderStore::open_existing(
        &path.database,
        PROVIDER,
        StoreOptions::default(),
        Arc::clone(&authority) as Arc<dyn RollbackFloorAuthorityV1>,
    )
    .unwrap();
    let submitted = reopened
        .cashu_swap_intent_by_input_v1(&proposed.mint_id, &proposed.input_set_digest)
        .unwrap()
        .unwrap();
    assert_eq!(submitted.state, CashuSwapIntentStateV1::Submitted);

    assert!(reopened
        .mark_cashu_swap_attention_v1(&proposed.intent_id, 102)
        .unwrap());
    assert!(!reopened
        .mark_cashu_swap_attention_v1(&proposed.intent_id, 102)
        .unwrap());
    assert!(!reopened
        .begin_cashu_swap_submission_v1(&proposed.intent_id, 102)
        .unwrap());
    assert!(matches!(
        reopened.claim_cashu_swap_grant_once_v1(&proposed.intent_id, &custody_lot(), 102),
        Err(StoreError::CashuSwapStateConflict)
    ));
    assert_eq!(reopened.identity().unwrap().store_generation, 3);

    let replacement = replacement_recovery();
    assert!(reopened
        .commit_cashu_swap_wallet_v1(&proposed.intent_id, &replacement, 103)
        .unwrap());
    assert!(!reopened
        .commit_cashu_swap_wallet_v1(&proposed.intent_id, &replacement, 103)
        .unwrap());
    assert!(!reopened
        .mark_cashu_swap_attention_v1(&proposed.intent_id, 103)
        .unwrap());
    assert_eq!(reopened.identity().unwrap().store_generation, 4);

    assert!(
        reopened
            .claim_cashu_swap_grant_once_v1(&proposed.intent_id, &custody_lot(), 104)
            .unwrap()
            .issued
    );
    assert!(
        !reopened
            .claim_cashu_swap_grant_once_v1(&proposed.intent_id, &custody_lot(), 104)
            .unwrap()
            .issued
    );
    let identity = reopened.identity().unwrap();
    assert_eq!(identity.store_generation, 5);
    assert_eq!(identity.spend_commit_seq, 1);
    let granted = reopened
        .cashu_swap_intent_by_input_v1(&proposed.mint_id, &proposed.input_set_digest)
        .unwrap()
        .unwrap();
    assert_eq!(granted.state, CashuSwapIntentStateV1::GrantIssued);
    assert_eq!(granted.sealed_recovery, replacement);
    assert_eq!(authority.floor().store_generation, 5);
    assert_eq!(authority.floor().spend_commit_seq, 1);
}

#[test]
fn concurrent_prepare_submit_and_grant_each_have_one_winner() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = Arc::new(create_store(&path.database, Arc::clone(&authority)));
    let proposed = Arc::new(intent());

    let barrier = Arc::new(Barrier::new(WORKERS));
    let prepares = (0..WORKERS)
        .map(|_| {
            let store = Arc::clone(&store);
            let proposed = Arc::clone(&proposed);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.insert_cashu_swap_intent_v1(&proposed, limits())
            })
        })
        .collect::<Vec<_>>();
    let inserted = prepares
        .into_iter()
        .map(|worker| worker.join().unwrap().unwrap().inserted)
        .filter(|value| *value)
        .count();
    assert_eq!(inserted, 1);
    assert_eq!(store.identity().unwrap().store_generation, 1);

    let barrier = Arc::new(Barrier::new(WORKERS));
    let submissions = (0..WORKERS)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let intent_id = proposed.intent_id;
            std::thread::spawn(move || {
                barrier.wait();
                store.begin_cashu_swap_submission_v1(&intent_id, 101)
            })
        })
        .collect::<Vec<_>>();
    let submitted = submissions
        .into_iter()
        .map(|worker| worker.join().unwrap().unwrap())
        .filter(|value| *value)
        .count();
    assert_eq!(submitted, 1);
    assert_eq!(store.identity().unwrap().store_generation, 2);

    store
        .commit_cashu_swap_wallet_v1(&proposed.intent_id, &replacement_recovery(), 102)
        .unwrap();
    let barrier = Arc::new(Barrier::new(WORKERS));
    let grants = (0..WORKERS)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let intent_id = proposed.intent_id;
            std::thread::spawn(move || {
                barrier.wait();
                store.claim_cashu_swap_grant_once_v1(&intent_id, &custody_lot(), 103)
            })
        })
        .collect::<Vec<_>>();
    let granted = grants
        .into_iter()
        .map(|worker| worker.join().unwrap().unwrap().issued)
        .filter(|value| *value)
        .count();
    assert_eq!(granted, 1);
    let identity = store.identity().unwrap();
    assert_eq!(identity.store_generation, 4);
    assert_eq!(identity.spend_commit_seq, 1);
}

#[test]
fn exact_cashu_grants_from_equal_predecessors_have_distinct_commitments() {
    let first_path = TestPath::new();
    let second_path = TestPath::new();
    let first_authority = Arc::new(MemoryRollbackAuthority::default());
    let second_authority = Arc::new(MemoryRollbackAuthority::default());
    let first = create_store(&first_path.database, first_authority);
    let second = create_store(&second_path.database, second_authority);
    let proposed = intent();
    let recovery = replacement_recovery();

    for store in [&first, &second] {
        store
            .insert_cashu_swap_intent_v1(&proposed, limits())
            .unwrap();
        store
            .begin_cashu_swap_submission_v1(&proposed.intent_id, 101)
            .unwrap();
        store
            .commit_cashu_swap_wallet_v1(&proposed.intent_id, &recovery, 102)
            .unwrap();
    }
    let first_predecessor = first.identity().unwrap();
    let second_predecessor = second.identity().unwrap();
    assert_eq!(first_predecessor, second_predecessor);

    assert!(
        first
            .claim_cashu_swap_grant_once_v1(&proposed.intent_id, &custody_lot(), 103)
            .unwrap()
            .issued
    );
    assert!(
        second
            .claim_cashu_swap_grant_once_v1(&proposed.intent_id, &custody_lot(), 103)
            .unwrap()
            .issued
    );
    let first_grant = first.identity().unwrap();
    let second_grant = second.identity().unwrap();
    assert_eq!(first_grant.store_generation, 4);
    assert_eq!(second_grant.store_generation, 4);
    assert_eq!(first_grant.spend_commit_seq, 1);
    assert_eq!(second_grant.spend_commit_seq, 1);
    assert_eq!(
        first_grant.rollback_parent_commitment,
        first_predecessor.rollback_commitment
    );
    assert_eq!(
        second_grant.rollback_parent_commitment,
        second_predecessor.rollback_commitment
    );
    assert_ne!(
        first_grant.rollback_commitment,
        second_grant.rollback_commitment
    );
}

#[test]
fn grant_nonce_failure_rolls_back_cashu_custody_and_state() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    let proposed = intent();
    store
        .insert_cashu_swap_intent_v1(&proposed, limits())
        .unwrap();
    store
        .begin_cashu_swap_submission_v1(&proposed.intent_id, 101)
        .unwrap();
    store
        .commit_cashu_swap_wallet_v1(&proposed.intent_id, &replacement_recovery(), 102)
        .unwrap();
    let before = store.identity().unwrap();

    crate::fail_next_grant_transition_nonce_for_current_thread_v1();
    assert!(matches!(
        store.claim_cashu_swap_grant_once_v1(&proposed.intent_id, &custody_lot(), 103),
        Err(StoreError::Io(_))
    ));
    assert_eq!(store.identity().unwrap(), before);
    assert_eq!(
        store
            .cashu_swap_intent_by_input_v1(&proposed.mint_id, &proposed.input_set_digest)
            .unwrap()
            .unwrap()
            .state,
        CashuSwapIntentStateV1::WalletStored
    );
    let inventory = store.operational_inventory().unwrap();
    assert_eq!(inventory.cashu_custody_lot_rows, 0);
    assert_eq!(inventory.cashu_custody_note_rows, 0);

    assert!(
        store
            .claim_cashu_swap_grant_once_v1(&proposed.intent_id, &custody_lot(), 103)
            .unwrap()
            .issued
    );
}

#[test]
fn lost_submit_cas_response_recovers_as_submitted_without_new_generation() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    let proposed = intent();
    store
        .insert_cashu_swap_intent_v1(&proposed, limits())
        .unwrap();
    authority.lose_response_at(2);

    assert!(matches!(
        store.begin_cashu_swap_submission_v1(&proposed.intent_id, 101),
        Err(StoreError::UnanchoredCommit {
            store_generation: 2,
            ..
        })
    ));
    assert_eq!(authority.floor().store_generation, 2);
    drop(store);

    let reopened = ProviderStore::open_existing(
        &path.database,
        PROVIDER,
        StoreOptions::default(),
        Arc::clone(&authority) as Arc<dyn RollbackFloorAuthorityV1>,
    )
    .unwrap();
    let recovered = reopened
        .cashu_swap_intent_by_input_v1(&proposed.mint_id, &proposed.input_set_digest)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.state, CashuSwapIntentStateV1::Submitted);
    assert!(!reopened
        .begin_cashu_swap_submission_v1(&proposed.intent_id, 102)
        .unwrap());
    assert_eq!(reopened.identity().unwrap().store_generation, 2);
}

#[test]
fn stale_prepared_backup_cannot_reenable_nut03_or_grant() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    let proposed = intent();
    store
        .insert_cashu_swap_intent_v1(&proposed, limits())
        .unwrap();
    copy_database_without_wal(&path.database, &path.backup);

    store
        .begin_cashu_swap_submission_v1(&proposed.intent_id, 101)
        .unwrap();
    store
        .commit_cashu_swap_wallet_v1(&proposed.intent_id, &replacement_recovery(), 102)
        .unwrap();
    store
        .claim_cashu_swap_grant_once_v1(&proposed.intent_id, &custody_lot(), 103)
        .unwrap();
    assert_eq!(authority.floor().store_generation, 4);
    drop(store);

    remove_sqlite_sidecars(&path.database);
    std::fs::copy(&path.backup, &path.database).unwrap();
    assert!(matches!(
        ProviderStore::open_existing(&path.database, PROVIDER, StoreOptions::default(), authority,),
        Err(StoreError::RollbackDetected {
            database_generation: 1,
            authority_generation: 4,
        })
    ));
}

#[test]
fn prior_v6_schema_is_strictly_rejected_without_automatic_migration() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    drop(store);
    let connection = Connection::open(&path.database).unwrap();
    connection.pragma_update(None, "user_version", 6).unwrap();
    connection
        .execute("UPDATE store_identity SET schema_version = 6", [])
        .unwrap();
    drop(connection);

    assert!(matches!(
        ProviderStore::open_existing(
            &path.database,
            PROVIDER,
            StoreOptions::default(),
            authority,
        ),
        Err(StoreError::SchemaMismatch(message)) if message == "user_version is unsupported"
    ));
    let connection = Connection::open(&path.database).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        6
    );
}

#[test]
fn prior_v5_schema_is_strictly_rejected_without_automatic_migration() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    drop(store);
    let connection = Connection::open(&path.database).unwrap();
    connection.pragma_update(None, "user_version", 5).unwrap();
    connection
        .execute("UPDATE store_identity SET schema_version = 5", [])
        .unwrap();
    connection
        .execute("DROP TABLE cashu_swap_intents", [])
        .unwrap();
    drop(connection);

    assert!(matches!(
        ProviderStore::open_existing(
            &path.database,
            PROVIDER,
            StoreOptions::default(),
            authority,
        ),
        Err(StoreError::SchemaMismatch(message)) if message == "user_version is unsupported"
    ));
    let connection = Connection::open(&path.database).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        5
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'cashu_swap_intents'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}
