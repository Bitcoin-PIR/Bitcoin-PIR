use ed25519_dalek::SigningKey;
use pir_service_protocol::{
    AcquisitionMethod, AuthPaddingClassV1, AuthScheme, BackendId, DatasetBindingV1,
    DeploymentStatus, EntitlementLimitsV1, FreeModeV1, PolicyRollbackGuardV1, PriceV1,
    PrivacyLeakageV1, ServiceOfferV1, ServicePolicyEpochFloorsV1, ServicePolicyV1,
    ServiceScopePolicyV1, ServiceScopeV1, VerificationMode, WorkloadId,
};
use pir_service_store::{
    NewSpendNamespace, ProviderStore, RollbackFloorAuthorityErrorV1, RollbackFloorAuthorityV1,
    RollbackFloorV1, SpendRequest, StoreError, StoreOptions,
};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use tempfile::{Builder, TempDir};

const PROVIDER: [u8; 32] = [0x11; 32];
const STORE_INSTANCE: [u8; 16] = [0x22; 16];
const POLICY_SEED: [u8; 32] = [0x33; 32];
const NAMESPACE: [u8; 32] = [0x44; 32];

#[derive(Debug, Default)]
struct MemoryRollbackAuthority {
    floor: Mutex<Option<RollbackFloorV1>>,
    unavailable: AtomicBool,
    lose_next_advance_response: AtomicBool,
    reject_next_advance: AtomicBool,
}

impl MemoryRollbackAuthority {
    fn floor(&self) -> Option<RollbackFloorV1> {
        *self.floor.lock().unwrap()
    }

    fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::SeqCst);
    }

    fn lose_next_advance_response(&self) {
        self.lose_next_advance_response
            .store(true, Ordering::SeqCst);
    }

    fn reject_next_advance(&self) {
        self.reject_next_advance.store(true, Ordering::SeqCst);
    }

    fn check_available(&self) -> Result<(), RollbackFloorAuthorityErrorV1> {
        if self.unavailable.load(Ordering::SeqCst) {
            Err(RollbackFloorAuthorityErrorV1::new(
                "injected authority outage",
            ))
        } else {
            Ok(())
        }
    }
}

impl RollbackFloorAuthorityV1 for MemoryRollbackAuthority {
    fn load(
        &self,
        _provider_id: &[u8; 32],
    ) -> Result<Option<RollbackFloorV1>, RollbackFloorAuthorityErrorV1> {
        self.check_available()?;
        Ok(*self.floor.lock().unwrap())
    }

    fn initialize(
        &self,
        initial: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        self.check_available()?;
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
        self.check_available()?;
        if self.reject_next_advance.swap(false, Ordering::SeqCst) {
            return Err(RollbackFloorAuthorityErrorV1::new(
                "injected pre-commit CAS failure",
            ));
        }
        let mut floor = self.floor.lock().unwrap();
        if floor.as_ref() == Some(expected) {
            *floor = Some(*next);
        }
        let current = floor
            .ok_or_else(|| RollbackFloorAuthorityErrorV1::new("floor disappeared during CAS"))?;
        if self
            .lose_next_advance_response
            .swap(false, Ordering::SeqCst)
        {
            return Err(RollbackFloorAuthorityErrorV1::new(
                "injected lost CAS response",
            ));
        }
        Ok(current)
    }
}

#[derive(Debug)]
struct BlockFirstCompareAuthority {
    inner: Arc<MemoryRollbackAuthority>,
    compare_calls: AtomicUsize,
    first_compare_entered: Arc<Barrier>,
    release_first_compare: Arc<Barrier>,
}

impl RollbackFloorAuthorityV1 for BlockFirstCompareAuthority {
    fn load(
        &self,
        provider_id: &[u8; 32],
    ) -> Result<Option<RollbackFloorV1>, RollbackFloorAuthorityErrorV1> {
        self.inner.load(provider_id)
    }

    fn initialize(
        &self,
        initial: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        self.inner.initialize(initial)
    }

    fn compare_and_advance(
        &self,
        expected: &RollbackFloorV1,
        next: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        if self.compare_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first_compare_entered.wait();
            self.release_first_compare.wait();
        }
        self.inner.compare_and_advance(expected, next)
    }
}

struct TestPath {
    _directory: TempDir,
    database: PathBuf,
    backup: PathBuf,
    fork: PathBuf,
}

impl TestPath {
    fn new() -> Self {
        let directory = Builder::new()
            .prefix("bitcoinpir-provider-rollback-floor-test-")
            .tempdir()
            .unwrap();
        Self {
            database: directory.path().join("provider.sqlite3"),
            backup: directory.path().join("provider-backup.sqlite3"),
            fork: directory.path().join("provider-fork.sqlite3"),
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

fn signed_open_policy(epoch: u64, issued_at: u64) -> ServicePolicyV1 {
    let scope = ServiceScopeV1 {
        provider_id: PROVIDER,
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        protocol_version: 1,
        dataset: DatasetBindingV1::Class { class_id: 7 },
        operation_profile: 1,
        entitlement_profile: 1,
    };
    let offer = ServiceOfferV1 {
        offer_id: 1,
        acquisition: AcquisitionMethod::FreeV1,
        free_mode: FreeModeV1::OpenBestEffort,
        free_quota: 0,
        free_window_seconds: 0,
        free_pow_difficulty_bits: 0,
        priority_class: 1,
        authorization: AuthScheme::FreeV1,
        verification: VerificationMode::ProviderLocal,
        deployment_status: DeploymentStatus::Stable,
        price: PriceV1::Free,
        issuer_id: [0; 32],
        key_id: Vec::new(),
        credential_binding: None,
        cashu_mint_manifest: None,
        endpoint: String::new(),
        invoice_expiry_seconds: 0,
        claim_window_seconds: 0,
        minimum_credential_validity_seconds: 30,
        retired_policy_grace_seconds: 0,
        credential_count: 1,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::KNOWN_MASK).unwrap(),
    };
    ServicePolicyV1::sign(
        PROVIDER,
        epoch,
        issued_at,
        issued_at + 100,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope,
            limits: EntitlementLimitsV1 {
                max_logical_inputs: 1,
                max_frames: 8,
                max_request_bytes: 1_000,
                max_response_bytes: 2_000,
                max_wall_time_ms: 5_000,
                max_concurrent_sockets: 1,
                max_hint_groups: 0,
                max_work_units: 10,
            },
            offers: vec![offer],
        }],
        &SigningKey::from_bytes(&POLICY_SEED),
    )
    .unwrap()
}

fn try_apply_policy(
    store: &ProviderStore,
    policy: &ServicePolicyV1,
    now: u64,
) -> Result<(), StoreError> {
    let verified = policy
        .verify_current_for_acquisition(
            &PROVIDER,
            now,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::default(),
            &SigningKey::from_bytes(&POLICY_SEED).verifying_key(),
        )
        .unwrap();
    store.apply_verified_policy_state_v1(&verified).map(|_| ())
}

fn apply_policy(store: &ProviderStore, policy: &ServicePolicyV1, now: u64) {
    try_apply_policy(store, policy, now).unwrap();
}

fn spend_namespace() -> NewSpendNamespace {
    NewSpendNamespace {
        namespace_id: NAMESPACE,
        scheme: AuthScheme::Bolt11DirectReceiptV1 as u16,
        issuer_id: [0x55; 32],
        key_id: vec![0x66; 16],
        binding_digest: [0x77; 32],
        not_after: 1_000,
        exclusive_key_lineage: None,
    }
}

fn copy_database_without_wal(source: &Path, destination: &Path) {
    let connection = Connection::open(source).unwrap();
    connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_row| Ok(()))
        .unwrap();
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
fn fresh_create_and_normal_restart_require_the_exact_external_floor() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    let identity = store.identity().unwrap();
    assert_eq!(identity.store_generation, 0);
    assert_eq!(identity.spend_commit_seq, 0);
    let inventory = store.operational_inventory().unwrap();
    assert_eq!(inventory.observed_store_generation, 0);
    assert_eq!(inventory.observed_spend_commit_seq, 0);
    assert_eq!(inventory.namespace_rows, 0);
    assert_eq!(inventory.spent_capability_rows, 0);
    assert_eq!(inventory.free_rate_limit_bucket_rows, 0);
    assert_eq!(inventory.cashu_swap_intent_rows, 0);
    assert_eq!(inventory.cashu_custody_lot_rows, 0);
    assert_eq!(inventory.cashu_custody_note_rows, 0);
    assert_eq!(inventory.cashu_custody_export_batch_rows, 0);
    assert_eq!(
        authority.floor().unwrap().rollback_commitment,
        identity.rollback_commitment
    );
    drop(store);

    ProviderStore::open_existing(&path.database, PROVIDER, StoreOptions::default(), authority)
        .unwrap();
}

#[test]
fn stale_backup_restore_is_rejected_and_cannot_revive_old_state() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    store.install_namespace(&spend_namespace()).unwrap();
    copy_database_without_wal(&path.database, &path.backup);
    store
        .spend(SpendRequest {
            namespace_id: NAMESPACE,
            spend_key: [0x88; 32],
            now_unix_seconds: 150,
        })
        .unwrap();
    assert_eq!(authority.floor().unwrap().store_generation, 2);
    assert_eq!(authority.floor().unwrap().spend_commit_seq, 1);
    drop(store);

    remove_sqlite_sidecars(&path.database);
    std::fs::copy(&path.backup, &path.database).unwrap();
    assert!(matches!(
        ProviderStore::open_existing(&path.database, PROVIDER, StoreOptions::default(), authority,),
        Err(StoreError::RollbackDetected {
            database_generation: 1,
            authority_generation: 2
        })
    ));
}

#[test]
fn backup_at_the_exact_anchored_generation_restores_normally() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    apply_policy(&store, &signed_open_policy(1, 100), 150);
    copy_database_without_wal(&path.database, &path.backup);
    assert_eq!(authority.floor().unwrap().store_generation, 1);
    drop(store);

    remove_sqlite_sidecars(&path.database);
    std::fs::copy(&path.backup, &path.database).unwrap();
    let restored =
        ProviderStore::open_existing(&path.database, PROVIDER, StoreOptions::default(), authority)
            .unwrap();
    assert_eq!(restored.identity().unwrap().store_generation, 1);
    assert_eq!(
        restored
            .policy_head()
            .unwrap()
            .unwrap()
            .highest_policy_epoch,
        1
    );
}

#[test]
fn lost_floor_and_wrong_store_identity_fail_closed() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    drop(store);

    let lost = Arc::new(MemoryRollbackAuthority::default());
    assert!(matches!(
        ProviderStore::open_existing(&path.database, PROVIDER, StoreOptions::default(), lost,),
        Err(StoreError::RollbackFloorMissing)
    ));

    let wrong = Arc::new(MemoryRollbackAuthority::default());
    let wrong_initial = RollbackFloorV1 {
        store_instance_id: [0x99; 16],
        provider_id: PROVIDER,
        store_generation: 0,
        spend_commit_seq: 0,
        rollback_commitment: [0x88; 32],
        schema_version: pir_service_store::SCHEMA_VERSION,
    };
    wrong.initialize(&wrong_initial).unwrap();
    assert!(matches!(
        ProviderStore::open_existing(&path.database, PROVIDER, StoreOptions::default(), wrong,),
        Err(StoreError::RollbackFloorIdentityMismatch)
    ));
}

#[test]
fn authority_outage_never_falls_back_to_sqlite_metadata() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    drop(store);
    authority.set_unavailable(true);
    assert!(matches!(
        ProviderStore::open_existing(&path.database, PROVIDER, StoreOptions::default(), authority,),
        Err(StoreError::RollbackAuthorityUnavailable(_))
    ));
}

#[test]
fn committed_but_unacknowledged_generation_recovers_idempotently() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    authority.reject_next_advance();
    let policy = signed_open_policy(1, 100);
    let verified = policy
        .verify_current_for_acquisition(
            &PROVIDER,
            150,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::default(),
            &SigningKey::from_bytes(&POLICY_SEED).verifying_key(),
        )
        .unwrap();
    assert!(matches!(
        store.apply_verified_policy_state_v1(&verified),
        Err(StoreError::UnanchoredCommit {
            store_generation: 1,
            ..
        })
    ));
    assert_eq!(authority.floor().unwrap().store_generation, 0);
    drop(store);

    let recovered = ProviderStore::open_existing(
        &path.database,
        PROVIDER,
        StoreOptions::default(),
        authority.clone(),
    )
    .unwrap();
    assert_eq!(recovered.identity().unwrap().store_generation, 1);
    assert_eq!(authority.floor().unwrap().store_generation, 1);
}

#[test]
fn lost_cas_response_recovers_without_a_second_generation() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    authority.lose_next_advance_response();
    let policy = signed_open_policy(1, 100);
    let verified = policy
        .verify_current_for_acquisition(
            &PROVIDER,
            150,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::default(),
            &SigningKey::from_bytes(&POLICY_SEED).verifying_key(),
        )
        .unwrap();
    assert!(matches!(
        store.apply_verified_policy_state_v1(&verified),
        Err(StoreError::UnanchoredCommit {
            store_generation: 1,
            ..
        })
    ));
    assert_eq!(authority.floor().unwrap().store_generation, 1);
    drop(store);

    let reopened =
        ProviderStore::open_existing(&path.database, PROVIDER, StoreOptions::default(), authority)
            .unwrap();
    assert_eq!(reopened.identity().unwrap().store_generation, 1);
}

#[test]
fn cloned_store_fork_and_same_generation_commitment_tamper_are_rejected() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    copy_database_without_wal(&path.database, &path.fork);
    apply_policy(&store, &signed_open_policy(1, 100), 150);
    drop(store);

    assert!(matches!(
        ProviderStore::open_existing(
            &path.fork,
            PROVIDER,
            StoreOptions::default(),
            authority.clone(),
        ),
        Err(StoreError::RollbackDetected { .. })
    ));

    let connection = Connection::open(&path.database).unwrap();
    connection
        .execute(
            "UPDATE store_identity SET rollback_commitment = ?1 WHERE singleton = 1",
            [[0xa5_u8; 32].as_slice()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        ProviderStore::open_existing(&path.database, PROVIDER, StoreOptions::default(), authority,),
        Err(StoreError::RollbackFork)
    ));
}

#[test]
fn concurrent_exact_policy_application_creates_one_generation() {
    const WORKERS: usize = 8;
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = Arc::new(create_store(&path.database, Arc::clone(&authority)));
    let policy = Arc::new(signed_open_policy(1, 100));
    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut workers = Vec::new();
    for _ in 0..WORKERS {
        let store = Arc::clone(&store);
        let policy = Arc::clone(&policy);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let verifying_key = SigningKey::from_bytes(&POLICY_SEED).verifying_key();
            let verified = policy
                .verify_current_for_acquisition(
                    &PROVIDER,
                    150,
                    &PolicyRollbackGuardV1::initial(),
                    &ServicePolicyEpochFloorsV1::default(),
                    &verifying_key,
                )
                .unwrap();
            barrier.wait();
            store.apply_verified_policy_state_v1(&verified)
        }));
    }
    for worker in workers {
        worker.join().unwrap().unwrap();
    }
    assert_eq!(store.identity().unwrap().store_generation, 1);
    assert_eq!(authority.floor().unwrap().store_generation, 1);
}

#[test]
fn superseding_anchor_on_same_database_confirms_earlier_commit() {
    let path = TestPath::new();
    let inner = Arc::new(MemoryRollbackAuthority::default());
    let first_compare_entered = Arc::new(Barrier::new(2));
    let release_first_compare = Arc::new(Barrier::new(2));
    let authority = Arc::new(BlockFirstCompareAuthority {
        inner: Arc::clone(&inner),
        compare_calls: AtomicUsize::new(0),
        first_compare_entered: Arc::clone(&first_compare_entered),
        release_first_compare: Arc::clone(&release_first_compare),
    });
    let store = ProviderStore::create(
        &path.database,
        STORE_INSTANCE,
        PROVIDER,
        StoreOptions::default(),
        authority,
    )
    .unwrap();

    let first_store = store.clone();
    let first = std::thread::spawn(move || {
        try_apply_policy(&first_store, &signed_open_policy(1, 100), 150)
    });
    first_compare_entered.wait();

    // Reconciliation anchors generation 1 for the blocked caller, then this
    // second mutation commits and anchors generation 2 before the first CAS
    // receives its response.
    let second = try_apply_policy(&store, &signed_open_policy(2, 101), 150);
    release_first_compare.wait();

    assert!(second.is_ok(), "second mutation failed: {second:?}");
    let first = first.join().unwrap();
    assert!(first.is_ok(), "earlier commit was not confirmed: {first:?}");
    assert_eq!(store.identity().unwrap().store_generation, 2);
    assert_eq!(inner.floor().unwrap().store_generation, 2);
}

#[test]
fn superseding_anchor_from_cloned_fork_does_not_confirm_losing_commit() {
    let path = TestPath::new();
    let inner = Arc::new(MemoryRollbackAuthority::default());
    let first_compare_entered = Arc::new(Barrier::new(2));
    let release_first_compare = Arc::new(Barrier::new(2));
    let authority = Arc::new(BlockFirstCompareAuthority {
        inner: Arc::clone(&inner),
        compare_calls: AtomicUsize::new(0),
        first_compare_entered: Arc::clone(&first_compare_entered),
        release_first_compare: Arc::clone(&release_first_compare),
    });
    let original = ProviderStore::create(
        &path.database,
        STORE_INSTANCE,
        PROVIDER,
        StoreOptions::default(),
        authority.clone(),
    )
    .unwrap();
    copy_database_without_wal(&path.database, &path.fork);
    let fork =
        ProviderStore::open_existing(&path.fork, PROVIDER, StoreOptions::default(), authority)
            .unwrap();

    let original_worker = original.clone();
    let losing = std::thread::spawn(move || {
        try_apply_policy(&original_worker, &signed_open_policy(1, 100), 150)
    });
    first_compare_entered.wait();

    // Different policy contents create a conflicting generation-1 lineage on
    // the cloned file. Advancing that winning fork again must not make the
    // blocked original commit look transitively anchored.
    let winner_one = try_apply_policy(&fork, &signed_open_policy(1, 101), 150);
    let winner_two = try_apply_policy(&fork, &signed_open_policy(2, 102), 150);
    release_first_compare.wait();

    assert!(
        winner_one.is_ok(),
        "fork generation 1 failed: {winner_one:?}"
    );
    assert!(
        winner_two.is_ok(),
        "fork generation 2 failed: {winner_two:?}"
    );
    assert!(matches!(
        losing.join().unwrap(),
        Err(StoreError::UnanchoredCommit {
            store_generation: 1,
            ..
        })
    ));
    assert!(matches!(
        original.identity(),
        Err(StoreError::RollbackDetected {
            database_generation: 1,
            authority_generation: 2
        })
    ));
    assert_eq!(fork.identity().unwrap().store_generation, 2);
    assert_eq!(inner.floor().unwrap().store_generation, 2);
}
