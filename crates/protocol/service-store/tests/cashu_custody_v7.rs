use pir_service_store::{
    CashuCustodyExportArtifactV1, CashuCustodyExportStateV1, CashuCustodyExposureLimitsV1,
    CashuCustodyLotStateV1, CashuCustodyRetirementNoteCheckV1, CashuCustodyRetirementNoteStateV1,
    CashuCustodyRetirementSnapshotRequestV1, CashuCustodyRetirementSnapshotV1,
    CashuCustodySealedBlobV1, CashuCustodySpentConfirmationRequestV1, CashuSwapSealedRecoveryV1,
    NewCashuCustodyExportV1, NewCashuCustodyLotV1, NewCashuSwapIntentV1, ProviderStore,
    RollbackFloorAuthorityErrorV1, RollbackFloorAuthorityV1, RollbackFloorV1, StoreError,
    StoreOptions, MAX_CASHU_CUSTODY_EXPORT_ARTIFACT_BYTES_V1,
    MAX_CASHU_CUSTODY_EXPORT_KEYSET_GROUPS_V1, MAX_CASHU_CUSTODY_EXPORT_NOTES_V1,
    MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1,
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use tempfile::{Builder, TempDir};

const PROVIDER: [u8; 32] = [0xd1; 32];
const STORE_INSTANCE: [u8; 16] = [0xd2; 16];

#[derive(Debug, Default)]
struct MemoryRollbackAuthority {
    floor: Mutex<Option<RollbackFloorV1>>,
    lose_response_at_generation: AtomicU64,
}

impl MemoryRollbackAuthority {
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
        if self
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
}

impl TestPath {
    fn new() -> Self {
        let directory = Builder::new()
            .prefix("bitcoinpir-cashu-custody-v7-test-")
            .tempdir()
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("restrict Cashu custody test directory permissions");
        }
        Self {
            database: directory.path().join("provider.sqlite3"),
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

fn limits(value: u64, notes: u64) -> CashuCustodyExposureLimitsV1 {
    CashuCustodyExposureLimitsV1 {
        max_unsettled_value: value,
        max_unsettled_notes: notes,
    }
}

fn intent(seed: u8) -> NewCashuSwapIntentV1 {
    NewCashuSwapIntentV1 {
        intent_id: [seed; 16],
        mint_id: [0xe1; 32],
        manifest_digest: [0xe2; 32],
        unit: "sat".to_owned(),
        input_set_digest: [seed.wrapping_add(1); 32],
        request_digest: [seed.wrapping_add(2); 32],
        output_set_digest: [seed.wrapping_add(3); 32],
        offer_binding_digest: [seed.wrapping_add(4); 32],
        settlement_value: 7,
        expected_output_count: 2,
        sealed_recovery: CashuSwapSealedRecoveryV1 {
            key_epoch: 1,
            nonce: vec![seed.wrapping_add(5); 24],
            ciphertext: vec![seed.wrapping_add(6); 96],
        },
        created_bucket: 500,
    }
}

fn y(prefix: u8, fill: u8) -> [u8; 33] {
    let mut value = [fill; 33];
    value[0] = prefix;
    value
}

fn lot(seed: u8, first_y: u8, second_y: u8) -> NewCashuCustodyLotV1 {
    NewCashuCustodyLotV1 {
        lot_id: [seed; 16],
        manifest_digest: [0xe2; 32],
        active_keyset_digest: [seed.wrapping_add(3); 32],
        note_set_digest: [seed.wrapping_add(4); 32],
        note_ys: vec![y(0x02, first_y), y(0x03, second_y)],
        sealed_notes: CashuCustodySealedBlobV1 {
            key_epoch: 2,
            nonce: vec![seed.wrapping_add(1); 24],
            ciphertext: vec![seed.wrapping_add(2); 128],
        },
    }
}

fn intent_with_count(seed: u8, expected_output_count: u32) -> NewCashuSwapIntentV1 {
    let mut proposed = intent(seed);
    proposed.expected_output_count = expected_output_count;
    proposed
}

fn indexed_y(index: u32) -> [u8; 33] {
    let mut value = [0_u8; 33];
    value[0] = if index % 2 == 0 { 0x02 } else { 0x03 };
    value[29..].copy_from_slice(&index.to_be_bytes());
    value
}

fn lot_with_count(
    seed: u8,
    active_keyset_digest: [u8; 32],
    first_y_index: u32,
    note_count: usize,
) -> NewCashuCustodyLotV1 {
    NewCashuCustodyLotV1 {
        lot_id: [seed; 16],
        manifest_digest: [0xe2; 32],
        active_keyset_digest,
        note_set_digest: [seed.wrapping_add(4); 32],
        note_ys: (0..note_count)
            .map(|offset| indexed_y(first_y_index + u32::try_from(offset).unwrap()))
            .collect(),
        sealed_notes: CashuCustodySealedBlobV1 {
            key_epoch: 2,
            nonce: vec![seed.wrapping_add(1); 24],
            ciphertext: vec![seed.wrapping_add(2); 128],
        },
    }
}

fn advance_to_wallet(store: &ProviderStore, proposed: &NewCashuSwapIntentV1) {
    store
        .begin_cashu_swap_submission_v1(&proposed.intent_id, 501)
        .unwrap();
    store
        .commit_cashu_swap_wallet_v1(
            &proposed.intent_id,
            &CashuSwapSealedRecoveryV1 {
                key_epoch: 2,
                nonce: vec![0xf1; 24],
                ciphertext: vec![0xf2; 160],
            },
            502,
        )
        .unwrap();
}

fn insert_and_grant(
    store: &ProviderStore,
    proposed: &NewCashuSwapIntentV1,
    custody_lot: &NewCashuCustodyLotV1,
) {
    store
        .insert_cashu_swap_intent_v1(proposed, limits(1_000, 100))
        .unwrap();
    advance_to_wallet(store, proposed);
    assert!(
        store
            .claim_cashu_swap_grant_once_v1(&proposed.intent_id, custody_lot, 503)
            .unwrap()
            .issued
    );
}

fn insert_and_grant_with_limits(
    store: &ProviderStore,
    proposed: &NewCashuSwapIntentV1,
    custody_lot: &NewCashuCustodyLotV1,
) {
    store
        .insert_cashu_swap_intent_v1(proposed, limits(1_000_000, 10_000))
        .unwrap();
    advance_to_wallet(store, proposed);
    assert!(
        store
            .claim_cashu_swap_grant_once_v1(&proposed.intent_id, custody_lot, 503)
            .unwrap()
            .issued
    );
}

fn spent_confirmation(
    store: &ProviderStore,
    export_id: [u8; 16],
    artifact_digest: [u8; 32],
    member_lot_ids: Vec<[u8; 16]>,
    ys: Vec<[u8; 33]>,
) -> CashuCustodySpentConfirmationRequestV1 {
    let identity = store.identity().unwrap();
    CashuCustodySpentConfirmationRequestV1 {
        provider_id: identity.provider_id,
        store_instance_id: identity.store_instance_id,
        precondition_store_generation: identity.store_generation,
        precondition_spend_commit_seq: identity.spend_commit_seq,
        precondition_rollback_commitment: identity.rollback_commitment,
        export_id,
        artifact_digest,
        member_lot_ids,
        note_checks: ys
            .into_iter()
            .map(|y| CashuCustodyRetirementNoteCheckV1 {
                y,
                state: CashuCustodyRetirementNoteStateV1::Spent,
            })
            .collect(),
        nut07_response_digest: [0xa7; 32],
    }
}

fn retirement_snapshot_request(
    store: &ProviderStore,
    export_id: [u8; 16],
) -> CashuCustodyRetirementSnapshotRequestV1 {
    let identity = store.identity().unwrap();
    CashuCustodyRetirementSnapshotRequestV1 {
        provider_id: identity.provider_id,
        store_instance_id: identity.store_instance_id,
        export_id,
    }
}

fn deliver_single_export(
    store: &ProviderStore,
    seed: u8,
    custody_lot: &NewCashuCustodyLotV1,
) -> (NewCashuCustodyExportV1, [u8; 32]) {
    let proposed_intent = intent(seed);
    insert_and_grant(store, &proposed_intent, custody_lot);
    let export = NewCashuCustodyExportV1 {
        export_id: [seed.wrapping_add(0x40); 16],
        mint_id: proposed_intent.mint_id,
        unit: proposed_intent.unit,
        recipient_key_id: [seed.wrapping_add(0x41); 32],
        max_lots: 1,
    };
    store.reserve_cashu_custody_export_v1(&export).unwrap();
    let artifact = [seed.wrapping_add(0x42); 64];
    let persisted = store
        .persist_cashu_custody_export_artifact_v1(&export.export_id, &artifact)
        .unwrap();
    let artifact_digest = persisted.batch.artifact.unwrap().digest;
    assert!(store
        .acknowledge_cashu_custody_export_v1(&export.export_id, &artifact_digest)
        .unwrap());
    (export, artifact_digest)
}

#[test]
fn exposure_moves_from_intent_to_lot_and_only_spent_confirmation_releases_it() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    let first = intent(0x11);
    let second = intent(0x21);
    store
        .insert_cashu_swap_intent_v1(&first, limits(7, 2))
        .unwrap();
    assert!(matches!(
        store.insert_cashu_swap_intent_v1(&second, limits(7, 2)),
        Err(StoreError::CashuCustodyExposureExceeded)
    ));

    advance_to_wallet(&store, &first);
    let first_lot = lot(0x31, 0x41, 0x42);
    store
        .claim_cashu_swap_grant_once_v1(&first.intent_id, &first_lot, 503)
        .unwrap();
    let after_grant = store
        .cashu_custody_inventory_v1(&first.mint_id, "sat")
        .unwrap();
    assert_eq!(after_grant.pending_intent_value, 0);
    assert_eq!(after_grant.available_value, 7);
    assert_eq!(after_grant.available_notes, 2);
    assert!(matches!(
        store.insert_cashu_swap_intent_v1(&second, limits(7, 2)),
        Err(StoreError::CashuCustodyExposureExceeded)
    ));

    let export = NewCashuCustodyExportV1 {
        export_id: [0x51; 16],
        mint_id: first.mint_id,
        unit: "sat".to_owned(),
        recipient_key_id: [0x52; 32],
        max_lots: 1,
    };
    store.reserve_cashu_custody_export_v1(&export).unwrap();
    let after_reserve = store
        .cashu_custody_inventory_v1(&first.mint_id, "sat")
        .unwrap();
    assert_eq!(after_reserve.available_value, 0);
    assert_eq!(after_reserve.reserved_value, 7);
    assert!(matches!(
        store.insert_cashu_swap_intent_v1(&second, limits(7, 2)),
        Err(StoreError::CashuCustodyExposureExceeded)
    ));

    let artifact = b"recipient-sealed-canonical-cashu-export-v1";
    let persisted = store
        .persist_cashu_custody_export_artifact_v1(&export.export_id, artifact)
        .unwrap();
    let artifact_digest = persisted.batch.artifact.as_ref().unwrap().digest;
    assert!(store
        .acknowledge_cashu_custody_export_v1(&export.export_id, &artifact_digest)
        .unwrap());
    let after_ack = store
        .cashu_custody_inventory_v1(&first.mint_id, "sat")
        .unwrap();
    assert_eq!(after_ack.reserved_value, 0);
    assert_eq!(after_ack.reserved_notes, 0);
    assert_eq!(after_ack.acknowledged_lot_count, 1);
    assert_eq!(after_ack.acknowledged_value, 7);
    assert_eq!(after_ack.acknowledged_notes, 2);
    assert!(matches!(
        store.insert_cashu_swap_intent_v1(&second, limits(7, 2)),
        Err(StoreError::CashuCustodyExposureExceeded)
    ));

    let confirmation = spent_confirmation(
        &store,
        export.export_id,
        artifact_digest,
        vec![first_lot.lot_id],
        first_lot.note_ys.clone(),
    );
    assert!(
        store
            .confirm_cashu_custody_export_spent_v1(&confirmation)
            .unwrap()
            .confirmed
    );
    let after_spent = store
        .cashu_custody_inventory_v1(&first.mint_id, "sat")
        .unwrap();
    assert_eq!(after_spent.acknowledged_value, 0);
    assert_eq!(after_spent.spent_confirmed_lot_count, 1);
    assert_eq!(after_spent.spent_confirmed_value, 7);
    assert_eq!(after_spent.spent_confirmed_notes, 2);
    assert_eq!(after_spent.spent_confirmed_export_count, 1);
    store
        .insert_cashu_swap_intent_v1(&second, limits(7, 2))
        .unwrap();
}

#[test]
fn concurrent_prepares_cannot_cross_the_exposure_limit() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = Arc::new(create_store(&path.database, authority));
    let barrier = Arc::new(Barrier::new(2));
    let workers = [intent(0x11), intent(0x21)]
        .into_iter()
        .map(|proposed| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.insert_cashu_swap_intent_v1(&proposed, limits(7, 2))
            })
        })
        .collect::<Vec<_>>();
    let mut inserted = 0;
    let mut limited = 0;
    for result in workers.into_iter().map(|worker| worker.join().unwrap()) {
        match result {
            Ok(result) if result.inserted => inserted += 1,
            Err(StoreError::CashuCustodyExposureExceeded) => limited += 1,
            _ => panic!("unexpected concurrent prepare result"),
        }
    }
    assert_eq!(inserted, 1);
    assert_eq!(limited, 1);
    assert_eq!(store.identity().unwrap().store_generation, 1);
}

#[test]
fn exposure_limits_reject_zero_and_non_sqlite_values_before_new_or_replay() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    let proposed = intent(0x11);
    let invalid_limits = [
        limits(0, 1),
        limits(1, 0),
        limits((i64::MAX as u64) + 1, 1),
        limits(1, (i64::MAX as u64) + 1),
        limits(u64::MAX - 1, 1),
        limits(1, u64::MAX - 1),
    ];

    for invalid in invalid_limits {
        assert!(matches!(
            store.insert_cashu_swap_intent_v1(&proposed, invalid),
            Err(StoreError::InvalidInput(_))
        ));
    }
    assert_eq!(store.identity().unwrap().store_generation, 0);

    store
        .insert_cashu_swap_intent_v1(&proposed, limits(i64::MAX as u64, i64::MAX as u64))
        .unwrap();
    for invalid in invalid_limits {
        assert!(matches!(
            store.insert_cashu_swap_intent_v1(&proposed, invalid),
            Err(StoreError::InvalidInput(_))
        ));
    }
    assert_eq!(store.identity().unwrap().store_generation, 1);
}

#[test]
fn grant_and_note_uniqueness_are_atomic_and_exact_replay_returns_first_lot() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    let first = intent(0x11);
    let first_lot = lot(0x31, 0x41, 0x42);
    insert_and_grant(&store, &first, &first_lot);

    let mut replay = lot(0x31, 0x41, 0x42);
    replay.note_ys.reverse();
    replay.sealed_notes = CashuCustodySealedBlobV1 {
        key_epoch: 9,
        nonce: vec![0xaa; 24],
        ciphertext: vec![0xbb; 64],
    };
    let replayed = store
        .claim_cashu_swap_grant_once_v1(&first.intent_id, &replay, 503)
        .unwrap();
    assert!(!replayed.issued);
    assert!(replayed.lot.sealed_notes == first_lot.sealed_notes);

    let second = intent(0x21);
    store
        .insert_cashu_swap_intent_v1(&second, limits(1_000, 100))
        .unwrap();
    advance_to_wallet(&store, &second);
    let overlapping = lot(0x32, 0x41, 0x52);
    let generation_before = store.identity().unwrap().store_generation;
    assert!(matches!(
        store.claim_cashu_swap_grant_once_v1(&second.intent_id, &overlapping, 503),
        Err(StoreError::CashuCustodyLotConflict)
    ));
    assert_eq!(
        store.identity().unwrap().store_generation,
        generation_before
    );
    let inventory = store
        .cashu_custody_inventory_v1(&second.mint_id, "sat")
        .unwrap();
    assert_eq!(inventory.pending_intent_value, 7);
    assert_eq!(inventory.available_lot_count, 1);

    let distinct = lot(0x32, 0x51, 0x52);
    assert!(
        store
            .claim_cashu_swap_grant_once_v1(&second.intent_id, &distinct, 503)
            .unwrap()
            .issued
    );
    assert_eq!(store.identity().unwrap().spend_commit_seq, 2);
}

#[test]
fn export_reservation_artifact_and_acknowledgement_are_exact_and_monotonic() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    insert_and_grant(&store, &intent(0x11), &lot(0x31, 0x41, 0x42));
    insert_and_grant(&store, &intent(0x21), &lot(0x32, 0x51, 0x52));

    let export = NewCashuCustodyExportV1 {
        export_id: [0x61; 16],
        mint_id: [0xe1; 32],
        unit: "sat".to_owned(),
        recipient_key_id: [0x63; 32],
        max_lots: 2,
    };
    let reserved = store.reserve_cashu_custody_export_v1(&export).unwrap();
    assert!(reserved.reserved);
    assert_eq!(reserved.batch.state, CashuCustodyExportStateV1::Reserved);
    assert_eq!(reserved.batch.lot_count, 2);
    assert_eq!(reserved.batch.keyset_group_count, 2);
    assert_eq!(reserved.batch.recipient_key_id, export.recipient_key_id);
    assert_eq!(reserved.batch.settlement_value, 14);
    assert_eq!(reserved.batch.note_count, 4);
    assert_eq!(reserved.sealed_lots.len(), 2);
    assert!(reserved
        .sealed_lots
        .iter()
        .all(|lot| lot.state == CashuCustodyLotStateV1::Reserved));

    let replay = store.reserve_cashu_custody_export_v1(&export).unwrap();
    assert!(!replay.reserved);
    assert!(replay.sealed_lots == reserved.sealed_lots);
    let mut changed_recipient = export.clone();
    changed_recipient.recipient_key_id[0] ^= 1;
    assert!(matches!(
        store.reserve_cashu_custody_export_v1(&changed_recipient),
        Err(StoreError::CashuCustodyExportConflict)
    ));
    let unavailable = NewCashuCustodyExportV1 {
        export_id: [0x62; 16],
        ..export.clone()
    };
    assert!(matches!(
        store.reserve_cashu_custody_export_v1(&unavailable),
        Err(StoreError::CashuCustodyUnavailable)
    ));

    let generation_before_oversized_artifact = store.identity().unwrap().store_generation;
    let oversized_artifact = vec![0x5a; MAX_CASHU_CUSTODY_EXPORT_ARTIFACT_BYTES_V1 + 1];
    assert!(matches!(
        store.persist_cashu_custody_export_artifact_v1(&export.export_id, &oversized_artifact),
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(
        store.identity().unwrap().store_generation,
        generation_before_oversized_artifact
    );
    assert_eq!(
        store
            .cashu_custody_export_v1(&export.export_id)
            .unwrap()
            .unwrap()
            .state,
        CashuCustodyExportStateV1::Reserved
    );

    let artifact = b"recipient-sealed-canonical-export-with-ephemeral-header";
    let persisted = store
        .persist_cashu_custody_export_artifact_v1(&export.export_id, artifact)
        .unwrap();
    assert!(persisted.persisted);
    assert_eq!(
        persisted.batch.state,
        CashuCustodyExportStateV1::ArtifactStored
    );
    let stored_artifact = persisted.batch.artifact.as_ref().unwrap();
    assert_eq!(stored_artifact.bytes, artifact);
    let expected_digest: [u8; 32] = Sha256::digest(artifact).into();
    assert_eq!(stored_artifact.digest, expected_digest);
    let exact = store
        .persist_cashu_custody_export_artifact_v1(&export.export_id, artifact)
        .unwrap();
    assert!(!exact.persisted);
    assert!(matches!(
        store.persist_cashu_custody_export_artifact_v1(&export.export_id, b"different"),
        Err(StoreError::CashuCustodyExportConflict)
    ));
    let after_materialization = store.reserve_cashu_custody_export_v1(&export).unwrap();
    assert!(after_materialization.sealed_lots.is_empty());
    assert_eq!(
        after_materialization.batch.artifact.as_ref().unwrap().bytes,
        artifact
    );

    assert!(matches!(
        store.acknowledge_cashu_custody_export_v1(&export.export_id, &[0x99; 32]),
        Err(StoreError::CashuCustodyExportConflict)
    ));
    assert!(store
        .acknowledge_cashu_custody_export_v1(&export.export_id, &expected_digest)
        .unwrap());
    assert!(!store
        .acknowledge_cashu_custody_export_v1(&export.export_id, &expected_digest)
        .unwrap());
    let loaded = store
        .cashu_custody_export_v1(&export.export_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.state,
        CashuCustodyExportStateV1::DeliveryAcknowledged
    );
    assert_eq!(loaded.artifact.unwrap().bytes, artifact);
    let identity = store.identity().unwrap();
    assert_eq!(identity.store_generation, 11);
    assert_eq!(identity.spend_commit_seq, 2);

    let operational = store.operational_inventory().unwrap();
    assert_eq!(operational.cashu_custody_lot_rows, 2);
    assert_eq!(operational.cashu_custody_note_rows, 4);
    assert_eq!(operational.cashu_custody_export_batch_rows, 1);
    assert_eq!(operational.cashu_custody_retirement_evidence_rows, 0);
}

#[test]
fn spent_confirmation_is_atomic_exact_idempotent_and_survives_restart() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    let custody_lot = lot(0x31, 0x41, 0x42);
    let (export, artifact_digest) = deliver_single_export(&store, 0x11, &custody_lot);
    let request = spent_confirmation(
        &store,
        export.export_id,
        artifact_digest,
        vec![custody_lot.lot_id],
        custody_lot.note_ys.clone(),
    );
    let generation_before = store.identity().unwrap().store_generation;

    let confirmed = store
        .confirm_cashu_custody_export_spent_v1(&request)
        .unwrap();
    assert!(confirmed.confirmed);
    assert_eq!(
        confirmed.evidence.precondition_store_generation,
        generation_before
    );
    assert_eq!(
        confirmed.evidence.confirmed_store_generation,
        generation_before + 1
    );
    assert_eq!(confirmed.evidence.note_count, 2);
    assert!(!confirmed
        .evidence
        .member_set_digest
        .iter()
        .all(|byte| *byte == 0));
    assert!(!confirmed
        .evidence
        .y_set_digest
        .iter()
        .all(|byte| *byte == 0));
    let evidence_debug = format!("{:?}", confirmed.evidence);
    assert!(!evidence_debug.contains("209"));
    assert!(!evidence_debug.contains("210"));
    assert!(!evidence_debug.contains("167"));
    assert_eq!(
        store.identity().unwrap().store_generation,
        generation_before + 1
    );
    assert_eq!(
        store
            .cashu_custody_export_v1(&export.export_id)
            .unwrap()
            .unwrap()
            .state,
        CashuCustodyExportStateV1::SpentConfirmed
    );

    let replay = store
        .confirm_cashu_custody_export_spent_v1(&request)
        .unwrap();
    assert!(!replay.confirmed);
    assert_eq!(replay.evidence, confirmed.evidence);
    assert_eq!(
        store.identity().unwrap().store_generation,
        generation_before + 1
    );
    drop(store);

    let reopened =
        ProviderStore::open_existing(&path.database, PROVIDER, StoreOptions::default(), authority)
            .unwrap();
    let replay_after_restart = reopened
        .confirm_cashu_custody_export_spent_v1(&request)
        .unwrap();
    assert!(!replay_after_restart.confirmed);
    assert_eq!(replay_after_restart.evidence, confirmed.evidence);
    assert_eq!(
        reopened
            .cashu_custody_retirement_evidence_v1(&export.export_id)
            .unwrap(),
        Some(confirmed.evidence)
    );
}

#[test]
fn owner_retirement_snapshot_is_exact_and_terminal_state_never_releases_secrets() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    let proposed_intent = intent(0x11);
    let mut custody_lot = lot(0x31, 0x41, 0x42);
    insert_and_grant(&store, &proposed_intent, &custody_lot);
    let export = NewCashuCustodyExportV1 {
        export_id: [0x61; 16],
        mint_id: proposed_intent.mint_id,
        unit: proposed_intent.unit.clone(),
        recipient_key_id: [0x62; 32],
        max_lots: 1,
    };
    store.reserve_cashu_custody_export_v1(&export).unwrap();
    let snapshot_request = retirement_snapshot_request(&store, export.export_id);
    assert!(matches!(
        store.cashu_custody_retirement_snapshot_owner_v1(&snapshot_request),
        Err(StoreError::CashuCustodyStateConflict)
    ));

    let artifact = b"owner-only-sensitive-recipient-artifact";
    let persisted = store
        .persist_cashu_custody_export_artifact_v1(&export.export_id, artifact)
        .unwrap();
    let artifact_digest = persisted.batch.artifact.unwrap().digest;
    let artifact_snapshot = store
        .cashu_custody_retirement_snapshot_owner_v1(&snapshot_request)
        .unwrap();
    let CashuCustodyRetirementSnapshotV1::Checkable(artifact_snapshot) = artifact_snapshot else {
        panic!("artifact-stored export did not return a checkable snapshot");
    };
    assert_eq!(
        artifact_snapshot.batch.state,
        CashuCustodyExportStateV1::ArtifactStored
    );
    assert_eq!(artifact_snapshot.member_lot_ids, [custody_lot.lot_id]);
    assert_eq!(artifact_snapshot.sealed_lots.len(), 1);
    assert_eq!(artifact_snapshot.sealed_lots[0].lot_id, custody_lot.lot_id);
    assert_eq!(
        artifact_snapshot.batch.artifact.as_ref().unwrap().bytes,
        artifact
    );
    let snapshot_debug = format!("{artifact_snapshot:?}");
    assert!(!snapshot_debug.contains("owner-only-sensitive-recipient-artifact"));
    assert!(!snapshot_debug.contains("209"), "provider identity leaked");
    assert!(!snapshot_debug.contains("210"), "store identity leaked");
    drop(artifact_snapshot);

    assert!(store
        .acknowledge_cashu_custody_export_v1(&export.export_id, &artifact_digest)
        .unwrap());
    let delivery_snapshot = store
        .cashu_custody_retirement_snapshot_owner_v1(&snapshot_request)
        .unwrap();
    let CashuCustodyRetirementSnapshotV1::Checkable(delivery_snapshot) = delivery_snapshot else {
        panic!("delivery-acknowledged export did not return a checkable snapshot");
    };
    assert_eq!(
        delivery_snapshot.batch.state,
        CashuCustodyExportStateV1::DeliveryAcknowledged
    );
    assert_eq!(
        delivery_snapshot.checked_identity,
        store.identity().unwrap(),
        "snapshot identity is the exact confirmation precondition"
    );
    drop(delivery_snapshot);

    let confirmation = spent_confirmation(
        &store,
        export.export_id,
        artifact_digest,
        vec![custody_lot.lot_id],
        std::mem::take(&mut custody_lot.note_ys),
    );
    let confirmed = store
        .confirm_cashu_custody_export_spent_v1(&confirmation)
        .unwrap();
    let terminal = store
        .cashu_custody_retirement_snapshot_owner_v1(&snapshot_request)
        .unwrap();
    let CashuCustodyRetirementSnapshotV1::SpentConfirmed(terminal) = terminal else {
        panic!("spent-confirmed export exposed a checkable secret snapshot");
    };
    assert_eq!(terminal.export_id, export.export_id);
    assert_eq!(terminal.mint_id, export.mint_id);
    assert_eq!(terminal.unit, export.unit);
    assert_eq!(terminal.settlement_value, 7);
    assert_eq!(terminal.note_count, 2);
    assert_eq!(terminal.artifact_digest, artifact_digest);
    assert_eq!(terminal.evidence, confirmed.evidence);
    assert!(!format!("{terminal:?}").contains("97"));
}

#[test]
fn owner_retirement_snapshot_rejects_wrong_store_and_noncanonical_member_order() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    let custody_lot = lot(0x31, 0x41, 0x42);
    let (export, _) = deliver_single_export(&store, 0x11, &custody_lot);

    let mut wrong_provider = retirement_snapshot_request(&store, export.export_id);
    wrong_provider.provider_id[0] ^= 1;
    assert!(matches!(
        store.cashu_custody_retirement_snapshot_owner_v1(&wrong_provider),
        Err(StoreError::ProviderMismatch)
    ));
    let mut wrong_store = retirement_snapshot_request(&store, export.export_id);
    wrong_store.store_instance_id[0] ^= 1;
    assert!(matches!(
        store.cashu_custody_retirement_snapshot_owner_v1(&wrong_store),
        Err(StoreError::CashuCustodyRetirementFloorMismatch)
    ));

    let connection = Connection::open(&path.database).unwrap();
    connection
        .execute(
            "UPDATE cashu_custody_export_members SET member_index = 1
             WHERE export_id = ?1 AND member_index = 0",
            [export.export_id.as_slice()],
        )
        .unwrap();
    drop(connection);
    let exact = retirement_snapshot_request(&store, export.export_id);
    assert!(matches!(
        store.cashu_custody_retirement_snapshot_owner_v1(&exact),
        Err(StoreError::SchemaMismatch(_))
    ));
}

#[test]
fn artifact_stored_snapshot_rejects_cross_table_tamper() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    let proposed_intent = intent(0x11);
    let custody_lot = lot(0x31, 0x41, 0x42);
    insert_and_grant(&store, &proposed_intent, &custody_lot);
    let export = NewCashuCustodyExportV1 {
        export_id: [0x61; 16],
        mint_id: proposed_intent.mint_id,
        unit: proposed_intent.unit,
        recipient_key_id: [0x62; 32],
        max_lots: 1,
    };
    store.reserve_cashu_custody_export_v1(&export).unwrap();
    store
        .persist_cashu_custody_export_artifact_v1(
            &export.export_id,
            b"artifact-stored-before-cross-table-tamper",
        )
        .unwrap();
    let connection = Connection::open(&path.database).unwrap();
    connection
        .execute(
            "UPDATE cashu_custody_lots SET note_count = 3 WHERE lot_id = ?1",
            [custody_lot.lot_id.as_slice()],
        )
        .unwrap();
    drop(connection);
    let request = retirement_snapshot_request(&store, export.export_id);
    assert!(matches!(
        store.cashu_custody_retirement_snapshot_owner_v1(&request),
        Err(StoreError::SchemaMismatch(_))
    ));
}

#[test]
fn old_snapshot_floor_is_stale_after_intervening_mutation_and_fresh_rebind_succeeds() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    let custody_lot = lot(0x31, 0x41, 0x42);
    let (export, artifact_digest) = deliver_single_export(&store, 0x11, &custody_lot);
    let snapshot_request = retirement_snapshot_request(&store, export.export_id);
    let snapshot = store
        .cashu_custody_retirement_snapshot_owner_v1(&snapshot_request)
        .unwrap();
    let CashuCustodyRetirementSnapshotV1::Checkable(snapshot) = snapshot else {
        panic!("delivery-acknowledged export did not return a checkable snapshot");
    };
    let old_identity = snapshot.checked_identity;
    drop(snapshot);

    let intervening = intent(0x21);
    store
        .insert_cashu_swap_intent_v1(&intervening, limits(1_000, 100))
        .unwrap();
    let stale = CashuCustodySpentConfirmationRequestV1 {
        provider_id: old_identity.provider_id,
        store_instance_id: old_identity.store_instance_id,
        precondition_store_generation: old_identity.store_generation,
        precondition_spend_commit_seq: old_identity.spend_commit_seq,
        precondition_rollback_commitment: old_identity.rollback_commitment,
        export_id: export.export_id,
        artifact_digest,
        member_lot_ids: vec![custody_lot.lot_id],
        note_checks: custody_lot
            .note_ys
            .iter()
            .map(|y| CashuCustodyRetirementNoteCheckV1 {
                y: *y,
                state: CashuCustodyRetirementNoteStateV1::Spent,
            })
            .collect(),
        nut07_response_digest: [0xa7; 32],
    };
    assert!(matches!(
        store.confirm_cashu_custody_export_spent_v1(&stale),
        Err(StoreError::CashuCustodyRetirementFloorMismatch)
    ));

    let fresh_snapshot = store
        .cashu_custody_retirement_snapshot_owner_v1(&snapshot_request)
        .unwrap();
    let CashuCustodyRetirementSnapshotV1::Checkable(fresh_snapshot) = fresh_snapshot else {
        panic!("unretired export did not return a fresh checkable snapshot");
    };
    assert!(fresh_snapshot.checked_identity.store_generation > old_identity.store_generation);
    let fresh_identity = fresh_snapshot.checked_identity;
    drop(fresh_snapshot);
    let rebound = CashuCustodySpentConfirmationRequestV1 {
        provider_id: fresh_identity.provider_id,
        store_instance_id: fresh_identity.store_instance_id,
        precondition_store_generation: fresh_identity.store_generation,
        precondition_spend_commit_seq: fresh_identity.spend_commit_seq,
        precondition_rollback_commitment: fresh_identity.rollback_commitment,
        export_id: export.export_id,
        artifact_digest,
        member_lot_ids: vec![custody_lot.lot_id],
        note_checks: custody_lot
            .note_ys
            .iter()
            .map(|y| CashuCustodyRetirementNoteCheckV1 {
                y: *y,
                state: CashuCustodyRetirementNoteStateV1::Spent,
            })
            .collect(),
        nut07_response_digest: [0xa7; 32],
    };
    assert!(
        store
            .confirm_cashu_custody_export_spent_v1(&rebound)
            .unwrap()
            .confirmed
    );
}

#[test]
fn nonspent_missing_malformed_and_stale_checks_never_retire_custody() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    let custody_lot = lot(0x31, 0x41, 0x42);
    let (export, artifact_digest) = deliver_single_export(&store, 0x11, &custody_lot);
    let generation_before = store.identity().unwrap().store_generation;

    for state in [
        CashuCustodyRetirementNoteStateV1::Unspent,
        CashuCustodyRetirementNoteStateV1::Pending,
        CashuCustodyRetirementNoteStateV1::Unknown,
    ] {
        let mut request = spent_confirmation(
            &store,
            export.export_id,
            artifact_digest,
            vec![custody_lot.lot_id],
            custody_lot.note_ys.clone(),
        );
        request.note_checks[0].state = state;
        assert!(matches!(
            store.confirm_cashu_custody_export_spent_v1(&request),
            Err(StoreError::CashuCustodyNotesNotFullySpent)
        ));
    }

    let mut missing = spent_confirmation(
        &store,
        export.export_id,
        artifact_digest,
        vec![custody_lot.lot_id],
        custody_lot.note_ys.clone(),
    );
    missing.note_checks.pop();
    assert!(matches!(
        store.confirm_cashu_custody_export_spent_v1(&missing),
        Err(StoreError::CashuCustodyRetirementEvidenceConflict)
    ));
    let mut unknown_y = spent_confirmation(
        &store,
        export.export_id,
        artifact_digest,
        vec![custody_lot.lot_id],
        custody_lot.note_ys.clone(),
    );
    unknown_y.note_checks[0].y[1] ^= 1;
    assert!(matches!(
        store.confirm_cashu_custody_export_spent_v1(&unknown_y),
        Err(StoreError::CashuCustodyRetirementEvidenceConflict)
    ));
    let mut malformed_y = spent_confirmation(
        &store,
        export.export_id,
        artifact_digest,
        vec![custody_lot.lot_id],
        custody_lot.note_ys.clone(),
    );
    malformed_y.note_checks[0].y[0] = 0x04;
    assert!(matches!(
        store.confirm_cashu_custody_export_spent_v1(&malformed_y),
        Err(StoreError::InvalidInput(_))
    ));
    let mut wrong_members = spent_confirmation(
        &store,
        export.export_id,
        artifact_digest,
        vec![custody_lot.lot_id],
        custody_lot.note_ys.clone(),
    );
    wrong_members.member_lot_ids[0][0] ^= 1;
    assert!(matches!(
        store.confirm_cashu_custody_export_spent_v1(&wrong_members),
        Err(StoreError::CashuCustodyRetirementEvidenceConflict)
    ));
    let mut stale = spent_confirmation(
        &store,
        export.export_id,
        artifact_digest,
        vec![custody_lot.lot_id],
        custody_lot.note_ys.clone(),
    );
    stale.precondition_store_generation -= 1;
    assert!(matches!(
        store.confirm_cashu_custody_export_spent_v1(&stale),
        Err(StoreError::CashuCustodyRetirementFloorMismatch)
    ));

    assert_eq!(
        store.identity().unwrap().store_generation,
        generation_before
    );
    assert!(store
        .cashu_custody_retirement_evidence_v1(&export.export_id)
        .unwrap()
        .is_none());
    let inventory = store
        .cashu_custody_inventory_v1(&export.mint_id, "sat")
        .unwrap();
    assert_eq!(inventory.acknowledged_value, 7);
    assert_eq!(inventory.spent_confirmed_value, 0);
}

#[test]
fn concurrent_spent_confirmation_has_one_commit_and_one_exact_replay() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = Arc::new(create_store(&path.database, authority));
    let custody_lot = lot(0x31, 0x41, 0x42);
    let (export, artifact_digest) = deliver_single_export(&store, 0x11, &custody_lot);
    let requests = (0..2)
        .map(|_| {
            spent_confirmation(
                &store,
                export.export_id,
                artifact_digest,
                vec![custody_lot.lot_id],
                custody_lot.note_ys.clone(),
            )
        })
        .collect::<Vec<_>>();
    let generation_before = store.identity().unwrap().store_generation;
    let barrier = Arc::new(Barrier::new(2));
    let workers = requests
        .into_iter()
        .map(|request| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.confirm_cashu_custody_export_spent_v1(&request)
            })
        })
        .collect::<Vec<_>>();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.confirmed).count(),
        1
    );
    assert_eq!(
        outcomes.iter().filter(|outcome| !outcome.confirmed).count(),
        1
    );
    assert_eq!(outcomes[0].evidence, outcomes[1].evidence);
    assert_eq!(
        store.identity().unwrap().store_generation,
        generation_before + 1
    );
}

#[test]
fn lost_retirement_anchor_response_recovers_as_exact_idempotent_replay() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    let mut custody_lot = lot(0x31, 0x41, 0x42);
    let (export, artifact_digest) = deliver_single_export(&store, 0x11, &custody_lot);
    let request = spent_confirmation(
        &store,
        export.export_id,
        artifact_digest,
        vec![custody_lot.lot_id],
        std::mem::take(&mut custody_lot.note_ys),
    );
    let next_generation = store.identity().unwrap().store_generation + 1;
    authority.lose_response_at(next_generation);
    assert!(matches!(
        store.confirm_cashu_custody_export_spent_v1(&request),
        Err(StoreError::UnanchoredCommit {
            store_generation,
            ..
        }) if store_generation == next_generation
    ));
    drop(store);

    let reopened =
        ProviderStore::open_existing(&path.database, PROVIDER, StoreOptions::default(), authority)
            .unwrap();
    let recovered = reopened
        .confirm_cashu_custody_export_spent_v1(&request)
        .unwrap();
    assert!(!recovered.confirmed);
    assert_eq!(
        recovered.evidence.confirmed_store_generation,
        next_generation
    );
}

#[test]
fn export_reservation_caps_notes_and_leaves_overflow_lots_available() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    let lots_at_note_cap = MAX_CASHU_CUSTODY_EXPORT_NOTES_V1 / MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1;
    assert_eq!(lots_at_note_cap * MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1, 512);

    for index in 0..lots_at_note_cap {
        let proposed = intent_with_count(
            0x10_u8.wrapping_add(u8::try_from(index).unwrap()),
            u32::try_from(MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1).unwrap(),
        );
        let custody_lot = lot_with_count(
            0x40_u8.wrapping_add(u8::try_from(index).unwrap()),
            [0xa1; 32],
            u32::try_from(index * MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1).unwrap() + 1,
            MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1,
        );
        insert_and_grant_with_limits(&store, &proposed, &custody_lot);
    }
    let overflow_intent = intent_with_count(0x30, 1);
    let overflow_lot = lot_with_count(0x70, [0xa1; 32], 10_000, 1);
    insert_and_grant_with_limits(&store, &overflow_intent, &overflow_lot);

    let export = NewCashuCustodyExportV1 {
        export_id: [0xb1; 16],
        mint_id: [0xe1; 32],
        unit: "sat".to_owned(),
        recipient_key_id: [0xb2; 32],
        max_lots: u32::try_from(lots_at_note_cap + 1).unwrap(),
    };
    let reserved = store.reserve_cashu_custody_export_v1(&export).unwrap();
    assert_eq!(
        reserved.batch.note_count,
        u64::try_from(MAX_CASHU_CUSTODY_EXPORT_NOTES_V1).unwrap()
    );
    assert_eq!(
        reserved.batch.lot_count,
        u32::try_from(lots_at_note_cap).unwrap()
    );
    assert_eq!(reserved.batch.keyset_group_count, 1);

    let inventory = store
        .cashu_custody_inventory_v1(&export.mint_id, "sat")
        .unwrap();
    assert_eq!(
        inventory.reserved_lot_count,
        u64::try_from(lots_at_note_cap).unwrap()
    );
    assert_eq!(inventory.reserved_notes, 512);
    assert_eq!(inventory.available_lot_count, 1);
    assert_eq!(inventory.available_notes, 1);
}

#[test]
fn export_reservation_caps_distinct_keysets_and_leaves_the_seventeenth_available() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    let lot_count = MAX_CASHU_CUSTODY_EXPORT_KEYSET_GROUPS_V1 + 1;

    for index in 0..lot_count {
        let proposed = intent_with_count(0x10_u8.wrapping_add(u8::try_from(index).unwrap()), 1);
        let custody_lot = lot_with_count(
            0x40_u8.wrapping_add(u8::try_from(index).unwrap()),
            [0x80_u8.wrapping_add(u8::try_from(index).unwrap()); 32],
            20_000 + u32::try_from(index).unwrap(),
            1,
        );
        insert_and_grant_with_limits(&store, &proposed, &custody_lot);
    }

    let export = NewCashuCustodyExportV1 {
        export_id: [0xc1; 16],
        mint_id: [0xe1; 32],
        unit: "sat".to_owned(),
        recipient_key_id: [0xc2; 32],
        max_lots: u32::try_from(lot_count).unwrap(),
    };
    let reserved = store.reserve_cashu_custody_export_v1(&export).unwrap();
    assert_eq!(
        reserved.batch.keyset_group_count,
        u32::try_from(MAX_CASHU_CUSTODY_EXPORT_KEYSET_GROUPS_V1).unwrap()
    );
    assert_eq!(
        reserved.batch.lot_count,
        u32::try_from(MAX_CASHU_CUSTODY_EXPORT_KEYSET_GROUPS_V1).unwrap()
    );
    assert_eq!(reserved.batch.note_count, 16);

    let inventory = store
        .cashu_custody_inventory_v1(&export.mint_id, "sat")
        .unwrap();
    assert_eq!(inventory.reserved_lot_count, 16);
    assert_eq!(inventory.reserved_notes, 16);
    assert_eq!(inventory.available_lot_count, 1);
    assert_eq!(inventory.available_notes, 1);
}

#[test]
fn lost_grant_anchor_response_recovers_grant_and_lot_as_one_generation() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    let proposed = intent(0x11);
    store
        .insert_cashu_swap_intent_v1(&proposed, limits(100, 10))
        .unwrap();
    advance_to_wallet(&store, &proposed);
    let proposed_lot = lot(0x31, 0x41, 0x42);
    authority.lose_response_at(4);
    assert!(matches!(
        store.claim_cashu_swap_grant_once_v1(&proposed.intent_id, &proposed_lot, 503),
        Err(StoreError::UnanchoredCommit {
            store_generation: 4,
            ..
        })
    ));
    drop(store);

    let reopened =
        ProviderStore::open_existing(&path.database, PROVIDER, StoreOptions::default(), authority)
            .unwrap();
    let recovered = reopened
        .claim_cashu_swap_grant_once_v1(&proposed.intent_id, &proposed_lot, 503)
        .unwrap();
    assert!(!recovered.issued);
    assert_eq!(recovered.lot.state, CashuCustodyLotStateV1::Available);
    assert_eq!(reopened.identity().unwrap().store_generation, 4);
    assert_eq!(reopened.identity().unwrap().spend_commit_seq, 1);
}

#[test]
fn lost_export_anchor_responses_recover_each_exact_transition() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, Arc::clone(&authority));
    insert_and_grant(&store, &intent(0x11), &lot(0x31, 0x41, 0x42));
    let export = NewCashuCustodyExportV1 {
        export_id: [0x71; 16],
        mint_id: [0xe1; 32],
        unit: "sat".to_owned(),
        recipient_key_id: [0x73; 32],
        max_lots: 1,
    };

    authority.lose_response_at(5);
    assert!(matches!(
        store.reserve_cashu_custody_export_v1(&export),
        Err(StoreError::UnanchoredCommit {
            store_generation: 5,
            ..
        })
    ));
    let mut wrong_recipient_after_lost_response = export.clone();
    wrong_recipient_after_lost_response.recipient_key_id[0] ^= 1;
    assert!(matches!(
        store.reserve_cashu_custody_export_v1(&wrong_recipient_after_lost_response),
        Err(StoreError::CashuCustodyExportConflict)
    ));
    let recovered_reservation = store.reserve_cashu_custody_export_v1(&export).unwrap();
    assert!(!recovered_reservation.reserved);
    assert_eq!(recovered_reservation.sealed_lots.len(), 1);

    let artifact = b"recipient-sealed-export-after-lost-response";
    authority.lose_response_at(6);
    assert!(matches!(
        store.persist_cashu_custody_export_artifact_v1(&export.export_id, artifact),
        Err(StoreError::UnanchoredCommit {
            store_generation: 6,
            ..
        })
    ));
    let recovered_artifact = store
        .persist_cashu_custody_export_artifact_v1(&export.export_id, artifact)
        .unwrap();
    assert!(!recovered_artifact.persisted);
    let artifact_digest = recovered_artifact.batch.artifact.unwrap().digest;

    authority.lose_response_at(7);
    assert!(matches!(
        store.acknowledge_cashu_custody_export_v1(&export.export_id, &artifact_digest),
        Err(StoreError::UnanchoredCommit {
            store_generation: 7,
            ..
        })
    ));
    assert!(!store
        .acknowledge_cashu_custody_export_v1(&export.export_id, &artifact_digest)
        .unwrap());
    assert_eq!(store.identity().unwrap().store_generation, 7);
    let inventory = store
        .cashu_custody_inventory_v1(&export.mint_id, "sat")
        .unwrap();
    assert_eq!(inventory.acknowledged_lot_count, 1);
    assert_eq!(inventory.reserved_value, 0);
}

#[test]
fn custody_schema_stores_only_digests_opaque_ciphertext_and_coarse_public_fields() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    drop(store);
    let connection = Connection::open(&path.database).unwrap();
    let table_columns = |table: &str| {
        connection
            .prepare(&format!("PRAGMA table_info('{table}')"))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert_eq!(
        table_columns("cashu_custody_notes"),
        ["note_fingerprint", "lot_id"]
    );
    let all_columns = [
        "cashu_custody_lots",
        "cashu_custody_notes",
        "cashu_custody_export_batches",
        "cashu_custody_export_members",
        "cashu_custody_retirement_evidence",
    ]
    .into_iter()
    .flat_map(table_columns)
    .collect::<Vec<_>>();
    for forbidden in [
        "proof_secret",
        "secret",
        "raw_y",
        "query",
        "invoice",
        "payment_hash",
        "preimage",
        "payer",
        "created_at",
        "updated_at",
        "timestamp",
    ] {
        assert!(!all_columns.iter().any(|column| column == forbidden));
    }
}

#[test]
fn sqlite_rejects_zero_sentinels_and_custody_capacity_overflow() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    insert_and_grant(&store, &intent(0x11), &lot(0x31, 0x41, 0x42));
    let export = NewCashuCustodyExportV1 {
        export_id: [0xd3; 16],
        mint_id: [0xe1; 32],
        unit: "sat".to_owned(),
        recipient_key_id: [0xd4; 32],
        max_lots: 1,
    };
    store.reserve_cashu_custody_export_v1(&export).unwrap();
    store
        .persist_cashu_custody_export_artifact_v1(
            &export.export_id,
            b"recipient-sealed-artifact-for-sql-constraints",
        )
        .unwrap();

    let connection = Connection::open(&path.database).unwrap();
    for (table, column, width) in [
        ("cashu_swap_intents", "intent_id", 16),
        ("cashu_swap_intents", "mint_id", 32),
        ("cashu_swap_intents", "manifest_digest", 32),
        ("cashu_swap_intents", "input_set_digest", 32),
        ("cashu_swap_intents", "request_digest", 32),
        ("cashu_swap_intents", "output_set_digest", 32),
        ("cashu_swap_intents", "offer_binding_digest", 32),
        ("cashu_custody_lots", "lot_id", 16),
        ("cashu_custody_lots", "intent_id", 16),
        ("cashu_custody_lots", "mint_id", 32),
        ("cashu_custody_lots", "manifest_digest", 32),
        ("cashu_custody_lots", "active_keyset_digest", 32),
        ("cashu_custody_lots", "note_set_digest", 32),
        ("cashu_custody_notes", "note_fingerprint", 32),
        ("cashu_custody_notes", "lot_id", 16),
        ("cashu_custody_export_batches", "export_id", 16),
        ("cashu_custody_export_batches", "mint_id", 32),
        ("cashu_custody_export_batches", "recipient_key_id", 32),
        ("cashu_custody_export_batches", "artifact_digest", 32),
        ("cashu_custody_export_members", "export_id", 16),
        ("cashu_custody_export_members", "lot_id", 16),
    ] {
        let statement = format!("UPDATE {table} SET {column} = zeroblob({width})");
        assert!(
            connection.execute(&statement, []).is_err(),
            "SQLite accepted zero sentinel for {table}.{column}"
        );
    }
    for statement in [
        "UPDATE cashu_swap_intents SET expected_output_count = 65",
        "UPDATE cashu_custody_lots SET note_count = 65",
        "UPDATE cashu_custody_export_batches SET note_count = 513",
        "UPDATE cashu_custody_export_batches SET keyset_group_count = 17",
        "UPDATE cashu_custody_export_batches SET artifact = zeroblob(262145)",
    ] {
        assert!(
            connection.execute(statement, []).is_err(),
            "SQLite accepted custody capacity overflow: {statement}"
        );
    }
}

#[test]
fn custody_ciphertext_debug_output_is_redacted() {
    assert!(std::mem::needs_drop::<CashuCustodyRetirementNoteCheckV1>());
    assert!(std::mem::needs_drop::<CashuCustodySpentConfirmationRequestV1>());
    assert!(std::mem::needs_drop::<CashuSwapSealedRecoveryV1>());
    assert!(std::mem::needs_drop::<CashuCustodySealedBlobV1>());
    assert!(std::mem::needs_drop::<CashuCustodyExportArtifactV1>());
    let recovery = CashuSwapSealedRecoveryV1 {
        key_epoch: 6,
        nonce: b"sensitive-recovery-nonce".to_vec(),
        ciphertext: b"sensitive-recovery-ciphertext".to_vec(),
    };
    let recovery_debug = format!("{recovery:?}");
    assert_eq!(
        recovery_debug,
        "CashuSwapSealedRecoveryV1 { envelope: \"[REDACTED]\" }"
    );

    let sealed = CashuCustodySealedBlobV1 {
        key_epoch: 7,
        nonce: b"sensitive-nonce".to_vec(),
        ciphertext: b"sensitive-ciphertext".to_vec(),
    };
    let sealed_debug = format!("{sealed:?}");
    assert_eq!(
        sealed_debug,
        "CashuCustodySealedBlobV1 { envelope: \"[REDACTED]\" }"
    );

    let artifact = CashuCustodyExportArtifactV1 {
        digest: [0xa5; 32],
        bytes: b"sensitive-recipient-envelope".to_vec(),
    };
    let artifact_debug = format!("{artifact:?}");
    assert_eq!(
        artifact_debug,
        "CashuCustodyExportArtifactV1 { artifact: \"[REDACTED]\" }"
    );

    let note_check = CashuCustodyRetirementNoteCheckV1 {
        y: [231; 33],
        state: CashuCustodyRetirementNoteStateV1::Spent,
    };
    assert!(!format!("{note_check:?}").contains("231"));
}

#[test]
fn custody_cross_table_and_artifact_tamper_fail_closed() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    insert_and_grant(&store, &intent(0x11), &lot(0x31, 0x41, 0x42));
    let connection = Connection::open(&path.database).unwrap();
    connection
        .execute(
            "UPDATE cashu_custody_lots SET note_count = 3 WHERE lot_id = ?1",
            [[0x31_u8; 16].as_slice()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.cashu_custody_inventory_v1(&[0xe1; 32], "sat"),
        Err(StoreError::SchemaMismatch(_))
    ));

    let second_path = TestPath::new();
    let second_authority = Arc::new(MemoryRollbackAuthority::default());
    let second_store = create_store(&second_path.database, second_authority);
    insert_and_grant(&second_store, &intent(0x11), &lot(0x31, 0x41, 0x42));
    let export = NewCashuCustodyExportV1 {
        export_id: [0x81; 16],
        mint_id: [0xe1; 32],
        unit: "sat".to_owned(),
        recipient_key_id: [0x83; 32],
        max_lots: 1,
    };
    second_store
        .reserve_cashu_custody_export_v1(&export)
        .unwrap();
    second_store
        .persist_cashu_custody_export_artifact_v1(
            &export.export_id,
            b"recipient-sealed-artifact-before-tamper",
        )
        .unwrap();
    let connection = Connection::open(&second_path.database).unwrap();
    connection
        .execute(
            "UPDATE cashu_custody_export_batches SET
                artifact = zeroblob(length(artifact)) WHERE export_id = ?1",
            [export.export_id.as_slice()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        second_store.cashu_custody_export_v1(&export.export_id),
        Err(StoreError::SchemaMismatch(_))
    ));
}

#[test]
fn missing_or_tampered_retirement_evidence_fails_closed() {
    let path = TestPath::new();
    let authority = Arc::new(MemoryRollbackAuthority::default());
    let store = create_store(&path.database, authority);
    let mut custody_lot = lot(0x31, 0x41, 0x42);
    let (export, artifact_digest) = deliver_single_export(&store, 0x11, &custody_lot);
    let request = spent_confirmation(
        &store,
        export.export_id,
        artifact_digest,
        vec![custody_lot.lot_id],
        std::mem::take(&mut custody_lot.note_ys),
    );
    store
        .confirm_cashu_custody_export_spent_v1(&request)
        .unwrap();

    let connection = Connection::open(&path.database).unwrap();
    connection
        .execute(
            "UPDATE cashu_custody_retirement_evidence
             SET y_set_digest = ?2 WHERE export_id = ?1",
            rusqlite::params![export.export_id.as_slice(), [0xee_u8; 32].as_slice()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.cashu_custody_retirement_evidence_v1(&export.export_id),
        Err(StoreError::SchemaMismatch(_))
    ));

    let missing_path = TestPath::new();
    let missing_authority = Arc::new(MemoryRollbackAuthority::default());
    let missing_store = create_store(&missing_path.database, missing_authority);
    let mut missing_lot = lot(0x32, 0x51, 0x52);
    let (missing_export, missing_artifact_digest) =
        deliver_single_export(&missing_store, 0x12, &missing_lot);
    let missing_request = spent_confirmation(
        &missing_store,
        missing_export.export_id,
        missing_artifact_digest,
        vec![missing_lot.lot_id],
        std::mem::take(&mut missing_lot.note_ys),
    );
    missing_store
        .confirm_cashu_custody_export_spent_v1(&missing_request)
        .unwrap();
    let connection = Connection::open(&missing_path.database).unwrap();
    connection
        .execute(
            "DELETE FROM cashu_custody_retirement_evidence WHERE export_id = ?1",
            [missing_export.export_id.as_slice()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        missing_store.cashu_custody_export_v1(&missing_export.export_id),
        Err(StoreError::CashuCustodyRetirementEvidenceMissing)
    ));
}
