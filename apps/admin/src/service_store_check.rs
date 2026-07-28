//! Fail-closed provider-store startup/SLO probe with no listener.

use clap::Args;
use pir_service_store::{
    ProviderStore, ProviderStoreOperationalInventoryV1, RollbackFloorAuthorityV1,
    SqliteRollbackFloorAuthorityV1, StoreOptions,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Args, Debug)]
pub struct ServiceStoreCheckArgs {
    /// Exact provider audience (32 bytes, canonical lowercase hex).
    #[arg(long)]
    pub provider_id_hex: String,
    /// Existing provider-local admission/spent-set SQLite file.
    #[arg(long)]
    pub store: PathBuf,
    /// Existing local SQLite rollback floor (development/test only).
    #[arg(
        long,
        required_unless_present = "remote_rollback_authority_config",
        conflicts_with = "remote_rollback_authority_config"
    )]
    pub rollback_authority: Option<PathBuf>,
    /// Existing owner-only production remote-authority deployment config.
    #[arg(
        long,
        required_unless_present = "rollback_authority",
        conflicts_with = "rollback_authority"
    )]
    pub remote_rollback_authority_config: Option<PathBuf>,
    /// SQLite busy timeout in milliseconds (1..=60000).
    #[arg(long, default_value_t = 5_000)]
    pub busy_timeout_ms: u64,
}

pub fn run(args: ServiceStoreCheckArgs) -> Result<(), String> {
    let provider_id =
        crate::payment_artifact::parse_hex_exact::<32>("--provider-id-hex", &args.provider_id_hex)?;
    if provider_id.iter().all(|byte| *byte == 0) {
        return Err("--provider-id-hex must not be all zero".to_owned());
    }
    if !(1..=60_000).contains(&args.busy_timeout_ms) {
        return Err("--busy-timeout-ms must be in 1..=60000".to_owned());
    }
    let store_path = crate::service_store_init::validate_existing_private_file_path(
        &args.store,
        "provider store",
    )?;
    let timeout = Duration::from_millis(args.busy_timeout_ms);
    let started = Instant::now();
    let authority: Arc<dyn RollbackFloorAuthorityV1> =
        match crate::service_store_init::provider_rollback_authority_source_v1(
            args.rollback_authority.as_deref(),
            args.remote_rollback_authority_config.as_deref(),
        )? {
            crate::service_store_init::ProviderRollbackAuthoritySourceV1::LocalSqlite(path) => {
                eprintln!(
                    "warning: local SQLite provider rollback authority is development/test-only; use --remote-rollback-authority-config for production"
                );
                let authority_path =
                    crate::service_store_init::validate_existing_private_file_path(
                        path,
                        "provider rollback authority",
                    )?;
                if crate::service_store_init::private_database_paths_alias(
                    &store_path,
                    &authority_path,
                )? {
                    return Err(
                        "provider store and rollback authority resolve to the same file/inode"
                            .to_owned(),
                    );
                }
                Arc::new(
                    SqliteRollbackFloorAuthorityV1::open_existing(&authority_path, timeout)
                        .map_err(|error| format!("open provider rollback authority: {error}"))?,
                )
            }
            crate::service_store_init::ProviderRollbackAuthoritySourceV1::RemoteConfig(path) => {
                crate::service_store_init::open_remote_provider_rollback_authority_v1(
                    provider_id,
                    path,
                )?
            }
        };
    let store = ProviderStore::open_existing(
        &store_path,
        provider_id,
        StoreOptions {
            busy_timeout: timeout,
        },
        authority,
    )
    .map_err(|error| format!("open provider store: {error}"))?;
    let identity = store
        .identity()
        .map_err(|error| format!("read provider store identity: {error}"))?;
    let inventory = store
        .operational_inventory()
        .map_err(|error| format!("read provider store inventory: {error}"))?;

    println!("provider_id={}", hex::encode(identity.provider_id));
    println!(
        "store_instance_id={}",
        hex::encode(identity.store_instance_id)
    );
    println!("schema_version={}", identity.schema_version);
    println!("store_generation={}", inventory.observed_store_generation);
    println!("spend_commit_seq={}", inventory.observed_spend_commit_seq);
    println!("startup_check_ms={}", started.elapsed().as_millis());
    println!("namespace_rows={}", inventory.namespace_rows);
    println!("spent_capability_rows={}", inventory.spent_capability_rows);
    println!(
        "free_rate_limit_bucket_rows={}",
        inventory.free_rate_limit_bucket_rows
    );
    println!(
        "cashu_swap_intent_rows={}",
        inventory.cashu_swap_intent_rows
    );
    for line in cashu_custody_inventory_lines(&inventory) {
        println!("{line}");
    }
    Ok(())
}

fn cashu_custody_inventory_lines(inventory: &ProviderStoreOperationalInventoryV1) -> [String; 3] {
    [
        format!(
            "cashu_custody_lot_rows={}",
            inventory.cashu_custody_lot_rows
        ),
        format!(
            "cashu_custody_note_rows={}",
            inventory.cashu_custody_note_rows
        ),
        format!(
            "cashu_custody_export_batch_rows={}",
            inventory.cashu_custody_export_batch_rows
        ),
    ]
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn initialized_paths() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let store_parent = root.path().join("provider-store");
        let authority_parent = root.path().join("provider-floor");
        std::fs::create_dir(&store_parent).unwrap();
        std::fs::create_dir(&authority_parent).unwrap();
        std::fs::set_permissions(&store_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&authority_parent, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let store = store_parent.join("admission.sqlite3");
        let authority = authority_parent.join("floor.sqlite3");
        crate::service_store_init::run(crate::service_store_init::ServiceStoreInitArgs {
            provider_id_hex: hex::encode([0x31_u8; 32]),
            store: store.clone(),
            rollback_authority: Some(authority.clone()),
            remote_rollback_authority_config: None,
            store_instance_id_hex: None,
            busy_timeout_ms: 1_000,
        })
        .unwrap();
        (root, store, authority)
    }

    fn args(store: PathBuf, authority: PathBuf) -> ServiceStoreCheckArgs {
        ServiceStoreCheckArgs {
            provider_id_hex: hex::encode([0x31_u8; 32]),
            store,
            rollback_authority: Some(authority),
            remote_rollback_authority_config: None,
            busy_timeout_ms: 1_000,
        }
    }

    #[test]
    fn serving_equivalent_check_accepts_exact_initialized_pair() {
        let (_root, store, authority) = initialized_paths();
        run(args(store.clone(), authority.clone())).unwrap();
        let timeout = Duration::from_secs(1);
        let rollback = SqliteRollbackFloorAuthorityV1::open_existing(&authority, timeout).unwrap();
        let opened = ProviderStore::open_existing(
            &store,
            [0x31; 32],
            StoreOptions {
                busy_timeout: timeout,
            },
            Arc::new(rollback),
        )
        .unwrap();
        let inventory = opened.operational_inventory().unwrap();
        assert_eq!(
            cashu_custody_inventory_lines(&inventory),
            [
                "cashu_custody_lot_rows=0".to_owned(),
                "cashu_custody_note_rows=0".to_owned(),
                "cashu_custody_export_batch_rows=0".to_owned(),
            ]
        );
    }

    #[test]
    fn check_rejects_wrong_provider_symlink_and_same_inode_alias() {
        let (_root, store, authority) = initialized_paths();
        let mut wrong = args(store.clone(), authority.clone());
        wrong.provider_id_hex = hex::encode([0x32_u8; 32]);
        assert!(run(wrong).unwrap_err().contains("identity mismatch"));

        let link = store.parent().unwrap().join("store-link.sqlite3");
        symlink(&store, &link).unwrap();
        assert!(run(args(link, authority.clone())).is_err());

        let alias = authority.parent().unwrap().join("store-alias.sqlite3");
        std::fs::hard_link(&store, &alias).unwrap();
        assert!(run(args(store, alias)).is_err());
    }
}
