//! Explicit, one-shot initialization of a provider admission store and its
//! independently configured rollback-floor authority.

use clap::Args;
use pir_rollback_authority_client::load_remote_rollback_authority_deployment_for_business_domain_v1;
use pir_service_store::{
    ProviderStore, RemoteProviderRollbackFloorAuthorityV1, RollbackFloorAuthorityV1,
    SqliteRollbackFloorAuthorityV1, StoreOptions, SCHEMA_VERSION,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Args, Debug)]
pub struct ServiceStoreInitArgs {
    /// Exact provider audience (32 bytes, canonical lowercase hex).
    #[arg(long)]
    pub provider_id_hex: String,
    /// New provider-local admission/spent-set SQLite file.
    #[arg(long)]
    pub store: PathBuf,
    /// New local SQLite rollback floor (development/test only).
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
    /// Exact nonzero 16-byte ID required for remote initialization. Local
    /// development/test initialization rejects it and generates a random ID.
    #[arg(long)]
    pub store_instance_id_hex: Option<String>,
    /// SQLite busy timeout in milliseconds (1..=60000).
    #[arg(long, default_value_t = 5_000)]
    pub busy_timeout_ms: u64,
}

pub fn run(args: ServiceStoreInitArgs) -> Result<(), String> {
    run_with_pre_store_create_v1(args, |_| {})
}

fn run_with_pre_store_create_v1<F>(
    args: ServiceStoreInitArgs,
    pre_store_create: F,
) -> Result<(), String>
where
    F: FnOnce(&Path),
{
    let provider_id =
        crate::payment_artifact::parse_hex_exact::<32>("--provider-id-hex", &args.provider_id_hex)?;
    if provider_id.iter().all(|byte| *byte == 0) {
        return Err("--provider-id-hex must not be all zero".to_owned());
    }
    if !(1..=60_000).contains(&args.busy_timeout_ms) {
        return Err("--busy-timeout-ms must be in 1..=60000".to_owned());
    }
    let authority_source = provider_rollback_authority_source_v1(
        args.rollback_authority.as_deref(),
        args.remote_rollback_authority_config.as_deref(),
    )?;
    let store_instance_id = match (authority_source, args.store_instance_id_hex.as_deref()) {
        (ProviderRollbackAuthoritySourceV1::RemoteConfig(_), Some(value)) => {
            crate::payment_artifact::parse_hex_exact::<16>("--store-instance-id-hex", value)?
        }
        (ProviderRollbackAuthoritySourceV1::RemoteConfig(_), None) => {
            return Err(
                "--store-instance-id-hex is required with --remote-rollback-authority-config so an interrupted initialization can resume the exact remote binding"
                    .to_owned(),
            );
        }
        (ProviderRollbackAuthoritySourceV1::LocalSqlite(_), Some(_)) => {
            return Err(
                "--store-instance-id-hex is reserved for remote-authority initialization; local development/test initialization always generates a fresh random ID"
                    .to_owned(),
            );
        }
        (ProviderRollbackAuthoritySourceV1::LocalSqlite(_), None) => {
            random_nonzero_store_instance_id()?
        }
    };
    if store_instance_id.iter().all(|byte| *byte == 0) {
        return Err("--store-instance-id-hex must not be all zero".to_owned());
    }
    let store_path = prepare_new_private_file_path(&args.store)?;
    let timeout = Duration::from_millis(args.busy_timeout_ms);
    let (authority, local_authority_path): (Arc<dyn RollbackFloorAuthorityV1>, Option<PathBuf>) =
        match authority_source {
            ProviderRollbackAuthoritySourceV1::LocalSqlite(configured_path) => {
                eprintln!(
                    "warning: local SQLite provider rollback authority is development/test-only; use --remote-rollback-authority-config for production"
                );
                let authority_path = prepare_new_private_file_path(configured_path)?;
                if store_path == authority_path {
                    return Err(
                        "--store and --rollback-authority must be different paths".to_owned()
                    );
                }
                if store_path.parent() == authority_path.parent() {
                    eprintln!(
                        "warning: local provider store and rollback authority share one directory; this mode is development/test only"
                    );
                }
                let authority =
                    match SqliteRollbackFloorAuthorityV1::create(&authority_path, timeout) {
                        Ok(authority) => authority,
                        Err(error) => {
                            let detail = format!(
                                "create rollback authority {}: {error}",
                                authority_path.display()
                            );
                            return if std::fs::symlink_metadata(&authority_path).is_ok() {
                                Err(incomplete_local_ceremony_error(
                                    detail,
                                    &store_path,
                                    &authority_path,
                                ))
                            } else {
                                Err(detail)
                            };
                        }
                    };
                (Arc::new(authority), Some(authority_path))
            }
            ProviderRollbackAuthoritySourceV1::RemoteConfig(config_path) => (
                open_remote_provider_rollback_authority_v1(provider_id, config_path)?,
                None,
            ),
        };
    pre_store_create(&store_path);
    let finish = || -> Result<(), String> {
        if let Some(authority_path) = local_authority_path.as_deref() {
            set_owner_only(authority_path)?;
        }
        let store = ProviderStore::create(
            &store_path,
            store_instance_id,
            provider_id,
            StoreOptions {
                busy_timeout: timeout,
            },
            Arc::clone(&authority),
        )
        .map_err(|error| format!("create provider store {}: {error}", store_path.display()))?;
        set_owner_only(&store_path)?;
        let identity = store
            .identity()
            .map_err(|error| format!("read back provider store identity: {error}"))?;
        if identity.provider_id != provider_id
            || identity.store_instance_id != store_instance_id
            || identity.schema_version != SCHEMA_VERSION
            || identity.store_generation != 0
            || identity.spend_commit_seq != 0
        {
            return Err("new provider store failed exact identity self-check".to_owned());
        }
        // Reopen the authority through the same selected production boundary;
        // remote mode deliberately creates a fresh pinned HTTPS client and
        // performs a fresh authenticated Read during ProviderStore open.
        let reopened_authority: Arc<dyn RollbackFloorAuthorityV1> = match authority_source {
            ProviderRollbackAuthoritySourceV1::LocalSqlite(_) => {
                let authority_path = local_authority_path
                    .as_deref()
                    .ok_or_else(|| "local rollback authority path was lost".to_owned())?;
                Arc::new(
                    SqliteRollbackFloorAuthorityV1::open_existing(authority_path, timeout)
                        .map_err(|error| format!("reopen rollback authority: {error}"))?,
                )
            }
            ProviderRollbackAuthoritySourceV1::RemoteConfig(config_path) => {
                open_remote_provider_rollback_authority_v1(provider_id, config_path)?
            }
        };
        let reopened = ProviderStore::open_existing(
            &store_path,
            provider_id,
            StoreOptions {
                busy_timeout: timeout,
            },
            reopened_authority,
        )
        .map_err(|error| format!("reopen provider store: {error}"))?;
        if reopened
            .identity()
            .map_err(|error| format!("read reopened provider identity: {error}"))?
            != identity
        {
            return Err("reopened provider store identity changed".to_owned());
        }
        Ok(())
    };
    if let Some(authority_path) = local_authority_path.as_deref() {
        finish()
            .map_err(|error| incomplete_local_ceremony_error(error, &store_path, authority_path))?;
    } else {
        finish().map_err(|error| {
            incomplete_remote_ceremony_error(error, &store_path, store_instance_id)
        })?;
    };

    println!("provider_id={}", hex::encode(provider_id));
    println!("store_instance_id={}", hex::encode(store_instance_id));
    println!("schema_version={SCHEMA_VERSION}");
    println!("store={}", store_path.display());
    match authority_source {
        ProviderRollbackAuthoritySourceV1::LocalSqlite(_) => println!(
            "rollback_authority={}",
            local_authority_path
                .as_deref()
                .ok_or_else(|| "local rollback authority path was lost".to_owned())?
                .display()
        ),
        ProviderRollbackAuthoritySourceV1::RemoteConfig(config_path) => {
            println!("remote_rollback_authority_config={}", config_path.display())
        }
    }
    Ok(())
}

fn incomplete_local_ceremony_error(error: String, store: &Path, authority: &Path) -> String {
    format!(
        "{error}; initialization ceremony is incomplete and neither {} nor {} may be used as live state; inspect both paths, then manually remove only the files created by this failed ceremony before rerunning (this command never auto-deletes or adopts partial state)",
        store.display(),
        authority.display()
    )
}

fn incomplete_remote_ceremony_error(
    error: String,
    store: &Path,
    store_instance_id: [u8; 16],
) -> String {
    format!(
        "{error}; remote initialization may already have committed the floor for store_instance_id={}; preserve the exact remote config and ID, inspect {}, and resume only this same ceremony (never create a replacement identity or lower/reset the remote floor)",
        hex::encode(store_instance_id),
        store.display()
    )
}

#[derive(Clone, Copy)]
pub(crate) enum ProviderRollbackAuthoritySourceV1<'a> {
    LocalSqlite(&'a Path),
    RemoteConfig(&'a Path),
}

pub(crate) fn provider_rollback_authority_source_v1<'a>(
    local_sqlite: Option<&'a Path>,
    remote_config: Option<&'a Path>,
) -> Result<ProviderRollbackAuthoritySourceV1<'a>, String> {
    match (local_sqlite, remote_config) {
        (Some(path), None) => Ok(ProviderRollbackAuthoritySourceV1::LocalSqlite(path)),
        (None, Some(path)) => Ok(ProviderRollbackAuthoritySourceV1::RemoteConfig(path)),
        (None, None) => Err(
            "exactly one of --rollback-authority or --remote-rollback-authority-config is required"
                .to_owned(),
        ),
        (Some(_), Some(_)) => Err(
            "--rollback-authority and --remote-rollback-authority-config are mutually exclusive"
                .to_owned(),
        ),
    }
}

pub(crate) fn open_remote_provider_rollback_authority_v1(
    provider_id: [u8; 32],
    config_path: &Path,
) -> Result<Arc<dyn RollbackFloorAuthorityV1>, String> {
    let configured =
        load_remote_rollback_authority_deployment_for_business_domain_v1(config_path, provider_id)
            .map_err(|error| {
                format!("load remote provider rollback-authority configuration: {error}")
            })?;
    let (client, codec, operation_timeout) = configured.into_parts();
    let authority =
        RemoteProviderRollbackFloorAuthorityV1::new(provider_id, client, codec, operation_timeout)
            .map_err(|error| format!("construct remote provider rollback authority: {error}"))?;
    Ok(Arc::new(authority))
}

fn prepare_new_private_file_path(path: &Path) -> Result<PathBuf, String> {
    pir_private_files::prepare_new_private_file_v1(path, true, "service store")
}

/// Validate an existing sensitive SQLite file using the same owner, mode,
/// canonical-parent, and final-component rules required by serving startup.
pub(crate) fn validate_existing_private_file_path(
    path: &Path,
    label: &str,
) -> Result<PathBuf, String> {
    pir_private_files::checked_existing_private_file_v1(
        path,
        pir_private_files::PrivateFileModeV1::ReadWrite,
        label,
    )
    .map(|checked| checked.path().to_path_buf())
}

pub(crate) fn private_database_paths_alias(first: &Path, second: &Path) -> Result<bool, String> {
    if first == second {
        return Ok(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let first = std::fs::symlink_metadata(first)
            .map_err(|error| format!("inspect {}: {error}", first.display()))?;
        let second = std::fs::symlink_metadata(second)
            .map_err(|error| format!("inspect {}: {error}", second.display()))?;
        Ok(first.dev() == second.dev() && first.ino() == second.ino())
    }
    #[cfg(not(unix))]
    {
        Err("sensitive SQLite path alias checks are unsupported on non-Unix platforms".to_owned())
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("set owner-only permissions on {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_owner_only(path: &Path) -> Result<(), String> {
    Err(format!(
        "service-store-init is unsupported on non-Unix platforms because mode 0600 cannot be enforced: {}",
        path.display()
    ))
}

fn random_nonzero_store_instance_id() -> Result<[u8; 16], String> {
    let mut value = [0u8; 16];
    loop {
        getrandom::getrandom(&mut value)
            .map_err(|error| format!("operating-system randomness failed: {error}"))?;
        if value.iter().any(|byte| *byte != 0) {
            return Ok(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(root: &Path) -> ServiceStoreInitArgs {
        let store_dir = root.join("provider-domain");
        let authority_dir = root.join("rollback-domain");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::fs::create_dir_all(&authority_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&authority_dir, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        ServiceStoreInitArgs {
            provider_id_hex: hex::encode([7u8; 32]),
            store: store_dir.join("provider.sqlite3"),
            rollback_authority: Some(authority_dir.join("floor.sqlite3")),
            remote_rollback_authority_config: None,
            store_instance_id_hex: None,
            busy_timeout_ms: 1_000,
        }
    }

    #[test]
    fn creates_and_reopens_exact_store_and_independent_authority() {
        let directory = tempfile::tempdir().unwrap();
        let args = args(directory.path());
        let store_path = args.store.clone();
        let authority_path = args.rollback_authority.clone().unwrap();
        run(args).unwrap();
        assert!(store_path.is_file());
        assert!(authority_path.is_file());
        assert_ne!(store_path.parent(), authority_path.parent());
        let authority =
            SqliteRollbackFloorAuthorityV1::open_existing(&authority_path, Duration::from_secs(1))
                .unwrap();
        let store = ProviderStore::open_existing(
            &store_path,
            [7; 32],
            StoreOptions {
                busy_timeout: Duration::from_secs(1),
            },
            Arc::new(authority),
        )
        .unwrap();
        let identity = store.identity().unwrap();
        assert!(identity.store_instance_id.iter().any(|byte| *byte != 0));
        assert_eq!(identity.provider_id, [7; 32]);
    }

    #[test]
    fn rejects_overwrite_and_same_path() {
        let directory = tempfile::tempdir().unwrap();
        let first = args(directory.path());
        run(first).unwrap();
        assert!(run(args(directory.path()))
            .unwrap_err()
            .contains("already exists"));

        let other = tempfile::tempdir().unwrap();
        let mut same = args(other.path());
        same.rollback_authority = Some(same.store.clone());
        assert!(run(same).unwrap_err().contains("different paths"));
    }

    #[cfg(unix)]
    #[test]
    fn store_and_authority_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let args = args(directory.path());
        let store_path = args.store.clone();
        let authority_path = args.rollback_authority.clone().unwrap();
        run(args).unwrap();
        for path in [store_path, authority_path] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_public_parent_directory() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let mut args = args(directory.path());
        let unsafe_dir = directory.path().join("unsafe");
        std::fs::create_dir(&unsafe_dir).unwrap();
        std::fs::set_permissions(&unsafe_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        args.store = unsafe_dir.join("provider.sqlite3");
        assert!(run(args).unwrap_err().contains("mode-0700"));
    }

    #[test]
    fn every_post_authority_error_is_marked_as_an_incomplete_ceremony() {
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("provider.sqlite3");
        let authority = directory.path().join("authority.sqlite3");
        let message = incomplete_local_ceremony_error(
            "later self-check failed".to_owned(),
            &store,
            &authority,
        );
        assert!(message.contains("initialization ceremony is incomplete"));
        assert!(message.contains("never auto-deletes or adopts partial state"));
        assert!(message.contains(store.to_str().unwrap()));
        assert!(message.contains(authority.to_str().unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn provider_creation_failure_preserves_authority_and_reports_incomplete_ceremony() {
        let directory = tempfile::tempdir().unwrap();
        let args = args(directory.path());
        let authority_path = args.rollback_authority.clone().unwrap();
        let result = run_with_pre_store_create_v1(args, |store_path| {
            std::fs::write(store_path, b"deterministic provider-create blocker").unwrap();
        });

        let error = result.unwrap_err();
        assert!(
            error.contains("initialization ceremony is incomplete"),
            "{error}"
        );
        assert!(
            error.contains("never auto-deletes or adopts partial state"),
            "{error}"
        );
        assert!(
            authority_path.is_file(),
            "authority must be preserved for operator inspection"
        );
    }

    #[test]
    fn authority_source_is_exactly_one_and_local_rejects_explicit_identity() {
        let local = Path::new("/local.sqlite3");
        let remote = Path::new("/remote.toml");
        assert!(matches!(
            provider_rollback_authority_source_v1(Some(local), None).unwrap(),
            ProviderRollbackAuthoritySourceV1::LocalSqlite(path) if path == local
        ));
        assert!(matches!(
            provider_rollback_authority_source_v1(None, Some(remote)).unwrap(),
            ProviderRollbackAuthoritySourceV1::RemoteConfig(path) if path == remote
        ));
        assert!(provider_rollback_authority_source_v1(None, None).is_err());
        assert!(provider_rollback_authority_source_v1(Some(local), Some(remote)).is_err());

        let directory = tempfile::tempdir().unwrap();
        let mut local_args = args(directory.path());
        local_args.store_instance_id_hex = Some(hex::encode([9u8; 16]));
        assert!(run(local_args)
            .unwrap_err()
            .contains("reserved for remote-authority initialization"));

        let other = tempfile::tempdir().unwrap();
        let mut remote_args = args(other.path());
        let store_path = remote_args.store.clone();
        remote_args.rollback_authority = None;
        remote_args.remote_rollback_authority_config =
            Some(other.path().join("missing-remote.toml"));
        assert!(run(remote_args)
            .unwrap_err()
            .contains("required with --remote-rollback-authority-config"));
        assert!(!store_path.exists());

        let remote_error = incomplete_remote_ceremony_error(
            "response lost".to_owned(),
            Path::new("/provider.sqlite3"),
            [0x42; 16],
        );
        assert!(remote_error.contains("preserve the exact remote config and ID"));
        assert!(remote_error.contains("never create a replacement identity"));
        assert!(remote_error.contains(&hex::encode([0x42; 16])));
    }
}
