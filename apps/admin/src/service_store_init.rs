//! Explicit, one-shot initialization of a provider admission store and its
//! independently configured rollback-floor authority.

use clap::Args;
use pir_service_store::{
    ProviderStore, SqliteRollbackFloorAuthorityV1, StoreOptions, SCHEMA_VERSION,
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
    /// New rollback-floor SQLite file in an independent backup/restore domain.
    #[arg(long)]
    pub rollback_authority: PathBuf,
    /// Optional exact 16-byte store-instance ID. Random when omitted.
    #[arg(long)]
    pub store_instance_id_hex: Option<String>,
    /// SQLite busy timeout in milliseconds (1..=60000).
    #[arg(long, default_value_t = 5_000)]
    pub busy_timeout_ms: u64,
}

pub fn run(args: ServiceStoreInitArgs) -> Result<(), String> {
    let provider_id =
        crate::payment_artifact::parse_hex_exact::<32>("--provider-id-hex", &args.provider_id_hex)?;
    if provider_id.iter().all(|byte| *byte == 0) {
        return Err("--provider-id-hex must not be all zero".to_owned());
    }
    if !(1..=60_000).contains(&args.busy_timeout_ms) {
        return Err("--busy-timeout-ms must be in 1..=60000".to_owned());
    }
    let store_path = prepare_new_private_file_path(&args.store)?;
    let authority_path = prepare_new_private_file_path(&args.rollback_authority)?;
    if store_path == authority_path {
        return Err("--store and --rollback-authority must be different paths".to_owned());
    }
    if store_path.parent() == authority_path.parent() {
        eprintln!(
            "warning: provider store and rollback authority share one directory; use independent backup/restore domains in production"
        );
    }

    let store_instance_id = match args.store_instance_id_hex {
        Some(value) => {
            crate::payment_artifact::parse_hex_exact::<16>("--store-instance-id-hex", &value)?
        }
        None => random_nonzero_store_instance_id()?,
    };
    if store_instance_id.iter().all(|byte| *byte == 0) {
        return Err("--store-instance-id-hex must not be all zero".to_owned());
    }
    let timeout = Duration::from_millis(args.busy_timeout_ms);
    let authority = match SqliteRollbackFloorAuthorityV1::create(&authority_path, timeout) {
        Ok(authority) => authority,
        Err(error) => {
            let detail = format!(
                "create rollback authority {}: {error}",
                authority_path.display()
            );
            return if std::fs::symlink_metadata(&authority_path).is_ok() {
                Err(incomplete_ceremony_error(
                    detail,
                    &store_path,
                    &authority_path,
                ))
            } else {
                Err(detail)
            };
        }
    };
    let finish = || -> Result<(), String> {
        set_owner_only(&authority_path)?;
        let store = ProviderStore::create(
            &store_path,
            store_instance_id,
            provider_id,
            StoreOptions {
                busy_timeout: timeout,
            },
            Arc::new(authority),
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
        // Reopen both independently; initialization is successful only if the
        // same production open-existing path used at startup accepts them.
        let reopened_authority =
            SqliteRollbackFloorAuthorityV1::open_existing(&authority_path, timeout)
                .map_err(|error| format!("reopen rollback authority: {error}"))?;
        let reopened = ProviderStore::open_existing(
            &store_path,
            provider_id,
            StoreOptions {
                busy_timeout: timeout,
            },
            Arc::new(reopened_authority),
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
    finish().map_err(|error| incomplete_ceremony_error(error, &store_path, &authority_path))?;

    println!("provider_id={}", hex::encode(provider_id));
    println!("store_instance_id={}", hex::encode(store_instance_id));
    println!("schema_version={SCHEMA_VERSION}");
    println!("store={}", store_path.display());
    println!("rollback_authority={}", authority_path.display());
    Ok(())
}

fn incomplete_ceremony_error(error: String, store: &Path, authority: &Path) -> String {
    format!(
        "{error}; initialization ceremony is incomplete and neither {} nor {} may be used as live state; inspect both paths, then manually remove only the files created by this failed ceremony before rerunning (this command never auto-deletes or adopts partial state)",
        store.display(),
        authority.display()
    )
}

fn prepare_new_private_file_path(path: &Path) -> Result<PathBuf, String> {
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("{} is not a file path", path.display()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_was_missing = !parent.exists();
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create {}: {error}", parent.display()))?;
    if parent_was_missing {
        set_private_directory(parent)?;
    }
    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|error| format!("canonicalize {}: {error}", parent.display()))?;
    ensure_private_directory(&canonical_parent)?;
    let canonical = canonical_parent.join(file_name);
    match std::fs::symlink_metadata(&canonical) {
        Ok(_) => Err(format!(
            "{} already exists; service-store-init never overwrites or adopts files",
            canonical.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(canonical),
        Err(error) => Err(format!("inspect {}: {error}", canonical.display())),
    }
}

/// Validate an existing sensitive SQLite file using the same owner, mode,
/// canonical-parent, and final-component rules required by serving startup.
pub(crate) fn validate_existing_private_file_path(
    path: &Path,
    label: &str,
) -> Result<PathBuf, String> {
    let configured = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect configured {label} {}: {error}", path.display()))?;
    if configured.file_type().is_symlink() || !configured.file_type().is_file() {
        return Err(format!(
            "configured {label} must be a non-symlink regular file: {}",
            path.display()
        ));
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("{label} is not a file path: {}", path.display()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|error| format!("canonicalize {label} parent {}: {error}", parent.display()))?;
    ensure_serving_private_directory(&canonical_parent, label)?;
    let canonical = canonical_parent.join(file_name);
    let resolved = std::fs::symlink_metadata(&canonical)
        .map_err(|error| format!("inspect resolved {label} {}: {error}", canonical.display()))?;
    if resolved.file_type().is_symlink() || !resolved.file_type().is_file() {
        return Err(format!(
            "resolved {label} must be a non-symlink regular file: {}",
            canonical.display()
        ));
    }
    ensure_owner_only_file(&resolved, &canonical, label)?;
    ensure_same_file(&configured, &resolved, label)?;
    Ok(canonical)
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
fn ensure_serving_private_directory(path: &Path, label: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} parent {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(format!(
            "{label} parent must be a real directory owned by this user with mode 0700: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_serving_private_directory(path: &Path, label: &str) -> Result<(), String> {
    Err(format!(
        "{label} parent {} is unsupported on non-Unix platforms because owner and mode checks cannot be enforced",
        path.display()
    ))
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("set private permissions on {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_private_directory(path: &Path) -> Result<(), String> {
    Err(format!(
        "service-store-init is unsupported on non-Unix platforms because private directory permissions cannot be enforced: {}",
        path.display()
    ))
}

#[cfg(unix)]
fn ensure_private_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(format!(
            "{} must be a real directory owned by this user with mode 0700/0500",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_directory(path: &Path) -> Result<(), String> {
    Err(format!(
        "service-store-init is unsupported on non-Unix platforms because directory owner and mode checks cannot be enforced: {}",
        path.display()
    ))
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("set owner-only permissions on {}: {error}", path.display()))
}

#[cfg(unix)]
fn ensure_owner_only_file(
    metadata: &std::fs::Metadata,
    path: &Path,
    label: &str,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o777 != 0o600 {
        return Err(format!(
            "{label} must be owned by the effective user with mode 0600: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owner_only_file(
    _metadata: &std::fs::Metadata,
    path: &Path,
    label: &str,
) -> Result<(), String> {
    Err(format!(
        "{label} {} is unsupported on non-Unix platforms because owner and mode checks cannot be enforced",
        path.display()
    ))
}

#[cfg(unix)]
fn ensure_same_file(
    configured: &std::fs::Metadata,
    resolved: &std::fs::Metadata,
    label: &str,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if configured.dev() != resolved.dev() || configured.ino() != resolved.ino() {
        return Err(format!(
            "configured {label} changed while its canonical parent was resolved"
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_same_file(
    _configured: &std::fs::Metadata,
    _resolved: &std::fs::Metadata,
    label: &str,
) -> Result<(), String> {
    Err(format!(
        "{label} is unsupported on non-Unix platforms because file identity checks cannot be enforced"
    ))
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
            rollback_authority: authority_dir.join("floor.sqlite3"),
            store_instance_id_hex: Some(hex::encode([9u8; 16])),
            busy_timeout_ms: 1_000,
        }
    }

    #[test]
    fn creates_and_reopens_exact_store_and_independent_authority() {
        let directory = tempfile::tempdir().unwrap();
        let args = args(directory.path());
        let store_path = args.store.clone();
        let authority_path = args.rollback_authority.clone();
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
        assert_eq!(identity.store_instance_id, [9; 16]);
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
        same.rollback_authority = same.store.clone();
        assert!(run(same).unwrap_err().contains("different paths"));
    }

    #[cfg(unix)]
    #[test]
    fn store_and_authority_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let args = args(directory.path());
        let store_path = args.store.clone();
        let authority_path = args.rollback_authority.clone();
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
        assert!(run(args).unwrap_err().contains("0700/0500"));
    }

    #[test]
    fn every_post_authority_error_is_marked_as_an_incomplete_ceremony() {
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("provider.sqlite3");
        let authority = directory.path().join("authority.sqlite3");
        let message =
            incomplete_ceremony_error("later self-check failed".to_owned(), &store, &authority);
        assert!(message.contains("initialization ceremony is incomplete"));
        assert!(message.contains("never auto-deletes or adopts partial state"));
        assert!(message.contains(store.to_str().unwrap()));
        assert!(message.contains(authority.to_str().unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn provider_creation_failure_preserves_authority_and_reports_incomplete_ceremony() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let args = args(directory.path());
        let store_parent = args.store.parent().unwrap().to_path_buf();
        let authority_path = args.rollback_authority.clone();
        std::fs::set_permissions(&store_parent, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = run(args);
        std::fs::set_permissions(&store_parent, std::fs::Permissions::from_mode(0o700)).unwrap();

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
}
