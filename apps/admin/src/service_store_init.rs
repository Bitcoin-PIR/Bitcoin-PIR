//! Explicit, one-shot initialization of a provider admission store.

use clap::Args;
use pir_service_store::{ProviderStore, StoreOptions, SCHEMA_VERSION};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Args, Debug)]
pub struct ServiceStoreInitArgs {
    /// Exact provider audience (32 bytes, canonical lowercase hex).
    #[arg(long)]
    pub provider_id_hex: String,
    /// New provider-local admission/spent-set SQLite file.
    #[arg(long)]
    pub store: PathBuf,
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
    let store_instance_id = random_nonzero_store_instance_id()?;
    let store_path = prepare_new_private_file_path(&args.store)?;
    let timeout = Duration::from_millis(args.busy_timeout_ms);
    pre_store_create(&store_path);
    let finish = || -> Result<(), String> {
        let store = ProviderStore::create(
            &store_path,
            store_instance_id,
            provider_id,
            StoreOptions {
                busy_timeout: timeout,
            },
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
        // Reopen through the same production open-existing path.
        let reopened = ProviderStore::open_existing(
            &store_path,
            provider_id,
            StoreOptions {
                busy_timeout: timeout,
            },
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
    finish().map_err(|error| incomplete_local_ceremony_error(error, &store_path))?;

    println!("provider_id={}", hex::encode(provider_id));
    println!("store_instance_id={}", hex::encode(store_instance_id));
    println!("schema_version={SCHEMA_VERSION}");
    println!("store={}", store_path.display());
    Ok(())
}

fn incomplete_local_ceremony_error(error: String, store: &Path) -> String {
    format!(
        "{error}; initialization ceremony is incomplete and {} may not be used as live state; inspect the path, then manually remove only the files created by this failed ceremony before rerunning (this command never auto-deletes or adopts partial state)",
        store.display()
    )
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
        std::fs::create_dir_all(&store_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        ServiceStoreInitArgs {
            provider_id_hex: hex::encode([7u8; 32]),
            store: store_dir.join("provider.sqlite3"),
            busy_timeout_ms: 1_000,
        }
    }

    #[test]
    fn creates_and_reopens_exact_store() {
        let directory = tempfile::tempdir().unwrap();
        let args = args(directory.path());
        let store_path = args.store.clone();
        run(args).unwrap();
        assert!(store_path.is_file());
        let store = ProviderStore::open_existing(
            &store_path,
            [7; 32],
            StoreOptions {
                busy_timeout: Duration::from_secs(1),
            },
        )
        .unwrap();
        let identity = store.identity().unwrap();
        assert!(identity.store_instance_id.iter().any(|byte| *byte != 0));
        assert_eq!(identity.provider_id, [7; 32]);
    }

    #[test]
    fn rejects_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let first = args(directory.path());
        run(first).unwrap();
        assert!(run(args(directory.path()))
            .unwrap_err()
            .contains("already exists"));
    }

    #[cfg(unix)]
    #[test]
    fn store_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let args = args(directory.path());
        let store_path = args.store.clone();
        run(args).unwrap();
        assert_eq!(
            std::fs::metadata(store_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
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

    #[cfg(unix)]
    #[test]
    fn provider_creation_failure_reports_incomplete_ceremony() {
        let directory = tempfile::tempdir().unwrap();
        let args = args(directory.path());
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
    }
}
