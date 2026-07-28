//! `bpir-admin keygen` — generate an ed25519 keypair for admin auth.
//!
//! Writes the 32-byte secret seed to a file (mode 0600 on Unix) and
//! prints the corresponding public key as 64-char hex. The operator
//! pastes the hex into the server's `--admin-pubkey-hex` flag.

use clap::Args;
use ed25519_dalek::SigningKey;
use std::io::Read;
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Write the secret key to this path. Default:
    /// `$XDG_CONFIG_HOME/bpir-admin/admin.key` (or
    /// `~/.config/bpir-admin/admin.key`).
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Overwrite an existing key file. Without this, refuses to
    /// clobber an existing key (so an accidental rerun doesn't lose
    /// the operator's only copy of the privkey).
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: KeygenArgs) -> Result<SecretWriteCompletionV1, String> {
    let out = args.out.unwrap_or_else(default_keyfile_path);
    prepare_secret_key_parent(&out)?;

    let mut seed = [0u8; 32];
    if let Err(error) = getrandom::getrandom(&mut seed) {
        seed.zeroize();
        return Err(format!("getrandom: {error}"));
    }
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    let pk_hex = hex::encode(pk.to_bytes());

    let write_result = write_secret_key(&out, &seed, args.force);
    seed.zeroize();
    let completion = write_result?;

    eprintln!(
        "wrote secret key (32 bytes, mode 0600) to {}",
        out.display()
    );
    eprintln!();
    eprintln!("Public key (paste into server's --admin-pubkey-hex):");
    println!("{}", pk_hex);
    Ok(completion)
}

#[cfg(all(test, unix))]
pub(crate) fn write_secret_key_unix(path: &std::path::Path, seed: &[u8; 32]) -> Result<(), String> {
    write_secret_bytes_unix(path, seed)
}

#[cfg(all(test, not(unix)))]
pub(crate) fn write_secret_key_unix(path: &std::path::Path, seed: &[u8; 32]) -> Result<(), String> {
    write_secret_bytes_unix(path, seed)
}

pub(crate) fn write_secret_key_unix_with_force(
    path: &std::path::Path,
    seed: &[u8; 32],
    force: bool,
) -> Result<SecretWriteCompletionV1, String> {
    write_secret_bytes_unix_with_force(path, seed, force)
}

/// Write arbitrary fixed-size secret material with the same owner-only and
/// no-symlink guarantees as the admin signing key. Payment V1 needs this for
/// the four-scalar (128-byte) experimental ARC key.
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
pub(crate) fn write_secret_bytes_unix(path: &std::path::Path, secret: &[u8]) -> Result<(), String> {
    require_durable_secret_write(write_secret_bytes_unix_with_force(path, secret, true)?)
}

/// Atomically enforces the caller's no-clobber choice without a racy
/// `Path::exists` preflight. Both paths first create and sync a private
/// same-directory temporary. `force=true` atomically replaces a previously
/// validated target; otherwise `RENAME_NOREPLACE` is the sole commit authority,
/// so a concurrent winner cannot be truncated. The containing directory is
/// synced before and after the namespace commit.
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
pub(crate) fn write_secret_bytes_unix_with_force(
    path: &std::path::Path,
    secret: &[u8],
    force: bool,
) -> Result<SecretWriteCompletionV1, String> {
    if secret.is_empty() {
        return Err("refusing to write empty secret material".to_owned());
    }
    let outcome = write_secret_bytes_atomically_unix(path, secret, force)?;
    match outcome {
        SecretWriteOutcomeV1::Durable => return Ok(SecretWriteCompletionV1::Durable),
        SecretWriteOutcomeV1::CommittedDurabilityUnknown { parent, error } => {
            eprintln!("secret_write_status=committed_durability_unknown");
            eprintln!(
                "WARNING: the new secret was atomically committed at {} but directory durability is unknown because syncing {} failed: {}",
                path.display(),
                parent.display(),
                error
            );
            eprintln!(
                "WARNING: DO NOT retry --force. Inspect the exact target and preserve the public key/fingerprint this command prints."
            );
        }
        SecretWriteOutcomeV1::CommittedPathUnknown {
            parent,
            error,
            durability_error,
        } => {
            eprintln!("secret_write_status=committed_path_unknown");
            eprintln!(
                "WARNING: the new secret reached the atomic commit point in {} but the requested path can no longer be proven to name it: {}",
                parent.display(),
                error
            );
            if let Some(error) = durability_error {
                eprintln!("WARNING: committed directory durability is also unknown: {error}");
            }
            eprintln!(
                "WARNING: DO NOT retry --force. Reconcile the pinned directory inode, exact target, and public identity this command prints."
            );
        }
    }
    Ok(SecretWriteCompletionV1::CommittedAmbiguous)
}

/// Command-facing completion state. A committed-but-ambiguous write must still
/// print its public identity, but it must not be reported as ordinary success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretWriteCompletionV1 {
    Durable,
    CommittedAmbiguous,
}

pub(crate) const COMMITTED_AMBIGUOUS_EXIT_CODE_V1: i32 = 2;

impl SecretWriteCompletionV1 {
    pub(crate) const fn exit_code(self) -> i32 {
        match self {
            Self::Durable => 0,
            Self::CommittedAmbiguous => COMMITTED_AMBIGUOUS_EXIT_CODE_V1,
        }
    }
}

fn require_durable_secret_write(completion: SecretWriteCompletionV1) -> Result<(), String> {
    match completion {
        SecretWriteCompletionV1::Durable => Ok(()),
        SecretWriteCompletionV1::CommittedAmbiguous => Err(
            "secret write committed ambiguously; reconcile the installed path and do not retry"
                .to_owned(),
        ),
    }
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum SecretWriteOutcomeV1 {
    Durable,
    CommittedDurabilityUnknown {
        parent: PathBuf,
        error: String,
    },
    CommittedPathUnknown {
        parent: PathBuf,
        error: String,
        durability_error: Option<String>,
    },
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SecretTargetSnapshotV1 {
    device: u128,
    inode: u128,
    mode: u64,
    size: i128,
    uid: u32,
    links: u128,
    modified_seconds: i128,
    modified_nanoseconds: i128,
    changed_seconds: i128,
    changed_nanoseconds: i128,
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn secret_target_snapshot_v1(stat: &rustix::fs::Stat) -> SecretTargetSnapshotV1 {
    SecretTargetSnapshotV1 {
        device: stat.st_dev as u128,
        inode: stat.st_ino as u128,
        mode: stat.st_mode as u64,
        size: stat.st_size as i128,
        uid: stat.st_uid,
        links: stat.st_nlink as u128,
        modified_seconds: stat.st_mtime as i128,
        modified_nanoseconds: stat.st_mtime_nsec as i128,
        changed_seconds: stat.st_ctime as i128,
        changed_nanoseconds: stat.st_ctime_nsec as i128,
    }
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn open_secret_parent_v1(
    path: &std::path::Path,
) -> Result<(std::fs::File, std::ffi::OsString, PathBuf), String> {
    let parent_path = secret_parent(path).to_path_buf();
    let file_name = path
        .file_name()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{} must name a secret file", path.display()))?
        .to_os_string();
    let parent = open_secret_directory_components_v1(&parent_path, true)?;
    Ok((parent, file_name, parent_path))
}

/// Create and validate the parent before generating secret material. The
/// writer repeats the same fd-relative walk immediately before committing, so
/// no path-based reopen can reintroduce an intermediate-symlink race.
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
pub(crate) fn prepare_secret_key_parent(path: &std::path::Path) -> Result<(), String> {
    let _ = open_secret_parent_v1(path)?;
    Ok(())
}

#[cfg(not(all(unix, any(target_os = "linux", target_os = "macos"))))]
pub(crate) fn prepare_secret_key_parent(path: &std::path::Path) -> Result<(), String> {
    let _ = path;
    Err("secret generation is production-supported only on Linux and macOS".to_owned())
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn open_existing_secret_parent_v1(
    path: &std::path::Path,
) -> Result<(std::fs::File, std::ffi::OsString, PathBuf), String> {
    let parent_path = secret_parent(path).to_path_buf();
    let file_name = path
        .file_name()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{} must name a secret file", path.display()))?
        .to_os_string();
    let parent = open_secret_directory_components_v1(&parent_path, false)?;
    Ok((parent, file_name, parent_path))
}

#[cfg(target_os = "macos")]
fn macos_system_root_alias_target_v1(name: &std::ffi::OsStr) -> Option<&'static std::path::Path> {
    if name == std::ffi::OsStr::new("var") {
        Some(std::path::Path::new("private/var"))
    } else if name == std::ffi::OsStr::new("tmp") {
        Some(std::path::Path::new("private/tmp"))
    } else if name == std::ffi::OsStr::new("etc") {
        Some(std::path::Path::new("private/etc"))
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn macos_system_root_alias_is_byte_exact_v1(
    name: &std::ffi::OsStr,
    target: &std::path::Path,
) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    macos_system_root_alias_target_v1(name)
        .is_some_and(|expected| target.as_os_str().as_bytes() == expected.as_os_str().as_bytes())
}

/// macOS exposes `/var`, `/tmp`, and `/etc` as root-owned fixed aliases into
/// `/private`. Accept only those byte-exact platform aliases, then resume the
/// ordinary component-wise `O_NOFOLLOW` walk at the real `/private/...` path.
/// This is not a general symlink-resolution mechanism.
#[cfg(target_os = "macos")]
fn normalize_macos_system_root_alias_v1(path: &std::path::Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Component;

    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Ok(path.to_path_buf());
    }
    let Some(Component::Normal(first)) = components.next() else {
        return Ok(path.to_path_buf());
    };
    let Some(expected_target) = macos_system_root_alias_target_v1(first) else {
        return Ok(path.to_path_buf());
    };

    let alias = std::path::Path::new("/").join(first);
    let metadata = std::fs::symlink_metadata(&alias).map_err(|error| {
        format!(
            "inspect fixed macOS system alias {}: {error}",
            alias.display()
        )
    })?;
    if !metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.nlink() != 1 {
        return Err(format!(
            "fixed macOS system alias {} must be a single-link root-owned symlink",
            alias.display()
        ));
    }
    let target = std::fs::read_link(&alias)
        .map_err(|error| format!("read fixed macOS system alias {}: {error}", alias.display()))?;
    if !macos_system_root_alias_is_byte_exact_v1(first, &target) {
        return Err(format!(
            "fixed macOS system alias {} must point byte-exactly to {}",
            alias.display(),
            expected_target.display()
        ));
    }

    let mut normalized = std::path::PathBuf::from("/").join(expected_target);
    for component in components {
        normalized.push(component.as_os_str());
    }
    Ok(normalized)
}

#[cfg(target_os = "linux")]
fn normalize_macos_system_root_alias_v1(path: &std::path::Path) -> Result<PathBuf, String> {
    Ok(path.to_path_buf())
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn open_secret_directory_components_v1(
    path: &std::path::Path,
    create_missing: bool,
) -> Result<std::fs::File, String> {
    use rustix::fs::{self as rustix_fs, Mode, OFlags};
    use std::path::Component;

    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let walked_path = normalize_macos_system_root_alias_v1(path)?;
    let start = if walked_path.is_absolute() {
        std::path::Path::new("/")
    } else {
        std::path::Path::new(".")
    };
    let start_fd = rustix_fs::open(start, directory_flags, Mode::empty())
        .map_err(|error| format!("open secret path base {}: {error}", start.display()))?;
    let mut current = std::fs::File::from(start_fd);

    for component in walked_path.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir => {
                return Err(format!(
                    "secret directory {} must not contain '..' components",
                    path.display()
                ));
            }
            Component::Prefix(_) => {
                return Err(format!(
                    "unsupported secret directory prefix in {}",
                    path.display()
                ));
            }
        };

        let mut created = false;
        let next = match rustix_fs::openat(&current, name, directory_flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) if create_missing => {
                match rustix_fs::mkdirat(&current, name, Mode::from_bits_truncate(0o700)) {
                    Ok(()) => {
                        created = true;
                        current.sync_all().map_err(|error| {
                            format!(
                                "sync containing directory after creating {}: {error}",
                                path.display()
                            )
                        })?;
                    }
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => {
                        return Err(format!(
                            "create secret directory component {:?} in {}: {error}",
                            name,
                            path.display()
                        ));
                    }
                }
                rustix_fs::openat(&current, name, directory_flags, Mode::empty()).map_err(
                    |error| {
                        format!(
                            "open newly created secret directory component {:?} in {} without following symlinks: {error}",
                            name,
                            path.display()
                        )
                    },
                )?
            }
            Err(error) => {
                return Err(format!(
                    "open secret directory component {:?} in {} without following symlinks: {error}",
                    name,
                    path.display()
                ));
            }
        };
        current = std::fs::File::from(next);
        if created {
            validate_secret_parent_fd_v1(&current, path)?;
        }
    }

    validate_secret_parent_fd_v1(&current, path)?;
    Ok(current)
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn validate_secret_parent_fd_v1(
    parent: &std::fs::File,
    display_path: &std::path::Path,
) -> Result<(), String> {
    use rustix::fs::{self as rustix_fs, FileType};

    let stat = rustix_fs::fstat(parent)
        .map_err(|error| format!("inspect secret parent {}: {error}", display_path.display()))?;
    let is_directory = FileType::from_raw_mode(stat.st_mode).is_dir();
    let expected_uid = rustix::process::geteuid().as_raw();
    let permissions = stat.st_mode & 0o777;
    if !is_directory || stat.st_uid != expected_uid || permissions != 0o700 {
        return Err(format!(
            "{} must be a real effective-user-owned directory with mode 0700 (is_directory={is_directory}, uid={}, expected_uid={expected_uid}, mode={permissions:04o})",
            display_path.display(),
            stat.st_uid,
        ));
    }
    reject_extended_acl_v1(parent, &format!("secret parent {}", display_path.display()))
}

#[cfg(target_os = "macos")]
mod macos_acl_v1 {
    use std::ffi::{c_int, c_void};

    pub(super) const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    pub(super) const ACL_FIRST_ENTRY: c_int = 0;

    unsafe extern "C" {
        pub(super) fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
        pub(super) fn acl_get_entry(
            acl: *mut c_void,
            entry_id: c_int,
            entry: *mut *mut c_void,
        ) -> c_int;
        pub(super) fn acl_init(count: c_int) -> *mut c_void;
        pub(super) fn acl_set_fd_np(fd: c_int, acl: *mut c_void, acl_type: c_int) -> c_int;
        pub(super) fn acl_free(value: *mut c_void) -> c_int;
    }
}

#[cfg(target_os = "macos")]
struct MacosAclGuardV1(*mut std::ffi::c_void);

#[cfg(target_os = "macos")]
impl Drop for MacosAclGuardV1 {
    fn drop(&mut self) {
        // SAFETY: the pointer was returned by an ACL allocation API and this
        // guard owns the one required acl_free call.
        unsafe {
            let _ = macos_acl_v1::acl_free(self.0);
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_extended_acl_has_entries_v1(fd: i32) -> Result<bool, String> {
    let acl = {
        // SAFETY: fd is a live descriptor borrowed for this call.
        unsafe { macos_acl_v1::acl_get_fd_np(fd, macos_acl_v1::ACL_TYPE_EXTENDED) }
    };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) {
            return Ok(false);
        }
        return Err(format!("read macOS extended ACL: {error}"));
    }
    let _guard = MacosAclGuardV1(acl);
    let mut entry = std::ptr::null_mut();
    let result = {
        // SAFETY: acl remains live through the guard and entry points to valid
        // output storage for the duration of the call.
        unsafe { macos_acl_v1::acl_get_entry(acl, macos_acl_v1::ACL_FIRST_ENTRY, &mut entry) }
    };
    if result == 0 {
        return Ok(true);
    }
    Err(format!(
        "enumerate macOS extended ACL: {}",
        std::io::Error::last_os_error()
    ))
}

#[cfg(target_os = "macos")]
fn reject_extended_acl_v1<Fd: std::os::fd::AsRawFd>(
    fd: &Fd,
    description: &str,
) -> Result<(), String> {
    if macos_extended_acl_has_entries_v1(fd.as_raw_fd())? {
        return Err(format!("{description} must not have a macOS extended ACL"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn clear_extended_acl_v1<Fd: std::os::fd::AsRawFd>(
    fd: &Fd,
    description: &str,
) -> Result<(), String> {
    let acl = {
        // SAFETY: acl_init allocates an empty ACL owned by the returned guard.
        unsafe { macos_acl_v1::acl_init(1) }
    };
    if acl.is_null() {
        return Err(format!(
            "allocate empty macOS ACL for {description}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let _guard = MacosAclGuardV1(acl);
    let result = {
        // SAFETY: fd is live and acl is a valid empty ACL for this call.
        unsafe { macos_acl_v1::acl_set_fd_np(fd.as_raw_fd(), acl, macos_acl_v1::ACL_TYPE_EXTENDED) }
    };
    if result != 0 {
        return Err(format!(
            "clear macOS extended ACL on {description}: {}",
            std::io::Error::last_os_error()
        ));
    }
    reject_extended_acl_v1(fd, description)
}

// Linux POSIX ACLs are not enumerated here. The production contract remains
// explicit DAC-only on Linux until a reviewed ACL dependency/parser is added.
#[cfg(target_os = "linux")]
fn reject_extended_acl_v1<Fd: std::os::fd::AsRawFd>(
    fd: &Fd,
    description: &str,
) -> Result<(), String> {
    let _ = (fd.as_raw_fd(), description);
    Ok(())
}

#[cfg(target_os = "linux")]
fn clear_extended_acl_v1<Fd: std::os::fd::AsRawFd>(
    fd: &Fd,
    description: &str,
) -> Result<(), String> {
    let _ = (fd.as_raw_fd(), description);
    Ok(())
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn inspect_secret_target_v1(
    parent: &std::fs::File,
    file_name: &std::ffi::OsStr,
    display_path: &std::path::Path,
) -> Result<Option<SecretTargetSnapshotV1>, String> {
    use rustix::fs::{self as rustix_fs, AtFlags, FileType, Mode, OFlags};

    let named = match rustix_fs::statat(parent, file_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(format!(
                "inspect existing {} without following symlinks: {error}",
                display_path.display()
            ));
        }
    };
    if !FileType::from_raw_mode(named.st_mode).is_file()
        || named.st_uid != rustix::process::geteuid().as_raw()
        || named.st_nlink != 1
    {
        return Err(format!(
            "{} must be a single-link regular file owned by the effective user",
            display_path.display()
        ));
    }
    let fd = rustix_fs::openat(
        parent,
        file_name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("open existing {} safely: {error}", display_path.display()))?;
    let opened = rustix_fs::fstat(&fd)
        .map_err(|error| format!("inspect opened {}: {error}", display_path.display()))?;
    let named = secret_target_snapshot_v1(&named);
    let opened = secret_target_snapshot_v1(&opened);
    if named != opened {
        return Err(format!(
            "{} changed while its existing inode was validated",
            display_path.display()
        ));
    }
    // `--force` is a rotation ceremony, not an ACL-remediation shortcut. If
    // the old key has an extended ACL it may already be exposed; fail closed
    // so the operator handles revocation/incident response explicitly instead
    // of silently replacing the evidence.
    reject_extended_acl_v1(&fd, &format!("existing secret {}", display_path.display()))?;
    Ok(Some(opened))
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn validate_open_secret_parent_still_named_v1(
    parent: &std::fs::File,
    parent_path: &std::path::Path,
) -> Result<(), String> {
    use rustix::fs::{self as rustix_fs, FileType};

    let named_parent = open_secret_directory_components_v1(parent_path, false)
        .map_err(|error| format!("reinspect secret parent {}: {error}", parent_path.display()))?;
    let named = rustix_fs::fstat(&named_parent)
        .map_err(|error| format!("inspect named secret parent: {error}"))?;
    let opened = rustix_fs::fstat(parent)
        .map_err(|error| format!("reinspect opened secret parent: {error}"))?;
    if !FileType::from_raw_mode(named.st_mode).is_dir()
        || !FileType::from_raw_mode(opened.st_mode).is_dir()
        || named.st_uid != opened.st_uid
        || named.st_mode & 0o777 != 0o700
        || opened.st_uid != rustix::process::geteuid().as_raw()
        || opened.st_mode & 0o777 != 0o700
        || named.st_dev as u128 != opened.st_dev as u128
        || named.st_ino as u128 != opened.st_ino as u128
    {
        return Err(format!(
            "secret parent {} changed after it was opened",
            parent_path.display()
        ));
    }
    reject_extended_acl_v1(parent, &format!("secret parent {}", parent_path.display()))
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn secret_temporary_name_v1() -> Result<std::ffi::OsString, String> {
    let mut random = [0u8; 16];
    if let Err(error) = getrandom::getrandom(&mut random) {
        random.zeroize();
        return Err(format!(
            "OS randomness unavailable for atomic key rotation: {error}"
        ));
    }
    let nonce = hex::encode(random);
    random.zeroize();
    // Keep the temporary basename ASCII-only and independent of the target
    // basename. Carrying arbitrary target bytes into a second filename can
    // fail before the atomic commit on filesystems that reject non-UTF-8
    // names. The random suffix plus O_EXCL still gives the temporary its
    // collision and no-clobber guarantees; the final target remains subject
    // to the host filesystem's native filename rules.
    let mut temporary = std::ffi::OsString::from(".bpir-secret-rotation-");
    temporary.push(nonce);
    temporary.push(".tmp");
    Ok(temporary)
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn write_secret_bytes_atomically_unix(
    path: &std::path::Path,
    secret: &[u8],
    force: bool,
) -> Result<SecretWriteOutcomeV1, String> {
    use rustix::fs::{
        self as rustix_fs, AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags,
    };
    use std::io::Write as _;

    let owner_only = Mode::from_bits_truncate(0o600);
    let (parent, file_name, parent_path) = open_secret_parent_v1(path)?;
    rustix_fs::flock(&parent, FlockOperation::NonBlockingLockExclusive)
        .map_err(|error| format!("secret parent {} is busy: {error}", parent_path.display()))?;
    parent
        .sync_all()
        .map_err(|error| format!("preflight secret parent {}: {error}", parent_path.display()))?;
    let before = inspect_secret_target_v1(&parent, &file_name, path)?;
    if before.is_some() && !force {
        return Err(format!(
            "{} already exists; use --force only after confirming key rotation",
            path.display()
        ));
    }

    let temporary_name = secret_temporary_name_v1()?;
    let mut temporary_created = false;
    let result = (|| {
        let fd = rustix_fs::openat(
            &parent,
            &temporary_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            owner_only,
        )
        .map_err(|e| format!("create private rotation temporary: {e}"))?;
        temporary_created = true;
        rustix_fs::fchmod(&fd, owner_only)
            .map_err(|e| format!("secure private rotation temporary: {e}"))?;
        // macOS can inherit an extended ACL independently of mode 0600.
        // Remove and re-read it before the first byte of secret material is
        // written. Linux remains explicitly DAC-only for this release.
        clear_extended_acl_v1(&fd, "private rotation temporary")?;
        let mut file = std::fs::File::from(fd);
        file.write_all(secret)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("write private rotation temporary: {e}"))?;
        let stat = rustix_fs::fstat(&file)
            .map_err(|e| format!("inspect private rotation temporary: {e}"))?;
        if !FileType::from_raw_mode(stat.st_mode).is_file()
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_nlink != 1
            || stat.st_mode & 0o777 != 0o600
            || stat.st_size as i128 != secret.len() as i128
        {
            return Err(
                "private rotation temporary failed owner/mode/length validation".to_owned(),
            );
        }
        let committed_snapshot = secret_target_snapshot_v1(&stat);
        drop(file);
        parent
            .sync_all()
            .map_err(|error| format!("sync private rotation temporary: {error}"))?;
        validate_open_secret_parent_still_named_v1(&parent, &parent_path)?;
        let current = inspect_secret_target_v1(&parent, &file_name, path)?;
        if current != before {
            return Err(format!(
                "{} changed before atomic key commit; refusing replacement",
                path.display()
            ));
        }
        if before.is_none() {
            rustix_fs::renameat_with(
                &parent,
                &temporary_name,
                &parent,
                &file_name,
                RenameFlags::NOREPLACE,
            )
        } else {
            rustix_fs::renameat(&parent, &temporary_name, &parent, &file_name)
        }
        .map_err(|error| format!("atomically commit {}: {error}", path.display()))?;
        temporary_created = false;
        let durability_error = parent.sync_all().err().map(|error| error.to_string());
        let mut path_errors = Vec::new();
        if let Err(error) = validate_open_secret_parent_still_named_v1(&parent, &parent_path) {
            path_errors.push(error);
        }
        match inspect_secret_target_v1(&parent, &file_name, path) {
            Ok(Some(installed))
                if installed.device == committed_snapshot.device
                    && installed.inode == committed_snapshot.inode
                    && installed.uid == committed_snapshot.uid
                    && installed.links == 1
                    && installed.mode & 0o777 == 0o600
                    && installed.size == secret.len() as i128 => {}
            Ok(Some(_)) => path_errors.push(
                "the committed target was replaced before post-commit verification".to_owned(),
            ),
            Ok(None) => path_errors.push(
                "the committed target disappeared before post-commit verification".to_owned(),
            ),
            Err(error) => path_errors.push(error),
        }
        if !path_errors.is_empty() {
            Ok(SecretWriteOutcomeV1::CommittedPathUnknown {
                parent: parent_path.clone(),
                error: path_errors.join("; "),
                durability_error,
            })
        } else if let Some(error) = durability_error {
            Ok(SecretWriteOutcomeV1::CommittedDurabilityUnknown {
                parent: parent_path.clone(),
                error,
            })
        } else {
            Ok(SecretWriteOutcomeV1::Durable)
        }
    })();
    if temporary_created {
        let original = result
            .as_ref()
            .err()
            .cloned()
            .unwrap_or_else(|| "private temporary cleanup reached an invalid state".to_owned());
        let cleanup = rustix_fs::unlinkat(&parent, &temporary_name, AtFlags::empty());
        if let Err(cleanup_error) = cleanup {
            return Err(format!(
                "{original}; cleanup failed for owner-only temporary {}: {cleanup_error}",
                parent_path.join(&temporary_name).display()
            ));
        }
        if let Err(sync_error) = parent.sync_all() {
            return Err(format!(
                "{original}; temporary was removed but cleanup durability is unknown: {sync_error}"
            ));
        }
    }
    result
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn secret_parent(path: &std::path::Path) -> &std::path::Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
}

#[cfg(not(all(unix, any(target_os = "linux", target_os = "macos"))))]
pub(crate) fn write_secret_bytes_unix(path: &std::path::Path, secret: &[u8]) -> Result<(), String> {
    require_durable_secret_write(write_secret_bytes_unix_with_force(path, secret, true)?)
}

#[cfg(not(all(unix, any(target_os = "linux", target_os = "macos"))))]
pub(crate) fn write_secret_bytes_unix_with_force(
    path: &std::path::Path,
    secret: &[u8],
    force: bool,
) -> Result<SecretWriteCompletionV1, String> {
    let _ = (path, secret, force);
    Err("secret generation is production-supported only on Linux and macOS".to_owned())
}

/// Read an exact-size secret without following symlinks or accepting
/// group/world-readable files.
pub(crate) fn read_secret_bytes<const N: usize>(path: &std::path::Path) -> Result<[u8; N], String> {
    #[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
    {
        use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};

        let (parent, file_name, _parent_path) = open_existing_secret_parent_v1(path)?;
        let fd = rustix_fs::openat(
            &parent,
            &file_name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("read {}: {}", path.display(), e))?;
        let stat =
            rustix_fs::fstat(&fd).map_err(|e| format!("inspect open {}: {}", path.display(), e))?;
        let permissions = stat.st_mode & 0o777;
        if !FileType::from_raw_mode(stat.st_mode).is_file()
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_nlink != 1
            || (permissions != 0o600 && permissions != 0o400)
            || stat.st_size != N as i64
        {
            return Err(format!(
                "{}: secret must be a single-link {N}-byte regular file owned by this user with mode 0600/0400",
                path.display()
            ));
        }
        reject_extended_acl_v1(&fd, &format!("secret file {}", path.display()))?;
        let mut file = std::fs::File::from(fd);
        let mut secret = [0u8; N];
        if let Err(error) = file.read_exact(&mut secret) {
            secret.zeroize();
            return Err(format!("read {}: {}", path.display(), error));
        }
        let mut extra = [0u8; 1];
        match file.read(&mut extra) {
            Ok(0) => Ok(secret),
            Ok(_) => {
                secret.zeroize();
                Err(format!("{} changed while it was read", path.display()))
            }
            Err(error) => {
                secret.zeroize();
                Err(format!("read {}: {}", path.display(), error))
            }
        }
    }

    #[cfg(not(all(unix, any(target_os = "linux", target_os = "macos"))))]
    {
        let mut bytes =
            std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        if bytes.len() != N {
            bytes.zeroize();
            return Err(format!("{}: expected {N} secret bytes", path.display()));
        }
        let mut secret = [0u8; N];
        secret.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(secret)
    }
}

#[cfg(unix)]
fn write_secret_key(
    path: &std::path::Path,
    seed: &[u8; 32],
    force: bool,
) -> Result<SecretWriteCompletionV1, String> {
    write_secret_key_unix_with_force(path, seed, force)
}

#[cfg(not(unix))]
fn write_secret_key(
    path: &std::path::Path,
    seed: &[u8; 32],
    force: bool,
) -> Result<SecretWriteCompletionV1, String> {
    write_secret_key_unix_with_force(path, seed, force)
}

fn default_keyfile_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("bpir-admin").join("admin.key");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config/bpir-admin/admin.key");
    }
    PathBuf::from("./admin.key")
}

#[cfg(all(test, unix))]
pub(crate) fn private_tempdir_v1() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt as _;

    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

#[cfg(all(test, not(unix)))]
pub(crate) fn private_tempdir_v1() -> std::io::Result<tempfile::TempDir> {
    tempfile::tempdir()
}

/// Read a 32-byte secret key from `path`. Used by the upload command
/// to load the admin key. Validates length and existence.
pub fn read_secret_key(path: &std::path::Path) -> Result<SigningKey, String> {
    let mut seed = read_secret_bytes::<32>(path)?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

#[cfg(all(test, unix, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::private_tempdir_v1 as tempdir;
    use super::*;

    #[test]
    fn committed_ambiguity_has_a_dedicated_nonzero_exit_code() {
        assert_eq!(SecretWriteCompletionV1::Durable.exit_code(), 0);
        assert_eq!(
            SecretWriteCompletionV1::CommittedAmbiguous.exit_code(),
            COMMITTED_AMBIGUOUS_EXIT_CODE_V1
        );
        assert_ne!(COMMITTED_AMBIGUOUS_EXIT_CODE_V1, 0);
        assert_ne!(COMMITTED_AMBIGUOUS_EXIT_CODE_V1, 1);
    }

    #[test]
    fn keygen_writes_pubkey_matching_privkey() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k");
        run(KeygenArgs {
            out: Some(path.clone()),
            force: false,
        })
        .unwrap();

        let sk = read_secret_key(&path).unwrap();
        // Roundtripping: the file should contain the same seed we
        // generated, so the recovered pubkey is the matching one.
        let pk = sk.verifying_key().to_bytes();
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn keygen_refuses_to_overwrite_without_force() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k");
        run(KeygenArgs {
            out: Some(path.clone()),
            force: false,
        })
        .unwrap();
        let err = run(KeygenArgs {
            out: Some(path.clone()),
            force: false,
        })
        .unwrap_err();
        assert!(err.contains("already exists"), "got: {}", err);
    }

    #[test]
    fn keygen_with_force_replaces_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k");
        run(KeygenArgs {
            out: Some(path.clone()),
            force: false,
        })
        .unwrap();
        let sk1 = read_secret_key(&path).unwrap();
        run(KeygenArgs {
            out: Some(path.clone()),
            force: true,
        })
        .unwrap();
        let sk2 = read_secret_key(&path).unwrap();
        // Two distinct keys (extremely high probability)
        assert_ne!(
            sk1.verifying_key().to_bytes(),
            sk2.verifying_key().to_bytes()
        );
    }

    #[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn concurrent_no_force_writers_have_exactly_one_nontruncating_winner() {
        use std::sync::{Arc, Barrier};

        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("concurrent.key"));
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for byte in [0x31_u8, 0x72_u8] {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                write_secret_bytes_unix_with_force(&path, &[byte; 32], false).map(|_| byte)
            }));
        }
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|result| result.is_err()).count(), 1);
        let winner = outcomes.into_iter().find_map(Result::ok).unwrap();
        assert_eq!(std::fs::read(path.as_ref()).unwrap(), vec![winner; 32]);
    }

    #[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn forced_write_rejects_hardlink_before_truncating_either_name() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir().unwrap();
        let path = dir.path().join("original.key");
        let alias = dir.path().join("alias.key");
        std::fs::write(&path, [0x41_u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();

        let error = write_secret_bytes_unix_with_force(&path, &[0x99_u8; 32], true)
            .expect_err("hard-linked production key must be rejected");
        assert!(error.contains("single-link"), "unexpected error: {error}");
        assert_eq!(std::fs::read(&path).unwrap(), vec![0x41_u8; 32]);
        assert_eq!(std::fs::read(&alias).unwrap(), vec![0x41_u8; 32]);
    }

    #[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn forced_write_atomically_replaces_the_inode_and_leaves_no_temporary() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = tempdir().unwrap();
        let path = dir.path().join("rotation.key");
        std::fs::write(&path, [0x21_u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let original_inode = std::fs::metadata(&path).unwrap().ino();

        write_secret_bytes_unix_with_force(&path, &[0xa4_u8; 32], true).unwrap();

        let replacement = std::fs::metadata(&path).unwrap();
        assert_ne!(replacement.ino(), original_inode);
        assert_eq!(replacement.mode() & 0o777, 0o600);
        assert_eq!(replacement.nlink(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), vec![0xa4_u8; 32]);
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("rotation.key")]);
    }

    #[test]
    fn nested_secret_parents_are_created_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir().unwrap();
        let first = dir.path().join("first");
        let second = first.join("second");
        let path = second.join("key");
        write_secret_bytes_unix_with_force(&path, &[0x2a_u8; 32], false).unwrap();

        assert_eq!(
            std::fs::metadata(&first).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&second).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn intermediate_symlink_is_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let dir = tempdir().unwrap();
        let actual = dir.path().join("actual");
        std::fs::create_dir(&actual).unwrap();
        std::fs::set_permissions(&actual, std::fs::Permissions::from_mode(0o700)).unwrap();
        let redirect = dir.path().join("redirect");
        symlink(&actual, &redirect).unwrap();

        let error =
            write_secret_bytes_unix_with_force(&redirect.join("key"), &[0x7c_u8; 32], false)
                .expect_err("intermediate symlink must not be followed");
        assert!(
            error.contains("without following symlinks"),
            "unexpected error: {error}"
        );
        assert!(!actual.join("key").exists());
    }

    #[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn bare_secret_name_uses_the_open_current_directory() {
        assert_eq!(
            secret_parent(std::path::Path::new("bare.key")),
            std::path::Path::new(".")
        );
    }

    #[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn forced_write_rejects_a_fifo_without_waiting_for_a_writer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fifo.key");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("POSIX mkfifo must be available for this Unix-only test");
        assert!(status.success());

        let error = write_secret_bytes_unix_with_force(&path, &[0x55_u8; 32], true)
            .expect_err("FIFO must be rejected before any blocking open");
        assert!(error.contains("regular file"), "unexpected error: {error}");
    }

    #[test]
    fn secret_reader_rejects_a_fifo_without_waiting_for_a_writer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fifo.key");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("POSIX mkfifo must be available for this Unix-only test");
        assert!(status.success());

        let error = read_secret_bytes::<32>(&path)
            .expect_err("nonblocking reader must reject a FIFO immediately");
        assert!(error.contains("regular file"), "unexpected error: {error}");
    }

    #[test]
    fn secret_reader_rejects_hardlinked_keys() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir().unwrap();
        let path = dir.path().join("key");
        let alias = dir.path().join("alias");
        std::fs::write(&path, [0x19_u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();

        let error = read_secret_bytes::<32>(&path).expect_err("hardlink alias must be rejected");
        assert!(error.contains("single-link"), "unexpected error: {error}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_only_accepts_byte_exact_fixed_root_aliases() {
        use std::ffi::OsStr;

        assert!(macos_system_root_alias_is_byte_exact_v1(
            OsStr::new("var"),
            std::path::Path::new("private/var")
        ));
        assert!(macos_system_root_alias_is_byte_exact_v1(
            OsStr::new("tmp"),
            std::path::Path::new("private/tmp")
        ));
        assert!(macos_system_root_alias_is_byte_exact_v1(
            OsStr::new("etc"),
            std::path::Path::new("private/etc")
        ));
        assert!(!macos_system_root_alias_is_byte_exact_v1(
            OsStr::new("var"),
            std::path::Path::new("/private/var")
        ));
        assert!(!macos_system_root_alias_is_byte_exact_v1(
            OsStr::new("var"),
            std::path::Path::new("private/../private/var")
        ));
        assert!(!macos_system_root_alias_is_byte_exact_v1(
            OsStr::new("other"),
            std::path::Path::new("private/var")
        ));

        assert_eq!(
            normalize_macos_system_root_alias_v1(std::path::Path::new("/var/example")).unwrap(),
            std::path::Path::new("/private/var/example")
        );
    }

    #[cfg(target_os = "macos")]
    fn add_macos_acl(path: &std::path::Path, entry: &str) {
        let status = std::process::Command::new("chmod")
            .arg("+a")
            .arg(entry)
            .arg(path)
            .status()
            .expect("macOS chmod must be available");
        assert!(status.success(), "failed to add test ACL: {entry}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_parent_extended_acl_is_rejected() {
        let dir = tempdir().unwrap();
        add_macos_acl(
            dir.path(),
            "everyone allow list,search,add_file,delete_child",
        );

        let error = prepare_secret_key_parent(&dir.path().join("key"))
            .expect_err("parent ACL must fail closed");
        assert!(error.contains("extended ACL"), "unexpected error: {error}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_acl_reader_only_treats_enoent_as_no_acl() {
        let error = macos_extended_acl_has_entries_v1(-1)
            .expect_err("an invalid descriptor must fail closed instead of looking ACL-free");
        assert!(
            error.contains("read macOS extended ACL"),
            "unexpected error: {error}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_temporary_acl_is_cleared_and_reverified_before_use() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir().unwrap();
        let path = dir.path().join("temporary");
        std::fs::write(&path, []).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        add_macos_acl(&path, "everyone allow read");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        reject_extended_acl_v1(&file, "test temporary")
            .expect_err("test setup must install an ACL");
        clear_extended_acl_v1(&file, "test temporary").unwrap();
        reject_extended_acl_v1(&file, "test temporary").unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reader_rejects_key_acl() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, [0x51_u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        add_macos_acl(&path, "everyone allow read");

        let error = read_secret_bytes::<32>(&path).expect_err("key ACL must fail closed");
        assert!(error.contains("extended ACL"), "unexpected error: {error}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_forced_rotation_rejects_existing_key_acl_as_incident() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, [0x52_u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        add_macos_acl(&path, "everyone allow read");

        let error = write_secret_bytes_unix_with_force(&path, &[0x53_u8; 32], true)
            .expect_err("forced rotation must not silently remediate an exposed key");
        assert!(error.contains("extended ACL"), "unexpected error: {error}");
        assert_eq!(std::fs::read(&path).unwrap(), vec![0x52_u8; 32]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forced_write_accepts_a_non_utf8_unix_file_name() {
        use std::os::unix::ffi::OsStringExt as _;

        let dir = tempdir().unwrap();
        let path = dir
            .path()
            .join(std::ffi::OsString::from_vec(vec![b'k', b'e', b'y', 0xff]));
        write_secret_bytes_unix_with_force(&path, &[0x18_u8; 32], false).unwrap();
        write_secret_bytes_unix_with_force(&path, &[0x81_u8; 32], true).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), vec![0x81_u8; 32]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rejected_non_utf8_target_leaves_no_private_temporary() {
        use std::os::unix::ffi::OsStringExt as _;

        let dir = tempdir().unwrap();
        let path = dir
            .path()
            .join(std::ffi::OsString::from_vec(vec![b'k', b'e', b'y', 0xff]));
        write_secret_bytes_unix_with_force(&path, &[0x18_u8; 32], false)
            .expect_err("the native macOS filesystem rejects this target name");
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn read_secret_key_rejects_wrong_length() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad");
        std::fs::write(&path, b"too short").unwrap();
        let err = read_secret_key(&path).unwrap_err();
        assert!(err.contains("32-byte"), "got: {}", err);
    }
}
