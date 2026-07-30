//! Shared fail-closed filesystem boundary for production secrets and stores.
//!
//! Linux V1 deliberately enforces DAC owner/mode rules only. macOS V1 also
//! rejects extended ACLs, because an inherited ACL can make a mode-0600 file
//! readable by another local principal. All target operations are relative to
//! a component-by-component `O_NOFOLLOW` parent walk. Existing targets are
//! opened with `O_NONBLOCK` before their type is inspected, so a FIFO cannot
//! block startup.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateFileModeV1 {
    /// Mutable state, including every SQLite main database.
    ReadWrite,
    /// Immutable secrets/configuration may be mode 0400 or 0600.
    ReadOnlyOrReadWrite,
}

impl PrivateFileModeV1 {
    fn accepts(self, mode: u32) -> bool {
        match self {
            Self::ReadWrite => mode == 0o600,
            Self::ReadOnlyOrReadWrite => mode == 0o600 || mode == 0o400,
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::ReadWrite => "0600",
            Self::ReadOnlyOrReadWrite => "0600/0400",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateFileIdentityV1 {
    pub device: u128,
    pub inode: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedPrivateFileV1 {
    path: PathBuf,
    identity: PrivateFileIdentityV1,
}

impl CheckedPrivateFileV1 {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn identity(&self) -> PrivateFileIdentityV1 {
        self.identity
    }
}

#[derive(Debug)]
struct PrivateTargetV1 {
    parent: File,
    file_name: OsString,
    path: PathBuf,
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn target_v1(
    path: &Path,
    create_missing_parent: bool,
    label: &str,
) -> Result<PrivateTargetV1, String> {
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| format!("{label} must name a file: {}", path.display()))?
        .to_os_string();
    let configured_parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let absolute_parent = if configured_parent.is_absolute() {
        configured_parent.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("resolve current directory for {label}: {error}"))?
            .join(configured_parent)
    };
    let walked_parent = normalize_macos_system_root_alias_v1(&absolute_parent)?;
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    let root = rustix::fs::open("/", flags, rustix::fs::Mode::empty())
        .map_err(|error| format!("open filesystem root for {label}: {error}"))?;
    let mut current = File::from(root);
    let mut opened_path = PathBuf::from("/");
    validate_trusted_ancestor_fd_v1(&current, &opened_path, label)?;
    for component in walked_parent.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir => {
                return Err(format!(
                    "{label} path must not contain '..': {}",
                    path.display()
                ));
            }
            Component::Prefix(_) => {
                return Err(format!("{label} has an unsupported path prefix"));
            }
        };
        let mut created = false;
        let next = match rustix::fs::openat(&current, name, flags, rustix::fs::Mode::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) if create_missing_parent => {
                match rustix::fs::mkdirat(
                    &current,
                    name,
                    rustix::fs::Mode::from_bits_truncate(0o700),
                ) {
                    Ok(()) => {
                        created = true;
                        current.sync_all().map_err(|error| {
                            format!("sync parent after creating {label} directory: {error}")
                        })?;
                    }
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => {
                        return Err(format!(
                            "create {label} directory component failed: {error}"
                        ));
                    }
                }
                rustix::fs::openat(&current, name, flags, rustix::fs::Mode::empty()).map_err(
                    |error| format!("open newly created {label} directory failed: {error}"),
                )?
            }
            Err(error) => {
                return Err(format!(
                    "open {label} parent component without following symlinks failed: {error}"
                ));
            }
        };
        current = File::from(next);
        opened_path.push(name);
        if created {
            rustix::fs::fchmod(&current, rustix::fs::Mode::from_bits_truncate(0o700))
                .map_err(|error| format!("secure new {label} directory failed: {error}"))?;
            clear_extended_acl_v1(&current, &format!("new {label} directory"))?;
        }
        validate_trusted_ancestor_fd_v1(&current, &opened_path, label)?;
    }
    validate_private_parent_fd_v1(&current, &opened_path, label)?;
    Ok(PrivateTargetV1 {
        parent: current,
        file_name,
        path: opened_path.join(path.file_name().expect("validated filename")),
    })
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn validate_trusted_ancestor_fd_v1(
    directory: &File,
    path: &Path,
    label: &str,
) -> Result<(), String> {
    let stat = rustix::fs::fstat(directory)
        .map_err(|error| format!("inspect {label} ancestor {}: {error}", path.display()))?;
    let euid = rustix::process::geteuid().as_raw();
    let permissions = (stat.st_mode & 0o7777) as u32;
    let root_owned_sticky =
        stat.st_uid == 0 && permissions & 0o1000 != 0 && permissions & 0o022 != 0;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir()
        || (stat.st_uid != 0 && stat.st_uid != euid)
        || (permissions & 0o022 != 0 && !root_owned_sticky)
    {
        return Err(format!(
            "{label} ancestor must be root/effective-user owned and not group/world writable (except a root-owned sticky directory): {}",
            path.display()
        ));
    }
    reject_ancestor_acl_grants_v1(directory, &format!("{label} ancestor {}", path.display()))
}

#[cfg(not(all(unix, any(target_os = "linux", target_os = "macos"))))]
fn target_v1(
    _path: &Path,
    _create_missing_parent: bool,
    label: &str,
) -> Result<PrivateTargetV1, String> {
    Err(format!(
        "{label} private-file operations require Linux or macOS"
    ))
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn validate_private_parent_fd_v1(parent: &File, path: &Path, label: &str) -> Result<(), String> {
    let stat = rustix::fs::fstat(parent)
        .map_err(|error| format!("inspect {label} parent {}: {error}", path.display()))?;
    let permissions = (stat.st_mode & 0o7777) as u32;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || permissions != 0o700
    {
        return Err(format!(
            "{label} parent must be a real effective-user-owned mode-0700 directory: {}",
            path.display()
        ));
    }
    reject_extended_acl_v1(parent, &format!("{label} parent {}", path.display()))
}

pub fn prepare_private_parent_v1(
    path: &Path,
    create_missing: bool,
    label: &str,
) -> Result<PathBuf, String> {
    Ok(target_v1(path, create_missing, label)?.path)
}

/// Validate the parent of a local Unix-domain socket without forcing the
/// caller and socket daemon to share one UID.
///
/// Same-UID deployments require an effective-user-owned mode-0700 final
/// parent. Cross-UID deployments require an explicit trusted group and an
/// exact owner/group mode-0710 parent: the client may traverse to the socket,
/// but cannot list or replace names in that directory. Every ancestor is
/// opened component-by-component with `O_NOFOLLOW`; only root, the effective
/// user, or the expected daemon owner may own an ancestor, and writable
/// ancestors fail closed except for a root-owned sticky public directory.
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
pub fn prepare_private_unix_socket_parent_v1(
    path: &Path,
    expected_owner_uid: u32,
    expected_group_gid: Option<u32>,
    label: &str,
) -> Result<PathBuf, String> {
    prepare_private_service_parent_v1(
        path,
        expected_owner_uid,
        PrivateServiceParentPolicyV1::UnixSocket { expected_group_gid },
        label,
    )
}

/// Validate the parent of a cross-UID, group-readable private file.
///
/// The final parent must be owned by the expected daemon UID and trusted
/// reader GID with exact mode 2710. The setgid bit is mandatory so a daemon
/// that deliberately does not hold the reader group still creates the file
/// with that group. As with the Unix-socket validator, every component is
/// opened with `O_NOFOLLOW` and writable or untrusted ancestors fail closed.
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
pub fn prepare_private_setgid_group_file_parent_v1(
    path: &Path,
    expected_owner_uid: u32,
    expected_group_gid: u32,
    label: &str,
) -> Result<PathBuf, String> {
    prepare_private_service_parent_v1(
        path,
        expected_owner_uid,
        PrivateServiceParentPolicyV1::SetgidGroupFile { expected_group_gid },
        label,
    )
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
#[derive(Clone, Copy)]
enum PrivateServiceParentPolicyV1 {
    UnixSocket { expected_group_gid: Option<u32> },
    SetgidGroupFile { expected_group_gid: u32 },
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn prepare_private_service_parent_v1(
    path: &Path,
    expected_owner_uid: u32,
    policy: PrivateServiceParentPolicyV1,
    label: &str,
) -> Result<PathBuf, String> {
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| format!("{label} must name a protected entry: {}", path.display()))?
        .to_os_string();
    let configured_parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let absolute_parent = if configured_parent.is_absolute() {
        configured_parent.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("resolve current directory for {label}: {error}"))?
            .join(configured_parent)
    };
    let walked_parent = normalize_macos_system_root_alias_v1(&absolute_parent)?;
    let components: Vec<_> = walked_parent.components().collect();
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    let root = rustix::fs::open("/", flags, rustix::fs::Mode::empty())
        .map_err(|error| format!("open filesystem root for {label}: {error}"))?;
    let mut current = File::from(root);
    let mut opened_path = PathBuf::from("/");
    validate_socket_ancestor_fd_v1(&current, &opened_path, expected_owner_uid, label)?;

    let normal_count = components
        .iter()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    if normal_count == 0 {
        return Err(format!(
            "{label} socket parent must not be the filesystem root"
        ));
    }
    let mut normal_index = 0usize;
    for component in components {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir => {
                return Err(format!(
                    "{label} path must not contain '..': {}",
                    path.display()
                ));
            }
            Component::Prefix(_) => {
                return Err(format!("{label} has an unsupported path prefix"));
            }
        };
        normal_index += 1;
        let next = rustix::fs::openat(&current, name, flags, rustix::fs::Mode::empty()).map_err(
            |error| {
                format!("open {label} parent component without following symlinks failed: {error}")
            },
        )?;
        current = File::from(next);
        opened_path.push(name);
        if normal_index == normal_count {
            validate_socket_final_parent_fd_v1(
                &current,
                &opened_path,
                expected_owner_uid,
                policy,
                label,
            )?;
        } else {
            validate_socket_ancestor_fd_v1(&current, &opened_path, expected_owner_uid, label)?;
        }
    }
    Ok(opened_path.join(file_name))
}

#[cfg(not(all(unix, any(target_os = "linux", target_os = "macos"))))]
pub fn prepare_private_unix_socket_parent_v1(
    _path: &Path,
    _expected_owner_uid: u32,
    _expected_group_gid: Option<u32>,
    label: &str,
) -> Result<PathBuf, String> {
    Err(format!(
        "{label} protected Unix-socket operations require Linux or macOS"
    ))
}

#[cfg(not(all(unix, any(target_os = "linux", target_os = "macos"))))]
pub fn prepare_private_setgid_group_file_parent_v1(
    _path: &Path,
    _expected_owner_uid: u32,
    _expected_group_gid: u32,
    label: &str,
) -> Result<PathBuf, String> {
    Err(format!(
        "{label} protected group-file operations require Linux or macOS"
    ))
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn validate_socket_ancestor_fd_v1(
    directory: &File,
    path: &Path,
    expected_owner_uid: u32,
    label: &str,
) -> Result<(), String> {
    let stat = rustix::fs::fstat(directory)
        .map_err(|error| format!("inspect {label} ancestor {}: {error}", path.display()))?;
    let euid = rustix::process::geteuid().as_raw();
    let permissions = (stat.st_mode & 0o7777) as u32;
    let owner_is_trusted =
        stat.st_uid == 0 || stat.st_uid == euid || stat.st_uid == expected_owner_uid;
    let root_owned_sticky =
        stat.st_uid == 0 && permissions & 0o1000 != 0 && permissions & 0o022 != 0;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir()
        || !owner_is_trusted
        || (permissions & 0o022 != 0 && !root_owned_sticky)
    {
        return Err(format!(
            "{label} ancestor has an untrusted owner or writable namespace: {}",
            path.display()
        ));
    }
    reject_ancestor_acl_grants_v1(directory, &format!("{label} ancestor {}", path.display()))
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn validate_socket_final_parent_fd_v1(
    directory: &File,
    path: &Path,
    expected_owner_uid: u32,
    policy: PrivateServiceParentPolicyV1,
    label: &str,
) -> Result<(), String> {
    let stat = rustix::fs::fstat(directory)
        .map_err(|error| format!("inspect {label} final parent {}: {error}", path.display()))?;
    let euid = rustix::process::geteuid().as_raw();
    let permissions = (stat.st_mode & 0o7777) as u32;
    let valid_identity_and_mode = match policy {
        PrivateServiceParentPolicyV1::UnixSocket { .. } if expected_owner_uid == euid => {
            stat.st_uid == euid && permissions == 0o700
        }
        PrivateServiceParentPolicyV1::UnixSocket { expected_group_gid } => expected_group_gid
            .is_some_and(|gid| {
                stat.st_uid == expected_owner_uid && stat.st_gid == gid && permissions == 0o710
            }),
        PrivateServiceParentPolicyV1::SetgidGroupFile { expected_group_gid } => {
            expected_owner_uid != euid
                && stat.st_uid == expected_owner_uid
                && stat.st_gid == expected_group_gid
                && permissions == 0o2710
        }
    };
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir() || !valid_identity_and_mode {
        return Err(format!(
            "{label} final parent does not match its exact owner/group/mode policy: {}",
            path.display()
        ));
    }
    reject_extended_acl_v1(
        directory,
        &format!("{label} final parent {}", path.display()),
    )
}

pub fn prepare_new_private_file_v1(
    path: &Path,
    create_missing_parent: bool,
    label: &str,
) -> Result<PathBuf, String> {
    let target = target_v1(path, create_missing_parent, label)?;
    match rustix::fs::statat(
        &target.parent,
        &target.file_name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Err(rustix::io::Errno::NOENT) => Ok(target.path),
        Ok(_) => Err(format!("{label} already exists; refusing overwrite")),
        Err(error) => Err(format!("inspect {label} failed: {error}")),
    }
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn open_existing_v1(
    target: &PrivateTargetV1,
    mode: PrivateFileModeV1,
    label: &str,
) -> Result<(File, rustix::fs::Stat), String> {
    let fd = rustix::fs::openat(
        &target.parent,
        &target.file_name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| format!("open {label} {} safely: {error}", target.path.display()))?;
    let stat = rustix::fs::fstat(&fd)
        .map_err(|error| format!("inspect open {label} {}: {error}", target.path.display()))?;
    let permissions = stat.st_mode & 0o7777;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_nlink != 1
        || !mode.accepts(permissions as u32)
        || stat.st_size < 0
    {
        return Err(format!(
            "{label} must be a single-link regular file owned by the effective user with mode {}: {}",
            mode.description(),
            target.path.display()
        ));
    }
    reject_extended_acl_v1(&fd, &format!("{label} file {}", target.path.display()))?;
    Ok((File::from(fd), stat))
}

pub fn checked_existing_private_file_v1(
    path: &Path,
    mode: PrivateFileModeV1,
    label: &str,
) -> Result<CheckedPrivateFileV1, String> {
    let target = target_v1(path, false, label)?;
    let (_file, stat) = open_existing_v1(&target, mode, label)?;
    Ok(CheckedPrivateFileV1 {
        path: target.path,
        identity: PrivateFileIdentityV1 {
            device: stat.st_dev as u128,
            inode: stat.st_ino as u128,
        },
    })
}

pub fn read_private_file_bounded_v1(
    path: &Path,
    maximum: usize,
    mode: PrivateFileModeV1,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    read_private_file_bounded_with_identity_v1(path, maximum, mode, label).map(|(bytes, _)| bytes)
}

pub fn read_private_file_bounded_with_identity_v1(
    path: &Path,
    maximum: usize,
    mode: PrivateFileModeV1,
    label: &str,
) -> Result<(Zeroizing<Vec<u8>>, CheckedPrivateFileV1), String> {
    let target = target_v1(path, false, label)?;
    let (mut file, stat) = open_existing_v1(&target, mode, label)?;
    let size = usize::try_from(stat.st_size).map_err(|_| format!("{label} length is invalid"))?;
    if size > maximum {
        return Err(format!("{label} exceeds its {maximum}-byte bound"));
    }
    let mut bytes = Zeroizing::new(vec![0_u8; size]);
    if let Err(error) = file.read_exact(bytes.as_mut_slice()) {
        bytes.zeroize();
        return Err(format!("read {label} failed: {error}"));
    }
    let mut extra = Zeroizing::new([0_u8; 1]);
    let extra_len = file
        .read(extra.as_mut_slice())
        .map_err(|error| format!("finish reading {label} failed: {error}"))?;
    let after =
        rustix::fs::fstat(&file).map_err(|error| format!("reinspect {label} failed: {error}"))?;
    if extra_len != 0
        || after.st_dev != stat.st_dev
        || after.st_ino != stat.st_ino
        || after.st_uid != stat.st_uid
        || after.st_nlink != stat.st_nlink
        || after.st_mode != stat.st_mode
        || after.st_size != stat.st_size
    {
        return Err(format!("{label} changed while it was read"));
    }
    Ok((
        bytes,
        CheckedPrivateFileV1 {
            path: target.path,
            identity: PrivateFileIdentityV1 {
                device: stat.st_dev as u128,
                inode: stat.st_ino as u128,
            },
        },
    ))
}

pub fn read_exact_private_file_v1<const N: usize>(
    path: &Path,
    label: &str,
) -> Result<[u8; N], String> {
    let mut bytes =
        read_private_file_bounded_v1(path, N, PrivateFileModeV1::ReadOnlyOrReadWrite, label)?;
    if bytes.len() != N {
        return Err(format!("{label} must contain exactly {N} raw bytes"));
    }
    let mut exact = [0_u8; N];
    exact.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(exact)
}

fn create_new_at_target_v1(
    target: &PrivateTargetV1,
    label: &str,
) -> Result<(File, rustix::fs::Stat), String> {
    let fd = rustix::fs::openat(
        &target.parent,
        &target.file_name,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| format!("create {label} without replacement failed: {error}"))?;
    rustix::fs::fchmod(&fd, rustix::fs::Mode::from_bits_truncate(0o600))
        .map_err(|error| format!("secure new {label} failed: {error}"))?;
    // Must precede the first secret/state byte written by this process.
    clear_extended_acl_v1(&fd, &format!("new {label}"))?;
    let stat = rustix::fs::fstat(&fd).map_err(|error| format!("inspect new {label}: {error}"))?;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_size != 0
    {
        return Err(format!("new {label} failed private-file validation"));
    }
    Ok((File::from(fd), stat))
}

pub fn create_new_private_file_v1(path: &Path, label: &str) -> Result<File, String> {
    let target = target_v1(path, false, label)?;
    let (file, _) = create_new_at_target_v1(&target, label)?;
    // Persist the exact namespace entry through the same pinned parent used by
    // openat. Callers may add data later, but cannot receive a newly created
    // file whose directory entry has not first crossed this durability point.
    target
        .parent
        .sync_all()
        .map_err(|error| format!("sync new {label} parent failed: {error}"))?;
    Ok(file)
}

pub fn write_new_private_file_v1(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let target = target_v1(path, false, label)?;
    let (mut file, created) = create_new_at_target_v1(&target, label)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write and sync {label} failed: {error}"))?;
    let written =
        rustix::fs::fstat(&file).map_err(|error| format!("inspect written {label}: {error}"))?;
    if !rustix::fs::FileType::from_raw_mode(written.st_mode).is_file()
        || written.st_dev != created.st_dev
        || written.st_ino != created.st_ino
        || written.st_uid != created.st_uid
        || written.st_uid != rustix::process::geteuid().as_raw()
        || written.st_nlink != 1
        || written.st_mode & 0o7777 != 0o600
        || written.st_size as i128 != bytes.len() as i128
    {
        return Err(format!("written {label} failed private-file revalidation"));
    }
    target
        .parent
        .sync_all()
        .map_err(|error| format!("sync {label} parent failed: {error}"))
}

pub fn sync_private_file_and_parent_v1(path: &Path, label: &str) -> Result<(), String> {
    let target = target_v1(path, false, label)?;
    let (file, _) = open_existing_v1(&target, PrivateFileModeV1::ReadWrite, label)?;
    file.sync_all()
        .map_err(|error| format!("sync {label} failed: {error}"))?;
    target
        .parent
        .sync_all()
        .map_err(|error| format!("sync {label} parent failed: {error}"))
}

#[cfg(target_os = "macos")]
fn normalize_macos_system_root_alias_v1(path: &Path) -> Result<PathBuf, String> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;

    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Ok(path.to_path_buf());
    }
    let Some(Component::Normal(first)) = components.next() else {
        return Ok(path.to_path_buf());
    };
    let expected = if first == "var" {
        Path::new("private/var")
    } else if first == "tmp" {
        Path::new("private/tmp")
    } else if first == "etc" {
        Path::new("private/etc")
    } else {
        return Ok(path.to_path_buf());
    };
    let alias = Path::new("/").join(first);
    let metadata = std::fs::symlink_metadata(&alias)
        .map_err(|error| format!("inspect fixed macOS alias {}: {error}", alias.display()))?;
    let actual = std::fs::read_link(&alias)
        .map_err(|error| format!("read fixed macOS alias {}: {error}", alias.display()))?;
    if !metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || actual.as_os_str().as_bytes() != expected.as_os_str().as_bytes()
    {
        return Err(format!(
            "fixed macOS alias {} is not byte-exact",
            alias.display()
        ));
    }
    let mut normalized = PathBuf::from("/").join(expected);
    for component in components {
        normalized.push(component.as_os_str());
    }
    Ok(normalized)
}

#[cfg(not(target_os = "macos"))]
fn normalize_macos_system_root_alias_v1(path: &Path) -> Result<PathBuf, String> {
    Ok(path.to_path_buf())
}

#[cfg(target_os = "macos")]
mod macos_acl_v1 {
    use std::ffi::{c_char, c_int, c_void};

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
        pub(super) fn acl_to_text(acl: *mut c_void, length: *mut isize) -> *mut c_char;
        pub(super) fn acl_free(value: *mut c_void) -> c_int;
    }
}

#[cfg(target_os = "macos")]
fn reject_ancestor_acl_grants_v1<Fd: std::os::fd::AsRawFd>(
    fd: &Fd,
    description: &str,
) -> Result<(), String> {
    let acl = unsafe {
        // SAFETY: fd is live for the duration of this call.
        macos_acl_v1::acl_get_fd_np(fd.as_raw_fd(), macos_acl_v1::ACL_TYPE_EXTENDED)
    };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) {
            return Ok(());
        }
        return Err(format!("read macOS extended ACL on {description}: {error}"));
    }
    let _acl_guard = MacosAclGuardV1(acl);
    let mut length = 0_isize;
    let text = unsafe {
        // SAFETY: acl remains live and length is valid output storage.
        macos_acl_v1::acl_to_text(acl, &mut length)
    };
    if text.is_null() || length < 0 {
        return Err(format!(
            "render macOS extended ACL on {description}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let _text_guard = MacosAclGuardV1(text.cast());
    let bytes = unsafe {
        // SAFETY: acl_to_text returned `length` initialized bytes owned by the
        // text guard. We neither mutate nor outlive that allocation.
        std::slice::from_raw_parts(text.cast::<u8>(), length as usize)
    };
    // Darwin renders one ACE as
    // `tag:uuid:name:flags:allow[,inherit-flags]:permissions`. Do not search
    // for only `:allow:`: an inherited grant is rendered as
    // `:allow,file_inherit:` and was the original mode-0600 disclosure vector.
    let has_allow_entry = bytes.split(|byte| *byte == b'\n').any(|line| {
        line.split(|byte| *byte == b':')
            .nth(4)
            .and_then(|field| field.split(|byte| *byte == b',').next())
            == Some(b"allow".as_slice())
    });
    if has_allow_entry {
        return Err(format!(
            "{description} must not grant access through a macOS extended ACL"
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn reject_ancestor_acl_grants_v1<Fd: std::os::fd::AsRawFd>(
    fd: &Fd,
    description: &str,
) -> Result<(), String> {
    let _ = (fd.as_raw_fd(), description);
    Ok(())
}

#[cfg(target_os = "macos")]
struct MacosAclGuardV1(*mut std::ffi::c_void);

#[cfg(target_os = "macos")]
impl Drop for MacosAclGuardV1 {
    fn drop(&mut self) {
        // SAFETY: this guard exclusively owns an ACL API allocation.
        unsafe {
            let _ = macos_acl_v1::acl_free(self.0);
        }
    }
}

#[cfg(target_os = "macos")]
pub fn reject_extended_acl_v1<Fd: std::os::fd::AsRawFd>(
    fd: &Fd,
    description: &str,
) -> Result<(), String> {
    let acl = unsafe {
        // SAFETY: fd is live for the duration of this call.
        macos_acl_v1::acl_get_fd_np(fd.as_raw_fd(), macos_acl_v1::ACL_TYPE_EXTENDED)
    };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) {
            return Ok(());
        }
        return Err(format!("read macOS extended ACL on {description}: {error}"));
    }
    let _guard = MacosAclGuardV1(acl);
    let mut entry = std::ptr::null_mut();
    let result = unsafe {
        // SAFETY: acl and the output pointer remain live for the call.
        macos_acl_v1::acl_get_entry(acl, macos_acl_v1::ACL_FIRST_ENTRY, &mut entry)
    };
    if result == 0 {
        Err(format!("{description} must not have a macOS extended ACL"))
    } else {
        Err(format!(
            "enumerate macOS extended ACL on {description}: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(target_os = "macos")]
pub fn clear_extended_acl_v1<Fd: std::os::fd::AsRawFd>(
    fd: &Fd,
    description: &str,
) -> Result<(), String> {
    let acl = unsafe {
        // SAFETY: acl_init returns an allocation owned by the guard below.
        macos_acl_v1::acl_init(1)
    };
    if acl.is_null() {
        return Err(format!(
            "allocate empty macOS ACL for {description}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let _guard = MacosAclGuardV1(acl);
    let result = unsafe {
        // SAFETY: fd is live and acl is a valid empty ACL.
        macos_acl_v1::acl_set_fd_np(fd.as_raw_fd(), acl, macos_acl_v1::ACL_TYPE_EXTENDED)
    };
    if result != 0 {
        return Err(format!(
            "clear macOS extended ACL on {description}: {}",
            std::io::Error::last_os_error()
        ));
    }
    reject_extended_acl_v1(fd, description)
}

// Linux V1 is explicitly DAC-only until a reviewed POSIX/NFS ACL parser is
// introduced. Keep the API identical so every caller documents this boundary.
#[cfg(not(target_os = "macos"))]
pub fn reject_extended_acl_v1<Fd: std::os::fd::AsRawFd>(
    fd: &Fd,
    description: &str,
) -> Result<(), String> {
    let _ = (fd.as_raw_fd(), description);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn clear_extended_acl_v1<Fd: std::os::fd::AsRawFd>(
    fd: &Fd,
    description: &str,
) -> Result<(), String> {
    let _ = (fd.as_raw_fd(), description);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn private_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn exact_read_accepts_0600_and_0400() {
        let directory = private_tempdir();
        let path = directory.path().join("secret");
        write_new_private_file_v1(&path, &[7_u8; 32], "test secret").unwrap();
        assert_eq!(
            read_exact_private_file_v1::<32>(&path, "test secret").unwrap(),
            [7_u8; 32]
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            read_exact_private_file_v1::<32>(&path, "test secret").unwrap(),
            [7_u8; 32]
        );
    }

    #[test]
    fn hardlink_and_public_mode_are_rejected() {
        let directory = private_tempdir();
        let path = directory.path().join("secret");
        write_new_private_file_v1(&path, &[1_u8; 32], "test secret").unwrap();
        let link = directory.path().join("hard");
        std::fs::hard_link(&path, &link).unwrap();
        assert!(read_exact_private_file_v1::<32>(&path, "test secret").is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_exact_private_file_v1::<32>(&path, "test secret").is_err());
    }

    #[test]
    fn symlinked_component_is_rejected() {
        let root = private_tempdir();
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let secret = real.join("secret");
        write_new_private_file_v1(&secret, &[2_u8; 32], "test secret").unwrap();
        assert!(read_exact_private_file_v1::<32>(&link.join("secret"), "test secret").is_err());
    }

    #[test]
    fn writable_nonsticky_ancestor_is_rejected() {
        let root = private_tempdir();
        let writable = root.path().join("writable");
        let private = writable.join("private");
        std::fs::create_dir(&writable).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            prepare_new_private_file_v1(&private.join("secret"), false, "test secret").is_err()
        );
    }

    #[test]
    fn unix_socket_parent_requires_exact_same_uid_mode_or_explicit_cross_uid_group() {
        let directory = private_tempdir();
        let path = directory.path().join("lightning-rpc");
        let euid = rustix::process::geteuid().as_raw();
        let checked =
            prepare_private_unix_socket_parent_v1(&path, euid, None, "test RPC socket").unwrap();
        assert_eq!(checked.file_name(), path.file_name());

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o710)).unwrap();
        assert!(
            prepare_private_unix_socket_parent_v1(&path, euid, None, "test RPC socket").is_err()
        );

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let another_uid = euid.checked_add(1).unwrap_or(euid.saturating_sub(1));
        assert_ne!(another_uid, euid);
        assert!(
            prepare_private_unix_socket_parent_v1(&path, another_uid, None, "test RPC socket")
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn setgid_group_file_creation_linux_child() {
        use rustix::process::{Gid, Uid};
        use std::io::Write as _;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        let Ok(path) = std::env::var("BPIR_SETGID_FILE_CHILD_PATH") else {
            return;
        };
        let uid = std::env::var("BPIR_SETGID_FILE_CHILD_UID")
            .unwrap()
            .parse::<u32>()
            .unwrap();
        let primary_gid = std::env::var("BPIR_SETGID_FILE_CHILD_PRIMARY_GID")
            .unwrap()
            .parse::<u32>()
            .unwrap();
        let inherited_gid = std::env::var("BPIR_SETGID_FILE_CHILD_INHERITED_GID")
            .unwrap()
            .parse::<u32>()
            .unwrap();

        rustix::thread::set_thread_groups(&[]).unwrap();
        rustix::thread::set_thread_gid(Gid::from_raw(primary_gid)).unwrap();
        rustix::thread::set_thread_uid(Uid::from_raw(uid)).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&path)
            .unwrap();
        file.write_all(
            b"__cookie__:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        file.sync_all().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.gid(), inherited_gid);
        assert_eq!(metadata.mode() & 0o7777, 0o640);
        assert_eq!(metadata.nlink(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn setgid_group_file_parent_requires_exact_cross_uid_2710_shape() {
        use rustix::fs::chown;
        use rustix::process::{Gid, Uid};
        use std::os::unix::fs::MetadataExt as _;
        use std::process::Command;

        if !rustix::process::geteuid().is_root() {
            return;
        }

        const OWNER_UID: u32 = 60_101;
        const READER_GID: u32 = 60_102;
        let directory = private_tempdir();
        chown(
            directory.path(),
            Some(Uid::from_raw(OWNER_UID)),
            Some(Gid::from_raw(READER_GID)),
        )
        .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o2710))
            .unwrap();
        let path = directory.path().join(".cookie");

        assert_eq!(
            prepare_private_setgid_group_file_parent_v1(
                &path,
                OWNER_UID,
                READER_GID,
                "test Core RPC cookie",
            )
            .unwrap()
            .file_name(),
            path.file_name()
        );

        const DAEMON_PRIMARY_GID: u32 = 60_103;
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::setgid_group_file_creation_linux_child")
            .arg("--nocapture")
            .env("BPIR_SETGID_FILE_CHILD_PATH", &path)
            .env("BPIR_SETGID_FILE_CHILD_UID", OWNER_UID.to_string())
            .env(
                "BPIR_SETGID_FILE_CHILD_PRIMARY_GID",
                DAEMON_PRIMARY_GID.to_string(),
            )
            .env(
                "BPIR_SETGID_FILE_CHILD_INHERITED_GID",
                READER_GID.to_string(),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "setgid child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let inherited = std::fs::metadata(&path).unwrap();
        assert_eq!(inherited.uid(), OWNER_UID);
        assert_eq!(inherited.gid(), READER_GID);
        assert_eq!(inherited.mode() & 0o7777, 0o640);
        assert_eq!(inherited.nlink(), 1);

        for mode in [0o710, 0o2700, 0o2711, 0o3710] {
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(mode))
                .unwrap();
            assert!(prepare_private_setgid_group_file_parent_v1(
                &path,
                OWNER_UID,
                READER_GID,
                "test Core RPC cookie",
            )
            .is_err());
        }

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o2710))
            .unwrap();
        assert!(prepare_private_setgid_group_file_parent_v1(
            &path,
            OWNER_UID + 1,
            READER_GID,
            "test Core RPC cookie",
        )
        .is_err());
        assert!(prepare_private_setgid_group_file_parent_v1(
            &path,
            OWNER_UID,
            READER_GID + 1,
            "test Core RPC cookie",
        )
        .is_err());
        assert!(prepare_private_setgid_group_file_parent_v1(
            &path,
            rustix::process::geteuid().as_raw(),
            READER_GID,
            "test Core RPC cookie",
        )
        .is_err());
    }

    #[test]
    fn special_permission_bits_are_rejected() {
        let directory = private_tempdir();
        let path = directory.path().join("secret");
        write_new_private_file_v1(&path, &[9_u8; 32], "test secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o4600)).unwrap();
        assert!(read_exact_private_file_v1::<32>(&path, "test secret").is_err());

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o1700))
            .unwrap();
        assert!(prepare_new_private_file_v1(
            &directory.path().join("second"),
            false,
            "test secret"
        )
        .is_err());
    }

    #[test]
    fn fifo_is_rejected_without_blocking() {
        use std::process::Command;

        let directory = private_tempdir();
        let fifo = directory.path().join("fifo");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        std::fs::set_permissions(&fifo, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_exact_private_file_v1::<32>(&fifo, "test secret").is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parent_acl_is_rejected_before_a_new_file_is_created() {
        use std::process::Command;

        let directory = private_tempdir();
        let status = Command::new("chmod")
            .args(["+a", "everyone allow read,file_inherit"])
            .arg(directory.path())
            .status()
            .unwrap();
        assert!(status.success());
        let path = directory.path().join("secret");
        assert!(write_new_private_file_v1(&path, &[3_u8; 32], "test secret").is_err());
        assert!(!path.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn nonfinal_ancestor_allow_acl_is_rejected() {
        use std::process::Command;

        let directory = private_tempdir();
        let ancestor = directory.path().join("ancestor");
        let private = ancestor.join("private");
        std::fs::create_dir(&ancestor).unwrap();
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&ancestor)
            .status()
            .unwrap()
            .success());

        assert!(
            prepare_new_private_file_v1(&private.join("secret"), false, "test secret").is_err()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn acl_clear_is_reverified_before_secret_bytes() {
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::process::Command;

        let directory = private_tempdir();
        let path = directory.path().join("temporary");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        assert!(Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .status()
            .unwrap()
            .success());
        assert!(reject_extended_acl_v1(&file, "test temporary").is_err());
        clear_extended_acl_v1(&file, "test temporary").unwrap();
        reject_extended_acl_v1(&file, "test temporary").unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn existing_acl_is_rejected() {
        use std::process::Command;

        let directory = private_tempdir();
        let path = directory.path().join("secret");
        write_new_private_file_v1(&path, &[4_u8; 32], "test secret").unwrap();
        let status = Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(read_exact_private_file_v1::<32>(&path, "test secret").is_err());
    }
}
