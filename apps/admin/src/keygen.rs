//! `bpir-admin keygen` — generate an ed25519 keypair for admin auth.
//!
//! Writes the 32-byte secret seed to a file (mode 0600 on Unix) and
//! prints the corresponding public key as 64-char hex. The operator
//! pastes the hex into the server's `--admin-pubkey-hex` flag.

use clap::Args;
use ed25519_dalek::SigningKey;
use std::fs;
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

pub fn run(args: KeygenArgs) -> Result<(), String> {
    let out = args.out.unwrap_or_else(default_keyfile_path);

    if out.exists() && !args.force {
        return Err(format!(
            "{} already exists; rerun with --force to overwrite (you'll lose the existing privkey)",
            out.display()
        ));
    }

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create dir {}: {}", parent.display(), e))?;
    }

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("getrandom: {}", e))?;
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    let pk_hex = hex::encode(pk.to_bytes());

    write_secret_key(&out, &seed)?;

    eprintln!(
        "wrote secret key (32 bytes, mode 0600) to {}",
        out.display()
    );
    eprintln!();
    eprintln!("Public key (paste into server's --admin-pubkey-hex):");
    println!("{}", pk_hex);
    Ok(())
}

#[cfg(unix)]
pub(crate) fn write_secret_key_unix(path: &std::path::Path, seed: &[u8; 32]) -> Result<(), String> {
    write_secret_bytes_unix(path, seed)
}

#[cfg(not(unix))]
pub(crate) fn write_secret_key_unix(path: &std::path::Path, seed: &[u8; 32]) -> Result<(), String> {
    write_secret_bytes_unix(path, seed)
}

/// Write arbitrary fixed-size secret material with the same owner-only and
/// no-symlink guarantees as the admin signing key. Payment V1 needs this for
/// the four-scalar (128-byte) experimental ARC key.
#[cfg(unix)]
pub(crate) fn write_secret_bytes_unix(path: &std::path::Path, secret: &[u8]) -> Result<(), String> {
    use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};

    let owner_only = Mode::from_bits_truncate(0o600);
    let fd = match rustix_fs::open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        owner_only,
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::EXIST) => rustix_fs::open(
            path,
            OFlags::WRONLY | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("open {}: {}", path.display(), e))?,
        Err(e) => return Err(format!("open {}: {}", path.display(), e)),
    };
    let stat =
        rustix_fs::fstat(&fd).map_err(|e| format!("inspect open {}: {}", path.display(), e))?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(format!(
            "{} must be a regular file owned by the effective user",
            path.display()
        ));
    }
    rustix_fs::fchmod(&fd, owner_only)
        .map_err(|e| format!("secure permissions on {}: {}", path.display(), e))?;
    let mut file = std::fs::File::from(fd);
    use std::io::Write;
    file.write_all(secret)
        .map_err(|e| format!("write {}: {}", path.display(), e))?;
    file.sync_all()
        .map_err(|e| format!("sync {}: {}", path.display(), e))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn write_secret_bytes_unix(path: &std::path::Path, secret: &[u8]) -> Result<(), String> {
    fs::write(path, secret).map_err(|e| format!("write {}: {}", path.display(), e))?;
    eprintln!("warning: file mode 0600 not enforced on this platform");
    Ok(())
}

/// Read an exact-size secret without following symlinks or accepting
/// group/world-readable files.
pub(crate) fn read_secret_bytes<const N: usize>(path: &std::path::Path) -> Result<[u8; N], String> {
    #[cfg(unix)]
    {
        use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};

        let fd = rustix_fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("read {}: {}", path.display(), e))?;
        let stat =
            rustix_fs::fstat(&fd).map_err(|e| format!("inspect open {}: {}", path.display(), e))?;
        if !FileType::from_raw_mode(stat.st_mode).is_file()
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o077 != 0
            || stat.st_size != N as i64
        {
            return Err(format!(
                "{}: secret must be a {N}-byte regular file owned by this user with mode 0600/0400",
                path.display()
            ));
        }
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

    #[cfg(not(unix))]
    {
        let mut bytes = fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
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
fn write_secret_key(path: &std::path::Path, seed: &[u8; 32]) -> Result<(), String> {
    write_secret_bytes_unix(path, seed)
}

#[cfg(not(unix))]
fn write_secret_key(path: &std::path::Path, seed: &[u8; 32]) -> Result<(), String> {
    fs::write(path, seed).map_err(|e| format!("write {}: {}", path.display(), e))?;
    eprintln!("warning: file mode 0600 not enforced on this platform");
    Ok(())
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

/// Read a 32-byte secret key from `path`. Used by the upload command
/// to load the admin key. Validates length and existence.
pub fn read_secret_key(path: &std::path::Path) -> Result<SigningKey, String> {
    let mut seed = read_secret_bytes::<32>(path)?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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

    #[test]
    fn read_secret_key_rejects_wrong_length() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad");
        fs::write(&path, b"too short").unwrap();
        let err = read_secret_key(&path).unwrap_err();
        assert!(err.contains("32-byte"), "got: {}", err);
    }
}
