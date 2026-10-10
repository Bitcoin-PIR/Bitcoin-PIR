//! `bpir-admin keygen` — generate an Ed25519 keypair.
//!
//! Writes the 32-byte secret seed to a file (mode 0600) and prints the
//! public key as 64-char hex: for the server's `--admin-pubkey-hex`, a
//! server identity (`--identity-key-path`; the operator signs its pubkey
//! with `sign-identity`), or an operator key.

use clap::Args;
use ed25519_dalek::SigningKey;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
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

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|error| format!("getrandom: {error}"))?;
    let pk_hex = hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
    let write_result = write_secret_key(&out, &seed, args.force);
    seed.zeroize();
    write_result?;

    eprintln!(
        "wrote secret key (32 bytes, mode 0600) to {}",
        out.display()
    );
    eprintln!();
    eprintln!("Public key:");
    println!("{}", pk_hex);
    Ok(())
}

/// Write `secret` to `path` with mode 0600, creating missing parent
/// directories with mode 0700. Without `force` an existing file is kept.
pub(crate) fn write_secret_key(path: &Path, secret: &[u8], force: bool) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).mode(0o600);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "{} already exists; pass --force to overwrite it",
                path.display()
            )
        } else {
            format!("write {}: {error}", path.display())
        }
    })?;
    // An overwritten file keeps its old mode.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .and_then(|()| file.write_all(secret))
        .map_err(|error| format!("write {}: {error}", path.display()))
}

/// Read an exact-size secret.
pub(crate) fn read_secret_bytes<const N: usize>(path: &Path) -> Result<[u8; N], String> {
    let mut bytes =
        std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let secret = <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| format!("{}: expected a {N}-byte secret", path.display()));
    bytes.zeroize();
    secret
}

/// Read a 32-byte secret key from `path`.
pub fn read_secret_key(path: &Path) -> Result<SigningKey, String> {
    let mut seed = read_secret_bytes::<32>(path)?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

pub(crate) fn default_keyfile_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("bpir-admin").join("admin.key");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config/bpir-admin/admin.key");
    }
    PathBuf::from("./admin.key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_an_existing_key_unless_forced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/key");
        let run_once = |force| {
            run(KeygenArgs {
                out: Some(path.clone()),
                force,
            })
        };
        run_once(false).unwrap();
        let first = read_secret_bytes::<32>(&path).unwrap();
        assert!(run_once(false).unwrap_err().contains("already exists"));
        run_once(true).unwrap();
        assert_ne!(read_secret_bytes::<32>(&path).unwrap(), first);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
