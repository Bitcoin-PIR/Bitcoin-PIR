//! `bpir-admin sign-identity` — operator signs an IdentityCert.
//!
//! Runs OFFLINE on the operator's workstation. Reads the operator's
//! long-term Ed25519 secret key from disk, takes the server's
//! identity_pubkey (hex) + server_id + validity window as inputs, and
//! produces a canonically-encoded [`pir_identity::IdentityCert`] blob.
//!
//! The blob is then deployed to the server (path passed to
//! unified_server via `--identity-cert-path`) alongside the matching
//! server-identity key file (`--identity-key-path`).
//!
//! [HUMAN-decided 2026-05-21] No default validity window: the operator
//! MUST pass `--valid-until` explicitly. Pass `0` for an indefinite
//! upper bound if you actually want that.

use clap::Args;
use pir_identity::sign_identity_cert;
use std::fs;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct SignIdentityArgs {
    /// Path to the operator's Ed25519 secret key (raw 32-byte seed,
    /// from `bpir-admin keygen`).
    #[arg(long)]
    pub operator_key_path: PathBuf,

    /// Server identifier this cert is endorsed for, e.g. "pir1" or
    /// "pir2". MUST match the value the server will start with via
    /// `--identity-server-id`.
    #[arg(long)]
    pub server_id: String,

    /// Hex-encoded (64 chars / 32 bytes) Ed25519 public key of the
    /// server's identity keypair (from `bpir-admin keygen`'s stdout).
    #[arg(long)]
    pub identity_pubkey_hex: String,

    /// Earliest unix-seconds timestamp at which the cert is valid.
    /// Default 0 (no lower bound).
    #[arg(long, default_value_t = 0)]
    pub valid_from: i64,

    /// Latest unix-seconds timestamp at which the cert is valid.
    /// REQUIRED — the operator MUST think about cert expiry. Pass
    /// 0 for "no upper bound" (indefinite), but that's a deliberate
    /// choice, not a default.
    #[arg(long)]
    pub valid_until: i64,

    /// Write the encoded cert to this path. Default:
    /// `./<server_id>.cert`.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(args: SignIdentityArgs) -> Result<(), String> {
    let operator_sk = crate::keygen::read_secret_key(&args.operator_key_path)?;
    let mut identity_pubkey = [0u8; 32];
    hex::decode_to_slice(args.identity_pubkey_hex.trim(), &mut identity_pubkey)
        .map_err(|e| format!("--identity-pubkey-hex: {e}"))?;

    let encoded = sign_identity_cert(
        &operator_sk,
        &args.server_id,
        identity_pubkey,
        args.valid_from,
        args.valid_until,
    )
    .encode();

    let out = args
        .out
        .unwrap_or_else(|| PathBuf::from(format!("{}.cert", args.server_id)));
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create dir {}: {}", parent.display(), e))?;
        }
    }
    fs::write(&out, &encoded).map_err(|e| format!("write {}: {}", out.display(), e))?;

    let op_pk = operator_sk.verifying_key().to_bytes();
    eprintln!(
        "wrote IdentityCert ({} bytes) to {}",
        encoded.len(),
        out.display()
    );
    eprintln!("  server_id:        {}", args.server_id);
    eprintln!("  identity_pubkey:  {}", hex::encode(identity_pubkey));
    eprintln!("  operator_pubkey:  {}", hex::encode(op_pk));
    eprintln!("  valid_from:       {}", args.valid_from);
    eprintln!(
        "  valid_until:      {}{}",
        args.valid_until,
        if args.valid_until == 0 {
            " (indefinite)"
        } else {
            ""
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen;
    use ed25519_dalek::SigningKey;
    use pir_identity::IdentityCert;
    use tempfile::tempdir;

    fn write_op_key(dir: &std::path::Path) -> (PathBuf, SigningKey) {
        let path = dir.join("op.key");
        keygen::run(keygen::KeygenArgs {
            out: Some(path.clone()),
            force: false,
        })
        .unwrap();
        let sk = keygen::read_secret_key(&path).unwrap();
        (path, sk)
    }

    fn id_pubkey_hex(seed: u8) -> ([u8; 32], String) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (pk, hex::encode(pk))
    }

    #[test]
    fn sign_identity_produces_verifiable_cert() {
        let dir = tempdir().unwrap();
        let (op_key_path, op_sk) = write_op_key(dir.path());
        let (_id_pk, id_pk_hex) = id_pubkey_hex(0x42);
        let cert_path = dir.path().join("pir1.cert");

        run(SignIdentityArgs {
            operator_key_path: op_key_path,
            server_id: "pir1".into(),
            identity_pubkey_hex: id_pk_hex,
            valid_from: 0,
            valid_until: 1_900_000_000,
            out: Some(cert_path.clone()),
        })
        .unwrap();

        let bytes = fs::read(&cert_path).unwrap();
        let cert = IdentityCert::decode(&bytes).unwrap();
        cert.verify().unwrap();
        assert_eq!(cert.operator_pubkey, op_sk.verifying_key().to_bytes());
        assert_eq!(cert.server_id, "pir1");
        assert_eq!(cert.valid_until, 1_900_000_000);
    }
}
