//! Server-side admin authentication and (Slice 3b) DB upload state.
//!
//! ## Authentication (Slice 3a)
//!
//! Per-WebSocket-connection ed25519 challenge/response:
//!
//! 1. Client sends `REQ_ADMIN_AUTH_CHALLENGE`.
//! 2. Server generates a fresh 32-byte nonce, stashes it in
//!    [`AdminConnectionState::pending_challenge`], returns it.
//! 3. Client signs `ADMIN_AUTH_DOMAIN_TAG || nonce` with their
//!    ed25519 sk and sends `REQ_ADMIN_AUTH_RESPONSE { signature }`.
//! 4. Server calls [`AdminConnectionState::verify_response`] which
//!    consumes the pending challenge and verifies the signature
//!    against [`AdminConfig::admin_pubkey`]. On success the
//!    connection is marked authenticated for the rest of its
//!    lifetime; on failure the pending challenge is dropped (force
//!    re-issue).
//!
//! Disconnecting and reconnecting requires a fresh challenge — admin
//! state never persists across WebSocket lifetimes. This is the cheap
//! way to get session expiry without a clock.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashMap;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::manifest::{DbManifest, MANIFEST_FILENAME};
use crate::protocol::ADMIN_AUTH_DOMAIN_TAG;
use pir_core::merkle::{sha256, Hash256};

/// Server-wide admin config — loaded once at startup. Holds the
/// ed25519 public key the operator's `bpir-admin` CLI will sign with.
#[derive(Clone, Debug)]
pub struct AdminConfig {
    pub admin_pubkey: VerifyingKey,
}

impl AdminConfig {
    /// Parse an admin pubkey from a 64-character lowercase hex string
    /// (the on-the-wire representation of a 32-byte ed25519 pubkey).
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        if hex.len() != 64 {
            return Err(format!(
                "admin pubkey must be 64 hex chars (32 bytes), got {} chars",
                hex.len()
            ));
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            let byte_str = &hex[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(byte_str, 16)
                .map_err(|_| format!("invalid hex at byte {}: {:?}", i, byte_str))?;
        }
        let admin_pubkey = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| format!("invalid ed25519 pubkey bytes: {}", e))?;
        Ok(Self { admin_pubkey })
    }
}

/// Per-connection auth state. Created fresh for each WebSocket
/// accept; lives for the connection's lifetime.
#[derive(Default, Debug)]
pub struct AdminConnectionState {
    /// 32-byte nonce returned by the most recent
    /// `REQ_ADMIN_AUTH_CHALLENGE`. `None` if no challenge is
    /// outstanding (or if a response just consumed it).
    pub pending_challenge: Option<[u8; 32]>,
    /// `true` once a valid `REQ_ADMIN_AUTH_RESPONSE` has been
    /// processed. Stays true until the connection drops.
    pub authenticated: bool,
    /// In-progress uploads keyed by name. One entry per BEGIN that
    /// hasn't been ACTIVATEd or aborted yet. Concurrent uploads of
    /// different names from the same connection are allowed.
    pub uploads: HashMap<String, UploadState>,
}

/// State for one in-progress DB upload. Created on BEGIN, mutated by
/// CHUNK, validated on FINALIZE, consumed by ACTIVATE.
#[derive(Debug)]
pub struct UploadState {
    /// Operator-supplied name (also the staging-dir name).
    pub name: String,
    /// `data_root/.staging/<name>/` — absolute path.
    pub staging_dir: PathBuf,
    /// Parsed `MANIFEST.toml` listing expected files + hashes.
    pub manifest: DbManifest,
    /// Raw `MANIFEST.toml` bytes — kept so FINALIZE can hash them
    /// to produce the manifest_root.
    pub manifest_bytes: Vec<u8>,
}

impl AdminConnectionState {
    /// Generate and store a fresh challenge nonce. Returns the bytes
    /// to send to the client. Replaces any previously-pending
    /// challenge (forces the client to use the latest one).
    pub fn issue_challenge(&mut self) -> [u8; 32] {
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).expect("getrandom failed — kernel CSPRNG broken");
        self.pending_challenge = Some(nonce);
        nonce
    }

    /// Verify a client-supplied signature against the pending
    /// challenge and the server's configured admin pubkey.
    ///
    /// Always consumes the pending challenge (success or failure) so
    /// a failed attempt forces the client to request a new challenge
    /// — replays of the same signature against fresh challenges are
    /// impossible.
    pub fn verify_response(
        &mut self,
        signature: &[u8; 64],
        config: &AdminConfig,
    ) -> Result<(), AuthError> {
        let nonce = self.pending_challenge.take().ok_or(AuthError::NoChallenge)?;

        let mut signed_blob = Vec::with_capacity(ADMIN_AUTH_DOMAIN_TAG.len() + 32);
        signed_blob.extend_from_slice(ADMIN_AUTH_DOMAIN_TAG);
        signed_blob.extend_from_slice(&nonce);

        let sig = Signature::from_bytes(signature);
        config
            .admin_pubkey
            .verify(&signed_blob, &sig)
            .map_err(|_| AuthError::BadSignature)?;

        self.authenticated = true;
        Ok(())
    }
}

impl AdminConnectionState {
    /// Begin a new upload. Creates `data_root/.staging/<name>/`
    /// (clearing any prior contents from a failed attempt) and
    /// stores the parsed manifest.
    pub fn begin_upload(
        &mut self,
        name: String,
        manifest_toml: Vec<u8>,
        data_root: &Path,
    ) -> Result<(), UploadError> {
        validate_simple_name(&name).map_err(UploadError::InvalidName)?;
        let staging_dir = data_root.join(".staging").join(&name);

        // Parse the manifest before any disk side effects so a malformed
        // upload doesn't leave .staging detritus.
        let text = std::str::from_utf8(&manifest_toml)
            .map_err(|_| UploadError::InvalidManifest("not valid UTF-8".into()))?;
        let manifest: DbManifest = toml::from_str(text)
            .map_err(|e| UploadError::InvalidManifest(format!("toml parse: {}", e)))?;
        if manifest.manifest.version != crate::manifest::SUPPORTED_VERSION {
            return Err(UploadError::InvalidManifest(format!(
                "unsupported manifest version {} (expected {})",
                manifest.manifest.version,
                crate::manifest::SUPPORTED_VERSION
            )));
        }

        // Wipe any prior staging dir for this name (failed earlier upload).
        if staging_dir.exists() {
            fs::remove_dir_all(&staging_dir)
                .map_err(|e| UploadError::Io(format!("rm prior staging dir: {}", e)))?;
        }
        fs::create_dir_all(&staging_dir)
            .map_err(|e| UploadError::Io(format!("create staging dir: {}", e)))?;

        // Write MANIFEST.toml verbatim — it's part of the verification
        // surface and must hash to the same value as the bytes we received.
        fs::write(staging_dir.join(MANIFEST_FILENAME), &manifest_toml)
            .map_err(|e| UploadError::Io(format!("write MANIFEST.toml: {}", e)))?;

        self.uploads.insert(
            name.clone(),
            UploadState { name, staging_dir, manifest, manifest_bytes: manifest_toml },
        );
        Ok(())
    }

    /// Write a chunk of `data` at `offset` within `<staging>/<file_path>`.
    /// Validates that `file_path` is in the manifest and is path-safe.
    pub fn write_chunk(
        &mut self,
        name: &str,
        file_path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<(), UploadError> {
        let upload = self
            .uploads
            .get(name)
            .ok_or_else(|| UploadError::UnknownUpload(name.to_string()))?;
        if !upload.manifest.files.contains_key(file_path) {
            return Err(UploadError::FileNotInManifest(file_path.to_string()));
        }
        let safe_rel = validate_relative_path(file_path).map_err(UploadError::InvalidName)?;
        let target = upload.staging_dir.join(safe_rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| UploadError::Io(format!("create parent dir: {}", e)))?;
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&target)
            .map_err(|e| UploadError::Io(format!("open {}: {}", target.display(), e)))?;
        f.seek(SeekFrom::Start(offset))
            .map_err(|e| UploadError::Io(format!("seek: {}", e)))?;
        f.write_all(data)
            .map_err(|e| UploadError::Io(format!("write: {}", e)))?;
        Ok(())
    }

    /// Verify all staged files match the manifest. Returns the
    /// SHA-256 of `MANIFEST.toml` (the "manifest root").
    /// Leaves the upload state intact so a failed FINALIZE can be
    /// re-attempted with more chunks.
    pub fn finalize_upload(&self, name: &str) -> Result<Hash256, UploadError> {
        let upload = self
            .uploads
            .get(name)
            .ok_or_else(|| UploadError::UnknownUpload(name.to_string()))?;
        upload
            .manifest
            .verify_dir_contents(&upload.staging_dir)
            .map_err(|e| UploadError::Verification(e.to_string()))?;
        Ok(sha256(&upload.manifest_bytes))
    }

    /// Atomically rename `data_root/.staging/<name>/` →
    /// `data_root/<target_path>/`, with backup-and-rollback semantics.
    /// Removes the upload from the in-progress map on success.
    pub fn activate(
        &mut self,
        name: &str,
        target_path: &str,
        data_root: &Path,
    ) -> Result<(), UploadError> {
        let upload = self
            .uploads
            .get(name)
            .ok_or_else(|| UploadError::UnknownUpload(name.to_string()))?;
        let safe_target =
            validate_relative_path(target_path).map_err(UploadError::InvalidName)?;
        let target_abs = data_root.join(safe_target);
        if let Some(parent) = target_abs.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| UploadError::Io(format!("create target parent: {}", e)))?;
        }

        // If target exists, move it aside first so we can roll back if
        // the staging→target rename fails. Suffix with .old + ts to
        // make collisions on parallel activates impossible.
        let backup = if target_abs.exists() {
            let mut nonce = [0u8; 8];
            getrandom::getrandom(&mut nonce).expect("getrandom");
            let suffix: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
            let bak = target_abs.with_extension(format!("old.{}", suffix));
            fs::rename(&target_abs, &bak)
                .map_err(|e| UploadError::Io(format!("backup target: {}", e)))?;
            Some(bak)
        } else {
            None
        };

        // The actual atomic-ish move.
        match fs::rename(&upload.staging_dir, &target_abs) {
            Ok(()) => {
                // Drop the backup once the new dir is in place.
                if let Some(bak) = backup {
                    let _ = fs::remove_dir_all(&bak); // best-effort cleanup
                }
                self.uploads.remove(name);
                Ok(())
            }
            Err(e) => {
                // Try to roll back the backup.
                if let Some(bak) = backup {
                    let _ = fs::rename(&bak, &target_abs);
                }
                Err(UploadError::Io(format!("activate rename: {}", e)))
            }
        }
    }
}

/// Validate that a name is a single path segment with no `/` or
/// special chars — used for staging directory names.
fn validate_simple_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name is empty".into());
    }
    if name.len() > 128 {
        return Err(format!("name too long ({} > 128 bytes)", name.len()));
    }
    for c in name.chars() {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
            return Err(format!("name contains illegal char {:?}", c));
        }
    }
    if name == "." || name == ".." {
        return Err("name cannot be . or ..".into());
    }
    Ok(())
}

/// Validate a relative path that must stay inside its anchor dir.
/// Forbids `..`, leading `/`, and absolute paths. Returns the cleaned
/// `PathBuf` ready to join onto the anchor.
fn validate_relative_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("path is empty".into());
    }
    if path.starts_with('/') {
        return Err(format!("path must be relative: {:?}", path));
    }
    let p = PathBuf::from(path);
    for component in p.components() {
        use std::path::Component;
        match component {
            Component::Normal(_) => {}
            Component::CurDir => {}
            Component::ParentDir => return Err(format!("path contains ..: {:?}", path)),
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("absolute path not allowed: {:?}", path))
            }
        }
    }
    Ok(p)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    InvalidName(String),
    InvalidManifest(String),
    UnknownUpload(String),
    FileNotInManifest(String),
    Io(String),
    Verification(String),
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName(s) => write!(f, "invalid name/path: {}", s),
            Self::InvalidManifest(s) => write!(f, "invalid manifest: {}", s),
            Self::UnknownUpload(s) => write!(f, "no upload in progress for name {:?}", s),
            Self::FileNotInManifest(p) => write!(f, "file {:?} not listed in manifest", p),
            Self::Io(s) => write!(f, "io: {}", s),
            Self::Verification(s) => write!(f, "verification failed: {}", s),
        }
    }
}

impl std::error::Error for UploadError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Client sent REQ_ADMIN_AUTH_RESPONSE without first having a
    /// pending REQ_ADMIN_AUTH_CHALLENGE issued (or the previous
    /// challenge was already consumed).
    NoChallenge,
    /// Signature verification failed against the server's pubkey.
    BadSignature,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoChallenge => write!(f, "no pending challenge — call REQ_ADMIN_AUTH_CHALLENGE first"),
            Self::BadSignature => write!(f, "signature did not verify against admin pubkey"),
        }
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair() -> (SigningKey, AdminConfig) {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let cfg = AdminConfig {
            admin_pubkey: sk.verifying_key(),
        };
        (sk, cfg)
    }

    fn sign(sk: &SigningKey, nonce: &[u8; 32]) -> [u8; 64] {
        let mut blob = Vec::new();
        blob.extend_from_slice(ADMIN_AUTH_DOMAIN_TAG);
        blob.extend_from_slice(nonce);
        sk.sign(&blob).to_bytes()
    }

    #[test]
    fn happy_path_authenticates() {
        let (sk, cfg) = keypair();
        let mut state = AdminConnectionState::default();
        assert!(!state.authenticated);

        let nonce = state.issue_challenge();
        let sig = sign(&sk, &nonce);
        state.verify_response(&sig, &cfg).unwrap();

        assert!(state.authenticated);
        // Pending challenge should be cleared after consume.
        assert!(state.pending_challenge.is_none());
    }

    #[test]
    fn response_without_challenge_is_no_challenge_error() {
        let (sk, cfg) = keypair();
        let mut state = AdminConnectionState::default();
        let bogus_nonce = [0u8; 32];
        let sig = sign(&sk, &bogus_nonce);
        let err = state.verify_response(&sig, &cfg).unwrap_err();
        assert_eq!(err, AuthError::NoChallenge);
        assert!(!state.authenticated);
    }

    #[test]
    fn signature_against_wrong_nonce_fails() {
        let (sk, cfg) = keypair();
        let mut state = AdminConnectionState::default();

        // Issue and discard one nonce
        let _ = state.issue_challenge();
        // Sign a DIFFERENT nonce
        let wrong_nonce = [0xFFu8; 32];
        let sig = sign(&sk, &wrong_nonce);

        let err = state.verify_response(&sig, &cfg).unwrap_err();
        assert_eq!(err, AuthError::BadSignature);
        assert!(!state.authenticated);
        // Pending challenge consumed even on failure
        assert!(state.pending_challenge.is_none());
    }

    #[test]
    fn wrong_keypair_fails() {
        let (_real_sk, cfg) = keypair();
        let (attacker_sk, _) = keypair(); // different sk
        let mut state = AdminConnectionState::default();
        let nonce = state.issue_challenge();
        let sig = sign(&attacker_sk, &nonce);
        let err = state.verify_response(&sig, &cfg).unwrap_err();
        assert_eq!(err, AuthError::BadSignature);
    }

    #[test]
    fn replay_of_earlier_signature_fails() {
        // Even if attacker captures a valid signature, they can't
        // replay it: the second challenge has a different nonce.
        let (sk, cfg) = keypair();
        let mut state1 = AdminConnectionState::default();
        let nonce1 = state1.issue_challenge();
        let sig1 = sign(&sk, &nonce1);
        state1.verify_response(&sig1, &cfg).unwrap();

        // New connection, new state
        let mut state2 = AdminConnectionState::default();
        let _nonce2 = state2.issue_challenge();
        // Replay the OLD signature against the NEW challenge
        let err = state2.verify_response(&sig1, &cfg).unwrap_err();
        assert_eq!(err, AuthError::BadSignature);
    }

    #[test]
    fn config_from_hex_roundtrip() {
        let (sk, _) = keypair();
        let pk_bytes = sk.verifying_key().to_bytes();
        let hex: String = pk_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let cfg = AdminConfig::from_hex(&hex).unwrap();
        assert_eq!(cfg.admin_pubkey.to_bytes(), pk_bytes);
    }

    #[test]
    fn config_from_hex_rejects_wrong_length() {
        let err = AdminConfig::from_hex("deadbeef").unwrap_err();
        assert!(err.contains("64 hex chars"), "got: {}", err);
    }

    #[test]
    fn config_from_hex_rejects_non_hex_chars() {
        let bad = "z".repeat(64);
        let err = AdminConfig::from_hex(&bad).unwrap_err();
        assert!(err.contains("invalid hex"), "got: {}", err);
    }

    // ─── Upload state-machine tests (Slice 3b) ────────────────────────

    fn manifest_for(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut s = String::from("[manifest]\nversion = 1\n\n[files]\n");
        let mut sorted: Vec<_> = files.iter().collect();
        sorted.sort_by_key(|(n, _)| *n);
        for (name, content) in sorted {
            let h = sha256(content);
            let hex: String = h.iter().map(|b| format!("{:02x}", b)).collect();
            s.push_str(&format!("\"{}\" = \"{}\"\n", name, hex));
        }
        s.into_bytes()
    }

    #[test]
    fn happy_path_upload_finalize_activate() {
        let data_root = tempfile::tempdir().unwrap();
        let mut state = AdminConnectionState::default();

        let files: &[(&str, &[u8])] = &[("a.bin", b"hello"), ("sub/b.bin", b"world")];
        let manifest_toml = manifest_for(files);
        state
            .begin_upload("snap1".into(), manifest_toml.clone(), data_root.path())
            .expect("begin");

        // Stream chunks for each file.
        for (path, content) in files {
            state.write_chunk("snap1", path, 0, content).expect("write_chunk");
        }

        let root = state.finalize_upload("snap1").expect("finalize");
        assert_eq!(root, sha256(&manifest_toml));

        // Activate to checkpoints/snap1
        state
            .activate("snap1", "checkpoints/snap1", data_root.path())
            .expect("activate");

        // Verify staged dir is gone and target dir has the files.
        assert!(!data_root.path().join(".staging/snap1").exists());
        let final_dir = data_root.path().join("checkpoints/snap1");
        assert!(final_dir.exists());
        assert_eq!(fs::read(final_dir.join("a.bin")).unwrap(), b"hello");
        assert_eq!(fs::read(final_dir.join("sub/b.bin")).unwrap(), b"world");
        // Upload state cleaned up after activate
        assert!(!state.uploads.contains_key("snap1"));
    }

    #[test]
    fn finalize_with_missing_chunk_fails() {
        let data_root = tempfile::tempdir().unwrap();
        let mut state = AdminConnectionState::default();
        let files: &[(&str, &[u8])] = &[("a.bin", b"hello"), ("b.bin", b"world")];
        state
            .begin_upload("x".into(), manifest_for(files), data_root.path())
            .unwrap();

        // Only upload a.bin, skip b.bin
        state.write_chunk("x", "a.bin", 0, b"hello").unwrap();

        let err = state.finalize_upload("x").unwrap_err();
        match err {
            UploadError::Verification(msg) => {
                // Should mention missing file b.bin
                assert!(msg.contains("b.bin"), "unexpected msg: {}", msg);
            }
            _ => panic!("expected Verification error, got {:?}", err),
        }
    }

    #[test]
    fn finalize_with_corrupted_chunk_fails() {
        let data_root = tempfile::tempdir().unwrap();
        let mut state = AdminConnectionState::default();
        let files: &[(&str, &[u8])] = &[("a.bin", b"hello")];
        state
            .begin_upload("x".into(), manifest_for(files), data_root.path())
            .unwrap();

        // Write the wrong content.
        state.write_chunk("x", "a.bin", 0, b"WRONG").unwrap();

        let err = state.finalize_upload("x").unwrap_err();
        assert!(matches!(err, UploadError::Verification(_)), "got {:?}", err);
    }

    #[test]
    fn write_chunk_for_unlisted_file_rejected() {
        let data_root = tempfile::tempdir().unwrap();
        let mut state = AdminConnectionState::default();
        let files: &[(&str, &[u8])] = &[("a.bin", b"hello")];
        state
            .begin_upload("x".into(), manifest_for(files), data_root.path())
            .unwrap();

        let err = state.write_chunk("x", "stranger.bin", 0, b"x").unwrap_err();
        assert!(matches!(err, UploadError::FileNotInManifest(_)), "got {:?}", err);
    }

    #[test]
    fn write_chunk_with_dotdot_rejected() {
        let data_root = tempfile::tempdir().unwrap();
        let mut state = AdminConnectionState::default();
        // Manifest claims the file path "../escape.bin" — even if the
        // attacker controls the manifest, validate_relative_path stops it.
        let mut s = String::from("[manifest]\nversion = 1\n\n[files]\n");
        s.push_str(&format!(
            "\"../escape.bin\" = \"{}\"\n",
            sha256(b"x").iter().map(|b| format!("{:02x}", b)).collect::<String>()
        ));
        state
            .begin_upload("x".into(), s.into_bytes(), data_root.path())
            .unwrap();
        let err = state.write_chunk("x", "../escape.bin", 0, b"x").unwrap_err();
        assert!(matches!(err, UploadError::InvalidName(_)), "got {:?}", err);
    }

    #[test]
    fn unknown_upload_name_returns_unknown_error() {
        let mut state = AdminConnectionState::default();
        let err = state.write_chunk("nope", "a.bin", 0, b"x").unwrap_err();
        assert!(matches!(err, UploadError::UnknownUpload(_)), "got {:?}", err);
    }

    #[test]
    fn rebegin_clears_prior_staging() {
        // If a previous upload of "x" left files in staging, BEGIN
        // wipes them so the new upload starts clean.
        let data_root = tempfile::tempdir().unwrap();
        let mut state = AdminConnectionState::default();
        let files1: &[(&str, &[u8])] = &[("a.bin", b"first")];
        state
            .begin_upload("x".into(), manifest_for(files1), data_root.path())
            .unwrap();
        state.write_chunk("x", "a.bin", 0, b"first").unwrap();

        // Re-BEGIN with a different content — staging dir should be wiped
        let files2: &[(&str, &[u8])] = &[("a.bin", b"second")];
        state
            .begin_upload("x".into(), manifest_for(files2), data_root.path())
            .unwrap();
        state.write_chunk("x", "a.bin", 0, b"second").unwrap();
        let _ = state.finalize_upload("x").expect("finalize works");
    }

    #[test]
    fn activate_with_existing_target_swaps_atomically() {
        let data_root = tempfile::tempdir().unwrap();
        // Pre-populate target dir
        let target_dir = data_root.path().join("main");
        fs::create_dir_all(&target_dir).unwrap();
        fs::write(target_dir.join("old.bin"), b"old content").unwrap();

        let mut state = AdminConnectionState::default();
        let files: &[(&str, &[u8])] = &[("new.bin", b"new content")];
        state
            .begin_upload("upload1".into(), manifest_for(files), data_root.path())
            .unwrap();
        state.write_chunk("upload1", "new.bin", 0, b"new content").unwrap();
        state.finalize_upload("upload1").unwrap();
        state.activate("upload1", "main", data_root.path()).unwrap();

        // Old file gone, new file present
        assert!(!target_dir.join("old.bin").exists());
        assert!(target_dir.join("new.bin").exists());
    }

    #[test]
    fn invalid_name_rejected() {
        let data_root = tempfile::tempdir().unwrap();
        let mut state = AdminConnectionState::default();

        for bad in ["", "..", ".", "with/slash", "with space", "weird;char"] {
            let err = state
                .begin_upload(bad.into(), manifest_for(&[]), data_root.path())
                .unwrap_err();
            assert!(matches!(err, UploadError::InvalidName(_)), "name={:?} gave {:?}", bad, err);
        }
    }

    #[test]
    fn issue_challenge_overwrites_pending() {
        let (sk, cfg) = keypair();
        let mut state = AdminConnectionState::default();
        let n1 = state.issue_challenge();
        let n2 = state.issue_challenge();
        // Different nonces (CSPRNG)
        assert_ne!(n1, n2);
        // Stored challenge is the latest
        assert_eq!(state.pending_challenge, Some(n2));
        // Signing the old nonce should fail (it's no longer the pending one)
        let sig_old = sign(&sk, &n1);
        let err = state.verify_response(&sig_old, &cfg).unwrap_err();
        assert_eq!(err, AuthError::BadSignature);
    }
}
