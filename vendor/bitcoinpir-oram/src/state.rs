use crate::{CircuitEvictionSchedule, Error, OramBlock, OramParams, Result, TieredMerkleState};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Write},
    path::Path,
};
use zeroize::Zeroize;

const STATE_MAGIC: &[u8; 8] = b"BPORAM01";
const SEALED_STATE_MAGIC: &[u8; 8] = b"BPORAMS1";
const CIRCUIT_STATE_MAGIC: &[u8; 8] = b"BPCIRC01";
const CIRCUIT_SEALED_STATE_MAGIC: &[u8; 8] = b"BPCIRCS1";
const CIRCUIT_STORE_AUTH_MAGIC: &[u8; 8] = b"BPCSTA01";
const CIRCUIT_SEALED_STORE_AUTH_MAGIC: &[u8; 8] = b"BPCSTAS1";
const STATE_NONCE_LEN: usize = 12;

/// Trusted controller state needed to reopen an ORAM bucket image.
///
/// This contains the position map, stash, and RNG state. Treat it as TEE
/// private state; if written outside the TEE it must be encrypted or sealed.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OramState {
    magic: [u8; 8],
    /// Public ORAM sizing parameters.
    pub params: OramParams,
    /// Current logical-id to leaf-label position map.
    pub pos_map: Vec<u32>,
    /// Current stash contents.
    pub stash: Vec<OramBlock>,
    /// Current RNG state used for future remapping.
    pub rng: ChaCha20Rng,
}

impl OramState {
    /// Construct a state object.
    pub fn new(
        params: OramParams,
        pos_map: Vec<u32>,
        stash: Vec<OramBlock>,
        rng: ChaCha20Rng,
    ) -> Self {
        Self {
            magic: *STATE_MAGIC,
            params,
            pos_map,
            stash,
            rng,
        }
    }

    /// Persist state atomically via temp-file-and-rename.
    pub fn save_atomic(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let tmp = tmp_path(path);
        {
            let file = File::create(&tmp)?;
            let mut writer = BufWriter::new(file);
            bincode::serialize_into(&mut writer, self)?;
            writer.flush()?;
        }
        fs::rename(tmp, path)?;
        Ok(())
    }

    /// Persist an AEAD-encrypted state file atomically.
    pub fn save_encrypted_atomic(&self, path: impl AsRef<Path>, key: [u8; 32]) -> Result<()> {
        let mut plaintext = bincode::serialize(self)?;
        let mut nonce_bytes = [0u8; STATE_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = ChaCha20Poly1305::new((&key).into());
        let mut ciphertext = cipher.encrypt(
            Nonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: &plaintext,
                aad: SEALED_STATE_MAGIC,
            },
        )?;
        plaintext.zeroize();

        let mut envelope =
            Vec::with_capacity(SEALED_STATE_MAGIC.len() + nonce_bytes.len() + ciphertext.len());
        envelope.extend_from_slice(SEALED_STATE_MAGIC);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        ciphertext.zeroize();

        let path = path.as_ref();
        let tmp = tmp_path(path);
        let mut writer = BufWriter::new(File::create(&tmp)?);
        writer.write_all(&envelope)?;
        writer.flush()?;
        drop(writer);
        envelope.zeroize();
        fs::rename(tmp, path)?;
        Ok(())
    }

    /// Load a state file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let state: Self = bincode::deserialize_from(reader)?;
        if &state.magic != STATE_MAGIC {
            return Err(crate::Error::InvalidInput(
                "invalid ORAM state magic".into(),
            ));
        }
        Ok(state)
    }

    /// Load an AEAD-encrypted state file.
    pub fn load_encrypted(path: impl AsRef<Path>, key: [u8; 32]) -> Result<Self> {
        let mut envelope = fs::read(path)?;
        if envelope.len() < SEALED_STATE_MAGIC.len() + STATE_NONCE_LEN + 16 {
            return Err(Error::InvalidInput(
                "encrypted state file is too short".into(),
            ));
        }
        if &envelope[..SEALED_STATE_MAGIC.len()] != SEALED_STATE_MAGIC {
            return Err(Error::InvalidInput(
                "invalid encrypted ORAM state magic".into(),
            ));
        }

        let nonce_start = SEALED_STATE_MAGIC.len();
        let ciphertext_start = nonce_start + STATE_NONCE_LEN;
        let mut nonce = [0u8; STATE_NONCE_LEN];
        nonce.copy_from_slice(&envelope[nonce_start..ciphertext_start]);

        let cipher = ChaCha20Poly1305::new((&key).into());
        let mut plaintext = cipher.decrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &envelope[ciphertext_start..],
                aad: SEALED_STATE_MAGIC,
            },
        )?;
        envelope.zeroize();

        let state: Self = bincode::deserialize(&plaintext)?;
        plaintext.zeroize();
        if &state.magic != STATE_MAGIC {
            return Err(Error::InvalidInput("invalid ORAM state magic".into()));
        }
        Ok(state)
    }
}

/// Trusted controller state needed to reopen a split-store Circuit ORAM image.
///
/// This contains the position map, stash, RNG state, and public deterministic
/// eviction counters. Treat it as TEE-private state; if written outside the TEE
/// it must be encrypted or sealed.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CircuitOramState {
    magic: [u8; 8],
    /// Public ORAM sizing parameters.
    pub params: OramParams,
    /// Current logical-id to leaf-label position map.
    pub pos_map: Vec<u32>,
    /// Current fixed-capacity stash contents.
    pub stash: Vec<OramBlock>,
    /// Current RNG state used for future remapping.
    pub rng: ChaCha20Rng,
    /// Public deterministic Circuit ORAM eviction schedule.
    pub schedule: CircuitEvictionSchedule,
}

impl CircuitOramState {
    /// Construct a Circuit ORAM state object.
    pub fn new(
        params: OramParams,
        pos_map: Vec<u32>,
        stash: Vec<OramBlock>,
        rng: ChaCha20Rng,
        schedule: CircuitEvictionSchedule,
    ) -> Self {
        Self {
            magic: *CIRCUIT_STATE_MAGIC,
            params,
            pos_map,
            stash,
            rng,
            schedule,
        }
    }

    /// Persist state atomically via temp-file-and-rename.
    pub fn save_atomic(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let tmp = tmp_path(path);
        {
            let file = File::create(&tmp)?;
            let mut writer = BufWriter::new(file);
            bincode::serialize_into(&mut writer, self)?;
            writer.flush()?;
        }
        fs::rename(tmp, path)?;
        Ok(())
    }

    /// Persist an AEAD-encrypted Circuit ORAM state file atomically.
    pub fn save_encrypted_atomic(&self, path: impl AsRef<Path>, key: [u8; 32]) -> Result<()> {
        let mut plaintext = bincode::serialize(self)?;
        let mut nonce_bytes = [0u8; STATE_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = ChaCha20Poly1305::new((&key).into());
        let mut ciphertext = cipher.encrypt(
            Nonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: &plaintext,
                aad: CIRCUIT_SEALED_STATE_MAGIC,
            },
        )?;
        plaintext.zeroize();

        let mut envelope = Vec::with_capacity(
            CIRCUIT_SEALED_STATE_MAGIC.len() + nonce_bytes.len() + ciphertext.len(),
        );
        envelope.extend_from_slice(CIRCUIT_SEALED_STATE_MAGIC);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        ciphertext.zeroize();

        let path = path.as_ref();
        let tmp = tmp_path(path);
        let mut writer = BufWriter::new(File::create(&tmp)?);
        writer.write_all(&envelope)?;
        writer.flush()?;
        drop(writer);
        envelope.zeroize();
        fs::rename(tmp, path)?;
        Ok(())
    }

    /// Load a Circuit ORAM state file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let state: Self = bincode::deserialize_from(reader)?;
        if &state.magic != CIRCUIT_STATE_MAGIC {
            return Err(Error::InvalidInput(
                "invalid Circuit ORAM state magic".into(),
            ));
        }
        Ok(state)
    }

    /// Load an AEAD-encrypted Circuit ORAM state file.
    pub fn load_encrypted(path: impl AsRef<Path>, key: [u8; 32]) -> Result<Self> {
        let mut envelope = fs::read(path)?;
        if envelope.len() < CIRCUIT_SEALED_STATE_MAGIC.len() + STATE_NONCE_LEN + 16 {
            return Err(Error::InvalidInput(
                "encrypted Circuit ORAM state file is too short".into(),
            ));
        }
        if &envelope[..CIRCUIT_SEALED_STATE_MAGIC.len()] != CIRCUIT_SEALED_STATE_MAGIC {
            return Err(Error::InvalidInput(
                "invalid encrypted Circuit ORAM state magic".into(),
            ));
        }

        let nonce_start = CIRCUIT_SEALED_STATE_MAGIC.len();
        let ciphertext_start = nonce_start + STATE_NONCE_LEN;
        let mut nonce = [0u8; STATE_NONCE_LEN];
        nonce.copy_from_slice(&envelope[nonce_start..ciphertext_start]);

        let cipher = ChaCha20Poly1305::new((&key).into());
        let mut plaintext = cipher.decrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &envelope[ciphertext_start..],
                aad: CIRCUIT_SEALED_STATE_MAGIC,
            },
        )?;
        envelope.zeroize();

        let state: Self = bincode::deserialize(&plaintext)?;
        plaintext.zeroize();
        if &state.magic != CIRCUIT_STATE_MAGIC {
            return Err(Error::InvalidInput(
                "invalid Circuit ORAM state magic".into(),
            ));
        }
        Ok(state)
    }
}

/// Trusted authentication state for Circuit ORAM metadata and payload stores.
///
/// This sidecar is separate from [`CircuitOramState`] so existing controller
/// checkpoints remain readable. Treat it with the same trust boundary as the
/// controller state: keep it in TEE memory, or encrypt/seal it if it is written
/// outside the TEE.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CircuitStoreAuthState {
    magic: [u8; 8],
    /// Metadata store Merkle top-tree state.
    pub meta: TieredMerkleState,
    /// Payload store Merkle top-tree state.
    pub payload: TieredMerkleState,
}

impl CircuitStoreAuthState {
    /// Construct store-authentication state.
    pub fn new(meta: TieredMerkleState, payload: TieredMerkleState) -> Self {
        Self {
            magic: *CIRCUIT_STORE_AUTH_MAGIC,
            meta,
            payload,
        }
    }

    /// Persist state atomically via temp-file-and-rename.
    pub fn save_atomic(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let tmp = tmp_path(path);
        {
            let file = File::create(&tmp)?;
            let mut writer = BufWriter::new(file);
            bincode::serialize_into(&mut writer, self)?;
            writer.flush()?;
        }
        fs::rename(tmp, path)?;
        Ok(())
    }

    /// Persist an AEAD-encrypted store-authentication sidecar atomically.
    pub fn save_encrypted_atomic(&self, path: impl AsRef<Path>, key: [u8; 32]) -> Result<()> {
        let mut plaintext = bincode::serialize(self)?;
        let mut nonce_bytes = [0u8; STATE_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = ChaCha20Poly1305::new((&key).into());
        let mut ciphertext = cipher.encrypt(
            Nonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: &plaintext,
                aad: CIRCUIT_SEALED_STORE_AUTH_MAGIC,
            },
        )?;
        plaintext.zeroize();

        let mut envelope = Vec::with_capacity(
            CIRCUIT_SEALED_STORE_AUTH_MAGIC.len() + nonce_bytes.len() + ciphertext.len(),
        );
        envelope.extend_from_slice(CIRCUIT_SEALED_STORE_AUTH_MAGIC);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        ciphertext.zeroize();

        let path = path.as_ref();
        let tmp = tmp_path(path);
        let mut writer = BufWriter::new(File::create(&tmp)?);
        writer.write_all(&envelope)?;
        writer.flush()?;
        drop(writer);
        envelope.zeroize();
        fs::rename(tmp, path)?;
        Ok(())
    }

    /// Load a store-authentication sidecar.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let state: Self = bincode::deserialize_from(reader)?;
        if &state.magic != CIRCUIT_STORE_AUTH_MAGIC {
            return Err(Error::InvalidInput(
                "invalid Circuit ORAM store-auth magic".into(),
            ));
        }
        Ok(state)
    }

    /// Load an AEAD-encrypted store-authentication sidecar.
    pub fn load_encrypted(path: impl AsRef<Path>, key: [u8; 32]) -> Result<Self> {
        let mut envelope = fs::read(path)?;
        if envelope.len() < CIRCUIT_SEALED_STORE_AUTH_MAGIC.len() + STATE_NONCE_LEN + 16 {
            return Err(Error::InvalidInput(
                "encrypted Circuit ORAM store-auth sidecar is too short".into(),
            ));
        }
        if &envelope[..CIRCUIT_SEALED_STORE_AUTH_MAGIC.len()] != CIRCUIT_SEALED_STORE_AUTH_MAGIC {
            return Err(Error::InvalidInput(
                "invalid encrypted Circuit ORAM store-auth magic".into(),
            ));
        }

        let nonce_start = CIRCUIT_SEALED_STORE_AUTH_MAGIC.len();
        let ciphertext_start = nonce_start + STATE_NONCE_LEN;
        let mut nonce = [0u8; STATE_NONCE_LEN];
        nonce.copy_from_slice(&envelope[nonce_start..ciphertext_start]);

        let cipher = ChaCha20Poly1305::new((&key).into());
        let mut plaintext = cipher.decrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &envelope[ciphertext_start..],
                aad: CIRCUIT_SEALED_STORE_AUTH_MAGIC,
            },
        )?;
        envelope.zeroize();

        let state: Self = bincode::deserialize(&plaintext)?;
        plaintext.zeroize();
        if &state.magic != CIRCUIT_STORE_AUTH_MAGIC {
            return Err(Error::InvalidInput(
                "invalid Circuit ORAM store-auth magic".into(),
            ));
        }
        Ok(state)
    }
}

fn tmp_path(path: &Path) -> std::path::PathBuf {
    path.with_extension(format!(
        "{}tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| format!("{ext}."))
            .unwrap_or_default()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OramParams;
    use rand::SeedableRng;

    fn sample_state() -> OramState {
        OramState::new(
            OramParams::with_leaves(4, 8, 4).unwrap(),
            vec![0, 1, 2, 3],
            Vec::new(),
            ChaCha20Rng::from_seed([3; 32]),
        )
    }

    fn sample_circuit_state() -> CircuitOramState {
        let params = OramParams::with_leaves(4, 8, 4).unwrap();
        let mut schedule = CircuitEvictionSchedule::new(&params);
        schedule.record_access().unwrap();
        CircuitOramState::new(
            params,
            vec![0, 1, 2, 3],
            Vec::new(),
            ChaCha20Rng::from_seed([4; 32]),
            schedule,
        )
    }

    fn sample_store_auth_state() -> CircuitStoreAuthState {
        let merkle = TieredMerkleState {
            store_id: *b"bpir-idx-meta-v1",
            page_count: 8,
            page_size: 64,
            trusted_levels: 2,
            hash_page_size: 4096,
            trusted_hashes: vec![[0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]],
        };
        CircuitStoreAuthState::new(merkle.clone(), merkle)
    }

    #[test]
    fn encrypted_state_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("controller.state");
        let state = sample_state();
        state.save_encrypted_atomic(&path, [9; 32]).unwrap();

        let loaded = OramState::load_encrypted(&path, [9; 32]).unwrap();
        assert_eq!(loaded.params, state.params);
        assert_eq!(loaded.pos_map, state.pos_map);
    }

    #[test]
    fn encrypted_state_rejects_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("controller.state");
        sample_state()
            .save_encrypted_atomic(&path, [9; 32])
            .unwrap();

        assert!(OramState::load_encrypted(&path, [8; 32]).is_err());
    }

    #[test]
    fn encrypted_circuit_state_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("circuit.state");
        let state = sample_circuit_state();
        state.save_encrypted_atomic(&path, [7; 32]).unwrap();

        let loaded = CircuitOramState::load_encrypted(&path, [7; 32]).unwrap();
        assert_eq!(loaded.params, state.params);
        assert_eq!(loaded.pos_map, state.pos_map);
        assert_eq!(loaded.schedule.pending_evictions().unwrap(), 2);
    }

    #[test]
    fn encrypted_circuit_store_auth_state_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store-auth.state");
        let state = sample_store_auth_state();
        state.save_encrypted_atomic(&path, [8; 32]).unwrap();

        let loaded = CircuitStoreAuthState::load_encrypted(&path, [8; 32]).unwrap();
        assert_eq!(loaded.meta, state.meta);
        assert_eq!(loaded.payload, state.payload);
    }
}
