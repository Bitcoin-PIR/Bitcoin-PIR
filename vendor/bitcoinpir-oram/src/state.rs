use crate::{
    CircuitEvictionSchedule, EmbeddedTreeState, Error, OramBlock, OramParams, Result,
    TieredMerkleState,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
};
use zeroize::Zeroize;

const CIRCUIT_STATE_MAGIC: &[u8; 8] = b"BPCIRC01";
const CIRCUIT_SEALED_STATE_MAGIC: &[u8; 8] = b"BPCIRCS1";
const CIRCUIT_STORE_AUTH_MAGIC: &[u8; 8] = b"BPCSTA01";
const CIRCUIT_SEALED_STORE_AUTH_MAGIC: &[u8; 8] = b"BPCSTAS1";
const STATE_NONCE_LEN: usize = 12;

/// Trusted controller state needed to reopen a split-store Circuit ORAM image.
///
/// This contains the position map, stash, RNG state, and public deterministic
/// eviction counters. When authenticated stores are used, it also carries the
/// trusted auth roots expected by the metadata and payload stores. Treat it as
/// TEE-private state; if written outside the TEE it must be encrypted or sealed.
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
    /// Expected authenticated-store roots, when the image uses auth stores.
    pub auth: Option<CircuitStoreAuthState>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LegacyCircuitOramState {
    magic: [u8; 8],
    pub params: OramParams,
    pub pos_map: Vec<u32>,
    pub stash: Vec<OramBlock>,
    pub rng: ChaCha20Rng,
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
            auth: None,
        }
    }

    /// Attach expected authenticated-store roots to the controller state.
    pub fn with_auth(mut self, auth: Option<CircuitStoreAuthState>) -> Self {
        self.auth = auth;
        self
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        match bincode::deserialize::<Self>(bytes) {
            Ok(state) => {
                state.validate_magic()?;
                Ok(state)
            }
            Err(new_err) => {
                let legacy: LegacyCircuitOramState =
                    bincode::deserialize(bytes).map_err(|_| Error::Bincode(new_err))?;
                if &legacy.magic != CIRCUIT_STATE_MAGIC {
                    return Err(Error::InvalidInput(
                        "invalid Circuit ORAM state magic".into(),
                    ));
                }
                Ok(Self {
                    magic: legacy.magic,
                    params: legacy.params,
                    pos_map: legacy.pos_map,
                    stash: legacy.stash,
                    rng: legacy.rng,
                    schedule: legacy.schedule,
                    auth: None,
                })
            }
        }
    }

    fn validate_magic(&self) -> Result<()> {
        if &self.magic != CIRCUIT_STATE_MAGIC {
            return Err(Error::InvalidInput(
                "invalid Circuit ORAM state magic".into(),
            ));
        }
        Ok(())
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
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
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

        let state = Self::from_bytes(&plaintext)?;
        plaintext.zeroize();
        Ok(state)
    }
}

/// Trusted authentication state for Circuit ORAM metadata and payload stores.
///
/// This sidecar is separate from [`CircuitOramState`] so existing controller
/// checkpoints remain readable. Treat it with the same trust boundary as the
/// controller state: keep it in TEE memory, or encrypt/seal it if it is written
/// outside the TEE.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitStoreAuthState {
    magic: [u8; 8],
    /// Authenticated store layout and trusted roots.
    pub layout: CircuitStoreAuthLayout,
}

/// Authenticated store layout and trusted roots for both split stores.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CircuitStoreAuthLayout {
    /// Existing tiered Merkle sidecar layout.
    TieredMerkle {
        /// Metadata store Merkle top-tree state.
        meta: TieredMerkleState,
        /// Payload store Merkle top-tree state.
        payload: TieredMerkleState,
    },
    /// Embedded tree layout with child hashes inside bucket pages.
    EmbeddedTree {
        /// Metadata store embedded-tree root state.
        meta: EmbeddedTreeState,
        /// Payload store embedded-tree root state.
        payload: EmbeddedTreeState,
    },
}

#[derive(Clone, Debug, Deserialize)]
struct LegacyCircuitStoreAuthState {
    magic: [u8; 8],
    pub meta: TieredMerkleState,
    pub payload: TieredMerkleState,
}

impl CircuitStoreAuthState {
    /// Construct tiered-Merkle sidecar authentication state.
    pub fn new(meta: TieredMerkleState, payload: TieredMerkleState) -> Self {
        Self {
            magic: *CIRCUIT_STORE_AUTH_MAGIC,
            layout: CircuitStoreAuthLayout::TieredMerkle { meta, payload },
        }
    }

    /// Construct embedded-tree authentication state.
    pub fn new_embedded(meta: EmbeddedTreeState, payload: EmbeddedTreeState) -> Self {
        Self {
            magic: *CIRCUIT_STORE_AUTH_MAGIC,
            layout: CircuitStoreAuthLayout::EmbeddedTree { meta, payload },
        }
    }

    /// Return tiered-Merkle roots when this auth sidecar uses that layout.
    pub const fn tiered_merkle(&self) -> Option<(&TieredMerkleState, &TieredMerkleState)> {
        match &self.layout {
            CircuitStoreAuthLayout::TieredMerkle { meta, payload } => Some((meta, payload)),
            CircuitStoreAuthLayout::EmbeddedTree { .. } => None,
        }
    }

    /// Return embedded-tree roots when this auth sidecar uses that layout.
    pub const fn embedded_tree(&self) -> Option<(&EmbeddedTreeState, &EmbeddedTreeState)> {
        match &self.layout {
            CircuitStoreAuthLayout::EmbeddedTree { meta, payload } => Some((meta, payload)),
            CircuitStoreAuthLayout::TieredMerkle { .. } => None,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        match bincode::deserialize::<Self>(bytes) {
            Ok(state) => {
                state.validate_magic()?;
                Ok(state)
            }
            Err(new_err) => {
                let legacy: LegacyCircuitStoreAuthState =
                    bincode::deserialize(bytes).map_err(|_| Error::Bincode(new_err))?;
                if &legacy.magic != CIRCUIT_STORE_AUTH_MAGIC {
                    return Err(Error::InvalidInput(
                        "invalid Circuit ORAM store-auth magic".into(),
                    ));
                }
                Ok(Self::new(legacy.meta, legacy.payload))
            }
        }
    }

    fn validate_magic(&self) -> Result<()> {
        if &self.magic != CIRCUIT_STORE_AUTH_MAGIC {
            return Err(Error::InvalidInput(
                "invalid Circuit ORAM store-auth magic".into(),
            ));
        }
        Ok(())
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
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
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

        let state = Self::from_bytes(&plaintext)?;
        plaintext.zeroize();
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

    fn sample_legacy_circuit_state() -> LegacyCircuitOramState {
        let state = sample_circuit_state();
        LegacyCircuitOramState {
            magic: *CIRCUIT_STATE_MAGIC,
            params: state.params,
            pos_map: state.pos_map,
            stash: state.stash,
            rng: state.rng,
            schedule: state.schedule,
        }
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

    fn sample_embedded_store_auth_state() -> CircuitStoreAuthState {
        let embedded = EmbeddedTreeState {
            store_id: *b"bpir-idx-meta-v1",
            page_count: 8,
            logical_page_size: 64,
            root_hash: [7u8; 32],
        };
        CircuitStoreAuthState::new_embedded(embedded.clone(), embedded)
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
        assert!(loaded.auth.is_none());
    }

    #[test]
    fn encrypted_circuit_state_with_auth_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("circuit-auth-bound.state");
        let state = sample_circuit_state().with_auth(Some(sample_embedded_store_auth_state()));
        state.save_encrypted_atomic(&path, [7; 32]).unwrap();

        let loaded = CircuitOramState::load_encrypted(&path, [7; 32]).unwrap();
        assert_eq!(loaded.params, state.params);
        assert_eq!(loaded.pos_map, state.pos_map);
        assert_eq!(loaded.auth, state.auth);
    }

    #[test]
    fn legacy_circuit_state_loads_without_auth_binding() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy-circuit.state");
        let legacy = sample_legacy_circuit_state();
        fs::write(&path, bincode::serialize(&legacy).unwrap()).unwrap();

        let loaded = CircuitOramState::load(&path).unwrap();
        assert_eq!(loaded.params, legacy.params);
        assert_eq!(loaded.pos_map, legacy.pos_map);
        assert!(loaded.auth.is_none());
    }

    #[test]
    fn encrypted_circuit_store_auth_state_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store-auth.state");
        let state = sample_store_auth_state();
        state.save_encrypted_atomic(&path, [8; 32]).unwrap();

        let loaded = CircuitStoreAuthState::load_encrypted(&path, [8; 32]).unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn encrypted_circuit_embedded_store_auth_state_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("embedded-store-auth.state");
        let state = sample_embedded_store_auth_state();
        state.save_encrypted_atomic(&path, [8; 32]).unwrap();

        let loaded = CircuitStoreAuthState::load_encrypted(&path, [8; 32]).unwrap();
        assert_eq!(loaded, state);
    }
}
