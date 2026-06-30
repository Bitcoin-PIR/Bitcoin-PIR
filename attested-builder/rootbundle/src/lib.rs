//! Canonical signed root bundle.
//!
//! The bundle is the single client-facing trust artifact of the attested
//! builder design (see ../PLAN.md): it binds the PIR database Merkle
//! roots to a chain anchor (block hash + height), the Bitcoin Core
//! `muhash` of the UTXO set the database was built from, and every
//! build parameter that affects the output bytes. Builders (plain
//! hosts, Nitro enclaves, SEV guests) each sign the identical canonical
//! payload; clients accept a database root iff at least `threshold`
//! signatures from distinct pinned builder keys verify.
//!
//! Encoding follows the same hand-rolled, length-prefixed, canonical
//! style as `pir-identity` (no serde): one and only one byte string per
//! payload, strict decoding (no trailing bytes), so a signature commits
//! to exactly one interpretation.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Domain-separation prefix for bundle signatures. Versioned: any change
/// to the payload layout must bump both this tag and `PAYLOAD_VERSION`.
pub const SIGNING_DOMAIN: &[u8] = b"BitcoinPIR/attested-builder/root-bundle/v1\0";

/// Payload layout version (field of the payload itself).
pub const PAYLOAD_VERSION: u16 = 1;

/// Hard caps keeping decode allocation-bounded.
pub const MAX_ROOTS: usize = 1024;
pub const MAX_LABEL_LEN: usize = 64;

/// What was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildKind {
    /// Full snapshot at `anchor`.
    Snapshot,
    /// Delta from `from_anchor` (exclusive) to `anchor` (inclusive).
    Delta,
}

impl BuildKind {
    fn to_byte(self) -> u8 {
        match self {
            BuildKind::Snapshot => 0,
            BuildKind::Delta => 1,
        }
    }

    fn from_byte(b: u8) -> Result<Self, BundleError> {
        match b {
            0 => Ok(BuildKind::Snapshot),
            1 => Ok(BuildKind::Delta),
            _ => Err(BundleError::Malformed("unknown build kind")),
        }
    }
}

/// A Bitcoin chain anchor: block hash (internal byte order, as in
/// `chain_anchor.bin`) plus height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAnchor {
    pub block_hash: [u8; 32],
    pub height: u32,
}

/// One named Merkle root, e.g. `("dpf/index/super_root", …)`. Labels are
/// printable ASCII, unique, and sorted, so the payload bytes are
/// canonical for a given root set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedRoot {
    pub label: String,
    pub root: [u8; 32],
}

/// The unsigned, canonical bundle payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootBundlePayload {
    /// Network magic (mainnet `f9beb4d9`), so a testnet bundle can never
    /// satisfy a mainnet client.
    pub network_magic: [u8; 4],
    pub build_kind: BuildKind,
    /// Start anchor for deltas; all-zero hash + height 0 for snapshots.
    pub from_anchor: ChainAnchor,
    /// The chain state this database serves (end anchor for deltas).
    pub anchor: ChainAnchor,
    /// Bitcoin Core `gettxoutsetinfo muhash` of the FULL UTXO set at
    /// `anchor`, in Core's display byte order reversed back to raw
    /// digest bytes (i.e. `SHA256(residue)` output order).
    pub utxo_muhash: [u8; 32],
    /// Filter parameters — bound so "correct roots for different
    /// filtering" can't be substituted.
    pub dust_threshold_sats: u64,
    pub max_utxos_per_spk: u32,
    /// SHA256 of the canonical build-parameter blob (K, K_CHUNK, bin
    /// counts, slot sizes, format versions…). Clients pin the expected
    /// value for the format they speak.
    pub params_hash: [u8; 32],
    /// Unix seconds at signing time (advisory; freshness policy is the
    /// client's).
    pub issued_at: i64,
    /// Sorted-by-label, unique. See [`NamedRoot`].
    pub roots: Vec<NamedRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    Malformed(&'static str),
    /// Roots not strictly sorted by label, label invalid, or too many.
    InvalidRoots(&'static str),
    /// A signature from a pinned (trusted) key failed verification.
    BadSignature,
    /// The same builder key appears twice in the signature list.
    DuplicateSigner,
    /// Fewer than `threshold` valid signatures from distinct trusted keys.
    QuorumNotMet { valid: usize, threshold: usize },
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::Malformed(m) => write!(f, "malformed bundle: {m}"),
            BundleError::InvalidRoots(m) => write!(f, "invalid roots: {m}"),
            BundleError::BadSignature => write!(f, "bad signature from trusted key"),
            BundleError::DuplicateSigner => write!(f, "duplicate signer pubkey"),
            BundleError::QuorumNotMet { valid, threshold } => {
                write!(f, "quorum not met: {valid} valid of {threshold} required")
            }
        }
    }
}

impl std::error::Error for BundleError {}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(b);
}

fn take<'a>(cur: &mut &'a [u8], n: usize, what: &'static str) -> Result<&'a [u8], BundleError> {
    if cur.len() < n {
        return Err(BundleError::Malformed(what));
    }
    let (head, rest) = cur.split_at(n);
    *cur = rest;
    Ok(head)
}

fn take_arr<const N: usize>(cur: &mut &[u8], what: &'static str) -> Result<[u8; N], BundleError> {
    Ok(take(cur, N, what)?.try_into().unwrap())
}

fn validate_roots(roots: &[NamedRoot]) -> Result<(), BundleError> {
    if roots.is_empty() {
        return Err(BundleError::InvalidRoots("empty root list"));
    }
    if roots.len() > MAX_ROOTS {
        return Err(BundleError::InvalidRoots("too many roots"));
    }
    for r in roots {
        if r.label.is_empty() || r.label.len() > MAX_LABEL_LEN {
            return Err(BundleError::InvalidRoots("label length"));
        }
        if !r.label.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(BundleError::InvalidRoots("label must be printable ASCII, no spaces"));
        }
    }
    for w in roots.windows(2) {
        if w[0].label >= w[1].label {
            return Err(BundleError::InvalidRoots("labels must be strictly sorted"));
        }
    }
    Ok(())
}

impl RootBundlePayload {
    /// Canonical byte encoding. Fails if the root list is not canonical
    /// (so a non-canonical payload can never be signed).
    pub fn encode(&self) -> Result<Vec<u8>, BundleError> {
        validate_roots(&self.roots)?;
        let mut out = Vec::with_capacity(192 + self.roots.len() * 100);
        put_bytes(&mut out, &PAYLOAD_VERSION.to_le_bytes());
        put_bytes(&mut out, &self.network_magic);
        out.push(self.build_kind.to_byte());
        put_bytes(&mut out, &self.from_anchor.block_hash);
        put_bytes(&mut out, &self.from_anchor.height.to_le_bytes());
        put_bytes(&mut out, &self.anchor.block_hash);
        put_bytes(&mut out, &self.anchor.height.to_le_bytes());
        put_bytes(&mut out, &self.utxo_muhash);
        put_bytes(&mut out, &self.dust_threshold_sats.to_le_bytes());
        put_bytes(&mut out, &self.max_utxos_per_spk.to_le_bytes());
        put_bytes(&mut out, &self.params_hash);
        put_bytes(&mut out, &self.issued_at.to_le_bytes());
        put_bytes(&mut out, &(self.roots.len() as u16).to_le_bytes());
        for r in &self.roots {
            out.push(r.label.len() as u8);
            put_bytes(&mut out, r.label.as_bytes());
            put_bytes(&mut out, &r.root);
        }
        Ok(out)
    }

    /// Strict decode of [`encode`] output: rejects unknown versions,
    /// non-canonical root lists, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleError> {
        let cur = &mut &bytes[..];
        let version = u16::from_le_bytes(take_arr::<2>(cur, "version")?);
        if version != PAYLOAD_VERSION {
            return Err(BundleError::Malformed("unsupported payload version"));
        }
        let network_magic = take_arr::<4>(cur, "network magic")?;
        let build_kind = BuildKind::from_byte(take_arr::<1>(cur, "build kind")?[0])?;
        let from_anchor = ChainAnchor {
            block_hash: take_arr::<32>(cur, "from block hash")?,
            height: u32::from_le_bytes(take_arr::<4>(cur, "from height")?),
        };
        let anchor = ChainAnchor {
            block_hash: take_arr::<32>(cur, "block hash")?,
            height: u32::from_le_bytes(take_arr::<4>(cur, "height")?),
        };
        let utxo_muhash = take_arr::<32>(cur, "muhash")?;
        let dust_threshold_sats = u64::from_le_bytes(take_arr::<8>(cur, "dust threshold")?);
        let max_utxos_per_spk = u32::from_le_bytes(take_arr::<4>(cur, "max utxos")?);
        let params_hash = take_arr::<32>(cur, "params hash")?;
        let issued_at = i64::from_le_bytes(take_arr::<8>(cur, "issued at")?);
        let n_roots = u16::from_le_bytes(take_arr::<2>(cur, "root count")?) as usize;
        if n_roots > MAX_ROOTS {
            return Err(BundleError::InvalidRoots("too many roots"));
        }
        let mut roots = Vec::with_capacity(n_roots);
        for _ in 0..n_roots {
            let label_len = take_arr::<1>(cur, "label len")?[0] as usize;
            let label_bytes = take(cur, label_len, "label")?;
            let label = String::from_utf8(label_bytes.to_vec())
                .map_err(|_| BundleError::InvalidRoots("label not UTF-8"))?;
            let root = take_arr::<32>(cur, "root")?;
            roots.push(NamedRoot { label, root });
        }
        if !cur.is_empty() {
            return Err(BundleError::Malformed("trailing bytes"));
        }
        let payload = Self {
            network_magic,
            build_kind,
            from_anchor,
            anchor,
            utxo_muhash,
            dust_threshold_sats,
            max_utxos_per_spk,
            params_hash,
            issued_at,
            roots,
        };
        validate_roots(&payload.roots)?;
        Ok(payload)
    }

    /// The exact bytes a builder signs: domain tag ‖ canonical payload.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, BundleError> {
        let mut out = SIGNING_DOMAIN.to_vec();
        out.extend_from_slice(&self.encode()?);
        Ok(out)
    }

    /// Look up a root by label.
    pub fn root(&self, label: &str) -> Option<&[u8; 32]> {
        self.roots
            .binary_search_by(|r| r.label.as_str().cmp(label))
            .ok()
            .map(|i| &self.roots[i].root)
    }
}

/// One builder's detached signature over a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSignature {
    pub signer_pubkey: [u8; 32],
    pub signature: [u8; 64],
}

/// Payload + any number of builder signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRootBundle {
    pub payload: RootBundlePayload,
    pub signatures: Vec<BundleSignature>,
}

/// Sign `payload` with a builder key, returning the detached signature.
pub fn sign_root_bundle(
    payload: &RootBundlePayload,
    key: &SigningKey,
) -> Result<BundleSignature, BundleError> {
    let preimage = payload.signing_preimage()?;
    Ok(BundleSignature {
        signer_pubkey: key.verifying_key().to_bytes(),
        signature: key.sign(&preimage).to_bytes(),
    })
}

impl SignedRootBundle {
    /// Verify a k-of-n quorum: at least `threshold` cryptographically
    /// valid signatures from **distinct** keys in `trusted`.
    ///
    /// Policy:
    /// - Signatures from unknown (non-pinned) keys are ignored — forward
    ///   compatible with builder-set growth.
    /// - An *invalid* signature from a pinned key is a hard error, not a
    ///   skip: it is evidence of tampering, never of an honest builder.
    /// - Duplicate signer pubkeys are a hard error.
    ///
    /// Returns the number of valid trusted signatures on success.
    pub fn verify_quorum(
        &self,
        trusted: &[[u8; 32]],
        threshold: usize,
    ) -> Result<usize, BundleError> {
        if threshold == 0 {
            return Err(BundleError::Malformed("threshold must be >= 1"));
        }
        let preimage = self.payload.signing_preimage()?;
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(self.signatures.len());
        let mut valid = 0usize;
        for sig in &self.signatures {
            if seen.contains(&sig.signer_pubkey) {
                return Err(BundleError::DuplicateSigner);
            }
            seen.push(sig.signer_pubkey);
            if !trusted.contains(&sig.signer_pubkey) {
                continue;
            }
            let vk = VerifyingKey::from_bytes(&sig.signer_pubkey)
                .map_err(|_| BundleError::BadSignature)?;
            let signature = Signature::from_bytes(&sig.signature);
            vk.verify_strict(&preimage, &signature)
                .map_err(|_| BundleError::BadSignature)?;
            valid += 1;
        }
        if valid < threshold {
            return Err(BundleError::QuorumNotMet { valid, threshold });
        }
        Ok(valid)
    }

    /// Wire encoding: payload ‖ u16 sig count ‖ (pubkey ‖ sig)*.
    pub fn encode(&self) -> Result<Vec<u8>, BundleError> {
        let mut out = self.payload.encode()?;
        if self.signatures.len() > u16::MAX as usize {
            return Err(BundleError::Malformed("too many signatures"));
        }
        out.extend_from_slice(&(self.signatures.len() as u16).to_le_bytes());
        for s in &self.signatures {
            out.extend_from_slice(&s.signer_pubkey);
            out.extend_from_slice(&s.signature);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BundleError> {
        // Payload length is self-describing only via full parse; decode
        // payload greedily by re-using its strict parser on a prefix is
        // not possible, so parse inline: payload fields are fixed-size
        // except roots, which are length-prefixed — reparse via
        // RootBundlePayload::decode on the payload slice we can compute.
        //
        // Simpler: parse payload fields with the same cursor.
        let cur = &mut &bytes[..];
        let payload_start = *cur;
        // Skip through the payload using the same field sizes.
        let _version = take(cur, 2, "version")?;
        let _ = take(cur, 4 + 1 + 36 + 36 + 32 + 8 + 4 + 32 + 8, "fixed fields")?;
        let n_roots = u16::from_le_bytes(take_arr::<2>(cur, "root count")?) as usize;
        if n_roots > MAX_ROOTS {
            return Err(BundleError::InvalidRoots("too many roots"));
        }
        for _ in 0..n_roots {
            let label_len = take_arr::<1>(cur, "label len")?[0] as usize;
            let _ = take(cur, label_len + 32, "root entry")?;
        }
        let payload_len = payload_start.len() - cur.len();
        let payload = RootBundlePayload::decode(&payload_start[..payload_len])?;

        let n_sigs = u16::from_le_bytes(take_arr::<2>(cur, "sig count")?) as usize;
        let mut signatures = Vec::with_capacity(n_sigs.min(64));
        for _ in 0..n_sigs {
            signatures.push(BundleSignature {
                signer_pubkey: take_arr::<32>(cur, "signer pubkey")?,
                signature: take_arr::<64>(cur, "signature")?,
            });
        }
        if !cur.is_empty() {
            return Err(BundleError::Malformed("trailing bytes"));
        }
        Ok(Self { payload, signatures })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn payload() -> RootBundlePayload {
        RootBundlePayload {
            network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
            build_kind: BuildKind::Snapshot,
            from_anchor: ChainAnchor { block_hash: [0; 32], height: 0 },
            anchor: ChainAnchor { block_hash: [0xab; 32], height: 950_000 },
            utxo_muhash: [0xcd; 32],
            dust_threshold_sats: 576,
            max_utxos_per_spk: 100,
            params_hash: [0x11; 32],
            issued_at: 1_780_000_000,
            roots: vec![
                NamedRoot { label: "dpf/chunk/super_root".into(), root: [2; 32] },
                NamedRoot { label: "dpf/index/super_root".into(), root: [1; 32] },
                NamedRoot { label: "onion/super_root".into(), root: [3; 32] },
            ],
        }
    }

    #[test]
    fn payload_roundtrip() {
        let p = payload();
        let bytes = p.encode().unwrap();
        assert_eq!(RootBundlePayload::decode(&bytes).unwrap(), p);
    }

    #[test]
    fn rejects_unsorted_or_bad_roots() {
        let mut p = payload();
        p.roots.swap(0, 1);
        assert!(matches!(p.encode(), Err(BundleError::InvalidRoots(_))));

        let mut p = payload();
        p.roots[0].label = "has space".into();
        assert!(matches!(p.encode(), Err(BundleError::InvalidRoots(_))));

        let mut p = payload();
        p.roots.clear();
        assert!(matches!(p.encode(), Err(BundleError::InvalidRoots(_))));
    }

    #[test]
    fn root_lookup() {
        let p = payload();
        assert_eq!(p.root("dpf/index/super_root"), Some(&[1u8; 32]));
        assert_eq!(p.root("nope"), None);
    }

    #[test]
    fn quorum_2_of_3() {
        let p = payload();
        let (k1, k2, k3) = (key(1), key(2), key(3));
        let trusted = [
            k1.verifying_key().to_bytes(),
            k2.verifying_key().to_bytes(),
            k3.verifying_key().to_bytes(),
        ];
        let bundle = SignedRootBundle {
            payload: p.clone(),
            signatures: vec![
                sign_root_bundle(&p, &k1).unwrap(),
                sign_root_bundle(&p, &k3).unwrap(),
            ],
        };
        assert_eq!(bundle.verify_quorum(&trusted, 2), Ok(2));
        assert!(matches!(
            bundle.verify_quorum(&trusted, 3),
            Err(BundleError::QuorumNotMet { valid: 2, threshold: 3 })
        ));
    }

    #[test]
    fn unknown_signer_ignored_but_not_counted() {
        let p = payload();
        let (k1, stranger) = (key(1), key(9));
        let trusted = [key(1).verifying_key().to_bytes(), key(2).verifying_key().to_bytes()];
        let bundle = SignedRootBundle {
            payload: p.clone(),
            signatures: vec![
                sign_root_bundle(&p, &k1).unwrap(),
                sign_root_bundle(&p, &stranger).unwrap(),
            ],
        };
        assert_eq!(bundle.verify_quorum(&trusted, 1), Ok(1));
        assert!(bundle.verify_quorum(&trusted, 2).is_err());
    }

    #[test]
    fn tampered_payload_fails() {
        let p = payload();
        let k1 = key(1);
        let trusted = [k1.verifying_key().to_bytes()];
        let mut bundle = SignedRootBundle {
            payload: p.clone(),
            signatures: vec![sign_root_bundle(&p, &k1).unwrap()],
        };
        bundle.payload.roots[0].root = [0xff; 32];
        assert_eq!(bundle.verify_quorum(&trusted, 1), Err(BundleError::BadSignature));
    }

    #[test]
    fn duplicate_signer_rejected() {
        let p = payload();
        let k1 = key(1);
        let trusted = [k1.verifying_key().to_bytes()];
        let sig = sign_root_bundle(&p, &k1).unwrap();
        let bundle = SignedRootBundle {
            payload: p,
            signatures: vec![sig.clone(), sig],
        };
        assert_eq!(bundle.verify_quorum(&trusted, 1), Err(BundleError::DuplicateSigner));
    }

    #[test]
    fn signed_bundle_roundtrip() {
        let p = payload();
        let bundle = SignedRootBundle {
            payload: p.clone(),
            signatures: vec![
                sign_root_bundle(&p, &key(1)).unwrap(),
                sign_root_bundle(&p, &key(2)).unwrap(),
            ],
        };
        let bytes = bundle.encode().unwrap();
        assert_eq!(SignedRootBundle::decode(&bytes).unwrap(), bundle);
    }

    #[test]
    fn domain_separation() {
        // A signature over the raw payload (no domain tag) must not verify.
        let p = payload();
        let k1 = key(1);
        let trusted = [k1.verifying_key().to_bytes()];
        let raw_sig = k1.sign(&p.encode().unwrap());
        let bundle = SignedRootBundle {
            payload: p,
            signatures: vec![BundleSignature {
                signer_pubkey: k1.verifying_key().to_bytes(),
                signature: raw_sig.to_bytes(),
            }],
        };
        assert_eq!(bundle.verify_quorum(&trusted, 1), Err(BundleError::BadSignature));
    }
}
