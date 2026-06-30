//! Verification primitives for attested-builder database build evidence.
//!
//! This crate intentionally contains only pure parsing and verification logic.
//! It does not build databases, fetch SEV-SNP reports, or talk to servers.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub use rootbundle::{
    BuildKind, BundleError, BundleSignature, ChainAnchor, NamedRoot, RootBundlePayload,
    SignedRootBundle,
};

pub const EVIDENCE_DOMAIN: &[u8] = b"BitcoinPIR/attested-builder/build-evidence/v1\0";
pub const REPORT_DATA_DOMAIN: &[u8] =
    b"BitcoinPIR/attested-builder/build-evidence/report-data/v1\0";
pub const EVIDENCE_VERSION: u16 = 1;
pub const MAX_STRING_LEN: usize = 4096;
pub const MAX_MEASUREMENT_LEN: usize = 4096;
pub const SEV_SNP_REPORT_DATA_OFFSET: usize = 0x50;
pub const SEV_SNP_REPORT_DATA_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum DbAttestError {
    #[error("malformed build evidence: {0}")]
    Malformed(&'static str),
    #[error("{0}")]
    Message(String),
    #[error("I/O error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("root bundle: {0}")]
    RootBundle(#[from] rootbundle::BundleError),
    #[error("{field} mismatch: expected {expected}, got {actual}")]
    Mismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
}

pub type Result<T> = std::result::Result<T, DbAttestError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildEvidence {
    pub builder_git_commit: String,
    pub builder_binary_sha256: [u8; 32],
    pub tee_platform: String,
    pub tee_image_measurement: Vec<u8>,
    pub core_version: String,
    pub snapshot_sha256: [u8; 32],
    pub snapshot_bytes: u64,
    pub network_magic: [u8; 4],
    pub build_kind: BuildKind,
    pub from_anchor: ChainAnchor,
    pub anchor: ChainAnchor,
    pub utxo_muhash: [u8; 32],
    pub dust_threshold_sats: u64,
    pub max_utxos_per_spk: u32,
    pub params_hash: [u8; 32],
    pub index_bins_per_table: u32,
    pub chunk_bins_per_table: u32,
    pub onion_entry_size: u32,
    pub bucket_super_root: [u8; 32],
    pub onion_super_root: [u8; 32],
    pub root_bundle_payload_sha256: [u8; 32],
    pub signed_root_bundle_sha256: Option<[u8; 32]>,
    pub database_manifest_sha256: [u8; 32],
    pub all_artifacts_manifest_sha256: [u8; 32],
    pub server_db_manifest_sha256: [u8; 32],
}

impl BuildEvidence {
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_metadata_string("builder_git_commit", &self.builder_git_commit)?;
        validate_metadata_string("tee_platform", &self.tee_platform)?;
        validate_metadata_string("core_version", &self.core_version)?;
        if self.tee_image_measurement.len() > MAX_MEASUREMENT_LEN {
            return Err(DbAttestError::Message(format!(
                "tee_image_measurement too large: {} bytes",
                self.tee_image_measurement.len()
            )));
        }

        let mut out = Vec::with_capacity(512 + self.tee_image_measurement.len());
        put_u16(&mut out, EVIDENCE_VERSION);
        put_string(&mut out, &self.builder_git_commit)?;
        put_arr(&mut out, &self.builder_binary_sha256);
        put_string(&mut out, &self.tee_platform)?;
        put_bytes_with_u16_len(&mut out, &self.tee_image_measurement)?;
        put_string(&mut out, &self.core_version)?;
        put_arr(&mut out, &self.snapshot_sha256);
        put_u64(&mut out, self.snapshot_bytes);
        put_arr(&mut out, &self.network_magic);
        out.push(build_kind_to_byte(self.build_kind));
        put_anchor(&mut out, self.from_anchor);
        put_anchor(&mut out, self.anchor);
        put_arr(&mut out, &self.utxo_muhash);
        put_u64(&mut out, self.dust_threshold_sats);
        put_u32(&mut out, self.max_utxos_per_spk);
        put_arr(&mut out, &self.params_hash);
        put_u32(&mut out, self.index_bins_per_table);
        put_u32(&mut out, self.chunk_bins_per_table);
        put_u32(&mut out, self.onion_entry_size);
        put_arr(&mut out, &self.bucket_super_root);
        put_arr(&mut out, &self.onion_super_root);
        put_arr(&mut out, &self.root_bundle_payload_sha256);
        match self.signed_root_bundle_sha256 {
            Some(h) => {
                out.push(1);
                put_arr(&mut out, &h);
            }
            None => out.push(0),
        }
        put_arr(&mut out, &self.database_manifest_sha256);
        put_arr(&mut out, &self.all_artifacts_manifest_sha256);
        put_arr(&mut out, &self.server_db_manifest_sha256);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let cur = &mut &bytes[..];
        let version = take_u16(cur, "version")?;
        if version != EVIDENCE_VERSION {
            return Err(DbAttestError::Message(format!(
                "unsupported evidence version: {version}"
            )));
        }
        let builder_git_commit = take_string(cur, "builder_git_commit")?;
        let builder_binary_sha256 = take_arr::<32>(cur, "builder_binary_sha256")?;
        let tee_platform = take_string(cur, "tee_platform")?;
        let tee_image_measurement = take_bytes_with_u16_len(cur, "tee_image_measurement")?;
        let core_version = take_string(cur, "core_version")?;
        let snapshot_sha256 = take_arr::<32>(cur, "snapshot_sha256")?;
        let snapshot_bytes = take_u64(cur, "snapshot_bytes")?;
        let network_magic = take_arr::<4>(cur, "network_magic")?;
        let build_kind = byte_to_build_kind(take_u8(cur, "build_kind")?)?;
        let from_anchor = take_anchor(cur, "from_anchor")?;
        let anchor = take_anchor(cur, "anchor")?;
        let utxo_muhash = take_arr::<32>(cur, "utxo_muhash")?;
        let dust_threshold_sats = take_u64(cur, "dust_threshold_sats")?;
        let max_utxos_per_spk = take_u32(cur, "max_utxos_per_spk")?;
        let params_hash = take_arr::<32>(cur, "params_hash")?;
        let index_bins_per_table = take_u32(cur, "index_bins_per_table")?;
        let chunk_bins_per_table = take_u32(cur, "chunk_bins_per_table")?;
        let onion_entry_size = take_u32(cur, "onion_entry_size")?;
        let bucket_super_root = take_arr::<32>(cur, "bucket_super_root")?;
        let onion_super_root = take_arr::<32>(cur, "onion_super_root")?;
        let root_bundle_payload_sha256 = take_arr::<32>(cur, "root_bundle_payload_sha256")?;
        let signed_root_bundle_sha256 = match take_u8(cur, "has_signed_root_bundle")? {
            0 => None,
            1 => Some(take_arr::<32>(cur, "signed_root_bundle_sha256")?),
            _ => {
                return Err(DbAttestError::Malformed(
                    "bad signed root bundle option tag",
                ))
            }
        };
        let database_manifest_sha256 = take_arr::<32>(cur, "database_manifest_sha256")?;
        let all_artifacts_manifest_sha256 = take_arr::<32>(cur, "all_artifacts_manifest_sha256")?;
        let server_db_manifest_sha256 = take_arr::<32>(cur, "server_db_manifest_sha256")?;
        if !cur.is_empty() {
            return Err(DbAttestError::Malformed("trailing bytes"));
        }
        let evidence = Self {
            builder_git_commit,
            builder_binary_sha256,
            tee_platform,
            tee_image_measurement,
            core_version,
            snapshot_sha256,
            snapshot_bytes,
            network_magic,
            build_kind,
            from_anchor,
            anchor,
            utxo_muhash,
            dust_threshold_sats,
            max_utxos_per_spk,
            params_hash,
            index_bins_per_table,
            chunk_bins_per_table,
            onion_entry_size,
            bucket_super_root,
            onion_super_root,
            root_bundle_payload_sha256,
            signed_root_bundle_sha256,
            database_manifest_sha256,
            all_artifacts_manifest_sha256,
            server_db_manifest_sha256,
        };
        validate_metadata_string("builder_git_commit", &evidence.builder_git_commit)?;
        validate_metadata_string("tee_platform", &evidence.tee_platform)?;
        validate_metadata_string("core_version", &evidence.core_version)?;
        if evidence.tee_image_measurement.len() > MAX_MEASUREMENT_LEN {
            return Err(DbAttestError::Message(
                "tee_image_measurement too large".into(),
            ));
        }
        Ok(evidence)
    }

    pub fn evidence_digest(&self) -> Result<[u8; 32]> {
        evidence_digest(&self.encode()?)
    }

    pub fn evidence_file_sha256(&self) -> Result<[u8; 32]> {
        Ok(sha256_bytes(&self.encode()?))
    }

    pub fn report_data(&self) -> Result<[u8; 64]> {
        report_data_for_evidence_bytes(&self.encode()?)
    }

    pub fn verify_root_payload(&self, payload_bytes: &[u8]) -> Result<RootBundlePayload> {
        expect_hash(
            "root_bundle_payload_sha256",
            self.root_bundle_payload_sha256,
            sha256_bytes(payload_bytes),
        )?;
        let payload = RootBundlePayload::decode(payload_bytes)?;
        expect_arr("network_magic", self.network_magic, payload.network_magic)?;
        if self.build_kind != payload.build_kind {
            return Err(DbAttestError::Mismatch {
                field: "build_kind",
                expected: build_kind_label(self.build_kind).to_owned(),
                actual: build_kind_label(payload.build_kind).to_owned(),
            });
        }
        expect_anchor("from_anchor", self.from_anchor, payload.from_anchor)?;
        expect_anchor("anchor", self.anchor, payload.anchor)?;
        expect_hash("utxo_muhash", self.utxo_muhash, payload.utxo_muhash)?;
        expect_u64(
            "dust_threshold_sats",
            self.dust_threshold_sats,
            payload.dust_threshold_sats,
        )?;
        expect_u32(
            "max_utxos_per_spk",
            self.max_utxos_per_spk,
            payload.max_utxos_per_spk,
        )?;
        expect_hash("params_hash", self.params_hash, payload.params_hash)?;
        let bucket = payload
            .root("merkle/bucket/super_root")
            .ok_or(DbAttestError::Malformed(
                "payload missing bucket super root",
            ))?;
        let onion = payload
            .root("merkle/onion/super_root")
            .ok_or(DbAttestError::Malformed("payload missing onion super root"))?;
        expect_hash("bucket_super_root", self.bucket_super_root, *bucket)?;
        expect_hash("onion_super_root", self.onion_super_root, *onion)?;
        Ok(payload)
    }

    pub fn verify_sev_snp_report_data(&self, report: &[u8]) -> Result<()> {
        let actual = extract_sev_snp_report_data(report)?;
        let expected = self.report_data()?;
        expect_arr("sev_snp_report_data", expected, actual)
    }
}

#[derive(Clone, Debug)]
pub struct ProofDirectory {
    pub evidence: BuildEvidence,
    pub root_bundle_payload: RootBundlePayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofBundle {
    pub build_evidence: Vec<u8>,
    pub root_bundle_payload: Vec<u8>,
    pub sev_snp_report: Vec<u8>,
    pub database_manifest_sha256: Vec<u8>,
    pub all_artifacts_manifest_sha256: Vec<u8>,
    pub server_db_manifest_toml: Vec<u8>,
}

impl ProofBundle {
    pub fn verify(&self) -> Result<ProofDirectory> {
        let evidence = BuildEvidence::decode(&self.build_evidence)?;
        expect_hash(
            "build_evidence_file_sha256",
            evidence.evidence_file_sha256()?,
            sha256_bytes(&self.build_evidence),
        )?;

        let root_bundle_payload = evidence.verify_root_payload(&self.root_bundle_payload)?;
        expect_hash(
            "database_manifest_sha256",
            evidence.database_manifest_sha256,
            sha256_bytes(&self.database_manifest_sha256),
        )?;
        expect_hash(
            "all_artifacts_manifest_sha256",
            evidence.all_artifacts_manifest_sha256,
            sha256_bytes(&self.all_artifacts_manifest_sha256),
        )?;
        expect_hash(
            "server_db_manifest_sha256",
            evidence.server_db_manifest_sha256,
            sha256_bytes(&self.server_db_manifest_toml),
        )?;
        evidence.verify_sev_snp_report_data(&self.sev_snp_report)?;

        Ok(ProofDirectory {
            evidence,
            root_bundle_payload,
        })
    }
}

impl ProofDirectory {
    pub fn load_and_verify(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        ProofBundle {
            build_evidence: read_file(path.join("build-evidence.bin"))?,
            root_bundle_payload: read_file(path.join("root-bundle-payload.bin"))?,
            sev_snp_report: read_file(path.join("build-evidence.sev-snp-report.bin"))?,
            database_manifest_sha256: read_file(path.join("database.manifest.sha256"))?,
            all_artifacts_manifest_sha256: read_file(path.join("all-artifacts.manifest.sha256"))?,
            server_db_manifest_toml: read_file(path.join("server-db").join("MANIFEST.toml"))?,
        }
        .verify()
    }
}

pub fn evidence_digest(evidence_bytes: &[u8]) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(EVIDENCE_DOMAIN);
    h.update(evidence_bytes);
    Ok(h.finalize().into())
}

pub fn report_data_for_evidence_bytes(evidence_bytes: &[u8]) -> Result<[u8; 64]> {
    let evidence_hash = evidence_digest(evidence_bytes)?;
    let mut high = Sha256::new();
    high.update(REPORT_DATA_DOMAIN);
    high.update(evidence_hash);
    let high: [u8; 32] = high.finalize().into();

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&evidence_hash);
    out[32..].copy_from_slice(&high);
    Ok(out)
}

pub fn extract_sev_snp_report_data(report: &[u8]) -> Result<[u8; 64]> {
    if report.len() < SEV_SNP_REPORT_DATA_OFFSET + SEV_SNP_REPORT_DATA_LEN {
        return Err(DbAttestError::Message(format!(
            "SEV-SNP report too short for REPORT_DATA: {} bytes",
            report.len()
        )));
    }
    Ok(
        report[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + SEV_SNP_REPORT_DATA_LEN]
            .try_into()
            .unwrap(),
    )
}

pub fn display_hash_hex(internal: &[u8; 32]) -> String {
    let mut h = *internal;
    h.reverse();
    hex::encode(h)
}

pub fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

pub fn build_kind_label(kind: BuildKind) -> &'static str {
    match kind {
        BuildKind::Snapshot => "snapshot",
        BuildKind::Delta => "delta",
    }
}

fn validate_metadata_string(name: &str, value: &str) -> Result<()> {
    if value.len() > MAX_STRING_LEN {
        return Err(DbAttestError::Message(format!(
            "{name} too long: {} bytes",
            value.len()
        )));
    }
    if value.bytes().any(|b| b == b'\n' || b == b'\r' || b == 0) {
        return Err(DbAttestError::Message(format!(
            "{name} must not contain newline or NUL"
        )));
    }
    Ok(())
}

fn put_u16(out: &mut Vec<u8>, n: u16) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_arr<const N: usize>(out: &mut Vec<u8>, bytes: &[u8; N]) {
    out.extend_from_slice(bytes);
}

fn put_string(out: &mut Vec<u8>, value: &str) -> Result<()> {
    validate_metadata_string("string", value)?;
    put_bytes_with_u16_len(out, value.as_bytes())
}

fn put_bytes_with_u16_len(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len: u16 = bytes.len().try_into().map_err(|_| {
        DbAttestError::Message(format!("byte field too large: {} bytes", bytes.len()))
    })?;
    put_u16(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_anchor(out: &mut Vec<u8>, anchor: ChainAnchor) {
    out.extend_from_slice(&anchor.block_hash);
    put_u32(out, anchor.height);
}

fn take<'a>(cur: &mut &'a [u8], n: usize, what: &'static str) -> Result<&'a [u8]> {
    if cur.len() < n {
        return Err(DbAttestError::Malformed(what));
    }
    let (head, rest) = cur.split_at(n);
    *cur = rest;
    Ok(head)
}

fn take_arr<const N: usize>(cur: &mut &[u8], what: &'static str) -> Result<[u8; N]> {
    Ok(take(cur, N, what)?.try_into().unwrap())
}

fn take_u8(cur: &mut &[u8], what: &'static str) -> Result<u8> {
    Ok(take_arr::<1>(cur, what)?[0])
}

fn take_u16(cur: &mut &[u8], what: &'static str) -> Result<u16> {
    Ok(u16::from_le_bytes(take_arr::<2>(cur, what)?))
}

fn take_u32(cur: &mut &[u8], what: &'static str) -> Result<u32> {
    Ok(u32::from_le_bytes(take_arr::<4>(cur, what)?))
}

fn take_u64(cur: &mut &[u8], what: &'static str) -> Result<u64> {
    Ok(u64::from_le_bytes(take_arr::<8>(cur, what)?))
}

fn take_string(cur: &mut &[u8], what: &'static str) -> Result<String> {
    let bytes = take_bytes_with_u16_len(cur, what)?;
    let value = String::from_utf8(bytes)
        .map_err(|_| DbAttestError::Message(format!("{what} is not UTF-8")))?;
    validate_metadata_string(what, &value)?;
    Ok(value)
}

fn take_bytes_with_u16_len(cur: &mut &[u8], what: &'static str) -> Result<Vec<u8>> {
    let len = take_u16(cur, what)? as usize;
    Ok(take(cur, len, what)?.to_vec())
}

fn take_anchor(cur: &mut &[u8], what: &'static str) -> Result<ChainAnchor> {
    Ok(ChainAnchor {
        block_hash: take_arr::<32>(cur, what)?,
        height: take_u32(cur, what)?,
    })
}

fn build_kind_to_byte(kind: BuildKind) -> u8 {
    match kind {
        BuildKind::Snapshot => 0,
        BuildKind::Delta => 1,
    }
}

fn byte_to_build_kind(b: u8) -> Result<BuildKind> {
    match b {
        0 => Ok(BuildKind::Snapshot),
        1 => Ok(BuildKind::Delta),
        _ => Err(DbAttestError::Message(format!("unknown build kind: {b}"))),
    }
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn sha256_file(path: impl AsRef<Path>) -> Result<([u8; 32], u64)> {
    let path = path.as_ref();
    let mut file = File::open(path).map_err(|source| DbAttestError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    let mut bytes = 0u64;
    loop {
        let n = file.read(&mut buf).map_err(|source| DbAttestError::Io {
            path: path.display().to_string(),
            source,
        })?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        h.update(&buf[..n]);
    }
    Ok((h.finalize().into(), bytes))
}

pub fn sha256_file_32(path: impl AsRef<Path>) -> Result<[u8; 32]> {
    sha256_file(path).map(|(h, _)| h)
}

fn read_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref();
    std::fs::read(path).map_err(|source| DbAttestError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn expect_hash(field: &'static str, expected: [u8; 32], actual: [u8; 32]) -> Result<()> {
    expect_arr(field, expected, actual)
}

fn expect_arr<const N: usize>(
    field: &'static str,
    expected: [u8; N],
    actual: [u8; N],
) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(DbAttestError::Mismatch {
            field,
            expected: hex::encode(expected),
            actual: hex::encode(actual),
        })
    }
}

fn expect_anchor(field: &'static str, expected: ChainAnchor, actual: ChainAnchor) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(DbAttestError::Mismatch {
            field,
            expected: format!(
                "{}:{}",
                display_hash_hex(&expected.block_hash),
                expected.height
            ),
            actual: format!("{}:{}", display_hash_hex(&actual.block_hash), actual.height),
        })
    }
}

fn expect_u32(field: &'static str, expected: u32, actual: u32) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(DbAttestError::Mismatch {
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}

fn expect_u64(field: &'static str, expected: u64, actual: u64) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(DbAttestError::Mismatch {
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_evidence() -> BuildEvidence {
        BuildEvidence {
            builder_git_commit: "abc123".into(),
            builder_binary_sha256: [1u8; 32],
            tee_platform: "sev-snp".into(),
            tee_image_measurement: vec![2u8; 48],
            core_version: "Bitcoin Core v31.0.0".into(),
            snapshot_sha256: [3u8; 32],
            snapshot_bytes: 1234,
            network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
            build_kind: BuildKind::Snapshot,
            from_anchor: ChainAnchor {
                block_hash: [0u8; 32],
                height: 0,
            },
            anchor: ChainAnchor {
                block_hash: [4u8; 32],
                height: 953_383,
            },
            utxo_muhash: [5u8; 32],
            dust_threshold_sats: 576,
            max_utxos_per_spk: 100,
            params_hash: [6u8; 32],
            index_bins_per_table: 570_712,
            chunk_bins_per_table: 1_074_267,
            onion_entry_size: 3328,
            bucket_super_root: [7u8; 32],
            onion_super_root: [8u8; 32],
            root_bundle_payload_sha256: [9u8; 32],
            signed_root_bundle_sha256: Some([10u8; 32]),
            database_manifest_sha256: [11u8; 32],
            all_artifacts_manifest_sha256: [12u8; 32],
            server_db_manifest_sha256: [13u8; 32],
        }
    }

    #[test]
    fn evidence_roundtrip() {
        let evidence = sample_evidence();
        let encoded = evidence.encode().unwrap();
        assert_eq!(BuildEvidence::decode(&encoded).unwrap(), evidence);
    }

    #[test]
    fn report_data_is_full_64_byte_binding() {
        let evidence = sample_evidence();
        let encoded = evidence.encode().unwrap();
        let evidence_hash = evidence_digest(&encoded).unwrap();
        let report_data = evidence.report_data().unwrap();
        assert_eq!(&report_data[..32], &evidence_hash);
        assert_ne!(&report_data[32..], &[0u8; 32]);

        let mut changed = evidence.clone();
        changed.server_db_manifest_sha256 = [99u8; 32];
        assert_ne!(report_data, changed.report_data().unwrap());
    }

    #[test]
    fn rejects_newline_metadata() {
        let mut evidence = sample_evidence();
        evidence.core_version = "bad\nversion".into();
        assert!(matches!(evidence.encode(), Err(DbAttestError::Message(_))));
    }
}
