//! Client-side fetch and verification for attested-builder DB proof bundles.

use crate::protocol::{
    decode_catalog, encode_request, REQ_GET_DB_CATALOG, RESP_DB_CATALOG, RESP_ERROR,
};
use crate::transport::PirTransport;
use pir_db_attest::{
    build_kind_label, display_hash_hex, hex32, BuildKind, BuildParamsV2,
    ChainAnchor as AttestedChainAnchor, OnionQueryLayoutV2, ProofBundle, ProofDirectory,
    EVIDENCE_VERSION_V2,
};
use pir_sdk::{DatabaseCatalog, DatabaseInfo, DatabaseKind, PirError, PirResult};

pub const REQ_GET_DB_PROOF: u8 = 0x0a;
pub const RESP_DB_PROOF: u8 = 0x0a;
pub const REQ_GET_DB_PROOF_V2: u8 = 0x0c;
pub const RESP_DB_PROOF_V2: u8 = 0x0c;
pub const DATABASE_PROOF_BUNDLE_VERSION: u16 = 1;
pub const DATABASE_PROOF_BUNDLE_VERSION_V2: u16 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseProofBundle {
    pub db_id: u8,
    pub build_evidence: Vec<u8>,
    pub root_bundle_payload: Vec<u8>,
    pub sev_snp_report: Vec<u8>,
    pub database_manifest_sha256: Vec<u8>,
    pub all_artifacts_manifest_sha256: Vec<u8>,
    pub server_db_manifest_toml: Vec<u8>,
}

impl DatabaseProofBundle {
    pub fn as_attest_bundle(&self) -> ProofBundle {
        ProofBundle {
            build_evidence: self.build_evidence.clone(),
            root_bundle_payload: self.root_bundle_payload.clone(),
            sev_snp_report: self.sev_snp_report.clone(),
            database_manifest_sha256: self.database_manifest_sha256.clone(),
            all_artifacts_manifest_sha256: self.all_artifacts_manifest_sha256.clone(),
            server_db_manifest_toml: self.server_db_manifest_toml.clone(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DatabaseProofPolicy {
    pub expected_network_magic: Option<[u8; 4]>,
    pub expected_params_hash: Option<[u8; 32]>,
    pub allowed_builder_binary_sha256: Vec<[u8; 32]>,
    pub allowed_builder_git_commits: Vec<String>,
}

impl DatabaseProofPolicy {
    pub fn mainnet() -> Self {
        Self {
            expected_network_magic: Some([0xf9, 0xbe, 0xb4, 0xd9]),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDatabaseRoots {
    pub db_id: u8,
    pub build_kind: BuildKind,
    pub from_height: u32,
    pub from_block_hash: [u8; 32],
    pub height: u32,
    pub block_hash: [u8; 32],
    pub muhash: [u8; 32],
    pub bucket_super_root: [u8; 32],
    pub onion_super_root: [u8; 32],
    pub onion_entry_size: u32,
    pub onion_layout_v2: Option<OnionQueryLayoutV2>,
    pub params_hash: [u8; 32],
    pub network_magic: [u8; 4],
    pub builder_binary_sha256: [u8; 32],
    pub builder_git_commit: String,
}

impl VerifiedDatabaseRoots {
    pub fn block_hash_hex(&self) -> String {
        display_hash_hex(&self.block_hash)
    }

    pub fn from_block_hash_hex(&self) -> String {
        display_hash_hex(&self.from_block_hash)
    }

    pub fn muhash_hex(&self) -> String {
        display_hash_hex(&self.muhash)
    }

    pub fn bucket_super_root_hex(&self) -> String {
        hex32(&self.bucket_super_root)
    }

    pub fn onion_super_root_hex(&self) -> String {
        hex32(&self.onion_super_root)
    }
}

pub async fn fetch_database_proof(
    transport: &mut dyn PirTransport,
    db_id: u8,
) -> PirResult<DatabaseProofBundle> {
    let request = encode_request(REQ_GET_DB_PROOF, &[db_id]);
    let response = transport.roundtrip(&request).await?;
    decode_database_proof_response(&response)
}

pub async fn fetch_database_proof_v2(
    transport: &mut dyn PirTransport,
    db_id: u8,
) -> PirResult<DatabaseProofBundle> {
    let request = encode_request(REQ_GET_DB_PROOF_V2, &[db_id]);
    let response = transport.roundtrip(&request).await?;
    decode_database_proof_v2_response(&response)
}

pub async fn fetch_database_catalog(
    transport: &mut dyn PirTransport,
) -> PirResult<DatabaseCatalog> {
    let request = encode_request(REQ_GET_DB_CATALOG, &[]);
    let response = transport.roundtrip(&request).await?;
    if response.is_empty() {
        return Err(PirError::Decode("database catalog response empty".into()));
    }
    if response[0] == RESP_ERROR {
        return Err(PirError::ServerError(decode_error_message(&response)));
    }
    if response[0] != RESP_DB_CATALOG {
        return Err(PirError::UnexpectedResponse {
            expected: "RESP_DB_CATALOG (0x02)",
            actual: format!("0x{:02x}", response[0]),
        });
    }
    decode_catalog(&response[1..])
}

pub fn verify_database_proof(
    db_info: &DatabaseInfo,
    bundle: &DatabaseProofBundle,
    policy: &DatabaseProofPolicy,
) -> PirResult<VerifiedDatabaseRoots> {
    if bundle.db_id != db_info.db_id {
        return Err(proof_mismatch(
            "db_id",
            db_info.db_id.to_string(),
            bundle.db_id.to_string(),
        ));
    }

    let verified = bundle.as_attest_bundle().verify().map_err(|e| {
        PirError::VerificationFailed(format!("db proof verification failed: {}", e))
    })?;
    verify_against_catalog_and_policy(db_info, &verified, policy)
}

pub fn verify_database_proof_v2(
    db_info: &DatabaseInfo,
    bundle: &DatabaseProofBundle,
    policy: &DatabaseProofPolicy,
) -> PirResult<VerifiedDatabaseRoots> {
    let roots = verify_database_proof(db_info, bundle, policy)?;
    if roots.onion_layout_v2.is_none() {
        return Err(PirError::VerificationFailed(
            "strict OnionPIR requires database proof v2".into(),
        ));
    }
    Ok(roots)
}

/// Decode and verify a raw `RESP_DB_PROOF` payload without owning a
/// transport or client session.
///
/// `response_payload` starts at the response opcode and therefore does not
/// include the outer four-byte wire length prefix.  This is the synchronous
/// counterpart of [`fetch_database_proof`], intended for callers that own
/// their transport separately (for example the standalone browser OnionPIR
/// client).  Verification is deliberately side-effect free: the returned
/// roots still have to be installed explicitly by the caller after any
/// application-level production-pin comparison.
pub fn verify_database_proof_response(
    db_info: &DatabaseInfo,
    response_payload: &[u8],
    policy: &DatabaseProofPolicy,
) -> PirResult<VerifiedDatabaseRoots> {
    let bundle = decode_database_proof_response(response_payload)?;
    verify_database_proof(db_info, &bundle, policy)
}

pub fn verify_database_proof_v2_response(
    db_info: &DatabaseInfo,
    response_payload: &[u8],
    policy: &DatabaseProofPolicy,
) -> PirResult<VerifiedDatabaseRoots> {
    let bundle = decode_database_proof_v2_response(response_payload)?;
    verify_database_proof_v2(db_info, &bundle, policy)
}

pub fn decode_database_proof_response(data: &[u8]) -> PirResult<DatabaseProofBundle> {
    decode_database_proof_response_for(
        data,
        RESP_DB_PROOF,
        DATABASE_PROOF_BUNDLE_VERSION,
        "RESP_DB_PROOF (0x0a)",
    )
}

pub fn decode_database_proof_v2_response(data: &[u8]) -> PirResult<DatabaseProofBundle> {
    decode_database_proof_response_for(
        data,
        RESP_DB_PROOF_V2,
        DATABASE_PROOF_BUNDLE_VERSION_V2,
        "RESP_DB_PROOF_V2 (0x0c)",
    )
}

fn decode_database_proof_response_for(
    data: &[u8],
    expected_opcode: u8,
    expected_version: u16,
    expected_label: &'static str,
) -> PirResult<DatabaseProofBundle> {
    if data.is_empty() {
        return Err(PirError::Decode("db proof response empty".into()));
    }
    if data[0] == RESP_ERROR {
        return Err(PirError::ServerError(decode_error_message(data)));
    }
    if data[0] != expected_opcode {
        return Err(PirError::UnexpectedResponse {
            expected: expected_label,
            actual: format!("0x{:02x}", data[0]),
        });
    }
    decode_database_proof_bundle(&data[1..], expected_version)
}

fn verify_against_catalog_and_policy(
    db_info: &DatabaseInfo,
    verified: &ProofDirectory,
    policy: &DatabaseProofPolicy,
) -> PirResult<VerifiedDatabaseRoots> {
    let evidence = &verified.evidence;
    let expected_kind = match db_info.kind {
        DatabaseKind::Full => BuildKind::Snapshot,
        DatabaseKind::Delta { .. } => BuildKind::Delta,
    };
    if evidence.build_kind != expected_kind {
        return Err(proof_mismatch(
            "build_kind",
            build_kind_label(expected_kind).to_owned(),
            build_kind_label(evidence.build_kind).to_owned(),
        ));
    }
    expect_u32("height", db_info.height, evidence.anchor.height)?;
    expect_u32(
        "from_height",
        db_info.base_height(),
        evidence.from_anchor.height,
    )?;
    expect_u32(
        "index_bins_per_table",
        db_info.index_bins,
        evidence.index_bins_per_table,
    )?;
    expect_u32(
        "chunk_bins_per_table",
        db_info.chunk_bins,
        evidence.chunk_bins_per_table,
    )?;
    verify_catalog_anchor(db_info, verified)?;
    verify_catalog_query_parameters(db_info)?;
    if let Some(expected) = policy.expected_network_magic {
        expect_arr("network_magic", &expected, &evidence.network_magic)?;
    }
    if let Some(expected) = policy.expected_params_hash {
        expect_arr("params_hash", &expected, &evidence.params_hash)?;
    }
    let onion_layout_v2 = if evidence.version == EVIDENCE_VERSION_V2 {
        let layout = evidence.onion_layout_v2.ok_or_else(|| {
            PirError::VerificationFailed("v2 evidence missing typed Onion layout".into())
        })?;
        layout
            .validate()
            .map_err(|e| PirError::VerificationFailed(format!("invalid v2 Onion layout: {e}")))?;
        let params = BuildParamsV2 {
            index_bins_per_table: evidence.index_bins_per_table,
            chunk_bins_per_table: evidence.chunk_bins_per_table,
            onion: layout,
        };
        expect_arr(
            "params_hash_v2",
            &params.params_hash(),
            &evidence.params_hash,
        )?;
        Some(layout)
    } else {
        None
    };
    if !policy.allowed_builder_binary_sha256.is_empty()
        && !policy
            .allowed_builder_binary_sha256
            .contains(&evidence.builder_binary_sha256)
    {
        return Err(proof_mismatch(
            "builder_binary_sha256",
            policy
                .allowed_builder_binary_sha256
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>()
                .join(","),
            hex::encode(evidence.builder_binary_sha256),
        ));
    }
    if !policy.allowed_builder_git_commits.is_empty()
        && !policy
            .allowed_builder_git_commits
            .iter()
            .any(|allowed| allowed == &evidence.builder_git_commit)
    {
        return Err(proof_mismatch(
            "builder_git_commit",
            policy.allowed_builder_git_commits.join(","),
            evidence.builder_git_commit.clone(),
        ));
    }

    Ok(VerifiedDatabaseRoots {
        db_id: db_info.db_id,
        build_kind: evidence.build_kind,
        from_height: evidence.from_anchor.height,
        from_block_hash: evidence.from_anchor.block_hash,
        height: evidence.anchor.height,
        block_hash: evidence.anchor.block_hash,
        muhash: evidence.utxo_muhash,
        bucket_super_root: evidence.bucket_super_root,
        onion_super_root: evidence.onion_super_root,
        onion_entry_size: evidence.onion_entry_size,
        onion_layout_v2,
        params_hash: evidence.params_hash,
        network_magic: evidence.network_magic,
        builder_binary_sha256: evidence.builder_binary_sha256,
        builder_git_commit: evidence.builder_git_commit.clone(),
    })
}

fn decode_database_proof_bundle(
    data: &[u8],
    expected_version: u16,
) -> PirResult<DatabaseProofBundle> {
    if data.len() < 3 {
        return Err(PirError::Decode("db proof bundle too short".into()));
    }
    let version = u16::from_le_bytes(data[0..2].try_into().unwrap());
    if version != expected_version {
        return Err(PirError::Decode(format!(
            "unsupported db proof bundle version: {}",
            version
        )));
    }
    let db_id = data[2];
    let mut pos = 3;
    let build_evidence = take_lp_bytes(data, &mut pos, "build_evidence")?;
    let root_bundle_payload = take_lp_bytes(data, &mut pos, "root_bundle_payload")?;
    let sev_snp_report = take_lp_bytes(data, &mut pos, "sev_snp_report")?;
    let database_manifest_sha256 = take_lp_bytes(data, &mut pos, "database_manifest_sha256")?;
    let all_artifacts_manifest_sha256 =
        take_lp_bytes(data, &mut pos, "all_artifacts_manifest_sha256")?;
    let server_db_manifest_toml = take_lp_bytes(data, &mut pos, "server_db_manifest_toml")?;
    if pos != data.len() {
        return Err(PirError::Decode(
            "db proof bundle has trailing bytes".into(),
        ));
    }
    Ok(DatabaseProofBundle {
        db_id,
        build_evidence,
        root_bundle_payload,
        sev_snp_report,
        database_manifest_sha256,
        all_artifacts_manifest_sha256,
        server_db_manifest_toml,
    })
}

fn take_lp_bytes(data: &[u8], pos: &mut usize, field: &'static str) -> PirResult<Vec<u8>> {
    if *pos + 4 > data.len() {
        return Err(PirError::Decode(format!(
            "{}: missing u32 length prefix",
            field
        )));
    }
    let n = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + n > data.len() {
        return Err(PirError::Decode(format!(
            "{}: body truncated: claimed {} bytes, have {}",
            field,
            n,
            data.len() - *pos
        )));
    }
    let out = data[*pos..*pos + n].to_vec();
    *pos += n;
    Ok(out)
}

fn decode_error_message(data: &[u8]) -> String {
    if data.len() >= 5 {
        let len = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
        if 5 + len <= data.len() {
            return String::from_utf8_lossy(&data[5..5 + len]).into_owned();
        }
    }
    String::from_utf8_lossy(&data[1..]).into_owned()
}

fn verify_catalog_anchor(db_info: &DatabaseInfo, verified: &ProofDirectory) -> PirResult<()> {
    use pir_core::cuckoo::HeaderAnchor;

    let evidence = &verified.evidence;
    match (evidence.build_kind, db_info.chain_anchor()) {
        (BuildKind::Snapshot, Some(HeaderAnchor::Snapshot(anchor))) => {
            expect_chain_anchor(
                "catalog_anchor",
                &evidence.anchor,
                anchor.block_hash,
                anchor.block_height,
            )?;
        }
        (BuildKind::Delta, Some(HeaderAnchor::Delta(anchor))) => {
            expect_chain_anchor(
                "catalog_from_anchor",
                &evidence.from_anchor,
                anchor.from.block_hash,
                anchor.from.block_height,
            )?;
            expect_chain_anchor(
                "catalog_anchor",
                &evidence.anchor,
                anchor.to.block_hash,
                anchor.to.block_height,
            )?;
        }
        (_, None) => {
            return Err(proof_mismatch(
                "catalog_anchor",
                "chain-anchored catalog entry".into(),
                "missing or malformed catalog anchor".into(),
            ));
        }
        (BuildKind::Snapshot, Some(HeaderAnchor::Delta(_))) => {
            return Err(proof_mismatch(
                "catalog_anchor_kind",
                "snapshot".into(),
                "delta".into(),
            ));
        }
        (BuildKind::Delta, Some(HeaderAnchor::Snapshot(_))) => {
            return Err(proof_mismatch(
                "catalog_anchor_kind",
                "delta".into(),
                "snapshot".into(),
            ));
        }
    }
    Ok(())
}

/// Bind every catalog field that controls client-side query placement to the
/// chain anchor already authenticated by the database proof.
fn verify_catalog_query_parameters(db_info: &DatabaseInfo) -> PirResult<()> {
    use pir_core::cuckoo::HeaderAnchor;
    use pir_core::params::{compute_dpf_n, K, K_CHUNK};
    use pir_core::seeds::{DeltaSeeds, SnapshotSeeds};

    crate::protocol::validate_db_geometry(db_info).map_err(|err| {
        PirError::VerificationFailed(format!("db proof catalog geometry invalid: {err}"))
    })?;
    expect_usize("index_k", K, db_info.index_k as usize)?;
    expect_usize("chunk_k", K_CHUNK, db_info.chunk_k as usize)?;
    expect_usize(
        "dpf_n_index",
        compute_dpf_n(db_info.index_bins as usize) as usize,
        db_info.dpf_n_index as usize,
    )?;
    expect_usize(
        "dpf_n_chunk",
        compute_dpf_n(db_info.chunk_bins as usize) as usize,
        db_info.dpf_n_chunk as usize,
    )?;

    let (expected_tag_seed, expected_index_seed, expected_chunk_seed) = match db_info.chain_anchor()
    {
        Some(HeaderAnchor::Snapshot(anchor)) => {
            let seeds = SnapshotSeeds::derive(&anchor);
            (seeds.index_tag, seeds.index_master, seeds.chunk_master)
        }
        Some(HeaderAnchor::Delta(anchor)) => {
            let seeds = DeltaSeeds::derive(&anchor);
            (seeds.index_tag, seeds.index_master, seeds.chunk_master)
        }
        None => {
            return Err(proof_mismatch(
                "catalog_anchor",
                "chain-anchored catalog entry".into(),
                "missing or malformed catalog anchor".into(),
            ));
        }
    };

    expect_u64("tag_seed", expected_tag_seed, db_info.tag_seed)?;
    expect_u64(
        "index_master_seed",
        expected_index_seed,
        db_info.index_master_seed,
    )?;
    expect_u64(
        "chunk_master_seed",
        expected_chunk_seed,
        db_info.chunk_master_seed,
    )
}

fn expect_chain_anchor(
    field: &'static str,
    expected: &AttestedChainAnchor,
    actual_hash: [u8; 32],
    actual_height: u32,
) -> PirResult<()> {
    expect_arr(field, &expected.block_hash, &actual_hash)?;
    expect_u32(field, expected.height, actual_height)
}

fn expect_u32(field: &'static str, expected: u32, actual: u32) -> PirResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(proof_mismatch(
            field,
            expected.to_string(),
            actual.to_string(),
        ))
    }
}

fn expect_u64(field: &'static str, expected: u64, actual: u64) -> PirResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(proof_mismatch(
            field,
            expected.to_string(),
            actual.to_string(),
        ))
    }
}

fn expect_usize(field: &'static str, expected: usize, actual: usize) -> PirResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(proof_mismatch(
            field,
            expected.to_string(),
            actual.to_string(),
        ))
    }
}

fn expect_arr<const N: usize>(
    field: &'static str,
    expected: &[u8; N],
    actual: &[u8; N],
) -> PirResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(proof_mismatch(
            field,
            hex::encode(expected),
            hex::encode(actual),
        ))
    }
}

fn proof_mismatch(field: &'static str, expected: String, actual: String) -> PirError {
    PirError::VerificationFailed(format!(
        "db proof {} mismatch: expected {}, got {}",
        field, expected, actual
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::PirTransport;
    use async_trait::async_trait;
    use pir_core::seeds::{ChainAnchor as CoreChainAnchor, DeltaAnchor, DeltaSeeds, SnapshotSeeds};
    use pir_db_attest::{ChainAnchor, RootBundlePayload};
    use pir_sdk::PirResult;
    use sha2::{Digest, Sha256};

    fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn sample_bundle() -> (DatabaseProofBundle, DatabaseInfo) {
        let roots = vec![
            pir_db_attest::NamedRoot {
                label: "merkle/bucket/super_root".into(),
                root: [7u8; 32],
            },
            pir_db_attest::NamedRoot {
                label: "merkle/onion/super_root".into(),
                root: [8u8; 32],
            },
        ];
        let payload = RootBundlePayload {
            network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
            build_kind: BuildKind::Delta,
            from_anchor: ChainAnchor {
                block_hash: [3u8; 32],
                height: 940_611,
            },
            anchor: ChainAnchor {
                block_hash: [4u8; 32],
                height: 948_454,
            },
            utxo_muhash: [5u8; 32],
            dust_threshold_sats: 576,
            max_utxos_per_spk: 100,
            params_hash: [6u8; 32],
            issued_at: 1_700_000_000,
            roots,
        };
        let root_bundle_payload = payload.encode().unwrap();
        let database_manifest_sha256 = b"database manifest\n".to_vec();
        let all_artifacts_manifest_sha256 = b"all artifacts\n".to_vec();
        let server_db_manifest_toml = b"[[file]]\npath='batch_pir_cuckoo.bin'\n".to_vec();
        let evidence = pir_db_attest::BuildEvidence {
            version: pir_db_attest::EVIDENCE_VERSION_V1,
            builder_git_commit: "abc123".into(),
            builder_binary_sha256: [1u8; 32],
            tee_platform: "sev-snp".into(),
            tee_image_measurement: Vec::new(),
            core_version: "Bitcoin Core v31.0.0".into(),
            snapshot_sha256: [2u8; 32],
            snapshot_bytes: 42,
            network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
            build_kind: BuildKind::Delta,
            from_anchor: ChainAnchor {
                block_hash: [3u8; 32],
                height: 940_611,
            },
            anchor: ChainAnchor {
                block_hash: [4u8; 32],
                height: 948_454,
            },
            utxo_muhash: [5u8; 32],
            dust_threshold_sats: 576,
            max_utxos_per_spk: 100,
            params_hash: [6u8; 32],
            index_bins_per_table: 53_282,
            chunk_bins_per_table: 112_332,
            onion_entry_size: 3328,
            bucket_super_root: [7u8; 32],
            onion_super_root: [8u8; 32],
            root_bundle_payload_sha256: sha256(&root_bundle_payload),
            signed_root_bundle_sha256: None,
            database_manifest_sha256: sha256(&database_manifest_sha256),
            all_artifacts_manifest_sha256: sha256(&all_artifacts_manifest_sha256),
            server_db_manifest_sha256: sha256(&server_db_manifest_toml),
            evidence_mode: pir_db_attest::EvidenceMode::FullBuild,
            predecessor_evidence_sha256: None,
            onion_layout_v2: None,
        };
        let build_evidence = evidence.encode().unwrap();
        let report_data = pir_db_attest::report_data_for_evidence_bytes(
            pir_db_attest::EVIDENCE_VERSION_V1,
            &build_evidence,
        )
        .unwrap();
        let mut sev_snp_report = vec![
            0u8;
            pir_db_attest::SEV_SNP_REPORT_DATA_OFFSET
                + pir_db_attest::SEV_SNP_REPORT_DATA_LEN
        ];
        sev_snp_report[pir_db_attest::SEV_SNP_REPORT_DATA_OFFSET
            ..pir_db_attest::SEV_SNP_REPORT_DATA_OFFSET + pir_db_attest::SEV_SNP_REPORT_DATA_LEN]
            .copy_from_slice(&report_data);

        let bundle = DatabaseProofBundle {
            db_id: 1,
            build_evidence,
            root_bundle_payload,
            sev_snp_report,
            database_manifest_sha256,
            all_artifacts_manifest_sha256,
            server_db_manifest_toml,
        };
        let catalog_anchor = DeltaAnchor {
            from: CoreChainAnchor {
                block_hash: [3u8; 32],
                block_height: 940_611,
            },
            to: CoreChainAnchor {
                block_hash: [4u8; 32],
                block_height: 948_454,
            },
        };
        let seeds = DeltaSeeds::derive(&catalog_anchor);
        let db_info = DatabaseInfo {
            db_id: 1,
            kind: DatabaseKind::Delta {
                base_height: 940_611,
            },
            name: "delta_940611_948454".into(),
            height: 948_454,
            index_bins: 53_282,
            chunk_bins: 112_332,
            index_k: pir_core::params::K as u8,
            chunk_k: pir_core::params::K_CHUNK as u8,
            tag_seed: seeds.index_tag,
            dpf_n_index: 16,
            dpf_n_chunk: 17,
            has_bucket_merkle: true,
            index_master_seed: seeds.index_master,
            chunk_master_seed: seeds.chunk_master,
            anchor_kind: 2,
            anchor_bytes: catalog_anchor.to_bytes().to_vec(),
        };
        (bundle, db_info)
    }

    fn sample_bundle_v2() -> (DatabaseProofBundle, DatabaseInfo) {
        let (mut bundle, db_info) = sample_bundle();
        let mut evidence = pir_db_attest::BuildEvidence::decode(&bundle.build_evidence).unwrap();
        let layout = OnionQueryLayoutV2::current(116_030, 965, 4_792, 3_328);
        let params = BuildParamsV2 {
            index_bins_per_table: evidence.index_bins_per_table,
            chunk_bins_per_table: evidence.chunk_bins_per_table,
            onion: layout,
        };
        let mut payload = RootBundlePayload::decode(&bundle.root_bundle_payload).unwrap();
        payload.params_hash = params.params_hash();
        bundle.root_bundle_payload = payload.encode().unwrap();
        evidence.version = EVIDENCE_VERSION_V2;
        evidence.evidence_mode = pir_db_attest::EvidenceMode::ReattestExisting;
        evidence.predecessor_evidence_sha256 = Some([9u8; 32]);
        evidence.onion_layout_v2 = Some(layout);
        evidence.params_hash = params.params_hash();
        evidence.root_bundle_payload_sha256 = sha256(&bundle.root_bundle_payload);
        bundle.build_evidence = evidence.encode().unwrap();
        let report_data = pir_db_attest::report_data_for_evidence_bytes(
            EVIDENCE_VERSION_V2,
            &bundle.build_evidence,
        )
        .unwrap();
        bundle.sev_snp_report[pir_db_attest::SEV_SNP_REPORT_DATA_OFFSET
            ..pir_db_attest::SEV_SNP_REPORT_DATA_OFFSET + pir_db_attest::SEV_SNP_REPORT_DATA_LEN]
            .copy_from_slice(&report_data);
        (bundle, db_info)
    }

    fn encode_proof_response_version(
        bundle: &DatabaseProofBundle,
        version: u16,
        opcode: u8,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&version.to_le_bytes());
        body.push(bundle.db_id);
        lp(&mut body, &bundle.build_evidence);
        lp(&mut body, &bundle.root_bundle_payload);
        lp(&mut body, &bundle.sev_snp_report);
        lp(&mut body, &bundle.database_manifest_sha256);
        lp(&mut body, &bundle.all_artifacts_manifest_sha256);
        lp(&mut body, &bundle.server_db_manifest_toml);
        let mut response = vec![opcode];
        response.extend_from_slice(&body);
        response
    }

    fn encode_proof_response(bundle: &DatabaseProofBundle) -> Vec<u8> {
        encode_proof_response_version(bundle, DATABASE_PROOF_BUNDLE_VERSION, RESP_DB_PROOF)
    }

    fn encode_catalog_response(db: &DatabaseInfo) -> Vec<u8> {
        let mut response = vec![RESP_DB_CATALOG];
        response.push(1); // num_dbs
        response.push(db.db_id);
        response.push(match db.kind {
            DatabaseKind::Full => 0,
            DatabaseKind::Delta { .. } => 1,
        });
        response.push(db.name.len() as u8);
        response.extend_from_slice(db.name.as_bytes());
        response.extend_from_slice(&db.base_height().to_le_bytes());
        response.extend_from_slice(&db.height.to_le_bytes());
        response.extend_from_slice(&db.index_bins.to_le_bytes());
        response.extend_from_slice(&db.chunk_bins.to_le_bytes());
        response.push(db.index_k);
        response.push(db.chunk_k);
        response.extend_from_slice(&db.tag_seed.to_le_bytes());
        response.push(db.dpf_n_index);
        response.push(db.dpf_n_chunk);
        response.push(if db.has_bucket_merkle { 1 } else { 0 });
        response.push(0x01); // CATALOG_EXT_V1
        response.extend_from_slice(&db.index_master_seed.to_le_bytes());
        response.extend_from_slice(&db.chunk_master_seed.to_le_bytes());
        response.push(db.anchor_kind);
        response.extend_from_slice(&db.anchor_bytes);
        response
    }

    struct CannedTransport {
        replies: std::collections::VecDeque<Vec<u8>>,
        requests: Vec<Vec<u8>>,
    }

    impl CannedTransport {
        fn new(replies: Vec<Vec<u8>>) -> Self {
            Self {
                replies: replies.into(),
                requests: Vec::new(),
            }
        }
    }

    #[async_trait]
    impl PirTransport for CannedTransport {
        async fn send(&mut self, _data: Vec<u8>) -> PirResult<()> {
            Ok(())
        }

        async fn recv(&mut self) -> PirResult<Vec<u8>> {
            unimplemented!()
        }

        async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
            self.requests.push(request.to_vec());
            self.replies
                .pop_front()
                .ok_or_else(|| PirError::ServerError("no canned reply".into()))
        }

        async fn close(&mut self) -> PirResult<()> {
            Ok(())
        }

        fn url(&self) -> &str {
            "canned://db-proof"
        }
    }

    #[test]
    fn decode_database_proof_response_roundtrip() {
        let (bundle, _) = sample_bundle();
        let response = encode_proof_response(&bundle);

        assert_eq!(decode_database_proof_response(&response).unwrap(), bundle);
    }

    #[test]
    fn verify_database_proof_response_is_stateless() {
        let (bundle, db_info) = sample_bundle();
        let response = encode_proof_response(&bundle);
        let mut policy = DatabaseProofPolicy::mainnet();
        policy.expected_params_hash = Some([6u8; 32]);
        policy.allowed_builder_binary_sha256.push([1u8; 32]);
        policy.allowed_builder_git_commits.push("abc123".into());

        let verified = verify_database_proof_response(&db_info, &response, &policy).unwrap();
        assert_eq!(verified.db_id, db_info.db_id);
        assert_eq!(verified.onion_super_root, [8u8; 32]);
        assert_eq!(verified.onion_entry_size, 3328);
    }

    #[test]
    fn v2_verifier_recomputes_and_returns_typed_onion_layout() {
        let (bundle, db_info) = sample_bundle_v2();
        let response = encode_proof_response_version(
            &bundle,
            DATABASE_PROOF_BUNDLE_VERSION_V2,
            RESP_DB_PROOF_V2,
        );
        let verified =
            verify_database_proof_v2_response(&db_info, &response, &DatabaseProofPolicy::mainnet())
                .unwrap();
        let layout = verified.onion_layout_v2.unwrap();
        assert_eq!(layout.total_packed_entries, 116_030);
        assert_eq!(layout.index_bins_per_table, 965);
        assert_eq!(layout.chunk_bins_per_table, 4_792);
    }

    #[test]
    fn v2_verifier_never_falls_back_to_v1() {
        let (bundle, db_info) = sample_bundle();
        let response = encode_proof_response(&bundle);
        let err =
            verify_database_proof_v2_response(&db_info, &response, &DatabaseProofPolicy::mainnet())
                .unwrap_err();
        assert!(matches!(err, PirError::UnexpectedResponse { .. }));
    }

    #[test]
    fn v2_verifier_rejects_layout_not_committed_by_params_hash() {
        let (mut bundle, db_info) = sample_bundle_v2();
        let mut evidence = pir_db_attest::BuildEvidence::decode(&bundle.build_evidence).unwrap();
        evidence
            .onion_layout_v2
            .as_mut()
            .unwrap()
            .chunk_bins_per_table += 1;
        bundle.build_evidence = evidence.encode().unwrap();
        let report_data = pir_db_attest::report_data_for_evidence_bytes(
            EVIDENCE_VERSION_V2,
            &bundle.build_evidence,
        )
        .unwrap();
        bundle.sev_snp_report[pir_db_attest::SEV_SNP_REPORT_DATA_OFFSET
            ..pir_db_attest::SEV_SNP_REPORT_DATA_OFFSET + pir_db_attest::SEV_SNP_REPORT_DATA_LEN]
            .copy_from_slice(&report_data);
        let response = encode_proof_response_version(
            &bundle,
            DATABASE_PROOF_BUNDLE_VERSION_V2,
            RESP_DB_PROOF_V2,
        );
        let err =
            verify_database_proof_v2_response(&db_info, &response, &DatabaseProofPolicy::mainnet())
                .unwrap_err();
        assert!(err.to_string().contains("params_hash_v2 mismatch"));
    }

    #[test]
    fn verify_database_proof_response_rejects_substituted_db_id() {
        let (mut bundle, db_info) = sample_bundle();
        bundle.db_id = db_info.db_id.wrapping_add(1);
        let response = encode_proof_response(&bundle);

        let err =
            verify_database_proof_response(&db_info, &response, &DatabaseProofPolicy::mainnet())
                .unwrap_err();
        assert!(err.to_string().contains("db_id mismatch"));
    }

    #[test]
    fn verify_database_proof_response_rejects_wrong_opcode() {
        let (_, db_info) = sample_bundle();
        let err = verify_database_proof_response(
            &db_info,
            &[RESP_DB_CATALOG],
            &DatabaseProofPolicy::mainnet(),
        )
        .unwrap_err();
        assert!(matches!(err, PirError::UnexpectedResponse { .. }));
    }

    #[tokio::test]
    async fn fetch_catalog_and_proof_over_transport() {
        let (bundle, db_info) = sample_bundle();
        let mut transport = CannedTransport::new(vec![
            encode_catalog_response(&db_info),
            encode_proof_response(&bundle),
        ]);

        let catalog = fetch_database_catalog(&mut transport).await.unwrap();
        assert_eq!(catalog.databases.len(), 1);
        let catalog_db = &catalog.databases[0];
        assert_eq!(catalog_db.db_id, db_info.db_id);
        assert_eq!(catalog_db.name, db_info.name);
        assert_eq!(catalog_db.base_height(), db_info.base_height());
        assert_eq!(catalog_db.height, db_info.height);
        assert_eq!(catalog_db.index_bins, db_info.index_bins);
        assert_eq!(catalog_db.chunk_bins, db_info.chunk_bins);
        assert_eq!(catalog_db.index_k, db_info.index_k);
        assert_eq!(catalog_db.chunk_k, db_info.chunk_k);
        assert_eq!(catalog_db.has_bucket_merkle, db_info.has_bucket_merkle);

        let fetched = fetch_database_proof(&mut transport, 1).await.unwrap();
        assert_eq!(fetched, bundle);
        let verified = verify_database_proof(
            &catalog.databases[0],
            &fetched,
            &DatabaseProofPolicy::mainnet(),
        )
        .unwrap();
        assert_eq!(verified.muhash, [5u8; 32]);

        assert_eq!(transport.requests.len(), 2);
        assert_eq!(transport.requests[0][4], REQ_GET_DB_CATALOG);
        assert_eq!(transport.requests[1][4], REQ_GET_DB_PROOF);
        assert_eq!(transport.requests[1][5], 1);
    }

    #[test]
    fn verify_database_proof_checks_catalog_and_policy() {
        let (bundle, db_info) = sample_bundle();
        let mut policy = DatabaseProofPolicy::mainnet();
        policy.expected_params_hash = Some([6u8; 32]);
        policy.allowed_builder_binary_sha256.push([1u8; 32]);
        policy.allowed_builder_git_commits.push("abc123".into());

        let verified = verify_database_proof(&db_info, &bundle, &policy).unwrap();
        assert_eq!(verified.db_id, 1);
        assert_eq!(verified.height, 948_454);
        assert_eq!(verified.from_height, 940_611);
        assert_eq!(verified.bucket_super_root, [7u8; 32]);
        assert_eq!(verified.onion_super_root, [8u8; 32]);
        assert_eq!(verified.onion_entry_size, 3328);
    }

    #[test]
    fn verify_database_proof_rejects_untrusted_catalog_query_parameters() {
        let (bundle, db_info) = sample_bundle();
        let cases = [
            (
                "index_k",
                DatabaseInfo {
                    index_k: db_info.index_k.wrapping_sub(1),
                    ..db_info.clone()
                },
            ),
            (
                "chunk_k",
                DatabaseInfo {
                    chunk_k: db_info.chunk_k.wrapping_sub(1),
                    ..db_info.clone()
                },
            ),
            (
                "tag_seed",
                DatabaseInfo {
                    tag_seed: db_info.tag_seed ^ 1,
                    ..db_info.clone()
                },
            ),
            (
                "dpf_n_index",
                DatabaseInfo {
                    dpf_n_index: db_info.dpf_n_index.wrapping_add(1),
                    ..db_info.clone()
                },
            ),
            (
                "dpf_n_chunk",
                DatabaseInfo {
                    dpf_n_chunk: db_info.dpf_n_chunk.wrapping_add(1),
                    ..db_info.clone()
                },
            ),
            (
                "index_master_seed",
                DatabaseInfo {
                    index_master_seed: db_info.index_master_seed ^ 1,
                    ..db_info.clone()
                },
            ),
            (
                "chunk_master_seed",
                DatabaseInfo {
                    chunk_master_seed: db_info.chunk_master_seed ^ 1,
                    ..db_info.clone()
                },
            ),
        ];

        for (field, tampered) in cases {
            let err = verify_database_proof(&tampered, &bundle, &DatabaseProofPolicy::mainnet())
                .unwrap_err();
            assert!(
                err.to_string().contains(&format!("{} mismatch", field)),
                "unexpected error for {field}: {err}"
            );
        }
    }

    #[test]
    fn catalog_query_parameters_accept_snapshot_derived_seeds() {
        let (_, mut db_info) = sample_bundle();
        let anchor = CoreChainAnchor {
            block_hash: [9u8; 32],
            block_height: 940_611,
        };
        let seeds = SnapshotSeeds::derive(&anchor);
        db_info.kind = DatabaseKind::Full;
        db_info.height = anchor.block_height;
        db_info.index_k = pir_core::params::K as u8;
        db_info.chunk_k = pir_core::params::K_CHUNK as u8;
        db_info.tag_seed = seeds.index_tag;
        db_info.index_master_seed = seeds.index_master;
        db_info.chunk_master_seed = seeds.chunk_master;
        db_info.anchor_kind = 1;
        db_info.anchor_bytes = anchor.to_bytes().to_vec();

        verify_catalog_query_parameters(&db_info).unwrap();
    }

    #[test]
    fn verify_database_proof_rejects_height_mismatch() {
        let (bundle, mut db_info) = sample_bundle();
        db_info.height = 948_455;
        let err =
            verify_database_proof(&db_info, &bundle, &DatabaseProofPolicy::mainnet()).unwrap_err();
        assert!(err.to_string().contains("height mismatch"));
    }

    #[test]
    fn verify_database_proof_rejects_catalog_anchor_hash_mismatch() {
        let (bundle, mut db_info) = sample_bundle();
        let mut anchor = db_info.chain_anchor().expect("delta anchor");
        match &mut anchor {
            pir_core::cuckoo::HeaderAnchor::Delta(delta) => {
                delta.to.block_hash[0] ^= 0x55;
                db_info.anchor_bytes = delta.to_bytes().to_vec();
            }
            _ => panic!("expected delta anchor"),
        }

        let err =
            verify_database_proof(&db_info, &bundle, &DatabaseProofPolicy::mainnet()).unwrap_err();
        assert!(err.to_string().contains("catalog_anchor mismatch"));
    }
}
