//! Client-side fetch and verification for attested-builder DB proof bundles.

use crate::protocol::{
    decode_catalog, encode_request, REQ_GET_DB_CATALOG, RESP_DB_CATALOG, RESP_ERROR,
};
use crate::transport::PirTransport;
use pir_db_attest::{
    build_kind_label, display_hash_hex, hex32, BuildKind, ChainAnchor as AttestedChainAnchor,
    ProofBundle, ProofDirectory,
};
use pir_sdk::{DatabaseCatalog, DatabaseInfo, DatabaseKind, PirError, PirResult};

pub const REQ_GET_DB_PROOF: u8 = 0x0a;
pub const RESP_DB_PROOF: u8 = 0x0a;
pub const DATABASE_PROOF_BUNDLE_VERSION: u16 = 1;

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

pub fn decode_database_proof_response(data: &[u8]) -> PirResult<DatabaseProofBundle> {
    if data.is_empty() {
        return Err(PirError::Decode("db proof response empty".into()));
    }
    if data[0] == RESP_ERROR {
        return Err(PirError::ServerError(decode_error_message(data)));
    }
    if data[0] != RESP_DB_PROOF {
        return Err(PirError::UnexpectedResponse {
            expected: "RESP_DB_PROOF (0x0a)",
            actual: format!("0x{:02x}", data[0]),
        });
    }
    decode_database_proof_bundle(&data[1..])
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
    if let Some(expected) = policy.expected_network_magic {
        expect_arr("network_magic", &expected, &evidence.network_magic)?;
    }
    if let Some(expected) = policy.expected_params_hash {
        expect_arr("params_hash", &expected, &evidence.params_hash)?;
    }
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
        params_hash: evidence.params_hash,
        network_magic: evidence.network_magic,
        builder_binary_sha256: evidence.builder_binary_sha256,
        builder_git_commit: evidence.builder_git_commit.clone(),
    })
}

fn decode_database_proof_bundle(data: &[u8]) -> PirResult<DatabaseProofBundle> {
    if data.len() < 3 {
        return Err(PirError::Decode("db proof bundle too short".into()));
    }
    let version = u16::from_le_bytes(data[0..2].try_into().unwrap());
    if version != DATABASE_PROOF_BUNDLE_VERSION {
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
    use pir_core::seeds::{ChainAnchor as CoreChainAnchor, DeltaAnchor, DeltaSeeds};
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
        };
        let build_evidence = evidence.encode().unwrap();
        let report_data = pir_db_attest::report_data_for_evidence_bytes(&build_evidence).unwrap();
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
            index_k: 75,
            chunk_k: 80,
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

    fn encode_proof_response(bundle: &DatabaseProofBundle) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&DATABASE_PROOF_BUNDLE_VERSION.to_le_bytes());
        body.push(bundle.db_id);
        lp(&mut body, &bundle.build_evidence);
        lp(&mut body, &bundle.root_bundle_payload);
        lp(&mut body, &bundle.sev_snp_report);
        lp(&mut body, &bundle.database_manifest_sha256);
        lp(&mut body, &bundle.all_artifacts_manifest_sha256);
        lp(&mut body, &bundle.server_db_manifest_toml);
        let mut response = vec![RESP_DB_PROOF];
        response.extend_from_slice(&body);
        response
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
