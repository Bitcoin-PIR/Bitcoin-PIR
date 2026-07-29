#![cfg(unix)]

use pir_db_attest::{
    BuildEvidence, BuildKind, ChainAnchor, EvidenceMode, OnionQueryLayoutV2, EVIDENCE_VERSION_V2,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;

const INDEX_RECORD_SIZE: usize = 25;
const CHUNK_RECORD_SIZE: usize = 40;
const INDEX_SEED: u64 = 0x6f72_616d_6469_7231;

#[test]
fn strict_cli_stdout_evidence_and_bulk_output_do_not_disclose_secrets() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input");
    let out = root.path().join("bulk");
    let trusted = root.path().join("trusted");
    fs::create_dir_all(&input).unwrap();
    let index = input.join("utxo_chunks_index_nodust.bin");
    let chunks = input.join("utxo_chunks_nodust.bin");
    write_direct_index(&index, 16);
    fs::write(&chunks, vec![0x42; 16 * CHUNK_RECORD_SIZE]).unwrap();

    let index_bytes = fs::read(&index).unwrap();
    let chunk_bytes = fs::read(&chunks).unwrap();
    let index_sha = sha256(&index_bytes);
    let chunk_sha = sha256(&chunk_bytes);
    let muhash = [0x30; 32];
    let (evidence, manifest, payload) = write_certified_inputs(
        &input,
        index_sha,
        index_bytes.len() as u64,
        chunk_sha,
        chunk_bytes.len() as u64,
        muhash,
    );

    let page_key = [0xb7; 32];
    let page_key_hex = hex::encode(page_key);
    let output = Command::new(env!("CARGO_BIN_EXE_oramctl"))
        .args([
            "build-direct",
            "--index-file",
            index.to_str().unwrap(),
            "--chunks-file",
            chunks.to_str().unwrap(),
            "--out-dir",
            out.to_str().unwrap(),
            "--trusted-state-dir",
            trusted.to_str().unwrap(),
            "--level",
            "all",
            "--pack",
            "4",
            "--leaf-divisor",
            "2",
            "--bucket-size",
            "2",
            "--stash-capacity",
            "128",
            "--encrypted",
            "--key-hex",
            &page_key_hex,
            "--auth-store",
            "--auth-layout",
            "sidecar",
            "--auth-trusted-levels",
            "1",
            "--auth-hash-page-size",
            "64",
            "--index-slots-per-bin",
            "4",
            "--index-hash-fns",
            "2",
            "--index-load-factor",
            "0.8",
            "--index-seed",
            &INDEX_SEED.to_string(),
            "--db-build-evidence",
            evidence.to_str().unwrap(),
            "--server-db-manifest",
            manifest.to_str().unwrap(),
            "--root-bundle-payload",
            payload.to_str().unwrap(),
            "--expected-muhash",
            &display_hash(muhash),
            "--expected-index-sha256",
            &hex::encode(index_sha),
            "--expected-chunks-sha256",
            &hex::encode(chunk_sha),
            "--strict-source-binding",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "strict build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("oram_rng_seed_source=os_rng"));
    for public_text in [&stdout, &stderr] {
        assert!(!public_text.contains("seed_hex="));
        assert!(!public_text.contains("oram_rng_seed_hex"));
        assert!(!public_text.contains(&page_key_hex));
    }

    let evidence_json = fs::read(out.join("oram-build-evidence.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&evidence_json).unwrap();
    assert_eq!(parsed["version"], 2);
    assert_eq!(parsed["oram_params"]["oram_rng_seed_source"], "os_rng");
    assert!(parsed["oram_params"].get("oram_rng_seed_hex").is_none());

    let default_seed_hex = "0a".repeat(32);
    let default_seed = [0x0a; 32];
    let forbidden = [
        page_key.as_slice(),
        page_key_hex.as_bytes(),
        default_seed.as_slice(),
        default_seed_hex.as_bytes(),
    ];
    for entry in fs::read_dir(&out).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = fs::read(&path).unwrap();
            for secret in &forbidden {
                assert!(
                    !contains_subslice(&bytes, secret),
                    "untrusted artifact {} contains a forbidden seed/key representation",
                    path.display()
                );
            }
        }
    }
    for level in ["direct-index", "direct-chunk"] {
        for suffix in ["state", "auth.state", "metadata"] {
            assert!(!out.join(format!("{level}.{suffix}")).exists());
            assert!(trusted.join(format!("{level}.{suffix}")).exists());
        }
    }
}

fn write_direct_index(path: &Path, records: usize) {
    let mut bytes = Vec::with_capacity(records * INDEX_RECORD_SIZE);
    for record in 0..records {
        let mut row = [0u8; INDEX_RECORD_SIZE];
        for (offset, byte) in row[..20].iter_mut().enumerate() {
            *byte = record.wrapping_mul(31).wrapping_add(offset) as u8;
        }
        row[20..24].copy_from_slice(&(record as u32).to_le_bytes());
        row[24] = 1;
        bytes.extend_from_slice(&row);
    }
    fs::write(path, bytes).unwrap();
}

fn write_certified_inputs(
    dir: &Path,
    index_sha: [u8; 32],
    index_bytes: u64,
    chunk_sha: [u8; 32],
    chunk_bytes: u64,
    muhash: [u8; 32],
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let payload_path = dir.join("root-bundle-payload.bin");
    let payload = root_payload(muhash);
    fs::write(&payload_path, &payload).unwrap();
    let manifest = format!(
        "[manifest]\nversion = 1\n\n[direct_oram]\nversion = 1\nindex_sha256 = \"{}\"\nindex_bytes = {index_bytes}\nindex_records = {}\nchunk_sha256 = \"{}\"\nchunk_bytes = {chunk_bytes}\nchunk_records = {}\nindex_slots_per_bin = 4\nindex_hash_fns = 2\nindex_load_factor_ppb = 800000000\nindex_seed = {INDEX_SEED}\n\n[files]\n",
        hex::encode(index_sha),
        index_bytes / INDEX_RECORD_SIZE as u64,
        hex::encode(chunk_sha),
        chunk_bytes / CHUNK_RECORD_SIZE as u64,
    );
    let manifest_path = dir.join("MANIFEST.toml");
    fs::write(&manifest_path, manifest.as_bytes()).unwrap();
    let evidence = BuildEvidence {
        version: EVIDENCE_VERSION_V2,
        builder_git_commit: "strict-privacy-test".into(),
        builder_binary_sha256: [0x80; 32],
        tee_platform: "test".into(),
        tee_image_measurement: Vec::new(),
        core_version: "test".into(),
        snapshot_sha256: [0x81; 32],
        snapshot_bytes: index_bytes + chunk_bytes,
        network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
        build_kind: BuildKind::Snapshot,
        from_anchor: ChainAnchor {
            block_hash: [0; 32],
            height: 0,
        },
        anchor: ChainAnchor {
            block_hash: [0x10; 32],
            height: 950_000,
        },
        utxo_muhash: muhash,
        dust_threshold_sats: 576,
        max_utxos_per_spk: 100,
        params_hash: [0x20; 32],
        index_bins_per_table: 1,
        chunk_bins_per_table: 1,
        onion_entry_size: 3_840,
        bucket_super_root: [0x30; 32],
        onion_super_root: [0x40; 32],
        root_bundle_payload_sha256: sha256(&payload),
        signed_root_bundle_sha256: None,
        database_manifest_sha256: [0x50; 32],
        all_artifacts_manifest_sha256: [0x60; 32],
        server_db_manifest_sha256: sha256(manifest.as_bytes()),
        evidence_mode: EvidenceMode::FullBuild,
        predecessor_evidence_sha256: None,
        predecessor_report_sha256: None,
        onion_layout_v2: Some(OnionQueryLayoutV2::current(1, 1, 1, 3_840)),
    };
    let evidence_path = dir.join("build-evidence.bin");
    fs::write(&evidence_path, evidence.encode().unwrap()).unwrap();
    (evidence_path, manifest_path, payload_path)
}

fn root_payload(muhash: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&[0xf9, 0xbe, 0xb4, 0xd9]);
    out.push(0);
    out.extend_from_slice(&[0; 32]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[0x10; 32]);
    out.extend_from_slice(&950_000u32.to_le_bytes());
    out.extend_from_slice(&muhash);
    out.extend_from_slice(&576u64.to_le_bytes());
    out.extend_from_slice(&100u32.to_le_bytes());
    out.extend_from_slice(&[0x20; 32]);
    out.extend_from_slice(&1_780_000_000i64.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    let label = b"dpf/index/super_root";
    out.push(label.len() as u8);
    out.extend_from_slice(label);
    out.extend_from_slice(&[0x70; 32]);
    out
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn display_hash(mut hash: [u8; 32]) -> String {
    hash.reverse();
    hex::encode(hash)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
