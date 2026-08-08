use pir_db_attest::{RootBundlePayload, SignedRootBundle};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

// Upstream provenance: Bitcoin-PIR/attested-builder @
// 80ad9b185760d2e36fd24baef50dd3030af8e94f (protected release
// rootbundle-v0.1.0), recorded in verification/locks/rootbundle.json.
//
// The consumer Cargo.toml serves rootbundle from the in-repo vendor mirror
// (vendor/rootbundle) instead of a git revision, so provenance is established
// in three layers, none of which needs the network:
//   a. the lock records the upstream repository, commit, and release tag;
//   b. the lock pins an audited SHA-256 per vendored file
//      (vendored_files_sha256), the mirror's .cargo-checksum.json must agree
//      with that exact set, and every file is re-hashed from disk;
//   c. the shared golden vector (vendor testdata/v1_bundle.hex, byte-identical
//      to crates/trust/db-attest/testdata/rootbundle-v0.1.0-bundle.hex)
//      decodes to the lock's golden_bundle_sha256.
// This proves the vendored snapshot is byte-stable against an audited digest
// set recorded next to the upstream commit reference. It is not a proof that
// the vendor files came from that commit: nothing here re-downloads the
// upstream repository, so a rewritten upstream commit (or a colluding lock +
// mirror update) would go undetected without an external trusted source.
const UPSTREAM_COMMIT: &str = "80ad9b185760d2e36fd24baef50dd3030af8e94f";

const GOLDEN_BUNDLE_SHA256: &str =
    "71c32a0dbaf5d2fad4d2778fca5c6c88f317a0606358b4c49f429d368ebcd4dc";

// The vendored release file set, audited against the upstream release and
// mirrored by verification/locks/rootbundle.json "vendored_files_sha256".
// vendor Cargo.toml is the cargo-vendor normalized manifest, not a byte copy
// of the upstream Cargo.toml.
const VENDORED_FILES: [&str; 8] = [
    "COMPATIBILITY.md",
    "Cargo.toml",
    "examples/golden_vector.rs",
    "src/lib.rs",
    "testdata/v1_bundle.hex",
    "testdata/v1_payload.hex",
    "testdata/v1_trusted_keys.hex",
    "tests/golden_vectors.rs",
];

// Minimal structured parser for the TOML subset the two manifests under test
// use: `[section]` tables with single-line `key = value` entries, where the
// value is a quoted string or a one-line inline table `{ k = "v", ... }`.
// Both manifests are repo-owned, single-line-per-entry files, so this bounded
// subset is parsed on real key/value semantics instead of substring matches,
// and it needs no TOML dependency (adding one would churn Cargo.lock).
fn parse_manifest(text: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut tables = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            section = line
                .trim_end_matches(']')
                .trim_start_matches('[')
                .trim()
                .to_string();
            tables.entry(section.clone()).or_default();
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("unparseable manifest line: {line}"));
        tables
            .entry(section.clone())
            .or_default()
            .insert(key.trim().to_string(), collapse_whitespace(value.trim()));
    }
    tables
}

fn collapse_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut pending_space = false;
    for ch in text.chars() {
        match ch {
            '"' => {
                if pending_space && !out.is_empty() {
                    out.push(' ');
                }
                pending_space = false;
                in_string = !in_string;
                out.push(ch);
            }
            c if c.is_whitespace() && !in_string => pending_space = true,
            c => {
                if pending_space && !out.is_empty() {
                    out.push(' ');
                }
                pending_space = false;
                out.push(c);
            }
        }
    }
    out
}

fn split_quoted(text: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    for ch in text.chars() {
        if ch == '"' {
            in_string = !in_string;
            current.push(ch);
        } else if ch == separator && !in_string {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    parts.push(current);
    parts
}

fn inline_table_fields(value: &str) -> BTreeMap<String, String> {
    let inner = value
        .trim()
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or_else(|| panic!("expected inline table, got {value}"));
    let mut fields = BTreeMap::new();
    for part in split_quoted(inner, ',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .unwrap_or_else(|| panic!("unparseable inline table field: {part}"));
        fields.insert(key.trim().to_string(), value.trim().trim_matches('"').to_string());
    }
    fields
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|path| path.join("verification/locks/rootbundle.json").is_file())
        .expect("workspace root containing the rootbundle lock")
}

fn read_lock(repo: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(repo.join("verification/locks/rootbundle.json")).unwrap())
        .unwrap()
}

#[test]
fn consumer_lock_matches_the_vendored_rootbundle() {
    let repo = repo_root();
    let lock = read_lock(repo);

    // The lock records upstream provenance.
    assert_eq!(lock["repository"], "Bitcoin-PIR/attested-builder");
    assert_eq!(lock["commit"], UPSTREAM_COMMIT);
    assert_eq!(lock["release_tag"], "rootbundle-v0.1.0");
    assert_eq!(lock["golden_bundle_sha256"], GOLDEN_BUNDLE_SHA256);
    assert_eq!(
        lock["production_payload_sha256"],
        serde_json::json!([
            "cfbd67fd10d4f7cbaa29b82ffa1a60aa35229655bb24cdac8883547b221fca6f"
        ]),
        "every locked production payload hash must be covered by a fixture"
    );

    // The consumer depends on the vendored mirror, checked structurally.
    let manifest = parse_manifest(
        &fs::read_to_string(repo.join("crates/trust/db-attest/Cargo.toml")).unwrap(),
    );
    assert_eq!(manifest["package"]["name"], "\"pir-db-attest\"");
    let dep = inline_table_fields(&manifest["dependencies"]["rootbundle"]);
    assert_eq!(
        dep.get("path").map(String::as_str),
        Some("../../../vendor/rootbundle"),
        "pir-db-attest must consume the in-repo vendored mirror"
    );
    assert!(
        dep.get("git").is_none() && dep.get("rev").is_none() && dep.get("tag").is_none(),
        "the vendored dependency must not carry git/rev/tag pins"
    );

    // The vendored manifest is version 0.1.0, matching the locked release tag.
    let vendor_dir = repo.join("vendor/rootbundle");
    let vendor_manifest = parse_manifest(
        &fs::read_to_string(vendor_dir.join("Cargo.toml")).unwrap(),
    );
    assert_eq!(vendor_manifest["package"]["name"], "\"rootbundle\"");
    assert_eq!(vendor_manifest["package"]["version"], "\"0.1.0\"");

    // The lock pins exactly the audited vendored release file set.
    let locked_files = lock["vendored_files_sha256"]
        .as_object()
        .expect("lock must pin vendored_files_sha256");
    let mut locked_paths: Vec<&str> = locked_files.keys().map(String::as_str).collect();
    locked_paths.sort_unstable();
    assert_eq!(locked_paths, VENDORED_FILES);

    // The mirror's Cargo checksum manifest must cover exactly the same set
    // with the same digests; ignored files such as .DS_Store are not part of
    // the release set and are never read.
    let checksums: serde_json::Value = serde_json::from_slice(
        &fs::read(vendor_dir.join(".cargo-checksum.json")).unwrap(),
    )
    .unwrap();
    let checksum_files = checksums["files"].as_object().unwrap();
    assert_eq!(
        checksum_files.len(),
        VENDORED_FILES.len(),
        "checksum manifest must cover exactly the vendored release file set"
    );
    for (relative, locked_digest) in locked_files {
        let checksummed = checksum_files
            .get(relative)
            .unwrap_or_else(|| panic!("checksum manifest missing {relative}"))
            .as_str()
            .unwrap();
        assert_eq!(
            checksummed,
            locked_digest.as_str().unwrap(),
            "checksum manifest disagrees with the lock for {relative}"
        );
    }

    // Every expected file exists on disk as a regular file matching the lock.
    for relative in VENDORED_FILES {
        let path = vendor_dir.join(relative);
        let meta = fs::metadata(&path)
            .unwrap_or_else(|_| panic!("vendored file missing: {relative}"));
        assert!(meta.is_file(), "{relative} must be a regular file");
        let bytes = fs::read(&path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            locked_files[relative].as_str().unwrap(),
            "vendored file {relative} drifted from the audited lock digest"
        );
    }

    // The vendored golden vector decodes to the locked golden digest.
    let golden_bytes = hex::decode(
        fs::read_to_string(vendor_dir.join("testdata/v1_bundle.hex"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&golden_bytes)),
        GOLDEN_BUNDLE_SHA256
    );
}

#[test]
fn upstream_release_golden_bundle_decodes_reencodes_and_verifies() {
    let bytes = hex::decode(
        include_str!("../testdata/rootbundle-v0.1.0-bundle.hex").trim(),
    )
    .unwrap();
    assert_eq!(hex::encode(Sha256::digest(&bytes)), GOLDEN_BUNDLE_SHA256);
    let bundle = SignedRootBundle::decode(&bytes).unwrap();
    assert_eq!(bundle.encode().unwrap(), bytes);
    let trusted = [
        hex::decode("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")
            .unwrap()
            .try_into()
            .unwrap(),
        hex::decode("fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618")
            .unwrap()
            .try_into()
            .unwrap(),
    ];
    assert_eq!(bundle.verify_quorum(&trusted, 2), Ok(2));
}

#[test]
fn retained_production_payloads_still_decode_byte_for_byte() {
    let repo = repo_root();
    // The production web/public/proofs path was removed; the historical
    // payloads are retained under the forensic fixture tree and must decode
    // byte-for-byte. The fixture set is pinned to the lock's full
    // production_payload_sha256 array, so a new locked payload cannot pass
    // without its fixture and an entry in this mapping.
    let fixtures: [(&str, &str); 1] = [(
        "cfbd67fd10d4f7cbaa29b82ffa1a60aa35229655bb24cdac8883547b221fca6f",
        "web/src/__tests__/fixtures/oram-source-proof-v1-leaked/proofs/oram-source/mainnet_948454/db/root-bundle-payload.bin",
    )];
    let lock = read_lock(repo);
    let mut locked: Vec<&str> = lock["production_payload_sha256"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    locked.sort_unstable();
    let mut covered: Vec<&str> = fixtures.iter().map(|(sha, _)| *sha).collect();
    covered.sort_unstable();
    assert_eq!(
        locked, covered,
        "every locked production payload hash needs a fixture"
    );
    for (expected_sha256, relative) in fixtures {
        let bytes = fs::read(repo.join(relative)).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&bytes)), expected_sha256);
        let payload = RootBundlePayload::decode(&bytes).unwrap();
        assert_eq!(payload.encode().unwrap(), bytes, "{relative}");
    }
}
