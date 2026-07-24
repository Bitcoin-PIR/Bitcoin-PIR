//! Integration tests for PIR SDK Client.
//!
//! These tests require running PIR servers. By default they hit the public
//! deployment at `wss://weikeng1.bitcoinpir.org` / `wss://weikeng2.bitcoinpir.org`
//! (the same servers the production web client uses) — that's what CI runs
//! against and what a contributor gets out-of-the-box.
//!
//! Override via environment variables for local runs against
//! `unified_server`:
//!   - `PIR_DPF_SERVER0_URL` / `PIR_DPF_SERVER1_URL` (default: public pir1/pir2)
//!   - `PIR_HARMONY_HINT_URL` / `PIR_HARMONY_QUERY_URL` (default: public pir1/pir2)
//!   - `PIR_ONION_URL` (default: public pir1)
//!
//! Run with:
//!   cargo test -p pir-sdk-client --test integration_test -- --ignored
//!
//! For local servers:
//!   PIR_DPF_SERVER0_URL=ws://127.0.0.1:8091 \
//!   PIR_DPF_SERVER1_URL=ws://127.0.0.1:8092 \
//!     cargo test -p pir-sdk-client --test integration_test -- --ignored
//!
//! Before running locally, start the servers:
//!   cargo run --release -p runtime --bin unified_server -- --port 8091 &
//!   cargo run --release -p runtime --bin unified_server -- --port 8092 &

use pir_sdk_client::{
    DatabaseProofPolicy, DpfClient, HarmonyClient, PirClient, PirError, QueryResult, RootPolicy,
    ScriptHash, SyncResult, VerifiedDatabaseRoots, WsConnection,
};

/// Default to the public deployment so CI — and contributors who haven't
/// stood up a fixture server — can exercise the full stack against
/// real data. The public servers are the same ones the web client at
/// https://www.bitcoinpir.org uses.
const DEFAULT_DPF_SERVER0: &str = "wss://weikeng1.bitcoinpir.org";
const DEFAULT_DPF_SERVER1: &str = "wss://weikeng2.bitcoinpir.org";
// Production topology (memory: project_pir1_hint_pir2_query_split.md):
//   pir1 = Hetzner, no-SEV   → HINT server  (--serve-hints + --pool-size)
//   pir2 = VPSBG,   SEV-SNP  → QUERY server (--serve-queries)
// Defaults were reversed pre-2026-05-13 and silently worked because
// pir2 also had --pool-size enabled. After the mode-flag landing
// (commit fb8b8a64) pir2 rejects hint requests with a clear
// wire-level error ("server not configured to serve hints — start
// with --serve-hints"), which surfaced the reversal in CI.
const DEFAULT_HARMONY_HINT: &str = "wss://weikeng1.bitcoinpir.org";
const DEFAULT_HARMONY_QUERY: &str = "wss://weikeng2.bitcoinpir.org";
#[cfg(feature = "onion")]
const DEFAULT_ONION_URL: &str = "wss://weikeng1.bitcoinpir.org";

fn dpf_server0_url() -> String {
    std::env::var("PIR_DPF_SERVER0_URL").unwrap_or_else(|_| DEFAULT_DPF_SERVER0.into())
}

fn dpf_server1_url() -> String {
    std::env::var("PIR_DPF_SERVER1_URL").unwrap_or_else(|_| DEFAULT_DPF_SERVER1.into())
}

fn harmony_hint_url() -> String {
    std::env::var("PIR_HARMONY_HINT_URL").unwrap_or_else(|_| DEFAULT_HARMONY_HINT.into())
}

fn harmony_query_url() -> String {
    std::env::var("PIR_HARMONY_QUERY_URL").unwrap_or_else(|_| DEFAULT_HARMONY_QUERY.into())
}

#[cfg(feature = "onion")]
fn onion_url() -> String {
    std::env::var("PIR_ONION_URL").unwrap_or_else(|_| DEFAULT_ONION_URL.into())
}

/// A known test script hash (can be replaced with actual test data).
fn test_script_hash() -> ScriptHash {
    // All-zero hash: extremely unlikely to be a real scripthash, so the
    // query will exercise the "not found" Merkle verification path. That
    // is the more important path to test — it proves that per-bucket
    // Merkle verification across both cuckoo positions is working.
    [0u8; 20]
}

/// HASH160 of the first production demo scriptPubKey in
/// `web/src/example_spks.json`. The height-948454 snapshot contains UTXOs for
/// it, so pairing it with [`test_script_hash`] covers both found and verified
/// absence in one batch.
fn known_found_script_hash() -> ScriptHash {
    decode_hex_array("de2e69f96b7e622f6ad39609b6d8554b37e8aba3")
}

// The strict canaries deliberately duplicate the production database pins from
// `web/src/attest-pin.ts`. Keeping the values in the test binary is important:
// a live server response is evidence to be checked, never the source of trust.
// If a database is intentionally rotated, the frontend pin and this canary pin
// must be reviewed and updated together.
#[derive(Clone, Copy)]
struct ProductionDatabasePin {
    db_id: u8,
    build_kind: &'static str,
    from_height: u32,
    height: u32,
    from_block_hash_hex: &'static str,
    block_hash_hex: &'static str,
    muhash_hex: &'static str,
    bucket_super_root_hex: &'static str,
    onion_super_root_hex: &'static str,
    params_hash_hex: &'static str,
    network_magic_hex: &'static str,
    builder_binary_sha256_hex: &'static str,
    builder_git_commit: &'static str,
    onion_entry_size: u32,
}

const PRODUCTION_DATABASE_PINS: [ProductionDatabasePin; 2] = [
    ProductionDatabasePin {
        db_id: 0,
        build_kind: "snapshot",
        from_height: 0,
        height: 948_454,
        from_block_hash_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        block_hash_hex: "00000000000000000001ef683c02c383315db7e917c69d20f79e05985560a4e4",
        muhash_hex: "cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee",
        bucket_super_root_hex: "45def9b3c191cd28e630dae51f32d3e2f85f4d8ccf38c0712a23136967f2ec0b",
        onion_super_root_hex: "e83efa5730c47b94e8e6af09b1cb76a9e006634645fd39c939bd7b8ea554f8b4",
        params_hash_hex: "ac364eb24e24ba025e2dcfdd50b9ccf65ffd556488afc076b70b557084c5318e",
        network_magic_hex: "f9beb4d9",
        builder_binary_sha256_hex:
            "d4da29807e806c8a16eec94b86119bd16df7805a66fa4ff1c187a26832a36427",
        builder_git_commit: "b692aec18b9c20ac92cb9fe22588e96ff96ad27d",
        onion_entry_size: 3_328,
    },
    ProductionDatabasePin {
        db_id: 1,
        build_kind: "delta",
        from_height: 940_611,
        height: 948_454,
        from_block_hash_hex: "000000000000000000002c41243b3d74d135942031ef15f547bca1ce8f85eb99",
        block_hash_hex: "00000000000000000001ef683c02c383315db7e917c69d20f79e05985560a4e4",
        muhash_hex: "cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee",
        bucket_super_root_hex: "e2ba2eee6788424309a95f771893d5401cc8e3ceec6188dc2708900e211a910a",
        onion_super_root_hex: "f86baa3966a61cdcd70d8c0ad9bed233f591806eb351db2ae35ac0192a3fe997",
        params_hash_hex: "2b3e488c04433ed8bd293fd3adab72b49bf52346b81160365486d76f9b4d4e39",
        network_magic_hex: "f9beb4d9",
        builder_binary_sha256_hex:
            "34a677847b9be6580385c73f163279c81561772f8d3ad782d0ca08f1c01fad4a",
        builder_git_commit: "01e8db91d76037cd5562fce85c40e832ad156431",
        onion_entry_size: 3_328,
    },
];

/// V2 is activated only for strict OnionPIR. DPF/Harmony keep the v1 opcode
/// during the compatibility window, so their production pins above remain
/// intentionally unchanged.
fn production_onion_v2_pin(mut pin: ProductionDatabasePin) -> ProductionDatabasePin {
    pin.params_hash_hex = match pin.db_id {
        0 => "a600f33fa0e644aab533a050eabf9c03882aa00f1b293ddf9d7f4bf7c8142563",
        1 => "fe6f516696bafaa2226cc1bdc7888c7c69dd263a84817dd0f18cf8027123c45d",
        id => panic!("no production OnionPIR v2 pin for db {id}"),
    };
    pin.builder_binary_sha256_hex =
        "1150d6a2d746398d9046e677e1f0d36f4c4ccb3c390265ea8cf14d7c1f23671c";
    pin.builder_git_commit = "d49a199e290ccbb05b6481c5ba691cb516aa76bb";
    pin
}

fn assert_matches_production_onion_v2_layout(
    roots: &VerifiedDatabaseRoots,
    pin: ProductionDatabasePin,
) {
    let layout = roots
        .onion_layout_v2
        .unwrap_or_else(|| panic!("db {} strict OnionPIR proof fell back to v1", pin.db_id));
    let (total_packed, index_bins, chunk_bins) = match pin.db_id {
        0 => (948_640, 10_273, 37_954),
        1 => (116_030, 965, 4_792),
        id => panic!("no production OnionPIR v2 layout for db {id}"),
    };
    assert_eq!(layout.total_packed_entries, total_packed);
    assert_eq!(layout.index_bins_per_table, index_bins);
    assert_eq!(layout.chunk_bins_per_table, chunk_bins);
    assert_eq!(layout.entry_size, 3_328);
    assert_eq!(layout.index_slots_per_bin, 221);
    assert_eq!(layout.index_slot_size, 15);
    assert_eq!(layout.index_k, 75);
    assert_eq!(layout.chunk_k, 80);
    assert_eq!(layout.merkle_arity, 104);
    assert_eq!(layout.merkle_hash_bytes, 32);
}

/// The ordinary ignored integration suite still runs on pull requests and
/// pushes. The heavier strict production canaries are enabled explicitly by
/// the scheduled/manual workflow steps, avoiding duplicate live queries.
fn strict_production_canary_enabled() -> bool {
    matches!(
        std::env::var("PIR_STRICT_PRODUCTION_CANARY").as_deref(),
        Ok("1") | Ok("true")
    )
}

fn decode_hex_array<const N: usize>(value: &str) -> [u8; N] {
    let bytes = hex::decode(value).expect("production pin must be valid hex");
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("production pin must be exactly {N} bytes"))
}

fn production_proof_policy(pin: ProductionDatabasePin) -> DatabaseProofPolicy {
    let mut policy = DatabaseProofPolicy::mainnet();
    policy.expected_params_hash = Some(decode_hex_array(pin.params_hash_hex));
    policy.allowed_builder_binary_sha256 = vec![decode_hex_array(pin.builder_binary_sha256_hex)];
    policy.allowed_builder_git_commits = vec![pin.builder_git_commit.to_owned()];
    policy
}

/// Match every trust-relevant field before handing the roots to a client.
/// `DatabaseProofPolicy` rejects the network/params/builder tuple during Rust
/// verification; this second comparison pins the chain anchors and all query
/// roots as well, mirroring the production frontend's full comparison.
fn assert_matches_production_pin(roots: &VerifiedDatabaseRoots, pin: ProductionDatabasePin) {
    assert_eq!(roots.db_id, pin.db_id, "db_id pin mismatch");
    assert_eq!(
        pir_db_attest::build_kind_label(roots.build_kind),
        pin.build_kind,
        "db {} build kind pin mismatch",
        pin.db_id,
    );
    assert_eq!(
        roots.from_height, pin.from_height,
        "db {} from-height pin mismatch",
        pin.db_id,
    );
    assert_eq!(
        roots.height, pin.height,
        "db {} height pin mismatch",
        pin.db_id
    );
    assert_eq!(
        roots.from_block_hash_hex(),
        pin.from_block_hash_hex,
        "db {} from-block-hash pin mismatch",
        pin.db_id,
    );
    assert_eq!(
        roots.block_hash_hex(),
        pin.block_hash_hex,
        "db {} block-hash pin mismatch",
        pin.db_id,
    );
    assert_eq!(
        roots.muhash_hex(),
        pin.muhash_hex,
        "db {} MuHash pin mismatch",
        pin.db_id,
    );
    assert_eq!(
        roots.bucket_super_root_hex(),
        pin.bucket_super_root_hex,
        "db {} bucket super-root pin mismatch",
        pin.db_id,
    );
    assert_eq!(
        roots.onion_super_root_hex(),
        pin.onion_super_root_hex,
        "db {} OnionPIR super-root pin mismatch",
        pin.db_id,
    );
    assert_eq!(
        hex::encode(roots.params_hash),
        pin.params_hash_hex,
        "db {} params-hash pin mismatch",
        pin.db_id,
    );
    assert_eq!(
        hex::encode(roots.network_magic),
        pin.network_magic_hex,
        "db {} network-magic pin mismatch",
        pin.db_id,
    );
    assert_eq!(
        hex::encode(roots.builder_binary_sha256),
        pin.builder_binary_sha256_hex,
        "db {} builder-binary pin mismatch",
        pin.db_id,
    );
    assert_eq!(
        roots.builder_git_commit, pin.builder_git_commit,
        "db {} builder-commit pin mismatch",
        pin.db_id,
    );
    assert_eq!(
        roots.onion_entry_size, pin.onion_entry_size,
        "db {} OnionPIR entry-size pin mismatch",
        pin.db_id,
    );
}

fn assert_production_catalog_has_pinned_databases(
    catalog: &pir_sdk_client::DatabaseCatalog,
    require_bucket_merkle: bool,
) {
    for pin in PRODUCTION_DATABASE_PINS {
        let db = catalog
            .get(pin.db_id)
            .unwrap_or_else(|| panic!("production catalog missing db {}", pin.db_id));
        assert_eq!(
            db.height, pin.height,
            "db {} catalog height drift",
            pin.db_id
        );
        assert_eq!(
            db.base_height(),
            pin.from_height,
            "db {} catalog base-height drift",
            pin.db_id,
        );
        if require_bucket_merkle {
            assert!(
                db.has_bucket_merkle,
                "db {} must advertise bucket Merkle commitments",
                pin.db_id,
            );
        }
    }
}

fn assert_db0_found_and_not_found_verified(backend: &str, results: &[Option<QueryResult>]) {
    assert_eq!(
        results.len(),
        2,
        "{backend} db 0 strict canary returned the wrong result count",
    );
    let found = results[0]
        .as_ref()
        .unwrap_or_else(|| panic!("{backend} db 0 known-found probe was not found"));
    assert!(
        found.merkle_verified,
        "{backend} db 0 known-found result failed Merkle verification",
    );
    assert!(
        !found.entries.is_empty(),
        "{backend} db 0 known-found result contains no UTXOs",
    );
    assert!(
        results[1].is_none(),
        "{backend} db 0 all-zero probe should be a verified absence",
    );
}

fn assert_fresh_sync_verified(backend: &str, sync: &SyncResult) {
    assert!(sync.was_fresh_sync, "{backend} did not execute a fresh sync");
    assert_eq!(
        sync.synced_height, PRODUCTION_DATABASE_PINS[0].height,
        "{backend} fresh sync stopped at the wrong height",
    );
    assert_db0_found_and_not_found_verified(backend, &sync.results);
}

fn assert_delta_sync_verified(backend: &str, sync: &SyncResult) {
    assert!(!sync.was_fresh_sync, "{backend} did not execute the delta plan");
    assert_eq!(
        sync.synced_height, PRODUCTION_DATABASE_PINS[1].height,
        "{backend} delta sync stopped at the wrong height",
    );
    assert_eq!(
        sync.results.len(),
        2,
        "{backend} delta sync returned the wrong result count",
    );
    for result in sync.results.iter().flatten() {
        assert!(
            result.merkle_verified,
            "{backend} delta result failed Merkle verification",
        );
    }
}

fn assert_missing_verified_root(error: PirError, backend: &str, db_id: u8) {
    assert!(
        matches!(error, PirError::VerificationFailed(ref message)
            if message.contains("no installed VerifiedDatabaseRoots")),
        "{backend} db {db_id} should fail closed before proof installation; got {error}",
    );
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_connect() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());

    let result = client.connect().await;
    assert!(result.is_ok(), "Failed to connect: {:?}", result.err());
    assert!(client.is_connected());

    client.disconnect().await.unwrap();
    assert!(!client.is_connected());
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_fetch_catalog() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");

    let catalog = client.fetch_catalog().await.expect("fetch_catalog failed");

    assert!(!catalog.databases.is_empty(), "catalog should have at least one database");

    let main_db = &catalog.databases[0];
    assert_eq!(main_db.db_id, 0);
    assert!(main_db.index_bins > 0);
    assert!(main_db.chunk_bins > 0);
    assert!(main_db.index_k > 0);
    assert!(main_db.chunk_k > 0);

    println!("Catalog: {:#?}", catalog);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_sync_empty() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");

    // Sync with empty script hashes
    let script_hashes: Vec<ScriptHash> = vec![];
    let result = client.sync(&script_hashes, None).await.expect("sync failed");

    assert!(result.results.is_empty());
    assert!(result.synced_height > 0);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_sync_single() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");

    let script_hashes = vec![test_script_hash()];
    let result = client.sync(&script_hashes, None).await.expect("sync failed");

    assert_eq!(result.results.len(), 1);
    assert!(result.synced_height > 0);
    assert!(result.was_fresh_sync);

    println!("Sync result: {:?}", result);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_query_batch() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");
    client.fetch_catalog().await.expect("fetch_catalog failed");

    let script_hashes = vec![test_script_hash()];
    let results = client.query_batch(&script_hashes, 0).await.expect("query_batch failed");

    assert_eq!(results.len(), 1);

    // The all-zero scripthash should be `None` (not found). This exercises
    // the full INDEX round + per-bucket Merkle verification path end-to-end.
    match &results[0] {
        None => println!("All-zero scripthash correctly not found"),
        Some(r) => {
            println!(
                "All-zero scripthash unexpectedly found: merkle_verified={}, entries={}",
                r.merkle_verified,
                r.entries.len()
            );
        }
    }

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_multiple_queries() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");

    // Create multiple distinct script hashes
    let script_hashes: Vec<ScriptHash> = (0..5)
        .map(|i| {
            let mut hash = [0u8; 20];
            hash[0] = i as u8;
            hash[1] = (i * 17) as u8;
            hash[2] = (i * 31) as u8;
            hash
        })
        .collect();

    let result = client.sync(&script_hashes, None).await.expect("sync failed");

    assert_eq!(result.results.len(), 5);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_sync_with_cached_height() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");

    let script_hashes = vec![test_script_hash()];

    // First sync
    let result1 = client.sync(&script_hashes, None).await.expect("sync failed");
    let height = result1.synced_height;

    // Second sync with cached height (should use delta if available)
    let result2 = client.sync(&script_hashes, Some(height)).await.expect("sync failed");

    // Height should be >= previous
    assert!(result2.synced_height >= height);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_compute_sync_plan() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");

    let catalog = client.fetch_catalog().await.expect("fetch_catalog failed");

    // Fresh sync (no prior height)
    let plan = client.compute_sync_plan(&catalog, None).expect("compute_sync_plan failed");
    assert!(!plan.is_empty());
    assert!(plan.is_fresh_sync);

    // Delta sync (with prior height)
    let latest = catalog.latest_tip().unwrap_or(0);
    if latest > 1000 {
        let plan = client.compute_sync_plan(&catalog, Some(latest - 1000)).expect("compute_sync_plan failed");
        println!("Delta plan: {:?}", plan);
    }

    client.disconnect().await.unwrap();
}

// ─── HarmonyPIR Integration Tests (require running servers) ─────────────────

/// Scheduled native database-root canary for the complete DPF root flow:
/// catalog -> cryptographic proof verification -> exact production pin match
/// -> explicit install -> tree-top preflight -> verified query -> disconnect.
#[tokio::test]
#[ignore = "scheduled/manual strict production canary"]
async fn test_dpf_strict_production_canary() {
    if !strict_production_canary_enabled() {
        eprintln!("strict DPF canary disabled; set PIR_STRICT_PRODUCTION_CANARY=1");
        return;
    }

    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.set_root_policy(RootPolicy::RequireVerified);
    client.connect().await.expect("strict DPF connect failed");
    let catalog = client
        .fetch_catalog()
        .await
        .expect("strict DPF catalog fetch failed");
    assert_production_catalog_has_pinned_databases(&catalog, true);

    let probes = [known_found_script_hash(), test_script_hash()];
    let missing_root = client
        .sync(&probes, None)
        .await
        .expect_err("strict DPF fresh sync must fail before proof installation");
    assert_missing_verified_root(missing_root, "DPF", 0);

    for pin in PRODUCTION_DATABASE_PINS[..1].iter().copied() {
        let roots = client
            .verify_database_proof(pin.db_id, &production_proof_policy(pin))
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "DPF db {} database-proof verification failed: {error}",
                    pin.db_id
                )
            });
        assert_matches_production_pin(&roots, pin);
        client
            .install_verified_database_roots(roots)
            .unwrap_or_else(|error| {
                panic!(
                    "DPF db {} proof-root installation failed: {error}",
                    pin.db_id
                )
            });
    }

    let missing_delta_root = client
        .sync(&probes, Some(PRODUCTION_DATABASE_PINS[1].from_height))
        .await
        .expect_err("strict DPF delta sync must fail before db 1 proof installation");
    assert_missing_verified_root(missing_delta_root, "DPF", 1);

    for pin in PRODUCTION_DATABASE_PINS[1..].iter().copied() {
        let roots = client
            .verify_database_proof(pin.db_id, &production_proof_policy(pin))
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "DPF db {} database-proof verification failed: {error}",
                    pin.db_id
                )
            });
        assert_matches_production_pin(&roots, pin);
        client
            .install_verified_database_roots(roots)
            .unwrap_or_else(|error| {
                panic!(
                    "DPF db {} proof-root installation failed: {error}",
                    pin.db_id
                )
            });
    }

    for pin in PRODUCTION_DATABASE_PINS {
        client
            .preflight_verified_database(pin.db_id)
            .await
            .unwrap_or_else(|error| {
                panic!("DPF db {} tree-top preflight failed: {error}", pin.db_id)
            });
    }

    let fresh_sync = client
        .sync(&probes, None)
        .await
        .expect("strict DPF fresh sync failed");
    assert_fresh_sync_verified("DPF", &fresh_sync);

    let delta_sync = client
        .sync(&probes, Some(PRODUCTION_DATABASE_PINS[1].from_height))
        .await
        .expect("strict DPF delta sync failed");
    assert_delta_sync_verified("DPF", &delta_sync);

    client
        .disconnect()
        .await
        .expect("strict DPF disconnect failed");
    assert!(
        !client.is_connected(),
        "DPF remained connected after disconnect"
    );
    assert_eq!(client.root_policy(), RootPolicy::RequireVerified);
    for pin in PRODUCTION_DATABASE_PINS {
        assert!(
            client.verified_database_roots(pin.db_id).is_none(),
            "DPF db {} roots survived disconnect",
            pin.db_id,
        );
    }
    assert!(
        matches!(
            client.query_batch(&probes, 0).await,
            Err(PirError::NotConnected)
        ),
        "DPF accepted a query after disconnect",
    );
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_harmony_client_connect() {
    let mut client = HarmonyClient::new(&harmony_hint_url(), &harmony_query_url());

    let result = client.connect().await;
    assert!(result.is_ok(), "Failed to connect: {:?}", result.err());
    assert!(client.is_connected());

    client.disconnect().await.unwrap();
    assert!(!client.is_connected());
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_harmony_client_fetch_catalog() {
    let mut client = HarmonyClient::new(&harmony_hint_url(), &harmony_query_url());
    client.connect().await.expect("connect failed");

    let catalog = client.fetch_catalog().await.expect("fetch_catalog failed");

    assert!(!catalog.databases.is_empty(), "catalog should have at least one database");
    let main_db = &catalog.databases[0];
    assert_eq!(main_db.db_id, 0);
    assert!(main_db.index_bins > 0);
    assert!(main_db.chunk_bins > 0);
    assert!(main_db.index_k > 0);
    assert!(main_db.chunk_k > 0);

    println!("Catalog: {:#?}", catalog);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_harmony_client_sync_single() {
    let mut client = HarmonyClient::new(&harmony_hint_url(), &harmony_query_url());
    client.connect().await.expect("connect failed");

    let script_hashes = vec![test_script_hash()];
    let result = client.sync(&script_hashes, None).await.expect("sync failed");

    assert_eq!(result.results.len(), 1);
    // HarmonyClient now prefers REQ_GET_DB_CATALOG (0x02) over the legacy
    // REQ_HARMONY_GET_INFO (0x40), so `synced_height` reflects the real tip.
    assert!(
        result.synced_height > 0,
        "synced_height should be non-zero via REQ_GET_DB_CATALOG; got {}",
        result.synced_height,
    );
    assert!(result.was_fresh_sync);

    println!("Sync result: {:?}", result);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_harmony_client_query_batch() {
    let mut client = HarmonyClient::new(&harmony_hint_url(), &harmony_query_url());
    client.connect().await.expect("connect failed");
    client.fetch_catalog().await.expect("fetch_catalog failed");

    let script_hashes = vec![test_script_hash()];
    let results = client.query_batch(&script_hashes, 0).await.expect("query_batch failed");

    assert_eq!(results.len(), 1);

    println!("Query result: {:?}", results);

    client.disconnect().await.unwrap();
}

// ─── WsConnection Resilience Tests ───────────────────────────────────────

/// Scheduled native database-root canary for HarmonyPIR. Persisted hints may
/// be reused, but database roots and verified
/// tree-tops are session-bound and must be installed afresh.
#[tokio::test]
#[ignore = "scheduled/manual strict production canary"]
async fn test_harmony_strict_production_canary() {
    if !strict_production_canary_enabled() {
        eprintln!("strict HarmonyPIR canary disabled; set PIR_STRICT_PRODUCTION_CANARY=1");
        return;
    }

    let mut client = HarmonyClient::new(&harmony_hint_url(), &harmony_query_url());
    client.set_root_policy(RootPolicy::RequireVerified);
    client
        .connect()
        .await
        .expect("strict HarmonyPIR connect failed");
    let catalog = client
        .fetch_catalog()
        .await
        .expect("strict HarmonyPIR catalog fetch failed");
    assert_production_catalog_has_pinned_databases(&catalog, true);

    let probes = [known_found_script_hash(), test_script_hash()];
    let missing_root = client
        .sync(&probes, None)
        .await
        .expect_err("strict HarmonyPIR fresh sync must fail before proof installation");
    assert_missing_verified_root(missing_root, "HarmonyPIR", 0);

    for pin in PRODUCTION_DATABASE_PINS[..1].iter().copied() {
        let roots = client
            .verify_database_proof(pin.db_id, &production_proof_policy(pin))
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "HarmonyPIR db {} database-proof verification failed: {error}",
                    pin.db_id,
                )
            });
        assert_matches_production_pin(&roots, pin);
        client
            .install_verified_database_roots(roots)
            .unwrap_or_else(|error| {
                panic!(
                    "HarmonyPIR db {} proof-root installation failed: {error}",
                    pin.db_id,
                )
            });
    }

    let missing_delta_root = client
        .sync(&probes, Some(PRODUCTION_DATABASE_PINS[1].from_height))
        .await
        .expect_err("strict HarmonyPIR delta sync must fail before db 1 proof installation");
    assert_missing_verified_root(missing_delta_root, "HarmonyPIR", 1);

    for pin in PRODUCTION_DATABASE_PINS[1..].iter().copied() {
        let roots = client
            .verify_database_proof(pin.db_id, &production_proof_policy(pin))
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "HarmonyPIR db {} database-proof verification failed: {error}",
                    pin.db_id,
                )
            });
        assert_matches_production_pin(&roots, pin);
        client
            .install_verified_database_roots(roots)
            .unwrap_or_else(|error| {
                panic!(
                    "HarmonyPIR db {} proof-root installation failed: {error}",
                    pin.db_id,
                )
            });
    }

    for pin in PRODUCTION_DATABASE_PINS {
        client
            .preflight_verified_database(pin.db_id)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "HarmonyPIR db {} tree-top preflight failed: {error}",
                    pin.db_id,
                )
            });
    }

    let fresh_sync = client
        .sync(&probes, None)
        .await
        .expect("strict HarmonyPIR fresh sync failed");
    assert_fresh_sync_verified("HarmonyPIR", &fresh_sync);

    let delta_sync = client
        .sync(&probes, Some(PRODUCTION_DATABASE_PINS[1].from_height))
        .await
        .expect("strict HarmonyPIR delta sync failed");
    assert_delta_sync_verified("HarmonyPIR", &delta_sync);

    client
        .disconnect()
        .await
        .expect("strict HarmonyPIR disconnect failed");
    assert!(
        !client.is_connected(),
        "HarmonyPIR remained connected after disconnect",
    );
    assert_eq!(client.root_policy(), RootPolicy::RequireVerified);
    for pin in PRODUCTION_DATABASE_PINS {
        assert!(
            client.verified_database_roots(pin.db_id).is_none(),
            "HarmonyPIR db {} roots survived disconnect",
            pin.db_id,
        );
    }
    assert!(
        matches!(
            client.query_batch(&probes, 0).await,
            Err(PirError::NotConnected)
        ),
        "HarmonyPIR accepted a query after disconnect",
    );
}

/// End-to-end test that `WsConnection::reconnect` actually yields a working
/// transport — after reconnecting, we send a fresh `REQ_GET_DB_CATALOG`
/// and verify the response parses. The wire-format constants come from
/// `crate::protocol`, which isn't exposed, so we reconstruct the request
/// inline: `[4B len LE][0x02]`.
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_wsconnection_reconnect_roundtrip() {
    use pir_sdk_client::WsConnection;
    let mut conn = WsConnection::connect(&dpf_server0_url())
        .await
        .expect("connect failed");

    // Baseline: fetch catalog once.
    let req = {
        let mut buf = Vec::with_capacity(5);
        buf.extend_from_slice(&1u32.to_le_bytes()); // len=1 (just variant byte)
        buf.push(0x02); // REQ_GET_DB_CATALOG
        buf
    };
    let resp1 = conn.roundtrip(&req).await.expect("first roundtrip failed");
    assert!(!resp1.is_empty(), "first response empty");
    assert_eq!(resp1[0], 0x02, "expected RESP_DB_CATALOG");

    // Now force a reconnect — drops the existing TCP + WebSocket state
    // and re-handshakes. The new transport should still work.
    conn.reconnect().await.expect("reconnect failed");

    let resp2 = conn.roundtrip(&req).await.expect("post-reconnect roundtrip failed");
    assert!(!resp2.is_empty(), "post-reconnect response empty");
    assert_eq!(resp2[0], 0x02, "expected RESP_DB_CATALOG after reconnect");

    conn.close().await.unwrap();
}

// ─── OnionPIR Integration Tests (require running servers + `onion` feature) ─

#[cfg(feature = "onion")]
mod onion_tests {
    use super::*;
    use pir_sdk_client::OnionClient;

    #[tokio::test]
    #[ignore = "requires running PIR servers"]
    async fn test_onion_client_connect() {
        let mut client = OnionClient::new(&onion_url());

        let result = client.connect().await;
        assert!(result.is_ok(), "Failed to connect: {:?}", result.err());
        assert!(client.is_connected());

        client.disconnect().await.unwrap();
        assert!(!client.is_connected());
    }

    #[tokio::test]
    #[ignore = "requires running PIR servers"]
    async fn test_onion_client_fetch_catalog() {
        let mut client = OnionClient::new(&onion_url());
        client.connect().await.expect("connect failed");

        let catalog = client.fetch_catalog().await.expect("fetch_catalog failed");

        assert!(!catalog.databases.is_empty(), "catalog should have at least one database");
        let main_db = &catalog.databases[0];
        assert_eq!(main_db.db_id, 0);
        assert!(main_db.index_bins > 0);
        assert!(main_db.chunk_bins > 0);

        println!("Catalog: {:#?}", catalog);

        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires running PIR servers"]
    async fn test_onion_client_query_batch() {
        let mut client = OnionClient::new(&onion_url());
        client.connect().await.expect("connect failed");
        client.fetch_catalog().await.expect("fetch_catalog failed");

        let script_hashes = vec![test_script_hash()];
        let results = client.query_batch(&script_hashes, 0).await.expect("query_batch failed");

        assert_eq!(results.len(), 1);

        println!("Query result: {:?}", results);

        client.disconnect().await.unwrap();
    }

    /// Scheduled native database-root canary for OnionPIR. The public
    /// preflight binds tree-tops to the installed proof's Onion super-root;
    /// `server-info.super_root` remains diagnostic input only.
    #[tokio::test]
    #[ignore = "scheduled/manual strict production canary"]
    async fn test_onion_strict_production_canary() {
        if !strict_production_canary_enabled() {
            eprintln!("strict OnionPIR canary disabled; set PIR_STRICT_PRODUCTION_CANARY=1");
            return;
        }

        let mut client = OnionClient::new(&onion_url());
        client.set_root_policy(RootPolicy::RequireVerified);
        client
            .connect()
            .await
            .expect("strict OnionPIR connect failed");
        let catalog = client
            .fetch_catalog()
            .await
            .expect("strict OnionPIR catalog fetch failed");
        assert_production_catalog_has_pinned_databases(&catalog, false);

        let probes = [known_found_script_hash(), test_script_hash()];
        let missing_root = client
            .sync(&probes, None)
            .await
            .expect_err("strict OnionPIR fresh sync must fail before proof installation");
        assert_missing_verified_root(missing_root, "OnionPIR", 0);

        for pin in PRODUCTION_DATABASE_PINS[..1].iter().copied() {
            let pin = production_onion_v2_pin(pin);
            let roots = client
                .verify_database_proof_v2(pin.db_id, &production_proof_policy(pin))
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "OnionPIR db {} database-proof verification failed: {error}",
                        pin.db_id,
                    )
                });
            assert_matches_production_pin(&roots, pin);
            assert_matches_production_onion_v2_layout(&roots, pin);
            client
                .install_verified_database_roots(roots)
                .unwrap_or_else(|error| {
                    panic!(
                        "OnionPIR db {} proof-root installation failed: {error}",
                        pin.db_id,
                    )
                });
        }

        let missing_delta_root = client
            .sync(&probes, Some(PRODUCTION_DATABASE_PINS[1].from_height))
            .await
            .expect_err("strict OnionPIR delta sync must fail before db 1 proof installation");
        assert_missing_verified_root(missing_delta_root, "OnionPIR", 1);

        for pin in PRODUCTION_DATABASE_PINS[1..].iter().copied() {
            let pin = production_onion_v2_pin(pin);
            let roots = client
                .verify_database_proof_v2(pin.db_id, &production_proof_policy(pin))
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "OnionPIR db {} database-proof verification failed: {error}",
                        pin.db_id,
                    )
                });
            assert_matches_production_pin(&roots, pin);
            assert_matches_production_onion_v2_layout(&roots, pin);
            client
                .install_verified_database_roots(roots)
                .unwrap_or_else(|error| {
                    panic!(
                        "OnionPIR db {} proof-root installation failed: {error}",
                        pin.db_id,
                    )
                });
        }

        for pin in PRODUCTION_DATABASE_PINS {
            client
                .preflight_verified_database(pin.db_id)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "OnionPIR db {} tree-top preflight failed: {error}",
                        pin.db_id,
                    )
                });
        }

        let fresh_sync = client
            .sync(&probes, None)
            .await
            .expect("strict OnionPIR fresh sync failed");
        assert_fresh_sync_verified("OnionPIR", &fresh_sync);

        let delta_sync = client
            .sync(&probes, Some(PRODUCTION_DATABASE_PINS[1].from_height))
            .await
            .expect("strict OnionPIR delta sync failed");
        assert_delta_sync_verified("OnionPIR", &delta_sync);

        client
            .disconnect()
            .await
            .expect("strict OnionPIR disconnect failed");
        assert!(
            !client.is_connected(),
            "OnionPIR remained connected after disconnect",
        );
        assert_eq!(client.root_policy(), RootPolicy::RequireVerified);
        for pin in PRODUCTION_DATABASE_PINS {
            assert!(
                client.verified_database_roots(pin.db_id).is_none(),
                "OnionPIR db {} roots survived disconnect",
                pin.db_id,
            );
        }
        assert!(
            matches!(
                client.query_batch(&probes, 0).await,
                Err(PirError::NotConnected)
            ),
            "OnionPIR accepted a query after disconnect",
        );
    }
}

// ─── Sync Plan Tests (no server required) ───────────────────────────────────

use pir_sdk::{compute_sync_plan, DatabaseCatalog, DatabaseInfo, DatabaseKind};

fn make_test_catalog() -> DatabaseCatalog {
    DatabaseCatalog {
        databases: vec![
            DatabaseInfo {
                db_id: 0,
                kind: DatabaseKind::Full,
                name: "snapshot_900000".into(),
                height: 900000,
                index_bins: 1000,
                chunk_bins: 2000,
                index_k: 75,
                chunk_k: 80,
                tag_seed: 12345,
                dpf_n_index: 17,
                dpf_n_chunk: 18,
                has_bucket_merkle: false,
                index_master_seed: 0,
                chunk_master_seed: 0,
                anchor_kind: 0,
                anchor_bytes: Vec::new(),
            },
            DatabaseInfo {
                db_id: 1,
                kind: DatabaseKind::Delta { base_height: 900000 },
                name: "delta_900000_910000".into(),
                height: 910000,
                index_bins: 100,
                chunk_bins: 200,
                index_k: 75,
                chunk_k: 80,
                tag_seed: 12345,
                dpf_n_index: 14,
                dpf_n_chunk: 15,
                has_bucket_merkle: false,
                index_master_seed: 0,
                chunk_master_seed: 0,
                anchor_kind: 0,
                anchor_bytes: Vec::new(),
            },
            DatabaseInfo {
                db_id: 2,
                kind: DatabaseKind::Delta { base_height: 910000 },
                name: "delta_910000_920000".into(),
                height: 920000,
                index_bins: 100,
                chunk_bins: 200,
                index_k: 75,
                chunk_k: 80,
                tag_seed: 12345,
                dpf_n_index: 14,
                dpf_n_chunk: 15,
                has_bucket_merkle: false,
                index_master_seed: 0,
                chunk_master_seed: 0,
                anchor_kind: 0,
                anchor_bytes: Vec::new(),
            },
        ],
    }
}

#[test]
fn test_sync_plan_fresh() {
    let catalog = make_test_catalog();
    let plan = compute_sync_plan(&catalog, None).expect("compute_sync_plan failed");

    assert!(plan.is_fresh_sync);
    assert_eq!(plan.target_height, 920000);
    // Should include: snapshot + delta1 + delta2 = 3 steps
    assert_eq!(plan.steps.len(), 3);
    assert!(plan.steps[0].is_full());
    assert!(!plan.steps[1].is_full());
    assert!(!plan.steps[2].is_full());
}

#[test]
fn test_sync_plan_delta_only() {
    let catalog = make_test_catalog();
    // Start from height 900000 (after the snapshot)
    let plan = compute_sync_plan(&catalog, Some(900000)).expect("compute_sync_plan failed");

    assert!(!plan.is_fresh_sync);
    assert_eq!(plan.target_height, 920000);
    // Should include: delta1 + delta2 = 2 steps
    assert_eq!(plan.steps.len(), 2);
    assert!(!plan.steps[0].is_full());
    assert!(!plan.steps[1].is_full());
}

#[test]
fn test_sync_plan_already_synced() {
    let catalog = make_test_catalog();
    // Already at latest height
    let plan = compute_sync_plan(&catalog, Some(920000)).expect("compute_sync_plan failed");

    assert!(plan.is_empty());
    assert_eq!(plan.target_height, 920000);
}

#[test]
fn test_sync_plan_partial_delta() {
    let catalog = make_test_catalog();
    // Start from height 910000 (after delta1)
    let plan = compute_sync_plan(&catalog, Some(910000)).expect("compute_sync_plan failed");

    assert!(!plan.is_fresh_sync);
    assert_eq!(plan.target_height, 920000);
    // Should include: delta2 = 1 step
    assert_eq!(plan.steps.len(), 1);
}

#[test]
fn test_sync_plan_stale_height() {
    let catalog = make_test_catalog();
    // Start from height before snapshot - should fall back to fresh sync
    let plan = compute_sync_plan(&catalog, Some(850000)).expect("compute_sync_plan failed");

    assert!(plan.is_fresh_sync);
    assert_eq!(plan.target_height, 920000);
}

// ─────────────────────────────────────────────────────────────────────────
// REQ_ANNOUNCE — operator-signed identity, end-to-end through unified_server.
//
// This is the only test that drives the *production* dispatch arm for
// REQ_ANNOUNCE (the binary re-implements dispatch inline rather than going
// through pir-runtime-core's stateless RequestHandler). It connects, sends
// REQ_ANNOUNCE, parses the bundle, runs the in-bundle chain check, then
// operator-pubkey pinning (accept the right key, reject a wrong one).
//
// Unlike the other integration tests it does NOT default to the public
// deployment — pir1/pir2 run without --identity-* flags and answer
// "announce not configured". Point it at a locally-booted server:
//
//   # operator workflow (once):
//   bpir-admin generate-identity --purpose server   --out /tmp/s.key   # -> SERVER_PUB (stdout)
//   bpir-admin generate-identity --purpose operator --out /tmp/op.key  # -> OPERATOR_PUB (stdout)
//   bpir-admin sign-identity --operator-key-path /tmp/op.key --server-id pir-test \
//       --identity-pubkey-hex <SERVER_PUB> --valid-until <unix-ts> --out /tmp/s.cert
//   # boot (any local checkpoint works — announce is independent of the DB):
//   unified_server --port 8097 --data-dir <ckpt> --serve-queries \
//       --identity-key-path /tmp/s.key --identity-cert-path /tmp/s.cert \
//       --identity-server-id pir-test
//   # run:
//   PIR_ANNOUNCE_URL=ws://127.0.0.1:8097 \
//   PIR_ANNOUNCE_OPERATOR_PUB=<OPERATOR_PUB hex> \
//     cargo test -p pir-sdk-client --test integration_test \
//       test_announce_operator_identity_end_to_end -- --ignored --nocapture
#[tokio::test]
#[ignore = "requires a unified_server booted with --identity-* flags; see PIR_ANNOUNCE_* env vars"]
async fn test_announce_operator_identity_end_to_end() {
    use pir_sdk_client::announce::{announce, announce_with_pinned_operator};

    // Skip gracefully when unconfigured: unlike the other --ignored tests
    // there is no sensible public default (the public servers don't serve
    // announce), so CI runs this as a no-op unless both env vars are set.
    let (url, operator_pub_hex) =
        match (std::env::var("PIR_ANNOUNCE_URL"), std::env::var("PIR_ANNOUNCE_OPERATOR_PUB")) {
            (Ok(u), Ok(p)) => (u, p),
            _ => {
                eprintln!(
                    "skipping test_announce_operator_identity_end_to_end: set PIR_ANNOUNCE_URL \
                     + PIR_ANNOUNCE_OPERATOR_PUB (and optionally PIR_ANNOUNCE_SERVER_ID) to run"
                );
                return;
            }
        };
    let operator_pub = parse_pubkey_hex(&operator_pub_hex);

    // 1. Plain announce: the bundle decodes and the in-bundle chain check
    //    (manifest signature + cert/manifest cross-references) passes.
    let mut conn = WsConnection::connect(&url).await.expect("connect");
    let v = announce(&mut conn).await.expect("announce roundtrip");
    assert!(v.chain_verified, "chain check failed: {:?}", v.chain_error);
    // Expected server_id defaults to the local fixture's "pir-test"; override
    // with PIR_ANNOUNCE_SERVER_ID to verify a real deployment (e.g. "pir1").
    let expected_server_id =
        std::env::var("PIR_ANNOUNCE_SERVER_ID").unwrap_or_else(|_| "pir-test".into());
    assert_eq!(v.bundle.cert.server_id, expected_server_id);
    assert_eq!(
        v.bundle.cert.operator_pubkey, operator_pub,
        "cert's operator_pubkey should match the pinned operator"
    );

    // 2. Pinned to the correct operator pubkey → accepted (cert signature
    //    verifies under the pinned key and the chain check holds).
    let v2 = announce_with_pinned_operator(&mut conn, &operator_pub, 0)
        .await
        .expect("pinned announce with the correct operator must succeed");
    assert!(v2.chain_verified);

    // 3. Pinned to a wrong operator pubkey → rejected before trusting anything.
    let wrong = [0u8; 32];
    let err = announce_with_pinned_operator(&mut conn, &wrong, 0)
        .await
        .expect_err("pinned announce with a wrong operator must fail");
    match err {
        PirError::Protocol(m) => assert!(
            m.contains("does not match pinned operator"),
            "unexpected error: {m}"
        ),
        other => panic!("expected Protocol(does not match pinned operator), got {other:?}"),
    }
}

/// Parse a 64-char hex Ed25519 pubkey into 32 bytes (test helper).
fn parse_pubkey_hex(s: &str) -> [u8; 32] {
    let s = s.trim();
    assert_eq!(s.len(), 64, "operator pubkey hex must be 64 chars, got {}", s.len());
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("invalid hex in operator pubkey");
    }
    out
}
