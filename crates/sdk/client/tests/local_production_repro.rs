//! LOCAL reproduction harness for the three production Payment-V1 symptoms
//! (2026-08-06). Runs against a LOCAL `unified_server` booted with the
//! production db0/db1 and a locally signed policy mirroring the production
//! `harmony-query-job-v1` scope limits. Read-only toward production; never
//! touches live servers (unless REPRO_URL is overridden explicitly for
//! comparison, which requires the same locally-issued policy to exist there —
//! i.e. it cannot accidentally authorize on production).
//!
//! Env knobs (set by the repro script docs/repro-local.md):
//!   REPRO_URL             ws://127.0.0.1:18300
//!   REPRO_PROVIDER_ID_HEX provider id bound into the local signed policy
//!   REPRO_POLICY_KEY_HEX  ed25519 pubkey of the key that signed the policy
//!   REPRO_DB_ID           db_id for the harmony batch query (default 0)

use ed25519_dalek::VerifyingKey;
use pir_sdk_client::attest::attest;
use pir_sdk_client::channel::establish;
use pir_sdk_client::service::{
    dangerous_unpaired_authorize_service_operation_v1,
    dangerous_unpaired_build_authorization_proof_v1, fetch_verified_service_policy_v1,
    request_pow_challenge_v1, ServicePolicyCheckpointV1,
};
use pir_sdk_client::PirTransport;
use pir_sdk_client::WsConnection;
use pir_service_protocol::{
    AuthScheme, BackendId, FreeModeV1, OperationStartV1, ServicePolicyV1, WorkloadId,
};

const REQ_HARMONY_BATCH_QUERY: u8 = 0x43;
const RESP_HARMONY_BATCH_QUERY: u8 = 0x43;
const REQ_BUCKET_MERKLE_TREE_TOPS: u8 = 0x34;

fn encode_request(op: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + body.len());
    out.extend_from_slice(&((1 + body.len()) as u32).to_le_bytes());
    out.push(op);
    out.extend_from_slice(body);
    out
}

fn fresh_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    bytes
}

fn env_hex32(name: &str) -> [u8; 32] {
    let raw = std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));
    let bytes = hex::decode(raw.trim()).expect("hex");
    bytes.try_into().expect("32 bytes")
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn repro_key() -> VerifyingKey {
    VerifyingKey::from_bytes(&env_hex32("REPRO_POLICY_KEY_HEX")).expect("valid ed25519 key")
}

fn pick_free_scope_offer(
    policy: &ServicePolicyV1,
    backend: BackendId,
    workload: WorkloadId,
) -> ([u8; 32], u32, FreeModeV1) {
    let mut pow: Option<([u8; 32], u32)> = None;
    for scope_policy in policy.scopes.iter() {
        if scope_policy.scope.backend != backend || scope_policy.scope.workload != workload {
            continue;
        }
        let scope_id = scope_policy.scope.scope_id();
        for offer in scope_policy.offers.iter() {
            if offer.authorization != AuthScheme::FreeV1 {
                continue;
            }
            match offer.free_mode {
                FreeModeV1::OpenBestEffort | FreeModeV1::IpRateLimited => {
                    return (scope_id, offer.offer_id, offer.free_mode)
                }
                FreeModeV1::ProofOfWork => {
                    if pow.is_none() {
                        pow = Some((scope_id, offer.offer_id));
                    }
                }
                _ => {}
            }
        }
    }
    if let Some((sid, oid)) = pow {
        return (sid, oid, FreeModeV1::ProofOfWork);
    }
    panic!("no free scope/offer for {backend:?} {workload:?}");
}

/// Brute-force a Free-PoW solution (the VPSBG free offers use bits ≈ 4).
async fn solve_pow(challenge: &pir_service_protocol::PowChallengeResponseV1) -> Vec<u8> {
    let c = challenge.clone();
    tokio::task::spawn_blocking(move || {
        for nonce in 0..=u64::MAX {
            let sol = pir_service_protocol::FreePowProofV1 {
                challenge_id: c.challenge_id,
                nonce,
            };
            if pir_service_protocol::pow_solution_meets_difficulty_v1(&c, &sol).unwrap_or(false) {
                return sol.encode().expect("pow encode").to_vec();
            }
        }
        unreachable!("pow nonce exhausted");
    })
    .await
    .expect("solver task")
}

/// attest → X25519 → policy → OpenBestEffort authorize for `operation`.
/// Returns the sealed, granted transport.
async fn admit_backend_leg(
    backend: BackendId,
    workload: WorkloadId,
    operation: OperationStartV1,
) -> pir_sdk_client::channel::SecureChannelTransport<WsConnection> {
    let url = std::env::var("REPRO_URL").unwrap_or_else(|_| "ws://127.0.0.1:18300".into());
    let mut conn = WsConnection::connect(&url)
        .await
        .expect("connect failed");
    let attestation = attest(&mut conn, fresh_32()).await.expect("attest failed");
    assert!(
        !attestation.response.server_static_pub.iter().all(|b| *b == 0),
        "server static pubkey is all-zero"
    );
    let mut transport = establish(
        conn,
        attestation.response.server_static_pub,
        fresh_32(),
        fresh_32(),
    )
    .await
    .expect("secure-channel upgrade failed");
    let accepted = fetch_verified_service_policy_v1(
        &mut transport,
        env_hex32("REPRO_PROVIDER_ID_HEX"),
        &repro_key(),
        now_unix(),
        &ServicePolicyCheckpointV1::initial(),
    )
    .await
    .expect("policy fetch failed");
    let (scope_id, offer_id, free_mode) = pick_free_scope_offer(accepted.policy(), backend, workload);
    let proof_bytes: Vec<u8> = match free_mode {
        FreeModeV1::OpenBestEffort | FreeModeV1::IpRateLimited => Vec::new(),
        FreeModeV1::ProofOfWork => {
            let challenge = request_pow_challenge_v1(
                &mut transport,
                &accepted,
                scope_id,
                offer_id,
                operation.clone(),
                now_unix(),
            )
            .await
            .expect("pow challenge");
            solve_pow(&challenge).await
        }
        other => panic!("unexpected free mode {other:?}"),
    };
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &scope_id,
        offer_id,
        &proof_bytes,
    )
    .expect("proof build failed");
    let grant = dangerous_unpaired_authorize_service_operation_v1(
        &mut transport,
        &accepted,
        scope_id,
        offer_id,
        operation,
        proof,
    )
    .await
    .expect("authorize failed");
    println!(
        "[repro] authorized scope offer_id={} limits wall_time_ms={}",
        offer_id, grant.expires_in_ms
    );
    transport
}

/// Build one production-shaped Harmony batch query frame:
/// K groups × `indices_per_group` sorted distinct u32 indices.
/// Production db0: level-0 request ≈ 320 KB (K=75 × ~1065 indices).
fn build_batch_query(level: u8, round_id: u16, db_id: u8, groups: u16, bins_per_table: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(level);
    payload.extend_from_slice(&round_id.to_le_bytes());
    payload.extend_from_slice(&groups.to_le_bytes());
    payload.push(1u8); // sub_queries_per_group
    let indices_per_group: u32 = std::env::var("REPRO_INDICES_PER_GROUP")
        .ok()
        .as_deref()
        .map(|s| s.parse().unwrap())
        .unwrap_or(match level {
            // (T−1) values chosen to mirror the production db0 wire shape:
            // INDEX entry 52 B, CHUNK entry 44 B → L0 ~320 KB request.
            0 => 1065,
            1 => 2560,
            _ => 128,
        });
    for group_id in 0..groups {
        payload.push(group_id as u8);
        payload.extend_from_slice(&indices_per_group.to_le_bytes());
        assert!(bins_per_table >= indices_per_group);
        for i in 0..indices_per_group {
            payload.extend_from_slice(&i.to_le_bytes());
        }
    }
    if db_id != 0 {
        payload.push(db_id);
    }
    encode_request(REQ_HARMONY_BATCH_QUERY, &payload)
}

/// S1: with full Payment-V1 admission (attest → channel → policy → free
/// authorize), the granted harmony-query INDEX batch frame must get its
/// ~4 MB response back. Prints request/response sizes + elapsed wall time
/// so the production-failure hypothesis (handler hang vs transit loss) is
/// directly comparable against the same scope limits.
#[tokio::test]
#[ignore = "local repro; run via docs/repro-local.md"]
async fn harmony_batch_query_full_response_local() {
    let db_id: u8 = std::env::var("REPRO_DB_ID").ok().as_deref().unwrap_or("0").parse().unwrap();
    let bins_per_table: u32 = std::env::var("REPRO_BINS_PER_TABLE")
        .ok()
        .as_deref()
        .unwrap_or("567558")
        .parse()
        .unwrap();
    let mut transport = admit_backend_leg(
        BackendId::HarmonyPirV2,
        WorkloadId::HarmonyQueryJobV1,
        OperationStartV1::HarmonyQuery { db_id },
    )
    .await;

    for (level, round_id) in [(0u8, 0u16), (0, 1), (1, 0), (1, 1)] {
        let frame = build_batch_query(level, round_id, db_id, if level == 0 { 75 } else { 80 }, bins_per_table);
        println!("[repro] sending level={level} round={round_id} request={} bytes", frame.len());
        let t0 = std::time::Instant::now();
        let resp = transport
            .roundtrip(&frame)
            .await
            .expect("harmony batch query roundtrip failed");
        let elapsed = t0.elapsed();
        if resp[0] != RESP_HARMONY_BATCH_QUERY {
            panic!(
                "unexpected response variant 0x{:02x}, body={:?}",
                resp[0],
                String::from_utf8_lossy(&resp[1..resp.len().min(300)])
            );
        }
        println!(
            "[repro] level={level}: response={} bytes in {elapsed:.2?} (handler OK)",
            resp.len()
        );
        if std::env::var("REPRO_SKIP_SIZE_ASSERT").is_err() {
            assert!(
                resp.len() > 3_000_000,
                "level={level} response suspiciously small: {} bytes",
                resp.len(),
            );
        }
    }
}

/// Size-bisection probe: one single INDEX frame whose request size is set by
/// REPRO_INDICES_PER_GROUP. Prints only.
#[tokio::test]
#[ignore = "local repro; run via docs/repro-local.md"]
async fn harmony_size_probe_local() {
    let mut transport = admit_backend_leg(
        BackendId::HarmonyPirV2,
        WorkloadId::HarmonyQueryJobV1,
        OperationStartV1::HarmonyQuery { db_id: 0 },
    )
    .await;
    let frame = build_batch_query(0, 0, 0, 75, 567558);
    println!("[repro] probe request={} bytes", frame.len());
    let t0 = std::time::Instant::now();
    match transport.roundtrip(&frame).await {
        Ok(resp) => println!(
            "[repro] probe OK: variant=0x{:02x} response={} bytes in {:?}",
            resp[0],
            resp.len(),
            t0.elapsed()
        ),
        Err(error) => panic!("[repro] probe FAILED: {error}"),
    }
}

/// S1 discriminator: a deliberately malformed harmony batch request
/// (wrong group count) must get an immediate gate error *response* —
/// proves the granted dispatch loop answers small frames on this path.
#[tokio::test]
#[ignore = "local repro; run via docs/repro-local.md"]
async fn harmony_batch_malformed_gets_gate_error_local() {
    let mut transport = admit_backend_leg(
        BackendId::HarmonyPirV2,
        WorkloadId::HarmonyQueryJobV1,
        OperationStartV1::HarmonyQuery { db_id: 0 },
    )
    .await;
    // level=0, round=0, but only ONE group → violates K-padded classification.
    let frame = build_batch_query(0, 0, 0, 1, 567558);
    let resp = transport
        .roundtrip(&frame)
        .await
        .expect("malformed query roundtrip failed");
    println!(
        "[repro] malformed frame response: variant=0x{:02x} len={} preview={:?}",
        resp[0],
        resp.len(),
        String::from_utf8_lossy(&resp[..resp.len().min(120)])
    );
    assert_ne!(
        resp[0], RESP_HARMONY_BATCH_QUERY,
        "malformed request must not be served as a real batch"
    );
}

/// S3: db1's 23.4 MB tree-tops blob vs the pre-auth egress budget.
/// History: pre-fix (16 MiB byte budget) the atomic group reservation
/// failed the db1 fetch before any chunk left the socket and the server
/// closed the connection ("budget terminal"); the patched budget
/// (64 MiB / 192 messages) carries db0+db1 on one connection.
#[tokio::test]
#[ignore = "local repro; run via docs/repro-local.md"]
async fn db0_tops_succeeds_db1_tops_succeeds_postfix_local() {
    let url = std::env::var("REPRO_URL").unwrap_or_else(|_| "ws://127.0.0.1:18300".into());

    // db0 tops first: must complete fully (9,155,384 B + resp variant byte).
    let mut conn = WsConnection::connect(&url).await.expect("connect failed");
    let attestation = attest(&mut conn, fresh_32()).await.expect("attest failed");
    let mut transport = establish(
        conn,
        attestation.response.server_static_pub,
        fresh_32(),
        fresh_32(),
    )
    .await
    .expect("secure-channel upgrade failed");
    let t0 = std::time::Instant::now();
    let resp0 = transport
        .roundtrip(&encode_request(REQ_BUCKET_MERKLE_TREE_TOPS, &[0u8]))
        .await
        .expect("db0 tops roundtrip failed");
    println!(
        "[repro] db0 tops: variant=0x{:02x} bytes={} in {:.2?}",
        resp0[0],
        resp0.len(),
        t0.elapsed()
    );
    assert_eq!(resp0[0], REQ_BUCKET_MERKLE_TREE_TOPS);
    assert_eq!(resp0.len() - 1, 9_155_384, "db0 tops length");

    // Same sealed connection, db1 tops: 23,426,084 B ≈ 90 transport chunks.
    let t1 = std::time::Instant::now();
    let resp1 = transport
        .roundtrip(&encode_request(REQ_BUCKET_MERKLE_TREE_TOPS, &[1u8]))
        .await
        .expect("db1 tops terminated: the pre-auth egress budget is still too small");
    println!(
        "[repro] db1 tops: variant=0x{:02x} bytes={} in {:.2?} (postfix)",
        resp1[0],
        resp1.len(),
        t1.elapsed()
    );
    assert_eq!(resp1[0], REQ_BUCKET_MERKLE_TREE_TOPS);
    assert_eq!(resp1.len() - 1, 23_426_084, "db1 tops length");
}
