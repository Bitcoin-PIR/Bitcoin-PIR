//! Live-server Payment-V1 admission helpers shared by the integration tests.
//!
//! The public PIR deployment (`wss://weikeng1.bitcoinpir.org` /
//! `wss://weikeng2.bitcoinpir.org`) runs `unified_server` with
//! `--require-service-auth-v1` (see
//! `scripts/dracut/97bpir-tier3-init/unified-server-run.sh`), which puts the
//! connection into `AdmissionEnforcementV1::Enforced`: any backend frame
//! (INDEX / CHUNK / Merkle / ORAM) is rejected unless the client
//!
//! 1. established the X25519 encrypted channel (`REQ_HANDSHAKE`), and
//! 2. delivered an authorization grant for the exact scope/offer the query
//!    will use (`REQ_SERVICE_POLICY` → Free-PoW challenge → `REQ_AUTH`).
//!
//! The helpers in this module run that admission sequence so the live
//! integration tests keep exercising the real backend paths against the
//! production deployment (the same servers the web client uses).
//!
//! Provider pins are operator-published values mirrored from
//! `web/src/functional-beta-trusted-bootstrap.json` — the same trust anchors
//! the browser pins. Rotate them together with that file.
//!
//! Admission is deliberately **fail-closed**: if a provider no longer offers
//! a free scope/offer for the requested backend (or the PoW difficulty is
//! unsatisfiable), the helper returns an error and the test fails loudly
//! rather than silently skipping the backend path.

#![allow(dead_code)]

use ed25519_dalek::VerifyingKey;
use pir_sdk::{PirError, PirResult};
use pir_sdk_client::{
    dangerous_unpaired_build_authorization_proof_v1, AcceptedServicePolicyV1,
    DatabaseProofPolicy, DpfClient, HarmonyClient, OnionClient, PirClient, RootPolicy,
    ServicePolicyCheckpointV1,
};
use pir_service_protocol::{
    pow_solution_meets_difficulty_v1, AuthScheme, BackendId, FreeModeV1, FreePowProofV1,
    HintTransport, PowChallengeResponseV1, ServicePolicyV1, WorkloadId,
};

/// Operator-published trust anchors for one live provider, mirrored from
/// `web/src/functional-beta-trusted-bootstrap.json`.
pub struct LiveProviderPins {
    pub provider_id: [u8; 32],
    pub policy_signing_key: VerifyingKey,
}

/// Hetzner `wss://weikeng1.bitcoinpir.org` (DPF server0 / Harmony hint /
/// OnionPIR). No SEV-SNP attestation; binary SHA pin lives in the web
/// bootstrap file.
pub fn hetzner_pins() -> LiveProviderPins {
    LiveProviderPins {
        provider_id: decode_hex_array(
            "9110aee8843ff4eaa60eb5e2f36345cef03c779c08becbfe76f4cc0400fc0eb0",
        ),
        policy_signing_key: verifying_key(
            "6528d01b64275834460fd2c6f1d8b2df1374ea62ed0204ea2429adcc70246a93",
        ),
    }
}

/// VPSBG `wss://weikeng2.bitcoinpir.org` (DPF server1 / Harmony query).
/// SEV-SNP attested; measurement lives in the web bootstrap file.
pub fn vpsbg_pins() -> LiveProviderPins {
    LiveProviderPins {
        provider_id: decode_hex_array(
            "85bfdd55b1408402bcad886568b732818a32472747226aa009839d45e0b96cac",
        ),
        policy_signing_key: verifying_key(
            "73c5889ee3bb11b79a7628bad1aa24be927f6e047abadd6dd6ce38e45bb0cfd5",
        ),
    }
}

fn verifying_key(hex: &str) -> VerifyingKey {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex, &mut bytes).expect("policy signing key must be valid hex");
    VerifyingKey::from_bytes(&bytes).expect("policy signing key must be a valid Ed25519 public key")
}

/// Database-proof policy for the pinned production db0 (main) snapshot.
/// Mirrors the db0 entry of `PRODUCTION_DATABASE_PINS` in
/// `tests/integration_test.rs`; the leakage suite uses this for the
/// admission step (the server requires installed verified roots before it
/// issues a PoW challenge or accepts an authorization).
pub fn production_db0_proof_policy() -> DatabaseProofPolicy {
    let mut policy = DatabaseProofPolicy::mainnet();
    policy.expected_params_hash = Some(decode_hex_array(
        "ac364eb24e24ba025e2dcfdd50b9ccf65ffd556488afc076b70b557084c5318e",
    ));
    policy.allowed_builder_binary_sha256 = vec![decode_hex_array(
        "d4da29807e806c8a16eec94b86119bd16df7805a66fa4ff1c187a26832a36427",
    )];
    policy.allowed_builder_git_commits =
        vec!["b692aec18b9c20ac92cb9fe22588e96ff96ad27d".to_owned()];
    policy
}

/// Database-proof policy for the pinned production db0 OnionPIR v2 layout.
/// Mirrors `production_onion_v2_pin(PRODUCTION_DATABASE_PINS[0])` in
/// `tests/integration_test.rs`: v2 proofs must verify against the exact
/// OnionPIR builder artifact, not the generic bucket-Merkle builder.
/// `OnionClient::fetch_service_policy_v1` requires installed verified roots
/// and the strict canary binds its tree-top preflight to the v2 super-root,
/// so the OnionPIR admission path installs the v2 proof.
pub fn production_db0_onion_v2_proof_policy() -> DatabaseProofPolicy {
    let mut policy = production_db0_proof_policy();
    policy.expected_params_hash = Some(decode_hex_array(
        "a600f33fa0e644aab533a050eabf9c03882aa00f1b293ddf9d7f4bf7c8142563",
    ));
    policy.allowed_builder_binary_sha256 = vec![decode_hex_array(
        "1150d6a2d746398d9046e677e1f0d36f4c4ccb3c390265ea8cf14d7c1f23671c",
    )];
    policy.allowed_builder_git_commits =
        vec!["d49a199e290ccbb05b6481c5ba691cb516aa76bb".to_owned()];
    policy
}

fn decode_hex_array<const N: usize>(value: &str) -> [u8; N] {
    let bytes = hex::decode(value).expect("pin must be valid hex");
    bytes.try_into().expect("pin hex length must match")
}

fn proto_err(error: impl ToString) -> PirError {
    PirError::Protocol(error.to_string())
}

/// Trusted wall clock in whole Unix seconds (the service protocol's time unit).
pub fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}

fn fresh_32() -> PirResult<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        PirError::Protocol(format!("getrandom failed while preparing admission: {error}"))
    })?;
    Ok(bytes)
}

/// Pick the first FreeV1 scope/offer for `backend`/`workload` in the verified
/// policy. Free modes that need no proof (open-best-effort, IP rate-limited)
/// are preferred; proof-of-work is the fallback so providers whose only free
/// offer is PoW (the VPSBG beta) still work. Paid-only offers are never
/// selected — live integration tests must not spend money.
pub fn select_free_scope_offer(
    policy: &ServicePolicyV1,
    backend: BackendId,
    workload: WorkloadId,
) -> PirResult<([u8; 32], u32, FreeModeV1)> {
    let mut pow_fallback: Option<([u8; 32], u32)> = None;
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
                    return Ok((scope_id, offer.offer_id, offer.free_mode))
                }
                FreeModeV1::ProofOfWork => {
                    if pow_fallback.is_none() {
                        pow_fallback = Some((scope_id, offer.offer_id));
                    }
                }
                _ => {}
            }
        }
    }
    if let Some((scope_id, offer_id)) = pow_fallback {
        return Ok((scope_id, offer_id, FreeModeV1::ProofOfWork));
    }
    Err(PirError::InvalidState(format!(
        "no free scope/offer for backend {backend:?} workload {workload:?} in verified policy"
    )))
}

/// Brute-force a Free-PoW solution on a blocking thread, bounded by a 60 s
/// timeout so a misconfigured high-difficulty policy fails fast instead of
/// hanging the async test runtime. The server bounds difficulty at
/// `MAX_POW_DIFFICULTY_BITS_V1` and the beta policy uses a small target, so
/// this normally completes in milliseconds.
pub async fn solve_pow(challenge: &PowChallengeResponseV1) -> PirResult<FreePowProofV1> {
    let challenge = challenge.clone();
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            for nonce in 0..=u64::MAX {
                let solution = FreePowProofV1 {
                    challenge_id: challenge.challenge_id,
                    nonce,
                };
                if pow_solution_meets_difficulty_v1(&challenge, &solution).map_err(proto_err)? {
                    return Ok(solution);
                }
            }
            Err(PirError::Protocol(
                "proof-of-work nonce space exhausted".into(),
            ))
        }),
    )
    .await
    .map_err(|_| PirError::Protocol("proof-of-work solve timed out after 60s".into()))?
    .map_err(|join| PirError::Protocol(format!("proof-of-work solver task failed: {join}")))?
}

/// Build the authorization proof for a selected free offer: empty for
/// no-proof modes, a solved PoW otherwise.
async fn build_free_proof(
    client: &mut DpfClient,
    server_index: u8,
    db_id: u8,
    accepted: &AcceptedServicePolicyV1,
    scope_id: [u8; 32],
    offer_id: u32,
    free_mode: FreeModeV1,
) -> PirResult<pir_service_protocol::AuthorizationProofV1> {
    let proof_bytes: Vec<u8> = match free_mode {
        FreeModeV1::OpenBestEffort | FreeModeV1::IpRateLimited => Vec::new(),
        FreeModeV1::ProofOfWork => {
            let challenge = client
                .request_service_pow_challenge_v1(
                    server_index,
                    db_id,
                    accepted,
                    scope_id,
                    offer_id,
                    now_unix(),
                )
                .await?;
            let solution = solve_pow(&challenge).await?;
            solution.encode().map_err(proto_err)?.to_vec()
        }
        other => {
            return Err(PirError::InvalidState(format!(
                "unexpected free mode {other:?} in selected live offer"
            )))
        }
    };
    dangerous_unpaired_build_authorization_proof_v1(accepted, &scope_id, offer_id, &proof_bytes)
}

/// Admit one DPF server leg: attest → secure channel → policy → authorize.
async fn admit_dpf_server(
    client: &mut DpfClient,
    server_index: u8,
    db_id: u8,
    pins: &LiveProviderPins,
) -> PirResult<()> {
    let nonce = fresh_32()?;
    let attestation = client.attest(server_index, nonce).await?;
    if attestation.response.server_static_pub.iter().all(|b| *b == 0) {
        return Err(PirError::VerificationFailed(format!(
            "server{server_index} attestation returned all-zero server static pubkey"
        )));
    }
    let eph_seed = fresh_32()?;
    let hs_nonce = fresh_32()?;
    client
        .upgrade_server_to_secure_channel_with_seed(
            server_index,
            attestation.response.server_static_pub,
            eph_seed,
            hs_nonce,
        )
        .await?;

    let accepted = client
        .fetch_service_policy_v1(
            server_index,
            db_id,
            pins.provider_id,
            &pins.policy_signing_key,
            now_unix(),
            &ServicePolicyCheckpointV1::initial(),
        )
        .await?;
    let (scope_id, offer_id, free_mode) = select_free_scope_offer(
        accepted.policy(),
        BackendId::DpfPirV1,
        WorkloadId::DpfEvaluateJobV1,
    )?;
    let proof = build_free_proof(
        client,
        server_index,
        db_id,
        &accepted,
        scope_id,
        offer_id,
        free_mode,
    )
    .await?;
    client
        .dangerous_unpaired_authorize_service_v1(
            server_index, db_id, &accepted, scope_id, offer_id, proof,
        )
        .await?;
    Ok(())
}

/// Complete the live admission sequence for a DPF two-server query:
/// install the database proof, then admit both legs (server0 = Hetzner,
/// server1 = VPSBG).
pub async fn admit_dpf_live(
    client: &mut DpfClient,
    db_id: u8,
    proof_policy: &DatabaseProofPolicy,
) -> PirResult<()> {
    client.set_root_policy(RootPolicy::RequireVerified);
    let roots = client.verify_database_proof(db_id, proof_policy).await?;
    client.install_verified_database_roots(roots)?;
    admit_dpf_server(client, 0, db_id, &hetzner_pins()).await?;
    admit_dpf_server(client, 1, db_id, &vpsbg_pins()).await?;
    Ok(())
}

/// Produce the FreeV1 proof payload for a Harmony hint/query leg or an
/// OnionPIR session: empty for no-proof free modes, a solved PoW otherwise.
/// `fetch_challenge` is the backend-specific PoW-challenge roundtrip; it is
/// only driven when the selected offer is proof-of-work.
async fn free_proof_bytes<Fetch>(
    free_mode: FreeModeV1,
    fetch_challenge: Fetch,
) -> PirResult<Vec<u8>>
where
    Fetch: std::future::Future<Output = PirResult<PowChallengeResponseV1>>,
{
    match free_mode {
        FreeModeV1::OpenBestEffort | FreeModeV1::IpRateLimited => Ok(Vec::new()),
        FreeModeV1::ProofOfWork => {
            let challenge = fetch_challenge.await?;
            let solution = solve_pow(&challenge).await?;
            Ok(solution.encode().map_err(proto_err)?.to_vec())
        }
        other => Err(PirError::InvalidState(format!(
            "unexpected free mode {other:?} in selected live offer"
        ))),
    }
}

/// Admit one Harmony provider leg's secure channel: attest → X25519
/// handshake. Policy fetch + authorize are deliberately separate so the
/// caller can choose when the grant's `max_wall_time_ms` starts ticking.
async fn admit_harmony_leg_channel(
    client: &mut HarmonyClient,
    provider_index: u8,
) -> PirResult<()> {
    let nonce = fresh_32()?;
    let attestation = client.attest(provider_index, nonce).await?;
    if attestation.response.server_static_pub.iter().all(|b| *b == 0) {
        return Err(PirError::VerificationFailed(format!(
            "Harmony provider{provider_index} attestation returned all-zero server static pubkey"
        )));
    }
    let eph_seed = fresh_32()?;
    let hs_nonce = fresh_32()?;
    client
        .upgrade_provider_to_secure_channel_with_seed(
            provider_index,
            attestation.response.server_static_pub,
            eph_seed,
            hs_nonce,
        )
        .await
}

/// Authorize the Harmony hint leg's free offer with the V2Full hint
/// transport and no attach token, mirroring the WASM product flow
/// (`authorizeHintService` in `crates/sdk/wasm/src/client.rs`) — the only
/// hint transport the production V1 gate accepts without a paid pairing
/// token.
async fn admit_harmony_hint_authorize(
    client: &mut HarmonyClient,
    db_id: u8,
    pins: &LiveProviderPins,
) -> PirResult<()> {
    let accepted = client
        .fetch_service_policy_v1(
            0,
            db_id,
            pins.provider_id,
            &pins.policy_signing_key,
            now_unix(),
            &ServicePolicyCheckpointV1::initial(),
        )
        .await?;
    let (scope_id, offer_id, free_mode) = select_free_scope_offer(
        accepted.policy(),
        BackendId::HarmonyPirV2,
        WorkloadId::HarmonyHintBundleV1,
    )?;
    let proof_bytes = free_proof_bytes(
        free_mode,
        client.request_hint_pow_challenge_v1(db_id, &accepted, scope_id, offer_id, now_unix()),
    )
    .await?;
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &scope_id,
        offer_id,
        &proof_bytes,
    )?;
    client
        .dangerous_unpaired_authorize_hint_service_v1(
            db_id,
            &accepted,
            scope_id,
            offer_id,
            proof,
            HintTransport::V2Full,
            None,
            None,
        )
        .await?;
    Ok(())
}

/// Authorize the Harmony query leg's free offer. Call this only after all
/// hint-megabyte work is done: the live `harmony-query-job-v1` scope grants
/// `max_wall_time_ms = 120_000` measured from the AUTH grant, and a fresh
/// ~21 s main-bundle download plus per-level sibling streams must not eat
/// into the query phase's window.
async fn admit_harmony_query_authorize(
    client: &mut HarmonyClient,
    db_id: u8,
    pins: &LiveProviderPins,
) -> PirResult<()> {
    let accepted = client
        .fetch_service_policy_v1(
            1,
            db_id,
            pins.provider_id,
            &pins.policy_signing_key,
            now_unix(),
            &ServicePolicyCheckpointV1::initial(),
        )
        .await?;
    let (scope_id, offer_id, free_mode) = select_free_scope_offer(
        accepted.policy(),
        BackendId::HarmonyPirV2,
        WorkloadId::HarmonyQueryJobV1,
    )?;
    let proof_bytes = free_proof_bytes(
        free_mode,
        client.request_query_pow_challenge_v1(db_id, &accepted, scope_id, offer_id, now_unix()),
    )
    .await?;
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &scope_id,
        offer_id,
        &proof_bytes,
    )?;
    client
        .dangerous_unpaired_authorize_query_service_v1(db_id, &accepted, scope_id, offer_id, proof)
        .await?;
    Ok(())
}

/// `HintProgress` sink for test-side pre-fetch calls.
struct NoopHintProgress;
impl pir_sdk_client::HintProgress for NoopHintProgress {
    fn on_group_complete(&self, _done: u32, _total: u32, _phase: &str) {}
}

/// Complete the live admission sequence for a HarmonyPIR query, ordered to
/// respect the production grant windows (the same staging the browser
/// product uses):
///
/// 1. install the verified database proof,
/// 2. snapshot the catalog (once the hint-leg grant is flushed, the hint
///    connection accepts exactly the V2Full main-dispatch frame; any other
///    frame — even an otherwise-ungated one like REQ_GET_DB_CATALOG —
///    terminalizes it),
/// 3. open both legs' secure channels and authorize the hint leg
///    (`harmony-hint-bundle-v1`, V2Full transport),
/// 4. preflight the proof-verified tree tops over the query leg,
/// 5. download the complete main + Merkle-sibling hint bundle under the
///    V2Full grant — all hint-leg traffic, bounded by the hint scope's
///    300 s window,
/// 6. ONLY THEN authorize the query leg (`harmony-query-job-v1`), whose
///    grant allows 120 s total for the INDEX → CHUNK → Merkle query phase.
///
/// Authorizing the query leg up-front instead spends a double-digit share
/// of its 120 s window on the ~21 s main-bundle download + sibling streams
/// before the first INDEX frame leaves, so the admission sequence keeps
/// hint-leg megabytes outside the query grant's budget.
pub async fn admit_harmony_live(
    client: &mut HarmonyClient,
    db_id: u8,
    proof_policy: &DatabaseProofPolicy,
) -> PirResult<()> {
    client.set_root_policy(RootPolicy::RequireVerified);
    let roots = client.verify_database_proof(db_id, proof_policy).await?;
    client.install_verified_database_roots(roots)?;

    // Snapshot the catalog entry BEFORE the hint-leg grant. Once the V2Full
    // AUTH result is flushed, the hint connection accepts exactly one frame
    // — the bound main-dispatch — and any other frame on that connection
    // (even an otherwise-ungated one like REQ_GET_DB_CATALOG) terminalizes
    // the pending-reservation connection hard.
    let catalog = client.fetch_catalog().await?;
    let db_info = catalog
        .databases
        .iter()
        .find(|db| db.db_id == db_id)
        .cloned()
        .ok_or(PirError::DatabaseNotFound(db_id))?;

    admit_harmony_leg_channel(client, 0).await?;
    admit_harmony_hint_authorize(client, db_id, &hetzner_pins()).await?;
    // From here until `fetch_complete_hints_with_progress` returns, the
    // hint connection may only carry the V2Full main dispatch followed by
    // the canonical sibling sequence. Query-leg work below uses the other
    // connection and is unaffected.
    admit_harmony_leg_channel(client, 1).await?;
    client.preflight_verified_database(db_id).await?;
    client
        .fetch_complete_hints_with_progress(&db_info, &NoopHintProgress)
        .await?;

    admit_harmony_query_authorize(client, db_id, &vpsbg_pins()).await?;
    Ok(())
}

/// Complete the live admission sequence for an OnionPIR session on the
/// Hetzner provider: install the v2 database proof, attest, open the
/// secure channel, then authorize the `onion-evaluate-job-v1` free offer.
/// The resulting grant permits exactly one key registration followed by
/// the canonical INDEX → CHUNK → Merkle query sequence on this connection
/// (the production V1 register-once DFA).
pub async fn admit_onion_live(
    client: &mut OnionClient,
    db_id: u8,
    proof_policy: &DatabaseProofPolicy,
) -> PirResult<()> {
    client.set_root_policy(RootPolicy::RequireVerified);
    let roots = client.verify_database_proof_v2(db_id, proof_policy).await?;
    client.install_verified_database_roots(roots)?;

    let pins = hetzner_pins();
    let nonce = fresh_32()?;
    let attestation = client.attest(nonce).await?;
    if attestation.response.server_static_pub.iter().all(|b| *b == 0) {
        return Err(PirError::VerificationFailed(
            "OnionPIR attestation returned all-zero server static pubkey".into(),
        ));
    }
    let eph_seed = fresh_32()?;
    let hs_nonce = fresh_32()?;
    client
        .upgrade_to_secure_channel_with_seeds(attestation.response.server_static_pub, eph_seed, hs_nonce)
        .await?;
    let accepted = client
        .fetch_service_policy_v1(
            db_id,
            pins.provider_id,
            &pins.policy_signing_key,
            now_unix(),
            &ServicePolicyCheckpointV1::initial(),
        )
        .await?;
    let (scope_id, offer_id, free_mode) = select_free_scope_offer(
        accepted.policy(),
        BackendId::OnionPirV1,
        WorkloadId::OnionEvaluateJobV1,
    )?;
    let proof_bytes = free_proof_bytes(
        free_mode,
        client.request_service_pow_challenge_v1(db_id, &accepted, scope_id, offer_id, now_unix()),
    )
    .await?;
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &scope_id,
        offer_id,
        &proof_bytes,
    )?;
    client
        .authorize_service_v1(db_id, &accepted, scope_id, offer_id, proof)
        .await?;
    Ok(())
}
