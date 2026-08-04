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
    DatabaseProofPolicy, DpfClient, RootPolicy, ServicePolicyCheckpointV1,
};
use pir_service_protocol::{
    pow_solution_meets_difficulty_v1, AuthScheme, BackendId, FreeModeV1, FreePowProofV1,
    PowChallengeResponseV1, ServicePolicyV1, WorkloadId,
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

