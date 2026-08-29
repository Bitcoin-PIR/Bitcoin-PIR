//! Live-server session helpers shared by the integration tests.
//!
//! The public PIR deployment (`wss://weikeng1.bitcoinpir.org` /
//! `wss://weikeng2.bitcoinpir.org`) serves PIR over an X25519 encrypted
//! channel: a client attests, upgrades to the secure channel, installs the
//! verified database proof, and queries. There is no policy fetch, no
//! proof-of-work, and no authorization round — free queries are open.
//!
//! The helpers in this module run that session sequence so the live
//! integration tests keep exercising the real backend paths against the
//! production deployment (the same servers the web client uses).
//!
//! Session setup is deliberately **fail-closed**: if a provider's
//! attestation or database proof does not verify, the helper returns an
//! error and the test fails loudly rather than silently skipping the
//! backend path.

#![allow(dead_code)]

use pir_sdk::{PirError, PirResult};
use pir_sdk_client::{
    DatabaseProofPolicy, DpfClient, HarmonyClient, OnionClient, PirClient, RootPolicy,
};

/// Database-proof policy for the pinned production db0 (main) snapshot.
/// Mirrors the db0 entry of `PRODUCTION_DATABASE_PINS` in
/// `tests/integration_test.rs`; the leakage suite uses this for the
/// session step (the strict clients bind tree-top preflight to installed
/// verified roots).
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
/// `OnionClient::preflight_verified_database` requires installed verified
/// roots and the strict canary binds its tree-top preflight to the v2
/// super-root, so the OnionPIR session path installs the v2 proof.
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

fn fresh_32() -> PirResult<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        PirError::Protocol(format!("getrandom failed while preparing session: {error}"))
    })?;
    Ok(bytes)
}

/// Open one DPF server leg's secure channel: attest → X25519 handshake.
async fn open_dpf_server_channel(client: &mut DpfClient, server_index: u8) -> PirResult<()> {
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
    Ok(())
}

/// Complete the live session sequence for a DPF two-server query: install
/// the database proof, then open both legs' secure channels
/// (server0 = Hetzner, server1 = VPSBG).
pub async fn admit_dpf_live(
    client: &mut DpfClient,
    db_id: u8,
    proof_policy: &DatabaseProofPolicy,
) -> PirResult<()> {
    client.set_root_policy(RootPolicy::RequireVerified);
    let roots = client.verify_database_proof(db_id, proof_policy).await?;
    client.install_verified_database_roots(roots)?;
    open_dpf_server_channel(client, 0).await?;
    open_dpf_server_channel(client, 1).await?;
    Ok(())
}

/// Open one Harmony provider leg's secure channel: attest → X25519
/// handshake.
async fn open_harmony_leg_channel(client: &mut HarmonyClient, provider_index: u8) -> PirResult<()> {
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

/// `HintProgress` sink for test-side pre-fetch calls.
struct NoopHintProgress;
impl pir_sdk_client::HintProgress for NoopHintProgress {
    fn on_group_complete(&self, _done: u32, _total: u32, _phase: &str) {}
}

/// Complete the live session sequence for a HarmonyPIR query:
///
/// 1. install the verified database proof,
/// 2. snapshot the catalog (the hint download below needs the db geometry),
/// 3. open the query leg's secure channel and preflight the proof-verified
///    tree tops,
/// 4. open the hint leg's secure channel,
/// 5. download the complete main + Merkle-sibling hint bundle.
pub async fn admit_harmony_live(
    client: &mut HarmonyClient,
    db_id: u8,
    proof_policy: &DatabaseProofPolicy,
    _script_hashes: &[pir_sdk::ScriptHash],
) -> PirResult<()> {
    client.set_root_policy(RootPolicy::RequireVerified);
    let roots = client.verify_database_proof(db_id, proof_policy).await?;
    client.install_verified_database_roots(roots)?;

    let catalog = client.fetch_catalog().await?;
    let db_info = catalog
        .databases
        .iter()
        .find(|db| db.db_id == db_id)
        .cloned()
        .ok_or(PirError::DatabaseNotFound(db_id))?;
    open_harmony_leg_channel(client, 1).await?;
    client.preflight_verified_database(db_id).await?;

    open_harmony_leg_channel(client, 0).await?;
    client
        .fetch_complete_hints_with_progress(&db_info, &NoopHintProgress)
        .await?;
    Ok(())
}

/// Complete the live session sequence for an OnionPIR session on the
/// Hetzner provider: install the v2 database proof, attest, then open the
/// secure channel.
pub async fn admit_onion_live(
    client: &mut OnionClient,
    db_id: u8,
    proof_policy: &DatabaseProofPolicy,
) -> PirResult<()> {
    client.set_root_policy(RootPolicy::RequireVerified);
    let roots = client.verify_database_proof_v2(db_id, proof_policy).await?;
    client.install_verified_database_roots(roots)?;

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
    Ok(())
}
