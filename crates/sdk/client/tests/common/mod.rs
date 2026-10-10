//! Live-server session helpers shared by the integration tests.
//!
//! The public PIR deployment (`wss://weikeng1.bitcoinpir.org` /
//! `wss://bitcoin-pir-weikeng-laptop.chenweikeng.com`) serves PIR over an X25519 encrypted
//! channel: a client attests, upgrades to the secure channel, installs the
//! verified database proof, and queries. There is no policy fetch, no
//! proof-of-work, and no authorization round — free queries are open.
//!
//! The helpers in this module run that session sequence so the live
//! integration tests keep exercising the real backend paths against the
//! production deployment (the same servers the web client uses).
//!
//! If a provider's attestation or database proof does not verify, the
//! helper returns an error and the test fails rather than silently skipping
//! the backend path.

#![allow(dead_code)]

use pir_sdk::{PirError, PirResult};
use pir_sdk_client::{DatabaseProofPolicy, DpfClient, HarmonyClient, OnionClient, PirClient};

fn fresh_32() -> PirResult<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        PirError::Protocol(format!("getrandom failed while preparing session: {error}"))
    })?;
    Ok(bytes)
}

/// Operator-issued API key from `PIR_API_KEY` (docs/CREDITS.md "API keys").
/// When set, every leg presents it once its secure channel is open, so
/// backends that production charges for serve the suite unmetered.
pub fn api_key() -> Option<String> {
    std::env::var("PIR_API_KEY")
        .ok()
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
}

/// A server's attested channel key; an all-zero key means no channel.
fn channel_key(key: [u8; 32], label: &str) -> PirResult<[u8; 32]> {
    if key.iter().all(|b| *b == 0) {
        return Err(PirError::VerificationFailed(format!(
            "{label} attestation returned all-zero server static pubkey"
        )));
    }
    Ok(key)
}

/// Complete the live session sequence for a DPF two-server query: install
/// the database proof, attest both servers and open the secure channel
/// (server0 = Hetzner, server1 = pir2).
pub async fn admit_dpf_live(
    client: &mut DpfClient,
    db_id: u8,
    proof_policy: &DatabaseProofPolicy,
) -> PirResult<()> {
    let roots = client.verify_database_proof(db_id, proof_policy).await?;
    client.install_verified_database_roots(roots)?;
    let key0 = channel_key(
        client
            .attest(0, fresh_32()?)
            .await?
            .response
            .server_static_pub,
        "server0",
    )?;
    let key1 = channel_key(
        client
            .attest(1, fresh_32()?)
            .await?
            .response
            .server_static_pub,
        "server1",
    )?;
    client.upgrade_to_secure_channel(key0, key1).await?;
    if let Some(key) = api_key() {
        client.present_api_key(0, &key).await?;
        client.present_api_key(1, &key).await?;
    }
    Ok(())
}

/// `HintProgress` sink for test-side pre-fetch calls.
struct NoopHintProgress;
impl pir_sdk_client::HintProgress for NoopHintProgress {
    fn on_group_complete(&self, _done: u32, _total: u32, _phase: &str) {}
}

/// Complete the live session sequence for a HarmonyPIR query: install the
/// verified database proof, open the secure channel to both servers,
/// preflight the proof-verified tree tops, and download the main +
/// Merkle-sibling hints.
pub async fn admit_harmony_live(
    client: &mut HarmonyClient,
    db_id: u8,
    proof_policy: &DatabaseProofPolicy,
    _script_hashes: &[pir_sdk::ScriptHash],
) -> PirResult<()> {
    let roots = client.verify_database_proof(db_id, proof_policy).await?;
    client.install_verified_database_roots(roots)?;

    let catalog = client.fetch_catalog().await?;
    let db_info = catalog
        .databases
        .iter()
        .find(|db| db.db_id == db_id)
        .cloned()
        .ok_or(PirError::DatabaseNotFound(db_id))?;
    let hint_key = channel_key(
        client
            .attest(0, fresh_32()?)
            .await?
            .response
            .server_static_pub,
        "hint",
    )?;
    let query_key = channel_key(
        client
            .attest(1, fresh_32()?)
            .await?
            .response
            .server_static_pub,
        "query",
    )?;
    client
        .upgrade_to_secure_channel(hint_key, query_key)
        .await?;
    if let Some(key) = api_key() {
        client.present_api_key(0, &key).await?;
        client.present_api_key(1, &key).await?;
    }
    client.preflight_verified_database(db_id).await?;
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
    let roots = client.verify_database_proof_v2(db_id, proof_policy).await?;
    client.install_verified_database_roots(roots)?;

    let nonce = fresh_32()?;
    let attestation = client.attest(nonce).await?;
    if attestation
        .response
        .server_static_pub
        .iter()
        .all(|b| *b == 0)
    {
        return Err(PirError::VerificationFailed(
            "OnionPIR attestation returned all-zero server static pubkey".into(),
        ));
    }
    let eph_seed = fresh_32()?;
    let hs_nonce = fresh_32()?;
    client
        .upgrade_to_secure_channel_with_seeds(
            attestation.response.server_static_pub,
            eph_seed,
            hs_nonce,
        )
        .await?;
    if let Some(key) = api_key() {
        client.present_api_key(&key).await?;
    }
    Ok(())
}
