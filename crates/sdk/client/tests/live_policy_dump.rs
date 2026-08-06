//! Read-only diagnostic: fetch and print the *signed* ServicePolicyV1 each
//! live provider currently advertises (`REQ_SERVICE_POLICY_V1` is a public
//! pre-authorization opcode; attest + secure channel only). No PoW, no AUTH,
//! no backend frames — zero production impact besides one handshake per leg.
//!
//! Run: `cargo test -p pir-sdk-client --test live_policy_dump -- --ignored --nocapture`

mod common;

use common::{hetzner_pins, now_unix, vpsbg_pins, LiveProviderPins};
use pir_sdk_client::{DpfClient, PirClient, ServicePolicyCheckpointV1};

fn fresh_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    bytes
}

fn url(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

async fn dump_one(
    client: &mut DpfClient,
    server_index: u8,
    label: &str,
    pins: &LiveProviderPins,
) {
    let nonce = fresh_32();
    let attestation = client.attest(server_index, nonce).await.expect("attest failed");
    client
        .upgrade_server_to_secure_channel_with_seed(
            server_index,
            attestation.response.server_static_pub,
            fresh_32(),
            fresh_32(),
        )
        .await
        .expect("secure channel failed");
    let accepted = client
        .fetch_service_policy_v1(
            server_index,
            0,
            pins.provider_id,
            &pins.policy_signing_key,
            now_unix(),
            &ServicePolicyCheckpointV1::initial(),
        )
        .await
        .expect("policy fetch failed");
    let policy = accepted.policy();
    println!("\n===== {label} epoch={} issued_at={} expires_at={} =====",
        policy.policy_epoch, policy.issued_at, policy.expires_at);
    for scope in &policy.scopes {
        let l = &scope.limits;
        println!(
            "scope backend={:?} workload={:?} proto_v{} dataset={:?}\n  limits: logical_inputs={} frames={} request_bytes={} response_bytes={} wall_time_ms={} sockets={} hint_groups={} work_units={}",
            scope.scope.backend,
            scope.scope.workload,
            scope.scope.protocol_version,
            scope.scope.dataset,
            l.max_logical_inputs,
            l.max_frames,
            l.max_request_bytes,
            l.max_response_bytes,
            l.max_wall_time_ms,
            l.max_concurrent_sockets,
            l.max_hint_groups,
            l.max_work_units,
        );
        for offer in &scope.offers {
            println!(
                "  offer={}: acq={:?} free_mode={:?} auth={:?} verify={:?} deploy={:?} price={:?} pow_bits={}",
                offer.offer_id,
                offer.acquisition,
                offer.free_mode,
                offer.authorization,
                offer.verification,
                offer.deployment_status,
                offer.price,
                offer.free_pow_difficulty_bits,
            );
        }
    }
}

#[tokio::test]
#[ignore = "read-only live diagnostic; run explicitly"]
async fn dump_live_signed_service_policies() {
    let url0 = url("PIR_DPF_SERVER0_URL", "wss://weikeng1.bitcoinpir.org");
    let url1 = url("PIR_DPF_SERVER1_URL", "wss://weikeng2.bitcoinpir.org");
    let mut client = DpfClient::new(&url0, &url1);
    client.connect().await.expect("connect failed");
    client.set_root_policy(pir_sdk_client::RootPolicy::RequireVerified);
    let roots = client
        .verify_database_proof(0, &common::production_db0_proof_policy())
        .await
        .expect("db0 proof verification failed");
    client
        .install_verified_database_roots(roots)
        .expect("root installation failed");
    dump_one(&mut client, 0, "pir1 Hetzner (weikeng1)", &hetzner_pins()).await;
    dump_one(&mut client, 1, "pir2 VPSBG (weikeng2)", &vpsbg_pins()).await;
    client.disconnect().await.unwrap();
}
