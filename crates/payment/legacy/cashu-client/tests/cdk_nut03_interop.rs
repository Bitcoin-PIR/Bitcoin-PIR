//! Opt-in, disposable CDK 0.17.3 provider-side NUT-03/NUT-07 interoperability.
//!
//! This test is intentionally ignored. The repository runner starts a
//! loopback-only fake-wallet mint and passes owner-only fixture files. The
//! signed manifest contains the same private-CA HTTPS identity used by the
//! real-provider process test; this test-only transport maps only that exact
//! identity to the validated loopback process. Chromium spends the first of
//! two independently minted notes through the real provider. This test keeps
//! the second note for the native custody lifecycle, while independently
//! validating Chromium's canonical first spend against the same policy. It
//! then routes only the second spend through the real admission gate,
//! standard-Cashu committer, and production ProviderStore adapter/schema.
//! It proves replay rejection, consumed NUT-03
//! inputs are `SPENT`, newly committed provider custody notes are `UNSPENT`,
//! and a second independent BitcoinPIR
//! client can spend that custody through another real NUT-03 swap without
//! exposing the bearer in process arguments. The first custody lot must then
//! be `SPENT` while independently encrypted successor custody remains
//! `UNSPENT`.

#![cfg(feature = "insecure-dev-sqlite-store")]

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::VerifyingKey;
use pir_cashu_client::{
    check_cashu_custody_bundles_once_v1, CashuClientErrorV1, CashuCustodyExposureLimitsV1,
    CashuMintRouteV1, CashuMintTransportFailureKindV1, CashuMintTransportFailureV1,
    CashuMintTransportV1, CashuMintTrustV1, CashuSealedCustodyV1, CashuSwapProgressV1,
    CashuTokenV4V1, ChaCha20Poly1305CustodyCipherV1, ChaCha20Poly1305CustodyDecryptorV1,
    ChaCha20Poly1305RecoveryCipherV1, InsecureDevSqliteCashuSwapStoreV1,
    OsRandomCashuOutputMaterialGeneratorV1, StandardCashuAdmissionCommitterV1,
    StandardCashuClientV1, StoredCashuCustodyLotV1, MAX_CASHU_MINT_JSON_BYTES_V1,
};
use pir_payment_crypto::cashu_hash_to_curve_v1;
use pir_runtime_core::service_admission::{AdmissionEnforcementV1, ConnectionAdmissionGateV1};
use pir_service_protocol::{
    check_standard_cashu_spend_for_offer, derive_cashu_keyset_id_v2, AuthBeginV1, AuthRejectCode,
    AuthResultV1, AuthorizationProofV1, CashuDenominationKeyV1, CashuKeysetBindingV1,
    OperationStartV1, PolicyRollbackGuardV1, ServicePolicyEpochFloorsV1, ServicePolicyV1,
    StandardCashuProofV1, StandardCashuSpendV1, TrustedCatalogResolutionV1,
};
use pir_service_store::{ProviderStore, StoreOptions};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CdkKeysResponseV1 {
    keysets: Vec<CdkKeysetV1>,
}

#[derive(Deserialize)]
struct CdkKeysetV1 {
    id: String,
    unit: String,
    active: bool,
    keys: BTreeMap<String, String>,
    input_fee_ppk: u32,
    #[serde(default)]
    final_expiry: Option<u64>,
}

struct CurlLoopbackTransportV1 {
    actual_endpoint: String,
    signed_endpoint: String,
    swap_calls: AtomicUsize,
    check_state_calls: AtomicUsize,
}

impl CurlLoopbackTransportV1 {
    fn new(actual_endpoint: String, signed_endpoint: String) -> Self {
        validate_loopback_endpoint(&actual_endpoint);
        validate_signed_endpoint(&signed_endpoint);
        Self {
            actual_endpoint,
            signed_endpoint,
            swap_calls: AtomicUsize::new(0),
            check_state_calls: AtomicUsize::new(0),
        }
    }

    fn swap_calls(&self) -> usize {
        self.swap_calls.load(Ordering::SeqCst)
    }

    fn check_state_calls(&self) -> usize {
        self.check_state_calls.load(Ordering::SeqCst)
    }
}

impl CashuMintTransportV1 for CurlLoopbackTransportV1 {
    fn post_json(
        &self,
        trust: CashuMintTrustV1<'_>,
        route: CashuMintRouteV1,
        request_json: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, CashuMintTransportFailureV1> {
        if trust.mint_endpoint() != self.signed_endpoint {
            return Err(transport_failure(CashuMintTransportFailureKindV1::Network));
        }
        if route == CashuMintRouteV1::Swap {
            self.swap_calls.fetch_add(1, Ordering::SeqCst);
        }
        if route == CashuMintRouteV1::CheckState {
            self.check_state_calls.fetch_add(1, Ordering::SeqCst);
        }
        let url = format!("{}{}", self.actual_endpoint, route.path());
        let mut child = Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "15",
                "--connect-timeout",
                "3",
                "--request",
                "POST",
                "--header",
                "Content-Type: application/json",
                "--header",
                "Accept: application/json",
                "--data-binary",
                "@-",
                &url,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| transport_failure(CashuMintTransportFailureKindV1::Network))?;
        child
            .stdin
            .take()
            .ok_or_else(|| transport_failure(CashuMintTransportFailureKindV1::Network))?
            .write_all(request_json)
            .map_err(|_| transport_failure(CashuMintTransportFailureKindV1::Network))?;
        let output = child
            .wait_with_output()
            .map_err(|_| transport_failure(CashuMintTransportFailureKindV1::Network))?;
        if !output.status.success() {
            return Err(transport_failure(
                CashuMintTransportFailureKindV1::HttpError,
            ));
        }
        if output.stdout.len() > max_response_bytes {
            return Err(transport_failure(
                CashuMintTransportFailureKindV1::ResponseTooLarge,
            ));
        }
        Ok(output.stdout)
    }
}

#[test]
#[ignore = "requires scripts/payment-v1-cdk-regtest-e2e.sh and disposable CDK 0.17.3"]
fn real_cdk_nut03_swap_verifies_dleq_and_commits_custody() {
    let token = read_owner_only_string("BITCOINPIR_CDK_CASHUB_TOKEN_FILE");
    let keys_bytes = read_owner_only_bytes("BITCOINPIR_CDK_KEYS_FILE");
    let actual_endpoint =
        std::env::var("BITCOINPIR_CDK_MINT_ENDPOINT").expect("BITCOINPIR_CDK_MINT_ENDPOINT");
    let signed_endpoint = std::env::var("BITCOINPIR_CDK_SIGNED_MINT_ENDPOINT")
        .expect("BITCOINPIR_CDK_SIGNED_MINT_ENDPOINT");
    let expected_amount = std::env::var("BITCOINPIR_CDK_EXPECTED_AMOUNT")
        .expect("BITCOINPIR_CDK_EXPECTED_AMOUNT")
        .parse::<u64>()
        .expect("BITCOINPIR_CDK_EXPECTED_AMOUNT must be u64");
    assert!(expected_amount > 0);
    let now_unix = std::env::var("BITCOINPIR_CDK_NOW_UNIX")
        .expect("BITCOINPIR_CDK_NOW_UNIX")
        .parse::<u64>()
        .expect("BITCOINPIR_CDK_NOW_UNIX must be u64");
    assert!(now_unix > 0);

    let keysets: CdkKeysResponseV1 =
        serde_json::from_slice(&keys_bytes).expect("decode owner-only CDK /v1/keys fixture");
    let active = keysets
        .keysets
        .into_iter()
        .find(|keyset| keyset.active && keyset.unit == "sat")
        .expect("one active CDK sat keyset");
    let keyset = checked_keyset(active);
    let decoded = CashuTokenV4V1::decode_cashub(token.trim()).expect("decode real CDK cashuB");
    assert_eq!(decoded.mint_endpoint(), actual_endpoint);
    assert_eq!(decoded.unit(), "sat");
    let full_keyset_id = hex::decode(&keyset.keyset_id).expect("full CDK keyset ID hex");
    assert_eq!(full_keyset_id.len(), 33);
    let mut proofs = Vec::new();
    for group in decoded.groups() {
        assert_eq!(
            group.keyset_id(),
            &full_keyset_id[..group.keyset_id().len()]
        );
        for proof in group.proofs() {
            proofs.push(StandardCashuProofV1 {
                keyset_id: keyset.keyset_id.clone(),
                amount: proof.amount(),
                secret: proof.secret().to_owned(),
                c: *proof.c(),
            });
        }
    }
    let spend = StandardCashuSpendV1::new_canonical(proofs).expect("canonical real CDK spend");
    assert_eq!(spend.total_amount().unwrap(), expected_amount);
    let browser_spend_bytes = read_owner_only_bytes("BITCOINPIR_CDK_BROWSER_SPEND_FILE");
    let browser_spend = StandardCashuSpendV1::decode(&browser_spend_bytes)
        .expect("decode Chromium-generated canonical standard-Cashu spend");
    assert_eq!(
        browser_spend.encode().unwrap().as_slice(),
        browser_spend_bytes.as_slice(),
        "Chromium output must be canonical provider wire bytes"
    );
    assert_eq!(browser_spend.total_amount().unwrap(), expected_amount);
    assert_ne!(
        browser_spend, spend,
        "browser/provider and native-custody legs must use independent CDK notes"
    );

    let policy_bytes = read_owner_only_bytes("BITCOINPIR_CDK_POLICY_FILE");
    let policy = ServicePolicyV1::decode(&policy_bytes).expect("decode Chromium fixture policy");
    assert_eq!(
        policy.encode().unwrap().as_slice(),
        policy_bytes.as_slice(),
        "Chromium fixture policy must be canonical"
    );
    let expected_provider_id =
        read_fixed_hex_environment::<32>("BITCOINPIR_CDK_PROVIDER_ID_HEX", "provider ID");
    assert_eq!(policy.provider_id, expected_provider_id);
    let policy_public = read_fixed_hex_environment::<32>(
        "BITCOINPIR_CDK_POLICY_SIGNING_PUBKEY_HEX",
        "policy signing public key",
    );
    let policy_key = VerifyingKey::from_bytes(&policy_public)
        .expect("BITCOINPIR_CDK_POLICY_SIGNING_PUBKEY_HEX must be valid Ed25519");
    let verified_policy = policy
        .verify_current_for_acquisition(
            &expected_provider_id,
            now_unix,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &policy_key,
        )
        .expect("verify the exact signed policy accepted by Chromium");
    assert_eq!(policy.scopes.len(), 1);
    let verified_offer = verified_policy
        .offer(&policy.scopes[0].scope.scope_id(), 17)
        .expect("verified standard-Cashu offer");
    let manifest = verified_offer
        .offer()
        .cashu_mint_manifest
        .as_ref()
        .expect("verified offer carries a standard-Cashu manifest");
    assert_eq!(manifest.mint_endpoint, signed_endpoint);
    let expected_leaf_pin = read_fixed_hex_environment::<32>(
        "BITCOINPIR_CDK_SIGNED_MINT_LEAF_SPKI_SHA256_HEX",
        "signed mint leaf SPKI SHA-256 pin",
    );
    assert_eq!(manifest.leaf_spki_sha256_pins, vec![expected_leaf_pin]);
    assert_eq!(manifest.unit, "sat");
    assert_eq!(manifest.accepted_input_keysets, vec![keyset.clone()]);
    assert_eq!(manifest.active_output_keyset, keyset);
    check_standard_cashu_spend_for_offer(&browser_spend, &verified_offer, now_unix)
        .expect("browser canonical spend matches the independently verified provider offer");
    check_standard_cashu_spend_for_offer(&spend, &verified_offer, now_unix)
        .expect("independent native token matches the same verified provider offer");

    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make native custody fixture root owner-only");
    }
    let store_path = directory.path().join("provider-store.sqlite");
    let store = ProviderStore::create(
        &store_path,
        [0x61; 16],
        expected_provider_id,
        StoreOptions::default(),
    )
    .unwrap();
    let transport = CurlLoopbackTransportV1::new(actual_endpoint, signed_endpoint);
    let recovery = ChaCha20Poly1305RecoveryCipherV1::new(1, [(1, [0x41; 32])]).unwrap();
    let custody = ChaCha20Poly1305CustodyCipherV1::new(1, [(1, [0x42; 32])]).unwrap();
    let operation = OperationStartV1::DpfQuery { db_id: 7 };
    let request = AuthBeginV1 {
        policy_digest: policy.policy_digest().unwrap(),
        scope_id: policy.scopes[0].scope.scope_id(),
        offer_id: verified_offer.offer().offer_id,
        scheme: verified_offer.offer().authorization,
        key_id: verified_offer.offer().key_id.clone(),
        operation: operation.clone(),
        proof: AuthorizationProofV1::StandardCashu(spend.clone())
            .encode_for(
                verified_offer.offer().authorization,
                verified_offer.offer().free_mode,
            )
            .unwrap(),
    };
    let request = AuthBeginV1::decode_padded(&request.encode_padded().unwrap()).unwrap();
    let scope = &policy.scopes[0].scope;
    let resolution = TrustedCatalogResolutionV1::new(
        7,
        scope.backend,
        scope.workload,
        scope.protocol_version,
        scope.dataset.clone(),
        scope.operation_profile,
    );
    let catalog =
        |candidate: &OperationStartV1| (candidate == &operation).then(|| resolution.clone());
    {
        let committer = StandardCashuAdmissionCommitterV1::new(StandardCashuClientV1::new(
            &store,
            &transport,
            &recovery,
            &custody,
            CashuCustodyExposureLimitsV1::new(
                expected_amount.checked_mul(2).expect("bounded test amount"),
                128,
            )
            .unwrap(),
        ));
        let mut first_gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        first_gate.secure_channel_established();
        first_gate
            .policy_served(true, request.policy_digest)
            .unwrap();
        assert!(matches!(
            first_gate.authorize_and_commit(
                true,
                &request,
                verified_offer,
                &catalog,
                None,
                &committer,
                now_unix,
                1_000,
            ),
            AuthResultV1::Granted(_)
        ));
        assert_eq!(transport.swap_calls(), 1);

        let mut replay_gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        replay_gate.secure_channel_established();
        replay_gate
            .policy_served(true, request.policy_digest)
            .unwrap();
        assert!(matches!(
            replay_gate.authorize_and_commit(
                true,
                &request,
                verified_offer,
                &catalog,
                None,
                &committer,
                now_unix + 1,
                2_000,
            ),
            AuthResultV1::Rejected(rejected) if rejected.code == AuthRejectCode::InvalidOrSpent
        ));
        assert_eq!(
            transport.swap_calls(),
            1,
            "durable replay rejection must not submit another NUT-03 request"
        );
    }
    drop(store);

    let reopened = ProviderStore::open_existing(
        &store_path,
        expected_provider_id,
        StoreOptions::default(),
    )
    .unwrap();
    {
        let restarted_committer =
            StandardCashuAdmissionCommitterV1::new(StandardCashuClientV1::new(
                &reopened,
                &transport,
                &recovery,
                &custody,
                CashuCustodyExposureLimitsV1::new(
                    expected_amount.checked_mul(2).expect("bounded test amount"),
                    128,
                )
                .unwrap(),
            ));
        let mut restarted_gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        restarted_gate.secure_channel_established();
        restarted_gate
            .policy_served(true, request.policy_digest)
            .unwrap();
        assert!(matches!(
            restarted_gate.authorize_and_commit(
                true,
                &request,
                verified_offer,
                &catalog,
                None,
                &restarted_committer,
                now_unix + 2,
                3_000,
            ),
            AuthResultV1::Rejected(rejected) if rejected.code == AuthRejectCode::InvalidOrSpent
        ));
        assert_eq!(transport.swap_calls(), 1);
    }
    drop(reopened);

    let connection = rusqlite::Connection::open(&store_path).unwrap();
    assert_real_cdk_inputs_are_spent_once(
        &transport,
        CashuMintTrustV1::from_manifest(manifest).unwrap(),
        &spend,
    );
    assert_eq!(transport.check_state_calls(), 1);

    let (granted, lots, notes) = (
        row_count(&connection, "cashu_swap_intents", "state = 3"),
        row_count(&connection, "cashu_custody_lots", "1 = 1"),
        row_count(&connection, "cashu_custody_notes", "1 = 1"),
    );
    assert_eq!(granted, 1);
    assert_eq!(lots, 1);
    assert!(notes > 0);

    let stored_lot = load_only_custody_lot(&connection);
    let custody_decryptor = ChaCha20Poly1305CustodyDecryptorV1::new([(1, [0x42; 32])]).unwrap();
    let custody_bundle = custody_decryptor
        .open_bundle(
            &stored_lot.aad().expect("validated persisted custody AAD"),
            &stored_lot.sealed_notes,
        )
        .expect("authenticate and decrypt the persisted provider custody lot");
    let custody_state =
        check_cashu_custody_bundles_once_v1(&transport, std::slice::from_ref(&custody_bundle))
            .expect("strict real-CDK NUT-07 check for the exact provider custody lot");
    assert_eq!(transport.check_state_calls(), 2);
    assert_eq!(custody_state.lots().len(), 1);
    assert_eq!(custody_state.settlement_value(), expected_amount);
    assert_eq!(custody_state.note_count(), u32::try_from(notes).unwrap());
    assert_eq!(custody_state.unspent_count(), custody_state.note_count());
    assert_eq!(custody_state.pending_count(), 0);
    assert_eq!(custody_state.spent_count(), 0);
    assert!(!custody_state.all_spent());
    let checked_lot = &custody_state.lots()[0];
    assert_eq!(checked_lot.note_set_digest(), &stored_lot.note_set_digest);
    assert_eq!(checked_lot.settlement_value(), expected_amount);
    assert_eq!(checked_lot.unspent_count(), checked_lot.note_count());
    assert_eq!(checked_lot.pending_count(), 0);
    assert_eq!(checked_lot.spent_count(), 0);
    assert!(!checked_lot.all_spent());

    let custody_spend = StandardCashuSpendV1::new_canonical(
        custody_bundle
            .notes()
            .iter()
            .map(|note| StandardCashuProofV1 {
                keyset_id: custody_bundle.active_keyset_id().to_owned(),
                amount: note.amount(),
                secret: note.secret().to_owned(),
                c: *note.c(),
            })
            .collect(),
    )
    .expect("canonical spend reconstructed from authenticated provider custody");
    assert_eq!(custody_spend.total_amount().unwrap(), expected_amount);
    let checked_custody =
        check_standard_cashu_spend_for_offer(&custody_spend, &verified_offer, now_unix + 3)
            .expect("provider custody matches the same signed mint offer");
    let successor_output_materials = OsRandomCashuOutputMaterialGeneratorV1
        .generate(manifest, checked_custody.policy_price)
        .expect("generate independent successor-custody outputs");

    let successor_store_path = directory.path().join("cashu-successor-client.sqlite");
    let successor_store = InsecureDevSqliteCashuSwapStoreV1::open(&successor_store_path).unwrap();
    let successor_recovery = ChaCha20Poly1305RecoveryCipherV1::new(1, [(1, [0x51; 32])]).unwrap();
    let successor_custody = ChaCha20Poly1305CustodyCipherV1::new(1, [(1, [0x52; 32])]).unwrap();
    let successor_grant = {
        let successor_client = StandardCashuClientV1::new(
            &successor_store,
            &transport,
            &successor_recovery,
            &successor_custody,
            CashuCustodyExposureLimitsV1::new(
                expected_amount.checked_mul(2).expect("bounded test amount"),
                128,
            )
            .unwrap(),
        );
        match successor_client
            .start_swap(
                &custody_spend,
                &checked_custody,
                &verified_offer,
                manifest,
                successor_output_materials,
                now_unix + 3,
            )
            .expect("real CDK spend of provider custody into independent custody")
        {
            CashuSwapProgressV1::Grant(grant) => grant,
            other => panic!("expected successor custody grant, got {other:?}"),
        }
    };
    assert_eq!(successor_grant.settlement_value(), expected_amount);
    assert!(successor_grant.received_note_count() > 0);
    assert_eq!(transport.swap_calls(), 2);
    drop(successor_store);

    let spent_custody_state =
        check_cashu_custody_bundles_once_v1(&transport, std::slice::from_ref(&custody_bundle))
            .expect("strict real-CDK NUT-07 check after spending provider custody");
    assert_eq!(transport.check_state_calls(), 3);
    assert_eq!(spent_custody_state.unspent_count(), 0);
    assert_eq!(spent_custody_state.pending_count(), 0);
    assert_eq!(
        spent_custody_state.spent_count(),
        spent_custody_state.note_count()
    );
    assert!(spent_custody_state.all_spent());

    let successor_connection = rusqlite::Connection::open(successor_store_path).unwrap();
    let successor_stored_lot = load_only_custody_lot(&successor_connection);
    let successor_decryptor = ChaCha20Poly1305CustodyDecryptorV1::new([(1, [0x52; 32])]).unwrap();
    let successor_bundle = successor_decryptor
        .open_bundle(
            &successor_stored_lot
                .aad()
                .expect("validated successor custody AAD"),
            &successor_stored_lot.sealed_notes,
        )
        .expect("authenticate and decrypt independent successor custody");
    let successor_state =
        check_cashu_custody_bundles_once_v1(&transport, std::slice::from_ref(&successor_bundle))
            .expect("strict real-CDK NUT-07 check for successor custody");
    assert_eq!(transport.check_state_calls(), 4);
    assert_eq!(successor_state.settlement_value(), expected_amount);
    assert_eq!(
        successor_state.note_count(),
        u32::from(successor_grant.received_note_count())
    );
    assert_eq!(
        successor_state.unspent_count(),
        successor_state.note_count()
    );
    assert_eq!(successor_state.pending_count(), 0);
    assert_eq!(successor_state.spent_count(), 0);
    assert!(!successor_state.all_spent());
}

#[derive(Serialize)]
struct RealCdkNut07RequestV1<'a> {
    #[serde(rename = "Ys")]
    ys: &'a [String],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealCdkNut07ResponseV1 {
    states: Vec<RealCdkNut07StateEntryV1>,
}

#[derive(Clone, Copy, Eq, PartialEq, Deserialize)]
enum RealCdkNut07StateV1 {
    #[serde(rename = "UNSPENT")]
    Unspent,
    #[serde(rename = "PENDING")]
    Pending,
    #[serde(rename = "SPENT")]
    Spent,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealCdkNut07StateEntryV1 {
    #[serde(rename = "Y")]
    y: String,
    state: RealCdkNut07StateV1,
    #[serde(deserialize_with = "deserialize_required_nullable_string")]
    witness: Option<String>,
}

impl Drop for RealCdkNut07StateEntryV1 {
    fn drop(&mut self) {
        self.y.zeroize();
        if let Some(witness) = &mut self.witness {
            witness.zeroize();
        }
    }
}

fn deserialize_required_nullable_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

fn assert_real_cdk_inputs_are_spent_once(
    transport: &dyn CashuMintTransportV1,
    trust: CashuMintTrustV1<'_>,
    spend: &StandardCashuSpendV1,
) {
    let ys = Zeroizing::new(
        spend
            .proofs
            .iter()
            .map(|proof| {
                hex::encode(
                    cashu_hash_to_curve_v1(proof.secret.as_bytes())
                        .expect("hash real CDK input secret to its NUT-07 Y"),
                )
            })
            .collect::<Vec<_>>(),
    );
    let request = Zeroizing::new(
        serde_json::to_vec(&RealCdkNut07RequestV1 { ys: ys.as_slice() })
            .expect("encode bounded real-CDK NUT-07 request"),
    );
    let response_bytes = Zeroizing::new(
        transport
            .post_json(
                trust,
                CashuMintRouteV1::CheckState,
                &request,
                MAX_CASHU_MINT_JSON_BYTES_V1,
            )
            .expect("real CDK NUT-07 check for the consumed swap inputs"),
    );
    let response: RealCdkNut07ResponseV1 = serde_json::from_slice(&response_bytes)
        .expect("decode strict real-CDK NUT-07 response for the consumed inputs");
    assert_eq!(response.states.len(), ys.len());
    for (state, expected_y) in response.states.iter().zip(ys.iter()) {
        assert!(
            state.y.as_bytes() == expected_y.as_bytes(),
            "CDK NUT-07 reordered or substituted an input Y"
        );
        assert!(
            state.state == RealCdkNut07StateV1::Spent,
            "every original NUT-03 input must be SPENT"
        );
        assert!(
            state
                .witness
                .as_ref()
                .map_or(true, |witness| witness.len() <= 16 * 1024),
            "CDK NUT-07 witness exceeds the client bound"
        );
    }
}

fn load_only_custody_lot(connection: &rusqlite::Connection) -> StoredCashuCustodyLotV1 {
    connection
        .query_row(
            "SELECT lot_id, mint_id, manifest_digest, active_keyset_digest,
                    note_set_digest, unit, settlement_value, note_count,
                    sealed_key_epoch, sealed_nonce, sealed_ciphertext
             FROM cashu_custody_lots",
            [],
            |row| {
                Ok(StoredCashuCustodyLotV1 {
                    lot_id: fixed_bytes(row.get(0)?, "lot_id"),
                    mint_id: fixed_bytes(row.get(1)?, "mint_id"),
                    manifest_digest: fixed_bytes(row.get(2)?, "manifest_digest"),
                    active_keyset_digest: fixed_bytes(row.get(3)?, "active_keyset_digest"),
                    note_set_digest: fixed_bytes(row.get(4)?, "note_set_digest"),
                    unit: row.get(5)?,
                    settlement_value: u64::try_from(row.get::<_, i64>(6)?)
                        .expect("non-negative custody settlement_value"),
                    note_count: u32::try_from(row.get::<_, i64>(7)?)
                        .expect("bounded custody note_count"),
                    sealed_notes: CashuSealedCustodyV1 {
                        key_epoch: u64::try_from(row.get::<_, i64>(8)?)
                            .expect("positive custody key epoch"),
                        nonce: row.get(9)?,
                        ciphertext: row.get(10)?,
                    },
                })
            },
        )
        .expect("load the only encrypted provider custody lot")
}

fn fixed_bytes<const N: usize>(bytes: Vec<u8>, field: &str) -> [u8; N] {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{field} must contain exactly {N} bytes"))
}

fn checked_keyset(active: CdkKeysetV1) -> CashuKeysetBindingV1 {
    let mut keys = active
        .keys
        .into_iter()
        .map(|(amount, public_key)| CashuDenominationKeyV1 {
            amount: amount.parse().expect("CDK denomination amount"),
            public_key: hex::decode(public_key)
                .expect("CDK denomination public key hex")
                .try_into()
                .expect("CDK denomination public key length"),
        })
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| key.amount);
    assert_eq!(
        derive_cashu_keyset_id_v2(
            &keys,
            &active.unit,
            active.input_fee_ppk,
            active.final_expiry,
        )
        .expect("derive official NUT-02 V2 keyset ID"),
        active.id,
        "CDK /v1/keys ID must match the official full V2 derivation"
    );
    CashuKeysetBindingV1 {
        keyset_id: active.id,
        unit: active.unit,
        input_fee_ppk: active.input_fee_ppk,
        final_expiry: active.final_expiry,
        keys,
    }
}

fn read_fixed_hex_environment<const N: usize>(variable: &str, field: &str) -> [u8; N] {
    let value = std::env::var(variable).unwrap_or_else(|_| panic!("{variable}"));
    assert_eq!(value.len(), N * 2, "{field} must be exact-length hex");
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{field} must be canonical lowercase hex"
    );
    let decoded = hex::decode(value).unwrap_or_else(|_| panic!("{field} must be valid hex"));
    let fixed: [u8; N] = decoded
        .try_into()
        .unwrap_or_else(|_| panic!("{field} must contain exactly {N} bytes"));
    assert!(
        fixed.iter().any(|byte| *byte != 0),
        "{field} must be non-zero"
    );
    fixed
}

fn read_owner_only_string(variable: &str) -> Zeroizing<String> {
    let path = std::env::var(variable).unwrap_or_else(|_| panic!("{variable}"));
    assert_owner_only(&path);
    Zeroizing::new(std::fs::read_to_string(path).expect("read owner-only CDK token fixture"))
}

fn read_owner_only_bytes(variable: &str) -> Zeroizing<Vec<u8>> {
    let path = std::env::var(variable).unwrap_or_else(|_| panic!("{variable}"));
    assert_owner_only(&path);
    Zeroizing::new(std::fs::read(path).expect("read owner-only CDK keys fixture"))
}

fn assert_owner_only(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(path)
            .expect("CDK fixture metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "CDK fixture must be owner-only");
    }
}

fn validate_loopback_endpoint(endpoint: &str) {
    let port = endpoint
        .strip_prefix("http://127.0.0.1:")
        .and_then(|value| value.parse::<u16>().ok())
        .expect("test transport accepts only http://127.0.0.1:<port>");
    assert!(
        port >= 1_024,
        "test transport requires an unprivileged port"
    );
}

fn validate_signed_endpoint(endpoint: &str) {
    let port = endpoint
        .strip_prefix("https://localhost:")
        .and_then(|value| value.parse::<u16>().ok())
        .expect("test transport accepts only https://localhost:<port> signed identities");
    assert!(
        port >= 1_024,
        "test transport requires an unprivileged signed endpoint"
    );
}

fn transport_failure(kind: CashuMintTransportFailureKindV1) -> CashuMintTransportFailureV1 {
    CashuMintTransportFailureV1::ambiguous(kind, None)
}

fn row_count(connection: &rusqlite::Connection, table: &str, predicate: &str) -> u64 {
    let sql = format!("SELECT COUNT(*) FROM {table} WHERE {predicate}");
    u64::try_from(
        connection
            .query_row(&sql, [], |row| row.get::<_, i64>(0))
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn test_only_loopback_transport_rejects_non_loopback_actual_endpoints() {
    for endpoint in [
        "http://localhost:5000",
        "http://127.0.0.1:80",
        "https://127.0.0.1:5000",
        "http://127.0.0.1:5000/path",
    ] {
        assert!(std::panic::catch_unwind(|| validate_loopback_endpoint(endpoint)).is_err());
    }
    for endpoint in [
        "http://localhost:5000",
        "https://127.0.0.1:5000",
        "https://localhost:80",
        "https://localhost:5000/path",
    ] {
        assert!(std::panic::catch_unwind(|| validate_signed_endpoint(endpoint)).is_err());
    }
}

#[test]
fn exposure_errors_are_classified_before_any_transport_side_effect() {
    assert_eq!(
        CashuCustodyExposureLimitsV1::new(0, 1),
        Err(CashuClientErrorV1::InvalidExposureLimits)
    );
}
