//! Opt-in, disposable CDK 0.17.3 provider-side NUT-03/NUT-07 interoperability.
//!
//! This test is intentionally ignored. The repository runner starts a
//! loopback-only fake-wallet mint and passes owner-only fixture files. The
//! signed manifest still contains a synthetic HTTPS identity; this test-only
//! transport maps only that exact identity to the validated loopback process.
//! It proves consumed NUT-03 inputs are `SPENT` and the newly committed
//! provider custody notes are `UNSPENT` at the real mint.

#![cfg(feature = "insecure-dev-sqlite-store")]

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::SigningKey;
use pir_cashu_client::{
    check_cashu_custody_bundles_once_v1, CashuClientErrorV1, CashuCustodyExposureLimitsV1,
    CashuMintRouteV1, CashuMintTransportFailureKindV1, CashuMintTransportFailureV1,
    CashuMintTransportV1, CashuSealedCustodyV1, CashuSwapProgressV1, CashuTokenV4V1,
    ChaCha20Poly1305CustodyCipherV1, ChaCha20Poly1305CustodyDecryptorV1,
    ChaCha20Poly1305RecoveryCipherV1, InsecureDevSqliteCashuSwapStoreV1,
    OsRandomCashuOutputMaterialGeneratorV1, StandardCashuClientV1, StoredCashuCustodyLotV1,
    MAX_CASHU_MINT_JSON_BYTES_V1,
};
use pir_payment_crypto::cashu_hash_to_curve_v1;
use pir_service_protocol::{
    check_standard_cashu_spend_for_offer, derive_cashu_keyset_id_v2, AcquisitionMethod,
    AuthPaddingClassV1, AuthScheme, BackendId, CashuDenominationKeyV1, CashuKeysetBindingV1,
    CashuRequiredNutsV1, DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, FreeModeV1,
    PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1, ServicePolicyEpochFloorsV1,
    ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1, StandardCashuMintManifestV1,
    StandardCashuProofV1, StandardCashuSpendV1, VerificationMode, WorkloadId,
};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, Zeroizing};

const SYNTHETIC_MINT_ENDPOINT: &str = "https://cdk-loopback.invalid";
const TEST_NOW_UNIX: u64 = 100;

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
    swap_calls: AtomicUsize,
    check_state_calls: AtomicUsize,
}

impl CurlLoopbackTransportV1 {
    fn new(actual_endpoint: String) -> Self {
        validate_loopback_endpoint(&actual_endpoint);
        Self {
            actual_endpoint,
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
        mint_endpoint: &str,
        route: CashuMintRouteV1,
        request_json: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, CashuMintTransportFailureV1> {
        if mint_endpoint != SYNTHETIC_MINT_ENDPOINT {
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
    let expected_amount = std::env::var("BITCOINPIR_CDK_EXPECTED_AMOUNT")
        .expect("BITCOINPIR_CDK_EXPECTED_AMOUNT")
        .parse::<u64>()
        .expect("BITCOINPIR_CDK_EXPECTED_AMOUNT must be u64");
    assert!(expected_amount > 0);

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

    let manifest = StandardCashuMintManifestV1 {
        manifest_epoch: 1,
        mint_endpoint: SYNTHETIC_MINT_ENDPOINT.to_owned(),
        unit: "sat".to_owned(),
        required_nuts: CashuRequiredNutsV1::required_v1(),
        accepted_input_keysets: vec![keyset.clone()],
        active_output_keyset: keyset,
    };
    manifest.encode().expect("strict synthetic HTTPS manifest");
    let (policy, policy_key) = cashu_policy(manifest.clone(), expected_amount);
    let verified_policy = policy
        .verify_current_for_acquisition(
            &policy.provider_id,
            TEST_NOW_UNIX,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &policy_key.verifying_key(),
        )
        .expect("verify local signed policy");
    let verified_offer = verified_policy
        .offer(&policy.scopes[0].scope.scope_id(), 17)
        .expect("verified standard-Cashu offer");
    let checked = check_standard_cashu_spend_for_offer(&spend, &verified_offer, TEST_NOW_UNIX)
        .expect("real CDK token matches the signed offer");
    let output_materials = OsRandomCashuOutputMaterialGeneratorV1
        .generate(&manifest, checked.policy_price)
        .expect("generate exact provider-wallet outputs");

    let directory = tempfile::tempdir().unwrap();
    let store_path = directory.path().join("cashu-client.sqlite");
    let store = InsecureDevSqliteCashuSwapStoreV1::open(&store_path).unwrap();
    let transport = CurlLoopbackTransportV1::new(actual_endpoint);
    let recovery = ChaCha20Poly1305RecoveryCipherV1::new(1, [(1, [0x41; 32])]).unwrap();
    let custody = ChaCha20Poly1305CustodyCipherV1::new(1, [(1, [0x42; 32])]).unwrap();
    let grant = {
        let client = StandardCashuClientV1::new(
            &store,
            &transport,
            &recovery,
            &custody,
            CashuCustodyExposureLimitsV1::new(
                expected_amount.checked_mul(2).expect("bounded test amount"),
                128,
            )
            .unwrap(),
        );
        let grant = match client
            .start_swap(
                &spend,
                &checked,
                &verified_offer,
                &manifest,
                output_materials,
                TEST_NOW_UNIX,
            )
            .expect("real CDK NUT-03 swap, NUT-12 verification, and custody commit")
        {
            CashuSwapProgressV1::Grant(grant) => grant,
            other => panic!("expected one committed grant, got {other:?}"),
        };
        assert_eq!(grant.settlement_value(), expected_amount);
        assert!(grant.received_note_count() > 0);
        assert_eq!(transport.swap_calls(), 1);
        assert!(matches!(
            client
                .resume_swap(
                    &spend,
                    &checked,
                    &verified_offer,
                    &manifest,
                    TEST_NOW_UNIX + 1,
                )
                .unwrap(),
            CashuSwapProgressV1::AlreadyGranted { .. }
        ));
        assert_eq!(transport.swap_calls(), 1);
        grant
    };
    drop(store);

    let connection = rusqlite::Connection::open(store_path).unwrap();
    assert_real_cdk_inputs_are_spent_once(&transport, &spend);
    assert_eq!(transport.check_state_calls(), 1);

    let (granted, lots, notes) = (
        row_count(&connection, "cashu_swap_intents", "state = 3"),
        row_count(&connection, "cashu_custody_lots", "1 = 1"),
        row_count(&connection, "cashu_custody_notes", "1 = 1"),
    );
    assert_eq!(granted, 1);
    assert_eq!(lots, 1);
    assert_eq!(notes, u64::from(grant.received_note_count()));

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
    assert_eq!(
        custody_state.note_count(),
        u32::from(grant.received_note_count())
    );
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
                SYNTHETIC_MINT_ENDPOINT,
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

fn cashu_policy(
    manifest: StandardCashuMintManifestV1,
    price: u64,
) -> (ServicePolicyV1, SigningKey) {
    let provider_id = [0x51; 32];
    let scope = ServiceScopeV1 {
        provider_id,
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        protocol_version: 1,
        dataset: DatasetBindingV1::Class { class_id: 2 },
        operation_profile: 1,
        entitlement_profile: 8,
    };
    let offer = ServiceOfferV1 {
        offer_id: 17,
        acquisition: AcquisitionMethod::CashuEcashV1,
        free_mode: FreeModeV1::NotFree,
        free_quota: 0,
        free_window_seconds: 0,
        free_pow_difficulty_bits: 0,
        priority_class: 1,
        authorization: AuthScheme::CashuEcashV1,
        verification: VerificationMode::StandardCashuMintOnline,
        deployment_status: DeploymentStatus::Stable,
        price: PriceV1::Cashu {
            unit: "sat".to_owned(),
            amount: price,
        },
        issuer_id: manifest.mint_id(),
        key_id: manifest.manifest_digest().unwrap().to_vec(),
        credential_binding: None,
        cashu_mint_manifest: Some(manifest.clone()),
        endpoint: manifest.mint_endpoint.clone(),
        invoice_expiry_seconds: 0,
        claim_window_seconds: 0,
        minimum_credential_validity_seconds: 100,
        retired_policy_grace_seconds: 100,
        credential_count: 1,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::from_bits(
            PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
        )
        .unwrap(),
    };
    let policy_key = SigningKey::from_bytes(&[0x52; 32]);
    let policy = ServicePolicyV1::sign(
        provider_id,
        1,
        TEST_NOW_UNIX,
        10_000,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope,
            limits: EntitlementLimitsV1 {
                max_logical_inputs: 1,
                max_frames: 10,
                max_request_bytes: 1_000,
                max_response_bytes: 2_000,
                max_wall_time_ms: 1_000,
                max_concurrent_sockets: 1,
                max_hint_groups: 0,
                max_work_units: 100,
            },
            offers: vec![offer],
        }],
        &policy_key,
    )
    .unwrap();
    (policy, policy_key)
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
fn test_only_loopback_transport_rejects_non_loopback_or_manifest_identity_changes() {
    for endpoint in [
        "http://localhost:5000",
        "http://127.0.0.1:80",
        "https://127.0.0.1:5000",
        "http://127.0.0.1:5000/path",
    ] {
        assert!(std::panic::catch_unwind(|| validate_loopback_endpoint(endpoint)).is_err());
    }
    let transport = CurlLoopbackTransportV1::new("http://127.0.0.1:5000".to_owned());
    assert_eq!(
        transport.post_json(
            "https://different.invalid",
            CashuMintRouteV1::Swap,
            b"{}",
            1_024,
        ),
        Err(CashuMintTransportFailureV1::ambiguous(
            CashuMintTransportFailureKindV1::Network,
            None,
        ))
    );
    assert_eq!(transport.swap_calls(), 0);
}

#[test]
fn exposure_errors_are_classified_before_any_transport_side_effect() {
    assert_eq!(
        CashuCustodyExposureLimitsV1::new(0, 1),
        Err(CashuClientErrorV1::InvalidExposureLimits)
    );
}
