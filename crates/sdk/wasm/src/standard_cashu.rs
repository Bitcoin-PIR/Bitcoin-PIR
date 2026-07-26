//! Strict browser import for standard Cashu V3/V4 tokens.
//!
//! Wallet serialization is decoded only locally. The output is the protocol's
//! canonical [`StandardCashuSpendV1`] bytes, after closing the token against
//! the exact signed provider policy and embedded mint manifest. No mint I/O is
//! performed here.

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use pir_sdk_client::AcceptedServicePolicyV1;
use pir_service_protocol::{
    CashuKeysetBindingV1, StandardCashuMintManifestV1, StandardCashuProofV1, StandardCashuSpendV1,
    MAX_STANDARD_CASHU_PROOFS_V1,
};
use serde::{de::IgnoredAny, Deserialize, Deserializer};
use sha2::{Digest, Sha256};

const MAX_SERIALIZED_TOKEN_CHARS_V1: usize = 128 * 1024;
const MAX_DECODED_TOKEN_BYTES_V1: usize = 64 * 1024;
const MAX_TOKEN_MEMO_BYTES_V1: usize = 1_024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuTokenV3 {
    token: Vec<CashuTokenEntryV3>,
    unit: Option<String>,
    memo: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuTokenEntryV3 {
    mint: String,
    proofs: Vec<CashuProofV3>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuProofV3 {
    amount: u64,
    id: String,
    secret: String,
    #[serde(rename = "C")]
    c: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuTokenV4 {
    #[serde(rename = "m")]
    mint: String,
    #[serde(rename = "u")]
    unit: String,
    #[serde(rename = "d")]
    memo: Option<String>,
    #[serde(rename = "t")]
    token: Vec<CashuTokenEntryV4>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuTokenEntryV4 {
    #[serde(rename = "i", with = "serde_bytes")]
    keyset_id: Vec<u8>,
    #[serde(rename = "p")]
    proofs: Vec<CashuProofV4>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuProofV4 {
    #[serde(rename = "a")]
    amount: u64,
    #[serde(rename = "s")]
    secret: String,
    #[serde(rename = "c", with = "serde_bytes")]
    c: Vec<u8>,
    /// NUT-12 proof data is intentionally not forwarded. In particular the
    /// wallet-private blinding scalar `r` must never reach a PIR provider.
    #[serde(rename = "d", default)]
    dleq: RejectedCashuField,
    /// NUT-10/NUT-11 witness material is outside the V1 privacy profile.
    #[serde(rename = "w", default)]
    witness: RejectedCashuField,
}

#[derive(Default)]
struct RejectedCashuField(bool);

impl<'de> Deserialize<'de> for RejectedCashuField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        IgnoredAny::deserialize(deserializer)?;
        Ok(Self(true))
    }
}

pub(crate) fn import_standard_cashu_token_v1(
    accepted: &AcceptedServicePolicyV1,
    scope_id: &[u8; 32],
    offer_id: u32,
    serialized_token: &str,
    now_unix: u64,
) -> Result<Vec<u8>, String> {
    if now_unix == 0 {
        return Err("trusted wall clock is required for Cashu import".into());
    }
    let offer = accepted
        .policy()
        .scopes
        .iter()
        .find(|scope| &scope.scope.scope_id() == scope_id)
        .and_then(|scope| scope.offers.iter().find(|offer| offer.offer_id == offer_id))
        .ok_or_else(|| "selected Cashu scope/offer is not in the accepted policy".to_owned())?;
    let manifest = offer
        .cashu_mint_manifest
        .as_ref()
        .ok_or_else(|| "selected offer has no signed standard Cashu manifest".to_owned())?;

    let token = serialized_token
        .strip_prefix("cashu:")
        .unwrap_or(serialized_token);
    if token.len() > MAX_SERIALIZED_TOKEN_CHARS_V1 || token.trim() != token {
        return Err(
            "serialized Cashu token is oversized or contains surrounding whitespace".into(),
        );
    }
    let proofs = if let Some(encoded) = token.strip_prefix("cashuA") {
        parse_v3(encoded, manifest)?
    } else if let Some(encoded) = token.strip_prefix("cashuB") {
        parse_v4(encoded, manifest)?
    } else {
        return Err("only Cashu V3 (cashuA) and V4 (cashuB) tokens are accepted".into());
    };
    let spend = StandardCashuSpendV1::new_canonical(proofs)
        .map_err(|error| format!("Cashu proof list is invalid: {error}"))?;
    accepted
        .dangerous_unpaired_prepare_standard_cashu_spend_v1(scope_id, offer_id, &spend, now_unix)
        .map_err(|error| format!("Cashu token does not match the signed offer: {error}"))
}

fn parse_v3(
    encoded: &str,
    manifest: &StandardCashuMintManifestV1,
) -> Result<Vec<StandardCashuProofV1>, String> {
    let bytes = decode_token_base64(encoded)?;
    let token: CashuTokenV3 = serde_json::from_slice(&bytes)
        .map_err(|_| "Cashu V3 token is not strict known-field JSON".to_owned())?;
    if token.token.len() != 1 {
        return Err("Cashu V3 import requires exactly one mint entry".into());
    }
    validate_mint_unit_memo(
        &token.token[0].mint,
        token.unit.as_deref(),
        token.memo.as_deref(),
        manifest,
    )?;
    token.token[0]
        .proofs
        .iter()
        .map(|proof| {
            reject_nut10_secret(&proof.secret)?;
            Ok(StandardCashuProofV1 {
                keyset_id: resolve_text_keyset_id(&proof.id, manifest)?,
                amount: proof.amount,
                secret: proof.secret.clone(),
                c: decode_canonical_compressed_point_hex(&proof.c)?,
            })
        })
        .collect()
}

fn parse_v4(
    encoded: &str,
    manifest: &StandardCashuMintManifestV1,
) -> Result<Vec<StandardCashuProofV1>, String> {
    let bytes = decode_token_base64(encoded)?;
    let token: CashuTokenV4 = ciborium::from_reader(bytes.as_slice())
        .map_err(|_| "Cashu V4 token is not strict known-field CBOR".to_owned())?;
    validate_mint_unit_memo(
        &token.mint,
        Some(&token.unit),
        token.memo.as_deref(),
        manifest,
    )?;
    if token.token.is_empty() || token.token.len() > MAX_STANDARD_CASHU_PROOFS_V1 {
        return Err("Cashu V4 token has an invalid number of keyset groups".into());
    }
    let mut normalized = Vec::new();
    for group in token.token {
        let keyset_id = resolve_binary_keyset_id(&group.keyset_id, manifest)?;
        for proof in group.proofs {
            if proof.dleq.0 || proof.witness.0 {
                return Err(
                    "Cashu DLEQ or witness fields are disabled by the V1 privacy profile".into(),
                );
            }
            reject_nut10_secret(&proof.secret)?;
            let c: [u8; 33] = proof
                .c
                .try_into()
                .map_err(|_| "Cashu V4 C must be exactly one compressed point".to_owned())?;
            normalized.push(StandardCashuProofV1 {
                keyset_id: keyset_id.clone(),
                amount: proof.amount,
                secret: proof.secret,
                c,
            });
            if normalized.len() > MAX_STANDARD_CASHU_PROOFS_V1 {
                return Err("Cashu token contains too many proofs".into());
            }
        }
    }
    Ok(normalized)
}

fn validate_mint_unit_memo(
    mint: &str,
    unit: Option<&str>,
    memo: Option<&str>,
    manifest: &StandardCashuMintManifestV1,
) -> Result<(), String> {
    if mint != manifest.mint_endpoint {
        return Err("Cashu token mint does not match the signed manifest".into());
    }
    if unit.is_some_and(|value| value != manifest.unit) {
        return Err("Cashu token unit does not match the signed manifest".into());
    }
    if memo.is_some_and(|value| value.len() > MAX_TOKEN_MEMO_BYTES_V1) {
        return Err("Cashu token memo exceeds the local import bound".into());
    }
    Ok(())
}

fn decode_token_base64(encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.is_empty() || encoded.len() > MAX_SERIALIZED_TOKEN_CHARS_V1 {
        return Err("Cashu token payload is empty or oversized".into());
    }
    let decoded = if encoded.contains('=') {
        let decoded = URL_SAFE
            .decode(encoded)
            .map_err(|_| "Cashu token uses invalid padded base64url".to_owned())?;
        if URL_SAFE.encode(&decoded) != encoded {
            return Err("Cashu token uses a non-canonical padded base64url encoding".into());
        }
        decoded
    } else {
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "Cashu token uses invalid unpadded base64url".to_owned())?;
        if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
            return Err("Cashu token uses a non-canonical unpadded base64url encoding".into());
        }
        decoded
    };
    if decoded.is_empty() || decoded.len() > MAX_DECODED_TOKEN_BYTES_V1 {
        return Err("decoded Cashu token is empty or oversized".into());
    }
    Ok(decoded)
}

fn resolve_text_keyset_id(
    value: &str,
    manifest: &StandardCashuMintManifestV1,
) -> Result<String, String> {
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Cashu keyset ID must be canonical lowercase hex".into());
    }
    match value.len() {
        16 => resolve_short_keyset_id(value, manifest),
        66 => manifest
            .accepted_input_keysets
            .iter()
            .find(|keyset| keyset.keyset_id == value)
            .map(|keyset| keyset.keyset_id.clone())
            .ok_or_else(|| "Cashu keyset is not accepted by the signed manifest".to_owned()),
        _ => Err("Cashu keyset ID must use the 8-byte short or 33-byte full form".into()),
    }
}

fn resolve_binary_keyset_id(
    value: &[u8],
    manifest: &StandardCashuMintManifestV1,
) -> Result<String, String> {
    match value.len() {
        8 => resolve_short_keyset_id(&hex::encode(value), manifest),
        33 => resolve_text_keyset_id(&hex::encode(value), manifest),
        _ => Err("Cashu V4 keyset ID must be exactly 8 or 33 bytes".into()),
    }
}

fn resolve_short_keyset_id(
    short: &str,
    manifest: &StandardCashuMintManifestV1,
) -> Result<String, String> {
    let mut matches: Vec<&CashuKeysetBindingV1> = manifest
        .accepted_input_keysets
        .iter()
        .filter(|keyset| {
            keyset.keyset_id.starts_with(short) || legacy_keyset_id_v1(keyset) == short
        })
        .collect();
    matches.dedup_by_key(|keyset| keyset.keyset_id.as_str());
    match matches.as_slice() {
        [keyset] => Ok(keyset.keyset_id.clone()),
        [] => Err("short Cashu keyset ID is not accepted by the signed manifest".into()),
        _ => Err("short Cashu keyset ID is ambiguous in the signed manifest".into()),
    }
}

fn legacy_keyset_id_v1(keyset: &CashuKeysetBindingV1) -> String {
    let mut hasher = Sha256::new();
    for key in &keyset.keys {
        hasher.update(key.public_key);
    }
    let digest = hasher.finalize();
    format!("00{}", hex::encode(&digest[..7]))
}

fn decode_canonical_compressed_point_hex(value: &str) -> Result<[u8; 33], String> {
    if value.len() != 66
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Cashu V3 C must be canonical lowercase compressed-point hex".into());
    }
    let bytes = hex::decode(value).map_err(|_| "Cashu V3 C is not valid hex".to_owned())?;
    bytes
        .try_into()
        .map_err(|_| "Cashu V3 C must be exactly 33 bytes".to_owned())
}

fn reject_nut10_secret(secret: &str) -> Result<(), String> {
    if let Ok(serde_json::Value::Array(value)) = serde_json::from_str(secret) {
        if value.len() == 2 && value[0].is_string() && value[1].is_object() {
            return Err(
                "Cashu NUT-10 structured secrets are disabled by the V1 privacy profile".into(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pir_sdk_client::{accept_service_policy_response_v1, ServicePolicyCheckpointV1};
    use pir_service_protocol::{
        derive_cashu_keyset_id_v2, AcquisitionMethod, AuthPaddingClassV1, AuthScheme, BackendId,
        CashuDenominationKeyV1, CashuRequiredNutsV1, DatasetBindingV1, DeploymentStatus,
        EntitlementLimitsV1, FreeModeV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1,
        ServicePolicyResponseV1, ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1,
        VerificationMode, WorkloadId, RESP_SERVICE_POLICY_V1,
    };

    const GENERATOR_COMPRESSED: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn accepted_cashu_policy(price: u64) -> (AcceptedServicePolicyV1, [u8; 32]) {
        let keys = vec![CashuDenominationKeyV1 {
            amount: 1,
            public_key: GENERATOR_COMPRESSED,
        }];
        let keyset = CashuKeysetBindingV1 {
            keyset_id: derive_cashu_keyset_id_v2(&keys, "sat", 0, None).unwrap(),
            unit: "sat".into(),
            input_fee_ppk: 0,
            final_expiry: None,
            keys,
        };
        assert_eq!(
            keyset.keyset_id,
            "0106b3f35573b8d261be5295471cb08a8013c8448894e48905a00c13d968f54c31",
        );
        let manifest = StandardCashuMintManifestV1 {
            manifest_epoch: 1,
            mint_endpoint: "https://mint.example".into(),
            unit: "sat".into(),
            required_nuts: CashuRequiredNutsV1::required_v1(),
            accepted_input_keysets: vec![keyset.clone()],
            active_output_keyset: keyset,
        };
        let provider_id = [0x51; 32];
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 1,
        };
        let scope_id = scope.scope_id();
        let offer = ServiceOfferV1 {
            offer_id: 7,
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
                unit: "sat".into(),
                amount: price,
            },
            issuer_id: manifest.mint_id(),
            key_id: manifest.manifest_digest().unwrap().to_vec(),
            credential_binding: None,
            cashu_mint_manifest: Some(manifest),
            endpoint: "https://mint.example".into(),
            invoice_expiry_seconds: 0,
            claim_window_seconds: 0,
            minimum_credential_validity_seconds: 60,
            retired_policy_grace_seconds: 0,
            credential_count: 1,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .unwrap(),
        };
        let signing = SigningKey::from_bytes(&[0x52; 32]);
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            100,
            500,
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
            &signing,
        )
        .unwrap();
        let mut response = vec![RESP_SERVICE_POLICY_V1];
        response.extend_from_slice(&ServicePolicyResponseV1 { policy }.encode().unwrap());
        let accepted = accept_service_policy_response_v1(
            &response,
            provider_id,
            &signing.verifying_key(),
            120,
            &ServicePolicyCheckpointV1::initial(),
            [9; 32],
        )
        .unwrap();
        (accepted, scope_id)
    }

    fn cashu_a(json: &str) -> String {
        format!("cashuA{}", URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }

    fn fixture_json() -> &'static str {
        include_str!("../tests/fixtures/standard_cashu_v3.json").trim_end()
    }

    fn cashu_b(
        proofs: Vec<ciborium::value::Value>,
        extra_root: Option<(&str, ciborium::value::Value)>,
    ) -> String {
        use ciborium::value::Value;
        let full_id =
            hex::decode("0106b3f35573b8d261be5295471cb08a8013c8448894e48905a00c13d968f54c31")
                .unwrap();
        let mut root = vec![
            (
                Value::Text("m".into()),
                Value::Text("https://mint.example".into()),
            ),
            (Value::Text("u".into()), Value::Text("sat".into())),
            (
                Value::Text("t".into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("i".into()), Value::Bytes(full_id[..8].to_vec())),
                    (Value::Text("p".into()), Value::Array(proofs)),
                ])]),
            ),
        ];
        if let Some((key, value)) = extra_root {
            root.push((Value::Text(key.into()), value));
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(root), &mut bytes).unwrap();
        format!("cashuB{}", URL_SAFE_NO_PAD.encode(bytes))
    }

    fn v4_proof(extra: Option<(&str, ciborium::value::Value)>) -> ciborium::value::Value {
        use ciborium::value::Value;
        let mut fields = vec![
            (Value::Text("a".into()), Value::Integer(1u64.into())),
            (
                Value::Text("s".into()),
                Value::Text("fixture-secret".into()),
            ),
            (
                Value::Text("c".into()),
                Value::Bytes(GENERATOR_COMPRESSED.to_vec()),
            ),
        ];
        if let Some((key, value)) = extra {
            fields.push((Value::Text(key.into()), value));
        }
        Value::Map(fields)
    }

    #[test]
    fn locked_v3_fixture_imports_to_canonical_spend() {
        let (accepted, scope_id) = accepted_cashu_policy(1);
        let bytes =
            import_standard_cashu_token_v1(&accepted, &scope_id, 7, &cashu_a(fixture_json()), 120)
                .unwrap();
        let spend = StandardCashuSpendV1::decode(&bytes).unwrap();
        assert_eq!(spend.proofs.len(), 1);
        assert_eq!(spend.proofs[0].secret, "fixture-secret");
        assert_eq!(spend.proofs[0].keyset_id.len(), 66);
        assert_eq!(spend.encode().unwrap(), bytes);
    }

    #[test]
    fn v3_rejects_wrong_mint_unit_keyset_and_amount() {
        let (accepted, scope_id) = accepted_cashu_policy(1);
        for bad in [
            fixture_json().replace("https://mint.example", "https://other.example"),
            fixture_json().replace("\"unit\":\"sat\"", "\"unit\":\"usd\""),
            fixture_json().replace(
                "0106b3f35573b8d261be5295471cb08a8013c8448894e48905a00c13d968f54c31",
                "01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            fixture_json().replace("\"amount\":1", "\"amount\":2"),
        ] {
            assert!(
                import_standard_cashu_token_v1(&accepted, &scope_id, 7, &cashu_a(&bad), 120,)
                    .is_err()
            );
        }
    }

    #[test]
    fn v3_rejects_duplicate_unknown_witness_dleq_and_nut10() {
        let (accepted, scope_id) = accepted_cashu_policy(1);
        let proof = "{\"amount\":1,\"id\":\"0106b3f35573b8d261be5295471cb08a8013c8448894e48905a00c13d968f54c31\",\"secret\":\"fixture-secret\",\"C\":\"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"}";
        let duplicate = format!(
            "{{\"token\":[{{\"mint\":\"https://mint.example\",\"proofs\":[{proof},{proof}]}}],\"unit\":\"sat\"}}",
        );
        let unknown = fixture_json().replace("\"C\":", "\"unknown\":1,\"C\":");
        let witness = fixture_json().replace("\"C\":", "\"witness\":\"x\",\"C\":");
        let dleq = fixture_json().replace(
            "\"C\":",
            "\"dleq\":{\"e\":\"00\",\"s\":\"00\",\"r\":\"secret\"},\"C\":",
        );
        let nut10 = fixture_json().replace(
            "\"fixture-secret\"",
            "\"[\\\"P2PK\\\",{\\\"data\\\":\\\"02aa\\\"}]\"",
        );
        for bad in [duplicate, unknown, witness, dleq, nut10] {
            assert!(
                import_standard_cashu_token_v1(&accepted, &scope_id, 7, &cashu_a(&bad), 120,)
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_noncanonical_base64_and_uppercase_hex() {
        let (accepted, scope_id) = accepted_cashu_policy(1);
        let noncanonical = format!("{}=", cashu_a(fixture_json()));
        let uppercase = fixture_json().replace(
            "0106b3f35573b8d261be5295471cb08a8013c8448894e48905a00c13d968f54c31",
            "0106B3F35573B8D261BE5295471CB08A8013C8448894E48905A00C13D968F54C31",
        );
        assert!(
            import_standard_cashu_token_v1(&accepted, &scope_id, 7, &noncanonical, 120,).is_err()
        );
        assert!(
            import_standard_cashu_token_v1(&accepted, &scope_id, 7, &cashu_a(&uppercase), 120,)
                .is_err()
        );
    }

    #[test]
    fn v4_imports_short_v2_id_and_rejects_empty_or_disabled_fields() {
        use ciborium::value::Value;
        let (accepted, scope_id) = accepted_cashu_policy(1);
        let valid = cashu_b(vec![v4_proof(None)], None);
        let bytes = import_standard_cashu_token_v1(&accepted, &scope_id, 7, &valid, 120).unwrap();
        assert_eq!(
            StandardCashuSpendV1::decode(&bytes).unwrap().proofs.len(),
            1
        );

        let empty = cashu_b(Vec::new(), None);
        let dleq = cashu_b(
            vec![v4_proof(Some((
                "d",
                Value::Map(vec![(Value::Text("r".into()), Value::Bytes(vec![1; 32]))]),
            )))],
            None,
        );
        let witness = cashu_b(
            vec![v4_proof(Some(("w", Value::Text("signature".into()))))],
            None,
        );
        let unknown = cashu_b(
            vec![v4_proof(None)],
            Some(("x", Value::Integer(1u64.into()))),
        );
        for bad in [empty, dleq, witness, unknown] {
            assert!(import_standard_cashu_token_v1(&accepted, &scope_id, 7, &bad, 120,).is_err());
        }
    }
}
