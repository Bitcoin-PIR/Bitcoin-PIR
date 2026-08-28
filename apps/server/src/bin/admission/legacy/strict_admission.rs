//! Strict admission assembly extracted from `unified_server.rs` (legacy
//! payment surface; slated for removal with R4).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use pir_cashu_client::{
    CashuCustodyExposureLimitsV1, ChaCha20Poly1305CustodyCipherV1,
    ChaCha20Poly1305RecoveryCipherV1,
};
use pir_payment_crypto::K256CashuMintKeyringV1;
use pir_runtime_core::harmony_attach_runtime::HarmonyAttachRegistryV1;
use pir_runtime_core::service_policy_runtime::{
    activate_exact_storeless_free_pow_policy_v1, activate_retained_service_policy_v1,
    activate_service_policy_v1, validate_policy_method_coverage_v1,
    validate_retained_policy_method_coverage_v1,
};
use pir_arc_adapter::{ArcSecretKeyV1, ArcSecretKeyringV1};
use pir_service_protocol::{IssuerClearingApprovalV1, ProviderClearingAuthorizationV1, ServicePolicyV1};
use pir_service_store::{CashuCustodyInventoryV1, ProviderStore, StoreOptions};
use zeroize::{Zeroize, Zeroizing};

use crate::admission::legacy::cashu::{
    load_cashu_epoch_keys_v1, parse_cashu_exposure_limits_v1,
    validate_existing_private_sqlite_path_v1, zeroize_cashu_epoch_keys_v1,
};
use crate::unified_server_bat_v2::{
    load_storeless_bat_v2_profile_v2, SealedStorelessBatV2InputsV2,
};
use crate::{
    decode_fixed_hex_v1, read_exact_secret_v1, read_regular_file_bounded_v1, CliArgs,
    SERVICE_CONFIG_FILE_LIMIT_V1,
};
use super::admission_runtime::{
    ProviderAdmissionHttpsTransportV1, SharedIssuerRuntimeConfigV1, StrictServiceAdmissionRuntimeV1,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ExperimentalArcPolicyUsageV1 {
    any: bool,
    provider_local: bool,
}

impl ExperimentalArcPolicyUsageV1 {
    fn include(&mut self, other: Self) {
        self.any |= other.any;
        self.provider_local |= other.provider_local;
    }
}

pub(crate) fn experimental_arc_policy_usage_v1(policy: &ServicePolicyV1) -> ExperimentalArcPolicyUsageV1 {
    let mut usage = ExperimentalArcPolicyUsageV1::default();
    for scope in &policy.scopes {
        for offer in &scope.offers {
            if offer.authorization == pir_service_protocol::AuthScheme::ArcV1Experimental {
                usage.any = true;
                usage.provider_local |=
                    offer.verification == pir_service_protocol::VerificationMode::ProviderLocal;
            }
        }
    }
    usage
}

pub(crate) fn inspect_experimental_arc_policy_v1(
    canonical_signed_policy: &[u8],
    label: &str,
) -> Result<ExperimentalArcPolicyUsageV1, String> {
    let policy = ServicePolicyV1::decode(canonical_signed_policy)
        .map_err(|error| format!("{label} is not a canonical V1 service policy: {error}"))?;
    if policy
        .encode()
        .map_err(|error| format!("failed to re-encode {label}: {error}"))?
        .as_slice()
        != canonical_signed_policy
    {
        return Err(format!("{label} is not canonically encoded"));
    }
    Ok(experimental_arc_policy_usage_v1(&policy))
}

pub(crate) fn validate_experimental_arc_opt_in_v1(
    allow_experimental_arc: bool,
    policy_usage: ExperimentalArcPolicyUsageV1,
    provider_local_keys_configured: bool,
) -> Result<(), String> {
    let configured = policy_usage.any || provider_local_keys_configured;
    if !allow_experimental_arc && configured {
        return Err(
            "experimental ARC policy/key configuration requires explicit --allow-experimental-arc; ARC is unaudited and production-disabled"
                .to_owned(),
        );
    }
    if allow_experimental_arc && !configured {
        return Err(
            "--allow-experimental-arc was supplied but no current/retained ARC policy or provider-local ARC key is configured"
                .to_owned(),
        );
    }
    if provider_local_keys_configured && !policy_usage.provider_local {
        return Err(
            "--service-arc-key was supplied but no current/retained provider-local ARC policy uses it"
                .to_owned(),
        );
    }
    if policy_usage.provider_local && !provider_local_keys_configured {
        return Err(
            "current/retained provider-local ARC policy requires at least one --service-arc-key"
                .to_owned(),
        );
    }
    Ok(())
}

pub(crate) fn validate_legacy_experimental_arc_cli_v1(
    allow_experimental_arc: bool,
    require_arc: bool,
    arc_key_configured: bool,
    service_admission_v1_enabled: bool,
) -> Result<(), String> {
    let legacy_arc_configured = require_arc || arc_key_configured;
    if legacy_arc_configured && !allow_experimental_arc {
        return Err(
            "legacy experimental ARC configuration requires explicit --allow-experimental-arc; ARC is unaudited and production-disabled"
                .to_owned(),
        );
    }
    if arc_key_configured && !require_arc {
        return Err(
            "--arc-key requires --require-arc; refusing to ignore ARC key material".to_owned(),
        );
    }
    if allow_experimental_arc && !legacy_arc_configured && !service_admission_v1_enabled {
        return Err(
            "--allow-experimental-arc was supplied but neither legacy ARC nor service admission V1 is configured"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod experimental_arc_opt_in_tests_v1 {
    use super::{
        validate_experimental_arc_opt_in_v1, validate_legacy_experimental_arc_cli_v1,
        ExperimentalArcPolicyUsageV1,
    };

    #[test]
    fn acknowledgement_and_arc_configuration_must_be_exactly_paired() {
        let none = ExperimentalArcPolicyUsageV1::default();
        let shared = ExperimentalArcPolicyUsageV1 {
            any: true,
            provider_local: false,
        };
        let provider_local = ExperimentalArcPolicyUsageV1 {
            any: true,
            provider_local: true,
        };

        assert!(validate_experimental_arc_opt_in_v1(false, none, false).is_ok());
        assert!(validate_experimental_arc_opt_in_v1(true, none, false).is_err());
        assert!(validate_experimental_arc_opt_in_v1(false, shared, false).is_err());
        assert!(validate_experimental_arc_opt_in_v1(false, none, true).is_err());
        assert!(validate_experimental_arc_opt_in_v1(true, none, true).is_err());
        assert!(validate_experimental_arc_opt_in_v1(true, shared, false).is_ok());
        assert!(validate_experimental_arc_opt_in_v1(true, shared, true).is_err());
        assert!(validate_experimental_arc_opt_in_v1(true, provider_local, false).is_err());
        assert!(validate_experimental_arc_opt_in_v1(true, provider_local, true).is_ok());
    }

    #[test]
    fn legacy_arc_requires_the_same_explicit_acknowledgement() {
        assert!(validate_legacy_experimental_arc_cli_v1(false, false, false, false).is_ok());
        assert!(validate_legacy_experimental_arc_cli_v1(false, true, false, false).is_err());
        assert!(validate_legacy_experimental_arc_cli_v1(true, true, false, false).is_ok());
        assert!(validate_legacy_experimental_arc_cli_v1(true, false, true, false).is_err());
        assert!(validate_legacy_experimental_arc_cli_v1(true, false, false, false).is_err());
        assert!(validate_legacy_experimental_arc_cli_v1(true, false, false, true).is_ok());
    }
}

pub(crate) fn provider_store_startup_log_line_v1(elapsed_ms: u128) -> String {
    format!("  Provider store startup_check=ok elapsed_ms={elapsed_ms}")
}

#[cfg(test)]
mod provider_store_startup_log_tests_v1 {
    use super::provider_store_startup_log_line_v1;

    #[test]
    fn serving_startup_log_omits_exact_business_inventory() {
        let line = provider_store_startup_log_line_v1(17);
        assert_eq!(line, "  Provider store startup_check=ok elapsed_ms=17");
        for forbidden in [
            "store_generation",
            "spend_commit_seq",
            "namespace_rows",
            "spent_capability_rows",
            "free_rate_limit_bucket_rows",
            "cashu_swap_intent_rows",
            "cashu_custody_lot_rows",
            "cashu_custody_note_rows",
            "cashu_custody_export_batch_rows",
        ] {
            assert!(!line.contains(forbidden), "leaked {forbidden}");
        }
    }
}

pub(crate) fn load_strict_service_admission_v1(
    args: &CliArgs,
    now_unix: u64,
    sealed_bat_v2_inputs: Option<SealedStorelessBatV2InputsV2>,
) -> Result<Option<StrictServiceAdmissionRuntimeV1>, String> {
    #[cfg(feature = "standard-cashu-process-e2e")]
    let test_only_service_https_configured = args.test_only_service_https_root_pem.is_some();
    let has_partial_configuration = args.service_policy_path.is_some()
        || !args.service_retained_policy_paths.is_empty()
        || args.service_provider_id_hex.is_some()
        || args.service_policy_key_hex.is_some()
        || args.service_storeless_free_pow_policy_digest_hex.is_some()
        || args.service_storeless_bat_v2.any_configured()
        || args.service_store_path.is_some()
        || args.service_free_ip_key_path.is_some()
        || args.service_trust_direct_peer_ip
        || !args.service_bat_key_paths.is_empty()
        || !args.service_arc_key_specs.is_empty()
        || !args.service_cashu_recovery_key_specs.is_empty()
        || args.service_cashu_recovery_active_epoch.is_some()
        || !args.service_cashu_custody_key_specs.is_empty()
        || args.service_cashu_custody_active_epoch.is_some()
        || !args.service_cashu_exposure_limit_specs.is_empty()
        || args.service_shared_authorization_path.is_some()
        || args.service_shared_issuer_approval_path.is_some()
        || args.service_shared_operator_key_hex.is_some()
        || args.service_shared_issuer_settlement_key_hex.is_some()
        || args.service_shared_clearing_key_path.is_some()
        || args.service_shared_idempotency_key_path.is_some()
        || args.service_shared_minimum_authorization_epoch.is_some()
        || {
            #[cfg(feature = "standard-cashu-process-e2e")]
            {
                test_only_service_https_configured
            }
            #[cfg(not(feature = "standard-cashu-process-e2e"))]
            {
                false
            }
        };
    if !args.require_service_auth_v1 {
        if has_partial_configuration {
            return Err(
                "service-admission configuration requires --require-service-auth-v1; refusing to ignore security-sensitive flags"
                    .to_owned(),
            );
        }
        return Ok(None);
    }
    if args.require_arc || args.require_cashu {
        return Err(
            "--require-service-auth-v1 cannot be combined with legacy --require-arc/--require-cashu gates"
                .to_owned(),
        );
    }

    let policy_path = args
        .service_policy_path
        .as_deref()
        .ok_or_else(|| "--service-policy is required".to_owned())?;
    let provider_id = decode_fixed_hex_v1::<32>(
        args.service_provider_id_hex
            .as_deref()
            .ok_or_else(|| "--service-provider-id-hex is required".to_owned())?,
        "--service-provider-id-hex",
    )?;
    if provider_id.iter().all(|byte| *byte == 0) {
        return Err("--service-provider-id-hex must not be all zero".to_owned());
    }
    let verifying_key_bytes = decode_fixed_hex_v1::<32>(
        args.service_policy_key_hex
            .as_deref()
            .ok_or_else(|| "--service-policy-key-hex is required".to_owned())?,
        "--service-policy-key-hex",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| "--service-policy-key-hex is not a valid Ed25519 public key".to_owned())?;
    let signed_policy = read_regular_file_bounded_v1(
        policy_path,
        SERVICE_CONFIG_FILE_LIMIT_V1,
        "signed service policy",
    )?;
    let storeless_free_pow_policy_digest = args
        .service_storeless_free_pow_policy_digest_hex
        .as_deref()
        .map(|value| {
            decode_fixed_hex_v1::<32>(value, "--service-storeless-free-pow-policy-digest-hex")
        })
        .transpose()?;
    if args.service_storeless_bat_v2.any_configured() && !args.service_storeless_bat_v2.selected() {
        return Err(
            "partial storeless BAT V2 configuration requires --service-storeless-bat-v2-policy-digest-hex; refusing to fall back to V1 admission"
                .to_owned(),
        );
    }
    if args.service_storeless_bat_v2.selected() {
        if storeless_bat_v2_has_forbidden_configuration_v2(args) {
            return Err(
                "storeless BAT V2 mode forbids ProviderStore, rollback/idempotency state, V1 retained/shared/BAT/Cashu/ARC inputs, the Free-PoW-only profile, legacy paid gates, and test HTTPS roots"
                    .to_owned(),
            );
        }
        let loaded = load_storeless_bat_v2_profile_v2(
            &args.service_storeless_bat_v2,
            &signed_policy,
            provider_id,
            verifying_key,
            now_unix,
            sealed_bat_v2_inputs,
        )?;
        let runtime = StrictServiceAdmissionRuntimeV1 {
            policy: loaded.policy,
            retained_policies: loaded.retained_policies,
            provider_store: None,
            trust_direct_peer_ip: false,
            bat_keyring: None,
            experimental_arc_keyring: None,
            cashu_recovery_cipher: None,
            cashu_custody_cipher: None,
            cashu_exposure_limits: BTreeMap::new(),
            shared_issuer: None,
            storeless_bat_v2: Some(loaded.runtime),
            http_transport: ProviderAdmissionHttpsTransportV1 {
                connect_timeout: Duration::from_secs(5),
                io_timeout: Duration::from_secs(15),
                #[cfg(feature = "standard-cashu-process-e2e")]
                test_only_webpki_root_pem: None,
            },
            harmony_attach_registry: Arc::new(HarmonyAttachRegistryV1::default()),
            monotonic_origin: Instant::now(),
        };
        validate_policy_method_coverage_v1(runtime.policy.policy(), |route| {
            runtime.supports(route)
        })
        .map_err(|error| format!("incomplete storeless BAT V2 admission: {error}"))?;
        for retained in runtime.retained_policies.values() {
            validate_retained_policy_method_coverage_v1(retained.policy(), |route| {
                runtime.supports(route)
            })
            .map_err(|error| {
                format!(
                    "incomplete retained storeless BAT V2 admission for {}: {error}",
                    hex::encode(retained.policy_digest())
                )
            })?;
        }
        return Ok(Some(runtime));
    }
    if storeless_free_pow_policy_digest.is_some()
        && (!args.service_retained_policy_paths.is_empty()
            || args.arc_key_path.is_some()
            || !args.cashu_keysets.is_empty()
            || args.service_store_path.is_some()
            || args.service_free_ip_key_path.is_some()
            || args.service_trust_direct_peer_ip
            || !args.service_bat_key_paths.is_empty()
            || !args.service_arc_key_specs.is_empty()
            || args.allow_experimental_arc
            || !args.service_cashu_recovery_key_specs.is_empty()
            || args.service_cashu_recovery_active_epoch.is_some()
            || !args.service_cashu_custody_key_specs.is_empty()
            || args.service_cashu_custody_active_epoch.is_some()
            || !args.service_cashu_exposure_limit_specs.is_empty()
            || args.service_shared_authorization_path.is_some()
            || args.service_shared_issuer_approval_path.is_some()
            || args.service_shared_operator_key_hex.is_some()
            || args.service_shared_issuer_settlement_key_hex.is_some()
            || args.service_shared_clearing_key_path.is_some()
            || args.service_shared_idempotency_key_path.is_some()
            || args.service_shared_minimum_authorization_epoch.is_some()
            || {
                #[cfg(feature = "standard-cashu-process-e2e")]
                {
                    test_only_service_https_configured
                }
                #[cfg(not(feature = "standard-cashu-process-e2e"))]
                {
                    false
                }
            })
    {
        return Err(
            "storeless Free-PoW mode forbids retained policies, stores, rollback authorities, Free IP quota, credential/payment keys, legacy or V1 Cashu/ARC, shared issuer, and test HTTPS configuration"
                .to_owned(),
        );
    }
    let mut experimental_arc_usage =
        inspect_experimental_arc_policy_v1(&signed_policy, "signed service policy")?;
    let mut retained_policy_inputs = Vec::with_capacity(args.service_retained_policy_paths.len());
    for retained_path in &args.service_retained_policy_paths {
        let retained_bytes = read_regular_file_bounded_v1(
            retained_path,
            SERVICE_CONFIG_FILE_LIMIT_V1,
            "retained signed service policy",
        )?;
        experimental_arc_usage.include(inspect_experimental_arc_policy_v1(
            &retained_bytes,
            &format!("retained signed service policy {}", retained_path.display()),
        )?);
        retained_policy_inputs.push((retained_path.clone(), retained_bytes));
    }
    validate_experimental_arc_opt_in_v1(
        args.allow_experimental_arc,
        experimental_arc_usage,
        !args.service_arc_key_specs.is_empty(),
    )?;
    if experimental_arc_usage.any {
        eprintln!(
            "!!! WARNING: EXPERIMENTAL ARC ENABLED FOR THIS PIR SERVER; THE PINNED DRAFT-01 IMPLEMENTATION IS UNAUDITED AND MUST NOT BE USED IN PRODUCTION !!!"
        );
    }
    let provider_store = if storeless_free_pow_policy_digest.is_some() {
        None
    } else {
        let provider_store_path = args
            .service_store_path
            .as_deref()
            .ok_or_else(|| "--service-store is required".to_owned())?;
        let canonical_store =
            validate_existing_private_sqlite_path_v1(provider_store_path, "provider spend store")?;

        let options = StoreOptions::default();
        let store_startup_check_started = Instant::now();
        let store = ProviderStore::open_existing(&canonical_store, provider_id, options)
            .map_err(|error| format!("failed to open provider spend store: {error}"))?;
        let _store_inventory = store.operational_inventory().map_err(|error| {
            format!("failed to read provider store operational inventory: {error}")
        })?;
        let startup_line =
            provider_store_startup_log_line_v1(store_startup_check_started.elapsed().as_millis());
        println!("{startup_line}");
        Some(store)
    };

    let bat_keyring = if args.service_bat_key_paths.is_empty() {
        None
    } else {
        let mut secret_keys = Vec::with_capacity(args.service_bat_key_paths.len());
        for path in &args.service_bat_key_paths {
            secret_keys.push(read_exact_secret_v1::<32>(path, "service Cashu BAT key")?);
        }
        let result = K256CashuMintKeyringV1::from_secret_keys(secret_keys.iter().copied())
            .map_err(|error| format!("invalid service Cashu BAT keyring: {error}"));
        secret_keys.zeroize();
        Some(result?)
    };

    let experimental_arc_keyring = if args.service_arc_key_specs.is_empty() {
        None
    } else {
        let mut keys = Vec::with_capacity(args.service_arc_key_specs.len());
        for spec in &args.service_arc_key_specs {
            let (key_id_hex, path) = spec.split_once('=').ok_or_else(|| {
                "--service-arc-key must be <hex-key-id>=<raw-128-byte-key-path>".to_owned()
            })?;
            let key_id = hex::decode(key_id_hex)
                .map_err(|_| "--service-arc-key key ID is not valid hex".to_owned())?;
            if key_id.is_empty() || key_id.len() > pir_service_protocol::MAX_CREDENTIAL_KEY_ID_LEN {
                return Err(format!(
                    "--service-arc-key key ID must contain 1..={} bytes",
                    pir_service_protocol::MAX_CREDENTIAL_KEY_ID_LEN
                ));
            }
            if path.is_empty() {
                return Err("--service-arc-key path is empty".to_owned());
            }
            let secret = Zeroizing::new(read_exact_secret_v1::<
                { pir_arc_adapter::ARC_SECRET_KEY_LEN_V1 },
            >(
                std::path::Path::new(path),
                "experimental ARC private key",
            )?);
            keys.push(
                ArcSecretKeyV1::from_zeroizing_bytes(key_id, secret)
                    .map_err(|error| format!("invalid experimental ARC private key: {error}"))?,
            );
        }
        Some(
            ArcSecretKeyringV1::new(keys)
                .map_err(|error| format!("invalid experimental ARC keyring: {error}"))?,
        )
    };

    let mut cashu_recovery_key_material = load_cashu_epoch_keys_v1(
        args.service_cashu_recovery_active_epoch,
        &args.service_cashu_recovery_key_specs,
        "--service-cashu-recovery-active-epoch",
        "--service-cashu-recovery-key",
        "standard Cashu recovery key",
    )?;
    let mut cashu_custody_key_material = match load_cashu_epoch_keys_v1(
        args.service_cashu_custody_active_epoch,
        &args.service_cashu_custody_key_specs,
        "--service-cashu-custody-active-epoch",
        "--service-cashu-custody-key",
        "standard Cashu custody key",
    ) {
        Ok(material) => material,
        Err(error) => {
            zeroize_cashu_epoch_keys_v1(&mut cashu_recovery_key_material);
            return Err(error);
        }
    };
    if let (Some((_, recovery_keys)), Some((_, custody_keys))) = (
        cashu_recovery_key_material.as_ref(),
        cashu_custody_key_material.as_ref(),
    ) {
        if recovery_keys.iter().any(|(_, recovery_key)| {
            custody_keys
                .iter()
                .any(|(_, custody_key)| recovery_key == custody_key)
        }) {
            zeroize_cashu_epoch_keys_v1(&mut cashu_recovery_key_material);
            zeroize_cashu_epoch_keys_v1(&mut cashu_custody_key_material);
            return Err(
                "standard Cashu recovery and custody keyrings must use distinct key material"
                    .to_owned(),
            );
        }
    }
    let cashu_recovery_cipher =
        match cashu_recovery_key_material.take() {
            None => None,
            Some((active_epoch, mut keys)) => {
                let result = ChaCha20Poly1305RecoveryCipherV1::new(
                    active_epoch,
                    keys.iter().map(|(epoch, key)| (*epoch, *key)),
                );
                for (_, key) in &mut keys {
                    key.zeroize();
                }
                Some(result.map_err(|error| {
                    format!("invalid standard Cashu recovery keyring: {error:?}")
                })?)
            }
        };
    let cashu_custody_cipher =
        match cashu_custody_key_material.take() {
            None => None,
            Some((active_epoch, mut keys)) => {
                let result = ChaCha20Poly1305CustodyCipherV1::new(
                    active_epoch,
                    keys.iter().map(|(epoch, key)| (*epoch, *key)),
                );
                for (_, key) in &mut keys {
                    key.zeroize();
                }
                Some(result.map_err(|error| {
                    format!("invalid standard Cashu custody keyring: {error:?}")
                })?)
            }
        };
    let cashu_exposure_limits =
        parse_cashu_exposure_limits_v1(&args.service_cashu_exposure_limit_specs)?;

    let shared_field_count = [
        args.service_shared_authorization_path.is_some(),
        args.service_shared_issuer_approval_path.is_some(),
        args.service_shared_operator_key_hex.is_some(),
        args.service_shared_issuer_settlement_key_hex.is_some(),
        args.service_shared_clearing_key_path.is_some(),
        args.service_shared_idempotency_key_path.is_some(),
        args.service_shared_minimum_authorization_epoch.is_some(),
    ]
    .into_iter()
    .filter(|configured| *configured)
    .count();
    let shared_issuer = if shared_field_count == 0 {
        None
    } else if shared_field_count != 7 {
        return Err(
            "shared issuer clearing requires all --service-shared-* authorization, approval, operator key, issuer settlement key, clearing key, idempotency key and minimum epoch fields"
                .to_owned(),
        );
    } else {
        let authorization_bytes = read_regular_file_bounded_v1(
            args.service_shared_authorization_path
                .as_deref()
                .expect("count checked"),
            SERVICE_CONFIG_FILE_LIMIT_V1,
            "provider clearing authorization",
        )?;
        let authorization = ProviderClearingAuthorizationV1::decode(&authorization_bytes)
            .map_err(|error| format!("invalid provider clearing authorization: {error}"))?;
        if authorization
            .encode()
            .map_err(|error| format!("invalid provider clearing authorization: {error}"))?
            != authorization_bytes
        {
            return Err("provider clearing authorization is not canonical".to_owned());
        }
        let approval_bytes = read_regular_file_bounded_v1(
            args.service_shared_issuer_approval_path
                .as_deref()
                .expect("count checked"),
            SERVICE_CONFIG_FILE_LIMIT_V1,
            "issuer clearing approval",
        )?;
        let issuer_approval = IssuerClearingApprovalV1::decode(&approval_bytes)
            .map_err(|error| format!("invalid issuer clearing approval: {error}"))?;
        if issuer_approval.encode() != approval_bytes {
            return Err("issuer clearing approval is not canonical".to_owned());
        }
        let operator_verifying_key = VerifyingKey::from_bytes(&decode_fixed_hex_v1::<32>(
            args.service_shared_operator_key_hex
                .as_deref()
                .expect("count checked"),
            "--service-shared-operator-key-hex",
        )?)
        .map_err(|_| "shared operator key is not valid Ed25519".to_owned())?;
        let issuer_settlement_verifying_key = VerifyingKey::from_bytes(&decode_fixed_hex_v1::<32>(
            args.service_shared_issuer_settlement_key_hex
                .as_deref()
                .expect("count checked"),
            "--service-shared-issuer-settlement-key-hex",
        )?)
        .map_err(|_| "shared issuer settlement key is not valid Ed25519".to_owned())?;
        let mut clearing_key_bytes = read_exact_secret_v1::<32>(
            args.service_shared_clearing_key_path
                .as_deref()
                .expect("count checked"),
            "provider clearing signing key",
        )?;
        let clearing_signing_key = ed25519_dalek::SigningKey::from_bytes(&clearing_key_bytes);
        clearing_key_bytes.zeroize();
        let idempotency_key = Zeroizing::new(read_exact_secret_v1::<32>(
            args.service_shared_idempotency_key_path
                .as_deref()
                .expect("count checked"),
            "provider clearing idempotency key",
        )?);
        let minimum_authorization_epoch = args
            .service_shared_minimum_authorization_epoch
            .expect("count checked");
        if minimum_authorization_epoch == 0 {
            return Err("shared minimum authorization epoch must be non-zero".to_owned());
        }
        Some(SharedIssuerRuntimeConfigV1 {
            authorization,
            issuer_approval,
            operator_verifying_key,
            issuer_settlement_verifying_key,
            clearing_signing_key,
            minimum_authorization_epoch,
            idempotency_key,
        })
    };

    #[cfg(feature = "standard-cashu-process-e2e")]
    let test_only_webpki_root_pem = args
        .test_only_service_https_root_pem
        .as_deref()
        .map(|path| {
            pir_private_files::read_private_file_bounded_v1(
                path,
                16 * 1024,
                pir_private_files::PrivateFileModeV1::ReadOnlyOrReadWrite,
                "test-only service WebPKI root",
            )
            .map(|bytes| Arc::<[u8]>::from(bytes.as_slice()))
        })
        .transpose()?;
    let http_transport = ProviderAdmissionHttpsTransportV1 {
        connect_timeout: Duration::from_secs(5),
        io_timeout: Duration::from_secs(15),
        #[cfg(feature = "standard-cashu-process-e2e")]
        test_only_webpki_root_pem,
    };
    if let Some(shared) = shared_issuer.as_ref() {
        http_transport
            .validate_trust(
                &shared.authorization.claims.redeem_endpoint,
                &shared.authorization.claims.redeem_leaf_spki_sha256_pins,
            )
            .map_err(|error| format!("shared issuer HTTPS trust is invalid: {error}"))?;
        shared
            .committer(
                provider_store.as_ref().ok_or_else(|| {
                    "shared issuer configuration requires a provider store".to_owned()
                })?,
                &http_transport,
            )
            .map_err(|error| format!("shared issuer clearing configuration is invalid: {error}"))?;
        shared
            .authorization
            .verify_for(
                &provider_id,
                &shared.authorization.claims.issuer_id,
                &shared.operator_verifying_key,
                now_unix,
                shared.minimum_authorization_epoch,
            )
            .map_err(|error| format!("provider clearing authorization is not current: {error}"))?;
        shared
            .issuer_approval
            .verify_for(
                &shared.authorization,
                &shared.issuer_settlement_verifying_key,
                now_unix,
                shared.minimum_authorization_epoch,
            )
            .map_err(|error| format!("issuer clearing approval is not current: {error}"))?;
    }

    let policy = match storeless_free_pow_policy_digest {
        Some(expected_digest) => activate_exact_storeless_free_pow_policy_v1(
            &signed_policy,
            provider_id,
            verifying_key,
            expected_digest,
            now_unix,
        ),
        None => activate_service_policy_v1(
            &signed_policy,
            provider_id,
            verifying_key,
            provider_store
                .as_ref()
                .ok_or_else(|| "provider store is unavailable".to_owned())?,
            now_unix,
            experimental_arc_keyring
                .as_ref()
                .map(|keyring| keyring as &dyn pir_service_store::ArcExclusiveKeyLineageVerifierV1),
        ),
    }
    .map_err(|error| format!("failed to activate signed service policy: {error}"))?;
    let mut retained_policies = BTreeMap::new();
    for (retained_path, retained_bytes) in retained_policy_inputs {
        let retained =
            activate_retained_service_policy_v1(&retained_bytes, &policy).map_err(|error| {
                format!(
                    "failed to activate retained service policy {}: {error} \
                     (V1 requires every retained policy to verify under the current \
                     --service-policy-key-hex)",
                    retained_path.display()
                )
            })?;
        let digest = retained.policy_digest();
        if retained_policies.insert(digest, retained).is_some() {
            return Err(format!(
                "duplicate retained service policy digest {}",
                hex::encode(digest)
            ));
        }
    }
    let runtime = StrictServiceAdmissionRuntimeV1 {
        policy,
        retained_policies,
        provider_store,
        trust_direct_peer_ip: args.service_trust_direct_peer_ip,
        bat_keyring,
        experimental_arc_keyring,
        cashu_recovery_cipher,
        cashu_custody_cipher,
        cashu_exposure_limits,
        shared_issuer,
        storeless_bat_v2: None,
        http_transport,
        harmony_attach_registry: Arc::new(HarmonyAttachRegistryV1::default()),
        monotonic_origin: Instant::now(),
    };
    validate_cashu_runtime_configuration_v1(&runtime)?;
    validate_policy_method_coverage_v1(runtime.policy.policy(), |route| runtime.supports(route))
        .map_err(|error| format!("incomplete service admission configuration: {error}"))?;
    for retained in runtime.retained_policies.values() {
        validate_retained_policy_method_coverage_v1(retained.policy(), |route| {
            runtime.supports(route)
        })
        .map_err(|error| {
            format!(
                "incomplete retained-policy redemption configuration for {}: {error}",
                hex::encode(retained.policy_digest())
            )
        })?;
        for scope_policy in &retained.policy().scopes {
            let scope_id = scope_policy.scope.scope_id();
            for offer in &scope_policy.offers {
                if offer.credential_binding.is_none() {
                    continue;
                }
                let verified_offer = retained
                    .verified_offer_for_redemption(
                        &scope_id,
                        offer.offer_id,
                        retained.policy().issued_at,
                    )
                    .map_err(|error| {
                        format!(
                            "retained policy {} has an invalid redemption offer: {error}",
                            hex::encode(retained.policy_digest())
                        )
                    })?;
                let readiness = runtime
                    .provider_store
                    .as_ref()
                    .ok_or_else(|| "retained policy requires a provider store".to_owned())?
                    .verify_existing_verified_offer_namespace_v1(
                        &verified_offer,
                        retained.policy().issued_at,
                        runtime.experimental_arc_keyring.as_ref().map(|keyring| {
                            keyring as &dyn pir_service_store::ArcExclusiveKeyLineageVerifierV1
                        }),
                    )
                    .map_err(|error| {
                        format!(
                            "retained policy {} is missing exact durable redemption state: {error}",
                            hex::encode(retained.policy_digest())
                        )
                    })?;
                if readiness
                    == pir_service_store::VerifiedOfferNamespaceReadinessV1::UnsupportedExperimental
                {
                    return Err(format!(
                        "retained policy {} requires an unavailable experimental ARC adapter",
                        hex::encode(retained.policy_digest())
                    ));
                }
            }
        }
    }

    for configured_policy in runtime.all_policies() {
        for scope in &configured_policy.scopes {
            for offer in &scope.offers {
                if offer.credential_binding.is_none() {
                    continue;
                }
                if offer.verification == pir_service_protocol::VerificationMode::SharedIssuerOnline
                {
                    let shared = runtime.shared_issuer.as_ref().ok_or_else(|| {
                        "policy advertises shared issuer redemption without clearing configuration"
                            .to_owned()
                    })?;
                    let binding = offer.credential_binding.as_ref().ok_or_else(|| {
                        "shared issuer offer is missing its credential binding".to_owned()
                    })?;
                    let digest = binding
                        .binding_digest()
                        .map_err(|error| format!("invalid shared issuer binding: {error}"))?;
                    shared
                        .authorization
                        .rule_for_binding(&digest)
                        .ok_or_else(|| {
                            "shared issuer clearing authorization has no rule for an advertised offer"
                                .to_owned()
                        })?;
                    if offer.issuer_id != shared.authorization.claims.issuer_id
                        || scope.scope.provider_id != shared.authorization.claims.provider_id
                        || offer.endpoint != shared.authorization.claims.redeem_endpoint
                    {
                        return Err(
                            "shared issuer offer audience or endpoint does not match clearing authorization"
                                .to_owned(),
                        );
                    }
                }
            }
        }
    }

    if let Some(keyring) = runtime.bat_keyring.as_ref() {
        let retained = keyring.denomination_public_keys();
        for configured_policy in runtime.all_policies() {
            for scope in &configured_policy.scopes {
                for offer in &scope.offers {
                    if offer.credential_binding.is_none() {
                        continue;
                    }
                    if offer.authorization == pir_service_protocol::AuthScheme::BitcoinPirCashuBatV1
                        && offer.verification
                            == pir_service_protocol::VerificationMode::ProviderLocal
                    {
                        let verification_key = offer
                            .credential_binding
                            .as_ref()
                            .and_then(|binding| {
                                <[u8; 33]>::try_from(binding.claims.verification_key.as_slice())
                                    .ok()
                            })
                            .ok_or_else(|| {
                                "provider-local BAT offer has no exact 33-byte verification key"
                                    .to_owned()
                            })?;
                        if !retained.contains(&verification_key) {
                            return Err(
                                "provider-local BAT offer references a key not retained by this server"
                                    .to_owned(),
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(Some(runtime))
}

pub(crate) fn storeless_bat_v2_has_forbidden_configuration_v2(args: &CliArgs) -> bool {
    let test_only_https = {
        #[cfg(feature = "standard-cashu-process-e2e")]
        {
            args.test_only_service_https_root_pem.is_some()
        }
        #[cfg(not(feature = "standard-cashu-process-e2e"))]
        {
            false
        }
    };
    args.service_storeless_free_pow_policy_digest_hex.is_some()
        || !args.service_retained_policy_paths.is_empty()
        || args.arc_key_path.is_some()
        || !args.cashu_keysets.is_empty()
        || args.service_store_path.is_some()
        || args.service_free_ip_key_path.is_some()
        || args.service_trust_direct_peer_ip
        || !args.service_bat_key_paths.is_empty()
        || !args.service_arc_key_specs.is_empty()
        || args.allow_experimental_arc
        || !args.service_cashu_recovery_key_specs.is_empty()
        || args.service_cashu_recovery_active_epoch.is_some()
        || !args.service_cashu_custody_key_specs.is_empty()
        || args.service_cashu_custody_active_epoch.is_some()
        || !args.service_cashu_exposure_limit_specs.is_empty()
        || args.service_shared_authorization_path.is_some()
        || args.service_shared_issuer_approval_path.is_some()
        || args.service_shared_operator_key_hex.is_some()
        || args.service_shared_issuer_settlement_key_hex.is_some()
        || args.service_shared_clearing_key_path.is_some()
        || args.service_shared_idempotency_key_path.is_some()
        || args.service_shared_minimum_authorization_epoch.is_some()
        || test_only_https
}

pub(crate) fn validate_cashu_runtime_configuration_v1(
    runtime: &StrictServiceAdmissionRuntimeV1,
) -> Result<(), String> {
    let mut required = std::collections::BTreeSet::new();
    for policy in runtime.all_policies() {
        for scope in &policy.scopes {
            for offer in &scope.offers {
                if let Some(manifest) = offer.cashu_mint_manifest.as_ref() {
                    runtime
                        .http_transport
                        .validate_trust(&manifest.mint_endpoint, &manifest.leaf_spki_sha256_pins)
                        .map_err(|error| {
                            format!("standard Cashu mint HTTPS trust is invalid: {error}")
                        })?;
                    required.insert((manifest.mint_id(), manifest.unit.clone()));
                }
            }
        }
    }

    if required.is_empty() {
        if runtime.cashu_recovery_cipher.is_some()
            || runtime.cashu_custody_cipher.is_some()
            || !runtime.cashu_exposure_limits.is_empty()
        {
            return Err(
                "standard Cashu keys or limits were configured but no current/retained policy advertises standard Cashu"
                    .to_owned(),
            );
        }
        return Ok(());
    }
    if runtime.cashu_recovery_cipher.is_none() || runtime.cashu_custody_cipher.is_none() {
        return Err(
            "every standard Cashu offer requires separate recovery and custody keyrings".to_owned(),
        );
    }
    for (mint_id, unit) in &required {
        let limits = runtime
            .cashu_exposure_limits
            .get(&(*mint_id, unit.clone()))
            .ok_or_else(|| {
                format!(
                    "standard Cashu offer for mint {} unit {} has no exact finite exposure limit",
                    hex::encode(mint_id),
                    unit,
                )
            })?;
        let inventory = runtime
            .provider_store
            .as_ref()
            .ok_or_else(|| "standard Cashu requires a provider store".to_owned())?
            .cashu_custody_inventory_v1(mint_id, unit)
            .map_err(|error| {
                format!(
                    "failed to validate standard Cashu exposure for mint {} unit {}: {error}",
                    hex::encode(mint_id),
                    unit,
                )
            })?;
        if !cashu_inventory_within_limits_v1(&inventory, *limits)? {
            return Err(format!(
                "existing standard Cashu exposure for mint {} unit {} exceeds its configured finite cap",
                hex::encode(mint_id),
                unit,
            ));
        }
    }
    for (mint_id, unit) in runtime.cashu_exposure_limits.keys() {
        if !required.contains(&(*mint_id, unit.clone())) {
            return Err(format!(
                "standard Cashu exposure limit for mint {} unit {} is not referenced by any current/retained policy",
                hex::encode(mint_id),
                unit,
            ));
        }
    }
    Ok(())
}

pub(crate) fn cashu_inventory_within_limits_v1(
    inventory: &CashuCustodyInventoryV1,
    limits: CashuCustodyExposureLimitsV1,
) -> Result<bool, String> {
    let unsettled_value = inventory
        .pending_intent_value
        .checked_add(inventory.available_value)
        .and_then(|value| value.checked_add(inventory.reserved_value))
        .and_then(|value| value.checked_add(inventory.acknowledged_value))
        .ok_or_else(|| {
            "standard Cashu startup exposure value overflowed; refusing activation".to_owned()
        })?;
    let unsettled_notes = inventory
        .pending_intent_notes
        .checked_add(inventory.available_notes)
        .and_then(|value| value.checked_add(inventory.reserved_notes))
        .and_then(|value| value.checked_add(inventory.acknowledged_notes))
        .ok_or_else(|| {
            "standard Cashu startup exposure note count overflowed; refusing activation".to_owned()
        })?;
    Ok(unsettled_value <= limits.max_unsettled_value()
        && unsettled_notes <= limits.max_unsettled_notes())
}

