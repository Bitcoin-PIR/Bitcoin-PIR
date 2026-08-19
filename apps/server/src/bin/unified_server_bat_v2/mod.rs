//! Closed, payment-storeless BAT V2 configuration module for `unified_server`.
//!
//! This module deliberately has no `ProviderStore`, rollback authority,
//! idempotency key, or V1 shared-issuer adapter.  The current policy, every
//! retained policy, and every issuer class are immutable release inputs with
//! explicit digest pins.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use pir_provider_clearing_client::{
    BatV2ProviderRedeemTrustV2, StorelessBatV2ProviderRedeemClientV2,
    StrictHttpsBatV2RedeemTransportV2,
};
use pir_runtime_core::service_policy_runtime::{
    activate_exact_storeless_bat_v2_policy_v1, activate_exact_storeless_retained_bat_v2_policy_v1,
    ActivatedRetainedServicePolicyV1, ActivatedServicePolicyV1,
};
use pir_service_protocol::{
    bat_verification_key_fingerprint_v1, verify_bat_acceptance_class_member_projection_v2,
    AuthScheme, BatAcceptanceClassV2, IssuerAccountingApprovalV2,
    ProviderAccountingAuthorizationV2, ProviderId, ServiceProtocolError,
    VerifiedBatAcceptanceMemberV2, MAX_BAT_ACCEPTANCE_CLASS_LEN_V2,
};
use zeroize::Zeroize;

use super::{
    decode_fixed_hex_v1, read_exact_secret_v1, read_regular_file_bounded_v1,
    SERVICE_CONFIG_FILE_LIMIT_V1,
};

#[derive(Debug, Default)]
pub(super) struct StorelessBatV2CliV2 {
    pub current_policy_digest_hex: Option<String>,
    pub retained_policy_specs: Vec<String>,
    pub class_specs: Vec<String>,
    pub accounting_authorization_path: Option<PathBuf>,
    pub issuer_approval_path: Option<PathBuf>,
    pub operator_key_hex: Option<String>,
    pub issuer_settlement_key_hex: Option<String>,
    /// Raw Ed25519 seed accepted only for the pir1/local-test slice.  pir2
    /// must replace this input with the separately reviewed SNP-sealed key
    /// loader; this field is never an implicit fallback for that path.
    pub pir1_clearing_key_path: Option<PathBuf>,
    pub minimum_authorization_epoch: Option<u64>,
}

impl StorelessBatV2CliV2 {
    pub fn any_configured(&self) -> bool {
        self.current_policy_digest_hex.is_some()
            || !self.retained_policy_specs.is_empty()
            || !self.class_specs.is_empty()
            || self.accounting_authorization_path.is_some()
            || self.issuer_approval_path.is_some()
            || self.operator_key_hex.is_some()
            || self.issuer_settlement_key_hex.is_some()
            || self.pir1_clearing_key_path.is_some()
            || self.minimum_authorization_epoch.is_some()
    }

    pub fn selected(&self) -> bool {
        self.current_policy_digest_hex.is_some()
    }
}

pub(super) struct LoadedStorelessBatV2ProfileV2 {
    pub policy: ActivatedServicePolicyV1,
    pub retained_policies: BTreeMap<[u8; 32], ActivatedRetainedServicePolicyV1>,
    pub runtime: StorelessBatV2RuntimeConfigV2,
}

/// Public artifacts plus the clearing key transferred from the measured pir2
/// sealed dispatcher. The loader accepts this only when the plaintext pir1
/// key path is absent.
pub(super) struct SealedStorelessBatV2InputsV2 {
    pub clearing_signing_key: SigningKey,
    pub authorization: ProviderAccountingAuthorizationV2,
    pub issuer_approval: IssuerAccountingApprovalV2,
}

pub(super) struct StorelessBatV2RuntimeConfigV2 {
    classes_by_digest: BTreeMap<[u8; 32], BatAcceptanceClassV2>,
    authorization: ProviderAccountingAuthorizationV2,
    issuer_approval: IssuerAccountingApprovalV2,
    operator_verifying_key: VerifyingKey,
    issuer_settlement_verifying_key: VerifyingKey,
    clearing_signing_key: SigningKey,
    minimum_authorization_epoch: u64,
    transport: StrictHttpsBatV2RedeemTransportV2,
}

impl core::fmt::Debug for StorelessBatV2RuntimeConfigV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StorelessBatV2RuntimeConfigV2")
            .field("provider_id", &self.authorization.claims.provider_id)
            .field("issuer_id", &self.authorization.claims.issuer_id)
            .field("class_count", &self.classes_by_digest.len())
            .field(
                "minimum_authorization_epoch",
                &self.minimum_authorization_epoch,
            )
            .field("clearing_signing_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl StorelessBatV2RuntimeConfigV2 {
    pub fn class_for_digest(&self, digest: &[u8; 32]) -> Option<&BatAcceptanceClassV2> {
        self.classes_by_digest.get(digest)
    }

    pub fn client(&self) -> Result<StorelessBatV2ProviderRedeemClientV2<'_>, ServiceProtocolError> {
        StorelessBatV2ProviderRedeemClientV2::new(
            BatV2ProviderRedeemTrustV2 {
                expected_provider_id: self.authorization.claims.provider_id,
                expected_issuer_id: self.authorization.claims.issuer_id,
                authorization: self.authorization.clone(),
                issuer_approval: self.issuer_approval.clone(),
                operator_verifying_key: self.operator_verifying_key,
                issuer_settlement_verifying_key: self.issuer_settlement_verifying_key,
                minimum_authorization_epoch: self.minimum_authorization_epoch,
            },
            self.clearing_signing_key.clone(),
            &self.transport,
        )
    }
}

pub(super) fn load_storeless_bat_v2_profile_v2(
    cli: &StorelessBatV2CliV2,
    signed_current_policy: &[u8],
    expected_provider_id: ProviderId,
    policy_verifying_key: VerifyingKey,
    now_unix: u64,
    sealed_inputs: Option<SealedStorelessBatV2InputsV2>,
) -> Result<LoadedStorelessBatV2ProfileV2, String> {
    validate_complete_cli_group_v2(cli, sealed_inputs.is_some())?;

    let current_digest = decode_nonzero_digest_v2(
        cli.current_policy_digest_hex
            .as_deref()
            .expect("complete group checked"),
        "--service-storeless-bat-v2-policy-digest-hex",
    )?;
    let policy = activate_exact_storeless_bat_v2_policy_v1(
        signed_current_policy,
        expected_provider_id,
        policy_verifying_key,
        current_digest,
        now_unix,
    )
    .map_err(|error| format!("failed to activate exact storeless BAT V2 policy: {error}"))?;

    let mut retained_policies = BTreeMap::new();
    for spec in &cli.retained_policy_specs {
        let (expected_digest, path) =
            parse_digest_path_spec_v2(spec, "--service-storeless-bat-v2-retained-policy")?;
        let bytes = read_regular_file_bounded_v1(
            &path,
            SERVICE_CONFIG_FILE_LIMIT_V1,
            "retained storeless BAT V2 signed policy",
        )?;
        let retained = activate_exact_storeless_retained_bat_v2_policy_v1(
            &bytes,
            expected_digest,
            &policy,
            now_unix,
        )
        .map_err(|error| {
            format!(
                "failed to activate retained storeless BAT V2 policy {}: {error}",
                path.display()
            )
        })?;
        if retained_policies
            .insert(expected_digest, retained)
            .is_some()
        {
            return Err(format!(
                "duplicate retained storeless BAT V2 policy digest {}",
                hex::encode(expected_digest)
            ));
        }
    }

    let (authorization, issuer_approval, sealed_clearing_signing_key) = match sealed_inputs {
        Some(inputs) => (
            inputs.authorization,
            inputs.issuer_approval,
            Some(inputs.clearing_signing_key),
        ),
        None => {
            let authorization_path = cli
                .accounting_authorization_path
                .as_deref()
                .expect("complete group checked");
            let authorization_bytes = read_regular_file_bounded_v1(
                authorization_path,
                SERVICE_CONFIG_FILE_LIMIT_V1,
                "BAT V2 provider accounting authorization",
            )?;
            let authorization = ProviderAccountingAuthorizationV2::decode(&authorization_bytes)
                .map_err(|error| {
                    format!("invalid BAT V2 provider accounting authorization: {error}")
                })?;
            if authorization.encode().map_err(|error| {
                format!("invalid BAT V2 provider accounting authorization: {error}")
            })? != authorization_bytes
            {
                return Err("BAT V2 provider accounting authorization is not canonical".to_owned());
            }

            let approval_path = cli
                .issuer_approval_path
                .as_deref()
                .expect("complete group checked");
            let approval_bytes = read_regular_file_bounded_v1(
                approval_path,
                SERVICE_CONFIG_FILE_LIMIT_V1,
                "BAT V2 issuer accounting approval",
            )?;
            let issuer_approval = IssuerAccountingApprovalV2::decode(&approval_bytes)
                .map_err(|error| format!("invalid BAT V2 issuer accounting approval: {error}"))?;
            if issuer_approval.encode().as_slice() != approval_bytes.as_slice() {
                return Err("BAT V2 issuer accounting approval is not canonical".to_owned());
            }
            (authorization, issuer_approval, None)
        }
    };

    let operator_verifying_key = decode_verifying_key_v2(
        cli.operator_key_hex
            .as_deref()
            .expect("complete group checked"),
        "--service-storeless-bat-v2-operator-key-hex",
    )?;
    let issuer_settlement_verifying_key = decode_verifying_key_v2(
        cli.issuer_settlement_key_hex
            .as_deref()
            .expect("complete group checked"),
        "--service-storeless-bat-v2-issuer-settlement-key-hex",
    )?;
    let minimum_authorization_epoch = cli
        .minimum_authorization_epoch
        .expect("complete group checked");
    if minimum_authorization_epoch == 0 {
        return Err(
            "--service-storeless-bat-v2-minimum-authorization-epoch must be non-zero".to_owned(),
        );
    }

    let clearing_signing_key = match sealed_clearing_signing_key {
        Some(key) => key,
        None => {
            let mut clearing_seed = read_exact_secret_v1::<32>(
                cli.pir1_clearing_key_path
                    .as_deref()
                    .expect("complete group checked"),
                "pir1/local-test plaintext BAT V2 clearing signing key (not pir2 SNP-sealed input)",
            )?;
            let key = SigningKey::from_bytes(&clearing_seed);
            clearing_seed.zeroize();
            key
        }
    };

    authorization
        .verify_for(
            &expected_provider_id,
            &authorization.claims.issuer_id,
            &operator_verifying_key,
            now_unix,
            minimum_authorization_epoch,
        )
        .map_err(|error| format!("BAT V2 accounting authorization is not current: {error}"))?;
    issuer_approval
        .verify_for(
            &authorization,
            &issuer_settlement_verifying_key,
            now_unix,
            minimum_authorization_epoch,
        )
        .map_err(|error| format!("BAT V2 issuer accounting approval is not current: {error}"))?;

    let transport = StrictHttpsBatV2RedeemTransportV2::new(
        authorization.claims.redeem_endpoint.clone(),
        Duration::from_secs(5),
        Duration::from_secs(15),
        &authorization.claims.redeem_leaf_spki_sha256_pins,
    )
    .map_err(|error| format!("BAT V2 strict HTTPS trust is invalid: {error}"))?;

    let classes_by_digest = load_class_registry_v2(cli, &authorization)?;
    let runtime = StorelessBatV2RuntimeConfigV2 {
        classes_by_digest,
        authorization,
        issuer_approval,
        operator_verifying_key,
        issuer_settlement_verifying_key,
        clearing_signing_key,
        minimum_authorization_epoch,
        transport,
    };
    runtime
        .client()
        .map_err(|error| format!("BAT V2 provider clearing trust is invalid: {error}"))?;

    let members = collect_live_policy_members_v2(&policy, &retained_policies, now_unix)?;
    validate_class_registry_coverage_v2(&runtime, &members, now_unix)?;

    if cli.pir1_clearing_key_path.is_some() {
        eprintln!(
            "!!! BAT V2 CLEARING KEY SOURCE IS PLAINTEXT PIR1/LOCAL-TEST INPUT; THIS IS NOT THE PIR2 SNP-SEALED KEY PATH !!!"
        );
    }
    Ok(LoadedStorelessBatV2ProfileV2 {
        policy,
        retained_policies,
        runtime,
    })
}

fn validate_complete_cli_group_v2(
    cli: &StorelessBatV2CliV2,
    sealed_clearing_key: bool,
) -> Result<(), String> {
    if !cli.selected() {
        return Err(
            "storeless BAT V2 configuration requires --service-storeless-bat-v2-policy-digest-hex"
                .to_owned(),
        );
    }
    if cli.class_specs.is_empty()
        || cli.accounting_authorization_path.is_none()
        || cli.issuer_approval_path.is_none()
        || cli.operator_key_hex.is_none()
        || cli.issuer_settlement_key_hex.is_none()
        || cli.minimum_authorization_epoch.is_none()
    {
        return Err(
            "storeless BAT V2 clearing requires current policy digest, at least one digest-pinned class, accounting authorization, issuer approval, operator key, issuer settlement key, pir1/local-test plaintext clearing key, and minimum authorization epoch"
                .to_owned(),
        );
    }
    if sealed_clearing_key == cli.pir1_clearing_key_path.is_some() {
        return Err(
            "storeless BAT V2 requires exactly one clearing-key source: pir1 plaintext path or pir2 sealed injection"
                .to_owned(),
        );
    }
    Ok(())
}

fn load_class_registry_v2(
    cli: &StorelessBatV2CliV2,
    authorization: &ProviderAccountingAuthorizationV2,
) -> Result<BTreeMap<[u8; 32], BatAcceptanceClassV2>, String> {
    let mut classes = BTreeMap::new();
    let mut coordinate_digests = BTreeMap::new();
    let mut terms_by_class_id = BTreeMap::new();
    let mut raw_key_owners = BTreeMap::new();
    let mut key_fingerprint_owners = BTreeMap::new();
    let mut bat_key_id_owners = BTreeMap::new();
    for spec in &cli.class_specs {
        let (expected_digest, path) =
            parse_digest_path_spec_v2(spec, "--service-storeless-bat-v2-class")?;
        let bytes = read_regular_file_bounded_v1(
            &path,
            MAX_BAT_ACCEPTANCE_CLASS_LEN_V2,
            "BAT V2 acceptance class",
        )?;
        let class = BatAcceptanceClassV2::decode(&bytes)
            .map_err(|error| format!("invalid BAT V2 acceptance class: {error}"))?;
        let canonical = class
            .encode()
            .map_err(|error| format!("invalid BAT V2 acceptance class: {error}"))?;
        if canonical != bytes {
            return Err(format!(
                "BAT V2 acceptance class {} is not canonical",
                path.display()
            ));
        }
        class
            .verify()
            .map_err(|error| format!("BAT V2 acceptance class signature is invalid: {error}"))?;
        let computed_digest = class
            .class_digest()
            .map_err(|error| format!("invalid BAT V2 acceptance class digest: {error}"))?;
        if computed_digest != expected_digest {
            return Err(format!(
                "BAT V2 acceptance class {} does not match its exact digest pin",
                path.display()
            ));
        }
        if class.issuer_id != authorization.claims.issuer_id {
            return Err(format!(
                "BAT V2 acceptance class {} belongs to another issuer",
                path.display()
            ));
        }
        if classes.contains_key(&expected_digest) {
            return Err(format!(
                "duplicate BAT V2 acceptance class digest {}",
                hex::encode(expected_digest)
            ));
        }

        let coordinate = (class.issuer_id, class.class_id, class.key_epoch);
        if let Some(existing_digest) = coordinate_digests.get(&coordinate) {
            return Err(format!(
                "BAT V2 acceptance class coordinate ({}, {}, {}) is forked between digests {} and {}",
                hex::encode(class.issuer_id),
                hex::encode(class.class_id),
                class.key_epoch,
                hex::encode(existing_digest),
                hex::encode(expected_digest)
            ));
        }

        let terms_digest = class
            .common_terms
            .terms_digest()
            .map_err(|error| format!("invalid BAT V2 common terms digest: {error}"))?;
        if terms_by_class_id
            .get(&class.class_id)
            .is_some_and(|existing| existing != &terms_digest)
        {
            return Err(format!(
                "BAT V2 acceptance class {} changes common terms across key epochs",
                hex::encode(class.class_id)
            ));
        }

        let key_fingerprint = bat_verification_key_fingerprint_v1(&class.bat_verification_key)
            .map_err(|error| format!("invalid BAT V2 key fingerprint: {error}"))?;
        let bat_key_id = class.bat_key_id();
        if raw_key_owners.contains_key(&class.bat_verification_key)
            || key_fingerprint_owners.contains_key(&key_fingerprint)
            || bat_key_id_owners.contains_key(&bat_key_id)
        {
            return Err(format!(
                "BAT V2 acceptance class ({}, {}, {}) reuses an existing raw key identity",
                hex::encode(class.issuer_id),
                hex::encode(class.class_id),
                class.key_epoch
            ));
        }

        coordinate_digests.insert(coordinate, expected_digest);
        terms_by_class_id.insert(class.class_id, terms_digest);
        raw_key_owners.insert(class.bat_verification_key, coordinate);
        key_fingerprint_owners.insert(key_fingerprint, coordinate);
        bat_key_id_owners.insert(bat_key_id, coordinate);
        // Registry identity is the signed class digest, not class_id.  This
        // permits multiple key epochs for the same class_id only when the
        // signed terms stay fixed and every epoch has a fresh BAT key.
        classes.insert(expected_digest, class);
    }
    Ok(classes)
}

fn collect_live_policy_members_v2(
    policy: &ActivatedServicePolicyV1,
    retained: &BTreeMap<[u8; 32], ActivatedRetainedServicePolicyV1>,
    now_unix: u64,
) -> Result<Vec<VerifiedBatAcceptanceMemberV2>, String> {
    let mut members = Vec::new();
    for scope_policy in &policy.policy().scopes {
        let scope_id = scope_policy.scope.scope_id();
        for offer in &scope_policy.offers {
            if offer.authorization == AuthScheme::BitcoinPirCashuBatV2 {
                members.push(
                    policy
                        .verified_bat_v2_member_for_admission(&scope_id, offer.offer_id, now_unix)
                        .map_err(|error| {
                            format!("current BAT V2 policy member is invalid: {error}")
                        })?,
                );
            }
        }
    }
    for retained_policy in retained.values() {
        for scope_policy in &retained_policy.policy().scopes {
            let scope_id = scope_policy.scope.scope_id();
            for offer in &scope_policy.offers {
                if offer.authorization == AuthScheme::BitcoinPirCashuBatV2 {
                    // One retained policy may contain several signed horizons;
                    // expired members are closed while its remaining live
                    // members continue to redeem.
                    if let Ok(member) = retained_policy.verified_bat_v2_member_for_redemption(
                        &scope_id,
                        offer.offer_id,
                        now_unix,
                    ) {
                        members.push(member);
                    }
                }
            }
        }
    }
    Ok(members)
}

fn validate_class_registry_coverage_v2(
    runtime: &StorelessBatV2RuntimeConfigV2,
    members: &[VerifiedBatAcceptanceMemberV2],
    now_unix: u64,
) -> Result<(), String> {
    for member in members {
        let covered = runtime.classes_by_digest.values().any(|class| {
            verify_bat_acceptance_class_member_projection_v2(class, member).is_ok()
                && class.common_terms.issuer_endpoint
                    == runtime.authorization.claims.redeem_endpoint
                && now_unix >= class.key_not_before
                && now_unix <= class.key_not_after
                && runtime
                    .authorization
                    .rule_for_member(&member.member, &class.class_id)
                    .is_some()
        });
        if !covered {
            return Err(format!(
                "BAT V2 policy member {}:{} has no currently valid digest-pinned class and accounting rule",
                hex::encode(member.member.policy_digest),
                member.member.offer_id
            ));
        }
    }
    for (digest, class) in &runtime.classes_by_digest {
        let referenced = members
            .iter()
            .any(|member| verify_bat_acceptance_class_member_projection_v2(class, member).is_ok());
        if !referenced {
            return Err(format!(
                "BAT V2 class {} has no exact member in the configured current/retained policies",
                hex::encode(digest)
            ));
        }
    }
    Ok(())
}

fn parse_digest_path_spec_v2(spec: &str, flag: &str) -> Result<([u8; 32], PathBuf), String> {
    let (digest_hex, path) = spec
        .split_once('=')
        .ok_or_else(|| format!("{flag} must be <expected-digest-hex>=<path>"))?;
    if path.is_empty() {
        return Err(format!("{flag} path is empty"));
    }
    Ok((
        decode_nonzero_digest_v2(digest_hex, flag)?,
        Path::new(path).to_path_buf(),
    ))
}

fn decode_nonzero_digest_v2(input: &str, label: &str) -> Result<[u8; 32], String> {
    let digest = decode_fixed_hex_v1::<32>(input, label)?;
    if digest.iter().all(|byte| *byte == 0) {
        return Err(format!("{label} digest must not be all zero"));
    }
    Ok(digest)
}

fn decode_verifying_key_v2(input: &str, label: &str) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(&decode_fixed_hex_v1::<32>(input, label)?)
        .map_err(|_| format!("{label} is not a valid Ed25519 public key"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pir_service_protocol::{
        derive_issuer_id, AcquisitionMethod, AuthPaddingClassV1, BackendId, BatAcceptanceMemberV2,
        BatAcceptanceTermsV2, DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, FreeModeV1,
        PriceV1, PrivacyLeakageV1, ProviderAccountingAuthorizationClaimsV2,
        ProviderAccountingRuleV2, ServiceOfferV1, ServicePolicyV1, ServiceScopePolicyV1,
        ServiceScopeV1, SettlementUnitV1, VerificationMode, WorkloadId,
    };

    #[test]
    fn digest_path_specs_are_exact_and_nonzero() {
        let digest = [7; 32];
        let spec = format!("{}=/tmp/class.bin", hex::encode(digest));
        assert_eq!(
            parse_digest_path_spec_v2(&spec, "--class").unwrap(),
            (digest, PathBuf::from("/tmp/class.bin"))
        );
        assert!(parse_digest_path_spec_v2("missing-separator", "--class").is_err());
        assert!(parse_digest_path_spec_v2(
            &format!("{}=/tmp/class.bin", hex::encode([0; 32])),
            "--class"
        )
        .is_err());
    }

    #[test]
    fn partial_profile_never_silently_falls_back() {
        let mut cli = StorelessBatV2CliV2::default();
        cli.class_specs
            .push(format!("{}=/tmp/class.bin", hex::encode([1; 32])));
        assert!(cli.any_configured());
        assert!(!cli.selected());
        assert!(validate_complete_cli_group_v2(&cli, false).is_err());
    }

    #[test]
    fn class_registry_enforces_lineage_and_allows_fresh_key_epochs() {
        let issuer_key = SigningKey::from_bytes(&[8; 32]);
        let operator_key = SigningKey::from_bytes(&[11; 32]);
        let clearing_key = SigningKey::from_bytes(&[6; 32]);
        let class_id = [7; 32];
        let member = BatAcceptanceMemberV2 {
            provider_id: [2; 32],
            policy_digest: [3; 32],
            scope_id: [4; 32],
            offer_id: 5,
        };
        let terms = test_terms_v2();
        let point_epoch_1 = test_bat_key_v2(1);
        let point_epoch_2 = test_bat_key_v2(2);
        let class_epoch_1 = BatAcceptanceClassV2::sign(
            class_id,
            1,
            100,
            1_000,
            point_epoch_1,
            terms.clone(),
            vec![member.clone()],
            &issuer_key,
        )
        .unwrap();
        let class_epoch_2 = BatAcceptanceClassV2::sign(
            class_id,
            2,
            100,
            1_000,
            point_epoch_2,
            terms.clone(),
            vec![member.clone()],
            &issuer_key,
        )
        .unwrap();
        let coordinate_fork = BatAcceptanceClassV2::sign(
            class_id,
            1,
            100,
            1_000,
            point_epoch_2,
            terms.clone(),
            vec![member.clone()],
            &issuer_key,
        )
        .unwrap();
        let raw_key_reuse = BatAcceptanceClassV2::sign(
            class_id,
            3,
            100,
            1_000,
            point_epoch_1,
            terms.clone(),
            vec![member.clone()],
            &issuer_key,
        )
        .unwrap();
        let mut changed_terms = terms;
        changed_terms.price_msat += 1;
        let terms_drift = BatAcceptanceClassV2::sign(
            class_id,
            3,
            100,
            1_000,
            point_epoch_2,
            changed_terms,
            vec![member.clone()],
            &issuer_key,
        )
        .unwrap();
        let authorization = ProviderAccountingAuthorizationV2::sign(
            ProviderAccountingAuthorizationClaimsV2 {
                authorization_id: [9; 16],
                authorization_epoch: 1,
                provider_id: member.provider_id,
                issuer_id: class_epoch_1.issuer_id,
                redeem_endpoint: "https://issuer.invalid".to_owned(),
                redeem_leaf_spki_sha256_pins: vec![[10; 32]],
                settlement_account_id: [12; 32],
                clearing_verifying_key: clearing_key.verifying_key().to_bytes(),
                not_before: 100,
                not_after: 1_000,
                rules: vec![ProviderAccountingRuleV2 {
                    class_id,
                    policy_digest: member.policy_digest,
                    scope_id: member.scope_id,
                    offer_id: member.offer_id,
                    unit: SettlementUnitV1::AuthCredit,
                    accepted_value: 10,
                    provider_credit: 8,
                    issuer_fee: 2,
                }],
            },
            &operator_key,
        )
        .unwrap();

        let root = tempfile::tempdir().unwrap();
        let path_1 = root.path().join("class-epoch-1.bin");
        let path_2 = root.path().join("class-epoch-2.bin");
        let fork_path = root.path().join("class-epoch-1-fork.bin");
        let reuse_path = root.path().join("class-epoch-3-reused-key.bin");
        let drift_path = root.path().join("class-epoch-3-drifted-terms.bin");
        std::fs::write(&path_1, class_epoch_1.encode().unwrap()).unwrap();
        std::fs::write(&path_2, class_epoch_2.encode().unwrap()).unwrap();
        std::fs::write(&fork_path, coordinate_fork.encode().unwrap()).unwrap();
        std::fs::write(&reuse_path, raw_key_reuse.encode().unwrap()).unwrap();
        std::fs::write(&drift_path, terms_drift.encode().unwrap()).unwrap();
        let digest_1 = class_epoch_1.class_digest().unwrap();
        let digest_2 = class_epoch_2.class_digest().unwrap();
        let fork_digest = coordinate_fork.class_digest().unwrap();
        let reuse_digest = raw_key_reuse.class_digest().unwrap();
        let drift_digest = terms_drift.class_digest().unwrap();
        assert_ne!(digest_1, digest_2);

        let mut cli = StorelessBatV2CliV2::default();
        cli.class_specs = vec![
            format!("{}={}", hex::encode(digest_1), path_1.display()),
            format!("{}={}", hex::encode(digest_2), path_2.display()),
        ];
        let registry = load_class_registry_v2(&cli, &authorization).unwrap();
        assert_eq!(registry.len(), 2);
        assert_eq!(registry.get(&digest_1).unwrap().class_id, class_id);
        assert_eq!(registry.get(&digest_2).unwrap().class_id, class_id);
        assert_eq!(registry.get(&digest_1).unwrap().key_epoch, 1);
        assert_eq!(registry.get(&digest_2).unwrap().key_epoch, 2);

        cli.class_specs = vec![
            format!("{}={}", hex::encode(digest_1), path_1.display()),
            format!("{}={}", hex::encode(fork_digest), fork_path.display()),
        ];
        assert!(load_class_registry_v2(&cli, &authorization)
            .unwrap_err()
            .contains("coordinate"));

        cli.class_specs = vec![
            format!("{}={}", hex::encode(digest_1), path_1.display()),
            format!("{}={}", hex::encode(reuse_digest), reuse_path.display()),
        ];
        assert!(load_class_registry_v2(&cli, &authorization)
            .unwrap_err()
            .contains("raw key identity"));

        cli.class_specs = vec![
            format!("{}={}", hex::encode(digest_1), path_1.display()),
            format!("{}={}", hex::encode(drift_digest), drift_path.display()),
        ];
        assert!(load_class_registry_v2(&cli, &authorization)
            .unwrap_err()
            .contains("changes common terms"));

        cli.class_specs = vec![
            format!("{}={}", hex::encode(digest_1), path_1.display()),
            format!("{}={}", hex::encode(digest_2), path_2.display()),
        ];
        cli.class_specs[0] = format!("{}={}", hex::encode([13; 32]), path_1.display());
        assert!(load_class_registry_v2(&cli, &authorization).is_err());
    }

    #[test]
    fn complete_closed_profile_loads_without_provider_state() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let provider_id = [2; 32];
        let policy_key = SigningKey::from_bytes(&[3; 32]);
        let issuer_key = SigningKey::from_bytes(&[8; 32]);
        let operator_key = SigningKey::from_bytes(&[11; 32]);
        let settlement_key = SigningKey::from_bytes(&[24; 32]);
        let clearing_key = SigningKey::from_bytes(&[6; 32]);
        let class_id = [7; 32];
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 2,
        };
        let scope_id = scope.scope_id();
        let limits = test_limits_v2();
        let privacy = test_privacy_v2();
        let policy = ServicePolicyV1::sign(
            provider_id,
            8,
            100,
            1_000,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits,
                offers: vec![
                    ServiceOfferV1 {
                        offer_id: 1,
                        acquisition: AcquisitionMethod::FreeV1,
                        free_mode: FreeModeV1::ProofOfWork,
                        free_quota: 0,
                        free_window_seconds: 0,
                        free_pow_difficulty_bits: 8,
                        priority_class: 1,
                        authorization: AuthScheme::FreeV1,
                        verification: VerificationMode::ProviderLocal,
                        deployment_status: DeploymentStatus::Stable,
                        price: PriceV1::Free,
                        issuer_id: [0; 32],
                        key_id: Vec::new(),
                        credential_binding: None,
                        cashu_mint_manifest: None,
                        endpoint: String::new(),
                        invoice_expiry_seconds: 0,
                        claim_window_seconds: 0,
                        minimum_credential_validity_seconds: 1,
                        retired_policy_grace_seconds: 0,
                        credential_count: 1,
                        credential_presentation_limit: 1,
                        privacy_leakage: PrivacyLeakageV1::NONE,
                    },
                    ServiceOfferV1 {
                        offer_id: 2,
                        acquisition: AcquisitionMethod::Bolt11V1,
                        free_mode: FreeModeV1::NotFree,
                        free_quota: 0,
                        free_window_seconds: 0,
                        free_pow_difficulty_bits: 0,
                        priority_class: 1,
                        authorization: AuthScheme::BitcoinPirCashuBatV2,
                        verification: VerificationMode::SharedIssuerOnline,
                        deployment_status: DeploymentStatus::Stable,
                        price: PriceV1::MilliSatoshi(2_000),
                        issuer_id: derive_issuer_id(&issuer_key.verifying_key().to_bytes()),
                        key_id: class_id.to_vec(),
                        credential_binding: None,
                        cashu_mint_manifest: None,
                        endpoint: "https://issuer.invalid".to_owned(),
                        invoice_expiry_seconds: 60,
                        claim_window_seconds: 120,
                        minimum_credential_validity_seconds: 300,
                        retired_policy_grace_seconds: 480,
                        credential_count: 2,
                        credential_presentation_limit: 1,
                        privacy_leakage: privacy,
                    },
                ],
            }],
            &policy_key,
        )
        .unwrap();
        let policy_digest = policy.policy_digest().unwrap();
        let member = BatAcceptanceMemberV2 {
            provider_id,
            policy_digest,
            scope_id,
            offer_id: 2,
        };
        let point: [u8; 33] =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap();
        let class = BatAcceptanceClassV2::sign(
            class_id,
            13,
            100,
            1_480,
            point,
            test_terms_v2(),
            vec![member.clone()],
            &issuer_key,
        )
        .unwrap();
        let class_digest = class.class_digest().unwrap();
        let authorization = ProviderAccountingAuthorizationV2::sign(
            ProviderAccountingAuthorizationClaimsV2 {
                authorization_id: [9; 16],
                authorization_epoch: 7,
                provider_id,
                issuer_id: class.issuer_id,
                redeem_endpoint: "https://issuer.invalid".to_owned(),
                redeem_leaf_spki_sha256_pins: vec![[10; 32]],
                settlement_account_id: [12; 32],
                clearing_verifying_key: clearing_key.verifying_key().to_bytes(),
                not_before: 100,
                not_after: 1_400,
                rules: vec![ProviderAccountingRuleV2 {
                    class_id,
                    policy_digest,
                    scope_id,
                    offer_id: 2,
                    unit: SettlementUnitV1::AuthCredit,
                    accepted_value: 10,
                    provider_credit: 8,
                    issuer_fee: 2,
                }],
            },
            &operator_key,
        )
        .unwrap();
        let approval =
            IssuerAccountingApprovalV2::sign(&authorization, 100, 1_300, &settlement_key).unwrap();

        let class_path = root.path().join("class.bin");
        let authorization_path = root.path().join("accounting.bin");
        let approval_path = root.path().join("approval.bin");
        let clearing_path = root.path().join("clearing.key");
        std::fs::write(&class_path, class.encode().unwrap()).unwrap();
        std::fs::write(&authorization_path, authorization.encode().unwrap()).unwrap();
        std::fs::write(&approval_path, approval.encode()).unwrap();
        std::fs::write(&clearing_path, clearing_key.to_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&clearing_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }

        let cli = StorelessBatV2CliV2 {
            current_policy_digest_hex: Some(hex::encode(policy_digest)),
            retained_policy_specs: Vec::new(),
            class_specs: vec![format!(
                "{}={}",
                hex::encode(class_digest),
                class_path.display()
            )],
            accounting_authorization_path: Some(authorization_path),
            issuer_approval_path: Some(approval_path),
            operator_key_hex: Some(hex::encode(operator_key.verifying_key().to_bytes())),
            issuer_settlement_key_hex: Some(hex::encode(settlement_key.verifying_key().to_bytes())),
            pir1_clearing_key_path: Some(clearing_path),
            minimum_authorization_epoch: Some(7),
        };
        let loaded = load_storeless_bat_v2_profile_v2(
            &cli,
            &policy.encode().unwrap(),
            provider_id,
            policy_key.verifying_key(),
            150,
            None,
        )
        .unwrap();
        assert_eq!(loaded.policy.policy_digest(), policy_digest);
        assert!(loaded.retained_policies.is_empty());
        assert_eq!(
            loaded
                .runtime
                .class_for_digest(&class_digest)
                .unwrap()
                .key_epoch,
            13
        );
        assert!(loaded.runtime.client().is_ok());

        assert!(load_storeless_bat_v2_profile_v2(
            &cli,
            &policy.encode().unwrap(),
            provider_id,
            policy_key.verifying_key(),
            150,
            Some(SealedStorelessBatV2InputsV2 {
                clearing_signing_key: clearing_key.clone(),
                authorization: authorization.clone(),
                issuer_approval: approval.clone(),
            }),
        )
        .is_err());

        let mut sealed_cli = cli;
        sealed_cli.pir1_clearing_key_path = None;
        let sealed_loaded = load_storeless_bat_v2_profile_v2(
            &sealed_cli,
            &policy.encode().unwrap(),
            provider_id,
            policy_key.verifying_key(),
            150,
            Some(SealedStorelessBatV2InputsV2 {
                clearing_signing_key: clearing_key,
                authorization,
                issuer_approval: approval,
            }),
        )
        .unwrap();
        assert!(sealed_loaded.runtime.client().is_ok());
    }

    fn test_terms_v2() -> BatAcceptanceTermsV2 {
        BatAcceptanceTermsV2 {
            auth_padding_class: AuthPaddingClassV1::Class16KiB,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 2,
            limits: test_limits_v2(),
            priority_class: 1,
            deployment_status: DeploymentStatus::Stable,
            price_msat: 2_000,
            issuer_endpoint: "https://issuer.invalid".to_owned(),
            invoice_expiry_seconds: 60,
            claim_window_seconds: 120,
            minimum_credential_validity_seconds: 300,
            retired_policy_grace_seconds: 480,
            credential_count: 2,
            credential_presentation_limit: 1,
            privacy_leakage: test_privacy_v2(),
        }
    }

    fn test_limits_v2() -> EntitlementLimitsV1 {
        EntitlementLimitsV1 {
            max_logical_inputs: 4,
            max_frames: 200,
            max_request_bytes: 1_000_000,
            max_response_bytes: 2_000_000,
            max_wall_time_ms: 60_000,
            max_concurrent_sockets: 1,
            max_hint_groups: 0,
            max_work_units: 9_000,
        }
    }

    fn test_privacy_v2() -> PrivacyLeakageV1 {
        PrivacyLeakageV1::from_bits(
            PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
        )
        .unwrap()
    }

    fn test_bat_key_v2(multiplier: u8) -> [u8; 33] {
        let encoded = match multiplier {
            1 => "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            2 => "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            _ => panic!("unsupported BAT test-key multiplier"),
        };
        hex::decode(encoded).unwrap().try_into().unwrap()
    }
}
