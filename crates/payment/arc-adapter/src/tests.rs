use std::collections::HashMap;

use arc::group::serialize_scalar;
use arc::{make_presentation_state, present, setup_server};
use ed25519_dalek::SigningKey;
#[cfg(feature = "provider-store")]
use pir_service_protocol::{
    bind_auth_begin_v1, AcquisitionMethod, ArcPresentationV1, AuthBeginV1, AuthPaddingClassV1,
    BackendId, BoundAuthAttemptV1, DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1,
    FreeModeV1, OperationStartV1, PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1,
    ServicePolicyEpochFloorsV1, ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1,
    TrustedCatalogResolutionV1, VerificationMode, VerifiedServiceOfferV1, WorkloadId,
};
use pir_service_protocol::{
    ArcPresentationCanonicalizerV1 as ProtocolArcPresentationCanonicalizerV1, AuthScheme,
    CredentialKeyBindingClaimsV1, CredentialUnitV1,
};
#[cfg(feature = "provider-store")]
use pir_service_store::{
    verify_provider_local_arc_spend_v1, ProviderStore, StoreError, StoreOptions,
    VerifiedOfferNamespaceInstallOutcomeV1,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use super::*;

const NOW: u64 = 1_500;
struct Fixture {
    binding: CredentialKeyBindingV1,
    keyring: ArcSecretKeyringV1,
}

impl Fixture {
    fn new(limit: u32, seed: u8) -> Self {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let (secret, public) = setup_server(&mut rng);
        let mut secret_bytes = Zeroizing::new([0u8; ARC_SECRET_KEY_LEN_V1]);
        secret_bytes[0..32].copy_from_slice(&serialize_scalar(&secret.x0));
        secret_bytes[32..64].copy_from_slice(&serialize_scalar(&secret.x1));
        secret_bytes[64..96].copy_from_slice(&serialize_scalar(&secret.x2));
        secret_bytes[96..128].copy_from_slice(&serialize_scalar(&secret.x0_blinding));
        let key_id = vec![seed; 16];
        let key = ArcSecretKeyV1::from_zeroizing_bytes(key_id.clone(), secret_bytes).unwrap();
        assert_eq!(key.public_key_bytes(), &public.to_bytes());
        let issuer_key = SigningKey::from_bytes(&[7; 32]);
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id: [2; 32],
                scope_id: [4; 32],
                offer_id: 9,
                scheme: AuthScheme::ArcV1Experimental,
                keyset_epoch: 1,
                entitlement_profile: 3,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: limit,
                not_before: 900,
                not_after: 3_000,
                credential_key_id: key_id,
                verification_key: public.to_bytes().to_vec(),
            },
            &issuer_key,
        )
        .unwrap();
        Self {
            binding,
            keyring: ArcSecretKeyringV1::new(vec![key]).unwrap(),
        }
    }

    fn expectation(&self) -> CredentialKeyBindingExpectationV1<'_> {
        expectation_for(&self.binding)
    }

    fn issue_unpersisted(&self, rng: &mut ChaCha20Rng) -> UnpersistedArcClientCredentialV1 {
        let (request, pending) =
            create_arc_credential_request(&self.binding, &self.expectation(), NOW, rng).unwrap();
        let response = self
            .keyring
            .issue_credential_response(&self.binding, &self.expectation(), NOW, &request, rng)
            .unwrap();
        pending
            .finalize_response(&self.binding, &self.expectation(), NOW, &response)
            .unwrap()
    }
}

#[cfg(feature = "provider-store")]
#[cfg(feature = "provider-store")]
#[cfg(feature = "provider-store")]
struct ProviderArcFixtureV1 {
    policy: ServicePolicyV1,
    policy_verifying_key: ed25519_dalek::VerifyingKey,
    keyring: ArcSecretKeyringV1,
}

#[cfg(feature = "provider-store")]
impl ProviderArcFixtureV1 {
    fn new(seed: u8) -> Self {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let (secret, public) = setup_server(&mut rng);
        let mut secret_bytes = Zeroizing::new([0u8; ARC_SECRET_KEY_LEN_V1]);
        secret_bytes[0..32].copy_from_slice(&serialize_scalar(&secret.x0));
        secret_bytes[32..64].copy_from_slice(&serialize_scalar(&secret.x1));
        secret_bytes[64..96].copy_from_slice(&serialize_scalar(&secret.x2));
        secret_bytes[96..128].copy_from_slice(&serialize_scalar(&secret.x0_blinding));
        let key_id = vec![seed; 16];
        let key = ArcSecretKeyV1::from_zeroizing_bytes(key_id.clone(), secret_bytes).unwrap();
        let scope = ServiceScopeV1 {
            provider_id: [2; 32],
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 7 },
            operation_profile: 9,
            entitlement_profile: 3,
        };
        let issuer_key = SigningKey::from_bytes(&[7; 32]);
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id: scope.provider_id,
                scope_id: scope.scope_id(),
                offer_id: 9,
                scheme: AuthScheme::ArcV1Experimental,
                keyset_epoch: 1,
                entitlement_profile: scope.entitlement_profile,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 4,
                not_before: 900,
                not_after: 3_000,
                credential_key_id: key_id.clone(),
                verification_key: public.to_bytes().to_vec(),
            },
            &issuer_key,
        )
        .unwrap();
        let offer = ServiceOfferV1 {
            offer_id: 9,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::ArcV1Experimental,
            verification: VerificationMode::ProviderLocal,
            deployment_status: DeploymentStatus::Experimental,
            price: PriceV1::MilliSatoshi(2_000),
            issuer_id: binding.issuer_id,
            key_id,
            credential_binding: Some(binding),
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".into(),
            invoice_expiry_seconds: 10,
            claim_window_seconds: 20,
            minimum_credential_validity_seconds: 30,
            retired_policy_grace_seconds: 1_000,
            credential_count: 1,
            credential_presentation_limit: 4,
            privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::KNOWN_MASK).unwrap(),
        };
        let limits = EntitlementLimitsV1 {
            max_logical_inputs: 1,
            max_frames: 8,
            max_request_bytes: 1_000_000,
            max_response_bytes: 2_000_000,
            max_wall_time_ms: 60_000,
            max_concurrent_sockets: 1,
            max_hint_groups: 0,
            max_work_units: 9_000,
        };
        let policy_key = SigningKey::from_bytes(&[0x21; 32]);
        let policy_verifying_key = policy_key.verifying_key();
        let policy = ServicePolicyV1::sign(
            scope.provider_id,
            1,
            1_000,
            2_000,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits,
                offers: vec![offer],
            }],
            &policy_key,
        )
        .unwrap();
        Self {
            policy,
            policy_verifying_key,
            keyring: ArcSecretKeyringV1::new(vec![key]).unwrap(),
        }
    }

    fn verified_offer(&self) -> VerifiedServiceOfferV1<'_> {
        let verified_policy = self
            .policy
            .verify_current_for_acquisition(
                &self.policy.provider_id,
                NOW,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::default(),
                &self.policy_verifying_key,
            )
            .unwrap();
        let scope = &self.policy.scopes[0].scope;
        verified_policy.offer(&scope.scope_id(), 9).unwrap()
    }

    fn issue_ready_presentation(&self, seed: u8) -> ArcPresentationV1 {
        let binding = self.policy.scopes[0].offers[0]
            .credential_binding
            .as_ref()
            .unwrap();
        let expectation = expectation_for(binding);
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let (request, pending) =
            create_arc_credential_request(binding, &expectation, NOW, &mut rng).unwrap();
        let response = self
            .keyring
            .issue_credential_response(binding, &expectation, NOW, &request, &mut rng)
            .unwrap();
        let unpersisted = pending
            .finalize_response(binding, &expectation, NOW, &response)
            .unwrap();
        let mut client_store = MemoryStore::default();
        let client = unpersisted.persist_initial(&mut client_store).unwrap();
        let awaiting_persistence = client.prepare_presentation(&mut rng).unwrap();
        let (_, ready) = awaiting_persistence
            .persist_successor(&mut client_store)
            .unwrap();
        ready.into_presentation()
    }

    fn bind_presentation(&self, presentation: ArcPresentationV1) -> BoundAuthAttemptV1<'_> {
        let verified_offer = self.verified_offer();
        let offer = verified_offer.offer();
        let scope = verified_offer.scope().clone();
        let request = AuthBeginV1 {
            policy_digest: verified_offer.policy_digest(),
            scope_id: scope.scope_id(),
            offer_id: offer.offer_id,
            scheme: AuthScheme::ArcV1Experimental,
            key_id: offer.key_id.clone(),
            operation: OperationStartV1::DpfQuery { db_id: 7 },
            proof: presentation.encode().unwrap(),
        };
        let catalog = |_operation: &OperationStartV1| {
            Some(TrustedCatalogResolutionV1::new(
                7,
                scope.backend,
                scope.workload,
                scope.protocol_version,
                scope.dataset.clone(),
                scope.operation_profile,
            ))
        };
        let binding = offer.credential_binding.as_ref().unwrap();
        let canonicalizer = ArcPresentationCanonicalizerV1::from_verified_binding(
            binding,
            &expectation_for(binding),
            NOW,
        )
        .unwrap();
        bind_auth_begin_v1(&request, verified_offer, &catalog, Some(&canonicalizer)).unwrap()
    }

    fn create_provider_store(&self, path: &std::path::Path, instance_byte: u8) -> ProviderStore {
        ProviderStore::create(
            path,
            [instance_byte; 16],
            self.policy.provider_id,
            StoreOptions::default(),
        )
        .unwrap()
    }
}

fn expectation_for(binding: &CredentialKeyBindingV1) -> CredentialKeyBindingExpectationV1<'_> {
    CredentialKeyBindingExpectationV1 {
        issuer_id: &binding.issuer_id,
        provider_id: &binding.claims.provider_id,
        scope_id: &binding.claims.scope_id,
        offer_id: binding.claims.offer_id,
        scheme: AuthScheme::ArcV1Experimental,
        minimum_keyset_epoch: binding.claims.keyset_epoch,
        entitlement_profile: binding.claims.entitlement_profile,
        presentation_limit: binding.claims.presentation_limit,
        credential_key_id: &binding.claims.credential_key_id,
    }
}

#[cfg(feature = "provider-store")]
fn private_provider_tempdir(prefix: &str) -> tempfile::TempDir {
    let directory = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory
}

fn raw_credential(fixture: &Fixture, request_context: &[u8], rng: &mut ChaCha20Rng) -> Credential {
    let (secrets, typed_request) = arc::create_credential_request(request_context, rng).unwrap();
    let request = ArcCredentialRequestV1::decode_canonical(
        &typed_request.to_bytes(),
        &ArcIssuanceCanonicalizerV1,
    )
    .unwrap();
    let response = fixture
        .keyring
        .issue_credential_response(&fixture.binding, &fixture.expectation(), NOW, &request, rng)
        .unwrap();
    let typed_response = CredentialResponse::from_bytes(response.as_bytes()).unwrap();
    let facts = verify_binding(&fixture.binding, &fixture.expectation(), NOW).unwrap();
    finalize_credential(&secrets, &facts.public_key, &typed_request, &typed_response).unwrap()
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MemoryStoreError {
    AlreadyExists,
    Missing,
    CompareAndSwap,
    Injected,
}

#[test]
fn draft_01_working_group_wire_vectors_decode_and_reencode() {
    // draft-ietf-privacypass-arc-crypto-01 section 10.2 / WG PoC
    // allVectors.json. These are the exact request, response, and first
    // presentation bytes, not values generated by this implementation.
    let request = hex::decode(concat!(
        "033fe5d950712f711e5d292d68f804fad4c35fb7f3f1866516448647d4aab12590",
        "026502a833ed1d972ee27175e750b1719adee12726c653125887c0d32b1f3747ab",
        "2a088673e302502a3dc80d6100a1bb709083ac7b31da34f9a7c52e7cfeaa2ea3",
        "0b7341133086e64b79dfc6cdac9f348ddbed0b087746f0167ea238d3ddf17e61",
        "3880b73e85f499c7eddc6555355ea71487b49862400091b5b32cb219d7104f57",
        "1306bc6f2487bab299bb2e9a1078dee94d83b6536ed570f8114ee9c97b8b602b",
        "facbeb3764f6a22915a19c24895a6bf7048c663337f7690f0182a1f866586d9e",
    ))
    .unwrap();
    let response = hex::decode(concat!(
        "021cf52318c97c33472cc8fb42a5b5a774f83c3b36e6c782209d53e5945d99a493",
        "02ae23020d5427c7f785a72d77c24997f955e66ab7c378c334b7c259dabdf572d7",
        "031523abe64e436e65e592abdae322dc556fcbea707757e18d4160ba57d574cd87",
        "023cc3b53807f6e0082b675794ae9f6b370483ca5a3e6d688c3b81f2fdb6d4ec00",
        "0329dc7c93f8a231a1f16ec69f0fba446e022ce69945b20f37386a7fda3e573b79",
        "0389746891b6dbf062511619eae7d72ae87630bea1e277a925708fdfef8363a1d4",
        "ec342aee0d481435379ea6bbe919edd5d2eb9c12198a083e0e899da1f14dbc46",
        "a8048f5a12c5cae21e5f5949fe08d1c15c266c63544615400def4ce9a6cf8aee",
        "32052ced26e7a9d854f2c45ea23ffea0f6bf977f6155d412991abc0e2d1ad835",
        "04129c1ac8319b2a45940c52c4b41bde80969313641b9cb727445e20b44d0ea8",
        "84e9b180cd152442883038b97d72772201f281d76a18d22e374bd989accd7654",
        "8067399162428c4d25daf1b7f68f3580a38cc4564a88f28494649064500f06c5",
        "b946dde032a389f8fe337605627ce91a92c20db911100a2c7c42ae15fde5a5cb",
        "d9d078b819a80423593192c40d70ce77f1a6d377770fe5c05781782bd1eaa43f",
    ))
    .unwrap();
    let presentation = hex::decode(concat!(
        "0216af8901c1ad38a703bf9003fabea440b411b4f072fd23b5254cb17d1b5bf33d",
        "03140f8e6f6c5eab3d03a7fba5d542362a9bc00a89d80caa5051b4e4446b0b01f3",
        "0214d0297c21120d621cc6fed75852569de3cbf0bd9f5a8a812cf6b024bf51e627",
        "0281428e61688f4e7989dbe8dab170705c81b294c4a73b785a0754712fc968eb40",
        "032326abcd4eb2fd1a47053ec9ce1aab3ee91e98373d610e9752a7d16a5c1e38d8",
        "032326abcd4eb2fd1a47053ec9ce1aab3ee91e98373d610e9752a7d16a5c1e38d8",
        "946f5f0b44e34f826b41ec59a4e2dcfaa826b8a39cc278e10b1b02b5dbaafdb6",
        "e789639885a8d2d69269a9fea55830f1d7e1fd0a771183b7b4eebe5e03e0c025",
        "5d1ba614de7e31d4f46eb93a24e0ffe9864b002527109a516a10dc1ad718b8d9",
        "84efd16ab245d7a5dfabe2d0027e23796981422b19c2821a831cb46a8e9b8b56",
        "6bbdb55b649021bf2f777b9130c2e375f560eee4691d04bd38e9571d94512578",
        "58d9128002a2f8908d7e4521510a2185244fa533e2502b61e502fd157d974f91",
        "acc4f2ba0d724f2bfd182d5df4d038e74b5c35cc7c4aa7622c2682e040877eeb",
        "cc18fe822cc6abab5d3adc9db836991d3d1ecf699658245b8b0756946ba0d775",
        "6b433aae3b476ccbc2186b2fe2ecc2fe0da30df264802829254df8196a8307f0",
    ))
    .unwrap();

    let issuance_codec = ArcIssuanceCanonicalizerV1;
    assert_eq!(
        issuance_codec
            .decode_and_reencode_request(&request)
            .unwrap(),
        request
    );
    assert_eq!(
        issuance_codec
            .decode_and_reencode_response(&response)
            .unwrap(),
        response
    );
    let fixture = Fixture::new(2, 10);
    let presentation_codec = ArcPresentationCanonicalizerV1::from_verified_binding(
        &fixture.binding,
        &fixture.expectation(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        presentation_codec
            .decode_and_reencode(&presentation)
            .unwrap(),
        presentation
    );
}

#[derive(Default)]
struct MemoryStore {
    current: HashMap<[u8; 32], ([u8; 32], Vec<u8>)>,
    cas_calls: usize,
    fail_next_cas: bool,
}

impl ArcClientStateStoreV1 for MemoryStore {
    type Error = MemoryStoreError;

    fn persist_initial(
        &mut self,
        credential_id: &[u8; 32],
        state_digest: &[u8; 32],
        encoded_state: &[u8],
    ) -> Result<(), Self::Error> {
        if self.current.contains_key(credential_id) {
            return Err(MemoryStoreError::AlreadyExists);
        }
        self.current
            .insert(*credential_id, (*state_digest, encoded_state.to_vec()));
        Ok(())
    }

    fn compare_and_swap_successor(
        &mut self,
        credential_id: &[u8; 32],
        expected_state_digest: &[u8; 32],
        successor_state_digest: &[u8; 32],
        encoded_successor_state: &[u8],
    ) -> Result<(), Self::Error> {
        self.cas_calls += 1;
        if self.fail_next_cas {
            self.fail_next_cas = false;
            return Err(MemoryStoreError::Injected);
        }
        let current = self
            .current
            .get_mut(credential_id)
            .ok_or(MemoryStoreError::Missing)?;
        if &current.0 != expected_state_digest {
            return Err(MemoryStoreError::CompareAndSwap);
        }
        *current = (*successor_state_digest, encoded_successor_state.to_vec());
        Ok(())
    }

    fn load_current(
        &mut self,
        credential_id: &[u8; 32],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(self
            .current
            .get(credential_id)
            .map(|(_, bytes)| Zeroizing::new(bytes.clone())))
    }
}

impl core::fmt::Display for MemoryStoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[test]
fn issuance_canonicalizers_are_typed_and_strict() {
    let fixture = Fixture::new(4, 11);
    let mut rng = ChaCha20Rng::from_seed([21; 32]);
    let (request, pending) =
        create_arc_credential_request(&fixture.binding, &fixture.expectation(), NOW, &mut rng)
            .unwrap();
    let response = fixture
        .keyring
        .issue_credential_response(
            &fixture.binding,
            &fixture.expectation(),
            NOW,
            &request,
            &mut rng,
        )
        .unwrap();
    let codec = ArcIssuanceCanonicalizerV1;
    assert_eq!(
        codec
            .decode_and_reencode_request(request.as_bytes())
            .unwrap(),
        request.as_bytes()
    );
    assert_eq!(
        codec
            .decode_and_reencode_response(response.as_bytes())
            .unwrap(),
        response.as_bytes()
    );

    let mut bad_request = *request.as_bytes();
    bad_request[0] = 0;
    assert!(codec.decode_and_reencode_request(&bad_request).is_err());
    let mut bad_response = *response.as_bytes();
    bad_response[0] = 0;
    assert!(codec.decode_and_reencode_response(&bad_response).is_err());

    let stored_pending = pending.encode_for_encrypted_storage().unwrap();
    let (restored_request, restored_pending) = restore_arc_credential_request(
        &fixture.binding,
        &fixture.expectation(),
        NOW,
        &stored_pending,
    )
    .unwrap();
    assert_eq!(restored_request, request);
    assert_eq!(
        restored_pending.encode_for_encrypted_storage().unwrap(),
        stored_pending
    );
    let mut tampered = stored_pending.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        restore_arc_credential_request(&fixture.binding, &fixture.expectation(), NOW, &tampered,),
        Err(ArcAdapterErrorV1::InvalidClientState)
    ));
}

#[test]
fn issue_finalize_persist_present_verify_and_exact_replay_tag() {
    let fixture = Fixture::new(4, 12);
    let mut rng = ChaCha20Rng::from_seed([22; 32]);
    let initial = fixture.issue_unpersisted(&mut rng);
    let credential_id = *initial.credential_id();
    let mut store = MemoryStore::default();
    let current = initial.persist_initial(&mut store).unwrap();
    assert_eq!(current.remaining_presentations(), 4);

    let prepared = current.prepare_presentation(&mut rng).unwrap();
    let (current, ready) = prepared.persist_successor(&mut store).unwrap();
    assert_eq!(current.remaining_presentations(), 3);
    let presentation = ready.into_presentation();
    let first = fixture
        .keyring
        .verify_presentation(&fixture.binding, &fixture.expectation(), NOW, &presentation)
        .unwrap();
    let replay = fixture
        .keyring
        .verify_presentation(&fixture.binding, &fixture.expectation(), NOW, &presentation)
        .unwrap();
    assert_eq!(first.canonical_tag(), replay.canonical_tag());
    assert_eq!(first.spend_key(), replay.spend_key());
    assert_eq!(
        first.binding_digest(),
        &fixture.binding.binding_digest().unwrap()
    );

    let restored = ArcClientCredentialV1::load_current(
        &mut store,
        credential_id,
        &fixture.binding,
        &fixture.expectation(),
        NOW,
    )
    .unwrap()
    .unwrap();
    assert_eq!(restored.remaining_presentations(), 3);
}

#[test]
fn sequential_nonces_have_distinct_tags_and_store_cas_serializes_tabs() {
    let fixture = Fixture::new(4, 13);
    let mut rng = ChaCha20Rng::from_seed([23; 32]);
    let initial = fixture.issue_unpersisted(&mut rng);
    let credential_id = *initial.credential_id();
    let mut store = MemoryStore::default();
    initial.persist_initial(&mut store).unwrap();

    let tab_a = ArcClientCredentialV1::load_current(
        &mut store,
        credential_id,
        &fixture.binding,
        &fixture.expectation(),
        NOW,
    )
    .unwrap()
    .unwrap();
    let tab_b = ArcClientCredentialV1::load_current(
        &mut store,
        credential_id,
        &fixture.binding,
        &fixture.expectation(),
        NOW,
    )
    .unwrap()
    .unwrap();
    let (_, ready_a) = tab_a
        .prepare_presentation(&mut rng)
        .unwrap()
        .persist_successor(&mut store)
        .unwrap();
    let rejected_b = tab_b
        .prepare_presentation(&mut rng)
        .unwrap()
        .persist_successor(&mut store);
    assert!(matches!(
        rejected_b,
        Err(ArcClientStateErrorV1::Store(
            MemoryStoreError::CompareAndSwap
        ))
    ));

    let current = ArcClientCredentialV1::load_current(
        &mut store,
        credential_id,
        &fixture.binding,
        &fixture.expectation(),
        NOW,
    )
    .unwrap()
    .unwrap();
    let (_, ready_next) = current
        .prepare_presentation(&mut rng)
        .unwrap()
        .persist_successor(&mut store)
        .unwrap();
    let spend_a = fixture
        .keyring
        .verify_presentation(
            &fixture.binding,
            &fixture.expectation(),
            NOW,
            &ready_a.into_presentation(),
        )
        .unwrap();
    let spend_next = fixture
        .keyring
        .verify_presentation(
            &fixture.binding,
            &fixture.expectation(),
            NOW,
            &ready_next.into_presentation(),
        )
        .unwrap();
    assert_ne!(spend_a.canonical_tag(), spend_next.canonical_tag());
    assert_ne!(spend_a.spend_key(), spend_next.spend_key());
}

#[test]
fn presentation_is_withheld_when_successor_persistence_fails() {
    let fixture = Fixture::new(2, 14);
    let mut rng = ChaCha20Rng::from_seed([24; 32]);
    let initial = fixture.issue_unpersisted(&mut rng);
    let credential_id = *initial.credential_id();
    let mut store = MemoryStore::default();
    let current = initial.persist_initial(&mut store).unwrap();
    store.fail_next_cas = true;
    let result = current
        .prepare_presentation(&mut rng)
        .unwrap()
        .persist_successor(&mut store);
    assert!(matches!(
        result,
        Err(ArcClientStateErrorV1::Store(MemoryStoreError::Injected))
    ));
    assert_eq!(store.cas_calls, 1);
    let restored = ArcClientCredentialV1::load_current(
        &mut store,
        credential_id,
        &fixture.binding,
        &fixture.expectation(),
        NOW,
    )
    .unwrap()
    .unwrap();
    assert_eq!(restored.remaining_presentations(), 2);
}

#[test]
fn wrong_key_expectation_and_expiry_fail_closed() {
    let fixture = Fixture::new(4, 15);
    let wrong_key = Fixture::new(4, 16);
    let mut rng = ChaCha20Rng::from_seed([25; 32]);
    let initial = fixture.issue_unpersisted(&mut rng);
    let mut store = MemoryStore::default();
    let current = initial.persist_initial(&mut store).unwrap();
    let (_, ready) = current
        .prepare_presentation(&mut rng)
        .unwrap()
        .persist_successor(&mut store)
        .unwrap();
    let presentation = ready.into_presentation();

    assert_eq!(
        wrong_key.keyring.verify_presentation(
            &fixture.binding,
            &fixture.expectation(),
            NOW,
            &presentation,
        ),
        Err(ArcAdapterErrorV1::KeyNotFound)
    );

    let mut other_rng = ChaCha20Rng::from_seed([77; 32]);
    let (other_secret, _) = setup_server(&mut other_rng);
    let mut other_secret_bytes = Zeroizing::new([0u8; ARC_SECRET_KEY_LEN_V1]);
    other_secret_bytes[0..32].copy_from_slice(&serialize_scalar(&other_secret.x0));
    other_secret_bytes[32..64].copy_from_slice(&serialize_scalar(&other_secret.x1));
    other_secret_bytes[64..96].copy_from_slice(&serialize_scalar(&other_secret.x2));
    other_secret_bytes[96..128].copy_from_slice(&serialize_scalar(&other_secret.x0_blinding));
    let wrong_same_id = ArcSecretKeyringV1::new(vec![ArcSecretKeyV1::from_zeroizing_bytes(
        fixture.binding.claims.credential_key_id.clone(),
        other_secret_bytes,
    )
    .unwrap()])
    .unwrap();
    assert_eq!(
        wrong_same_id.verify_presentation(
            &fixture.binding,
            &fixture.expectation(),
            NOW,
            &presentation,
        ),
        Err(ArcAdapterErrorV1::SecretKeyDoesNotMatchBinding)
    );
    assert_eq!(
        fixture.keyring.verify_presentation(
            &fixture.binding,
            &fixture.expectation(),
            fixture.binding.claims.not_after + 1,
            &presentation,
        ),
        Err(ArcAdapterErrorV1::BindingExpired)
    );

    let mut wrong_expected = fixture.expectation();
    wrong_expected.offer_id += 1;
    assert_eq!(
        fixture
            .keyring
            .verify_presentation(&fixture.binding, &wrong_expected, NOW, &presentation,),
        Err(ArcAdapterErrorV1::InvalidBinding)
    );
}

#[test]
fn binding_signature_scheme_and_public_key_are_checked() {
    let fixture = Fixture::new(4, 31);
    let mut bad_signature = fixture.binding.clone();
    bad_signature.signature[0] ^= 1;
    assert_eq!(
        ArcPresentationCanonicalizerV1::from_verified_binding(
            &bad_signature,
            &fixture.expectation(),
            NOW,
        ),
        Err(ArcAdapterErrorV1::InvalidBinding)
    );

    let issuer_key = SigningKey::from_bytes(&[7; 32]);
    let mut invalid_point_claims = fixture.binding.claims.clone();
    invalid_point_claims.verification_key = vec![0; ARC_PUBLIC_KEY_LEN_V1];
    let invalid_point = CredentialKeyBindingV1::sign(invalid_point_claims, &issuer_key).unwrap();
    assert_eq!(
        ArcPresentationCanonicalizerV1::from_verified_binding(
            &invalid_point,
            &expectation_for(&invalid_point),
            NOW,
        ),
        Err(ArcAdapterErrorV1::InvalidPublicKey)
    );

    let free_binding = CredentialKeyBindingV1::sign(
        CredentialKeyBindingClaimsV1 {
            provider_id: [8; 32],
            scope_id: [9; 32],
            offer_id: 3,
            scheme: AuthScheme::FreeV1,
            keyset_epoch: 1,
            entitlement_profile: 2,
            unit: CredentialUnitV1::Entitlement,
            amount: 1,
            presentation_limit: 1,
            not_before: 900,
            not_after: 7_000,
            credential_key_id: vec![3; 16],
            verification_key: vec![4; 32],
        },
        &issuer_key,
    )
    .unwrap();
    let free_expected = CredentialKeyBindingExpectationV1 {
        issuer_id: &free_binding.issuer_id,
        provider_id: &free_binding.claims.provider_id,
        scope_id: &free_binding.claims.scope_id,
        offer_id: free_binding.claims.offer_id,
        scheme: AuthScheme::FreeV1,
        minimum_keyset_epoch: free_binding.claims.keyset_epoch,
        entitlement_profile: free_binding.claims.entitlement_profile,
        presentation_limit: free_binding.claims.presentation_limit,
        credential_key_id: &free_binding.claims.credential_key_id,
    };
    assert_eq!(
        ArcPresentationCanonicalizerV1::from_verified_binding(&free_binding, &free_expected, NOW,),
        Err(ArcAdapterErrorV1::WrongScheme)
    );
}

#[test]
fn request_context_presentation_context_and_limit_are_binding_fixed() {
    let fixture = Fixture::new(4, 17);
    let facts = verify_binding(&fixture.binding, &fixture.expectation(), NOW).unwrap();
    let mut rng = ChaCha20Rng::from_seed([26; 32]);

    let wrong_request_credential =
        raw_credential(&fixture, b"attacker-selected-request-context", &mut rng);
    let wrong_request_state = make_presentation_state(
        wrong_request_credential,
        &facts.presentation_context,
        facts.presentation_limit,
    );
    let (_, _, presentation) = present(&wrong_request_state, &mut rng).unwrap();
    let envelope = ArcPresentationV1::from_canonical_bytes(presentation.to_bytes()).unwrap();
    assert_eq!(
        fixture.keyring.verify_presentation(
            &fixture.binding,
            &fixture.expectation(),
            NOW,
            &envelope,
        ),
        Err(ArcAdapterErrorV1::PresentationVerificationFailed)
    );

    let correct_credential = raw_credential(&fixture, &facts.request_context, &mut rng);
    let wrong_presentation_context_state = make_presentation_state(
        correct_credential.clone(),
        b"attacker-selected-presentation-context",
        facts.presentation_limit,
    );
    let (_, _, presentation) = present(&wrong_presentation_context_state, &mut rng).unwrap();
    let envelope = ArcPresentationV1::from_canonical_bytes(presentation.to_bytes()).unwrap();
    assert_eq!(
        fixture.keyring.verify_presentation(
            &fixture.binding,
            &fixture.expectation(),
            NOW,
            &envelope,
        ),
        Err(ArcAdapterErrorV1::PresentationVerificationFailed)
    );

    let wrong_limit_state = make_presentation_state(
        correct_credential,
        &facts.presentation_context,
        facts.presentation_limit * 2,
    );
    let (_, _, presentation) = present(&wrong_limit_state, &mut rng).unwrap();
    let envelope = ArcPresentationV1::from_canonical_bytes(presentation.to_bytes()).unwrap();
    assert!(matches!(
        fixture.keyring.verify_presentation(
            &fixture.binding,
            &fixture.expectation(),
            NOW,
            &envelope,
        ),
        Err(ArcAdapterErrorV1::InvalidPresentation)
            | Err(ArcAdapterErrorV1::PresentationVerificationFailed)
    ));

    let codec = ArcPresentationCanonicalizerV1::from_verified_binding(
        &fixture.binding,
        &fixture.expectation(),
        NOW,
    )
    .unwrap();
    assert_eq!(codec.binding_digest(), &facts.binding_digest);

    let correct_credential = raw_credential(&fixture, &facts.request_context, &mut rng);
    let correct_state = make_presentation_state(
        correct_credential,
        &facts.presentation_context,
        facts.presentation_limit,
    );
    let (_, _, correct_presentation) = present(&correct_state, &mut rng).unwrap();
    assert_eq!(
        codec
            .decode_and_reencode(&correct_presentation.to_bytes())
            .unwrap(),
        correct_presentation.to_bytes()
    );
}

#[test]
fn binding_limits_cover_one_two_non_power_and_protocol_maximum() {
    let mut unsupported_claims = Fixture::new(2, 39).binding.claims;
    unsupported_claims.presentation_limit = 1;
    assert!(
        CredentialKeyBindingV1::sign(unsupported_claims, &SigningKey::from_bytes(&[7; 32]))
            .is_err()
    );

    for (index, limit) in [2u32, 3, 10, MAX_CREDENTIAL_PRESENTATIONS_V1]
        .into_iter()
        .enumerate()
    {
        let fixture = Fixture::new(limit, 40 + index as u8);
        let facts = verify_binding(&fixture.binding, &fixture.expectation(), NOW).unwrap();
        let mut rng = ChaCha20Rng::from_seed([50 + index as u8; 32]);
        let credential = raw_credential(&fixture, &facts.request_context, &mut rng);
        let mut state = make_presentation_state(
            credential,
            &facts.presentation_context,
            facts.presentation_limit,
        );
        state.next_nonce = facts.presentation_limit - 1;
        let (exhausted, _, presentation) = present(&state, &mut rng).unwrap();
        let envelope = ArcPresentationV1::from_canonical_bytes(presentation.to_bytes()).unwrap();
        fixture
            .keyring
            .verify_presentation(&fixture.binding, &fixture.expectation(), NOW, &envelope)
            .unwrap_or_else(|error| panic!("limit {limit} failed verification: {error:?}"));
        assert!(matches!(
            present(&exhausted, &mut rng),
            Err(arc::Error::LimitExceeded)
        ));
    }
}

#[test]
fn binding_lineage_changes_context_and_rejects_old_credential() {
    let fixture = Fixture::new(4, 18);
    let mut rng = ChaCha20Rng::from_seed([27; 32]);
    let initial = fixture.issue_unpersisted(&mut rng);
    let mut store = MemoryStore::default();
    let current = initial.persist_initial(&mut store).unwrap();
    let (_, ready) = current
        .prepare_presentation(&mut rng)
        .unwrap()
        .persist_successor(&mut store)
        .unwrap();
    let presentation = ready.into_presentation();

    let mut changed_claims = fixture.binding.claims.clone();
    changed_claims.keyset_epoch += 1;
    let changed =
        CredentialKeyBindingV1::sign(changed_claims, &SigningKey::from_bytes(&[7; 32])).unwrap();
    assert_ne!(
        fixture.binding.binding_digest().unwrap(),
        changed.binding_digest().unwrap()
    );
    assert_ne!(
        fixture.binding.request_context_digest().unwrap(),
        changed.request_context_digest().unwrap()
    );
    assert_ne!(
        fixture.binding.presentation_context_digest().unwrap(),
        changed.presentation_context_digest().unwrap()
    );
    let old_lineage = ArcExclusiveKeyLineageV1::from_verified_binding(
        &fixture.binding,
        &fixture.expectation(),
        NOW,
    )
    .unwrap();
    let changed_lineage =
        ArcExclusiveKeyLineageV1::from_verified_binding(&changed, &expectation_for(&changed), NOW)
            .unwrap();
    assert_eq!(
        old_lineage.public_key_fingerprint(),
        changed_lineage.public_key_fingerprint()
    );
    assert_ne!(
        old_lineage.lineage_digest(),
        changed_lineage.lineage_digest()
    );
    assert_ne!(
        old_lineage.binding_digest(),
        changed_lineage.binding_digest()
    );
    assert_eq!(
        fixture.keyring.verify_presentation(
            &changed,
            &expectation_for(&changed),
            NOW,
            &presentation,
        ),
        Err(ArcAdapterErrorV1::PresentationVerificationFailed)
    );
}

#[test]
fn keyring_rejects_duplicate_lineages_and_debug_redacts_secrets() {
    let mut rng = ChaCha20Rng::from_seed([28; 32]);
    let (secret, _) = setup_server(&mut rng);
    let encode = || {
        let mut bytes = Zeroizing::new([0u8; ARC_SECRET_KEY_LEN_V1]);
        bytes[0..32].copy_from_slice(&serialize_scalar(&secret.x0));
        bytes[32..64].copy_from_slice(&serialize_scalar(&secret.x1));
        bytes[64..96].copy_from_slice(&serialize_scalar(&secret.x2));
        bytes[96..128].copy_from_slice(&serialize_scalar(&secret.x0_blinding));
        bytes
    };
    let first = ArcSecretKeyV1::from_zeroizing_bytes(vec![1], encode()).unwrap();
    let debug = format!("{first:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&format!("{:?}", serialize_scalar(&secret.x0))));
    let same_public = ArcSecretKeyV1::from_zeroizing_bytes(vec![2], encode()).unwrap();
    assert_eq!(
        ArcSecretKeyringV1::new(vec![first, same_public]).unwrap_err(),
        ArcAdapterErrorV1::DuplicatePublicKey
    );

    let zero = Zeroizing::new([0u8; ARC_SECRET_KEY_LEN_V1]);
    assert_eq!(
        ArcSecretKeyV1::from_zeroizing_bytes(vec![3], zero).unwrap_err(),
        ArcAdapterErrorV1::SecretKeyMalformed
    );
}

#[test]
fn client_state_tampering_and_wrong_binding_are_rejected() {
    let fixture = Fixture::new(4, 19);
    let other = Fixture::new(4, 20);
    let mut rng = ChaCha20Rng::from_seed([29; 32]);
    let initial = fixture.issue_unpersisted(&mut rng);
    let credential_id = *initial.credential_id();
    let mut store = MemoryStore::default();
    initial.persist_initial(&mut store).unwrap();

    assert!(matches!(
        ArcClientCredentialV1::load_current(
            &mut store,
            credential_id,
            &other.binding,
            &other.expectation(),
            NOW,
        ),
        Err(ArcClientStateErrorV1::Adapter(
            ArcAdapterErrorV1::ClientStateBindingMismatch
        ))
    ));

    store.current.get_mut(&credential_id).unwrap().1[81..113].fill(0);
    assert!(matches!(
        ArcClientCredentialV1::load_current(
            &mut store,
            credential_id,
            &fixture.binding,
            &fixture.expectation(),
            NOW,
        ),
        Err(ArcClientStateErrorV1::Adapter(
            ArcAdapterErrorV1::InvalidClientState
        ))
    ));
}

#[cfg(feature = "provider-store")]
#[test]
fn real_arc_adapter_installs_namespace_spends_once_and_survives_restart() {
    let fixture = ProviderArcFixtureV1::new(31);
    let directory = private_provider_tempdir("bitcoinpir-real-arc-provider-");
    let path = directory.path().join("provider.sqlite3");
    let store = ProviderStore::create(
        &path,
        [31; 16],
        fixture.policy.provider_id,
        StoreOptions::default(),
    )
    .unwrap();
    assert!(matches!(
        store
            .install_verified_offer_namespace_v1(
                &fixture.verified_offer(),
                NOW,
                Some(&fixture.keyring),
            )
            .unwrap(),
        VerifiedOfferNamespaceInstallOutcomeV1::Namespace { .. }
    ));

    let presentation = fixture.issue_ready_presentation(41);
    let bound = fixture.bind_presentation(presentation);
    let verified = verify_provider_local_arc_spend_v1(&bound, NOW, &fixture.keyring).unwrap();
    assert_eq!(
        store
            .spend_verified_arc_provider_local_v1(verified)
            .unwrap()
            .spend_commit_seq,
        1
    );

    let reopened = ProviderStore::open_existing(
        &path,
        fixture.policy.provider_id,
        StoreOptions::default(),
    )
    .unwrap();
    let replay = verify_provider_local_arc_spend_v1(&bound, NOW, &fixture.keyring).unwrap();
    assert!(matches!(
        reopened.spend_verified_arc_provider_local_v1(replay),
        Err(StoreError::AlreadySpent)
    ));
}

#[cfg(feature = "provider-store")]
#[test]
fn real_arc_adapter_rejects_wrong_key_and_has_one_concurrent_spend_winner() {
    let fixture = ProviderArcFixtureV1::new(32);
    let wrong_key = ProviderArcFixtureV1::new(33);
    let directory = private_provider_tempdir("bitcoinpir-real-arc-concurrent-");
    let store = fixture.create_provider_store(&directory.path().join("provider.sqlite3"), 32);
    assert!(matches!(
        store
            .install_verified_offer_namespace_v1(
                &fixture.verified_offer(),
                NOW,
                Some(&fixture.keyring),
            )
            .unwrap(),
        VerifiedOfferNamespaceInstallOutcomeV1::Namespace { .. }
    ));

    let presentation = fixture.issue_ready_presentation(42);
    let bound = fixture.bind_presentation(presentation);
    assert!(verify_provider_local_arc_spend_v1(&bound, NOW, &wrong_key.keyring).is_err());

    let results = std::thread::scope(|thread_scope| {
        (0..8)
            .map(|_| {
                let provider_store = store.clone();
                let bound = &bound;
                let keyring = &fixture.keyring;
                thread_scope.spawn(move || {
                    let verified = verify_provider_local_arc_spend_v1(bound, NOW, keyring)?;
                    provider_store.spend_verified_arc_provider_local_v1(verified)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StoreError::AlreadySpent)))
            .count(),
        7
    );
}
