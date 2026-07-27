use super::*;
use static_assertions::assert_not_impl_any;

const EXPORT_ID: [u8; 16] = [0x11; 16];
const PROVIDER_ID: [u8; 32] = [0x22; 32];
const RECIPIENT_SECRET: [u8; 32] = [0x33; 32];
const EPHEMERAL_SECRET: [u8; 32] = [0x44; 32];
const NONCE: [u8; 24] = [0x55; 24];
const PLAINTEXT: &[u8] = b"canonical cashuB payload remains opaque to this crate";

assert_not_impl_any!(CashuCustodyRecipientSecretKeyV1: core::fmt::Debug, Clone, Copy);
assert_not_impl_any!(CashuCustodySealMaterialV1: core::fmt::Debug, Clone, Copy);
assert_not_impl_any!(CashuCustodyEnvelopeV1: Clone, Copy);
assert_not_impl_any!(OpenedCashuCustodyPlaintextV1: core::fmt::Debug, Clone, Copy);

fn recipient() -> CashuCustodyRecipientSecretKeyV1 {
    CashuCustodyRecipientSecretKeyV1::from_bytes(RECIPIENT_SECRET).unwrap()
}

fn expect_error<T>(result: Result<T, CashuCustodyErrorV1>) -> CashuCustodyErrorV1 {
    match result {
        Ok(_) => panic!("expected fail-closed custody error"),
        Err(error) => error,
    }
}

fn deterministic_envelope() -> CashuCustodyEnvelopeV1 {
    let recipient = recipient();
    let material = CashuCustodySealMaterialV1::for_test(EPHEMERAL_SECRET, NONCE).unwrap();
    seal_cashu_custody_with_test_material_v1(
        EXPORT_ID,
        PROVIDER_ID,
        &recipient.public_key(),
        PLAINTEXT,
        material,
    )
    .unwrap()
}

#[test]
fn deterministic_roundtrip_and_exact_replay() {
    let recipient = recipient();
    let envelope = deterministic_envelope();
    let exact_bytes = envelope.as_bytes().to_vec();
    let replay = CashuCustodyEnvelopeV1::decode(&exact_bytes).unwrap();
    assert_eq!(replay.as_bytes(), exact_bytes);
    assert_eq!(replay.export_id(), EXPORT_ID);
    assert_eq!(replay.provider_id(), PROVIDER_ID);
    assert_eq!(replay.recipient_key_id(), recipient.public_key().key_id());

    let opened = open_cashu_custody_v1(&replay, &recipient).unwrap();
    assert_eq!(opened.as_bytes(), PLAINTEXT);
}

#[test]
fn envelope_debug_is_redacted_and_into_bytes_transfers_exact_allocation() {
    let envelope = deterministic_envelope();
    let exact_bytes = envelope.as_bytes().to_vec();
    assert_eq!(
        format!("{envelope:?}"),
        "CashuCustodyEnvelopeV1 { encoded: \"[REDACTED_ENVELOPE]\" }"
    );
    assert_eq!(envelope.into_bytes(), exact_bytes);
}

#[test]
fn os_random_seals_are_fresh_and_open() {
    let recipient = recipient();
    let first = seal_cashu_custody_with_os_random_v1(
        EXPORT_ID,
        PROVIDER_ID,
        &recipient.public_key(),
        PLAINTEXT,
    )
    .unwrap();
    let second = seal_cashu_custody_with_os_random_v1(
        EXPORT_ID,
        PROVIDER_ID,
        &recipient.public_key(),
        PLAINTEXT,
    )
    .unwrap();
    assert_ne!(first.as_bytes(), second.as_bytes());
    assert_eq!(
        open_cashu_custody_v1(&first, &recipient)
            .unwrap()
            .as_bytes(),
        PLAINTEXT
    );
    assert_eq!(
        open_cashu_custody_v1(&second, &recipient)
            .unwrap()
            .as_bytes(),
        PLAINTEXT
    );
}

#[test]
fn every_authenticated_field_and_ciphertext_reject_tampering() {
    let envelope = deterministic_envelope();
    let cases = [
        (EXPORT_ID_OFFSET, CashuCustodyErrorV1::AuthenticationFailed),
        (
            PROVIDER_ID_OFFSET,
            CashuCustodyErrorV1::AuthenticationFailed,
        ),
        (RECIPIENT_KEY_ID_OFFSET, CashuCustodyErrorV1::WrongRecipient),
        (
            EPHEMERAL_PUBLIC_KEY_OFFSET,
            CashuCustodyErrorV1::AuthenticationFailed,
        ),
        (NONCE_OFFSET, CashuCustodyErrorV1::AuthenticationFailed),
        (HEADER_BYTES_V1, CashuCustodyErrorV1::AuthenticationFailed),
    ];
    for (offset, expected) in cases {
        let mut tampered = envelope.as_bytes().to_vec();
        tampered[offset] ^= 1;
        let parsed = CashuCustodyEnvelopeV1::decode(&tampered).unwrap();
        assert_eq!(
            expect_error(open_cashu_custody_v1(&parsed, &recipient())),
            expected,
            "offset {offset}"
        );
    }

    let mut magic = envelope.as_bytes().to_vec();
    magic[0] ^= 1;
    assert!(matches!(
        CashuCustodyEnvelopeV1::decode(&magic),
        Err(CashuCustodyErrorV1::InvalidEnvelope)
    ));

    let mut length = envelope.as_bytes().to_vec();
    length[CIPHERTEXT_LENGTH_OFFSET + 3] ^= 1;
    assert!(matches!(
        CashuCustodyEnvelopeV1::decode(&length),
        Err(CashuCustodyErrorV1::InvalidEnvelope)
    ));
}

#[test]
fn wrong_recipient_and_non_contributory_keys_fail_closed() {
    let envelope = deterministic_envelope();
    let wrong = CashuCustodyRecipientSecretKeyV1::from_bytes([0x77; 32]).unwrap();
    assert_eq!(
        expect_error(open_cashu_custody_v1(&envelope, &wrong)),
        CashuCustodyErrorV1::WrongRecipient
    );
    assert!(matches!(
        CashuCustodyRecipientSecretKeyV1::from_bytes([0u8; 32]),
        Err(CashuCustodyErrorV1::InvalidRecipientKey)
    ));
    assert_eq!(
        expect_error(CashuCustodyRecipientPublicKeyV1::from_bytes([0u8; 32])),
        CashuCustodyErrorV1::InvalidRecipientKey
    );

    let mut noncanonical = [0u8; 32];
    noncanonical[31] = 0x80;
    assert_eq!(
        expect_error(CashuCustodyRecipientPublicKeyV1::from_bytes(noncanonical)),
        CashuCustodyErrorV1::InvalidRecipientKey
    );

    // u=1 is a low-order X25519 input: non-zero encoding but a
    // non-contributory exchange for a clamped scalar.
    let mut low_order = [0u8; 32];
    low_order[0] = 1;
    assert_eq!(
        expect_error(CashuCustodyRecipientPublicKeyV1::from_bytes(low_order)),
        CashuCustodyErrorV1::InvalidRecipientKey
    );

    let mut low_order_ephemeral = envelope.as_bytes().to_vec();
    low_order_ephemeral[EPHEMERAL_PUBLIC_KEY_OFFSET..EPHEMERAL_PUBLIC_KEY_OFFSET + 32].fill(0);
    low_order_ephemeral[EPHEMERAL_PUBLIC_KEY_OFFSET] = 1;
    assert!(matches!(
        CashuCustodyEnvelopeV1::decode(&low_order_ephemeral),
        Err(CashuCustodyErrorV1::InvalidEphemeralKey)
    ));
}

#[test]
fn truncation_trailing_bytes_empty_and_bounds_reject() {
    let envelope = deterministic_envelope();
    for length in [
        0,
        1,
        HEADER_BYTES_V1 - 1,
        HEADER_BYTES_V1,
        envelope.as_bytes().len() - 1,
    ] {
        assert!(matches!(
            CashuCustodyEnvelopeV1::decode(&envelope.as_bytes()[..length]),
            Err(CashuCustodyErrorV1::InvalidEnvelope)
        ));
    }
    let mut trailing = envelope.as_bytes().to_vec();
    trailing.push(0);
    assert!(matches!(
        CashuCustodyEnvelopeV1::decode(&trailing),
        Err(CashuCustodyErrorV1::InvalidEnvelope)
    ));

    let mut oversized = envelope.as_bytes().to_vec();
    oversized[CIPHERTEXT_LENGTH_OFFSET..CIPHERTEXT_LENGTH_OFFSET + 4]
        .copy_from_slice(&((MAX_CIPHERTEXT_BYTES_V1 as u32) + 1).to_be_bytes());
    oversized.resize(HEADER_BYTES_V1 + MAX_CIPHERTEXT_BYTES_V1 + 1, 0);
    assert!(matches!(
        CashuCustodyEnvelopeV1::decode(&oversized),
        Err(CashuCustodyErrorV1::InvalidEnvelope)
    ));
    assert_eq!(
        MAX_CASHU_CUSTODY_ENVELOPE_BYTES_V1,
        HEADER_BYTES_V1 + MAX_CIPHERTEXT_BYTES_V1
    );

    let recipient = recipient();
    let material = CashuCustodySealMaterialV1::for_test(EPHEMERAL_SECRET, NONCE).unwrap();
    assert_eq!(
        expect_error(seal_cashu_custody_with_test_material_v1(
            EXPORT_ID,
            PROVIDER_ID,
            &recipient.public_key(),
            b"",
            material,
        )),
        CashuCustodyErrorV1::EmptyPlaintext
    );
    let too_long = vec![0xabu8; MAX_CASHU_CUSTODY_PLAINTEXT_BYTES_V1 + 1];
    let material = CashuCustodySealMaterialV1::for_test(EPHEMERAL_SECRET, NONCE).unwrap();
    assert_eq!(
        expect_error(seal_cashu_custody_with_test_material_v1(
            EXPORT_ID,
            PROVIDER_ID,
            &recipient.public_key(),
            &too_long,
            material,
        )),
        CashuCustodyErrorV1::PlaintextTooLong
    );
    let max = vec![0xcdu8; MAX_CASHU_CUSTODY_PLAINTEXT_BYTES_V1];
    let material = CashuCustodySealMaterialV1::for_test(EPHEMERAL_SECRET, NONCE).unwrap();
    let envelope = seal_cashu_custody_with_test_material_v1(
        EXPORT_ID,
        PROVIDER_ID,
        &recipient.public_key(),
        &max,
        material,
    )
    .unwrap();
    assert_eq!(
        open_cashu_custody_v1(&envelope, &recipient).unwrap().len(),
        MAX_CASHU_CUSTODY_PLAINTEXT_BYTES_V1
    );
}

#[test]
fn zero_ids_are_rejected_at_seal_and_decode() {
    let recipient = recipient();
    for (export_id, provider_id) in [([0u8; 16], PROVIDER_ID), (EXPORT_ID, [0u8; 32])] {
        let material = CashuCustodySealMaterialV1::for_test(EPHEMERAL_SECRET, NONCE).unwrap();
        assert_eq!(
            expect_error(seal_cashu_custody_with_test_material_v1(
                export_id,
                provider_id,
                &recipient.public_key(),
                PLAINTEXT,
                material,
            )),
            CashuCustodyErrorV1::InvalidIdentifier
        );
    }

    let envelope = deterministic_envelope();
    for (start, length) in [
        (EXPORT_ID_OFFSET, 16),
        (PROVIDER_ID_OFFSET, 32),
        (RECIPIENT_KEY_ID_OFFSET, 32),
    ] {
        let mut bytes = envelope.as_bytes().to_vec();
        bytes[start..start + length].fill(0);
        assert!(matches!(
            CashuCustodyEnvelopeV1::decode(&bytes),
            Err(CashuCustodyErrorV1::InvalidIdentifier)
        ));
    }
}

#[test]
fn domain_separation_and_v1_vector_are_stable() {
    let recipient = recipient();
    let public_key = recipient.public_key().to_bytes();
    let key_id = recipient.public_key().key_id();
    assert_ne!(key_id, Sha256::digest(public_key).as_slice());
    assert_ne!(
        domain_hash_v1(RECIPIENT_KEY_ID_DOMAIN_V1, &public_key),
        domain_hash_v1(HKDF_SALT_DOMAIN_V1, &public_key)
    );
    assert_ne!(
        domain_message_v1(HKDF_INFO_DOMAIN_V1, &[&public_key]),
        domain_message_v1(AAD_DOMAIN_V1, &[&public_key])
    );

    // Pins every domain string, field order, integer encoding, KDF input and
    // AEAD output. Changing this vector requires an explicit protocol version.
    assert_eq!(
        hex::encode(key_id),
        "1c239dadf7a8984db88414dc7c2372564164103bcd8d3e4961e9e64da1d9b3cf"
    );
    assert_eq!(
        hex::encode(deterministic_envelope().as_bytes()),
        "42504343455631001111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222221c239dadf7a8984db88414dc7c2372564164103bcd8d3e4961e9e64da1d9b3cfff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b555555555555555555555555555555555555555555555555000000454ed3f904d08146116bdc44ae1aa2ad05b9cf391bb85b17ed52a7ffe12bb07310bbf956b74fae0d2a0b57f088929aead1fa6f4389f4e473609c7f97d9de8c4bfa2dd6a85127"
    );
}

#[test]
fn errors_do_not_embed_secret_material() {
    let error = expect_error(CashuCustodyRecipientSecretKeyV1::from_bytes([0u8; 32]));
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(&hex::encode(RECIPIENT_SECRET)));
    assert!(!rendered.contains(core::str::from_utf8(PLAINTEXT).unwrap()));
}
