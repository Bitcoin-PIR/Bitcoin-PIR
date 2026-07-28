#![cfg(feature = "provider-store")]

use pir_payment_crypto::{
    blind_cashu_message_v1, verify_and_unblind_cashu_promise_v1, K256CashuMintKeyringV1,
};
use pir_service_protocol::BitcoinPirCashuBatProofV1;
use pir_service_store::CashuBatProofVerifierV1;

#[test]
fn production_bat_keyring_implements_the_provider_store_verifier_boundary() {
    let keyring = K256CashuMintKeyringV1::from_secret_keys([[13; 32]]).unwrap();
    let public_key = keyring.denomination_public_keys()[0];
    let secret_raw = [0x11; 32];
    let blinding_scalar = [7; 32];
    let blinded_message = blind_cashu_message_v1(&secret_raw, &blinding_scalar).unwrap();
    let promise = keyring
        .blind_sign_with_dleq_v1(&public_key, &blinded_message, &[17; 32])
        .unwrap();
    let unblinded = verify_and_unblind_cashu_promise_v1(
        &secret_raw,
        &blinding_scalar,
        &public_key,
        &blinded_message,
        promise.blinded_signature(),
        promise.dleq_e(),
        promise.dleq_s(),
    )
    .unwrap();
    let proof = BitcoinPirCashuBatProofV1 {
        secret_raw,
        c: *unblinded.unblinded_signature(),
    };

    keyring
        .verify_cashu_bat_proof_v1(&proof, &public_key)
        .unwrap();

    let mut tampered = proof;
    tampered.secret_raw[0] ^= 1;
    assert!(keyring
        .verify_cashu_bat_proof_v1(&tampered, &public_key)
        .is_err());
}
