//! Runtime adapter for authoritative standard-Cashu admission.

use std::collections::{BTreeMap, HashSet};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use getrandom::getrandom;
use k256::elliptic_curve::ff::Field;
use k256::Scalar;
use pir_runtime_core::service_admission::{
    AdmissionCommitErrorV1, AdmissionMethodCommitterV1, AdmissionMethodRouteV1,
};
use pir_service_protocol::{
    check_standard_cashu_spend_for_offer, AuthorizationProofV1, BoundAuthAttemptV1,
    StandardCashuMintManifestV1, MAX_STANDARD_CASHU_PROOFS_V1,
};
use rand_core::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CashuClientErrorV1, CashuOutputMaterialV1, CashuRecoveryAadV1, CashuRecoveryCipherErrorV1,
    CashuRecoveryCipherV1, CashuSealedRecoveryV1, CashuSwapProgressV1, StandardCashuClientV1,
};

const CASHU_RECOVERY_NONCE_LEN_V1: usize = 24;

/// Authenticated recovery cipher with explicit key epochs.  Operators load the
/// keys from a secret store; only the epoch and a fresh public nonce enter the
/// provider database.  Old keys must remain available until every intent
/// encrypted under them has reached an operator-defined archival horizon.
pub struct ChaCha20Poly1305RecoveryCipherV1 {
    active_epoch: u64,
    keys: BTreeMap<u64, Zeroizing<[u8; 32]>>,
}

impl core::fmt::Debug for ChaCha20Poly1305RecoveryCipherV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ChaCha20Poly1305RecoveryCipherV1")
            .field("active_epoch", &self.active_epoch)
            .field("loaded_epoch_count", &self.keys.len())
            .finish()
    }
}

impl ChaCha20Poly1305RecoveryCipherV1 {
    pub fn new(
        active_epoch: u64,
        keys: impl IntoIterator<Item = (u64, [u8; 32])>,
    ) -> Result<Self, CashuRecoveryCipherErrorV1> {
        if active_epoch == 0 {
            return Err(CashuRecoveryCipherErrorV1::UnknownKeyEpoch);
        }
        let mut loaded = BTreeMap::new();
        for (epoch, mut key) in keys {
            if epoch == 0 || key.iter().all(|byte| *byte == 0) || loaded.contains_key(&epoch) {
                key.zeroize();
                return Err(CashuRecoveryCipherErrorV1::UnknownKeyEpoch);
            }
            loaded.insert(epoch, Zeroizing::new(key));
        }
        if !loaded.contains_key(&active_epoch) {
            return Err(CashuRecoveryCipherErrorV1::UnknownKeyEpoch);
        }
        Ok(Self {
            active_epoch,
            keys: loaded,
        })
    }
}

impl CashuRecoveryCipherV1 for ChaCha20Poly1305RecoveryCipherV1 {
    fn seal(
        &self,
        aad: &CashuRecoveryAadV1,
        plaintext: &[u8],
    ) -> Result<CashuSealedRecoveryV1, CashuRecoveryCipherErrorV1> {
        let key = self
            .keys
            .get(&self.active_epoch)
            .ok_or(CashuRecoveryCipherErrorV1::UnknownKeyEpoch)?;
        let mut nonce = vec![0u8; CASHU_RECOVERY_NONCE_LEN_V1];
        getrandom(&mut nonce).map_err(|_| CashuRecoveryCipherErrorV1::Unavailable)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad.encode(),
                },
            )
            .map_err(|_| CashuRecoveryCipherErrorV1::Unavailable)?;
        Ok(CashuSealedRecoveryV1 {
            key_epoch: self.active_epoch,
            nonce,
            ciphertext,
        })
    }

    fn open(
        &self,
        aad: &CashuRecoveryAadV1,
        sealed: &CashuSealedRecoveryV1,
    ) -> Result<Vec<u8>, CashuRecoveryCipherErrorV1> {
        if sealed.nonce.len() != CASHU_RECOVERY_NONCE_LEN_V1 {
            return Err(CashuRecoveryCipherErrorV1::InvalidPlaintext);
        }
        let key = self
            .keys
            .get(&sealed.key_epoch)
            .ok_or(CashuRecoveryCipherErrorV1::UnknownKeyEpoch)?;
        XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
            .decrypt(
                XNonce::from_slice(&sealed.nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad: &aad.encode(),
                },
            )
            .map_err(|_| CashuRecoveryCipherErrorV1::AuthenticationFailed)
    }
}

/// Fresh provider-wallet output material.  The exact output denominations are
/// derived solely from the signed active keyset and exact signed offer price.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandomCashuOutputMaterialGeneratorV1;

impl OsRandomCashuOutputMaterialGeneratorV1 {
    pub fn generate(
        &self,
        manifest: &StandardCashuMintManifestV1,
        value: u64,
    ) -> Result<Vec<CashuOutputMaterialV1>, CashuClientErrorV1> {
        let amounts = exact_greedy_denominations_v1(manifest, value)?;
        let mut seen_secrets = HashSet::with_capacity(amounts.len());
        let mut seen_blindings = HashSet::with_capacity(amounts.len());
        let mut materials = Vec::with_capacity(amounts.len());
        for amount in amounts {
            let secret = loop {
                let mut candidate = [0u8; 32];
                getrandom(&mut candidate).map_err(|_| CashuClientErrorV1::InvalidOutputMaterial)?;
                if candidate.iter().any(|byte| *byte != 0) && seen_secrets.insert(candidate) {
                    break candidate;
                }
            };
            let blinding = loop {
                let scalar = Scalar::random(&mut OsRng);
                let candidate: [u8; 32] = scalar.to_bytes().into();
                if candidate.iter().any(|byte| *byte != 0) && seen_blindings.insert(candidate) {
                    break candidate;
                }
            };
            materials.push(CashuOutputMaterialV1::new(amount, secret, blinding));
        }
        Ok(materials)
    }
}

fn exact_greedy_denominations_v1(
    manifest: &StandardCashuMintManifestV1,
    value: u64,
) -> Result<Vec<u64>, CashuClientErrorV1> {
    if value == 0 {
        return Err(CashuClientErrorV1::InvalidOutputMaterial);
    }
    let mut remaining = value;
    let mut amounts = Vec::new();
    for key in manifest.active_output_keyset.keys.iter().rev() {
        while remaining >= key.amount && amounts.len() < MAX_STANDARD_CASHU_PROOFS_V1 {
            amounts.push(key.amount);
            remaining -= key.amount;
        }
    }
    if remaining != 0 || amounts.is_empty() || amounts.len() > MAX_STANDARD_CASHU_PROOFS_V1 {
        return Err(CashuClientErrorV1::InvalidOutputMaterial);
    }
    Ok(amounts)
}

/// Exact standard-Cashu runtime adapter.  A grant is returned only after the
/// pinned mint's NUT-03 transition and provider-wallet recovery state commit.
pub struct StandardCashuAdmissionCommitterV1<'a> {
    client: StandardCashuClientV1<'a>,
    output_materials: OsRandomCashuOutputMaterialGeneratorV1,
}

impl<'a> StandardCashuAdmissionCommitterV1<'a> {
    pub const fn new(client: StandardCashuClientV1<'a>) -> Self {
        Self {
            client,
            output_materials: OsRandomCashuOutputMaterialGeneratorV1,
        }
    }
}

impl AdmissionMethodCommitterV1 for StandardCashuAdmissionCommitterV1<'_> {
    fn verify_and_commit_v1(
        &self,
        route: AdmissionMethodRouteV1,
        attempt: &BoundAuthAttemptV1<'_>,
        now_unix_seconds: u64,
    ) -> Result<(), AdmissionCommitErrorV1> {
        if route != AdmissionMethodRouteV1::StandardCashuMintOnline {
            return Err(AdmissionCommitErrorV1::UnsupportedScheme);
        }
        let AuthorizationProofV1::StandardCashu(spend) = attempt.proof() else {
            return Err(AdmissionCommitErrorV1::InvalidOrSpent);
        };
        let manifest = attempt
            .offer()
            .cashu_mint_manifest
            .as_ref()
            .ok_or(AdmissionCommitErrorV1::ScopeUnavailable)?;
        let checked =
            check_standard_cashu_spend_for_offer(spend, attempt.verified_offer(), now_unix_seconds)
                .map_err(|_| AdmissionCommitErrorV1::InvalidOrSpent)?;
        let output_materials = self
            .output_materials
            .generate(manifest, checked.policy_price)
            .map_err(|_| AdmissionCommitErrorV1::ScopeUnavailable)?;
        match self.client.start_swap(
            spend,
            &checked,
            attempt.verified_offer(),
            manifest,
            output_materials,
            now_unix_seconds,
        ) {
            Ok(CashuSwapProgressV1::Grant(_)) => Ok(()),
            Ok(CashuSwapProgressV1::AlreadyGranted { .. }) => {
                Err(AdmissionCommitErrorV1::InvalidOrSpent)
            }
            Ok(CashuSwapProgressV1::RecoveryPending { .. })
            | Ok(CashuSwapProgressV1::AttentionRequired { .. }) => {
                Err(AdmissionCommitErrorV1::InternalAfterSpend)
            }
            Err(
                CashuClientErrorV1::InvalidCheckedSpend
                | CashuClientErrorV1::InvalidManifest
                | CashuClientErrorV1::ConditionalTokenUnsupported
                | CashuClientErrorV1::InvalidOutputMaterial
                | CashuClientErrorV1::InvalidItemCount
                | CashuClientErrorV1::Underpayment
                | CashuClientErrorV1::Overpayment
                | CashuClientErrorV1::InvalidJson
                | CashuClientErrorV1::JsonTooLarge
                | CashuClientErrorV1::InvalidMintPoint
                | CashuClientErrorV1::InvalidMintScalar
                | CashuClientErrorV1::MintResponseMismatch
                | CashuClientErrorV1::MintDleqVerificationFailed,
            ) => Err(AdmissionCommitErrorV1::InvalidOrSpent),
            Err(
                CashuClientErrorV1::InvalidCiphertextEnvelope
                | CashuClientErrorV1::RecoveryCipherUnavailable
                | CashuClientErrorV1::RecoveryAuthenticationFailed
                | CashuClientErrorV1::RecoveryPlaintextInvalid
                | CashuClientErrorV1::StoreUnavailable
                | CashuClientErrorV1::StoreConflict
                | CashuClientErrorV1::IntentNotFound
                | CashuClientErrorV1::StateConflict,
            ) => Err(AdmissionCommitErrorV1::InternalAfterSpend),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_cipher_round_trips_and_authenticates_aad() {
        let cipher =
            ChaCha20Poly1305RecoveryCipherV1::new(2, [(1, [7; 32]), (2, [8; 32])]).unwrap();
        let aad = CashuRecoveryAadV1 {
            intent_id: [1; 16],
            mint_id: [2; 32],
            input_set_digest: [3; 32],
            request_digest: [4; 32],
            output_set_digest: [5; 32],
            offer_binding_digest: [6; 32],
            settlement_value: 7,
        };
        let sealed = cipher.seal(&aad, b"secret recovery").unwrap();
        assert_eq!(sealed.key_epoch, 2);
        assert_eq!(cipher.open(&aad, &sealed).unwrap(), b"secret recovery");
        let mut wrong = aad;
        wrong.settlement_value += 1;
        assert_eq!(
            cipher.open(&wrong, &sealed),
            Err(CashuRecoveryCipherErrorV1::AuthenticationFailed)
        );
    }
}
