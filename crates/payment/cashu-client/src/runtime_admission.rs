//! Runtime adapter for authoritative standard-Cashu admission.

use std::collections::BTreeMap;

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
    StandardCashuMintManifestV1,
};
use rand_core::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CashuClientErrorV1, CashuCustodyAadV1, CashuCustodyBundleV1, CashuCustodyCipherErrorV1,
    CashuCustodyCipherV1, CashuOutputMaterialV1, CashuRecoveryAadV1, CashuRecoveryCipherErrorV1,
    CashuRecoveryCipherV1, CashuSealedCustodyV1, CashuSealedRecoveryV1, CashuSwapProgressV1,
    SensitiveBytes32SetV1, StandardCashuClientV1,
};

const CASHU_RECOVERY_NONCE_LEN_V1: usize = 24;
const CASHU_CUSTODY_NONCE_LEN_V1: usize = 24;

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

/// A separately configured AEAD keyring for note-only custody material. The
/// distinct type and AAD make accidental recovery-domain reuse impossible at
/// the trait boundary.
pub struct ChaCha20Poly1305CustodyCipherV1 {
    active_epoch: u64,
    keys: BTreeMap<u64, Zeroizing<[u8; 32]>>,
}

impl core::fmt::Debug for ChaCha20Poly1305CustodyCipherV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ChaCha20Poly1305CustodyCipherV1")
            .field("active_epoch", &self.active_epoch)
            .field("loaded_epoch_count", &self.keys.len())
            .finish()
    }
}

impl ChaCha20Poly1305CustodyCipherV1 {
    pub fn new(
        active_epoch: u64,
        keys: impl IntoIterator<Item = (u64, [u8; 32])>,
    ) -> Result<Self, CashuCustodyCipherErrorV1> {
        if active_epoch == 0 {
            return Err(CashuCustodyCipherErrorV1::UnknownKeyEpoch);
        }
        let mut loaded = BTreeMap::new();
        for (epoch, mut key) in keys {
            if epoch == 0 || key.iter().all(|byte| *byte == 0) || loaded.contains_key(&epoch) {
                key.zeroize();
                return Err(CashuCustodyCipherErrorV1::UnknownKeyEpoch);
            }
            loaded.insert(epoch, Zeroizing::new(key));
        }
        if !loaded.contains_key(&active_epoch) {
            return Err(CashuCustodyCipherErrorV1::UnknownKeyEpoch);
        }
        Ok(Self {
            active_epoch,
            keys: loaded,
        })
    }
}

impl CashuCustodyCipherV1 for ChaCha20Poly1305CustodyCipherV1 {
    fn seal(
        &self,
        aad: &CashuCustodyAadV1,
        plaintext: &[u8],
    ) -> Result<CashuSealedCustodyV1, CashuCustodyCipherErrorV1> {
        let key = self
            .keys
            .get(&self.active_epoch)
            .ok_or(CashuCustodyCipherErrorV1::UnknownKeyEpoch)?;
        let mut nonce = vec![0u8; CASHU_CUSTODY_NONCE_LEN_V1];
        getrandom(&mut nonce).map_err(|_| CashuCustodyCipherErrorV1::Unavailable)?;
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad.encode(),
                },
            )
            .map_err(|_| CashuCustodyCipherErrorV1::Unavailable)?;
        Ok(CashuSealedCustodyV1 {
            key_epoch: self.active_epoch,
            nonce,
            ciphertext,
        })
    }

    fn open(
        &self,
        aad: &CashuCustodyAadV1,
        sealed: &CashuSealedCustodyV1,
    ) -> Result<Vec<u8>, CashuCustodyCipherErrorV1> {
        if sealed.nonce.len() != CASHU_CUSTODY_NONCE_LEN_V1 {
            return Err(CashuCustodyCipherErrorV1::InvalidPlaintext);
        }
        let key = self
            .keys
            .get(&sealed.key_epoch)
            .ok_or(CashuCustodyCipherErrorV1::UnknownKeyEpoch)?;
        XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
            .decrypt(
                XNonce::from_slice(&sealed.nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad: &aad.encode(),
                },
            )
            .map_err(|_| CashuCustodyCipherErrorV1::AuthenticationFailed)
    }
}

/// Decryption-only custody keyring for offline export tooling. It has no
/// active epoch and cannot accidentally seal new operational custody lots.
pub struct ChaCha20Poly1305CustodyDecryptorV1 {
    keys: BTreeMap<u64, Zeroizing<[u8; 32]>>,
}

impl core::fmt::Debug for ChaCha20Poly1305CustodyDecryptorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ChaCha20Poly1305CustodyDecryptorV1")
            .field("loaded_epoch_count", &self.keys.len())
            .finish()
    }
}

impl ChaCha20Poly1305CustodyDecryptorV1 {
    pub fn new(
        keys: impl IntoIterator<Item = (u64, [u8; 32])>,
    ) -> Result<Self, CashuCustodyCipherErrorV1> {
        let mut loaded = BTreeMap::new();
        for (epoch, mut key) in keys {
            if epoch == 0 || key.iter().all(|byte| *byte == 0) || loaded.contains_key(&epoch) {
                key.zeroize();
                return Err(CashuCustodyCipherErrorV1::UnknownKeyEpoch);
            }
            loaded.insert(epoch, Zeroizing::new(key));
        }
        if loaded.is_empty() {
            return Err(CashuCustodyCipherErrorV1::UnknownKeyEpoch);
        }
        Ok(Self { keys: loaded })
    }

    pub fn open_bundle(
        &self,
        aad: &CashuCustodyAadV1,
        sealed: &CashuSealedCustodyV1,
    ) -> Result<CashuCustodyBundleV1, CashuClientErrorV1> {
        sealed.validate()?;
        if sealed.nonce.len() != CASHU_CUSTODY_NONCE_LEN_V1 {
            return Err(CashuClientErrorV1::InvalidCustodyCiphertextEnvelope);
        }
        let key = self
            .keys
            .get(&sealed.key_epoch)
            .ok_or(CashuClientErrorV1::CustodyCipherUnavailable)?;
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
                .decrypt(
                    XNonce::from_slice(&sealed.nonce),
                    Payload {
                        msg: &sealed.ciphertext,
                        aad: &aad.encode(),
                    },
                )
                .map_err(|_| CashuClientErrorV1::CustodyAuthenticationFailed)?,
        );
        let bundle = CashuCustodyBundleV1::decode_canonical(&plaintext)?;
        bundle.validate_for_aad(aad)?;
        Ok(bundle)
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
        let amounts = crate::solve_cashu_output_denominations_v1(manifest, value)?;
        let mut seen_secrets = SensitiveBytes32SetV1::with_capacity(amounts.len());
        let mut seen_blindings = SensitiveBytes32SetV1::with_capacity(amounts.len());
        let mut materials = Vec::with_capacity(amounts.len());
        for amount in amounts {
            let secret: Zeroizing<[u8; 32]> = loop {
                let mut candidate = Zeroizing::new([0u8; 32]);
                getrandom(&mut *candidate)
                    .map_err(|_| CashuClientErrorV1::InvalidOutputMaterial)?;
                if candidate.iter().any(|byte| *byte != 0) && seen_secrets.insert(*candidate) {
                    break candidate;
                }
            };
            let blinding: Zeroizing<[u8; 32]> = loop {
                let scalar = Scalar::random(&mut OsRng);
                let candidate: Zeroizing<[u8; 32]> = Zeroizing::new(scalar.to_bytes().into());
                if candidate.iter().any(|byte| *byte != 0) && seen_blindings.insert(*candidate) {
                    break candidate;
                }
            };
            materials.push(CashuOutputMaterialV1::from_zeroizing(
                amount, secret, blinding,
            ));
        }
        Ok(materials)
    }
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
                | CashuClientErrorV1::MintDleqVerificationFailed
                | CashuClientErrorV1::MintDefiniteRejection
                | CashuClientErrorV1::InvalidCashuToken,
            ) => Err(AdmissionCommitErrorV1::InvalidOrSpent),
            Err(
                CashuClientErrorV1::InvalidCiphertextEnvelope
                | CashuClientErrorV1::RecoveryCipherUnavailable
                | CashuClientErrorV1::RecoveryAuthenticationFailed
                | CashuClientErrorV1::RecoveryPlaintextInvalid
                | CashuClientErrorV1::InvalidCustodyCiphertextEnvelope
                | CashuClientErrorV1::CustodyCipherUnavailable
                | CashuClientErrorV1::CustodyAuthenticationFailed
                | CashuClientErrorV1::InvalidCustodyPlaintext
                | CashuClientErrorV1::StoreUnavailable
                | CashuClientErrorV1::StoreConflict
                | CashuClientErrorV1::IntentNotFound
                | CashuClientErrorV1::StateConflict
                | CashuClientErrorV1::Nut07CheckUnavailable
                | CashuClientErrorV1::Nut07ResponseInvalid,
            ) => Err(AdmissionCommitErrorV1::InternalAfterSpend),
            Err(
                CashuClientErrorV1::InvalidExposureLimits
                | CashuClientErrorV1::NoExactDenominationSolution
                | CashuClientErrorV1::DenominationSearchLimitExceeded,
            ) => Err(AdmissionCommitErrorV1::ScopeUnavailable),
            Err(CashuClientErrorV1::ExposureLimitExceeded) => {
                Err(AdmissionCommitErrorV1::ServerBusy {
                    retry_after_ms: 60_000,
                })
            }
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
            manifest_digest: [8; 32],
            unit_digest: [9; 32],
            input_set_digest: [3; 32],
            request_digest: [4; 32],
            output_set_digest: [5; 32],
            offer_binding_digest: [6; 32],
            settlement_value: 7,
            expected_output_count: 1,
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
