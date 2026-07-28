//! Role-labelled offline key generation for payment/service V1.

use clap::{Args, ValueEnum};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::SigningKey as SchnorrSigningKey;
use k256::SecretKey as Secp256k1SecretKey;
use pir_arc_adapter::{ArcSecretKeyV1, ARC_SECRET_KEY_LEN_V1};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ServiceKeyRole {
    /// Provider service-policy Ed25519 key; never the operator identity key.
    PolicyEd25519,
    /// Issuer root/delegation Ed25519 key.
    IssuerRootEd25519,
    /// Short-lived online BOLT11 quote Ed25519 signing key.
    QuoteEd25519,
    /// Provider-local direct-receipt Ed25519 key.
    ReceiptEd25519,
    /// Free anonymous-ticket Ed25519 key.
    AnonymousTicketEd25519,
    /// Provider/issuer clearing Ed25519 key.
    ClearingEd25519,
    /// Central directory Nostr BIP340 key.
    DirectoryNostr,
    /// BIP340 claim/recovery key (normally browser generated).
    Bip340Claim,
    /// Cashu/BAT secp256k1 DHKE scalar.
    CashuBat,
    /// Standard Cashu denomination secp256k1 DHKE scalar.
    CashuEcash,
    /// Issuer deterministic credential-response derivation key.
    CredentialDerivation,
    /// Issuer deterministic redeem-response derivation key.
    RedeemDerivation,
    /// Experimental ARC draft-01 four-scalar key (128 bytes).
    ArcExperimental,
}

#[derive(Args, Debug)]
pub struct ServiceKeygenArgs {
    #[arg(long, value_enum)]
    pub role: ServiceKeyRole,
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: ServiceKeygenArgs) -> Result<crate::keygen::SecretWriteCompletionV1, String> {
    crate::keygen::prepare_secret_key_parent(&args.out)?;
    if matches!(args.role, ServiceKeyRole::ArcExperimental) {
        return generate_arc_key(args);
    }

    let mut secret = [0u8; 32];
    let public = loop {
        if let Err(error) = getrandom::getrandom(&mut secret) {
            secret.zeroize();
            return Err(format!("operating-system randomness failed: {error}"));
        }
        let parsed = match args.role {
            ServiceKeyRole::PolicyEd25519
            | ServiceKeyRole::IssuerRootEd25519
            | ServiceKeyRole::QuoteEd25519
            | ServiceKeyRole::ReceiptEd25519
            | ServiceKeyRole::AnonymousTicketEd25519
            | ServiceKeyRole::ClearingEd25519 => Some(hex::encode(
                Ed25519SigningKey::from_bytes(&secret)
                    .verifying_key()
                    .to_bytes(),
            )),
            ServiceKeyRole::DirectoryNostr | ServiceKeyRole::Bip340Claim => {
                SchnorrSigningKey::from_bytes(&secret)
                    .ok()
                    .map(|key| hex::encode(key.verifying_key().to_bytes()))
            }
            ServiceKeyRole::CashuBat | ServiceKeyRole::CashuEcash => {
                Secp256k1SecretKey::from_slice(&secret)
                    .ok()
                    .map(|key| hex::encode(key.public_key().to_encoded_point(true).as_bytes()))
            }
            ServiceKeyRole::CredentialDerivation | ServiceKeyRole::RedeemDerivation => {
                (!secret.iter().all(|byte| *byte == 0)).then(|| {
                    let mut hasher = Sha256::new();
                    hasher.update(b"BitcoinPIR/operator-secret-fingerprint/v1");
                    hasher.update(secret);
                    hex::encode(hasher.finalize())
                })
            }
            ServiceKeyRole::ArcExperimental => unreachable!("handled above"),
        };
        if let Some(public) = parsed {
            break public;
        }
        secret.zeroize();
    };
    let write_result =
        crate::keygen::write_secret_key_unix_with_force(&args.out, &secret, args.force);
    secret.zeroize();
    let completion = write_result?;
    eprintln!(
        "wrote {:?} secret key (32 raw bytes, owner-only mode) to {}",
        args.role,
        args.out.display()
    );
    println!("role={:?}", args.role);
    if matches!(
        args.role,
        ServiceKeyRole::CredentialDerivation | ServiceKeyRole::RedeemDerivation
    ) {
        println!("secret_fingerprint={public}");
    } else {
        println!("public_key={public}");
    }
    Ok(completion)
}

fn generate_arc_key(
    args: ServiceKeygenArgs,
) -> Result<crate::keygen::SecretWriteCompletionV1, String> {
    let mut secret = [0u8; ARC_SECRET_KEY_LEN_V1];
    let parsed = loop {
        if let Err(error) = getrandom::getrandom(&mut secret) {
            secret.zeroize();
            return Err(format!("operating-system randomness failed: {error}"));
        }
        if let Ok(key) = ArcSecretKeyV1::from_zeroizing_bytes(vec![1], Zeroizing::new(secret)) {
            break key;
        }
        secret.zeroize();
    };
    let write_result =
        crate::keygen::write_secret_bytes_unix_with_force(&args.out, &secret, args.force);
    secret.zeroize();
    let completion = write_result?;
    eprintln!(
        "wrote {:?} secret key ({} raw bytes, owner-only mode) to {}",
        args.role,
        ARC_SECRET_KEY_LEN_V1,
        args.out.display()
    );
    println!("role={:?}", args.role);
    println!("public_key={}", hex::encode(parsed.public_key_bytes()));
    println!(
        "public_key_fingerprint={}",
        hex::encode(parsed.public_key_fingerprint())
    );
    Ok(completion)
}

#[cfg(all(test, unix, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use crate::keygen::private_tempdir_v1 as private_tempdir;

    #[test]
    fn every_role_writes_a_parseable_owner_only_key() {
        for role in [
            ServiceKeyRole::PolicyEd25519,
            ServiceKeyRole::IssuerRootEd25519,
            ServiceKeyRole::QuoteEd25519,
            ServiceKeyRole::ReceiptEd25519,
            ServiceKeyRole::AnonymousTicketEd25519,
            ServiceKeyRole::ClearingEd25519,
            ServiceKeyRole::DirectoryNostr,
            ServiceKeyRole::Bip340Claim,
            ServiceKeyRole::CashuBat,
            ServiceKeyRole::CashuEcash,
            ServiceKeyRole::CredentialDerivation,
            ServiceKeyRole::RedeemDerivation,
            ServiceKeyRole::ArcExperimental,
        ] {
            let directory = private_tempdir().unwrap();
            let path = directory.path().join("key");
            run(ServiceKeygenArgs {
                role,
                out: path.clone(),
                force: false,
            })
            .unwrap();
            let expected_len = if matches!(role, ServiceKeyRole::ArcExperimental) {
                ARC_SECRET_KEY_LEN_V1
            } else {
                32
            };
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(bytes.len(), expected_len);
            match role {
                ServiceKeyRole::DirectoryNostr | ServiceKeyRole::Bip340Claim => {
                    SchnorrSigningKey::from_bytes(bytes.as_slice()).unwrap();
                }
                ServiceKeyRole::CashuBat | ServiceKeyRole::CashuEcash => {
                    Secp256k1SecretKey::from_slice(&bytes).unwrap();
                }
                ServiceKeyRole::CredentialDerivation | ServiceKeyRole::RedeemDerivation => {
                    assert!(bytes.iter().any(|byte| *byte != 0));
                }
                ServiceKeyRole::ArcExperimental => {
                    let secret: [u8; ARC_SECRET_KEY_LEN_V1] = bytes.try_into().unwrap();
                    ArcSecretKeyV1::from_zeroizing_bytes(vec![1], Zeroizing::new(secret)).unwrap();
                }
                ServiceKeyRole::PolicyEd25519
                | ServiceKeyRole::IssuerRootEd25519
                | ServiceKeyRole::QuoteEd25519
                | ServiceKeyRole::ReceiptEd25519
                | ServiceKeyRole::AnonymousTicketEd25519
                | ServiceKeyRole::ClearingEd25519 => {
                    let seed: [u8; 32] = bytes.try_into().unwrap();
                    Ed25519SigningKey::from_bytes(&seed);
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn directory_key_no_force_preserves_an_existing_secret() {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("directory-nostr.key");
        crate::keygen::write_secret_bytes_unix_with_force(&path, &[0x5a_u8; 32], false).unwrap();

        let error = run(ServiceKeygenArgs {
            role: ServiceKeyRole::DirectoryNostr,
            out: path.clone(),
            force: false,
        })
        .expect_err("a second no-force directory keygen must fail");
        assert!(
            error.contains("already exists"),
            "unexpected error: {error}"
        );
        assert_eq!(std::fs::read(path).unwrap(), vec![0x5a_u8; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn production_service_keygen_rejects_a_writable_parent_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = private_tempdir().unwrap();
        let parent = directory.path().join("public");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let path = parent.join("directory-nostr.key");

        let error = run(ServiceKeygenArgs {
            role: ServiceKeyRole::DirectoryNostr,
            out: path.clone(),
            force: false,
        })
        .expect_err("service keys require a private parent");
        assert!(error.contains("mode 0700"), "{error}");
        assert!(!path.exists());
    }
}
