//! Strict, shared production configuration loader for rollback-authority
//! clients. Provider and issuer binaries use the same parser so neither can
//! accidentally grow a weaker key, pin, path, or timeout policy.

use core::fmt;
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use pir_rollback_authority_protocol::{
    authority_client_key_id_v1, AuthorityClientSignerV1, AuthorityValueCodecV1,
    AuthorityValueRootKeyV1,
};
use pir_strict_https::StrictHttpsClientV1;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::RemoteRollbackAuthorityClientV1;

const CONFIG_SCHEMA_V1: &str = "bitcoinpir_remote_rollback_authority_v1";
const MAX_CONFIG_BYTES_V1: u64 = 8 * 1024;
const SECRET_BYTES_V1: u64 = 32;
const MAX_TIMEOUT_MILLIS_V1: u64 = 60_000;
#[cfg(feature = "test-only-webpki-root")]
const MAX_TEST_ONLY_WEBPKI_ROOT_PEM_BYTES_V1: u64 = 16 * 1024;

pub const MIN_INDEPENDENT_DEPLOYMENTS_V1: usize = 2;
pub const MAX_INDEPENDENT_DEPLOYMENTS_V1: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteAuthorityDeploymentConfigErrorV1 {
    UnsupportedPlatform,
    UnsafeConfigPath,
    ConfigReadFailed,
    ConfigTooLarge,
    InvalidConfig,
    UnsafeSecretPath,
    SecretReadFailed,
    InvalidSecret,
    SecretPathsAlias,
    CryptographicRoleCollision,
    ClientKeyMismatch,
    InvalidCryptographicBinding,
    InvalidTransportConfiguration,
    InvalidDeploymentSetSize,
    DeploymentSetNotIndependent,
}

impl fmt::Display for RemoteAuthorityDeploymentConfigErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => {
                "remote rollback-authority deployment requires Unix secure-file semantics"
            }
            Self::UnsafeConfigPath => {
                "remote rollback-authority config path failed private-file validation"
            }
            Self::ConfigReadFailed => "remote rollback-authority config read failed",
            Self::ConfigTooLarge => "remote rollback-authority config exceeds its size bound",
            Self::InvalidConfig => "remote rollback-authority config is invalid",
            Self::UnsafeSecretPath => {
                "remote rollback-authority secret path failed private-file validation"
            }
            Self::SecretReadFailed => "remote rollback-authority secret read failed",
            Self::InvalidSecret => "remote rollback-authority secret is invalid",
            Self::SecretPathsAlias => {
                "remote rollback-authority signing and value-root secrets must be different files"
            }
            Self::CryptographicRoleCollision => {
                "remote rollback-authority cryptographic roles must use independent keys"
            }
            Self::ClientKeyMismatch => {
                "remote rollback-authority client seed does not match its configured public key"
            }
            Self::InvalidCryptographicBinding => {
                "remote rollback-authority cryptographic binding is invalid"
            }
            Self::InvalidTransportConfiguration => {
                "remote rollback-authority HTTPS or timeout configuration is invalid"
            }
            Self::InvalidDeploymentSetSize => {
                "remote rollback-authority deployment set size is invalid"
            }
            Self::DeploymentSetNotIndependent => {
                "remote rollback-authority deployment set is not independent"
            }
        })
    }
}

impl std::error::Error for RemoteAuthorityDeploymentConfigErrorV1 {}

/// Fully constructed production boundary. No field implements `Debug`, and
/// callers must consume the value to obtain the client, value codec, and one
/// absolute domain-operation timeout.
pub struct ConfiguredRemoteRollbackAuthorityV1 {
    client: RemoteRollbackAuthorityClientV1,
    codec: AuthorityValueCodecV1,
    operation_timeout: Duration,
}

impl fmt::Debug for ConfiguredRemoteRollbackAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredRemoteRollbackAuthorityV1")
            .field("client", &"[REDACTED]")
            .field("codec", &"[REDACTED]")
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

impl ConfiguredRemoteRollbackAuthorityV1 {
    pub fn into_parts(
        self,
    ) -> (
        RemoteRollbackAuthorityClientV1,
        AuthorityValueCodecV1,
        Duration,
    ) {
        (self.client, self.codec, self.operation_timeout)
    }
}

/// Public-only fields from one strict production deployment config.
///
/// Construction reads and validates only the owner-only config file. It never
/// opens either referenced secret file and performs no network request. The
/// fields remain private so callers use the set validator rather than logging
/// identifiers or reimplementing partial independence checks.
pub struct RemoteRollbackAuthorityDeploymentDescriptorV1 {
    endpoint: String,
    authority_instance_id: [u8; 32],
    authority_verifying_key: [u8; 32],
    namespace: [u8; 32],
    client_verifying_key: [u8; 32],
    client_key_id: [u8; 32],
    leaf_spki_sha256_pins: Vec<[u8; 32]>,
}

impl fmt::Debug for RemoteRollbackAuthorityDeploymentDescriptorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteRollbackAuthorityDeploymentDescriptorV1")
            .field("deployment", &"[REDACTED]")
            .finish()
    }
}

struct ParsedDeploymentConfigV1 {
    descriptor: RemoteRollbackAuthorityDeploymentDescriptorV1,
    client_signing_seed_path: PathBuf,
    value_root_key_path: PathBuf,
    connect_timeout: Duration,
    io_timeout: Duration,
    attempt_timeout: Duration,
    operation_timeout: Duration,
    #[cfg(feature = "test-only-webpki-root")]
    test_only_webpki_root_pem_path: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentConfigFileV1 {
    schema: String,
    endpoint: String,
    authority_instance_id_hex: String,
    authority_verifying_key_hex: String,
    namespace_hex: String,
    client_verifying_key_hex: String,
    client_signing_seed_path: String,
    value_root_key_path: String,
    leaf_spki_sha256_pins_hex: Vec<String>,
    connect_timeout_ms: u64,
    io_timeout_ms: u64,
    attempt_timeout_ms: u64,
    operation_timeout_ms: u64,
    #[cfg(feature = "test-only-webpki-root")]
    test_only_webpki_root_pem_path: Option<String>,
}

/// Reads one strict owner-only config and returns only its public deployment
/// descriptor. Referenced client signing and value-root secret files are not
/// opened, inspected, or required to exist.
pub fn load_remote_rollback_authority_deployment_descriptor_v1(
    config_path: &Path,
) -> Result<RemoteRollbackAuthorityDeploymentDescriptorV1, RemoteAuthorityDeploymentConfigErrorV1> {
    parse_remote_rollback_authority_deployment_config_v1(config_path)
        .map(|parsed| parsed.descriptor)
}

/// Verifies the public separation invariants for one bounded deployment set.
///
/// The two through sixteen configs must have distinct endpoints and globally
/// distinct public 32-byte bindings: authority instance IDs, namespaces,
/// authority/client verifying keys, derived authority client-key IDs, and all
/// one-or-two TLS leaf SPKI pins. Failure is reported through one redacted
/// error variant and never identifies the colliding role or value. This
/// public-only check deliberately does not read either referenced secret and
/// therefore cannot establish secret-material or operational independence.
pub fn validate_independent_remote_rollback_authority_deployments_v1(
    deployments: &[RemoteRollbackAuthorityDeploymentDescriptorV1],
) -> Result<(), RemoteAuthorityDeploymentConfigErrorV1> {
    if !(MIN_INDEPENDENT_DEPLOYMENTS_V1..=MAX_INDEPENDENT_DEPLOYMENTS_V1)
        .contains(&deployments.len())
    {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::InvalidDeploymentSetSize);
    }
    for deployment in deployments {
        if !remote_deployment_public_material_is_distinct_v1(deployment) {
            return Err(RemoteAuthorityDeploymentConfigErrorV1::DeploymentSetNotIndependent);
        }
    }
    for (left_index, left) in deployments.iter().enumerate() {
        for right in deployments.iter().skip(left_index + 1) {
            if left.endpoint == right.endpoint {
                return Err(RemoteAuthorityDeploymentConfigErrorV1::DeploymentSetNotIndependent);
            }
            let left_material = remote_deployment_public_material_v1(left);
            let right_material = remote_deployment_public_material_v1(right);
            for left_value in &left_material {
                if right_material.contains(left_value) {
                    return Err(
                        RemoteAuthorityDeploymentConfigErrorV1::DeploymentSetNotIndependent,
                    );
                }
            }
        }
    }
    Ok(())
}

fn remote_deployment_public_material_v1(
    deployment: &RemoteRollbackAuthorityDeploymentDescriptorV1,
) -> Vec<&[u8; 32]> {
    let mut material = vec![
        &deployment.authority_instance_id,
        &deployment.authority_verifying_key,
        &deployment.namespace,
        &deployment.client_verifying_key,
        &deployment.client_key_id,
    ];
    material.extend(deployment.leaf_spki_sha256_pins.iter());
    material
}

fn remote_deployment_public_material_is_distinct_v1(
    deployment: &RemoteRollbackAuthorityDeploymentDescriptorV1,
) -> bool {
    let material = remote_deployment_public_material_v1(deployment);
    material
        .iter()
        .enumerate()
        .all(|(index, value)| !material.iter().skip(index + 1).any(|other| value == other))
}

/// Loads one owner-only configuration and both owner-only raw 32-byte secret
/// files, verifies every public/secret binding locally, then constructs the
/// mandatory-WebPKI-plus-SPKI-pinned production client. No network request is
/// performed by this function.
#[cfg(test)]
fn load_remote_rollback_authority_deployment_v1(
    config_path: &Path,
) -> Result<ConfiguredRemoteRollbackAuthorityV1, RemoteAuthorityDeploymentConfigErrorV1> {
    load_remote_rollback_authority_deployment_for_domain_inner_v1(config_path, None)
}

/// Loads a production deployment and additionally proves that its two raw
/// secrets and every authority binding are distinct from the provider or
/// issuer identity which will consume it.
pub fn load_remote_rollback_authority_deployment_for_business_domain_v1(
    config_path: &Path,
    business_domain_id: [u8; 32],
) -> Result<ConfiguredRemoteRollbackAuthorityV1, RemoteAuthorityDeploymentConfigErrorV1> {
    if business_domain_id.iter().all(|byte| *byte == 0) {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::CryptographicRoleCollision);
    }
    load_remote_rollback_authority_deployment_for_domain_inner_v1(
        config_path,
        Some(business_domain_id),
    )
}

fn load_remote_rollback_authority_deployment_for_domain_inner_v1(
    config_path: &Path,
    business_domain_id: Option<[u8; 32]>,
) -> Result<ConfiguredRemoteRollbackAuthorityV1, RemoteAuthorityDeploymentConfigErrorV1> {
    let parsed = parse_remote_rollback_authority_deployment_config_v1(config_path)?;
    let ParsedDeploymentConfigV1 {
        descriptor,
        client_signing_seed_path: signing_path,
        value_root_key_path: value_root_path,
        connect_timeout,
        io_timeout,
        attempt_timeout,
        operation_timeout,
        #[cfg(feature = "test-only-webpki-root")]
        test_only_webpki_root_pem_path,
    } = parsed;
    let RemoteRollbackAuthorityDeploymentDescriptorV1 {
        endpoint,
        authority_instance_id,
        authority_verifying_key: authority_key_bytes,
        namespace,
        client_verifying_key: expected_client_key,
        client_key_id,
        leaf_spki_sha256_pins: pins,
    } = descriptor;
    let authority_verifying_key = VerifyingKey::from_bytes(&authority_key_bytes)
        .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidConfig)?;

    let (signing_seed, signing_identity) =
        read_private_file_bounded_v1(&signing_path, SECRET_BYTES_V1, PrivateFileKindV1::Secret)?;
    let (value_root_bytes, value_root_identity) =
        read_private_file_bounded_v1(&value_root_path, SECRET_BYTES_V1, PrivateFileKindV1::Secret)?;
    if signing_identity == value_root_identity {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::SecretPathsAlias);
    }
    let signing_seed = exact_nonzero_secret_v1(signing_seed)?;
    let value_root_bytes = exact_nonzero_secret_v1(value_root_bytes)?;
    if signing_seed.as_slice() == value_root_bytes.as_slice() {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::CryptographicRoleCollision);
    }
    // A secret which is byte-for-byte equal to any configured public value is
    // not secret at all. This is especially catastrophic for the value root:
    // it is the HKDF input from which the authority value AEAD/HMAC keys are
    // derived. Reject the same misconfiguration for the signing seed so a
    // public instance, namespace, key, or TLS pin can never become signing
    // material either.
    let public_material = [
        authority_instance_id,
        authority_key_bytes,
        namespace,
        expected_client_key,
        client_key_id,
    ];
    if business_domain_id.is_some_and(|business_id| {
        public_material.contains(&business_id) || pins.contains(&business_id)
    }) {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::CryptographicRoleCollision);
    }
    let collides_with_public_material = |secret: &[u8]| {
        public_material
            .iter()
            .any(|value| secret == value.as_slice())
            || pins.iter().any(|pin| secret == pin.as_slice())
            || business_domain_id.is_some_and(|business_id| secret == business_id.as_slice())
    };
    if collides_with_public_material(signing_seed.as_slice())
        || collides_with_public_material(value_root_bytes.as_slice())
    {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::CryptographicRoleCollision);
    }
    let signing_key = SigningKey::from_bytes(&signing_seed);
    if signing_key.verifying_key().to_bytes() != expected_client_key {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::ClientKeyMismatch);
    }
    if signing_key.verifying_key() == authority_verifying_key {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::CryptographicRoleCollision);
    }

    let signer = AuthorityClientSignerV1::new(authority_instance_id, namespace, signing_key)
        .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidCryptographicBinding)?;
    let value_root_key = AuthorityValueRootKeyV1::from_bytes(*value_root_bytes)
        .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidCryptographicBinding)?;
    let codec = AuthorityValueCodecV1::derive(
        &value_root_key,
        authority_instance_id,
        namespace,
        &signer.verifying_key(),
    )
    .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidCryptographicBinding)?;
    if codec.binding() != signer.binding() {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::InvalidCryptographicBinding);
    }

    #[cfg(not(feature = "test-only-webpki-root"))]
    let client = RemoteRollbackAuthorityClientV1::new(
        endpoint,
        connect_timeout,
        io_timeout,
        attempt_timeout,
        &pins,
        signer,
        authority_verifying_key,
    )
    .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidTransportConfiguration)?;
    #[cfg(feature = "test-only-webpki-root")]
    let client = match test_only_webpki_root_pem_path {
        Some(path) => {
            let (root_pem, _) = read_private_file_bounded_v1(
                &path,
                MAX_TEST_ONLY_WEBPKI_ROOT_PEM_BYTES_V1,
                PrivateFileKindV1::Config,
            )?;
            RemoteRollbackAuthorityClientV1::new_with_test_only_webpki_root_pem(
                endpoint,
                connect_timeout,
                io_timeout,
                attempt_timeout,
                &pins,
                root_pem.as_slice(),
                signer,
                authority_verifying_key,
            )
        }
        None => RemoteRollbackAuthorityClientV1::new(
            endpoint,
            connect_timeout,
            io_timeout,
            attempt_timeout,
            &pins,
            signer,
            authority_verifying_key,
        ),
    }
    .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidTransportConfiguration)?;
    if client.binding() != codec.binding() {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::InvalidCryptographicBinding);
    }
    Ok(ConfiguredRemoteRollbackAuthorityV1 {
        client,
        codec,
        operation_timeout,
    })
}

fn parse_remote_rollback_authority_deployment_config_v1(
    config_path: &Path,
) -> Result<ParsedDeploymentConfigV1, RemoteAuthorityDeploymentConfigErrorV1> {
    let (config_bytes, _) =
        read_private_file_bounded_v1(config_path, MAX_CONFIG_BYTES_V1, PrivateFileKindV1::Config)?;
    let config_text = std::str::from_utf8(config_bytes.as_slice())
        .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidConfig)?;
    let config: DeploymentConfigFileV1 = toml::from_str(config_text)
        .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidConfig)?;
    if config.schema != CONFIG_SCHEMA_V1 {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::InvalidConfig);
    }

    StrictHttpsClientV1::validate_base_endpoint(&config.endpoint)
        .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidTransportConfiguration)?;

    let authority_instance_id = decode_lower_hex_v1::<32>(&config.authority_instance_id_hex)?;
    let authority_key_bytes = decode_lower_hex_v1::<32>(&config.authority_verifying_key_hex)?;
    VerifyingKey::from_bytes(&authority_key_bytes)
        .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidConfig)?;
    let namespace = decode_lower_hex_v1::<32>(&config.namespace_hex)?;
    let expected_client_key = decode_lower_hex_v1::<32>(&config.client_verifying_key_hex)?;
    let expected_client_verifying_key = VerifyingKey::from_bytes(&expected_client_key)
        .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidConfig)?;
    let client_key_id = authority_client_key_id_v1(&expected_client_verifying_key);
    if authority_instance_id.iter().all(|byte| *byte == 0)
        || namespace.iter().all(|byte| *byte == 0)
        || authority_key_bytes.iter().all(|byte| *byte == 0)
        || expected_client_key.iter().all(|byte| *byte == 0)
    {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::InvalidConfig);
    }

    let signing_path = absolute_path_v1(&config.client_signing_seed_path)?;
    let value_root_path = absolute_path_v1(&config.value_root_key_path)?;
    if signing_path == value_root_path {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::SecretPathsAlias);
    }
    if authority_key_bytes == expected_client_key {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::CryptographicRoleCollision);
    }

    let pins = decode_pins_v1(&config.leaf_spki_sha256_pins_hex)?;
    let connect_timeout = timeout_v1(config.connect_timeout_ms)?;
    let io_timeout = timeout_v1(config.io_timeout_ms)?;
    let attempt_timeout = timeout_v1(config.attempt_timeout_ms)?;
    let operation_timeout = timeout_v1(config.operation_timeout_ms)?;
    #[cfg(feature = "test-only-webpki-root")]
    let test_only_webpki_root_pem_path = config
        .test_only_webpki_root_pem_path
        .as_deref()
        .map(absolute_path_v1)
        .transpose()?;
    if connect_timeout > attempt_timeout
        || io_timeout > attempt_timeout
        || attempt_timeout
            .checked_mul(3)
            .map_or(true, |minimum| minimum > operation_timeout)
    {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::InvalidTransportConfiguration);
    }
    let descriptor = RemoteRollbackAuthorityDeploymentDescriptorV1 {
        endpoint: config.endpoint,
        authority_instance_id,
        authority_verifying_key: authority_key_bytes,
        namespace,
        client_verifying_key: expected_client_key,
        client_key_id,
        leaf_spki_sha256_pins: pins,
    };
    if !remote_deployment_public_material_is_distinct_v1(&descriptor) {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::CryptographicRoleCollision);
    }
    Ok(ParsedDeploymentConfigV1 {
        descriptor,
        client_signing_seed_path: signing_path,
        value_root_key_path: value_root_path,
        connect_timeout,
        io_timeout,
        attempt_timeout,
        operation_timeout,
        #[cfg(feature = "test-only-webpki-root")]
        test_only_webpki_root_pem_path,
    })
}

fn decode_pins_v1(
    encoded: &[String],
) -> Result<Vec<[u8; 32]>, RemoteAuthorityDeploymentConfigErrorV1> {
    if !(1..=2).contains(&encoded.len()) {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::InvalidTransportConfiguration);
    }
    let mut pins = Vec::with_capacity(encoded.len());
    for value in encoded {
        let pin = decode_lower_hex_v1::<32>(value)
            .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidTransportConfiguration)?;
        if pin.iter().all(|byte| *byte == 0) || pins.contains(&pin) {
            return Err(RemoteAuthorityDeploymentConfigErrorV1::InvalidTransportConfiguration);
        }
        pins.push(pin);
    }
    Ok(pins)
}

fn timeout_v1(milliseconds: u64) -> Result<Duration, RemoteAuthorityDeploymentConfigErrorV1> {
    if !(1..=MAX_TIMEOUT_MILLIS_V1).contains(&milliseconds) {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::InvalidTransportConfiguration);
    }
    Ok(Duration::from_millis(milliseconds))
}

fn absolute_path_v1(encoded: &str) -> Result<PathBuf, RemoteAuthorityDeploymentConfigErrorV1> {
    let path = PathBuf::from(encoded);
    if encoded.is_empty() || !path.is_absolute() || path.file_name().is_none() {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::UnsafeSecretPath);
    }
    Ok(path)
}

fn decode_lower_hex_v1<const N: usize>(
    encoded: &str,
) -> Result<[u8; N], RemoteAuthorityDeploymentConfigErrorV1> {
    if encoded.len() != N.saturating_mul(2)
        || !encoded
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::InvalidConfig);
    }
    hex::decode(encoded)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RemoteAuthorityDeploymentConfigErrorV1::InvalidConfig)
}

fn exact_nonzero_secret_v1(
    bytes: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<[u8; 32]>, RemoteAuthorityDeploymentConfigErrorV1> {
    let value: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| RemoteAuthorityDeploymentConfigErrorV1::InvalidSecret)?;
    let value = Zeroizing::new(value);
    if value.iter().all(|byte| *byte == 0) {
        return Err(RemoteAuthorityDeploymentConfigErrorV1::InvalidSecret);
    }
    Ok(value)
}

type PrivateFileIdentityV1 = pir_private_files::PrivateFileIdentityV1;

#[derive(Clone, Copy)]
enum PrivateFileKindV1 {
    Config,
    Secret,
}

fn read_private_file_bounded_v1(
    path: &Path,
    maximum: u64,
    kind: PrivateFileKindV1,
) -> Result<(Zeroizing<Vec<u8>>, PrivateFileIdentityV1), RemoteAuthorityDeploymentConfigErrorV1> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(path_error_v1(kind));
    }
    let maximum = usize::try_from(maximum).map_err(|_| size_error_v1(kind))?;
    let (bytes, checked) = pir_private_files::read_private_file_bounded_with_identity_v1(
        path,
        maximum,
        pir_private_files::PrivateFileModeV1::ReadOnlyOrReadWrite,
        match kind {
            PrivateFileKindV1::Config => "remote rollback-authority config",
            PrivateFileKindV1::Secret => "remote rollback-authority secret",
        },
    )
    .map_err(|_| path_error_v1(kind))?;
    Ok((bytes, checked.identity()))
}

const fn path_error_v1(kind: PrivateFileKindV1) -> RemoteAuthorityDeploymentConfigErrorV1 {
    match kind {
        PrivateFileKindV1::Config => RemoteAuthorityDeploymentConfigErrorV1::UnsafeConfigPath,
        PrivateFileKindV1::Secret => RemoteAuthorityDeploymentConfigErrorV1::UnsafeSecretPath,
    }
}

const fn size_error_v1(kind: PrivateFileKindV1) -> RemoteAuthorityDeploymentConfigErrorV1 {
    match kind {
        PrivateFileKindV1::Config => RemoteAuthorityDeploymentConfigErrorV1::ConfigTooLarge,
        PrivateFileKindV1::Secret => RemoteAuthorityDeploymentConfigErrorV1::InvalidSecret,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    use tempfile::tempdir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    #[cfg(unix)]
    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    fn fixture() -> (tempfile::TempDir, PathBuf, SigningKey) {
        let root = tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let authority = SigningKey::from_bytes(&[7; 32]);
        let client = SigningKey::from_bytes(&[9; 32]);
        let signing_path = root.path().join("client.seed");
        let value_path = root.path().join("value.key");
        write_private(&signing_path, &[9; 32]);
        write_private(&value_path, &[11; 32]);
        let config = format!(
            "schema = \"{CONFIG_SCHEMA_V1}\"\nendpoint = \"https://authority.example\"\nauthority_instance_id_hex = \"{}\"\nauthority_verifying_key_hex = \"{}\"\nnamespace_hex = \"{}\"\nclient_verifying_key_hex = \"{}\"\nclient_signing_seed_path = \"{}\"\nvalue_root_key_path = \"{}\"\nleaf_spki_sha256_pins_hex = [\"{}\"]\nconnect_timeout_ms = 1000\nio_timeout_ms = 1000\nattempt_timeout_ms = 2000\noperation_timeout_ms = 6000\n",
            hex::encode([3; 32]),
            hex::encode(authority.verifying_key().to_bytes()),
            hex::encode([5; 32]),
            hex::encode(client.verifying_key().to_bytes()),
            signing_path.display(),
            value_path.display(),
            hex::encode([13; 32]),
        );
        let config_path = root.path().join("remote.toml");
        write_private(&config_path, config.as_bytes());
        (root, config_path, client)
    }

    #[cfg(unix)]
    fn descriptor(index: u8) -> RemoteRollbackAuthorityDeploymentDescriptorV1 {
        let authority = SigningKey::from_bytes(&[index; 32]);
        let client = SigningKey::from_bytes(&[index.saturating_add(16); 32]);
        RemoteRollbackAuthorityDeploymentDescriptorV1 {
            endpoint: format!("https://authority-{index}.example"),
            authority_instance_id: [index.saturating_add(32); 32],
            authority_verifying_key: authority.verifying_key().to_bytes(),
            namespace: [index.saturating_add(64); 32],
            client_verifying_key: client.verifying_key().to_bytes(),
            client_key_id: authority_client_key_id_v1(&client.verifying_key()),
            leaf_spki_sha256_pins: vec![[index.saturating_add(96); 32]],
        }
    }

    #[cfg(unix)]
    fn assert_not_independent(deployments: &[RemoteRollbackAuthorityDeploymentDescriptorV1]) {
        assert_eq!(
            validate_independent_remote_rollback_authority_deployments_v1(deployments),
            Err(RemoteAuthorityDeploymentConfigErrorV1::DeploymentSetNotIndependent)
        );
    }

    #[cfg(unix)]
    #[test]
    fn deployment_loader_constructs_exact_bound_pinned_client() {
        let (_root, config, _client) = fixture();
        let configured = load_remote_rollback_authority_deployment_v1(&config).unwrap();
        let (client, codec, timeout) = configured.into_parts();
        assert_eq!(client.binding(), codec.binding());
        assert_eq!(timeout, Duration::from_secs(6));
    }

    #[cfg(unix)]
    #[test]
    fn public_descriptor_never_reads_secret_files_and_redacts_debug() {
        let (root, config, _client) = fixture();
        fs::remove_file(root.path().join("client.seed")).unwrap();
        fs::remove_file(root.path().join("value.key")).unwrap();

        let descriptor = load_remote_rollback_authority_deployment_descriptor_v1(&config).unwrap();
        let rendered = format!("{descriptor:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("authority.example"));
        assert!(!rendered.contains(&hex::encode([3; 32])));
        assert_eq!(
            load_remote_rollback_authority_deployment_v1(&config).unwrap_err(),
            RemoteAuthorityDeploymentConfigErrorV1::UnsafeSecretPath
        );
    }

    #[cfg(unix)]
    #[test]
    fn public_descriptor_config_read_rejects_symlink_and_hardlink() {
        use std::os::unix::fs::symlink;

        let (root, config, _client) = fixture();
        let symlink_path = root.path().join("remote-link.toml");
        symlink(&config, &symlink_path).unwrap();
        assert_eq!(
            load_remote_rollback_authority_deployment_descriptor_v1(&symlink_path).unwrap_err(),
            RemoteAuthorityDeploymentConfigErrorV1::UnsafeConfigPath
        );

        let hardlink_path = root.path().join("remote-hardlink.toml");
        fs::hard_link(&config, &hardlink_path).unwrap();
        assert_eq!(
            load_remote_rollback_authority_deployment_descriptor_v1(&config).unwrap_err(),
            RemoteAuthorityDeploymentConfigErrorV1::UnsafeConfigPath
        );
    }

    #[cfg(unix)]
    #[test]
    fn deployment_set_validator_accepts_only_globally_independent_public_bindings() {
        for count in [2_usize, 3, 4, MAX_INDEPENDENT_DEPLOYMENTS_V1] {
            let independent: Vec<_> = (1..=count)
                .map(|index| descriptor(u8::try_from(index).unwrap()))
                .collect();
            validate_independent_remote_rollback_authority_deployments_v1(&independent).unwrap();
        }

        for invalid in [0_usize, 1, MAX_INDEPENDENT_DEPLOYMENTS_V1 + 1] {
            let deployments: Vec<_> = (1..=invalid)
                .map(|index| descriptor(u8::try_from(index).unwrap()))
                .collect();
            assert_eq!(
                validate_independent_remote_rollback_authority_deployments_v1(&deployments),
                Err(RemoteAuthorityDeploymentConfigErrorV1::InvalidDeploymentSetSize)
            );
        }

        let mut duplicate_endpoint = [descriptor(1), descriptor(2), descriptor(3)];
        let repeated = duplicate_endpoint[0].endpoint.clone();
        duplicate_endpoint[1].endpoint = repeated;
        assert_not_independent(&duplicate_endpoint);

        let mut duplicate_instance = [descriptor(1), descriptor(2), descriptor(3)];
        let repeated = duplicate_instance[0].authority_instance_id;
        duplicate_instance[1].authority_instance_id = repeated;
        assert_not_independent(&duplicate_instance);

        let mut duplicate_authority_key = [descriptor(1), descriptor(2), descriptor(3)];
        let repeated = duplicate_authority_key[0].authority_verifying_key;
        duplicate_authority_key[1].authority_verifying_key = repeated;
        assert_not_independent(&duplicate_authority_key);

        let mut duplicate_namespace = [descriptor(1), descriptor(2), descriptor(3)];
        let repeated = duplicate_namespace[0].namespace;
        duplicate_namespace[1].namespace = repeated;
        assert_not_independent(&duplicate_namespace);

        let mut duplicate_client_key = [descriptor(1), descriptor(2), descriptor(3)];
        let repeated = duplicate_client_key[0].client_verifying_key;
        duplicate_client_key[1].client_verifying_key = repeated;
        assert_not_independent(&duplicate_client_key);

        let mut duplicate_client_key_id = [descriptor(1), descriptor(2), descriptor(3)];
        let repeated = duplicate_client_key_id[0].client_key_id;
        duplicate_client_key_id[1].client_key_id = repeated;
        assert_not_independent(&duplicate_client_key_id);

        let mut cross_role_key_reuse = [descriptor(1), descriptor(2), descriptor(3)];
        let repeated = cross_role_key_reuse[0].authority_verifying_key;
        cross_role_key_reuse[1].client_verifying_key = repeated;
        assert_not_independent(&cross_role_key_reuse);

        let mut cross_role_public_reuse = [descriptor(1), descriptor(2), descriptor(3)];
        let repeated = cross_role_public_reuse[0].client_key_id;
        cross_role_public_reuse[1].namespace = repeated;
        assert_not_independent(&cross_role_public_reuse);

        let mut within_deployment_public_reuse = [descriptor(1), descriptor(2)];
        within_deployment_public_reuse[0].authority_instance_id =
            within_deployment_public_reuse[0].client_key_id;
        assert_not_independent(&within_deployment_public_reuse);

        let mut overlapping_pin = [descriptor(1), descriptor(2), descriptor(3)];
        let repeated = overlapping_pin[0].leaf_spki_sha256_pins.clone();
        overlapping_pin[1].leaf_spki_sha256_pins = repeated;
        assert_not_independent(&overlapping_pin);
    }

    #[cfg(unix)]
    #[test]
    fn deployment_loader_rejects_key_mismatch_and_unsafe_mode() {
        let (root, config, _client) = fixture();
        let seed = root.path().join("client.seed");
        fs::write(&seed, [17; 32]).unwrap();
        assert_eq!(
            load_remote_rollback_authority_deployment_v1(&config).unwrap_err(),
            RemoteAuthorityDeploymentConfigErrorV1::ClientKeyMismatch
        );
        fs::write(&seed, [9; 32]).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            load_remote_rollback_authority_deployment_v1(&config).unwrap_err(),
            RemoteAuthorityDeploymentConfigErrorV1::UnsafeConfigPath
        );
    }

    #[cfg(unix)]
    #[test]
    fn deployment_loader_rejects_aliases_unknown_fields_and_duplicate_pins() {
        let (root, config, _client) = fixture();
        let original = fs::read_to_string(&config).unwrap();
        let value_path = root.path().join("value.key");
        let signing_path = root.path().join("client.seed");
        fs::remove_file(&value_path).unwrap();
        fs::hard_link(&signing_path, &value_path).unwrap();
        assert_eq!(
            load_remote_rollback_authority_deployment_v1(&config).unwrap_err(),
            RemoteAuthorityDeploymentConfigErrorV1::UnsafeSecretPath
        );

        fs::remove_file(&value_path).unwrap();
        fs::set_permissions(&signing_path, fs::Permissions::from_mode(0o600)).unwrap();
        write_private(&value_path, &[11; 32]);
        fs::write(&config, format!("{original}unknown = true\n")).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_remote_rollback_authority_deployment_v1(&config).unwrap_err(),
            RemoteAuthorityDeploymentConfigErrorV1::InvalidConfig
        );

        let duplicated = original.replace(
            &format!(
                "leaf_spki_sha256_pins_hex = [\"{}\"]",
                hex::encode([13; 32])
            ),
            &format!(
                "leaf_spki_sha256_pins_hex = [\"{0}\", \"{0}\"]",
                hex::encode([13; 32])
            ),
        );
        fs::write(&config, duplicated).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_remote_rollback_authority_deployment_v1(&config).unwrap_err(),
            RemoteAuthorityDeploymentConfigErrorV1::InvalidTransportConfiguration
        );
    }

    #[cfg(all(unix, not(feature = "test-only-webpki-root")))]
    #[test]
    fn production_config_rejects_test_only_webpki_root_field() {
        let (_root, config, _client) = fixture();
        let original = fs::read_to_string(&config).unwrap();
        fs::write(
            &config,
            format!("{original}test_only_webpki_root_pem_path = \"/private/test-root.pem\"\n"),
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_remote_rollback_authority_deployment_v1(&config).unwrap_err(),
            RemoteAuthorityDeploymentConfigErrorV1::InvalidConfig
        );
    }

    #[cfg(all(unix, feature = "test-only-webpki-root"))]
    #[test]
    fn test_only_webpki_root_requires_owner_only_regular_file() {
        let (root, config, _client) = fixture();
        let root_path = root.path().join("test-root.pem");
        fs::write(&root_path, b"not inspected before path security").unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o644)).unwrap();
        let original = fs::read_to_string(&config).unwrap();
        fs::write(
            &config,
            format!(
                "{original}test_only_webpki_root_pem_path = {:?}\n",
                root_path.display().to_string()
            ),
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_remote_rollback_authority_deployment_v1(&config).unwrap_err(),
            RemoteAuthorityDeploymentConfigErrorV1::UnsafeConfigPath
        );
    }

    #[cfg(unix)]
    #[test]
    fn deployment_loader_rejects_equal_key_material_across_roles() {
        let (root, config, client) = fixture();
        let original = fs::read_to_string(&config).unwrap();
        let value_path = root.path().join("value.key");
        fs::write(&value_path, [9; 32]).unwrap();
        assert_eq!(
            load_remote_rollback_authority_deployment_v1(&config).unwrap_err(),
            RemoteAuthorityDeploymentConfigErrorV1::CryptographicRoleCollision
        );

        fs::write(&value_path, [11; 32]).unwrap();
        let client_key = hex::encode(client.verifying_key().to_bytes());
        let authority_key = SigningKey::from_bytes(&[7; 32]);
        let authority_key = hex::encode(authority_key.verifying_key().to_bytes());
        let collapsed = original.replace(&authority_key, &client_key);
        fs::write(&config, collapsed).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_remote_rollback_authority_deployment_v1(&config).unwrap_err(),
            RemoteAuthorityDeploymentConfigErrorV1::CryptographicRoleCollision
        );
    }

    #[cfg(unix)]
    #[test]
    fn deployment_loader_rejects_secret_material_equal_to_any_public_binding() {
        let authority_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        let client_verifying_key = SigningKey::from_bytes(&[9; 32]).verifying_key();
        let client_key = client_verifying_key.to_bytes();
        let client_key_id = authority_client_key_id_v1(&client_verifying_key);
        let public_values = [
            [3; 32],
            authority_key,
            [5; 32],
            client_key,
            client_key_id,
            [13; 32],
        ];
        for public_value in public_values {
            let (root, config, _client) = fixture();
            fs::write(root.path().join("value.key"), public_value).unwrap();
            assert_eq!(
                load_remote_rollback_authority_deployment_v1(&config).unwrap_err(),
                RemoteAuthorityDeploymentConfigErrorV1::CryptographicRoleCollision
            );
        }

        // The collision check runs before the Ed25519 public-key binding check,
        // so even a wrongly provisioned seed that equals the configured client
        // public key or its derived authority key ID is classified as exposed
        // role material rather than merely as a mismatched key.
        for public_value in public_values {
            let (root, config, _client) = fixture();
            fs::write(root.path().join("client.seed"), public_value).unwrap();
            assert_eq!(
                load_remote_rollback_authority_deployment_v1(&config).unwrap_err(),
                RemoteAuthorityDeploymentConfigErrorV1::CryptographicRoleCollision
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn business_domain_loader_rejects_zero_and_every_cross_role_collision() {
        let authority_key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let client_key = SigningKey::from_bytes(&[9; 32]).verifying_key();
        let client_key_id = authority_client_key_id_v1(&client_key);
        for business_domain_id in [
            [0; 32],
            [3; 32],
            authority_key.to_bytes(),
            [5; 32],
            client_key.to_bytes(),
            client_key_id,
            [13; 32],
            [9; 32],
            [11; 32],
        ] {
            let (_root, config, _client) = fixture();
            assert_eq!(
                load_remote_rollback_authority_deployment_for_business_domain_v1(
                    &config,
                    business_domain_id,
                )
                .unwrap_err(),
                RemoteAuthorityDeploymentConfigErrorV1::CryptographicRoleCollision
            );
        }

        let (_root, config, _client) = fixture();
        load_remote_rollback_authority_deployment_for_business_domain_v1(&config, [97; 32])
            .unwrap();
    }
}
