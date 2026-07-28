use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use pir_rollback_authority_protocol::authority_client_key_id_v1;
use zeroize::{Zeroize, Zeroizing};

const AUTHORITY_METADATA_MAGIC_V1: &str = "bitcoinpir_rollback_authority_public_v1";
const CLIENT_METADATA_MAGIC_V1: &str = "bitcoinpir_rollback_authority_client_v1";
const MAX_METADATA_BYTES_V1: u64 = 512;

pub(crate) struct AuthorityPublicMetadataV1 {
    pub(crate) authority_instance_id: [u8; 32],
    pub(crate) authority_verifying_key: VerifyingKey,
}

impl AuthorityPublicMetadataV1 {
    pub(crate) fn encode(&self) -> String {
        format!(
            "{AUTHORITY_METADATA_MAGIC_V1}\nauthority_instance_id={}\nauthority_verifying_key={}\n",
            hex::encode(self.authority_instance_id),
            hex::encode(self.authority_verifying_key.as_bytes()),
        )
    }
}

pub(crate) struct ClientProvisioningMetadataV1 {
    pub(crate) namespace: [u8; 32],
    pub(crate) client_key_id: [u8; 32],
    pub(crate) client_verifying_key: VerifyingKey,
}

impl ClientProvisioningMetadataV1 {
    pub(crate) fn encode(&self) -> String {
        format!(
            "{CLIENT_METADATA_MAGIC_V1}\nnamespace={}\nclient_key_id={}\nclient_verifying_key={}\n",
            hex::encode(self.namespace),
            hex::encode(self.client_key_id),
            hex::encode(self.client_verifying_key.as_bytes()),
        )
    }
}

pub(crate) fn generate_authority_v1(
    secret_path: &Path,
    metadata_path: &Path,
) -> Result<AuthorityPublicMetadataV1, String> {
    let (secret_target, metadata_target) = preflight_distinct_new_outputs_v1(
        secret_path,
        metadata_path,
        "authority secret",
        "authority metadata",
    )?;
    let mut secret = random_nonzero_v1("authority signing seed")?;
    let signing_key = SigningKey::from_bytes(&secret);
    let instance_id = random_nonzero_v1("authority instance ID")?;
    let metadata = AuthorityPublicMetadataV1 {
        authority_instance_id: *instance_id,
        authority_verifying_key: signing_key.verifying_key(),
    };
    if let Err(error) =
        write_new_private_file_v1(&secret_target, secret.as_slice(), "authority secret")
    {
        return Err(format!(
            "partial authority generation: secret was not completed and metadata was not started; inspect both outputs: {error}"
        ));
    }
    secret.zeroize();
    if let Err(error) = write_new_private_file_v1(
        &metadata_target,
        metadata.encode().as_bytes(),
        "authority metadata",
    ) {
        return Err(format!(
            "partial authority generation: secret was created but metadata was not completed; inspect both outputs: {error}"
        ));
    }
    Ok(metadata)
}

pub(crate) fn generate_client_v1(
    secret_path: &Path,
    value_root_key_path: &Path,
    metadata_path: &Path,
) -> Result<ClientProvisioningMetadataV1, String> {
    generate_client_with_writer_v1(
        secret_path,
        value_root_key_path,
        metadata_path,
        write_new_private_file_v1,
    )
}

fn generate_client_with_writer_v1(
    secret_path: &Path,
    value_root_key_path: &Path,
    metadata_path: &Path,
    mut writer: impl FnMut(&Path, &[u8], &str) -> Result<(), String>,
) -> Result<ClientProvisioningMetadataV1, String> {
    let secret_target = checked_new_target_v1(secret_path, "client secret")?;
    let value_root_key_target =
        checked_new_target_v1(value_root_key_path, "client value root key")?;
    let metadata_target = checked_new_target_v1(metadata_path, "client metadata")?;
    if secret_target == value_root_key_target
        || secret_target == metadata_target
        || value_root_key_target == metadata_target
    {
        return Err("client output paths must resolve to three distinct targets".to_owned());
    }
    let mut secret = random_nonzero_v1("client signing seed")?;
    let value_root_key = random_nonzero_v1("client value root key")?;
    let signing_key = SigningKey::from_bytes(&secret);
    let client_verifying_key = signing_key.verifying_key();
    let namespace = random_nonzero_v1("client namespace")?;
    let metadata = ClientProvisioningMetadataV1 {
        namespace: *namespace,
        client_key_id: authority_client_key_id_v1(&client_verifying_key),
        client_verifying_key,
    };
    if let Err(error) = writer(&secret_target, secret.as_slice(), "client secret") {
        return Err(format!(
            "partial client generation: signing secret was not completed and later outputs were not started; inspect all three outputs: {error}"
        ));
    }
    secret.zeroize();
    if let Err(error) = writer(
        &value_root_key_target,
        value_root_key.as_slice(),
        "client value root key",
    ) {
        return Err(format!(
            "partial client generation: signing secret was created but value root key was not completed and metadata was not started; inspect all three outputs: {error}"
        ));
    }
    if let Err(error) = writer(
        &metadata_target,
        metadata.encode().as_bytes(),
        "client metadata",
    ) {
        return Err(format!(
            "partial client generation: signing secret and value root key were created but metadata was not completed; inspect all three outputs: {error}"
        ));
    }
    Ok(metadata)
}

#[cfg(test)]
pub(crate) fn generate_client_failing_at_stage_for_tests_v1(
    secret_path: &Path,
    value_root_key_path: &Path,
    metadata_path: &Path,
    failing_stage: usize,
) -> Result<ClientProvisioningMetadataV1, String> {
    let mut stage = 0_usize;
    generate_client_with_writer_v1(
        secret_path,
        value_root_key_path,
        metadata_path,
        |path, bytes, label| {
            stage = stage.saturating_add(1);
            if stage == failing_stage {
                Err("injected ceremony write failure".to_owned())
            } else {
                write_new_private_file_v1(path, bytes, label)
            }
        },
    )
}

pub(crate) fn read_authority_metadata_v1(path: &Path) -> Result<AuthorityPublicMetadataV1, String> {
    let bytes = read_private_file_bounded_v1(path, "authority metadata", MAX_METADATA_BYTES_V1)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "authority metadata must be canonical UTF-8 text".to_owned())?;
    let mut lines = text.lines();
    if lines.next() != Some(AUTHORITY_METADATA_MAGIC_V1) {
        return Err("authority metadata magic is invalid".to_owned());
    }
    let authority_instance_id = parse_exact_field_v1::<32>(
        lines.next(),
        "authority_instance_id",
        "authority instance ID",
    )?;
    let authority_verifying_key_bytes = parse_exact_field_v1::<32>(
        lines.next(),
        "authority_verifying_key",
        "authority verifying key",
    )?;
    if lines.next().is_some() || !text.ends_with('\n') {
        return Err("authority metadata is not canonical".to_owned());
    }
    if authority_instance_id.iter().all(|byte| *byte == 0) {
        return Err("authority instance ID must be nonzero".to_owned());
    }
    let authority_verifying_key = VerifyingKey::from_bytes(&authority_verifying_key_bytes)
        .map_err(|_| "authority verifying key is invalid".to_owned())?;
    let metadata = AuthorityPublicMetadataV1 {
        authority_instance_id,
        authority_verifying_key,
    };
    if metadata.encode().as_bytes() != bytes.as_slice() {
        return Err("authority metadata is not canonical".to_owned());
    }
    Ok(metadata)
}

pub(crate) fn read_client_metadata_v1(path: &Path) -> Result<ClientProvisioningMetadataV1, String> {
    let bytes = read_private_file_bounded_v1(path, "client metadata", MAX_METADATA_BYTES_V1)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "client metadata must be canonical UTF-8 text".to_owned())?;
    let mut lines = text.lines();
    if lines.next() != Some(CLIENT_METADATA_MAGIC_V1) {
        return Err("client metadata magic is invalid".to_owned());
    }
    let namespace = parse_exact_field_v1::<32>(lines.next(), "namespace", "client namespace")?;
    let client_key_id = parse_exact_field_v1::<32>(lines.next(), "client_key_id", "client key ID")?;
    let client_verifying_key_bytes =
        parse_exact_field_v1::<32>(lines.next(), "client_verifying_key", "client verifying key")?;
    if lines.next().is_some() || !text.ends_with('\n') {
        return Err("client metadata is not canonical".to_owned());
    }
    if namespace.iter().all(|byte| *byte == 0) {
        return Err("client namespace must be nonzero".to_owned());
    }
    let client_verifying_key = VerifyingKey::from_bytes(&client_verifying_key_bytes)
        .map_err(|_| "client verifying key is invalid".to_owned())?;
    if authority_client_key_id_v1(&client_verifying_key) != client_key_id {
        return Err("client key ID does not match the client verifying key".to_owned());
    }
    let metadata = ClientProvisioningMetadataV1 {
        namespace,
        client_key_id,
        client_verifying_key,
    };
    if metadata.encode().as_bytes() != bytes.as_slice() {
        return Err("client metadata is not canonical".to_owned());
    }
    Ok(metadata)
}

pub(crate) fn read_secret_seed_v1(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let bytes = read_private_file_bounded_v1(path, "signing secret", 32)?;
    if bytes.len() != 32 {
        return Err("signing secret must contain exactly 32 raw bytes".to_owned());
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&bytes);
    if seed.iter().all(|byte| *byte == 0) {
        return Err("signing secret must be nonzero".to_owned());
    }
    Ok(seed)
}

#[cfg(test)]
pub(crate) fn read_value_root_key_for_tests_v1(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let bytes = read_private_file_bounded_v1(path, "client value root key", 32)?;
    if bytes.len() != 32 {
        return Err("client value root key must contain exactly 32 raw bytes".to_owned());
    }
    let mut root = Zeroizing::new([0_u8; 32]);
    root.copy_from_slice(&bytes);
    if root.iter().all(|byte| *byte == 0) {
        return Err("client value root key must be nonzero".to_owned());
    }
    Ok(root)
}

pub(crate) fn validate_existing_private_file_v1(path: &Path, label: &str) -> Result<(), String> {
    pir_private_files::checked_existing_private_file_v1(
        path,
        pir_private_files::PrivateFileModeV1::ReadWrite,
        label,
    )?;
    Ok(())
}

pub(crate) fn decode_canonical_hex_v1<const N: usize>(
    encoded: &str,
    label: &str,
) -> Result<[u8; N], String> {
    if encoded.len() != N.saturating_mul(2)
        || !encoded
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(format!(
            "{label} must be exactly {} lowercase hexadecimal characters",
            N.saturating_mul(2)
        ));
    }
    let decoded = hex::decode(encoded).map_err(|_| format!("{label} is invalid"))?;
    decoded
        .try_into()
        .map_err(|_| format!("{label} is invalid"))
}

fn parse_exact_field_v1<const N: usize>(
    line: Option<&str>,
    field: &str,
    label: &str,
) -> Result<[u8; N], String> {
    let line = line.ok_or_else(|| format!("{label} is missing"))?;
    let prefix = format!("{field}=");
    let value = line
        .strip_prefix(&prefix)
        .ok_or_else(|| format!("{label} field is invalid"))?;
    decode_canonical_hex_v1(value, label)
}

fn random_nonzero_v1(label: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    for _ in 0..8 {
        let mut value = Zeroizing::new([0_u8; 32]);
        getrandom::getrandom(value.as_mut())
            .map_err(|_| format!("operating-system randomness failed for {label}"))?;
        if value.iter().any(|byte| *byte != 0) {
            return Ok(value);
        }
    }
    Err(format!(
        "operating-system randomness returned an invalid {label}"
    ))
}

fn preflight_distinct_new_outputs_v1(
    first: &Path,
    second: &Path,
    first_label: &str,
    second_label: &str,
) -> Result<(PathBuf, PathBuf), String> {
    let first_target = checked_new_target_v1(first, first_label)?;
    let second_target = checked_new_target_v1(second, second_label)?;
    if first_target == second_target {
        return Err("secret and metadata output paths must be distinct".to_owned());
    }
    Ok((first_target, second_target))
}

fn checked_new_target_v1(path: &Path, label: &str) -> Result<PathBuf, String> {
    pir_private_files::prepare_new_private_file_v1(path, false, label)
}

fn write_new_private_file_v1(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    pir_private_files::write_new_private_file_v1(path, bytes, label)
}

fn read_private_file_bounded_v1(
    path: &Path,
    label: &str,
    maximum: u64,
) -> Result<Zeroizing<Vec<u8>>, String> {
    pir_private_files::read_private_file_bounded_v1(
        path,
        usize::try_from(maximum).map_err(|_| format!("{label} size bound is invalid"))?,
        pir_private_files::PrivateFileModeV1::ReadOnlyOrReadWrite,
        label,
    )
}
