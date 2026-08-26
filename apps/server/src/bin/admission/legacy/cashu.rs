//! Cashu credential loading and validation helpers extracted from
//! `unified_server.rs` (legacy payment surface; slated for removal with R4).

use std::collections::BTreeMap;
use std::path::PathBuf;

use pir_cashu_client::CashuCustodyExposureLimitsV1;
use zeroize::Zeroize;

use crate::{decode_fixed_hex_v1, read_exact_secret_v1};

pub(crate) type CashuEpochKeysV1 = (u64, Vec<(u64, [u8; 32])>);

pub(crate) fn load_cashu_epoch_keys_v1(
    active_epoch: Option<u64>,
    specs: &[String],
    active_flag: &str,
    key_flag: &str,
    key_label: &str,
) -> Result<Option<CashuEpochKeysV1>, String> {
    match (active_epoch, specs.is_empty()) {
        (None, true) => Ok(None),
        (Some(active_epoch), false) if active_epoch != 0 => {
            let mut keys: Vec<(u64, [u8; 32])> = Vec::with_capacity(specs.len());
            let mut epochs = std::collections::BTreeSet::new();
            for spec in specs {
                let (epoch, path) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("{key_flag} must be <epoch>=<raw-32-byte-path>"))?;
                let epoch = epoch
                    .parse::<u64>()
                    .map_err(|_| format!("{key_flag} epoch must be a non-zero u64"))?;
                if epoch == 0 || path.is_empty() || !epochs.insert(epoch) {
                    for (_, key) in &mut keys {
                        key.zeroize();
                    }
                    return Err(format!(
                        "{key_flag} epochs and paths must be non-empty, non-zero, and unique"
                    ));
                }
                match read_exact_secret_v1::<32>(std::path::Path::new(path), key_label) {
                    Ok(mut key) => {
                        if keys.iter().any(|(_, existing)| existing == &key) {
                            key.zeroize();
                            for (_, loaded_key) in &mut keys {
                                loaded_key.zeroize();
                            }
                            return Err(format!(
                                "{key_flag} must not reuse the same key bytes across epochs"
                            ));
                        }
                        keys.push((epoch, key));
                    }
                    Err(error) => {
                        for (_, key) in &mut keys {
                            key.zeroize();
                        }
                        return Err(error);
                    }
                }
            }
            if !epochs.contains(&active_epoch) {
                for (_, key) in &mut keys {
                    key.zeroize();
                }
                return Err(format!(
                    "{active_flag} must select an epoch loaded by {key_flag}"
                ));
            }
            Ok(Some((active_epoch, keys)))
        }
        _ => Err(format!(
            "standard Cashu requires {active_flag} together with at least one {key_flag}"
        )),
    }
}

pub(crate) fn zeroize_cashu_epoch_keys_v1(material: &mut Option<CashuEpochKeysV1>) {
    if let Some((_, keys)) = material {
        for (_, key) in keys {
            key.zeroize();
        }
    }
}

pub(crate) fn parse_cashu_exposure_limits_v1(
    specs: &[String],
) -> Result<BTreeMap<([u8; 32], String), CashuCustodyExposureLimitsV1>, String> {
    let mut limits = BTreeMap::new();
    for spec in specs {
        let fields = spec.split(':').collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(
                "--service-cashu-exposure-limit must be <mint-id-hex>:<unit>:<max-unsettled-value>:<max-unsettled-notes>"
                    .to_owned(),
            );
        }
        let mint_id =
            decode_fixed_hex_v1::<32>(fields[0], "--service-cashu-exposure-limit mint ID")?;
        if mint_id.iter().all(|byte| *byte == 0) {
            return Err("--service-cashu-exposure-limit mint ID must not be all zero".to_owned());
        }
        let unit = fields[1];
        if unit.is_empty()
            || unit.len() > pir_service_protocol::MAX_PRICE_UNIT_LEN
            || !unit.is_ascii()
            || !unit
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(
                "--service-cashu-exposure-limit unit must be bounded lowercase ASCII".to_owned(),
            );
        }
        let max_value = fields[2]
            .parse::<u64>()
            .map_err(|_| "Cashu max-unsettled-value must be a finite non-zero u64".to_owned())?;
        let max_notes = fields[3]
            .parse::<u64>()
            .map_err(|_| "Cashu max-unsettled-notes must be a finite non-zero u64".to_owned())?;
        let value = CashuCustodyExposureLimitsV1::new(max_value, max_notes)
            .map_err(|_| "Cashu exposure limits must be finite and non-zero".to_owned())?;
        if limits.insert((mint_id, unit.to_owned()), value).is_some() {
            return Err("duplicate standard Cashu exposure limit for one mint/unit".to_owned());
        }
    }
    Ok(limits)
}

/// Resolve one sensitive SQLite database through a pinned, symlink-free parent
/// walk. The final 0700 directory is the local single-user boundary protecting
/// both the main file and SQLite's runtime `-wal`/`-shm` sidecars; the final
/// component must independently be a single-link euid-owned mode-0600 file.
pub(crate) fn validate_existing_private_sqlite_path_v1(
    path: &std::path::Path,
    label: &str,
) -> Result<PathBuf, String> {
    pir_private_files::checked_existing_private_file_v1(
        path,
        pir_private_files::PrivateFileModeV1::ReadWrite,
        label,
    )
    .map(|checked| checked.path().to_path_buf())
}

