use std::fmt;
use std::path::{Path, PathBuf};

use clap::Args;
use pir_rollback_authority_client::{
    load_remote_rollback_authority_deployment_descriptor_v1,
    validate_independent_remote_rollback_authority_deployments_v1,
    RemoteRollbackAuthorityDeploymentDescriptorV1, MAX_INDEPENDENT_DEPLOYMENTS_V1,
    MIN_INDEPENDENT_DEPLOYMENTS_V1,
};

const PASS_LINE_V1: &str = "rollback-authority-deployment-set=PASS";
const FAILURE_V1: &str = "rollback-authority deployment-set lint failed";

/// Offline public-config lint for one bounded actual deployment set. No
/// referenced client secret is read and no network request is performed.
#[derive(Args)]
pub struct RollbackAuthorityDeploymentLintArgs {
    /// One absolute owner-only remote authority config; repeat 2 through 16 times.
    #[arg(long = "config", required = true, action = clap::ArgAction::Append, num_args = 1)]
    configs: Vec<PathBuf>,
}

impl fmt::Debug for RollbackAuthorityDeploymentLintArgs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RollbackAuthorityDeploymentLintArgs")
            .field("configs", &"[REDACTED]")
            .finish()
    }
}

pub fn run(args: RollbackAuthorityDeploymentLintArgs) -> Result<(), String> {
    if !(MIN_INDEPENDENT_DEPLOYMENTS_V1..=MAX_INDEPENDENT_DEPLOYMENTS_V1)
        .contains(&args.configs.len())
    {
        return Err(FAILURE_V1.to_owned());
    }
    let mut deployments = Vec::with_capacity(args.configs.len());
    for config in &args.configs {
        deployments.push(load_descriptor_v1(config)?);
    }
    validate_independent_remote_rollback_authority_deployments_v1(&deployments)
        .map_err(|_| FAILURE_V1.to_owned())?;
    println!("{PASS_LINE_V1}");
    Ok(())
}

fn load_descriptor_v1(
    path: &Path,
) -> Result<RemoteRollbackAuthorityDeploymentDescriptorV1, String> {
    load_remote_rollback_authority_deployment_descriptor_v1(path).map_err(|_| FAILURE_V1.to_owned())
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    use super::*;

    fn private_tempdir_v1() -> TempDir {
        let directory = tempfile::Builder::new()
            .prefix("bpir-authority-deployment-lint-")
            .tempdir()
            .unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn write_private_v1(path: &Path, bytes: &[u8]) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn write_config_v1(directory: &TempDir, index: u8, pin: u8) -> PathBuf {
        let authority = SigningKey::from_bytes(&[index.saturating_add(16); 32]);
        let client = SigningKey::from_bytes(&[index.saturating_add(32); 32]);
        let config = format!(
            "schema = \"bitcoinpir_remote_rollback_authority_v1\"\nendpoint = \"https://authority-{index}.example\"\nauthority_instance_id_hex = \"{}\"\nauthority_verifying_key_hex = \"{}\"\nnamespace_hex = \"{}\"\nclient_verifying_key_hex = \"{}\"\nclient_signing_seed_path = \"/separate/deployment-{index}/client.seed\"\nvalue_root_key_path = \"/separate/deployment-{index}/value-root.key\"\nleaf_spki_sha256_pins_hex = [\"{}\"]\nconnect_timeout_ms = 1000\nio_timeout_ms = 1000\nattempt_timeout_ms = 2000\noperation_timeout_ms = 6000\n",
            hex::encode([index.saturating_add(48); 32]),
            hex::encode(authority.verifying_key().to_bytes()),
            hex::encode([index.saturating_add(64); 32]),
            hex::encode(client.verifying_key().to_bytes()),
            hex::encode([pin; 32]),
        );
        let path = directory.path().join(format!("deployment-{index}.toml"));
        write_private_v1(&path, config.as_bytes());
        path
    }

    fn args_v1(paths: &[PathBuf]) -> RollbackAuthorityDeploymentLintArgs {
        RollbackAuthorityDeploymentLintArgs {
            configs: paths.to_vec(),
        }
    }

    #[test]
    fn bounded_lint_accepts_two_three_four_and_sixteen_independent_configs_without_secrets() {
        for count in [2_usize, 3, 4, MAX_INDEPENDENT_DEPLOYMENTS_V1] {
            let directory = private_tempdir_v1();
            let configs: Vec<_> = (1..=count)
                .map(|index| {
                    let index = u8::try_from(index).unwrap();
                    write_config_v1(&directory, index, index.saturating_add(100))
                })
                .collect();
            run(args_v1(&configs)).unwrap();
        }
    }

    #[test]
    fn bounded_lint_rejects_zero_one_seventeen_and_overlap_with_one_generic_error() {
        for count in [0_usize, 1, MAX_INDEPENDENT_DEPLOYMENTS_V1 + 1] {
            let configs = vec![PathBuf::from("/not/read.toml"); count];
            assert_eq!(run(args_v1(&configs)).unwrap_err(), FAILURE_V1);
        }

        let directory = private_tempdir_v1();
        let configs = vec![
            write_config_v1(&directory, 1, 101),
            write_config_v1(&directory, 2, 101),
            write_config_v1(&directory, 3, 103),
        ];
        assert_eq!(run(args_v1(&configs)).unwrap_err(), FAILURE_V1);
    }

    #[test]
    fn bounded_lint_preserves_owner_only_no_link_config_boundary() {
        let directory = private_tempdir_v1();
        let first = write_config_v1(&directory, 1, 101);
        let second = write_config_v1(&directory, 2, 102);

        fs::set_permissions(&first, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            run(args_v1(&[first.clone(), second.clone()])).unwrap_err(),
            FAILURE_V1
        );
        fs::set_permissions(&first, fs::Permissions::from_mode(0o600)).unwrap();

        let symlink_path = directory.path().join("deployment-link.toml");
        symlink(&first, &symlink_path).unwrap();
        assert_eq!(
            run(args_v1(&[symlink_path.clone(), second.clone()])).unwrap_err(),
            FAILURE_V1
        );
        fs::remove_file(&symlink_path).unwrap();

        let hardlink_path = directory.path().join("deployment-hardlink.toml");
        fs::hard_link(&first, &hardlink_path).unwrap();
        assert_eq!(
            run(args_v1(&[hardlink_path, second])).unwrap_err(),
            FAILURE_V1
        );
    }
}
