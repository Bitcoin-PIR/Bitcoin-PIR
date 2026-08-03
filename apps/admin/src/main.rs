//! `bpir-admin` — operator CLI for the BitcoinPIR server fleet.
//!
//! Subcommands:
//! - `keygen` — generate an ed25519 keypair for the admin auth flow.
//!   Writes the private key to a file (mode 0600) and prints the
//!   public key as 64-char hex for the operator to put into the
//!   server's `--admin-pubkey-hex` flag.
//! - `attest` — exercise REQ_ATTEST against a server, verify the
//!   REPORT_DATA binding, optionally cross-check against expected
//!   binary hash / manifest roots.
//! - `channel-test` — end-to-end smoke test of the encrypted channel:
//!   attest → handshake → encrypted ping/pong + get_info. Use post-deploy
//!   to confirm the cloudflared-blind path actually works.
//! - `upload` — authenticate, build a manifest, stream a DB directory
//!   to the server's staging area, finalize, optionally activate.
//! - `db-proof verify` — verify attested-builder evidence, root bundle,
//!   artifact manifests, and SEV-SNP REPORT_DATA binding for a database
//!   build proof directory.
//! - `service-keygen`, `payment-artifact`, and `service-policy` — offline
//!   Payment V1 key generation, canonical artifact construction, and policy
//!   signing without a listener or Lightning backend.
//! - `service-store-init` — explicitly create a provider admission store and
//!   its independently configured rollback-floor authority.
//! - `service-store-check` — run the serving-equivalent provider-store open
//!   and report aggregate startup/SLO counters without starting a listener.
//! - `cashu-custody` — owner-only standard-Cashu custody inventory, export,
//!   decrypt, acknowledgement, and explicit one-shot NUT-07 retirement.
//! - `payment-v1-no-funds-fixture` — emit deterministic public test vectors
//!   for two providers, five payment methods, and five workloads.
//! - `lightning-staging` — strict default-Signet/CLN bootstrap/full preflights
//!   plus an explicit local, digest-only backup-receipt ceremony.
//! - `rollback-authority-deployment-lint` — offline bounded deployment-set
//!   public-config independence validation without reading client secrets.
//!
//! Wire protocol surfaces consumed by this tool live in
//! `pir-sdk-client::{attest, admin}` and are tested independently.
//! This crate only orchestrates them.

use clap::{Parser, Subcommand};

mod attest;
mod cashu_custody;
mod channel_test;
mod db_proof;
mod directory_artifact;
mod directory_publish;
mod generate_identity;
mod keygen;
mod lightning_staging;
mod payment_artifact;
mod payment_fixture;
mod payment_v1_signet_smoke;
mod rollback_authority_deployment_lint;
mod service_keygen;
mod service_policy;
mod service_store_check;
mod service_store_init;
mod show_vcek_url;
mod sign_identity;
mod upload;

#[derive(Parser, Debug)]
#[command(name = "bpir-admin", about = "BitcoinPIR operator CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate an ed25519 admin keypair.
    Keygen(keygen::KeygenArgs),
    /// Generate an Ed25519 identity keypair (server identity OR
    /// operator long-term key — see `--purpose`). For the
    /// operator-signed announcement bundle flow.
    #[command(name = "generate-identity")]
    GenerateIdentity(generate_identity::GenerateIdentityArgs),
    /// Operator signs an IdentityCert for a server, OFFLINE on the
    /// operator's workstation. Output is deployed to the server at
    /// the path passed to unified_server via `--identity-cert-path`.
    #[command(name = "sign-identity")]
    SignIdentity(sign_identity::SignIdentityArgs),
    /// Send REQ_ATTEST to a server and verify the response.
    Attest(attest::AttestArgs),
    /// End-to-end smoke test of the encrypted channel: attest → handshake
    /// → encrypted ping/pong + get_info. Use post-deploy to confirm the
    /// cloudflared-blind path works.
    #[command(name = "channel-test")]
    ChannelTest(channel_test::ChannelTestArgs),
    /// Print the AMD KDS URLs for the connected server's chip + TCB so
    /// the operator can curl them down and place in --vcek-dir.
    #[command(name = "show-vcek-url")]
    ShowVcekUrl(show_vcek_url::ShowVcekUrlArgs),
    /// Upload a DB directory: auth → BEGIN → CHUNK* → FINALIZE → ACTIVATE.
    Upload(upload::UploadArgs),
    /// Verify attested-builder database build proof artifacts.
    #[command(name = "db-proof")]
    DbProof(db_proof::DbProofArgs),
    /// Offline canonical service-policy signing, validation and inspection.
    #[command(name = "service-policy")]
    ServicePolicy(service_policy::ServicePolicyArgs),
    /// Generate a role-labelled service/payment key without printing secrets.
    #[command(name = "service-keygen")]
    ServiceKeygen(service_keygen::ServiceKeygenArgs),
    /// Create a provider store with exactly one local-dev or remote authority.
    #[command(name = "service-store-init")]
    ServiceStoreInit(service_store_init::ServiceStoreInitArgs),
    /// Fail-closed provider store/selected rollback-floor startup and SLO check.
    /// May reconcile one legitimate unanchored successor, like serving startup.
    #[command(name = "service-store-check")]
    ServiceStoreCheck(service_store_check::ServiceStoreCheckArgs),
    /// Owner-only standard-Cashu custody operations. Only explicit
    /// `spent-confirm` contacts the exact mint over strict HTTPS for NUT-07;
    /// no command opens a listener or contacts a wallet/PIR server.
    #[command(name = "cashu-custody")]
    CashuCustody(cashu_custody::CashuCustodyArgs),
    /// Build and self-verify offline Payment V1 protocol artifacts.
    #[command(name = "payment-artifact")]
    PaymentArtifact(payment_artifact::PaymentArtifactArgs),
    /// Emit the deterministic two-provider Payment V1 no-funds fixture.
    #[command(name = "payment-v1-no-funds-fixture")]
    PaymentV1NoFundsFixture(payment_fixture::PaymentFixtureArgs),
    /// Explicit Signet-only paid capability smoke: verify provider and quote,
    /// invoke an isolated payer CLN, claim one capability, and prove provider
    /// admission without executing a PIR query.
    #[command(name = "payment-v1-signet-smoke")]
    PaymentV1SignetSmoke(payment_v1_signet_smoke::PaymentV1SignetSmokeArgs),
    /// Build, self-verify, or publish signed Nostr directory artifacts.
    #[command(name = "directory-artifact")]
    DirectoryArtifact(directory_artifact::DirectoryArtifactArgs),
    /// Strict default-Signet/CLN bootstrap/full preflights and backup ceremony.
    #[command(name = "lightning-staging")]
    LightningStaging(lightning_staging::LightningStagingArgs),
    /// Validate 2..=16 authority configs pairwise offline without reading
    /// referenced secrets or printing paths, roles, or identifiers.
    #[command(name = "rollback-authority-deployment-lint")]
    RollbackAuthorityDeploymentLint(
        rollback_authority_deployment_lint::RollbackAuthorityDeploymentLintArgs,
    ),
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Keygen(args) => match keygen::run(args) {
            Ok(completion) => completion.exit_code(),
            Err(e) => {
                eprintln!("keygen: {}", e);
                1
            }
        },
        Command::GenerateIdentity(args) => match generate_identity::run(args) {
            Ok(completion) => completion.exit_code(),
            Err(e) => {
                eprintln!("generate-identity: {}", e);
                1
            }
        },
        Command::SignIdentity(args) => match sign_identity::run(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("sign-identity: {}", e);
                1
            }
        },
        Command::Attest(args) => match attest::run(args).await {
            Ok(()) => 0,
            Err(code) => code,
        },
        Command::ChannelTest(args) => match channel_test::run(args).await {
            Ok(()) => 0,
            Err(code) => code,
        },
        Command::ShowVcekUrl(args) => match show_vcek_url::run(args).await {
            Ok(()) => 0,
            Err(code) => code,
        },
        Command::Upload(args) => match upload::run(args).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("upload: {}", e);
                1
            }
        },
        Command::DbProof(args) => match db_proof::run(args).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("db-proof: {}", e);
                1
            }
        },
        Command::ServicePolicy(args) => match service_policy::run(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("service-policy: {}", e);
                1
            }
        },
        Command::ServiceKeygen(args) => match service_keygen::run(args) {
            Ok(completion) => completion.exit_code(),
            Err(e) => {
                eprintln!("service-keygen: {}", e);
                1
            }
        },
        Command::ServiceStoreInit(args) => match service_store_init::run(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("service-store-init: {}", e);
                1
            }
        },
        Command::ServiceStoreCheck(args) => match service_store_check::run(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("service-store-check: {}", e);
                1
            }
        },
        Command::CashuCustody(args) => match cashu_custody::run(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("cashu-custody: {}", e);
                1
            }
        },
        Command::PaymentArtifact(args) => match payment_artifact::run(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("payment-artifact: {}", e);
                1
            }
        },
        Command::PaymentV1NoFundsFixture(args) => match payment_fixture::run(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("payment-v1-no-funds-fixture: {}", e);
                1
            }
        },
        Command::PaymentV1SignetSmoke(args) => match payment_v1_signet_smoke::run(args).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("payment-v1-signet-smoke: {e}");
                1
            }
        },
        Command::DirectoryArtifact(args) => match directory_artifact::run(args).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("directory-artifact: {}", e);
                1
            }
        },
        Command::LightningStaging(args) => match lightning_staging::run(args).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("lightning-staging: {}", e);
                1
            }
        },
        Command::RollbackAuthorityDeploymentLint(args) => {
            match rollback_authority_deployment_lint::run(args) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("rollback-authority-deployment-lint: {e}");
                    1
                }
            }
        }
    };
    std::process::exit(exit_code);
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn payment_and_store_commands_are_present_in_help() {
        Cli::command().debug_assert();
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        for subcommand in [
            "service-policy",
            "service-keygen",
            "service-store-init",
            "service-store-check",
            "cashu-custody",
            "payment-artifact",
            "payment-v1-no-funds-fixture",
            "directory-artifact",
            "lightning-staging",
            "rollback-authority-deployment-lint",
        ] {
            assert!(help.contains(subcommand), "missing {subcommand} from help");
        }
    }

    #[test]
    fn service_policy_scope_ids_accepts_an_unsigned_config() {
        let parsed = Cli::try_parse_from([
            "bpir-admin",
            "service-policy",
            "scope-ids",
            "--config",
            "/private/service-policy.toml",
        ])
        .unwrap();
        assert!(matches!(parsed.command, Command::ServicePolicy(_)));
    }

    #[test]
    fn rollback_authority_deployment_lint_accepts_repeated_anonymous_config_paths() {
        let parsed = Cli::try_parse_from([
            "bpir-admin",
            "rollback-authority-deployment-lint",
            "--config",
            "/private/deployment-a.toml",
            "--config",
            "/private/deployment-b.toml",
        ])
        .unwrap();
        assert!(matches!(
            &parsed.command,
            Command::RollbackAuthorityDeploymentLint(_)
        ));
        let rendered = format!("{parsed:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("deployment-a.toml"));
        assert!(!rendered.contains("deployment-b.toml"));

        assert!(
            Cli::try_parse_from(["bpir-admin", "rollback-authority-deployment-lint",]).is_err()
        );
    }

    #[test]
    fn service_store_init_cli_requires_explicit_paths_and_provider() {
        let provider_id = hex::encode([1u8; 32]);
        let parsed = Cli::try_parse_from([
            "bpir-admin",
            "service-store-init",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
            "--rollback-authority",
            "/independent/floor.sqlite3",
        ])
        .unwrap();
        assert!(matches!(parsed.command, Command::ServiceStoreInit(_)));

        assert!(Cli::try_parse_from([
            "bpir-admin",
            "service-store-init",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "bpir-admin",
            "service-store-init",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
            "--rollback-authority",
            "/independent/floor.sqlite3",
            "--remote-rollback-authority-config",
            "/private/remote.toml",
        ])
        .is_err());
        let remote = Cli::try_parse_from([
            "bpir-admin",
            "service-store-init",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
            "--remote-rollback-authority-config",
            "/private/remote.toml",
            "--store-instance-id-hex",
            &hex::encode([2u8; 16]),
        ])
        .unwrap();
        assert!(matches!(remote.command, Command::ServiceStoreInit(_)));
    }

    #[test]
    fn service_store_check_cli_requires_explicit_paths_and_provider() {
        let provider_id = hex::encode([1u8; 32]);
        let parsed = Cli::try_parse_from([
            "bpir-admin",
            "service-store-check",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
            "--rollback-authority",
            "/independent/floor.sqlite3",
        ])
        .unwrap();
        assert!(matches!(parsed.command, Command::ServiceStoreCheck(_)));

        assert!(Cli::try_parse_from([
            "bpir-admin",
            "service-store-check",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "bpir-admin",
            "service-store-check",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
            "--rollback-authority",
            "/independent/floor.sqlite3",
            "--remote-rollback-authority-config",
            "/private/remote.toml",
        ])
        .is_err());
        let remote = Cli::try_parse_from([
            "bpir-admin",
            "service-store-check",
            "--provider-id-hex",
            &provider_id,
            "--store",
            "/private/provider.sqlite3",
            "--remote-rollback-authority-config",
            "/private/remote.toml",
        ])
        .unwrap();
        assert!(matches!(remote.command, Command::ServiceStoreCheck(_)));
    }

    #[test]
    fn directory_publish_cli_accepts_repeated_artifacts_and_relays() {
        let parsed = Cli::try_parse_from([
            "bpir-admin",
            "directory-artifact",
            "publish",
            "--artifact",
            "entry.event.json",
            "--artifact",
            "checkpoints.json",
            "--relay",
            "wss://one.example",
            "--relay",
            "wss://two.example/nostr",
            "--directory-pubkey-hex",
            &hex::encode([1u8; 32]),
            "--now-unix",
            "1500",
            "--validate-only",
        ])
        .unwrap();
        assert!(matches!(parsed.command, Command::DirectoryArtifact(_)));

        let centralized = Cli::try_parse_from([
            "bpir-admin",
            "directory-artifact",
            "publish",
            "--artifact",
            "entry.event.json",
            "--relay",
            "wss://central.example",
            "--centralized-single-relay",
            "--directory-pubkey-hex",
            &hex::encode([1u8; 32]),
            "--now-unix",
            "1500",
            "--validate-only",
        ])
        .unwrap();
        assert!(matches!(centralized.command, Command::DirectoryArtifact(_)));
    }

    #[test]
    fn no_funds_fixture_cli_requires_explicit_acknowledgement_at_runtime() {
        let parsed = Cli::try_parse_from([
            "bpir-admin",
            "payment-v1-no-funds-fixture",
            "--out",
            "/tmp/payment-v1-fixture",
        ])
        .unwrap();
        let Command::PaymentV1NoFundsFixture(args) = parsed.command else {
            panic!("wrong subcommand");
        };
        assert!(!args.acknowledge_deterministic_test_keys);
    }

    #[test]
    fn lightning_staging_preflight_requires_out_of_band_config_trust_boundary() {
        let parsed = Cli::try_parse_from([
            "bpir-admin",
            "lightning-staging",
            "preflight",
            "--config",
            "/srv/bitcoinpir/preflight.toml",
            "--config-protected-parent",
            "/srv/bitcoinpir",
            "--config-expected-uid",
            "0",
            "--config-expected-gid",
            "991",
            "--config-reader-expected-uid",
            "991",
        ])
        .unwrap();
        assert!(matches!(parsed.command, Command::LightningStaging(_)));
    }

    #[test]
    fn lightning_staging_supervisor_uses_the_same_closed_trust_boundary() {
        let parsed = Cli::try_parse_from([
            "bpir-admin",
            "lightning-staging",
            "preflight-supervisor",
            "--config",
            "/srv/bitcoinpir/preflight.toml",
            "--config-protected-parent",
            "/srv/bitcoinpir",
            "--config-expected-uid",
            "0",
            "--config-expected-gid",
            "991",
            "--config-reader-expected-uid",
            "991",
        ])
        .unwrap();
        assert!(matches!(parsed.command, Command::LightningStaging(_)));
    }

    #[test]
    fn lightning_staging_bootstrap_preflight_uses_the_same_trust_boundary() {
        let parsed = Cli::try_parse_from([
            "bpir-admin",
            "lightning-staging",
            "bootstrap-preflight",
            "--config",
            "/srv/bitcoinpir/preflight.toml",
            "--config-protected-parent",
            "/srv/bitcoinpir",
            "--config-expected-uid",
            "0",
            "--config-expected-gid",
            "991",
            "--config-reader-expected-uid",
            "991",
        ])
        .unwrap();
        assert!(matches!(parsed.command, Command::LightningStaging(_)));
    }

    #[test]
    fn lightning_staging_backup_receipt_requires_both_explicit_acknowledgements() {
        let base = [
            "bpir-admin",
            "lightning-staging",
            "record-backup-receipt",
            "--config",
            "/srv/bitcoinpir/preflight.toml",
            "--config-protected-parent",
            "/srv/bitcoinpir",
            "--config-expected-uid",
            "0",
            "--config-expected-gid",
            "991",
            "--config-reader-expected-uid",
            "991",
        ];
        assert!(Cli::try_parse_from(base).is_err());

        let mut only_identity = base.to_vec();
        only_identity.push("--acknowledge-identity-secret-offline-backup-restore-checked");
        assert!(Cli::try_parse_from(only_identity).is_err());

        let mut only_channel = base.to_vec();
        only_channel.push("--acknowledge-channel-state-recovery-backup-restore-checked");
        assert!(Cli::try_parse_from(only_channel).is_err());

        let mut both = base.to_vec();
        both.extend([
            "--acknowledge-identity-secret-offline-backup-restore-checked",
            "--acknowledge-channel-state-recovery-backup-restore-checked",
        ]);
        let parsed = Cli::try_parse_from(both).unwrap();
        assert!(matches!(parsed.command, Command::LightningStaging(_)));
    }
}
