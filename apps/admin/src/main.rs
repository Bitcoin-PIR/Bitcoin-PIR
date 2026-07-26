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
//! - `payment-v1-no-funds-fixture` — emit deterministic public test vectors
//!   for two providers, five payment methods, and five workloads.
//!
//! Wire protocol surfaces consumed by this tool live in
//! `pir-sdk-client::{attest, admin}` and are tested independently.
//! This crate only orchestrates them.

use clap::{Parser, Subcommand};

mod attest;
mod channel_test;
mod db_proof;
mod directory_artifact;
mod generate_identity;
mod keygen;
mod payment_artifact;
mod payment_fixture;
mod service_keygen;
mod service_policy;
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
    /// Explicitly create a provider store and separate rollback authority.
    #[command(name = "service-store-init")]
    ServiceStoreInit(service_store_init::ServiceStoreInitArgs),
    /// Build and self-verify offline Payment V1 protocol artifacts.
    #[command(name = "payment-artifact")]
    PaymentArtifact(payment_artifact::PaymentArtifactArgs),
    /// Emit the deterministic two-provider Payment V1 no-funds fixture.
    #[command(name = "payment-v1-no-funds-fixture")]
    PaymentV1NoFundsFixture(payment_fixture::PaymentFixtureArgs),
    /// Build and self-verify offline Nostr directory publishing artifacts.
    #[command(name = "directory-artifact")]
    DirectoryArtifact(directory_artifact::DirectoryArtifactArgs),
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Keygen(args) => match keygen::run(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("keygen: {}", e);
                1
            }
        },
        Command::GenerateIdentity(args) => match generate_identity::run(args) {
            Ok(()) => 0,
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
            Ok(()) => 0,
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
        Command::DirectoryArtifact(args) => match directory_artifact::run(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("directory-artifact: {}", e);
                1
            }
        },
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
            "service-keygen",
            "service-store-init",
            "payment-artifact",
            "payment-v1-no-funds-fixture",
        ] {
            assert!(help.contains(subcommand), "missing {subcommand} from help");
        }
    }

    #[test]
    fn service_store_init_cli_requires_explicit_paths_and_provider() {
        let parsed = Cli::try_parse_from([
            "bpir-admin",
            "service-store-init",
            "--provider-id-hex",
            &hex::encode([1u8; 32]),
            "--store",
            "/private/provider.sqlite3",
            "--rollback-authority",
            "/independent/floor.sqlite3",
        ])
        .unwrap();
        assert!(matches!(parsed.command, Command::ServiceStoreInit(_)));
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
}
