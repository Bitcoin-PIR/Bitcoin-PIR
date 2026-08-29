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
//! - `pir2-sealed-release` — verify a fresh SNP observation and emit one
//!   canonical pir2 release.
//!
//! Wire protocol surfaces consumed by this tool live in
//! `pir-sdk-client::{attest, admin}` and are tested independently.
//! This crate only orchestrates them.

use clap::{Parser, Subcommand};

mod attest;
mod channel_test;
mod db_proof;
mod generate_identity;
mod keygen;
mod pir2_sealed_release;
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
    /// Verify a fresh SNP observation and emit one canonical pir2 release.
    #[command(name = "pir2-sealed-release")]
    Pir2SealedRelease(Box<pir2_sealed_release::Pir2SealedReleaseArgs>),
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
        Command::Pir2SealedRelease(args) => match pir2_sealed_release::run(*args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("pir2-sealed-release: {e}");
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
    fn kept_operator_commands_are_present_in_help() {
        Cli::command().debug_assert();
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        for subcommand in [
            "keygen",
            "generate-identity",
            "sign-identity",
            "attest",
            "channel-test",
            "show-vcek-url",
            "upload",
            "db-proof",
            "pir2-sealed-release",
        ] {
            assert!(help.contains(subcommand), "missing {subcommand} from help");
        }
        for deleted in [
            "service-policy",
            "service-keygen",
            "service-store-init",
            "payment-artifact",
            "directory-artifact",
            "lightning-staging",
            "mainnet-lightning-v1",
        ] {
            assert!(
                !help.contains(deleted),
                "deleted Payment V1 command {deleted} still in help"
            );
        }
    }
}
