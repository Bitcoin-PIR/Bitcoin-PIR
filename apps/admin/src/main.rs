//! `bpir-admin` — operator CLI for the BitcoinPIR server fleet.
//!
//! Subcommands:
//! - `api-key new` — mint an operator API key for the server's
//!   `--api-key-file` (docs/CREDITS.md "API keys").
//! - `keygen` — generate an Ed25519 keypair (server identity or operator
//!   key). Writes the 32-byte seed to a file (mode 0600) and prints the
//!   public key as 64-char hex.
//! - `sign-identity` — the operator signs a server's IdentityCert.
//! - `attest` — exercise REQ_ATTEST against a server, verify the
//!   REPORT_DATA binding, optionally cross-check the binary hash,
//!   launch MEASUREMENT and AMD certificate chain against pins.
//! - `channel-test` — end-to-end smoke test of the encrypted channel:
//!   attest → handshake → encrypted ping/pong + get_info. Use post-deploy
//!   to confirm the cloudflared-blind path actually works.
//! - `db-proof verify` / `verify-live` — verify attested-builder evidence,
//!   root bundle, artifact manifests, and SEV-SNP REPORT_DATA binding for
//!   a local proof directory or a live server's proof.
//!
//! Wire protocol surfaces consumed by this tool live in
//! `pir-sdk-client::attest` and are tested independently.
//! This crate only orchestrates them.

use clap::{Parser, Subcommand};

mod api_key;
mod attest;
mod channel_test;
mod db_proof;
mod keygen;
mod sign_identity;

#[derive(Parser, Debug)]
#[command(name = "bpir-admin", about = "BitcoinPIR operator CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Mint an operator API key for `unified_server --api-key-file`
    /// (docs/CREDITS.md "API keys").
    #[command(name = "api-key")]
    ApiKey(api_key::ApiKeyArgs),
    /// Generate an Ed25519 keypair: server identity or operator key.
    Keygen(keygen::KeygenArgs),
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
    /// Verify attested-builder database build proof artifacts.
    #[command(name = "db-proof")]
    DbProof(db_proof::DbProofArgs),
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();
    let (name, result) = match cli.command {
        Command::ApiKey(args) => ("api-key", api_key::run(args)),
        Command::Keygen(args) => ("keygen", keygen::run(args)),
        Command::SignIdentity(args) => ("sign-identity", sign_identity::run(args)),
        Command::Attest(args) => ("attest", attest::run(args).await),
        Command::ChannelTest(args) => ("channel-test", channel_test::run(args).await),
        Command::DbProof(args) => ("db-proof", db_proof::run(args).await),
    };
    if let Err(e) = result {
        eprintln!("{name}: {e}");
        std::process::exit(1);
    }
}
