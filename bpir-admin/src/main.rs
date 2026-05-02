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
//! - `upload` — authenticate, build a manifest, stream a DB directory
//!   to the server's staging area, finalize, optionally activate.
//!
//! Wire protocol surfaces consumed by this tool live in
//! `pir-sdk-client::{attest, admin}` and are tested independently.
//! This crate only orchestrates them.

use clap::{Parser, Subcommand};

mod attest;
mod keygen;
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
    /// Send REQ_ATTEST to a server and verify the response.
    Attest(attest::AttestArgs),
    /// Upload a DB directory: auth → BEGIN → CHUNK* → FINALIZE → ACTIVATE.
    Upload(upload::UploadArgs),
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
        Command::Attest(args) => match attest::run(args).await {
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
    };
    std::process::exit(exit_code);
}
