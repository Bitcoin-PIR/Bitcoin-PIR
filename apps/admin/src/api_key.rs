//! `bpir-admin api-key new` — mint an operator API key (docs/CREDITS.md
//! "API keys").
//!
//! Prints the key once on stdout, for the client, and the line to append
//! to the server's `--api-key-file` on stderr. The server keeps only the
//! key's SHA-256, so a lost key cannot be recovered: mint a new one and
//! delete the old line.

use clap::{Args, Subcommand};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Longest label the server's key file accepts.
const MAX_LABEL_LEN: usize = 64;

#[derive(Args, Debug)]
pub struct ApiKeyArgs {
    #[command(subcommand)]
    pub command: ApiKeyCommand,
}

#[derive(Subcommand, Debug)]
pub enum ApiKeyCommand {
    /// Mint a key: the key on stdout, its `--api-key-file` line on stderr.
    New {
        /// Name the server's key file lists the key under (1 to 64 of
        /// A-Z a-z 0-9 . _ -).
        #[arg(long)]
        label: String,
    },
}

pub fn run(args: ApiKeyArgs) -> Result<(), String> {
    match args.command {
        ApiKeyCommand::New { label } => {
            let (key, line) = mint(&label)?;
            eprintln!("Append this line to the server's --api-key-file and restart the server:");
            eprintln!("{line}");
            eprintln!();
            eprintln!("API key (shown once; give it to the client):");
            println!("{key}");
            Ok(())
        }
    }
}

/// A fresh key and its key-file line.
fn mint(label: &str) -> Result<(String, String), String> {
    if label.is_empty()
        || label.len() > MAX_LABEL_LEN
        || !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "--label must be 1 to {MAX_LABEL_LEN} of A-Z a-z 0-9 . _ -"
        ));
    }
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).map_err(|error| format!("getrandom: {error}"))?;
    let key = format!("bpk_{}", hex::encode(secret));
    secret.zeroize();
    let hash = hex::encode(Sha256::digest(key.as_bytes()));
    Ok((key, format!("{hash} {label}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_line_lists_the_sha256_of_the_key() {
        let (key, line) = mint("ci-canary").unwrap();
        assert!(key.starts_with("bpk_") && key.len() == 4 + 64);
        let (hash, label) = line.split_once(' ').unwrap();
        assert_eq!(hash, hex::encode(Sha256::digest(key.as_bytes())));
        assert_eq!(label, "ci-canary");
        assert_ne!(mint("ci-canary").unwrap().0, key);
    }

    #[test]
    fn labels_the_server_would_refuse_are_refused_here() {
        for label in ["", "has space", "bang!", &"a".repeat(MAX_LABEL_LEN + 1)] {
            assert!(mint(label).is_err(), "{label:?}");
        }
    }
}
