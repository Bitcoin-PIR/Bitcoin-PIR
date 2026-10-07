//! Operator-issued API keys (docs/CREDITS.md "API keys").
//!
//! `--api-key-file FILE` lists one key per line as `SHA256HEX LABEL`; blank
//! lines and `#` comments are ignored. A connection that presents a listed
//! key with `REQ_API_KEY`, inside the encrypted channel, is served unmetered
//! at normal priority for the rest of its life. The server keeps only the
//! hashes; `bpir-admin api-key new` mints a key and its line.

use pir_core::merkle::{sha256, Hash256, HASH_SIZE};
use std::collections::BTreeMap;
use std::path::Path;

/// Longest label a key line may carry.
const MAX_LABEL_LEN: usize = 64;

#[derive(Debug)]
pub(crate) struct ApiKeysV1 {
    labels: BTreeMap<Hash256, String>,
}

impl ApiKeysV1 {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("--api-key-file {}: {error}", path.display()))?;
        Self::parse(&text).map_err(|error| format!("--api-key-file {}: {error}", path.display()))
    }

    fn parse(text: &str) -> Result<Self, String> {
        let mut labels = BTreeMap::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line_no = index + 1;
            let mut fields = line.split_whitespace();
            let (Some(hash_hex), Some(label), None) = (fields.next(), fields.next(), fields.next())
            else {
                return Err(format!("line {line_no}: expected `SHA256HEX LABEL`"));
            };
            let hash = parse_hash(hash_hex)
                .ok_or_else(|| format!("line {line_no}: the hash must be 64 hex characters"))?;
            if label.len() > MAX_LABEL_LEN
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            {
                return Err(format!(
                    "line {line_no}: the label must be 1 to {MAX_LABEL_LEN} of A-Z a-z 0-9 . _ -"
                ));
            }
            if labels.insert(hash, label.to_owned()).is_some() {
                return Err(format!("line {line_no}: this hash is already listed"));
            }
        }
        if labels.is_empty() {
            return Err("lists no keys".into());
        }
        Ok(Self { labels })
    }

    pub(crate) fn len(&self) -> usize {
        self.labels.len()
    }

    /// The label `key` is listed under, if any.
    pub(crate) fn label(&self, key: &[u8]) -> Option<&str> {
        self.labels.get(&sha256(key)).map(String::as_str)
    }
}

fn parse_hash(hex: &str) -> Option<Hash256> {
    if hex.len() != HASH_SIZE * 2 {
        return None;
    }
    let mut hash = [0u8; HASH_SIZE];
    for (byte, pair) in hash.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(key: &str, label: &str) -> String {
        let hash: String = sha256(key.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{hash} {label}\n")
    }

    #[test]
    fn listed_keys_resolve_to_their_labels() {
        let text = format!(
            "# owner keys\n\n{}{}",
            line("bpk_one", "ci-canary"),
            line("bpk_two", "wallet.dev")
        );
        let keys = ApiKeysV1::parse(&text).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.label(b"bpk_one"), Some("ci-canary"));
        assert_eq!(keys.label(b"bpk_two"), Some("wallet.dev"));
        assert_eq!(keys.label(b"bpk_three"), None);
        // The file holds hashes: presenting a listed hash is not the key.
        let hash_hex = line("bpk_one", "x")[..64].to_owned();
        assert_eq!(keys.label(hash_hex.as_bytes()), None);
    }

    #[test]
    fn malformed_files_are_refused_with_the_line_number() {
        for (text, expected) in [
            (String::new(), "lists no keys"),
            ("# only a comment\n".into(), "lists no keys"),
            (
                "abcd label\n".into(),
                "line 1: the hash must be 64 hex characters",
            ),
            (
                "zz".repeat(32) + " label\n",
                "line 1: the hash must be 64 hex characters",
            ),
            (line("k", "bad!"), "line 1: the label"),
            (
                line("k", "a").trim_end().to_owned() + " extra\n",
                "line 1: expected",
            ),
            (
                format!("{}{}", line("k", "a"), line("k", "b")),
                "line 2: this hash is already listed",
            ),
        ] {
            let error = ApiKeysV1::parse(&text).unwrap_err();
            assert!(error.starts_with(expected), "{text:?}: {error}");
        }
    }
}
