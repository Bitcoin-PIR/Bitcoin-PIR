//! Session-grant admission for query-bearing opcodes.
//!
//! The server pins one or more cashier public keys (`--session-grant-pubkey
//! FILE`, repeatable) and verifies presented grants offline with
//! `pir_session_grant`. With `--require-session-grant`, query-bearing frames
//! are rejected until the connection has presented a valid grant; every
//! accepted query-bearing frame then spends one credit in the ledger shared
//! by all connections. Without the require flag, grants are optional but a
//! presented grant is still metered.
//!
//! Nothing here touches payment: the cashier that sells grants runs outside
//! the PIR hosts, so price or payment-rail changes never reach this binary.

use std::path::Path;
use std::sync::Mutex;

use pir_session_grant::{
    parse_public_key_file, GrantId, GrantLedger, PublicKey, SessionGrant, TrustedIssuers,
};
use runtime::onionpir::{
    REQ_ONIONPIR_CHUNK_QUERY, REQ_ONIONPIR_INDEX_QUERY, REQ_ONIONPIR_MERKLE_DATA_SIBLING,
    REQ_ONIONPIR_MERKLE_DATA_TREE_TOP, REQ_ONIONPIR_MERKLE_INDEX_SIBLING,
    REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP, REQ_REGISTER_KEYS,
};
use runtime::protocol::{
    REQ_BUCKET_MERKLE_SIB_BATCH, REQ_BUCKET_MERKLE_TREE_TOPS, REQ_CHUNK_BATCH,
    REQ_HARMONY_BATCH_QUERY, REQ_HARMONY_QUERY, REQ_INDEX_BATCH, REQ_ORAM_LOOKUP,
};

use crate::{read_regular_file_bounded_v1, CliArgs};

/// A public-key file is 32 raw bytes or 64 hex characters plus whitespace.
const MAX_PUBLIC_KEY_FILE_BYTES: usize = 128;

/// Request variants that spend a credit and are refused without a grant
/// when one is required. Everything else (info, ping, attest, handshake,
/// announce, catalog, DB proofs, HarmonyPIR hints, admin, and the grant
/// presentation itself) stays free.
pub(crate) fn is_query_bearing_variant(variant: u8) -> bool {
    matches!(
        variant,
        REQ_INDEX_BATCH
            | REQ_CHUNK_BATCH
            | REQ_BUCKET_MERKLE_SIB_BATCH
            | REQ_BUCKET_MERKLE_TREE_TOPS
            | REQ_HARMONY_QUERY
            | REQ_HARMONY_BATCH_QUERY
            | REQ_ORAM_LOOKUP
            | REQ_REGISTER_KEYS
            | REQ_ONIONPIR_INDEX_QUERY
            | REQ_ONIONPIR_CHUNK_QUERY
            | REQ_ONIONPIR_MERKLE_INDEX_SIBLING
            | REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP
            | REQ_ONIONPIR_MERKLE_DATA_SIBLING
            | REQ_ONIONPIR_MERKLE_DATA_TREE_TOP
    )
}

/// Pinned cashier keys plus the shared credit ledger for this process.
#[derive(Debug)]
pub(crate) struct SessionGrantGateV1 {
    issuers: TrustedIssuers,
    ledger: Mutex<GrantLedger>,
    require: bool,
}

impl SessionGrantGateV1 {
    /// `None` when no cashier key is pinned (free service, presentations
    /// are refused). `--require-session-grant` without a key is a
    /// configuration error rather than a silently open server.
    pub(crate) fn from_cli(args: &CliArgs) -> Result<Option<Self>, String> {
        if args.session_grant_pubkeys.is_empty() {
            if args.require_session_grant {
                return Err(
                    "--require-session-grant needs at least one --session-grant-pubkey FILE"
                        .to_owned(),
                );
            }
            return Ok(None);
        }
        let mut keys: Vec<PublicKey> = Vec::with_capacity(args.session_grant_pubkeys.len());
        for path in &args.session_grant_pubkeys {
            keys.push(load_public_key(path)?);
        }
        let issuers =
            TrustedIssuers::new(&keys).map_err(|error| format!("session grant keys: {error}"))?;
        Ok(Some(Self {
            issuers,
            ledger: Mutex::new(GrantLedger::new()),
            require: args.require_session_grant,
        }))
    }

    pub(crate) fn require(&self) -> bool {
        self.require
    }

    pub(crate) fn startup_log_line(&self) -> String {
        format!(
            "Session grants: {} ({} cashier key(s) pinned)",
            if self.require {
                "required for queries"
            } else {
                "accepted, not required"
            },
            self.issuers.len()
        )
    }

    /// Verify a presented grant and attach it to the ledger. Returns the
    /// grant id the connection should remember and the remaining credits.
    pub(crate) fn present(&self, body: &[u8], now: u64) -> Result<(GrantId, u32), String> {
        let grant =
            SessionGrant::decode(body).map_err(|error| format!("session grant: {error}"))?;
        let verified = grant
            .verify(&self.issuers, now)
            .map_err(|error| format!("session grant: {error}"))?;
        let remaining = self
            .ledger
            .lock()
            .unwrap()
            .admit(&verified, now)
            .map_err(|error| format!("session grant: {error}"))?;
        Ok((verified.grant_id, remaining))
    }

    /// Spend one credit of an attached grant; returns the remaining credits.
    pub(crate) fn consume(&self, grant_id: &GrantId, now: u64) -> Result<u32, String> {
        self.ledger
            .lock()
            .unwrap()
            .consume(grant_id, now)
            .map_err(|error| format!("session grant: {error}"))
    }
}

fn load_public_key(path: &Path) -> Result<PublicKey, String> {
    let bytes =
        read_regular_file_bounded_v1(path, MAX_PUBLIC_KEY_FILE_BYTES, "session grant public key")?;
    parse_public_key_file(&bytes)
        .map_err(|error| format!("session grant public key {}: {error}", path.display()))
}
