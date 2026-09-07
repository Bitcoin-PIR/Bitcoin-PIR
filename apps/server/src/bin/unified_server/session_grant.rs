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
    REQ_HARMONY_BATCH_QUERY, REQ_HARMONY_HINTS, REQ_HARMONY_HINTS_V2, REQ_HARMONY_QUERY,
    REQ_INDEX_BATCH, REQ_ORAM_LOOKUP,
};

use crate::{read_regular_file_bounded_v1, CliArgs};

/// A public-key file is 32 raw bytes or 64 hex characters plus whitespace.
const MAX_PUBLIC_KEY_FILE_BYTES: usize = 128;

/// Request variants that spend a credit and are refused without a grant
/// when one is required. Everything else (info, ping, attest, handshake,
/// announce, catalog, DB proofs, HarmonyPIR hints, admin, and the grant
/// presentation itself) stays free.
/// Credits one HarmonyPIR hint set costs unless `--session-grant-hint-credits`
/// says otherwise. Measured on pir1 (i7-8700): regenerating one pool entry
/// takes about 136 CPU-seconds, a metered DPF frame about 0.9, so 150 keeps
/// hint sets priced by compute with some margin (docs/SESSION_GRANTS.md).
pub(crate) const DEFAULT_HINT_SET_CREDITS: u32 = 150;

/// Credits a request frame costs: one per query-bearing frame, the hint-set
/// price for the two HarmonyPIR hint requests that take a pool entry
/// (`REQ_HARMONY_HINTS`, `REQ_HARMONY_HINTS_V2`), nothing for everything
/// else. `REQ_HARMONY_HINTS_V2_HALF` streams the second half of an entry the
/// `_V2` request already paid for, so it is free.
pub(crate) fn credit_cost(variant: u8, hint_set_credits: u32) -> u32 {
    match variant {
        REQ_HARMONY_HINTS | REQ_HARMONY_HINTS_V2 => hint_set_credits,
        _ if is_query_bearing_variant(variant) => 1,
        _ => 0,
    }
}

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
    hint_set_credits: u32,
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
            hint_set_credits: args.session_grant_hint_credits,
        }))
    }

    pub(crate) fn require(&self) -> bool {
        self.require
    }

    /// Credits `variant` costs on this host (see [`credit_cost`]).
    pub(crate) fn credit_cost(&self, variant: u8) -> u32 {
        credit_cost(variant, self.hint_set_credits)
    }

    pub(crate) fn startup_log_line(&self) -> String {
        format!(
            "Session grants: {} ({} cashier key(s) pinned; query frame = 1 credit, hint set = {} credits)",
            if self.require {
                "required for queries"
            } else {
                "accepted, not required"
            },
            self.issuers.len(),
            self.hint_set_credits
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

    /// Spend `credits` credits of an attached grant at once; returns the
    /// remaining credits. A grant that cannot cover the amount is left
    /// untouched and the error names both numbers.
    pub(crate) fn consume_n(
        &self,
        grant_id: &GrantId,
        credits: u32,
        now: u64,
    ) -> Result<u32, String> {
        self.ledger
            .lock()
            .unwrap()
            .consume_n(grant_id, credits, now)
            .map_err(|error| format!("session grant: {error}"))
    }

    /// Spend one credit of an attached grant; returns the remaining credits.
    #[cfg(test)]
    pub(crate) fn consume(&self, grant_id: &GrantId, now: u64) -> Result<u32, String> {
        self.consume_n(grant_id, 1, now)
    }
}

fn load_public_key(path: &Path) -> Result<PublicKey, String> {
    let bytes =
        read_regular_file_bounded_v1(path, MAX_PUBLIC_KEY_FILE_BYTES, "session grant public key")?;
    parse_public_key_file(&bytes)
        .map_err(|error| format!("session grant public key {}: {error}", path.display()))
}
