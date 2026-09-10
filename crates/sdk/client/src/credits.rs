//! Client-side credits (docs/CREDITS.md): presenting credits on a connected
//! server, the gas card a server publishes in `GET_INFO_JSON`, and the
//! per-connection meter that decides when a top-up is due.
//!
//! What this does:
//!
//! - Sends `REQ_CREDIT_PRESENT` (`0x12`, `[kind][len u32][payload]`) over any
//!   [`PirTransport`] and parses `RESP_CREDIT_OK { gas_added u64, gas_balance
//!   i64 }`; surfaces the server's `RESP_ERROR` text (issuer refusals, double
//!   spends, "credits not enabled") as [`PirError::ServerError`].
//! - Parses the `"gas"` section of the server info JSON into a
//!   [`ServerGasCard`] and prices a frame the way the server will
//!   (`work + base_gas_per_frame`, egress charged after the response).
//! - Keeps a [`ConnectionCreditMeter`]: the balance the server holds for
//!   this connection as far as the client can tell, so the client presents
//!   exactly what the next frame needs and loses nothing on disconnect.
//!
//! What this does NOT do: build presentations. ARC credentials live in the
//! wasm bindings (`pir-sdk-wasm`) and the browser; Cashu tokens come from a
//! wallet. The presentation payload arrives here as bytes.

use std::collections::BTreeMap;

use pir_credit::gas::{MeteredOp, TableKind};
use pir_credit::GasParams;
use pir_sdk::{PirError, PirResult};
use serde::Deserialize;

use crate::protocol::encode_request;
use crate::transport::PirTransport;

/// Mirrors `pir_runtime_core::protocol::REQ_CREDIT_PRESENT`.
pub(crate) const REQ_CREDIT_PRESENT: u8 = 0x12;
/// Mirrors `pir_runtime_core::protocol::RESP_CREDIT_OK`.
pub(crate) const RESP_CREDIT_OK: u8 = 0x12;
/// Mirrors `pir_runtime_core::protocol::MAX_CREDIT_PRESENT_PAYLOAD_LEN`.
pub const MAX_CREDIT_PRESENT_PAYLOAD_LEN: usize = 256 * 1024;
/// Generic server-side error envelope.
const RESP_ERROR: u8 = 0xff;

pub use pir_credit::issuer::{CREDIT_PRESENT_KIND_ARC, CREDIT_PRESENT_KIND_CASHU};

/// What the server answered to a presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreditReceipt {
    /// Gas the presentation bought.
    pub gas_added: u64,
    /// The connection's balance afterwards.
    pub gas_balance: i64,
}

/// Body of a `REQ_CREDIT_PRESENT` frame (after the variant byte).
pub fn encode_credit_present_body(kind: u8, payload: &[u8]) -> PirResult<Vec<u8>> {
    if payload.is_empty() {
        return Err(PirError::Protocol("empty credit presentation".into()));
    }
    if payload.len() > MAX_CREDIT_PRESENT_PAYLOAD_LEN {
        return Err(PirError::Protocol(format!(
            "credit presentation is {} bytes, the limit is {MAX_CREDIT_PRESENT_PAYLOAD_LEN}",
            payload.len()
        )));
    }
    let mut body = Vec::with_capacity(5 + payload.len());
    body.push(kind);
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(payload);
    Ok(body)
}

/// Present `payload` of `kind` on `transport` and return the server's
/// receipt. Bearer material: call only over the encrypted channel.
pub async fn present_credits<T: PirTransport + ?Sized>(
    transport: &mut T,
    kind: u8,
    payload: &[u8],
) -> PirResult<CreditReceipt> {
    let body = encode_credit_present_body(kind, payload)?;
    let request = encode_request(REQ_CREDIT_PRESENT, &body);
    let response = transport.roundtrip(&request).await?;
    parse_credit_response(&response)
}

/// Parse a raw response payload (starting at the variant byte).
pub fn parse_credit_response(response: &[u8]) -> PirResult<CreditReceipt> {
    match response.first() {
        None => Err(PirError::Protocol("empty credit response".into())),
        Some(&RESP_CREDIT_OK) => {
            if response.len() != 17 {
                return Err(PirError::Protocol(format!(
                    "credit response must be 17 bytes, got {}",
                    response.len()
                )));
            }
            Ok(CreditReceipt {
                gas_added: u64::from_le_bytes(response[1..9].try_into().expect("eight bytes")),
                gas_balance: i64::from_le_bytes(response[9..17].try_into().expect("eight bytes")),
            })
        }
        Some(&RESP_ERROR) => Err(PirError::ServerError(decode_error_envelope(response))),
        Some(variant) => Err(PirError::Protocol(format!(
            "unexpected response variant 0x{variant:02x} for credit presentation"
        ))),
    }
}

/// `[RESP_ERROR][u32 len LE][utf-8 msg]`, tolerant of truncation.
fn decode_error_envelope(response: &[u8]) -> String {
    if response.len() >= 5 {
        let len = u32::from_le_bytes(response[1..5].try_into().expect("four bytes")) as usize;
        if 5 + len <= response.len() {
            return String::from_utf8_lossy(&response[5..5 + len]).into_owned();
        }
        return "<truncated error message>".into();
    }
    String::from_utf8_lossy(&response[1..]).into_owned()
}

/// The server's refusal of a metered frame, as its message states it:
/// "insufficient gas: this frame needs N and the connection has M; …".
pub fn parse_insufficient_gas(message: &str) -> Option<(u64, i64)> {
    let rest = message.strip_prefix("insufficient gas: this frame needs ")?;
    let (needed, rest) = rest.split_once(" and the connection has ")?;
    let balance = rest.split(';').next()?;
    Some((needed.trim().parse().ok()?, balance.trim().parse().ok()?))
}

/// Work gas per metered request kind of one database, as the server
/// publishes it under `"gas"."databases"."<db_id>"` in `GET_INFO_JSON`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct DatabaseGasCard {
    pub dpf_index_round: Option<u64>,
    pub dpf_chunk_round: Option<u64>,
    pub dpf_index_sibling_pass: Vec<u64>,
    pub dpf_chunk_sibling_pass: Vec<u64>,
    pub tree_tops: Option<u64>,
    pub onion_register_keys: Option<u64>,
    pub onion_index_query: Option<u64>,
    pub onion_chunk_query: Option<u64>,
    pub onion_sibling_query: Option<u64>,
    pub harmony_pool_entry: Option<u64>,
    pub harmony_index_sibling_set: Vec<u64>,
    pub harmony_chunk_sibling_set: Vec<u64>,
    pub harmony_query_index: Option<u64>,
    pub harmony_query_chunk: Option<u64>,
    pub oram_lookup: Option<u64>,
}

impl DatabaseGasCard {
    /// Work gas of `op` on this database, `None` when the server does not
    /// serve that backend for it. HarmonyPIR queries at a sibling level and
    /// batch queries are priced from the published single-query figures.
    pub fn work_gas(&self, op: MeteredOp) -> Option<u64> {
        match op {
            MeteredOp::DpfIndexRound => self.dpf_index_round,
            MeteredOp::DpfChunkRound => self.dpf_chunk_round,
            MeteredOp::DpfSiblingPass { table, level } => match table {
                TableKind::Index => self.dpf_index_sibling_pass.get(usize::from(level)).copied(),
                TableKind::Chunk => self.dpf_chunk_sibling_pass.get(usize::from(level)).copied(),
            },
            MeteredOp::TreeTops => self.tree_tops,
            MeteredOp::OnionRegisterKeys => self.onion_register_keys,
            MeteredOp::OnionIndexQuery => self.onion_index_query,
            MeteredOp::OnionChunkQuery => self.onion_chunk_query,
            MeteredOp::OnionSiblingQuery { .. } => self.onion_sibling_query,
            MeteredOp::OnionTreeTops => self.tree_tops.or(Some(5)),
            MeteredOp::HarmonyPoolEntry => self.harmony_pool_entry,
            MeteredOp::HarmonyContinuation => Some(0),
            MeteredOp::HarmonyHintSet { level } => match pir_credit::gas::harmony_level(level)? {
                (TableKind::Index, None) => self.harmony_pool_entry.map(|g| g / 3),
                (TableKind::Chunk, None) => self.harmony_pool_entry.map(|g| g - g / 3),
                (TableKind::Index, Some(level)) => self
                    .harmony_index_sibling_set
                    .get(usize::from(level))
                    .copied(),
                (TableKind::Chunk, Some(level)) => self
                    .harmony_chunk_sibling_set
                    .get(usize::from(level))
                    .copied(),
            },
            MeteredOp::HarmonyQuery { level, sub_queries } => {
                let single = match pir_credit::gas::harmony_level(level)? {
                    (TableKind::Index, _) => self.harmony_query_index,
                    (TableKind::Chunk, _) => self.harmony_query_chunk,
                }?;
                Some(single.saturating_mul(u64::from(sub_queries.max(1))))
            }
            MeteredOp::OramLookup => self.oram_lookup,
        }
    }
}

/// The `"gas"` section of a server's info JSON.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ServerGasCard {
    pub unit: String,
    pub params: GasParams,
    #[serde(default)]
    pub databases: BTreeMap<String, DatabaseGasCard>,
}

impl ServerGasCard {
    /// The card embedded in an info JSON document, `None` when the server
    /// predates gas metering.
    pub fn from_info_json(info_json: &str) -> PirResult<Option<Self>> {
        #[derive(Deserialize)]
        struct Envelope {
            gas: Option<ServerGasCard>,
        }
        let envelope: Envelope = serde_json::from_str(info_json)
            .map_err(|e| PirError::Protocol(format!("server info JSON: {e}")))?;
        Ok(envelope.gas)
    }

    pub fn database(&self, db_id: u8) -> Option<&DatabaseGasCard> {
        self.databases.get(&db_id.to_string())
    }

    /// Gas the server will charge before dispatching `op` on `db_id`
    /// (work plus base fee), `None` when unmetered there.
    pub fn frame_gas(&self, db_id: u8, op: MeteredOp) -> Option<u64> {
        let work = self.database(db_id)?.work_gas(op)?;
        Some(self.params.frame_gas(work))
    }
}

/// The client's view of one connection's gas balance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionCreditMeter {
    card: ServerGasCard,
    balance: i64,
}

impl ConnectionCreditMeter {
    pub fn new(card: ServerGasCard) -> Self {
        Self { card, balance: 0 }
    }

    pub fn card(&self) -> &ServerGasCard {
        &self.card
    }

    pub fn balance(&self) -> i64 {
        self.balance
    }

    /// Gas a frame will be charged before dispatch, `None` when unmetered.
    pub fn frame_gas(&self, db_id: u8, op: MeteredOp) -> Option<u64> {
        self.card.frame_gas(db_id, op)
    }

    /// Credits to present so the balance covers `frame_gas` plus the
    /// expected egress of `expected_response_bytes`; 0 when it already does.
    pub fn credits_to_present(&self, frame_gas: u64, expected_response_bytes: u64) -> u64 {
        let needed = i128::from(frame_gas)
            + i128::from(self.card.params.egress_gas(expected_response_bytes));
        let shortfall = needed - i128::from(self.balance);
        if shortfall <= 0 {
            return 0;
        }
        let shortfall = u64::try_from(shortfall).unwrap_or(u64::MAX);
        self.card.params.credits_to_cover(shortfall)
    }

    /// The server accepted a presentation: adopt its balance.
    pub fn record_receipt(&mut self, receipt: CreditReceipt) {
        self.balance = receipt.gas_balance;
    }

    /// A metered frame went out: the server charged its work plus base fee.
    pub fn record_frame(&mut self, frame_gas: u64) {
        self.balance = self
            .balance
            .saturating_sub(i64::try_from(frame_gas).unwrap_or(i64::MAX));
    }

    /// A response came back: the server charged its egress.
    pub fn record_response(&mut self, response_bytes: u64) {
        let egress = self.card.params.egress_gas(response_bytes);
        self.balance = self
            .balance
            .saturating_sub(i64::try_from(egress).unwrap_or(i64::MAX));
    }

    /// The server refused a frame and named its numbers: resynchronise.
    pub fn record_refusal(&mut self, message: &str) -> Option<u64> {
        let (needed, balance) = parse_insufficient_gas(message)?;
        self.balance = balance;
        Some(needed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &str = r#"{"index_bins_per_table":1,"role":"primary","gas":{"unit":"cpu_ms_pir1","params":{"credit_sat":10,"gas_per_credit":72000,"base_gas_per_frame":20,"egress_gas_per_mb":1000},"databases":{"0":{"dpf_index_round":1380,"dpf_chunk_round":4550,"dpf_index_sibling_pass":[456,57,7],"dpf_chunk_sibling_pass":[914,114,14],"tree_tops":5,"onion_register_keys":200,"onion_index_query":197506,"onion_chunk_query":403260,"onion_sibling_query":21000,"harmony_pool_entry":129970,"harmony_index_sibling_set":[3780,470,60],"harmony_chunk_sibling_set":[7570,950,120],"harmony_query_index":8,"harmony_query_chunk":12},"1":{"oram_lookup":512}}}}"#;

    #[test]
    fn frame_body_and_response_codecs() {
        let body = encode_credit_present_body(CREDIT_PRESENT_KIND_ARC, &[1, 2, 3]).unwrap();
        assert_eq!(body, vec![2, 3, 0, 0, 0, 1, 2, 3]);
        assert!(encode_credit_present_body(1, &[]).is_err());
        assert!(
            encode_credit_present_body(1, &vec![0; MAX_CREDIT_PRESENT_PAYLOAD_LEN + 1]).is_err()
        );
        let mut ok = vec![RESP_CREDIT_OK];
        ok.extend_from_slice(&72_000u64.to_le_bytes());
        ok.extend_from_slice(&(-15i64).to_le_bytes());
        assert_eq!(
            parse_credit_response(&ok).unwrap(),
            CreditReceipt {
                gas_added: 72_000,
                gas_balance: -15
            }
        );
        assert!(parse_credit_response(&ok[..16]).is_err());
        let mut error = vec![RESP_ERROR];
        error.extend_from_slice(&11u32.to_le_bytes());
        error.extend_from_slice(b"double_spend");
        assert!(
            matches!(parse_credit_response(&error), Err(PirError::ServerError(m)) if m == "double_spen")
        );
        assert!(parse_credit_response(&[]).is_err());
        assert!(parse_credit_response(&[0x11]).is_err());
    }

    #[test]
    fn refusal_messages_are_parsed_exactly() {
        assert_eq!(
            parse_insufficient_gas("insufficient gas: this frame needs 1400 and the connection has -7; present credits with REQ_CREDIT_PRESENT"),
            Some((1_400, -7))
        );
        assert_eq!(
            parse_insufficient_gas("credits not enabled on this server"),
            None
        );
    }

    #[test]
    fn gas_card_prices_frames_like_the_server() {
        let card = ServerGasCard::from_info_json(INFO).unwrap().unwrap();
        assert_eq!(card.unit, "cpu_ms_pir1");
        assert_eq!(card.params, GasParams::PRODUCTION_2026_09);
        assert_eq!(card.frame_gas(0, MeteredOp::DpfIndexRound), Some(1_400));
        assert_eq!(
            card.frame_gas(
                0,
                MeteredOp::DpfSiblingPass {
                    table: TableKind::Chunk,
                    level: 2
                }
            ),
            Some(34)
        );
        assert_eq!(
            card.frame_gas(
                0,
                MeteredOp::DpfSiblingPass {
                    table: TableKind::Chunk,
                    level: 3
                }
            ),
            None
        );
        assert_eq!(card.frame_gas(0, MeteredOp::OnionChunkQuery), Some(403_280));
        assert_eq!(
            card.frame_gas(0, MeteredOp::HarmonyHintSet { level: 21 }),
            Some(970)
        );
        assert_eq!(
            card.frame_gas(
                0,
                MeteredOp::HarmonyQuery {
                    level: 1,
                    sub_queries: 3
                }
            ),
            Some(56)
        );
        assert_eq!(card.frame_gas(0, MeteredOp::HarmonyContinuation), Some(20));
        assert_eq!(card.frame_gas(0, MeteredOp::OramLookup), None);
        assert_eq!(card.frame_gas(1, MeteredOp::OramLookup), Some(532));
        assert_eq!(card.frame_gas(2, MeteredOp::OramLookup), None);
        assert!(ServerGasCard::from_info_json(r#"{"role":"primary"}"#)
            .unwrap()
            .is_none());
        assert!(ServerGasCard::from_info_json("nope").is_err());
    }

    #[test]
    fn meter_tops_up_exactly_what_the_next_frame_needs() {
        let card = ServerGasCard::from_info_json(INFO).unwrap().unwrap();
        let mut meter = ConnectionCreditMeter::new(card);
        let index = meter.frame_gas(0, MeteredOp::DpfIndexRound).unwrap();
        // 1,400 gas of work plus 8 KiB of egress: one credit.
        assert_eq!(meter.credits_to_present(index, 8_192), 1);
        meter.record_receipt(CreditReceipt {
            gas_added: 72_000,
            gas_balance: 72_000,
        });
        assert_eq!(meter.credits_to_present(index, 8_192), 0);
        meter.record_frame(index);
        meter.record_response(8_192);
        assert_eq!(meter.balance(), 72_000 - 1_400 - 8);
        // An OnionPIR CHUNK query needs six more credits from that balance.
        let chunk = meter.frame_gas(0, MeteredOp::OnionChunkQuery).unwrap();
        assert_eq!(meter.credits_to_present(chunk, 1_000_000), 5);
        // The server's own numbers win on a refusal.
        assert_eq!(
            meter.record_refusal("insufficient gas: this frame needs 403280 and the connection has 100; present credits with REQ_CREDIT_PRESENT"),
            Some(403_280)
        );
        assert_eq!(meter.balance(), 100);
        assert_eq!(meter.credits_to_present(403_280, 0), 6);
    }
}
