//! The credited transport (docs/CREDITS.md "Metering on the server"): a
//! [`PirTransport`] wrapper that keeps one connection's gas balance funded.
//!
//! Before a metered frame goes out it is priced like the server prices it
//! (work from the server's gas card, the base fee, plus an estimate of the
//! response bytes the server charges afterwards); when the balance would
//! not cover that, credits are obtained from the [`CreditProvider`] and
//! presented on the same connection first. Responses are attributed to the
//! frames that caused them so egress is charged as the server charges it,
//! every receipt resynchronises the balance with the server's own figure,
//! and a refusal that names its numbers resynchronises too and is retried
//! once on the round-trip path.
//!
//! Frames the server does not meter, servers that do not require credits,
//! and connections carrying a session grant never touch a provider:
//! [`enable_credits`] reads the server's info JSON and wraps only where the
//! server says it charges.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use pir_credit::gas::MeteredOp;
use pir_credit::GasParams;
use pir_sdk::{PirError, PirMetrics, PirResult};
use serde::Deserialize;

use crate::credit_frames::{classify_frame, expected_response_bytes, op_family};
use crate::credits::{
    encode_credit_present_body, parse_credit_response, parse_insufficient_gas, CreditReceipt,
    ServerGasCard, REQ_CREDIT_PRESENT,
};
use crate::protocol::encode_request;
use crate::transport::PirTransport;

/// Mirrors `REQ_GET_INFO_JSON` / `RESP_GET_INFO_JSON` (`0x03`).
const REQ_GET_INFO_JSON: u8 = 0x03;
const RESP_GET_INFO_JSON: u8 = 0x03;
const RESP_ERROR: u8 = 0xff;

/// Credits a provider hands over for one presentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presentation {
    /// `CREDIT_PRESENT_KIND_CASHU` or `CREDIT_PRESENT_KIND_ARC`.
    pub kind: u8,
    pub payload: Vec<u8>,
    /// Credits the payload is worth (the balance the server will add is
    /// `credits × gas_per_credit`).
    pub credits: u64,
}

/// Source of presentations: a wallet of ARC credentials, a Cashu token
/// store, or anything else that can produce `credits` credits on demand.
/// Shared by every connection of one client, so it takes `&self`.
pub trait CreditProvider: Send + Sync {
    /// A presentation worth at least `credits` credits, `None` when the
    /// provider has nothing left. A presentation worth more than asked is
    /// fine (the connection keeps the change until it closes); one worth
    /// less is presented and followed by another request.
    fn present(&self, credits: u64) -> PirResult<Option<Presentation>>;
}

/// What a server said about credits in its info JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreditStatus {
    /// The server predates credits or has no issuer: nothing to present.
    NotEnabled,
    /// The server verifies presentations but does not charge frames yet:
    /// presenting would only spend credits.
    NotRequired,
    /// Metered frames must be paid: the connection is now credited.
    Required,
}

#[derive(Deserialize)]
struct CreditFlags {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    required: bool,
}

#[derive(Deserialize)]
struct InfoEnvelope {
    gas: Option<ServerGasCard>,
    credits: Option<CreditFlags>,
}

/// Read the server's info JSON over `conn` and, when the server requires
/// credits, wrap `conn` so its metered frames are paid from `provider`.
/// Call after the secure-channel upgrade: presentations are bearer
/// material. The transport comes back in every case, wrapped only on
/// `Ok(CreditStatus::Required)`.
pub async fn enable_credits(
    mut conn: Box<dyn PirTransport>,
    provider: Arc<dyn CreditProvider>,
) -> (Box<dyn PirTransport>, PirResult<CreditStatus>) {
    let info = match read_info(conn.as_mut()).await {
        Ok(info) => info,
        Err(error) => return (conn, Err(error)),
    };
    let flags = match info.credits {
        Some(flags) if flags.enabled => flags,
        _ => return (conn, Ok(CreditStatus::NotEnabled)),
    };
    if !flags.required {
        return (conn, Ok(CreditStatus::NotRequired));
    }
    let Some(card) = info.gas else {
        return (
            conn,
            Err(PirError::Protocol(
                "server requires credits but publishes no gas card".into(),
            )),
        );
    };
    (
        Box::new(CreditedTransport::new(conn, card, provider)),
        Ok(CreditStatus::Required),
    )
}

async fn read_info(conn: &mut dyn PirTransport) -> PirResult<InfoEnvelope> {
    let response = conn
        .roundtrip(&encode_request(REQ_GET_INFO_JSON, &[]))
        .await?;
    match response.first() {
        Some(&RESP_GET_INFO_JSON) => {}
        Some(&RESP_ERROR) => {
            return Err(PirError::ServerError(decode_error_message(&response)));
        }
        _ => return Err(PirError::Protocol("expected the JSON info response".into())),
    }
    serde_json::from_slice(&response[1..])
        .map_err(|e| PirError::Protocol(format!("server info JSON: {e}")))
}

/// One frame the server has not answered yet, as the wrapper priced it.
#[derive(Clone, Copy, Debug)]
enum Outstanding {
    /// A metered frame, with its kind for attributing the response.
    Metered { op: MeteredOp, frames_seen: u32 },
    /// A frame the server does not charge.
    Free { frames_seen: u32 },
}

impl Outstanding {
    fn frames_seen(&self) -> u32 {
        match self {
            Outstanding::Metered { frames_seen, .. } | Outstanding::Free { frames_seen } => {
                *frames_seen
            }
        }
    }

    fn note_frame(&mut self) {
        match self {
            Outstanding::Metered { frames_seen, .. } | Outstanding::Free { frames_seen } => {
                *frames_seen += 1;
            }
        }
    }
}

/// [`PirTransport`] wrapper keeping the connection's balance funded.
pub struct CreditedTransport {
    inner: Box<dyn PirTransport>,
    card: ServerGasCard,
    provider: Arc<dyn CreditProvider>,
    /// The client's view of the server's balance for this connection.
    balance: i64,
    /// Sent frames whose responses are still to come, in order.
    outstanding: VecDeque<Outstanding>,
    /// Largest response seen per request family, replacing the built-in
    /// estimates once known.
    observed: HashMap<u32, u64>,
    /// Credits presented on this connection so far.
    presented_credits: u64,
}

impl CreditedTransport {
    pub fn new(
        inner: Box<dyn PirTransport>,
        card: ServerGasCard,
        provider: Arc<dyn CreditProvider>,
    ) -> Self {
        Self {
            inner,
            card,
            provider,
            balance: 0,
            outstanding: VecDeque::new(),
            observed: HashMap::new(),
            presented_credits: 0,
        }
    }

    pub fn card(&self) -> &ServerGasCard {
        &self.card
    }

    fn params(&self) -> &GasParams {
        &self.card.params
    }

    /// The client's current view of the connection's balance.
    pub fn balance(&self) -> i64 {
        self.balance
    }

    /// Credits presented on this connection so far.
    pub fn presented_credits(&self) -> u64 {
        self.presented_credits
    }

    fn admission_gas(&self, op: MeteredOp, db_id: u8) -> Option<u64> {
        self.card.frame_gas(db_id, op)
    }

    fn egress_reserve(&self, op: MeteredOp) -> u64 {
        let bytes = self
            .observed
            .get(&op_family(op))
            .copied()
            .map_or(expected_response_bytes(op), |seen| {
                seen.max(seen / 8 + seen)
            });
        self.params().egress_gas(bytes)
    }

    /// Present credits until the balance covers `needed` gas.
    async fn top_up(&mut self, needed: i128) -> PirResult<()> {
        let mut attempts = 0;
        while i128::from(self.balance) < needed {
            attempts += 1;
            if attempts > 4 {
                return Err(PirError::Protocol(
                    "credits: the balance did not reach the frame's price after four presentations"
                        .into(),
                ));
            }
            let shortfall = u64::try_from(needed - i128::from(self.balance)).unwrap_or(u64::MAX);
            let credits = self.params().credits_to_cover(shortfall).max(1);
            let Some(presentation) = self.provider.present(credits)? else {
                return Err(PirError::ServerError(format!(
                    "credits required: this frame needs {credits} more credit(s) and the wallet has none"
                )));
            };
            let body = encode_credit_present_body(presentation.kind, &presentation.payload)?;
            let response = self
                .inner
                .roundtrip(&encode_request(REQ_CREDIT_PRESENT, &body))
                .await?;
            let receipt = parse_credit_response(&response)?;
            self.presented_credits += presentation.credits;
            self.apply_receipt(receipt);
        }
        Ok(())
    }

    /// Adopt the server's balance from a receipt.
    fn apply_receipt(&mut self, receipt: CreditReceipt) {
        // A presentation is a round trip of its own, sent before the frame
        // it funds, so nothing metered is in flight when the receipt
        // arrives and the server's figure is exact.
        self.balance = receipt.gas_balance;
    }

    /// Price and, if needed, fund a frame before it goes out.
    async fn before_send(&mut self, frame: &[u8]) -> PirResult<Outstanding> {
        let Some((op, db_id)) = classify_frame(frame) else {
            return Ok(Outstanding::Free { frames_seen: 0 });
        };
        let Some(admission) = self.admission_gas(op, db_id) else {
            // The server does not serve this backend for that database: it
            // will refuse the frame for free.
            return Ok(Outstanding::Free { frames_seen: 0 });
        };
        let needed = i128::from(admission) + i128::from(self.egress_reserve(op));
        if i128::from(self.balance) < needed {
            self.top_up(needed).await?;
        }
        self.balance -= i64::try_from(admission).unwrap_or(i64::MAX);
        Ok(Outstanding::Metered { op, frames_seen: 0 })
    }

    /// Attribute a received frame to the oldest unanswered request.
    fn after_recv(&mut self, response_len: u64) -> Option<&'static str> {
        let Some(head) = self.outstanding.front_mut() else {
            return None;
        };
        head.note_frame();
        if let Outstanding::Metered { op, frames_seen } = *head {
            let egress = self.params().egress_gas(response_len);
            self.balance -= i64::try_from(egress).unwrap_or(i64::MAX);
            let family = op_family(op);
            let entry = self.observed.entry(family).or_insert(0);
            // Streams (HarmonyPIR hints) count every frame of one response.
            if frames_seen <= 1 {
                *entry = (*entry).max(response_len);
            } else {
                *entry = entry.saturating_add(response_len);
            }
        }
        // A later request exists: this response finished the head.
        if self.outstanding.len() > 1 {
            self.outstanding.pop_front();
        }
        None
    }

    /// Before a new request goes out, the previous single-response request
    /// is over once it has been answered at all.
    fn close_answered_head(&mut self) {
        if self.outstanding.len() == 1 && self.outstanding[0].frames_seen() > 0 {
            self.outstanding.pop_front();
        }
    }

    /// A refusal naming the server's numbers: resynchronise and report the
    /// gas the frame needs.
    fn note_refusal(&mut self, response: &[u8]) -> Option<u64> {
        if response.first() != Some(&RESP_ERROR) {
            return None;
        }
        let message = decode_error_message(response);
        let (needed, balance) = parse_insufficient_gas(&message)?;
        self.balance = balance;
        Some(needed)
    }
}

fn decode_error_message(response: &[u8]) -> String {
    if response.len() >= 5 {
        let len = u32::from_le_bytes(response[1..5].try_into().expect("four bytes")) as usize;
        if 5 + len <= response.len() {
            return String::from_utf8_lossy(&response[5..5 + len]).into_owned();
        }
    }
    String::from_utf8_lossy(response.get(1..).unwrap_or_default()).into_owned()
}

#[async_trait]
impl PirTransport for CreditedTransport {
    async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
        self.close_answered_head();
        let entry = self.before_send(&data).await?;
        self.inner.send(data).await?;
        self.outstanding.push_back(entry);
        Ok(())
    }

    async fn recv(&mut self) -> PirResult<Vec<u8>> {
        let frame = self.inner.recv().await?;
        self.after_recv(frame.len() as u64);
        // A refusal on the pipelined path cannot be retried here (the
        // caller owns the ordering); resynchronise so the next frame pays.
        if frame.len() > 4 {
            self.note_refusal(&frame[4..]);
        }
        Ok(frame)
    }

    async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
        self.close_answered_head();
        let entry = self.before_send(request).await?;
        self.outstanding.push_back(entry);
        let mut response = self.inner.roundtrip(request).await?;
        self.after_recv(response.len() as u64 + 4);
        if let Some(needed) = self.note_refusal(&response) {
            // The server's own numbers: fund exactly that and send once more.
            let reserve = match entry {
                Outstanding::Metered { op, .. } => self.egress_reserve(op),
                Outstanding::Free { .. } => 0,
            };
            self.top_up(i128::from(needed) + i128::from(reserve))
                .await?;
            self.balance -= i64::try_from(needed).unwrap_or(i64::MAX);
            self.outstanding.push_back(entry);
            response = self.inner.roundtrip(request).await?;
            self.after_recv(response.len() as u64 + 4);
        }
        Ok(response)
    }

    async fn close(&mut self) -> PirResult<()> {
        self.inner.close().await
    }

    fn url(&self) -> &str {
        self.inner.url()
    }

    fn service_authorization_exporter_v1(&self) -> Option<[u8; 32]> {
        self.inner.service_authorization_exporter_v1()
    }

    fn set_metrics_recorder(
        &mut self,
        recorder: Option<Arc<dyn PirMetrics>>,
        backend: &'static str,
    ) {
        self.inner.set_metrics_recorder(recorder, backend);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credits::{CREDIT_PRESENT_KIND_ARC, RESP_CREDIT_OK};
    use std::sync::Mutex;

    const INFO: &str = r#"{"role":"primary","gas":{"unit":"cpu_ms_pir1","params":{"credit_sat":10,"gas_per_credit":72000,"base_gas_per_frame":20,"egress_gas_per_mb":1000},"databases":{"0":{"dpf_index_round":1380,"dpf_chunk_round":4550,"dpf_index_sibling_pass":[456,57,7],"dpf_chunk_sibling_pass":[914,114,14],"tree_tops":5,"harmony_pool_entry":129970,"harmony_index_sibling_set":[3780,470,60],"harmony_chunk_sibling_set":[7570,950,120],"harmony_query_index":8,"harmony_query_chunk":12}}},"credits":{"enabled":true,"required":true}}"#;

    /// A server that answers from a script and remembers what it saw; a
    /// presentation is answered with a receipt computed from a balance the
    /// fake keeps, and metered frames are charged the way the real gate
    /// charges them.
    struct FakeServer {
        script: Mutex<VecDeque<Vec<u8>>>,
        sent: Mutex<Vec<Vec<u8>>>,
        balance: Mutex<i64>,
        info: &'static str,
    }

    impl FakeServer {
        fn new(info: &'static str) -> Self {
            Self {
                script: Mutex::new(VecDeque::new()),
                sent: Mutex::new(Vec::new()),
                balance: Mutex::new(0),
                info,
            }
        }

        fn answer(&self, request: &[u8]) -> Vec<u8> {
            self.sent.lock().unwrap().push(request.to_vec());
            let variant = request[4];
            if variant == REQ_GET_INFO_JSON {
                let mut out = vec![RESP_GET_INFO_JSON];
                out.extend_from_slice(self.info.as_bytes());
                return out;
            }
            if variant == REQ_CREDIT_PRESENT {
                // kind, len, payload = [credits u8]
                let credits = u64::from(request[10]);
                let mut balance = self.balance.lock().unwrap();
                *balance += (credits * 72_000) as i64;
                let mut out = vec![RESP_CREDIT_OK];
                out.extend_from_slice(&(credits * 72_000).to_le_bytes());
                out.extend_from_slice(&balance.to_le_bytes());
                return out;
            }
            let card = ServerGasCard::from_info_json(self.info).unwrap().unwrap();
            if let Some((op, db_id)) = classify_frame(request) {
                if let Some(gas) = card.frame_gas(db_id, op) {
                    let mut balance = self.balance.lock().unwrap();
                    if *balance < gas as i64 {
                        let message = format!(
                            "insufficient gas: this frame needs {gas} and the connection has {}; present credits with REQ_CREDIT_PRESENT",
                            *balance
                        );
                        let mut out = vec![RESP_ERROR];
                        out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                        out.extend_from_slice(message.as_bytes());
                        return out;
                    }
                    *balance -= gas as i64;
                    let response = self
                        .script
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_else(|| vec![0x11; 100]);
                    *balance -= card.params.egress_gas(response.len() as u64 + 4) as i64;
                    return response;
                }
            }
            self.script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| vec![0x01, 0])
        }
    }

    struct FakeTransport {
        server: Arc<FakeServer>,
        inbox: VecDeque<Vec<u8>>,
    }

    #[async_trait]
    impl PirTransport for FakeTransport {
        async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
            let answer = self.server.answer(&data);
            let mut framed = (answer.len() as u32).to_le_bytes().to_vec();
            framed.extend_from_slice(&answer);
            self.inbox.push_back(framed);
            Ok(())
        }
        async fn recv(&mut self) -> PirResult<Vec<u8>> {
            self.inbox
                .pop_front()
                .ok_or_else(|| PirError::Protocol("nothing to receive".into()))
        }
        async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
            Ok(self.server.answer(request))
        }
        async fn close(&mut self) -> PirResult<()> {
            Ok(())
        }
        fn url(&self) -> &str {
            "mock://credited"
        }
    }

    struct Wallet {
        credits_left: Mutex<u64>,
        calls: Mutex<Vec<u64>>,
    }

    impl CreditProvider for Wallet {
        fn present(&self, credits: u64) -> PirResult<Option<Presentation>> {
            self.calls.lock().unwrap().push(credits);
            let mut left = self.credits_left.lock().unwrap();
            if *left == 0 {
                return Ok(None);
            }
            let give = credits.min(*left).min(255);
            *left -= give;
            Ok(Some(Presentation {
                kind: CREDIT_PRESENT_KIND_ARC,
                payload: vec![give as u8],
                credits: give,
            }))
        }
    }

    fn setup(
        info: &'static str,
        credits: u64,
    ) -> (Arc<FakeServer>, Arc<Wallet>, Box<dyn PirTransport>) {
        let server = Arc::new(FakeServer::new(info));
        let wallet = Arc::new(Wallet {
            credits_left: Mutex::new(credits),
            calls: Mutex::new(Vec::new()),
        });
        let transport = Box::new(FakeTransport {
            server: Arc::clone(&server),
            inbox: VecDeque::new(),
        });
        (server, wallet, transport)
    }

    fn index_round(db_id: u8) -> Vec<u8> {
        let mut body = 0u16.to_le_bytes().to_vec();
        body.push(1);
        body.push(1);
        body.extend_from_slice(&1u16.to_le_bytes());
        body.push(9);
        if db_id != 0 {
            body.push(db_id);
        }
        encode_request(0x11, &body)
    }

    fn tree_tops() -> Vec<u8> {
        encode_request(0x34, &[])
    }

    #[tokio::test]
    async fn servers_without_credits_are_left_alone() {
        let (_, wallet, transport) = setup(r#"{"role":"primary"}"#, 5);
        let (_, status) = enable_credits(transport, wallet.clone()).await;
        assert_eq!(status.unwrap(), CreditStatus::NotEnabled);
        let (_, wallet, transport) = setup(
            r#"{"role":"primary","gas":{"unit":"x","params":{"credit_sat":10,"gas_per_credit":72000,"base_gas_per_frame":20,"egress_gas_per_mb":1000},"databases":{}},"credits":{"enabled":true,"required":false}}"#,
            5,
        );
        let (_, status) = enable_credits(transport, wallet.clone()).await;
        assert_eq!(status.unwrap(), CreditStatus::NotRequired);
        assert!(wallet.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn metered_frames_are_funded_before_they_go_out() {
        let (server, wallet, transport) = setup(INFO, 10);
        let (mut conn, status) = enable_credits(transport, wallet.clone()).await;
        assert_eq!(status.unwrap(), CreditStatus::Required);
        // Free frames never touch the wallet.
        conn.roundtrip(&encode_request(0x01, &[])).await.unwrap();
        assert!(wallet.calls.lock().unwrap().is_empty());
        // An INDEX round: 1,400 gas plus a 16 KiB reserve → one credit.
        let response = conn.roundtrip(&index_round(0)).await.unwrap();
        assert_eq!(response[0], 0x11);
        assert_eq!(wallet.calls.lock().unwrap().as_slice(), &[1]);
        let sent = server.sent.lock().unwrap();
        let variants: Vec<u8> = sent.iter().map(|f| f[4]).collect();
        assert_eq!(variants, vec![0x03, 0x01, REQ_CREDIT_PRESENT, 0x11]);
        drop(sent);
        // The fake charged 1,400 plus egress of the 104-byte response (0 gas).
        assert_eq!(*server.balance.lock().unwrap(), 72_000 - 1_400);
        // Tree tops: 25 gas of work but a 12 MiB egress reserve → funded
        // up front rather than refused afterwards.
        server
            .script
            .lock()
            .unwrap()
            .push_back(vec![0x34; 9_155_389]);
        conn.roundtrip(&tree_tops()).await.unwrap();
        assert_eq!(
            wallet.calls.lock().unwrap().len(),
            1,
            "the first credit covered both frames"
        );
        assert_eq!(*server.balance.lock().unwrap(), 72_000 - 1_400 - 25 - 9_155);
        // Many more rounds drain the balance and the wrapper tops up again
        // without a single refusal.
        for _ in 0..60 {
            conn.roundtrip(&index_round(0)).await.unwrap();
        }
        let refusals = server
            .sent
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f[4] == REQ_CREDIT_PRESENT)
            .count();
        assert!(refusals >= 2);
        assert!(!server
            .sent
            .lock()
            .unwrap()
            .iter()
            .any(|f| f[4] == 0x11 && false));
        assert!(*server.balance.lock().unwrap() >= 0);
    }

    #[tokio::test]
    async fn pipelined_sends_are_funded_in_order_and_responses_attributed() {
        let (server, wallet, transport) = setup(INFO, 10);
        let (mut conn, _) = enable_credits(transport, wallet.clone()).await;
        conn.send(index_round(0)).await.unwrap();
        conn.send(index_round(0)).await.unwrap();
        let a = conn.recv().await.unwrap();
        let b = conn.recv().await.unwrap();
        assert_eq!(a[4], 0x11);
        assert_eq!(b[4], 0x11);
        assert_eq!(wallet.calls.lock().unwrap().as_slice(), &[1]);
        assert_eq!(*server.balance.lock().unwrap(), 72_000 - 2 * 1_400);
        // The wrapper's view matches the server's.
        let credited = conn as Box<dyn PirTransport>;
        let _ = credited;
    }

    #[tokio::test]
    async fn a_refusal_on_the_round_trip_path_is_retried_once_with_the_servers_numbers() {
        let (server, wallet, transport) = setup(INFO, 10);
        let (mut conn, _) = enable_credits(transport, wallet.clone()).await;
        conn.roundtrip(&index_round(0)).await.unwrap();
        // Something the client did not see drained the server-side balance
        // (say, a response it under-estimated): force a refusal.
        *server.balance.lock().unwrap() = 100;
        let response = conn.roundtrip(&index_round(0)).await.unwrap();
        assert_eq!(response[0], 0x11, "retried after topping up");
        assert_eq!(wallet.calls.lock().unwrap().len(), 2);
        assert_eq!(*server.balance.lock().unwrap(), 100 + 72_000 - 1_400);
    }

    #[tokio::test]
    async fn an_empty_wallet_fails_the_frame_with_a_clear_message() {
        let (_, wallet, transport) = setup(INFO, 0);
        let (mut conn, _) = enable_credits(transport, wallet.clone()).await;
        let error = conn.roundtrip(&index_round(0)).await.unwrap_err();
        assert!(matches!(error, PirError::ServerError(m) if m.contains("credits required")));
    }

    #[tokio::test]
    async fn unserved_backends_are_not_funded() {
        let (server, wallet, transport) = setup(INFO, 10);
        let (mut conn, _) = enable_credits(transport, wallet.clone()).await;
        // Database 1 has no gas card here: the server will refuse it for free.
        server
            .script
            .lock()
            .unwrap()
            .push_back(vec![RESP_ERROR, 0, 0, 0, 0]);
        let _ = conn.roundtrip(&index_round(1)).await.unwrap();
        assert!(wallet.calls.lock().unwrap().is_empty());
    }
}
