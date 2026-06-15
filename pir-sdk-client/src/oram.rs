//! Native TEE ORAM client.
//!
//! This client speaks the `REQ_ORAM_LOOKUP` opcode exposed by
//! `unified_server` when it is built with the `cuckoo-oram` feature and
//! configured with ORAM-backed INDEX + CHUNK cuckoo tables. The request carries
//! plaintext scripthashes, so callers must authenticate the server and upgrade
//! the transport to the encrypted channel before calling [`OramClient::lookup_raw`]
//! or [`OramClient::query_batch`]. The server rejects cleartext ORAM lookup
//! frames as a second line of defense.

#[cfg(not(target_arch = "wasm32"))]
use crate::connection::WsConnection;
use crate::protocol::{
    decode_catalog, encode_request, REQ_GET_DB_CATALOG, RESP_DB_CATALOG, RESP_ERROR,
};
use crate::transport::PirTransport;
#[cfg(target_arch = "wasm32")]
use crate::wasm_transport::WasmWebSocketTransport;
use pir_core::params::SCRIPT_HASH_SIZE;
use pir_sdk::{
    DatabaseCatalog, PirError, PirMetrics, PirResult, QueryResult, ScriptHash, UtxoEntry,
};
use std::sync::Arc;

const REQ_ORAM_LOOKUP: u8 = 0x60;
const RESP_ORAM_LOOKUP: u8 = 0x60;
const MAX_ORAM_LOOKUP_SCRIPTHASHES: usize = 256;

/// One decoded item from `RESP_ORAM_LOOKUP`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OramLookupItem {
    pub found: bool,
    pub whale: bool,
    pub start_chunk_id: u32,
    pub num_chunks: u8,
    /// Raw concatenated chunk payloads in chunk-id order. Empty for not-found
    /// and whale results.
    pub raw_chunk_data: Vec<u8>,
}

/// Decoded ORAM lookup response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OramLookupResult {
    pub db_id: u8,
    pub items: Vec<OramLookupItem>,
}

/// Single-server ORAM client for the attested TEE backend.
pub struct OramClient {
    server_url: String,
    conn: Option<Box<dyn PirTransport>>,
    catalog: Option<DatabaseCatalog>,
    metrics_recorder: Option<Arc<dyn PirMetrics>>,
}

impl OramClient {
    /// Create a client for one `unified_server` endpoint.
    pub fn new(server_url: &str) -> Self {
        Self {
            server_url: server_url.to_string(),
            conn: None,
            catalog: None,
            metrics_recorder: None,
        }
    }

    /// Install or replace a metrics recorder.
    pub fn set_metrics_recorder(&mut self, recorder: Option<Arc<dyn PirMetrics>>) {
        self.metrics_recorder = recorder.clone();
        if let Some(conn) = &mut self.conn {
            conn.set_metrics_recorder(recorder, "oram");
        }
    }

    /// Install a pre-built transport, mainly for tests.
    pub fn connect_with_transport(&mut self, conn: Box<dyn PirTransport>) {
        self.conn = Some(conn);
        if let Some(rec) = self.metrics_recorder.clone() {
            if let Some(conn) = &mut self.conn {
                conn.set_metrics_recorder(Some(rec), "oram");
            }
        }
        self.fire_connect();
    }

    /// Open the WebSocket transport.
    pub async fn connect(&mut self) -> PirResult<()> {
        #[cfg(not(target_arch = "wasm32"))]
        let conn: Box<dyn PirTransport> = Box::new(WsConnection::connect(&self.server_url).await?);

        #[cfg(target_arch = "wasm32")]
        let conn: Box<dyn PirTransport> =
            Box::new(WasmWebSocketTransport::connect(&self.server_url).await?);

        self.conn = Some(conn);
        if let Some(rec) = self.metrics_recorder.clone() {
            if let Some(conn) = &mut self.conn {
                conn.set_metrics_recorder(Some(rec), "oram");
            }
        }
        self.fire_connect();
        Ok(())
    }

    /// Close the transport and clear cached catalog state.
    pub async fn disconnect(&mut self) -> PirResult<()> {
        if let Some(conn) = &mut self.conn {
            let _ = conn.close().await;
        }
        self.conn = None;
        self.catalog = None;
        self.fire_disconnect();
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.conn.is_some()
    }

    /// Fetch and cache the server catalog. This may be called before or after
    /// encrypted-channel upgrade; it does not reveal a queried scripthash.
    pub async fn fetch_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        let request = encode_request(REQ_GET_DB_CATALOG, &[]);
        let response = self.conn_mut()?.roundtrip(&request).await?;
        if response.is_empty() {
            return Err(PirError::Protocol("empty catalog response".into()));
        }
        match response[0] {
            RESP_DB_CATALOG => {
                let catalog = decode_catalog(&response[1..])?;
                self.catalog = Some(catalog.clone());
                Ok(catalog)
            }
            RESP_ERROR => Err(decode_error_response(&response)),
            other => Err(PirError::UnexpectedResponse {
                expected: "RESP_DB_CATALOG (0x02)",
                actual: format!("0x{:02x}", other),
            }),
        }
    }

    pub fn cached_catalog(&self) -> Option<&DatabaseCatalog> {
        self.catalog.as_ref()
    }

    /// Run REQ_ATTEST on the current connection.
    pub async fn attest(
        &mut self,
        nonce: [u8; 32],
    ) -> PirResult<crate::attest::AttestVerification> {
        crate::attest::attest(self.conn_mut()?.as_mut(), nonce).await
    }

    /// Run REQ_ATTEST with the nonce bound to the handshake ephemeral pubkey.
    pub async fn attest_with_eph_binding(
        &mut self,
        eph_seed: [u8; 32],
        random_32: [u8; 32],
    ) -> PirResult<crate::attest::AttestVerification> {
        crate::attest::attest_with_eph_binding(self.conn_mut()?.as_mut(), eph_seed, random_32)
            .await
    }

    /// Upgrade the existing connection to the encrypted channel.
    ///
    /// The `server_static_pub` must come from a verified attestation or
    /// operator-signed announcement. This overload mints fresh handshake
    /// material internally; use [`Self::upgrade_to_secure_channel_with_seeds`]
    /// when binding the same ephemeral public key into an attestation nonce.
    pub async fn upgrade_to_secure_channel(
        &mut self,
        server_static_pub: [u8; 32],
    ) -> PirResult<()> {
        let mut eph_seed = [0u8; 32];
        let mut hs_nonce = [0u8; 32];
        getrandom::getrandom(&mut eph_seed)
            .map_err(|e| PirError::Protocol(format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut hs_nonce)
            .map_err(|e| PirError::Protocol(format!("getrandom: {}", e)))?;
        self.upgrade_to_secure_channel_with_seeds(server_static_pub, eph_seed, hs_nonce)
            .await
    }

    /// Upgrade with caller-supplied handshake seed and HKDF salt.
    pub async fn upgrade_to_secure_channel_with_seeds(
        &mut self,
        server_static_pub: [u8; 32],
        eph_seed: [u8; 32],
        hs_nonce: [u8; 32],
    ) -> PirResult<()> {
        let raw = self
            .conn
            .take()
            .ok_or_else(|| PirError::Protocol("upgrade: ORAM server not connected".into()))?;
        let wrapped = crate::channel::establish(raw, server_static_pub, eph_seed, hs_nonce).await?;
        self.conn = Some(Box::new(wrapped));
        if let Some(rec) = self.metrics_recorder.clone() {
            if let Some(conn) = &mut self.conn {
                conn.set_metrics_recorder(Some(rec), "oram");
            }
        }
        Ok(())
    }

    /// Send one raw ORAM lookup request and return the decoded response.
    ///
    /// This request leaks `script_hashes.len()` by design. Callers that need a
    /// fixed batch shape should pad the input at their layer.
    pub async fn lookup_raw(
        &mut self,
        script_hashes: &[ScriptHash],
        db_id: u8,
    ) -> PirResult<OramLookupResult> {
        let request = encode_oram_lookup_request(db_id, script_hashes)?;
        let response = self.conn_mut()?.roundtrip(&request).await?;
        let result = decode_oram_lookup_response(&response)?;
        if result.db_id != db_id {
            return Err(PirError::Decode(format!(
                "ORAM response db_id {} does not match request db_id {}",
                result.db_id, db_id
            )));
        }
        Ok(result)
    }

    /// Query a database and decode found results into SDK `QueryResult`s.
    pub async fn query_batch(
        &mut self,
        script_hashes: &[ScriptHash],
        db_id: u8,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        let started_at = self.fire_query_start(db_id, script_hashes.len());
        let raw = self.lookup_raw(script_hashes, db_id).await;
        let success = raw.is_ok();
        self.fire_query_end(db_id, script_hashes.len(), success, started_at);
        let raw = raw?;
        if raw.items.len() != script_hashes.len() {
            return Err(PirError::Decode(format!(
                "ORAM response item count {} does not match request count {}",
                raw.items.len(),
                script_hashes.len()
            )));
        }
        raw.items
            .into_iter()
            .map(lookup_item_to_query_result)
            .collect()
    }

    fn conn_mut(&mut self) -> PirResult<&mut Box<dyn PirTransport>> {
        self.conn.as_mut().ok_or(PirError::NotConnected)
    }

    fn fire_connect(&self) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_connect("oram", &self.server_url);
        }
    }

    fn fire_disconnect(&self) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_disconnect("oram");
        }
    }

    fn fire_query_start(&self, db_id: u8, num_queries: usize) -> Option<pir_sdk::Instant> {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_query_start("oram", db_id, num_queries);
            Some(pir_sdk::Instant::now())
        } else {
            None
        }
    }

    fn fire_query_end(
        &self,
        db_id: u8,
        num_queries: usize,
        success: bool,
        started_at: Option<pir_sdk::Instant>,
    ) {
        if let Some(rec) = &self.metrics_recorder {
            let duration = started_at.map(|t| t.elapsed()).unwrap_or_default();
            rec.on_query_end("oram", db_id, num_queries, success, duration);
        }
    }
}

fn encode_oram_lookup_request(db_id: u8, script_hashes: &[ScriptHash]) -> PirResult<Vec<u8>> {
    if script_hashes.len() > MAX_ORAM_LOOKUP_SCRIPTHASHES {
        return Err(PirError::Protocol(format!(
            "ORAM lookup batch size {} exceeds maximum {}",
            script_hashes.len(),
            MAX_ORAM_LOOKUP_SCRIPTHASHES
        )));
    }
    let mut payload = Vec::with_capacity(3 + script_hashes.len() * SCRIPT_HASH_SIZE);
    payload.push(db_id);
    payload.extend_from_slice(&(script_hashes.len() as u16).to_le_bytes());
    for sh in script_hashes {
        payload.extend_from_slice(sh);
    }
    Ok(encode_request(REQ_ORAM_LOOKUP, &payload))
}

fn decode_oram_lookup_response(response: &[u8]) -> PirResult<OramLookupResult> {
    if response.is_empty() {
        return Err(PirError::Protocol("empty ORAM lookup response".into()));
    }
    match response[0] {
        RESP_ORAM_LOOKUP => decode_oram_lookup_result(&response[1..]),
        RESP_ERROR => Err(decode_error_response(response)),
        other => Err(PirError::UnexpectedResponse {
            expected: "RESP_ORAM_LOOKUP (0x60)",
            actual: format!("0x{:02x}", other),
        }),
    }
}

fn decode_oram_lookup_result(data: &[u8]) -> PirResult<OramLookupResult> {
    if data.len() < 3 {
        return Err(PirError::Decode("ORAM lookup result too short".into()));
    }
    let db_id = data[0];
    let count = u16::from_le_bytes(data[1..3].try_into().unwrap()) as usize;
    let mut pos = 3;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 10 > data.len() {
            return Err(PirError::Decode("truncated ORAM lookup item".into()));
        }
        let flags = data[pos];
        pos += 1;
        let start_chunk_id = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let num_chunks = data[pos];
        pos += 1;
        let data_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + data_len > data.len() {
            return Err(PirError::Decode("truncated ORAM lookup chunk data".into()));
        }
        items.push(OramLookupItem {
            found: flags & 0x01 != 0,
            whale: flags & 0x02 != 0,
            start_chunk_id,
            num_chunks,
            raw_chunk_data: data[pos..pos + data_len].to_vec(),
        });
        pos += data_len;
    }
    Ok(OramLookupResult { db_id, items })
}

fn lookup_item_to_query_result(item: OramLookupItem) -> PirResult<Option<QueryResult>> {
    if !item.found {
        return Ok(None);
    }
    if item.whale {
        let mut qr = QueryResult::empty();
        qr.is_whale = true;
        return Ok(Some(qr));
    }
    let entries = decode_utxo_entries(&item.raw_chunk_data)?;
    let mut qr = QueryResult::with_entries(entries);
    qr.raw_chunk_data = Some(item.raw_chunk_data);
    Ok(Some(qr))
}

fn decode_utxo_entries(data: &[u8]) -> PirResult<Vec<UtxoEntry>> {
    let mut entries = Vec::new();
    if data.is_empty() {
        return Ok(entries);
    }
    let (count, mut pos) = pir_core::codec::try_read_varint(data)
        .map_err(|e| PirError::Decode(format!("UTXO count varint: {}", e)))?;
    for _ in 0..count {
        if pos + 32 > data.len() {
            break;
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        if pos >= data.len() {
            break;
        }
        let (vout, vr) = pir_core::codec::try_read_varint(&data[pos..])
            .map_err(|e| PirError::Decode(format!("UTXO vout varint: {}", e)))?;
        pos += vr;
        if pos >= data.len() {
            break;
        }
        let (amount, ar) = pir_core::codec::try_read_varint(&data[pos..])
            .map_err(|e| PirError::Decode(format!("UTXO amount varint: {}", e)))?;
        pos += ar;
        entries.push(UtxoEntry {
            txid,
            vout: vout as u32,
            amount_sats: amount,
        });
    }
    Ok(entries)
}

fn decode_error_response(response: &[u8]) -> PirError {
    if response.len() >= 5 {
        let len = u32::from_le_bytes(response[1..5].try_into().unwrap()) as usize;
        if 5 + len <= response.len() {
            return PirError::ServerError(
                String::from_utf8_lossy(&response[5..5 + len]).to_string(),
            );
        }
        return PirError::ServerError("<truncated error message>".into());
    }
    PirError::ServerError(String::from_utf8_lossy(&response[1..]).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn encode_test_response(db_id: u8, items: &[OramLookupItem]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(RESP_ORAM_LOOKUP);
        payload.push(db_id);
        payload.extend_from_slice(&(items.len() as u16).to_le_bytes());
        for item in items {
            let mut flags = 0u8;
            if item.found {
                flags |= 0x01;
            }
            if item.whale {
                flags |= 0x02;
            }
            payload.push(flags);
            payload.extend_from_slice(&item.start_chunk_id.to_le_bytes());
            payload.push(item.num_chunks);
            payload.extend_from_slice(&(item.raw_chunk_data.len() as u32).to_le_bytes());
            payload.extend_from_slice(&item.raw_chunk_data);
        }
        framed(&payload)
    }

    #[tokio::test]
    async fn lookup_raw_sends_expected_frame_and_decodes_response() {
        let script_hash = [7u8; SCRIPT_HASH_SIZE];
        let item = OramLookupItem {
            found: true,
            whale: false,
            start_chunk_id: 42,
            num_chunks: 1,
            raw_chunk_data: vec![1, 2, 3],
        };
        let mut mock = MockTransport::new("mock://oram");
        mock.enqueue_response(encode_test_response(3, &[item.clone()]));

        let mut client = OramClient::new("mock://oram");
        client.connect_with_transport(Box::new(mock));
        let result = client.lookup_raw(&[script_hash], 3).await.unwrap();

        assert_eq!(
            result,
            OramLookupResult {
                db_id: 3,
                items: vec![item]
            }
        );
    }

    #[test]
    fn encode_lookup_request_matches_wire_format() {
        let a = [1u8; SCRIPT_HASH_SIZE];
        let b = [2u8; SCRIPT_HASH_SIZE];
        let encoded = encode_oram_lookup_request(4, &[a, b]).unwrap();

        assert_eq!(&encoded[..4], &(44u32).to_le_bytes());
        assert_eq!(encoded[4], REQ_ORAM_LOOKUP);
        assert_eq!(encoded[5], 4);
        assert_eq!(&encoded[6..8], &(2u16).to_le_bytes());
        assert_eq!(&encoded[8..28], &a);
        assert_eq!(&encoded[28..48], &b);
    }

    #[tokio::test]
    async fn query_batch_decodes_utxos_and_preserves_raw_chunk_data() {
        let script_hash = [9u8; SCRIPT_HASH_SIZE];
        let raw = pir_core::codec::serialize_utxo_data(&[pir_core::codec::UtxoEntry {
            txid: [0xab; 32],
            vout: 2,
            amount: 50_000,
        }]);
        let item = OramLookupItem {
            found: true,
            whale: false,
            start_chunk_id: 11,
            num_chunks: 1,
            raw_chunk_data: raw.clone(),
        };
        let mut mock = MockTransport::new("mock://oram");
        mock.enqueue_response(encode_test_response(0, &[item]));

        let mut client = OramClient::new("mock://oram");
        client.connect_with_transport(Box::new(mock));
        let results = client.query_batch(&[script_hash], 0).await.unwrap();

        let qr = results[0].as_ref().unwrap();
        assert_eq!(qr.entries.len(), 1);
        assert_eq!(qr.entries[0].txid, [0xab; 32]);
        assert_eq!(qr.entries[0].vout, 2);
        assert_eq!(qr.entries[0].amount_sats, 50_000);
        assert_eq!(qr.raw_chunk_data.as_ref(), Some(&raw));
    }

    #[tokio::test]
    async fn lookup_raw_rejects_oversized_batch_before_send() {
        let mut client = OramClient::new("mock://oram");
        client.connect_with_transport(Box::new(MockTransport::new("mock://oram")));
        let script_hashes = vec![[0u8; SCRIPT_HASH_SIZE]; MAX_ORAM_LOOKUP_SCRIPTHASHES + 1];

        match client.lookup_raw(&script_hashes, 0).await {
            Err(PirError::Protocol(msg)) => assert!(msg.contains("exceeds maximum")),
            other => panic!("expected oversized batch protocol error, got {:?}", other),
        }
    }

    #[test]
    fn decode_error_response_accepts_length_prefixed_envelope() {
        let mut response = vec![RESP_ERROR];
        response.extend_from_slice(&4u32.to_le_bytes());
        response.extend_from_slice(b"nope");
        match decode_error_response(&response) {
            PirError::ServerError(msg) => assert_eq!(msg, "nope"),
            other => panic!("expected ServerError, got {:?}", other),
        }
    }
}
