//! Browser entry points of the Nostr service directory
//! (`docs/DIRECTORY_PROTOCOL.md`).
//!
//! JavaScript fetches the catalog: it sends the 16 shard `REQ`s from
//! [`directory_catalog_requests_v1`] to every configured relay and passes the
//! raw `EVENT` messages of each relay that reached `EOSE` on all of them to
//! [`verify_directory_catalog_v1`], together with the stored rollback floors.
//! The verification itself is `pir_directory_nostr::verify_directory_catalog_views_v1`,
//! shared with the native SDK; this module only carries JSON across the
//! boundary.

use pir_directory_nostr::{
    full_catalog_req_json_v1, verify_directory_catalog_views_v1, DirectoryRollbackFloorsV1,
};
use wasm_bindgen::prelude::*;

/// The 16 NIP-01 `REQ` messages of a full catalog refresh, byte-exact as the
/// directory relay profile expects them (`authors`, `kinds`, `#s`).
#[wasm_bindgen(js_name = directoryCatalogRequestsV1)]
pub fn directory_catalog_requests_v1(directory_pubkey: &[u8]) -> Result<Vec<String>, JsError> {
    catalog_requests(directory_pubkey).map_err(|error| JsError::new(&error))
}

/// Verify complete relay views of the catalog. `relays_json` is one JSON
/// array of raw `EVENT` message strings per relay; `state_json` the floors a
/// previous call returned (absent on first use). Returns the catalog JSON:
/// `{ validUntil, shards, entries, rejected, state }`.
#[wasm_bindgen(js_name = verifyDirectoryCatalogV1)]
pub fn verify_directory_catalog_v1(
    relays_json: &str,
    state_json: Option<String>,
    directory_pubkey: &[u8],
    now_unix: u64,
) -> Result<String, JsError> {
    verify_catalog_json(
        relays_json,
        state_json.as_deref(),
        directory_pubkey,
        now_unix,
    )
    .map_err(|error| JsError::new(&error))
}

fn catalog_requests(directory_pubkey: &[u8]) -> Result<Vec<String>, String> {
    full_catalog_req_json_v1(&directory_key(directory_pubkey)?)
        .map_err(reason)?
        .into_iter()
        .map(|request| String::from_utf8(request).map_err(reason))
        .collect()
}

fn verify_catalog_json(
    relays_json: &str,
    state_json: Option<&str>,
    directory_pubkey: &[u8],
    now_unix: u64,
) -> Result<String, String> {
    let key = directory_key(directory_pubkey)?;
    let relays: Vec<Vec<String>> = serde_json::from_str(relays_json)
        .map_err(|_| "relay views must be arrays of EVENT message strings".to_owned())?;
    let floors = match state_json {
        Some(json) => serde_json::from_str(json)
            .map_err(|_| "stored directory rollback floors are malformed".to_owned())?,
        None => DirectoryRollbackFloorsV1::default(),
    };
    serde_json::to_string(&verify_directory_catalog_views_v1(
        &relays, floors, &key, now_unix,
    ))
    .map_err(reason)
}

fn directory_key(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "directory public key must be 32 bytes".to_owned())
}

fn reason(error: impl core::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests;
