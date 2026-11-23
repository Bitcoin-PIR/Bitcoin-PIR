use pir_sdk_client::WsConnection;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Clone, Debug)]
pub struct HealthReport {
    pub endpoint: String,
    pub checked_at_unix: u64,
    pub info: serde_json::Value,
}

pub async fn probe(endpoint: String) -> Result<HealthReport, String> {
    let mut connection = WsConnection::connect_once(&endpoint)
        .await
        .map_err(|error| error.to_string())?;
    let response = connection
        .roundtrip(&[1, 0, 0, 0, 0x03])
        .await
        .map_err(|error| error.to_string())?;
    let _ = connection.close().await;
    if response.first() != Some(&0x03) {
        return Err("Expected a 0x03 GET_INFO_JSON response".to_owned());
    }
    let info = serde_json::from_slice(&response[1..])
        .map_err(|error| format!("Invalid GET_INFO_JSON payload: {error}"))?;
    let checked_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    Ok(HealthReport {
        endpoint,
        checked_at_unix,
        info,
    })
}
