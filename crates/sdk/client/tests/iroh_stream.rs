#![cfg(not(target_arch = "wasm32"))]

use futures_util::{SinkExt, StreamExt};
use pir_sdk_client::{transport_over_iroh, PirTransport};
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn stream_upgrade_and_coalesced_responses() {
    let (a, b) = tokio::io::duplex(1024);
    let server = tokio::spawn(async move {
        let mut ws = tokio_tungstenite::accept_async(b).await.unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap().into_data(),
            [1, 0, 0, 0, 42]
        );
        ws.send(Message::Binary(vec![1, 0, 0, 0, 6])).await.unwrap();
        ws.send(Message::Binary(vec![1, 0, 0, 0, 7, 1, 0, 0, 0, 8]))
            .await
            .unwrap();
    });
    let (recv, send) = tokio::io::split(a);
    let mut t = transport_over_iroh("test-peer", recv, send).await.unwrap();
    assert_eq!(t.roundtrip(&[1, 0, 0, 0, 42]).await.unwrap(), [6]);
    assert_eq!(t.recv().await.unwrap(), [1, 0, 0, 0, 7]);
    assert_eq!(t.recv().await.unwrap(), [1, 0, 0, 0, 8]);
    server.await.unwrap();
}
