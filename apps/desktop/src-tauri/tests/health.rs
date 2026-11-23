use bpir_desktop_lib::health::probe;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn probe_reads_get_info_json_from_a_loopback_peer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let request = socket.next().await.unwrap().unwrap();
        let Message::Binary(request) = request else {
            panic!("expected a binary request");
        };
        assert_eq!(request, vec![1, 0, 0, 0, 0x03]);
        let json = br#"{"role":"primary"}"#;
        let mut response = ((json.len() + 1) as u32).to_le_bytes().to_vec();
        response.push(0x03);
        response.extend_from_slice(json);
        socket.send(Message::Binary(response.into())).await.unwrap();
        let _ = socket.close(None).await;
    });

    let report = probe(format!("ws://{address}")).await.unwrap();
    assert_eq!(report.info["role"], "primary");
    server.await.unwrap();
}
