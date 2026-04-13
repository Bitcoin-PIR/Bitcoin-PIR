//! WebSocket connection utilities.

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use pir_sdk::{PirError, PirResult};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// A WebSocket connection to a PIR server.
pub struct WsConnection {
    sink: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    stream: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    url: String,
}

impl WsConnection {
    /// Connect to a WebSocket URL.
    pub async fn connect(url: &str) -> PirResult<Self> {
        let (ws, _) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| PirError::ConnectionFailed(format!("{}: {}", url, e)))?;

        let (sink, stream) = ws.split();

        Ok(Self {
            sink,
            stream,
            url: url.to_string(),
        })
    }

    /// Get the URL this connection is connected to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Send a binary message.
    pub async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
        self.sink
            .send(Message::Binary(data.into()))
            .await
            .map_err(|e| PirError::ConnectionClosed(format!("send: {}", e)))
    }

    /// Receive a binary message, handling ping/pong automatically.
    pub async fn recv(&mut self) -> PirResult<Vec<u8>> {
        loop {
            let msg = self
                .stream
                .next()
                .await
                .ok_or_else(|| PirError::ConnectionClosed("stream ended".into()))?
                .map_err(|e| PirError::ConnectionClosed(format!("recv: {}", e)))?;

            match msg {
                Message::Binary(b) => return Ok(b.into()),
                Message::Ping(p) => {
                    let _ = self.sink.send(Message::Pong(p)).await;
                }
                Message::Pong(_) => continue,
                Message::Close(_) => {
                    return Err(PirError::ConnectionClosed("server closed".into()))
                }
                Message::Text(_) => continue,
                Message::Frame(_) => continue,
            }
        }
    }

    /// Send a request and receive a response.
    ///
    /// The request is encoded as: [4B length LE][payload]
    /// The response is: [4B length LE][payload]
    pub async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
        // Send request (already includes length prefix from protocol encoding)
        self.send(request.to_vec()).await?;

        // Receive response
        let response = self.recv().await?;

        // Skip 4-byte length prefix
        if response.len() < 4 {
            return Err(PirError::Protocol("response too short".into()));
        }

        Ok(response[4..].to_vec())
    }

    /// Close the connection.
    pub async fn close(&mut self) -> PirResult<()> {
        let _ = self.sink.send(Message::Close(None)).await;
        Ok(())
    }
}
