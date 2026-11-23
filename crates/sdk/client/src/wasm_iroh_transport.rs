//! Browser Iroh transport using the public N0 relay preset.
//!
//! Each DPF session shares one endpoint, while each server leg owns an
//! independent connection and an inner WebSocket byte stream.

#![cfg(target_arch = "wasm32")]

use crate::{transport_over_iroh, PirTransport, IROH_WS_ALPN};
use async_trait::async_trait;
use iroh::{
    endpoint::{presets, Connection, VarInt},
    Endpoint, EndpointAddr,
};
use iroh_tickets::endpoint::EndpointTicket;
use pir_sdk::{PirError, PirMetrics, PirResult};
use std::sync::Arc;

pub struct WasmIrohTransport {
    inner: Box<dyn PirTransport>,
    // Keep the shared endpoint alive until both legs have been dropped.
    _endpoint: Endpoint,
    connection: Connection,
    closed: bool,
}

impl WasmIrohTransport {
    /// Connect a DPF pair through the public N0 relay/discovery preset.
    pub async fn connect_pair(ticket0: &str, ticket1: &str) -> PirResult<(Self, Self)> {
        let addr0 = parse_ticket(ticket0, "server0")?;
        let addr1 = parse_ticket(ticket1, "server1")?;
        let endpoint = Endpoint::bind(presets::N0)
            .await
            .map_err(|e| PirError::ConnectionFailed(format!("Iroh endpoint bind: {e}")))?;

        let result = async {
            let transport0 =
                Self::connect_with_endpoint(endpoint.clone(), addr0, "server0").await?;
            let transport1 =
                Self::connect_with_endpoint(endpoint.clone(), addr1, "server1").await?;
            Ok((transport0, transport1))
        }
        .await;
        if result.is_err() {
            endpoint.close().await;
        }
        result
    }

    async fn connect_with_endpoint(
        endpoint: Endpoint,
        addr: EndpointAddr,
        peer: &'static str,
    ) -> PirResult<Self> {
        let connection = endpoint
            .connect(addr, IROH_WS_ALPN)
            .await
            .map_err(|e| PirError::ConnectionFailed(format!("Iroh connect to {peer}: {e}")))?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| PirError::ConnectionFailed(format!("Iroh open_bi for {peer}: {e}")))?;
        let inner = transport_over_iroh(peer, recv, send).await?;
        Ok(Self {
            inner: Box::new(inner),
            _endpoint: endpoint,
            connection,
            closed: false,
        })
    }

    fn check_open(&self) -> PirResult<()> {
        if self.closed {
            Err(PirError::ConnectionClosed(self.inner.url().to_string()))
        } else {
            Ok(())
        }
    }
}

fn parse_ticket(input: &str, peer: &str) -> PirResult<EndpointAddr> {
    let ticket = input
        .trim()
        .parse::<EndpointTicket>()
        .map_err(|e| PirError::ConnectionFailed(format!("Invalid Iroh ticket for {peer}: {e}")))?;
    Ok(ticket.endpoint_addr().clone())
}

#[async_trait]
impl PirTransport for WasmIrohTransport {
    async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
        self.check_open()?;
        self.inner.send(data).await
    }

    async fn recv(&mut self) -> PirResult<Vec<u8>> {
        self.check_open()?;
        self.inner.recv().await
    }

    async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
        self.check_open()?;
        self.inner.roundtrip(request).await
    }

    async fn close(&mut self) -> PirResult<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let result = self.inner.close().await;
        self.connection.close(VarInt::from_u32(0), b"");
        result
    }

    fn url(&self) -> &str {
        self.inner.url()
    }

    fn set_metrics_recorder(
        &mut self,
        recorder: Option<Arc<dyn PirMetrics>>,
        backend: &'static str,
    ) {
        self.inner.set_metrics_recorder(recorder, backend);
    }
}

impl Drop for WasmIrohTransport {
    fn drop(&mut self) {
        self.connection.close(VarInt::from_u32(0), b"");
    }
}
