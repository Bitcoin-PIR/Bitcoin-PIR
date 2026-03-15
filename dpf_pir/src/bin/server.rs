//! DPF-PIR WebSocket Server
//! 
//! A WebSocket-based PIR server for browser clients.
//! Supports multiple queries over a single WebSocket connection.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --bin server_ws -- --port 8091
//! ```
//!
//! The server accepts WebSocket connections and processes PIR queries
//! using the same binary protocol as the TCP server.

use dpf_pir::load_configuration;
use dpf_pir::websocket::{DataStore, DataStoreManager};
use log::{error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

#[tokio::main]
async fn main() {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let mut port = 8091; // Default WebSocket port
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse::<u16>().unwrap_or(8091);
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("DPF-PIR WebSocket Server");
                println!("Usage: {} [OPTIONS]", args[0]);
                println!();
                println!("Options:");
                println!("  --port, -p <PORT>  Port to listen on (default: 8091)");
                println!("  --help, -h         Show this help message");
                println!();
                println!("This server accepts WebSocket connections from browser clients.");
                println!("The protocol uses binary messages with bincode serialization.");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    // Load configuration (databases are registered in server_config.rs)
    let server_config = load_configuration();

    info!("Starting DPF-PIR WebSocket server on port {}", port);
    info!("Load to memory: {}", server_config.load_to_memory);

    // Create data store manager
    let mut store_manager = DataStoreManager::new();

    // Initialize data stores for each registered database
    for db_id in server_config.registry.list() {
        if let Some(db) = server_config.registry.get(db_id) {
            info!("Initializing data store for database '{}':", db_id);
            info!("  Path: {}", db.data_path());
            info!("  Buckets: {}", db.num_buckets());
            info!("  Entry size: {} bytes", db.entry_size());
            info!("  Bucket size: {} entries", db.bucket_size());

            let store = DataStore::new(
                db.data_path(),
                db.num_buckets(),
                db.entry_size(),
                db.bucket_size(),
                server_config.load_to_memory,
            ).unwrap_or_else(|e| {
                error!("Failed to create data store for '{}': {}", db_id, e);
                std::process::exit(1);
            });

            store_manager.add(db_id.to_string(), store);
        }
    }

    info!("Registered {} database(s)", server_config.registry.len());

    // Check if any databases are registered
    if server_config.registry.is_empty() {
        error!("No databases registered. Edit dpf_pir/src/server_config.rs to add databases.");
        std::process::exit(1);
    }

    // Bind to the port
    let addr: SocketAddr = format!("0.0.0.0:{}", port)
        .parse()
        .expect("Invalid address");

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    info!("WebSocket server listening on ws://{}", addr);
    info!("Connect from browser using: ws://localhost:{}", port);

    // Wrap in Arc for sharing across tasks
    let store_manager = Arc::new(store_manager);
    let registry = Arc::new(server_config.registry);

    // Accept connections loop
    loop {
        info!("[SERVER] Waiting for incoming connection...");
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => {
                info!("[SERVER] Step 1: Connection accepted from {}", conn.1);
                conn
            },
            Err(e) => {
                error!("[SERVER] Failed to accept connection: {}", e);
                continue;
            }
        };

        info!("[SERVER] Step 2: Spawning task to handle connection from {}", peer_addr);
        let store_manager = Arc::clone(&store_manager);
        let registry = Arc::clone(&registry);
        
        tokio::spawn(async move {
            info!("[SERVER] Step 3: Starting WebSocket handshake for {}", peer_addr);
            // Use accept_hdr_async to handle CORS and allow connections from any origin
            let callback = |req: &Request, mut response: Response| {
                let origin = req.headers().get("origin").map(|v| v.to_str().unwrap_or("*")).unwrap_or("*");
                info!("[SERVER] Step 4: WebSocket handshake request from origin: {}", origin);
                info!("[SERVER] Request headers: {:?}", req.headers());
                
                // Add CORS headers to the response
                let headers = response.headers_mut();
                headers.insert(
                    tokio_tungstenite::tungstenite::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                    tokio_tungstenite::tungstenite::http::HeaderValue::from_static("*"),
                );
                headers.insert(
                    tokio_tungstenite::tungstenite::http::header::ACCESS_CONTROL_ALLOW_METHODS,
                    tokio_tungstenite::tungstenite::http::HeaderValue::from_static("GET, POST, OPTIONS"),
                );
                headers.insert(
                    tokio_tungstenite::tungstenite::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
                    tokio_tungstenite::tungstenite::http::HeaderValue::from_static("Content-Type, Authorization"),
                );
                info!("[SERVER] Step 5: CORS headers added to response");
                Ok(response)
            };
            
            info!("[SERVER] Step 6: Calling accept_hdr_async to complete WebSocket handshake...");
            match accept_hdr_async(stream, callback).await {
                Ok(ws_stream) => {
                    info!("[SERVER] Step 7: WebSocket handshake SUCCESS for {}", peer_addr);
                    info!("[SERVER] Step 8: Starting WebSocket message handler for {}", peer_addr);
                    dpf_pir::websocket::handle_websocket_connection(
                        ws_stream, store_manager, registry
                    ).await;
                    info!("[SERVER] Step 9: WebSocket handler completed for {}", peer_addr);
                }
                Err(e) => {
                    error!("[SERVER] Step ERROR: WebSocket handshake FAILED for {}: {}", peer_addr, e);
                    error!("[SERVER] Error details: {:?}", e);
                }
            }
        });
    }
}