//! PIR SDK Server: Load databases and serve PIR requests.
//!
//! This crate provides a clean API for building PIR servers:
//!
//! ```ignore
//! use pir_sdk_server::PirServerBuilder;
//!
//! // Simple: load from config file
//! PirServerBuilder::new()
//!     .from_config("databases.toml")?
//!     .port(8091)
//!     .build().await?
//!     .run().await?;
//!
//! // Advanced: programmatic configuration
//! PirServerBuilder::new()
//!     .add_full_db("/data/checkpoint/940611", 940611)
//!     .add_delta_db("/data/delta/940611_944000", 940611, 944000)
//!     .role(ServerRole::Primary)
//!     .warmup(true)
//!     .build().await?
//!     .run().await?;
//! ```

mod config;
mod loader;
mod server;

pub use config::{DatabaseEntry, ServerConfig};
pub use loader::DatabaseLoader;
pub use server::{PirServer, PirServerBuilder, ShutdownHandle};

// Re-export SDK types
pub use pir_sdk::{
    DatabaseCatalog, DatabaseInfo, DatabaseKind, PirBackend, PirBackendType, ServerRole,
};
