//! Server configuration types.

use pir_sdk::{DatabaseKind, ServerRole};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Configuration for a single database (full checkpoint or delta).
#[derive(Deserialize, Clone, Debug)]
pub struct DatabaseEntry {
    /// Human-readable name (e.g. "main", "delta_940611_944000").
    pub name: String,
    /// "full" for a complete UTXO snapshot, "delta" for a diff between heights.
    #[serde(rename = "type")]
    pub db_type: String,
    /// Path to the database directory.
    pub path: PathBuf,
    /// Optional attested-builder proof directory for this database.
    #[serde(default)]
    pub proof_dir: Option<PathBuf>,
    /// Starting height (0 for full snapshots, start height for deltas).
    #[serde(default)]
    pub base_height: u32,
    /// Snapshot height (full) or end height (delta).
    pub height: u32,
}

impl DatabaseEntry {
    /// Create a new full snapshot entry.
    pub fn full(name: impl Into<String>, path: impl Into<PathBuf>, height: u32) -> Self {
        Self {
            name: name.into(),
            db_type: "full".into(),
            path: path.into(),
            proof_dir: None,
            base_height: 0,
            height,
        }
    }

    /// Create a new delta entry.
    pub fn delta(
        name: impl Into<String>,
        path: impl Into<PathBuf>,
        base_height: u32,
        tip_height: u32,
    ) -> Self {
        Self {
            name: name.into(),
            db_type: "delta".into(),
            path: path.into(),
            proof_dir: None,
            base_height,
            height: tip_height,
        }
    }

    /// Returns the database kind.
    pub fn kind(&self) -> DatabaseKind {
        if self.db_type == "delta" {
            DatabaseKind::Delta {
                base_height: self.base_height,
            }
        } else {
            DatabaseKind::Full
        }
    }

    /// Returns true if this is a delta database.
    pub fn is_delta(&self) -> bool {
        self.db_type == "delta"
    }
}

/// Top-level server configuration.
#[derive(Deserialize, Clone, Debug)]
pub struct ServerConfig {
    /// Server role.
    #[serde(default)]
    pub role: ServerRoleConfig,
    /// Port to listen on.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Database entries.
    #[serde(rename = "database", default)]
    pub databases: Vec<DatabaseEntry>,
    /// Whether to enable DPF backend.
    #[serde(default = "default_true")]
    pub enable_dpf: bool,
    /// Whether to enable HarmonyPIR backend.
    #[serde(default = "default_true")]
    pub enable_harmony: bool,
    /// Whether to enable OnionPIR backend.
    #[serde(default = "default_true")]
    pub enable_onion: bool,
    /// Maximum simultaneously open TCP/WebSocket connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Maximum CPU-heavy PIR requests evaluated at once across all clients.
    #[serde(default = "default_max_in_flight_requests")]
    pub max_in_flight_requests: usize,
    /// Deadline for completing the WebSocket handshake.
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    /// Close a connection that sends no message within this interval.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            role: ServerRoleConfig::default(),
            port: default_port(),
            databases: Vec::new(),
            enable_dpf: true,
            enable_harmony: true,
            enable_onion: true,
            max_connections: default_max_connections(),
            max_in_flight_requests: default_max_in_flight_requests(),
            handshake_timeout_secs: default_handshake_timeout_secs(),
            idle_timeout_secs: default_idle_timeout_secs(),
        }
    }
}

fn default_port() -> u16 {
    8091
}

fn default_true() -> bool {
    true
}

fn default_max_connections() -> usize {
    128
}

fn default_max_in_flight_requests() -> usize {
    8
}

fn default_handshake_timeout_secs() -> u64 {
    10
}

fn default_idle_timeout_secs() -> u64 {
    120
}

/// Server role configuration (for TOML parsing).
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum ServerRoleConfig {
    #[default]
    Primary,
    Secondary,
    Standalone,
}

impl From<ServerRoleConfig> for ServerRole {
    fn from(r: ServerRoleConfig) -> Self {
        match r {
            ServerRoleConfig::Primary => ServerRole::Primary,
            ServerRoleConfig::Secondary => ServerRole::Secondary,
            ServerRoleConfig::Standalone => ServerRole::Standalone,
        }
    }
}

impl ServerConfig {
    /// Create a new empty configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(path.display().to_string(), e))?;

        let mut config: ServerConfig = toml::from_str(&contents)
            .map_err(|e| ConfigError::ParseError(path.display().to_string(), e.to_string()))?;

        // Resolve relative paths against the config file's parent directory
        let base_dir = path.parent().unwrap_or(Path::new("."));
        for db in &mut config.databases {
            if db.path.is_relative() {
                db.path = base_dir.join(&db.path);
            }
            if let Some(proof_dir) = db.proof_dir.as_mut() {
                if proof_dir.is_relative() {
                    *proof_dir = base_dir.join(&proof_dir);
                }
            }
        }

        config.validate()?;

        Ok(config)
    }

    /// Reject settings that would disable overload protection or make Tokio's
    /// semaphores panic when the server starts.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_connections == 0 {
            return Err(ConfigError::Invalid(
                "max_connections must be at least 1".into(),
            ));
        }
        if self.max_connections > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(ConfigError::Invalid(format!(
                "max_connections must not exceed {}",
                tokio::sync::Semaphore::MAX_PERMITS
            )));
        }
        if self.max_in_flight_requests == 0 {
            return Err(ConfigError::Invalid(
                "max_in_flight_requests must be at least 1".into(),
            ));
        }
        if self.max_in_flight_requests > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(ConfigError::Invalid(format!(
                "max_in_flight_requests must not exceed {}",
                tokio::sync::Semaphore::MAX_PERMITS
            )));
        }
        if self.handshake_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "handshake_timeout_secs must be at least 1".into(),
            ));
        }
        if self.idle_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "idle_timeout_secs must be at least 1".into(),
            ));
        }
        Ok(())
    }

    /// Add a full snapshot database.
    pub fn add_full_db(&mut self, path: impl Into<PathBuf>, height: u32) -> &mut Self {
        let path = path.into();
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("full_{}", height));
        self.databases.push(DatabaseEntry::full(name, path, height));
        self
    }

    /// Add a delta database.
    pub fn add_delta_db(
        &mut self,
        path: impl Into<PathBuf>,
        base_height: u32,
        tip_height: u32,
    ) -> &mut Self {
        let path = path.into();
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("delta_{}_{}", base_height, tip_height));
        self.databases
            .push(DatabaseEntry::delta(name, path, base_height, tip_height));
        self
    }

    /// Set the server role.
    pub fn role(&mut self, role: ServerRole) -> &mut Self {
        self.role = match role {
            ServerRole::Primary => ServerRoleConfig::Primary,
            ServerRole::Secondary => ServerRoleConfig::Secondary,
            ServerRole::Standalone => ServerRoleConfig::Standalone,
        };
        self
    }

    /// Set the port.
    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {0}: {1}")]
    IoError(String, std::io::Error),
    #[error("failed to parse config file {0}: {1}")]
    ParseError(String, String),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bpir-sdk-server-config-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn load_resolves_relative_database_and_proof_paths_against_config_dir() {
        let dir = temp_dir();
        let config_path = dir.join("databases.toml");
        std::fs::write(
            &config_path,
            r#"
[[database]]
name = "delta_940611_948454"
type = "delta"
path = "deltas/940611_948454_canonical_20260615"
proof_dir = "attestations/delta_940611_948454_sev_snp"
base_height = 940611
height = 948454
"#,
        )
        .unwrap();

        let config = ServerConfig::load(&config_path).unwrap();
        let db = &config.databases[0];

        assert_eq!(db.path, dir.join("deltas/940611_948454_canonical_20260615"));
        assert_eq!(
            db.proof_dir.as_ref().unwrap(),
            &dir.join("attestations/delta_940611_948454_sev_snp")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn safe_limits_are_enabled_by_default() {
        let config = ServerConfig::new();
        assert_eq!(config.max_connections, 128);
        assert_eq!(config.max_in_flight_requests, 8);
        assert_eq!(config.handshake_timeout_secs, 10);
        assert_eq!(config.idle_timeout_secs, 120);
        config.validate().unwrap();
    }

    #[test]
    fn invalid_limits_are_rejected() {
        let mut config = ServerConfig::new();
        config.max_connections = 0;
        assert!(config.validate().is_err());

        config.max_connections = tokio::sync::Semaphore::MAX_PERMITS + 1;
        assert!(config.validate().is_err());

        config.max_connections = 1;
        config.max_in_flight_requests = 0;
        assert!(config.validate().is_err());

        config.max_in_flight_requests = tokio::sync::Semaphore::MAX_PERMITS + 1;
        assert!(config.validate().is_err());
    }
}
