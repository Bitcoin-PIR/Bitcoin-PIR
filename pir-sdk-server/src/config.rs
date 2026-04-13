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
    /// Starting height (0 for full snapshots, start height for deltas).
    #[serde(default)]
    pub base_height: u32,
    /// Snapshot height (full) or end height (delta).
    pub height: u32,
    /// Warmup priority: lower = higher priority.
    #[serde(default = "default_priority")]
    pub priority: u32,
}

fn default_priority() -> u32 {
    5
}

impl DatabaseEntry {
    /// Create a new full snapshot entry.
    pub fn full(name: impl Into<String>, path: impl Into<PathBuf>, height: u32) -> Self {
        Self {
            name: name.into(),
            db_type: "full".into(),
            path: path.into(),
            base_height: 0,
            height,
            priority: default_priority(),
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
            base_height,
            height: tip_height,
            priority: default_priority(),
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
#[derive(Deserialize, Clone, Debug, Default)]
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
    /// Whether to perform warmup.
    #[serde(default)]
    pub warmup: bool,
}

fn default_port() -> u16 {
    8091
}

fn default_true() -> bool {
    true
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
        }

        Ok(config)
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

    /// Enable or disable warmup.
    pub fn warmup(&mut self, enable: bool) -> &mut Self {
        self.warmup = enable;
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
