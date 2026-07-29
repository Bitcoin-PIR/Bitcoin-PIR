//! BitcoinPIR directory-profile relay.
//!
//! This is intentionally not a generic Nostr relay. It implements only the
//! bounded NIP-01 subset used to publish and snapshot BitcoinPIR's signed
//! service directory.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use pir_private_files::{read_private_file_bounded_v1, PrivateFileModeV1};
use serde::Deserialize;

pub mod server;
pub mod store;
pub mod wire;

#[derive(Clone, Debug, Parser)]
#[command(name = "bitcoinpir-directory-relay")]
#[command(about = "Minimal loopback-only BitcoinPIR directory-profile relay")]
#[command(version)]
pub struct Cli {
    /// Exact owner-only v1 TOML configuration. No CLI override path exists.
    #[arg(long)]
    pub config: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayFileConfig {
    profile: String,
    public_listen: SocketAddr,
    publisher_listen: SocketAddr,
    database: PathBuf,
    directory_pubkey_hex: String,
    max_connections: usize,
    max_public_connections: usize,
    max_publisher_connections: usize,
    max_in_flight_operations: usize,
    max_public_in_flight_operations: usize,
    max_publisher_in_flight_operations: usize,
    max_operations_per_second: u32,
    max_public_operations_per_second: u32,
    max_publisher_operations_per_second: u32,
    max_egress_bytes_per_second: u64,
    max_public_egress_bytes_per_second: u64,
    max_publisher_egress_bytes_per_second: u64,
    max_egress_bytes_per_connection: u64,
    max_archive_events: u64,
    max_archive_bytes: u64,
    handshake_timeout_seconds: u64,
    idle_timeout_seconds: u64,
    connection_timeout_seconds: u64,
    operation_timeout_seconds: u64,
    egress_timeout_seconds: u64,
}

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub public_listen: SocketAddr,
    pub publisher_listen: SocketAddr,
    pub database: PathBuf,
    pub directory_pubkey: [u8; 32],
    pub max_connections: usize,
    pub max_public_connections: usize,
    pub max_publisher_connections: usize,
    pub max_in_flight_operations: usize,
    pub max_public_in_flight_operations: usize,
    pub max_publisher_in_flight_operations: usize,
    pub max_operations_per_second: u32,
    pub max_public_operations_per_second: u32,
    pub max_publisher_operations_per_second: u32,
    pub max_egress_bytes_per_second: u64,
    pub max_public_egress_bytes_per_second: u64,
    pub max_publisher_egress_bytes_per_second: u64,
    pub max_egress_bytes_per_connection: u64,
    pub max_archive_events: u64,
    pub max_archive_bytes: u64,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub connection_timeout: Duration,
    pub operation_timeout: Duration,
    pub egress_timeout: Duration,
}

impl TryFrom<Cli> for RelayConfig {
    type Error = String;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        if !cli.config.is_absolute() {
            return Err("directory relay configuration path must be absolute".to_owned());
        }
        let bytes = read_private_file_bounded_v1(
            &cli.config,
            16 * 1024,
            PrivateFileModeV1::ReadOnlyOrReadWrite,
            "directory relay configuration",
        )?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "directory relay configuration is not UTF-8".to_owned())?;
        let file: RelayFileConfig = toml::from_str(text)
            .map_err(|_| "directory relay configuration is invalid".to_owned())?;
        if file.profile != "bitcoinpir-directory-relay-v1" {
            return Err("directory relay configuration profile is unsupported".to_owned());
        }
        if !file.public_listen.ip().is_loopback()
            || !file.publisher_listen.ip().is_loopback()
            || file.public_listen == file.publisher_listen
        {
            return Err(
                "directory relay requires distinct numeric loopback public and publisher binds"
                    .to_owned(),
            );
        }
        if !file.database.is_absolute() {
            return Err("directory relay database path must be absolute".to_owned());
        }
        let directory_pubkey = decode_public_key(&file.directory_pubkey_hex)?;
        if file.max_connections == 0
            || file.max_connections > 4_096
            || file.max_public_connections == 0
            || file.max_publisher_connections == 0
            || file.max_public_connections > file.max_connections
            || file.max_publisher_connections > file.max_connections
            || file.max_in_flight_operations == 0
            || file.max_in_flight_operations > 256
            || file.max_public_in_flight_operations == 0
            || file.max_publisher_in_flight_operations == 0
            || file.max_public_in_flight_operations > file.max_in_flight_operations
            || file.max_publisher_in_flight_operations > file.max_in_flight_operations
            || file.max_operations_per_second == 0
            || file.max_operations_per_second > 1_000_000
            || file.max_public_operations_per_second == 0
            || file.max_publisher_operations_per_second == 0
            || file.max_public_operations_per_second > file.max_operations_per_second
            || file.max_publisher_operations_per_second > file.max_operations_per_second
            || file.max_egress_bytes_per_second < 1024 * 1024
            || file.max_egress_bytes_per_second > 1024 * 1024 * 1024
            || file.max_public_egress_bytes_per_second < 1024 * 1024
            || file.max_publisher_egress_bytes_per_second < 1024 * 1024
            || file.max_public_egress_bytes_per_second > file.max_egress_bytes_per_second
            || file.max_publisher_egress_bytes_per_second > file.max_egress_bytes_per_second
            || file.max_egress_bytes_per_connection < 2 * 1024 * 1024
            || file.max_egress_bytes_per_connection > 8 * 1024 * 1024 * 1024
            || file.max_archive_events < 16_400
            || file.max_archive_events > 10_000_000
            || file.max_archive_bytes < 16 * 1024 * 1024
            || file.max_archive_bytes > 1024 * 1024 * 1024 * 1024
        {
            return Err(
                "directory relay concurrency/rate limits are outside safe bounds".to_owned(),
            );
        }
        if file
            .max_public_connections
            .checked_add(file.max_publisher_connections)
            != Some(file.max_connections)
            || file
                .max_public_in_flight_operations
                .checked_add(file.max_publisher_in_flight_operations)
                != Some(file.max_in_flight_operations)
            || file
                .max_public_operations_per_second
                .checked_add(file.max_publisher_operations_per_second)
                != Some(file.max_operations_per_second)
            || file
                .max_public_egress_bytes_per_second
                .checked_add(file.max_publisher_egress_bytes_per_second)
                != Some(file.max_egress_bytes_per_second)
        {
            return Err(
                "directory relay lane reservations must exactly partition each global limit"
                    .to_owned(),
            );
        }
        for (label, value, maximum) in [
            ("handshake timeout", file.handshake_timeout_seconds, 60),
            ("idle timeout", file.idle_timeout_seconds, 600),
            ("connection timeout", file.connection_timeout_seconds, 3_600),
            ("operation timeout", file.operation_timeout_seconds, 120),
            ("egress timeout", file.egress_timeout_seconds, 120),
        ] {
            if value == 0 || value > maximum {
                return Err(format!("{label} must be in 1..={maximum} seconds"));
            }
        }
        Ok(Self {
            public_listen: file.public_listen,
            publisher_listen: file.publisher_listen,
            database: file.database,
            directory_pubkey,
            max_connections: file.max_connections,
            max_public_connections: file.max_public_connections,
            max_publisher_connections: file.max_publisher_connections,
            max_in_flight_operations: file.max_in_flight_operations,
            max_public_in_flight_operations: file.max_public_in_flight_operations,
            max_publisher_in_flight_operations: file.max_publisher_in_flight_operations,
            max_operations_per_second: file.max_operations_per_second,
            max_public_operations_per_second: file.max_public_operations_per_second,
            max_publisher_operations_per_second: file.max_publisher_operations_per_second,
            max_egress_bytes_per_second: file.max_egress_bytes_per_second,
            max_public_egress_bytes_per_second: file.max_public_egress_bytes_per_second,
            max_publisher_egress_bytes_per_second: file.max_publisher_egress_bytes_per_second,
            max_egress_bytes_per_connection: file.max_egress_bytes_per_connection,
            max_archive_events: file.max_archive_events,
            max_archive_bytes: file.max_archive_bytes,
            handshake_timeout: Duration::from_secs(file.handshake_timeout_seconds),
            idle_timeout: Duration::from_secs(file.idle_timeout_seconds),
            connection_timeout: Duration::from_secs(file.connection_timeout_seconds),
            operation_timeout: Duration::from_secs(file.operation_timeout_seconds),
            egress_timeout: Duration::from_secs(file.egress_timeout_seconds),
        })
    }
}

fn decode_public_key(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err("directory public key must be exact lowercase 32-byte hex".to_owned());
    }
    let bytes = hex::decode(value).map_err(|_| "directory public key is invalid hex".to_owned())?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "directory public key has the wrong length".to_owned())?;
    if key.iter().all(|byte| *byte == 0) {
        return Err("directory public key cannot be all zero".to_owned());
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn configuration_is_loopback_only_and_key_strict() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("relay.toml");
        let render = |public_listen: &str, publisher_listen: &str, key: &str| {
            format!(
                r#"
profile = "bitcoinpir-directory-relay-v1"
public_listen = "{public_listen}"
publisher_listen = "{publisher_listen}"
database = "/tmp/bitcoinpir-directory-test.sqlite"
directory_pubkey_hex = "{key}"
max_connections = 2
max_public_connections = 1
max_publisher_connections = 1
max_in_flight_operations = 2
max_public_in_flight_operations = 1
max_publisher_in_flight_operations = 1
max_operations_per_second = 2
max_public_operations_per_second = 1
max_publisher_operations_per_second = 1
max_egress_bytes_per_second = 2097152
max_public_egress_bytes_per_second = 1048576
max_publisher_egress_bytes_per_second = 1048576
max_egress_bytes_per_connection = 2097152
max_archive_events = 16400
max_archive_bytes = 16777216
handshake_timeout_seconds = 1
idle_timeout_seconds = 1
connection_timeout_seconds = 1
operation_timeout_seconds = 1
egress_timeout_seconds = 1
"#
            )
        };
        fs::write(
            &path,
            render("127.0.0.1:8080", "127.0.0.1:8081", &"01".repeat(32)),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(RelayConfig::try_from(Cli {
            config: path.clone()
        })
        .is_ok());
        fs::write(
            &path,
            render("0.0.0.0:8080", "127.0.0.1:8081", &"01".repeat(32)),
        )
        .unwrap();
        assert!(RelayConfig::try_from(Cli {
            config: path.clone()
        })
        .is_err());
        fs::write(
            &path,
            render("127.0.0.1:8080", "127.0.0.1:8081", &"AA".repeat(32)),
        )
        .unwrap();
        assert!(RelayConfig::try_from(Cli { config: path }).is_err());
    }
}
