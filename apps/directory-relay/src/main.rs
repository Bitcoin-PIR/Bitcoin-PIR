use clap::Parser;
use log::LevelFilter;

use bitcoinpir_directory_relay::{server, Cli, RelayConfig};

#[tokio::main]
async fn main() {
    init_logger();
    let result = match RelayConfig::try_from(Cli::parse()) {
        Ok(config) => server::run(config).await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!("bitcoinpir-directory-relay: {error}");
        std::process::exit(1);
    }
}

fn init_logger() {
    let mut builder = env_logger::Builder::from_default_env();
    silence_frame_logging(&mut builder);
    builder.init();
}

fn silence_frame_logging(builder: &mut env_logger::Builder) {
    // tungstenite trace records include complete frame payloads. Directory
    // requests and signed events must stay out of logs even under RUST_LOG=trace.
    builder.filter_module("tungstenite", LevelFilter::Off);
    builder.filter_module("tokio_tungstenite", LevelFilter::Off);
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::{Log, Metadata};

    #[test]
    fn dependency_frame_targets_remain_silent_at_trace() {
        let mut builder = env_logger::Builder::new();
        builder.filter_level(LevelFilter::Trace);
        builder.filter_module("tungstenite", LevelFilter::Trace);
        builder.filter_module("tokio_tungstenite", LevelFilter::Trace);
        silence_frame_logging(&mut builder);
        let logger = builder.build();
        let metadata = |target: &'static str| {
            Metadata::builder()
                .level(log::Level::Trace)
                .target(target)
                .build()
        };
        assert!(!logger.enabled(&metadata("tungstenite::protocol")));
        assert!(!logger.enabled(&metadata("tokio_tungstenite::handshake")));
        assert!(logger.enabled(&metadata("bitcoinpir_directory_relay")));
    }
}
