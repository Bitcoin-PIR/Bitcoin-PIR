use clap::Parser;

use bitcoinpir_cln_rpc_guard::{run, Cli, GuardConfig};

fn main() {
    let config = match GuardConfig::try_from(Cli::parse()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("bitcoinpir-cln-rpc-guard: {error}");
            std::process::exit(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("bitcoinpir-cln-rpc-guard: initialize async runtime failed");
            std::process::exit(1);
        }
    };
    if let Err(error) = runtime.block_on(run(config)) {
        eprintln!("bitcoinpir-cln-rpc-guard: {error}");
        std::process::exit(1);
    }
}
