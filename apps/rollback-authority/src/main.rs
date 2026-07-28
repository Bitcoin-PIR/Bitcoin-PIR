use clap::Parser;

fn main() {
    if let Err(error) = rollback_authority::run(rollback_authority::Cli::parse()) {
        eprintln!("rollback-authority: {error}");
        std::process::exit(1);
    }
}
