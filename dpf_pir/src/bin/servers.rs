//! DPF-PIR Dual Server Runner
//!
//! This binary runs both PIR servers concurrently for testing purposes.

use dpf_pir::{SERVER1_PORT, SERVER2_PORT};
use log::{error, info};
use std::process::Command;

#[tokio::main]
async fn main() {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("Starting two DPF-PIR servers...");

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let mut data_path = String::from("data.bin");
    let mut num_buckets = dpf_pir::NUM_BUCKETS;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data" | "-d" => {
                if i + 1 < args.len() {
                    data_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "--buckets" | "-b" => {
                if i + 1 < args.len() {
                    num_buckets = args[i + 1].parse().unwrap_or(num_buckets);
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("DPF-PIR Dual Server Runner");
                println!("Usage: {} [OPTIONS]", args[0]);
                println!();
                println!("This spawns two servers on ports {} and {}", SERVER1_PORT, SERVER2_PORT);
                println!();
                println!("Options:");
                println!("  --data, -d <PATH>       Path to data file (default: {})", data_path);
                println!("  --buckets, -b <NUM>     Number of buckets (default: {})", num_buckets);
                println!("  --help, -h              Show this help message");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    // Spawn server 1
    let data_path1 = data_path.clone();
    let data_path2 = data_path;
    
    info!("Spawning Server 1 on port {}", SERVER1_PORT);
    let mut server1 = match Command::new(std::env::current_exe().unwrap().parent().unwrap().join("server"))
        .arg("--port")
        .arg(SERVER1_PORT.to_string())
        .arg("--data")
        .arg(&data_path1)
        .arg("--buckets")
        .arg(num_buckets.to_string())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            error!("Failed to spawn server 1: {}", e);
            std::process::exit(1);
        }
    };

    info!("Spawning Server 2 on port {}", SERVER2_PORT);
    let mut server2 = match Command::new(std::env::current_exe().unwrap().parent().unwrap().join("server"))
        .arg("--port")
        .arg(SERVER2_PORT.to_string())
        .arg("--data")
        .arg(&data_path2)
        .arg("--buckets")
        .arg(num_buckets.to_string())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            error!("Failed to spawn server 2: {}", e);
            let _ = server1.kill();
            std::process::exit(1);
        }
    };

    info!("Both servers started. Press Ctrl+C to stop.");

    // Wait for servers to finish (they won't unless killed)
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for Ctrl+C");

    info!("Shutting down servers...");
    let _ = server1.kill();
    let _ = server2.kill();
    info!("Servers stopped.");
}