//! HarmonyPIR demo / CLI entry point.

use harmonypir::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn main() {
    let n = 1024;
    let w = 32;

    // Build a simple test database.
    let db: Vec<Vec<u8>> = (0..n)
        .map(|i| {
            let mut entry = vec![0u8; w];
            entry[..8].copy_from_slice(&(i as u64).to_le_bytes());
            entry
        })
        .collect();
    let server = Server::new(db.clone());

    // Choose balanced parameters and HarmonyPIR0 (Hoang PRP).
    let params = Params::with_balanced_t(n, w).unwrap();
    println!(
        "HarmonyPIR0: N={}, w={}, T={}, M={}, max_queries={}",
        params.n, params.w, params.t, params.m, params.max_queries
    );

    let key = [0x42u8; 16];
    let prp = Box::new(HoangPrp::new(2 * n, params.r, &key));

    // Offline phase.
    let mut client = Client::offline(params, prp, &server).unwrap();
    println!("Offline phase complete.");

    // Online phase: query a few indices.
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let test_indices = [0, 42, 100, 1023];
    for &q in &test_indices {
        if client.queries_remaining() == 0 {
            println!("No more queries available.");
            break;
        }
        let result = client.query(q, &server, &mut rng).unwrap();
        let expected = &db[q];
        let ok = result == *expected;
        println!("  query({q}): correct={ok}");
    }

    println!(
        "Queries used: {}/{}",
        client.queries_used(),
        params.max_queries
    );
}
