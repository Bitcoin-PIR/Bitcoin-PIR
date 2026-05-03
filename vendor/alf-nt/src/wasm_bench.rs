use alf_nt::alf_nt::AlfNt;
use alf_nt::bigint::M192i;
use alf_nt::ktm::Ktm;

fn main() {
    unsafe {
        println!("=== ALF-n-t WASM Benchmark (software AES) ===\n");

        let ref_key: [u8; 16] = [
            0x05, 0x0a, 0x0f, 0x14, 0x19, 0x1e, 0x23, 0x28,
            0x2d, 0x32, 0x37, 0x3c, 0x41, 0x46, 0x4b, 0x50,
        ];
        let ref_tweak: [u8; 16] = [
            0x0b, 0x16, 0x21, 0x2c, 0x37, 0x42, 0x4d, 0x58,
            0x63, 0x6e, 0x79, 0x84, 0x8f, 0x9a, 0xa5, 0xb0,
        ];
        let ref_app_id: u64 = 0xf1f2f3f4f5f6f7f8u64;

        // ============================================================
        // Correctness: T4 reference test (ALF-2-0b)
        // ============================================================
        println!("--- Correctness: T4 (ALF-2-0b, Q=2^16) ---");
        {
            let mut qmax = M192i::set_pwr2(16);
            qmax.subc(1);

            let mut alf = AlfNt::new();
            alf.engine_init(qmax, 0);
            assert!(alf.is_binary && alf.n == 2 && alf.t == 0 && alf.rounds == 20);

            let mut ktm = Ktm::new();
            alf.key_init(&mut ktm, &ref_key, ref_app_id);
            alf.tweak_init(&ktm, &ref_tweak);

            let mut data = [0u8; 32];
            alf.encrypt(&mut data);
            let enc1 = u16::from_le_bytes([data[0], data[1]]);
            println!("Enc^1(0) = 0x{:04x} {}", enc1,
                if enc1 == 0x7e59 { "OK" } else { "FAILED" });

            for _ in 0..4 { alf.encrypt(&mut data); }
            let enc5 = u16::from_le_bytes([data[0], data[1]]);
            println!("Enc^5(0) = 0x{:04x} {}", enc5,
                if enc5 == 0x7501 { "OK" } else { "FAILED" });

            for _ in 0..994 { alf.encrypt(&mut data); }
            let enc999 = u16::from_le_bytes([data[0], data[1]]);
            println!("Enc^999(0) = 0x{:04x} {}", enc999,
                if enc999 == 0x98a9 { "OK" } else { "FAILED" });

            alf.prepare_decrypt();
            for _ in 0..999 { alf.decrypt(&mut data); }
            let dec = u16::from_le_bytes([data[0], data[1]]);
            println!("Dec^999(Enc^999(0)) = 0x{:04x} {}", dec,
                if dec == 0 { "OK" } else { "FAILED" });
        }

        // ============================================================
        // Correctness: T5 reference test (ALF-2-0n, non-binary)
        // ============================================================
        println!("\n--- Correctness: T5 (ALF-2-0n, Q=2^15+1) ---");
        {
            let mut qmax = M192i::set_pwr2(15);
            qmax.addc(1);
            qmax.subc(1);

            let mut alf = AlfNt::new();
            alf.engine_init(qmax, 0);
            assert!(!alf.is_binary && alf.n == 2 && alf.t == 0);

            let mut ktm = Ktm::new();
            alf.key_init(&mut ktm, &ref_key, ref_app_id);
            alf.tweak_init(&ktm, &ref_tweak);

            let mut data = [0u8; 32];
            alf.encrypt(&mut data);
            let enc1 = u16::from_le_bytes([data[0], data[1]]);
            println!("Enc^1(0) = 0x{:04x} {}", enc1,
                if enc1 == 0x7acd { "OK" } else { "FAILED" });

            for _ in 0..998 { alf.encrypt(&mut data); }
            let enc999 = u16::from_le_bytes([data[0], data[1]]);

            alf.prepare_decrypt();
            for _ in 0..999 { alf.decrypt(&mut data); }
            let dec = u16::from_le_bytes([data[0], data[1]]);
            println!("Enc^999(0) = 0x{:04x}, Dec roundtrip: {}", enc999,
                if dec == 0 { "OK" } else { "FAILED" });
        }

        // ============================================================
        // Correctness: ALF-2-7b (with extra bits)
        // ============================================================
        println!("\n--- Correctness: ALF-2-7b (Q=2^23) ---");
        {
            let mut qmax = M192i::set_pwr2(23);
            qmax.subc(1);
            let mut alf = AlfNt::new();
            alf.engine_init(qmax, 0);
            assert!(alf.is_binary && alf.n == 2 && alf.t == 7 && alf.rounds == 28);

            let mut ktm = Ktm::new();
            alf.key_init(&mut ktm, &ref_key, ref_app_id);
            alf.tweak_init(&ktm, &ref_tweak);

            let mut data = [0u8; 32];
            alf.encrypt(&mut data);
            let ok = data[0] == 0xdb && data[1] == 0xfb && data[2] == 0x08;
            println!("Enc^1(0) = [{:02x} {:02x} {:02x}] {}",
                data[0], data[1], data[2], if ok { "OK" } else { "FAILED" });

            alf.prepare_decrypt();
            alf.decrypt(&mut data);
            let dec_ok = data[0] == 0 && data[1] == 0 && data[2] == 0;
            println!("Roundtrip: {}", if dec_ok { "OK" } else { "FAILED" });
        }

        // ============================================================
        // Benchmark helper
        // ============================================================
        fn bench_variant(
            label: &str, qmax: M192i,
            key: &[u8; 16], tweak: &[u8; 16], app_id: u64,
            enc_iters: u64, dec_iters: u64,
        ) {
            unsafe {
                let mut alf = AlfNt::new();
                alf.engine_init(qmax, 0);
                let mut ktm = Ktm::new();
                alf.key_init(&mut ktm, key, app_id);
                alf.tweak_init(&ktm, tweak);

                println!("\n--- Benchmark: {} (n={}, t={}, r={}) ---",
                    label, alf.n, alf.t, alf.rounds);

                let mut d = [0u8; 32];

                // Warm up
                for _ in 0..500 { alf.encrypt(&mut d); }

                // Encrypt
                let start = std::time::Instant::now();
                for _ in 0..enc_iters {
                    alf.encrypt(&mut d);
                }
                let enc_ns = start.elapsed().as_nanos() as f64 / enc_iters as f64;
                println!("Encrypt: {:.1} ns/op  ({:.2} M ops/sec)  [{} iters]",
                    enc_ns, 1e9 / enc_ns / 1e6, enc_iters);

                // Decrypt
                alf.prepare_decrypt();
                for _ in 0..500 { alf.decrypt(&mut d); }
                let start = std::time::Instant::now();
                for _ in 0..dec_iters {
                    alf.decrypt(&mut d);
                }
                let dec_ns = start.elapsed().as_nanos() as f64 / dec_iters as f64;
                println!("Decrypt: {:.1} ns/op  ({:.2} M ops/sec)  [{} iters]",
                    dec_ns, 1e9 / dec_ns / 1e6, dec_iters);

                // Roundtrip sanity (use small value that fits all domains)
                alf.tweak_init(&ktm, tweak);
                let mut san = [0u8; 32];
                san[0] = 0x42; san[1] = 0x01;
                let saved = [san[0], san[1]];
                alf.encrypt(&mut san);
                alf.prepare_decrypt();
                alf.decrypt(&mut san);
                let ok = san[0] == saved[0] && san[1] == saved[1];
                println!("Roundtrip: {}", if ok { "OK" } else { "FAIL" });
            }
        }

        // ============================================================
        // Benchmark: ALF-2-0b (binary, t=0, r=20) — simplest variant
        // ============================================================
        {
            let mut qm = M192i::set_pwr2(16);
            qm.subc(1);
            bench_variant("ALF-2-0b", qm, &ref_key, &ref_tweak, ref_app_id,
                1_000_000, 1_000_000);
        }

        // ============================================================
        // Benchmark: ALF-2-7b (binary, t=7, r=28) — with clmul
        // ============================================================
        {
            let mut qm = M192i::set_pwr2(23);
            qm.subc(1);
            bench_variant("ALF-2-7b", qm, &ref_key, &ref_tweak, ref_app_id,
                1_000_000, 1_000_000);
        }

        // ============================================================
        // Benchmark: ALF-4-0b (binary, t=0, r=14) — 32-bit domain
        // ============================================================
        {
            let mut qm = M192i::set_pwr2(32);
            qm.subc(1);
            bench_variant("ALF-4-0b", qm, &ref_key, &ref_tweak, ref_app_id,
                500_000, 500_000);
        }

        // ============================================================
        // Benchmark: ALF-2-0n (non-binary, cycle-walking)
        // ============================================================
        {
            let qm = M192i::set1(49999);
            bench_variant("ALF-2-0n (Q=50000)", qm, &ref_key, &ref_tweak, ref_app_id,
                500_000, 500_000);
        }

        // ============================================================
        // Benchmark: ALF-8-0b (binary, t=0, r=12) — 64-bit domain
        // ============================================================
        {
            let mut qm = M192i::set_pwr2(64);
            qm.subc(1);
            bench_variant("ALF-8-0b", qm, &ref_key, &ref_tweak, ref_app_id,
                500_000, 500_000);
        }
    }
}
