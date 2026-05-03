use alf_nt::alf_nt::AlfNt;
use alf_nt::bigint::M192i;
use alf_nt::ktm::Ktm;

fn main() {
    unsafe {
        println!("=== ALF-n-t Rust Implementation (ARM64 NEON+AES) ===\n");

        // Reference test constants (matching C++ refcode)
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
        // Test T4: Q=2^16, n=2, t=0, binary
        // Qmax = 0xFFFF
        // ============================================================
        println!("--- Test T4: ALF-2-0b (Q=2^16, binary, t=0, r=20) ---");

        let mut qmax = M192i::set_pwr2(16);
        qmax.subc(1);
        assert_eq!(qmax.u[0], 0xFFFF);

        let mut alf = AlfNt::new();
        alf.engine_init(qmax, 0);
        println!("n={}, t={}, rounds={}, is_binary={}", alf.n, alf.t, alf.rounds, alf.is_binary);
        assert_eq!(alf.n, 2);
        assert_eq!(alf.t, 0);
        assert_eq!(alf.rounds, 20);
        assert!(alf.is_binary);

        let mut ktm = Ktm::new();
        alf.key_init(&mut ktm, &ref_key, ref_app_id);

        // Check KTM state after KeyInit (from test vector T4)
        let expected_a1: [u8; 16] = [
            0x96, 0xa0, 0x51, 0xd0, 0x93, 0x5b, 0xd8, 0x01,
            0xbe, 0xef, 0xeb, 0x65, 0x07, 0x77, 0x29, 0xcf,
        ];
        let expected_a2: [u8; 16] = [
            0x3e, 0x5c, 0x7e, 0xb2, 0x5e, 0xe6, 0x74, 0x9d,
            0x41, 0x8b, 0x71, 0xbb, 0xd5, 0x3c, 0x35, 0x09,
        ];
        let expected_a3: [u8; 16] = [
            0x56, 0x25, 0xa3, 0x0a, 0xb6, 0xc6, 0x6c, 0x02,
            0x06, 0xb9, 0xc9, 0x63, 0xb3, 0x03, 0xc2, 0xa7,
        ];

        let mut a1_buf = [0u8; 16];
        let mut a2_buf = [0u8; 16];
        let mut a3_buf = [0u8; 16];
        alf_nt::simd::store128(a1_buf.as_mut_ptr(), ktm.a1);
        alf_nt::simd::store128(a2_buf.as_mut_ptr(), ktm.a2);
        alf_nt::simd::store128(a3_buf.as_mut_ptr(), ktm.a3);

        let key_ok = a1_buf == expected_a1 && a2_buf == expected_a2 && a3_buf == expected_a3;
        println!("KeyInit: {}", if key_ok { "OK" } else { "FAILED" });
        if !key_ok {
            print!("  A1: "); for b in &a1_buf { print!("{:02x} ", b); } println!();
            print!("  A2: "); for b in &a2_buf { print!("{:02x} ", b); } println!();
            print!("  A3: "); for b in &a3_buf { print!("{:02x} ", b); } println!();
            print!("  Expected A1: "); for b in &expected_a1 { print!("{:02x} ", b); } println!();
            print!("  Expected A2: "); for b in &expected_a2 { print!("{:02x} ", b); } println!();
            print!("  Expected A3: "); for b in &expected_a3 { print!("{:02x} ", b); } println!();
        }

        alf.tweak_init(&ktm, &ref_tweak);

        // Check RK[0..3] (from test vector T4)
        let expected_rk: [[u8; 2]; 4] = [
            [0x6f, 0x3c],
            [0x73, 0x46],
            [0xf9, 0x32],
            [0xcc, 0x52],
        ];
        let mut rk_ok = true;
        for r in 0..4 {
            let mut rk_buf = [0u8; 16];
            alf_nt::simd::store128(rk_buf.as_mut_ptr(), alf.rk[r]);
            if rk_buf[0] != expected_rk[r][0] || rk_buf[1] != expected_rk[r][1] {
                rk_ok = false;
                print!("  RK[{}]: ", r); for b in &rk_buf[..2] { print!("{:02x} ", b); }
                print!(" (expected: "); for b in &expected_rk[r] { print!("{:02x} ", b); } println!(")");
            }
        }
        println!("TweakInit RKs: {}", if rk_ok { "OK" } else { "FAILED" });

        // Encrypt 0 → expected 0x7e59
        let mut data = [0u8; 32];
        alf.encrypt(&mut data);
        let enc1 = u16::from_le_bytes([data[0], data[1]]);
        let enc1_ok = enc1 == 0x7e59;
        println!("Enc^1(0) = 0x{:04x} {}", enc1, if enc1_ok { "OK" } else { "FAILED (expected 0x7e59)" });

        // Enc^5: encrypt 4 more times
        for _ in 0..4 {
            alf.encrypt(&mut data);
        }
        let enc5 = u16::from_le_bytes([data[0], data[1]]);
        let enc5_ok = enc5 == 0x7501;
        println!("Enc^5(0) = 0x{:04x} {}", enc5, if enc5_ok { "OK" } else { "FAILED (expected 0x7501)" });

        // Enc^999: encrypt 994 more times
        for _ in 0..994 {
            alf.encrypt(&mut data);
        }
        let enc999 = u16::from_le_bytes([data[0], data[1]]);
        let enc999_ok = enc999 == 0x98a9;
        println!("Enc^999(0) = 0x{:04x} {}", enc999, if enc999_ok { "OK" } else { "FAILED (expected 0x98a9)" });

        // Decryption test: decrypt 999 times to get back to 0
        alf.prepare_decrypt();

        // Check decryption RK[0..3] (from test vector T4)
        let expected_dec_rk: [[u8; 2]; 4] = [
            [0x34, 0x8c],
            [0xef, 0x8a],
            [0xd3, 0x92],
            [0x53, 0x62],
        ];
        let mut dec_rk_ok = true;
        for r in 0..4 {
            let mut rk_buf = [0u8; 16];
            alf_nt::simd::store128(rk_buf.as_mut_ptr(), alf.rk[r]);
            if rk_buf[0] != expected_dec_rk[r][0] || rk_buf[1] != expected_dec_rk[r][1] {
                dec_rk_ok = false;
                print!("  Dec RK[{}]: ", r); for b in &rk_buf[..2] { print!("{:02x} ", b); }
                print!(" (expected: "); for b in &expected_dec_rk[r] { print!("{:02x} ", b); } println!(")");
            }
        }
        println!("PrepareDecrypt RKs: {}", if dec_rk_ok { "OK" } else { "FAILED" });

        for _ in 0..999 {
            alf.decrypt(&mut data);
        }
        let dec_val = u16::from_le_bytes([data[0], data[1]]);
        let dec_ok = dec_val == 0;
        println!("Dec^999(Enc^999(0)) = 0x{:04x} {}", dec_val, if dec_ok { "OK" } else { "FAILED (expected 0x0000)" });

        // ============================================================
        // Test T5: Q=2^15+1, n=2, t=0, non-binary
        // Qmax = 0x8000
        // ============================================================
        println!("\n--- Test T5: ALF-2-0n (Q=2^15+1, non-binary, t=0, r=20) ---");

        let mut qmax5 = M192i::set_pwr2(15);
        // Qmax = 2^15 + 1 - 1 = 2^15 = 0x8000
        // get_ntc(n,t,c, 5): c=1, idx'=2; t=0, idx'=1; n=2
        // Qmax = set_pwr2(16-1) + 1 - 1 = 2^15
        // Actually: Qmax = set_pwr2(8*2+0-1) + 1 - 1 = 2^15 + 1 - 1 = 2^15 = 0x8000
        // Wait: set_pwr2(15) = 0x8000, then .u[0] += c=1 → 0x8001, then subc(1) → 0x8000
        qmax5.addc(1); // +c where c=1
        qmax5.subc(1); // -1

        let mut alf5 = AlfNt::new();
        alf5.engine_init(qmax5, 0);
        assert!(!alf5.is_binary); // 0x8000 has only 1 bit set but bw=16
        assert_eq!(alf5.n, 2);
        assert_eq!(alf5.t, 0);
        assert_eq!(alf5.rounds, 20);

        let mut ktm5 = Ktm::new();
        alf5.key_init(&mut ktm5, &ref_key, ref_app_id);
        alf5.tweak_init(&ktm5, &ref_tweak);

        let mut data5 = [0u8; 32];
        alf5.encrypt(&mut data5);
        let enc1_5 = u16::from_le_bytes([data5[0], data5[1]]);
        println!("Enc^1(0) = 0x{:04x} {}", enc1_5,
            if enc1_5 == 0x7acd { "OK" } else { "FAILED (expected 0x7acd)" });

        for _ in 0..4 { alf5.encrypt(&mut data5); }
        let enc5_5 = u16::from_le_bytes([data5[0], data5[1]]);
        println!("Enc^5(0) = 0x{:04x} {}", enc5_5,
            if enc5_5 == 0x177e { "OK" } else { "FAILED (expected 0x177e)" });

        for _ in 0..994 { alf5.encrypt(&mut data5); }
        let enc999_5 = u16::from_le_bytes([data5[0], data5[1]]);
        println!("Enc^999(0) = 0x{:04x} {}", enc999_5,
            if enc999_5 == 0x7529 { "OK" } else { "FAILED (expected 0x7529)" });

        // Decryption roundtrip
        alf5.prepare_decrypt();
        for _ in 0..999 { alf5.decrypt(&mut data5); }
        let dec5_val = u16::from_le_bytes([data5[0], data5[1]]);
        println!("Dec^999(Enc^999(0)) = 0x{:04x} {}", dec5_val,
            if dec5_val == 0 { "OK" } else { "FAILED" });

        // ============================================================
        // Comprehensive tests across various n/t/binary combinations
        // Expected Enc^1(0) from C++ testvec.hpp (little-endian bytes)
        // ============================================================
        println!("\n--- Comprehensive variant tests ---");

        // (idx, expected_enc1_le_bytes)
        let comp_tests: &[(usize, &[u8])] = &[
            (4,  &[0x59, 0x7e]),                                                    // ALF-2-0b
            (5,  &[0xcd, 0x7a]),                                                    // ALF-2-0n
            (6,  &[0xdb, 0xfb, 0x08]),                                              // ALF-2-7b
            (7,  &[0xb6, 0x18, 0x10]),                                              // ALF-2-7n
            (8,  &[0x31, 0x94, 0x2c]),                                              // ALF-3-0b
            (9,  &[0xa0, 0x2e, 0x56]),                                              // ALF-3-0n
            (12, &[0x8a, 0xe7, 0x05, 0x98]),                                        // ALF-4-0b
            (13, &[0x91, 0xd1, 0x40, 0x68]),                                        // ALF-4-0n
            (16, &[0xe6, 0xb6, 0xac, 0x6b, 0xf8]),                                  // ALF-5-0b
            (20, &[0x54, 0xed, 0x44, 0x82, 0x63, 0x29]),                            // ALF-6-0b
            (24, &[0xcd, 0x2a, 0x0c, 0xf5, 0x8f, 0x25, 0x8c]),                      // ALF-7-0b
            (28, &[0x9b, 0xb6, 0xc3, 0x2c, 0xf2, 0x18, 0xb8, 0xb8]),                // ALF-8-0b
            (36, &[0x65, 0x04, 0xf4, 0x33, 0x15, 0x01, 0x23, 0x82, 0xb9, 0x9e]),    // ALF-10-0b
        ];

        let mut all_pass = true;
        for &(idx, expected) in comp_tests {
            let c = idx % 2;
            let t = 7 * ((idx / 2) % 2);
            let n = idx / 4 + 1;
            let bit_width = 8 * n + t - c;

            let mut qm = M192i::set_pwr2(bit_width as u32);
            qm.u[0] = qm.u[0].wrapping_add(c as u64);
            qm.subc(1);

            let mut a = AlfNt::new();
            a.engine_init(qm, 0);
            let mut k = Ktm::new();
            a.key_init(&mut k, &ref_key, ref_app_id);
            a.tweak_init(&k, &ref_tweak);

            let mut d = [0u8; 32];
            a.encrypt(&mut d);
            let enc_ok = &d[..expected.len()] == expected;

            a.prepare_decrypt();
            a.decrypt(&mut d);
            let nbytes = if t > 0 { n + 1 } else { n };
            let dec_ok = d[..nbytes].iter().all(|&b| b == 0);

            if !enc_ok || !dec_ok { all_pass = false; }
            let bn = if a.is_binary { "b" } else { "n" };
            println!("  T{:>2}: ALF-{:>2}-{}{} r={:>2} enc={} dec={}",
                idx, a.n, a.t, bn, a.rounds,
                if enc_ok { "OK  " } else { "FAIL" },
                if dec_ok { "OK" } else { "FAIL" });
        }

        // Also test Q = 2^102 - 98 roundtrip (n=12, t=6, non-binary)
        let mut qmax_ex = M192i::set_pwr2(102);
        qmax_ex.subc(99);
        let mut alf_ex = AlfNt::new();
        alf_ex.engine_init(qmax_ex, 0);
        let key_ex: [u8; 16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
        let tweak_ex: [u8; 16] = [16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
        let mut ktm_ex = Ktm::new();
        alf_ex.key_init(&mut ktm_ex, &key_ex, 0xf0f1f2f3f4f5f6f7u64);
        alf_ex.tweak_init(&ktm_ex, &tweak_ex);
        let mut data_ex = [0u8; 32];
        alf_ex.encrypt(&mut data_ex);
        alf_ex.prepare_decrypt();
        alf_ex.decrypt(&mut data_ex);
        let rt_ok = data_ex[..13].iter().all(|&b| b == 0);
        if !rt_ok { all_pass = false; }
        println!("  Q=2^102-98 (ALF-12-6n) roundtrip: {}", if rt_ok { "OK" } else { "FAIL" });

        println!("\nAll tests: {}", if all_pass { "PASSED" } else { "SOME FAILED" });

        // ============================================================
        // PRP test: encrypt all 2^16 values, verify bijection
        // ============================================================
        println!("\n--- PRP test: ALF-2-0b, Q=2^16, all 65536 values ---");
        {
            let mut qm = M192i::set_pwr2(16);
            qm.subc(1); // Qmax = 0xFFFF
            let mut a = AlfNt::new();
            a.engine_init(qm, 0);
            let mut k = Ktm::new();
            a.key_init(&mut k, &ref_key, ref_app_id);
            a.tweak_init(&k, &ref_tweak);

            let n = 65536usize;
            let mut seen = vec![false; n];
            let mut collisions = 0u32;
            let mut out_of_range = 0u32;

            let start = std::time::Instant::now();
            for i in 0..n {
                let mut buf = [0u8; 32];
                buf[0] = (i & 0xFF) as u8;
                buf[1] = ((i >> 8) & 0xFF) as u8;
                a.encrypt(&mut buf);
                let ct = (buf[0] as usize) | ((buf[1] as usize) << 8);
                if ct >= n {
                    out_of_range += 1;
                } else if seen[ct] {
                    collisions += 1;
                } else {
                    seen[ct] = true;
                }
            }
            let elapsed = start.elapsed();

            let all_seen = seen.iter().all(|&s| s);
            println!("  Encrypted {} values in {:.1}ms", n, elapsed.as_secs_f64() * 1000.0);
            println!("  Collisions: {}  Out-of-range: {}", collisions, out_of_range);
            println!("  All {} outputs unique: {}", n, if all_seen && collisions == 0 && out_of_range == 0 { "YES — valid PRP" } else { "NO — BROKEN" });

            // Also verify decrypt is the inverse
            let mut dec_ok = true;
            for i in 0..n {
                let mut buf = [0u8; 32];
                buf[0] = (i & 0xFF) as u8;
                buf[1] = ((i >> 8) & 0xFF) as u8;
                a.encrypt(&mut buf);
                a.prepare_decrypt();
                a.decrypt(&mut buf);
                let pt = (buf[0] as usize) | ((buf[1] as usize) << 8);
                if pt != i {
                    println!("  Dec(Enc({})) = {} MISMATCH", i, pt);
                    dec_ok = false;
                    break;
                }
                // Re-init encrypt keys for next iteration
                a.tweak_init(&k, &ref_tweak);
            }
            println!("  Dec(Enc(x)) == x for all: {}", if dec_ok { "YES" } else { "NO" });
        }

        // Non-binary PRP test: Q = 50000 (not a power of 2)
        println!("\n--- PRP test: ALF-2-0n, Q=50000, all 50000 values ---");
        {
            let qm = M192i::set1(49999); // Qmax = 49999 → Q = 50000
            let mut a = AlfNt::new();
            a.engine_init(qm, 0);
            let mut k = Ktm::new();
            a.key_init(&mut k, &ref_key, ref_app_id);
            a.tweak_init(&k, &ref_tweak);

            let n = 50000usize;
            let mut seen = vec![false; n];
            let mut collisions = 0u32;
            let mut out_of_range = 0u32;

            let start = std::time::Instant::now();
            for i in 0..n {
                let mut buf = [0u8; 32];
                buf[0] = (i & 0xFF) as u8;
                buf[1] = ((i >> 8) & 0xFF) as u8;
                a.encrypt(&mut buf);
                let ct = (buf[0] as usize) | ((buf[1] as usize) << 8);
                if ct >= n {
                    out_of_range += 1;
                } else if seen[ct] {
                    collisions += 1;
                } else {
                    seen[ct] = true;
                }
            }
            let elapsed = start.elapsed();

            let all_seen = seen.iter().all(|&s| s);
            println!("  Encrypted {} values in {:.1}ms", n, elapsed.as_secs_f64() * 1000.0);
            println!("  Collisions: {}  Out-of-range: {}", collisions, out_of_range);
            println!("  All {} outputs unique: {}", n, if all_seen && collisions == 0 && out_of_range == 0 { "YES — valid PRP" } else { "NO — BROKEN" });
        }

        // ============================================================
        // Benchmark: N=2^27 domain (n=3, t=3, binary, rounds=24)
        // ============================================================
        println!("\n--- Benchmark: N=2^27 (ALF-3-3b, 134M element domain) ---");
        {
            let bw = 27u32;
            let mut qm = M192i::set_pwr2(bw);
            qm.subc(1); // Qmax = 2^27 - 1
            let mut a = AlfNt::new();
            a.engine_init(qm, 0);
            println!("  n={}, t={}, rounds={}, is_binary={}", a.n, a.t, a.rounds, a.is_binary);

            let mut k = Ktm::new();
            a.key_init(&mut k, &ref_key, ref_app_id);
            a.tweak_init(&k, &ref_tweak);

            // Single-block throughput
            let iters = 5_000_000u64;
            let mut d = [0u8; 32];
            for _ in 0..1000 { a.encrypt(&mut d); }

            let start = std::time::Instant::now();
            for _ in 0..iters { a.encrypt(&mut d); }
            let enc_ns = start.elapsed().as_nanos() as f64 / iters as f64;
            println!("  Single encrypt: {:.1} ns/op  ({:.2} M ops/sec)", enc_ns, 1e9 / enc_ns / 1e6);

            // Batch throughput
            a.tweak_init(&k, &ref_tweak);
            let batch = 16usize;
            let mut bufs = vec![[0u8; 32]; batch];
            let mut ptrs: Vec<*mut u8> = bufs.iter_mut().map(|b| b.as_mut_ptr()).collect();
            for _ in 0..1000 { a.encrypt_batch(&mut ptrs); }

            let batch_iters = 2_000_000u64;
            let start = std::time::Instant::now();
            for _ in 0..batch_iters { a.encrypt_batch(&mut ptrs); }
            let total = batch_iters * batch as u64;
            let batch_ns = start.elapsed().as_nanos() as f64 / total as f64;
            println!("  Batch encrypt (16x): {:.1} ns/op  ({:.2} M ops/sec)", batch_ns, 1e9 / batch_ns / 1e6);

            // Estimate full-domain permutation
            let domain = 1u64 << bw;
            let single_secs = (domain as f64) * enc_ns / 1e9;
            let batch_secs = (domain as f64) * batch_ns / 1e9;
            println!("  Full domain (2^{} = {} elements):", bw, domain);
            println!("    Single: {:.2}s", single_secs);
            println!("    Batch:  {:.2}s", batch_secs);

            // Quick PRP sanity: encrypt+decrypt 1000 random-ish values
            a.tweak_init(&k, &ref_tweak);
            let mut prp_ok = true;
            for i in 0..1000u32 {
                let val = (i.wrapping_mul(2654435761)) & ((1 << bw) - 1); // spread values
                let mut buf = [0u8; 32];
                buf[0] = (val & 0xFF) as u8;
                buf[1] = ((val >> 8) & 0xFF) as u8;
                buf[2] = ((val >> 16) & 0xFF) as u8;
                buf[3] = ((val >> 24) & 0xFF) as u8;
                let saved = [buf[0], buf[1], buf[2], buf[3]];
                a.encrypt(&mut buf);
                // Check output in range
                let ct = (buf[0] as u32) | ((buf[1] as u32) << 8)
                    | ((buf[2] as u32) << 16) | ((buf[3] as u32) << 24);
                if ct >= (1 << bw) {
                    println!("    OUT OF RANGE: Enc({}) = {}", val, ct);
                    prp_ok = false; break;
                }
                a.prepare_decrypt();
                a.decrypt(&mut buf);
                if buf[0..4] != saved {
                    println!("    ROUNDTRIP FAIL at {}", val);
                    prp_ok = false; break;
                }
                a.tweak_init(&k, &ref_tweak);
            }
            println!("  PRP sanity (1000 values): {}", if prp_ok { "OK" } else { "FAIL" });
        }

        // ============================================================
        // Benchmark: ALF-2-7b (n=2, t=7, binary, rounds=28)
        // ============================================================
        println!("\n--- Benchmark: ALF-2-7b (n=2, t=7) ---");
        {
            // idx=6: c=0, t=7, n=2, bit_width=23, binary
            let mut qm = M192i::set_pwr2(23);
            qm.subc(1); // Qmax = 2^23 - 1
            let mut a = AlfNt::new();
            a.engine_init(qm, 0);
            let mut k = Ktm::new();
            a.key_init(&mut k, &ref_key, ref_app_id);
            a.tweak_init(&k, &ref_tweak);

            let iters: u64 = 10_000_000;
            let mut d = [0u8; 32];

            // Warm up
            for _ in 0..1000 { a.encrypt(&mut d); }

            // Benchmark encryption
            let start = std::time::Instant::now();
            for _ in 0..iters {
                a.encrypt(&mut d);
            }
            let enc_elapsed = start.elapsed();
            let enc_ns = enc_elapsed.as_nanos() as f64 / iters as f64;
            let enc_mops = 1e9 / enc_ns / 1e6;
            println!("Encrypt: {:.1} ns/op  ({:.2} M ops/sec)  [{} iterations]",
                enc_ns, enc_mops, iters);

            // Benchmark decryption
            a.prepare_decrypt();
            let start = std::time::Instant::now();
            for _ in 0..iters {
                a.decrypt(&mut d);
            }
            let dec_elapsed = start.elapsed();
            let dec_ns = dec_elapsed.as_nanos() as f64 / iters as f64;
            let dec_mops = 1e9 / dec_ns / 1e6;
            println!("Decrypt: {:.1} ns/op  ({:.2} M ops/sec)  [{} iterations]",
                dec_ns, dec_mops, iters);

            // Verify roundtrip still works
            d = [0u8; 32];
            a.tweak_init(&k, &ref_tweak); // re-init for encrypt
            a.encrypt(&mut d);
            a.prepare_decrypt();
            a.decrypt(&mut d);
            let ok = d[..3].iter().all(|&b| b == 0);
            println!("Roundtrip check: {}", if ok { "OK" } else { "FAIL" });

            // --- Batch benchmark: 4-way interleaved ---
            println!("\n--- Batch Benchmark: 4-way interleaved ---");
            a.tweak_init(&k, &ref_tweak);

            let batch = 16usize;
            let mut bufs = vec![[0u8; 32]; batch];
            let mut ptrs: Vec<*mut u8> = bufs.iter_mut().map(|b| b.as_mut_ptr()).collect();

            // Warm up
            for _ in 0..1000 { a.encrypt_batch(&mut ptrs); }

            let batch_iters: u64 = 2_000_000;
            let start = std::time::Instant::now();
            for _ in 0..batch_iters {
                a.encrypt_batch(&mut ptrs);
            }
            let elapsed = start.elapsed();
            let total_ops = batch_iters * batch as u64;
            let ns_per_op = elapsed.as_nanos() as f64 / total_ops as f64;
            let mops = 1e9 / ns_per_op / 1e6;
            println!("Batch encrypt ({}×): {:.1} ns/op  ({:.2} M ops/sec)  [{} total ops]",
                batch, ns_per_op, mops, total_ops);

            // Batch decrypt
            a.prepare_decrypt();
            for _ in 0..1000 { a.decrypt_batch(&mut ptrs); }
            let start = std::time::Instant::now();
            for _ in 0..batch_iters {
                a.decrypt_batch(&mut ptrs);
            }
            let elapsed = start.elapsed();
            let ns_per_op = elapsed.as_nanos() as f64 / total_ops as f64;
            let mops = 1e9 / ns_per_op / 1e6;
            println!("Batch decrypt ({}×): {:.1} ns/op  ({:.2} M ops/sec)  [{} total ops]",
                batch, ns_per_op, mops, total_ops);

            // ---- Verify batch vs single consistency ----
            println!("\n--- Batch vs Single consistency check ---");

            // Sanity: single roundtrip of one block
            a.tweak_init(&k, &ref_tweak);
            let mut san = [0u8; 32];
            san[0] = 0xAB; san[1] = 0xCD; san[2] = 0x07;
            a.encrypt(&mut san);
            let enc_snap = [san[0], san[1], san[2]];
            a.prepare_decrypt();
            a.decrypt(&mut san);
            println!("Sanity single: enc=[{:02x} {:02x} {:02x}] dec=[{:02x} {:02x} {:02x}] {}",
                enc_snap[0], enc_snap[1], enc_snap[2],
                san[0], san[1], san[2],
                if san[0]==0xAB && san[1]==0xCD && san[2]==0x07 {"OK"} else {"FAIL"});

            a.tweak_init(&k, &ref_tweak);

            // Encrypt 16 distinct plaintexts with single-block API
            // For t>0, byte n (the extra bits) must fit in t bits
            let e_mask: u8 = if a.t > 0 { (1u8 << a.t) - 1 } else { 0 };
            let mut single_enc = vec![[0u8; 32]; batch];
            for i in 0..batch {
                single_enc[i][0] = (i * 7 + 3) as u8;
                single_enc[i][1] = (i * 13 + 5) as u8;
                if a.t > 0 {
                    single_enc[i][a.n] = ((i * 17 + 11) as u8) & e_mask;
                }
            }
            let plaintexts: Vec<[u8; 32]> = single_enc.clone();
            for buf in single_enc.iter_mut() {
                a.encrypt(buf);
            }

            // Encrypt same plaintexts with batch API
            let mut batch_enc = plaintexts.clone();
            ptrs = batch_enc.iter_mut().map(|b| b.as_mut_ptr()).collect();
            a.encrypt_batch(&mut ptrs);

            // Compare
            let enc_match = single_enc.iter().zip(batch_enc.iter())
                .enumerate()
                .all(|(_, (s, b))| s[..3] == b[..3]);
            println!("Encrypt batch==single: {}", if enc_match { "OK" } else { "FAIL" });

            // Decrypt single_enc with single-block API
            a.prepare_decrypt();
            for buf in single_enc.iter_mut() {
                a.decrypt(buf);
            }
            let cmp_len = if a.t > 0 { a.n + 1 } else { a.n };
            let single_dec_ok = single_enc.iter().zip(plaintexts.iter())
                .enumerate()
                .all(|(i, (dec, pt))| {
                    let ok = dec[..cmp_len] == pt[..cmp_len];
                    if !ok {
                        print!("  MISMATCH block {}: dec=[", i);
                        for b in &dec[..cmp_len] { print!("{:02x} ", b); }
                        print!("] pt=[");
                        for b in &pt[..cmp_len] { print!("{:02x} ", b); }
                        println!("]");
                    }
                    ok
                });

            // Decrypt batch ciphertexts with batch API
            ptrs = batch_enc.iter_mut().map(|b| b.as_mut_ptr()).collect();
            a.decrypt_batch(&mut ptrs);
            let batch_dec_ok = batch_enc.iter().zip(plaintexts.iter())
                .all(|(dec, pt)| dec[..cmp_len] == pt[..cmp_len]);

            println!("Decrypt single roundtrip: {}", if single_dec_ok { "OK" } else { "FAIL" });
            println!("Decrypt batch  roundtrip: {}", if batch_dec_ok { "OK" } else { "FAIL" });

            // Cross-check: encrypt with batch, decrypt with single (and vice versa)
            let mut cross1 = plaintexts.clone();
            ptrs = cross1.iter_mut().map(|b| b.as_mut_ptr()).collect();
            a.tweak_init(&k, &ref_tweak);
            a.encrypt_batch(&mut ptrs);
            a.prepare_decrypt();
            for buf in cross1.iter_mut() {
                a.decrypt(buf);  // single decrypt of batch-encrypted
            }
            let cross1_ok = cross1.iter().zip(plaintexts.iter())
                .all(|(dec, pt)| dec[..cmp_len] == pt[..cmp_len]);
            println!("Batch enc → single dec:  {}", if cross1_ok { "OK" } else { "FAIL" });

            let mut cross2 = plaintexts.clone();
            a.tweak_init(&k, &ref_tweak);
            for buf in cross2.iter_mut() {
                a.encrypt(buf);  // single encrypt
            }
            a.prepare_decrypt();
            ptrs = cross2.iter_mut().map(|b| b.as_mut_ptr()).collect();
            a.decrypt_batch(&mut ptrs);  // batch decrypt of single-encrypted
            let cross2_ok = cross2.iter().zip(plaintexts.iter())
                .all(|(dec, pt)| dec[..cmp_len] == pt[..cmp_len]);
            println!("Single enc → batch dec:  {}", if cross2_ok { "OK" } else { "FAIL" });
        }
    }
}
