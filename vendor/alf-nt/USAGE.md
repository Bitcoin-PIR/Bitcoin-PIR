# ALF-n-t Rust Library

Rust implementation of format-preserving encryption (FPE) using the ALF cipher family.
Encrypts values in an arbitrary domain `[0, Qmax]` to the same domain — a small-domain pseudorandom permutation (PRP).

Based on the paper:
> **Introducing the ALF family: AES-NI-based length- and format-preserving encryption**
> Dachao Wang, Alexander Maximov, Thomas Johansson
> https://eprint.iacr.org/2025/2148

## Requirements

- **Platform**: aarch64 (Apple Silicon / ARM64) with NEON + AES + PMULL crypto extensions, or x86_64 with AES-NI + SSE4.1 (+ optional AVX-512 VAES), or **wasm32** (software AES fallback)
- **Rust edition**: 2021, stable toolchain

## Add as dependency

```toml
# Cargo.toml
[dependencies]
alf-nt = { path = "../alf-rust" }
# or publish to a registry and use: alf-nt = "0.1.0"
```

## Quick start

```rust
use alf_nt::bigint::M192i;
use alf_nt::alf_nt::AlfNt;
use alf_nt::ktm::Ktm;

fn main() {
    unsafe {
        // 1. Define the domain: Qmax = 2^27 - 1  (134M element domain)
        let bit_width = 27u32;
        let mut qmax = M192i::set_pwr2(bit_width);
        qmax.subc(1);

        // 2. Create engine and initialize for this domain
        let mut engine = AlfNt::new();
        engine.engine_init(qmax, 0); // 0 = auto-detect bit_width from qmax

        // 3. Key setup (128-bit key + 64-bit application ID)
        let key: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let app_id: u64 = 0;
        let mut ktm = Ktm::new();
        engine.key_init(&mut ktm, &key, app_id);

        // 4. Tweak setup (128-bit tweak — can be changed per message)
        let tweak: [u8; 16] = [0u8; 16];
        engine.tweak_init(&ktm, &tweak);

        // 5. Encrypt: write plaintext into a 32-byte buffer, encrypt in-place
        let mut buf = [0u8; 32];
        buf[0] = 42; // plaintext value = 42
        engine.encrypt(&mut buf);

        // Read ciphertext (little-endian, first n bytes + t bits)
        let ct = buf[0] as u32 | (buf[1] as u32) << 8
               | (buf[2] as u32) << 16 | (buf[3] as u32) << 24;
        println!("Enc(42) = {}", ct); // guaranteed: ct < 2^27

        // 6. Decrypt: prepare for decryption, then decrypt
        engine.prepare_decrypt();
        engine.decrypt(&mut buf);
        let pt = buf[0] as u32 | (buf[1] as u32) << 8
               | (buf[2] as u32) << 16 | (buf[3] as u32) << 24;
        assert_eq!(pt, 42);
    }
}
```

## API reference

### `M192i` — 192-bit unsigned integer

Used to represent Qmax (the maximum domain value).

```rust
M192i::set_pwr2(27)           // 2^27
M192i::set1(999_999)          // from u64
qmax.subc(1)                  // subtract: 2^27 - 1
qmax.addc(1)                  // add
qmax.mulc(10)                 // multiply by u64
qmax.divremc(10)              // divide, returns remainder
qmax.bitwidth()               // number of significant bits
qmax.is_zero()
qmax.as_bytes() / M192i::from_bytes(&bytes)
```

### `AlfNt` — the cipher engine

```rust
// Lifecycle (all methods are unsafe — they use SIMD intrinsics)
let mut engine = AlfNt::new();

// Phase 1: engine_init — sets n, t, rounds based on domain
//   bit_width=0 means auto-detect from qmax
engine.engine_init(qmax, bit_width);

// Phase 2: key_init — derives round keys via KTM+SMAC
let mut ktm = Ktm::new();
engine.key_init(&mut ktm, &key_16bytes, app_id_u64);

// Phase 3: tweak_init — applies tweak to round keys (repeatable)
engine.tweak_init(&ktm, &tweak_16bytes);

// Encrypt / Decrypt (in-place on a 32-byte buffer)
engine.encrypt(&mut buf);       // after tweak_init
engine.prepare_decrypt();       // convert round keys for decryption
engine.decrypt(&mut buf);       // after prepare_decrypt

// To re-encrypt after decrypting: call tweak_init again
engine.tweak_init(&ktm, &tweak);
engine.encrypt(&mut buf);
```

### Buffer layout

The 32-byte buffer stores the value in **little-endian** byte order:

```
buf[0..n]   →  X part (the main n bytes)
buf[n]      →  E part (the extra t bits, in the low t bits of this byte)
buf[n+1..32] → unused (zeroed)
```

For a 27-bit value (n=3, t=3), the value `v` is stored as:
```rust
buf[0] = (v & 0xFF) as u8;
buf[1] = ((v >> 8) & 0xFF) as u8;
buf[2] = ((v >> 16) & 0xFF) as u8;
buf[3] = ((v >> 24) & 0x07) as u8;  // only low 3 bits (t=3)
```

### Batch API (4-way interleaved)

For high throughput, encrypt/decrypt multiple independent blocks simultaneously.
The 4-way interleaving hides AES pipeline latency, achieving ~3.5x speedup:

```rust
// Prepare 16 independent buffers
let mut bufs = vec![[0u8; 32]; 16];
// ... fill each buf with a plaintext value ...

// Collect mutable pointers
let mut ptrs: Vec<*mut u8> = bufs.iter_mut().map(|b| b.as_mut_ptr()).collect();

// Encrypt all 16 in parallel (processed in groups of 4)
engine.encrypt_batch(&mut ptrs);

// For decryption:
engine.prepare_decrypt();
engine.decrypt_batch(&mut ptrs);
```

## Choosing the domain

| Use case | Qmax | Setup |
|---|---|---|
| Binary power-of-2 | 2^n - 1 | `M192i::set_pwr2(n); qmax.subc(1);` |
| Credit card (10^16) | 10^16 - 1 | `M192i::set1(10_000_000_000_000_000 - 1);` |
| IPv4 (2^32) | 2^32 - 1 | `M192i::set_pwr2(32); qmax.subc(1);` |
| Custom range [0, N) | N - 1 | `M192i::set1(N - 1);` |
| Large (e.g. 2^102-98) | 2^102 - 98 | `M192i::set_pwr2(102); qmax.subc(98);` |

**Binary domains** (Qmax = 2^k - 1) use the fast path — no rejection sampling.
**Non-binary domains** use cycle-walking and are slightly slower (variable time per element).

## Cipher parameters (auto-selected)

| n (bytes) | bit range | rounds (t=0) | rounds (t>0) |
|---|---|---|---|
| 2 | 16-23 | 20 | 28 |
| 3 | 24-31 | 16 | 24 |
| 4 | 32-39 | 14 | 20 |
| 5 | 40-47 | 14 | 18 |
| 6 | 48-55 | 14 | 18 |
| 7 | 56-63 | 14 | 16 |
| 8-9 | 64-79 | 12 | 14 |
| 10-11 | 80-95 | 12 | 14 |
| 12-15 | 96-127 | 12 | 14 |

## Performance (Apple M-series, single core)

| Config | Single (ns/op) | Batch 4-way (ns/op) | Throughput |
|---|---|---|---|
| ALF-2-7b (23-bit, r=28) | ~83 | ~23 | 43 M ops/sec |
| ALF-3-3b (27-bit, r=24) | ~72 | ~20 | 50 M ops/sec |
| ALF-2-0b (16-bit, r=20) | ~60 | ~17 | 59 M ops/sec |

Full-domain permutation of 2^27 (134M) elements: ~2.7s with batch API.

### WASM performance (software AES)

Benchmarked via wasmtime (WASI) and Chrome V8 (browser):

| Config | Wasmtime (ns/op) | Chrome V8 (ns/op) | Native (ns/op) |
|---|---|---|---|
| ALF-2-0b (16-bit, r=20) | ~500 | ~1225 | ~60 |
| ALF-2-7b (23-bit, r=28) | ~2458 | ~2343 | ~83 |
| ALF-4-0b (32-bit, r=14) | ~369 | ~901 | — |
| ALF-8-0b (64-bit, r=12) | ~316 | ~781 | — |

Decrypt is ~2x slower than encrypt in software (InvMixColumns requires GF(2^8) multiply by 9/11/13/14 vs just xtime for forward).

## Building

```bash
cargo build --release

# Run tests and benchmarks
cargo run --release
```

### Build configuration

`.cargo/config.toml` enables the required platform crypto extensions:
```toml
[target.aarch64-apple-darwin]
rustflags = ["-C", "target-feature=+aes,+neon,+sha2,+sha3"]

[target.x86_64-apple-darwin]
rustflags = ["-C", "target-feature=+aes,+ssse3,+sse4.1,+pclmulqdq"]

[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "target-feature=+aes,+ssse3,+sse4.1,+pclmulqdq"]
```

### WASM build (wasmtime / WASI)

```bash
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1 --bin wasm-bench
wasmtime target/wasm32-wasip1/release/wasm-bench.wasm
```

### WASM build (browser)

Requires [wasm-pack](https://rustwasm.github.io/wasm-pack/):

```bash
cd web-bench
wasm-pack build --target web --release
python3 -m http.server 8080
# Open http://localhost:8080/index.html in browser
```

The browser benchmark uses `performance.now()` for high-resolution timing and runs correctness checks before benchmarking.

## Security notes

- ALF is a tweakable block cipher designed for format-preserving encryption
- Key: 128-bit AES key
- Tweak: 128-bit (can encode context: row ID, column ID, timestamp, etc.)
- App ID: 64-bit application identifier mixed into key derivation
- The cipher is a PRP over the domain `[0, Qmax]` — every input maps to a unique output
- Non-binary domains use cycle-walking (rejection sampling), which leaks timing information proportional to `ceil(2^bitwidth / (Qmax+1))`. For most practical domains this ratio is < 2
