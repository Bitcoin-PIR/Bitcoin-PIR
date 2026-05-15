# Bug report to OnionPIRv2: `deserialize_bv_galois_keys` has no bounds-checking → 60 s silent stall on malformed input

**Status:** authored 2026-05-15, superseding two earlier (wrong) drafts of
this file. The earlier drafts blamed the `2402b16` thread-safety patch and
then a hint-pool CPU-thrashing issue. **Both were wrong.** A full
gdb + byte-level trace on pir1 found the real cause. This doc is the
corrected, final version.

**Audience:** the OnionPIRv2 AI agent. Self-contained.

**TL;DR:** `(anonymous namespace)::deserialize_bv_galois_keys` in
`src/onion_ffi.cpp` reads `num_keys`, `num_cts`, `poly` as raw `u32`s
from the wire and loops on them with **zero validation**. When the
input byte stream is malformed (truncated / mis-framed by the
*caller's* transport — a separate BitcoinPIR-side bug, see §4), the
first `u32` is garbage (observed: `0x0410a15e` = 67,936,606) and the
function spends **55–60 seconds** in `vector::assign` (memset) +
`malloc`/`free` before either finishing or OOM-ing. The downstream
symptom is a 60 s "key registration" that then makes every
`answer_query` return empty.

**The ask:** add cheap sanity bounds-checks to
`deserialize_bv_galois_keys` and `deserialize_gsw_ct` (and ideally the
other `deserialize_*` helpers) so malformed input fails **fast and
loud** (`throw std::runtime_error`) instead of stalling for a minute.
This is defense-in-depth — it doesn't fix the malformed input, but it
turns a silent 60 s hang into an instant, debuggable error.

---

## 1. Evidence: gdb backtrace pins the stall

pir1 (Intel i7-8700, Ubuntu 24.04) running an OnionPIRv2 `2402b16`
build. A client registers keys; the server's worker thread stalls
~60 s. Six gdb backtraces of the worker thread (LWP 6650), 9 s apart,
captured during the stall — ALL show:

```
Thread 14 (LWP 6650 "unified_server"):
#0  (anonymous namespace)::deserialize_bv_galois_keys(unsigned char const*, unsigned long)
#1  onion_key_store_set_galois_keys
#2  std::sys::backtrace::__rust_begin_short_backtrace
...
```

Snapshot 5 caught it inside `__memset_avx2_unaligned_erms` (called
from `std::vector::assign`); snapshot 6 inside `munmap` / `__libc_free`
(the `.cold` path of the same function). So the 60 s is: allocate a
huge buffer → memset it → free it → repeat. Classic "looping on a
garbage count" signature.

Server-side instrumentation confirmed the split:
`set_galois=55.17 s, set_gsw=0.70 s` — almost all of it in the galois
deserialize.

## 2. Evidence: the input byte stream is malformed

We instrumented both ends with a 16-byte head dump.

**Client side** — what `Client::galois_keys()` produces and the
caller hands to the transport:

```
[PIR-DIAG] register_keys: galois=2621564B head=[0a 00 00 00 01 08 00 00 08 00 00 00 00 08 00 00]
```

`0a 00 00 00` = `num_keys = 10` ✓ (= `TREE_HEIGHT`).
`01 08 00 00` = `galois_k = 2049` ✓ (first expansion key).
`08 00 00 00` = `num_cts = 8`, `00 08 00 00` = `poly = 2048` ✓.
Total `2,621,564 B` = `4 + 10 × (12 + 8 × 2 × 2048 × 8)` ✓ —
a perfectly well-formed `serialize_bv_galois_keys` output.

**Server side** — what `onion_key_store_set_galois_keys` received:

```
client 1 RegisterKeys recv: galois=379022B head=[5e a1 10 04 01 00 00 00 8e c8 05 00 ...]
```

`379,022 B`, not `2,621,564 B` — the blob is **truncated to ~14 %**.
And it starts with `5e a1 10 04` — `deserialize_bv_galois_keys` reads
that as `num_keys = 0x0410a15e = 67,936,606` and loops 67 million
times.

So the deserializer is fed garbage. It has no way to know — but it
*could* notice the garbage is implausible and bail.

## 3. The ask: bounds-check the deserializers

`deserialize_bv_galois_keys` (`src/onion_ffi.cpp:156`) currently:

```cpp
bvks::BvGaloisKeys deserialize_bv_galois_keys(const uint8_t *data, size_t len) {
    Reader r(data, len);
    const uint32_t num_keys = r.u32();
    bvks::BvGaloisKeys keys;
    keys.keys.reserve(num_keys);            // ← reserve(67 million)
    for (uint32_t i = 0; i < num_keys; i++) {
        bvks::BvKeySwitchKey ksk;
        ksk.galois_k = r.u32();
        const uint32_t num_cts = r.u32();
        const uint32_t poly = r.u32();
        ksk.cts.resize(num_cts);            // ← resize(garbage)
        for (uint32_t j = 0; j < num_cts; j++) {
            ksk.cts[j].a.assign(poly, 0);   // ← assign(garbage, 0): memset
            ksk.cts[j].b.assign(poly, 0);
            r.u64_array(ksk.cts[j].a.data(), poly);
            r.u64_array(ksk.cts[j].b.data(), poly);
        }
        keys.keys.push_back(std::move(ksk));
    }
    return keys;
}
```

`Reader::u32()` / `Reader::u64_array()` already throw on short reads
(`has(n)` check) — so the function *does* eventually fail. But with a
67 M `num_keys` and a `poly` that's also garbage, each iteration
allocates+memsets a multi-MB buffer before the Reader runs out of
bytes. That's the 60 s.

Proposed fix — validate the counts against `len` up front and as you
go. The total serialized size is exactly derivable:

```cpp
bvks::BvGaloisKeys deserialize_bv_galois_keys(const uint8_t *data, size_t len) {
    Reader r(data, len);
    const uint32_t num_keys = r.u32();
    // A galois-key set is TREE_HEIGHT entries; even a generous cap of
    // 1024 is ~100x headroom. Reject obvious garbage before reserve().
    if (num_keys > 1024)
        throw std::runtime_error("deserialize_bv_galois_keys: implausible num_keys "
                                 + std::to_string(num_keys));
    bvks::BvGaloisKeys keys;
    keys.keys.reserve(num_keys);
    for (uint32_t i = 0; i < num_keys; i++) {
        bvks::BvKeySwitchKey ksk;
        ksk.galois_k = r.u32();
        const uint32_t num_cts = r.u32();
        const uint32_t poly = r.u32();
        // num_cts is L_KS (≤ 16 realistically); poly is N*K (≤ 8192).
        if (num_cts > 64 || poly > 1u << 20)
            throw std::runtime_error("deserialize_bv_galois_keys: implausible "
                                     "num_cts/poly");
        // Total bytes still to read for this key must fit in `len`.
        const size_t need = static_cast<size_t>(num_cts) * poly * 2 * sizeof(uint64_t);
        if (!r.has(need))
            throw std::runtime_error("deserialize_bv_galois_keys: truncated key body");
        ksk.cts.resize(num_cts);
        for (uint32_t j = 0; j < num_cts; j++) {
            ksk.cts[j].a.assign(poly, 0);
            ksk.cts[j].b.assign(poly, 0);
            r.u64_array(ksk.cts[j].a.data(), poly);
            r.u64_array(ksk.cts[j].b.data(), poly);
        }
        keys.keys.push_back(std::move(ksk));
    }
    return keys;
}
```

The same treatment for `deserialize_gsw_ct` (`onion_ffi.cpp:190`):
cap `num_rows` and `row_size`, and `r.has(num_rows * row_size * 8)`
before the loop. (On pir1 the gsw blob was also malformed —
`5e a1 10 04` → `num_rows = 67 M`, `row_size = 1` — but `row_size=1`
made it "only" 0.7 s instead of 55 s. Still wrong, still worth
guarding.)

With these checks, a malformed blob throws in microseconds. The
existing `catch (...)` in `onion_key_store_set_galois_keys` already
swallows the throw and the FFI returns cleanly — so no API change,
no behavior change for well-formed input. Just: fast failure instead
of a 60 s hang.

Suggested cap rationale (tune to taste): `num_keys ≤ 1024`,
`num_cts ≤ 64`, `poly ≤ 2²⁰`. All are >50× the real values for every
shipped `ACTIVE_CONFIG`, so no real input is ever rejected.

## 4. The OTHER half of the bug is on BitcoinPIR's side (not yours)

To be clear: **the malformed input is BitcoinPIR's fault, not
OnionPIRv2's.** The client serializes a perfect 2,621,564-byte blob;
something in BitcoinPIR's WebSocket / encrypted-channel transport
truncates the ~3.1 MB `RegisterKeys` message (2.6 MB galois +
0.5 MB gsw) down to ~0.71 MB before it reaches the FFI. That is being
tracked + fixed on the BitcoinPIR side
(`docs/PIR1_REGISTER_KEYS_TRUNCATION.md`).

The reason this is still worth an upstream change: a robust
deserializer should never spend 60 s of CPU on bad input. If the
bounds-checks had been there, this entire multi-hour debugging
session would have been a 1-minute "deserialize threw: implausible
num_keys" log line. Defense-in-depth pays for itself.

## 5. What is NOT being asked

- No change to `serialize_*` — the wire format is fine.
- No change to the thread-safety patch (`2402b16`) — it is sound and
  the `parallel_answer_query_via_shared_keystore` test still passes.
- No API / ABI change.

If you add the bounds-checks, please bump a tag/commit and reply with
the SHA; BitcoinPIR will pick it up alongside the transport fix.
