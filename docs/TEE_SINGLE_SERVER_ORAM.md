# Single-Server, TEE-Only Mode via Oblivious Lookup (ORAM Analysis)

**Status:** advisory / design analysis, 2026-06-12. No code changes yet.

## Question

Today the HarmonyPIR deployment gives "TEE **OR** non-colluding": pir1
(Hetzner, no SEV) serves hints + queries, pir2 (VPSBG, SEV-SNP Tier 3)
serves the query phase inside an attested TEE
([runtime/src/bin/unified_server.rs:126-132](../runtime/src/bin/unified_server.rs)).
Privacy holds if *either* the two operators don't collude *or* the TEE
is sound. Should we add a mode that assumes **only** the TEE — one
server, no non-collusion arm — using an ORAM inside the enclave?

## Verdict (TL;DR)

1. **Yes, build it — as a fourth backend, not a replacement.** It
   completes the trust-assumption spectrum (2-server IT-secure →
   2-server+TEE hedge → 1-server lattice-crypto → 1-server hardware)
   and collapses client cost to one round trip and a few KB.
2. **Don't start with a tree ORAM.** At our database scale (~10⁶
   entries, low hundreds of MB), an **oblivious linear scan** inside
   the SEV-SNP guest — the degenerate, trivially-oblivious ORAM — is
   faster in absolute terms, radically simpler, and *more* robust to
   SEV's side-channel profile than Path/Circuit ORAM. Define the wire
   interface so a doubly-oblivious ORAM (ZeroTrace/Oblix-style) can
   replace the scan kernel transparently if the database ever grows
   ~100×.
3. **The same work hardens the existing deployment.** The HarmonyPIR
   query phase dereferences `T−1` client-chosen plaintext row indices
   *inside* the guest; SEV-SNP encrypts memory contents but not access
   patterns, so the host can recover that index set at page
   granularity (controlled-channel / SEV-Step class attacks). The "TEE
   arm" of TEE-OR-noncolluding is therefore weaker than stated for
   HarmonyPIR today (DPF is fine — DPF evaluation is a full scan by
   construction). An oblivious lookup kernel repairs this even if we
   never ship the single-server mode.
4. **It closes the admitted UTXO-count leak.** Fixed-size encrypted
   responses cost response *bytes*, not 16× PIR *work* — the reason
   the M=16 chunk pad was removed (CLAUDE.md, Phase 4) does not apply
   here.

## 1. Trust-model landscape

| Backend | Servers | Privacy assumption | Client cost / batch |
|---|---|---|---|
| DPF-PIR | 2 | non-collusion (IT-secure); TEE on server-2 removes its operator | ~500 KB up / ~420 KB down, 19 rounds |
| HarmonyPIR | 2 roles | non-collusion **OR** TEE on query server (but see §3) | ~200–300 KB + 40 MB hint download, 20 rounds |
| OnionPIR | 1 | RLWE hardness | ~17.4 MB up / ~7.2 MB down, 10 rounds |
| **TEE-oblivious (proposed)** | **1** | **SEV-SNP confidentiality only** | **~KB up / fixed ~KB down, 1 round** |

(Byte/round figures: [docs/WIRE_ROUND_AND_BYTE_INVENTORY.md](WIRE_ROUND_AND_BYTE_INVENTORY.md).)

"TEE-only" is a strictly *smaller* defense-in-depth than
"TEE OR non-colluding" — one SEV-SNP confidentiality break and privacy
is gone, with no fallback. Two honest counterpoints:

- For users who believe pir1 and pir2 share an operator (see
  [docs/OPERATOR_IDENTITY.md](OPERATOR_IDENTITY.md)), the
  non-collusion arm is already discounted; for them TEE-only is the
  *truthful* model and the 2-server machinery is pure overhead.
- The proposed design needs a *narrower* TEE property than the current
  deployment does. Because data access is oblivious by construction,
  we only need SEV-SNP to keep the channel key and request plaintext
  confidential (register state + a few KB of guest memory). We do
  **not** need it to hide access patterns — which is precisely the
  property SEV-SNP does not deliver (§3).

Recommendation: ship as an additional user-selectable backend (the
Electrum plugin already has a protocol selector), keep DPF/Onion for
users who reject hardware trust.

## 2. Why "TEE-only" forces obliviousness

Moving to a single server makes the host the *only* adversary, and
SEV-SNP's adversary model gives that host:

- **Page-granular access traces** — the hypervisor controls nested
  page tables and can fault/single-step the guest (controlled-channel,
  SEV-Step). 4 KiB pages over 13–168 B rows ⇒ ~24–300-row ambiguity,
  far below query privacy.
- **Cache side channels** — standard Prime+Probe etc.; SEV has no
  enclave-style cache partitioning.
- **Ciphertext side channels** (CipherLeaks class) — SEV memory
  encryption is deterministic per physical address, so the host can
  detect when a location is rewritten with an identical value. Any
  in-place secret-dependent write must be freshly randomized
  (AEAD-seal with a new nonce) before it hits guest-shared or
  swappable memory; in-guest private memory writes are encrypted by
  hardware but equality-of-block still leaks to a host that reads
  ciphertext pages.

So a naive "decrypt query in TEE, index into the table" leaks the
queried row to the host. Every lookup the enclave performs against the
database must be **data-independent** — that is the ORAM requirement,
and it applies to the enclave's own metadata accesses too ("doubly
oblivious", per Oblix/ZeroTrace).

## 3. The same gap exists in today's TEE arm (HarmonyPIR)

The HarmonyPIR online server receives `T−1` sorted plaintext u32
indices per group and reads exactly those rows
([docs/WIRE_ROUND_AND_BYTE_INVENTORY.md](WIRE_ROUND_AND_BYTE_INVENTORY.md),
"Per-group request payload"). Inside the TEE those indices arrive via
the X25519 channel, so the host can't read them — but it can watch
which pages the guest touches. With INDEX bucket rows of w=168 B,
a 4 KiB page covers ~24 rows; the `T−1 ≈ 511` touched indices map to
≤511 identifiable pages out of ~10,750 per bucket. That is most of the
information the query server was supposed to be *allowed* to see only
under non-collusion. Consequence: a pir2 host that also colludes with
the hint-server operator defeats HarmonyPIR despite the TEE — the
exact scenario the TEE arm was meant to neutralize
([pdf/part3_2server.tex](../pdf/part3_2server.tex) §"What the TEE
Changes" claims collusion is "harmless"; §"Scope and Limitations"
already caveats side channels).

DPF on pir2 is unaffected: DPF evaluation XOR-scans every row of every
group per query, which is trivially oblivious. Merkle sibling serving
under Harmony has the same `T−1`-indices shape as the query phase and
shares the gap.

**Takeaway:** an oblivious lookup kernel is not just the enabler for a
new mode — it is the fix that makes the *existing* "TEE OR
non-colluding" claim hold against a side-channel-capable host.

## 4. Mechanism choice: scan vs. tree ORAM

### Option A — oblivious linear scan (recommended now)

Per batch: the enclave sweeps the entire flat table once; for each
element it executes a branchless (cmov-style) tag comparison against
all B queries and conditionally accumulates the payload. Every byte of
the table is touched on every batch ⇒ no access-pattern signal at any
granularity (page, cache line, ciphertext block). Only the comparison
must be constant-time.

Scale check against our data
([pir-core/src/params.rs](../pir-core/src/params.rs)): INDEX ≈ 565 K
bins × 52 B ≈ 30 MB; CHUNK ≈ 1.06 M bins × 132 B ≈ 140 MB. A ~170 MB
sweep at ≥10 GB/s memory bandwidth is **~15–20 ms per batch**, and one
sweep serves the whole batch (B comparators per element are ALU-cheap;
the sweep is bandwidth-bound). Two-phase lookup (INDEX then CHUNK) =
two sweeps. Compare: OnionPIR server compute per batch is seconds, and
HarmonyPIR needs a 40 MB offline hint phase. The scan also handles
delta databases (small flat tables) and the ~10-minute rebuild cadence
trivially — regenerating a flat sorted table is the cheapest of all
four backends (no NTT, no hints).

### Option B — doubly-oblivious tree ORAM (ZeroTrace / Oblix style)

Path/Circuit ORAM gives O(log² N) blocks per access (~5 KB touched per
lookup at N=2²⁰) instead of a full sweep — but requires: an oblivious
position map (itself recursively ORAM'd or linearly scanned), an
oblivious stash (every stash access must be a full constant-time
sweep of the stash), write-back on every read, serialization of all
accesses through one ORAM controller (concurrency needs Snoopy-style
oblivious load balancing), and careful re-randomization of every
written block to defeat the ciphertext side channel. The crossover
where this beats a scan is roughly when
`sweep_time > accesses_per_batch × path_time` — at 170 MB vs ~5 KB ×
(2 levels × B), the scan wins for any realistic batch until the table
is **multiple GB**. The dust/whale filtering policy
([pdf/part7_deployment.tex](../pdf/part7_deployment.tex) §"Dust
filtering") is what keeps us far from that regime.

### Option C — oblivious batched join (bitonic sort, Snoopy buckets)

Sort-based oblivious joins amortize well only for batch sizes
approaching table size; irrelevant at B ≤ a few hundred.

**Decision:** Option A, with the request/response protocol and handler
trait defined over an abstract `ObliviousLookup` so Option B can be
slotted in later without a wire change.

## 5. What the mode buys

Everything in CLAUDE.md's "CRITICAL SECURITY REQUIREMENTS" exists
because the server *sees query structure*. In this mode the server
sees an opaque AEAD pipe, so for this backend (and only this backend):

- No K=75 / K_CHUNK=80 padded groups, no cuckoo double-probe wire
  symmetry, no PBC planning, no Merkle item-count symmetry, no
  CHUNK-round-presence machinery. The simulator property reduces to
  "fixed-size request in, fixed-size response out, constant time".
- **The Phase-4 admitted leak closes.** Per-query UTXO count is hidden
  by padding the *encrypted response* to a fixed R chunks (e.g. R=16
  ⇒ 16×44 B = 704 B per query slot). The original objection to M=16
  padding — 16× chunk-layer PIR work pinning the batch ceiling at
  ~K_CHUNK/16 — does not apply: here padding costs only ciphertext
  bytes.
- Client: one attested round trip; no hint download/refresh lifecycle;
  no SEAL, no DPF, no WASM heavy path — trivially portable to
  wasm32 and the Electrum plugin.

What must still be enforced (the new, much shorter invariant list):

1. **Fixed-size requests** (B_max query slots, dummy-padded by the
   client) and **fixed-size responses** (B_max × R chunk slots) — the
   host sees ciphertext lengths.
2. **Constant-rate processing** — the sweep takes the same time
   regardless of hit pattern; respond on a fixed schedule to blunt
   timing.
3. **Fresh-nonce sealing of every outbound frame** (already what
   `pir-channel`'s ChaCha20-Poly1305 session does) and no
   secret-dependent in-place plaintext writes, per the ciphertext
   side channel.
4. **Keep client-side Merkle verification against R\*.** The
   attestation already binds the super-root
   (`REPORT_DATA = SHA256("BPIR-ATTEST-V2" ‖ … ‖ R* ‖ …)`,
   [pir-sdk-client/src/attest.rs](../pir-sdk-client/src/attest.rs)).
   The enclave returns entry + inclusion proof inline (no leakage —
   the channel is opaque), and the client checks it. This keeps
   integrity and rollback-resistance even if TEE *confidentiality*
   fails, and defends against the host replaying an old database
   image at the enclave: the client compares the attested R\* /
   tip height against the catalog it trusts.

## 6. Honest risk assessment

- **Single point of failure.** SEV-SNP's record includes
  CipherLeaks-class ciphertext channels, SEV-Step single-stepping,
  and BadRAM-class physical attacks (firmware-patched, but
  illustrative). The TCB is large: AMD-SP firmware + microcode + the
  whole measured UKI (kernel, initramfs, binary). Users get one
  assumption, not two. This must be presented plainly in the backend
  selector, mirroring how OnionPIR is presented as "1-server,
  lattice assumption".
- **Mitigated by construction:** because lookups are oblivious and
  framing is fixed-size/constant-rate, the *needed* TEE property
  shrinks to confidentiality of the channel key and in-flight request
  plaintext. Access-pattern, page-fault, and most cache adversaries
  get nothing even on a degraded TEE. That is a meaningfully smaller
  attack surface than the current Harmony-in-TEE arm requires (§3).
- **Operator metadata:** client IP, connection timing, and batch
  cadence remain visible — identical to all existing backends.

## 7. Implementation sketch (this codebase)

Most of the hard infrastructure already exists and carries over
unchanged: attestation with key+R\* binding (`bpir-admin attest`,
`pir-sdk-client/src/attest.rs`), the E2E X25519/ChaCha20-Poly1305
channel (`pir-channel`, `pir-sdk-client/src/channel.rs`,
`SecureChannelTransport`), the catalog / db_id routing, delta sync
planning, and Merkle tree-tops.

New pieces:

1. **`pir-runtime-core`**: an `ObliviousLookup` handler + new opcode
   family (e.g. `TEE_LOOKUP_BATCH`) accepted **only** inside an
   established secure channel; v1 implementation = branchless sweep
   over an mmap'd flat sorted table (one per db_id), fixed-size
   response assembly with inline Merkle proofs.
2. **`runtime/unified_server`**: role flag (e.g.
   `--serve-tee-lookup`), enabled on pir2 Tier 3 only; refuse the
   opcode outside a sealed session.
3. **`build/`**: emit the flat table artifact (the existing cuckoo
   bins already are flat arrays; a plain sorted `(tag, entry)` table
   is simpler and removes cuckoo entirely for this backend).
4. **`pir-sdk-client`**: a `TeeClient` backend beside
   `dpf.rs`/`harmony.rs`/`onion.rs`: attest → establish → send padded
   batch → verify proofs vs R\* → assemble results. WASM binding is
   trivial (no SEAL constraint).
5. **Leakage tests**: byte-identical-profile tests are almost
   degenerate here (every request/response is the same size by
   construction) — assert exactly that, plus a constant-time test on
   the sweep kernel (e.g. `dudect`-style).

Rough order: the sweep kernel + framing is days, not weeks; the bulk
of the effort is the build-artifact plumbing and the constant-rate
response scheduling.

Independently sequenceable hardening (per §3): port the same sweep
kernel under the existing HarmonyPIR query/sibling handlers when
running with `--serve-queries` inside the TEE, so pir2 answers
Harmony's `T−1`-index requests via oblivious selection instead of
direct dereference. Wire format unchanged; restores the intended
strength of the TEE arm.

## 8. Recommendation

Adopt Option A as a fourth backend ("TEE-oblivious", single-server,
hardware-trust), keep the existing three, and apply the oblivious
sweep to the in-TEE Harmony query path regardless. Revisit tree ORAM
only if the post-filter database grows past ~1–2 GB or per-batch
latency budgets drop below the sweep time.
