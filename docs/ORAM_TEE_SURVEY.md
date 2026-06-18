# ORAM-inside-TEE as a Fourth BitcoinPIR Backend — Landscape Survey

*Reader: cryptography/systems PhD level. Goal: pick 1–3 ORAM constructions to
prototype as a fourth backend alongside DPF / OnionPIR / HarmonyPIR.*

The brief: **AMD SEV-SNP gives us encrypted DRAM + launch attestation but
NOT access-pattern privacy** — the host bus, page-fault sequence,
ciphertext side channel, and shared LLC are all still observable by the
hypervisor and co-tenants. Anything we put in the enclave needs to be
data-oblivious *with respect to these channels* on top of whatever
property the ORAM construction itself provides for accesses against
host-resident storage. This survey walks the candidate families,
flags TEE-specific concerns, and ends with a shortlist.

---

## 0. Threat model recap (calibrated to SEV-SNP)

What SEV-SNP gives us for free (vs. SGX or non-TEE deployments):

- DRAM **confidentiality + integrity** of in-VM memory via the AMD-SP
  memory controller (RMP-protected) — we do *not* need to build a Merkle
  tree over enclave RAM the way ZeroTrace did under SGX EPC.
- Launch-time attestation (we already wire this — see
  [docs/VERIFICATION_OVERVIEW.md](VERIFICATION_OVERVIEW.md) and
  `web/src/attest-pin.ts`).
- No EPC size limit. We can have hundreds of GB of guest RAM (vs.
  SGXv1's ~128 MB EPC, which forced ZeroTrace/Oblix to treat any working
  set > EPC as "external memory" with paging-amplification leakage).

What SEV-SNP does **not** give us, and is therefore what the ORAM layer
must handle:

- **Page-fault side channel** (Xu/Cui/Peinado'15 style; replicated for
  SEV in Li et al. and subsequent SNPeek/Heracles/WeSee work — see
  references below). The hypervisor can unmap pages and watch faults at
  4 KB granularity. So we need code that is oblivious at the *page*
  level as well, not just byte-level.
- **Ciphertext side channel** ([Li et al. S&P'22](https://yinqian.org/papers/sp22b.pdf))
  — deterministic encryption of DRAM lines lets the attacker watch
  cache-line-granularity ciphertext changes and learn whether memory at
  address X just got written or not. Mitigations: avoid writing
  secret-dependent values to fixed locations. ORAM constructions that
  rewrite *every* path / every bucket on every access (Path / Ring /
  Circuit) are favored over constructions that update a single
  block-in-place.
- **Cache and LLC side channels** (Prime+Probe still works against an
  SEV guest from a co-tenant, especially across SMT). Forces
  constant-time, data-oblivious in-enclave code — i.e. exactly the
  oblivious-primitives discipline ZeroTrace and Oblix codified.
- **Network/timing side channels** (we have these in DPF/Onion/Harmony
  too; covered by existing K, K_CHUNK padding and round-presence
  invariants in `CLAUDE.md`).

Two consequences for backend choice:

1. The TEE host swap path is poison. Eviction from in-VM RAM to host
   swap is observable to the hypervisor at page granularity; we should
   size the working set to live entirely in guest DRAM, and let the
   ORAM construction handle "external memory" as encrypted blocks the
   in-VM code fetches over an IPC-like channel rather than as a paged
   address space.
2. The in-enclave ORAM controller code must follow ZeroTrace-style
   data-oblivious primitives — every `if (secret)` becomes a CMOV /
   oblivious scan, every memory access touches a fixed address sequence.
   This is a coding discipline, not an algorithm; but it disqualifies
   "just run [X] inside the VM and assume SEV hides everything."

---

## 1. Candidate ORAM families

### 1.1 Path ORAM (Stefanov–van Dijk–Shi et al., CCS'13)

**Mechanism.** Binary-tree of buckets of size Z (typ. 4). Each block is
mapped to a random leaf; invariant: the block lives somewhere on the
path from root to that leaf, or in a small client-side stash. Access(x):
read the entire path to x's current leaf, remap x to a fresh random
leaf, write the whole path back (pushing blocks as deep as the new
leaf-map allows).

**Asymptotics.** O(log N) blocks transferred per access for block size
B = Ω(log² N) bits. Position map is N log N bits → recurse into smaller
Path ORAM ⇒ O(log² N / log χ) blowup overall. Stash is O(log N · ω(1))
with negligible overflow probability for Z = 4 ([Stefanov et al.,
arXiv:1202.5150](https://arxiv.org/abs/1202.5150);
[JACM'18](https://dl.acm.org/doi/10.1145/3177872)).

**Concrete.** For N=2²⁵ blocks of 256 B: per-access bandwidth ≈ Z · L · B
≈ 4 · 25 · 256 B = 25 KB plus recursive position-map traffic
(~3 levels of recursion at χ=8 ⇒ ~2× total). So ~50 KB per single-block
read at our DB scale; latency dominated by sequential round-trip.

**Implementations.** Reference C++ in
[ZeroTrace](https://github.com/sshsshy/ZeroTrace); Rust in
[mc-oblivious](https://github.com/mobilecoinfoundation/mc-oblivious)
(MobileCoin Foundation, audited, used in production for Signal-like
contact discovery on SGX); Rust in
[obliviouslabs/rostl](https://github.com/obliviouslabs/rostl) (Tinoco
et al.). **Strong fit for SEV — every access rewrites a whole path,
which side-steps the ciphertext side channel by maximizing in-place
ciphertext rotation.**

### 1.2 Ring ORAM (Ren–Fletcher–Kwon–Stefanov–Shi–van Dijk–Devadas,
USENIX Sec'15)

**Mechanism.** Variant of Path ORAM with bucket size Z + extra dummy
slots S; per-access only reads *one real block per bucket* online
(O(log N) blocks of bandwidth, but no real data on the rest), defers
the full path-eviction until every A-th access. Server-side XOR trick:
if the server is willing to XOR same-position dummy slots across all
buckets on a path, online bandwidth drops to **O(1)** real blocks
returned to the client.

**Asymptotics.** Same O(log N) total; online bandwidth ≈ **2.3×–4×
better than Path ORAM** ([Ren et al., USENIX'15](
https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-ling.pdf));
~60× when XOR-trick is used and the "server" can compute.

**Implementations.** Reference C++ alongside Path ORAM in
[ZeroTrace](https://github.com/sshsshy/ZeroTrace) and in academic
codebases (FastPRP / FreeCursive ORAM).

**Fit for SEV.** Excellent: the server-side XOR is *free* inside the
enclave (it's just code running in the same SEV VM as the client
proxy), so we get the online-bandwidth-O(1) variant without paying the
two-party-protocol overhead.

### 1.3 Circuit ORAM (Wang–Chan–Shi, CCS'15)

**Mechanism.** Tree-based like Path ORAM but with a tightly designed
deterministic eviction that minimizes *circuit* size (number of MUXes /
non-free gates) — designed for the MPC/garbled-circuit setting where
every operation must be expressed as a constant-depth circuit. The
sequence of reads/writes is fixed given the access count, secret-data
choices are made via oblivious CMOV-equivalents.

**Asymptotics.** O(log N) bandwidth; matches Goldreich-Ostrovsky lower
bound up to constants; **uses ~30× fewer non-free gates than Path
ORAM** at 4 GB / 32-bit blocks ([Wang–Chan–Shi, CCS'15](
https://eprint.iacr.org/2014/672); [Scoram code](
http://wangxiao1254.github.io/SCORAM/)).

**Fit for SEV.** Circuit ORAM's discipline — every secret-dependent
decision compiled to a CMOV — is *exactly* what we want for resisting
the cache + page-fault channels inside the SEV VM. **ZeroTrace
reports Circuit ORAM is more efficient than Path ORAM in their
oblivious-execution setting** ([Sasy–Gorbunov–Fletcher, NDSS'18](
https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_02B-4_Sasy_paper.pdf)).
This is the single strongest candidate as the inner ORAM layer.

### 1.4 OptORAMa (Asharov–Komargodski–Lin–Nayak–Peserico–Shi,
Eurocrypt'20) and the hierarchical line

**Mechanism.** Hierarchical (Goldreich-Ostrovsky) ORAM with a
sequence of buffers of doubling size, periodically rebuilt via oblivious
sort / oblivious tight compaction. OptORAMa is the first construction
matching the Ω(log N) lower bound *with constant-factor-tight constants*
([Springer LNCS 12106](
https://link.springer.com/chapter/10.1007/978-3-030-45724-2_14)).
Subsequent work by [Asharov et al.](
https://link.springer.com/article/10.1007/s00145-023-09447-5)
de-amortizes to worst-case O(log N).

**Asymptotics.** O(log N) amortized, the absolute theoretical optimum.
But the constants — even in the optimized version — are larger than
Path/Circuit ORAM at practical N (~2²⁵ – 2²⁸), because the rebuild
steps involve oblivious sort with non-trivial constants.

**Implementations.** No production-grade implementation that we are
aware of. This is a theory frontier; pragmatic systems still use
tree ORAMs.

**Fit for SEV.** Not first-choice. The rebuild phase is a long burst
of in-enclave work whose page-access pattern, while oblivious by
construction, makes timing variance large (think 100s of ms periodic
hiccups) — bad for an interactive wallet query.

### 1.5 Bucket ORAM (Fletcher–Naveed–Ren–Shi–Stefanov, ePrint'15)

**Mechanism.** Single-online-round, amortized constant overall
bandwidth — combines tree-ORAM and hierarchical-ORAM ideas with an
expensive periodic reshuffle. ([ePrint 2015/1065](
https://eprint.iacr.org/2015/1065)). Worst-case bandwidth is linear in
N due to the reshuffle, so it's amortized-only.

**Fit for SEV.** Same problem as OptORAMa — periodic reshuffle hurts
interactive tail latency. Skip for v1.

### 1.6 Onion ORAM / Onion-Ring ORAM (Devadas–van Dijk–Fletcher–Ren–
Shi–Wichs, TCC'16; Chen–Chillotti–Ren, CCS'19)

**Mechanism.** Constant bandwidth blowup using additively-homomorphic
encryption — the server folds the path computation under the
ciphertext. Onion-Ring uses leveled TFHE to make it actually practical.
([Devadas et al., TCC'16](
https://people.csail.mit.edu/devadas/pubs/onionORAM.pdf);
[Chen–Chillotti–Ren, CCS'19](
https://www.semanticscholar.org/paper/Onion-Ring-ORAM%3A-Efficient-Constant-Bandwidth-RAM-Chen-Chillotti/7fd37a0728b387002ae2319b59dce9a543e80e72)).

**Fit for SEV.** **Don't.** The whole point of Onion ORAM is to push
work onto an untrusted server using FHE so the *client*'s bandwidth
stays constant. Inside a TEE, the server *is* trusted (the SEV VM is
the server) — we'd be paying FHE compute for a property we already
get from running inside the VM. Use plain Ring/Circuit ORAM instead.

### 1.7 ZeroTrace (Sasy–Gorbunov–Fletcher, NDSS'18)

**Mechanism.** Not a new ORAM — a *TEE-specialized implementation* of
Path ORAM + Circuit ORAM with a data-oblivious oblivious-primitives
library (constant-time CMOV-based block compare/swap/copy), recursive
position map, and an in-enclave controller. Targets Intel SGX,
~6,600 LOC C/C++/asm, ~4,000 inside the enclave. Two backends: Path
ORAM and Circuit ORAM. ([Sasy et al., NDSS'18](
https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_02B-4_Sasy_paper.pdf);
[code](https://github.com/sshsshy/ZeroTrace)).

**Concrete.** Reports per-access latency in *milliseconds* at N = 10⁷
blocks; Circuit ORAM beats Path ORAM in their setting.

**Fit for SEV.** This is essentially the blueprint we'd port. The
oblivious primitives (the contents of `enclave/oassert.h`,
`enclave/PathORAM.h` etc.) translate to SEV directly — they don't
depend on SGX intrinsics, just on x86 CMOV. **For a v1 prototype,
porting ZeroTrace's Circuit ORAM backend into the SEV guest is the
shortest path.** Last code commit appears to be 2018 — would need
re-validation against modern compiler optimizations.

### 1.8 Oblix (Mishra–Poddar–Chen–Chiesa–Popa, S&P'18)

**Mechanism.** *Doubly-oblivious* search index: a Path ORAM whose
in-enclave controller is *also* data-oblivious (so even SGX-internal
access patterns leak nothing). Wraps an oblivious AVL tree / oblivious
sorted skip-list on top, giving an oblivious dynamic key→value map with
log-factor overhead over a non-oblivious map. ([Mishra et al., S&P'18](
https://people.eecs.berkeley.edu/~raluca/oblix.pdf);
[blog summary, Colyer](
https://blog.acolyer.org/2018/07/06/oblix-an-efficient-oblivious-search-index/)).

**Fit for SEV.** Directly relevant — our workload *is* a dynamic
key→value lookup (scripthash → UTXO list). The "doubly oblivious"
property is exactly the page-fault / cache side-channel resistance we
need inside the SEV guest.

### 1.9 EnigMap (Tinoco–Gao–Shi, USENIX Sec'23)

**Mechanism.** Oblivious AVL tree map, designed with an *external-
memory* algorithmic model — i.e. minimizing the number of page swaps
between EPC and untrusted DRAM under SGX. Open-source C++ at
[github.com/odslib/EnigMap](https://github.com/odslib/EnigMap).
([Tinoco et al., USENIX'23](
https://www.usenix.org/system/files/usenixsecurity23-tinoco.pdf);
[ePrint 2022/1083](https://eprint.iacr.org/2022/1083)).

**Concrete.** At **N = 256M records** with batch size 1000:
**15× faster than Signal's linear-scan contact-discovery**, **53× faster
than Oblix** (the prior state-of-the-art). Tested on SGX with 192 GB EPC
(Icelake) + 256 GB RAM.

**Fit for SEV.** Best-published key→value oblivious map. The
"external-memory" lens is less critical under SEV than under SGX (SEV
doesn't have EPC eviction at all), so EnigMap should run *even
better* under SEV than under SGX — the algorithm is correct, and we
just don't pay the paging penalty it was optimizing against.
**Strongest candidate** for the directly-usable key→value layer.

### 1.10 Snoopy (Dauterman–Fang–Demertzis–Crooks–Popa, SOSP'21)

**Mechanism.** Multi-client, distributed oblivious storage. Many enclave
"sub-ORAMs" sharded by a logical bucket; an oblivious load-balancer
groups incoming requests into fixed-size batches without revealing the
mapping. Each sub-ORAM is a Path-ORAM-like tree inside an enclave; the
trusted set is the union of all sub-ORAM enclaves and the load
balancers ([Dauterman et al., SOSP'21](
https://nacrooks.github.io/bibliography/publications/2021-sosp-snoopy.pdf);
[ePrint 2021/1280](https://eprint.iacr.org/2021/1280)).

**Concrete.** **92K req/s at 18 machines** with average latency
< 500 ms over 2M × 160-byte objects — **13.7× over Obladi**. The
spike between 8 and 9 machines comes from sharding reducing recursive
position-map levels from 3 to 2.

**Fit for SEV.** **Architecturally the closest match to a wallet-
facing PIR backend**: multi-client by construction; trust assumption
is the union of enclaves (we already trust SEV); scales horizontally,
which matters because OnionPIR's 28–44 GB working set was the
sharding-blocker in the Fly migration. **Snoopy's design is
explicitly TEE-agnostic** ("not tied to Intel SGX, applies to Keystone,
MI6, Sanctum" — SEV is the obvious next port).

Caveat: Snoopy's per-batch latency floor is ~hundreds of ms; for our
1–25-scripthash interactive workload, a single-machine ZeroTrace-style
backend will probably beat it on tail latency, while Snoopy wins at
throughput. We'd run Snoopy if we wanted to serve thousands of
concurrent wallets from one fleet.

### 1.11 PRO-ORAM (Tople–Jia–Saxena, RAID'19)

**Mechanism.** Read-only ORAM, aggressively parallelized, leveraging
SGX to do the shuffle in parallel with reads. Sub-second latency on
gigabyte-sized data, 256 KB blocks. ([Tople et al., RAID'19](
https://www.usenix.org/system/files/raid2019-tople.pdf)).

**Fit for SEV.** Tempting because our workload is mostly read with
occasional batched delta updates — but PRO-ORAM's "writes happen
in a separate phase" model would force us to take the DB offline
during delta application (or run a shadow DB), which complicates the
delta-streaming model we already use. Worth revisiting only if read
latency is the dominant pain point.

### 1.12 Pancake (Grubbs–Khandelwal et al., USENIX Sec'20)

**Mechanism.** *Not* full ORAM — frequency smoothing. Replaces each key
with several encrypted "copies" sized to the steady-state access
frequency of the most popular key, so a passive observer sees uniform
key access. ([Grubbs et al., USENIX'20](
https://www.usenix.org/system/files/sec20-grubbs.pdf);
[ePrint 2020/1501](https://eprint.iacr.org/2020/1501)).

**Concrete.** **229× faster than non-recursive Path ORAM**, within 3–6×
of plaintext baseline on Redis/Memcached.

**Fit for SEV.** Worth comparing as a *baseline* because we know the
Bitcoin scripthash distribution (most addresses are queried rarely,
with a long Zipf-ish tail driven by exchanges and miners). But
Pancake's security is *only against passive observers with stationary
distribution*; an attacker who can observe a long history or
correlate timing learns the access pattern. **Probably too weak for
our threat model** (we're shipping a privacy story that we don't
weaken under active or adaptive adversaries), but useful as a
performance ceiling.

### 1.13 Waffle (Maiyya–Ibrahim–Crooks et al., SIGMOD'24)

**Mechanism.** Online oblivious datastore — replaces ORAM's heavy
machinery with a *cache-of-decoy-accesses* approach that decouples
the access pattern from the workload's natural frequency.
**45–57% faster than Pancake**, **102× faster than TaoStore**
([ePrint 2023/1285](https://eprint.iacr.org/2023/1285.pdf)).

**Fit for SEV.** Same caveat as Pancake — Waffle's security is
weaker than full ORAM (it's an online frequency-smoothing
construction, not a position-map-based ORAM). Mention for
completeness; **prefer ZeroTrace/EnigMap if we want full-strength
obliviousness**.

### 1.14 TaoStore (Sahin–Zakhary–El Abbadi–Lin–Tessaro, S&P'16) and
the multi-client line

**Mechanism.** Multi-client tree-ORAM with a trusted proxy that batches
+ serializes concurrent client requests. Predecessor to Obladi and
Snoopy. ([Sahin et al., S&P'16](
https://sites.cs.ucsb.edu/~rachel.lin/papers/TaoStore-CameraReady.pdf)).

**Fit for SEV.** Superseded by Snoopy on every dimension. Reference
only.

### 1.15 Obladi (Crooks–Burke–Cecchetti–Harel–Agarwal–Alvisi, OSDI'18)

**Mechanism.** ACID transactions on top of oblivious storage, using
epoch-based batching to amortize ORAM overhead. ([Crooks et al.,
OSDI'18](https://www.usenix.org/system/files/osdi18-crooks.pdf)).

**Fit for SEV.** Not relevant — we don't need transactional
guarantees for a read-mostly UTXO snapshot. Useful as a performance
baseline (the number Snoopy beats by 13.7×).

### 1.16 Distributed / 2-server ORAM: Floram (Doerner–Shelat,
CCS'17) and Duoram (Vadapalli–Henry–Goldberg, USENIX Sec'23)

**Mechanism.** Floram uses (2,2) function-secret-sharing to give two
non-colluding servers a sublinear-MPC ORAM. Duoram improves the
asymptotic from O(m√n) to O(m log n) words of communication using a
clever secret-shared dot-product trick. ([Doerner–Shelat, CCS'17](
https://eprint.iacr.org/2017/827.pdf);
[Vadapalli et al., USENIX'23](
https://www.usenix.org/system/files/sec23fall-prepub-339-vadapalli.pdf);
[ePrint 2022/1747](https://eprint.iacr.org/2022/1747)).

**Fit for SEV.** Relevant *as a comparison*: our DPF/Harmony backends
already lean on 2-server PIR; Floram/Duoram are the natural
2-server-ORAM points to benchmark against. But the assumption is
"two non-colluding servers" — we'd need a second SEV host with
attested independence to match. That's the same operational pain we
already have with pir1/pir2 (Hetzner + VPSBG). Maybe — but if we're
deploying 2 SEV hosts anyway, we can use them for ORAM *or* for
existing 2-server PIR; the latter is already shipped.

### 1.17 Oblivious data structures (Wang–Nayak–Liu–Shi, CCS'14)

**Mechanism.** Framework for building oblivious maps / sets / queues /
trees with asymptotically better constants than running a generic
data structure on top of ORAM, by exploiting structural locality
(pointer-following becomes one path traversal). ([Wang et al., CCS'14;
ePrint 2014/185](https://eprint.iacr.org/2014/185.pdf)).

**Fit for SEV.** Foundational — Oblix and EnigMap both build on this
line. The relevant constructions for us are oblivious sorted maps
(scripthash → entry pointer) and oblivious B-trees.

---

## 2. TEE-specific concerns

### 2.1 Page-fault side channel (Xu–Cui–Peinado S&P'15, replicated for
SEV in [Li et al. S&P'22](https://yinqian.org/papers/sp22b.pdf), and
ongoing in [SNPeek NDSS'26](
https://www.ndss-symposium.org/wp-content/uploads/2026-f699-paper.pdf),
[Heracles CCS'25](https://heracles-attack.github.io/Heracles-CCS2025.pdf),
[WeSee](https://arxiv.org/pdf/2404.03526))

The hypervisor can unmap pages from the SEV guest's nested page table
and observe the resulting #VC (or page fault under older SEV) events.
Result: **4 KB-granularity access trace** of the guest's heap. The
ORAM's in-VM controller must therefore touch the *same sequence of
4 KB pages* on every access, regardless of the secret query. That
means:

- The position map (recursive Path ORAM) must scan a fixed sequence of
  pages. The recursion itself is fine, but each level's bucket lookup
  must use an oblivious-scan that *touches every page in that
  level's working set* per access — not a binary search.
- The stash scan is byte-oblivious in the literature; under page-fault
  attacks it must also be *page-oblivious*. Use a fixed page-aligned
  layout and a fixed-stride scan.
- The eviction logic must rewrite every bucket on every path
  *unconditionally*, never an "if-empty-skip" branch.

**Verdict:** Circuit ORAM is the cleanest fit because every operation
in its inner loop is already CMOV-compiled. Path ORAM works if we keep
ZeroTrace's `enclave/PathORAM.h` discipline of oblivious-scan
everywhere.

### 2.2 Ciphertext side channel ([Li et al. S&P'22](
https://yinqian.org/papers/sp22b.pdf))

SEV-SNP uses a *tweaked* XEX mode where the tweak is the physical
address — so a fixed plaintext at a fixed address always re-encrypts
to the same ciphertext. Co-tenant or hypervisor can dump DRAM
ciphertext and watch for *changes* at fixed cache-lines. Implications:

- **Re-encrypt every block touched** under a fresh nonce. Standard
  Path/Ring/Circuit ORAM already does this (the path-write step
  re-encrypts).
- Avoid in-place "this counter just incremented" patterns in
  in-enclave metadata — wrap them in always-rewritten buckets.
- The position map's recursive ORAM has the same property at every
  level.

This is actively researched (Heracles is a chosen-plaintext attack
against SEV-SNP from CCS'25 — see link above). The mitigation lands
inside AMD-SP firmware over time; for now, *we should design as if
the ciphertext channel is open*.

### 2.3 Cache + LLC side channels

Prime+Probe on shared LLC still works against SEV. The
data-oblivious-coding discipline (no secret-indexed memory accesses,
no secret-dependent branches) handles this if we apply it everywhere
in the controller. ZeroTrace's oblivious primitives library is the
template; [DR.SGX](https://arxiv.org/pdf/1709.09917) and
[Obelix](https://arxiv.org/html/2509.18909v1) explore stronger
defense (dynamic re-randomization) that we probably don't need on
top of an already-oblivious ORAM.

### 2.4 Working-set sizing inside SEV-SNP

Unlike SGX, SEV has *no EPC limit*. A current bare-metal Hetzner box
gives us 128–256 GB RAM, all SEV-encrypted. For our UTXO database
(~28–44 GB OnionPIR, ~17 GB Harmony), the entire ORAM tree fits in
guest DRAM — **no in-VM swapping needed, no host-paging leakage**.
This is the single biggest win over the SGX-era literature: EnigMap's
external-memory optimization is unnecessary for us, but its data
structure is still the best.

---

## 3. Workload model: scripthash → UTXO-list lookups

Our PIR workload is:

- **Keyspace.** ~10–50M distinct scripthashes (and growing).
- **Value.** UTXO list — variable size, ~99% are 1 chunk (32 B
  outpoint + amount + sundries → ~50 B), tail extends to thousands of
  chunks for exchange addresses.
- **Read-only-ish.** Reads dominate by ~10⁶ : 1. Writes are batched
  per block (~144/day, ~3,000 new UTXOs per block, ~1,500 spent).
- **Batch.** Wallets do small batches (1–25 scripthashes per query)
  for change-address discovery; not the 1,000-batch regime that
  EnigMap/Snoopy benchmark.

### Mapping to ORAM:

- **Direct: key→value oblivious map.** Use Oblix or EnigMap directly —
  scripthash is the AVL-tree key, the value is a pointer into a
  separate chunk-storage ORAM. This is the cleanest design.
- **Indirect: index-then-fetch (current architecture).** Two ORAM
  instances: one for the scripthash→entry-id map (small, ~1 GB), one
  for entry-id→chunk-list data (large, ~30 GB). This mirrors what we
  do with cuckoo bins + chunk DB today; lets us tune ORAM parameters
  separately.

The indirect design is cheaper because the position-map ORAM stays
much smaller; the direct design is simpler and matches EnigMap's
benchmark setting. **Recommendation: prototype indirect.**

### Updates / delta stream:

- **Path/Ring/Circuit ORAM** support writes natively: re-mapping a
  block on every access already gives us O(log N) write cost per
  update. A new-block delta of ~3K UTXOs is ~3K ORAM writes — fine.
- **EnigMap** is a dynamic map (oblivious insertion / deletion /
  lookup) — also fine.
- **PRO-ORAM** is read-only and needs a separate shuffle phase to
  apply writes — *not* a good fit for our streaming delta model.
- **Pancake / Waffle** rely on a stationary frequency distribution;
  delta updates partially invalidate that. Possible but tricky.

### Batched 1–25 lookups:

- A single-client ORAM serves these sequentially. With ~5 ms / lookup
  (Circuit ORAM, SEV, ~30 GB), a 25-batch = ~125 ms. Acceptable for a
  wallet UX.
- *Batch ORAM* / OPRAM (Boyle–Chung–Pass) saves work asymptotically
  but the constants don't help in the m ≤ 25 regime, and the
  conflict-resolution adds complexity.
- Snoopy's batched-load-balancer is designed for thousands of
  concurrent batches across a fleet — overkill for one wallet's
  25-batch but the right tool for the *aggregate fleet* throughput.

---

## 4. Multi-client story

Default ORAM is single-client: the position map and the access history
are state. Putting N wallets behind one ORAM naively means their
queries interfere — the server (= the SEV VM, but also the
hypervisor watching the VM) sees a sequence that is the merged
access pattern of all N clients, which leaks pair-wise correlations
between clients.

Three options:

1. **One ORAM per client, shared encrypted storage.** Each wallet has
   its own position map (kept in the SEV VM on their behalf, indexed
   by client session ID), but the underlying ciphertext blocks are
   shared. **Problem:** wallets that look up the same scripthash will
   produce correlated access patterns on the underlying storage — we
   re-introduce some leakage. **Fix:** independent re-mapping per
   client per access, i.e. each client logically holds a fresh copy of
   the tree. Storage cost = N × DB size — untenable.

2. **One shared ORAM, the SEV VM serializes clients.** The VM is the
   trusted controller; it queues incoming queries, runs them through
   the single ORAM in some order, and returns answers. This is what
   ZeroTrace + a queue would give us. **Problem:** throughput
   bottleneck (one ORAM controller); leakage from interaction
   ordering (Snoopy explicitly addresses this with its
   oblivious load-balancer / fixed-size batch).

3. **Snoopy-style.** Shard the keyspace across multiple sub-ORAMs;
   batch queries obliviously into fixed-size buckets; serve in
   parallel. Designed for our exact problem.

**Verdict.** For v1 prototype, option (2) inside one SEV VM is fine —
parallels the single-machine OnionPIR backend we already run. If we
hit throughput limits, evolve to Snoopy-style sharding.

### Client-side state

Path ORAM client state is:
- The position map: ~N · log N bits, recursed away inside the SEV VM
  (the client just sends the scripthash + session token).
- A small stash: O(log N) blocks, also held inside the SEV VM on the
  client's behalf.

**So the actual wallet client (wasm runtime in the browser) holds
~nothing.** The trust shift is "the SEV VM is doing the ORAM for me"
— attested by the launch measurement. This is *the* clean property
of ORAM-in-TEE vs. multi-server PIR: the client doesn't need wasm
SEAL or PRP machinery. The trade-off is that the TEE is on the
trust path.

---

## 5. Recommendation matrix

Scoring legend: ★★★ excellent, ★★ acceptable, ★ poor. n ≈ 5·10⁷,
block ≈ 256 B.

| Construction | Impl | SEV fit | Per-query BW | Update cost | Multi-client | Maturity |
|---|---|---|---|---|---|---|
| **Path ORAM** (ZeroTrace, mc-oblivious, rostl) | ★★★ Rust + C++ | ★★★ | O(log N), ~50 KB | O(log N) | needs serialization | ★★★ shipped in production (MobileCoin Signal CDS) |
| **Ring ORAM** (ZeroTrace) | ★★ C++ | ★★★ | O(1) online | O(log N) | as Path | ★★ research-grade |
| **Circuit ORAM** (ZeroTrace, obliviouslabs) | ★★★ C++ + Rust | ★★★★ (best CMOV discipline) | O(log N) | O(log N) | as Path | ★★ research-grade, actively maintained |
| **OptORAMa** | ★ none | ★ rebuild hiccups | O(log N) optimal | O(log N) | n/a | ★ theory only |
| **Onion-Ring ORAM** | ★ TFHE | ★ pointless under TEE | O(1) | high | n/a | ★ research |
| **ZeroTrace** | ★★★ C++ + SGX glue | ★★★ port-and-pray | as backend | as backend | one-VM serialize | ★★ 2018, unmaintained |
| **Oblix** | ★ research code | ★★★ doubly-oblivious | O(log² N) | O(log² N) | one-VM | ★ research |
| **EnigMap** | ★★★ [odslib/EnigMap](https://github.com/odslib/EnigMap) C++ | ★★★ ext-memory model wasted but algorithm wins | 53× faster than Oblix | dynamic | one-VM | ★★★ USENIX'23, actively maintained |
| **Snoopy** | ★★ research artifact (SOSP'21) | ★★★ explicitly TEE-agnostic | O(log N) sharded | O(log N) | ★★★ designed for it | ★★ research-grade, working artifact |
| **PRO-ORAM** | ★ research SGX | ★★ write-phase awkward | sub-second / 256 KB block | offline | one-VM | ★ research |
| **Pancake** | ★★ production-style | ★★ but weak threat model | constant | tricky | many | ★★★ deployed against Redis |
| **Waffle** | ★ research | ★ weak threat model | constant | ok | many | ★ research |
| **TaoStore** | ★ research | ★★ proxy model | tree-ORAM | tree-ORAM | ★★ async | ★ superseded by Snoopy |
| **Floram / Duoram** | ★★ [github.com/jackdoerner/floram](https://github.com/jackdoerner/floram), Duoram artifact | ★ needs 2 non-colluding TEEs | O(log n) words MPC | O(log n) | n/a (per-client) | ★★ |

---

## 6. Shortlist for prototyping

### Pick 1: **EnigMap inside SEV-SNP**

**Why first.** Oblivious-map-as-a-service is exactly our workload
abstraction (scripthash → entry-id). EnigMap is the most recent and
fastest in the line; it has an actively maintained C++ implementation
([odslib/EnigMap](https://github.com/odslib/EnigMap)) with a tested
oblivious-primitives library underneath. Its external-memory
optimization was for SGX EPC pressure — we don't pay that cost on SEV,
which means EnigMap should run *strictly better* on SEV than the
benchmark numbers show. At 256M entries on SGX it's 53× faster than
the Oblix prior baseline.

**Prototype scope.** Port the EnigMap C++ to compile inside a
bare-metal SEV-SNP guest (we already have the build/UKI pipeline from
the VPSBG / Hetzner ops work). Wrap it with our existing
`pir-runtime-core` protocol so the wire shape is recognizable to the
existing client. Measure 1-query and 25-query latency at 50M
scripthashes / ~30 GB total data.

**Risk.** The C++ codebase wasn't designed for SEV's specific side
channels; we will likely need to re-audit some inner loops for the
ciphertext side channel (cache-line-granular re-encryption) once we
have measurements.

### Pick 2: **Circuit ORAM (via obliviouslabs/rostl) inside SEV-SNP,
behind a thin key→pointer index**

**Why second.** If EnigMap turns out to be too heavyweight or its
licensing/maintenance status is awkward, the
[obliviouslabs/rostl](https://github.com/obliviouslabs/rostl) Rust
crate gives us Circuit ORAM (HeapTree backend) as a clean library we
can integrate directly into `pir-runtime-core`. Pair it with a much
simpler in-VM linear-scan index for the position map at v1; we already
own the data-oblivious-scan discipline from
`pir-sdk-client/src/dpf.rs` invariants. Rust + SEV is a cleaner
software-supply-chain story than ZeroTrace's circa-2018 C++.

**Prototype scope.** Stand up an `pir-oram` crate that wraps
rostl::oram::circuit; implement the `RequestHandler` shape so it slots
in as a fourth backend alongside DPF/Harmony/Onion.

**Risk.** rostl is fairly new — we should audit the oblivious
primitives against the SEV ciphertext channel and confirm the Rust
compiler isn't optimizing CMOVs away (the canonical risk in any
constant-time Rust crate). The MobileCoin
[mc-oblivious](https://github.com/mobilecoinfoundation/mc-oblivious)
Path-ORAM Rust crate is the more conservative alternative — audited
and deployed in MobileCoin/Signal contact discovery.

### Pick 3: **Snoopy as a longer-term multi-client target**

**Why third / later.** Once we have a working single-VM ORAM backend
and want to scale beyond what one box can serve, Snoopy is the
designed-for-multi-client construction. The architecture (sharded
sub-ORAM enclaves + oblivious load balancer) is explicitly
TEE-agnostic — porting from "any TEE" to SEV-SNP is plumbing, not
research. At 18 machines they reach 92K req/s; one such fleet would
absorb the entire Bitcoin wallet population.

**Prototype scope (long-horizon).** Not a v1 task. Run only if/when
the single-VM Pick-1/Pick-2 prototype shows throughput as the
bottleneck.

**Risk.** Operational complexity (managing N attested SEV hosts,
coordinating their position-map epochs, dealing with one going
offline). Today's DPF/Harmony 2-server setup is already painful at
N=2 — N=18 would need real fleet automation.

---

## 7. Pragmatic order of operations

1. Pick a single-VM ORAM (start with EnigMap; if blocked, fall back
   to `rostl` Circuit ORAM or `mc-oblivious` Path ORAM).
2. Stand up a minimal SEV-SNP guest that runs the ORAM controller and
   exposes the existing `pir-runtime-core` protocol surface.
3. Port the same leakage-integration tests we use for DPF/Harmony/Onion
   (the wire-shape-invariants suite in `tests/` against
   `wss://weikeng2.bitcoinpir.org`) to verify the new backend's
   query traces are independent of the secret scripthash — this is
   the same simulator-property test we already mechanized, just with
   a new backend ID.
4. If throughput is fine, ship. If not, sub-shard à la Snoopy.

---

## 8. Sources

ORAM constructions:
- [Stefanov et al., Path ORAM, CCS'13 / arXiv:1202.5150](https://arxiv.org/abs/1202.5150) · [JACM'18](https://dl.acm.org/doi/10.1145/3177872)
- [Ren et al., Ring ORAM, USENIX Sec'15](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-ling.pdf)
- [Wang–Chan–Shi, Circuit ORAM, CCS'15](https://eprint.iacr.org/2014/672)
- [Asharov et al., OptORAMa, Eurocrypt'20](https://link.springer.com/chapter/10.1007/978-3-030-45724-2_14) · [worst-case version, JoC'23](https://link.springer.com/article/10.1007/s00145-023-09447-5)
- [Fletcher et al., Bucket ORAM, ePrint 2015/1065](https://eprint.iacr.org/2015/1065)
- [Devadas et al., Onion ORAM, TCC'16](https://people.csail.mit.edu/devadas/pubs/onionORAM.pdf) · [Chen–Chillotti–Ren, Onion-Ring ORAM, CCS'19](https://dl.acm.org/doi/10.1145/3319535.3354226)
- [Boyle–Chung–Pass, OPRAM, TCC'15 / ePrint 2014/594](https://eprint.iacr.org/2014/594.pdf)
- [Wang–Nayak–Liu–Shi, Oblivious Data Structures, CCS'14 / ePrint 2014/185](https://eprint.iacr.org/2014/185.pdf)

TEE-specialized ORAM / oblivious data structures:
- [Sasy–Gorbunov–Fletcher, ZeroTrace, NDSS'18](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_02B-4_Sasy_paper.pdf) · [ePrint 2017/549](https://eprint.iacr.org/2017/549) · [code](https://github.com/sshsshy/ZeroTrace)
- [Mishra et al., Oblix, S&P'18](https://people.eecs.berkeley.edu/~raluca/oblix.pdf)
- [Ahmad et al., Obliviate, NDSS'18](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_06A-2_Ahmad_paper.pdf)
- [Tinoco–Gao–Shi, EnigMap, USENIX Sec'23](https://www.usenix.org/system/files/usenixsecurity23-tinoco.pdf) · [ePrint 2022/1083](https://eprint.iacr.org/2022/1083) · [code](https://github.com/odslib/EnigMap)
- [Tople–Jia–Saxena, PRO-ORAM, RAID'19](https://www.usenix.org/system/files/raid2019-tople.pdf)

Multi-client / distributed oblivious storage:
- [Sahin et al., TaoStore, S&P'16](https://sites.cs.ucsb.edu/~rachel.lin/papers/TaoStore-CameraReady.pdf)
- [Crooks et al., Obladi, OSDI'18](https://www.usenix.org/system/files/osdi18-crooks.pdf)
- [Dauterman et al., Snoopy, SOSP'21](https://nacrooks.github.io/bibliography/publications/2021-sosp-snoopy.pdf) · [ePrint 2021/1280](https://eprint.iacr.org/2021/1280)
- [Doerner–Shelat, Floram, CCS'17 / ePrint 2017/827](https://eprint.iacr.org/2017/827.pdf)
- [Vadapalli–Henry–Goldberg, Duoram, USENIX Sec'23](https://www.usenix.org/system/files/sec23fall-prepub-339-vadapalli.pdf) · [ePrint 2022/1747](https://eprint.iacr.org/2022/1747)

Frequency-smoothing alternatives:
- [Grubbs et al., Pancake, USENIX Sec'20](https://www.usenix.org/system/files/sec20-grubbs.pdf) · [ePrint 2020/1501](https://eprint.iacr.org/2020/1501)
- [Maiyya et al., Waffle, SIGMOD'24 / ePrint 2023/1285](https://eprint.iacr.org/2023/1285.pdf)

SEV-SNP side-channel context:
- [Li et al., Ciphertext side channels on AMD SEV-SNP, S&P'22](https://yinqian.org/papers/sp22b.pdf)
- [SNPeek, NDSS'26](https://www.ndss-symposium.org/wp-content/uploads/2026-f699-paper.pdf)
- [Heracles, CCS'25](https://heracles-attack.github.io/Heracles-CCS2025.pdf)
- [WeSee, arXiv:2404.03526](https://arxiv.org/pdf/2404.03526)

Open-source implementations:
- [github.com/sshsshy/ZeroTrace](https://github.com/sshsshy/ZeroTrace) — Path + Circuit ORAM, SGX, C++/asm
- [github.com/mobilecoinfoundation/mc-oblivious](https://github.com/mobilecoinfoundation/mc-oblivious) — Path ORAM, Rust, audited, production
- [github.com/obliviouslabs/oram](https://github.com/obliviouslabs/oram) — Circuit ORAM, C++, parallel
- [github.com/obliviouslabs/rostl](https://github.com/obliviouslabs/rostl) — Circuit / Linear / Recursive / HeapTree ORAM, Rust, TEE-targeted (Intel TDX named)
- [github.com/odslib/EnigMap](https://github.com/odslib/EnigMap) — Oblivious AVL treemap, C++

[CMU CSD blog summary of oblivious maps for TEEs (2024)](https://www.cs.cmu.edu/~csd-phd-blog/2024/oblivious-maps/) is a useful longer-form readers' guide to the Oblix → EnigMap line.
