# Direct ORAM TEE Debug Runbook

This document records the August 2026 VPSBG Direct ORAM incident, the known-good
build baseline, and the bounded workflow for the next measured-boot test. It is
the operator source of truth for this debug cycle. It does not authorize a
production deployment.

## Completed debug boundary

The dedicated debug UKI completed one small encrypted Direct ORAM build inside
SEV-SNP. Its progress, result, and failed-attempt diagnostics were copied from
`/home/pir/data/oram-tee-debug/` to the external archive described below. The
server was then detached from measured boot and returned to stock/none mode.

The next boundary is planning only: prepare the full-production UKI preflight,
but do not build or attach it until the operator explicitly authorizes a new
build/deployment cycle.

Time limits are part of acceptance:

| Stage | Expected | Hard stop |
| --- | ---: | ---: |
| Local/stock UKI build | under 10 minutes | 20 minutes |
| VPSBG upload and measured boot | under 5 minutes | 10 minutes |
| Minimal TEE Direct ORAM build | under 1 minute | 5 minutes |
| No progress heartbeat | never more than 30 seconds | fail after 90 seconds |

An overrun is a failure to diagnose, not a reason to wait indefinitely.

## What happened

Three independent issues were initially conflated:

1. The historical Direct ORAM builds were unencrypted. Strict source binding
   later required encrypted bulk and authentication pages. The initial Merkle
   builder updated every 32-byte hash by reading, decrypting, modifying,
   encrypting, and rewriting an entire 4096-byte page. That pre-existing
   algorithmic cost became visible only when encryption became mandatory.
2. A candidate db1 `server-db` omitted generated
   `merkle_bucket_{index,chunk}_sib_L*.bin` files. `unified_server` therefore
   loaded db0 and then panicked on db1. Runit restarted it every second, hiding
   the deterministic three-minute load-and-panic cycle behind a persistent 502.
3. The db0 manifest also contained large Onion artifacts that the secondary
   runtime did not use. Manifest verification read those files in full before
   startup. This increased startup time and memory, but it was not the db1
   panic's root cause.

The Direct ORAM placement algorithm itself was not replaced. The August 11
change only optimizes the trusted, offline Merkle construction path: compute the
tree in memory, then write each packed hash page once in order. Runtime reads,
writes, authentication, and eviction remain disk-backed and unchanged.

## Known-good none-mode baseline

VPSBG stock/none mode used the production db0 direct inputs:

```text
index bytes  = 1,345,875,975
index sha256 = d0b9573488abdda8e17dc52bb52bf5ff11520b4511683020f5f1a22bc8d8d26c
chunk bytes  = 3,239,380,480
chunk sha256 = 9a81a02bf82af49414b5f2ae6380c97c1f231fcac6890b605f6cde22b0adc521
MuHash       = cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee
```

The strict, encrypted build completed successfully:

```text
wall time        3:53.82
index elapsed    29.318 seconds
chunk elapsed    127.588 seconds
maximum RSS      3,778,228 KiB
swap             0
exit status      0
source binding   true for index and chunk authentication stores
```

For comparison, the old encrypted path required 115.303 seconds for index
alone and did not finish chunk before a five-minute diagnostic cutoff. The old
unencrypted complete build took 2:47.48. The optimized encrypted result is
therefore within the established operational range.

## Artifact retention

The irreplaceable inputs and small evidence are retained; generated ORAM images
are disposable.

Retain offline for operational diagnosis only:

- `/Volumes/Bitcoin/data/archive/local-oram-repro-20260811/db0/oram-direct-inputs/`
- db0 `build-evidence.bin`, `root-bundle-payload.bin`, and exact
  `server-db/MANIFEST.toml`
- the none-mode logs and successful `oram-build-evidence.{json,bin}`
- this runbook and the external archive README

Safe to remove after evidence is copied:

- VPSBG `/home/pir/data/oram-debug/stock-none-20260811/db0-old-method`
- VPSBG `/home/pir/data/oram-debug/stock-none-20260811/db0-encrypted`
- VPSBG `/home/pir/data/oram-debug/stock-none-20260811/db0-encrypted-batched`
- local external `builds/current-unencrypted`

These paths contain derived, disposable ORAM images only. They are not inputs
to the browser source proof. Deleting them is not a database or source-proof
deletion.

## Bounded workflow

1. Confirm the server is in stock/none mode, no `oramctl` or `unified_server`
   remains, and enough disk is free for exactly one output generation.
2. Verify the two source hashes and all source-binding evidence before the
   timer starts.
3. Start one supervised build. Record `started_at`, current phase, last
   heartbeat, process elapsed time, RSS, output bytes, and final exit status.
4. Enforce the hard stop externally. Never rely on the worker to stop itself.
5. Require both `built_direct` records, both `source_bound=true` auth records,
   `oram-build-evidence.{json,bin}`, and all controller/auth state files.
6. Preserve logs and small evidence, then remove only the derived bulk images.

## Runit failure suppression

The Tier 3 service must stop after three consecutive short-lived failures.
Runit's `finish` hook records the start time and consecutive-failure count under
`/run`; a runtime that survives the stability window resets the old sequence.
On the third short failure, the hook runs `sv down` for `unified_server` and
leaves a reason/status file. It must not reboot the machine or delete data.

The dedicated debug UKI uses a one-shot ORAM service instead of the production
server loop. Its result must remain readable after returning to stock mode.

## Dedicated TEE debug UKI acceptance

The debug image must:

- contain the exact locally tested `oramctl` build;
- mount only `/home/pir/data` from the unmeasured root filesystem;
- copy a small deterministic Direct INDEX/CHUNK fixture into protected tmpfs;
- create a fresh in-guest page key and never print it;
- run encrypted Direct ORAM with sidecar authentication and a five-minute hard
  timeout;
- write atomic `status.env`, an append-only `progress.log`, and the small build
  evidence under `/home/pir/data/oram-tee-debug/<run-id>/`;
- record SEV-SNP availability, binary hash, phase times, final status, output
  sizes, and peak RSS without recording the page key;
- execute the builder exactly once; after it exits, keep the read-only status
  endpoint available for collection without restarting the builder.

## TEE result and archive

The accepted image was VPSBG measured-boot image `239`, built from repository
revision prefix `2bf7810c`:

```text
image file      bpir-oram-debug-2bf7810c-oramdebug4-20260810T1800Z-original.efi
image bytes     94,717,440
image sha256    40547d4130bbd455dc4b208b2cb08cd23de81038e0834a141ef8ff30426e7568
result          success / complete
SEV device      present
runner exit     0
oramctl sha256  fb16d45437a13d51851daa9b626c58abc79c16884b24eb4dafb3646467b52b7e
output bytes    19,190
page key        guest urandom; never recorded
```

The fixture completed within a one-second sampling interval, so
`elapsed_seconds=0` is a coarse observation rather than a claim of zero work.
`progress.log` records `prepare`, `build-direct`, `verify-output`, and
`complete` in order. The small fixture is intentionally non-strict; it proves
that the exact encrypted Direct ORAM executable can initialize and finish in a
SEV guest, not that production db0/db1 have been rebuilt.

Two earlier attempts are retained because they explain control-plane fixes:

- `oramdebug2` stopped during `network-and-sev` before the runner could report
  a result;
- `oramdebug3` reached `sev-device-validate`, exposing init/runner output and
  timeout handling that was corrected in `oramdebug4`.

The byte-for-byte archive is:

```text
/Volumes/Bitcoin/data/archive/uki-debug/tee-runs-20260810T1800Z/
```

Its `SHA256SUMS` covers all 27 collected evidence/output files. The successful
UKI is retained next to that directory. VPSBG is currently in stock/none mode;
image `239` remains available as the known-good debug rollback artifact.
