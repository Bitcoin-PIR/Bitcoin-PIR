# pir2 deployment workflow pain points (2026-09-05 → 2026-09-07)

Collected while running two pir2 measured-image campaigns (image 303, then
image 305 with the session-grant pin) and the paid-access rollout. Each item
names what hurt, the evidence, and a proposed cleanup. Live state is never
inferred from this page; identity values stay in `web/src/attest-pin.ts`
and command output.


Each item: what hurt, evidence, proposed cleanup.

1. `scripts/vpsbg-data-disk.sh open`: VPSBG returns HTTP 423 on the stop right after
   detach, then the delayed stop lands after the wrapper's start; the wrapper either
   exits 22 or waits forever on a stopped guest (hit 4 times; one 900 s hard stop).
   Fix: after detach, poll state; treat 423 as "retry stop later"; if stock+stopped,
   issue start; wait for SSH with a single loop.
   **Fixed:** `open` now settles by readback (`settle_to_stock_ssh`), with an
   offline simulation of the race in `scripts/vpsbg-data-disk.test.mjs`.
2. `scripts/pir2-post-switch-check.sh`: `status_args[@]: unbound variable` when no
   `--server-id` is given (noted in the epoch-5 handoff, still unfixed).
   **Fixed:** the empty array is expanded with the `${status_args[@]+"${status_args[@]}"}`
   form (bash 3.2 under `set -u`); `scripts/ops-operator-scripts.test.sh` checks that no
   unguarded expansion comes back.
3. Hint-pool generation timing is compiled out in production
   (`test-only-unsafe-query-logging`); capacity planning needed /proc CPU sampling.
   Fix: a non-sensitive duration counter (no keys, no query data) in the info log.
   **Fixed:** the generator keeps an aggregate window (count, mean, max wall seconds per
   generated hint set) and prints one `[hint-pool db=N] last 3600s: …` line per hour
   from its idle loop on the interval boundary — never on a generation event, never a
   key or group, so the production log audit test still holds. Effective from the next
   pir1 rebuild / pir2 image.
4. Ready receipts are retrievable only through a later Flow F window, which costs a
   full ORAM rebuild (Ready N → window → Ready N+1). Fix: let Ready publish the two
   receipts through the bounded recovery root like Observe/Enroll/Probe do, or copy
   them to a world-readable data-disk path the status API can serve.
   **Fixed:** the serving Ready guest answers the read-only opcode
   `REQ_PIR2_SEALED_RECEIPT_GET` with both receipts and the preflight marker;
   `scripts/pir2-sealed-ceremony.sh fetch` (`bpir-admin pir2-sealed-receipt-fetch`)
   copies them out and `receipt` accepts them offline. Effective from the first
   image built after that change; image 305 still needs the Flow F window.
5. UFW rate-limits SSH (6 conns/30 s); scripted campaigns that open one ssh per step
   get locked out. Fix: document; batch steps per session; consider a control
   socket (`ControlMaster`) in the wrapper.
   **Fixed:** `scripts/vpsbg-data-disk.sh` multiplexes every ssh/scp of a window over a
   ControlMaster socket (`ControlPersist=600`, private control directory), torn down
   by `open` and `close` (tested in `scripts/vpsbg-data-disk.test.mjs`); the r7
   campaign's per-step pacing is now a courtesy, not the mechanism.
6. `cargo fmt --all` reformats `unified_server_pir2_sealed/mod.rs` on main (file is not
   rustfmt-clean); every PR touching the server has to revert it. Fix: format it once.
   **Fixed:** formatted once; the Rust `core` CI lane now runs `cargo fmt --all -- --check`
   so no file can drift again.
7. Contract test regexes match comments (`--require-session-grant` mention failed the
   test); pipelines `node --test | grep` hide failures. Fix: anchor to flag lines; run
   tests without a masking pipe (or `set -o pipefail`).
   **Fixed:** the contract test's negative checks run on the sources with full-line
   comments stripped (a comment may mention a retired flag; a real line still fails),
   with a regression test for both directions.
8. Running `node --test a.mjs | grep … && node --test b.mjs` masks the first failure and
   starves the second (observed pass 0/fail 1 that vanished when run alone). Fix: one
   `node --test scripts/*.test.mjs` invocation in `docs/TESTING.md`/CI.
   **Fixed:** `scripts/test-scripts.sh` is the single list and single `node --test`
   invocation; CI's supply-chain step and `docs/TESTING.md` both run it.
9. Receipt evidence tooling lives in the session scratchpad (`observe-receipt-fields.py`,
   `fetch-receipt.sh`, `poll-receipt.sh`, `receipt-verify.sh`): promote the useful ones
   into `scripts/` (Observe field extraction + hash-checked fetch + phase poll).
   **Fixed:** `bpir-admin pir2-sealed-observe-fields`, `scripts/pir2-sealed-recovery-receipt.sh`
   (poll + hash-checked fetch + quarantine, tested against a fake origin), and the whole
   r7 window orchestration as `scripts/pir2-sealed-campaign.sh plan|build|enroll|probe|ready`
   with `scripts/pir2-sealed-remote/` guest-side build steps, `--dry-run` plans, and an
   offline test of every plan; the runbook's "Campaign" section documents the env file.
10. `unified_server` rejects `--help` (breaks install sanity checks); add `--help`/
    `--version`.
    **Fixed:** `--help`/`-h` prints a flag reference that a unit test keeps in sync with
    the parser; `--version`/`-V` prints crate version, git revision, and binary sha256;
    both exit 0 as the sole argument and never start a server (integration test
    `apps/server/tests/unified_server_cli.rs`, run by the runtime CI lane).
11. `scripts/pir2-sealed-ceremony.sh` runs `cargo run --locked --offline -p bpir-admin`
    (debug profile) for `release`/`receipt`; after any runtime change the first call
    recompiles for >10 min in the middle of a ceremony window (observed 2026-09-07).
    Fix: accept `BPIR_ADMIN=/path/to/reviewed/bpir-admin` like
    `verify_oram_tier3_deploy.sh` does, or build once before the window.
    **Fixed:** `BPIR_ADMIN=/absolute/path/bpir-admin` runs a prebuilt binary for
    `release`/`receipt`/`fetch` (the runbook builds it once before the ceremony);
    `scripts/pir2-sealed-ceremony.test.mjs` checks the previews, the override, and
    the forwarded exit status, and `receipt --dry-run` no longer dies on an empty
    option list under bash 3.2.
12. `vpsbg-measured-boot.sh upload` returns the image id but the name is truncated by
    VPSBG (`tier3-20260907T05043`); the sidecar has the real name — record both in
    the release record.
    **Fixed:** the image-307 release record carries both `uki_name` (sidecar) and
    `vpsbg_image_name` (control plane), written by the record generator from the
    evidence files.

## Observed in the r7 campaign (image 307, 2026-09-07)

With #301–#304 in place the whole campaign (build → Observe → release → Enroll →
two Probes → Ready → receipts accepted) took 34 minutes and five data-disk windows;
the Ready receipts came back over `REQ_PIR2_SEALED_RECEIPT_GET` 60 s after the live
attestation passed, so no Ready N+1 boot was needed. Two smaller items remain:

13. `remote-prep-enroll` (the rollback-preserving step before Enroll) copies whatever
    `startup.env` is current, which by then is the new image's Observe file; the
    previous image's Ready startup survives only as the `.bak` taken in the build
    window. Fix: make the rollback set explicit (envelope, release, cert, and the
    previous Ready startup) in a reviewed script under `scripts/`.
    **Fixed:** `scripts/pir2-sealed-rollback-set.sh preserve|verify|detach-envelope|restore`
    (guest side, manifest-checked, tested offline by
    `scripts/pir2-sealed-rollback-set.test.mjs`); the runbook's "Rollback set" section
    places `preserve` before the Observe startup and `detach-envelope` in the Enroll window.
14. The release record's `db0/db1_server_manifest_sha256` still need a Flow F read of
    `<db>/server-db/MANIFEST.toml`; the serving guest could publish those digests
    (for example in the JSON info response) so the record closes without a window.
    **Fixed:** no server change needed — the per-DB manifest root the guest already
    attests is sha256 of the served `MANIFEST.toml`, and `bpir-admin attest` prints
    it; `scripts/generate-release-record.sh --attest-log` takes the measurement and
    both digests from a verified attest run (tested by
    `scripts/generate-release-record.test.mjs`). Image 307's record is regenerated
    from its live attestation; 303/305 keep TODO (their guests are retired).
