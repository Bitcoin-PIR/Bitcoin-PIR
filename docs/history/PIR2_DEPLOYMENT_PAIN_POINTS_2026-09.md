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
3. Hint-pool generation timing is compiled out in production
   (`test-only-unsafe-query-logging`); capacity planning needed /proc CPU sampling.
   Fix: a non-sensitive duration counter (no keys, no query data) in the info log.
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
6. `cargo fmt --all` reformats `unified_server_pir2_sealed/mod.rs` on main (file is not
   rustfmt-clean); every PR touching the server has to revert it. Fix: format it once.
7. Contract test regexes match comments (`--require-session-grant` mention failed the
   test); pipelines `node --test | grep` hide failures. Fix: anchor to flag lines; run
   tests without a masking pipe (or `set -o pipefail`).
8. Running `node --test a.mjs | grep … && node --test b.mjs` masks the first failure and
   starves the second (observed pass 0/fail 1 that vanished when run alone). Fix: one
   `node --test scripts/*.test.mjs` invocation in `docs/TESTING.md`/CI.
9. Receipt evidence tooling lives in the session scratchpad (`observe-receipt-fields.py`,
   `fetch-receipt.sh`, `poll-receipt.sh`, `receipt-verify.sh`): promote the useful ones
   into `scripts/` (Observe field extraction + hash-checked fetch + phase poll).
10. `unified_server` rejects `--help` (breaks install sanity checks); add `--help`/
    `--version`.
11. `scripts/pir2-sealed-ceremony.sh` runs `cargo run --locked --offline -p bpir-admin`
    (debug profile) for `release`/`receipt`; after any runtime change the first call
    recompiles for >10 min in the middle of a ceremony window (observed 2026-09-07).
    Fix: accept `BPIR_ADMIN=/path/to/reviewed/bpir-admin` like
    `verify_oram_tier3_deploy.sh` does, or build once before the window.
12. `vpsbg-measured-boot.sh upload` returns the image id but the name is truncated by
    VPSBG (`tier3-20260907T05043`); the sidecar has the real name — record both in
    the release record.
