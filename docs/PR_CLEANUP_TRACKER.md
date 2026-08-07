# PR and legacy work tracker

Status date: 2026-08-05

This is the working queue for stale pull requests, merged-work follow-ups, and
documentation drift across the Bitcoin-PIR organization. It is intentionally
separate from production rollout records. A row is not complete until its
evidence and follow-up are closed.

## Scope snapshot

- Organization repositories scanned: 15, including the two organization forks.
- Open pull requests: 8.
- Merged pull requests: 147.
- Closed but unmerged pull requests: 1; Bitcoin-PIR #21 is explicitly
  superseded by merged #22 and needs no action.
- Open issues: 0.
- The working tree was `fix/ci-live-admission-dpf`; no user files were changed
  during the inventory.

## Priority queue

Status values: `OPEN`, `BLOCKED`, `QUEUED`, `IN PROGRESS`, `DONE`, `CLOSED`.

| ID | Priority | Item | Repository / PR | Status | Evidence and next action |
| --- | --- | --- | --- | --- | --- |
| P0-1 | P0 | Live SDK integration admission | [Bitcoin-PIR #139](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/139) | DEPLOYED (2026-08-07) | Root cause mapped + fixed + deployed 2026-08-06/07. (2) Harmony granted `harmony-query-job-v1` silent hang → RESOLVED: the Payment-V1 listener's 2 MiB `max_write_buffer_size` + 512 KiB message cap (962fd4c5) killed the only unchunked response arm (a live-scale 4.15–27 MB harmony batch response hit `WriteBufferFull`; the swallowed error wedged the connection, and the Cloudflare idle-kill caused the '~120 s 1006 close' seen by the browser). Fix = chunked response + fail-close logging (`9b7128f0` + two tungstenite-level regressions) PLUS a policy response-budget raise (a verified session aggregates ≈60–65 MiB of responses, so both hosts' harmony-query `max_response_bytes` went 64→128 MiB: weikeng2 epoch-3→4 (UKI image 229, MEASUREMENT `1c375b26…`), weikeng1 epoch-9→10). Witnesses live on production: `test_harmony_strict_production_canary_sync_single`, `…_query_batch`, and the raw-pair/driver probes in `tests/local_production_repro.rs` (4.15 MB INDEX + 27 MB CHUNK full round-trips in seconds through Cloudflare). (3) Onion free-scope 16 MiB request ceiling → RESOLVED by weikeng1 epoch-9/10 policy raise to 24 MiB (register-once + INDEX + CHUNK + INDEX/DATA Merkle sessions verified end-to-end; no metering defect and no protocol semantics change). (4) db1 tree-tops (23.4 MB) NOW SERVES on both hosts thanks to `9b7128f0`'s pre-auth budget raise (64 MiB/192 msg; witness 9,155,384 + 23,426,084 byte responses in <1 s E2E each). Remaining strict-canary gaps are NOT these items: the **db1-specific** stages in the root-tier canaries (DPF delta frames, harmony db1-context sync) are intentionally blocked until a separately priced db1 scope + fresh BAT/ARC bindings ship per the templates' stated plan; the DPF/harmony/onion db0 query flows themselves are deployable-green and can re-gate CI whenever governance wants |
| P0-2 | P0 | Formal proof lock uses an unmerged draft | [protocol-proofs #1](https://github.com/Bitcoin-PIR/protocol-proofs/pull/1) | OPEN | `verification/locks/formal-proofs.json:5-9` pins draft head `c519f196`; `protocol-proofs/main` is `64bf4cf`. Merge the proof PR or restore the previously merged proof lock. |
| P0-3 | P0 | Rootbundle compatibility test is red | Bitcoin-PIR trust tests | DONE | `cargo test --locked -p pir-db-attest --test rootbundle_compat` = 3/3; `cargo test --locked -p pir-db-attest` = 5 lib + 3 compat. Test renamed `consumer_lock_matches_the_vendored_rootbundle`; `verification/locks/rootbundle.json` gained an audited `vendored_files_sha256` (8-file digest set), which must match `vendor/rootbundle/.cargo-checksum.json` exactly; every vendored file is re-hashed from disk; `production_payload_sha256` is checked as a full array against the forensic fixture set; Cargo.toml entries are parsed structurally (dependency-free TOML-subset parser, no Cargo.lock churn). Remaining provenance boundary: the test is offline and cannot detect a rewritten upstream commit or a colluding lock+mirror update; upstream-to-vendor binding rests on the audited digest set in the lock, not on the network. |
| P1-1 | P1 | Shipped Onion WASM came from an unmerged fork PR | [OnionPIRv2-fork #3](https://github.com/Bitcoin-PIR/OnionPIRv2-fork/pull/3) | OPEN | `web/public/wasm/BUILD_PROVENANCE.md:3-20` names draft commit `0d8b556`. Merge the fork PR or make the product build reproduce and own the patch. |
| P1-2 | P1 | Paid TEE-ORAM activation remains blocked but old docs claim live readiness | [Bitcoin-PIR #133](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/133) and ORAM docs | BLOCKED | `docs/ORAM_LIVE_IMAGE_BINDING_PLAN.md:3-12,42-53` is current; `PHASE3_ROADMAP.md`, `STRICT_VERIFICATION_PROGRESS.md`, and `PROJECT_CLOSEOUT_TODO.md` contain older claims. Create an attested-builder follow-up for fresh full-build-v2 and measured delta evidence. |
| P1-3 | P1 | Functional-beta template lineage draft has a failed gate | [Bitcoin-PIR #124](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/124) | BLOCKED | Run [30712001300](https://github.com/Bitcoin-PIR/Bitcoin-PIR/actions/runs/30712001300) rejects `bitcoinpir-payment-issuer-functional-beta.service.in` as an unreviewed path. Fix the gate/template set and rerun. |
| P1-4 | P1 | Source-fair ingress draft is stale and conflicted | [Bitcoin-PIR #92](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/92) | BLOCKED | Draft has been unchanged since 2026-07-29, is `DIRTY`, and its Linux capability check failed. Rebase and compare with the merged #104-#107 relay work, or close as superseded. |
| P1-5 | P1 | Paid Harmony process draft is stale and conflicted | [Bitcoin-PIR #93](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/93) | BLOCKED | Stacked on the old source-fair branch, unchanged since 2026-07-29, with no checks. Rebase against current Payment V1 process coverage or close as superseded. |
| P1-6 | P1 | Shared issuer clearing draft is stale and conflicted | [Bitcoin-PIR #94](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/94) | BLOCKED | Checks passed on the old base, but the branch is `DIRTY` and has no review. Rebase before deciding whether this is still the canonical implementation. |
| P1-7 | P1 | Paid TEE-ORAM process draft is stale and conflicted | [Bitcoin-PIR #95](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/95) | BLOCKED | The body only claims local NoSevHost process coverage; it is not production evidence. Rebase only after the ORAM proof blocker has a tracked owner, otherwise close or split the local test. |
| P2-1 | P2 | Warmup rollout document still gives pending instructions | `docs/SERVER_WARMUP_REMOVAL_ROLLOUT.md` | DONE | Marked historical and linked the current ORAM eligibility document. PRs #42 and #43 remain the rollout evidence. |
| P2-2 | P2 | Database rotation runbook still references removed v1 Onion layout pins | `docs/DATABASE_ROOT_ROTATION_RUNBOOK.md` | DONE | Replaced the obsolete layout-pin procedure with `PRODUCTION_ONION_DB_PROOF_V2_PINS` and explicit v2-only language. |
| P2-3 | P2 | RegisterKeys postmortem contradicts its resolved status | `docs/PIR1_REGISTER_KEYS_TRUNCATION.md` | DONE | Marked pre-fix evidence historical and documented the landed Rust/server/Web transport chunking. |
| P2-4 | P2 | Upstream thread-safety request describes landed work as pending | `docs/UPSTREAM_REQUEST_THREAD_SAFETY.md` | DONE | Marked the request resolved, documented downstream adoption, and removed the obsolete `build/` update path. |
| P2-5 | P2 | Web protocol document describes legacy opcodes and advisory proof flow | `doc/WEB.md` | QUEUED | Confirm the current protocol constants and rewrite or explicitly label the old section as legacy. |
| P2-6 | P2 | Repository-boundary and ORAM status documents need a single current-status pass | `docs/REPOSITORY_BOUNDARIES.md`, `docs/PHASE3_ROADMAP.md`, `docs/STRICT_VERIFICATION_PROGRESS.md` | QUEUED | Preserve historical evidence, but add explicit historical labels and link the current blockers from one status section. |

## Selected first batch

The first batch deliberately contains documentation-only changes with no wire,
cryptographic, deployment, or payment behavior changes:

1. Mark the completed warmup rollout as historical.
2. Update the database rotation runbook to the v2-only Onion proof surface.
3. Reconcile the resolved RegisterKeys postmortem.
4. Mark the upstream thread-safety request resolved.

The rootbundle test was the next low-complexity code change; it is closed
separately (P0-3) because it changes test assumptions around repository
boundaries.

The first batch was completed on 2026-08-05. No production, protocol,
cryptographic, proof-lock, payment, or deployment files were changed.

## Working rules

- Do not merge or close a PR solely because it is old; compare its diff with
  current `main` first.
- Do not treat a passing local or no-funds process test as production evidence.
- Do not change production pins, UKI inputs, proof locks, or payment policy as
  part of documentation cleanup.
- Add the command, CI URL, or file/line evidence to a row when its status
  changes.
