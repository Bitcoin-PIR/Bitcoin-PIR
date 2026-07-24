# Project closeout TODO

Status date: 2026-07-24

This file tracks the ordered closeout after the strict-verification and Tier 3
ORAM regenerate-on-boot rollout. A checked item means the work is merged into
the authoritative repository and, where applicable, activated and verified in
production. A draft PR or an implementation on an unmerged branch is not
complete.

## 0. Reconcile completed rollout documentation

- [x] Record PRs #70 and #71 as merged and the Tier 3 regenerate-on-boot rollout
      as complete.
- [x] Mark the final UKI build, archive, upload, boot, acceptance gates, and pin
      publication complete in `ORAM_LIVE_IMAGE_BINDING_PLAN.md`.
- [x] Reconcile `BUILD_REPRODUCIBILITY.md` with the landed client-side anchor
      verification and synthetic cross-build determinism CI.
- [x] Merge this documentation reconciliation into `main` (PR #72).

## 1. Automate browser-only strict production gates

Tracking PR: BitcoinPIR #67.

- [x] Rebase or merge current `main` into the PR branch.
- [x] Review the Playwright assertions for runtime pin, operator identity,
      encrypted channel, result verification, and per-query disconnect.
- [x] Re-run local Web tests and the production browser canary.
- [x] Mark the PR ready, merge it, and confirm the scheduled/manual workflow is
      present on `main`.

## 2. Fail fast on malformed HarmonyPIR V2 streams

Tracking PR: BitcoinPIR #68.

- [x] Rebase or merge current `main` into the PR branch.
- [x] Review duplicate-group, preamble, terminal-metadata, and socket-discard
      behavior, including regression coverage.
- [x] Run the SDK, WASM, Web, and formal-wire-shape gates affected by the diff.
- [x] Mark the PR ready and merge it.

## 3. Land database proof v2 capability

Tracking PRs: `Bitcoin-PIR/attested-builder` #1 and BitcoinPIR #69.

- [x] Review and merge the producer/re-attester implementation in
      `attested-builder` without treating a recorded verifier result as a trust
      input.
- [x] Review BitcoinPIR #69's v2 parser, typed Onion layout, dual-serving wire
      path, WASM handle, and strict no-fallback behavior.
- [x] Rebase, rerun all affected Rust/WASM/Web/formal gates, and merge #69 as a
      capability-only change.
- [x] Keep the deployed v1 path and explicit Onion layout pins active through
      the capability merge and server-side dual-serving rollout; move clients
      only in the separate fail-closed activation PR below.

## 4. Activate database proof v2 in production

- [x] Inventory Hetzner's retained db 0/db 1 Onion artifacts and implement the
      final-serving-image re-attestation path in `attested-builder` PR #4.
- [x] Confirm the same retained paths on VPSBG before booting the re-attestation
      UKI.
- [x] Re-attest both existing layouts and archive canonical v2 evidence, SNP
      reports, inputs, and independent verifier output.
- [x] Import the evidence into the proof registry and pin the merged registry
      commit, verification records, deployment records, and replayed proof
      fields in the consumer lock before activation.
- [x] Stage identical v2 sidecars on Hetzner and VPSBG.
- [x] Rebuild and deploy the server binary and Tier 3 UKI required for dual
      serving; rotate reviewed runtime pins without a fallback window.
- [x] Verify the db 0/db 1 v2 wire responses and evidence digests on both
      production hosts.
- [x] Switch strict native/WASM/Web clients to v2, remove temporary v1 Onion
      layout pins, and fail closed rather than falling back to v1.
- [x] Pass all strict production browser/native canaries after the client
      cutover.

## 5. Continue repository-boundary migration

The initial HarmonyPIR, SDK-directory, and formal-proof milestone is complete in
PRs #61, #62, and #63. Continue in the order defined by
`REPOSITORY_BOUNDARIES.md`:

- [x] Move immutable generated proof bundles into `proof-registry` and add
      `verification/locks/generated-proofs.json` plus consumer re-verification.
- [x] Reconcile the duplicate `rootbundle` implementations: pin the protected
      `attested-builder` release, verify shared golden and retained production
      payloads, and remove the nested copy.
- [ ] Move remaining `pdf/` sources into `Bitcoin-PIR/whitepaper` after a
      reproducible build comparison.
- [ ] Group remaining in-repository crates/apps/tools in small path-only PRs.
- [ ] Extract a reusable Web client package while keeping production trust
      policy in this repository.
- [ ] Consider standalone explorer/Electrum/development-issuer repositories only
      after they consume the shared strict client flow.
- [ ] Handle full builder extraction and `vendor/` replacement last, gated on a
      byte-identical hermetic offline build.

## 6. Independent non-blocking maintenance

- [x] Resolve issue #18 by producing empirical DPF/Harmony wire fixtures and
      implementing the all-Merkle-levels-parallel optimization.
- [x] Review and merge or close outstanding dependency-update PRs separately
      from the security and proof activation sequence.

## Closeout invariants

- Production activation and capability landing are separate decisions.
- No v2-to-v1 silent fallback is permitted in strict mode.
- Any server/UKI change must use an exact merged commit, archived artifact,
  reviewed binary/UKI/MEASUREMENT pins, and post-deploy attestation/channel/query
  gates.
- Any new snapshot or delta follows `DATABASE_ROOT_ROTATION_RUNBOOK.md`.
- Historical or superseded checklists are not reopened unless current code or
  production evidence demonstrates an actual gap.
