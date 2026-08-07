# Production rollout remainder — after the 2026-08-06/07 harmony fix

Status: 2026-08-07. This file is the handoff for the next session. Everything below is
a *remaining* item; nothing here is already finished. For the decided root-cause
verdicts see PR #139/#146 and `docs/PR_CLEANUP_TRACKER.md` (P0-1, state DEPLOYED).

## State right now (verified live)

| Item | Value |
|---|---|
| weikeng1 (Hetzner provider, hint+query+onion) | binary `c836e11a…` (`git_rev=831a5ea1`), policy **epoch 10**, no SEV |
| weikeng2 (VPSBG Tier-3, DPF+harmony-query) | binary `4f51c64d…` (`--features cuckoo-oram`), UKI `dcb5c867…`, MEASUREMENT **`1c375b26…`**, policy **epoch 4**, measured-boot **image id 229** |
| pir2 rollback targets | images **223, 225, 227** retained in the VPSBG API image list |
| Web bootstrap pins | `web/src/attest-pin.ts` + `web/src/functional-beta-trusted-bootstrap.json` point at the live values above |
| Green on production | DPF live paths; hint V2 download; `query_batch` / `sync_single` harmony; onion register-once + full Merkle; db0+db1 tree-tops (<1 s round trips) |

## R1 — OPEN defect: V2-half CHUNK rejection in the root-tier harmony canary

**Observed (reproducible, deterministic):**
`test_harmony_strict_production_canary` (the variant that installs **both** db0 and
db1 database roots first) fails inside `client.sync(&probes, None)` at its first
V2-half fetch with:

```
strict HarmonyPIR fresh sync failed: ServerError("V2-half CHUNK: service authorization
required: secure encrypted channel is required")
```

The two simpler variants (`…_sync_single`, the raw driver in
`crates/sdk/client/tests/local_production_repro.rs`, and the four-pair production
frames) all pass. Failure is deterministic on both post-fix providers.

**Where the error comes from:** server-side gate branch for *unencrypted* backend
frames: `apps/server/src/bin/unified_server.rs:10547-10558` →
`GateErrorV1::SecureChannelRequired`. Two real mechanisms reach it:
1. the client genuinely sent the frame unsealed, or
2. the server could not `open()` the sealed payload with that connection's session —
   the same code path means an unresolvable/stale-session key ALSO lands here as if
   it were cleartext.

**Why it's probably a client-side channel/grant lifecycle issue (needs proof, not a
guess):** on the working trace-based runs earlier the V2-half downloads for db0
completed fine before the failure appeared; the failing variant differs only by
having db1's verified roots installed first. So what changed is leg/conn routing
or channel state after db1 root installation.

**Suggested first investigation step next session:**
1. temporarily re-add the client frame trace (env-gated in
   `crates/sdk/client/src/connection.rs`, ~6 lines; the version used in the
   2026-08-06 session printed opcode + size + a cumulative counter per reassembled
   record) and re-run the failing test. Capture EXACTLY:
   - which opcode the server rejects (expected: V2-half/bucket-bucket hint fetch),
   - which connection it goes over (hint vs query provider slot),
   - whether the channel session on that leg was refreshed after db1 root
     installation (if it wasn't, the server behavior is CORRECT and the client
     needs to re-add the channel/grant update step).
2. Once localized: whether it is client leg-routing or a server gate ordering
   issue (e.g., the gate mapping V2-half fetch to the wrong grant's operation when
   db1 the second manifest root got attached).

**Files:** `crates/sdk/client/tests/integration_test.rs:884-950` (canary body),
`HarmonyClient::{preflight_verified_database, sync}` (`crates/sdk/client/src/harmony.rs`).

## R2 — INTENDED (next stage already promised by the templates): db1 paid tier

The current production policies only admit **db0-bound** scopes:
- VPSBG template comment («add a separately priced scope and fresh BAT/ARC bindings
  before ever admitting db1») and Hetzner deployment notes — db1 was deliberately
  deferred.

So all db1-specific query/delta flows today terminate at
`OperationMismatch`/`OperationSequence` by design. The temporal dependencies are NOT
bugs. To make them work requires the operator-side deliverables below (order
matters):

1. db1 manifest root (the delta super-root, its bundle/proof-v2 piece is already
   installed for the strict clients) + a **separately priced db1 scope** with its
   own BAT/ARC bindings (the issuer's `issuer-root.key` and the same
   `bpir-admin payment-artifact credential-binding` pattern used in the
   `build-v*-bindings.sh` rolls).
2. Sign a new policy epoch incorporating the db1 scope (same four existing scopes
   byte-preserved) — e.g., weikeng1 → epoch 11+; VPSBG → epoch 5+ (requires ONE
   more Tier-3 UKI bake + upload since the policy is embedded).
3. After that, re-run the db1-context strict-canary variants and mark P0-1(4)
   FULLY closed.

Affected by intent right now (and expected to stay red UNTIL R2):
`test_dpf_strict_production_canary` (its delta-sync phase),
`test_harmony_strict_production_canary`**(first sync too, see R1)**, plus anything under
a future `tee-oram-query-v1` scope (no provider offers it yet).

## R3 — CI re-gating (after R1 and R2)

In `.github/workflows/pir-sdk-integration.yml`, flip these back from
`continue-on-error: true` to required once R1 closes (and R2 ships for db1):
- step `Run native database-root canary (DPF + HarmonyPIR)`
- step `Run native database-root canary (OnionPIR)`
- steps `Run HarmonyPIR leakage invariants (one retry)` and `Run OnionPIR leakage invariants`
Then refresh their inline advisory comments (they currently describe the pre-fix
ground truth).

## R4 — Deployment hygiene (safe to defer, each needs an explicit operator call)

- **VPSBG measured-boot image cleanup**: 223 / 225 / 227 are superseded.
  `DELETE /v1/measured-boot-images/{id}` is irreversible — only once the operator
  confirms the rollback window is closed. Do not automate.
- **pir-secondary (8092)** still runs the old dev binary from
  `/home/pir/BitcoinPIR/target/release/unified_server` (`cc4ec24b…`). Not routed
  publicly today; either swap it onto the `c836e11a` staging path or retire the
  unit.
- **UKI staging artifacts** in `deploy/uki/` (227 + 229 `.efi` ≈314 MB each,
  `.meta`, `.sha256`) are untracked locally. Prior repo convention committed these;
  decide once whether the two new ones go in (and fill `active_image_id=227/229`
  in their `.meta` files first).
- **pir1 rollback safeties kept**: `/opt/bitcoinpir/unified-server/d23b5841…`
  mirror retained; `pir-primary.service.bak-*` unit backups;
  `/etc/bitcoinpir/.../provider/service-policy-v5.bin` retained (pre-epoch-10
  artifact; rollback floor in the provider store).
- **Failed-rotation artifacts** (`service-policy-v6.failed-arc-lineage-…`,
  `service-policy-v7.failed-spend-namespace-…`) kept as-is: the epoch 9/10 lineage
  verified cleanly on top of them.

## R5 — Signing/operator materials (locations, no secrets here)

| Provider / role | Live reference (public) | Where its *signing* keys live |
|---|---|---|
| weikeng1 (`9110aee8`, pir1-payment-beta) | policy pub `6528d01b…` | **`/etc/bitcoinpir/payment-v1/functional-beta/provider/policy-signing.key`** on pir-hetzner (NOT locally on the laptop — deliberate) |
| weikeng2 (`85bfdd55`, pir2-vpsbg-dpf-v1) | policy pub `73c5889e`, operator pub `7ecb79` | `…/production-deployments/artifacts/vpsbg-free-pow-premium-beta-20260802/private-inputs/vpsbg-policy-signing.key` (Laptop, verified) |
| provider2 (`83076521`, pir2-payment-beta, third-party leg) | policy pub `c2e0598b` | `~/bitcoin-pir/production-secrets/payment-v1-functional-beta-provider2-20260802/{policy,operator,server-identity}.key` (Laptop) |
| VPSBG portal API | measured-boot images + reboot | `~/.config/bitcoinpir/secrets/vpsbg-api-token` (Laptop; **first `kernel_image_id` field for the apply**, a bare `image_id` just restarts) |

## R6 — Verification snippets (reuse as-is)

```bash
# live policy dump (epoch / limits per scope; any provider):
REPRO_LEG=1 cargo test -p pir-sdk-client --test live_policy_dump -- --ignored --nocapture   # weikeng1
REPRO_LEG=2 cargo test -p pir-sdk-client --test live_policy_dump -- --ignored --nocapture   # weikeng2

# strict canary matrix (DB0 flows):
PIR_STRICT_PRODUCTION_CANARY=1 cargo test -p pir-sdk-client --features fastprp \
  --test integration_test strict_production_canary -- --ignored --test-threads=1 --nocapture

# onion full verified session:
PIR_STRICT_PRODUCTION_CANARY=1 cargo test -p pir-sdk-client --features onion,fastprp \
  --test integration_test onion_tests::test_onion_strict_production_canary_query_batch \
  -- --ignored --nocapture

# db0+db1 tree-tops (;<1 s each against production after the budget fix):
REPRO_URL=wss://weikeng1.bitcoinpir.org \
  cargo test -p pir-sdk-client --test local_production_repro \
  db0_tops_succeeds_db1_tops_succeeds_postfix_local -- --ignored --nocapture
```

## PR / commit ledger

- PR #139 — merged: server fix `9b7128f0`, canary/test wiring `831a5ea1`,
  harness `49c6c3fc`, tracker evidence `a52fb5cf`, pins publish `f7c64e5e`.
  (Additionally the Deploy-side ops that day: pir1 binary swap, pir2 UKI 227
  from the same branch at 831a5ea1.)
- PR #146 — merged: repoint pir2 pins to epoch-4 measurement (`10721af0`),
  P0-1 → DEPLOYED with witnesses (`68177f9b`).
- Production prove-out loop over both merge sets:
  `test_harmony_strict_production_canary_{sync_single,query_batch}`,
  `onion_tests::test_onion_strict_production_canary_query_batch`,
  `db0+db1 tree-tops`, and the strict attestation (`--expect-measurement`)
  all PASS against live.
