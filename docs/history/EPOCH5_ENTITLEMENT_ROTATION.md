# pir2 entitlement rotation: a one-field quota change cost two full key ceremonies

**Status:** closed 2026-08-26. Production is green on the epoch-5 policy and
the originally failing workflow now passes on main. Root causes are listed
below in the order an operator hit them; each is paired with the fix that
landed or the structural question it leaves open.

**TL;DR:** The strict Harmony production canary started failing deterministically
on 2026-08-22 because the signed entitlement scope no longer covered the real
product query. The scope limits live inside the SEV-SNP measured identity, so
correcting them meant re-running the entire sealed key ceremony — and because
the first correction was sized from a *lower bound* instead of an exact count,
that ceremony ran twice before the budget was right.

## Timeline

- **2026-08-22 — deterministic canary failure begins.** DPF canary passes;
  Harmony fresh sync fails ~20 s in with `Connection reset without closing
  handshake`. Rerunning the same workflow on different CI runners fails
  identically. Last known green run is 2026-08-20.
- **First diagnosis: work units.** The signed Harmony scope carried
  `max_work_units = 10,000`; the minimum legal query on the live database
  already required 393,200. The failure had no config-error signature because
  the server's `ResourceLimitExceeded` surfaced to the client as a bare
  WebSocket reset, and the Rust canary had no preflight — it burned PoW, hint
  downloads, and authorization before hitting the wall.
- **PR #256 (merged 2026-08-24): client preflight.** `query_plan.rs` gained a
  signed-scope preflight; the canary now fails fast with
  `requires at least 393200 work units, signed maximum 10000`.
- **Epoch-4 ceremony (2026-08-24/25).** A new policy raised the Harmony
  work-unit cap to 1,000,000 — sized from the 393,200 lower bound plus
  headroom, on the ground that a historical template had used 1,000,000. The
  full rotation executed: new tier-3 UKI pinned to the epoch-4 policy,
  ordinal 23–30 Observe/Enroll/Probe/Ready boots, generation-1 identity,
  clearing epoch 1, artifact chain, activation.
- **2026-08-26 — canary still red.** DPF and OnionPIR pass; Harmony now fails
  with an explicit `service entitlement limit exceeded` during the Merkle
  sibling CHUNK round. Exact measurement of the complete transcript showed the
  real constraint: `max_request_bytes`. The product transcript needs
  2,153,811 bytes; the signed scope allowed 2,097,152 — short by 56,659
  (2.7%). The work-unit fix had addressed a limit the query never reached.
- **PR #257 (merged 2026-08-26): exact transcript accounting.** The client
  planner now counts the full mandatory Harmony request (INDEX, CHUNK-on-field,
  and Merkle sibling frames) before any auth/PoW/download, with regression
  tests pinning the byte count.
- **Epoch-5 ceremony (2026-08-26).** Policy epoch 5 raised the Harmony request
  budget to 4 MiB. A second full rotation ran on a new runtime UKI (ordinals
  31–38, identity generation 3, clearing epoch 2, artifact chain, activation).
  PR #259 pinned the epoch-5 runtime for the web client; Pages deployed.
- **Closure.** The manually dispatched integration workflow on the merge
  commit passed every job, including the three privacy-leakage canaries.

## Root causes

1. **Signed limits drifted below the product transcript.** The Harmony scope
   was configured before the database grew to its current shape; nothing
   recomputed the required budget when databases rotated until the canary
   turned red. The DPF scope never drifted — its transcript is smaller.
2. **Client bounds vs. server accounting mismatch (the expensive one).** The
   planner intentionally produced *lower bounds* and omitted Merkle sibling
   traffic; the server's grant tracker counts every frame's bytes exactly.
   Sizing the epoch-4 fix from a lower bound therefore undershot the real
   constraint, and the undershoot was only discovered after the full epoch-4
   ceremony had executed. Rule now encoded in the planner: a policy budget
   must be sized from the exact mandatory transcript, never from a bound.
3. **Entitlement limits live inside the measured identity.** Because the
   policy document is locked into the tier-3 UKI measurement, any entitlement
   edit is not a config reload: it is a new measured identity, an envelope
   wipe, fresh wraps of both Ed25519 seeds, a new identity generation, a new
   clearing epoch authorization chain, 4+ attested boots with fresh ordinals
   and nonces, republished pins, and a Pages release. That coupling is a
   deliberate design property (clients attesting to pir2 can require that the
   operator cannot silently change published quotas); it also means a 2.7%
   quota error costs a complete ceremony. Whether resource quotas should stay
   in the measurement or move to a measurement-attested operator-signed
   document is the structural question this incident leaves open; it is not
   pre-decided here.
4. **Failure observability.** The server's structured `ResourceLimitExceeded`
   became a transport reset by the time it reached the client, which is why
   days of reruns looked like network flakiness. The #256 preflight now
   surfaces the exact dimension and numbers before any paid work.

## Operational friction catalog (all fixed or documented during the incident)

- **Cloudflare cached a receipt across phases.** The recovery HTTP root serves
  `Cache-Control: max-age=14400`; an Enroll receipt fetch returned the previous
  Observe receipt with `CF-Cache-Status: HIT`. Mitigation is now written into
  the sealed-release runbook: verify the receipt hash against the phase status
  JSON, and retrieve gating receipts through the Flow F data-disk window.
- **VPSBG API races.** A detach can succeed while the immediately following
  stop returns HTTP 423; `close` attaches an image but does not start the
  guest, and the platform auto-start can take tens of seconds to settle. Read
  back nested `state.running` before concluding anything. Documented in
  `docs/KEY_MANAGEMENT.md` and `docs/PRODUCTION_OPERATIONS.md`.
- **Hetzner dracut drift.** The tier-3 UKI contract could not be reproduced on
  the Hetzner builder (BusyBox module check rejection, forbidden plymouth/drm
  pull-in); the runtime UKI was built in the VPSBG stock environment instead.
  Build-environment drift is a standing risk for Flow E.
- **macOS bash 3.2.** Both status wrappers crashed on empty-array expansion
  under `set -u` (#261, #262 — now guarded in the offline ops fixture), and
  `vpsbg-measured-boot.sh status` learned to accept `--token-file` for linked
  worktrees (#262).

## Evidence and retained material

- Pull requests: #256, #257, #259 (code/pins); #260 (operator docs); #261,
  #262 (script fixes).
- Local operator archives, outside git: `.keys/pir2-ceremony/epoch5/` (the
  deployed ceremony, with the full HANDOFF) and
  `.keys/pir2-ceremony/retired/epoch4-image293/` and
  `.keys/pir2-ceremony/retired/epoch4-candidate/` (the superseded epoch-4
  materials, retained for the rollback envelope and audit trail; their
  ordinals, nonces, and digests must never be replayed).
