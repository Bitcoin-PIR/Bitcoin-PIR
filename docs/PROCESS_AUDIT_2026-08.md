# Engineering-process and repository-architecture audit (2026-08-14)

Status: point-in-time audit record and improvement plan, produced from a
read-only review of `main` at `137056d2`. It changes no production behavior.
The follow-up documentation work it prescribes is tracked as "Step 1" below.

Scope: development/testing entry points, CI coverage, the database production
lifecycle, release-identity sources of truth, documentation layering, and
repository-split evaluation. Production live state was deliberately **not**
queried; nothing here is a claim about what is currently serving.

## Findings

Severity uses the repository rule: only P0/P1 may block delivery. There are
no P0 findings. None of the P1 findings are protocol or correctness defects;
they are operational-safety and process-clarity defects.

### P1-A — "Which tests do I run?" has no trustworthy answer

- `AGENTS.md` names `docs/TESTING.md` as the default entry, but that file
  only documented the Payment V1 profiles (`--quick` runs a single
  `pir-runtime-core` service-admission test; see
  `scripts/payment-v1-local-check.sh`).
- `--pr` calls itself "CI-equivalent" but covers none of: `pir-core`,
  `tools/db-builder`, `explorer/`, `electrum_plugin/`, UKI contracts.
- The real change→check mapping only existed implicitly in the `paths:`
  filters of nine workflows.

Resolution: `docs/TESTING.md` now carries a change-class matrix and
`docs/README.md` is the operations/documentation index.

### P1-B — CI contradicts its own stated policy and has blind spots

- `.github/workflows/pir-sdk-integration.yml` states (header, lines 15–21)
  that PRs run only deterministic tests and live coverage belongs to the
  scheduled canary — but the OnionPIR live `--ignored` step (line 235) has no
  event filter, so every PR touching SDK paths hits production and can fail
  on production availability changes. The sibling DPF step (line 114–116)
  and both canary steps are correctly filtered.
- No workflow covers `crates/sdk/server`, `tools/db-builder`, `explorer/`,
  `electrum_plugin/`, `apps/dev-issuer`, or the `scripts/build_*.sh` data
  pipeline scripts. `tools/db-builder` has no `tests/` directory at all.
- `main` has no aggregate required check; merges are manual inspection of
  path-filtered Actions results (`docs/PROJECT_CLOSEOUT_TODO.md:124-126`).
  This is a known, deliberate state — recorded here, not re-litigated.

Planned fix (separate one-line PR, not this documentation change): add the
same `if: schedule || workflow_dispatch` guard to the OnionPIR live step.

### P1-C — Two contradictory database-production narratives

- Legacy narrative: `scripts/README.md` ("Regular database refresh
  runbook") and `doc/DEPLOYMENT.md` describe local `build_full.sh` → rsync →
  SSH → `systemctl restart`, ending with **deleting** the previous
  checkpoint.
- Current contract: `docs/DATABASE_ROOT_ROTATION_RUNBOOK.md` +
  `docs/DATABASE_ARTIFACT_RETENTION.md` — attested-builder producer,
  independent `db-proof verify`, dual-host staging without activation,
  maintenance-window atomic switch, and retention of the prior generation;
  the two raw Core snapshots are irreplaceable (a delta cannot reconstruct
  the earlier snapshot's spent Coin fields).
- Neither side referenced the other. Following the legacy text can cause
  irreversible data loss. Resolution: banners on the legacy documents.

### P1-D — Stale release-identity copies in high-authority locations

Old values written in present tense where agents/operators read first:

| Location | Said | Actual authority |
|---|---|---|
| `CLAUDE.md` attestation-pins section | image 229, binary `4f51c64d…`, measurement `1c375b26…` | `web/src/attest-pin.ts` (image 265, `4b05fc90…`, `e3f6b4df…`) + `docs/data-retention/production-release-image-265.env` |
| `.claude/skills/hetzner-pir/SKILL.md` | pir1/pir2 = one Hetzner box, two ports | Hetzner hint + VPSBG Tier 3 query split (`pir-sdk-integration.yml:71-79`) |
| `docs/ORAM_LIVE_IMAGE_BINDING_PLAN.md:6` | "Production VPSBG image 261" | design record; live state must be queried |
| `docs/OPERATOR_IDENTITY.md:8-14` | "LIVE" + v22/v23 binary hashes | `attest-pin.ts` |

Resolution: replace copied values with pointers; banner the stale documents.
Rule going forward: **do not copy pin values into prose documents** — link
`web/src/attest-pin.ts`, `docs/data-retention/`, and the status script.

### P2-E — Split build authority for the pir2 production binary

`scripts/build_unified_server.sh:30-40` and `flake.nix` present
`nix build .#unified-server` as the canonical pinned-hash build, while
`CLAUDE.md` forbids both for Tier 3 (neither enables `cuckoo-oram`) and
`scripts/build_uki_tier3.sh:94` requires
`cargo build --release -p runtime --features cuckoo-oram`. Open question for
the owner: which path built the live pir1 binary, so the losing instructions
can be deleted rather than merely bannered.

*(Resolved 2026-08-15 — see Q2 below. Two bare-Cargo profiles are now the
declared production authority; the flake is a development/reproducibility
harness only. CLAUDE.md, `build_unified_server.sh`, and `flake.nix` updated.)*

### P2-F — `deploy/` is half-tracked; ops facts are not clone-recoverable

*(Corrected 2026-08-14 during Step 2: the five `deploy/systemd/*.service`
units were already tracked — tracked files bypass the `deploy/*` ignore.
The genuinely untracked items are as below.)*

`git ls-files deploy` returns `deploy/payment-v1/**` and
`deploy/systemd/*.service`, but the working tree also contains untracked
`installimage.conf`, `known_hosts`, `vpsbg_known_hosts`, `uki/`, `logs/`,
`attested-builder-runs/`, and a sensitive `cloudflared_tunnel.env`.
Consequences:

- the Hetzner skill's "source of truth" links point partly at files a
  fresh clone does not have;
- the SSH host-key pinning defense depends on an untracked `known_hosts`,
  so the defense itself is not reproducible from the repository;
- `deploy/uki/` (where CLAUDE.md says release UKIs are archived) is
  local-only state.

Suggested follow-up (separate PR, owner decision): track the non-secret
fixed values (`known_hosts`, `vpsbg_known_hosts`, `installimage.conf`);
document the locations and backup story of the secret and artifact entries
in a `deploy/README.md`.

### P2-G — Documentation layering

Two documentation roots (`doc/` and `docs/`); dated plans, completed
rollouts, and a stale whitepaper checklist in the `docs/` root;
`docs/history/README.md` indexes only part of the historical set; there was
no `docs/README.md`. Resolution: the new index classifies documents and
names the single current entry point per operation.

### P3-H — Miscellaneous drift

- `scripts/build_uki_tier3.sh:1-24` header still self-describes as the
  "Phase 3.1" minimal UKI though it now enforces the policy digest and
  bakes the full server.
- `docs/PROJECT_CLOSEOUT_TODO.md:128-130` ("no remaining backlog") vs
  `docs/PR_CLEANUP_TRACKER.md` P1-2 (paid TEE-ORAM BLOCKED).
- `scripts/start_pir_servers.sh` is a local two-port topology; fine, but
  should be labeled dev-only.

## Repository-split evaluation (summary)

No new repository should be split now. Payment V1, the production Web app,
trust/verification consumers, deployment integration, and `vendor/` must
stay (they need atomic commits with the runtime and hold the production
trust policy). `explorer/`, `electrum_plugin/`, and a reusable web-client
package remain "split only after the `docs/REPOSITORY_BOUNDARIES.md` gates
are met" — none currently are. Already-external repositories
(protocol-proofs, proof-registry, attested-builder, harmonypir, oram,
whitepaper) stay external behind their exact-commit locks.

## Improvement plan

### Step 1 (documentation only — implemented alongside this record)

1. `docs/README.md` — operations and documentation index (new).
2. `docs/TESTING.md` — change-class → required-checks matrix; `--quick`
   demoted to the Payment/agent default rather than a whole-repo test.
3. Banners: `scripts/README.md` (legacy DB refresh + deletion advice),
   `doc/DEPLOYMENT.md` (historical self-hosting sketch),
   `docs/OPERATOR_IDENTITY.md` (status section historical).
4. `CLAUDE.md` attestation-pins section → pointers only, no copied values.
5. `.claude/skills/hetzner-pir/SKILL.md` — topology correction and
   untracked-`deploy/` warning.

No CI change, no file moves, no new gates, no pin/policy/proof changes.

### Step 2 (1–2 weeks, three independent small PRs)

1. OnionPIR live-test event filter in `pir-sdk-integration.yml` (enforces
   the workflow's own stated policy).
2. `deploy/` tracking boundary (P2-F above).
3. Build-authority declaration or deletion in `build_unified_server.sh` /
   `flake.nix`, after the owner answers which path is canonical.

### Step 3 (1–3 months, as needed)

- A release-record template generalizing
  `docs/data-retention/production-release-image-265.env` (one filled per
  release; evidence, never a substitute for querying live state).
- Converge `tools/db-builder` scripts with the external attested-builder:
  either wrap the locked producer or label the local pipeline
  research/dev-only.
- Design an internal `packages/web-client` (the prerequisite for any future
  explorer/electrum extraction). Do **not** move `web/` → `apps/web` as a
  standalone rename.
- Automate identity-consistency checks only (extending the existing
  `web/src/__tests__/proof-registry-lock.test.ts` pattern), not builds or
  deployments.

## Open questions for the owner

1. Is the local `scripts/build_full.sh` pipeline still permitted for a
   production database build, or is attested-builder the only producer?

   *(Answered 2026-08-15, from the owner's session-record investigation.)*
   **The current serving generations are of mixed provenance, and no
   "attested-builder is the exclusive producer" decision was ever made —
   that status cannot be claimed retroactively.** Facts:
   - Catalog: db0 = full at height 948454; db1 = delta 940611→948454
     (940611 is the delta base, not the serving full height).
   - weikeng1 db0 (June 2026 generation) is a hybrid: local-pipeline
     `utxo_set.bin` input → attested-builder rebuild of the
     DPF/Harmony/Merkle stages → OnionPIR serving files copied from the
     2026-05-24 local checkpoint (roots byte-equal) → manifest written by
     this repo's `build_db_manifest.sh`.
   - weikeng1 db1 is attested-builder from two raw Core snapshots for the
     core stages, but `gen_2_onion`/`gen_3_onion`/`gen_4_build_merkle_onion`
     + the manifest came from this repo's tools (2026-06-16).
   - weikeng2 (August 2026, image 265) serves native-V2 `server-db`
     output built end-to-end by attested-builder commit `8d9d21a6…` —
     weikeng1 and weikeng2 no longer serve identical physical files.
   - Last confirmed fully-local production generation: 2026-05-24
     (manifests dated 2026-05-23). Later use of the three local wrappers:
     no record either way.

   **Agreed forward path for roadmap item 3.2:** first extend
   attested-builder to produce the complete server-loadable output
   (including the OnionPIR serving preprocessing and the manifest), run
   one end-to-end consistency acceptance against the hybrid generation,
   and only from that dated point declare "local wrappers are
   development/regression-only; attested-builder is the sole production
   producer". Until then the local pipeline stays bannered (not
   forbidden), as `scripts/README.md` already states.

2. How was the live pir1 binary (`c836e11a…`) actually built — cargo with
   features, the Nix flake, or `build_unified_server.sh`?

   *(Answered 2026-08-15, verified on the build host.)* Bare Cargo on
   `pir-hetzner`, worktree `/home/pir/build-831a5ea1` at commit
   `831a5ea1`, default features (`default` + `fastprp`), **no**
   `cuckoo-oram`, not Nix, not the wrapper script. Evidence: the deployed
   binary embeds `/home/pir/build-831a5ea1/vendor/...` source paths
   (the wrapper remaps those via `--remap-path-prefix`; Nix sources live
   in the store) and the cargo feature fingerprint recorded
   `["default","fastprp"]`; a later same-checkout `cuckoo-oram` build
   produced a different hash (`8d892590…`, never deployed to pir1).
   Exact flag string and an explicit `strip --strip-debug` invocation
   are unrecorded (binary state is consistent with strip-debug). pir1's
   roles (DPF-0 + OnionPIR + Harmony hint) do not need `cuckoo-oram`;
   that feature gates the Direct/Circuit ORAM path only (pir2).

   **Decision:** two bare-Cargo profiles are the production build
   authority —
   pir1: `cargo build --locked --release -p runtime --bin unified_server`;
   pir2: `cargo build --locked --release -p runtime --features cuckoo-oram --bin unified_server`;
   each followed by `strip --strip-debug`. The Nix flake is retained as a
   development/reproducibility harness only and is no longer described as
   a production authority anywhere; restoring it would require adding the
   feature plus fresh cross-host hash and runtime acceptance.
3. Are `explorer/` and `electrum_plugin/` still product surfaces, or
   experiments that should be demoted in the README?
   *(Answered 2026-08-14/15: owner decided to remove both —
   `electrum_plugin/` and then `explorer/` had each fallen behind the
   protocol, and the owner is considering direct BDK integration as the
   future wallet path instead. Both removed.)*
4. Should the three builder identities (v1 DPF/Harmony, Onion v2 re-attest,
   ORAM native) be collapsed to one at the next root rotation?
5. Is an aggregate required-check for `main` wanted, or is manual merge
   inspection the deliberate long-term state?
