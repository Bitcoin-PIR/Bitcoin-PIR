# Publishing

This document is the operator's runbook for publishing the BitcoinPIR
crates to [crates.io](https://crates.io) and the `pir-sdk-wasm` package
to [npm](https://www.npmjs.com).

It is **not** yet a press-the-button runbook: several blockers must be
resolved first. Each blocker is listed below with a suggested fix.

## Publishable artefacts

| Artefact                          | Registry   | Status                                                    |
|-----------------------------------|------------|-----------------------------------------------------------|
| `pir-core`                        | crates.io  | 🟢 Packageable (registry dependencies only).              |
| `pir-sdk`                         | crates.io  | 🟢 Packageable after `pir-core` is published.             |
| `pir-channel`                     | crates.io  | 🟢 Packageable (registry dependencies only).              |
| `pir-identity`                    | crates.io  | 🟢 Packageable (registry dependencies only).              |
| `pir-attest-verify`               | crates.io  | 🟢 Packageable (registry dependencies only).              |
| `pir-runtime-core`                | crates.io  | 🟡 Blocked — git deps on `libdpf` and `arc`.               |
| `pir-sdk-client`                  | crates.io  | 🟡 Blocked — git deps and unpublished internal path deps. |
| `pir-sdk-wasm` (as a crate)       | crates.io  | 🟡 Blocked — direct and transitive non-registry deps.     |
| `pir-sdk-wasm` (as npm package)   | npm        | 🟢 Packageable (wasm-pack bundles all Rust deps).         |
| `pir-sdk-server`                  | crates.io  | 🟡 Blocked — transitively via `pir-runtime-core`.         |

🟢 = ready; 🟡 = blocked, unblocking is tracked below; 🔴 = needs
upstream refactoring, no ETA.

## Blocker 1 — dependencies that crates.io cannot resolve

### Current state

The affected packages currently contain these non-registry dependencies:

```toml
# pir-runtime-core/Cargo.toml
libdpf = { git = "...", rev = "..." }
arc = { git = "...", rev = "..." }

# pir-sdk-client/Cargo.toml
libdpf = { git = "...", rev = "..." }
harmonypir = { git = "...", rev = "..." }
pir-db-attest = { path = "../pir-db-attest" }
onionpir = { git = "...", rev = "...", optional = true }

# pir-sdk-wasm/Cargo.toml
arc = { git = "...", rev = "..." }
pir-db-attest = { path = "../pir-db-attest" }
pir-sdk-client = { path = "../pir-sdk-client", version = "0.1.0" }
```

`pir-db-attest` is currently `publish = false` and has an unpublished path
dependency on `rootbundle`. HarmonyPIR client state now comes directly from
the revision-pinned upstream `harmonypir` crate; the former workspace-local
WASM wrapper has been retired.

All git dependencies above are revision-pinned, which is appropriate
for reproducible workspace builds, but a pin is not a crates.io source.
Every non-development dependency in a published package must resolve
from a registry. That includes optional dependencies such as
`onionpir`: disabling its feature by default does not remove it from
the published manifest. A local `git` or `path` source may be retained
for development only when the same dependency also has a compatible
registry `version` fallback.

### Fixes (in increasing order of work)

1. **Publish or replace the external crates.** Publish compatible
   versions of `libdpf`, `arc`, `harmonypir`, and `onionpir`, then add
   registry `version` fallbacks to every git dependency. If a crate is
   not intended for crates.io, move the required code behind a
   publishable workspace interface instead.

2. **Resolve the internal path-only crates.** Make `rootbundle` and
   `pir-db-attest` publishable in dependency order and give each path
   dependency a `version`, or fold their public functionality into an
   already-publishable crate.

3. **Re-run packaging from the registry form.** Run `cargo package`
   and `cargo publish --dry-run` for each dependent crate. `--list`
   checks the file set but does not prove that the packaged dependency
   graph can be resolved from crates.io.

## Blocker 2 — `pir-sdk-server` depends on internal binary crates (RESOLVED)

### Resolution

Extracted the shared server runtime primitives into a new publishable
library crate `pir-runtime-core` (≈2 kLOC: `protocol` wire format,
`table` mmap'd cuckoo reader, `eval` DPF evaluation, `handler` request
dispatch). Both `pir-sdk-server` and the workspace-internal `runtime/`
binary crate now depend on `pir-runtime-core` instead of maintaining
parallel copies. `pir-sdk-server` dropped its unused `build` dep and
the `publish = false` gate.

The extraction itself is complete. `pir-sdk-server` is now blocked
only transitively by `pir-runtime-core`, whose remaining registry
incompatibilities are the git-only `libdpf` and `arc` dependencies.
After both have registry versions, the server-side publish order is:

```
pir-core + pir-channel + pir-identity → pir-sdk → pir-runtime-core → pir-sdk-server
```

🔒 PIR invariants preserved. The extraction is a pure code move; the
wire format, slot layout, DPF evaluation, and request-dispatch
semantics are byte-identical. K=75 INDEX / K_CHUNK=80 CHUNK /
25-MERKLE padding continues to be enforced in `pir-sdk-client`, and
`pir-runtime-core` is the server-side counterpart that answers padded
queries uniformly.

## Publish order

Once the blockers above are cleared, publish in this order to respect
the dependency graph:

1. `pir-core`, `pir-channel`, `pir-identity`, and `pir-attest-verify`
   (registry dependencies only).
2. `pir-sdk` (depends on `pir-core`).
3. Registry releases for `libdpf`, `arc`, `harmonypir`, and `onionpir`.
4. `rootbundle` and `pir-db-attest`, if they remain separate crates rather
   than being folded into publishable parents.
5. `pir-runtime-core` (depends on `pir-core`, `pir-channel`,
   `pir-identity`, `libdpf`, and `arc`).
6. `pir-sdk-server` and `pir-sdk-client` after their respective
   dependency graphs are available from crates.io.
7. `pir-sdk-wasm` as a crate (depends on `pir-sdk-client`,
   `pir-attest-verify`, `pir-db-attest`, and `arc`).

Between each step, wait ~30 s for crates.io's index propagation
before the next `cargo publish` so Cargo can resolve the
just-published dep.

## crates.io publishing — per-crate checklist

For each crate:

1. **Update version** in the crate's `Cargo.toml`. Pre-1.0: bump
   patch for bug fixes (`0.1.0` → `0.1.1`), minor for new APIs
   (`0.1.0` → `0.2.0`). Workspace crates currently ship in lockstep
   at the first release, with per-crate semver freedom afterward.

2. **Update release notes**: if the crate has a `CHANGELOG.md`, move the
   `Unreleased` section under a new version heading and add a fresh empty
   `Unreleased`. Add a changelog before the first public release if the
   crate is intended to maintain one.

3. **Verify clean package**: `cargo package -p <crate> --list` to see
   what ships, `cargo package -p <crate>` to build the tarball.
   Sanity-check: the tarball should include `LICENSE-MIT`,
   `LICENSE-APACHE`, `README.md`, any maintained `CHANGELOG.md`, and only
   the required source/metadata files (not the whole workspace).

4. **Dry run**: `cargo publish -p <crate> --dry-run`.

5. **Publish**: `cargo publish -p <crate>`.

6. **Tag the release**: `git tag -s <crate>-v<version> -m "..."`,
   `git push origin <crate>-v<version>`.

## npm publishing (`pir-sdk-wasm`)

wasm-pack does **not** copy every field from `Cargo.toml` into the
generated `pkg/package.json`. The missing fields (repository,
homepage, keywords, license) are patched in by
`scripts/prepare-wasm-publish.sh` (see next section).

### Steps

1. Build release: `wasm-pack build --target web --out-dir pkg --release`
   inside `pir-sdk-wasm/`.
2. Patch metadata:
   `./scripts/prepare-wasm-publish.sh`
   (edits `pir-sdk-wasm/pkg/package.json` in place to add
   `repository`, `homepage`, `keywords`, `bugs`, and a tighter
   `description`).
3. Dry run: `(cd pir-sdk-wasm/pkg && npm publish --dry-run)`.
4. Publish: `(cd pir-sdk-wasm/pkg && npm publish --access public)`.
   The `--access public` is required for unscoped packages on a
   free npm account.
5. Tag the release:
   `git tag -s pir-sdk-wasm-npm-v<version> -m "..."`.

The npm version **must** match the Rust crate version. Let the
helper script's sanity-check enforce this — it reads the version
from `Cargo.toml` and refuses to proceed if `pkg/package.json` is
out of sync.

## Version bump checklist

Use this before every crate or npm release:

- [ ] `version` bumped in `Cargo.toml` (or `package.json` for npm).
- [ ] `CHANGELOG.md` Unreleased section promoted to versioned
      heading; `[Unreleased]` / `[<version>]` compare links updated.
- [ ] `cargo test` / `cargo test --features onion` clean where
      applicable.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.
- [ ] `cargo doc --no-deps -p <crate>` builds without warnings.
- [ ] (for `pir-sdk-wasm`) `wasm-pack build --target web` succeeds,
      `pkg/pir_sdk_wasm.d.ts` matches the public API in the README.
- [ ] (for npm release) `scripts/prepare-wasm-publish.sh` run; diff
      on `pkg/package.json` checked.
- [ ] `git status` clean on the release branch.

## Unpublishing

crates.io does not support unpublishing. The only remediation is
**`cargo yank`**:

```bash
cargo yank --vers <version> -p <crate>
```

A yanked version stays on the registry (dep resolvers that already
have it in a `Cargo.lock` continue to work) but is hidden from fresh
resolves. Yanking is reversible: `cargo yank --vers <version>
--undo -p <crate>`.

For npm, `npm unpublish <pkg>@<version>` works for 72 hours after
publish. Past that, use `npm deprecate` with a migration message.

## Preserving PIR invariants across releases

🔒 Every release must preserve the **Merkle INDEX item-count
symmetry** invariant and the K=75 INDEX / K_CHUNK=80 CHUNK /
25-MERKLE padding. Before tagging a release, re-read the
"CRITICAL SECURITY REQUIREMENTS" section of the root `CLAUDE.md`
and confirm that no change in the release window has touched:

- `pir-sdk-client::dpf::query_batch` / `harmony::query_single` /
  `onion::query_index_level` symmetric-probe paths.
- `pir-sdk-client::merkle_verify::verify_bucket_merkle_batch_generic`
  K-padded sibling-batch driver.
- `pir-sdk-client::onion_merkle::verify_onion_merkle_batch`
  K-padded FHE sibling-batch driver.
- `pir-sdk-wasm::client::WasmDpfClient` /
  `WasmHarmonyClient::sync` / `query_batch` — they're thin shims;
  a change in the native client does not reach through them, but a
  change in the WASM layer can bypass them.

If any of those files appear in `git log --oneline v<prev>..HEAD`,
make a note in the release PR explaining how the invariants are
preserved.
