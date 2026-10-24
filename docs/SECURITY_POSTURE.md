# Security posture

Where every pin, key and backup lives, who holds it, and what the last
review found in the dependencies, the TEE platform floor and the hosts.
Last review: 2026-10-12; the host and key rows were brought up to date on
2026-10-21, and the Rust dependencies were bumped again the same day (below).
The pir1 row, the key and backup rows and the open list were brought up to
date on 2026-10-24, after the E5 follow-ups (D4 backups, Core Lightning
v26.06.9, OS updates, `SECURITY.md`).
Repeat the review at each release and when AMD, RustSec or
an upstream publishes an advisory. This page names pins and keys; their
values stay in the files it names. The privacy invariants and their proofs
are in [Verification overview](VERIFICATION_OVERVIEW.md).

## Dependencies

How they are watched:

- **Rust, this repository:** `cargo audit` in
  [`audit.yml`](../.github/workflows/audit.yml), weekly and on every
  `Cargo.lock` change. It reports and never blocks. `.cargo/audit.toml`
  ignores RUSTSEC-2023-0071 and RUSTSEC-2026-0381 and says why.
- **Bumping a vendored crate by hand:** `.cargo/config.toml` replaces
  crates.io with `vendor/`, so Dependabot cannot bump Rust crates and
  `cargo update` sees only vendored versions.
  1. Work in a copy of the workspace whose `.cargo/config.toml` has no
     `[source]` tables. Keep the copy outside any checkout, because cargo
     also reads the config files of parent directories.
  2. Run `cargo update -p CRATE@OLD --precise NEW` there.
  3. Vendor the new version and replace its directory in `vendor/`.
  4. Update `vendor/bitcoinpir-oram/Cargo.lock` as well: that crate is
     excluded from the workspace and keeps its own lockfile, which the
     `runtime-features` CI lane tests with `--locked --offline`.
- **npm (`web/`) and GitHub Actions:** Dependabot, weekly.
- **No advisory database covers:** the git dependencies (libdpf,
  harmonypir, OnionPIRv2-fork with SEAL, fastprp). They are our own forks.
- **No automation at all:** the issuer and the playground repositories, and
  the binaries on pir1 that no lockfile covers (Core Lightning, cdk-mintd,
  Bitcoin Core, cloudflared, Caddy, the Ubuntu packages). See
  [Hosts](#hosts).

Results on 2026-10-12:

| Scope | Vulnerabilities | Warnings, and what was done |
| --- | --- | --- |
| This repository, Rust (321 crates) | 0 | Three crates had patched releases and were bumped: memmap2 (unsound range functions; we call none of them), rand 0.8 (unsound only with its `log` feature, which is off here) and the yanked spin 0.9.8. Left: bincode 1.3.3, unmaintained, via harmonypir; its authors call 1.3.3 complete. |
| `web/`, npm | 0 in runtime dependencies | 4 in the vitest 3 test chain: a tinypool prototype-pollution gadget, @vitest/mocker path traversal, and a source-map-js DoS. All are dev-only; vitest 5 fixes them. |
| Issuer, Rust (370 crates) | 0 | paste (a proc-macro) is unmaintained. |
| Playground, npm | next 14 (critical, high), monaco-editor via DOMPurify (moderate), nanoid, postcss, source-map-js | The site is a static export on GitHub Pages and no Next.js server runs, so the Next server advisories (image optimizer, server actions, middleware, RSC) do not reach visitors. DOMPurify is Monaco's internal sanitizer for its hovers and markdown. Next 14 → 16 is a major upgrade that nothing forces now. |

2026-10-21: the advisories of 2026-10-14 to 2026-10-20 moved rustls 0.23.45 →
0.23.46 (RUSTSEC-2026-0346 to 0349), rustls-webpki 0.103.15 → 0.103.16
(RUSTSEC-2026-0382) and webpki-roots 1.0.6 → 1.0.10 (RUSTSEC-2026-0381; its
0.26.11 shim is the one ignore). The ORAM crate's lockfile has none of these
crates. Every host runs a build from before this bump until the next release.

## TEE platform floor (Milan)

- **The rule:** every SEV-SNP report chained to the Milan ARK must meet
  `AMD_MILAN_SEV_SNP_FLOOR` in
  [`web/src/attest-pin.ts`](../web/src/attest-pin.ts). That means a minimum
  reported TCB per component, the alias-check bit, and mitigation-vector
  bit 1. The constant's comment lists the AMD bulletins the floor covers
  and those a report cannot show.
- **Who checks it:**
  - Browsers, through `applySevSnpPlatformFloor` on every verification.
  - `bpir-admin attest` (`--min-tcb`, `--require-alias-check-complete`,
    `--required-mit-vector-bits`), together with the default report policy.
    `scripts/production-pins.py` reads the floor from the same constant for
    the daily CI ORAM check, `scripts/production-status.sh` and
    `scripts/oram-host-check.sh`. Before 2026-10-12 only browsers checked
    it, so a host below the floor would have failed for every user while CI
    stayed green.
- **The 2026-10-12 review** (AMD bulletins 3000–3070 and 7025–7080):
  - No SEV bulletin was published or changed after 2026-10-02.
  - The floor's TCB is still the highest any Milan bulletin asks for.
  - **AMD-SB-3016 (IOMMU write buffer) was missing from the list.** The
    floor meets its firmware TCB. Its other half is mitigation-vector bit 2,
    which needs a fix in the host kernel; on 2026-10-12 server 26939 did not
    set the bit (launch and current vectors 0xb), so requiring it would have
    rejected the production host. **VPSBG's host kernel update of 2026-10-23
    set it:** on 2026-10-24 the live report's launch and current vectors are
    0xf, and `bpir-admin attest --required-mit-vector-bits 6` passes. Raise
    the floor to `0b110` (Open, below).
  - AMD has withdrawn Milan mitigation-bit and TCB indicators three times:
    3023's bit 3 in April 2026, and 3030's and 3034's on 2026-09-24. Read a
    bulletin's current text before relying on one.
  - **BadFuse** (arXiv 2605.12990, May 2026; reported, not reproduced here).
    The claimed attack needs root on the host and a firmware reflash:
    1. Downgrade Milan's off-chip bootloader to an AMD-signed recovery
       image; Milan has no anti-rollback for it.
    2. Run code on the AMD Secure Processor (MilanLaunchy, AMD-SB-3045).
    3. Recover the VCEK seed, which signs valid reports at any TCB.

    AMD answered that no action is needed, and there is no CVE. No floor can
    catch it, so against whoever controls the host's firmware (VPSBG) a Milan
    report proves less than it claims.
  - The microcode floor is a Milan (B1) value; server 26939 is an EPYC
    7713P. A Milan-X host would fail it.
- **To raise the floor:**
  1. Edit the constant.
  2. Run `scripts/production-status.sh`. The live ORAM host must still
     pass; otherwise Direct ORAM fails for every user until VPSBG updates
     the platform.
  3. Run Flow C ([Production operations](PRODUCTION_OPERATIONS.md)).

## Hosts

| Host | Exposure | State on 2026-10-12 |
| --- | --- | --- |
| pir1 (Hetzner) | ufw denies by default and opens: 22 (key-only root, rate-limited), 80/443 (Caddy, the old BHTM proof endpoint; stopped and disabled on 2026-10-21, nothing listens there now), 8333 (Bitcoin P2P), 9735 (Lightning P2P). The PIR server, issuer, mint and directory relay listen on loopback behind the Cloudflare tunnel. | Ubuntu 24.04, kernel 7.0.0-38 (HWE), rebooted 2026-10-24 after the first full update since 2026-05-05. What had blocked apt and unattended-upgrades for five months: the half-installed 7.0.0-15 kernel and a `libkmod2` 34.2 that is not from the noble archive, both left by a May experiment. dpkg repaired, `libkmod2` back to the noble version, the GA kernel meta `linux-image-generic` and the unused 6.8 kernels purged, 194 packages upgraded; `unattended-upgrade --dry-run` is clean again. Still from that experiment: the initramfs is built by a `dracut` 110 that is not from the noble archive (`initramfs-tools` is removed); it built the 7.0.0-38 initrd that booted. **Core Lightning v26.06.9** since 2026-10-24 (wallet DB schema 284; `database-upgrade=false` again; the v26.06.6 tree stays beside it). `bpir-cln-rpc-guard` runs from the 2026-09-28 issuer release directory, because the issuer releases since 2026-10-11 ship only `bpir-issuer` (found when the restart exposed it). cdk-mintd 0.17.3, against 0.18.1 current. Caddy stopped on 2026-10-21. cloudflared 2026.8.3, against 2026.10.0. Bitcoin Core v31.1. |
| Direct ORAM host (VPSBG 26939) | The Cloudflare tunnel only; a measured UKI with no SSH in production | Runtime image 407 (r12, since 2026-10-21). It meets the Milan floor and the report policy. VPSBG restarted the host on 2026-10-23 with a new host kernel and a fixed vCPU model (EPYC-Milan-v3); measurement, TCB and chip ID unchanged, and the report now carries mitigation-vector bit 2 (AMD-SB-3016): launch and current vectors 0xf on 2026-10-24. |
| MacBook (server 1) | Cloudflare tunnel | Offline for repair on 2026-10-12 (#385); back on 2026-10-14 on the ce5b4373 build (#437, #440). |

## Pins

| Pin | Where | Changes when |
| --- | --- | --- |
| AMD ARK fingerprints (Milan, Turin) | `attest-pin.ts`; Rust copies in `crates/trust/attest-verify` | never (AMD root keys) |
| Milan platform floor | `attest-pin.ts` `AMD_MILAN_SEV_SNP_FLOOR` | AMD publishes a Milan fix |
| Server binaries, ORAM MEASUREMENT | `attest-pin.ts` `PIR1_PIN`, `PIR2_MACBOOK_PIN`, `PIR2_TIER3_PIN` | each release ([Release checklist](RELEASE.md)) |
| Database proofs | `attest-pin.ts` `*_DB_PROOF_PIN(S)` | a new generation (Flow H) |
| Provider endpoints, operator public keys | [`web/src/production-providers.ts`](../web/src/production-providers.ts) | a provider changes (Flow C) |
| Directory publisher key | `production-providers.ts` `PRODUCTION_DIRECTORY` (pinned 2026-10-19, #441); the relay config on pir1, `/etc/bitcoinpir/directory-relay/config.toml` | the key is rotated |
| Issuer URL | `web/src/constants.ts` `PRODUCTION_ISSUER_URL` | the issuer moves |
| Issuer public key | servers: `--credit-issuer-pubkey /etc/bitcoinpir/issuer/grant.pub` (pir1's unit, the MacBook's plist) | issuer key rotation ([Issuer and mint](runbooks/issuer-and-mint.md)) |
| Operators that may redeem | issuer config `operator_pubkeys` | an operator is added or rotated |
| SSH host keys | `deploy/known_hosts` (pir1), `deploy/vpsbg_known_hosts` | a host is reinstalled |

The playground vendors `web/src` (`vendor/SOURCE_COMMIT.txt` in
Bitcoin-PIR/playground), so it carries the pins of the commit it vendors.

## Keys and secrets

The workstation files are described per file in
[Key management](KEY_MANAGEMENT.md).

| Secret | Where | Backup | If lost or leaked |
| --- | --- | --- | --- |
| pir1 operator key (signs pir1's identity certificate) | Mac Studio, `~/bitcoin-pir/production-secrets/payment-v1-functional-beta-operator-v1/operator.key` | maintainer's own | Lost: a new key, a new pir1 certificate, re-pin `PIR1_PROVIDER` and the issuer's `operator_pubkeys`. Leaked: anyone can certify a server as this operator. |
| pir2 / ORAM operator key | Mac Studio, `.keys/pir2-operator.key` | maintainer's own | The same, for the MacBook node and the ORAM host's directory assertion. |
| Directory publisher key | Mac Studio, `.keys/directory/directory-nostr.key` (generated 2026-10-19) | maintainer's own | Lost: a new key, re-pin `PRODUCTION_DIRECTORY`. Leaked: forged directory entries; clients still verify each provider's attestation or operator assertion. |
| Server identity keys | pir1 `/etc/bitcoinpir/payment-v1/functional-beta/provider/provider-identity.key`; the MacBook's `identity/server.key`. The ORAM host has none since image 375. | none; regenerable | A new key and a new certificate from the operator key. |
| Mint seed | pir1 `/etc/bitcoinpir/mint/seed` | offline bundle of 2026-10-23 ([Backups](#backups)) | Every issued ecash becomes unredeemable. |
| Issuer key (`grant.key`), issuer wallet seed | pir1 `/etc/bitcoinpir/issuer/` | offline bundle of 2026-10-23 ([Backups](#backups)) | Key: rotate and re-pin the servers. Wallet seed: the issuer's ecash claim on the mint is lost. |
| CLN `hsm_secret`, `emergency.recover` | pir1 `/srv/lightning/bitcoin/` | offline bundle of 2026-10-23 ([Backups](#backups)) | The node's on-chain funds and channel balance. |
| API keys | pir1 `/etc/bitcoinpir/api-keys` | offline bundle of 2026-10-23 ([Backups](#backups)) | Reissue to their holders. |
| Cloudflare tunnel tokens | pir1 `/etc/cloudflared/tunnel.env`; the ORAM host's data disk, `/home/pir/data/cloudflared/tunnel.env` (plaintext, outside the measurement); the MacBook | Cloudflare reissues them | A leaked token lets someone add a connector to that tunnel. That costs availability only: an impostor fails attestation. |
| VPSBG API token, VPSBG SSH key | Mac Studio, `.secrets/vpsbg-api-token`, `.keys/vpsbg-ssh.key` | maintainer's own | The ORAM host's control plane: reboot, image switch, the data disk. |
| Accounts: GitHub (Bitcoin-PIR org), Cloudflare (DNS, tunnels), Hetzner, VPSBG, Amboss (the liquidity order) | maintainer | — | — |
| Retired | `.keys/pir1-operator.key` and `.keys/pir1-server-identity.key` (pinned nowhere), `.keys/pir2-ceremony/`, pir1 `/etc/bitcoinpir/issuer/arc.seed` | — | nothing |

## Backups

| What | Backup today |
| --- | --- |
| Mint seed and database, issuer key, wallet seed, database and ledgers, CLN `hsm_secret`, `emergency.recover` and database, API keys, the service configs | One gpg-encrypted bundle (AES-256, passphrase held by the maintainer, never stored) staged in pir1's tmpfs on 2026-10-23 with online-backup snapshots of the live SQLite files, decrypt-verified there, copied to the maintainer's workstation and offline, and removed from pir1. Restore rehearsal on 2026-10-24 on a RAM disk: `hsm_secret` re-derives the live node id, `grant.key` the pinned issuer pubkey, the mint seed the live keyset (all 32 keys, from the seed alone as well), and the issuer wallet the live balance. The record sits next to the bundle, outside this repository. Repeat after any key rotation or issuer/mint change. A CLN database snapshot must not be started while the channel may have advanced: recover from `hsm_secret` + `emergency.recover` instead. |
| Workstation keys (`.keys/`, `.secrets/`, `production-secrets/`) | Not recorded here: the maintainer's own. |
| Database artifacts and UKI images | [Database artifact retention](DATABASE_ARTIFACT_RETENTION.md) |

## Open

As of 2026-10-24, in the order to do them:

1. **Enable GitHub private vulnerability reporting** on Bitcoin-PIR/Bitcoin-PIR,
   Bitcoin-PIR/issuer and Bitcoin-PIR/playground (Settings → Code security
   and analysis), then merge the `SECURITY.md` pull requests (#450,
   issuer #14, playground #31). The advisory links in those files work only
   once reporting is enabled.
2. **Milan residuals** (see [TEE platform floor](#tee-platform-floor-milan)):
   - Raise the floor: `requiredMitVectorBits` `0b10` → `0b110` in
     `web/src/attest-pin.ts` (the daily CI check and the scripts read the
     same constant) is #452; after it merges, Flow C and the playground
     re-vendor. VPSBG's host kernel update of 2026-10-23 set bit 2; verified
     2026-10-24. No question to VPSBG is needed.
   - BadFuse: decided 2026-10-24, an accepted residual, recorded in
     [Verification overview](VERIFICATION_OVERVIEW.md) by #453; another
     TEE generation for Direct ORAM was set aside.
3. **Issuer release layout.** A release must ship `bpir-cln-rpc-guard` next
   to `bpir-issuer`; the guard unit on pir1 points at the 2026-09-28
   release directory until it does.
4. **pir1 leftovers of the May experiment.** `dracut` 110 (not from the noble
   archive) builds the initramfs with `initramfs-tools` removed; decide
   whether to return to `initramfs-tools` before the next kernel. Four
   autoremovable packages (`hwdata`, `iputils-arping`, `linux-tools-common`,
   `pigz`) were left in place.
5. **Lower priority:**
   - cdk-mintd 0.18.2: a breaking release that moves the configuration
     into the mint database. The migration was rehearsed on 2026-10-24 on a
     tmpfs snapshot of the live database (same keyset, keys and mint
     pubkey after `config migrate` → `validate` → `init --existing-mint`);
     the production switch is a separate operation.
   - The issuer lockfile's rustls, rustls-webpki and webpki-roots advisories
     (the set #443 fixed here), and the `cargo audit` job that will keep
     reporting them (Bitcoin-PIR/issuer#15).
   - Done: cloudflared 2026.10.3 came with the 2026-10-24 dist-upgrade.

Done on 2026-10-24 (#429, E5): D4 backups and restore rehearsal; Core
Lightning v26.06.9 on pir1; pir1 dpkg repair, updates and reboot;
`SECURITY.md` opened in the three repositories.
