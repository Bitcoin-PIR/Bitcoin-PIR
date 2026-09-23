# R5 free-query switch (campaign log)

Dated operator log for the R5 production switch. Live identity values stay
in [`web/src/attest-pin.ts`](../../web/src/attest-pin.ts) or command output.
Query live state with `scripts/production-status.sh`; do not infer it here.

## Split

| Slice | Scope | Status |
| --- | --- | --- |
| R5.1 | Put the merged free-query world on pir1, pir2, then Pages. Keep dummy sealed files and the existing reviewed UKI policy embed. Do not enable `--require-arc` / `--require-cashu`. Do not deploy the issuer. | **in progress** |
| R5.2 | Rebuild Lightning collection, paid gate, issuer as collector, drop dummy sealed / UKI policy embed. | not started |

Source lock for R5.1 is `origin/main` at the squash merge of PR #279
(R3 stage 4). PIR query paths and the pir1/pir2 host split are unchanged.

## R5.1 checklist

| Step | Flow | What | Status |
| --- | --- | --- | --- |
| 1 | B | Checkout reviewed `main` | done |
| 2 | A | Read pir1 + pir2 | done |
| 3 | D | pir1 unit: drop deleted Payment V1 flags; rebuild `unified_server`; restart `pir-primary` | done (`:8091` listening; ARC/Cashu off) |
| 4 | E.2 | `vpsbg-measured-boot.sh images` | done (quota had spare slots) |
| 5 | F | `open` onto stock for the then-live runtime UKI | done (detach then delayed stop; explicit `start` recovered SSH) |
| 6 | E.3 | Runtime UKI on VPSBG stock (`build_uki_tier3.sh`), same KERNEL class as the previous live UKI, reused reviewed policy / oramctl / BHTM | done (`PASS uki_build`) |
| 7 | E.3 archive | Laptop-mirror EFI + sidecar to Hetzner `/home/pir/uki-archive/tier3/` | done |
| 8 | E.4 | `upload --apply` | done (new measured-boot image recorded in command output) |
| 9 | E.5 | First `switch --apply` to the uploaded image | done, then **rolled back** to the pre-open image after Ready dispatcher fatal |
| 10 | E.6 | `pir2-post-switch-check.sh` | **hard stop** on the first new UKI (unknown Payment V1 flags). Rollback to the previous live image is done. |
| 10b | B | Drop deleted `--service-*` flags from `unified-server-run.sh`; keep `--pir2-snp-sealed-*` | merged as PR #280 (`origin/main` squash) |
| 10c | F then E.3 | Rebuild runtime UKI from the #280 squash on VPSBG stock | done (`PASS uki_build`; Hetzner archive mirrored) |
| 10d | E.4 | `upload --apply` of the #280 UKI | done (new measured-boot image recorded in command output) |
| 10e | E.5 | `switch --apply` to that image | done (measured + running) |
| 10f | E.6 | `pir2-post-switch-check.sh` on the #280 UKI | **hard stop**. Guest is measured and running on the new image. `/status.json` Ready dispatcher failed: fresh SNP report measurement differs from the pinned sealed `release.bin` (still bound to the previous UKI). WSS 502. `attest-pin.ts` was not edited. |
| 10g | G | Rebind sealed `release.bin` to the new UKI via Observe → release → Enroll → Probe → Ready | Observe 39, Enroll 40, Probe 41+42, Ready 43 all completed on image 301. Ready wrote preflight+runtime receipts; Direct ORAM built; runtime log shows `Listening on ws://[::]:8091` with ARC/Cashu off. Public 502 after that was this Flow F `open` (guest is stock again). Generation 4 / clearing 3 still inactive. **Next Auth:** `close` back to image 301 so pir2 serves, then E.6 (expected pin mismatch), then Human pin + optional Pages. |
| 11 | C | Pages `deploy-web.yml` on `main` | not started (servers first) |
| 12 | Human | Update `PIR1_PIN` / `PIR2_TIER3_PIN` after both servers serve the new binaries | not started |

Flow F `close` onto the pre-open image is **not** the R5.1 attach. From stock,
`switch` to the uploaded image both leaves the data-disk window and boots the
new UKI. `close` to the old image would restore the previous measured world.

## Out of scope until R5.2

Lightning, issuer collection, `--require-arc` / `--require-cashu`, ripping
`BPIR_TIER3_SERVICE_POLICY` out of `build_uki_tier3.sh`, deleting dummy sealed
ceremony files, Hetzner as UKI build host.

Recorded 2026-08-30.
