# Full Direct ORAM UKI preflight — 2026-08-11

Status: **NOT READY — preflight only; no full build was started.**

This report freezes the exact input, capacity, time, observability, and VPSBG
conditions for a future full db0/db1 Direct ORAM UKI. It is not deployment
authorization. Re-run all volatile checks immediately before a later build.

## Current VPSBG state

The target is VPSBG server `25285` (`pir-server-vpsbg`). The API reported it
active, unlocked, running, reachable, and booted from the Ubuntu 26.04 stock
image with `state.measured_boot = null`. This is the required `none` state.

All five measured-boot slots are occupied and inactive:

| ID | Name | Bytes | Role |
| ---: | --- | ---: | --- |
| 229 | `vpsbg-harmony-respon` | 314,208,768 | historical runtime |
| 231 | `attested-builder-nat` | 310,477,824 | historical builder |
| 233 | `bpir-tier3-oram-v2-2` | 314,055,680 | prior Tier 3 runtime |
| 237 | `bpir-oram-debug-2bf7` | 94,718,976 | failed debug attempt |
| 239 | `bpir-oram-debug-2bf7` | 94,717,440 | known-good TEE debug |

A future upload is blocked until the operator separately authorizes deletion
of one reviewed obsolete image. Do not delete `239`; do not infer deletion
authority from this report.

## Exact active database generation

`/home/pir/data/databases.toml` points both entries at:

```text
/home/pir/data/generations/native-v2-948454/
```

| DB | Meaning | Base height | End height | Generation bytes | `server-db` bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| db0 | full main database | 0 | 948,454 | 52,235,207,383 | 47,649,940,332 |
| db1 | delta database | 940,611 | 948,454 | 5,063,750,813 | 4,597,642,244 |

No candidate-generation pointer was present; this is the active generation.

### Direct inputs

| DB | File | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| db0 | `utxo_chunks_index_nodust.bin` | 1,345,875,975 | `d0b9573488abdda8e17dc52bb52bf5ff11520b4511683020f5f1a22bc8d8d26c` |
| db0 | `utxo_chunks_nodust.bin` | 3,239,380,480 | `9a81a02bf82af49414b5f2ae6380c97c1f231fcac6890b605f6cde22b0adc521` |
| db1 | `utxo_chunks_index_nodust.bin` | 125,867,300 | `e06fc3c9f79919fd3d4e501337cf2797b88853835d2a6a9a8f06a24f827a6a16` |
| db1 | `utxo_chunks_nodust.bin` | 340,230,840 | `536acba7438940577e84c098d3d7c72f59f32536d4fdc84193c2d166883d3e0a` |

The two `direct-inputs.sha256` manifests passed. Every nonzero file named by
each runtime `server-db/MANIFEST.toml` also passed. The read-only runtime-closure
verification took 151 seconds under a 300-second hard timeout.

### Evidence identity

| DB | Artifact | SHA-256 |
| --- | --- | --- |
| db0 | `build-evidence.bin` | `3b9e38d5422e5a3983e5ab356d540f5fcb0ba8bc71992f6ae4f4d2916b9c3394` |
| db0 | `build-evidence.sev-snp-report.bin` | `9fd1daa48952e41662630627115e092b0d4ccc758503d0e40e2dc551d83b513d` |
| db0 | root bundle | `a1902bd2173801b6af4a00533d633f8b4e27b48726267ecc4a63ccad4ec8ef78` |
| db0 | server manifest | `91421138ba94e44665bef2617af296b1c1847dea13c4df29b565012d1e0b74a6` |
| db1 | `build-evidence.bin` | `06f4ebe959aec371fc2ad35a7ee51b6ee2f02768ccef7e1f5896792a61bc382c` |
| db1 | `build-evidence.sev-snp-report.bin` | `25476442a39b01ad9440acff719310785e37702e09eaab13dd3f103b0d217f51` |
| db1 | root bundle | `8cc8e7c20b13521df0060bf5c2bf547d827ac11af1aa49dcaa438a869a518362` |
| db1 | server manifest | `047a5b6713bf0df29d9de308fb47ff757243e365a9818cf746f399bea457d00c` |

The BHTM leaf proof for height 940,611 is 4,294 bytes with SHA-256
`2e54cb56ae63d89036c1e74754b68a72e012ed775dff8b0204a6efc023b08195`.
It binds block hash
`000000000000000000002c41243b3d74d135942031ef15f547bca1ce8f85eb99`,
Core MuHash
`aebb29df12e045ef5279036263aba3b8f8e9e816e05b04a58f57e63b3b25756b`,
and tree root
`babeea635812c3b1a2d5f352ab0a5d1ee8a4e9c668c43c05d6603ef3c3766ba6`.
The proof records `verified_against_tree_root=true`.

## Capacity and bounded timing

The read-only capacity snapshot was:

```text
RAM total       66,397,003,776 bytes
RAM available   65,387,905,024 bytes
swap            0
/run tmpfs       13,279,404,032 bytes total
disk free       70,251,692,032 bytes
running builder none
```

`oramctl size-direct` projected:

- db0 combined AEAD image: 14,736,682,388 bytes; historical split/auth output:
  16,217,140,572 bytes;
- db1 combined AEAD image: 1,842,081,172 bytes; split/auth output estimate:
  approximately 2.03 GB;
- both final outputs: approximately 18.24 GB, leaving roughly 52 GB from the
  observed free-space snapshot.

The real db0 stock/none encrypted build completed in 3:53.82. A future full
cycle should budget 8–12 minutes and enforce these failure boundaries:

| Boundary | Hard limit |
| --- | ---: |
| db0 Direct ORAM | 8 minutes |
| db1 Direct ORAM | 3 minutes |
| total full build path | 15 minutes |
| no progress heartbeat | 90 seconds |

Crossing a limit is a failure requiring interruption and diagnosis. It is not
permission to wait longer.

## Blocking conditions

The future full build is **not ready** until all of the following are closed:

1. `scripts/dracut/97bpir-tier3-init/unified-server-run.sh` currently fixes
   `VPSBG_DPF_ONLY_FUNCTIONAL_BETA=1`. A newly built production UKI would remain
   DPF-only and would not execute the Direct ORAM construction path.
2. The full runtime path lacks the debug image's phase heartbeat and per-db /
   overall watchdog. The new runit finish hook limits repeated process exits,
   but cannot interrupt one hung builder invocation. Observability and hard
   timeouts must be ported before building.
3. VPSBG has 5/5 image slots occupied. One obsolete image must be explicitly
   selected and deleted by the operator before an upload can succeed.
4. The staged runtime closure is complete and verified, but its broader
   `all-artifacts.manifest.sha256` refers to historical build-only intermediates
   not retained in the active generation. This does not block runtime startup;
   it is an archival reproducibility gap that must be documented or satisfied
   before claiming a self-contained rebuild archive.

## Required go/no-go sequence

Before a later full build, produce one fresh report that:

1. re-confirms stock/none mode, capacity, no running builder, and source hashes;
2. closes the DPF-only flag and validates that db0 and db1 take the Direct path;
3. demonstrates heartbeat fields and automatic 8/3/15-minute hard stops on a
   bounded fixture without running production data;
4. records the exact release commit, `unified_server`/`oramctl` hashes, BHTM
   proof hash, UKI path/size/hash, and selected rollback image;
5. obtains explicit operator authorization for image deletion, upload, attach,
   and reboot as separate mutations.

No full ORAM or production UKI build was started while preparing this report.
