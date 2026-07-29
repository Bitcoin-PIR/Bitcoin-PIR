# Forensic legacy ORAM source proof — never publish or deploy

This directory preserves the exact historical `mainnet_948454` proof bytes so
the browser can regression-test its fail-closed legacy handling. The v1 ORAM
evidence disclosed `oram_rng_seed_hex`; that seed is already present in Git
history and makes this evidence permanently ineligible for production.

The files were mechanically moved from `web/public/proofs/oram-source/` without
rewriting or re-hashing them. They are test fixtures, not production web assets:

- never copy this tree back under `web/public`;
- never treat a matching hash chain as proof of confidentiality;
- never return a `verified` production status for v1 evidence;
- do not use the historical deployment claims as current operational evidence.

Production remains fail closed at `/proofs/oram-source/current.json` until a new
measured full-build v2 ceremony publishes secret-free evidence, an exact typed
server manifest, AMD ARK/ASK/VCEK verification artifacts, and a matching live
database proof.
