# BitcoinPIR production data handoff

This directory is the discovery point for the retained `940611 -> 948454`
production lineage. The large files remain at the canonical paths listed in
`inventory.tsv`; this directory does not duplicate them unnecessarily.

Start with the repository document
`docs/DATABASE_ARTIFACT_RETENTION.md`. Before a rebuild, verify the relevant
entries with:

```bash
shasum -a 256 -c SHA256SUMS
```

The external volume contains both raw Core snapshots, db0 and db1 Direct ORAM
inputs, the 948454 checkpoint, an exact mirror of the Hetzner canonical delta,
the live V2 proof evidence, and retained UKI/debug evidence. Mutable ORAM output
pages are not source inputs.

`production-release-image-265.env` is the point-in-time release identity that
paired the current UKI, runtime binary, policy, measurement, and db0/db1 roots
during the 2026-08-13 browser acceptance.

Updated: 2026-08-13. No secret, payment key, API token, or invoice material is
stored in this handoff.
