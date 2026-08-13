# BitcoinPIR production data handoff

This directory is the discovery point for the retained `940611 -> 948454`
production lineage on the Hetzner archive host. The large checkpoint, delta,
snapshot, and db0 Direct input files remain at their established canonical
paths listed in `inventory.tsv`.

Start with the repository document
`docs/DATABASE_ARTIFACT_RETENTION.md`. Verify the retained identities with:

```bash
sha256sum -c SHA256SUMS
```

This handoff also keeps a second host copy of the db1 Direct inputs and the
exact small V2 evidence used by the live source-binding pins. It is an archive
and debug entry point only; nothing below this directory is read by the active
service configuration.

`production-release-image-265.env` is a point-in-time release record; query the
VPSBG control plane before treating any image id as current.

Updated: 2026-08-13. No secret, payment key, API token, or invoice material is
stored in this handoff.
