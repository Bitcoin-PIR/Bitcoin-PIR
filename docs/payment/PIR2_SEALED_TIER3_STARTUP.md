# pir2 sealed Tier 3 startup contract

This is the source/runtime contract for the payment-storeless pir2 profile. It
does not authorize a UKI build, upload, switch, reboot, public activation, key
authorization, or funds.

The runit entry point executes only the measured
`/usr/local/bin/unified_server`. It never falls back to a binary on the mutable
root filesystem. Before any sealed open it sets the core limit to zero and
refuses an active swap entry.

## Public startup selection

The default startup input is
`/home/pir/data/pir2-sealed/startup.env`. It is parsed as data, never sourced as
shell, and must contain exactly these eight non-empty fields with no extras:

```text
schema=bitcoinpir-pir2-sealed-startup-v1
profile=pir2-snp-sealed-v1
phase=observe
ordinal=1
verifier_nonce_hex=<64 lowercase hex characters>
current_policy_digest_hex=<64 lowercase hex characters>
class_digest_hex=<64 lowercase hex characters>
minimum_authorization_epoch=<non-zero decimal integer>
```

`phase` is exactly `observe`, `enroll`, `probe`, or `ready`. A complete
environment group may replace the file by setting all of:

- `BPIR_PIR2_SNP_SEALED_PROFILE`
- `BPIR_PIR2_SNP_SEALED_PHASE`
- `BPIR_PIR2_SNP_SEALED_ORDINAL`
- `BPIR_PIR2_SNP_SEALED_VERIFIER_NONCE_HEX`
- `BPIR_PIR2_SNP_SEALED_POLICY_DIGEST_HEX`
- `BPIR_PIR2_SNP_SEALED_CLASS_DIGEST_HEX`
- `BPIR_PIR2_SNP_SEALED_MINIMUM_AUTHORIZATION_EPOCH`

Supplying only part of that environment group fails closed. All these values
and the startup file are public ceremony/configuration inputs; none is a
private seed.

## Persistent artifacts

The default root `/home/pir/data/pir2-sealed` contains only the ciphertext
envelope and public artifacts:

- `release.bin`
- `credentials.envelope.bin`
- `identity.cert`
- `provider-accounting-authorization.bin`
- `issuer-accounting-approval.bin`
- `bat-acceptance-class.bin`
- per-boot receipts below `receipts/`
- per-boot success markers below `markers/`

The root and the two output directories are forced to mode `0700` and must not
be symlinks. No plaintext identity key, clearing key, ProviderStore,
idempotency key, or payment rollback state is accepted. The signed current
service policy remains a public measured UKI input.

## Phase ordering

Observe, Enroll, and Probe invoke the measured binary before waiting for
`databases.toml`. A valid result writes a current-boot receipt and exact marker,
exits with status 42, and never reaches database loading, ORAM mutation, or a
listener. The runit finish hook takes the service down on the first such result
only when status 42, boot ID, phase, receipt digest, receipt file, and marker
schema all match. An unbound status 42 follows the existing bounded retry path.

Ready has two measured invocations:

1. A Ready preflight opens the envelope, verifies the identity certificate,
   provider accounting authorization, and issuer approval, writes its own
   current-boot receipt/marker, exits 42 as a child process, and drops the keys.
2. Only after that success may the script validate database inputs and rebuild
   Direct ORAM. The final `exec` opens the same envelope again with
   `--pir2-snp-sealed-require-ready`; that process retains the keys in memory
   while serving the closed storeless BAT V2 profile.

Ready-preflight and final-runtime receipts use different paths. A same-boot
restart may reuse an exact Ready-preflight marker, avoiding a conflicting
no-replace write, but the Ready-preflight marker is never a terminal marker for
the runit finish hook.

Focused source checks are:

```sh
node --test scripts/tier3-uki-policy-contract.test.mjs
node scripts/vpsbg-tier3-generation.test.mjs
sh -n scripts/dracut/97bpir-tier3-init/unified-server-run.sh
sh -n scripts/dracut/97bpir-tier3-init/unified-server-finish.sh
```
