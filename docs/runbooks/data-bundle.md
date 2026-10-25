# Data bundle: the public download of a database generation

The directories the reference catalog names, served read-only from a
Cloudflare R2 bucket behind `https://data.bitcoinpir.org/<generation>/`,
with `SHA256SUMS` over every file and the catalog with relative paths at the
root. `scripts/data-bundle.sh` does the four steps (`hash`, `upload`,
`verify`, `fetch`); the node side is
[Operator guide §3](../OPERATOR_GUIDE.md#3-data). The hash list of each
published generation is committed under `deploy/data-bundles/<generation>/`,
so a download can be checked against this repository and not only against
the bucket it came from.

## Why R2

Egress is free and storage is $0.015 per GB-month with 10 GB free, so a
57 GB generation costs about $0.70 a month, and a download costs nothing
however many operators fetch it. It uses none of pir1's bandwidth or disk,
and a custom domain on the `bitcoinpir.org` zone gives it a stable name. The
managed `r2.dev` URL stays off: it is rate-limited and for development only.
Prices and limits: <https://developers.cloudflare.com/r2/pricing/>,
<https://developers.cloudflare.com/r2/platform/limits/> (read 2026-10-25;
objects up to 5 TiB, multipart parts up to 10,000, which `upload` uses).

## Once: bucket, domain, token — Human

1. Dashboard → R2 → Create bucket `bitcoinpir-data` (Standard storage; the
   location hint Europe is nearest the hosts; the name is not public).
2. Bucket → Settings → Custom Domains → Connect `data.bitcoinpir.org`.
   Cloudflare adds the CNAME; the status turns Active within minutes. Leave
   the r2.dev subdomain disabled.
3. R2 → Manage R2 API Tokens → Create: Object Read & Write, this bucket only,
   a TTL that covers the upload. Save it as `.secrets/r2-bundle.env`
   (gitignored):

   ```sh
   R2_ACCOUNT_ID=<account id>
   R2_ACCESS_KEY_ID=<token access key>
   R2_SECRET_ACCESS_KEY=<token secret>
   ```

   Nothing on pir1 keeps the token; roll it after the upload if it has no TTL.
4. pir1, once: `sudo apt-get install rclone` (noble's 1.60 knows the
   Cloudflare provider).

## Publish a generation — Auth ([Database rebuild §8.4](../DATABASE_REBUILD.md#84-activate-and-publish--auth-rotation-5) step 8)

`<gen>` is the height of `db_id` 0 (948454). `hash` and `upload` run on pir1,
where the data is and whose egress is free:

```sh
scp scripts/data-bundle.sh pir-hetzner:/root/data-bundle.sh
```

1. Hash (read-only; direct I/O; about 5 min for 57 GB) and commit:

   ```sh
   mkdir -p deploy/data-bundles/<gen>
   ssh pir-hetzner /root/data-bundle.sh hash /home/pir/data /home/pir/data/databases.toml \
     > deploy/data-bundles/<gen>/SHA256SUMS
   ```

   Write `deploy/data-bundles/<gen>/databases.toml`: pir1's catalog with the
   paths relative, like 948454's. Cross-check before committing: the hashes
   of `chain_anchor.bin`, `merkle_*_root.bin` and `oram-direct-inputs/*` must
   equal the attested builder's `database.manifest.sha256` in the proof
   directories, and every non-zero entry of each `MANIFEST.toml` must appear
   in the list. Open the PR with the operator guide's §3.1 table updated.

2. Upload from pir1 (about 15 min at 60 MB/s; `BPIR_BUNDLE_BWLIMIT=30M` when
   the node is busy). The token reaches pir1 as a file that is removed after:

   ```sh
   scp .secrets/r2-bundle.env pir-hetzner:/root/r2-bundle.env
   scp -r deploy/data-bundles/<gen> pir-hetzner:/root/data-bundle-<gen>
   ssh pir-hetzner 'set -a; . /root/r2-bundle.env; set +a
     export RCLONE_CONFIG_R2_TYPE=s3 RCLONE_CONFIG_R2_PROVIDER=Cloudflare \
       RCLONE_CONFIG_R2_ACCESS_KEY_ID=$R2_ACCESS_KEY_ID \
       RCLONE_CONFIG_R2_SECRET_ACCESS_KEY=$R2_SECRET_ACCESS_KEY \
       RCLONE_CONFIG_R2_ENDPOINT=https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com
     /root/data-bundle.sh upload /home/pir/data /root/data-bundle-<gen> r2:bitcoinpir-data/<gen>
     rm /root/r2-bundle.env'
   ```

   `upload` is `rclone copy` per directory: re-run after an interruption and
   it skips what is already there with the same size and modification time.

3. Verify the public copy from pir1 (streams all 57 GB back through
   `sha256sum`, nothing written; about 10 min):

   ```sh
   ssh pir-hetzner /root/data-bundle.sh verify /root/data-bundle-<gen> https://data.bitcoinpir.org/<gen>
   ```

   Success: `0 failure(s)`. Then merge the PR and add the generation below.

4. Retire the previous generation only after its rollback window
   ([§8.5](../DATABASE_REBUILD.md#85-rollback--auth-rotation-7)) closes:
   `rclone purge r2:bitcoinpir-data/<old>`.

## Published generations

| Generation | Files | Size | Published | Hash list |
| --- | --- | --- | --- | --- |
| 948454 (delta 940611→948454) | 128 | 57.3 GB | pending | `deploy/data-bundles/948454/SHA256SUMS` |
