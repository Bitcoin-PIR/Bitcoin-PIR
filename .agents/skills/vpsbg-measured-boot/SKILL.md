---
name: vpsbg-measured-boot
description: Manage BitcoinPIR's VPSBG AMD SEV measured-boot UKI images through the VPSBG v1 API. Use this skill whenever the user asks to inspect, upload, switch, reboot, deploy, verify, or roll back a VPSBG UKI / measured-boot image, including Chinese requests such as “上传 VPSBG 镜像”, “切换 UKI”, “重启 VPSBG”, or “回滚 VPSBG”. Prefer this API workflow to asking the user to upload an image manually in the VPSBG portal.
compatibility: Requires curl, jq, a local VPSBG API token with Write permission for mutations, and an already-built UKI artifact.
---

# VPSBG measured-boot release

Use the VPSBG API for image upload, attachment, restart, state polling, and
rollback. This keeps the operator out of the portal for ordinary UKI releases,
while preserving the existing BitcoinPIR strict verification gate after boot.

## Scope and authorization

- Treat `GET` status and image-list calls as read-only diagnostics.
- `POST /measured-boot-images` uploads an image. `POST
  /servers/{id}/measured-boot` attaches it and immediately reboots the server.
  Do not issue either call unless the user explicitly authorizes this release.
- Do not delete images automatically. VPSBG permits at most five images, so
  retain the active and immediately preceding image for rollback.
- Never print, commit, upload, or put an API token in a command transcript.
  A VPSBG Write token can make all API calls for the account.
- Do not assume that the API can detach a UKI and return to stock rootfs. Its
  documented `None` / null semantics are not confirmed; ask before relying on
  that operation.

## Inputs

Require these facts before any mutation:

1. Absolute path to the finished UKI/EFI artifact, with a unique filename
   containing a release identifier (for example git revision and UTC date).
2. Expected BitcoinPIR binary hash and SEV measurement, or the declared plan
   for deriving and pinning them after boot.
3. VPSBG numeric server ID. Discover it with `GET /servers`; never guess from
   a hostname.
4. A current API token. Read it from `VPSBG_API_TOKEN_FILE`, or, when it
   exists on this workstation, from
   `/Users/cusgadmin/.config/bitcoinpir/secrets/vpsbg-api-token`. Read it into
   a shell variable and strip its trailing newline; do not echo it.

The API base URL is `https://api.vpsbg.eu/v1`. Send `Accept:
application/json` and `Authorization: Bearer <token>` on every request.

## Read-only preflight

Run this sequence before proposing or applying a release:

1. Run `scripts/vpsbg-production-status.sh` for the bounded, read-only status
   view. Verify the token file exists and is nonempty without printing its
   contents.
2. Fetch `GET /servers`, select the intended server, and record only its ID,
   hostname, active/running/reachable state, SEV level, and current
   `state.measured_boot` object.
3. Fetch `GET /measured-boot-images`; record each image's ID, name, size, and
   `in_use` field. Do not delete inactive images as a side effect.
4. Locally calculate the artifact SHA-256 and reject files at or over
   1,000,000,000 bytes. VPSBG documents a 1 GB upload limit.
5. Report the planned server ID, current image ID (if any), candidate filename
   and SHA-256, and whether a rollback image is available. Stop here for a
   status, planning, or dry-run request.

## Apply an authorized release

When the user explicitly authorizes upload, attachment, and reboot:

1. Re-run the preflight immediately. Do not reuse an old server or image
   listing.
2. Upload the verified artifact with multipart `POST /measured-boot-images`
   and parse the returned image ID, name, and size. Store those non-secret
   values in the release report.
3. Do not require the returned `type` to equal `kernel`: an existing VPSBG
   image may return `type: null`. Use the unique filename, returned ID, size,
   and the later attached-image ID as the binding evidence.
4. Attach the uploaded image with `POST /servers/{server_id}/measured-boot`.
   Start with the minimal documented body:

   ```json
   {"kernel_image_id": 12345}
   ```

   The API documentation also shows `initrd_image_id`, `account_password`,
   and `otp`. If VPSBG returns a validation error requiring account password or
   OTP, stop and ask for one-time runtime input; never persist either value.
5. Expect the attachment request to reboot the server immediately. If its HTTP
   response is lost, do not resend it blindly: poll `GET /servers/{id}` and
   compare `state.measured_boot.kernel_image.id` with the uploaded image ID.
6. Poll until the server reports running and reachable, then use the normal
   BitcoinPIR post-deployment process: strict attestation against the expected
   binary/measurement, secure-channel test, policy/root verification, and the
   applicable Free/Premium admission smoke tests.
7. Only after those checks pass may the release be called live. Keep the
   previous image; do not use VPSBG's irreversible delete endpoint in the
   first release workflow.
8. Preserve the successful `.efi`, `.sha256`, `.meta`, runtime revision,
   binary/policy/measurement identities, and db0/db1 manifest roots using
   `docs/DATABASE_ARTIFACT_RETENTION.md`. Keep the point-in-time release record
   on both the external Bitcoin volume and the Hetzner archive host. Do not put
   tokens or payment secrets in that record.

## Rollback

If strict verification or admission smoke fails after a new attachment:

1. Keep the failed image for investigation.
2. Use the recorded previous image ID with the same measured-boot attachment
   endpoint; this triggers another immediate reboot.
3. Poll state and repeat strict attestation before declaring rollback complete.
4. Report the failure and both image IDs without exposing credentials.

## Official API references

- API key permissions: <https://dev.vpsbg.eu/doc-338632>
- Upload image: <https://dev.vpsbg.eu/api-4106491>
- List images: <https://dev.vpsbg.eu/api-4128678>
- Attach image / immediate reboot: <https://dev.vpsbg.eu/api-4128691>
- Inspect server state: <https://dev.vpsbg.eu/api-3487367>
- Delete image (irreversible; do not automate): <https://dev.vpsbg.eu/api-4128684>
