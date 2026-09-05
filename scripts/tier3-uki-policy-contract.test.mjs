#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const buildPath = resolve(repository, "scripts/build_uki_tier3.sh");
const modulePath = resolve(
  repository,
  "scripts/dracut/96bpir-unified-server/module-setup.sh",
);
const runPath = resolve(
  repository,
  "scripts/dracut/97bpir-tier3-init/unified-server-run.sh",
);

// The runtime UKI carries no admission policy, payment artifact, or plaintext
// identity input. Access control lives outside the measured image, so a
// payment change never forces a new measurement or sealed ceremony.
const PAYMENT_RESIDUE = /BPIR_TIER3_SERVICE_POLICY|service-policy|service_policy|public-artifact-set|accounting-authorization|issuer-approval|class_digest|minimum_authorization_epoch/;

function validateBuildContract(source) {
  assert.match(source, /for input_name in KERNEL BINARY ORAMCTL BHTM_FROM_LEAF_PROOF OUT/);
  assert.match(
    source,
    /error: \$input_name must be set explicitly for a production Tier 3 UKI/,
  );
  assert.doesNotMatch(source, PAYMENT_RESIDUE);
  assert.match(source, /etc\/bitcoinpir\/payment\//);
  assert.match(source, /payment artifacts must not be embedded in the Tier 3 UKI/);
  assert.match(source, /TIER3_INITRD_COMPRESSION=zstd/);
  assert.match(source, /TIER3_INITRD_MAGIC=28b52ffd/);
  assert.match(source, /TIER3_MAX_UKI_BYTES=\$\(\(256 \* 1024 \* 1024\)\)/);
  assert.match(source, /--compress "\$TIER3_INITRD_COMPRESSION"/);
  assert.match(source, /--no-early-microcode/);
  assert.match(source, /TIER3_OMIT_DRACUT_MODULES="[^"]*drm[^"]*"/);
  assert.match(source, /TIER3_OMIT_DRACUT_MODULES="[^"]*bpir-verify[^"]*"/);
  assert.match(source, /usr\/lib\/firmware\/nvidia\//);
  assert.match(source, /kernel\/x86\/microcode\//);
  assert.match(source, /forbidden build-host payload leaked into Tier 3 initramfs/);
  assert.match(source, /\[ "\$INITRD_MAGIC" != "\$TIER3_INITRD_MAGIC" \]/);
  assert.match(source, /\[ "\$UKI_BYTES" -gt "\$TIER3_MAX_UKI_BYTES" \]/);
  assert.ok(
    source.indexOf('[ "$UKI_BYTES" -gt "$TIER3_MAX_UKI_BYTES" ]') <
      source.indexOf('"$ARCHIVE_SCRIPT" tier3 "$OUT"'),
    "oversized UKIs must be rejected before archival",
  );
  assert.match(source, /"initrd_compression=\$TIER3_INITRD_COMPRESSION"/);
  assert.match(source, /"dracut_version=\$DRACUT_VERSION"/);
  assert.match(source, /"ukify_version=\$UKIFY_VERSION"/);
  assert.doesNotMatch(source, /BPIR_TIER3_IDENTITY_KEY/);
  assert.match(
    source,
    /private identity key must not be embedded in the Tier 3 UKI/,
  );
}

function validateDracutModuleContract(source) {
  assert.doesNotMatch(source, PAYMENT_RESIDUE);
  assert.doesNotMatch(source, /inst_dir \/etc\/bitcoinpir\/payment/);
  assert.doesNotMatch(source, /BPIR_TIER3_IDENTITY_KEY/);
  assert.doesNotMatch(source, /server\.key/);
}

function validateMeasuredRunContract(source) {
  assert.match(source, /UNIFIED_SERVER=\/usr\/local\/bin\/unified_server/);
  assert.match(source, /ORAMCTL=\/usr\/local\/bin\/oramctl/);
  assert.doesNotMatch(source, /target\/release\/unified_server/);
  assert.doesNotMatch(source, /target\/release\/oramctl/);
  assert.doesNotMatch(source, /--identity-key-path/);
  assert.doesNotMatch(source, /server\.key/);
  assert.doesNotMatch(source, /--service-|--require-service-auth-v1/);
  assert.doesNotMatch(source, PAYMENT_RESIDUE);
  assert.match(source, /--pir2-snp-sealed-envelope/);
  assert.match(source, /--pir2-snp-sealed-identity-cert/);
}

test("production Tier3 build takes exactly the runtime inputs and embeds no policy", () => {
  validateBuildContract(readFileSync(buildPath, "utf8"));
});

test("production Tier3 build rejects a policy or payment-artifact regression", () => {
  const source = readFileSync(buildPath, "utf8");
  assert.throws(() =>
    validateBuildContract(`${source}\nBPIR_TIER3_SERVICE_POLICY=/tmp/policy.bin\n`),
  );
  assert.throws(() =>
    validateBuildContract(
      source.replace(
        "payment artifacts must not be embedded in the Tier 3 UKI",
        "payment artifacts embedded in the Tier 3 UKI",
      ),
    ),
  );
});

test("production Tier3 build pins compression and rejects oversized output", () => {
  const source = readFileSync(buildPath, "utf8");
  assert.throws(() =>
    validateBuildContract(
      source.replace(
        '--compress "$TIER3_INITRD_COMPRESSION"',
        '--no-compress',
      ),
    ),
  );
  assert.throws(() =>
    validateBuildContract(
      source.replace(
        '[ "$UKI_BYTES" -gt "$TIER3_MAX_UKI_BYTES" ]',
        '[ "$UKI_BYTES" -lt "$TIER3_MAX_UKI_BYTES" ]',
      ),
    ),
  );
});

test("dracut module installs no policy and no identity seed", () => {
  validateDracutModuleContract(readFileSync(modulePath, "utf8"));
});

test("Tier3 UKI and measured run path contain no plaintext identity or payment input", () => {
  validateMeasuredRunContract(readFileSync(runPath, "utf8"));
});

test("dracut module rejects a policy re-introduction", () => {
  const source = readFileSync(modulePath, "utf8");
  assert.throws(() =>
    validateDracutModuleContract(
      `${source}\ninst_simple "$service_policy" /etc/bitcoinpir/payment/service-policy.bin\n`,
    ),
  );
});
