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
const reviewedPolicySha256 =
  "ef076d5fcb4ccc89c7ad4b883d332005ef59cfa09617e1ea66359d37f962dc14";

function validateBuildContract(source) {
  const policyRequirement = source.indexOf(
    '[ -n "${BPIR_TIER3_SERVICE_POLICY:-}" ] || {',
  );
  const dracutBuild = source.indexOf("SOURCE_DATE_EPOCH=0 dracut");
  assert.ok(policyRequirement >= 0, "Tier3 build must require an explicit policy");
  assert.ok(
    policyRequirement < dracutBuild,
    "Tier3 build must reject a missing policy before invoking dracut",
  );
  assert.match(
    source,
    new RegExp(`TIER3_SERVICE_POLICY_SHA256=${reviewedPolicySha256}`),
  );
  assert.match(
    source,
    /\[ "\$SERVICE_POLICY_HASH" != "\$TIER3_SERVICE_POLICY_SHA256" \]/,
  );
  assert.match(
    source,
    /lsinitrd -f \/etc\/bitcoinpir\/payment\/service-policy\.bin/,
  );
  assert.match(
    source,
    /\[ "\$EMBEDDED_SERVICE_POLICY_HASH" != "\$SERVICE_POLICY_HASH" \]/,
  );
  assert.match(source, /"service_policy_sha256=\$SERVICE_POLICY_HASH"/);
  assert.doesNotMatch(source, /BPIR_TIER3_IDENTITY_KEY/);
  assert.match(
    source,
    /private identity key must not be embedded in the Tier 3 UKI/,
  );
}

function validateDracutModuleContract(source) {
  assert.match(source, /\[ -z "\$service_policy" \]/);
  assert.match(source, /\[ ! -f "\$service_policy" \]/);
  assert.match(source, /\[ ! -r "\$service_policy" \]/);
  assert.match(source, /\[ ! -s "\$service_policy" \]/);
  assert.match(
    source,
    /inst_simple "\$service_policy" \/etc\/bitcoinpir\/payment\/service-policy\.bin/,
  );
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
  assert.doesNotMatch(source, /--service-shared-clearing-key/);
  assert.doesNotMatch(source, /--service-shared-idempotency-key/);
  assert.doesNotMatch(source, /--service-storeless-bat-v2-pir1-clearing-key/);
  assert.match(source, /--pir2-snp-sealed-envelope/);
  assert.match(source, /--pir2-snp-sealed-identity-cert/);
  assert.match(source, /--pir2-snp-sealed-accounting-authorization/);
  assert.match(source, /--pir2-snp-sealed-issuer-approval/);
}

test("production Tier3 build requires and byte-verifies reviewed policy", () => {
  validateBuildContract(readFileSync(buildPath, "utf8"));
});

test("production Tier3 build rejects policy lock or embedded-byte regressions", () => {
  const source = readFileSync(buildPath, "utf8");
  assert.throws(() =>
    validateBuildContract(
      source.replace(reviewedPolicySha256, "0".repeat(64)),
    ),
  );
  assert.throws(() =>
    validateBuildContract(
      source.replace(
        '[ "$EMBEDDED_SERVICE_POLICY_HASH" != "$SERVICE_POLICY_HASH" ]',
        '[ "$EMBEDDED_SERVICE_POLICY_HASH" = "$SERVICE_POLICY_HASH" ]',
      ),
    ),
  );
});

test("dracut module refuses to omit the measured policy", () => {
  validateDracutModuleContract(readFileSync(modulePath, "utf8"));
});

test("Tier3 UKI and measured run path contain no plaintext identity fallback", () => {
  validateMeasuredRunContract(readFileSync(runPath, "utf8"));
});

test("dracut module rejects an optional-policy regression", () => {
  const source = readFileSync(modulePath, "utf8");
  assert.throws(() =>
    validateDracutModuleContract(
      source.replace('[ -z "$service_policy" ]', '[ -n "$service_policy" ]'),
    ),
  );
});
