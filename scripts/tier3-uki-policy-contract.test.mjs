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

test("dracut module rejects an optional-policy regression", () => {
  const source = readFileSync(modulePath, "utf8");
  assert.throws(() =>
    validateDracutModuleContract(
      source.replace('[ -z "$service_policy" ]', '[ -n "$service_policy" ]'),
    ),
  );
});
