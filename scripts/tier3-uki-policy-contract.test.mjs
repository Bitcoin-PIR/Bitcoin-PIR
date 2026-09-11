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

// Negative checks run on the code only: a shell comment that merely mentions a
// retired flag or artifact must not fail the contract, and a real line must
// (pain point 7). Positive checks keep the full source.
function withoutComments(source) {
  return source.split("\n").filter((line) => !/^\s*#/.test(line)).join("\n");
}

function validateBuildContract(source) {
  const code = withoutComments(source);
  // The baked cloudflared is inside MEASUREMENT: the build must pin the exact
  // official release by version and SHA-256 rather than take whatever the
  // build host has installed.
  assert.match(source, /^TIER3_CLOUDFLARED_VERSION=\d{4}\.\d+\.\d+$/m);
  assert.match(source, /^TIER3_CLOUDFLARED_SHA256=[0-9a-f]{64}$/m);
  assert.match(source, /"\$cloudflared_sha256" = "\$TIER3_CLOUDFLARED_SHA256"/);
  assert.match(source, /for input_name in KERNEL BINARY ORAMCTL BHTM_FROM_LEAF_PROOF OUT/);
  assert.match(
    source,
    /error: \$input_name must be set explicitly for a production Tier 3 UKI/,
  );
  assert.doesNotMatch(code, PAYMENT_RESIDUE);
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
  assert.doesNotMatch(code, /BPIR_TIER3_IDENTITY_KEY/);
  assert.match(
    source,
    /private identity key must not be embedded in the Tier 3 UKI/,
  );
}

function validateDracutModuleContract(source) {
  const code = withoutComments(source);
  assert.doesNotMatch(code, PAYMENT_RESIDUE);
  assert.doesNotMatch(code, /inst_dir \/etc\/bitcoinpir\/payment/);
  assert.doesNotMatch(code, /BPIR_TIER3_IDENTITY_KEY/);
  assert.doesNotMatch(code, /server\.key/);
}

function validateMeasuredRunContract(source) {
  const code = withoutComments(source);
  assert.match(source, /UNIFIED_SERVER=\/usr\/local\/bin\/unified_server/);
  assert.match(source, /ORAMCTL=\/usr\/local\/bin\/oramctl/);
  assert.doesNotMatch(code, /target\/release\/unified_server/);
  assert.doesNotMatch(code, /target\/release\/oramctl/);
  assert.doesNotMatch(code, /--identity-key-path/);
  assert.doesNotMatch(code, /server\.key/);
  assert.doesNotMatch(code, /--service-|--require-service-auth-v1/);
  assert.doesNotMatch(code, PAYMENT_RESIDUE);
  assert.match(source, /--pir2-snp-sealed-envelope/);
  assert.match(source, /--pir2-snp-sealed-identity-cert/);
}

test("production Tier3 build takes exactly the runtime inputs and embeds no policy", () => {
  validateBuildContract(readFileSync(buildPath, "utf8"));
});

test("production Tier3 build pins the baked cloudflared release", () => {
  const source = readFileSync(buildPath, "utf8");
  assert.throws(() =>
    validateBuildContract(source.replace(/^TIER3_CLOUDFLARED_SHA256=[0-9a-f]{64}$/m, "")),
  );
  assert.throws(() =>
    validateBuildContract(source.replace(/^TIER3_CLOUDFLARED_VERSION=.*$/m, "TIER3_CLOUDFLARED_VERSION=latest")),
  );
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

test("runtime UKI pins the cashier key and the hint-set price, never --require-session-grant", () => {
  const source = readFileSync(runPath, "utf8");
  assert.match(source, /^PIR2_SESSION_GRANT_PUBKEY_HEX=[0-9a-f]{64}$/m);
  assert.match(source, /^PIR2_SESSION_GRANT_HINT_CREDITS=[1-9][0-9]*$/m);
  assert.match(source, /--session-grant-pubkey "\$PIR2_SESSION_GRANT_PUBKEY_FILE"/);
  assert.match(source, /--session-grant-hint-credits "\$PIR2_SESSION_GRANT_HINT_CREDITS"/);
  // A flag line, not a mention: the free path is closed by an operator, not by the image.
  assert.doesNotMatch(withoutComments(source), /^\s*--require-session-grant\b/m);
});

test("runtime UKI names the credit issuer and never --require-credits", () => {
  const source = readFileSync(runPath, "utf8");
  assert.match(source, /^PIR2_CREDIT_ISSUER_URL=https:\/\/[a-z0-9.-]+$/m);
  assert.match(source, /--credit-issuer-url "\$PIR2_CREDIT_ISSUER_URL"/);
  assert.doesNotMatch(withoutComments(source), /^\s*--require-credits\b/m);
});

test("a comment mentioning a retired flag or artifact does not fail any contract, a real line does", () => {
  const mention = "\n# historical note: --require-session-grant, server.key, BPIR_TIER3_SERVICE_POLICY, target/release/unified_server\n";
  validateBuildContract(readFileSync(buildPath, "utf8") + mention);
  validateDracutModuleContract(readFileSync(modulePath, "utf8") + mention);
  validateMeasuredRunContract(readFileSync(runPath, "utf8") + mention);
  assert.throws(() => validateMeasuredRunContract(`${readFileSync(runPath, "utf8")}\n    --identity-key-path /home/pir/data/server.key \\\n`));
  assert.throws(() => validateMeasuredRunContract(`${readFileSync(runPath, "utf8")}\nUNIFIED_SERVER=target/release/unified_server\n`));
  assert.throws(() => validateDracutModuleContract(`${readFileSync(modulePath, "utf8")}\ninst_simple /etc/bitcoinpir/server.key\n`));
  assert.throws(() => validateBuildContract(`${readFileSync(buildPath, "utf8")}\nBPIR_TIER3_SERVICE_POLICY=/tmp/policy.bin\n`));
});
