import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const root = new URL("../deploy/payment-v1/functional-beta/", import.meta.url);
const policy = readFileSync(new URL("service-policy.toml.in", root), "utf8");
const provider = readFileSync(new URL("provider-all-methods.args.in", root), "utf8");
const issuer = readFileSync(new URL("issuer-all-methods.args.in", root), "utf8");
const providerUnit = readFileSync(
  new URL("bitcoinpir-provider-functional-beta.service.in", root),
  "utf8",
);
const issuerUnit = readFileSync(
  new URL("bitcoinpir-payment-issuer-functional-beta.service.in", root),
  "utf8",
);
const caddyFragment = readFileSync(
  new URL("hetzner-existing-caddy.fragment.in", root),
  "utf8",
);

function scopeBlocks() {
  return policy.split("\n[[scopes]]\n").slice(1);
}

function priceFor(scope, authorization) {
  const offers = scope.split("\n[[scopes.offers]]\n").slice(1);
  const offer = offers.find((candidate) =>
    candidate.includes(`authorization = "${authorization}"`)
  );
  assert.ok(offer, `missing ${authorization} offer`);
  const amount = /\namount = (\d+)\n/.exec(offer)?.[1];
  assert.ok(amount, `missing ${authorization} amount`);
  return Number(amount);
}

function offerFor(scope, authorization) {
  const offers = scope.split("\n[[scopes.offers]]\n").slice(1);
  const offer = offers.find((candidate) =>
    candidate.includes(`authorization = "${authorization}"`)
  );
  assert.ok(offer, `missing ${authorization} offer`);
  return offer;
}

test("functional beta policy has five independent workload scopes and methods", () => {
  const scopes = scopeBlocks();
  assert.equal(scopes.length, 5);
  const expectedWorkloads = [
    "dpf-evaluate-job-v1",
    "harmony-hint-bundle-v1",
    "harmony-query-job-v1",
    "onion-evaluate-job-v1",
    "tee-oram-query-v1",
  ];
  for (const workload of expectedWorkloads) {
    const scope = scopes.find((candidate) =>
      candidate.includes(`workload = "${workload}"`)
    );
    assert.ok(scope, `missing ${workload}`);
    assert.equal((scope.match(/\[\[scopes\.offers\]\]/g) ?? []).length, 5);
    for (const authorization of [
      "free",
      "bolt11-direct-receipt",
      "cashu-ecash",
      "cashu-bat",
      "arc-experimental",
    ]) {
      assert.ok(
        scope.includes(`authorization = "${authorization}"`),
        `${workload} missing ${authorization}`,
      );
    }
  }

  const hint = scopes.find((scope) =>
    scope.includes('workload = "harmony-hint-bundle-v1"')
  );
  const query = scopes.find((scope) =>
    scope.includes('workload = "harmony-query-job-v1"')
  );
  assert.ok(hint && query);
  assert.ok(
    priceFor(hint, "bolt11-direct-receipt") >
      priceFor(query, "bolt11-direct-receipt"),
  );
  assert.ok(priceFor(hint, "cashu-ecash") > priceFor(query, "cashu-ecash"));
});

test("functional beta keeps direct, BAT, and ARC lineages distinct per scope", () => {
  const lineages = [
    [
      "dpf-evaluate-job-v1",
      "DIRECT_RECEIPT_KEY_ID_DPF_EVALUATE_JOB_V1_HEX",
      "BAT_KEY_ID_DPF_EVALUATE_JOB_V1_HEX",
      "ARC_KEY_ID_DPF_EVALUATE_JOB_V1_HEX",
    ],
    [
      "harmony-hint-bundle-v1",
      "DIRECT_RECEIPT_KEY_ID_HARMONY_HINT_BUNDLE_V1_HEX",
      "BAT_KEY_ID_HARMONY_HINT_BUNDLE_V1_HEX",
      "ARC_KEY_ID_HARMONY_HINT_BUNDLE_V1_HEX",
    ],
    [
      "harmony-query-job-v1",
      "DIRECT_RECEIPT_KEY_ID_HARMONY_QUERY_JOB_V1_HEX",
      "BAT_KEY_ID_HARMONY_QUERY_JOB_V1_HEX",
      "ARC_KEY_ID_HARMONY_QUERY_JOB_V1_HEX",
    ],
    [
      "onion-evaluate-job-v1",
      "DIRECT_RECEIPT_KEY_ID_ONION_EVALUATE_JOB_V1_HEX",
      "BAT_KEY_ID_ONION_EVALUATE_JOB_V1_HEX",
      "ARC_KEY_ID_ONION_EVALUATE_JOB_V1_HEX",
    ],
    [
      "tee-oram-query-v1",
      "DIRECT_RECEIPT_KEY_ID_TEE_ORAM_QUERY_V1_HEX",
      "BAT_KEY_ID_TEE_ORAM_QUERY_V1_HEX",
      "ARC_KEY_ID_TEE_ORAM_QUERY_V1_HEX",
    ],
  ];
  const seen = {
    "bolt11-direct-receipt": new Set(),
    "cashu-bat": new Set(),
    "arc-experimental": new Set(),
  };

  for (const [workload, directKeyId, batKeyId, arcKeyId] of lineages) {
    const scope = scopeBlocks().find((candidate) =>
      candidate.includes(`workload = "${workload}"`)
    );
    assert.ok(scope, `missing ${workload}`);
    for (const [authorization, keyId] of [
      ["bolt11-direct-receipt", directKeyId],
      ["cashu-bat", batKeyId],
      ["arc-experimental", arcKeyId],
    ]) {
      const offer = offerFor(scope, authorization);
      assert.ok(
        offer.includes(`key_id_hex = "@${keyId}@"`),
        `${workload} has the wrong ${authorization} key ID`,
      );
      seen[authorization].add(keyId);
    }

    const slug = workload;
    assert.ok(
      issuer.includes(`direct-receipt-${slug}.key`),
      `issuer missing ${workload} direct receipt key`,
    );
    assert.ok(
      issuer.includes(`cashu-bat-${slug}.key`),
      `issuer missing ${workload} BAT key`,
    );
    assert.ok(
      issuer.includes(`arc-experimental-${slug}.key`),
      `issuer missing ${workload} ARC key`,
    );
  }
  for (const [authorization, keyIds] of Object.entries(seen)) {
    assert.equal(keyIds.size, lineages.length, `${authorization} key IDs are reused`);
  }
  assert.ok(!provider.includes("--service-arc-key"));
  assert.ok(!providerUnit.includes("--service-arc-key"));
});

test("provider fragment loads its selected and shared runtime adapters", () => {
  for (const flag of [
    "--require-service-auth-v1",
    "--service-bat-key",
    "--allow-experimental-arc",
    "--service-cashu-recovery-key",
    "--service-cashu-custody-key",
    "--service-cashu-exposure-limit",
    "--service-shared-authorization",
    "--service-shared-issuer-approval",
    "--service-shared-clearing-key",
  ]) {
    assert.ok(provider.includes(flag), `provider missing ${flag}`);
  }
});

test("issuer fragment can issue direct receipts, BAT and experimental ARC", () => {
  for (const flag of [
    "--quote-delegation",
    "--quote-signing-key",
    "--receipt-signing-key",
    "--bat-key",
    "--arc-key",
    "--allow-experimental-arc",
    "--clearing-authorization",
    "--clearing-approval",
    "--issuer-settlement-signing-key",
    "--cln-rpc-socket",
  ]) {
    assert.ok(issuer.includes(flag), `issuer missing ${flag}`);
  }
});

test("functional beta units and Caddy fragment stay isolated from legacy listeners", () => {
  for (const [unit, expected] of [
    [
      issuerUnit,
      [
        "bitcoinpir-payment-issuer-functional-beta.service",
        "bitcoinpir-payment-issuer-functional-beta",
        "/etc/bitcoinpir/payment-v1/functional-beta/issuer",
        "--bind 127.0.0.1:@FUNCTIONAL_BETA_ISSUER_PORT@",
        "--allow-experimental-arc",
        "--bat-key",
        "--cln-rpc-socket",
      ],
    ],
    [
      providerUnit,
      [
        "bitcoinpir-provider-functional-beta.service",
        "bitcoinpir-provider-functional-beta",
        "/etc/bitcoinpir/payment-v1/functional-beta/provider",
        "--port @FUNCTIONAL_BETA_PROVIDER_PORT@",
        "--require-service-auth-v1",
        "--service-cashu-exposure-limit",
        "--service-bat-key",
        "--allow-experimental-arc",
        "--service-shared-authorization",
      ],
    ],
  ]) {
    for (const value of expected) {
      assert.ok(unit.includes(value), `unit missing ${value}`);
    }
    assert.ok(unit.includes("[Install]\nWantedBy=multi-user.target"));
    assert.ok(!unit.includes("--port 8091"));
    assert.ok(!unit.includes("--bind 127.0.0.1:5601"));
  }

  assert.match(
    caddyFragment,
    /@FUNCTIONAL_BETA_PROVIDER_WSS_HOST@ \{[\s\S]*handle \/v1\/pir \{[\s\S]*127\.0\.0\.1:@FUNCTIONAL_BETA_PROVIDER_PORT@/,
  );
  assert.match(
    caddyFragment,
    /@FUNCTIONAL_BETA_ISSUER_HTTPS_HOST@ \{[\s\S]*127\.0\.0\.1:@FUNCTIONAL_BETA_ISSUER_PORT@/,
  );
});
