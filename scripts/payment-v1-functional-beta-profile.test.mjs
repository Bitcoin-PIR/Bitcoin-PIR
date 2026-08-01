import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const root = new URL("../deploy/payment-v1/functional-beta/", import.meta.url);
const policy = readFileSync(new URL("service-policy.toml.in", root), "utf8");
const provider = readFileSync(new URL("provider-all-methods.args.in", root), "utf8");
const issuer = readFileSync(new URL("issuer-all-methods.args.in", root), "utf8");

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

test("provider fragment loads every local and shared runtime adapter", () => {
  for (const flag of [
    "--require-service-auth-v1",
    "--service-bat-key",
    "--service-arc-key",
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
