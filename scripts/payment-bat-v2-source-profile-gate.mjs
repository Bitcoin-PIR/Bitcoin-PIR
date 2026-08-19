#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const PROFILE_SCHEMA = "bitcoinpir-bat-v2-public-source-profile-v1";
const SOURCE_ROOT = "deploy/payment-v1/bat-v2-source-ready";
const MAX_RETAINED_PER_PROVIDER = 8;
const MAX_POLICIES = 2 + (2 * MAX_RETAINED_PER_PROVIDER);
const MAX_RETAINED_CLASSES = 8;
const MAX_CLASSES = 1 + MAX_RETAINED_CLASSES;
const PLACEHOLDER = /^@[A-Z0-9_]+@$/u;
const LOWER_HEX_32 = /^[0-9a-f]{64}$/u;

function fail(message) {
  throw new Error(message);
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${label} fields must match the closed schema`);
  }
}

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0) fail(`${label} must be non-empty`);
  return value;
}

function requireHexOrPlaceholder(value, label) {
  requireString(value, label);
  if (!LOWER_HEX_32.test(value) && !PLACEHOLDER.test(value)) {
    fail(`${label} must be canonical nonzero 32-byte lowercase hex or one render placeholder`);
  }
  if (LOWER_HEX_32.test(value) && /^0+$/u.test(value)) fail(`${label} must not be all zero`);
  return value;
}

function requireEpochOrPlaceholder(value, label) {
  requireString(value, label);
  if (!/^[1-9][0-9]*$/u.test(value) && !PLACEHOLDER.test(value)) {
    fail(`${label} must be a nonzero decimal or one render placeholder`);
  }
  return value;
}

function requireAbsolutePath(value, prefix, label) {
  requireString(value, label);
  if (!value.startsWith(`${prefix}/`) || value.includes("..") || /[\s=]/u.test(value)) {
    fail(`${label} is outside its closed absolute path root`);
  }
  return value;
}

function addUnique(set, value, label) {
  if (set.has(value)) fail(`duplicate ${label}: ${value}`);
  set.add(value);
}

function arrayBounded(value, min, max, label) {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    fail(`${label} must contain ${min}..${max} entries`);
  }
  return value;
}

function sameSet(actual, expected, label) {
  const left = [...actual].sort();
  const right = [...expected].sort();
  if (JSON.stringify(left) !== JSON.stringify(right)) fail(`${label} does not match the manifest`);
}

function sameOrder(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(`${label} order does not match the manifest`);
}

function requireStrictOrder(values, label) {
  for (let index = 1; index < values.length; index += 1) {
    if (values[index - 1] >= values[index]) fail(`${label} must use strict digest order`);
  }
}

function valuesForFlag(command, flag) {
  const tokens = command.trim().split(/\s+/u);
  const values = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index] === flag) {
      if (index + 1 >= tokens.length || tokens[index + 1].startsWith("--")) {
        fail(`${flag} requires an explicit value`);
      }
      values.push(tokens[index + 1]);
    }
  }
  return values;
}

function oneValue(command, flag, label) {
  const values = valuesForFlag(command, flag);
  if (values.length !== 1) fail(`${label} must contain exactly one ${flag}`);
  return values[0];
}

function execStart(source, label) {
  if (/^\[Install\]$/mu.test(source)) fail(`${label} must remain inert without [Install]`);
  const flattened = source.replace(/\\\r?\n[ \t]*/gu, " ");
  const commands = [...flattened.matchAll(/^ExecStart=(.+)$/gmu)].map((match) => match[1]);
  if (commands.length !== 1) fail(`${label} must contain exactly one ExecStart`);
  return commands[0];
}

function validatePolicy(value, index, seenDigests, seenPaths) {
  const label = `issuer.policies[${index}]`;
  const expectedKeys = [
    "state", "provider", "digestHex", "fileSha256Hex", "path", "verifyingKeyHex",
    "scopeIdHex", "offerId",
    ...(value.provider === "pir2" ? ["pir2RuntimePath"] : []),
  ];
  exactKeys(value, expectedKeys, label);
  if (!new Set(["current", "retained"]).has(value.state)) fail(`${label}.state is invalid`);
  if (!new Set(["pir1", "pir2"]).has(value.provider)) fail(`${label}.provider is invalid`);
  requireHexOrPlaceholder(value.digestHex, `${label}.digestHex`);
  requireHexOrPlaceholder(value.fileSha256Hex, `${label}.fileSha256Hex`);
  requireHexOrPlaceholder(value.verifyingKeyHex, `${label}.verifyingKeyHex`);
  requireHexOrPlaceholder(value.scopeIdHex, `${label}.scopeIdHex`);
  requireEpochOrPlaceholder(value.offerId, `${label}.offerId`);
  requireAbsolutePath(value.path, "/etc/bitcoinpir/payment-v1/bat-v2/public/policies", `${label}.path`);
  if (value.provider === "pir2") {
    if (value.state === "current") {
      if (value.pir2RuntimePath !== "/etc/bitcoinpir/payment/service-policy.bin") {
        fail(`${label}.pir2RuntimePath must use the measured current policy path`);
      }
    } else {
      requireAbsolutePath(value.pir2RuntimePath, "/home/pir/data/pir2-sealed/public/policies", `${label}.pir2RuntimePath`);
      if (value.pir2RuntimePath !== `/home/pir/data/pir2-sealed/public/policies/${value.digestHex}.bin`) {
        fail(`${label}.pir2RuntimePath must be immutable by exact policy digest`);
      }
    }
    addUnique(seenPaths, value.pir2RuntimePath, "pir2 runtime artifact path");
  }
  addUnique(seenDigests, value.digestHex, "policy digest");
  addUnique(seenPaths, value.path, "public artifact path");
}

function validateClass(value, index, policyDigests, seenDigests, seenPaths, seenSecretPaths, coverage) {
  const label = `issuer.classes[${index}]`;
  exactKeys(value, [
    "state", "classIdHex", "keyEpoch", "digestHex", "fileSha256Hex", "path",
    "pir2RuntimePath", "classVerifyingKeyHex", "batKeyIdHex", "batSigningKeyPath",
    "memberPolicyDigestsHex",
  ], label);
  if (!new Set(["current", "retained"]).has(value.state)) fail(`${label}.state is invalid`);
  for (const field of ["classIdHex", "digestHex", "fileSha256Hex", "classVerifyingKeyHex", "batKeyIdHex"]) {
    requireHexOrPlaceholder(value[field], `${label}.${field}`);
  }
  requireEpochOrPlaceholder(value.keyEpoch, `${label}.keyEpoch`);
  requireAbsolutePath(value.path, "/etc/bitcoinpir/payment-v1/bat-v2/public/classes", `${label}.path`);
  requireAbsolutePath(value.pir2RuntimePath, "/home/pir/data/pir2-sealed/public/classes", `${label}.pir2RuntimePath`);
  if (value.pir2RuntimePath !== `/home/pir/data/pir2-sealed/public/classes/${value.digestHex}.bin`) {
    fail(`${label}.pir2RuntimePath must be immutable by exact class digest`);
  }
  requireAbsolutePath(value.batSigningKeyPath, "/etc/bitcoinpir/payment-v1/bat-v2/issuer", `${label}.batSigningKeyPath`);
  addUnique(seenDigests, value.digestHex, "class digest");
  addUnique(seenPaths, value.path, "public artifact path");
  addUnique(seenPaths, value.pir2RuntimePath, "pir2 runtime artifact path");
  addUnique(seenSecretPaths, value.batSigningKeyPath, "private signing-key path");
  const members = arrayBounded(value.memberPolicyDigestsHex, 1, MAX_POLICIES, `${label}.memberPolicyDigestsHex`);
  const local = new Set();
  for (const digest of members) {
    requireHexOrPlaceholder(digest, `${label}.memberPolicyDigestsHex[]`);
    if (!policyDigests.has(digest)) fail(`${label} contains an unknown policy member`);
    addUnique(local, digest, "class member");
    coverage.set(digest, (coverage.get(digest) ?? 0) + 1);
  }
}

function validateAccounting(value, index, seenPaths) {
  const label = `issuer.accounting[${index}]`;
  const expectedKeys = [
    "provider", "authorizationDigestHex", "authorizationFileSha256Hex", "authorizationPath",
    "approvalDigestHex", "approvalFileSha256Hex", "approvalPath", "operatorVerifyingKeyHex",
    "operatorVerifyingKeyPath", "minimumAuthorizationEpoch",
  ];
  if (value.provider === "pir2") expectedKeys.push("pir2AuthorizationPath", "pir2ApprovalPath");
  exactKeys(value, expectedKeys, label);
  if (!new Set(["pir1", "pir2"]).has(value.provider)) fail(`${label}.provider is invalid`);
  for (const field of [
    "authorizationDigestHex", "authorizationFileSha256Hex", "approvalDigestHex",
    "approvalFileSha256Hex", "operatorVerifyingKeyHex",
  ]) requireHexOrPlaceholder(value[field], `${label}.${field}`);
  requireEpochOrPlaceholder(value.minimumAuthorizationEpoch, `${label}.minimumAuthorizationEpoch`);
  requireAbsolutePath(value.authorizationPath, "/etc/bitcoinpir/payment-v1/bat-v2/public/accounting", `${label}.authorizationPath`);
  requireAbsolutePath(value.approvalPath, "/etc/bitcoinpir/payment-v1/bat-v2/public/accounting", `${label}.approvalPath`);
  requireAbsolutePath(value.operatorVerifyingKeyPath, "/etc/bitcoinpir/payment-v1/bat-v2/public/keys", `${label}.operatorVerifyingKeyPath`);
  for (const path of [value.authorizationPath, value.approvalPath, value.operatorVerifyingKeyPath]) {
    addUnique(seenPaths, path, "public artifact path");
  }
  if (value.provider === "pir2") {
    if (value.pir2AuthorizationPath !== "/home/pir/data/pir2-sealed/provider-accounting-authorization.bin") {
      fail(`${label}.pir2AuthorizationPath must match the sealed Ready loader path`);
    }
    if (value.pir2ApprovalPath !== "/home/pir/data/pir2-sealed/issuer-accounting-approval.bin") {
      fail(`${label}.pir2ApprovalPath must match the sealed Ready loader path`);
    }
    addUnique(seenPaths, value.pir2AuthorizationPath, "pir2 runtime artifact path");
    addUnique(seenPaths, value.pir2ApprovalPath, "pir2 runtime artifact path");
  }
}

export function validateSourceProfileV1(profile) {
  exactKeys(profile, ["schema", "profile", "issuer", "providers"], "profile");
  if (profile.schema !== PROFILE_SCHEMA) fail(`profile.schema must equal ${PROFILE_SCHEMA}`);
  if (profile.profile !== "issuer-pir1-pir2-storeless-v1") fail("profile.profile is unsupported");
  exactKeys(profile.issuer, [
    "issuerIdHex", "settlementVerifyingKeyHex", "settlementSigningKeyPath", "unitPath",
    "policies", "classes", "accounting",
  ], "issuer");
  requireHexOrPlaceholder(profile.issuer.issuerIdHex, "issuer.issuerIdHex");
  requireHexOrPlaceholder(profile.issuer.settlementVerifyingKeyHex, "issuer.settlementVerifyingKeyHex");
  requireAbsolutePath(profile.issuer.settlementSigningKeyPath, "/etc/bitcoinpir/payment-v1/bat-v2/issuer", "issuer.settlementSigningKeyPath");
  if (profile.issuer.unitPath !== `${SOURCE_ROOT}/issuer-lightning-mainnet-bat-v2-payment-issuer.service.in`) {
    fail("issuer.unitPath is outside the versioned source profile");
  }

  const seenDigests = new Set();
  const seenPaths = new Set();
  const seenSecretPaths = new Set();
  addUnique(seenSecretPaths, profile.issuer.settlementSigningKeyPath, "private signing-key path");
  const policies = arrayBounded(profile.issuer.policies, 4, MAX_POLICIES, "issuer.policies");
  policies.forEach((value, index) => validatePolicy(value, index, seenDigests, seenPaths));
  const policyDigests = new Set(policies.map((policy) => policy.digestHex));
  const coverage = new Map();
  const classes = arrayBounded(profile.issuer.classes, 2, MAX_CLASSES, "issuer.classes");
  classes.forEach((value, index) => validateClass(
    value, index, policyDigests, seenDigests, seenPaths, seenSecretPaths, coverage,
  ));
  const classCoordinates = new Set();
  for (const entry of classes) {
    addUnique(classCoordinates, `${entry.classIdHex}:${entry.keyEpoch}`, "class coordinate");
  }
  for (const digest of policyDigests) {
    if (!coverage.has(digest)) fail(`policy ${digest} must be covered by at least one configured class`);
  }
  if (classes.filter((value) => value.state === "current").length !== 1) fail("issuer must have exactly one current class");
  if (!classes.some((value) => value.state === "retained")) fail("issuer must have retained class material");
  requireStrictOrder(
    classes.filter((value) => value.state === "retained").map((value) => value.digestHex),
    "issuer retained classes",
  );

  const accounting = arrayBounded(profile.issuer.accounting, 2, 2, "issuer.accounting");
  accounting.forEach((value, index) => validateAccounting(value, index, seenPaths));
  sameSet(accounting.map((value) => value.provider), ["pir1", "pir2"], "issuer accounting providers");

  const providers = arrayBounded(profile.providers, 2, 2, "providers");
  const names = providers.map((provider) => provider.name);
  sameSet(names, ["pir1", "pir2"], "provider roles");
  const providerIds = new Set();
  const roleKeys = new Map([[profile.issuer.settlementVerifyingKeyHex, "issuer settlement key"]]);
  const batKeyIds = new Set();
  const classSigner = classes[0].classVerifyingKeyHex;
  if (classes.some((value) => value.classVerifyingKeyHex !== classSigner)) {
    fail("all BAT V2 classes for one issuer must use the same class artifact signer");
  }
  if (roleKeys.has(classSigner)) {
    fail(`raw/public role-key reuse between ${roleKeys.get(classSigner)} and class artifact signer`);
  }
  roleKeys.set(classSigner, "class artifact signer");
  for (const value of classes) {
    addUnique(batKeyIds, value.batKeyIdHex, "BAT key id");
  }

  for (const [index, provider] of providers.entries()) {
    const label = `providers[${index}]`;
    const expectedKeys = [
      "name", "providerIdHex", "policyVerifyingKeyHex", "clearingKeySource",
      "clearingVerifyingKeyHex", "currentPolicyDigestHex", "retainedPolicyDigestsHex",
      "classDigestsHex", "accountingAuthorizationDigestHex", "accountingApprovalDigestHex",
      "operatorVerifyingKeyHex", "minimumAuthorizationEpoch", "renderPath",
      ...(provider.name === "pir2" ? ["artifactSetPath", "startupPath"] : []),
    ];
    exactKeys(provider, expectedKeys, label);
    if (!new Set(["pir1", "pir2"]).has(provider.name)) fail(`${label}.name is invalid`);
    for (const field of [
      "providerIdHex", "policyVerifyingKeyHex", "clearingVerifyingKeyHex",
      "currentPolicyDigestHex", "accountingAuthorizationDigestHex",
      "accountingApprovalDigestHex", "operatorVerifyingKeyHex",
    ]) requireHexOrPlaceholder(provider[field], `${label}.${field}`);
    requireEpochOrPlaceholder(provider.minimumAuthorizationEpoch, `${label}.minimumAuthorizationEpoch`);
    addUnique(providerIds, provider.providerIdHex, "provider id");
    const expectedSource = provider.name === "pir1" ? "plaintext-pir1" : "snp-sealed-ready";
    if (provider.clearingKeySource !== expectedSource) fail(`${label} has the wrong clearing-key source`);
    const providerPolicies = policies.filter((policy) => policy.provider === provider.name);
    const current = providerPolicies.filter((policy) => policy.state === "current");
    const retained = providerPolicies.filter((policy) => policy.state === "retained");
    if (current.length !== 1) fail(`${label} must have exactly one current signed policy`);
    arrayBounded(retained, 1, MAX_RETAINED_PER_PROVIDER, `${label} retained policies`);
    requireStrictOrder(retained.map((policy) => policy.digestHex), `${label} retained policies`);
    if (providerPolicies.some((policy) => policy.verifyingKeyHex !== provider.policyVerifyingKeyHex)) {
      fail(`${label} policy verifying key is inconsistent with its signed-policy set`);
    }
    if (provider.currentPolicyDigestHex !== current[0].digestHex) fail(`${label} current policy is inconsistent`);
    sameSet(provider.retainedPolicyDigestsHex, retained.map((policy) => policy.digestHex), `${label} retained policies`);
    const expectedClassDigests = classes
      .filter((entry) => entry.memberPolicyDigestsHex.some((digest) => providerPolicies.some((policy) => policy.digestHex === digest)))
      .map((entry) => entry.digestHex);
    sameSet(provider.classDigestsHex, expectedClassDigests, `${label} classes`);
    const relation = accounting.find((entry) => entry.provider === provider.name);
    if (provider.accountingAuthorizationDigestHex !== relation.authorizationDigestHex
      || provider.accountingApprovalDigestHex !== relation.approvalDigestHex
      || provider.operatorVerifyingKeyHex !== relation.operatorVerifyingKeyHex
      || provider.minimumAuthorizationEpoch !== relation.minimumAuthorizationEpoch) {
      fail(`${label} current accounting relationship is inconsistent`);
    }
    for (const [key, role] of [
      [provider.policyVerifyingKeyHex, `${provider.name} policy key`],
      [provider.clearingVerifyingKeyHex, `${provider.name} clearing key`],
      [provider.operatorVerifyingKeyHex, `${provider.name} operator key`],
    ]) {
      if (roleKeys.has(key)) fail(`raw/public role-key reuse between ${roleKeys.get(key)} and ${role}`);
      roleKeys.set(key, role);
    }
    const expectedRender = provider.name === "pir1"
      ? `${SOURCE_ROOT}/pir1-storeless-bat-v2-provider.service.in`
      : "scripts/dracut/97bpir-tier3-init/unified-server-run.sh";
    if (provider.renderPath !== expectedRender) fail(`${label}.renderPath is unsupported`);
    if (provider.name === "pir2") {
      if (provider.artifactSetPath !== `${SOURCE_ROOT}/pir2-public-artifact-set.env.in`
        || provider.startupPath !== `${SOURCE_ROOT}/pir2-sealed-startup.env.in`) {
        fail("pir2 render inputs must use the reviewed versioned artifact/startup templates");
      }
    }
  }
  return profile;
}

function forbid(command, patterns, label) {
  for (const [pattern, description] of patterns) {
    if (pattern.test(command)) fail(`${label} contains forbidden ${description}`);
  }
}

export function validateIssuerUnitV1(source, profile) {
  const command = execStart(source, "BAT V2 issuer unit");
  for (const sentinel of [
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/BAT-V2-SOURCE-PROFILE-RENDERED",
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/MAINNET-BAT-V2-ACTIVATION-APPROVED",
  ]) {
    if (!source.includes(sentinel)) fail(`BAT V2 issuer unit is missing ${sentinel}`);
  }
  if (source.includes("MAINNET-LIGHTNING-V1-ACTIVATION-APPROVED")) {
    fail("BAT V2 issuer unit must not reuse the V1 activation approval");
  }
  if (!command.startsWith("/opt/bitcoinpir/payment-issuer/@PAYMENT_ISSUER_SHA256@/payment-issuer serve-cln ")) {
    fail("BAT V2 issuer unit has the wrong executable or backend");
  }
  forbid(command, [
    [/--receipt-signing-key(?:\s|$)/u, "Direct receipt key"],
    [/--clearing-(?:authorization|approval|provider-request-verifying-key)(?:\s|$)/u, "V1 clearing"],
    [/--redeem-response-derivation-key(?:\s|$)/u, "V1 idempotency derivation"],
    [/--(?:arc-key|allow-experimental-arc)(?:\s|$)/u, "ARC"],
    [/--retained-issuer-settlement-verifying-key(?:\s|$)/u, "retained accounting runtime"],
  ], "BAT V2 issuer unit");
  sameSet(valuesForFlag(command, "--service-policy"), profile.issuer.policies.map((policy) => `${policy.path}=${policy.verifyingKeyHex}`), "issuer policy argv");
  sameSet(valuesForFlag(command, "--bat-v2-class"), profile.issuer.classes.map((entry) => entry.path), "issuer class argv");
  sameSet(valuesForFlag(command, "--bat-key"), profile.issuer.classes.map((entry) => entry.batSigningKeyPath), "issuer BAT key argv");
  sameOrder(valuesForFlag(command, "--bat-v2-accounting-authorization"), profile.issuer.accounting.map((entry) => entry.authorizationPath), "issuer accounting authorization argv");
  sameOrder(valuesForFlag(command, "--bat-v2-accounting-approval"), profile.issuer.accounting.map((entry) => entry.approvalPath), "issuer accounting approval argv");
  sameOrder(valuesForFlag(command, "--bat-v2-accounting-operator-verifying-key"), profile.issuer.accounting.map((entry) => entry.operatorVerifyingKeyPath), "issuer operator-key argv");
  if (oneValue(command, "--issuer-settlement-signing-key", "BAT V2 issuer unit") !== profile.issuer.settlementSigningKeyPath) {
    fail("issuer settlement signing-key path does not match the profile");
  }
}

export function validatePir1UnitV1(source, profile) {
  const command = execStart(source, "pir1 BAT V2 unit");
  for (const sentinel of [
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/BAT-V2-SOURCE-PROFILE-RENDERED",
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/PIR1-BAT-V2-ACTIVATION-APPROVED",
  ]) {
    if (!source.includes(sentinel)) fail(`pir1 BAT V2 unit is missing ${sentinel}`);
  }
  const provider = profile.providers.find((entry) => entry.name === "pir1");
  const policies = profile.issuer.policies.filter((entry) => entry.provider === "pir1");
  const current = policies.find((entry) => entry.state === "current");
  const retained = policies.filter((entry) => entry.state === "retained");
  const classes = profile.issuer.classes.filter((entry) => provider.classDigestsHex.includes(entry.digestHex));
  const accounting = profile.issuer.accounting.find((entry) => entry.provider === "pir1");
  forbid(command, [
    [/--service-store(?:\s|$)/u, "ProviderStore"],
    [/--service-(?:remote-)?rollback-authority(?:\s|$)/u, "rollback authority"],
    [/--service-shared-/u, "V1 shared clearing"],
    [/--service-(?:bat-key|arc-key|cashu-)/u, "V1 BAT/ARC/Standard Cashu"],
    [/--service-retained-policy(?:\s|$)/u, "V1 retained policy"],
    [/--(?:allow-experimental-arc|require-arc|require-cashu)(?:\s|$)/u, "legacy paid gate"],
  ], "pir1 BAT V2 unit");
  const serviceFlags = [...command.matchAll(/--service-[a-z0-9-]+/gu)].map((match) => match[0]);
  const allowedBase = new Set([
    "--service-policy", "--service-provider-id-hex", "--service-policy-key-hex",
    "--service-max-concurrent-auth", "--service-max-concurrent-online-v2full-auth",
    "--service-pre-auth-timeout-ms",
  ]);
  for (const flag of serviceFlags) {
    if (!allowedBase.has(flag) && !flag.startsWith("--service-storeless-bat-v2-")) {
      fail(`pir1 BAT V2 unit uses unsupported service flag ${flag}`);
    }
  }
  if (oneValue(command, "--service-policy", "pir1 BAT V2 unit") !== current.path
    || oneValue(command, "--service-provider-id-hex", "pir1 BAT V2 unit") !== provider.providerIdHex
    || oneValue(command, "--service-policy-key-hex", "pir1 BAT V2 unit") !== provider.policyVerifyingKeyHex
    || oneValue(command, "--service-storeless-bat-v2-policy-digest-hex", "pir1 BAT V2 unit") !== current.digestHex) {
    fail("pir1 current policy argv does not match the profile");
  }
  sameSet(valuesForFlag(command, "--service-storeless-bat-v2-retained-policy"), retained.map((entry) => `${entry.digestHex}=${entry.path}`), "pir1 retained policy argv");
  sameSet(valuesForFlag(command, "--service-storeless-bat-v2-class"), classes.map((entry) => `${entry.digestHex}=${entry.path}`), "pir1 class argv");
  if (oneValue(command, "--service-storeless-bat-v2-accounting-authorization", "pir1 BAT V2 unit") !== accounting.authorizationPath
    || oneValue(command, "--service-storeless-bat-v2-issuer-approval", "pir1 BAT V2 unit") !== accounting.approvalPath
    || oneValue(command, "--service-storeless-bat-v2-operator-key-hex", "pir1 BAT V2 unit") !== provider.operatorVerifyingKeyHex
    || oneValue(command, "--service-storeless-bat-v2-issuer-settlement-key-hex", "pir1 BAT V2 unit") !== profile.issuer.settlementVerifyingKeyHex
    || oneValue(command, "--service-storeless-bat-v2-minimum-authorization-epoch", "pir1 BAT V2 unit") !== provider.minimumAuthorizationEpoch) {
    fail("pir1 current accounting argv does not match the profile");
  }
  oneValue(command, "--service-storeless-bat-v2-pir1-clearing-key", "pir1 BAT V2 unit");
}

export function validatePrivateSecretPathsV1(issuerSource, pir1Source, profile) {
  const issuerCommand = execStart(issuerSource, "BAT V2 issuer unit");
  const pir1Command = execStart(pir1Source, "pir1 BAT V2 unit");
  const privatePaths = [
    [oneValue(issuerCommand, "--issuer-settlement-signing-key", "BAT V2 issuer unit"), "issuer settlement signing key"],
    ...valuesForFlag(issuerCommand, "--bat-key").map((value) => [value, "issuer BAT scalar"]),
    [oneValue(issuerCommand, "--quote-signing-key", "BAT V2 issuer unit"), "issuer quote signing key"],
    [oneValue(issuerCommand, "--credential-derivation-key", "BAT V2 issuer unit"), "issuer credential derivation key"],
    [oneValue(pir1Command, "--identity-key-path", "pir1 BAT V2 unit"), "pir1 identity signing key"],
    [oneValue(pir1Command, "--service-storeless-bat-v2-pir1-clearing-key", "pir1 BAT V2 unit"), "pir1 clearing signing key"],
  ];
  const seen = new Set();
  for (const [value, label] of privatePaths) {
    requireAbsolutePath(value, "/etc/bitcoinpir/payment-v1/bat-v2", label);
    addUnique(seen, value, "private signing-key path");
  }
  sameSet(
    valuesForFlag(issuerCommand, "--bat-key"),
    profile.issuer.classes.map((entry) => entry.batSigningKeyPath),
    "issuer BAT private-path set",
  );
}

function parseEnv(source, label) {
  if (!source.endsWith("\n") || source.includes("\r")) fail(`${label} must be canonical LF text`);
  const entries = [];
  for (const [index, line] of source.trimEnd().split("\n").entries()) {
    const split = line.indexOf("=");
    if (split <= 0 || split === line.length - 1) fail(`${label} line ${index + 1} is malformed`);
    entries.push([line.slice(0, split), line.slice(split + 1)]);
  }
  return entries;
}

function measuredHexConstant(runSource, name) {
  const pattern = new RegExp(`^${name}=([0-9a-f]{64})$`, "gmu");
  const matches = [...runSource.matchAll(pattern)];
  if (matches.length !== 1) fail(`pir2 measured run path must define exactly one ${name}`);
  return matches[0][1];
}

export function validatePir2RenderInputsV1(artifactSource, startupSource, runSource, profile) {
  const provider = profile.providers.find((entry) => entry.name === "pir2");
  const policies = profile.issuer.policies.filter((entry) => entry.provider === "pir2");
  const currentPolicy = policies.find((entry) => entry.state === "current");
  const retainedPolicies = policies.filter((entry) => entry.state === "retained");
  const classes = profile.issuer.classes.filter((entry) => provider.classDigestsHex.includes(entry.digestHex));
  const currentClass = classes.find((entry) => entry.state === "current");
  const retainedClasses = classes.filter((entry) => entry.state === "retained");
  const accounting = profile.issuer.accounting.find((entry) => entry.provider === "pir2");
  for (const [actual, constantName, label] of [
    [provider.providerIdHex, "PIR2_SEALED_PROVIDER_ID_HEX", "provider id"],
    [provider.policyVerifyingKeyHex, "PIR2_SEALED_POLICY_KEY_HEX", "policy key"],
    [provider.operatorVerifyingKeyHex, "PIR2_SEALED_OPERATOR_KEY_HEX", "operator key"],
    [profile.issuer.settlementVerifyingKeyHex, "PIR2_SEALED_ISSUER_SETTLEMENT_KEY_HEX", "issuer settlement key"],
  ]) {
    if (actual !== measuredHexConstant(runSource, constantName)) {
      fail(`pir2 ${label} does not match measured source constant ${constantName}`);
    }
  }
  const artifact = parseEnv(artifactSource, "pir2 artifact set");
  if (artifact.length < 7 || artifact.length > 4 + MAX_RETAINED_PER_PROVIDER + MAX_CLASSES) {
    fail("pir2 artifact set is outside its bounded entry count");
  }
  if (artifact[0][0] !== "schema" || artifact[0][1] !== "bitcoinpir-pir2-bat-v2-public-artifact-set-v1") {
    fail("pir2 artifact set schema is unsupported");
  }
  const expectedArtifact = [
    ["current_policy", `${currentPolicy.digestHex}=${currentPolicy.fileSha256Hex}=${currentPolicy.pir2RuntimePath}`],
    ...retainedPolicies.map((entry) => ["retained_policy", `${entry.digestHex}=${entry.fileSha256Hex}=${entry.pir2RuntimePath}`]),
    ["current_class", `${currentClass.digestHex}=${currentClass.fileSha256Hex}=${currentClass.pir2RuntimePath}`],
    ...retainedClasses.map((entry) => ["retained_class", `${entry.digestHex}=${entry.fileSha256Hex}=${entry.pir2RuntimePath}`]),
    ["accounting_authorization", `${accounting.authorizationDigestHex}=${accounting.authorizationFileSha256Hex}=${accounting.pir2AuthorizationPath}`],
    ["accounting_approval", `${accounting.approvalDigestHex}=${accounting.approvalFileSha256Hex}=${accounting.pir2ApprovalPath}`],
  ];
  if (JSON.stringify(artifact.slice(1)) !== JSON.stringify(expectedArtifact)) {
    fail("pir2 artifact set entries do not match the profile in canonical order");
  }
  const startup = parseEnv(startupSource, "pir2 startup config");
  const startupKeys = startup.map(([key]) => key);
  const expectedKeys = [
    "schema", "profile", "phase", "ordinal", "verifier_nonce_hex",
    "current_policy_digest_hex", "class_digest_hex", "artifact_set_path",
    "artifact_set_sha256", "minimum_authorization_epoch",
  ];
  if (JSON.stringify(startupKeys) !== JSON.stringify(expectedKeys)) fail("pir2 startup config fields/order are not canonical v2");
  const startupMap = new Map(startup);
  if (startupMap.get("schema") !== "bitcoinpir-pir2-sealed-startup-v2"
    || startupMap.get("profile") !== "pir2-snp-sealed-v1"
    || startupMap.get("current_policy_digest_hex") !== currentPolicy.digestHex
    || startupMap.get("class_digest_hex") !== currentClass.digestHex
    || startupMap.get("artifact_set_path") !== "/home/pir/data/pir2-sealed/public-artifact-set.env"
    || startupMap.get("minimum_authorization_epoch") !== provider.minimumAuthorizationEpoch) {
    fail("pir2 startup config does not bind the profile");
  }
  for (const required of [
    "bitcoinpir-pir2-sealed-startup-v2", "artifact_set_path", "artifact_set_sha256",
    "PIR2_SEALED_ARTIFACT_SET_SHA256", "validate_pir2_public_artifact_set",
    "PIR2_SEALED_TRUSTED_ARTIFACT_SET_PATH", "PIR2_ACTIVE_ARTIFACT_SET_PATH",
    "artifact_set_sha256=", "--service-storeless-bat-v2-retained-policy",
    "--service-storeless-bat-v2-class",
  ]) {
    if (!runSource.includes(required)) fail(`pir2 measured run path is missing ${required}`);
  }
  if (/--service-storeless-bat-v2-pir1-clearing-key/u.test(runSource)
    || /--service-shared-(?:clearing|idempotency)/u.test(runSource)) {
    fail("pir2 measured run path contains a plaintext or V1 clearing fallback");
  }
}

export function validateRepository(root) {
  const sourceRoot = join(root, SOURCE_ROOT);
  const profile = validateSourceProfileV1(JSON.parse(readFileSync(join(sourceRoot, "source-profile.json.in"), "utf8")));
  const issuerSource = readFileSync(join(sourceRoot, "issuer-lightning-mainnet-bat-v2-payment-issuer.service.in"), "utf8");
  const pir1Source = readFileSync(join(sourceRoot, "pir1-storeless-bat-v2-provider.service.in"), "utf8");
  validateIssuerUnitV1(issuerSource, profile);
  validatePir1UnitV1(pir1Source, profile);
  validatePrivateSecretPathsV1(issuerSource, pir1Source, profile);
  validatePir2RenderInputsV1(
    readFileSync(join(sourceRoot, "pir2-public-artifact-set.env.in"), "utf8"),
    readFileSync(join(sourceRoot, "pir2-sealed-startup.env.in"), "utf8"),
    readFileSync(join(root, "scripts/dracut/97bpir-tier3-init/unified-server-run.sh"), "utf8"),
    profile,
  );
  return { schema: PROFILE_SCHEMA, result: "PASS" };
}

const isMain = process.argv[1] !== undefined
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  const repository = process.argv[2]
    ? resolve(process.argv[2])
    : resolve(dirname(fileURLToPath(import.meta.url)), "..");
  try {
    process.stdout.write(`${JSON.stringify(validateRepository(repository))}\n`);
  } catch (error) {
    process.stderr.write(`payment-bat-v2-source-profile-gate: ${error.message}\n`);
    process.exitCode = 1;
  }
}
