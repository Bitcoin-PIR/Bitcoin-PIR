import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  PROFILE_SCHEMA,
  validateIssuerUnitV1,
  validatePir1UnitV1,
  validatePir2RenderInputsV1,
  validateRepository,
  validateSourceProfileV1,
} from "./payment-bat-v2-source-profile-gate.mjs";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = join(repository, "deploy/payment-v1/bat-v2-source-ready");
const profileSource = readFileSync(join(sourceRoot, "source-profile.json.in"), "utf8");
const issuerSource = readFileSync(
  join(sourceRoot, "issuer-lightning-mainnet-bat-v2-payment-issuer.service.in"),
  "utf8",
);
const pir1Source = readFileSync(
  join(sourceRoot, "pir1-storeless-bat-v2-provider.service.in"),
  "utf8",
);
const artifactSource = readFileSync(join(sourceRoot, "pir2-public-artifact-set.env.in"), "utf8");
const startupSource = readFileSync(join(sourceRoot, "pir2-sealed-startup.env.in"), "utf8");
const runSource = readFileSync(
  join(repository, "scripts/dracut/97bpir-tier3-init/unified-server-run.sh"),
  "utf8",
);

function profile() {
  return JSON.parse(profileSource);
}

test("checked-in BAT V2 source profile and all three render roles pass", () => {
  assert.deepEqual(validateRepository(repository), { schema: PROFILE_SCHEMA, result: "PASS" });
  const stdout = execFileSync(
    process.execPath,
    [join(repository, "scripts/payment-bat-v2-source-profile-gate.mjs"), repository],
    { encoding: "utf8" },
  );
  assert.deepEqual(JSON.parse(stdout), { schema: PROFILE_SCHEMA, result: "PASS" });
});

test("profile schema is closed and retained material is mandatory", () => {
  const unknown = profile();
  unknown.issuer.retainedAccounting = [];
  assert.throws(() => validateSourceProfileV1(unknown), /fields must match the closed schema/u);

  const noRetained = profile();
  noRetained.issuer.policies = noRetained.issuer.policies.filter((entry) => entry.state === "current");
  assert.throws(() => validateSourceProfileV1(noRetained), /issuer\.policies must contain 4/u);

  const tooManyRetainedClasses = profile();
  tooManyRetainedClasses.issuer.classes.push(...Array.from({ length: 8 }, () => ({})));
  assert.throws(
    () => validateSourceProfileV1(tooManyRetainedClasses),
    /issuer\.classes must contain 2\.\.9 entries/u,
  );
});

test("class membership covers every policy and is coordinate-fork-free", () => {
  const missing = profile();
  missing.issuer.classes[1].memberPolicyDigestsHex.pop();
  assert.throws(() => validateSourceProfileV1(missing), /covered by at least one configured class/u);

  const fork = profile();
  fork.issuer.classes[1].classIdHex = fork.issuer.classes[0].classIdHex;
  fork.issuer.classes[1].keyEpoch = fork.issuer.classes[0].keyEpoch;
  assert.throws(() => validateSourceProfileV1(fork), /duplicate class coordinate/u);

  const reusedBatPath = profile();
  reusedBatPath.issuer.classes[1].batSigningKeyPath = reusedBatPath.issuer.classes[0].batSigningKeyPath;
  assert.throws(() => validateSourceProfileV1(reusedBatPath), /duplicate issuer BAT signing-key path/u);
});

test("provider ids, policy roots, and role keys cannot be reused", () => {
  const duplicateProvider = profile();
  duplicateProvider.providers[1].providerIdHex = duplicateProvider.providers[0].providerIdHex;
  assert.throws(() => validateSourceProfileV1(duplicateProvider), /duplicate provider id/u);

  const wrongPolicyRoot = profile();
  wrongPolicyRoot.providers[0].policyVerifyingKeyHex = "@PIR1_OTHER_POLICY_VERIFYING_KEY_HEX@";
  assert.throws(() => validateSourceProfileV1(wrongPolicyRoot), /policy verifying key is inconsistent/u);

  const roleReuse = profile();
  roleReuse.providers[1].operatorVerifyingKeyHex = roleReuse.issuer.settlementVerifyingKeyHex;
  roleReuse.issuer.accounting[1].operatorVerifyingKeyHex = roleReuse.issuer.settlementVerifyingKeyHex;
  assert.throws(() => validateSourceProfileV1(roleReuse), /role-key reuse/u);
});

test("issuer argv rejects V1 redemption and keeps exact V2 artifact sets", () => {
  const checked = validateSourceProfileV1(profile());
  assert.throws(
    () => validateIssuerUnitV1(
      issuerSource.replace(
        "    --bat-v2-class /etc/bitcoinpir/payment-v1/bat-v2/public/classes/current.bin \\\n",
        "    --receipt-signing-key /tmp/direct.key \\\n    --bat-v2-class /etc/bitcoinpir/payment-v1/bat-v2/public/classes/current.bin \\\n",
      ),
      checked,
    ),
    /forbidden Direct receipt key/u,
  );
  assert.throws(
    () => validateIssuerUnitV1(
      issuerSource.replace(
        "    --bat-v2-class /etc/bitcoinpir/payment-v1/bat-v2/public/classes/retained.bin \\\n",
        "",
      ),
      checked,
    ),
    /issuer class argv does not match/u,
  );
  const swappedApprovals = issuerSource
    .replace("/etc/bitcoinpir/payment-v1/bat-v2/public/accounting/pir1-approval.bin", "@SWAP_APPROVAL@")
    .replace("/etc/bitcoinpir/payment-v1/bat-v2/public/accounting/pir2-approval.bin", "/etc/bitcoinpir/payment-v1/bat-v2/public/accounting/pir1-approval.bin")
    .replace("@SWAP_APPROVAL@", "/etc/bitcoinpir/payment-v1/bat-v2/public/accounting/pir2-approval.bin");
  assert.throws(
    () => validateIssuerUnitV1(swappedApprovals, checked),
    /issuer accounting approval argv order does not match/u,
  );
});

test("pir1 argv is storeless and has one complete current accounting group", () => {
  const checked = validateSourceProfileV1(profile());
  assert.throws(
    () => validatePir1UnitV1(
      pir1Source.replace(
        "    --service-policy /etc/bitcoinpir/payment-v1/bat-v2/public/policies/pir1-current.bin \\\n",
        "    --service-store /tmp/provider.sqlite3 \\\n    --service-policy /etc/bitcoinpir/payment-v1/bat-v2/public/policies/pir1-current.bin \\\n",
      ),
      checked,
    ),
    /forbidden ProviderStore/u,
  );
  assert.throws(
    () => validatePir1UnitV1(
      pir1Source.replace(
        /    --service-storeless-bat-v2-issuer-approval .*\\\n/u,
        "",
      ),
      checked,
    ),
    /exactly one --service-storeless-bat-v2-issuer-approval/u,
  );
  assert.throws(
    () => validatePir1UnitV1(
      pir1Source.replace(
        /    --service-storeless-bat-v2-class @BAT_V2_RETAINED_CLASS_DIGEST_HEX@=.*\\\n/u,
        "",
      ),
      checked,
    ),
    /pir1 class argv does not match/u,
  );
});

test("pir2 render input is canonical, bounded, and SHA/token bound", () => {
  const checked = validateSourceProfileV1(profile());
  assert.throws(
    () => validatePir2RenderInputsV1(
      artifactSource.replace("retained_policy=", "unknown_policy="),
      startupSource,
      runSource,
      checked,
    ),
    /entries do not match/u,
  );
  assert.throws(
    () => validatePir2RenderInputsV1(
      artifactSource,
      startupSource.replace("bitcoinpir-pir2-sealed-startup-v2", "bitcoinpir-pir2-sealed-startup-v1"),
      runSource,
      checked,
    ),
    /does not bind the profile/u,
  );
  assert.throws(
    () => validatePir2RenderInputsV1(
      artifactSource,
      startupSource,
      runSource.replaceAll("artifact_set_sha256=", "artifact_set_unbound="),
      checked,
    ),
    /missing artifact_set_sha256=/u,
  );
  assert.throws(
    () => validatePir2RenderInputsV1(
      artifactSource,
      startupSource,
      `${runSource}\n--service-storeless-bat-v2-pir1-clearing-key /tmp/plaintext\n`,
      checked,
    ),
    /plaintext or V1 clearing fallback/u,
  );
  const reusedRuntimePath = profile();
  reusedRuntimePath.issuer.classes[1].pir2RuntimePath =
    reusedRuntimePath.issuer.classes[0].pir2RuntimePath;
  assert.throws(
    () => validateSourceProfileV1(reusedRuntimePath),
    /immutable by exact class digest|duplicate pir2 runtime artifact path/u,
  );
});
