import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const retired = readFileSync(
  new URL("./payment-v1-core-pattern-systemd-integration.sh", import.meta.url),
  "utf8",
);
const gate = readFileSync(
  new URL("./payment-v1-core-pattern-independent-kernel-gate.sh", import.meta.url),
  "utf8",
);
const workflow = readFileSync(
  new URL("../.github/workflows/payment-platform.yml", import.meta.url),
  "utf8",
);

test("shared-kernel privileged PID1 path is retired and absent from automatic CI", () => {
  assert.match(retired, /deliberately\s+disabled/u);
  assert.match(retired, /exit 78/u);
  assert.doesNotMatch(retired, /\bdocker\b|--privileged/u);
  assert.doesNotMatch(workflow, /payment-v1-core-pattern-systemd-integration\.sh/u);
  assert.doesNotMatch(
    workflow,
    /^\s*(?:sudo\s+)?(?:sh\s+)?scripts\/payment-v1-core-pattern-independent-kernel-gate\.sh(?:\s|$)/mu,
  );
  assert.match(workflow, /sh -n scripts\/payment-v1-core-pattern-independent-kernel-gate\.sh/u);
  assert.match(workflow, /payment-v1-core-pattern-independent-kernel-gate\.test\.mjs/u);
});

test("guest gate requires independent VM, boot-bound run ID, marker, and reviewed matrix", () => {
  for (const required of [
    "systemd-detect-virt --container",
    "systemd-detect-virt --vm",
    "bitcoinpir.core_pattern_vm_run_id=$run_id",
    "BITCOINPIR_CORE_PATTERN_VM_ACK",
    "BITCOINPIR_CORE_PATTERN_MATRIX_SHA256",
    "boot_id=%s",
    "matrix_sha256=%s",
    "root:root:400:regular file",
    "root:root:500:regular file",
    "sha256sum",
  ]) assert.ok(gate.includes(required), required);
  assert.doesNotMatch(gate, /\bdocker\b|--privileged|systemctl\s+(?:reboot|poweroff)/u);
});
