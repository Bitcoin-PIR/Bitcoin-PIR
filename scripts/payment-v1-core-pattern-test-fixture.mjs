import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { dirname } from "node:path";

import {
  APPORT_ENABLEMENT_PATH,
  APPORT_ENABLEMENT_TARGET,
  APPORT_COREDUMP_HOOK_DROPIN_PATH,
  APPORT_COREDUMP_HOOK_UNIT_PATH,
  APPORT_GATE_DIRECTORY,
  APPORT_GATE_PATH,
  APPORT_HANDLER_PATH,
  APPORT_MASK_PATH,
  APPORT_MASK_TARGET,
  APPORT_SYSCTLS,
  APPORT_UNIT,
  APPORT_UNIT_PATH,
  CEREMONY_KIND,
  COREDUMP_ADMIN_MASKS,
  EXECUTOR_PATH,
  GUARD_ENABLEMENT_PATH,
  GUARD_UNIT_PATH,
  NOBLE_APPORT_ARCHIVE_SHA256,
  NOBLE_APPORT_COREDUMP_HOOK_DROPIN_BYTES,
  NOBLE_APPORT_COREDUMP_HOOK_UNIT_BYTES,
  NOBLE_APPORT_HANDLER_SOURCE_SHA256,
  NOBLE_APPORT_SOURCE_URL,
  NOBLE_APPORT_UNIT_BYTES,
  NOBLE_SYSTEMD_SYSCTL_BINARY_SHA256,
  NOBLE_SYSTEMD_SYSCTL_UNIT_BYTES,
  PERSISTENT_POLICY_PATH,
  PREFLIGHT_KIND,
  LEASE_KIND,
  PENDING_KIND,
  SYSCTL_GATE_DIRECTORY,
  SYSCTL_GATE_PATH,
  SYSCTL_CREDENTIAL_CLOSURE_PATH,
  SYSTEMD_SYSCTL_BINARY_PATH,
  SYSTEMD_SYSCTL_ENABLEMENT_PATH,
  SYSTEMD_SYSCTL_ENABLEMENT_TARGET,
  SYSTEMD_SYSCTL_UNIT_PATH,
  SYSTEMD_COREDUMP_ABSENT_PATHS,
  SYSTEMD_MANAGER_UNIT_PATHS,
  TARGET_CORE_PATTERN,
  TARGET_SYSCTLS,
  canonicalJson,
  expectedPreimage,
  reviewedCoreDumpManagedLoadPathClosure,
  sha256,
  planSha256,
  guardUnitBytes,
  transactionLayout,
} from "./payment-v1-core-pattern-ceremony.mjs";

export const FIXED_NOW = Date.parse("2026-07-30T08:30:00Z");
export const PLAN_BOOT_ID = "14d184fd-83ce-435d-ab4d-116f00a98dcc";
export const FRESH_BOOT_ID = "982877cd-f12b-4a35-91d4-0d76312a36cb";

function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function pin(path, bytes, mode, owner) {
  const body = Buffer.from(bytes);
  const metadata = owner || { gid: 0, uid: 0 };
  return {
    gid: metadata.gid,
    mode: mode || "0644",
    nlink: 1,
    path,
    sha256: hash(body),
    size: body.length,
    uid: metadata.uid,
  };
}

export function embeddedPin(path, bytes, mode, owner) {
  return {
    ...pin(path, bytes, mode, owner),
    bytes_base64: Buffer.from(bytes).toString("base64"),
  };
}

function executable(path, label) {
  return pin(path, label + "\n", "0555");
}

function fixtureUnitPathAncestors() {
  const roots = new Set(SYSTEMD_MANAGER_UNIT_PATHS);
  const ancestors = new Set();
  for (const root of roots) {
    let current = dirname(root);
    for (;;) {
      if (!roots.has(current)) ancestors.add(current);
      if (current === "/") break;
      current = dirname(current);
    }
  }
  return Array.from(ancestors).sort();
}

export function fixturePlan() {
  const ceremonyId = "hetzner-core-pattern-20260730-v2";
  const policy =
    "kernel.core_pattern=" + TARGET_CORE_PATTERN + "\n" +
    "fs.suid_dumpable=0\n" +
    "kernel.core_pipe_limit=0\n";
  const guard = guardUnitBytes(ceremonyId);
  const unit = embeddedPin(APPORT_UNIT_PATH, NOBLE_APPORT_UNIT_BYTES, "0644");
  return {
    candidate: {
      apport_gate: embeddedPin(
        APPORT_GATE_PATH,
        "[Service]\n" +
          "ExecStop=\n" +
          "ExecCondition=/usr/bin/node " + EXECUTOR_PATH + " early-apport-gate\n" +
          "Environment=LANG=C\n" +
          "Environment=LC_ALL=C\n" +
          "Environment=PATH=/usr/sbin:/usr/bin\n" +
          "Environment=TZ=UTC\n" +
          "UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH\n",
        "0644",
      ),
      apport_gate_directory: {
        gid: 0,
        mode: "0755",
        path: APPORT_GATE_DIRECTORY,
        uid: 0,
      },
      apport_mask: {
        gid: 0,
        path: APPORT_MASK_PATH,
        target: APPORT_MASK_TARGET,
        uid: 0,
      },
      coredump_admin_masks: COREDUMP_ADMIN_MASKS.map(function ({ gid, path, target, uid }) {
        return { gid, path, target, uid };
      }),
      guard_enablement: {
        gid: 0,
        path: GUARD_ENABLEMENT_PATH,
        target: GUARD_UNIT_PATH,
        uid: 0,
      },
      guard_unit: embeddedPin(GUARD_UNIT_PATH, guard, "0644"),
      persistent_policy: embeddedPin(PERSISTENT_POLICY_PATH, policy, "0644"),
      sysctl_credential_closure: embeddedPin(
        SYSCTL_CREDENTIAL_CLOSURE_PATH,
        "[Service]\n" +
          "ImportCredential=\n" +
          "LoadCredential=\n" +
          "LoadCredentialEncrypted=\n" +
          "SetCredential=\n" +
          "SetCredentialEncrypted=\n",
        "0644",
      ),
      sysctl_gate: embeddedPin(
        SYSCTL_GATE_PATH,
        "[Service]\n" +
          "ExecCondition=/usr/bin/node " + EXECUTOR_PATH + " early-sysctl-gate\n" +
          "Environment=LANG=C\n" +
          "Environment=LC_ALL=C\n" +
          "Environment=PATH=/usr/sbin:/usr/bin\n" +
          "Environment=TZ=UTC\n" +
          "UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH\n",
        "0644",
      ),
      sysctl_gate_directory: {
        gid: 0,
        mode: "0755",
        path: SYSCTL_GATE_DIRECTORY,
        uid: 0,
      },
      sysctls: { ...TARGET_SYSCTLS },
    },
    ceremony_id: ceremonyId,
    executor: {
      busctl: executable("/usr/bin/busctl", "busctl"),
      dpkg_query: executable("/usr/bin/dpkg-query", "dpkg-query"),
      exchange_helper: executable(
        "/opt/bitcoinpir/payment-v1-rename-exchange/" + hash("exchange\n") +
          "/payment-v1-rename-exchange",
        "exchange",
      ),
      false_handler: executable("/usr/bin/false", "false"),
      maintenance_lock_helper: executable(
        "/usr/local/libexec/bitcoinpir/payment-v1-core-pattern-lock-exec",
        "lock",
      ),
      node: executable("/usr/bin/node", "node"),
      source: executable(EXECUTOR_PATH, "source"),
      systemctl: executable("/usr/bin/systemctl", "systemctl"),
    },
    host: {
      machine_id_sha256: "9".repeat(64),
      os_release: pin("/usr/lib/os-release", "ubuntu noble\n", "0644"),
      plan_boot_id: PLAN_BOOT_ID,
      systemd_unit_path_generation: {
        ancestors: fixtureUnitPathAncestors().map(function (path, index) {
          return {
            ctime_ns: String(3_000_000 + index),
            device: "2049",
            gid: 0,
            inode: String(20_000 + index),
            mode: "0755",
            mtime_ns: String(4_000_000 + index),
            nlink: 2,
            path,
            state: "present",
            uid: 0,
          };
        }),
        directories: Array.from(SYSTEMD_MANAGER_UNIT_PATHS).sort().map(function (path, index) {
          return {
            ctime_ns: String(1_000_000 + index),
            device: "2049",
            gid: 0,
            inode: String(10_000 + index),
            mode: "0755",
            mtime_ns: String(2_000_000 + index),
            nlink: 2,
            path,
            state: "present",
            uid: 0,
          };
        }),
        unit_path: Array.from(SYSTEMD_MANAGER_UNIT_PATHS),
      },
      systemd_version: "systemd 255 (255.4-1ubuntu8.15)",
    },
    kind: CEREMONY_KIND,
    official_noble_apport: {
      archive_sha256: NOBLE_APPORT_ARCHIVE_SHA256,
      coredump_hook_dropin: embeddedPin(
        APPORT_COREDUMP_HOOK_DROPIN_PATH,
        NOBLE_APPORT_COREDUMP_HOOK_DROPIN_BYTES,
        "0644",
      ),
      coredump_hook_unit: embeddedPin(
        APPORT_COREDUMP_HOOK_UNIT_PATH,
        NOBLE_APPORT_COREDUMP_HOOK_UNIT_BYTES,
        "0644",
      ),
      handler: {
        gid: 0,
        mode: "0755",
        nlink: 1,
        path: APPORT_HANDLER_PATH,
        sha256: NOBLE_APPORT_HANDLER_SOURCE_SHA256,
        size: 44730,
        uid: 0,
      },
      handler_source_sha256: NOBLE_APPORT_HANDLER_SOURCE_SHA256,
      source_url: NOBLE_APPORT_SOURCE_URL,
      unit,
      unit_semantics: {
        exec_start: ["/usr/share/apport/apport --start"],
        exec_stop: ["/usr/share/apport/apport --stop"],
        remain_after_exit: true,
        type: "oneshot",
        wanted_by: ["multi-user.target"],
      },
    },
    preimage: {
      apport_enablement_symlinks: [{
        gid: 0,
        path: APPORT_ENABLEMENT_PATH,
        target: APPORT_ENABLEMENT_TARGET,
        uid: 0,
      }],
      apport_gate_state: "absent",
      apport_mask_state: "absent",
      apport_runtime_observation: {
        active_state: "active",
        load_state: "loaded",
        need_daemon_reload: "no",
        sub_state: "exited",
      },
      apport_service: {
        dropin_paths: [],
        fragment: pin(APPORT_UNIT_PATH, NOBLE_APPORT_UNIT_BYTES, "0644"),
        name: APPORT_UNIT,
      },
      crash_directory: {
        device: "2049",
        gid: 0,
        inode: "455",
        mode: "3777",
        path: "/var/crash",
        uid: 0,
      },
      crash_entries: [],
      coredump_admin_masks: COREDUMP_ADMIN_MASKS.map(function ({ name, path }) {
        return { name, path, state: "absent" };
      }),
      coredump_managed_load_paths: reviewedCoreDumpManagedLoadPathClosure(),
      guard_state: "absent",
      persistent_policy_state: "absent",
      preflight_state: "absent",
      sysctl_credential_closure_state: "absent",
      sysctl_gate_state: "absent",
      sysctl_assignment_files: [{
        assignments: ["kernel.core_pattern=" + APPORT_SYSCTLS["kernel.core_pattern"]],
        file: pin(
          "/usr/lib/sysctl.d/50-apport.conf",
          "kernel.core_pattern=" + APPORT_SYSCTLS["kernel.core_pattern"] + "\n",
          "0644",
        ),
      }],
      sysctls: { ...APPORT_SYSCTLS },
      systemd_coredump_absence: {
        absent_paths: Array.from(SYSTEMD_COREDUMP_ABSENT_PATHS),
        package_state: "absent",
      },
    },
    rollback_policy: "fresh-receipt-bound-approval-with-reboot-lineage-v2",
    schema_version: 2,
    systemd_sysctl: {
      binary: {
        gid: 0,
        mode: "0755",
        nlink: 1,
        path: SYSTEMD_SYSCTL_BINARY_PATH,
        sha256: NOBLE_SYSTEMD_SYSCTL_BINARY_SHA256,
        size: 23104,
        uid: 0,
      },
      enablement: {
        gid: 0,
        path: SYSTEMD_SYSCTL_ENABLEMENT_PATH,
        target: SYSTEMD_SYSCTL_ENABLEMENT_TARGET,
        uid: 0,
      },
      unit: embeddedPin(
        SYSTEMD_SYSCTL_UNIT_PATH,
        NOBLE_SYSTEMD_SYSCTL_UNIT_BYTES,
        "0644",
      ),
    },
    transaction: transactionLayout(ceremonyId),
  };
}

export function contextFor(plan, options) {
  const config = options || {};
  const actionBootId = config.actionBootId || PLAN_BOOT_ID;
  return {
    actionBootId,
    applyApprovalActionBootId: config.applyApprovalActionBootId || actionBootId,
    approvalSha256: config.approvalSha256 || "a".repeat(64),
    approvedAtUtc: config.approvedAtUtc || FIXED_NOW,
    ceremonyId: plan.ceremony_id,
    planSha256: planSha256(plan),
    recoveryApprovedSubjectSha256: config.recoveryApprovedSubjectSha256,
    recoveryApprovalActionBootId: config.recoveryApprovalActionBootId || actionBootId,
    recoveryApprovalSha256: config.recoveryApprovalSha256 || "b".repeat(64),
    recoverySubjectKind: config.recoverySubjectKind || "pending",
    rollbackApprovalActionBootId: config.rollbackApprovalActionBootId || actionBootId,
    sourceSha256: plan.executor.source.sha256,
  };
}

export class FakeOps {
  constructor(plan, serialized, options) {
    this.plan = plan;
    this.options = options || {};
    if (serialized === undefined) {
      this.state = structuredClone(expectedPreimage(plan));
      this.pending = null;
      this.preflight = null;
      this.lease = null;
      this.receipts = {};
      this.locked = false;
    } else {
      this.state = structuredClone(serialized.state);
      this.pending = structuredClone(serialized.pending);
      this.preflight = structuredClone(serialized.preflight ?? null);
      this.lease = structuredClone(serialized.lease ?? null);
      this.receipts = structuredClone(serialized.receipts);
      this.locked = serialized.locked;
    }
    this.calls = [];
    this.releaseFailed = false;
  }

  serialize() {
    return {
      locked: this.locked,
      lease: structuredClone(this.lease),
      pending: structuredClone(this.pending),
      preflight: structuredClone(this.preflight),
      receipts: structuredClone(this.receipts),
      state: structuredClone(this.state),
    };
  }

  before(name) {
    this.calls.push(name);
    if (this.options.failBefore?.includes(name)) throw new Error("forced before " + name);
  }

  after(name) {
    if (typeof this.options.onBoundary === "function") {
      this.options.onBoundary(name, this.serialize());
    }
    if (this.options.failAfter?.includes(name)) throw new Error("forced after " + name);
  }

  async inspect() {
    this.before("inspect");
    const value = structuredClone(this.state);
    this.after("inspect");
    return value;
  }

  async verifyHostAndTools(_plan, actionBootId, freshAllowed) {
    this.before("verify-host-tools");
    if (!freshAllowed) assert.equal(actionBootId, PLAN_BOOT_ID);
    this.after("verify-host-tools");
  }

  async assertRuntime(phase) {
    this.before("assert-runtime:" + phase);
    this.after("assert-runtime:" + phase);
  }

  async reloadManager() {
    this.before("reload-manager");
    this.after("reload-manager");
  }

  async acquireLock(_path, _context, lease) {
    this.before("acquire-lock");
    assert.equal(this.locked, false);
    this.locked = true;
    this.lease = structuredClone(lease);
    this.after("acquire-lock");
    return this.release.bind(this);
  }

  async recoverLock(_path, _context, lease) {
    this.before("recover-lock");
    assert.equal(this.locked, true);
    assert.equal(this.same(this.lease, lease), true);
    this.after("recover-lock");
    return this.release.bind(this);
  }

  async release() {
    this.before("release-lock");
    if (this.options.releaseFailure) {
      this.releaseFailed = true;
      throw new Error("forced release failure");
    }
    this.locked = false;
    this.lease = null;
    this.after("release-lock");
  }

  async finalizeTerminal(_lockPath, _pendingPath, receipt) {
    this.before("finalize-terminal");
    if (!this.locked) {
      assert.equal(this.pending, null);
      assert.equal(this.preflight, null);
      assert.equal(this.same(this.state, receipt.post_state), true);
      this.after("finalize-terminal");
      return;
    }
    if (this.pending !== null) {
      this.before("terminal-clear-pending");
      assert.equal(this.same(this.pending.receipt_candidate, receipt), true);
      this.pending = null;
      this.after("terminal-clear-pending");
    }
    if (this.preflight !== null) {
      this.before("terminal-clear-preflight");
      assert.equal(receipt.preflight_sha256, sha256(Buffer.from(canonicalJson(this.preflight))));
      this.preflight = null;
      this.after("terminal-clear-preflight");
    }
    this.before("terminal-remove-guard");
    this.state.guard = { state: "absent" };
    this.state.apport_gate = {
      directory_path: APPORT_GATE_DIRECTORY,
      file_path: APPORT_GATE_PATH,
      state: "absent",
    };
    this.state.apport_service.dropin_paths = [];
    this.state.sysctl_gate = {
      directory_path: SYSCTL_GATE_DIRECTORY,
      file_path: SYSCTL_GATE_PATH,
      state: "absent",
    };
    this.after("terminal-remove-guard");
    await this.reloadManager();
    await this.assertRuntime(
      receipt.outcome === "committed"
        ? "apply-cleanup-pre-release"
        : "rollback-cleanup-pre-release",
    );
    assert.equal(this.same(await this.inspect(), receipt.post_state), true);
    if (this.locked) await this.release();
    assert.equal(this.same(this.state, receipt.post_state), true);
    this.after("finalize-terminal");
  }

  async createPending(_path, value) {
    this.before("create-pending");
    if (this.pending !== null && !this.same(this.pending, value)) {
      throw new Error("different pending state exists");
    }
    this.pending = structuredClone(value);
    this.after("create-pending");
  }

  async createPreflight(value) {
    this.before("create-preflight");
    if (this.preflight !== null && !this.same(this.preflight, value)) {
      throw new Error("different preflight intent exists");
    }
    this.preflight = structuredClone(value);
    this.after("create-preflight");
  }

  async clearPending(_path, value) {
    this.before("clear-pending");
    assert.equal(this.same(this.pending, value), true);
    this.pending = null;
    this.after("clear-pending");
  }

  async readPending() {
    this.before("read-pending");
    const value = structuredClone(this.pending);
    this.after("read-pending");
    return value;
  }

  async readPreflight() {
    this.before("read-preflight");
    const value = structuredClone(this.preflight);
    this.after("read-preflight");
    return value;
  }

  async readLease() {
    this.before("read-lease");
    const value = structuredClone(this.lease);
    this.after("read-lease");
    return value;
  }

  async readRecoverySubject() {
    this.before("read-recovery-subject");
    const value = this.pending !== null
      ? { kind: "pending", value: structuredClone(this.pending) }
      : this.preflight !== null
        ? { kind: "preflight", value: structuredClone(this.preflight) }
        : this.lease !== null
          ? { kind: "lease", value: structuredClone(this.lease) }
          : null;
    this.after("read-recovery-subject");
    return value;
  }

  async writePending(_path, value) {
    this.before("write-pending");
    assert.notEqual(this.pending, null);
    this.pending = structuredClone(value);
    this.after("write-pending");
  }

  async writePreflight(value) {
    this.before("write-preflight");
    assert.notEqual(this.preflight, null);
    this.preflight = structuredClone(value);
    this.after("write-preflight");
  }

  async readReceipt(path) {
    this.before("read-receipt");
    const value = Object.hasOwn(this.receipts, path)
      ? structuredClone(this.receipts[path])
      : null;
    this.after("read-receipt");
    return value;
  }

  async publishReceipt(path, value) {
    this.before(path.endsWith(".rollback.json") ? "publish-rollback-receipt" : "publish-receipt");
    if (Object.hasOwn(this.receipts, path) && !this.same(this.receipts[path], value)) {
      throw new Error("receipt path already has different bytes");
    }
    this.receipts[path] = structuredClone(value);
    const name = path.endsWith(".rollback.json") ? "publish-rollback-receipt" : "publish-receipt";
    this.after(name);
  }

  async publishReceiptAfterFullInspection(path, value, expected, _label) {
    const name = path.endsWith(".rollback.json")
      ? "publish-rollback-receipt-after-full-inspection"
      : "publish-receipt-after-full-inspection";
    this.before(name);
    assert.equal(this.same(this.state, expected), true);
    if (Object.hasOwn(this.receipts, path) && !this.same(this.receipts[path], value)) {
      throw new Error("receipt path already has different bytes");
    }
    this.receipts[path] = structuredClone(value);
    this.after(name);
  }

  async ensureGuard(unit, enablement) {
    this.before("ensure-guard");
    this.state.guard = {
      enablement: structuredClone(enablement),
      state: "present",
      unit: structuredClone(unit),
    };
    this.state.apport_gate = {
      directory: structuredClone(this.plan.candidate.apport_gate_directory),
      file: structuredClone(this.plan.candidate.apport_gate),
      state: "present",
    };
    this.state.apport_service.dropin_paths = [APPORT_GATE_PATH];
    this.state.sysctl_gate = {
      directory: structuredClone(this.plan.candidate.sysctl_gate_directory),
      file: structuredClone(this.plan.candidate.sysctl_gate),
      state: "present",
    };
    this.after("ensure-guard");
  }

  async removeGuard() {
    this.before("remove-guard");
    this.state.guard = { state: "absent" };
    this.state.apport_gate = {
      directory_path: APPORT_GATE_DIRECTORY,
      file_path: APPORT_GATE_PATH,
      state: "absent",
    };
    this.state.apport_service.dropin_paths = [];
    this.state.sysctl_gate = {
      directory_path: SYSCTL_GATE_DIRECTORY,
      file_path: SYSCTL_GATE_PATH,
      state: "absent",
    };
    this.after("remove-guard");
  }

  async installPersistent(pinValue) {
    this.before("install-persistent");
    this.state.persistent_policy = { file: structuredClone(pinValue), state: "present" };
    this.state.sysctl_credential_closure = {
      directory: structuredClone(this.plan.candidate.sysctl_gate_directory),
      file: structuredClone(this.plan.candidate.sysctl_credential_closure),
      state: "present",
    };
    const assignments = this.state.sysctl_assignment_files.filter(function (entry) {
      return entry.file.path !== pinValue.path;
    });
    const bytes = Buffer.from(pinValue.bytes_base64, "base64").toString("utf8");
    assignments.push({
      assignments: bytes.trimEnd().split("\n"),
      file: this.withoutBytes(pinValue),
    });
    this.state.sysctl_assignment_files = assignments.sort(function (a, b) {
      return a.file.path.localeCompare(b.file.path);
    });
    this.after("install-persistent");
  }

  async removePersistent() {
    this.before("remove-persistent");
    if (this.options.concurrentPersistentMutation) {
      this.options.concurrentPersistentMutationRestored = true;
      throw new Error("concurrent root mutation exchanged and restored");
    }
    this.state.persistent_policy = { path: PERSISTENT_POLICY_PATH, state: "absent" };
    this.state.sysctl_credential_closure = {
      directory_path: SYSCTL_GATE_DIRECTORY,
      file_path: SYSCTL_CREDENTIAL_CLOSURE_PATH,
      state: "absent",
    };
    this.state.sysctl_assignment_files = this.state.sysctl_assignment_files.filter(function (entry) {
      return entry.file.path !== PERSISTENT_POLICY_PATH;
    });
    this.after("remove-persistent");
  }

  async writeSysctl(name, value) {
    const call = "write:" + name + "=" + value;
    this.before(call);
    if (name === "kernel.core_pattern" && value === "core") {
      throw new Error("native core is forbidden");
    }
    this.state.sysctls[name] = value;
    this.after(call);
  }

  async assertSysctls(expected) {
    this.before("readback-sysctls");
    for (const key of Object.keys(expected)) assert.equal(this.state.sysctls[key], expected[key]);
    this.after("readback-sysctls");
  }

  async removeApportEnablement() {
    this.before("remove-apport-enablement");
    this.state.apport_enablement_symlinks = [];
    this.after("remove-apport-enablement");
  }

  async ensureApportMask(link) {
    this.before("ensure-apport-mask");
    this.state.apport_mask = { link: structuredClone(link), state: "present" };
    this.after("ensure-apport-mask");
  }

  async ensureCoreDumpMasks(links) {
    this.before("ensure-coredump-admin-masks");
    this.state.coredump_admin_masks = COREDUMP_ADMIN_MASKS.map(function (reviewed, index) {
      return {
        link: structuredClone(links[index]),
        name: reviewed.name,
        state: "present",
      };
    });
    this.after("ensure-coredump-admin-masks");
  }

  async removeApportMask() {
    this.before("remove-apport-mask");
    this.state.apport_mask = { path: APPORT_MASK_PATH, state: "absent" };
    this.after("remove-apport-mask");
  }

  async removeCoreDumpMasks() {
    this.before("reprove-coredump-absence-closure:pre-unmask");
    assert.deepEqual(
      this.state.coredump_vendor_closure,
      expectedPreimage(this.plan).coredump_vendor_closure,
    );
    assert.equal(
      this.state.coredump_admin_masks.every(function (entry) {
        return entry.state === "present";
      }),
      true,
    );
    this.after("reprove-coredump-absence-closure:pre-unmask");
    this.before("remove-coredump-admin-masks");
    this.state.coredump_admin_masks = COREDUMP_ADMIN_MASKS.map(function ({ name, path }) {
      return { name, path, state: "absent" };
    });
    this.after("remove-coredump-admin-masks");
  }

  async reproveCoreDumpRollbackRemovalClosure() {
    this.before("reprove-coredump-absence-closure:pre-restore");
    assert.deepEqual(
      this.state.coredump_vendor_closure,
      expectedPreimage(this.plan).coredump_vendor_closure,
    );
    assert.equal(
      this.state.coredump_admin_masks.every(function (entry) {
        return entry.state === "present";
      }),
      true,
    );
    this.after("reprove-coredump-absence-closure:pre-restore");
  }

  simulateReboot() {
    const candidateMask = this.state.apport_mask.state === "present";
    if (this.preflight !== null || candidateMask) {
      this.state.sysctls = structuredClone(TARGET_SYSCTLS);
      return;
    }
    this.state.sysctls = structuredClone(APPORT_SYSCTLS);
  }

  async ensureApportEnablement(link) {
    this.before("ensure-apport-enablement");
    this.state.apport_enablement_symlinks = [structuredClone(link)];
    this.after("ensure-apport-enablement");
  }

  same(left, right) {
    return canonicalJson(left) === canonicalJson(right);
  }

  withoutBytes(pinValue) {
    const value = { ...pinValue };
    delete value.bytes_base64;
    return value;
  }
}

export function serializedDigest(value) {
  return sha256(Buffer.from(canonicalJson(value), "utf8"));
}

export function pendingFor(plan, mode, originalApprovalSha, actionBootId) {
  const preflight = preflightFor(plan, mode, originalApprovalSha, actionBootId);
  return {
    action_boot_id: actionBootId || PLAN_BOOT_ID,
    apply_boot_id: PLAN_BOOT_ID,
    ceremony_id: plan.ceremony_id,
    generation: 0,
    kind: PENDING_KIND,
    mode,
    original_approval_sha256: originalApprovalSha || "a".repeat(64),
    plan_sha256: planSha256(plan),
    preflight_sha256: serializedDigest(preflight),
    previous_generation_sha256: null,
    receipt_candidate: null,
    recovery_approval_sha256s: [],
    schema_version: 2,
    source_sha256: plan.executor.source.sha256,
    started_at_utc: "2026-07-30T08:30:00Z",
  };
}

export function leaseFor(plan, mode, originalApprovalSha, actionBootId) {
  return {
    action_boot_id: actionBootId || PLAN_BOOT_ID,
    ceremony_id: plan.ceremony_id,
    kind: LEASE_KIND,
    mode,
    original_approval_sha256: originalApprovalSha || "a".repeat(64),
    plan_sha256: planSha256(plan),
    schema_version: 2,
    source_sha256: plan.executor.source.sha256,
    started_at_utc: "2026-07-30T08:30:00Z",
  };
}

export function preflightFor(plan, mode, originalApprovalSha, actionBootId) {
  const lease = leaseFor(plan, mode, originalApprovalSha, actionBootId);
  return {
    action_boot_id: lease.action_boot_id,
    apply_boot_id: PLAN_BOOT_ID,
    ceremony_id: plan.ceremony_id,
    generation: 0,
    kind: PREFLIGHT_KIND,
    mode,
    original_approval_sha256: lease.original_approval_sha256,
    plan_sha256: planSha256(plan),
    previous_generation_sha256: null,
    recovery_approval_sha256s: [],
    schema_version: 2,
    source_sha256: plan.executor.source.sha256,
    started_at_utc: lease.started_at_utc,
  };
}
