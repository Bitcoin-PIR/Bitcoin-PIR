import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  MANAGED_BLOCK_SOURCE,
  OVERLAY_COLLECTOR,
  buildOverlayCandidate,
  computeApprovedOverlayPlanSha256,
  validateOverlayPlan,
  validateOverlayReceipt,
} from "./payment-v1-integrated-caddy-overlay-gate.mjs";

const REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE = readFileSync(join(REPOSITORY, MANAGED_BLOCK_SOURCE));
const GATE_SOURCE = readFileSync(
  join(REPOSITORY, "scripts/payment-v1-integrated-caddy-overlay-gate.mjs"),
);
const EXECUTOR_SOURCE = readFileSync(
  join(REPOSITORY, "scripts/payment-v1-integrated-caddy-overlay-transaction.mjs"),
);
const PREIMAGE = Buffer.from(
  "existing.example.net {\n\treverse_proxy 127.0.0.1:18080\n}\n",
);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function clone(value) {
  return structuredClone(value);
}

function render(text, placeholders) {
  let output = text;
  for (const [name, value] of Object.entries(placeholders)) {
    output = output.split(`@${name}@`).join(value);
  }
  return output;
}

function pin(path, digest, mode, { gid = 0, uid = 0, size = "64" } = {}) {
  return {
    ctime_ns: "1700000000000000000",
    device: "2049",
    gid,
    inode: "42001",
    mode,
    mtime_ns: "1700000000000000000",
    nlink: 1,
    path,
    sha256: digest,
    size,
    uid,
  };
}

function generation(unitName, { canReload, pid }) {
  return {
    active_enter_timestamp_monotonic: "2000000",
    active_state: "active",
    can_reload: canReload,
    control_group: `/system.slice/${unitName}`,
    invocation_id: "12345678-1234-4234-9234-123456789abc",
    main_pid: pid,
    sub_state: "running",
    unit_name: unitName,
  };
}

function makePlan() {
  const placeholders = {
    DIRECTORY_PUBLISHER_CLIENT_IP: "10.23.0.6",
    DIRECTORY_PUBLISHER_HTTPS_HOST: "publisher.example.net",
    DIRECTORY_PUBLISHER_PRIVATE_BIND: "10.23.0.5",
    DIRECTORY_RELAY_WSS_HOST: "directory.example.net",
    PAYMENT_ISSUER_HTTPS_HOST: "pay.example.net",
    PROVIDER_WSS_HOST: "pir.example.net",
    PUBLIC_HTTPS_BIND: "198.51.100.23",
  };
  const rendered = Buffer.from(render(SOURCE.toString("utf8"), placeholders));
  const candidate = Buffer.concat([PREIMAGE, Buffer.from("\n"), rendered]);
  const haproxySha = sha256("reviewed-haproxy");
  const exchangeSha = sha256("reviewed-rename-exchange");
  const exchangePath =
    `/opt/bitcoinpir/payment-v1-rename-exchange/${exchangeSha}/payment-v1-rename-exchange`;
  const exchangeManifest = Buffer.from(`${exchangeSha}  ${exchangePath}\n`);
  const preimageSha = sha256(PREIMAGE);
  const transactionId = "integrated-caddy-test-1";
  const plan = {
    deployment_profile: "integrated-existing-bhtm-caddy-v1",
    health_checks: [
      {
        connect_ip: placeholders.PUBLIC_HTTPS_BIND,
        expected_body_sha256: null,
        expected_status: 101,
        host: placeholders.DIRECTORY_RELAY_WSS_HOST,
        kind: "websocket-upgrade",
        lane: "directory-public",
        leaf_certificate_sha256: "a".repeat(64),
        max_response_bytes: 16384,
        path: "/v1/directory",
        timeout_ms: 5000,
      },
      {
        connect_ip: placeholders.DIRECTORY_PUBLISHER_PRIVATE_BIND,
        expected_body_sha256: null,
        expected_status: 101,
        host: placeholders.DIRECTORY_PUBLISHER_HTTPS_HOST,
        kind: "websocket-upgrade",
        lane: "directory-publisher",
        leaf_certificate_sha256: "b".repeat(64),
        max_response_bytes: 16384,
        path: "/v1/directory",
        timeout_ms: 5000,
      },
      {
        connect_ip: placeholders.PUBLIC_HTTPS_BIND,
        expected_body_sha256: "c".repeat(64),
        expected_status: 200,
        host: placeholders.PAYMENT_ISSUER_HTTPS_HOST,
        kind: "https-response",
        lane: "issuer",
        leaf_certificate_sha256: "d".repeat(64),
        max_response_bytes: 65536,
        path: "/v1/quote-keys/current",
        timeout_ms: 5000,
      },
      {
        connect_ip: placeholders.PUBLIC_HTTPS_BIND,
        expected_body_sha256: null,
        expected_status: 101,
        host: placeholders.PROVIDER_WSS_HOST,
        kind: "websocket-upgrade",
        lane: "provider",
        leaf_certificate_sha256: "e".repeat(64),
        max_response_bytes: 16384,
        path: "/v1/pir",
        timeout_ms: 5000,
      },
    ],
    managed_block: {
      candidate_sha256: sha256(candidate),
      placeholders,
      rendered_sha256: sha256(rendered),
      source_path: MANAGED_BLOCK_SOURCE,
      source_sha256: sha256(SOURCE),
    },
    runtime: {
      exchange_helper: pin(exchangePath, exchangeSha, "0555"),
      exchange_manifest: pin(
        "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/rename-exchange.sha256",
        sha256(exchangeManifest),
        "0444",
        { size: String(exchangeManifest.length) },
      ),
      executor: pin(
        "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-transaction.mjs",
        sha256(EXECUTOR_SOURCE),
        "0555",
      ),
      gate: pin(
        "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs",
        sha256(GATE_SOURCE),
        "0555",
      ),
      managed_block: pin(
        "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/managed.Caddyfile",
        sha256(rendered),
        "0444",
        { size: String(rendered.length) },
      ),
      node_binary: pin("/usr/bin/node", "f".repeat(64), "0755"),
    },
    schema_version: 1,
    source_fair: {
      deployment_manifest_sha256: "1".repeat(64),
      deployment_profile: "integrated-existing-bhtm-caddy-v1",
      haproxy_binary: pin(
        `/opt/bitcoinpir/haproxy/${haproxySha}/haproxy`,
        haproxySha,
        "0555",
      ),
      haproxy_config: pin(
        "/etc/bitcoinpir/payment-v1/source-fair-edge/haproxy.cfg",
        "2".repeat(64),
        "0440",
        { gid: 732 },
      ),
      runtime_evidence_sha256: "3".repeat(64),
      runtime_paths: [
        {
          file_type: "directory",
          gid: 732,
          mode: "0750",
          path: "/run/bitcoinpir-source-fair-edge",
          uid: 731,
        },
        ...[
          "directory-public.sock",
          "directory-publisher.sock",
          "issuer.sock",
          "provider.sock",
        ].map((name) => ({
          file_type: "socket",
          gid: 732,
          mode: "0660",
          path: `/run/bitcoinpir-source-fair-edge/${name}`,
          uid: 731,
        })),
      ],
      unit_fragment: pin(
        "/etc/systemd/system/bitcoinpir-payment-v1-source-fair-edge.service",
        "4".repeat(64),
        "0644",
      ),
      unit_generation: generation(
        "bitcoinpir-payment-v1-source-fair-edge.service",
        { canReload: "no", pid: "4242" },
      ),
    },
    target: {
      binary: pin("/usr/bin/caddy", "5".repeat(64), "0755"),
      config_parent: {
        device: "2049",
        gid: 0,
        inode: "43001",
        mode: "0755",
        path: "/etc/caddy",
        uid: 0,
      },
      config_preimage: pin(
        "/etc/caddy/Caddyfile",
        preimageSha,
        "0644",
        { size: String(PREIMAGE.length) },
      ),
      unit_fragment: pin(
        "/etc/systemd/system/bhtm-caddy.service",
        "6".repeat(64),
        "0644",
      ),
      unit_generation: generation("bhtm-caddy.service", {
        canReload: "yes",
        pid: "4343",
      }),
    },
    tls_dependencies: [
      {
        class: "certificate",
        parent: {
          device: "2049",
          gid: 0,
          inode: "44001",
          mode: "0700",
          path: "/etc/bitcoinpir/payment-v1/edge",
          uid: 0,
        },
        pin: pin(
          "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.crt",
          "7".repeat(64),
          "0444",
        ),
      },
      {
        class: "private-key",
        parent: {
          device: "2049",
          gid: 0,
          inode: "44001",
          mode: "0700",
          path: "/etc/bitcoinpir/payment-v1/edge",
          uid: 0,
        },
        pin: pin(
          "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.key",
          "8".repeat(64),
          "0400",
        ),
      },
    ],
    transaction: {
      adapt_argv: [
        "/usr/bin/caddy",
        "adapt",
        "--config",
        `/etc/caddy/.bitcoinpir-${transactionId}.candidate`,
        "--adapter",
        "caddyfile",
      ],
      adapted_json_path:
        `/var/lib/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/adapted/${transactionId}.json`,
      backup_mode: "exclusive-create-fsync-file-and-parent",
      backup_path:
        `/var/lib/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/backups/${transactionId}-${preimageSha}.Caddyfile`,
      candidate_path: `/etc/caddy/.bitcoinpir-${transactionId}.candidate`,
      installation_mode:
        "same-directory-renameat2-exchange-verify-swapped-preimage-and-live-candidate-parent-fsync",
      lock_path:
        "/run/lock/bitcoinpir-payment-v1-integrated-bhtm-caddy.lock",
      reload_argv: ["/usr/bin/systemctl", "reload", "bhtm-caddy.service"],
      receipt_path:
        `/var/lib/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/receipts/${transactionId}.json`,
      receipt_pending_path:
        `/var/lib/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/receipts/${transactionId}.json.pending`,
      require_same_active_enter_timestamp_monotonic: true,
      require_same_invocation_id: true,
      require_same_main_pid: true,
      restart_forbidden: true,
      rollback_mode:
        "same-directory-renameat2-exchange-verify-swapped-candidate-and-restored-preimage-parent-fsync-then-reload",
      rollback_on_any_post_install_failure: true,
      state_directory:
        `/var/lib/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/transactions/${transactionId}`,
      validate_argv: [
        "/usr/bin/caddy",
        "validate",
        "--config",
        `/etc/caddy/.bitcoinpir-${transactionId}.candidate`,
        "--adapter",
        "caddyfile",
      ],
    },
    transaction_id: transactionId,
    trust_acknowledgements: {
      append_only_cannot_disable_global_admin: true,
      append_only_cannot_disable_global_logging: true,
      append_only_cannot_disable_global_zero_rtt: true,
      existing_preimage_remains_authoritative: true,
      existing_root_caddy_retains_admin_acme_and_journal_trust: true,
      existing_root_caddy_expands_failure_domain: true,
      reload_does_not_refresh_cold_runtime_evidence: true,
    },
  };
  return plan;
}

function afterConfig(plan, digest) {
  return {
    ...clone(plan.target.config_preimage),
    ctime_ns: "1700000001000000000",
    inode: "42002",
    mtime_ns: "1700000001000000000",
    sha256: digest,
    size: "12345",
  };
}

function makeReceipt(plan, outcome = "committed") {
  const committed = outcome === "committed";
  const receipt = {
    after: {
      binary: clone(plan.target.binary),
      config: afterConfig(
        plan,
        committed
          ? plan.managed_block.candidate_sha256
          : plan.target.config_preimage.sha256,
      ),
      source_fair_generation: clone(plan.source_fair.unit_generation),
      target_generation: clone(plan.target.unit_generation),
      unit_fragment: clone(plan.target.unit_fragment),
    },
    approved_plan_sha256: computeApprovedOverlayPlanSha256(plan),
    backup: {
      directory_fsync: true,
      exclusive_create: true,
      file_fsync: true,
      gid: 0,
      mode: "0400",
      nlink: 1,
      path: plan.transaction.backup_path,
      sha256: plan.target.config_preimage.sha256,
      uid: 0,
    },
    before: {
      binary: clone(plan.target.binary),
      config: clone(plan.target.config_preimage),
      source_fair_generation: clone(plan.source_fair.unit_generation),
      target_generation: clone(plan.target.unit_generation),
      unit_fragment: clone(plan.target.unit_fragment),
    },
    collector: OVERLAY_COLLECTOR,
    health_results: committed
      ? plan.health_checks.map((check) => ({
          body_sha256: check.expected_body_sha256,
          check: clone(check),
          leaf_certificate_sha256: check.leaf_certificate_sha256,
          status: check.expected_status,
          success: true,
        }))
      : [],
    host: {
      boot_id: "22345678-1234-4234-9234-123456789abc",
      machine_id_sha256: "9".repeat(64),
    },
    installation: {
      candidate_path: plan.transaction.candidate_path,
      config_parent_fsync: true,
      exchange_helper_sha256: plan.runtime.exchange_helper.sha256,
      exchanged: true,
      live_candidate_verified: true,
      same_filesystem: true,
      swapped_out_preimage_verified: true,
    },
    outcome,
    preparation: {
      adapt_argv: clone(plan.transaction.adapt_argv),
      adapt_exit_status: 0,
      adapted_json_sha256: "a".repeat(64),
      candidate_sha256: plan.managed_block.candidate_sha256,
      managed_block_sha256: plan.managed_block.rendered_sha256,
      preimage_sha256: plan.target.config_preimage.sha256,
      validate_argv: clone(plan.transaction.validate_argv),
      validate_exit_status: 0,
    },
    reload: {
      argv: clone(plan.transaction.reload_argv),
      exit_status: committed ? 0 : 1,
      restart_invoked: false,
    },
    rollback: committed
      ? {
          attempted: false,
          directory_fsync: false,
          exact_candidate_swapped_out: false,
          exact_preimage_restored: false,
          exchanged: false,
          reload_exit_status: null,
        }
      : {
          attempted: true,
          directory_fsync: true,
          exact_candidate_swapped_out: true,
          exact_preimage_restored: true,
          exchanged: true,
          reload_exit_status: 0,
        },
    schema_version: 1,
    transaction_id: plan.transaction_id,
  };
  return receipt;
}

test("integrated overlay plan and exact candidate pass", () => {
  const plan = makePlan();
  assert.equal(validateOverlayPlan(plan), true);
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  const model = buildOverlayCandidate({
    approvedPlanSha256,
    plan,
    preimageBytes: PREIMAGE,
    sourceBytes: SOURCE,
  });
  assert.equal(model.preimageSha256, plan.target.config_preimage.sha256);
  assert.equal(model.blockSha256, plan.managed_block.rendered_sha256);
  assert.equal(model.candidateSha256, plan.managed_block.candidate_sha256);
});

test("committed and exact rolled-back receipts pass", () => {
  const plan = makePlan();
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  assert.equal(
    validateOverlayReceipt({
      approvedPlanSha256,
      plan,
      receipt: makeReceipt(plan),
    }),
    true,
  );
  assert.equal(
    validateOverlayReceipt({
      approvedPlanSha256,
      plan,
      receipt: makeReceipt(plan, "rolled-back"),
    }),
    true,
  );
});

for (const [label, mutate, expected] of [
  [
    "different Caddy unit",
    (plan) => { plan.target.unit_generation.unit_name = "caddy.service"; },
    /unit_name must equal bhtm-caddy.service/,
  ],
  [
    "Caddy cannot reload",
    (plan) => { plan.target.unit_generation.can_reload = "no"; },
    /can_reload must equal yes/,
  ],
  [
    "HAProxy manifest profile drift",
    (plan) => { plan.source_fair.deployment_profile = "edge-hetzner-v1"; },
    /source_fair.deployment_profile/,
  ],
  [
    "missing source-fair socket",
    (plan) => { plan.source_fair.runtime_paths.pop(); },
    /one directory and four sockets/,
  ],
  [
    "public publisher ingress",
    (plan) => { plan.managed_block.placeholders.DIRECTORY_PUBLISHER_PRIVATE_BIND = "198.51.100.24"; },
    /RFC1918|ULA/,
  ],
  [
    "hostname reuse",
    (plan) => { plan.managed_block.placeholders.PROVIDER_WSS_HOST = plan.managed_block.placeholders.PAYMENT_ISSUER_HTTPS_HOST; },
    /four distinct hostnames/,
  ],
  [
    "restart command",
    (plan) => { plan.transaction.reload_argv[1] = "restart"; },
    /reload_argv/,
  ],
  [
    "weak backup mode",
    (plan) => { plan.transaction.backup_mode = "copy"; },
    /backup_mode/,
  ],
  [
    "trust-domain denial",
    (plan) => { plan.trust_acknowledgements.existing_root_caddy_expands_failure_domain = false; },
    /expands_failure_domain/,
  ],
  [
    "shared existing-Caddy trust denial",
    (plan) => { plan.trust_acknowledgements.existing_root_caddy_retains_admin_acme_and_journal_trust = false; },
    /retains_admin_acme_and_journal_trust/,
  ],
]) {
  test(`overlay plan rejects ${label}`, () => {
    const plan = makePlan();
    mutate(plan);
    assert.throws(() => validateOverlayPlan(plan), expected);
  });
}

test("candidate rejects changed preimage, duplicate marker and changed source", () => {
  const plan = makePlan();
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  assert.throws(
    () => buildOverlayCandidate({
      approvedPlanSha256,
      plan,
      preimageBytes: Buffer.from("changed\n"),
      sourceBytes: SOURCE,
    }),
    /preimage SHA-256/,
  );
  const marked = Buffer.from(`${PREIMAGE}${"# BEGIN BITCOINPIR PAYMENT V1 MANAGED BLOCK integrated-existing-bhtm-caddy-v1"}\n`);
  const markedPlan = makePlan();
  markedPlan.target.config_preimage.sha256 = sha256(marked);
  markedPlan.target.config_preimage.size = String(marked.length);
  markedPlan.transaction.backup_path =
    `/var/lib/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/backups/${markedPlan.transaction_id}-${sha256(marked)}.Caddyfile`;
  markedPlan.managed_block.candidate_sha256 = sha256(
    Buffer.concat([
      marked,
      Buffer.from("\n"),
      Buffer.from(render(SOURCE.toString("utf8"), markedPlan.managed_block.placeholders)),
    ]),
  );
  assert.throws(
    () => buildOverlayCandidate({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(markedPlan),
      plan: markedPlan,
      preimageBytes: marked,
      sourceBytes: SOURCE,
    }),
    /already contains the managed overlay marker/,
  );
  const changedSource = Buffer.from(SOURCE.toString("utf8").replace("proxy_protocol v2", ""));
  assert.throws(
    () => buildOverlayCandidate({
      approvedPlanSha256,
      plan,
      preimageBytes: PREIMAGE,
      sourceBytes: changedSource,
    }),
    /source SHA-256/,
  );
});

for (const [label, mutate, expected] of [
  [
    "restart invocation",
    (receipt) => { receipt.reload.restart_invoked = true; },
    /no restart/,
  ],
  [
    "PID change",
    (receipt) => { receipt.after.target_generation.main_pid = "9999"; },
    /target_generation drifted/,
  ],
  [
    "missing backup fsync",
    (receipt) => { receipt.backup.file_fsync = false; },
    /durable exclusive exact-preimage copy/,
  ],
  [
    "missing config-parent fsync",
    (receipt) => { receipt.installation.config_parent_fsync = false; },
    /durable same-directory exchange/,
  ],
  [
    "failed health check",
    (receipt) => { receipt.health_results[0].success = false; },
    /failed or drifted/,
  ],
]) {
  test(`committed receipt rejects ${label}`, () => {
    const plan = makePlan();
    const receipt = makeReceipt(plan);
    mutate(receipt);
    assert.throws(
      () => validateOverlayReceipt({
        approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
        plan,
        receipt,
      }),
      expected,
    );
  });
}

test("rolled-back receipt must prove exact durable restore and second reload", () => {
  const plan = makePlan();
  const receipt = makeReceipt(plan, "rolled-back");
  receipt.rollback.directory_fsync = false;
  assert.throws(
    () => validateOverlayReceipt({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      plan,
      receipt,
    }),
    /exact durable preimage restoration/,
  );
});
