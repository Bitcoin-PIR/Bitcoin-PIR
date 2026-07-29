import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  MANAGED_BLOCK_SOURCE,
  canonicalJson,
} from "./payment-v1-integrated-caddy-overlay-gate.mjs";
import {
  ADMIN_DIAL,
  ADMIN_DIRECTORY,
  ADMIN_LISTEN,
  ADMIN_PROBE_PATH,
  ADMIN_SOCKET,
  CADDY_AMD64_BINARY,
  CADDY_AMD64_MANIFEST,
  CADDY_IMAGE_INDEX,
  COLLECTOR,
  NODE_AMD64_MANIFEST,
  NODE_IMAGE_INDEX,
  PROFILE,
  SETPRIV_PATH,
  buildHardenedCaddyfile,
  buildHardenedUnit,
  canonicalJson as canonicalAdminUdsJson,
  computeApprovedPlanSha256,
} from "./payment-v1-caddy-admin-uds-gate.mjs";

export const TEST_REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const TEST_SOURCE = readFileSync(join(TEST_REPOSITORY, MANAGED_BLOCK_SOURCE));
const HARDENING_CONFIG_PREIMAGE = Buffer.from(
  "{\n\tadmin 127.0.0.1:2019\n}\n\nexisting.example.net {\n\treverse_proxy 127.0.0.1:18080\n}\n",
);
export const TEST_PREIMAGE = Buffer.from(
  `{\n\tadmin ${ADMIN_LISTEN}\n}\n\nexisting.example.net {\n\treverse_proxy 127.0.0.1:18080\n}\n`,
);
const HARDENING_UNIT_PREIMAGE = Buffer.from(`[Unit]
Description=Existing bhtm Caddy

[Service]
Type=notify
User=root
Group=root
Environment=CADDY_ADMIN=127.0.0.1:2019
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile --adapter caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force

[Install]
WantedBy=multi-user.target
`);
export const TEST_ADAPTED_JSON = {
  admin: { listen: ADMIN_LISTEN },
  apps: {},
};
const TEST_HARDENING_EVIDENCE = new WeakMap();

export function testSha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function render(text, placeholders) {
  let output = text;
  for (const [name, value] of Object.entries(placeholders)) {
    output = output.split(`@${name}@`).join(value);
  }
  return output;
}

export function testPin(path, digest, mode, { gid = 0, uid = 0, size = "64", inode = "42001" } = {}) {
  return {
    ctime_ns: "1700000000000000000",
    device: "2049",
    gid,
    inode,
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

export function testCaddyEffectiveUnit(plan) {
  const binary = plan.target.binary.path;
  return {
    dropin_paths: [],
    environment_names: [],
    environment_files: [],
    exec_reload: {
      argv: `${binary} reload --config /etc/caddy/Caddyfile --adapter caddyfile --address ${ADMIN_DIAL}`,
      ignore_errors: "no",
      path: binary,
    },
    exec_start: {
      argv: `${binary} run --config /etc/caddy/Caddyfile --adapter caddyfile`,
      ignore_errors: "no",
      path: binary,
    },
    fragment_path: plan.target.unit_fragment.path,
    group: "root",
    need_daemon_reload: "no",
    pass_environment: [],
    runtime_directory: ["bitcoinpir-caddy-admin"],
    runtime_directory_mode: "0700",
    runtime_directory_preserve: "no",
    umask: "0077",
    unset_environment: ["CADDY_ADMIN"],
    user: "root",
  };
}

export function testCaddyProcessRuntime(plan) {
  return {
    caddy_admin_environment_absent: true,
    cmdline_argv: [
      plan.target.binary.path,
      "run",
      "--config",
      "/etc/caddy/Caddyfile",
      "--adapter",
      "caddyfile",
    ],
    effective_environment_names: ["HOME", "PATH"],
    main_pid: plan.target.unit_generation.main_pid,
    start_time_ticks: "987654",
  };
}

function contentPin(path, bytes, mode) {
  return { gid: 0, mode, path, sha256: testSha256(bytes), size: String(bytes.length), uid: 0 };
}

function hardeningGeneration({ activeEnter, invocation, mainPid }) {
  return {
    active_enter_timestamp_monotonic: activeEnter,
    active_state: "active",
    control_group: "/system.slice/bhtm-caddy.service",
    invocation_id: invocation,
    main_pid: mainPid,
    sub_state: "running",
    unit_name: "bhtm-caddy.service",
  };
}

function stoppedHardeningGeneration() {
  return {
    active_enter_timestamp_monotonic: "0",
    active_state: "inactive",
    control_group: "/system.slice/bhtm-caddy.service",
    invocation_id: "",
    main_pid: "0",
    sub_state: "dead",
    unit_name: "bhtm-caddy.service",
  };
}

function makeHardeningEvidence(targetGeneration) {
  const candidateConfig = buildHardenedCaddyfile(
    HARDENING_CONFIG_PREIMAGE,
    "replace-explicit-tcp-admin",
  );
  if (!candidateConfig.equals(TEST_PREIMAGE)) throw new Error("hardening fixture candidate drifted");
  const candidateUnit = buildHardenedUnit(HARDENING_UNIT_PREIMAGE);
  const binaryPreimage = testPin("/usr/bin/caddy", "5".repeat(64), "0755", {
    size: "48521378",
    inode: "52001",
  });
  const configPreimage = testPin(
    "/etc/caddy/Caddyfile",
    testSha256(HARDENING_CONFIG_PREIMAGE),
    "0644",
    { size: String(HARDENING_CONFIG_PREIMAGE.length), inode: "52002" },
  );
  const unitPreimage = testPin(
    "/etc/systemd/system/bhtm-caddy.service",
    testSha256(HARDENING_UNIT_PREIMAGE),
    "0644",
    { size: String(HARDENING_UNIT_PREIMAGE.length), inode: "52003" },
  );
  const serviceUidInventory = [
    { name: "cloudflared", uid: 62901 },
    { name: "pir", uid: 62902 },
  ];
  const probeBytes = Buffer.from("reviewed Caddy admin probe fixture\n");
  const plan = {
    candidate: {
      binary: {
        gid: 0,
        mode: "0755",
        path: "/usr/bin/caddy",
        sha256: binaryPreimage.sha256,
        size: binaryPreimage.size,
        uid: 0,
      },
      config: contentPin("/etc/caddy/Caddyfile", candidateConfig, "0644"),
      unit: contentPin("/etc/systemd/system/bhtm-caddy.service", candidateUnit, "0644"),
      unit_policy: {
        admin_dial: ADMIN_DIAL,
        admin_listen: ADMIN_LISTEN,
        caddy_admin_environment_absent: true,
        dropins: [],
        runtime_directory: ADMIN_DIRECTORY,
        runtime_directory_mode: "0700",
        runtime_directory_preserve: "no",
        service_gid: 0,
        service_uid: 0,
        umask: "0077",
      },
    },
    config_edit_mode: "replace-explicit-tcp-admin",
    deployment_profile: PROFILE,
    preimage: {
      admin: { kind: "tcp", listen: "127.0.0.1:2019" },
      binary: binaryPreimage,
      config: configPreimage,
      unit: unitPreimage,
      unit_generation: hardeningGeneration({
        activeEnter: "1000000",
        invocation: "22345678-1234-4234-9234-123456789abd",
        mainPid: "3333",
      }),
    },
    privileged_access_inventory: {
      boot_id: "22345678-1234-4234-9234-123456789abc",
      captured_monotonic_ns: "1500000",
      evidence_sha256: "d".repeat(64),
      process_count: 12,
      root_or_cap_dac_override_not_isolated: true,
      scope: "capability-free-unprivileged-non-root-dac-only",
    },
    runtime: {
      gate: testPin(
        "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-gate.mjs",
        "a".repeat(64),
        "0555",
        { inode: "52004" },
      ),
      node_binary: testPin("/usr/bin/node", "f".repeat(64), "0755", { inode: "52005" }),
      node_version: "v22.22.2",
      probe: testPin(ADMIN_PROBE_PATH, testSha256(probeBytes), "0555", {
        inode: "52006",
        size: String(probeBytes.length),
      }),
      setpriv_binary: testPin(SETPRIV_PATH, "6".repeat(64), "0755", {
        inode: "52007",
      }),
    },
    schema_version: 1,
    service_uid_inventory: serviceUidInventory,
    site_preservation: {
      acme_storage_migration: "none",
      existing_site_inventory_sha256: "e".repeat(64),
      probe_ids: ["existing-site"],
    },
    supply_chain: {
      caddy: {
        amd64_binary_sha256: CADDY_AMD64_BINARY,
        amd64_manifest_digest: CADDY_AMD64_MANIFEST,
        image: "docker.io/library/caddy",
        image_index_digest: CADDY_IMAGE_INDEX,
        production_binary_sha256: binaryPreimage.sha256,
        resolved_tag: "2.11.4",
        version: "v2.11.4",
      },
      node: {
        amd64_manifest_digest: NODE_AMD64_MANIFEST,
        image: "docker.io/library/node",
        image_index_digest: NODE_IMAGE_INDEX,
        resolved_tag: "22.22.2-bookworm-slim",
        version: "v22.22.2",
      },
    },
    transaction: {
      activation_mode: "cold-stop-install-daemon-reload-start-new-generation",
      automatic_rollback_after_ambiguous_start: false,
      backup_config_path: "/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds/backups/caddy-admin-uds-test-1.old.Caddyfile",
      backup_unit_path: "/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds/backups/caddy-admin-uds-test-1.old.service",
      candidate_config_path: "/etc/caddy/.bitcoinpir-caddy-admin-uds-test-1.candidate",
      candidate_unit_path: "/etc/systemd/system/.bitcoinpir-caddy-admin-uds-test-1.candidate",
      classification: {
        allowed_stopped_pairs: ["old/old", "candidate/old", "candidate/candidate", "old/candidate"],
        unknown_pair_action: "leave-stopped-fail-closed",
      },
      daemon_reload_argv: ["/usr/bin/systemctl", "daemon-reload"],
      installation_mode: "service-stopped-two-exact-rename-replacements-with-parent-fsync",
      lock_path: "/run/lock/bitcoinpir-bhtm-caddy-admin-uds.lock",
      new_invocation_required: true,
      outcome_unknown_conditions: [
        "systemctl-command-error-after-start-request",
        "unclassified-config-unit-digest-pair",
        "active-generation-with-unproven-admin-readback",
        "receipt-publication-or-parent-fsync-uncertain",
      ],
      receipt_path: "/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds/receipts/caddy-admin-uds-test-1.json",
      reload_forbidden: true,
      rollback_mode: "stop-classify-exact-pair-restore-both-old-preimages-daemon-reload-start-old-generation",
      runtime_directory_creation: "systemd-first-cold-start-only",
      start_argv: ["/usr/bin/systemctl", "start", "bhtm-caddy.service"],
      state_directory: "/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds/transactions/caddy-admin-uds-test-1",
      stop_argv: ["/usr/bin/systemctl", "stop", "bhtm-caddy.service"],
    },
    transaction_id: "caddy-admin-uds-test-1",
    trust_acknowledgements: {
      acme_storage_not_migrated: true,
      append_only_overlay_cannot_perform_this_hardening: true,
      automatic_rollback_forbidden_after_ambiguous_start: true,
      candidate_config_changes_only_admin_endpoint_bytes: true,
      candidate_unit_changes_only_reviewed_admin_runtime_directives: true,
      existing_site_inventory_complete: true,
      no_remote_action_authorized: true,
      outcome_unknown_fails_closed: true,
      privileged_access_inventory_complete_for_boot: true,
      root_and_cap_dac_override_not_isolated: true,
      runtime_directory_requires_cold_start: true,
      service_uid_inventory_complete: true,
    },
  };
  const approved = computeApprovedPlanSha256(plan);
  const activationGeneration = hardeningGeneration({
    activeEnter: targetGeneration.active_enter_timestamp_monotonic,
    invocation: targetGeneration.invocation_id,
    mainPid: targetGeneration.main_pid,
  });
  const installed = (pin, inode) => ({
    ...pin,
    ctime_ns: "1700000001000000000",
    device: "2049",
    inode,
    mtime_ns: "1700000001000000000",
    nlink: 1,
  });
  const receipt = {
    activation: {
      binary_version: "v2.11.4",
      dropin_paths: [],
      effective_environment_names: [],
      fragment_path: "/etc/systemd/system/bhtm-caddy.service",
      need_daemon_reload: "no",
      properties: {
        Group: "root",
        RuntimeDirectory: "bitcoinpir-caddy-admin",
        RuntimeDirectoryMode: "0700",
        RuntimeDirectoryPreserve: "no",
        UMask: "0077",
        UnsetEnvironment: ["CADDY_ADMIN"],
        User: "root",
      },
      unit_generation: activationGeneration,
    },
    admin: {
      denied_service_uids: serviceUidInventory.map((entry) => ({
        cap_eff: "0000000000000000",
        error: "EACCES",
        gid: entry.uid,
        groups: [entry.uid],
        ...entry,
      })),
      root_readback: {
        body_sha256: "b".repeat(64),
        cap_eff: "0000000000000000",
        gid: 0,
        groups: [0],
        listen: ADMIN_LISTEN,
        path: "/config/",
        status: 200,
        transport: "unix",
        uid: 0,
      },
      runtime_directory: { gid: 0, mode: "0700", path: ADMIN_DIRECTORY, type: "directory", uid: 0 },
      socket: { gid: 0, mode: "0200", path: ADMIN_SOCKET, type: "socket", uid: 0 },
      tcp_admin: [
        { endpoint: "127.0.0.1:2019", result: "connection-refused" },
        { endpoint: "[::1]:2019", result: "connection-refused" },
      ],
    },
    approved_plan_sha256: approved,
    before: {
      binary: plan.preimage.binary,
      config: plan.preimage.config,
      unit: plan.preimage.unit,
      unit_generation: plan.preimage.unit_generation,
    },
    collector: COLLECTOR,
    deployment_profile: PROFILE,
    durability: { parent_fsynced: true, receipt_exclusive_create: true, receipt_file_fsynced: true },
    host: { boot_id: plan.privileged_access_inventory.boot_id, hostname: "fixture.invalid" },
    installed: {
      binary: installed(plan.candidate.binary, "53001"),
      config: installed(plan.candidate.config, "53002"),
      unit: installed(plan.candidate.unit, "53003"),
    },
    outcome: "committed",
    privileged_access_inventory: plan.privileged_access_inventory,
    recovery_classification: "candidate/candidate-new-generation",
    rollback: { outcome: "not-required", performed: false },
    runtime: plan.runtime,
    schema_version: 1,
    site_health: [{ after: "passed", before: "passed", id: "existing-site" }],
    stopped: {
      admin_socket_absent: true,
      tcp_admin: [
        { endpoint: "127.0.0.1:2019", result: "connection-refused" },
        { endpoint: "[::1]:2019", result: "connection-refused" },
      ],
      unit_generation: stoppedHardeningGeneration(),
    },
    transaction_id: plan.transaction_id,
  };
  return {
    candidateUnit,
    plan,
    planBytes: Buffer.from(canonicalAdminUdsJson(plan), "utf8"),
    probeBytes,
    receipt,
    receiptBytes: Buffer.from(canonicalAdminUdsJson(receipt), "utf8"),
  };
}

export function testHardeningPlanBytes(plan) {
  const evidence = TEST_HARDENING_EVIDENCE.get(plan);
  if (evidence === undefined) throw new Error("unknown integrated overlay test plan");
  return Buffer.from(evidence.planBytes);
}

export function testHardeningReceiptBytes(plan) {
  const evidence = TEST_HARDENING_EVIDENCE.get(plan);
  if (evidence === undefined) throw new Error("unknown integrated overlay test plan");
  return Buffer.from(evidence.receiptBytes);
}

export function makeIntegratedOverlayTestPlan() {
  const placeholders = {
    DIRECTORY_PUBLISHER_CLIENT_IP: "10.23.0.6",
    DIRECTORY_PUBLISHER_HTTPS_HOST: "publisher.example.net",
    DIRECTORY_PUBLISHER_PRIVATE_BIND: "10.23.0.5",
    DIRECTORY_RELAY_WSS_HOST: "directory.example.net",
    PAYMENT_ISSUER_HTTPS_HOST: "pay.example.net",
    PROVIDER_WSS_HOST: "pir.example.net",
    PUBLIC_HTTPS_BIND: "198.51.100.23",
  };
  const rendered = Buffer.from(render(TEST_SOURCE.toString("utf8"), placeholders));
  const candidate = Buffer.concat([TEST_PREIMAGE, Buffer.from("\n"), rendered]);
  const haproxySha = testSha256("reviewed-haproxy");
  const exchangeSha = testSha256("reviewed-rename-exchange");
  const exchangePath =
    `/opt/bitcoinpir/payment-v1-rename-exchange/${exchangeSha}/payment-v1-rename-exchange`;
  const exchangeManifest = Buffer.from(`${exchangeSha}  ${exchangePath}\n`);
  const preimageSha = testSha256(TEST_PREIMAGE);
  const transactionId = "integrated-caddy-test-1";
  const targetGeneration = generation("bhtm-caddy.service", {
    canReload: "yes",
    pid: "4343",
  });
  const hardeningEvidence = makeHardeningEvidence(targetGeneration);
  const hardeningSummary = {
    admin_listen: "unix//run/bitcoinpir-caddy-admin/admin.sock|0200",
    all_service_uids_denied: true,
    approved_plan_sha256: testSha256(hardeningEvidence.planBytes),
    binary_sha256: "5".repeat(64),
    cold_new_generation: true,
    config_sha256: preimageSha,
    deployment_profile: "bhtm-caddy-admin-uds-v1",
    runtime_directory: "/run/bitcoinpir-caddy-admin",
    runtime_directory_mode: "0700",
    setpriv_binary_sha256: hardeningEvidence.plan.runtime.setpriv_binary.sha256,
    service_uid_inventory_sha256: testSha256(
      Buffer.from(canonicalAdminUdsJson(hardeningEvidence.plan.service_uid_inventory), "utf8"),
    ),
    socket_mode: "0200",
    socket_path: "/run/bitcoinpir-caddy-admin/admin.sock",
    tcp_admin_absent: true,
    transaction_id: "caddy-admin-uds-test-1",
    unit_invocation_id: targetGeneration.invocation_id,
    unit_sha256: hardeningEvidence.plan.candidate.unit.sha256,
  };
  const hardeningReceiptBytes = hardeningEvidence.receiptBytes;
  const gateSource = readFileSync(join(TEST_REPOSITORY, "scripts/payment-v1-integrated-caddy-overlay-gate.mjs"));
  const executorSource = readFileSync(join(TEST_REPOSITORY, "scripts/payment-v1-integrated-caddy-overlay-transaction.mjs"));
  const overlayPlan = {
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
      candidate_adapted_json_sha256: testSha256(
        Buffer.from(canonicalJson(TEST_ADAPTED_JSON), "utf8"),
      ),
      candidate_sha256: testSha256(candidate),
      placeholders,
      rendered_sha256: testSha256(rendered),
      source_path: MANAGED_BLOCK_SOURCE,
      source_sha256: testSha256(TEST_SOURCE),
    },
    runtime: {
      admin_probe: {
        ...hardeningEvidence.plan.runtime.probe,
        inode: "42011",
      },
      exchange_helper: testPin(exchangePath, exchangeSha, "0555"),
      exchange_manifest: testPin(
        "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/rename-exchange.sha256",
        testSha256(exchangeManifest),
        "0444",
        { size: String(exchangeManifest.length) },
      ),
      executor: testPin(
        "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-transaction.mjs",
        testSha256(executorSource),
        "0555",
      ),
      gate: testPin(
        "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs",
        testSha256(gateSource),
        "0555",
      ),
      managed_block: testPin(
        "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/managed.Caddyfile",
        testSha256(rendered),
        "0444",
        { size: String(rendered.length) },
      ),
      node_binary: testPin("/usr/bin/node", "f".repeat(64), "0755"),
      setpriv_binary: {
        ...hardeningEvidence.plan.runtime.setpriv_binary,
        inode: "42013",
      },
    },
    schema_version: 1,
    source_fair: {
      deployment_manifest_sha256: "1".repeat(64),
      deployment_profile: "integrated-existing-bhtm-caddy-v1",
      haproxy_binary: testPin(
        `/opt/bitcoinpir/haproxy/${haproxySha}/haproxy`,
        haproxySha,
        "0555",
      ),
      haproxy_config: testPin(
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
      unit_fragment: testPin(
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
      admin_uds_hardening: {
        ...hardeningSummary,
        plan: testPin(
          "/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds/plans/caddy-admin-uds-test-1.json",
          testSha256(hardeningEvidence.planBytes),
          "0400",
          { size: String(hardeningEvidence.planBytes.length), inode: "42012" },
        ),
        receipt: testPin(
          "/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds/receipts/caddy-admin-uds-test-1.json",
          testSha256(hardeningReceiptBytes),
          "0400",
          { size: String(hardeningReceiptBytes.length) },
        ),
      },
      binary: testPin("/usr/bin/caddy", "5".repeat(64), "0755"),
      config_parent: {
        device: "2049",
        gid: 0,
        inode: "43001",
        mode: "0755",
        path: "/etc/caddy",
        uid: 0,
      },
      config_preimage: testPin(
        "/etc/caddy/Caddyfile",
        preimageSha,
        "0644",
        { size: String(TEST_PREIMAGE.length) },
      ),
      unit_fragment: testPin(
        "/etc/systemd/system/bhtm-caddy.service",
        hardeningEvidence.plan.candidate.unit.sha256,
        "0644",
        { size: hardeningEvidence.plan.candidate.unit.size },
      ),
      unit_generation: targetGeneration,
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
        pin: testPin(
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
        pin: testPin(
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
      lock_path: "/run/lock/bitcoinpir-payment-v1-integrated-bhtm-caddy.lock",
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
      fresh_admin_runtime_probes_required_before_and_after_reload: true,
      reload_does_not_refresh_cold_runtime_evidence: true,
    },
  };
  TEST_HARDENING_EVIDENCE.set(overlayPlan, hardeningEvidence);
  return overlayPlan;
}

export function renderedManagedBlock(plan) {
  return Buffer.from(render(TEST_SOURCE.toString("utf8"), plan.managed_block.placeholders));
}
