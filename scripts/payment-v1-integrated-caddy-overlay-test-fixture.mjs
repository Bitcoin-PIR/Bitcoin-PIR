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
  CADDY_BINARY_PATH,
  CADDY_AMD64_BINARY,
  CADDY_AMD64_MANIFEST,
  CADDY_IMAGE_INDEX,
  COLLECTOR,
  EXECUTOR_PATH,
  NODE_AMD64_MANIFEST,
  NODE_IMAGE_INDEX,
  PROFILE,
  PUBLISHER_NETNS_DROPIN_PATH,
  PUBLISHER_NETNS_HOST_INTERFACE_PATH,
  PUBLISHER_NETNS_LIFECYCLE_LOCK,
  PUBLISHER_NETNS_NAMESPACE_PATH,
  PUBLISHER_NETNS_SENTINEL_PATHS,
  PUBLISHER_NETNS_UNIT,
  SETPRIV_PATH,
  buildHardenedCaddyfile,
  buildHardenedUnit,
  canonicalJson as canonicalAdminUdsJson,
  computeApprovedPlanSha256,
} from "./payment-v1-caddy-admin-uds-gate.mjs";

export const TEST_REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const TEST_SOURCE = readFileSync(join(TEST_REPOSITORY, MANAGED_BLOCK_SOURCE));
export const HARDENING_CONFIG_PREIMAGE = Buffer.from(
  "{\n\tadmin 127.0.0.1:2019\n}\n\nexisting.example.net {\n\treverse_proxy 127.0.0.1:18080\n}\n",
);
export const TEST_PREIMAGE = Buffer.from(
  `{\n\tadmin ${ADMIN_LISTEN}\n}\n\nexisting.example.net {\n\treverse_proxy 127.0.0.1:18080\n}\n`,
);
export const HARDENING_UNIT_PREIMAGE = Buffer.from(`[Unit]
Description=Existing bhtm Caddy

[Service]
Type=notify
User=root
Group=root
Environment=CADDY_ADMIN=127.0.0.1:2019
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile --adapter caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force

[Install]
WantedBy=multi-user.target
`);
export const PUBLISHER_NETNS_DROPIN = Buffer.from(`# Reviewed drop-in for the pre-existing bhtm-caddy.service. Do not install alone.
[Unit]
Wants=bitcoinpir-payment-v1-publisher-netns.service
After=bitcoinpir-payment-v1-publisher-netns.service

# This dependency is intentionally one-way. Caddy asks systemd to prepare the
# private bind before Caddy starts, but namespace teardown must never propagate
# a stop to the shared Caddy process. A missing bind still fails a new Caddy
# start closed; an already-running Caddy keeps its unrelated public listeners.
`);
export const TEST_HARDENED_ADAPTED_JSON = {
  admin: { listen: ADMIN_LISTEN },
  apps: {},
};
export const TEST_PREIMAGE_ADAPTED_JSON = {
  admin: { listen: "127.0.0.1:2019" },
  apps: {},
};
export const TEST_OVERLAY_ADAPTED_JSON = {
  admin: { listen: ADMIN_LISTEN },
  apps: {
    http: {
      servers: {
        overlay: { listen: [":443"], routes: [] },
      },
    },
  },
};
const TEST_HARDENING_EVIDENCE = new WeakMap();
const TEST_NETNS_EVIDENCE = new WeakMap();

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
    invocation_id: "12345678123442349234123456789abc",
    main_pid: pid,
    sub_state: "running",
    unit_name: unitName,
  };
}

function publisherUnitState(name, active, { invocation = "0".repeat(32), pid = "0" } = {}) {
  return {
    active_enter_timestamp_monotonic: active ? "1500000" : "0",
    active_state: active ? "active" : "inactive",
    invocation_id: active ? invocation : "0".repeat(32),
    load_state: "loaded",
    main_pid: active ? pid : "0",
    name,
    need_daemon_reload: "no",
    sub_state: active ? "running" : "dead",
  };
}

function publisherLoadedNetnsUnit(installedFiles) {
  const helper = installedFiles.find((entry) => entry.id === "helper-binary").pin.path;
  return {
    condition_paths: [
      "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
      "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
      "/etc/bitcoinpir/payment-v1/PUBLISHER-NETNS-ACTIVATION-APPROVED",
    ],
    condition_source: "exact-fragment-pin-plus-NeedDaemonReload=no",
    dropin_paths: [],
    exec: {
      start: [{ argv: `${helper} run`, ignore_errors: "no", path: helper }],
      start_pre: [
        { argv: `/usr/bin/test -x ${helper}`, ignore_errors: "no", path: "/usr/bin/test" },
        {
          argv: "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/publisher-netns/helper.sha256",
          ignore_errors: "no",
          path: "/usr/bin/sha256sum",
        },
        { argv: `${helper} self-test`, ignore_errors: "no", path: helper },
      ],
      stop_post: [{ argv: `${helper} cleanup`, ignore_errors: "no", path: helper }],
    },
    fragment_path: "/etc/systemd/system/bitcoinpir-payment-v1-publisher-netns.service",
    need_daemon_reload: "no",
    relationships: {
      after: ["basic.target", "local-fs.target"],
      before: ["bhtm-caddy.service", "bitcoinpir-payment-v1-source-fair-edge.service"],
      binds_to: [],
      part_of: ["bhtm-caddy.service"],
      requires: [],
      wants: [],
    },
    service: {
      ambient_capabilities: [],
      capability_bounding_set: ["CAP_NET_ADMIN", "CAP_SYS_ADMIN"],
      group: "root",
      kill_mode: "control-group",
      limit_core: "0",
      lock_personality: "yes",
      memory_deny_write_execute: "yes",
      memory_max: "67108864",
      memory_swap_max: "0",
      no_new_privileges: "yes",
      notify_access: "main",
      restart: "no",
      restrict_address_families: ["AF_NETLINK", "AF_UNIX"],
      restrict_namespaces: "net",
      restrict_realtime: "yes",
      restrict_suid_sgid: "yes",
      standard_error: "null",
      standard_output: "null",
      state_directory: ["bitcoinpir-publisher-netns"],
      state_directory_mode: "0700",
      system_call_architectures: ["native"],
      tasks_max: "8",
      timeout_start_usec: "30s",
      timeout_stop_usec: "30s",
      type: "notify",
      umask: "0077",
      unset_environment: [
        "BASH_ENV", "ENV", "GLIBC_TUNABLES", "LD_AUDIT", "LD_LIBRARY_PATH",
        "LD_PRELOAD", "NODE_EXTRA_CA_CERTS", "NODE_OPTIONS", "NODE_PATH",
      ],
      user: "root",
      working_directory: "/var/lib/bitcoinpir-publisher-netns",
    },
  };
}

function publisherRuntimeTopology(plan) {
  return {
    client: {
      address: plan.topology.client_address,
      alias: "bitcoinpir-payment-v1-publisher-netns:0123456789abcdef0123456789abcdef:client",
      index: 52,
      interface: plan.topology.client_interface,
      mac: "02:11:22:33:44:55",
      peer_index: 51,
      prefix_length: plan.topology.prefix_length,
      up: true,
    },
    forwarding_sysctls: {
      "net.ipv4.ip_forward": 0,
      "net.ipv6.conf.all.forwarding": 0,
    },
    host: {
      address: plan.topology.host_address,
      alias: "bitcoinpir-payment-v1-publisher-netns:0123456789abcdef0123456789abcdef:host",
      index: 51,
      interface: plan.topology.host_interface,
      mac: "02:aa:bb:cc:dd:ee",
      peer_index: 52,
      prefix_length: plan.topology.prefix_length,
      up: true,
    },
    namespace: {
      device: "13",
      inert_interfaces: [],
      inode: "9001",
      interface_names: ["bpir-pub-c", "lo"],
      loopback: {
        addresses: [{ family: "inet", local: "127.0.0.1", prefix_length: 8 }],
        alias: "",
        index: 1,
        up: true,
      },
      path: plan.topology.namespace_path,
      type: "nsfs",
    },
    routes: {
      client_main: [{ default: false, destination: "10.203.0.0/30", gateway: null, nat: false }],
      host_main: [{ default: false, destination: "10.203.0.0/30", gateway: null, nat: false }],
    },
  };
}

export function testCaddyEffectiveUnit(plan) {
  const binary = plan.target.binary.path;
  return {
    dropin_paths: [PUBLISHER_NETNS_DROPIN_PATH],
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
    limit_core: "0",
    memory_swap_max: "0",
    need_daemon_reload: "no",
    pass_environment: [],
    publisher_netns_dependency: {
      after_namespace_owner: true,
      binds_to_namespace_owner: false,
      dropin_paths: [PUBLISHER_NETNS_DROPIN_PATH],
      need_daemon_reload: "no",
      part_of_namespace_owner: false,
      requires_namespace_owner: false,
      wants_namespace_owner: true,
    },
    runtime_directory: ["bitcoinpir-caddy-admin"],
    runtime_directory_mode: "0700",
    runtime_directory_preserve: "no",
    standard_error: "null",
    standard_output: "null",
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

function inactivePublisherNetnsPreimage() {
  return {
    activation_sentinels_absent: [...PUBLISHER_NETNS_SENTINEL_PATHS],
    host_interface_absent: PUBLISHER_NETNS_HOST_INTERFACE_PATH,
    namespace_path_absent: PUBLISHER_NETNS_NAMESPACE_PATH,
    unit_generation: {
      active_enter_timestamp_monotonic: "0",
      active_state: "inactive",
      control_group: `/system.slice/${PUBLISHER_NETNS_UNIT}`,
      invocation_id: "",
      main_pid: "0",
      sub_state: "dead",
      unit_name: PUBLISHER_NETNS_UNIT,
    },
  };
}

export function makeHardeningEvidence(targetGeneration) {
  const candidateConfig = buildHardenedCaddyfile(
    HARDENING_CONFIG_PREIMAGE,
    "replace-explicit-tcp-admin",
  );
  if (!candidateConfig.equals(TEST_PREIMAGE)) throw new Error("hardening fixture candidate drifted");
  const candidateUnit = buildHardenedUnit(HARDENING_UNIT_PREIMAGE);
  const candidateAdaptedJson = Buffer.from(
    canonicalAdminUdsJson(TEST_HARDENED_ADAPTED_JSON),
    "utf8",
  );
  const preimageAdaptedJson = Buffer.from(
    canonicalAdminUdsJson(TEST_PREIMAGE_ADAPTED_JSON),
    "utf8",
  );
  const binaryPreimage = testPin(CADDY_BINARY_PATH, "5".repeat(64), "0755", {
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
    { name: "cloudflared", uid: 52901 },
    { name: "pir", uid: 52902 },
  ];
  const probeBytes = Buffer.from("reviewed Caddy admin probe fixture\n");
  const plan = {
    candidate: {
      adapted_json_sha256: testSha256(candidateAdaptedJson),
      adapted_json_size: String(candidateAdaptedJson.length),
      binary: {
        gid: 0,
        mode: "0755",
        path: CADDY_BINARY_PATH,
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
        dropins: [PUBLISHER_NETNS_DROPIN_PATH],
        runtime_directory: ADMIN_DIRECTORY,
        runtime_directory_mode: "0700",
        runtime_directory_preserve: "no",
        service_gid: 0,
        service_uid: 0,
        limit_core: "0",
        memory_swap_max: "0",
        standard_error: "null",
        standard_output: "null",
        umask: "0077",
      },
    },
    config_edit_mode: "replace-explicit-tcp-admin",
    deployment_profile: PROFILE,
    preimage: {
      adapted_json_sha256: testSha256(preimageAdaptedJson),
      adapted_json_size: String(preimageAdaptedJson.length),
      admin: { kind: "tcp", listen: "127.0.0.1:2019" },
      binary: binaryPreimage,
      config: configPreimage,
      unit: unitPreimage,
      unit_generation: hardeningGeneration({
        activeEnter: "1000000",
        invocation: "22345678123442349234123456789abd",
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
    publisher_netns_dropin: testPin(
      PUBLISHER_NETNS_DROPIN_PATH,
      testSha256(PUBLISHER_NETNS_DROPIN),
      "0644",
      { size: String(PUBLISHER_NETNS_DROPIN.length), inode: "52009" },
    ),
    publisher_netns_preimage: inactivePublisherNetnsPreimage(),
    runtime: {
      executor: testPin(EXECUTOR_PATH, "b".repeat(64), "0555", {
        inode: "52008",
      }),
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
      systemd_version: "255",
    },
    schema_version: 2,
    service_uid_inventory: serviceUidInventory,
    site_preservation: {
      acme_storage_migration: "none",
      existing_site_inventory_sha256: "e".repeat(64),
      probe_ids: ["direct-upstream", "public-site", "tls-site"],
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
      lock_path: PUBLISHER_NETNS_LIFECYCLE_LOCK,
      new_invocation_required: true,
      outcome_unknown_conditions: [
        "systemctl-command-error-after-stop-request-without-complete-stopped-proof",
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
      dropin_paths: [PUBLISHER_NETNS_DROPIN_PATH],
      effective_environment_names: [],
      fragment_path: "/etc/systemd/system/bhtm-caddy.service",
      need_daemon_reload: "no",
      properties: {
        Group: "root",
        LimitCORE: "0",
        MemorySwapMax: "0",
        RuntimeDirectory: "bitcoinpir-caddy-admin",
        RuntimeDirectoryMode: "0700",
        RuntimeDirectoryPreserve: "no",
        StandardError: "null",
        StandardOutput: "null",
        UMask: "0077",
        UnsetEnvironment: ["CADDY_ADMIN"],
        User: "root",
      },
      publisher_netns_dependency: {
        after_namespace_owner: true,
        binds_to_namespace_owner: false,
        dropin_paths: [PUBLISHER_NETNS_DROPIN_PATH],
        need_daemon_reload: "no",
        part_of_namespace_owner: false,
        requires_namespace_owner: false,
        wants_namespace_owner: true,
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
        body_sha256: plan.candidate.adapted_json_sha256,
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
      publisher_netns_dependency: {
        after_namespace_owner: true,
        binds_to_namespace_owner: false,
        dropin_paths: [PUBLISHER_NETNS_DROPIN_PATH],
        need_daemon_reload: "no",
        part_of_namespace_owner: false,
        requires_namespace_owner: false,
        wants_namespace_owner: true,
      },
      publisher_netns_dropin: plan.publisher_netns_dropin,
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
      publisher_netns_dropin: plan.publisher_netns_dropin,
      unit: installed(plan.candidate.unit, "53003"),
    },
    outcome: "committed",
    privileged_access_inventory: plan.privileged_access_inventory,
    publisher_netns_dropin: plan.publisher_netns_dropin,
    recovery_classification: "candidate/candidate-new-generation",
    rollback: { outcome: "not-required", performed: false },
    runtime: plan.runtime,
    schema_version: 2,
    site_health: plan.site_preservation.probe_ids.map((id) => ({
      after: "passed",
      before: "passed",
      id,
    })),
    stopped: {
      admin_socket_absent: true,
      tcp_admin: [
        { endpoint: "127.0.0.1:2019", result: "connection-refused" },
        { endpoint: "[::1]:2019", result: "connection-refused" },
      ],
      unit_generation: stoppedHardeningGeneration(),
      unit_job_absent: true,
    },
    transaction_id: plan.transaction_id,
  };
  return {
    candidateAdaptedJson,
    candidateConfig,
    candidateUnit,
    configPreimage: HARDENING_CONFIG_PREIMAGE,
    plan,
    planBytes: Buffer.from(canonicalAdminUdsJson(plan), "utf8"),
    probeBytes,
    receipt,
    receiptBytes: Buffer.from(canonicalAdminUdsJson(receipt), "utf8"),
    unitPreimage: HARDENING_UNIT_PREIMAGE,
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

export function testPublisherNetnsPlanBytes(plan) {
  const evidence = TEST_NETNS_EVIDENCE.get(plan);
  if (evidence === undefined) throw new Error("unknown integrated overlay test plan");
  return Buffer.from(evidence.planBytes);
}

export function testPublisherNetnsReceiptBytes(plan) {
  const evidence = TEST_NETNS_EVIDENCE.get(plan);
  if (evidence === undefined) throw new Error("unknown integrated overlay test plan");
  return Buffer.from(evidence.receiptBytes);
}

export function makeIntegratedOverlayTestPlan() {
  const placeholders = {
    DIRECTORY_PUBLISHER_CLIENT_IP: "10.203.0.2",
    DIRECTORY_PUBLISHER_HTTPS_HOST: "publisher.example.net",
    DIRECTORY_PUBLISHER_PRIVATE_BIND: "10.203.0.1",
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
  const overlayConfigPreimage = testPin(
    "/etc/caddy/Caddyfile",
    preimageSha,
    "0644",
    { size: String(TEST_PREIMAGE.length) },
  );
  const transactionId = "integrated-caddy-test-1";
  const targetGeneration = generation("bhtm-caddy.service", {
    canReload: "yes",
    pid: "4343",
  });
  const hardeningEvidence = makeHardeningEvidence(targetGeneration);
  const publisherCeremonyCaddyState = {
    config: overlayConfigPreimage,
    dependency: {
      after_namespace_owner: true,
      binds_to_namespace_owner: false,
      drop_in_paths: [PUBLISHER_NETNS_DROPIN_PATH],
      part_of_namespace_owner: false,
      requires_namespace_owner: false,
      wants_namespace_owner: true,
    },
    unit: {
      active_enter_timestamp_monotonic:
        targetGeneration.active_enter_timestamp_monotonic,
      active_state: targetGeneration.active_state,
      invocation_id: targetGeneration.invocation_id,
      load_state: "loaded",
      main_pid: targetGeneration.main_pid,
      name: targetGeneration.unit_name,
      need_daemon_reload: "no",
      sub_state: targetGeneration.sub_state,
    },
  };
  const publisherNetnsCeremonyId = "publisher-netns-test-1";
  const publisherNetnsPlanPath =
    `/var/lib/bitcoinpir/payment-v1/publisher-netns/plans/${publisherNetnsCeremonyId}.json`;
  const publisherNetnsReceiptPath =
    `/var/lib/bitcoinpir/payment-v1/publisher-netns/receipts/${publisherNetnsCeremonyId}.json`;
  const publisherTopologyPlan = {
    address_family: "ipv4",
    client_address: "10.203.0.2",
    client_interface: "bpir-pub-c",
    default_route: false,
    forwarding: false,
    host_address: "10.203.0.1",
    host_interface: "bpir-pub-h",
    host_port: 443,
    hosts_path: "/etc/netns/bpir-directory-publisher/hosts",
    namespace_name: "bpir-directory-publisher",
    namespace_path: "/run/netns/bpir-directory-publisher",
    nat: false,
    prefix_length: 30,
    publisher_hostname: placeholders.DIRECTORY_PUBLISHER_HTTPS_HOST,
  };
  const helperSha256 = testSha256("publisher-netns-helper");
  const installedFiles = [
    ["caddy-netns-dropin", PUBLISHER_NETNS_DROPIN_PATH, hardeningEvidence.plan.publisher_netns_dropin.sha256, "0644"],
    ["directory-publisher-unit", "/etc/systemd/system/bitcoinpir-payment-v1-directory-publisher.service", "1".repeat(64), "0644"],
    ["helper-binary", `/opt/bitcoinpir/publisher-netns/${helperSha256}/payment-v1-publisher-netns`, helperSha256, "0555"],
    ["helper-manifest", "/etc/bitcoinpir/payment-v1/publisher-netns/helper.sha256", "2".repeat(64), "0444"],
    ["netns-hosts", publisherTopologyPlan.hosts_path, "3".repeat(64), "0444"],
    ["netns-nsswitch", "/etc/netns/bpir-directory-publisher/nsswitch.conf", "4".repeat(64), "0444"],
    ["netns-resolv", "/etc/netns/bpir-directory-publisher/resolv.conf", "5".repeat(64), "0444"],
    ["network-inputs-manifest", "/etc/bitcoinpir/payment-v1/directory-publisher/network-inputs.sha256", "6".repeat(64), "0444"],
    ["network-policy", "/etc/bitcoinpir/payment-v1/directory-publisher/network-policy.json", "7".repeat(64), "0444"],
    ["publisher-netns-unit", "/etc/systemd/system/bitcoinpir-payment-v1-publisher-netns.service", "8".repeat(64), "0644"],
  ].map(([id, path, digest, mode], index) => ({
    id,
    pin: id === "caddy-netns-dropin"
      ? { ...hardeningEvidence.plan.publisher_netns_dropin }
      : testPin(path, digest, mode, { inode: String(42100 + index) }),
  }));
  const launcherSha256 = "a".repeat(64);
  const publisherNodeElfClosure = {
    activation_state:
      "descriptor-pinned-loader-recursive-needed-closure-and-double-maps-sampling",
    architecture: "elf64-le-x86_64",
    interpreter_soname: "ld-linux-x86-64.so.2",
    kind: "bitcoinpir-payment-v1-publisher-node-elf-closure-v1",
    node_needed: ["libc.so.6", "libm.so.6"],
    objects: [
      {
        needed: [],
        pin: testPin(
          "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
          "3".repeat(64), "0755", { inode: "42211" },
        ),
        soname: "ld-linux-x86-64.so.2",
      },
      {
        needed: ["ld-linux-x86-64.so.2"],
        pin: testPin(
          "/usr/lib/x86_64-linux-gnu/libc.so.6",
          "4".repeat(64), "0755", { inode: "42212" },
        ),
        soname: "libc.so.6",
      },
      {
        needed: ["libc.so.6"],
        pin: testPin(
          "/usr/lib/x86_64-linux-gnu/libm.so.6",
          "5".repeat(64), "0755", { inode: "42213" },
        ),
        soname: "libm.so.6",
      },
    ],
    pt_interp: "/lib64/ld-linux-x86-64.so.2",
    schema_version: 1,
  };
  const publisherNodeLoaderClosureManifest = Buffer.from(
    publisherNodeElfClosure.objects.map((object) =>
      `${object.pin.sha256}  ${object.pin.path}\n`).join(""),
    "utf8",
  );
  const publisherRuntime = {
    executor: testPin(
      "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs",
      "b".repeat(64), "0555", { inode: "42201" },
    ),
    health_probe: testPin(
      "/usr/local/libexec/bitcoinpir/payment-v1-publisher-private-health-probe.mjs",
      "9".repeat(64), "0555", { inode: "42210" },
    ),
    integrated_caddy_gate: testPin(
      "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs",
      "c".repeat(64), "0555", { inode: "42202" },
    ),
    ip: testPin("/usr/bin/ip", "d".repeat(64), "0755", { inode: "42203" }),
    launcher: testPin(
      `/opt/bitcoinpir/publisher-netns-launcher/${launcherSha256}/payment-v1-publisher-netns-launcher`,
      launcherSha256, "0555", { inode: "42204" },
    ),
    launcher_manifest: testPin(
      "/etc/bitcoinpir/payment-v1/publisher-netns/launcher-inputs.sha256",
      "e".repeat(64), "0444", { inode: "42205" },
    ),
    node: testPin("/usr/bin/node", "f".repeat(64), "0755", { inode: "42206" }),
    node_loader_closure_manifest: testPin(
      "/etc/bitcoinpir/payment-v1/publisher-netns/node-loader-closure.sha256",
      testSha256(publisherNodeLoaderClosureManifest), "0444",
      { inode: "42214", size: String(publisherNodeLoaderClosureManifest.length) },
    ),
    publisher_netns_gate: testPin(
      "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-gate.mjs",
      "0".repeat(64), "0555", { inode: "42207" },
    ),
    schema_validator: testPin(
      "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-schema.mjs",
      "1".repeat(64), "0555", { inode: "42208" },
    ),
    systemctl: testPin("/usr/bin/systemctl", "2".repeat(64), "0755", { inode: "42209" }),
  };
  const activationSentinels = [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
    "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
    "/etc/bitcoinpir/payment-v1/PUBLISHER-NETNS-ACTIVATION-APPROVED",
  ].map((path, index) => testPin(path, String(index + 3).repeat(64), "0400", {
    inode: String(42300 + index),
  }));
  const publisherNetnsPlan = {
    activation_sentinels: activationSentinels,
    caddy_preimage: publisherCeremonyCaddyState,
    ceremony_id: publisherNetnsCeremonyId,
    firewall_evidence: testPin(
      "/var/lib/bitcoinpir/payment-v1/publisher-netns/evidence/firewall.json",
      "9".repeat(64), "0400", { inode: "42400" },
    ),
    host: {
      boot_id: "22345678-1234-4234-9234-123456789abc",
      machine_id_sha256: "9".repeat(64),
      systemd_manager_generation: {
        generators_finish_timestamp_monotonic: "1002",
        generators_start_timestamp_monotonic: "1001",
        pid1_exe_device: "2049",
        pid1_exe_inode: "501",
        pid1_exe_path: "/usr/lib/systemd/systemd",
        pid1_start_ticks: "100",
        units_load_finish_timestamp_monotonic: "1004",
        units_load_start_timestamp_monotonic: "1003",
      },
      systemd_version: "systemd 255 (255.4-1ubuntu8.10)",
    },
    installed_files: installedFiles,
    kind: "bitcoinpir-payment-v1-publisher-netns-ceremony-v1",
    launcher_static_elf: {
      byte_order: "little-endian",
      elf_class: "ELF64",
      machine: "EM_X86_64",
      object_type: "ET_EXEC",
      program_header_count: 10,
      pt_dynamic: false,
      pt_interp: false,
      sha256: launcherSha256,
    },
    node_elf_closure: publisherNodeElfClosure,
    preimage: {
      host_interface: "absent",
      loaded_netns_unit: publisherLoadedNetnsUnit(installedFiles),
      namespace_path: "absent",
      netns_unit: publisherUnitState("bitcoinpir-payment-v1-publisher-netns.service", false),
      publisher_unit: publisherUnitState("bitcoinpir-payment-v1-directory-publisher.service", false),
    },
    publisher_private_key_installed: false,
    relationship: {
      caddy_dependency: "Wants+After",
      integrated_profile: "integrated-existing-bhtm-caddy-v1",
      network_before_caddy: true,
      publisher_requires_namespace: true,
      receipt_generation_scope: "exact-boot-and-systemd-generation",
      reboot_recreation: "caddy-wants-after-persistent-sentinels",
      reverse_stop_propagation: false,
    },
    runtime: publisherRuntime,
    schema_version: 2,
    source_commit: "8".repeat(40),
    topology: publisherTopologyPlan,
    transaction: {
      lock_path: "/run/lock/bitcoinpir-payment-v1-publisher-lifecycle.lock",
      receipt_path: publisherNetnsReceiptPath,
      rollback_receipt_path:
        `/var/lib/bitcoinpir/payment-v1/publisher-netns/receipts/${publisherNetnsCeremonyId}.rollback.json`,
      state_directory:
        `/var/lib/bitcoinpir/payment-v1/publisher-netns/transactions/${publisherNetnsCeremonyId}`,
    },
  };
  const publisherNetnsPlanBytes = Buffer.from(
    canonicalJson(publisherNetnsPlan),
    "utf8",
  );
  const publisherNetnsPlanSha256 = testSha256(publisherNetnsPlanBytes);
  const publisherNetnsUnit = publisherUnitState(
    "bitcoinpir-payment-v1-publisher-netns.service", true,
    { invocation: "a".repeat(32), pid: "5151" },
  );
  const publisherUnit = publisherUnitState(
    "bitcoinpir-payment-v1-directory-publisher.service", false,
  );
  const publisherNetnsTopology = publisherRuntimeTopology(publisherNetnsPlan);
  const publisherNetnsReceipt = {
    activation_approval_sha256: "1".repeat(64),
    approved_approval_sha256: "2".repeat(64),
    approved_plan_sha256: publisherNetnsPlanSha256,
    caddy_after: publisherCeremonyCaddyState,
    caddy_before: publisherCeremonyCaddyState,
    ceremony_id: publisherNetnsCeremonyId,
    firewall_evidence_sha256: publisherNetnsPlan.firewall_evidence.sha256,
    host: publisherNetnsPlan.host,
    installed_files: publisherNetnsPlan.installed_files.map((entry) => entry.pin),
    kind: "bitcoinpir-payment-v1-publisher-netns-receipt-v1",
    loaded_netns_unit: publisherNetnsPlan.preimage.loaded_netns_unit,
    netns_unit: publisherNetnsUnit,
    outcome: "committed",
    publisher_unit: publisherUnit,
    runtime: publisherNetnsPlan.runtime,
    schema_version: 2,
    sentinels: publisherNetnsPlan.activation_sentinels,
    topology: publisherNetnsTopology,
  };
  const publisherNetnsReceiptBytes = Buffer.from(
    canonicalJson(publisherNetnsReceipt),
    "utf8",
  );
  const hardeningSummary = {
    admin_listen: "unix//run/bitcoinpir-caddy-admin/admin.sock|0200",
    adapted_json_sha256: hardeningEvidence.plan.candidate.adapted_json_sha256,
    all_service_uids_denied: true,
    approved_plan_sha256: testSha256(hardeningEvidence.planBytes),
    binary_sha256: "5".repeat(64),
    cold_new_generation: true,
    config_sha256: preimageSha,
    deployment_profile: "bhtm-caddy-admin-uds-v1",
    plan_schema_version: 2,
    publisher_netns_dropin_sha256:
      hardeningEvidence.plan.publisher_netns_dropin.sha256,
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
    receipt_schema_version: 2,
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
        network_namespace: "host",
        path: "/",
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
        network_namespace: "bpir-directory-publisher",
        path: "/",
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
        network_namespace: "host",
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
        network_namespace: "host",
        path: "/v1/pir",
        timeout_ms: 5000,
      },
    ],
    managed_block: {
      candidate_adapted_json_sha256: testSha256(
        Buffer.from(canonicalAdminUdsJson(TEST_OVERLAY_ADAPTED_JSON), "utf8"),
      ),
      candidate_sha256: testSha256(candidate),
      placeholders,
      rendered_sha256: testSha256(rendered),
      source_path: MANAGED_BLOCK_SOURCE,
      source_sha256: testSha256(TEST_SOURCE),
    },
    runtime: {
      admin_uds_gate: { ...hardeningEvidence.plan.runtime.gate },
      admin_probe: { ...hardeningEvidence.plan.runtime.probe },
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
    schema_version: 2,
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
      binary: testPin(CADDY_BINARY_PATH, "5".repeat(64), "0755"),
      config_parent: {
        device: "2049",
        gid: 0,
        inode: "43001",
        mode: "0755",
        path: "/etc/caddy",
        uid: 0,
      },
      config_preimage: overlayConfigPreimage,
      publisher_netns_ceremony: {
        approved_plan_sha256: publisherNetnsPlanSha256,
        client_address: publisherTopologyPlan.client_address,
        ceremony_id: publisherNetnsCeremonyId,
        dropin: hardeningEvidence.plan.publisher_netns_dropin,
        host_address: publisherTopologyPlan.host_address,
        host_port: publisherTopologyPlan.host_port,
        namespace_device: publisherNetnsTopology.namespace.device,
        namespace_inode: publisherNetnsTopology.namespace.inode,
        netns_invocation_id: publisherNetnsUnit.invocation_id,
        plan: testPin(
          publisherNetnsPlanPath,
          publisherNetnsPlanSha256,
          "0400",
          { size: String(publisherNetnsPlanBytes.length), inode: "42014" },
        ),
        plan_schema_version: 2,
        publisher_hostname: publisherTopologyPlan.publisher_hostname,
        receipt: testPin(
          publisherNetnsReceiptPath,
          testSha256(publisherNetnsReceiptBytes),
          "0400",
          { size: String(publisherNetnsReceiptBytes.length), inode: "42015" },
        ),
        receipt_schema_version: 2,
        topology_sha256: testSha256(
          Buffer.from(canonicalJson(publisherNetnsTopology), "utf8"),
        ),
      },
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
        CADDY_BINARY_PATH,
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
      lock_path: "/run/lock/bitcoinpir-payment-v1-publisher-lifecycle.lock",
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
        CADDY_BINARY_PATH,
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
      adapted_json_has_no_configured_log_sink: true,
      append_only_cannot_disable_global_zero_rtt: true,
      existing_preimage_remains_authoritative: true,
      existing_root_caddy_retains_admin_and_acme_trust: true,
      existing_root_caddy_expands_failure_domain: true,
      fresh_admin_runtime_probes_required_before_and_after_reload: true,
      reload_does_not_refresh_cold_runtime_evidence: true,
    },
  };
  TEST_HARDENING_EVIDENCE.set(overlayPlan, hardeningEvidence);
  TEST_NETNS_EVIDENCE.set(overlayPlan, {
    planBytes: publisherNetnsPlanBytes,
    receiptBytes: publisherNetnsReceiptBytes,
  });
  return overlayPlan;
}

export function renderedManagedBlock(plan) {
  return Buffer.from(render(TEST_SOURCE.toString("utf8"), plan.managed_block.placeholders));
}
