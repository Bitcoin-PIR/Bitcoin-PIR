import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

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
  buildCandidates,
  buildHardenedCaddyfile,
  buildHardenedUnit,
  canonicalJson,
  computeApprovedPlanSha256,
  normalizeSystemdInvocationId,
  parseCanonicalReceipt,
  parseStrictJson,
  sha256,
  validateCommittedReceipt,
  validateAdaptedCaddyPrivacy,
  validateHardenedCaddyfile,
  validateHardenedUnit,
  validatePlan,
  validateSystemdInvocationId,
} from "./payment-v1-caddy-admin-uds-gate.mjs";

const DIRECTORY = dirname(fileURLToPath(import.meta.url));
const GATE_SOURCE = join(DIRECTORY, "payment-v1-caddy-admin-uds-gate.mjs");
const PLAN_SKELETON = join(
  DIRECTORY,
  "../docs/payment/render-plan-skeletons/bhtm-caddy-admin-uds-v1.plan.json.example",
);
const UNIT_PREIMAGE_FIXTURE = join(
  DIRECTORY,
  "fixtures/payment-v1-caddy-admin-uds-preimage.service",
);
const UNIT_HARDENED_FIXTURE = join(
  DIRECTORY,
  "fixtures/payment-v1-caddy-admin-uds-hardened.service",
);
const PRODUCTION_CADDY_BINARY = "c".repeat(64);
const CONFIG = Buffer.from(`{
\temail ops@example.invalid
\tadmin 127.0.0.1:2019
}

one.example.invalid {
\trespond "one" 200
}

two.example.invalid {
\treverse_proxy 127.0.0.1:8080
}
`, "utf8");
const UNIT = Buffer.from(`[Unit]
Description=Existing bhtm Caddy
After=network-online.target

[Service]
Type=notify
User=root
Group=root
Environment=CADDY_ADMIN=127.0.0.1:2019
StandardOutput=journal
StandardError=inherit
LimitCORE=infinity
MemorySwapMax=infinity
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile --adapter caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force
TimeoutStopSec=5s

[Install]
WantedBy=multi-user.target
`, "utf8");

function snapshot(path, bytes, mode, seed) {
  return {
    ctime_ns: String(1_000 + seed),
    device: "2049",
    gid: 0,
    inode: String(5_000 + seed),
    mode,
    mtime_ns: String(2_000 + seed),
    nlink: 1,
    path,
    sha256: sha256(bytes),
    size: String(bytes.length),
    uid: 0,
  };
}

function contentPin(path, bytes, mode) {
  return {
    gid: 0,
    mode,
    path,
    sha256: sha256(bytes),
    size: String(bytes.length),
    uid: 0,
  };
}

function generation({
  activeEnter = "1000000",
  invocation = "123e4567e89b42d3a456426614174000",
  mainPid = "401",
} = {}) {
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

function stoppedGeneration() {
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

function fixture() {
  const candidateConfig = buildHardenedCaddyfile(CONFIG, "replace-explicit-tcp-admin");
  const candidateUnit = buildHardenedUnit(UNIT);
  const binarySnapshot = {
    ctime_ns: "1001",
    device: "2049",
    gid: 0,
    inode: "5001",
    mode: "0755",
    mtime_ns: "2001",
    nlink: 1,
    path: "/usr/bin/caddy",
    sha256: PRODUCTION_CADDY_BINARY,
    size: "48521378",
    uid: 0,
  };
  const plan = {
    candidate: {
      binary: {
        gid: 0,
        mode: "0755",
        path: "/usr/bin/caddy",
        sha256: PRODUCTION_CADDY_BINARY,
        size: "48521378",
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
      admin: { kind: "tcp", listen: "127.0.0.1:2019" },
      binary: binarySnapshot,
      config: snapshot("/etc/caddy/Caddyfile", CONFIG, "0644", 2),
      unit: snapshot("/etc/systemd/system/bhtm-caddy.service", UNIT, "0644", 3),
      unit_generation: generation(),
    },
    runtime: {
      gate: snapshot(
        "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-gate.mjs",
        Buffer.from("reviewed gate fixture\n"),
        "0555",
        4,
      ),
      node_binary: snapshot(
        "/usr/bin/node",
        Buffer.from("reviewed Node fixture\n"),
        "0755",
        5,
      ),
      node_version: "v22.22.2",
      probe: snapshot(
        ADMIN_PROBE_PATH,
        Buffer.from("reviewed probe fixture\n"),
        "0555",
        6,
      ),
      setpriv_binary: snapshot(
        SETPRIV_PATH,
        Buffer.from("reviewed setpriv fixture\n"),
        "0755",
        7,
      ),
    },
    privileged_access_inventory: {
      boot_id: "323e4567-e89b-42d3-a456-426614174002",
      captured_monotonic_ns: "1500000",
      evidence_sha256: "d".repeat(64),
      process_count: 12,
      root_or_cap_dac_override_not_isolated: true,
      scope: "capability-free-unprivileged-non-root-dac-only",
    },
    schema_version: 1,
    service_uid_inventory: [
      { name: "cloudflared", uid: 62901 },
      { name: "pir", uid: 62902 },
    ],
    site_preservation: {
      acme_storage_migration: "none",
      existing_site_inventory_sha256: "a".repeat(64),
      probe_ids: ["one", "two"],
    },
    supply_chain: {
      caddy: {
        amd64_binary_sha256: CADDY_AMD64_BINARY,
        amd64_manifest_digest: CADDY_AMD64_MANIFEST,
        image: "docker.io/library/caddy",
        image_index_digest: CADDY_IMAGE_INDEX,
        production_binary_sha256: PRODUCTION_CADDY_BINARY,
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
      backup_config_path:
        "/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds/backups/caddy-admin-uds-test.old.Caddyfile",
      backup_unit_path:
        "/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds/backups/caddy-admin-uds-test.old.service",
      candidate_config_path: "/etc/caddy/.bitcoinpir-caddy-admin-uds-test.candidate",
      candidate_unit_path:
        "/etc/systemd/system/.bitcoinpir-caddy-admin-uds-test.candidate",
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
      receipt_path:
        "/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds/receipts/caddy-admin-uds-test.json",
      reload_forbidden: true,
      rollback_mode:
        "stop-classify-exact-pair-restore-both-old-preimages-daemon-reload-start-old-generation",
      runtime_directory_creation: "systemd-first-cold-start-only",
      start_argv: ["/usr/bin/systemctl", "start", "bhtm-caddy.service"],
      state_directory:
        "/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds/transactions/caddy-admin-uds-test",
      stop_argv: ["/usr/bin/systemctl", "stop", "bhtm-caddy.service"],
    },
    transaction_id: "caddy-admin-uds-test",
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
  return { candidateConfig, candidateUnit, plan };
}

function receiptFixture(plan) {
  const approved = computeApprovedPlanSha256(plan);
  const installedBinary = {
    ...plan.preimage.binary,
    ctime_ns: "3001",
    inode: "9001",
    mtime_ns: "3002",
  };
  const installedConfig = {
    ...plan.candidate.config,
    ctime_ns: "3003",
    device: "2049",
    inode: "9002",
    mtime_ns: "3004",
    nlink: 1,
  };
  const installedUnit = {
    ...plan.candidate.unit,
    ctime_ns: "3005",
    device: "2049",
    inode: "9003",
    mtime_ns: "3006",
    nlink: 1,
  };
  const receipt = {
    activation: {
      binary_version: "v2.11.4",
      dropin_paths: [],
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
      unit_generation: generation({
        activeEnter: "2000000",
        invocation: "223e4567e89b42d3a456426614174001",
        mainPid: "502",
      }),
    },
    admin: {
      denied_service_uids: plan.service_uid_inventory.map((entry) => ({
        cap_eff: "0000000000000000",
        error: "EACCES",
        gid: entry.uid,
        groups: [entry.uid],
        name: entry.name,
        uid: entry.uid,
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
      runtime_directory: {
        gid: 0,
        mode: "0700",
        path: ADMIN_DIRECTORY,
        type: "directory",
        uid: 0,
      },
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
    durability: {
      parent_fsynced: true,
      receipt_exclusive_create: true,
      receipt_file_fsynced: true,
    },
    host: {
      boot_id: "323e4567-e89b-42d3-a456-426614174002",
      hostname: "fixture.invalid",
    },
    installed: { binary: installedBinary, config: installedConfig, unit: installedUnit },
    outcome: "committed",
    privileged_access_inventory: plan.privileged_access_inventory,
    recovery_classification: "candidate/candidate-new-generation",
    rollback: { outcome: "not-required", performed: false },
    runtime: plan.runtime,
    schema_version: 1,
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
      unit_generation: stoppedGeneration(),
    },
    transaction_id: plan.transaction_id,
  };
  return { approved, receipt };
}

test("exact preimages construct only the reviewed config and unit hardening", () => {
  const { candidateConfig, candidateUnit, plan } = fixture();
  assert.equal(validatePlan(plan), true);
  const built = buildCandidates({ configPreimageBytes: CONFIG, plan, unitPreimageBytes: UNIT });
  assert.deepEqual(built.config, candidateConfig);
  assert.deepEqual(built.unit, candidateUnit);
  const oldSites = CONFIG.toString("utf8").slice(CONFIG.toString("utf8").indexOf("one.example.invalid"));
  const newSites = candidateConfig
    .toString("utf8")
    .slice(candidateConfig.toString("utf8").indexOf("one.example.invalid"));
  assert.equal(newSites, oldSites, "all site and ACME-related bytes after the global block stay exact");
  assert.doesNotMatch(candidateUnit.toString("utf8"), /^Environment=.*CADDY_ADMIN/gmu);
  assert.doesNotMatch(candidateUnit.toString("utf8"), /--environ/u);
  assert.equal(
    candidateUnit.toString("utf8").match(/^ExecStart=\/usr\/bin\/caddy run --config \/etc\/caddy\/Caddyfile --adapter caddyfile$/gmu)?.length,
    1,
  );
  assert.match(candidateUnit.toString("utf8"), /RuntimeDirectory=bitcoinpir-caddy-admin/u);
  assert.match(candidateUnit.toString("utf8"), /^LimitCORE=0$/mu);
  assert.match(candidateUnit.toString("utf8"), /^MemorySwapMax=0$/mu);
  assert.match(candidateUnit.toString("utf8"), /^StandardOutput=null$/mu);
  assert.match(candidateUnit.toString("utf8"), /^StandardError=null$/mu);
  assert.doesNotMatch(candidateUnit.toString("utf8"), /^StandardOutput=journal$/mu);
  assert.doesNotMatch(candidateUnit.toString("utf8"), /^StandardError=inherit$/mu);
  assert.match(candidateUnit.toString("utf8"), /UMask=0077/u);
  assert.equal(validateHardenedCaddyfile(candidateConfig), true);
  assert.equal(validateHardenedUnit(candidateUnit), true);
  assert.deepEqual(buildHardenedUnit(readFileSync(UNIT_PREIMAGE_FIXTURE)), readFileSync(UNIT_HARDENED_FIXTURE));
});

test("implicit TCP default can be replaced without changing existing global options or sites", () => {
  const preimage = Buffer.from(`{
\temail ops@example.invalid
\tservers {
\t\tprotocols h1 h2
\t}
}

site.example.invalid {
\trespond "ok"
}
`, "utf8");
  const candidate = buildHardenedCaddyfile(preimage, "insert-existing-global-options");
  assert.match(candidate.toString("utf8"), /^\{\n\tadmin unix\/\/run\/bitcoinpir-caddy-admin\/admin\.sock\|0200\n\temail/mu);
  assert.equal(candidate.toString("utf8").split("site.example.invalid")[1], preimage.toString("utf8").split("site.example.invalid")[1]);
});

test("adapted Caddy privacy gate rejects configured and request-scoped log sinks", () => {
  const base = {
    admin: { listen: ADMIN_LISTEN },
    apps: { http: { servers: { srv0: { listen: [":443"], routes: [] } } } },
  };
  assert.equal(validateAdaptedCaddyPrivacy(base), true);
  assert.throws(
    () => validateAdaptedCaddyPrivacy({ ...base, logging: { logs: { default: {} } } }),
    /global logging sink/u,
  );
  assert.throws(
    () => validateAdaptedCaddyPrivacy({
      ...base,
      apps: { http: { servers: { srv0: { listen: [":443"], logs: {} } } } },
    }),
    /must not enable access logging/u,
  );
  assert.throws(
    () => validateAdaptedCaddyPrivacy({
      ...base,
      apps: { http: { servers: { srv0: { routes: [{ handle: [{ handler: "log_append" }] }] } } } },
    }),
    /runtime log handler/u,
  );
});

test("systemd InvocationID uses the real 32-lowercase-hex wire form", () => {
  assert.equal(validateSystemdInvocationId("123e4567e89b42d3a456426614174000"), true);
  assert.throws(
    () => validateSystemdInvocationId("123e4567-e89b-42d3-a456-426614174000"),
    /32-character lowercase systemd InvocationID/u,
  );
  assert.throws(
    () => validateSystemdInvocationId("0".repeat(32)),
    /nonzero/u,
  );
  assert.throws(
    () => validateSystemdInvocationId("A".repeat(32)),
    /lowercase/u,
  );
  assert.equal(normalizeSystemdInvocationId("", { active: false }), "");
  assert.equal(normalizeSystemdInvocationId("0".repeat(32), { active: false }), "");
  assert.throws(
    () => normalizeSystemdInvocationId("1".repeat(32), { active: false }),
    /inactive unit/u,
  );
});

test("a Caddyfile without global options gets only the exact prepended admin block", () => {
  const preimage = Buffer.from("site.example.invalid {\n\trespond \"ok\"\n}\n", "utf8");
  const candidate = buildHardenedCaddyfile(preimage, "prepend-new-global-options");
  assert.equal(
    candidate.toString("utf8"),
    `{\n\tadmin ${ADMIN_LISTEN}\n}\n\n${preimage.toString("utf8")}`,
  );
});

test("config construction rejects a second admin, imports and environment indirection", () => {
  assert.throws(
    () => buildHardenedCaddyfile(Buffer.from("{\n\tadmin 127.0.0.1:2019\n\tadmin off\n}\n"), "replace-explicit-tcp-admin"),
    /exactly one top-level global admin/u,
  );
  assert.throws(
    () => buildHardenedCaddyfile(Buffer.from("{\n\tadmin localhost:2019\n}\n"), "replace-explicit-tcp-admin"),
    /must equal 127\.0\.0\.1:2019/u,
  );
  assert.throws(
    () => buildHardenedCaddyfile(Buffer.from("{\n\tadmin {env.CADDY_ADMIN}\n}\n"), "replace-explicit-tcp-admin"),
    /environment-backed Caddy placeholders/u,
  );
  assert.throws(
    () => buildHardenedCaddyfile(Buffer.from("{\n\tadmin 127.0.0.1:2019\n}\nimport \/tmp\/extra.caddy\n"), "replace-explicit-tcp-admin"),
    /must not contain import directives/u,
  );
  assert.throws(
    () => buildHardenedCaddyfile(Buffer.from("{\n\tadmin 127.0.0.1:2019\n\timport \/tmp\/*.does-not-exist\n}\n"), "replace-explicit-tcp-admin"),
    /must not contain import directives/u,
  );
  assert.throws(
    () => buildHardenedCaddyfile(Buffer.from("{\n\tadmin 127.0.0.1:2019\n}\nsite.invalid {\n\timport dynamic-snippet\n}\n"), "replace-explicit-tcp-admin"),
    /must not contain import directives/u,
  );
  assert.throws(
    () => buildHardenedCaddyfile(Buffer.from("{\n\tadmin 127.0.0.1:2019\n}\nsite.invalid {\n\trespond {$DYNAMIC_BODY}\n}\n"), "replace-explicit-tcp-admin"),
    /environment-backed Caddy placeholders/u,
  );
  for (const codePoint of [
    0x000b, 0x000c, 0x0085, 0x00a0, 0x1680,
    0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
    0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f,
    0x3000,
  ]) {
    const whitespace = String.fromCodePoint(codePoint);
    assert.throws(
      () => buildHardenedCaddyfile(
        Buffer.from(`{\n\tadmin 127.0.0.1:2019\n}\nimport${whitespace}/tmp/override.Caddyfile\n`),
        "replace-explicit-tcp-admin",
      ),
      /non-canonical Caddy whitespace/u,
      `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")} import separator`,
    );
  }
  assert.throws(
    () => buildHardenedCaddyfile(
      Buffer.from("{\n\tadmin 127.0.0.1:2019\n\tadmin\u00a0127.0.0.1:2020\n}\n"),
      "replace-explicit-tcp-admin",
    ),
    /non-canonical Caddy whitespace/u,
  );
  for (const quoted of ['"admin"', "`admin`"]) {
    assert.throws(
      () => buildHardenedCaddyfile(
        Buffer.from(`{\n\tadmin 127.0.0.1:2019\n\t${quoted} 127.0.0.1:2020\n}\n`),
        "replace-explicit-tcp-admin",
      ),
      /quoted admin directives/u,
    );
  }
});

test("unit construction rejects non-root service and all unbounded environment sources", () => {
  assert.throws(
    () => buildHardenedUnit(Buffer.from(UNIT.toString("utf8").replace("User=root", "User=caddy"))),
    /must run as root:root/u,
  );
  assert.throws(
    () => buildHardenedUnit(Buffer.from(UNIT.toString("utf8").replace("Type=notify", "Type=notify\nEnvironmentFile=/etc/default/caddy"))),
    /EnvironmentFile cannot prove/u,
  );
  assert.throws(
    () => buildHardenedUnit(Buffer.from(UNIT.toString("utf8").replace("Type=notify", "Type=notify\nPassEnvironment=CADDY_ADMIN"))),
    /must not use PassEnvironment/u,
  );
  assert.throws(
    () => buildHardenedUnit(Buffer.from(UNIT.toString("utf8").replace("CADDY_ADMIN=127.0.0.1:2019", "CADDY_ADMIN=off"))),
    /unreviewed CADDY_ADMIN/u,
  );
  assert.throws(
    () => buildHardenedUnit(Buffer.from(UNIT.toString("utf8").replace("/usr/bin/caddy run", "/tmp/caddy run"))),
    /exact plan-pinned Caddy binary/u,
  );
  const hardened = buildHardenedUnit(UNIT).toString("utf8");
  assert.throws(
    () => validateHardenedUnit(Buffer.from(hardened.replace("caddy run --config", "caddy run --environ --config"))),
    /must not use --environ/u,
  );
  const withPinnedEnvironment = buildHardenedUnit(
    Buffer.from(UNIT.toString("utf8").replace("Type=notify", "Type=notify\nEnvironment=HOME=/var/lib/caddy")),
  );
  assert.match(withPinnedEnvironment.toString("utf8"), /^Environment=HOME=\/var\/lib\/caddy$/mu);
  assert.equal(validateHardenedUnit(withPinnedEnvironment), true);
});

test("plan rejects old Caddy evidence, Node drift, incomplete UID inventory and warm activation", () => {
  for (const [mutate, pattern] of [
    [(plan) => { plan.supply_chain.caddy.version = "v2.11.3"; }, /must equal v2\.11\.4/u],
    [(plan) => { plan.supply_chain.node.version = "v24.18.0"; }, /must equal v22\.22\.2/u],
    [(plan) => { plan.runtime.setpriv_binary.path = "/usr/local/bin/setpriv"; }, /must equal \/usr\/bin\/setpriv/u],
    [(plan) => { plan.service_uid_inventory = [{ name: "pir", uid: 62902 }]; }, /2\.\.128/u],
    [(plan) => { plan.preimage.unit_generation.invocation_id = "123e4567-e89b-42d3-a456-426614174000"; }, /32-character lowercase systemd InvocationID/u],
    [(plan) => { plan.preimage.unit_generation.invocation_id = "0".repeat(32); }, /nonzero 32-character lowercase systemd InvocationID/u],
    [(plan) => { plan.transaction.reload_forbidden = false; }, /reload_forbidden must equal true/u],
    [(plan) => { plan.transaction.automatic_rollback_after_ambiguous_start = true; }, /must equal false/u],
  ]) {
    const { plan } = fixture();
    mutate(plan);
    assert.throws(() => validatePlan(plan), pattern);
  }
});

test("candidate pins are recomputed from both exact preimages", () => {
  const { plan } = fixture();
  assert.throws(
    () => buildCandidates({ configPreimageBytes: Buffer.concat([CONFIG, Buffer.from("# drift\n")]), plan, unitPreimageBytes: UNIT }),
    /Caddyfile preimage bytes do not match/u,
  );
  const drifted = structuredClone(plan);
  drifted.candidate.unit.sha256 = "f".repeat(64);
  assert.throws(
    () => buildCandidates({ configPreimageBytes: CONFIG, plan: drifted, unitPreimageBytes: UNIT }),
    /candidate unit bytes do not match/u,
  );
});

test("an exact committed cold-generation receipt passes", () => {
  const { plan } = fixture();
  const { approved, receipt } = receiptFixture(plan);
  const trustedReceiptSha256 = sha256(Buffer.from(canonicalJson(receipt), "utf8"));
  assert.equal(validateCommittedReceipt({ approvedPlanSha256: approved, plan, receipt, trustedReceiptSha256 }), true);
});

test("receipt rejects warm generation, non-root access, TCP admin, socket drift and outcome unknown", () => {
  for (const [mutate, pattern] of [
    [
      (receipt, plan) => { receipt.activation.unit_generation.invocation_id = plan.preimage.unit_generation.invocation_id; },
      /new InvocationID/u,
    ],
    [
      (receipt) => { receipt.admin.denied_service_uids[0].error = "CONNECTED"; },
      /not an exact EACCES proof/u,
    ],
    [
      (receipt) => { receipt.admin.denied_service_uids[0].cap_eff = "0000000000000002"; },
      /not an exact EACCES proof/u,
    ],
    [
      (receipt) => { receipt.admin.denied_service_uids[0].groups = [0, 62901]; },
      /not an exact EACCES proof/u,
    ],
    [
      (receipt) => { receipt.admin.tcp_admin[0].result = "connected"; },
      /connection-refused/u,
    ],
    [
      (receipt) => { receipt.admin.socket.mode = "0660"; },
      /root:root 0200/u,
    ],
    [
      (receipt) => { receipt.activation.effective_environment_names.push("CADDY_ADMIN"); },
      /exclude CADDY_ADMIN/u,
    ],
    [
      (receipt) => { receipt.activation.properties.StandardOutput = "journal"; },
      /systemd properties do not match/u,
    ],
    [
      (receipt) => { receipt.activation.properties.StandardError = "inherit"; },
      /systemd properties do not match/u,
    ],
    [
      (receipt) => { receipt.activation.properties.MemorySwapMax = "infinity"; },
      /systemd properties do not match/u,
    ],
    [
      (receipt) => { receipt.activation.properties.LimitCORE = "infinity"; },
      /systemd properties do not match/u,
    ],
    [
      (receipt) => { receipt.outcome = "outcome-unknown"; },
      /only an exact committed/u,
    ],
  ]) {
    const { plan } = fixture();
    const { approved, receipt } = receiptFixture(plan);
    mutate(receipt, plan);
    const trustedReceiptSha256 = sha256(Buffer.from(canonicalJson(receipt), "utf8"));
    assert.throws(
      () => validateCommittedReceipt({ approvedPlanSha256: approved, plan, receipt, trustedReceiptSha256 }),
      pattern,
    );
  }
});

test("strict JSON rejects duplicate keys and gate has no mutating process surface", () => {
  assert.throws(() => parseStrictJson('{"a":1,"a":2}'), /duplicate key/u);
  assert.equal(parseCanonicalReceipt(Buffer.from('{"a":1}', "utf8")).a, 1);
  assert.throws(
    () => parseCanonicalReceipt(Buffer.from('{ "a": 1 }\n', "utf8")),
    /canonical JSON encoding/u,
  );
  const source = readFileSync(GATE_SOURCE, "utf8");
  assert.doesNotMatch(source, /node:child_process|writeFile|renameSync|spawnSync|execFileSync/u);
  assert.match(source, /no_remote_action_authorized/u);
});

test("checked-in maintenance skeleton is strict JSON but deliberately unusable", () => {
  const skeleton = parseStrictJson(readFileSync(PLAN_SKELETON, "utf8"), "maintenance skeleton");
  assert.throws(() => validatePlan(skeleton), /must be 64 lowercase hex|config_edit_mode is not reviewed/u);
});
