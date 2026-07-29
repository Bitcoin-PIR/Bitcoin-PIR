import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { MANAGED_BLOCK_SOURCE } from "./payment-v1-integrated-caddy-overlay-gate.mjs";

export const TEST_REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const TEST_SOURCE = readFileSync(join(TEST_REPOSITORY, MANAGED_BLOCK_SOURCE));
export const TEST_PREIMAGE = Buffer.from(
  "existing.example.net {\n\treverse_proxy 127.0.0.1:18080\n}\n",
);

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
  const gateSource = readFileSync(join(TEST_REPOSITORY, "scripts/payment-v1-integrated-caddy-overlay-gate.mjs"));
  const executorSource = readFileSync(join(TEST_REPOSITORY, "scripts/payment-v1-integrated-caddy-overlay-transaction.mjs"));
  return {
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
      candidate_sha256: testSha256(candidate),
      placeholders,
      rendered_sha256: testSha256(rendered),
      source_path: MANAGED_BLOCK_SOURCE,
      source_sha256: testSha256(TEST_SOURCE),
    },
    runtime: {
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
      reload_does_not_refresh_cold_runtime_evidence: true,
    },
  };
}

export function renderedManagedBlock(plan) {
  return Buffer.from(render(TEST_SOURCE.toString("utf8"), plan.managed_block.placeholders));
}
