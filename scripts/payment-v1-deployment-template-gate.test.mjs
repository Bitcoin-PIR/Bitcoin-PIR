import assert from "node:assert/strict";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  ACTIVE_BASELINES,
  REQUIRED_PREPARATION_FILES,
  validateDeploymentTree,
  validateRelaySelection,
} from "./payment-v1-deployment-template-gate.mjs";

const REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-deployment-gate-"));
  const paths = new Set([
    ...Object.keys(ACTIVE_BASELINES),
    ...REQUIRED_PREPARATION_FILES,
  ]);
  for (const relativePath of paths) {
    const destination = join(root, relativePath);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(join(REPOSITORY, relativePath), destination);
    chmodSync(destination, 0o644);
  }
  return root;
}

function withFixture(run) {
  const root = fixture();
  try {
    run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function mutate(root, relativePath, transform) {
  const path = join(root, relativePath);
  const before = readFileSync(path, "utf8");
  const after = transform(before);
  assert.notEqual(after, before, `test mutation must change ${relativePath}`);
  writeFileSync(path, after, "utf8");
}

function replaceRelayField(text, field, value) {
  const expression = new RegExp(`^${field}\\s*=.*$`, "m");
  assert.match(text, expression);
  return text.replace(expression, `${field} = ${JSON.stringify(value)}`);
}

function resolvedRelaySelection(text, overrides = {}) {
  const values = {
    status: "RESOLVED",
    directory_mode: "strict-multi-relay",
    implementation: "bitcoinpir-directory-only",
    source_repository: "https://github.com/Bitcoin-PIR/Bitcoin-PIR.git",
    source_commit: "1".repeat(40),
    source_archive_sha256: "2".repeat(64),
    cargo_lock_sha256: "3".repeat(64),
    build_manifest_sha256: "7".repeat(64),
    binary_sha256: "4".repeat(64),
    binary_version_output: "bitcoinpir-directory-relay 0.1.0",
    config_sha256: "5".repeat(64),
    publisher_pubkey_hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ...overrides,
  };
  let output = text;
  for (const [field, value] of Object.entries(values)) {
    output = replaceRelayField(output, field, value);
  }
  return output;
}

function unresolvedRelaySelection(text) {
  let output = replaceRelayField(text, "status", "UNRESOLVED");
  for (const field of [
    "directory_mode",
    "implementation",
    "source_repository",
    "source_commit",
    "source_archive_sha256",
    "cargo_lock_sha256",
    "build_manifest_sha256",
    "binary_sha256",
    "binary_version_output",
    "config_sha256",
    "publisher_pubkey_hex",
  ]) {
    output = replaceRelayField(output, field, "UNRESOLVED");
  }
  return output;
}

test("repository deployment preparation passes its fail-closed gate", () => {
  assert.equal(validateDeploymentTree(REPOSITORY), true);
});

test("a copied positive fixture passes", () => {
  withFixture((root) => assert.equal(validateDeploymentTree(root), true));
});

test("global activation never substitutes for a role-specific approval", () => {
  for (const [relativePath, roleSentinel] of [
    [
      "deploy/payment-v1/systemd/hetzner-provider.service.in",
      "PROVIDER-ACTIVATION-APPROVED",
    ],
    [
      "deploy/payment-v1/systemd/hetzner-provider-no-standard-cashu.service.in",
      "PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED",
    ],
    [
      "deploy/payment-v1/systemd/hetzner-provider-direct.service.in",
      "PROVIDER-DIRECT-ACTIVATION-APPROVED",
    ],
    [
      "deploy/payment-v1/systemd/rollback-authority.service.in",
      "ROLLBACK-AUTHORITY-ACTIVATION-APPROVED",
    ],
    [
      "deploy/payment-v1/systemd/hetzner-directory-relay.service.in",
      "RELAY-ACTIVATION-APPROVED",
    ],
    [
      "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
      "SIGNET-LIGHTNING-STAGING-APPROVED",
    ],
    [
      "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
      "SIGNET-ISSUER-ACTIVATION-APPROVED",
    ],
    [
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      "SIGNET-ISSUER-ACTIVATION-APPROVED",
    ],
    [
      "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
      "SIGNET-ISSUER-ACTIVATION-APPROVED",
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-public-edge.service.in",
      "EDGE-ACTIVATION-APPROVED",
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-source-fair-edge.service.in",
      "EDGE-ACTIVATION-APPROVED",
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-edge.service.in",
      "ROLLBACK-EDGE-ACTIVATION-APPROVED",
    ],
  ]) {
    withFixture((root) => {
      mutate(root, relativePath, (text) =>
        text.replace(
          `ConditionPathExists=/etc/bitcoinpir/payment-v1/${roleSentinel}\n`,
          "",
        ),
      );
      assert.throws(
        () => validateDeploymentTree(root),
        /Unit\.ConditionPathExists must equal/,
      );
    });
  }
});

test("provider profile sentinels are mutually exclusive at unit start", () => {
  for (const [relativePath, forbiddenSentinels] of [
    [
      "deploy/payment-v1/systemd/hetzner-provider.service.in",
      [
        "PROVIDER-DIRECT-ACTIVATION-APPROVED",
        "PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED",
      ],
    ],
    [
      "deploy/payment-v1/systemd/hetzner-provider-no-standard-cashu.service.in",
      [
        "PROVIDER-ACTIVATION-APPROVED",
        "PROVIDER-DIRECT-ACTIVATION-APPROVED",
      ],
    ],
    [
      "deploy/payment-v1/systemd/hetzner-provider-direct.service.in",
      [
        "PROVIDER-ACTIVATION-APPROVED",
        "PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED",
      ],
    ],
  ]) {
    for (const forbiddenSentinel of forbiddenSentinels) {
      withFixture((root) => {
        mutate(root, relativePath, (text) => text.replace(
          `ConditionPathExists=!/etc/bitcoinpir/payment-v1/${forbiddenSentinel}\n`,
          "",
        ));
        assert.throws(
          () => validateDeploymentTree(root),
          /Unit\.ConditionPathExists must equal/,
        );
      });
    }
  }
});

for (const [profile, relativePath] of [
  ["provider-v1", "deploy/payment-v1/systemd/hetzner-provider.service.in"],
  [
    "provider-no-standard-cashu-v1",
    "deploy/payment-v1/systemd/hetzner-provider-no-standard-cashu.service.in",
  ],
  ["provider-direct-v1", "deploy/payment-v1/systemd/hetzner-provider-direct.service.in"],
]) {
  test(`${profile} is an explicit zero-retained closed template`, () => {
    withFixture((root) => {
      mutate(root, relativePath, (text) => text.replace(
        "    --max-connections 128",
        "    --service-retained-policy /private/retained-policy.bin \\\n    --max-connections 128",
      ));
      assert.throws(
        () => validateDeploymentTree(root),
        /zero-retained closed profile.*--service-retained-policy/,
      );
    });
  });
}

test("provider enforcement, ledger-only issuer and remote rollback are mandatory", () => {
  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-provider.service.in",
      (text) => text.replace("    --require-service-auth-v1 \\\n", ""),
    );
    assert.throws(
      () => validateDeploymentTree(root),
      /--require-service-auth-v1/,
    );
  });

  for (const [flag, expected] of [
    ["--clearing-payout-target 11=22", /production clearing payout target/],
    ["--clearing-payout-fee 1", /production clearing payout fee/],
    ["--clearing-payout-intent-ttl-seconds 60", /production payout intent TTL/],
  ]) {
    withFixture((root) => {
      mutate(
        root,
        "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
        (text) => text.replace(
          "    --issuer-settlement-signing-key",
          `    ${flag} \\\n    --issuer-settlement-signing-key`,
        ),
      );
      assert.throws(() => validateDeploymentTree(root), expected);
    });
  }

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-provider.service.in",
      (text) =>
        text.replace(
          "--service-remote-rollback-authority-config",
          "--service-rollback-authority",
        ),
    );
    assert.throws(() => validateDeploymentTree(root), /local provider rollback authority/);
  });

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-provider.service.in",
      (text) => text.replace(/^.*--service-shared-idempotency-key.*\n/m, ""),
    );
    assert.throws(
      () => validateDeploymentTree(root),
      /--service-shared-idempotency-key/,
    );
  });

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-provider.service.in",
      (text) =>
        text.replace(
          "cashu-custody-epoch-1.key",
          "cashu-recovery-epoch-1.key",
        ),
    );
    assert.throws(() => validateDeploymentTree(root), /--service-cashu-custody-key/);
  });
});

test("no-Standard-Cashu provider is an explicit closed method profile", () => {
  const provider =
    "deploy/payment-v1/systemd/hetzner-provider-no-standard-cashu.service.in";
  const source = readFileSync(join(REPOSITORY, provider), "utf8");
  assert.match(source, /--require-service-auth-v1/u);
  assert.match(source, /--service-bat-key/u);
  assert.match(source, /--service-shared-authorization/u);
  assert.doesNotMatch(
    source,
    /--service-cashu-(?:recovery|custody|exposure)/u,
  );

  for (const [mutation, expected] of [
    [
      (text) => text.replace(/^.*--service-bat-key.*\n/m, ""),
      /--service-bat-key/,
    ],
    [
      (text) => text.replace(/^.*--service-shared-idempotency-key.*\n/m, ""),
      /--service-shared-idempotency-key/,
    ],
    [
      (text) => text.replace(
        "    --max-connections 128",
        "    --service-cashu-exposure-limit 11:sat:1:1 \\\n    --max-connections 128",
      ),
      /--max-connections|ExecStart option set differs/,
    ],
  ]) {
    withFixture((root) => {
      mutate(root, provider, mutation);
      assert.throws(() => validateDeploymentTree(root), expected);
    });
  }
});

test("direct provider excludes every optional payment adapter", () => {
  const provider = "deploy/payment-v1/systemd/hetzner-provider-direct.service.in";
  const source = readFileSync(join(REPOSITORY, provider), "utf8");
  assert.match(source, /--require-service-auth-v1/u);
  assert.match(source, /--service-remote-rollback-authority-config/u);
  assert.doesNotMatch(
    source,
    /--service-(?:bat-key|cashu-[a-z-]+|shared-[a-z-]+|arc-key|free-ip-key|trust-direct-peer-ip)|--allow-experimental-arc/u,
  );

  for (const flag of [
    "--service-bat-key /private/bat.key",
    "--service-cashu-exposure-limit 11:sat:1:1",
    "--service-shared-authorization /private/shared.bin",
  ]) {
    withFixture((root) => {
      mutate(root, provider, (text) => text.replace(
        "    --max-connections 128",
        `    ${flag} \\\n    --max-connections 128`,
      ));
      assert.throws(
        () => validateDeploymentTree(root),
        /--max-connections|ExecStart option set differs/,
      );
    });
  }
});

test("production templates reject ARC, fake, local and proxied Free-IP flags", () => {
  const mutations = [
    ["--allow-experimental-arc", /experimental ARC/],
    ["--service-arc-key /private/arc.key", /provider ARC key/],
    ["--allow-local-service-rollback-authority-dev", /local provider rollback/],
    ["--service-free-ip-key /private/free-ip.key", /Free IP key behind a proxy/],
    ["--service-trust-direct-peer-ip", /direct peer-IP trust/],
    ["--test-only-service-https-root-pem /private/test.pem", /test-only trust root/],
  ];
  for (const relativePath of [
    "deploy/payment-v1/systemd/hetzner-provider.service.in",
    "deploy/payment-v1/systemd/hetzner-provider-no-standard-cashu.service.in",
    "deploy/payment-v1/systemd/hetzner-provider-direct.service.in",
  ]) {
    for (const [flag, expected] of mutations) {
      withFixture((root) => {
        mutate(
          root,
          relativePath,
          (text) => text.replace("    --max-connections 128", `    ${flag} \\\n    --max-connections 128`),
        );
        assert.throws(() => validateDeploymentTree(root), expected);
      });
    }
  }

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
      (text) => text.replace("payment-issuer serve-cln", "payment-issuer serve-fake"),
    );
    assert.throws(() => validateDeploymentTree(root), /fake Lightning serving mode/);
  });

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
      (text) => text.replace(/^.*--receipt-signing-key.*\n/m, ""),
    );
    assert.throws(
      () => validateDeploymentTree(root),
      /--receipt-signing-key/,
    );
  });

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
      (text) => text.replace(/^.*--clearing-approval.*\n/m, ""),
    );
    assert.throws(
      () => validateDeploymentTree(root),
      /--clearing-approval/,
    );
  });

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
      (text) => text.replace(/^.*--clearing-provider-request-verifying-key.*\n/m, ""),
    );
    assert.throws(
      () => validateDeploymentTree(root),
      /--clearing-provider-request-verifying-key/,
    );
  });

});

test("issuer and authority origins must remain loopback", () => {
  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
      (text) => text.replace("--bind 127.0.0.1:5610", "--bind 0.0.0.0:5610"),
    );
    assert.throws(() => validateDeploymentTree(root), /--bind must equal/);
  });

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/rollback-authority.service.in",
      (text) => text.replace("--bind 127.0.0.1:8099", "--bind 0.0.0.0:8099"),
    );
    assert.throws(() => validateDeploymentTree(root), /--bind must equal/);
  });
});

test("VPSBG fragment remains service-auth-only, exact-pinned and storeless Free-PoW-only", () => {
  for (const flag of [
    "--serve-hints",
    "--service-bat-key /home/pir/data/bat.key",
    "--service-cashu-recovery-key 1=/home/pir/data/recovery.key",
    "--service-shared-authorization /home/pir/data/shared.bin",
  ]) {
    withFixture((root) => {
      mutate(
        root,
        "deploy/payment-v1/vpsbg/vpsbg-free-pow-service-auth.args.in",
        (text) => `${text}\n${flag}\n`,
      );
      assert.throws(
        () => validateDeploymentTree(root),
        /unreviewed|canonical order|forbidden Free IP/,
      );
    });
  }

  for (const forbidden of [
    "--service-store /home/pir/data/provider.sqlite3",
    "--service-remote-rollback-authority-config /home/pir/data/authority.toml",
    "--service-free-ip-key /home/pir/data/free-ip.key",
  ]) {
    withFixture((root) => {
      mutate(
        root,
        "deploy/payment-v1/vpsbg/vpsbg-free-pow-service-auth.args.in",
        (text) => `${text}\n${forbidden}\n`,
      );
      assert.throws(
        () => validateDeploymentTree(root),
        /unreviewed|canonical order|forbidden Free IP/,
      );
    });
  }

  for (const [line, expected] of [
    ["#!/bin/sh", /shebang/],
    ["exec /usr/local/bin/unified_server", /exec command/],
    ["--direct-oram-db 0=/wrong/path", /canonical order|unreviewed/],
  ]) {
    withFixture((root) => {
      mutate(
        root,
        "deploy/payment-v1/vpsbg/vpsbg-free-pow-service-auth.args.in",
        (text) => `${line}\n${text}`,
      );
      assert.throws(() => validateDeploymentTree(root), expected);
    });
  }

  withFixture((root) => {
    mutate(
      root,
      "docs/payment/HETZNER_VPSBG_DEPLOYMENT.md",
      (text) => text.replaceAll("P1 activation blocker", "deployment note"),
    );
    assert.throws(() => validateDeploymentTree(root), /P1 activation blocker/);
  });
});

test("systemd resets, duplicate CLI overrides, and secret argv fail closed", () => {
  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-provider.service.in",
      (text) => text.replace("[Service]", "ConditionPathExists=\n\n[Service]"),
    );
    assert.throws(() => validateDeploymentTree(root), /empty ConditionPathExists= reset/);
  });

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-provider.service.in",
      (text) => `${text}\nExecStart=\nExecStart=/usr/bin/true\n`,
    );
    assert.throws(() => validateDeploymentTree(root), /empty ExecStart= reset/);
  });

  for (const injected of [
    "--bind-address 0.0.0.0",
    "--direct-oram-key-hex deadbeef",
  ]) {
    withFixture((root) => {
      mutate(
        root,
        "deploy/payment-v1/systemd/hetzner-provider.service.in",
        (text) =>
          text.replace(
            "    --service-pre-auth-timeout-ms 60000",
            `    --service-pre-auth-timeout-ms 60000 \\\n    ${injected}`,
          ),
      );
      assert.throws(
        () => validateDeploymentTree(root),
        /unreviewed, duplicate, or positional argv value/,
      );
    });
  }
});

test("systemd hardening values and relay environment are exact", () => {
  const providerMutations = [
    ["User=bitcoinpir-provider", "User=root", /Service\.User must equal/],
    ["UMask=0077", "UMask=0000", /Service\.UMask must equal/],
    ["PrivateTmp=true", "PrivateTmp=false", /Service\.PrivateTmp must equal/],
    [
      "ProtectKernelLogs=true",
      "ProtectKernelLogs=false",
      /Service\.ProtectKernelLogs must equal/,
    ],
    [
      "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
      "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET",
      /Service\.RestrictAddressFamilies must equal/,
    ],
    [
      "ReadWritePaths=/var/lib/bitcoinpir-provider-payment-v1",
      "ReadWritePaths=/",
      /Service\.ReadWritePaths must equal/,
    ],
  ];
  for (const [before, after, expected] of providerMutations) {
    withFixture((root) => {
      mutate(
        root,
        "deploy/payment-v1/systemd/hetzner-provider.service.in",
        (text) => text.replace(before, after),
      );
      assert.throws(() => validateDeploymentTree(root), expected);
    });
  }

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-directory-relay.service.in",
      (text) => text.replace("Environment=RUST_LOG=error", "Environment=LD_PRELOAD=/tmp/evil.so"),
    );
    assert.throws(
      () => validateDeploymentTree(root),
      /Service\.Environment must equal/,
    );
  });

  for (const [before, after, expected] of [
    ["ProtectProc=invisible", "ProtectProc=default", /Service\.ProtectProc must equal/u],
    ["ProcSubset=pid", "ProcSubset=all", /Service\.ProcSubset must equal/u],
  ]) {
    withFixture((root) => {
      mutate(
        root,
        "deploy/payment-v1/systemd/hetzner-directory-relay.service.in",
        (text) => text.replace(before, after),
      );
      assert.throws(() => validateDeploymentTree(root), expected);
    });
  }
});

test("edge and Lightning templates reject reviewed P1 bypass mutations", () => {
  const mutations = [
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => text.replace(
        "reverse_proxy unix//run/bitcoinpir-source-fair-edge/provider.sock",
        "reverse_proxy attacker.example:443",
      ),
      /reverse_proxy upstream multiset|non-reviewed upstream/,
    ],
    [
      "deploy/payment-v1/lightning/lightningd.conf.in",
      (text) => text.replace("disable-plugin=commando", "plugin=/tmp/evil-plugin"),
      /closed-world configuration|dynamic plugin/,
    ],
    [
      "deploy/payment-v1/lightning/lightningd.conf.in",
      (text) => text.replace("disable-plugin=commando\n", ""),
      /closed-world configuration/,
    ],
    [
      "deploy/payment-v1/lightning/lightningd.conf.in",
      (text) => text.replace(
        "disable-plugin=commando",
        "disable-plugin=commando\ndisable-plugin=commando",
      ),
      /closed-world configuration/,
    ],
    [
      "deploy/payment-v1/lightning/lightningd.conf.in",
      (text) => text.replace(
        "disable-plugin=commando",
        "clear-plugins\ndisable-plugin=commando",
      ),
      /closed-world configuration|dynamic plugin/,
    ],
    [
      "deploy/payment-v1/lightning/lightningd.conf.in",
      (text) => text.replace(
        "disable-dns",
        "disable-dns\ninvoices-onchain-fallback=false",
      ),
      /closed-world configuration|on-chain invoice fallback/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      (text) => text.replace(
        "/opt/bitcoinpir/bpir-admin/@BPIR_ADMIN_SHA256@/bpir-admin lightning-staging preflight-supervisor",
        "/usr/bin/true",
      ),
      /command prefix/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      (text) => text.replace("StateDirectoryMode=0700", "StateDirectoryMode=0750"),
      /StateDirectoryMode must equal/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      (text) => text.replace("--config-expected-uid 0", "--config-expected-uid @PREFLIGHT_UID@"),
      /--config-expected-uid|argument set/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      (text) => text.replace("--config-reader-expected-uid @PREFLIGHT_UID@", ""),
      /--config-reader-expected-uid|argument set|Service directive keys/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      (text) => text.replace(" /var/lib/bitcoinpir-lightning-preflight", ""),
      /ReadOnlyPaths must equal/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      (text) => text.replace("Type=notify", "Type=oneshot"),
      /Service\.Type must equal/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      (text) => text.replace("WatchdogSec=90", "WatchdogSec=0"),
      /WatchdogSec must equal/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      (text) => text.replace("Restart=no", "Restart=on-failure"),
      /Restart must equal/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      (text) => text.replace(" /run/systemd/units", ""),
      /ReadOnlyPaths must equal/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      (text) => text.replace(
        "ReadWritePaths=/run/bitcoinpir-lightning-preflight",
        "ReadWritePaths=/run",
      ),
      /ReadWritePaths must equal/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
      (text) => text.replace(" bitcoinpir-lightning-preflight.service", ""),
      /Unit\.(?:After|Requires|BindsTo) must equal/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
      (text) => text.replace("User=bitcoinpir-lightning", "User=root"),
      /Service\.User must equal/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
      (text) => text.replace(
        "InaccessiblePaths=/srv/lightning/plugins\n",
        "",
      ),
      /InaccessiblePaths|Service directive keys/,
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-edge.service.in",
      (text) => text.replace(
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SYS_ADMIN",
      ),
      /Service\.CapabilityBoundingSet must equal/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-provider.service.in",
      (text) => text.replace("PrivateDevices=true", "PrivateDevices=false"),
      /Service\.PrivateDevices must equal/,
    ],
  ];
  for (const [relativePath, transform, expected] of mutations) {
    withFixture((root) => {
      mutate(root, relativePath, transform);
      assert.throws(() => validateDeploymentTree(root), expected);
    });
  }

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/lightning/activation-prerequisites.toml.example",
      (text) => text.replace("real_funds_authorized = false", "real_funds_authorized = true"),
    );
    assert.throws(() => validateDeploymentTree(root), /real_funds_authorized must equal false/);
  });

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
      (text) => text.replace(
        "Requires=bitcoinpir-core-lightning.service bitcoinpir-cln-rpc-guard.service bitcoinpir-lightning-preflight.service\n",
        "",
      ),
    );
    assert.throws(
      () => validateDeploymentTree(root),
      /Unit directive keys|Unit\.Requires must equal/,
    );
  });
});

test("public issuer edge exposes ledger accrual only", () => {
  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => text.replace(
        "path /v1/redeems /v1/settlement/balance",
        "path /v1/redeems /v1/settlement/balance /v1/settlement/payouts",
      ),
    );
    assert.throws(
      () => validateDeploymentTree(root),
      /production payout route/,
    );
  });
});

test("integrated existing-Caddy managed block rejects trust and privacy bypasses", () => {
  const path =
    "deploy/payment-v1/edge/integrated-existing-bhtm-caddy.managed.Caddyfile.in";
  for (const [transform, expected] of [
    [
      (text) => `{\n\tadmin off\n}\n${text}`,
      /global options block|four reviewed hostname blocks/,
    ],
    [
      (text) => text.replace("header_up -*", "header_up Authorization {http.request.header.Authorization}"),
      /header_up -\*|auth/,
    ],
    [
      (text) => text.replace(
        "reverse_proxy unix//run/bitcoinpir-source-fair-edge/provider.sock",
        "reverse_proxy 127.0.0.1:8191",
      ),
      /source-fair Unix socket|direct application bypass/,
    ],
    [
      (text) => text.replace("proxy_protocol v2", "proxy_protocol v1"),
      /proxy_protocol v2/,
    ],
    [
      (text) => text.replace('respond "" 404', 'respond "" 200'),
      /respond.*404/,
    ],
    [
      (text) => text.replace(
        "@PROVIDER_WSS_HOST@ {",
        "@PROVIDER_WSS_HOST@ {\n\tlog",
      ),
      /access logging/,
    ],
    [
      (text) => text.replace(
        "bind @DIRECTORY_PUBLISHER_PRIVATE_BIND@",
        "bind @PUBLIC_HTTPS_BIND@",
      ),
      /PUBLIC_HTTPS_BIND.*exactly 3|PRIVATE_BIND.*exactly 1/,
    ],
    [
      (text) => text.replace("\t\tpath /\n", "\t\tpath /v1/directory\n"),
      /public directory site.*origin-root path/,
    ],
  ]) {
    withFixture((root) => {
      mutate(root, path, transform);
      assert.throws(() => validateDeploymentTree(root), expected);
    });
  }
});

test("directory-public static edge rejects notify, restart and dynamic artifact drift", () => {
  const mutations = [
    [
      "deploy/payment-v1/systemd/payment-v1-directory-public-edge.service.in",
      (text) => text.replace("Type=exec", "Type=notify"),
      /Service\.Type must equal/u,
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-directory-public-edge.service.in",
      (text) => text.replace("-W -db", "-Ws -db"),
      /static|systemd-notify|ExecStart/u,
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-directory-public-edge.service.in",
      (text) => text.replace("Restart=no", "Restart=on-failure\nRestartSec=5"),
      /Service directive keys|Restart must equal|restart/u,
    ],
    [
      "deploy/payment-v1/edge/directory-public-haproxy.cfg.in",
      (text) => `${text}\nresolvers ambient_dns\n  nameserver dns 127.0.0.53:53\n`,
      /not a reviewed section|section order/u,
    ],
    [
      "deploy/payment-v1/edge/directory-public-haproxy-build-manifest.json.in",
      (text) => text.replace("2.8.26.tar.gz", "2.8.25.tar.gz"),
      /build manifest source/u,
    ],
  ];
  for (const [relativePath, transform, expected] of mutations) {
    withFixture((root) => {
      mutate(root, relativePath, transform);
      assert.throws(() => validateDeploymentTree(root), expected);
    });
  }
});

test("source-fair edge rejects identity leaks, persistence, bypasses, and unbounded lanes", () => {
  const mutations = [
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => text.replace("proxy_protocol v2", "proxy_protocol v1"),
      /proxy_protocol v2|PROXY v2/,
    ],
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => text.replace(
        /(https:\/\/:443 \{[\s\S]*?)respond "" 404/u,
        '$1respond "" 200',
      ),
      /no-host fallback site.*respond/,
    ],
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => text.replace(
        "@DIRECTORY_PUBLISHER_HTTPS_HOST@ {\n\tbind @DIRECTORY_PUBLISHER_PRIVATE_BIND@",
        "@DIRECTORY_PUBLISHER_HTTPS_HOST@ {\n\tbind @DIRECTORY_PUBLISHER_PRIVATE_BIND@\n\tbind @PUBLIC_HTTPS_BIND@",
      ),
      /site binds must equal/,
    ],
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => text.replace("\t\tpath /\n", "\t\tpath /v1/directory\n"),
      /public directory site.*path/,
    ],
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => `(extra_public_bind) {\n\tbind @PUBLIC_HTTPS_BIND@\n}\nimport extra_public_bind\n${text}`,
      /import\/invoke expansion|snippet or named route/,
    ],
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => `import /etc/bitcoinpir/payment-v1/edge/optional/*.Caddyfile\n${text}`,
      /import\/invoke expansion/,
    ],
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => `${text}\nhttps://0.0.0.0:444 { respond "" 404 }\n`,
      /top-level block headers must equal/,
    ],
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => `${text}\n&(cross_lane) {\n\treverse_proxy unix//run/bitcoinpir-source-fair-edge/provider.sock {\n\t\ttransport http {\n\t\t\tproxy_protocol v1\n\t\t}\n\t}\n}\ninvoke cross_lane\n`,
      /import\/invoke expansion|snippet or named route/,
    ],
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => text.replace(
        "@DIRECTORY_PUBLISHER_HTTPS_HOST@ {",
        "@DIRECTORY_PUBLISHER_HTTPS_HOST@ {\n\treverse_proxy unix//run/bitcoinpir-source-fair-edge/provider.sock {\n\t}",
      ),
      /reverse_proxy upstream multiset must equal/,
    ],
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => text.replace("header_up -*", "header_up X-Forwarded-For {http.request.remote.host}"),
      /clear all client headers|header_up -\*|source or correlation header/,
    ],
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => text.replace(
        "header_up -*",
        "header_up -*\n\t\t\theader_up CF-Connecting-IP {http.request.remote.host}",
      ),
      /source identity header forwarding/,
    ],
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => text
        .replaceAll("directory-public.sock", "directory-lane-swap.sock")
        .replaceAll("directory-publisher.sock", "directory-public.sock")
        .replaceAll("directory-lane-swap.sock", "directory-publisher.sock"),
      /site upstreams must equal/,
    ],
    [
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      (text) => text
        .replace(
          "@DIRECTORY_RELAY_WSS_HOST@ {\n\tbind @PUBLIC_HTTPS_BIND@",
          "@DIRECTORY_RELAY_WSS_HOST@ {\n\tbind @DIRECTORY_PUBLISHER_PRIVATE_BIND@",
        )
        .replace(
          "@DIRECTORY_PUBLISHER_HTTPS_HOST@ {\n\tbind @DIRECTORY_PUBLISHER_PRIVATE_BIND@",
          "@DIRECTORY_PUBLISHER_HTTPS_HOST@ {\n\tbind @PUBLIC_HTTPS_BIND@",
        ),
      /site binds must equal/,
    ],
    [
      "deploy/payment-v1/edge/source-fair-haproxy.cfg.in",
      (text) => text.replace("    no log\n", "    log stdout format raw local0\n"),
      /no log|logging|persistent/,
    ],
    [
      "deploy/payment-v1/edge/source-fair-haproxy.cfg.in",
      (text) => text.replace(
        "http-request deny deny_status 404 unless { path -m str / }",
        "http-request deny deny_status 404 unless { path -m str /v1/directory }",
      ),
      /exact origin-root path/,
    ],
    [
      "deploy/payment-v1/edge/source-fair-haproxy.cfg.in",
      (text) => text.replace("expire 2m nopurge", "expire 24h"),
      /bounded|expiring|nopurge|stick-table/,
    ],
    [
      "deploy/payment-v1/edge/source-fair-haproxy.cfg.in",
      (text) => text.replace(
        "    http-request deny deny_status 429 unless { sc0_tracked }\n",
        "",
      ),
      /immediately reject|post-allocation tracking guards/,
    ],
    [
      "deploy/payment-v1/edge/source-fair-haproxy.cfg.in",
      (text) => text.replace(
        "server provider 127.0.0.1:8191 maxconn 128",
        "server provider 127.0.0.1:8191 maxconn 128 send-proxy-v2",
      ),
      /PROXY|source|application backend/,
    ],
    [
      "deploy/payment-v1/edge/source-fair-haproxy.cfg.in",
      (text) => text.replace(
        "server provider 127.0.0.1:8191 maxconn 128",
        "server provider 127.0.0.1:8191 maxconn 128\n    server observer 127.0.0.1:8192",
      ),
      /exactly the four reviewed source-free loopback application peers/,
    ],
    [
      "deploy/payment-v1/edge/source-fair-haproxy.cfg.in",
      (text) => text.replace("    http-request del-header CF-Connecting-IP\n", ""),
      /delete CF-Connecting-IP independently on all four application lanes/,
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-source-fair-edge.service.in",
      (text) => text.replace(
        "RuntimeDirectory=bitcoinpir-source-fair-edge",
        "StateDirectory=bitcoinpir-source-fair-edge\nRuntimeDirectory=bitcoinpir-source-fair-edge",
      ),
      /StateDirectory|directive keys/,
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-public-edge.service.in",
      (text) => text.replace(
        "Requires=bitcoinpir-payment-v1-source-fair-edge.service\n",
        "",
      ),
      /Requires|directive keys/,
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-public-edge.service.in",
      (text) => text.replace("StandardOutput=null", "StandardOutput=journal"),
      /StandardOutput/,
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-source-fair-edge.service.in",
      (text) => text.replace("StandardError=null", "StandardError=journal"),
      /StandardError/,
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-public-edge.service.in",
      (text) => text.replace("LimitCORE=0", "LimitCORE=infinity"),
      /LimitCORE/,
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-source-fair-edge.service.in",
      (text) => text.replace("MemorySwapMax=0", "MemorySwapMax=infinity"),
      /MemorySwapMax/,
    ],
    [
      "deploy/payment-v1/edge/rollback-authority.Caddyfile.in",
      (text) => text.replace("\tbind @ROLLBACK_AUTHORITY_PRIVATE_BIND@\n", ""),
      /ROLLBACK_AUTHORITY_PRIVATE_BIND|bind/,
    ],
    [
      "deploy/payment-v1/edge/rollback-authority.Caddyfile.in",
      (text) => text.replace(
        "\ttls /etc/bitcoinpir/payment-v1/edge/rollback-authority-server.crt /etc/bitcoinpir/payment-v1/edge/rollback-authority-server.key\n",
        "",
      ),
      /rollback-authority-server|tls/,
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-edge.service.in",
      (text) => text.replace(
        "IPAddressAllow=localhost @ROLLBACK_AUTHORITY_CLIENT_IP@",
        "IPAddressAllow=localhost",
      ),
      /ROLLBACK_AUTHORITY_CLIENT_IP|IPAddressAllow/,
    ],
    [
      "deploy/payment-v1/systemd/payment-v1-edge.service.in",
      (text) => text.replace(
        "RuntimeDirectory=bitcoinpir-rollback-authority-edge",
        "StateDirectory=bitcoinpir-rollback-authority-edge\nRuntimeDirectory=bitcoinpir-rollback-authority-edge",
      ),
      /StateDirectory|directive keys/,
    ],
  ];
  for (const [relativePath, transform, expected] of mutations) {
    withFixture((root) => {
      mutate(root, relativePath, transform);
      assert.throws(() => validateDeploymentTree(root), expected);
    });
  }
});

test("CLN guard and cross-UID isolation reject topology regressions", () => {
  const mutations = [
    [
      "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
      (text) => text.replace("--max-invoice-msat", "--unsafe-max-invoice-msat"),
      /--max-invoice-msat|argument set/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
      (text) => text.replace("--max-invoices-per-minute", "--unsafe-max-invoices-per-minute"),
      /--max-invoices-per-minute|argument set/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
      (text) => text.replace("--max-invoice-burst", "--unsafe-max-invoice-burst"),
      /--max-invoice-burst|argument set/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
      (text) => text.replace("--max-invoices-per-runtime", "--unsafe-max-invoices-per-runtime"),
      /--max-invoices-per-runtime|argument set/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
      (text) => text.replace("Restart=no", "Restart=on-failure"),
      /Service\.Restart must equal/,
    ],
    [
      "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in",
      (text) => text.replace("0710 bitcoinpir-cln-rpc-guard", "0700 bitcoinpir-cln-rpc-guard"),
      /closed-world layout/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
      (text) => text.replace(
        "Group=bitcoinpir-issuer\n",
        "Group=bitcoinpir-issuer\nSupplementaryGroups=bitcoinpir-cln-guard\n",
      ),
      /Service directive keys/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
      (text) => text.replace(
        "InaccessiblePaths=-/srv/lightning -/srv/bitcoin -/run/bitcoinpir-source-fair-edge\n",
        "",
      ),
      /InaccessiblePaths/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      (text) => text.replace("User=bitcoinpir-lightning-preflight", "User=bitcoinpir-issuer"),
      /Service\.User must equal/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
      (text) => text.replace("SupplementaryGroups=bitcoinpir-bitcoin-rpc\n", ""),
      /SupplementaryGroups/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
      (text) => text.replace(
        "Environment=LD_LIBRARY_PATH=/opt/bitcoinpir/core-lightning-libpq/@CLN_LIBPQ_SHA256@",
        "Environment=LD_PRELOAD=/tmp/evil.so",
      ),
      /Service\.Environment must equal/,
    ],
    [
      "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
      (text) => text.replace("User=bitcoinpir-cln-rpc-guard", "User=root"),
      /Service\.User must equal/,
    ],
    ...[
      "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
    ].map((sourcePath) => [
      sourcePath,
      (text) => text.replace(
        "ConditionPathExists=/etc/bitcoinpir/payment-v1/CLN-LOADER-MAPS-APPROVED\n",
        "",
      ),
      /ConditionPathExists/,
    ]),
    [
      "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
      (text) => text.replace(
        "ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-IDENTITY-RESTORE-APPROVED\n",
        "ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-IDENTITY-RESTORE-APPROVED\n" +
          "ConditionPathExists=/etc/bitcoinpir/payment-v1/CLN-LOADER-MAPS-APPROVED\n",
      ),
      /ConditionPathExists/,
    ],
    [
      "deploy/payment-v1/lightning/verify-layout.sh.in",
      (text) => text.replace(":400:32\" ] || bpir_fail", ":600:32\" ] || bpir_fail"),
      /exact native hsm_secret boundary/,
    ],
    [
      "deploy/payment-v1/lightning/verify-layout.sh.in",
      (text) => text.replace(
        '[ -f "${bpir_hsm_secret}" ] && [ ! -L "${bpir_hsm_secret}" ] || bpir_fail',
        ': # omitted restored identity check',
      ),
      /exact native hsm_secret boundary/,
    ],
    [
      "deploy/payment-v1/lightning/verify-layout.sh.in",
      (text) => text.replace(
        '    "${bpir_lightning_dir}/config" \\\n',
        '    "${bpir_lightning_base}/plugins" \\\n' +
          '    "${bpir_lightning_dir}/config" \\\n',
      ),
      /must reject only the exact unmasked config and network-local plugin lookalikes/,
    ],
    [
      "deploy/payment-v1/lightning/verify-layout.sh.in",
      (text) => text.replace(
        '    "${bpir_lightning_dir}/plugins"\n',
        "",
      ),
      /must reject only the exact unmasked config and network-local plugin lookalikes/,
    ],
  ];

  for (const [relativePath, transform, expected] of mutations) {
    withFixture((root) => {
      mutate(root, relativePath, transform);
      assert.throws(() => validateDeploymentTree(root), expected);
    });
  }
});

test("reviewed edge and Lightning source bytes are frozen", () => {
  for (const relativePath of [
    "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
    "deploy/payment-v1/lightning/verify-layout.sh.in",
    "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
  ]) {
    withFixture((root) => {
      mutate(root, relativePath, (text) => `${text}\n# unreviewed but semantic no-op\n`);
      assert.throws(
        () => validateDeploymentTree(root),
        /reviewed deployment source SHA-256 changed/,
      );
    });
  }
});

test("relay selection is explicitly resolved and rejects unsafe implementations", () => {
  const checkedIn = readFileSync(
    join(REPOSITORY, "deploy/payment-v1/relay-selection.toml.example"),
    "utf8",
  );
  const resolved = validateRelaySelection(checkedIn);
  assert.equal(resolved.status, "RESOLVED");
  assert.equal(resolved.directoryMode, "centralized-single-relay");
  assert.equal(
    resolved.sourceCommit,
    "d60d5b5f0949d64a6e8350d80b8ed385d5dbb26d",
  );
  const unresolved = unresolvedRelaySelection(checkedIn);
  assert.deepEqual(validateRelaySelection(unresolved), { status: "UNRESOLVED" });

  assert.throws(
    () => validateRelaySelection(`${unresolved}\nunreviewed_field = true\n`),
    /fields must equal/,
  );

  const thirdParty = replaceRelayField(
    unresolved,
    "implementation",
    "nostr-rs-relay",
  );
  assert.throws(() => validateRelaySelection(thirdParty), /refuses nostr-rs-relay/);

  const unsafePin = resolvedRelaySelection(unresolved, {
    source_commit: "ff65ec2acd781150a585a78e1c60b0cdb104698e",
  });
  assert.throws(() => validateRelaySelection(unsafePin), /refuses audited unsafe commit/);

  const mutable = resolvedRelaySelection(unresolved, { source_commit: "master" });
  assert.throws(() => validateRelaySelection(mutable), /full lowercase 40-hex commit/);

  const zeroPublisher = resolvedRelaySelection(unresolved, {
    publisher_pubkey_hex: "0".repeat(64),
  });
  assert.throws(() => validateRelaySelection(zeroPublisher), /must be non-zero/);

  for (const invalidPublisher of ["06".repeat(32), "ff".repeat(32)]) {
    assert.throws(
      () => validateRelaySelection(resolvedRelaySelection(unresolved, {
        publisher_pubkey_hex: invalidPublisher,
      })),
      /must be a valid secp256k1 x-only key/,
    );
  }

  const zeroArtifactHash = resolvedRelaySelection(unresolved, {
    build_manifest_sha256: "0".repeat(64),
  });
  assert.throws(() => validateRelaySelection(zeroArtifactHash), /non-zero lowercase SHA-256/);

  const implicitOrUnknownMode = resolvedRelaySelection(unresolved, {
    directory_mode: "single",
  });
  assert.throws(
    () => validateRelaySelection(implicitOrUnknownMode),
    /directory_mode must be strict-multi-relay or centralized-single-relay/,
  );

  assert.equal(
    validateRelaySelection(resolvedRelaySelection(unresolved, {
      directory_mode: "centralized-single-relay",
    })).directoryMode,
    "centralized-single-relay",
  );
});

test("a future directory-only exact-hash relay selection is accepted", () => {
  const checkedIn = readFileSync(
    join(REPOSITORY, "deploy/payment-v1/relay-selection.toml.example"),
    "utf8",
  );
  const unresolved = unresolvedRelaySelection(checkedIn);
  assert.deepEqual(validateRelaySelection(resolvedRelaySelection(unresolved)), {
    status: "RESOLVED",
    directoryMode: "strict-multi-relay",
    sourceCommit: "1".repeat(40),
    sourceArchiveSha256: "2".repeat(64),
    cargoLockSha256: "3".repeat(64),
    buildManifestSha256: "7".repeat(64),
    binarySha256: "4".repeat(64),
    binaryVersionOutput: "bitcoinpir-directory-relay 0.1.0",
    configSha256: "5".repeat(64),
    publisherPubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  });

  withFixture((root) => assert.equal(validateDeploymentTree(root), true));

  withFixture((root) => {
    mutate(
      root,
      "deploy/payment-v1/systemd/hetzner-directory-relay.service.in",
      (text) =>
        text.replace(
          " --config /etc/bitcoinpir/payment-v1/directory-relay/config.toml",
          " --config /etc/bitcoinpir/payment-v1/directory-relay/config.toml --listen 0.0.0.0:8080",
        ),
    );
    assert.throws(() => validateDeploymentTree(root), /only the pinned binary and one absolute --config path/);
  });
});

test("any active unit or measured runit mutation fails the frozen baseline", () => {
  for (const relativePath of Object.keys(ACTIVE_BASELINES)) {
    withFixture((root) => {
      mutate(root, relativePath, (text) => `${text}\n# unauthorized mutation\n`);
      assert.throws(
        () => validateDeploymentTree(root),
        new RegExp(`active deployment file changed.*${relativePath.replaceAll("/", "\\/")}`),
      );
    });
  }
});

test("activatable or executable files are forbidden in the template tree", () => {
  withFixture((root) => {
    const path = join(root, "deploy/payment-v1/systemd/accidental.service");
    writeFileSync(path, "[Service]\nExecStart=/usr/bin/true\n", "utf8");
    assert.throws(() => validateDeploymentTree(root), /activatable unit\/script/);
  });

  withFixture((root) => {
    const path = join(root, "deploy/payment-v1/runit/replacement.run.in");
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, "exec /usr/local/bin/unified_server\n", "utf8");
    assert.throws(() => validateDeploymentTree(root), /unreviewed file type/);
  });

  withFixture((root) => {
    const path = join(root, "deploy/payment-v1/vpsbg/vpsbg-free-pow-service-auth.args.in");
    chmodSync(path, 0o755);
    assert.throws(() => validateDeploymentTree(root), /must not be executable/);
  });
});
