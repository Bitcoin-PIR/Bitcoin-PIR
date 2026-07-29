import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildManifestFromFacts,
  collectBuildArtifactFacts,
  DIRECTORY_RELAY_BUILD_IMAGE,
  DIRECTORY_RELAY_PINNED_GIT_GLOBAL_OPTIONS,
  DIRECTORY_RELAY_UNPRIVILEGED_GID,
  DIRECTORY_RELAY_UNPRIVILEGED_UID,
  requireWritableBindHostIdentity,
  pinnedDockerRun,
  assertCanonicalDirectoryChainUnchangedV1,
  snapshotCanonicalDirectoryChainV1,
  validateBuildManifest,
  validateDockerMountHostPath,
  validateSelectionBindings,
  verifyBuildArtifactSet,
} from "./payment-v1-directory-relay-artifact-gate.mjs";
import { canonicalJson } from "./payment-v1-rendered-artifact-gate.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const HAS_NATIVE_RUSTC =
  spawnSync("rustc", ["--version"], { encoding: "utf8" }).status === 0;

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function clone(value) {
  return structuredClone(value);
}

function facts() {
  return {
    binaryVersionOutput: "bitcoinpir-directory-relay 0.1.0",
    digests: {
      build1: hash("binary"),
      build2: hash("binary"),
      cargoLock: hash("Cargo.lock"),
      gitVersion: hash("git version 2.39.5\n"),
      selected: hash("binary"),
      sourceArchive: hash("source.tar"),
      tarVersion: hash("tar (GNU tar) 1.34\n"),
    },
    gitVersionOutput: "git version 2.39.5",
    sourceCommit: "1".repeat(40),
    tarVersionOutput: "tar (GNU tar) 1.34",
  };
}

function selectionFor(buildFacts, manifestBytes, configBytes) {
  return {
    binarySha256: buildFacts.digests.selected,
    binaryVersionOutput: buildFacts.binaryVersionOutput,
    buildManifestSha256: hash(manifestBytes),
    cargoLockSha256: buildFacts.digests.cargoLock,
    configSha256: hash(configBytes),
    publisherPubkey: "2".repeat(64),
    sourceArchiveSha256: buildFacts.digests.sourceArchive,
    sourceCommit: buildFacts.sourceCommit,
    status: "RESOLVED",
  };
}

test("build manifest is deterministic and exactly binds two clean amd64 builds", () => {
  const buildFacts = facts();
  const first = buildManifestFromFacts(buildFacts);
  const second = buildManifestFromFacts(clone(buildFacts));
  assert.equal(canonicalJson(first), canonicalJson(second));
  assert.equal(validateBuildManifest(first, buildFacts), true);
  assert.equal(first.build.container_image, DIRECTORY_RELAY_BUILD_IMAGE);
  assert.equal(first.build.docker_platform, "linux/amd64");
  assert.equal(first.build.docker_network, "none");
  assert.equal(first.reproducibility.clean_build_count, 2);
  assert.equal(first.reproducibility.byte_identical, true);
  assert.equal(first.reproducibility.verifier_clean_rebuild_count, 2);
  assert.equal(first.reproducibility.verifier_rebuilds_match_selected, true);
  assert.equal(first.binaries[0].sha256, first.binaries[1].sha256);
  assert.equal(first.binaries[0].sha256, first.selected_binary.sha256);
  assert.equal(first.source_toolchain.container_image, DIRECTORY_RELAY_BUILD_IMAGE);
  assert.equal(
    first.source_toolchain.git_input_profile,
    "minimal-bare-copied-objects-no-alternates-v1",
  );
  assert.equal(first.source_toolchain.git.version_output, buildFacts.gitVersionOutput);
  assert.equal(first.source_toolchain.tar.version_output, buildFacts.tarVersionOutput);
});

for (const [label, mutate] of [
  ["unknown manifest field", (manifest) => { manifest.unreviewed = true; }],
  ["source commit drift", (manifest) => { manifest.source_commit = "2".repeat(40); }],
  ["archive digest drift", (manifest) => { manifest.source_archive.sha256 = hash("other archive"); }],
  ["Cargo.lock digest drift", (manifest) => { manifest.cargo_lock.sha256 = hash("other lock"); }],
  ["first binary drift", (manifest) => { manifest.binaries[0].sha256 = hash("other binary"); }],
  ["second binary drift", (manifest) => { manifest.binaries[1].sha256 = hash("other binary"); }],
  ["selected binary drift", (manifest) => { manifest.selected_binary.sha256 = hash("other binary"); }],
  ["version drift", (manifest) => { manifest.selected_binary.version_output = "bitcoinpir-directory-relay 9.9.9"; }],
  ["container drift", (manifest) => { manifest.build.container_image = "rust:latest"; }],
  ["platform drift", (manifest) => { manifest.build.docker_platform = "linux/arm64"; }],
  ["network drift", (manifest) => { manifest.build.docker_network = "bridge"; }],
  ["source Git version drift", (manifest) => { manifest.source_toolchain.git.version_output = "git version 9.9.9"; }],
  ["source Tar version drift", (manifest) => { manifest.source_toolchain.tar.version_output = "tar (GNU tar) 9.9"; }],
  ["source toolchain image drift", (manifest) => { manifest.source_toolchain.container_image = "rust:latest"; }],
  ["source Git input profile drift", (manifest) => { manifest.source_toolchain.git_input_profile = "ambient-repository-v1"; }],
  ["single build claim", (manifest) => { manifest.reproducibility.clean_build_count = 1; }],
  ["single verifier rebuild claim", (manifest) => { manifest.reproducibility.verifier_clean_rebuild_count = 1; }],
  ["non-identical claim", (manifest) => { manifest.reproducibility.byte_identical = false; }],
]) {
  test(`build manifest rejects ${label}`, () => {
    const buildFacts = facts();
    const manifest = buildManifestFromFacts(buildFacts);
    mutate(manifest);
    assert.throws(() => validateBuildManifest(manifest, buildFacts));
  });
}

test("resolved selection binds manifest, archive, lockfile, binary, version and config bytes", () => {
  const buildFacts = facts();
  const manifest = buildManifestFromFacts(buildFacts);
  const buildManifestBytes = Buffer.from(canonicalJson(manifest));
  const configBytes = Buffer.from("profile = \"bitcoinpir-directory-relay-v1\"\n");
  const selection = selectionFor(buildFacts, buildManifestBytes, configBytes);
  assert.equal(validateSelectionBindings({
    buildManifestBytes,
    configBytes,
    facts: buildFacts,
    manifest,
    selection,
  }), true);
});

for (const [label, mutate] of [
  ["unresolved status", ({ selection }) => { selection.status = "UNRESOLVED"; }],
  ["manifest digest", ({ selection }) => { selection.buildManifestSha256 = hash("other manifest"); }],
  ["source commit", ({ selection }) => { selection.sourceCommit = "3".repeat(40); }],
  ["archive digest", ({ selection }) => { selection.sourceArchiveSha256 = hash("other archive"); }],
  ["Cargo.lock digest", ({ selection }) => { selection.cargoLockSha256 = hash("other lock"); }],
  ["binary digest", ({ selection }) => { selection.binarySha256 = hash("other binary"); }],
  ["binary version", ({ selection }) => { selection.binaryVersionOutput = "bitcoinpir-directory-relay 0.2.0"; }],
  ["config bytes", (fixture) => { fixture.configBytes = Buffer.from("changed\n"); }],
]) {
  test(`selection binding rejects ${label} drift`, () => {
    const buildFacts = facts();
    const manifest = buildManifestFromFacts(buildFacts);
    const buildManifestBytes = Buffer.from(canonicalJson(manifest));
    const configBytes = Buffer.from("config\n");
    const fixture = {
      buildManifestBytes,
      configBytes,
      facts: buildFacts,
      manifest,
      selection: selectionFor(buildFacts, buildManifestBytes, configBytes),
    };
    mutate(fixture);
    assert.throws(() => validateSelectionBindings(fixture));
  });
}

test("build recipe is pinned, offline, canonical, and invokes exactly two clean builds", () => {
  const recipe = readFileSync(join(SCRIPT_DIRECTORY, "build-payment-v1-directory-relay.sh"), "utf8");
  assert.match(recipe, new RegExp(DIRECTORY_RELAY_BUILD_IMAGE.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
  assert.match(recipe, /--platform linux\/amd64/gu);
  assert.match(recipe, /--network none/gu);
  assert.match(recipe, /--pull=never/gu);
  assert.match(recipe, /\[\[ "\$candidate" =~ \[\[:cntrl:\],\] \]\]/gu);
  assert.match(recipe, /\/usr\/bin\/timeout --signal=KILL 300s \/bin\/bash/gu);
  assert.match(recipe, /\/usr\/bin\/timeout --signal=KILL 1800s \/bin\/bash/gu);
  assert.match(recipe, /\/usr\/bin\/timeout --signal=KILL 15s \\\n+  \/proof\/bitcoinpir-directory-relay --version/gu);
  assert.match(recipe, /--tmpfs "\/work:rw,exec,nosuid,nodev,size=4g,uid=\$host_uid,gid=\$host_gid,mode=0700"/gu);
  assert.match(recipe, /if \[\[ "\$host_uid" == '0' \|\| "\$host_gid" == '0' \]\]/gu);
  assert.match(recipe, /--user "\$unprivileged_uid:\$unprivileged_gid"/gu);
  assert.match(recipe, /--tmpfs "\/work:rw,exec,nosuid,nodev,size=64m,uid=\$unprivileged_uid,gid=\$unprivileged_gid,mode=0700"/gu);
  assert.match(recipe, /type=bind,src=\$staging\/bitcoinpir-directory-relay,dst=\/proof\/bitcoinpir-directory-relay,readonly/gu);
  assert.doesNotMatch(recipe, /type=bind,src=\$staging,dst=\/artifacts,readonly/gu);
  assert.doesNotMatch(recipe, /--tmpfs \/work:[^\n]*noexec/gu);
  assert.match(recipe, /--format=tar/gu);
  assert.match(recipe, /--prefix="BitcoinPIR-\$SOURCE_COMMIT\/"/gu);
  assert.match(recipe, /type=bind,src=\$repository,dst=\/repository,readonly/gu);
  assert.deepEqual(
    DIRECTORY_RELAY_PINNED_GIT_GLOBAL_OPTIONS,
    [
      "--no-replace-objects",
      "-c",
      "core.attributesFile=/dev/null",
      "--git-dir=/work/source.git",
    ],
  );
  assert.match(recipe, /\/usr\/bin\/git init --bare --quiet \/work\/source\.git/gu);
  assert.match(recipe, /\/bin\/cp -a \/repository\/\.git\/objects\/\. \/work\/source\.git\/objects\//gu);
  assert.match(recipe, /--no-replace-objects/gu);
  assert.match(recipe, /core\.attributesFile=\/dev\/null/gu);
  assert.match(recipe, /--git-dir=\/work\/source\.git/gu);
  assert.match(recipe, /GIT_ATTR_NOSYSTEM=1/gu);
  assert.match(recipe, /GIT_CONFIG_NOSYSTEM=1/gu);
  assert.match(recipe, /GIT_NO_REPLACE_OBJECTS=1/gu);
  assert.doesNotMatch(recipe, /--env HOME=/gu);
  assert.match(recipe, /objects\/info\/alternates/gu);
  assert.match(recipe, /objects\/info\/http-alternates/gu);
  assert.match(recipe, /! -d \/repository\/\.git\/objects \|\| -L \/repository\/\.git\/objects/gu);
  assert.equal(recipe.match(/--memory 3221225472/gmu)?.length, 1);
  assert.equal(recipe.match(/--memory-swap 3221225472/gmu)?.length, 1);
  assert.equal(recipe.match(/--pids-limit 128/gmu)?.length, 1);
  assert.equal(recipe.match(/--memory 6442450944/gmu)?.length, 1);
  assert.equal(recipe.match(/--memory-swap 6442450944/gmu)?.length, 1);
  assert.equal(recipe.match(/--pids-limit 512/gmu)?.length, 1);
  assert.equal(recipe.match(/--memory 268435456/gmu)?.length, 1);
  assert.equal(recipe.match(/--memory-swap 268435456/gmu)?.length, 1);
  assert.equal(recipe.match(/--pids-limit 64/gmu)?.length, 1);
  assert.equal(recipe.match(/--ulimit core=0:0/gmu)?.length, 4);
  assert.equal(recipe.match(/--ulimit nofile=/gmu)?.length, 4);
  for (const seconds of ["30", "60", "330", "1830"]) {
    assert.match(
      recipe,
      new RegExp(`"\\$host_timeout_path" --signal=KILL ${seconds}s`, "u"),
    );
  }
  assert.match(recipe, /payment-v1-renameat2-noreplace\.rs/gu);
  assert.match(recipe, /verify-directory-chain \\/gu);
  assert.match(recipe, /verify-directory-chain-identity \\/gu);
  assert.match(recipe, /\/work\/payment-v1-renameat2-noreplace "\$1" "\$2"/gu);
  assert.match(recipe, /readonly staging_identity[\s\S]{0,160}staging_identity=/gu);
  assert.match(recipe, /"\$output_identity" != "\$staging_identity"/gu);
  assert.match(recipe, /if \[\[ -e "\$staging" \|\| ! -d "\$output" \|\| -L "\$output" \|\| \\/gu);
  assert.doesNotMatch(recipe, /^mv "\$staging" "\$output"$/gmu);
  assert.doesNotMatch(recipe, /\/usr\/bin\/mv --no-clobber/gu);
  assert.match(recipe, /\/usr\/bin\/git --version > \/output\/git-version\.txt/gu);
  assert.match(recipe, /\/usr\/bin\/tar --version \| \/usr\/bin\/sed -n "1p" > \/output\/tar-version\.txt/gu);
  assert.doesNotMatch(recipe, /\/usr\/bin\/git -C "\$repository"/gu);
  assert.match(recipe, /node "\$script_root\/scripts\/payment-v1-directory-relay-artifact-gate\.mjs"/gu);
  assert.match(recipe, /cargo build --release --locked --offline -p bitcoinpir-directory-relay --bin bitcoinpir-directory-relay/gu);
  assert.equal(recipe.match(/^build_once [12]$/gmu)?.length, 2);
  assert.match(recipe, /cmp -s/gu);
  assert.doesNotMatch(recipe, /cargo (?:build|run|test).*(?:^|\s)--manifest-path/gu);
});

test("default verifier isolates Git metadata and rebuilds only private byte snapshots", () => {
  const gate = readFileSync(
    join(SCRIPT_DIRECTORY, "payment-v1-directory-relay-artifact-gate.mjs"),
    "utf8",
  );
  for (const pattern of [
    /GIT_ATTR_NOSYSTEM=1/gu,
    /GIT_CONFIG_GLOBAL=\/dev\/null/gu,
    /GIT_CONFIG_NOSYSTEM=1/gu,
    /GIT_DEFAULT_HASH=sha1/gu,
    /GIT_NO_REPLACE_OBJECTS=1/gu,
    /core\.attributesFile=\/dev\/null/gu,
    /git init --bare --quiet \/work\/source\.git/gu,
    /\/bin\/cp -a \/repository\/\.git\/objects\/\. \/work\/source\.git\/objects\//gu,
    /\/bin\/rm -rf \/work\/source\.git\/objects\/info/gu,
    /constants\.O_RDONLY \| constants\.O_NOFOLLOW/gu,
    /chmodSync\(root, 0o700\)/gu,
    /private source archive snapshot/gu,
    /private selected binary snapshot/gu,
    /defaultRebuildRunner\(\{ artifactRoot, dockerPath, sourceArchive, sourceCommit \}\)/gu,
    /timeout: timeoutMs/gu,
    /nofile=4096:4096/gu,
    /core=0:0/gu,
    /source archive final confirmation/gu,
  ]) {
    assert.match(gate, pattern);
  }
  assert.doesNotMatch(gate, /(?:^|[^A-Z_])HOME=\/nonexistent/gmu);
  assert.match(gate, /for \(const buildNumber of \[1, 2\]\)/gu);
  assert.match(gate, /"--memory",\s*"268435456"/gu);
  assert.match(gate, /"--memory-swap",\s*"268435456"/gu);
  assert.match(gate, /"--pids-limit",\s*"64"/gu);
  assert.match(gate, /"--user",\s*`\$\{DIRECTORY_RELAY_UNPRIVILEGED_UID\}:\$\{DIRECTORY_RELAY_UNPRIVILEGED_GID\}`/gu);
  assert.match(gate, /size=4g,uid=\$\{DIRECTORY_RELAY_UNPRIVILEGED_UID\},gid=\$\{DIRECTORY_RELAY_UNPRIVILEGED_GID\},mode=0700/gu);
  assert.match(gate, /size=64m,uid=\$\{DIRECTORY_RELAY_UNPRIVILEGED_UID\},gid=\$\{DIRECTORY_RELAY_UNPRIVILEGED_GID\},mode=0700/gu);
});

test("Docker mount paths reject commas and control bytes", () => {
  assert.equal(validateDockerMountHostPath("/safe/path"), "/safe/path");
  for (const path of ["/unsafe,source", "/unsafe\nsource", "/unsafe\tsource", "relative"] ) {
    assert.throws(() => validateDockerMountHostPath(path), /mount delimiters or control bytes/u);
  }
});

test("pinned Docker execution times out and fails closed when the client hangs", (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-fake-docker-")));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const docker = join(root, "docker");
  writeFileSync(docker, "#!/bin/sh\n/bin/sleep 2\n", { mode: 0o700 });
  chmodSync(docker, 0o700);
  assert.throws(
    () => pinnedDockerRun(docker, [], ["ignored"], "hanging Docker test", 1024, { timeoutMs: 25 }),
    /timed out/u,
  );
});

test("pinned Docker execution uses an uncatchable outer timeout signal", () => {
  const gate = readFileSync(
    join(SCRIPT_DIRECTORY, "payment-v1-directory-relay-artifact-gate.mjs"),
    "utf8",
  );
  assert.match(gate, /killSignal: "SIGKILL"/u);
});

test("artifact directory-chain snapshots reject leaf metadata ABA and parent replacement", (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-relay-chain-")));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const parent = join(root, "parent");
  const leaf = join(parent, "leaf");
  mkdirSync(parent, { mode: 0o700 });
  mkdirSync(leaf, { mode: 0o700 });

  const leafSnapshot = snapshotCanonicalDirectoryChainV1(
    leaf,
    "test artifact chain",
    { ownerOnlyLeaf: true },
  );
  const marker = join(leaf, "marker");
  writeFileSync(marker, "mutate directory timestamps\n");
  unlinkSync(marker);
  assert.throws(
    () => assertCanonicalDirectoryChainUnchangedV1(
      leafSnapshot,
      leaf,
      "test artifact chain",
      { ownerOnlyLeaf: true },
    ),
    /ABA fingerprint changed/u,
  );

  const sharedAncestorSnapshot = snapshotCanonicalDirectoryChainV1(
    leaf,
    "test shared ancestor chain",
    { ownerOnlyLeaf: true },
  );
  const unrelatedSibling = join(root, "unrelated-sibling");
  mkdirSync(unrelatedSibling, { mode: 0o700 });
  rmSync(unrelatedSibling, { recursive: true });
  assert.equal(
    assertCanonicalDirectoryChainUnchangedV1(
      sharedAncestorSnapshot,
      leaf,
      "test shared ancestor chain",
      { ownerOnlyLeaf: true },
    ),
    true,
  );

  const parentSnapshot = snapshotCanonicalDirectoryChainV1(
    leaf,
    "test parent chain",
    { ownerOnlyLeaf: true },
  );
  const moved = `${parent}.moved`;
  renameSync(parent, moved);
  mkdirSync(parent, { mode: 0o700 });
  mkdirSync(leaf, { mode: 0o700 });
  assert.throws(
    () => assertCanonicalDirectoryChainUnchangedV1(
      parentSnapshot,
      leaf,
      "test parent chain",
      { ownerOnlyLeaf: true },
    ),
    /descriptor chain or ABA fingerprint changed/u,
  );
});

function runChild(path, args) {
  return new Promise((resolvePromise) => {
    const child = spawn(path, args, { stdio: "ignore" });
    child.once("exit", (status, signal) => resolvePromise({ signal, status }));
  });
}

test("Linux renameat2 publisher is atomic, no-clobber, concurrent, and ENOSYS-closed", {
  skip: process.platform !== "linux" || !HAS_NATIVE_RUSTC,
}, async (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-renameat2-")));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const source = join(SCRIPT_DIRECTORY, "payment-v1-renameat2-noreplace.rs");
  const binary = join(root, "renameat2-noreplace");
  const compile = spawnSync("rustc", [
    "--edition=2024",
    "--check-cfg",
    "cfg(payment_v1_test_force_enosys)",
    "-Dwarnings",
    source,
    "-o",
    binary,
  ], { encoding: "utf8" });
  assert.equal(compile.status, 0, compile.stderr);

  for (const targetKind of ["file", "directory", "symlink"]) {
    const sourcePath = join(root, `source-${targetKind}`);
    const destinationPath = join(root, `destination-${targetKind}`);
    mkdirSync(sourcePath);
    writeFileSync(join(sourcePath, "marker"), targetKind);
    if (targetKind === "file") writeFileSync(destinationPath, "existing");
    if (targetKind === "directory") mkdirSync(destinationPath);
    if (targetKind === "symlink") symlinkSync("missing-target", destinationPath);
    const refused = spawnSync(binary, [sourcePath, destinationPath]);
    assert.notEqual(refused.status, 0, `${targetKind} target was clobbered`);
    assert.equal(existsSync(sourcePath), true);
    if (targetKind === "symlink") {
      assert.equal(lstatSync(destinationPath).isSymbolicLink(), true);
    } else {
      assert.equal(existsSync(destinationPath), true);
    }
  }

  const first = join(root, "concurrent-first");
  const second = join(root, "concurrent-second");
  const destination = join(root, "concurrent-destination");
  mkdirSync(first);
  mkdirSync(second);
  writeFileSync(join(first, "winner"), "first");
  writeFileSync(join(second, "winner"), "second");
  const results = await Promise.all([
    runChild(binary, [first, destination]),
    runChild(binary, [second, destination]),
  ]);
  assert.deepEqual(
    results.map(({ status }) => status).sort(),
    [0, 1],
  );
  assert.equal(existsSync(join(destination, "winner")), true);
  assert.equal(Number(existsSync(first)) + Number(existsSync(second)), 1);

  const unsupportedBinary = join(root, "renameat2-enosys");
  const unsupportedCompile = spawnSync("rustc", [
    "--edition=2024",
    "--check-cfg",
    "cfg(payment_v1_test_force_enosys)",
    "--cfg",
    "payment_v1_test_force_enosys",
    "-Dwarnings",
    source,
    "-o",
    unsupportedBinary,
  ], { encoding: "utf8" });
  assert.equal(unsupportedCompile.status, 0, unsupportedCompile.stderr);
  const unsupportedSource = join(root, "unsupported-source");
  const unsupportedDestination = join(root, "unsupported-destination");
  mkdirSync(unsupportedSource);
  const unsupported = spawnSync(
    unsupportedBinary,
    [unsupportedSource, unsupportedDestination],
  );
  assert.notEqual(unsupported.status, 0);
  assert.equal(existsSync(unsupportedSource), true);
  assert.equal(existsSync(unsupportedDestination), false);
});

test("writable bind identity accepts non-root numeric IDs and rejects root or malformed IDs", () => {
  assert.deepEqual(requireWritableBindHostIdentity(501, 20), { gid: 20, uid: 501 });
  for (const [uid, gid] of [
    [0, 20],
    [501, 0],
    [-1, 20],
    [501, -1],
    [1.5, 20],
    [501, Number.NaN],
  ]) {
    assert.throws(
      () => requireWritableBindHostIdentity(uid, gid),
      /non-root numeric host UID\/GID/u,
    );
  }
  assert.equal(DIRECTORY_RELAY_UNPRIVILEGED_UID, 65532);
  assert.equal(DIRECTORY_RELAY_UNPRIVILEGED_GID, 65532);
});

function elfAmd64(marker = 0x41) {
  const bytes = Buffer.alloc(128, marker);
  bytes[0] = 0x7f;
  bytes[1] = 0x45;
  bytes[2] = 0x4c;
  bytes[3] = 0x46;
  bytes[4] = 2;
  bytes[5] = 1;
  bytes.writeUInt16LE(0x3e, 18);
  return bytes;
}

function filesystemFixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-relay-artifacts-")));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const artifactRoot = join(root, "artifacts");
  const repositoryRoot = join(root, "repository");
  mkdirSync(artifactRoot);
  chmodSync(artifactRoot, 0o700);
  mkdirSync(repositoryRoot);
  mkdirSync(join(repositoryRoot, ".git"));
  mkdirSync(join(repositoryRoot, ".git", "objects"));

  const sourceCommit = "4".repeat(40);
  const sourceArchive = Buffer.from("canonical git archive bytes\n");
  const cargoLock = Buffer.from("# canonical lockfile\n");
  const binary = elfAmd64();
  const binaryVersion = "bitcoinpir-directory-relay 0.1.0\n";
  const gitVersion = "git version 2.39.5\n";
  const tarVersion = "tar (GNU tar) 1.34\n";
  const fileBytes = {
    "Cargo.lock": cargoLock,
    "binary-version.txt": Buffer.from(binaryVersion),
    "bitcoinpir-directory-relay": binary,
    "bitcoinpir-directory-relay.build-1": binary,
    "bitcoinpir-directory-relay.build-2": binary,
    "git-version.txt": Buffer.from(gitVersion),
    "source.tar": sourceArchive,
    "tar-version.txt": Buffer.from(tarVersion),
  };
  for (const [name, bytes] of Object.entries(fileBytes)) {
    writeFileSync(join(artifactRoot, name), bytes);
  }
  const fixtureFacts = {
    binaryVersionOutput: binaryVersion.slice(0, -1),
    digests: {
      build1: hash(binary),
      build2: hash(binary),
      cargoLock: hash(cargoLock),
      gitVersion: hash(gitVersion),
      selected: hash(binary),
      sourceArchive: hash(sourceArchive),
      tarVersion: hash(tarVersion),
    },
    gitVersionOutput: gitVersion.slice(0, -1),
    sourceCommit,
    tarVersionOutput: tarVersion.slice(0, -1),
  };
  writeFileSync(
    join(artifactRoot, "build-manifest.json"),
    canonicalJson(buildManifestFromFacts(fixtureFacts)),
  );

  return {
    artifactRoot,
    binary,
    canonicalSourceRunner: () => ({
      archivedCargoLock: cargoLock,
      commitCargoLock: cargoLock,
      gitVersion,
      resolvedCommit: sourceCommit,
      sourceArchive,
      tarVersion,
    }),
    dockerPath: "/test/docker",
    rebuildRunner: () => [binary, binary],
    repositoryRoot,
    sourceCommit,
    versionRunner: () => binaryVersion,
  };
}

test("real artifact directory verifies with injected pinned-tool outputs", (t) => {
  const fixture = filesystemFixture(t);
  assert.equal(verifyBuildArtifactSet(fixture).facts.sourceCommit, fixture.sourceCommit);
});

test("real artifact directory requires current-euid ownership and exact mode 0700", (t) => {
  const fixture = filesystemFixture(t);
  chmodSync(fixture.artifactRoot, 0o755);
  assert.throws(
    () => verifyBuildArtifactSet(fixture),
    /current effective UID with exact mode 0700|current-euid owned mode 0700/u,
  );
});

test("repository source path and inode are rechecked after long verification", (t) => {
  const fixture = filesystemFixture(t);
  const original = fixture.repositoryRoot;
  const moved = `${original}.moved`;
  fixture.rebuildRunner = () => {
    renameSync(original, moved);
    mkdirSync(original);
    mkdirSync(join(original, ".git"));
    mkdirSync(join(original, ".git", "objects"));
    return [fixture.binary, fixture.binary];
  };
  assert.throws(() => verifyBuildArtifactSet(fixture), /repository root path, inode/u);
});

test("source archive is reread after long verification", (t) => {
  const fixture = filesystemFixture(t);
  fixture.rebuildRunner = () => {
    writeFileSync(join(fixture.artifactRoot, "source.tar"), "replaced while rebuilding\n");
    return [fixture.binary, fixture.binary];
  };
  assert.throws(() => verifyBuildArtifactSet(fixture), /source archive path or bytes changed/u);
});

test("real artifact directory rejects an extra unknown file", (t) => {
  const fixture = filesystemFixture(t);
  writeFileSync(join(fixture.artifactRoot, "unreviewed"), "unexpected\n");
  assert.throws(() => verifyBuildArtifactSet(fixture), /artifact root files must equal/u);
});

test("real artifact directory rejects a symlinked repository object store", (t) => {
  const fixture = filesystemFixture(t);
  const objects = join(fixture.repositoryRoot, ".git", "objects");
  rmSync(objects, { recursive: true });
  symlinkSync(fixture.artifactRoot, objects);
  assert.throws(() => verifyBuildArtifactSet(fixture), /object database storage/u);
});

test("real artifact directory rejects source archive byte tampering", (t) => {
  const fixture = filesystemFixture(t);
  writeFileSync(join(fixture.artifactRoot, "source.tar"), "tampered archive\n");
  assert.throws(() => verifyBuildArtifactSet(fixture), /canonical git archive/u);
});

test("real artifact directory rejects a symlink artifact", (t) => {
  const fixture = filesystemFixture(t);
  const target = join(fixture.artifactRoot, "source.tar");
  unlinkSync(target);
  symlinkSync(join(dirname(fixture.artifactRoot), "outside.tar"), target);
  assert.throws(() => verifyBuildArtifactSet(fixture), /one-link regular file/u);
});

test("real artifact directory rejects hardlinked clean-build binaries", (t) => {
  const fixture = filesystemFixture(t);
  const first = join(fixture.artifactRoot, "bitcoinpir-directory-relay.build-1");
  const second = join(fixture.artifactRoot, "bitcoinpir-directory-relay.build-2");
  unlinkSync(second);
  linkSync(first, second);
  assert.throws(() => verifyBuildArtifactSet(fixture), /one-link regular file/u);
});

test("real artifact directory rejects non-ELF selected and clean-build files", (t) => {
  const fixture = filesystemFixture(t);
  for (const name of [
    "bitcoinpir-directory-relay.build-1",
    "bitcoinpir-directory-relay.build-2",
    "bitcoinpir-directory-relay",
  ]) {
    writeFileSync(join(fixture.artifactRoot, name), Buffer.alloc(128, 0x42));
  }
  assert.throws(() => verifyBuildArtifactSet(fixture), /ELF64 little-endian x86-64/u);
});

test("real artifact directory rejects non-identical clean builds", (t) => {
  const fixture = filesystemFixture(t);
  writeFileSync(
    join(fixture.artifactRoot, "bitcoinpir-directory-relay.build-2"),
    elfAmd64(0x43),
  );
  assert.throws(() => verifyBuildArtifactSet(fixture), /not byte-identical/u);
});

test("real artifact directory rejects selected binary version mismatch", (t) => {
  const fixture = filesystemFixture(t);
  fixture.versionRunner = () => "bitcoinpir-directory-relay 0.2.0\n";
  assert.throws(() => collectBuildArtifactFacts(fixture), /recorded version bytes/u);
});

test("real artifact directory rejects a binary not reproduced from canonical source", (t) => {
  const fixture = filesystemFixture(t);
  fixture.rebuildRunner = () => [fixture.binary, elfAmd64(0x44)];
  assert.throws(() => collectBuildArtifactFacts(fixture), /independent clean rebuild 2/u);
});
