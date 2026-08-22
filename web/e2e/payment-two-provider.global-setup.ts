import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer, connect } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export type PaymentTwoProviderVariantV1 = 'direct-bat' | 'free-arc-experimental';

type BrowserHarnessMethodV1 =
  | 'free'
  | 'bolt11-direct-receipt'
  | 'cashu-bat'
  | 'arc-experimental';

interface BrowserHarnessOfferInventoryV1 {
  variant: PaymentTwoProviderVariantV1;
  offer_id: number;
  method: BrowserHarnessMethodV1;
  free_mode: 'not-free' | 'open-best-effort' | 'ip-rate-limited';
  deployment_status: 'stable' | 'experimental';
}

interface BrowserHarnessProviderInventoryV1 {
  name: string;
  provider_id: string;
  policy_signing_pubkey: string;
  expected_payee_pubkey: string;
  issuer_id: string;
  policy_path: string;
  quote_delegation_path: string;
  scope_id: string;
  entitlement_profile: number;
  offers: BrowserHarnessOfferInventoryV1[];
  free_ip_key_path: string | null;
  bat_key_path: string | null;
  arc_key_path: string | null;
  arc_key_id: string | null;
}

interface BrowserHarnessInventoryV1 {
  boundary: string;
  database_path: string;
  database_config_path: string;
  manifest_root: string;
  database_proof: BrowserDatabaseProofHarnessInventoryV1;
  providers: BrowserHarnessProviderInventoryV1[];
}

interface BrowserDatabaseProofHarnessInventoryV1 {
  boundary: string;
  proof_path: string;
  db_id: number;
  build_kind: 'snapshot';
  from_height: number;
  from_block_hash: string;
  height: number;
  block_hash: string;
  anchor_hex: string;
  index_master_seed_hex: string;
  chunk_master_seed_hex: string;
  tag_seed_hex: string;
  muhash: string;
  bucket_super_root: string;
  onion_super_root: string;
  onion_entry_size: number;
  params_hash: string;
  network_magic: string;
  builder_binary_sha256: string;
  builder_git_commit: string;
  proof_version: number;
}

interface FixtureInventoryV1 {
  test_only: boolean;
  deterministic: boolean;
  funds_capable: boolean;
  network: string;
  providers: Array<{
    name: string;
    stable_server_id: string;
    provider_id: string;
    operator_pubkey: string;
    policy_signing_pubkey: string;
  }>;
  browser_two_provider_harness?: BrowserHarnessInventoryV1;
}

export interface PaymentTwoProviderFixtureV1 {
  testOnly: true;
  deterministic: true;
  fundsCapable: false;
  network: 'regtest';
  settlementMode: 'fake' | 'external';
  boundary: string;
  manifestRootHex: string;
  databaseProof: {
    boundary: string;
    dbId: 0;
    buildKind: 'snapshot';
    fromHeight: 0;
    fromBlockHashHex: string;
    height: number;
    blockHashHex: string;
    anchorHex: string;
    indexMasterSeedHex: string;
    chunkMasterSeedHex: string;
    tagSeedHex: string;
    muhashHex: string;
    bucketSuperRootHex: string;
    onionSuperRootHex: string;
    onionEntrySize: number;
    paramsHashHex: string;
    networkMagicHex: 'f9beb4d9';
    builderBinarySha256Hex: string;
    builderGitCommit: string;
    proofVersion: 1;
  };
  providers: Array<{
    index: 0 | 1;
    name: string;
    providerIdHex: string;
    policySigningPubkeyHex: string;
    /** Test-only trusted-bootstrap output, cross-checked against the
     * deterministic bpir-admin provider inventory by global setup. */
    trustedOperatorSigningKeyHex: string;
    expectedPayeePubkeyHex: string;
    issuerIdHex: string;
    scopeIdHex: string;
    entitlementProfile: number;
    offers: Array<{
      variant: PaymentTwoProviderVariantV1;
      offerId: number;
      method: BrowserHarnessMethodV1;
      freeMode: 'not-free' | 'open-best-effort' | 'ip-rate-limited';
      deploymentStatus: 'stable' | 'experimental';
    }>;
    arcKeyIdHex: string | null;
    issuerOrigin: string;
    serverWsUrl: string;
    serverLogPath: string;
  }>;
}

type PaymentTwoProviderBackendV1 = 'fake' | 'cln-regtest';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const cargoTargetRoot = process.env.CARGO_TARGET_DIR
  ? resolve(repositoryRoot, process.env.CARGO_TARGET_DIR)
  : join(repositoryRoot, 'target');

function cargoDebugBinary(name: string): string {
  return join(cargoTargetRoot, 'debug', process.platform === 'win32' ? `${name}.exe` : name);
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  const webOrigin = process.env.BITCOINPIR_PAYMENT_TWO_PROVIDER_WEB_ORIGIN;
  if (!webOrigin) throw new Error('two-provider E2E web origin was not configured');
  const backendMode = paymentBackendMode();
  if (backendMode === 'cln-regtest'
      && process.env.BITCOINPIR_PAYMENT_CLN_ACKNOWLEDGE_LOCAL_REGTEST_ONLY !== '1') {
    throw new Error('joined CLN E2E requires explicit local-regtest-only acknowledgement');
  }
  const clnPayeePubkey = backendMode === 'cln-regtest'
    ? exactCompressedPubkey(requiredEnvironment('BITCOINPIR_PAYMENT_CLN_PAYEE_PUBKEY'))
    : null;
  const clnSocket = backendMode === 'cln-regtest'
    ? await checkedClnSocket(requiredEnvironment('BITCOINPIR_PAYMENT_CLN_RPC_SOCKET'))
    : null;
  const runtimeRoot = await mkdtemp(join(tmpdir(), 'bitcoinpir-payment-two-provider-'));
  await chmod(runtimeRoot, 0o700);
  const children: ChildProcessWithoutNullStreams[] = [];
  const independentStatePaths = new Set<string>();
  try {
    // Keep every fixture binary in one Cargo feature-resolution/build graph.
    // Separate invocations can alternate shared dependency feature sets and
    // force a clean runner to rebuild most of the graph twice before the
    // Playwright global timeout starts exercising any browser assertion.
    const cargoBuildArgs = [
      'build',
      '--locked',
      '--offline',
      '-p',
      'bpir-admin',
      '-p',
      'payment-issuer',
      '-p',
      'runtime',
      '--bin',
      'bpir-admin',
      '--bin',
      'payment-issuer',
      '--bin',
      'unified_server',
    ];
    if (backendMode === 'fake') {
      cargoBuildArgs.push(
        '--features',
        'payment-issuer/test-only-fake-lightning',
      );
    }
    runChecked('cargo', cargoBuildArgs);

    const fixtureRoot = join(runtimeRoot, 'fixture');
    runChecked(cargoDebugBinary('bpir-admin'), [
      'payment-v1-no-funds-fixture',
      '--acknowledge-deterministic-test-keys',
      '--include-browser-two-provider-harness',
      '--out',
      fixtureRoot,
    ]);
    const inventory = JSON.parse(
      await readFile(join(fixtureRoot, 'fixture.json'), 'utf8'),
    ) as FixtureInventoryV1;
    if (!inventory.test_only
        || !inventory.deterministic
        || inventory.funds_capable
        || inventory.network !== 'regtest') {
      throw new Error('refusing a fixture that is not deterministic, test-only, no-funds regtest');
    }
    const harness = inventory.browser_two_provider_harness;
    if (!harness
        || !harness.database_proof
        || !harness.database_config_path
        || !harness.boundary.includes('explicit NoSEV')
        || harness.providers.length !== 2
        || harness.providers[0]?.name !== 'provider-0'
        || harness.providers[1]?.name !== 'provider-1'
        || harness.providers.some((provider) =>
          provider.issuer_id === provider.provider_id
            || provider.issuer_id === provider.policy_signing_pubkey
            || provider.provider_id === provider.policy_signing_pubkey)
        || !hasExactBrowserOffer(
          harness.providers[0],
          'direct-bat',
          'bolt11-direct-receipt',
          'not-free',
          'stable',
        )
        || !hasExactBrowserOffer(
          harness.providers[0],
          'free-arc-experimental',
          'free',
          'ip-rate-limited',
          'stable',
        )
        || !hasExactBrowserOffer(
          harness.providers[1],
          'direct-bat',
          'cashu-bat',
          'not-free',
          'stable',
        )
        || !hasExactBrowserOffer(
          harness.providers[1],
          'free-arc-experimental',
          'arc-experimental',
          'not-free',
          'experimental',
        )
        || typeof harness.providers[0].free_ip_key_path !== 'string'
        || harness.providers[0].free_ip_key_path.length === 0
        || harness.providers[1].free_ip_key_path !== null) {
      throw new Error('fixture is missing the exact direct/BAT and Free/experimental-ARC variants');
    }
    const trustedOperatorSigningKeys = trustedHarnessOperatorKeys(inventory, harness);
    const databasePath = fixturePath(fixtureRoot, harness.database_path);
    const databaseConfigPath = fixturePath(fixtureRoot, harness.database_config_path);
    fixturePath(fixtureRoot, harness.database_proof.proof_path);
    const proof = harness.database_proof;
    if (proof.db_id !== 0
        || proof.build_kind !== 'snapshot'
        || proof.from_height !== 0
        || proof.from_block_hash !== '0'.repeat(64)
        || proof.network_magic !== 'f9beb4d9'
        || proof.proof_version !== 1
        || !proof.boundary.includes('not AMD SEV-SNP signature')) {
      throw new Error('fixture synthetic database-proof boundary or fixed fields drifted');
    }
    const databaseProof: PaymentTwoProviderFixtureV1['databaseProof'] = {
      boundary: proof.boundary,
      dbId: 0,
      buildKind: 'snapshot',
      fromHeight: 0,
      fromBlockHashHex: exactZeroHex('from_block_hash', proof.from_block_hash, 32),
      height: exactPositiveInteger('database proof height', proof.height),
      blockHashHex: exactHex('block_hash', proof.block_hash, 32),
      anchorHex: exactHex('anchor_hex', proof.anchor_hex, 36),
      indexMasterSeedHex: exactHex('index_master_seed_hex', proof.index_master_seed_hex, 8),
      chunkMasterSeedHex: exactHex('chunk_master_seed_hex', proof.chunk_master_seed_hex, 8),
      tagSeedHex: exactHex('tag_seed_hex', proof.tag_seed_hex, 8),
      muhashHex: exactHex('muhash', proof.muhash, 32),
      bucketSuperRootHex: exactHex('bucket_super_root', proof.bucket_super_root, 32),
      onionSuperRootHex: exactHex('onion_super_root', proof.onion_super_root, 32),
      onionEntrySize: exactPositiveInteger('onion_entry_size', proof.onion_entry_size),
      paramsHashHex: exactHex('params_hash', proof.params_hash, 32),
      networkMagicHex: 'f9beb4d9',
      builderBinarySha256Hex: exactHex(
        'builder_binary_sha256',
        proof.builder_binary_sha256,
        32,
      ),
      builderGitCommit: exactNonEmptyString('builder_git_commit', proof.builder_git_commit),
      proofVersion: 1,
    };
    const databaseManifest = await readFile(join(databasePath, 'MANIFEST.toml'));
    if (databaseManifest.length === 0
        || createHash('sha256').update(databaseManifest).digest('hex')
          !== harness.manifest_root) {
      throw new Error('fixture database manifest does not match its exact root');
    }
    const runtimeProviders: PaymentTwoProviderFixtureV1['providers'] = [];

    for (const [indexValue, provider] of harness.providers.entries()) {
      const index = indexValue as 0 | 1;
      const providerRoot = join(fixtureRoot, provider.name);
      const secretRoot = join(providerRoot, 'secrets');
      const stateRoot = join(runtimeRoot, provider.name);
      const issuerStoreParent = join(stateRoot, 'issuer-store');
      const serverStoreParent = join(stateRoot, 'server-store');
      for (const directory of [stateRoot, issuerStoreParent, serverStoreParent]) {
        await mkdir(directory, { recursive: true, mode: 0o700 });
        await chmod(directory, 0o700);
      }

      const issuerStore = join(issuerStoreParent, 'issuer.sqlite');
      recordIndependentStatePath(independentStatePaths, issuerStore);
      runChecked(cargoDebugBinary('payment-issuer'), [
        'init-store',
        '--store',
        issuerStore,
        '--issuer-id-hex',
        exactHex('issuer_id', provider.issuer_id, 32),
        '--network',
        'regtest',
      ]);

      const serverStore = join(serverStoreParent, 'provider.sqlite');
      recordIndependentStatePath(independentStatePaths, serverStore);
      runChecked(cargoDebugBinary('bpir-admin'), [
        'service-store-init',
        '--provider-id-hex',
        exactHex('provider_id', provider.provider_id, 32),
        '--store',
        serverStore,
      ]);

      const issuerPort = await reserveLoopbackPort();
      const issuerOrigin = `http://127.0.0.1:${issuerPort}`;
      let quoteDelegationPath = fixturePath(fixtureRoot, provider.quote_delegation_path);
      let expectedPayeePubkey = exactCompressedPubkey(provider.expected_payee_pubkey);
      if (backendMode === 'cln-regtest') {
        if (!clnPayeePubkey) throw new Error('checked CLN payee metadata is unavailable');
        expectedPayeePubkey = clnPayeePubkey;
        quoteDelegationPath = join(
          providerRoot,
          'public',
          'quote-key-delegation-cln-regtest-v1.bin',
        );
        runChecked(cargoDebugBinary('bpir-admin'), [
          'payment-artifact',
          'quote-delegation',
          '--issuer-root-key',
          join(secretRoot, 'issuer-root-ed25519.key'),
          '--quote-signing-key',
          join(secretRoot, 'quote-ed25519.key'),
          '--network',
          'regtest',
          '--expected-payee-pubkey-hex',
          expectedPayeePubkey,
          '--key-epoch',
          '2',
          '--not-before',
          '1700000000',
          '--not-after',
          '2000000000',
          '--out',
          quoteDelegationPath,
        ]);
      }
      const issuerArgs = [
        backendMode === 'fake' ? 'serve-fake' : 'serve-cln',
        '--bind',
        `127.0.0.1:${issuerPort}`,
        '--allow-origin',
        webOrigin,
        '--store',
        issuerStore,
        '--quote-delegation',
        quoteDelegationPath,
        '--quote-signing-key',
        join(secretRoot, 'quote-ed25519.key'),
        '--credential-derivation-key',
        join(secretRoot, 'credential-derivation.key'),
        '--service-policy',
        `${fixturePath(fixtureRoot, provider.policy_path)}=${provider.policy_signing_pubkey}`,
        '--receipt-signing-key',
        join(secretRoot, 'receipt-ed25519.key'),
        '--reconciliation-interval-seconds',
        backendMode === 'fake' ? '300' : '1',
      ];
      if (backendMode === 'fake') {
        issuerArgs.push(
          '--fake-lightning-signing-key',
          join(secretRoot, 'fake-lightning-secp256k1.key'),
          '--fake-lightning-derivation-seed',
          join(secretRoot, 'fake-lightning-derivation.key'),
        );
      } else {
        if (!clnSocket) throw new Error('checked CLN socket metadata is unavailable');
        issuerArgs.push(
          '--cln-rpc-socket',
          clnSocket.path,
          '--cln-rpc-expected-uid',
          String(clnSocket.uid),
        );
      }
      if (provider.bat_key_path) {
        issuerArgs.push('--bat-key', fixturePath(fixtureRoot, provider.bat_key_path));
      }
      if ((provider.arc_key_path === null) !== (provider.arc_key_id === null)) {
        throw new Error('browser ARC key path and key ID must be configured together');
      }
      if (provider.arc_key_path && provider.arc_key_id) {
        issuerArgs.push(
          '--arc-key',
          `${exactHex('arc_key_id', provider.arc_key_id, 32)}=${
            fixturePath(fixtureRoot, provider.arc_key_path)
          }`,
          '--allow-experimental-arc',
        );
      }
      const issuerLogPath = join(stateRoot, 'issuer.log');
      const issuer = await startLoggedProcess(
        cargoDebugBinary('payment-issuer'),
        issuerArgs,
        issuerLogPath,
      );
      children.push(issuer);
      await waitForIssuer(issuerOrigin, issuer, issuerLogPath);

      const serverPort = await reserveLoopbackPort();
      const serverWsUrl = new URL(`ws://127.0.0.1:${serverPort}/`).toString();
      const serverArgs = [
        '--bind-address',
        '127.0.0.1',
        '--port',
        String(serverPort),
        '--config',
        databaseConfigPath,
        '--role',
        index === 0 ? 'primary' : 'secondary',
        '--disable-onion',
        '--serve-queries',
        '--require-service-auth-v1',
        '--service-policy',
        fixturePath(fixtureRoot, provider.policy_path),
        '--service-provider-id-hex',
        exactHex('provider_id', provider.provider_id, 32),
        '--service-policy-key-hex',
        exactHex('policy_signing_pubkey', provider.policy_signing_pubkey, 32),
        '--service-store',
        serverStore,
        '--max-connections',
        '16',
        '--service-max-concurrent-auth',
        '4',
        '--websocket-handshake-timeout-ms',
        '1000',
        '--connection-idle-timeout-ms',
        '60000',
        '--service-pre-auth-timeout-ms',
        '60000',
      ];
      if (provider.bat_key_path) {
        serverArgs.push('--service-bat-key', fixturePath(fixtureRoot, provider.bat_key_path));
      }
      if (provider.free_ip_key_path) {
        if (index !== 0) {
          throw new Error('only loopback browser provider 0 may enable direct-peer Free/IP trust');
        }
        serverArgs.push(
          '--service-free-ip-key',
          fixturePath(fixtureRoot, provider.free_ip_key_path),
          '--service-trust-direct-peer-ip',
        );
      }
      if (provider.arc_key_path && provider.arc_key_id) {
        serverArgs.push(
          '--service-arc-key',
          `${exactHex('arc_key_id', provider.arc_key_id, 32)}=${
            fixturePath(fixtureRoot, provider.arc_key_path)
          }`,
          '--allow-experimental-arc',
        );
      }
      const serverLogPath = join(stateRoot, 'unified-server.log');
      const server = await startLoggedProcess(
        cargoDebugBinary('unified_server'),
        serverArgs,
        serverLogPath,
      );
      children.push(server);
      await waitForTcpListener(serverPort, server, serverLogPath);

      runtimeProviders.push({
        index,
        name: provider.name,
        providerIdHex: exactHex('provider_id', provider.provider_id, 32),
        policySigningPubkeyHex: exactHex(
          'policy_signing_pubkey',
          provider.policy_signing_pubkey,
          32,
        ),
        trustedOperatorSigningKeyHex: trustedOperatorSigningKeys[index],
        expectedPayeePubkeyHex: expectedPayeePubkey,
        issuerIdHex: exactHex('issuer_id', provider.issuer_id, 32),
        scopeIdHex: exactHex('scope_id', provider.scope_id, 32),
        entitlementProfile: exactPositiveInteger(
          'entitlement_profile',
          provider.entitlement_profile,
        ),
        offers: provider.offers.map(runtimeBrowserOffer),
        arcKeyIdHex: provider.arc_key_id === null
          ? null
          : exactHex('arc_key_id', provider.arc_key_id, 32),
        issuerOrigin,
        serverWsUrl,
        serverLogPath,
      });
    }

    const fixture: PaymentTwoProviderFixtureV1 = {
      testOnly: true,
      deterministic: true,
      fundsCapable: false,
      network: 'regtest',
      settlementMode: backendMode === 'fake' ? 'fake' : 'external',
      boundary: harness.boundary,
      manifestRootHex: exactHex('manifest_root', harness.manifest_root, 32),
      databaseProof,
      providers: runtimeProviders,
    };
    if (independentStatePaths.size !== 4) {
      throw new Error('two issuers and two providers did not receive four independent state paths');
    }
    assertIndependentRuntimeProviders(fixture.providers, backendMode);
    process.env.BITCOINPIR_PAYMENT_TWO_PROVIDER_FIXTURE = JSON.stringify(fixture);
    return async () => {
      await cleanup(children, runtimeRoot);
    };
  } catch (error) {
    try {
      await cleanup(children, runtimeRoot);
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        'two-provider setup failed and temporary process cleanup was incomplete',
      );
    }
    throw error;
  }
}

function runChecked(command: string, args: string[]): void {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    // The fixture validates protocol behavior, not release-code generation.
    // The workspace's dev profile is intentionally opt-level 3 for measured
    // binaries; forcing an unoptimized, non-incremental fixture keeps a clean
    // two-core CI runner from spending most of this browser job in LLVM while
    // preserving the exact source, features and wire behavior under test.
    env: {
      ...process.env,
      CARGO_NET_OFFLINE: 'true',
      CARGO_INCREMENTAL: '0',
      CARGO_PROFILE_DEV_OPT_LEVEL: '0',
      CARGO_PROFILE_DEV_DEBUG: '0',
    },
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const detail = `${result.stdout ?? ''}${result.stderr ?? ''}`.slice(-32_768);
    throw new Error(`${command} failed (${result.status ?? 'spawn'}):\n${detail}`, {
      cause: result.error,
    });
  }
}

function paymentBackendMode(): PaymentTwoProviderBackendV1 {
  const value = process.env.BITCOINPIR_PAYMENT_TWO_PROVIDER_BACKEND ?? 'fake';
  if (value === 'fake' || value === 'cln-regtest') return value;
  throw new Error('BITCOINPIR_PAYMENT_TWO_PROVIDER_BACKEND must be fake or cln-regtest');
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required for the selected two-provider backend`);
  return value;
}

async function checkedClnSocket(value: string): Promise<{ path: string; uid: number }> {
  const path = resolve(value);
  if (path !== value) throw new Error('CLN RPC socket must be an absolute normalized path');
  const metadata = await lstat(path);
  if (!metadata.isSocket()) throw new Error('CLN RPC path is not a Unix socket');
  if ((metadata.mode & 0o777) !== 0o600) {
    throw new Error('CLN RPC socket must be owner-only mode 0600 for this E2E');
  }
  if (typeof process.getuid === 'function' && metadata.uid !== process.getuid()) {
    throw new Error('CLN RPC socket must be owned by the current E2E user');
  }
  return { path, uid: metadata.uid };
}

async function startLoggedProcess(
  executable: string,
  args: string[],
  logPath: string,
): Promise<ChildProcessWithoutNullStreams> {
  await writeFile(logPath, '', { mode: 0o600 });
  const child = spawn(executable, args, {
    cwd: repositoryRoot,
    env: { ...process.env, CARGO_NET_OFFLINE: 'true' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  child.stdin.end();
  child.stdout.on('data', (chunk: Buffer) => appendFileSync(logPath, chunk));
  child.stderr.on('data', (chunk: Buffer) => appendFileSync(logPath, chunk));
  return child;
}

async function waitForIssuer(
  origin: string,
  child: ChildProcessWithoutNullStreams,
  logPath: string,
): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    await assertChildRunning(child, 'payment-issuer', logPath);
    try {
      const response = await fetch(`${origin}/v1/quote-keys/current`, {
        headers: {
          Accept: 'application/vnd.bitcoinpir.bolt11-quote-key-delegation-v1',
        },
        cache: 'no-store',
        signal: AbortSignal.timeout(1_000),
      });
      if (response.ok) {
        await response.arrayBuffer();
        return;
      }
    } catch {
      // Listener startup can race this loopback-only poll.
    }
    await delay(100);
  }
  throw new Error(`timed out waiting for payment-issuer:\n${await readTail(logPath)}`);
}

async function waitForTcpListener(
  port: number,
  child: ChildProcessWithoutNullStreams,
  logPath: string,
): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    await assertChildRunning(child, 'unified_server', logPath);
    if (await canConnect(port)) return;
    await delay(100);
  }
  throw new Error(`timed out waiting for unified_server:\n${await readTail(logPath)}`);
}

async function assertChildRunning(
  child: ChildProcessWithoutNullStreams,
  label: string,
  logPath: string,
): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {
    throw new Error(`${label} exited during startup:\n${await readTail(logPath)}`);
  }
}

async function canConnect(port: number): Promise<boolean> {
  return new Promise((resolveConnect) => {
    const socket = connect({ host: '127.0.0.1', port });
    const done = (value: boolean): void => {
      socket.removeAllListeners();
      socket.destroy();
      resolveConnect(value);
    };
    socket.setTimeout(250, () => done(false));
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
  });
}

async function reserveLoopbackPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    server.close();
    throw new Error('could not reserve a loopback TCP port');
  }
  await new Promise<void>((resolveClose, reject) => {
    server.close((error) => error ? reject(error) : resolveClose());
  });
  return address.port;
}

function fixturePath(root: string, relativePath: string): string {
  const candidate = resolve(root, relativePath);
  if (!candidate.startsWith(`${resolve(root)}${sep}`)) {
    throw new Error('fixture inventory path escaped its generated root');
  }
  return candidate;
}

function hasExactBrowserOffer(
  provider: BrowserHarnessProviderInventoryV1,
  variant: PaymentTwoProviderVariantV1,
  method: BrowserHarnessMethodV1,
  freeMode: BrowserHarnessOfferInventoryV1['free_mode'],
  deploymentStatus: BrowserHarnessOfferInventoryV1['deployment_status'],
): boolean {
  return provider.offers.length === 2
    && provider.offers.some((offer) => offer.variant === variant
      && offer.method === method
      && offer.free_mode === freeMode
      && offer.deployment_status === deploymentStatus);
}

/**
 * Model the adapter's already-verified operator-key output for this test-only
 * runtime. The key is accepted only from bpir-admin's deterministic provider
 * inventory, where provider_id is derived from that operator identity, and
 * only after the browser sub-inventory agrees on the exact provider and
 * policy key. It is never learned from a live service policy or directory
 * self-report.
 */
function trustedHarnessOperatorKeys(
  inventory: FixtureInventoryV1,
  harness: BrowserHarnessInventoryV1,
): [string, string] {
  if (!Array.isArray(inventory.providers)
      || inventory.providers.length !== 2
      || harness.providers.length !== 2) {
    throw new Error('fixture trust inventory must contain exactly two providers');
  }
  const keys = harness.providers.map((browserProvider, index) => {
    const provider = inventory.providers[index];
    if (!provider
        || provider.name !== browserProvider.name
        || provider.provider_id !== browserProvider.provider_id
        || provider.policy_signing_pubkey !== browserProvider.policy_signing_pubkey) {
      throw new Error(`browser provider ${index} does not match its trusted fixture inventory`);
    }
    const providerId = exactHex(`provider ${index} provider_id`, provider.provider_id, 32);
    const policyKey = exactHex(
      `provider ${index} policy_signing_pubkey`,
      provider.policy_signing_pubkey,
      32,
    );
    const operatorKey = exactHex(
      `provider ${index} operator_pubkey`,
      provider.operator_pubkey,
      32,
    );
    const stableServerId = exactStableServerId(
      `provider ${index} stable_server_id`,
      provider.stable_server_id,
    );
    const stableServerIdBytes = Buffer.from(stableServerId, 'utf8');
    const stableServerIdLength = Buffer.alloc(4);
    stableServerIdLength.writeUInt32LE(stableServerIdBytes.length);
    const derivedProviderId = createHash('sha256')
      .update('BitcoinPIR/provider-id/v1', 'utf8')
      .update(Buffer.from(operatorKey, 'hex'))
      .update(stableServerIdLength)
      .update(stableServerIdBytes)
      .digest('hex');
    if (derivedProviderId !== providerId) {
      throw new Error(`provider ${index} ID is not derived from its trusted operator identity`);
    }
    if (operatorKey === providerId || operatorKey === policyKey) {
      throw new Error(`provider ${index} operator trust key is not independently bound`);
    }
    return operatorKey;
  });
  if (keys[0] === keys[1]) {
    throw new Error('two-provider fixture reused one trusted operator key');
  }
  return keys as [string, string];
}

function runtimeBrowserOffer(
  offer: BrowserHarnessOfferInventoryV1,
): PaymentTwoProviderFixtureV1['providers'][number]['offers'][number] {
  if ((offer.variant !== 'direct-bat' && offer.variant !== 'free-arc-experimental')
      || ![
        'free',
        'bolt11-direct-receipt',
        'cashu-bat',
        'arc-experimental',
      ].includes(offer.method)
      || (offer.free_mode !== 'not-free'
        && offer.free_mode !== 'open-best-effort'
        && offer.free_mode !== 'ip-rate-limited')
      || (offer.deployment_status !== 'stable'
        && offer.deployment_status !== 'experimental')) {
    throw new Error('browser offer inventory contains an unsupported variant or policy value');
  }
  return {
    variant: offer.variant,
    offerId: exactPositiveInteger('offer_id', offer.offer_id),
    method: offer.method,
    freeMode: offer.free_mode,
    deploymentStatus: offer.deployment_status,
  };
}

function exactHex(field: string, value: string, bytes: number): string {
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)
      || /^0+$/.test(value)) {
    throw new Error(`${field} is not canonical non-zero ${bytes}-byte hex`);
  }
  return value;
}

function exactZeroHex(field: string, value: string, bytes: number): string {
  if (value !== '0'.repeat(bytes * 2)) {
    throw new Error(`${field} must be canonical all-zero ${bytes}-byte hex`);
  }
  return value;
}

function exactNonEmptyString(field: string, value: string): string {
  if (!value || value.trim() !== value || /[\0\r\n]/.test(value)) {
    throw new Error(`${field} must be one canonical non-empty line`);
  }
  return value;
}

function exactStableServerId(field: string, value: string): string {
  if (typeof value !== 'string'
      || Buffer.byteLength(value, 'utf8') < 1
      || Buffer.byteLength(value, 'utf8') > 256
      || Buffer.from(value, 'utf8').toString('utf8') !== value
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${field} must be 1..256 bytes of canonical control-free UTF-8`);
  }
  return value;
}

function exactCompressedPubkey(value: string): string {
  if (!/^(02|03)[0-9a-f]{64}$/.test(value)) {
    throw new Error('expected payee is not one compressed secp256k1 public key');
  }
  return value;
}

function exactPositiveInteger(field: string, value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${field} must be a positive safe integer`);
  }
  return value;
}

function recordIndependentStatePath(paths: Set<string>, path: string): void {
  const canonical = resolve(path);
  if (paths.has(canonical)) throw new Error('issuer/provider state paths unexpectedly alias');
  paths.add(canonical);
}

function assertIndependentRuntimeProviders(
  providers: PaymentTwoProviderFixtureV1['providers'],
  backendMode: PaymentTwoProviderBackendV1,
): void {
  if (providers.length !== 2) throw new Error('runtime requires exactly two providers');
  if (providers[0].offers.length !== 2
      || providers[1].offers.length !== 2
      || providers[0].arcKeyIdHex !== null
      || providers[1].arcKeyIdHex === null) {
    throw new Error('runtime does not expose the exact paid and Free/experimental-ARC variants');
  }
  const fields: Array<keyof Pick<
    PaymentTwoProviderFixtureV1['providers'][number],
    | 'providerIdHex'
    | 'policySigningPubkeyHex'
    | 'trustedOperatorSigningKeyHex'
    | 'issuerIdHex'
    | 'issuerOrigin'
    | 'serverWsUrl'
    | 'serverLogPath'
  >> = [
    'providerIdHex',
    'policySigningPubkeyHex',
    'trustedOperatorSigningKeyHex',
    'issuerIdHex',
    'issuerOrigin',
    'serverWsUrl',
    'serverLogPath',
  ];
  for (const field of fields) {
    if (providers[0][field] === providers[1][field]) {
      throw new Error(`two-provider runtime reused ${field}`);
    }
  }
  if (backendMode === 'fake'
      && providers[0].expectedPayeePubkeyHex === providers[1].expectedPayeePubkeyHex) {
    throw new Error('fake two-provider runtime unexpectedly reused a Lightning payee key');
  }
  if (backendMode === 'cln-regtest'
      && providers[0].expectedPayeePubkeyHex !== providers[1].expectedPayeePubkeyHex) {
    throw new Error('joined CLN runtime did not bind both issuers to the checked invoice node');
  }
  const ports = [
    new URL(providers[0].issuerOrigin).port,
    new URL(providers[1].issuerOrigin).port,
    new URL(providers[0].serverWsUrl).port,
    new URL(providers[1].serverWsUrl).port,
  ];
  if (new Set(ports).size !== 4) throw new Error('issuer/provider listeners reused a port');
}

async function readTail(path: string): Promise<string> {
  return (await readFile(path, 'utf8')).slice(-32_768);
}

async function terminateAll(children: ChildProcessWithoutNullStreams[]): Promise<void> {
  let firstError: unknown = null;
  for (const child of [...children].reverse()) {
    try {
      await terminate(child);
    } catch (error) {
      firstError ??= error;
    }
  }
  if (firstError) throw firstError;
}

async function cleanup(
  children: ChildProcessWithoutNullStreams[],
  runtimeRoot: string,
): Promise<void> {
  try {
    await terminateAll(children);
  } catch (error) {
    throw new Error(
      `temporary Payment V1 processes did not all exit; retained private evidence at ${runtimeRoot}`,
      { cause: error },
    );
  }
  try {
    await rm(runtimeRoot, { recursive: true, force: true });
  } catch (error) {
    throw new Error(`could not remove stopped Payment V1 runtime at ${runtimeRoot}`, {
      cause: error,
    });
  }
}

async function terminate(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (!processExited(child)) {
    child.kill('SIGTERM');
    if (!await waitForExit(child, 5_000)) {
      child.kill('SIGKILL');
      if (!await waitForExit(child, 5_000)) {
        throw new Error('temporary Payment V1 process did not exit after SIGKILL');
      }
    }
  }
  detachLogListeners(child);
}

function detachLogListeners(child: ChildProcessWithoutNullStreams): void {
  child.stdout.removeAllListeners('data');
  child.stderr.removeAllListeners('data');
}

async function waitForExit(
  child: ChildProcessWithoutNullStreams,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (processExited(child)) return true;
    await delay(25);
  }
  return processExited(child);
}

function processExited(child: ChildProcessWithoutNullStreams): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}
