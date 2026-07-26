import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

interface FixtureOfferV1 {
  method: string;
  credential_key_id: string | null;
}

interface FixtureScopeV1 {
  workload: string;
  offers: FixtureOfferV1[];
}

interface FixtureProviderV1 {
  name: string;
  issuer_id: string;
  policy_signing_pubkey: string;
  expected_payee_pubkey: string;
  policy_path: string;
  quote_delegation_path: string;
  scopes: FixtureScopeV1[];
}

interface FixtureInventoryV1 {
  test_only: boolean;
  deterministic: boolean;
  funds_capable: boolean;
  network: string;
  providers: FixtureProviderV1[];
}

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

type LightningBackendModeV1 = 'fake' | 'cln-regtest';

export default async function globalSetup(): Promise<() => Promise<void>> {
  const webOrigin = process.env.BITCOINPIR_PAYMENT_REAL_WEB_ORIGIN;
  if (!webOrigin) throw new Error('real issuer E2E web origin was not configured');
  const backendMode = lightningBackendMode();
  if (backendMode === 'cln-regtest'
      && process.env.BITCOINPIR_PAYMENT_CLN_ACKNOWLEDGE_LOCAL_REGTEST_ONLY !== '1') {
    throw new Error('CLN E2E requires explicit local-regtest-only acknowledgement');
  }

  const runtimeRoot = await mkdtemp(join(tmpdir(), 'bitcoinpir-payment-real-e2e-'));
  await chmod(runtimeRoot, 0o700);
  let issuer: ChildProcessWithoutNullStreams | null = null;
  try {
    runChecked('cargo', [
      'build',
      '--offline',
      '-p',
      'bpir-admin',
      '-p',
      'payment-issuer',
    ]);

    const fixtureRoot = join(runtimeRoot, 'fixture');
    runChecked(join(repositoryRoot, 'target/debug/bpir-admin'), [
      'payment-v1-no-funds-fixture',
      '--acknowledge-deterministic-test-keys',
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
    const provider = inventory.providers[0];
    if (!provider || provider.name !== 'provider-0') {
      throw new Error('deterministic fixture is missing provider-0');
    }

    const providerRoot = join(fixtureRoot, provider.name);
    const secretRoot = join(providerRoot, 'secrets');
    let quoteDelegation = fixturePath(fixtureRoot, provider.quote_delegation_path);
    let expectedPayeePubkey = provider.expected_payee_pubkey;
    let clnSocket: { path: string; uid: number } | null = null;
    if (backendMode === 'cln-regtest') {
      expectedPayeePubkey = canonicalCompressedPubkey(
        requiredEnvironment('BITCOINPIR_PAYMENT_CLN_PAYEE_PUBKEY'),
      );
      clnSocket = await checkedClnSocket(
        requiredEnvironment('BITCOINPIR_PAYMENT_CLN_RPC_SOCKET'),
      );
      quoteDelegation = join(providerRoot, 'public', 'quote-key-delegation-cln-regtest-v1.bin');
      runChecked(join(repositoryRoot, 'target/debug/bpir-admin'), [
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
        quoteDelegation,
      ]);
    }

    const storeParent = join(runtimeRoot, 'store');
    const floorParent = join(runtimeRoot, 'floor');
    await mkdir(storeParent, { mode: 0o700 });
    await mkdir(floorParent, { mode: 0o700 });
    const store = join(storeParent, 'issuer.sqlite');
    const rollbackAuthority = join(floorParent, 'rollback.sqlite');
    runChecked(join(repositoryRoot, 'target/debug/payment-issuer'), [
      'init-store',
      '--store',
      store,
      '--rollback-authority',
      rollbackAuthority,
      '--issuer-id-hex',
      provider.issuer_id,
      '--network',
      'regtest',
    ]);

    const issuerPort = await reserveLoopbackPort();
    const issuerOrigin = `http://127.0.0.1:${issuerPort}`;
    const args = [
      backendMode === 'fake' ? 'serve-fake' : 'serve-cln',
      '--bind',
      `127.0.0.1:${issuerPort}`,
      '--allow-origin',
      webOrigin,
      '--store',
      store,
      '--rollback-authority',
      rollbackAuthority,
      '--quote-delegation',
      quoteDelegation,
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
      args.push(
        '--fake-lightning-signing-key',
        join(secretRoot, 'fake-lightning-secp256k1.key'),
        '--fake-lightning-derivation-seed',
        join(secretRoot, 'fake-lightning-derivation.key'),
      );
    } else {
      if (!clnSocket) throw new Error('checked CLN socket metadata is unavailable');
      args.push(
        '--cln-rpc-socket',
        clnSocket.path,
        '--cln-rpc-expected-uid',
        String(clnSocket.uid),
      );
    }
    for (const scope of provider.scopes) {
      const bat = scope.offers.find((offer) => offer.method === 'cashu-bat');
      const arc = scope.offers.find((offer) => offer.method === 'arc-experimental');
      if (!bat?.credential_key_id || !arc?.credential_key_id) {
        throw new Error(`fixture scope ${scope.workload} is missing BAT or ARC key metadata`);
      }
      const workloadRoot = join(secretRoot, 'workloads', scope.workload);
      args.push('--bat-key', join(workloadRoot, 'cashu-bat.key'));
      args.push(
        '--arc-key',
        `${arc.credential_key_id}=${join(workloadRoot, 'arc-experimental.key')}`,
      );
    }

    const startedIssuer = spawn(join(repositoryRoot, 'target/debug/payment-issuer'), args, {
      cwd: repositoryRoot,
      env: { ...process.env, CARGO_NET_OFFLINE: 'true' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    startedIssuer.stdin.end();
    issuer = startedIssuer;
    let issuerLog = '';
    const appendLog = (chunk: Buffer): void => {
      issuerLog = `${issuerLog}${chunk.toString('utf8')}`.slice(-32_768);
    };
    startedIssuer.stdout.on('data', appendLog);
    startedIssuer.stderr.on('data', appendLog);
    await waitForIssuer(issuerOrigin, startedIssuer, () => issuerLog);

    process.env.BITCOINPIR_PAYMENT_REAL_FIXTURE = fixtureRoot;
    process.env.BITCOINPIR_PAYMENT_REAL_ISSUER_ORIGIN = issuerOrigin;
    process.env.BITCOINPIR_PAYMENT_REAL_EXPECTED_PAYEE = expectedPayeePubkey;
    process.env.BITCOINPIR_PAYMENT_REAL_SETTLEMENT_MODE =
      backendMode === 'fake' ? 'fake' : 'external';
    return async () => {
      await terminate(issuer);
      await rm(runtimeRoot, { recursive: true, force: true });
    };
  } catch (error) {
    await terminate(issuer);
    await rm(runtimeRoot, { recursive: true, force: true });
    throw error;
  }
}

function lightningBackendMode(): LightningBackendModeV1 {
  const value = process.env.BITCOINPIR_PAYMENT_REAL_BACKEND ?? 'fake';
  if (value === 'fake' || value === 'cln-regtest') return value;
  throw new Error('BITCOINPIR_PAYMENT_REAL_BACKEND must be fake or cln-regtest');
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required for the selected payment E2E backend`);
  return value;
}

function canonicalCompressedPubkey(value: string): string {
  if (!/^(02|03)[0-9a-f]{64}$/.test(value)) {
    throw new Error('CLN payee must be one canonical lowercase compressed secp256k1 public key');
  }
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
  return { path, uid: metadata.uid };
}

function runChecked(command: string, args: string[]): void {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    env: { ...process.env, CARGO_NET_OFFLINE: 'true' },
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const detail = `${result.stdout ?? ''}${result.stderr ?? ''}`.slice(-32_768);
    throw new Error(`${command} failed (${result.status ?? 'spawn'}):\n${detail}`, {
      cause: result.error,
    });
  }
}

function fixturePath(root: string, relative: string): string {
  const candidate = resolve(root, relative);
  if (!candidate.startsWith(`${resolve(root)}${sep}`)) {
    throw new Error('fixture inventory path escaped its generated root');
  }
  return candidate;
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

async function waitForIssuer(
  origin: string,
  child: ChildProcessWithoutNullStreams,
  log: () => string,
): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`payment-issuer exited during startup (${child.exitCode}):\n${log()}`);
    }
    try {
      const response = await fetch(`${origin}/v1/quote-keys/current`, {
        headers: {
          Accept: 'application/vnd.bitcoinpir.bolt11-quote-key-delegation-v1',
        },
        cache: 'no-store',
      });
      if (response.ok) {
        await response.arrayBuffer();
        return;
      }
    } catch {
      // Listener startup and incremental cargo linking can briefly race this poll.
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error(`timed out waiting for payment-issuer:\n${log()}`);
}

async function terminate(child: ChildProcessWithoutNullStreams | null): Promise<void> {
  if (!child || processExited(child)) return;
  child.kill('SIGTERM');
  if (!await waitForExit(child, 5_000)) {
    child.kill('SIGKILL');
    if (!await waitForExit(child, 5_000)) {
      throw new Error('temporary payment-issuer did not exit after SIGKILL');
    }
  }
}

async function waitForExit(
  child: ChildProcessWithoutNullStreams,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (processExited(child)) return true;
    await new Promise((resolveWait) => setTimeout(resolveWait, 25));
  }
  return processExited(child);
}

function processExited(child: ChildProcessWithoutNullStreams): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}
