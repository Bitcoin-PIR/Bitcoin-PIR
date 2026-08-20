#!/usr/bin/env node
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const repo = new URL('.', import.meta.url).pathname;
const init = join(repo, 'dracut/97bpir-pir2-sealed-provisioner/bpir-pir2-sealed-provisioner-init.sh');
const root = await mkdtemp(join(tmpdir(), 'bpir-sealed-provisioner-'));
const payload = join(root, 'payload');
const target = join(root, 'target');
const hash = value => createHash('sha256').update(value).digest('hex');
const files = {
  'startup.env': 'startup=v1\n',
  'release.bin': 'release\n',
  'public-artifact-set.env': 'public-set\n',
  'identity.cert': 'cert\n',
  'provider-accounting-authorization.bin': 'provider-auth\n',
  'issuer-accounting-approval.bin': 'issuer-approval\n',
  ['public/classes/' + 'a'.repeat(64) + '.bin']: 'class\n',
};
try {
  for (const [rel, value] of Object.entries(files)) {
    await mkdir(join(payload, rel, '..'), { recursive: true });
    await writeFile(join(payload, rel), value);
  }
  const manifest = Object.entries(files).map(([rel, value]) =>
    `${rel === 'startup.env' ? 'replace' : 'replay'}\t${rel}\t${hash(value)}\n`).join('');
  const manifestPath = join(root, 'manifest.tsv');
  await writeFile(manifestPath, manifest);
  const run = () => execFileSync('/bin/sh', [init], { env: { ...process.env,
    BPIR_SEALED_PROVISIONER_TEST_ROOT: target,
    BPIR_SEALED_PROVISIONER_TEST_PAYLOAD: payload,
    BPIR_SEALED_PROVISIONER_TEST_MANIFEST: manifestPath,
  }, stdio: 'pipe' });
  run(); // first install
  const installed = join(target, 'home/pir/data/pir2-sealed');
  if (await readFile(join(installed, 'release.bin'), 'utf8') !== files['release.bin']) throw new Error('first install');
  await writeFile(join(payload, 'startup.env'), 'startup=v2\n');
  await writeFile(manifestPath, manifest.replace(hash(files['startup.env']), hash('startup=v2\n')));
  run(); // startup replacement
  if (await readFile(join(installed, 'startup.env'), 'utf8') !== 'startup=v2\n') throw new Error('startup replace');
  const marker = join(installed, 'markers', `provision-${hash(await readFile(manifestPath))}.env`);
  if (((await stat(installed)).mode & 0o777) !== 0o700 ||
      ((await stat(join(installed, 'markers'))).mode & 0o777) !== 0o700 ||
      ((await stat(marker)).mode & 0o777) !== 0o600) throw new Error('sealed permissions or marker');
  run(); // exact replay accepted
  await writeFile(join(installed, 'release.bin'), 'conflict\n');
  let conflicted = false;
  try { run(); } catch { conflicted = true; }
  if (!conflicted || await readFile(join(installed, 'release.bin'), 'utf8') !== 'conflict\n') throw new Error('replay conflict overwrite');
  console.log('pir2 sealed provisioner: ok');
} finally { await rm(root, { recursive: true, force: true }); }
