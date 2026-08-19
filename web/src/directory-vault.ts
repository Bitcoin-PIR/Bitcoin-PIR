/**
 * Encrypted, cross-tab-safe rollback storage for the public Nostr directory.
 *
 * The directory data is public, but encrypting these floors avoids leaving a
 * plaintext browser-history index of previously seen providers. The
 * non-extractable key does not protect against same-origin script compromise.
 */

import type { WasmDirectoryCatalogCandidateV1 } from './sdk-bridge.js';
import { trustedNowUnixV1 } from './trusted-time.js';

const DB_NAME = 'bitcoinpir-directory-v1';
const DB_VERSION = 1;
const META_STORE = 'meta';
const STATE_STORE = 'rollback-state';
const KEY_ID = 'non-extractable-aes-gcm-v1';
const STATE_AAD_DOMAIN = 'BitcoinPIR/directory-rollback-state/v1';
const STATE_ID_DOMAIN = 'BitcoinPIR/directory-rollback-key/v1';

interface KeyRecordV1 {
  id: string;
  key: CryptoKey;
}

interface CipherStateRecordV1 {
  id: string;
  /** Public SHA-256 CAS tag; the state itself remains encrypted. */
  stateDigestHex: string;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
}

interface DirectoryStateKeysV1 {
  version: 1;
  directoryPubkeyHex: string;
  entries: string[];
  checkpoints: number[];
}

interface StateEnvelopeV1 {
  version: 1;
  directoryPubkeyHex: string;
  entries: Array<{ providerIdHex: string; state: number[] }>;
  checkpoints: Array<{ shard: number; state: number[] }>;
}

interface RollbackPlanV1 {
  version: 1;
  directoryPubkeyHex: string;
  entries: Array<{
    providerIdHex: string;
    expected: number[] | null;
    successor: number[];
  }>;
  checkpoints: Array<{
    shard: number;
    expected: number[] | null;
    successor: number[];
  }>;
}

interface PreparedCasWriteV1 {
  id: string;
  expectedDigestHex: string | null;
  successorDigestHex: string;
  successor: CipherStateRecordV1;
}

export interface DirectoryDiscoveryEntryJsonV1 {
  v: 1;
  provider_id: string;
  directory_sequence: number;
  directory_valid_until: number;
  status: 'active';
  operator_assertion: {
    v: 1;
    operator_pubkey_ed25519: string;
    stable_server_id: string;
    provider_id: string;
    assertion_epoch: number;
    not_before: number;
    valid_until: number;
    endpoints: Array<{ transport: 'wss'; url: string }>;
    policy_signing_key_ed25519: string;
    policy_epoch: number;
    policy_digest: string;
    signature_ed25519: string;
  };
  catalog_hints: Array<{
    scope_id: string;
    backend: 'dpf-pir-v1' | 'harmony-pir-v2' | 'onion-pir-v1' | 'tee-oram-v1';
    workload: 'dpf-evaluate-job-v1' | 'harmony-hint-bundle-v1'
      | 'harmony-query-job-v1' | 'onion-evaluate-job-v1' | 'tee-oram-query-v1';
    acquisition: 'free-v1' | 'bolt11-v1' | 'cashu-ecash-v1';
    authorization: 'free-v1' | 'bolt11-direct-receipt-v1' | 'cashu-ecash-v1'
      | 'bitcoinpir-cashu-bat-v1' | 'bitcoinpir-cashu-bat-v2'
      | 'arc-v1-experimental';
    deployment: 'stable' | 'experimental';
  }>;
  health: { class: 'unknown' | 'available' | 'degraded' | 'unavailable'; observed_bucket: number };
}

export interface SelectableDirectoryEntryV1 {
  providerIdHex: string;
  eventIdHex: string;
  directorySequence: string;
  directoryValidUntil: string;
  operatorPubkeyEd25519Hex: string;
  stableServerId: string;
  policySigningKeyEd25519Hex: string;
  assertionEpoch: string;
  policyEpoch: string;
  policyDigestHex: string;
  entry: DirectoryDiscoveryEntryJsonV1;
}

export interface SelectableDirectoryShardV1 {
  shard: number;
  checkpointEpoch: string;
  checkpointRootHex: string;
  checkpointValidUntilUnix: string;
  entries: SelectableDirectoryEntryV1[];
}

export interface SelectableDirectoryCatalogV1 {
  version: 1;
  directoryPubkeyHex: string;
  /** Relay transport assurance only; never persisted in rollback state. */
  directoryMode: 'strict-multi-relay' | 'centralized-single-relay';
  directoryAssurance:
    | 'multi-origin-split-view-compared'
    | 'centralized-degraded-no-relay-cross-check';
  /** Minimum of every authenticated checkpoint and entry, including tombstones. */
  catalogValidUntilUnix: string;
  shards: SelectableDirectoryShardV1[];
}

export class DirectoryRollbackVaultV1 {
  private constructor(
    private readonly db: IDBDatabase,
    private readonly key: CryptoKey,
  ) {}

  static async open(): Promise<DirectoryRollbackVaultV1> {
    requireBrowserPrimitives();
    return withExclusiveLock('bitcoinpir:directory-vault:init', async () => {
      const db = await openDb();
      let key = await getValue<KeyRecordV1>(db, META_STORE, KEY_ID).then((row) => row?.key);
      if (!key) {
        key = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt'],
        );
        await putValue(db, META_STORE, { id: KEY_ID, key } satisfies KeyRecordV1);
      }
      if (key.extractable || key.algorithm.name !== 'AES-GCM') {
        db.close();
        throw new Error('directory vault key is not a non-extractable AES-GCM key');
      }
      return new DirectoryRollbackVaultV1(db, key);
    });
  }

  close(): void {
    this.db.close();
  }

  /**
   * Execute load -> Rust transition -> atomic CAS -> Rust acknowledgement
   * under one directory-wide Web Lock. No catalog bytes are returned before
   * every entry and all 16 checkpoint floors commit together.
   */
  async acceptCatalog(
    candidate: WasmDirectoryCatalogCandidateV1,
    nowUnix?: bigint,
  ): Promise<SelectableDirectoryCatalogV1> {
    const keys = parseStateKeys(candidate.stateKeysJson());
    return withExclusiveLock(`bitcoinpir:directory:${keys.directoryPubkeyHex}`, async () => {
      const current = await this.loadStateEnvelope(keys);
      const plan = parseRollbackPlan(candidate.prepareRollback(encodeJson(current)), keys);
      const writes = await this.prepareCasWrites(plan);
      await applyAtomicCas(this.db, writes);
      const durable = successorEnvelope(plan);
      candidate.acknowledgePersisted(encodeJson(durable));
      return parseSelectableCatalog(
        candidate.selectableCatalogJson(),
        keys,
        nowUnix ?? trustedNowUnixV1(),
      );
    });
  }

  private async loadStateEnvelope(keys: DirectoryStateKeysV1): Promise<StateEnvelopeV1> {
    const entries: StateEnvelopeV1['entries'] = [];
    const checkpoints: StateEnvelopeV1['checkpoints'] = [];
    for (const providerIdHex of keys.entries) {
      const id = await stateId(keys.directoryPubkeyHex, 'entry', providerIdHex);
      const state = await this.loadState(id);
      if (state) entries.push({ providerIdHex, state: Array.from(state) });
    }
    for (const shard of keys.checkpoints) {
      const id = await stateId(keys.directoryPubkeyHex, 'checkpoint', shard.toString(16));
      const state = await this.loadState(id);
      if (state) checkpoints.push({ shard, state: Array.from(state) });
    }
    return { version: 1, directoryPubkeyHex: keys.directoryPubkeyHex, entries, checkpoints };
  }

  private async loadState(id: string): Promise<Uint8Array | null> {
    const row = await getValue<CipherStateRecordV1>(this.db, STATE_STORE, id);
    if (!row) return null;
    validateCipherRow(row, id);
    try {
      const plaintext = new Uint8Array(await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: row.iv,
          additionalData: aad(STATE_AAD_DOMAIN, id),
        },
        this.key,
        row.ciphertext,
      ));
      if (await sha256Hex(plaintext) !== row.stateDigestHex) throw new Error('digest');
      return plaintext;
    } catch {
      throw new Error('directory rollback state authentication failed');
    }
  }

  private async prepareCasWrites(plan: RollbackPlanV1): Promise<PreparedCasWriteV1[]> {
    const pending = [
      ...plan.entries.map((row) => ({
        kind: 'entry' as const,
        key: row.providerIdHex,
        expected: row.expected,
        successor: row.successor,
      })),
      ...plan.checkpoints.map((row) => ({
        kind: 'checkpoint' as const,
        key: row.shard.toString(16),
        expected: row.expected,
        successor: row.successor,
      })),
    ];
    const writes: PreparedCasWriteV1[] = [];
    for (const row of pending) {
      const expected = row.expected === null ? null : fixedStateBytes(row.expected);
      const successor = fixedStateBytes(row.successor);
      const id = await stateId(plan.directoryPubkeyHex, row.kind, row.key);
      const successorDigestHex = await sha256Hex(successor);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: ownedArrayBuffer(iv),
          additionalData: aad(STATE_AAD_DOMAIN, id),
        },
        this.key,
        ownedArrayBuffer(successor),
      );
      writes.push({
        id,
        expectedDigestHex: expected === null ? null : await sha256Hex(expected),
        successorDigestHex,
        successor: {
          id,
          stateDigestHex: successorDigestHex,
          iv: iv.buffer.slice(0),
          ciphertext,
        },
      });
    }
    return writes;
  }
}

function parseStateKeys(json: string): DirectoryStateKeysV1 {
  let value: DirectoryStateKeysV1;
  try {
    value = JSON.parse(json) as DirectoryStateKeysV1;
  } catch {
    throw new Error('WASM returned malformed directory state keys');
  }
  const directory = canonicalHex32('directoryPubkeyHex', value.directoryPubkeyHex);
  if (value.version !== 1 || !Array.isArray(value.entries) || !Array.isArray(value.checkpoints)) {
    throw new Error('WASM returned an unsupported directory state-key envelope');
  }
  const entries = value.entries.map((entry) => canonicalHex32('providerIdHex', entry));
  if (new Set(entries).size !== entries.length) throw new Error('duplicate directory state key');
  const checkpoints = value.checkpoints.map(canonicalShard);
  if (checkpoints.length !== 16 || new Set(checkpoints).size !== 16
      || checkpoints.some((shard, index) => shard !== index)) {
    throw new Error('directory state keys must contain all 16 ordered shards');
  }
  return { version: 1, directoryPubkeyHex: directory, entries, checkpoints };
}

function parseRollbackPlan(json: string, keys: DirectoryStateKeysV1): RollbackPlanV1 {
  let value: RollbackPlanV1;
  try {
    value = JSON.parse(json) as RollbackPlanV1;
  } catch {
    throw new Error('WASM returned malformed directory rollback plan');
  }
  if (value.version !== 1
      || canonicalHex32('directoryPubkeyHex', value.directoryPubkeyHex) !== keys.directoryPubkeyHex
      || !Array.isArray(value.entries) || !Array.isArray(value.checkpoints)) {
    throw new Error('WASM returned a directory rollback plan for the wrong namespace');
  }
  const entryKeys = value.entries.map((row) => canonicalHex32('providerIdHex', row.providerIdHex));
  if (entryKeys.length !== keys.entries.length
      || entryKeys.some((entry, index) => entry !== keys.entries[index])) {
    throw new Error('directory rollback plan entry keys do not match the verified catalog');
  }
  const shards = value.checkpoints.map((row) => canonicalShard(row.shard));
  if (shards.length !== 16 || shards.some((shard, index) => shard !== index)) {
    throw new Error('directory rollback plan is missing an ordered shard checkpoint');
  }
  for (const row of [...value.entries, ...value.checkpoints]) {
    if (row.expected !== null) fixedStateBytes(row.expected);
    fixedStateBytes(row.successor);
  }
  return value;
}

function successorEnvelope(plan: RollbackPlanV1): StateEnvelopeV1 {
  return {
    version: 1,
    directoryPubkeyHex: plan.directoryPubkeyHex,
    entries: plan.entries.map((row) => ({
      providerIdHex: row.providerIdHex,
      state: row.successor.slice(),
    })),
    checkpoints: plan.checkpoints.map((row) => ({
      shard: row.shard,
      state: row.successor.slice(),
    })),
  };
}

function parseSelectableCatalog(
  json: string,
  expectedKeys: DirectoryStateKeysV1,
  nowUnix: bigint,
): SelectableDirectoryCatalogV1 {
  let decoded: unknown;
  try {
    decoded = JSON.parse(json) as unknown;
  } catch {
    throw new Error('WASM returned malformed selectable directory catalog');
  }
  const value = exactRecord(decoded, [
    'version',
    'directoryPubkeyHex',
    'directoryMode',
    'directoryAssurance',
    'catalogValidUntilUnix',
    'shards',
  ], 'selectable directory catalog');
  if (value.version !== 1
      || canonicalHex32('directoryPubkeyHex', value.directoryPubkeyHex)
        !== expectedKeys.directoryPubkeyHex
      || !validDirectoryAssurance(value.directoryMode, value.directoryAssurance)
      || !Array.isArray(value.shards) || value.shards.length !== 16) {
    throw new Error('selectable directory catalog has the wrong namespace or shard count');
  }
  const providers = new Set<string>();
  let conservativeExpiry: bigint | null = null;
  const shards = value.shards.map((candidate, index): SelectableDirectoryShardV1 => {
    const shard = exactRecord(candidate, [
      'shard',
      'checkpointEpoch',
      'checkpointRootHex',
      'checkpointValidUntilUnix',
      'entries',
    ], 'selectable directory shard');
    if (canonicalShard(shard.shard) !== index
        || !isPositiveDecimal(shard.checkpointEpoch)
        || canonicalHex32('checkpointRootHex', shard.checkpointRootHex).length !== 64
        || !isPositiveDecimal(shard.checkpointValidUntilUnix)
        || !Array.isArray(shard.entries)) {
      throw new Error('selectable directory shard is malformed');
    }
    conservativeExpiry = minimumUnix(
      conservativeExpiry,
      BigInt(shard.checkpointValidUntilUnix),
    );
    const entries = shard.entries.map((candidateEntry): SelectableDirectoryEntryV1 => {
      const item = exactRecord(candidateEntry, [
        'providerIdHex',
        'eventIdHex',
        'directorySequence',
        'directoryValidUntil',
        'operatorPubkeyEd25519Hex',
        'stableServerId',
        'policySigningKeyEd25519Hex',
        'assertionEpoch',
        'policyEpoch',
        'policyDigestHex',
        'entry',
      ], 'selectable directory entry');
      const provider = canonicalHex32('providerIdHex', item.providerIdHex);
      if (providers.has(provider)) throw new Error('provider appears in multiple directory shards');
      providers.add(provider);
      const directoryValidUntil = positiveDecimal(
        'directoryValidUntil',
        item.directoryValidUntil,
      );
      const entry = parseDiscoveryEntry(item.entry, provider, item);
      if (provider[0] !== index.toString(16)
          || canonicalHex32('eventIdHex', item.eventIdHex).length !== 64
          || !isPositiveDecimal(item.directorySequence)
          || canonicalHex32('operatorPubkeyEd25519Hex', item.operatorPubkeyEd25519Hex).length !== 64
          || typeof item.stableServerId !== 'string' || item.stableServerId.length === 0
          || canonicalHex32(
            'policySigningKeyEd25519Hex',
            item.policySigningKeyEd25519Hex,
          ).length !== 64
          || item.policySigningKeyEd25519Hex === item.operatorPubkeyEd25519Hex
          || !isPositiveDecimal(item.assertionEpoch)
          || !isPositiveDecimal(item.policyEpoch)
          || canonicalHex32('policyDigestHex', item.policyDigestHex).length !== 64) {
        throw new Error('selectable directory entry is malformed or inconsistent');
      }
      conservativeExpiry = minimumUnix(conservativeExpiry, BigInt(directoryValidUntil));
      return {
        providerIdHex: provider,
        eventIdHex: canonicalHex32('eventIdHex', item.eventIdHex),
        directorySequence: positiveDecimal('directorySequence', item.directorySequence),
        directoryValidUntil,
        operatorPubkeyEd25519Hex: canonicalHex32(
          'operatorPubkeyEd25519Hex',
          item.operatorPubkeyEd25519Hex,
        ),
        stableServerId: item.stableServerId,
        policySigningKeyEd25519Hex: canonicalHex32(
          'policySigningKeyEd25519Hex',
          item.policySigningKeyEd25519Hex,
        ),
        assertionEpoch: positiveDecimal('assertionEpoch', item.assertionEpoch),
        policyEpoch: positiveDecimal('policyEpoch', item.policyEpoch),
        policyDigestHex: canonicalHex32('policyDigestHex', item.policyDigestHex),
        entry,
      };
    });
    return {
      shard: index,
      checkpointEpoch: positiveDecimal('checkpointEpoch', shard.checkpointEpoch),
      checkpointRootHex: canonicalHex32('checkpointRootHex', shard.checkpointRootHex),
      checkpointValidUntilUnix: positiveDecimal(
        'checkpointValidUntilUnix',
        shard.checkpointValidUntilUnix,
      ),
      entries,
    };
  });
  const claimedExpiry = positiveDecimal('catalogValidUntilUnix', value.catalogValidUntilUnix);
  const rollbackProviders = new Set(expectedKeys.entries);
  if ([...providers].some((provider) => !rollbackProviders.has(provider))) {
    throw new Error('selectable directory provider has no rollback state key');
  }
  // Tombstones participate in the Rust-computed catalog minimum but are not
  // exported as selectable entries. The claimed minimum may therefore be
  // earlier than every expiry visible here, but it must never extend one.
  if (conservativeExpiry === null || BigInt(claimedExpiry) > conservativeExpiry) {
    throw new Error('selectable directory catalog expiry extends authenticated validity');
  }
  if (nowUnix <= 0n || nowUnix > BigInt(claimedExpiry)) {
    throw new Error('selectable directory catalog is expired');
  }
  for (const shard of shards) {
    for (const entry of shard.entries) {
      freezeDiscoveryEntry(entry.entry);
      Object.freeze(entry);
    }
    Object.freeze(shard.entries);
    Object.freeze(shard);
  }
  Object.freeze(shards);
  return Object.freeze({
    version: 1,
    directoryPubkeyHex: expectedKeys.directoryPubkeyHex,
    directoryMode: value.directoryMode as SelectableDirectoryCatalogV1['directoryMode'],
    directoryAssurance:
      value.directoryAssurance as SelectableDirectoryCatalogV1['directoryAssurance'],
    catalogValidUntilUnix: claimedExpiry,
    shards,
  });
}

function freezeDiscoveryEntry(entry: DirectoryDiscoveryEntryJsonV1): void {
  for (const endpoint of entry.operator_assertion.endpoints) Object.freeze(endpoint);
  Object.freeze(entry.operator_assertion.endpoints);
  Object.freeze(entry.operator_assertion);
  for (const hint of entry.catalog_hints) Object.freeze(hint);
  Object.freeze(entry.catalog_hints);
  Object.freeze(entry.health);
  Object.freeze(entry);
}

/** Recheck immediately before admission/payment/token/query transitions. */
export function assertSelectableDirectoryCatalogFreshV1(
  catalog: SelectableDirectoryCatalogV1,
  nowUnix: bigint = trustedNowUnixV1(),
): void {
  const expiry = positiveDecimal('catalogValidUntilUnix', catalog.catalogValidUntilUnix);
  if (nowUnix <= 0n || nowUnix > BigInt(expiry)) {
    throw new Error('verified directory catalog expired; refresh is required');
  }
}

function parseDiscoveryEntry(
  candidate: unknown,
  providerIdHex: string,
  selectable: Record<string, unknown>,
): DirectoryDiscoveryEntryJsonV1 {
  const entry = exactRecord(candidate, [
    'v',
    'provider_id',
    'directory_sequence',
    'directory_valid_until',
    'status',
    'operator_assertion',
    'catalog_hints',
    'health',
  ], 'directory discovery entry');
  const assertion = exactRecord(entry.operator_assertion, [
    'v',
    'operator_pubkey_ed25519',
    'stable_server_id',
    'provider_id',
    'assertion_epoch',
    'not_before',
    'valid_until',
    'endpoints',
    'policy_signing_key_ed25519',
    'policy_epoch',
    'policy_digest',
    'signature_ed25519',
  ], 'directory operator assertion');
  if (!Array.isArray(assertion.endpoints) || assertion.endpoints.length === 0
      || !Array.isArray(entry.catalog_hints)) {
    throw new Error('directory discovery entry has malformed assertion or hints');
  }
  const endpoints = assertion.endpoints.map((candidateEndpoint) => {
    const endpoint = exactRecord(candidateEndpoint, ['transport', 'url'], 'directory endpoint');
    if (endpoint.transport !== 'wss' || typeof endpoint.url !== 'string'
        || endpoint.url.length === 0 || endpoint.url.length > 512) {
      throw new Error('directory endpoint is malformed');
    }
    return { transport: 'wss' as const, url: endpoint.url };
  });
  const catalogHints = entry.catalog_hints.map((candidateHint) => {
    const hint = exactRecord(candidateHint, [
      'scope_id', 'backend', 'workload', 'acquisition', 'authorization', 'deployment',
    ], 'directory catalog hint');
    return {
      scope_id: canonicalHex32('catalog hint scope_id', hint.scope_id),
      backend: exactStringMember('catalog hint backend', hint.backend, [
        'dpf-pir-v1', 'harmony-pir-v2', 'onion-pir-v1', 'tee-oram-v1',
      ] as const),
      workload: exactStringMember('catalog hint workload', hint.workload, [
        'dpf-evaluate-job-v1', 'harmony-hint-bundle-v1', 'harmony-query-job-v1',
        'onion-evaluate-job-v1', 'tee-oram-query-v1',
      ] as const),
      acquisition: exactStringMember('catalog hint acquisition', hint.acquisition, [
        'free-v1', 'bolt11-v1', 'cashu-ecash-v1',
      ] as const),
      authorization: exactStringMember('catalog hint authorization', hint.authorization, [
        'free-v1', 'bolt11-direct-receipt-v1', 'cashu-ecash-v1',
        // This advertises transport capability only. No class path, digest, or
        // issuer trust is ever accepted from the directory.
        'bitcoinpir-cashu-bat-v1', 'bitcoinpir-cashu-bat-v2', 'arc-v1-experimental',
      ] as const),
      deployment: exactStringMember('catalog hint deployment', hint.deployment, [
        'stable', 'experimental',
      ] as const),
    };
  });
  const health = exactRecord(entry.health, ['class', 'observed_bucket'], 'directory health');
  const directorySequence = positiveSafeInteger(
    'directory discovery sequence',
    entry.directory_sequence,
  );
  const directoryValidUntil = positiveSafeInteger(
    'directory discovery expiry',
    entry.directory_valid_until,
  );
  const assertionEpoch = positiveSafeInteger('assertion epoch', assertion.assertion_epoch);
  const assertionNotBefore = positiveSafeInteger('assertion not-before', assertion.not_before);
  const assertionValidUntil = positiveSafeInteger('assertion expiry', assertion.valid_until);
  const policyEpoch = positiveSafeInteger('assertion policy epoch', assertion.policy_epoch);
  const observedBucket = positiveSafeInteger('directory health bucket', health.observed_bucket);
  const healthClass = exactStringMember('directory health class', health.class, [
    'unknown', 'available', 'degraded', 'unavailable',
  ] as const);
  if (entry.v !== 1 || entry.status !== 'active'
      || entry.provider_id !== providerIdHex
      || String(directorySequence) !== selectable.directorySequence
      || String(directoryValidUntil) !== selectable.directoryValidUntil
      || assertion.v !== 1
      || assertion.provider_id !== providerIdHex
      || assertion.operator_pubkey_ed25519 !== selectable.operatorPubkeyEd25519Hex
      || assertion.stable_server_id !== selectable.stableServerId
      || String(assertionEpoch) !== selectable.assertionEpoch
      || assertion.policy_signing_key_ed25519 !== selectable.policySigningKeyEd25519Hex
      || String(policyEpoch) !== selectable.policyEpoch
      || assertion.policy_digest !== selectable.policyDigestHex
      || typeof assertion.signature_ed25519 !== 'string'
      || !/^[0-9a-f]{128}$/.test(assertion.signature_ed25519)
      || typeof assertion.stable_server_id !== 'string'
      || assertion.stable_server_id.length === 0
      || assertion.stable_server_id.length > 256) {
    throw new Error('directory discovery entry is inconsistent with selectable trust material');
  }
  return {
    v: 1,
    provider_id: providerIdHex,
    directory_sequence: directorySequence,
    directory_valid_until: directoryValidUntil,
    status: 'active',
    operator_assertion: {
      v: 1,
      operator_pubkey_ed25519: canonicalHex32(
        'assertion operator key',
        assertion.operator_pubkey_ed25519,
      ),
      stable_server_id: assertion.stable_server_id as string,
      provider_id: providerIdHex,
      assertion_epoch: assertionEpoch,
      not_before: assertionNotBefore,
      valid_until: assertionValidUntil,
      endpoints,
      policy_signing_key_ed25519: canonicalHex32(
        'assertion policy key',
        assertion.policy_signing_key_ed25519,
      ),
      policy_epoch: policyEpoch,
      policy_digest: canonicalHex32('assertion policy digest', assertion.policy_digest),
      signature_ed25519: assertion.signature_ed25519,
    },
    catalog_hints: catalogHints,
    health: { class: healthClass, observed_bucket: observedBucket },
  };
}

function exactRecord(
  candidate: unknown,
  expectedFields: readonly string[],
  label: string,
): Record<string, any> {
  if (candidate === null || typeof candidate !== 'object' || Array.isArray(candidate)) {
    throw new Error(`${label} must be an object`);
  }
  const value = candidate as Record<string, unknown>;
  const actual = Object.keys(value).sort();
  const expected = [...expectedFields].sort();
  if (actual.length !== expected.length
      || actual.some((field, index) => field !== expected[index])) {
    throw new Error(`${label} has unknown or missing fields`);
  }
  return value;
}

function positiveDecimal(field: string, value: unknown): string {
  if (!isPositiveDecimal(value)) throw new Error(`${field} must be a positive decimal string`);
  return value;
}

function positiveSafeInteger(field: string, value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new Error(`${field} must be a positive safe integer`);
  }
  return Number(value);
}

function exactStringMember<const T extends string>(
  field: string,
  value: unknown,
  allowed: readonly T[],
): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) {
    throw new Error(`${field} has an unsupported value`);
  }
  return value as T;
}

function minimumUnix(current: bigint | null, candidate: bigint): bigint {
  return current === null || candidate < current ? candidate : current;
}

function validDirectoryAssurance(
  mode: unknown,
  assurance: unknown,
): boolean {
  return (mode === 'strict-multi-relay'
      && assurance === 'multi-origin-split-view-compared')
    || (mode === 'centralized-single-relay'
      && assurance === 'centralized-degraded-no-relay-cross-check');
}

function fixedStateBytes(value: unknown): Uint8Array {
  if (!Array.isArray(value) || value.length === 0 || value.length > 4096
      || value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) {
    throw new Error('directory rollback state is not a bounded byte array');
  }
  return Uint8Array.from(value);
}

function canonicalHex32(field: string, value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value) || /^0{64}$/.test(value)) {
    throw new Error(`${field} must be non-zero lowercase 32-byte hex`);
  }
  return value;
}

function canonicalShard(value: unknown): number {
  if (!Number.isInteger(value) || Number(value) < 0 || Number(value) >= 16) {
    throw new Error('directory shard must be an integer in [0, 15]');
  }
  return Number(value);
}

function isPositiveDecimal(value: unknown): value is string {
  return typeof value === 'string' && /^[1-9][0-9]*$/.test(value);
}

function validateCipherRow(row: CipherStateRecordV1, expectedId: string): void {
  if (row.id !== expectedId || !/^[0-9a-f]{64}$/.test(row.stateDigestHex)
      || !(row.iv instanceof ArrayBuffer) || row.iv.byteLength !== 12
      || !(row.ciphertext instanceof ArrayBuffer) || row.ciphertext.byteLength === 0) {
    throw new Error('directory rollback ciphertext record is malformed');
  }
}

function requireBrowserPrimitives(): void {
  if (typeof indexedDB === 'undefined') throw new Error('IndexedDB is required for directory state');
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('WebCrypto is required for directory state');
  }
  if (typeof navigator === 'undefined' || !navigator.locks) {
    throw new Error('Web Locks are required for directory rollback CAS');
  }
}

async function withExclusiveLock<T>(name: string, body: () => Promise<T>): Promise<T> {
  if (typeof navigator === 'undefined' || !navigator.locks) {
    throw new Error('Web Locks are required for directory rollback CAS');
  }
  return navigator.locks.request(name, { mode: 'exclusive' }, body);
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(META_STORE)) {
        db.createObjectStore(META_STORE, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STATE_STORE)) {
        db.createObjectStore(STATE_STORE, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('failed to open directory IndexedDB'));
    request.onblocked = () => reject(new Error('directory IndexedDB upgrade is blocked'));
  });
}

function getValue<T>(db: IDBDatabase, store: string, key: IDBValidKey): Promise<T | undefined> {
  return requestInTransaction<T | undefined>(db, store, 'readonly', (objectStore) =>
    objectStore.get(key));
}

function putValue(db: IDBDatabase, store: string, value: unknown): Promise<void> {
  return requestInTransaction(db, store, 'readwrite', (objectStore) =>
    objectStore.put(value)).then(() => undefined);
}

function requestInTransaction<T>(
  db: IDBDatabase,
  storeName: string,
  mode: IDBTransactionMode,
  start: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, mode);
    const request = start(tx.objectStore(storeName));
    let result: T;
    request.onsuccess = () => { result = request.result; };
    request.onerror = () => reject(new Error(`IndexedDB ${storeName} request failed`));
    tx.oncomplete = () => resolve(result!);
    tx.onerror = () => reject(new Error(`IndexedDB ${storeName} transaction failed`));
    tx.onabort = () => reject(new Error(`IndexedDB ${storeName} transaction aborted`));
  });
}

function applyAtomicCas(db: IDBDatabase, writes: PreparedCasWriteV1[]): Promise<void> {
  if (writes.length < 16 || new Set(writes.map((write) => write.id)).size !== writes.length) {
    throw new Error('directory CAS plan is incomplete or contains duplicate keys');
  }
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STATE_STORE, 'readwrite');
    const store = tx.objectStore(STATE_STORE);
    let remaining = writes.length;
    let conflict = false;
    for (const write of writes) {
      const request = store.get(write.id) as IDBRequest<CipherStateRecordV1 | undefined>;
      request.onerror = () => tx.abort();
      request.onsuccess = () => {
        if (conflict) return;
        const current = request.result;
        const currentDigest = current?.stateDigestHex ?? null;
        if (currentDigest !== write.expectedDigestHex
            && currentDigest !== write.successorDigestHex) {
          conflict = true;
          tx.abort();
          return;
        }
        remaining -= 1;
        if (remaining === 0) {
          for (const pending of writes) store.put(pending.successor);
        }
      };
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error('directory rollback CAS transaction failed'));
    tx.onabort = () => reject(new Error(
      conflict
        ? 'directory rollback CAS conflict; restart the catalog refresh'
        : 'directory rollback CAS transaction aborted',
    ));
  });
}

async function stateId(
  directoryPubkeyHex: string,
  kind: 'entry' | 'checkpoint',
  key: string,
): Promise<string> {
  return sha256Hex(new TextEncoder().encode(
    `${STATE_ID_DOMAIN}\0${directoryPubkeyHex}\0${kind}\0${key}`,
  ));
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', ownedArrayBuffer(bytes));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function aad(domain: string, id: string): ArrayBuffer {
  return ownedArrayBuffer(new TextEncoder().encode(`${domain}\0${id}`));
}

function encodeJson(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
