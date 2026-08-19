import { Buffer } from 'buffer';

/**
 * Encrypted, issuer/class-scoped browser wallet for issuer-wide BAT V2.
 *
 * This database is intentionally disjoint from `bitcoinpir-admission-v1`.
 * BAT V2 records never acquire provider/policy/scope/offer coordinates and
 * V1 records are neither read nor migrated.  Web Locks serialize all wallet
 * mutations across tabs; IndexedDB transactions make pair reservation and
 * acquisition completion atomic.
 */

const DB_NAME = 'bitcoinpir-bat-v2';
const DB_VERSION = 1;
const META_STORE = 'meta';
const RECORD_STORE = 'records';
const RECOVERY_STORE = 'recoveries';
const QUOTE_KEY_STORE = 'quote-key-checkpoints';
const KEY_ID = 'non-extractable-aes-gcm-v1';
const GLOBAL_LOCK = 'bitcoinpir:bat-v2-vault:v1';
const RESERVATION_OWNER_LOCK_PREFIX = 'bitcoinpir:bat-v2-reservation-owner:v1';
const RECORD_AAD_DOMAIN = 'BitcoinPIR/bat-v2-vault/record/v1';
const RECOVERY_AAD_DOMAIN = 'BitcoinPIR/bat-v2-vault/recovery/v1';
const QUOTE_KEY_AAD_DOMAIN = 'BitcoinPIR/bat-v2-vault/quote-key-checkpoint/v1';
const QUOTE_KEY_ID_DOMAIN = 'BitcoinPIR/bat-v2-vault/quote-key-id/v1';
const SPEND_KEY_DIGEST_DOMAIN = 'BitcoinPIR/bat-v2-vault/spend-key/v1';
const SPEND_KEY_INDEX = 'by-spend-key-digest';
const BAT_V2_PROOF_LEN = 210;
const MAX_RECOVERY_STATE_LEN = 4 * 1024 * 1024;
const MAX_QUOTE_KEY_CHECKPOINT_LEN = 64 * 1024;

export type LightningNetworkNameV2 = 'bitcoin' | 'testnet' | 'signet' | 'regtest';

export interface BatV2ClassBindingV2 {
  issuerIdHex: string;
  classIdHex: string;
  classDigestHex: string;
  classKeyEpoch: string;
  batKeyIdHex: string;
}

export interface BatV2WalletRecordV2 extends BatV2ClassBindingV2 {
  proof: Uint8Array;
  globalSpendKeyHex: string;
}

export interface BatV2WalletInventoryV2 extends BatV2ClassBindingV2 {
  count: number;
}

export interface BatV2RecoveryRecordV2 {
  id: string;
  issuerEndpoint: string;
  issuerIdHex: string;
  network: LightningNetworkNameV2;
  expectedPayeePubkeyHex: string;
  /** Opaque secret-bearing `WasmBolt11BatV2AcquisitionV2` recovery bytes. */
  state: Uint8Array;
}

export interface BatV2ReservedProofV2 extends BatV2WalletRecordV2 {
  readonly recordId: string;
  readonly reservationId: string;
}

export interface BatV2DistinctPairReservationV2 {
  readonly reservationId: string;
  readonly first: BatV2ReservedProofV2;
  readonly second: BatV2ReservedProofV2;
}

export type BatV2ReservationDispositionV2 = 'recover-safe' | 'burn';

export interface LockedBatV2RecoveryV2 {
  persistState(state: Uint8Array): Promise<void>;
  complete(records: BatV2WalletRecordV2[]): Promise<string[]>;
}

interface KeyRecordV1 {
  id: string;
  key: CryptoKey;
}

interface CipherRecordV1 {
  id: string;
  spendKeyDigestHex: string;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
}

interface CipherRecoveryV1 {
  id: string;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
}

interface PlainRecordV1 extends BatV2ClassBindingV2 {
  version: 1;
  proofBase64: string;
  globalSpendKeyHex: string;
  state: 'available' | 'reserved';
  reservationId?: string;
}

interface PlainRecoveryV1 {
  version: 1;
  issuerEndpoint: string;
  issuerIdHex: string;
  network: LightningNetworkNameV2;
  expectedPayeePubkeyHex: string;
  stateBase64: string;
}

interface DecryptedRecordV1 {
  row: CipherRecordV1;
  plain: PlainRecordV1;
}

interface ReservationOwnerV1 {
  readonly remainingRecordIds: Set<string>;
  release(): void;
}

export class BatV2CredentialVaultV2 {
  private readonly reservationOwners = new Map<string, ReservationOwnerV1>();

  private constructor(
    private readonly db: IDBDatabase,
    private readonly key: CryptoKey,
  ) {}

  static async open(): Promise<BatV2CredentialVaultV2> {
    requireBrowserPrimitives();
    return withExclusiveLock(async () => {
      const db = await openDb();
      try {
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
          throw new Error('BAT V2 vault key is not a non-extractable AES-GCM key');
        }
        const vault = new BatV2CredentialVaultV2(db, key);
        await vault.burnOrphanedReservationsUnlocked();
        return vault;
      } catch (error) {
        db.close();
        throw error;
      }
    });
  }

  close(): void {
    for (const reservationId of [...this.reservationOwners.keys()]) {
      this.releaseReservationOwner(reservationId);
    }
    this.db.close();
  }

  /** Create encrypted class-only recovery before the first issuer POST. */
  async createRecovery(
    recovery: Omit<BatV2RecoveryRecordV2, 'id'>,
  ): Promise<BatV2RecoveryRecordV2> {
    const id = randomId();
    const value = { ...recovery, id, state: recovery.state.slice() };
    validateRecovery(value);
    const row = await this.encryptRecovery(value);
    await withExclusiveLock(async () => addValue(this.db, RECOVERY_STORE, row));
    return cloneRecovery(value);
  }

  async getRecovery(id: string): Promise<BatV2RecoveryRecordV2 | null> {
    canonicalOpaqueId('BAT V2 recovery ID', id);
    return withExclusiveLock(async () => {
      const row = await getValue<CipherRecoveryV1>(this.db, RECOVERY_STORE, id);
      return row ? this.decryptRecovery(row) : null;
    });
  }

  async listRecoveries(): Promise<BatV2RecoveryRecordV2[]> {
    return withExclusiveLock(async () => {
      const rows = await getAllValues<CipherRecoveryV1>(this.db, RECOVERY_STORE);
      return Promise.all(rows.map((row) => this.decryptRecovery(row)));
    });
  }

  /** Durably advance the issuer/network/payee quote-key rollback checkpoint. */
  async advanceQuoteKeyCheckpoint<T>(
    issuerIdHex: string,
    network: LightningNetworkNameV2,
    expectedPayeePubkeyHex: string,
    initialCheckpoint: Uint8Array,
    advance: (current: Uint8Array) => {
      nextCheckpoint: Uint8Array;
      value: T;
      discard?: () => void;
    },
  ): Promise<T> {
    const issuerId = canonicalHex32('issuerIdHex', issuerIdHex);
    if (!['bitcoin', 'testnet', 'signet', 'regtest'].includes(network)) {
      throw new Error('unsupported BAT V2 Lightning network');
    }
    const payee = canonicalCompressedPointHex('expectedPayeePubkeyHex', expectedPayeePubkeyHex);
    validateQuoteKeyCheckpoint(initialCheckpoint);
    const id = await quoteKeyCheckpointId(issuerId, network, payee);
    return withExclusiveLock(async () => {
      const row = await getValue<CipherRecoveryV1>(this.db, QUOTE_KEY_STORE, id);
      const current = row
        ? await this.decryptOpaqueBytes(row, QUOTE_KEY_AAD_DOMAIN)
        : initialCheckpoint.slice();
      const input = current.slice();
      let result: ReturnType<typeof advance>;
      try {
        result = advance(input);
      } finally {
        input.fill(0);
        current.fill(0);
      }
      try {
        validateQuoteKeyCheckpoint(result.nextCheckpoint);
        await putValue(
          this.db,
          QUOTE_KEY_STORE,
          await this.encryptOpaqueBytes(id, result.nextCheckpoint, QUOTE_KEY_AAD_DOMAIN),
        );
        return result.value;
      } catch (error) {
        result.discard?.();
        throw error;
      } finally {
        result.nextCheckpoint.fill(0);
      }
    });
  }

  /**
   * Serialize one restore/issuer-I/O/persist transition. The lock spans the
   * callback so a stale status response cannot overwrite a persisted claim.
   */
  async withRecovery<T>(
    recoveryId: string,
    operation: (
      recovery: BatV2RecoveryRecordV2,
      locked: LockedBatV2RecoveryV2,
    ) => Promise<T>,
  ): Promise<T> {
    canonicalOpaqueId('BAT V2 recovery ID', recoveryId);
    return withExclusiveLock(async () => {
      const row = await getValue<CipherRecoveryV1>(this.db, RECOVERY_STORE, recoveryId);
      if (!row) throw new Error('BAT V2 recovery was not found (it may be complete)');
      const current = await this.decryptRecovery(row);
      const exposed = cloneRecovery(current);
      let terminal = false;
      const locked: LockedBatV2RecoveryV2 = {
        persistState: async (state) => {
          if (terminal) throw new Error('BAT V2 recovery transition is already terminal');
          validateRecoveryState(state);
          const successor = { ...current, state: state.slice() };
          await putValue(this.db, RECOVERY_STORE, await this.encryptRecovery(successor));
          current.state.fill(0);
          current.state = successor.state;
          exposed.state.fill(0);
          exposed.state = successor.state.slice();
        },
        complete: async (records) => {
          if (terminal) throw new Error('BAT V2 recovery transition is already terminal');
          const ids = await this.completeAcquisitionUnlocked(recoveryId, current, records);
          terminal = true;
          return ids;
        },
      };
      try {
        return await operation(exposed, locked);
      } finally {
        current.state.fill(0);
        exposed.state.fill(0);
      }
    });
  }

  /**
   * Install a verified issuance batch and delete its recovery in one IDB
   * transaction. The issuer/class tuple is provider-independent.
   */
  async completeAcquisition(
    recoveryId: string,
    records: BatV2WalletRecordV2[],
  ): Promise<string[]> {
    canonicalOpaqueId('BAT V2 recovery ID', recoveryId);
    if (records.length === 0 || records.length > 65_535) {
      throw new Error('BAT V2 acquisition returned an invalid proof count');
    }
    return withExclusiveLock(async () => {
      const recoveryRow = await getValue<CipherRecoveryV1>(this.db, RECOVERY_STORE, recoveryId);
      if (!recoveryRow) throw new Error('BAT V2 recovery was not found (it may be complete)');
      const recovery = await this.decryptRecovery(recoveryRow);
      try {
        return await this.completeAcquisitionUnlocked(recoveryId, recovery, records);
      } finally {
        recovery.state.fill(0);
      }
    });
  }

  /** Aggregate non-secret class inventory; proofs and spend keys never escape. */
  async listInventory(): Promise<BatV2WalletInventoryV2[]> {
    return withExclusiveLock(async () => {
      const records = await this.decryptAllRecordsUnlocked();
      const aggregate = new Map<string, BatV2WalletInventoryV2>();
      try {
        for (const { plain } of records) {
          if (plain.state !== 'available') continue;
          const key = classBindingKey(plain);
          const existing = aggregate.get(key);
          if (existing) existing.count += 1;
          else aggregate.set(key, { ...classBinding(plain), count: 1 });
        }
        return [...aggregate.values()].sort((left, right) =>
          classBindingKey(left).localeCompare(classBindingKey(right)));
      } finally {
        zeroPlainRecords(records);
      }
    });
  }

  /**
   * Atomically reserve two distinct proofs before either provider sees one.
   * A single proof, or two rows with the same issuer-global spend key, yields
   * no lease and leaves the wallet unchanged.
   */
  async reserveDistinctPair(
    firstBinding: BatV2ClassBindingV2,
    secondBinding: BatV2ClassBindingV2,
    validateBeforeReserve?: (record: BatV2WalletRecordV2) => void,
  ): Promise<BatV2DistinctPairReservationV2 | null> {
    const first = normalizeClassBinding(firstBinding);
    const second = normalizeClassBinding(secondBinding);
    if (!sameClassBinding(first, second)) {
      throw new Error('a BAT V2 pair must use one exact acceptance class');
    }
    return withExclusiveLock(async () => {
      const records = await this.decryptAllRecordsUnlocked();
      let firstMatch: DecryptedRecordV1 | undefined;
      let secondMatch: DecryptedRecordV1 | undefined;
      try {
        firstMatch = records.find(({ plain }) =>
          plain.state === 'available' && sameClassBinding(plain, first));
        secondMatch = records.find(({ row, plain }) =>
          row.id !== firstMatch?.row.id
            && row.spendKeyDigestHex !== firstMatch?.row.spendKeyDigestHex
            && plain.state === 'available'
            && sameClassBinding(plain, second));
        if (!firstMatch || !secondMatch) return null;

        if (validateBeforeReserve) {
          for (const selected of [firstMatch, secondMatch]) {
            const candidate = walletRecord(selected.plain);
            try {
              validateBeforeReserve(candidate);
            } finally {
              candidate.proof.fill(0);
            }
          }
        }

        const reservationId = randomId();
        const owner = await acquireReservationOwnerLock(reservationId);
        this.reservationOwners.set(reservationId, {
          remainingRecordIds: new Set([firstMatch.row.id, secondMatch.row.id]),
          release: owner.release,
        });
        let firstLease: BatV2ReservedProofV2 | undefined;
        let secondLease: BatV2ReservedProofV2 | undefined;
        try {
          firstLease = reservedProof(firstMatch, reservationId);
          secondLease = reservedProof(secondMatch, reservationId);
          const replacements = await Promise.all([firstMatch, secondMatch].map(({ row, plain }) =>
            this.encryptRecord(
              row.id,
              walletRecord(plain),
              'reserved',
              reservationId,
              row.spendKeyDigestHex,
            )));
          await putRecordsTransaction(this.db, replacements);
          return { reservationId, first: firstLease, second: secondLease };
        } catch (error) {
          firstLease?.proof.fill(0);
          secondLease?.proof.fill(0);
          this.releaseReservationOwner(reservationId);
          throw error;
        }
      } finally {
        zeroPlainRecords(records);
      }
    });
  }

  /** Complete one reserved leg. Recover-safe makes it available; burn deletes it. */
  async finishReservation(
    lease: BatV2ReservedProofV2,
    disposition: BatV2ReservationDispositionV2,
  ): Promise<void> {
    if (disposition !== 'recover-safe' && disposition !== 'burn') {
      throw new Error('unknown BAT V2 reservation disposition');
    }
    canonicalOpaqueId('BAT V2 record ID', lease.recordId);
    canonicalOpaqueId('BAT V2 reservation ID', lease.reservationId);
    await withExclusiveLock(async () => {
      const row = await getValue<CipherRecordV1>(this.db, RECORD_STORE, lease.recordId);
      if (!row) throw new Error('BAT V2 reserved proof is no longer available');
      const decrypted = await this.decryptRecord(row);
      try {
        if (decrypted.plain.state !== 'reserved'
            || decrypted.plain.reservationId !== lease.reservationId
            || !sameClassBinding(decrypted.plain, lease)
            || decrypted.plain.globalSpendKeyHex !== lease.globalSpendKeyHex) {
          throw new Error('BAT V2 reservation lease does not match durable state');
        }
        if (disposition === 'burn') {
          await deleteValue(this.db, RECORD_STORE, row.id);
        } else {
          await putValue(
            this.db,
            RECORD_STORE,
            await this.encryptRecord(
              row.id,
              walletRecord(decrypted.plain),
              'available',
              undefined,
              row.spendKeyDigestHex,
            ),
          );
        }
        this.finishReservationOwnerLeg(lease.reservationId, lease.recordId);
      } finally {
        zeroPlainRecord(decrypted.plain);
        lease.proof.fill(0);
      }
    });
  }

  private async burnOrphanedReservationsUnlocked(): Promise<void> {
    const records = await this.decryptAllRecordsUnlocked();
    try {
      const reservations = new Map<string, string[]>();
      for (const { row, plain } of records) {
        if (plain.state !== 'reserved') continue;
        const reservationId = plain.reservationId!;
        const ids = reservations.get(reservationId) ?? [];
        ids.push(row.id);
        reservations.set(reservationId, ids);
      }
      for (const [reservationId, ids] of reservations) {
        await withAvailableReservationOwnerLock(reservationId, async () => {
          await deleteRecordsTransaction(this.db, ids);
        });
      }
    } finally {
      zeroPlainRecords(records);
    }
  }

  private finishReservationOwnerLeg(reservationId: string, recordId: string): void {
    const owner = this.reservationOwners.get(reservationId);
    if (!owner) return;
    owner.remainingRecordIds.delete(recordId);
    if (owner.remainingRecordIds.size === 0) this.releaseReservationOwner(reservationId);
  }

  private releaseReservationOwner(reservationId: string): void {
    const owner = this.reservationOwners.get(reservationId);
    if (!owner) return;
    this.reservationOwners.delete(reservationId);
    owner.release();
  }

  private async completeAcquisitionUnlocked(
    recoveryId: string,
    recovery: BatV2RecoveryRecordV2,
    records: BatV2WalletRecordV2[],
  ): Promise<string[]> {
    if (records.length === 0 || records.length > 65_535) {
      throw new Error('BAT V2 acquisition returned an invalid proof count');
    }
    const normalized = records.map(normalizeWalletRecord);
    try {
      for (const record of normalized) {
        if (record.issuerIdHex !== recovery.issuerIdHex) {
          throw new Error('issued BAT V2 proof does not match the recovery issuer');
        }
      }
      requireSingleClassBatch(normalized);
      const spendDigests = await Promise.all(normalized.map((record) =>
        spendKeyDigestHex(record.globalSpendKeyHex)));
      if (new Set(spendDigests).size !== spendDigests.length) {
        throw new Error('BAT V2 issuance returned a duplicate global spend key');
      }
      const ids = normalized.map(() => randomId());
      const encrypted = await Promise.all(normalized.map((record, index) =>
        this.encryptRecord(ids[index], record, 'available', undefined, spendDigests[index])));
      await completeAcquisitionTransaction(this.db, recoveryId, encrypted);
      recovery.state.fill(0);
      return ids;
    } finally {
      for (const record of normalized) record.proof.fill(0);
    }
  }

  private async decryptAllRecordsUnlocked(): Promise<DecryptedRecordV1[]> {
    const rows = await getAllValues<CipherRecordV1>(this.db, RECORD_STORE);
    const result: DecryptedRecordV1[] = [];
    try {
      for (const row of rows) result.push(await this.decryptRecord(row));
      return result;
    } catch (error) {
      zeroPlainRecords(result);
      throw error;
    }
  }

  private async encryptRecord(
    id: string,
    record: BatV2WalletRecordV2,
    state: PlainRecordV1['state'],
    reservationId: string | undefined,
    spendDigest?: string,
  ): Promise<CipherRecordV1> {
    canonicalOpaqueId('BAT V2 record ID', id);
    const normalized = normalizeWalletRecord(record);
    const spendKeyDigest = spendDigest ?? await spendKeyDigestHex(normalized.globalSpendKeyHex);
    canonicalHex32('spendKeyDigestHex', spendKeyDigest);
    if ((state === 'reserved') !== (reservationId !== undefined)) {
      throw new Error('BAT V2 reserved state must carry exactly one reservation ID');
    }
    if (reservationId !== undefined) canonicalOpaqueId('BAT V2 reservation ID', reservationId);
    const plain: PlainRecordV1 = {
      version: 1,
      ...classBinding(normalized),
      proofBase64: bytesToBase64(normalized.proof),
      globalSpendKeyHex: normalized.globalSpendKeyHex,
      state,
      ...(reservationId === undefined ? {} : { reservationId }),
    };
    const bytes = new TextEncoder().encode(JSON.stringify(plain));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    try {
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: ownedArrayBuffer(iv),
          additionalData: aad(RECORD_AAD_DOMAIN, id, spendKeyDigest),
        },
        this.key,
        ownedArrayBuffer(bytes),
      );
      return { id, spendKeyDigestHex: spendKeyDigest, iv: ownedArrayBuffer(iv), ciphertext };
    } finally {
      bytes.fill(0);
      normalized.proof.fill(0);
    }
  }

  private async decryptRecord(row: CipherRecordV1): Promise<DecryptedRecordV1> {
    try {
      canonicalOpaqueId('BAT V2 record ID', row.id);
      canonicalHex32('spendKeyDigestHex', row.spendKeyDigestHex);
      const bytes = new Uint8Array(await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: row.iv,
          additionalData: aad(RECORD_AAD_DOMAIN, row.id, row.spendKeyDigestHex),
        },
        this.key,
        row.ciphertext,
      ));
      try {
        const plain = JSON.parse(new TextDecoder().decode(bytes)) as PlainRecordV1;
        validatePlainRecord(plain);
        const actualDigest = await spendKeyDigestHex(plain.globalSpendKeyHex);
        if (actualDigest !== row.spendKeyDigestHex) throw new Error('spend key digest');
        return { row, plain };
      } finally {
        bytes.fill(0);
      }
    } catch {
      throw new Error('BAT V2 wallet record authentication or decoding failed');
    }
  }

  private async encryptRecovery(value: BatV2RecoveryRecordV2): Promise<CipherRecoveryV1> {
    validateRecovery(value);
    const plain: PlainRecoveryV1 = {
      version: 1,
      issuerEndpoint: canonicalIssuerEndpoint(value.issuerEndpoint),
      issuerIdHex: canonicalHex32('issuerIdHex', value.issuerIdHex),
      network: value.network,
      expectedPayeePubkeyHex: canonicalCompressedPointHex(
        'expectedPayeePubkeyHex', value.expectedPayeePubkeyHex,
      ),
      stateBase64: bytesToBase64(value.state),
    };
    const bytes = new TextEncoder().encode(JSON.stringify(plain));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    try {
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: ownedArrayBuffer(iv),
          additionalData: aad(RECOVERY_AAD_DOMAIN, value.id),
        },
        this.key,
        ownedArrayBuffer(bytes),
      );
      return { id: value.id, iv: ownedArrayBuffer(iv), ciphertext };
    } finally {
      bytes.fill(0);
    }
  }

  private async encryptOpaqueBytes(
    id: string,
    value: Uint8Array,
    domain: string,
  ): Promise<CipherRecoveryV1> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: ownedArrayBuffer(iv),
        additionalData: aad(domain, id),
      },
      this.key,
      ownedArrayBuffer(value),
    );
    return { id, iv: ownedArrayBuffer(iv), ciphertext };
  }

  private async decryptOpaqueBytes(row: CipherRecoveryV1, domain: string): Promise<Uint8Array> {
    try {
      return new Uint8Array(await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: row.iv,
          additionalData: aad(domain, row.id),
        },
        this.key,
        row.ciphertext,
      ));
    } catch {
      throw new Error('BAT V2 quote-key checkpoint authentication failed');
    }
  }

  private async decryptRecovery(row: CipherRecoveryV1): Promise<BatV2RecoveryRecordV2> {
    try {
      canonicalOpaqueId('BAT V2 recovery ID', row.id);
      const bytes = new Uint8Array(await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: row.iv,
          additionalData: aad(RECOVERY_AAD_DOMAIN, row.id),
        },
        this.key,
        row.ciphertext,
      ));
      try {
        const plain = JSON.parse(new TextDecoder().decode(bytes)) as PlainRecoveryV1;
        if (plain.version !== 1) throw new Error('version');
        const value: BatV2RecoveryRecordV2 = {
          id: row.id,
          issuerEndpoint: plain.issuerEndpoint,
          issuerIdHex: plain.issuerIdHex,
          network: plain.network,
          expectedPayeePubkeyHex: plain.expectedPayeePubkeyHex,
          state: base64ToBytes(plain.stateBase64),
        };
        validateRecovery(value);
        return value;
      } finally {
        bytes.fill(0);
      }
    } catch {
      throw new Error('BAT V2 recovery authentication or decoding failed');
    }
  }
}

export function validateBatV2ClassBindingV2(binding: BatV2ClassBindingV2): void {
  normalizeClassBinding(binding);
}

export function validateBatV2WalletRecordV2(record: BatV2WalletRecordV2): void {
  const normalized = normalizeWalletRecord(record);
  normalized.proof.fill(0);
}

function normalizeWalletRecord(record: BatV2WalletRecordV2): BatV2WalletRecordV2 {
  const binding = normalizeClassBinding(record);
  if (!(record.proof instanceof Uint8Array) || record.proof.length !== BAT_V2_PROOF_LEN) {
    throw new Error(`BAT V2 proof must be exactly ${BAT_V2_PROOF_LEN} bytes`);
  }
  return {
    ...binding,
    proof: record.proof.slice(),
    globalSpendKeyHex: canonicalHex32('globalSpendKeyHex', record.globalSpendKeyHex),
  };
}

function normalizeClassBinding(binding: BatV2ClassBindingV2): BatV2ClassBindingV2 {
  return {
    issuerIdHex: canonicalHex32('issuerIdHex', binding.issuerIdHex),
    classIdHex: canonicalHex32('classIdHex', binding.classIdHex),
    classDigestHex: canonicalHex32('classDigestHex', binding.classDigestHex),
    classKeyEpoch: canonicalPositiveDecimal('classKeyEpoch', binding.classKeyEpoch),
    batKeyIdHex: canonicalHex32('batKeyIdHex', binding.batKeyIdHex),
  };
}

function validatePlainRecord(plain: PlainRecordV1): void {
  if (plain.version !== 1) throw new Error('version');
  normalizeClassBinding(plain);
  canonicalHex32('globalSpendKeyHex', plain.globalSpendKeyHex);
  const proof = base64ToBytes(plain.proofBase64);
  try {
    if (proof.length !== BAT_V2_PROOF_LEN) throw new Error('proof length');
  } finally {
    proof.fill(0);
  }
  if (plain.state === 'available') {
    if (plain.reservationId !== undefined) throw new Error('available reservation');
  } else if (plain.state === 'reserved') {
    if (plain.reservationId === undefined) throw new Error('missing reservation');
    canonicalOpaqueId('BAT V2 reservation ID', plain.reservationId);
  } else {
    throw new Error('state');
  }
}

function walletRecord(plain: PlainRecordV1): BatV2WalletRecordV2 {
  return {
    ...classBinding(plain),
    proof: base64ToBytes(plain.proofBase64),
    globalSpendKeyHex: plain.globalSpendKeyHex,
  };
}

function reservedProof(record: DecryptedRecordV1, reservationId: string): BatV2ReservedProofV2 {
  return {
    ...walletRecord(record.plain),
    recordId: record.row.id,
    reservationId,
  };
}

function classBinding(value: BatV2ClassBindingV2): BatV2ClassBindingV2 {
  return {
    issuerIdHex: value.issuerIdHex,
    classIdHex: value.classIdHex,
    classDigestHex: value.classDigestHex,
    classKeyEpoch: value.classKeyEpoch,
    batKeyIdHex: value.batKeyIdHex,
  };
}

function classBindingKey(value: BatV2ClassBindingV2): string {
  return [
    value.issuerIdHex,
    value.classIdHex,
    value.classDigestHex,
    value.classKeyEpoch,
    value.batKeyIdHex,
  ].join(':');
}

function sameClassBinding(left: BatV2ClassBindingV2, right: BatV2ClassBindingV2): boolean {
  return classBindingKey(left) === classBindingKey(right);
}

function requireSingleClassBatch(records: BatV2WalletRecordV2[]): void {
  const first = classBindingKey(records[0]);
  if (records.some((record) => classBindingKey(record) !== first)) {
    throw new Error('one BAT V2 issuance batch must belong to one exact class');
  }
}

function validateRecovery(value: BatV2RecoveryRecordV2): void {
  canonicalOpaqueId('BAT V2 recovery ID', value.id);
  canonicalIssuerEndpoint(value.issuerEndpoint);
  canonicalHex32('issuerIdHex', value.issuerIdHex);
  if (!['bitcoin', 'testnet', 'signet', 'regtest'].includes(value.network)) {
    throw new Error('unsupported BAT V2 Lightning network');
  }
  canonicalCompressedPointHex('expectedPayeePubkeyHex', value.expectedPayeePubkeyHex);
  validateRecoveryState(value.state);
}

function validateRecoveryState(state: Uint8Array): void {
  if (!(state instanceof Uint8Array) || state.length === 0 || state.length > MAX_RECOVERY_STATE_LEN) {
    throw new Error('BAT V2 recovery state exceeds its bound');
  }
}

function validateQuoteKeyCheckpoint(value: Uint8Array): void {
  if (!(value instanceof Uint8Array)
      || value.length === 0
      || value.length > MAX_QUOTE_KEY_CHECKPOINT_LEN) {
    throw new Error('BAT V2 quote-key checkpoint exceeds its bound');
  }
}

async function quoteKeyCheckpointId(
  issuerIdHex: string,
  network: LightningNetworkNameV2,
  payeeHex: string,
): Promise<string> {
  const bytes = new TextEncoder().encode(
    `${QUOTE_KEY_ID_DOMAIN}\0${issuerIdHex}\0${network}\0${payeeHex}`,
  );
  try {
    return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
  } finally {
    bytes.fill(0);
  }
}

function cloneRecovery(value: BatV2RecoveryRecordV2): BatV2RecoveryRecordV2 {
  return { ...value, state: value.state.slice() };
}

function zeroPlainRecord(plain: PlainRecordV1): void {
  const proof = base64ToBytes(plain.proofBase64);
  proof.fill(0);
  plain.proofBase64 = '';
  plain.globalSpendKeyHex = '';
}

function zeroPlainRecords(records: DecryptedRecordV1[]): void {
  for (const { plain } of records) zeroPlainRecord(plain);
}

async function spendKeyDigestHex(globalSpendKeyHex: string): Promise<string> {
  const key = hexToBytes(canonicalHex32('globalSpendKeyHex', globalSpendKeyHex));
  const domain = new TextEncoder().encode(SPEND_KEY_DIGEST_DOMAIN);
  const bytes = new Uint8Array(domain.length + key.length);
  bytes.set(domain);
  bytes.set(key, domain.length);
  try {
    return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
  } finally {
    key.fill(0);
    bytes.fill(0);
  }
}

function requireBrowserPrimitives(): void {
  if (typeof indexedDB === 'undefined') throw new Error('IndexedDB is required for BAT V2 storage');
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('WebCrypto is required for BAT V2 storage');
  }
  if (typeof navigator === 'undefined' || !navigator.locks) {
    throw new Error('Web Locks are required for BAT V2 at-most-once storage');
  }
}

async function withExclusiveLock<T>(body: () => Promise<T>): Promise<T> {
  return navigator.locks.request(GLOBAL_LOCK, { mode: 'exclusive' }, body);
}

async function acquireReservationOwnerLock(
  reservationId: string,
): Promise<Pick<ReservationOwnerV1, 'release'>> {
  const name = reservationOwnerLockName(reservationId);
  let releaseHeldLock!: () => void;
  const held = new Promise<void>((resolve) => {
    releaseHeldLock = resolve;
  });
  let resolveAcquired!: () => void;
  let rejectAcquired!: (error: unknown) => void;
  const acquired = new Promise<void>((resolve, reject) => {
    resolveAcquired = resolve;
    rejectAcquired = reject;
  });
  let request: Promise<void>;
  try {
    request = Promise.resolve(
      navigator.locks.request(name, { mode: 'exclusive' }, async (lock) => {
        if (!lock) throw new Error('BAT V2 reservation owner lock was not acquired');
        resolveAcquired();
        await held;
      }),
    );
  } catch (error) {
    rejectAcquired(error);
    throw error;
  }
  void request.then(
    () => rejectAcquired(new Error('BAT V2 reservation owner lock ended before acquisition')),
    rejectAcquired,
  );
  await acquired;
  let released = false;
  return {
    release: () => {
      if (released) return;
      released = true;
      releaseHeldLock();
    },
  };
}

async function withAvailableReservationOwnerLock(
  reservationId: string,
  body: () => Promise<void>,
): Promise<void> {
  await navigator.locks.request(
    reservationOwnerLockName(reservationId),
    { mode: 'exclusive', ifAvailable: true },
    async (lock) => {
      if (!lock) return;
      await body();
    },
  );
}

function reservationOwnerLockName(reservationId: string): string {
  return `${RESERVATION_OWNER_LOCK_PREFIX}:${canonicalOpaqueId(
    'BAT V2 reservation ID', reservationId,
  )}`;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(META_STORE)) {
        db.createObjectStore(META_STORE, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(RECORD_STORE)) {
        const records = db.createObjectStore(RECORD_STORE, { keyPath: 'id' });
        records.createIndex(SPEND_KEY_INDEX, 'spendKeyDigestHex', { unique: true });
      }
      if (!db.objectStoreNames.contains(RECOVERY_STORE)) {
        db.createObjectStore(RECOVERY_STORE, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(QUOTE_KEY_STORE)) {
        db.createObjectStore(QUOTE_KEY_STORE, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('failed to open BAT V2 IndexedDB'));
    request.onblocked = () => reject(new Error('BAT V2 IndexedDB upgrade is blocked'));
  });
}

function getValue<T>(db: IDBDatabase, storeName: string, key: IDBValidKey): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const request = tx.objectStore(storeName).get(key);
    request.onsuccess = () => resolve(request.result as T | undefined);
    request.onerror = () => reject(new Error(`BAT V2 IndexedDB ${storeName} read failed`));
    tx.onabort = () => reject(new Error(`BAT V2 IndexedDB ${storeName} read aborted`));
  });
}

function getAllValues<T>(db: IDBDatabase, storeName: string): Promise<T[]> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const request = tx.objectStore(storeName).getAll();
    request.onsuccess = () => resolve(request.result as T[]);
    request.onerror = () => reject(new Error(`BAT V2 IndexedDB ${storeName} scan failed`));
    tx.onabort = () => reject(new Error(`BAT V2 IndexedDB ${storeName} scan aborted`));
  });
}

function putValue(db: IDBDatabase, storeName: string, value: unknown): Promise<void> {
  return writeOne(db, storeName, 'put', value);
}

function addValue(db: IDBDatabase, storeName: string, value: unknown): Promise<void> {
  return writeOne(db, storeName, 'add', value);
}

function deleteValue(db: IDBDatabase, storeName: string, key: IDBValidKey): Promise<void> {
  return writeOne(db, storeName, 'delete', key);
}

function writeOne(
  db: IDBDatabase,
  storeName: string,
  operation: 'put' | 'add' | 'delete',
  value: unknown,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    if (operation === 'delete') store.delete(value as IDBValidKey);
    else if (operation === 'put') store.put(value);
    else store.add(value);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error(`BAT V2 IndexedDB ${storeName} write failed`));
    tx.onabort = () => reject(new Error(`BAT V2 IndexedDB ${storeName} write aborted`));
  });
}

function completeAcquisitionTransaction(
  db: IDBDatabase,
  recoveryId: string,
  records: CipherRecordV1[],
): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction([RECOVERY_STORE, RECORD_STORE], 'readwrite');
    const recoveries = tx.objectStore(RECOVERY_STORE);
    const wallet = tx.objectStore(RECORD_STORE);
    const get = recoveries.get(recoveryId);
    get.onsuccess = () => {
      if (!get.result) {
        tx.abort();
        return;
      }
      for (const record of records) wallet.add(record);
      recoveries.delete(recoveryId);
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error('BAT V2 acquisition transaction failed'));
    tx.onabort = () => reject(new Error('BAT V2 acquisition was already complete or conflicted'));
  });
}

function putRecordsTransaction(db: IDBDatabase, records: CipherRecordV1[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(RECORD_STORE, 'readwrite');
    const store = tx.objectStore(RECORD_STORE);
    for (const record of records) store.put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error('BAT V2 pair reservation failed'));
    tx.onabort = () => reject(new Error('BAT V2 pair reservation aborted'));
  });
}

function deleteRecordsTransaction(db: IDBDatabase, ids: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(RECORD_STORE, 'readwrite');
    const store = tx.objectStore(RECORD_STORE);
    for (const id of ids) store.delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error('BAT V2 orphan burn failed'));
    tx.onabort = () => reject(new Error('BAT V2 orphan burn aborted'));
  });
}

function aad(domain: string, id: string, binding = ''): ArrayBuffer {
  return ownedArrayBuffer(new TextEncoder().encode(`${domain}\0${id}\0${binding}`));
}

function randomId(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}

function canonicalOpaqueId(field: string, value: string): string {
  return canonicalHex32(field, value);
}

function canonicalHex32(field: string, value: string): string {
  if (!/^[0-9a-fA-F]{64}$/.test(value) || /^0{64}$/i.test(value)) {
    throw new Error(`${field} must be non-zero 32-byte hex`);
  }
  return value.toLowerCase();
}

function canonicalPositiveDecimal(field: string, value: string): string {
  if (!/^[1-9][0-9]*$/.test(value)) throw new Error(`${field} must be a positive decimal`);
  const parsed = BigInt(value);
  if (parsed > 0xffff_ffff_ffff_ffffn) throw new Error(`${field} exceeds u64`);
  return parsed.toString();
}

function canonicalCompressedPointHex(field: string, value: string): string {
  if (!/^(02|03)[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${field} must be a compressed 33-byte point`);
  }
  return value.toLowerCase();
}

function canonicalIssuerEndpoint(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('BAT V2 issuer endpoint must be an absolute URL');
  }
  const loopback = url.hostname === '127.0.0.1'
    || url.hostname === 'localhost'
    || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error('BAT V2 issuer endpoint must use HTTPS');
  }
  if (url.username || url.password || url.search || url.hash
      || (url.pathname !== '' && url.pathname !== '/')) {
    throw new Error('BAT V2 issuer endpoint must be a credential-free origin');
  }
  return url.origin;
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function base64ToBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error('invalid base64');
  const bytes = new Uint8Array(Buffer.from(value, 'base64'));
  if (bytesToBase64(bytes) !== value) throw new Error('non-canonical base64');
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(value: string): Uint8Array {
  return new Uint8Array(value.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}
