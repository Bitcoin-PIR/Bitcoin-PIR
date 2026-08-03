/**
 * Encrypted, provider-scoped browser storage for V1 service capabilities.
 *
 * Security properties:
 * - IndexedDB only; no capability, ARC nonce state, quote, or invoice is
 *   written to localStorage. In-flight quote recovery is encrypted as one
 *   opaque record and is never joined to query/address history.
 * - AES-GCM under a non-extractable WebCrypto key stored as a structured
 *   clone. This prevents accidental plaintext persistence; it does not protect
 *   a copied browser profile or a compromised same-origin script (XSS can ask
 *   WebCrypto to decrypt).
 * - Web Locks serialize consume/ARC-advance across tabs.
 * - Single-use bytes are durably deleted before being returned to the caller.
 *   A network failure after that point is an ambiguous spend and is not
 *   automatically retried.
 * - Capability records are bound to exactly one
 *   provider/policy/scope/offer. There is no pair ID. Invoice/claim recovery
 *   exists only inside a separately authenticated ciphertext and is deleted
 *   when issuance completes.
 */

const DB_NAME = 'bitcoinpir-admission-v1';
const DB_VERSION = 4;
const META_STORE = 'meta';
const RECORD_STORE = 'records';
const CHECKPOINT_STORE = 'checkpoints';
const QUOTE_KEY_CHECKPOINT_STORE = 'quote-key-checkpoints';
const BOLT11_RECOVERY_STORE = 'bolt11-recovery';
const KEY_ID = 'non-extractable-aes-gcm-v1';
const RECORD_AAD_DOMAIN = 'BitcoinPIR/admission-vault/record/v1';
const CHECKPOINT_AAD_DOMAIN = 'BitcoinPIR/admission-vault/checkpoint/v1';
const QUOTE_KEY_CHECKPOINT_AAD_DOMAIN = 'BitcoinPIR/admission-vault/quote-key-checkpoint/v1';
const BOLT11_RECOVERY_AAD_DOMAIN = 'BitcoinPIR/admission-vault/bolt11-recovery/v1';
const MAX_CAPABILITY_BYTES_V1 = 12 * 1024;
const MAX_POLICY_CHECKPOINT_BYTES_V1 = 64 * 1024;
const MAX_BOLT11_RECOVERY_STATE_BYTES_V1 = 4 * 1024 * 1024;

export type AdmissionSchemeV1 =
  | 'free-anonymous-ticket'
  | 'bolt11-direct-receipt'
  | 'cashu-ecash'
  | 'cashu-bat'
  | 'arc-experimental';

export interface AdmissionCapabilityBindingV1 {
  providerIdHex: string;
  /** Exact signed policy which authorized this offer. */
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  scheme: AdmissionSchemeV1;
}

/**
 * Minimal historical payment context needed by the browser-only strict-pair
 * guard. It deliberately excludes invoice, payment hash, quote ID, wallet,
 * query, and result data.
 */
export interface Bolt11CapabilityAcquisitionContextV1 {
  kind: 'bolt11';
  issuerEndpoint: string;
  issuerIdHex: string;
  network: LightningNetworkNameV1;
  expectedPayeePubkeyHex: string;
}

export interface AdmissionCapabilityV1 extends AdmissionCapabilityBindingV1 {
  /** Canonical proof bytes, or serialized ARC presentation state. */
  payload: Uint8Array;
  /** Present only when this capability was minted through BOLT11. */
  acquisitionContext?: Bolt11CapabilityAcquisitionContextV1;
}

export interface AdmissionCapabilityInventoryV1 extends AdmissionCapabilityBindingV1 {
  count: number;
  /** Separates otherwise-identical inventory acquired through different payees. */
  acquisitionContext?: Bolt11CapabilityAcquisitionContextV1;
}

interface PlainRecordV2 {
  version: 2;
  providerIdHex: string;
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  scheme: AdmissionSchemeV1;
  payloadBase64: string;
}

interface PlainRecordV3 extends Omit<PlainRecordV2, 'version'> {
  version: 3;
  acquisitionContext?: Bolt11CapabilityAcquisitionContextV1;
}

type PlainRecordV1 = PlainRecordV2 | PlainRecordV3;

interface CipherRecordV1 {
  id: string;
  /** SHA-256 of the canonical binding used as part of AES-GCM AAD. */
  bindingDigestHex?: string;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
}

interface KeyRecordV1 {
  id: string;
  key: CryptoKey;
}

export type LightningNetworkNameV1 = 'bitcoin' | 'testnet' | 'signet' | 'regtest';

export interface Bolt11RecoveryRecordV1 {
  id: string;
  /** HTTPS issuer endpoint copied from the exact verified signed offer. */
  issuerEndpoint: string;
  /** Exact issuer identity committed by the signed offer and quote intent. */
  issuerIdHex: string;
  /** Exact Lightning network committed by the delegated quote key. */
  network: LightningNetworkNameV1;
  /** Independently trusted compressed payee key, never inferred on resume. */
  expectedPayeePubkeyHex: string;
  providerIdHex: string;
  /** Exact signed policy selected before any invoice was created. */
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  /** Exact capability family committed by the signed offer before quote I/O. */
  expectedScheme: Extract<
    AdmissionSchemeV1,
    'bolt11-direct-receipt' | 'cashu-bat' | 'arc-experimental'
  >;
  /** Opaque WASM state containing claim secrets and, after quote, the invoice. */
  state: Uint8Array;
}

interface PlainBolt11RecoveryRecordV1 {
  version: 4;
  issuerEndpoint: string;
  issuerIdHex: string;
  network: LightningNetworkNameV1;
  expectedPayeePubkeyHex: string;
  providerIdHex: string;
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  expectedScheme: Bolt11RecoveryRecordV1['expectedScheme'];
  stateBase64: string;
}

export interface ArcAdvanceV1 {
  nextState: Uint8Array;
  remaining: number;
  /** Called by the vault only after the successor transaction commits. */
  releaseAfterPersisted: () => Uint8Array;
  /** Dispose the withheld transition if persistence fails. */
  discard: () => void;
}

export interface PolicyCheckpointAdvanceV1<T> {
  nextCheckpoint: Uint8Array;
  value: T;
  /** Dispose an unreturned WASM handle if durable persistence fails. */
  discard?: () => void;
}

/**
 * Mutations available only while the recovery-specific cross-tab lock is held.
 * Keeping the lock across the issuer HTTP request is intentional: otherwise a
 * stale status poll can overwrite an exact, already-persisted claim envelope.
 */
export interface LockedBolt11RecoveryV1 {
  persistState(state: Uint8Array): Promise<void>;
  complete(capabilities: AdmissionCapabilityV1[]): Promise<string[]>;
}

export class AdmissionCredentialVaultV1 {
  private constructor(
    private readonly db: IDBDatabase,
    private readonly key: CryptoKey,
  ) {}

  static async open(): Promise<AdmissionCredentialVaultV1> {
    requireBrowserPrimitives();
    return withExclusiveLock('bitcoinpir:admission-vault:init', async () => {
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
        throw new Error('admission vault key is not a non-extractable AES-GCM key');
      }
      return new AdmissionCredentialVaultV1(db, key);
    });
  }

  close(): void {
    this.db.close();
  }

  /**
   * Store a provider-bound capability plus, when applicable, the minimal
   * encrypted BOLT11 context needed to prevent historical payee confusion.
   */
  async putCapability(capability: AdmissionCapabilityV1): Promise<string> {
    validateCapabilityV1(capability);
    if (capability.acquisitionContext !== undefined) {
      throw new Error('BOLT11 acquisition context is accepted only from atomic claim recovery');
    }
    const id = randomId();
    const encrypted = await this.encryptRecord(id, capability);
    await withExclusiveLock(lockName(capability), async () => {
      await addValue(this.db, RECORD_STORE, encrypted);
    });
    return id;
  }

  /**
   * Select and retire one single-use capability under a cross-tab lock.
   * ARC is rejected here because it needs an atomic state advance instead.
   * The exclusive lock is the local reservation: validation failure releases
   * it with the encrypted record unchanged, while validation success commits
   * deletion before any payload bytes are returned to application code.
   */
  async takeSingleUseCapability(
    binding: AdmissionCapabilityBindingV1,
    validateBeforeRetire?: (payload: Uint8Array) => void,
    expectedAcquisitionContext?: Bolt11CapabilityAcquisitionContextV1 | null,
  ): Promise<AdmissionCapabilityV1 | null> {
    validateBindingV1(binding);
    if (binding.scheme === 'arc-experimental') {
      throw new Error('ARC state must be advanced with advanceArcCredential');
    }
    return withExclusiveLock(lockName(binding), async () => {
      const match = await this.findExact(binding, expectedAcquisitionContext);
      if (!match) return null;
      // Local canonical validation must complete while the record is still
      // recoverable. Once deleted, all network outcomes are ambiguous.
      if (validateBeforeRetire) {
        const validationCopy = match.plain.payload.slice();
        try {
          validateBeforeRetire(validationCopy);
        } catch (error) {
          match.plain.payload.fill(0);
          throw error;
        } finally {
          validationCopy.fill(0);
        }
      }
      // Delete-before-return is the client-side half of at-most-once use.
      try {
        await deleteValue(this.db, RECORD_STORE, match.id);
      } catch (error) {
        match.plain.payload.fill(0);
        throw error;
      }
      return match.plain;
    });
  }

  /**
   * Return only the number of records matching one exact signed offer.
   * Secret payloads and record IDs never leave the vault. This is intended
   * for product UI inventory state before the destructive one-shot take.
   */
  async countCapabilities(
    binding: AdmissionCapabilityBindingV1,
    expectedAcquisitionContext?: Bolt11CapabilityAcquisitionContextV1 | null,
  ): Promise<number> {
    validateBindingV1(binding);
    return withExclusiveLock(lockName(binding), async () => {
      const rows = await getAllValues<CipherRecordV1>(this.db, RECORD_STORE);
      let count = 0;
      for (const row of rows) {
        const plain = await this.decryptRecord(row);
        try {
          if (sameBinding(plain, binding)
              && (expectedAcquisitionContext === undefined
                || sameAcquisitionContext(plain.acquisitionContext, expectedAcquisitionContext))) {
            count += 1;
          }
        } finally {
          plain.payload.fill(0);
        }
      }
      return count;
    });
  }

  /**
   * List only aggregate, non-secret exact bindings for retained-policy UI.
   * Payloads and record IDs never leave the vault. This snapshot is advisory;
   * the destructive per-binding lock remains authoritative at redemption.
   */
  async listCapabilityInventory(
    providerIdHex?: string,
  ): Promise<AdmissionCapabilityInventoryV1[]> {
    const provider = providerIdHex === undefined
      ? null
      : canonicalHex32('providerIdHex', providerIdHex);
    const rows = await getAllValues<CipherRecordV1>(this.db, RECORD_STORE);
    const inventory = new Map<string, AdmissionCapabilityInventoryV1>();
    for (const row of rows) {
      const capability = await this.decryptRecord(row);
      try {
        if (provider !== null && capability.providerIdHex !== provider) continue;
        const binding: AdmissionCapabilityBindingV1 = {
          providerIdHex: capability.providerIdHex,
          policyDigestHex: capability.policyDigestHex,
          scopeIdHex: capability.scopeIdHex,
          offerId: capability.offerId,
          scheme: capability.scheme,
        };
        const acquisitionContext = cloneAcquisitionContext(capability.acquisitionContext);
        const key = `${lockName(binding)}:${acquisitionContextFingerprint(acquisitionContext)}`;
        const existing = inventory.get(key);
        if (existing) existing.count += 1;
        else inventory.set(key, { ...binding, count: 1, acquisitionContext });
      } finally {
        capability.payload.fill(0);
      }
    }
    return [...inventory.values()].sort((left, right) =>
      left.policyDigestHex.localeCompare(right.policyDigestHex)
      || left.scopeIdHex.localeCompare(right.scopeIdHex)
      || left.offerId - right.offerId
      || left.scheme.localeCompare(right.scheme));
  }

  /**
   * Advance one ARC credential under a cross-tab lock and durably commit the
   * new nonce state before returning its presentation.
   */
  async advanceArcCredential(
    binding: AdmissionCapabilityBindingV1,
    advance: (serializedState: Uint8Array) => ArcAdvanceV1,
    expectedAcquisitionContext?: Bolt11CapabilityAcquisitionContextV1 | null,
  ): Promise<Uint8Array | null> {
    validateBindingV1(binding);
    if (binding.scheme !== 'arc-experimental') {
      throw new Error('advanceArcCredential requires arc-experimental binding');
    }
    return withExclusiveLock(lockName(binding), async () => {
      const match = await this.findExact(binding, expectedAcquisitionContext);
      if (!match) return null;
      const serializedState = match.plain.payload.slice();
      let advanced: ArcAdvanceV1;
      try {
        advanced = advance(serializedState);
      } finally {
        serializedState.fill(0);
        match.plain.payload.fill(0);
      }
      if (
        !(advanced.nextState instanceof Uint8Array) ||
        advanced.nextState.length === 0 ||
        advanced.nextState.length > MAX_CAPABILITY_BYTES_V1 ||
        !Number.isSafeInteger(advanced.remaining) ||
        advanced.remaining < 0 ||
        typeof advanced.releaseAfterPersisted !== 'function' ||
        typeof advanced.discard !== 'function'
      ) {
        try {
          if (typeof advanced.discard === 'function') advanced.discard();
        } finally {
          if (advanced.nextState instanceof Uint8Array) advanced.nextState.fill(0);
        }
        throw new Error('ARC advance callback returned an invalid state transition');
      }
      try {
        if (advanced.remaining === 0) {
          await deleteValue(this.db, RECORD_STORE, match.id);
        } else {
          const next = await this.encryptRecord(match.id, {
            ...match.plain,
            payload: advanced.nextState,
          });
          await putValue(this.db, RECORD_STORE, next);
        }
      } catch (error) {
        advanced.discard();
        throw error;
      } finally {
        advanced.nextState.fill(0);
      }
      let presentation: Uint8Array | null = null;
      try {
        presentation = advanced.releaseAfterPersisted();
        if (!(presentation instanceof Uint8Array) || presentation.length === 0) {
          throw new Error('ARC transition released an invalid presentation after persistence');
        }
        return presentation.slice();
      } catch (error) {
        advanced.discard();
        throw error;
      } finally {
        presentation?.fill(0);
      }
    });
  }

  /** Persist the anti-rollback checkpoint independently for one provider. */
  async putPolicyCheckpoint(providerIdHex: string, checkpoint: Uint8Array): Promise<void> {
    const provider = canonicalHex32('providerIdHex', providerIdHex);
    validatePolicyCheckpoint(checkpoint);
    const id = await checkpointId(provider);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: ownedArrayBuffer(iv),
        additionalData: aad(CHECKPOINT_AAD_DOMAIN, id),
      },
      this.key,
      ownedArrayBuffer(checkpoint),
    );
    await withExclusiveLock(`bitcoinpir:policy:${id}`, () =>
      putValue(this.db, CHECKPOINT_STORE, {
        id,
        iv: iv.buffer.slice(0),
        ciphertext,
      } satisfies CipherRecordV1),
    );
  }

  async getPolicyCheckpoint(providerIdHex: string): Promise<Uint8Array | null> {
    const provider = canonicalHex32('providerIdHex', providerIdHex);
    const id = await checkpointId(provider);
    return withExclusiveLock(`bitcoinpir:policy:${id}`, async () => {
      const row = await getValue<CipherRecordV1>(this.db, CHECKPOINT_STORE, id);
      if (!row) return null;
      try {
        const plaintext = await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: row.iv,
            additionalData: aad(CHECKPOINT_AAD_DOMAIN, id),
          },
          this.key,
          row.ciphertext,
        );
        return new Uint8Array(plaintext);
      } catch {
        throw new Error('service policy checkpoint authentication failed');
      }
    });
  }

  /**
   * Serialize load -> network verification -> durable advance for one provider
   * across every same-origin tab. The returned value is exposed only after the
   * successor checkpoint is committed.
   */
  async advancePolicyCheckpoint<T>(
    providerIdHex: string,
    initialCheckpoint: Uint8Array,
    advance: (
      currentCheckpoint: Uint8Array,
    ) => Promise<PolicyCheckpointAdvanceV1<T>> | PolicyCheckpointAdvanceV1<T>,
  ): Promise<T> {
    const provider = canonicalHex32('providerIdHex', providerIdHex);
    validatePolicyCheckpoint(initialCheckpoint);
    const id = await checkpointId(provider);
    return withExclusiveLock(`bitcoinpir:policy:${id}`, async () => {
      const row = await getValue<CipherRecordV1>(this.db, CHECKPOINT_STORE, id);
      const current = row
        ? await this.decryptBytes(
          row,
          CHECKPOINT_AAD_DOMAIN,
          'service policy checkpoint authentication failed',
        )
        : initialCheckpoint.slice();
      let result: PolicyCheckpointAdvanceV1<T> | null = null;
      try {
        result = await advance(current);
        validatePolicyCheckpoint(result.nextCheckpoint);
        await putValue(
          this.db,
          CHECKPOINT_STORE,
          await this.encryptBytes(id, result.nextCheckpoint, CHECKPOINT_AAD_DOMAIN),
        );
        return result.value;
      } catch (error) {
        result?.discard?.();
        throw error;
      }
    });
  }

  /** Persist one issuer/network/payee quote-key rollback stream. */
  async putQuoteKeyCheckpoint(
    issuerIdHex: string,
    network: LightningNetworkNameV1,
    expectedPayeePubkeyHex: string,
    checkpoint: Uint8Array,
  ): Promise<void> {
    const id = await quoteKeyCheckpointId(issuerIdHex, network, expectedPayeePubkeyHex);
    if (!(checkpoint instanceof Uint8Array) || checkpoint.length === 0) {
      throw new Error('BOLT11 quote-key checkpoint must be non-empty bytes');
    }
    const row = await this.encryptBytes(
      id,
      checkpoint,
      QUOTE_KEY_CHECKPOINT_AAD_DOMAIN,
    );
    await withExclusiveLock(`bitcoinpir:quote-key:${id}`, () =>
      putValue(this.db, QUOTE_KEY_CHECKPOINT_STORE, row),
    );
  }

  async getQuoteKeyCheckpoint(
    issuerIdHex: string,
    network: LightningNetworkNameV1,
    expectedPayeePubkeyHex: string,
  ): Promise<Uint8Array | null> {
    const id = await quoteKeyCheckpointId(issuerIdHex, network, expectedPayeePubkeyHex);
    return withExclusiveLock(`bitcoinpir:quote-key:${id}`, async () => {
      const row = await getValue<CipherRecordV1>(this.db, QUOTE_KEY_CHECKPOINT_STORE, id);
      if (!row) return null;
      return this.decryptBytes(row, QUOTE_KEY_CHECKPOINT_AAD_DOMAIN,
        'BOLT11 quote-key checkpoint authentication failed');
    });
  }

  /**
   * Serialize read/verify/advance/write for one quote-key stream across tabs.
   * The callback must obtain `nextCheckpoint` only from the WASM verifier.
   */
  async advanceQuoteKeyCheckpoint<T>(
    issuerIdHex: string,
    network: LightningNetworkNameV1,
    expectedPayeePubkeyHex: string,
    initialCheckpoint: Uint8Array,
    advance: (currentCheckpoint: Uint8Array) => Promise<{
      nextCheckpoint: Uint8Array;
      value: T;
    }> | { nextCheckpoint: Uint8Array; value: T },
  ): Promise<T> {
    if (!(initialCheckpoint instanceof Uint8Array) || initialCheckpoint.length === 0) {
      throw new Error('initial BOLT11 quote-key checkpoint must be non-empty bytes');
    }
    const id = await quoteKeyCheckpointId(issuerIdHex, network, expectedPayeePubkeyHex);
    return withExclusiveLock(`bitcoinpir:quote-key:${id}`, async () => {
      const row = await getValue<CipherRecordV1>(this.db, QUOTE_KEY_CHECKPOINT_STORE, id);
      const current = row
        ? await this.decryptBytes(
          row,
          QUOTE_KEY_CHECKPOINT_AAD_DOMAIN,
          'BOLT11 quote-key checkpoint authentication failed',
        )
        : initialCheckpoint.slice();
      const result = await advance(current);
      if (!(result.nextCheckpoint instanceof Uint8Array) || result.nextCheckpoint.length === 0) {
        throw new Error('advanced BOLT11 quote-key checkpoint must be non-empty bytes');
      }
      await putValue(
        this.db,
        QUOTE_KEY_CHECKPOINT_STORE,
        await this.encryptBytes(
          id,
          result.nextCheckpoint,
          QUOTE_KEY_CHECKPOINT_AAD_DOMAIN,
        ),
      );
      return result.value;
    });
  }

  /** Create a random-ID encrypted recovery record before any issuer POST. */
  async createBolt11Recovery(
    recovery: Omit<Bolt11RecoveryRecordV1, 'id'>,
  ): Promise<Bolt11RecoveryRecordV1> {
    const id = randomId();
    const value = { ...recovery, id };
    validateBolt11Recovery(value);
    const row = await this.encryptBolt11Recovery(value);
    await withExclusiveLock(`bitcoinpir:bolt11-recovery:${id}`, () =>
      addValue(this.db, BOLT11_RECOVERY_STORE, row),
    );
    return cloneRecovery(value);
  }

  /** Read-only recovery inspection used to restore one WASM state machine. */
  async getBolt11Recovery(id: string): Promise<Bolt11RecoveryRecordV1 | null> {
    canonicalOpaqueId('BOLT11 recovery ID', id);
    return withExclusiveLock(`bitcoinpir:bolt11-recovery:${id}`, () =>
      this.getBolt11RecoveryUnlocked(id));
  }

  async listBolt11Recoveries(): Promise<Bolt11RecoveryRecordV1[]> {
    const rows = await getAllValues<CipherRecordV1>(this.db, BOLT11_RECOVERY_STORE);
    const values: Bolt11RecoveryRecordV1[] = [];
    for (const row of rows) values.push(await this.decryptBolt11Recovery(row));
    return values;
  }

  /**
   * Run one recovery transition under a lock spanning restore, issuer I/O and
   * persistence. This is the only safe API for quote/status/claim operations;
   * get/list are read-only inspection primitives and must not be composed with
   * a separate write into a state transition.
   */
  async withBolt11Recovery<T>(
    recoveryId: string,
    operation: (
      recovery: Bolt11RecoveryRecordV1,
      locked: LockedBolt11RecoveryV1,
    ) => Promise<T>,
  ): Promise<T> {
    canonicalOpaqueId('BOLT11 recovery ID', recoveryId);
    return withExclusiveLock(`bitcoinpir:bolt11-recovery:${recoveryId}`, async () => {
      const current = await this.getBolt11RecoveryUnlocked(recoveryId);
      if (!current) {
        throw new Error('BOLT11 recovery record was not found (it may be complete)');
      }
      const exposed = cloneRecovery(current);
      let terminal = false;
      const locked: LockedBolt11RecoveryV1 = {
        persistState: async (state) => {
          if (terminal) throw new Error('BOLT11 recovery transition is already terminal');
          validateBolt11RecoveryState(state);
          const successor = { ...current, state: state.slice() };
          await putValue(
            this.db,
            BOLT11_RECOVERY_STORE,
            await this.encryptBolt11Recovery(successor),
          );
          current.state = successor.state;
          exposed.state = successor.state.slice();
        },
        complete: async (capabilities) => {
          if (terminal) throw new Error('BOLT11 recovery transition is already terminal');
          if (capabilities.length === 0) throw new Error('issuer returned no capabilities');
          for (const capability of capabilities) {
            validateCapabilityV1(capability);
            if (!sameRecoveryCapabilityBinding(current, capability)) {
              throw new Error(
                'issued capability does not match the exact recovery policy binding',
              );
            }
          }
          const ids = capabilities.map(() => randomId());
          const acquisitionContext = recoveryAcquisitionContext(current);
          const encrypted = await Promise.all(capabilities.map((capability, index) =>
            this.encryptRecord(ids[index], { ...capability, acquisitionContext })));
          await completeAcquisitionTransaction(this.db, recoveryId, encrypted);
          terminal = true;
          return ids;
        },
      };
      return operation(exposed, locked);
    });
  }

  private async getBolt11RecoveryUnlocked(id: string): Promise<Bolt11RecoveryRecordV1 | null> {
    const row = await getValue<CipherRecordV1>(this.db, BOLT11_RECOVERY_STORE, id);
    return row ? this.decryptBolt11Recovery(row) : null;
  }

  private async encryptBolt11Recovery(
    value: Bolt11RecoveryRecordV1,
  ): Promise<CipherRecordV1> {
    validateBolt11Recovery(value);
    const plain: PlainBolt11RecoveryRecordV1 = {
      version: 4,
      issuerEndpoint: value.issuerEndpoint,
      issuerIdHex: canonicalHex32('issuerIdHex', value.issuerIdHex),
      network: value.network,
      expectedPayeePubkeyHex: canonicalCompressedPointHex(
        'expectedPayeePubkeyHex', value.expectedPayeePubkeyHex,
      ),
      providerIdHex: canonicalHex32('providerIdHex', value.providerIdHex),
      policyDigestHex: canonicalHex32('policyDigestHex', value.policyDigestHex),
      scopeIdHex: canonicalHex32('scopeIdHex', value.scopeIdHex),
      offerId: value.offerId,
      expectedScheme: value.expectedScheme,
      stateBase64: bytesToBase64(value.state),
    };
    return this.encryptBoundBytesWithDigest(
      value.id,
      new TextEncoder().encode(JSON.stringify(plain)),
      BOLT11_RECOVERY_AAD_DOMAIN,
      await bolt11RecoveryBindingDigestHex(value),
    );
  }

  private async decryptBolt11Recovery(row: CipherRecordV1): Promise<Bolt11RecoveryRecordV1> {
    try {
      const bytes = await this.decryptBoundBytes(
        row,
        BOLT11_RECOVERY_AAD_DOMAIN,
        'BOLT11 recovery authentication failed',
      );
      const parsed = JSON.parse(new TextDecoder().decode(bytes)) as PlainBolt11RecoveryRecordV1;
      if (parsed.version !== 4) throw new Error('version');
      const value: Bolt11RecoveryRecordV1 = {
        id: row.id,
        issuerEndpoint: parsed.issuerEndpoint,
        issuerIdHex: parsed.issuerIdHex,
        network: parsed.network,
        expectedPayeePubkeyHex: parsed.expectedPayeePubkeyHex,
        providerIdHex: parsed.providerIdHex,
        policyDigestHex: parsed.policyDigestHex,
        scopeIdHex: parsed.scopeIdHex,
        offerId: parsed.offerId,
        expectedScheme: parsed.expectedScheme,
        state: base64ToBytes(parsed.stateBase64),
      };
      validateBolt11Recovery(value);
      await requireRecoveryBoundRowMatches(row, value);
      return value;
    } catch {
      throw new Error('BOLT11 recovery authentication or decoding failed');
    }
  }

  private async encryptBytes(
    id: string,
    bytes: Uint8Array,
    domain: string,
  ): Promise<CipherRecordV1> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: ownedArrayBuffer(iv),
        additionalData: aad(domain, id),
      },
      this.key,
      ownedArrayBuffer(bytes),
    );
    return { id, iv: iv.buffer.slice(0), ciphertext };
  }

  private async decryptBytes(
    row: CipherRecordV1,
    domain: string,
    failure: string,
  ): Promise<Uint8Array> {
    try {
      const plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: row.iv,
          additionalData: aad(domain, row.id),
        },
        this.key,
        row.ciphertext,
      );
      return new Uint8Array(plaintext);
    } catch {
      throw new Error(failure);
    }
  }

  private async encryptBoundBytes(
    id: string,
    bytes: Uint8Array,
    domain: string,
    binding: AdmissionCapabilityBindingV1,
  ): Promise<CipherRecordV1> {
    const bindingDigestHex = await capabilityBindingDigestHex(binding);
    return this.encryptBoundBytesWithDigest(id, bytes, domain, bindingDigestHex);
  }

  private async encryptBoundBytesWithDigest(
    id: string,
    bytes: Uint8Array,
    domain: string,
    bindingDigestHex: string,
  ): Promise<CipherRecordV1> {
    canonicalHex32('bindingDigestHex', bindingDigestHex);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: ownedArrayBuffer(iv),
        additionalData: boundAad(domain, id, bindingDigestHex),
      },
      this.key,
      ownedArrayBuffer(bytes),
    );
    return { id, bindingDigestHex, iv: iv.buffer.slice(0), ciphertext };
  }

  private async decryptBoundBytes(
    row: CipherRecordV1,
    domain: string,
    failure: string,
  ): Promise<Uint8Array> {
    try {
      const bindingDigestHex = canonicalHex32(
        'encrypted record binding digest',
        row.bindingDigestHex ?? '',
      );
      const plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: row.iv,
          additionalData: boundAad(domain, row.id, bindingDigestHex),
        },
        this.key,
        row.ciphertext,
      );
      return new Uint8Array(plaintext);
    } catch {
      throw new Error(failure);
    }
  }

  private async findExact(
    binding: AdmissionCapabilityBindingV1,
    expectedAcquisitionContext?: Bolt11CapabilityAcquisitionContextV1 | null,
  ): Promise<{ id: string; plain: AdmissionCapabilityV1 } | null> {
    const rows = await getAllValues<CipherRecordV1>(this.db, RECORD_STORE);
    for (const row of rows) {
      const plain = await this.decryptRecord(row);
      if (sameBinding(plain, binding)
          && (expectedAcquisitionContext === undefined
            || sameAcquisitionContext(plain.acquisitionContext, expectedAcquisitionContext))) {
        return { id: row.id, plain };
      }
      plain.payload.fill(0);
    }
    return null;
  }

  private async encryptRecord(
    id: string,
    capability: AdmissionCapabilityV1,
  ): Promise<CipherRecordV1> {
    const plain: PlainRecordV3 = {
      version: 3,
      providerIdHex: canonicalHex32('providerIdHex', capability.providerIdHex),
      policyDigestHex: canonicalHex32('policyDigestHex', capability.policyDigestHex),
      scopeIdHex: canonicalHex32('scopeIdHex', capability.scopeIdHex),
      offerId: capability.offerId,
      scheme: capability.scheme,
      payloadBase64: bytesToBase64(capability.payload),
      acquisitionContext: cloneAcquisitionContext(capability.acquisitionContext),
    };
    return this.encryptBoundBytes(
      id,
      new TextEncoder().encode(JSON.stringify(plain)),
      RECORD_AAD_DOMAIN,
      capability,
    );
  }

  private async decryptRecord(row: CipherRecordV1): Promise<AdmissionCapabilityV1> {
    let decrypted: Uint8Array | null = null;
    let capability: AdmissionCapabilityV1 | null = null;
    try {
      decrypted = await this.decryptBoundBytes(
        row,
        RECORD_AAD_DOMAIN,
        'admission capability authentication failed',
      );
      const parsed = JSON.parse(new TextDecoder().decode(decrypted)) as PlainRecordV1;
      if (parsed.version !== 2 && parsed.version !== 3) throw new Error('version');
      capability = {
        providerIdHex: parsed.providerIdHex,
        policyDigestHex: parsed.policyDigestHex,
        scopeIdHex: parsed.scopeIdHex,
        offerId: parsed.offerId,
        scheme: parsed.scheme,
        payload: base64ToBytes(parsed.payloadBase64),
        acquisitionContext: parsed.version === 3
          ? cloneAcquisitionContext(parsed.acquisitionContext)
          : undefined,
      };
      validateCapabilityV1(capability);
      await requireBoundRowMatches(row, capability);
      return capability;
    } catch {
      capability?.payload.fill(0);
      // Do not silently skip a damaged entry and select a different token.
      throw new Error('admission capability authentication or decoding failed');
    } finally {
      decrypted?.fill(0);
    }
  }
}

export function validateBindingV1(binding: AdmissionCapabilityBindingV1): void {
  canonicalHex32('providerIdHex', binding.providerIdHex);
  canonicalHex32('policyDigestHex', binding.policyDigestHex);
  canonicalHex32('scopeIdHex', binding.scopeIdHex);
  if (!Number.isSafeInteger(binding.offerId) || binding.offerId <= 0 || binding.offerId > 0xffff_ffff) {
    throw new Error('offerId must be a non-zero u32');
  }
  if (!isScheme(binding.scheme)) throw new Error('unknown admission capability scheme');
}

export function validateCapabilityV1(capability: AdmissionCapabilityV1): void {
  validateBindingV1(capability);
  if (!(capability.payload instanceof Uint8Array)
      || capability.payload.length === 0
      || capability.payload.length > MAX_CAPABILITY_BYTES_V1) {
    throw new Error('capability payload must be within the canonical V1 proof bound');
  }
  if (capability.acquisitionContext !== undefined) {
    validateAcquisitionContext(capability.acquisitionContext);
  }
}

function isScheme(value: string): value is AdmissionSchemeV1 {
  return value === 'free-anonymous-ticket'
    || value === 'bolt11-direct-receipt'
    || value === 'cashu-ecash'
    || value === 'cashu-bat'
    || value === 'arc-experimental';
}

function sameBinding(
  left: AdmissionCapabilityBindingV1,
  right: AdmissionCapabilityBindingV1,
): boolean {
  return left.providerIdHex === right.providerIdHex.toLowerCase()
    && left.policyDigestHex === right.policyDigestHex.toLowerCase()
    && left.scopeIdHex === right.scopeIdHex.toLowerCase()
    && left.offerId === right.offerId
    && left.scheme === right.scheme;
}

function sameRecoveryCapabilityBinding(
  recovery: Bolt11RecoveryRecordV1,
  capability: AdmissionCapabilityV1,
): boolean {
  return recovery.providerIdHex === capability.providerIdHex.toLowerCase()
    && recovery.policyDigestHex === capability.policyDigestHex.toLowerCase()
    && recovery.scopeIdHex === capability.scopeIdHex.toLowerCase()
    && recovery.offerId === capability.offerId
    && recovery.expectedScheme === capability.scheme;
}

function recoveryAcquisitionContext(
  recovery: Bolt11RecoveryRecordV1,
): Bolt11CapabilityAcquisitionContextV1 {
  return canonicalAcquisitionContext({
    kind: 'bolt11',
    issuerEndpoint: recovery.issuerEndpoint,
    issuerIdHex: recovery.issuerIdHex,
    network: recovery.network,
    expectedPayeePubkeyHex: recovery.expectedPayeePubkeyHex,
  });
}

function validateAcquisitionContext(value: Bolt11CapabilityAcquisitionContextV1): void {
  canonicalAcquisitionContext(value);
}

function canonicalAcquisitionContext(
  value: Bolt11CapabilityAcquisitionContextV1,
): Bolt11CapabilityAcquisitionContextV1 {
  if (!value || value.kind !== 'bolt11') {
    throw new Error('capability acquisition context must be BOLT11 V1');
  }
  if (!['bitcoin', 'testnet', 'signet', 'regtest'].includes(value.network)) {
    throw new Error('capability acquisition network is unsupported');
  }
  return {
    kind: 'bolt11',
    issuerEndpoint: canonicalIssuerEndpointForVault(value.issuerEndpoint),
    issuerIdHex: canonicalHex32('acquisition issuerIdHex', value.issuerIdHex),
    network: value.network,
    expectedPayeePubkeyHex: canonicalCompressedPointHex(
      'acquisition expectedPayeePubkeyHex',
      value.expectedPayeePubkeyHex,
    ),
  };
}

function cloneAcquisitionContext(
  value: Bolt11CapabilityAcquisitionContextV1 | undefined,
): Bolt11CapabilityAcquisitionContextV1 | undefined {
  return value === undefined ? undefined : canonicalAcquisitionContext(value);
}

function acquisitionContextFingerprint(
  value: Bolt11CapabilityAcquisitionContextV1 | undefined,
): string {
  if (value === undefined) return 'non-bolt11';
  const canonical = canonicalAcquisitionContext(value);
  return [
    canonical.kind,
    canonical.issuerEndpoint,
    canonical.issuerIdHex,
    canonical.network,
    canonical.expectedPayeePubkeyHex,
  ].join(':');
}

function sameAcquisitionContext(
  actual: Bolt11CapabilityAcquisitionContextV1 | undefined,
  expected: Bolt11CapabilityAcquisitionContextV1 | null,
): boolean {
  if (expected === null) return actual === undefined;
  if (actual === undefined) return false;
  return acquisitionContextFingerprint(actual) === acquisitionContextFingerprint(expected);
}

function canonicalHex32(field: string, value: string): string {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${field} must be exactly 32 bytes of hex`);
  }
  if (/^0{64}$/i.test(value)) throw new Error(`${field} must be non-zero`);
  return value.toLowerCase();
}

function lockName(binding: AdmissionCapabilityBindingV1): string {
  return `bitcoinpir:capability:${binding.providerIdHex.toLowerCase()}:${binding.policyDigestHex.toLowerCase()}:${binding.scopeIdHex.toLowerCase()}:${binding.offerId}:${binding.scheme}`;
}

function requireBrowserPrimitives(): void {
  if (typeof indexedDB === 'undefined') throw new Error('IndexedDB is required for admission storage');
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('WebCrypto is required for admission storage');
  }
  if (typeof navigator === 'undefined' || !navigator.locks) {
    throw new Error('Web Locks are required for cross-tab at-most-once admission');
  }
}

async function withExclusiveLock<T>(name: string, body: () => Promise<T>): Promise<T> {
  if (typeof navigator === 'undefined' || !navigator.locks) {
    throw new Error('Web Locks are required for cross-tab at-most-once admission');
  }
  return navigator.locks.request(name, { mode: 'exclusive' }, body);
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (event) => {
      const db = request.result;
      if (!db.objectStoreNames.contains(META_STORE)) db.createObjectStore(META_STORE, { keyPath: 'id' });
      if (!db.objectStoreNames.contains(RECORD_STORE)) db.createObjectStore(RECORD_STORE, { keyPath: 'id' });
      if (!db.objectStoreNames.contains(CHECKPOINT_STORE)) db.createObjectStore(CHECKPOINT_STORE, { keyPath: 'id' });
      if (!db.objectStoreNames.contains(QUOTE_KEY_CHECKPOINT_STORE)) {
        db.createObjectStore(QUOTE_KEY_CHECKPOINT_STORE, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(BOLT11_RECOVERY_STORE)) {
        db.createObjectStore(BOLT11_RECOVERY_STORE, { keyPath: 'id' });
      }
      // V2 capability/recovery ciphertexts did not bind the exact signed
      // policy digest. Scope/offer IDs can be reused after rotation, so those
      // records are unsafe to migrate. Delete them atomically and fail the
      // upgrade if IndexedDB cannot complete the deletion. Policy and quote
      // anti-rollback checkpoints remain valid and are deliberately retained.
      if (event.oldVersion > 0 && event.oldVersion < 3) {
        const tx = request.transaction;
        if (!tx) throw new Error('admission IndexedDB upgrade has no transaction');
        tx.objectStore(RECORD_STORE).clear();
        tx.objectStore(BOLT11_RECOVERY_STORE).clear();
      } else if (event.oldVersion === 3) {
        // Recovery V3 did not authenticate issuer/network/payee. It cannot be
        // resumed safely, while capability and anti-rollback records remain
        // usable under the stricter per-record checks.
        const tx = request.transaction;
        if (!tx) throw new Error('admission IndexedDB upgrade has no transaction');
        tx.objectStore(BOLT11_RECOVERY_STORE).clear();
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('failed to open admission IndexedDB'));
    request.onblocked = () => reject(new Error('admission IndexedDB upgrade is blocked'));
  });
}

function getValue<T>(db: IDBDatabase, store: string, key: IDBValidKey): Promise<T | undefined> {
  return requestInTransaction<T | undefined>(db, store, 'readonly', (objectStore) => objectStore.get(key));
}

function getAllValues<T>(db: IDBDatabase, store: string): Promise<T[]> {
  return requestInTransaction<T[]>(db, store, 'readonly', (objectStore) => objectStore.getAll());
}

function putValue(db: IDBDatabase, store: string, value: unknown): Promise<void> {
  return requestInTransaction(db, store, 'readwrite', (objectStore) => objectStore.put(value)).then(() => undefined);
}

function addValue(db: IDBDatabase, store: string, value: unknown): Promise<void> {
  return requestInTransaction(db, store, 'readwrite', (objectStore) => objectStore.add(value)).then(() => undefined);
}

function deleteValue(db: IDBDatabase, store: string, key: IDBValidKey): Promise<void> {
  return requestInTransaction(db, store, 'readwrite', (objectStore) => objectStore.delete(key)).then(() => undefined);
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

function completeAcquisitionTransaction(
  db: IDBDatabase,
  recoveryId: string,
  capabilities: CipherRecordV1[],
): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(
      [BOLT11_RECOVERY_STORE, RECORD_STORE],
      'readwrite',
    );
    const recovery = tx.objectStore(BOLT11_RECOVERY_STORE);
    const records = tx.objectStore(RECORD_STORE);
    const get = recovery.get(recoveryId);
    get.onerror = () => tx.abort();
    get.onsuccess = () => {
      if (!get.result) {
        tx.abort();
        return;
      }
      for (const capability of capabilities) records.add(capability);
      recovery.delete(recoveryId);
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error('atomic BOLT11 capability installation failed'));
    tx.onabort = () => reject(new Error(
      'BOLT11 recovery was already completed or capability installation aborted',
    ));
  });
}

function aad(domain: string, id: string): ArrayBuffer {
  return ownedArrayBuffer(new TextEncoder().encode(`${domain}\0${id}`));
}

function boundAad(domain: string, id: string, bindingDigestHex: string): ArrayBuffer {
  return ownedArrayBuffer(new TextEncoder().encode(
    `${domain}\0${id}\0${canonicalHex32('bindingDigestHex', bindingDigestHex)}`,
  ));
}

async function capabilityBindingDigestHex(
  binding: AdmissionCapabilityBindingV1,
): Promise<string> {
  validateBindingV1(binding);
  const canonical = [
    'BitcoinPIR/admission-capability-binding/v1',
    canonicalHex32('providerIdHex', binding.providerIdHex),
    canonicalHex32('policyDigestHex', binding.policyDigestHex),
    canonicalHex32('scopeIdHex', binding.scopeIdHex),
    binding.offerId.toString(10),
    binding.scheme,
  ].join('\0');
  const digest = await crypto.subtle.digest(
    'SHA-256',
    ownedArrayBuffer(new TextEncoder().encode(canonical)),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, '0')).join('');
}

async function requireBoundRowMatches(
  row: CipherRecordV1,
  binding: AdmissionCapabilityBindingV1,
): Promise<void> {
  const stored = canonicalHex32(
    'encrypted record binding digest',
    row.bindingDigestHex ?? '',
  );
  const expected = await capabilityBindingDigestHex(binding);
  if (stored !== expected) {
    throw new Error('encrypted record binding does not match authenticated plaintext');
  }
}

async function bolt11RecoveryBindingDigestHex(
  value: Bolt11RecoveryRecordV1,
): Promise<string> {
  validateBolt11Recovery(value);
  const canonical = [
    'BitcoinPIR/bolt11-recovery-binding/v1',
    canonicalIssuerEndpointForVault(value.issuerEndpoint),
    canonicalHex32('issuerIdHex', value.issuerIdHex),
    value.network,
    canonicalCompressedPointHex('expectedPayeePubkeyHex', value.expectedPayeePubkeyHex),
    canonicalHex32('providerIdHex', value.providerIdHex),
    canonicalHex32('policyDigestHex', value.policyDigestHex),
    canonicalHex32('scopeIdHex', value.scopeIdHex),
    value.offerId.toString(10),
    value.expectedScheme,
  ].join('\0');
  const digest = await crypto.subtle.digest(
    'SHA-256',
    ownedArrayBuffer(new TextEncoder().encode(canonical)),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, '0')).join('');
}

async function requireRecoveryBoundRowMatches(
  row: CipherRecordV1,
  recovery: Bolt11RecoveryRecordV1,
): Promise<void> {
  const stored = canonicalHex32(
    'encrypted recovery binding digest',
    row.bindingDigestHex ?? '',
  );
  const expected = await bolt11RecoveryBindingDigestHex(recovery);
  if (stored !== expected) {
    throw new Error('encrypted recovery does not match its authenticated payment binding');
  }
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function randomId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function checkpointId(providerIdHex: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    ownedArrayBuffer(
      new TextEncoder().encode(`BitcoinPIR/provider-policy-checkpoint/v1\0${providerIdHex}`),
    ),
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function quoteKeyCheckpointId(
  issuerIdHex: string,
  network: LightningNetworkNameV1,
  expectedPayeePubkeyHex: string,
): Promise<string> {
  const issuer = canonicalHex32('issuerIdHex', issuerIdHex);
  if (!['bitcoin', 'testnet', 'signet', 'regtest'].includes(network)) {
    throw new Error('unsupported Lightning network');
  }
  const payee = canonicalCompressedPointHex('expectedPayeePubkeyHex', expectedPayeePubkeyHex);
  const digest = await crypto.subtle.digest(
    'SHA-256',
    ownedArrayBuffer(new TextEncoder().encode(
      `BitcoinPIR/quote-key-checkpoint/v1\0${issuer}\0${network}\0${payee}`,
    )),
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function validateBolt11Recovery(value: Bolt11RecoveryRecordV1): void {
  canonicalOpaqueId('BOLT11 recovery ID', value.id);
  canonicalIssuerEndpointForVault(value.issuerEndpoint);
  canonicalHex32('issuerIdHex', value.issuerIdHex);
  if (!['bitcoin', 'testnet', 'signet', 'regtest'].includes(value.network)) {
    throw new Error('BOLT11 recovery network is unsupported');
  }
  canonicalCompressedPointHex('expectedPayeePubkeyHex', value.expectedPayeePubkeyHex);
  canonicalHex32('providerIdHex', value.providerIdHex);
  canonicalHex32('policyDigestHex', value.policyDigestHex);
  canonicalHex32('scopeIdHex', value.scopeIdHex);
  if (!Number.isSafeInteger(value.offerId) || value.offerId <= 0 || value.offerId > 0xffff_ffff) {
    throw new Error('offerId must be a non-zero u32');
  }
  if (value.expectedScheme !== 'bolt11-direct-receipt'
      && value.expectedScheme !== 'cashu-bat'
      && value.expectedScheme !== 'arc-experimental') {
    throw new Error('BOLT11 recovery expectedScheme is not a supported issued family');
  }
  validateBolt11RecoveryState(value.state);
}

function validatePolicyCheckpoint(checkpoint: Uint8Array): void {
  if (!(checkpoint instanceof Uint8Array)
      || checkpoint.length === 0
      || checkpoint.length > MAX_POLICY_CHECKPOINT_BYTES_V1) {
    throw new Error('service policy checkpoint exceeds its V1 bound');
  }
}

function validateBolt11RecoveryState(state: Uint8Array): void {
  if (!(state instanceof Uint8Array)
      || state.length === 0
      || state.length > MAX_BOLT11_RECOVERY_STATE_BYTES_V1) {
    throw new Error('BOLT11 recovery state exceeds its V1 bound');
  }
}

function cloneRecovery(value: Bolt11RecoveryRecordV1): Bolt11RecoveryRecordV1 {
  return { ...value, state: value.state.slice() };
}

function canonicalOpaqueId(field: string, value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value) || /^0{64}$/.test(value)) {
    throw new Error(`${field} must be non-zero lowercase 32-byte hex`);
  }
  return value;
}

function canonicalCompressedPointHex(field: string, value: string): string {
  if (!/^(02|03)[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${field} must be a compressed secp256k1 point`);
  }
  return value.toLowerCase();
}

function canonicalIssuerEndpointForVault(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('issuer endpoint must be an absolute URL');
  }
  const loopback = parsed.hostname === '127.0.0.1'
    || parsed.hostname === 'localhost'
    || parsed.hostname === '[::1]';
  if ((parsed.protocol !== 'https:' && !(loopback && parsed.protocol === 'http:'))
      || parsed.username || parsed.password || parsed.hash) {
    throw new Error('issuer endpoint must be credential-free HTTPS (or loopback HTTP for tests)');
  }
  const canonical = parsed.toString().replace(/\/$/, '');
  if (canonical !== value.replace(/\/$/, '')) {
    throw new Error('issuer endpoint must use a canonical absolute HTTPS URL');
  }
  return canonical;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error('invalid base64 capability payload');
  }
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
