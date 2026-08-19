import { webcrypto } from 'node:crypto';
import { indexedDB as fakeIndexedDB } from 'fake-indexeddb';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  BatV2CredentialVaultV2,
  type BatV2ClassBindingV2,
  type BatV2WalletRecordV2,
} from '../bat-v2-vault.js';

const databaseName = 'bitcoinpir-bat-v2';
const v1DatabaseName = 'bitcoinpir-admission-v1';
const issuerIdHex = '11'.repeat(32);
const classIdHex = '22'.repeat(32);
const classDigestHex = '33'.repeat(32);
const batKeyIdHex = '44'.repeat(32);
const payeeHex = `02${'55'.repeat(32)}`;
const binding: BatV2ClassBindingV2 = {
  issuerIdHex,
  classIdHex,
  classDigestHex,
  classKeyEpoch: '7',
  batKeyIdHex,
};
let opened: BatV2CredentialVaultV2[] = [];

beforeEach(async () => {
  Object.defineProperty(globalThis, 'indexedDB', {
    configurable: true,
    value: fakeIndexedDB,
  });
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: webcrypto,
  });
  const tails = new Map<string, Promise<unknown>>();
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    value: {
      locks: {
        request: <T>(name: string, _options: unknown, callback: () => Promise<T>) => {
          const previous = tails.get(name) ?? Promise.resolve();
          const result = previous.then(callback, callback);
          tails.set(name, result.then(() => undefined, () => undefined));
          return result;
        },
      },
    },
  });
  await deleteDatabase(databaseName);
  await deleteDatabase(v1DatabaseName);
  opened = [];
});

afterEach(async () => {
  for (const vault of opened) vault.close();
  opened = [];
  await deleteDatabase(databaseName);
  await deleteDatabase(v1DatabaseName);
});

describe('BAT V2 class-only encrypted vault', () => {
  it('uses an independent database and never imports V1 records or coordinates', async () => {
    await seedForeignV1Database();
    const vault = await openVault();
    await expect(vault.listInventory()).resolves.toEqual([]);

    await install(vault, [walletRecord(1, 2)]);
    const inventory = await vault.listInventory();
    expect(inventory).toEqual([{ ...binding, count: 1 }]);
    expect(inventory[0]).not.toHaveProperty('providerIdHex');
    expect(inventory[0]).not.toHaveProperty('policyDigestHex');
    expect(inventory[0]).not.toHaveProperty('scopeIdHex');
    expect(inventory[0]).not.toHaveProperty('offerId');
  });

  it('atomically rejects issuer-global spend-key reuse and retains recovery', async () => {
    const vault = await openVault();
    await install(vault, [walletRecord(1, 9)]);
    const recovery = await createRecovery(vault, 2);

    await expect(vault.completeAcquisition(recovery.id, [
      walletRecord(2, 10),
      walletRecord(3, 10),
    ])).rejects.toThrow(/duplicate global spend key/);
    await expect(vault.getRecovery(recovery.id)).resolves.not.toBeNull();
    await expect(vault.listInventory()).resolves.toEqual([{ ...binding, count: 1 }]);

    await expect(vault.completeAcquisition(recovery.id, [walletRecord(2, 9)]))
      .rejects.toThrow(/transaction|conflicted/);
    await expect(vault.getRecovery(recovery.id)).resolves.not.toBeNull();
    await expect(vault.listInventory()).resolves.toEqual([{ ...binding, count: 1 }]);
  });

  it('leaves a one-token wallet unchanged instead of leasing one proof twice', async () => {
    const vault = await openVault();
    await install(vault, [walletRecord(1, 2)]);

    await expect(vault.reserveDistinctPair(binding, binding)).resolves.toBeNull();
    await expect(vault.reserveDistinctPair(binding, {
      ...binding,
      classDigestHex: '99'.repeat(32),
    })).rejects.toThrow(/one exact acceptance class/);
    await expect(vault.listInventory()).resolves.toEqual([{ ...binding, count: 1 }]);
  });

  it('atomically leases two distinct proofs and supports recover-safe or burn completion', async () => {
    const vault = await openVault();
    await install(vault, [walletRecord(1, 2), walletRecord(3, 4)]);
    const validationCopies: Uint8Array[] = [];

    const pair = await vault.reserveDistinctPair(binding, binding, (record) => {
      validationCopies.push(record.proof);
    });
    expect(pair).not.toBeNull();
    expect(pair?.first.recordId).not.toBe(pair?.second.recordId);
    expect(pair?.first.globalSpendKeyHex).not.toBe(pair?.second.globalSpendKeyHex);
    expect(pair?.first.reservationId).toBe(pair?.second.reservationId);
    expect(validationCopies).toHaveLength(2);
    expect(validationCopies.every((proof) => proof.every((byte) => byte === 0))).toBe(true);
    await expect(vault.listInventory()).resolves.toEqual([]);

    await vault.finishReservation(pair!.first, 'recover-safe');
    await vault.finishReservation(pair!.second, 'burn');
    expect(pair!.first.proof.every((byte) => byte === 0)).toBe(true);
    expect(pair!.second.proof.every((byte) => byte === 0)).toBe(true);
    await expect(vault.listInventory()).resolves.toEqual([{ ...binding, count: 1 }]);
  });

  it('conservatively burns every orphaned reservation when the vault reopens', async () => {
    const vault = await openVault();
    await install(vault, [walletRecord(1, 2), walletRecord(3, 4)]);
    const pair = await vault.reserveDistinctPair(binding, binding);
    expect(pair).not.toBeNull();
    pair!.first.proof.fill(0);
    pair!.second.proof.fill(0);
    vault.close();
    opened = opened.filter((candidate) => candidate !== vault);

    const reopened = await openVault();
    await expect(reopened.listInventory()).resolves.toEqual([]);
    await expect(reopened.finishReservation(pair!.first, 'recover-safe'))
      .rejects.toThrow(/no longer available/);
  });
});

async function openVault(): Promise<BatV2CredentialVaultV2> {
  const vault = await BatV2CredentialVaultV2.open();
  opened.push(vault);
  return vault;
}

function walletRecord(proofByte: number, spendByte: number): BatV2WalletRecordV2 {
  return {
    ...binding,
    proof: new Uint8Array(210).fill(proofByte),
    globalSpendKeyHex: spendByte.toString(16).padStart(2, '0').repeat(32),
  };
}

async function createRecovery(vault: BatV2CredentialVaultV2, marker: number) {
  return vault.createRecovery({
    issuerEndpoint: 'https://issuer.example',
    issuerIdHex,
    network: 'signet',
    expectedPayeePubkeyHex: payeeHex,
    state: new Uint8Array([marker]),
  });
}

async function install(
  vault: BatV2CredentialVaultV2,
  records: BatV2WalletRecordV2[],
): Promise<void> {
  const recovery = await createRecovery(vault, records[0].proof[0]);
  await vault.completeAcquisition(recovery.id, records);
}

function seedForeignV1Database(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(v1DatabaseName, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore('records', { keyPath: 'id' });
    };
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction('records', 'readwrite');
      tx.objectStore('records').add({
        id: 'aa'.repeat(32),
        providerIdHex: 'bb'.repeat(32),
        payload: new Uint8Array(210).fill(7),
      });
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onabort = () => reject(new Error('failed to seed foreign V1 database'));
    };
    request.onerror = () => reject(new Error('failed to open foreign V1 database'));
  });
}

function deleteDatabase(name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(new Error(`failed to delete ${name}`));
    request.onblocked = () => reject(new Error(`delete ${name} was blocked`));
  });
}
