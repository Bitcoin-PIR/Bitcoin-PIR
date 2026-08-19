/**
 * Trusted, public BAT V2 class discovery.
 *
 * The Nostr directory may advertise scheme 6, but it never supplies any value
 * consumed here.  A trusted Web bootstrap pins one canonical catalog, and the
 * catalog in turn pins immutable class bytes.  Rust/WASM remains the final
 * authority for the class codec, issuer signature, validity, and exact member.
 */

import {
  validateBatV2ClassBindingV2,
  type BatV2ClassBindingV2,
} from './bat-v2-vault.js';
import { bytesToHex, sha256 } from './hash.js';
import { fetchProofArtifactBytesV1 } from './proof-artifact-fetch.js';
import type {
  ProductBatV2ClassMemberSelectorV2,
  ProductBatV2ClassResolverV2,
} from './product-admission-controller.js';
import type { BatV2ClassArtifactV2 } from './provider-payment-selection.js';
import {
  type ProviderAdmissionSessionV1,
  type RetainedBatV2ExactMemberV2,
} from './service-admission.js';
import type { WasmVerifiedBatV2RedemptionV2 } from './sdk-bridge.js';
import { trustedNowUnixV1 } from './trusted-time.js';

export const MAX_BAT_V2_PUBLIC_CLASS_CATALOG_BYTES_V2 = 2 * 1024 * 1024;
export const MAX_BAT_V2_PUBLIC_CLASS_BYTES_V2 = 512 * 1024;
export const MAX_BAT_V2_PUBLIC_CLASS_ENTRIES_V2 = 1_024;
export const MAX_BAT_V2_PUBLIC_CLASS_MEMBERS_V2 = 4_096;
export const MAX_BAT_V2_PUBLIC_CLASS_TOTAL_MEMBERS_V2 = 16_384;

const U64_MAX = 0xffff_ffff_ffff_ffffn;
const CATALOG_PATH = /^\/proofs\/bat-v2\/catalogs\/([0-9a-f]{64})\.json$/;
const CLASS_PATH = /^\/proofs\/bat-v2\/classes\/([0-9a-f]{64})\.bin$/;

export interface TrustedBatV2PublicClassCatalogRefV2 {
  version: 2;
  path: string;
  sha256Hex: string;
}

export interface BatV2PublicClassArtifactRefV2 {
  path: string;
  sha256Hex: string;
}

export interface BatV2PublicClassMemberV2 extends RetainedBatV2ExactMemberV2 {}

export interface BatV2PublicClassEntryV2 extends BatV2ClassBindingV2 {
  keyNotBeforeUnix: string;
  keyNotAfterUnix: string;
  /** Explicit acquisition head. Epoch/time are never used to infer it. */
  status: 'current' | 'retained';
  artifact: BatV2PublicClassArtifactRefV2;
  members: readonly BatV2PublicClassMemberV2[];
}

export interface BatV2PublicClassCatalogV2 {
  version: 2;
  entries: readonly BatV2PublicClassEntryV2[];
}

export interface BatV2PublicClassCatalogResolverOptionsV2 {
  baseHref?: string;
  fetchImpl?: typeof fetch;
  /** Test seam only. Production defaults to the browser's trusted wall clock. */
  nowUnix?: () => bigint;
}

export interface RetainedBatV2ClassResolutionInputV2 {
  binding: BatV2ClassBindingV2;
  providerIdHex: string;
  session: ProviderAdmissionSessionV1;
}

export interface RetainedBatV2ClassResolutionV2 {
  member: BatV2PublicClassMemberV2;
  classArtifact: BatV2ClassArtifactV2;
  /** Caller owns this opaque handle and must call `free()`. */
  verifiedRedemption: WasmVerifiedBatV2RedemptionV2;
}

/** Parse the only trusted-render input. Partial or mutable-looking refs fail closed. */
export function parseTrustedBatV2PublicClassCatalogRefV2(
  value: unknown,
): TrustedBatV2PublicClassCatalogRefV2 {
  const record = exactRecord(value, ['version', 'path', 'sha256Hex'], 'BAT V2 catalog ref');
  if (record.version !== 2) throw new Error('BAT V2 catalog ref has an unknown version');
  const sha256Hex = nonzeroHex32('BAT V2 catalog SHA-256', record.sha256Hex);
  const path = immutablePath('BAT V2 catalog', record.path, CATALOG_PATH, sha256Hex);
  return Object.freeze({ version: 2, path, sha256Hex });
}

/**
 * Parse the canonical source-gate format. The byte-for-byte JSON check rejects
 * whitespace, reordered/unknown keys, duplicate JSON keys, and alternate
 * numeric/string spellings before a catalog can be published and pinned.
 */
export function parseBatV2PublicClassCatalogV2(
  serialized: string,
): BatV2PublicClassCatalogV2 {
  if (typeof serialized !== 'string'
      || serialized.length > MAX_BAT_V2_PUBLIC_CLASS_CATALOG_BYTES_V2
      || new TextEncoder().encode(serialized).length > MAX_BAT_V2_PUBLIC_CLASS_CATALOG_BYTES_V2) {
    throw new Error('BAT V2 public class catalog exceeds its byte limit');
  }
  let parsed: unknown;
  try { parsed = JSON.parse(serialized); } catch {
    throw new Error('BAT V2 public class catalog must be valid JSON');
  }
  const envelope = exactRecord(parsed, ['version', 'entries'], 'BAT V2 public class catalog');
  if (envelope.version !== 2) throw new Error('BAT V2 public class catalog has an unknown version');
  if (!Array.isArray(envelope.entries) || envelope.entries.length === 0
      || envelope.entries.length > MAX_BAT_V2_PUBLIC_CLASS_ENTRIES_V2) {
    throw new Error('BAT V2 public class catalog has an invalid entry count');
  }

  let totalMembers = 0;
  const entries = envelope.entries.map((entry, index) => {
    const value = parseEntry(entry, index);
    totalMembers += value.members.length;
    if (totalMembers > MAX_BAT_V2_PUBLIC_CLASS_TOTAL_MEMBERS_V2) {
      throw new Error('BAT V2 public class catalog exceeds its total member limit');
    }
    return value;
  });
  requireStrictOrder(entries, compareEntries, 'BAT V2 class entries');
  requireUnique(entries.map((entry) => entry.artifact.path), 'BAT V2 class artifact path');
  requireExactlyOneCurrentHead(entries);

  const canonical = freezeCatalog({ version: 2, entries });
  if (JSON.stringify(canonical) !== serialized) {
    throw new Error('BAT V2 public class catalog is not canonical JSON');
  }
  return canonical;
}

export class BatV2PublicClassCatalogResolverV2 {
  private readonly trusted: TrustedBatV2PublicClassCatalogRefV2;
  private readonly options: BatV2PublicClassCatalogResolverOptionsV2;
  private catalogPromise: Promise<BatV2PublicClassCatalogV2> | null = null;
  private readonly artifactPromises = new Map<string, Promise<Uint8Array>>();

  constructor(
    trusted: TrustedBatV2PublicClassCatalogRefV2,
    options: BatV2PublicClassCatalogResolverOptionsV2 = {},
  ) {
    this.trusted = parseTrustedBatV2PublicClassCatalogRefV2(trusted);
    if (options.nowUnix !== undefined && typeof options.nowUnix !== 'function') {
      throw new Error('BAT V2 catalog nowUnix must be a function');
    }
    this.options = { ...options };
  }

  /** Drop-in resolver for the existing product current-policy controller. */
  readonly resolveCurrent: ProductBatV2ClassResolverV2 = async (selector) => {
    const exact = exactCurrentSelector(selector);
    const catalog = await this.catalog();
    const memberMatches = catalog.entries.filter((entry) =>
      entry.status === 'current'
      &&
      entry.issuerIdHex === exact.offer.issuerIdHex
      && entry.classIdHex === exact.offer.keyIdHex
      && entry.members.some((member) => sameMember(member, exact)));
    const entry = uniqueCurrentEntry(memberMatches, this.nowUnix());
    return this.artifact(entry);
  };

  /**
   * Resolve a historical wallet binding without trusting a caller-supplied
   * policy selector. The exact member is learned from the pinned catalog, then
   * the session fetches that one retained signed policy and Rust re-verifies
   * the canonical issuer-signed class/member.
   */
  readonly resolveRetained = async (
    input: RetainedBatV2ClassResolutionInputV2,
  ): Promise<RetainedBatV2ClassResolutionV2> => {
    validateBatV2ClassBindingV2(input.binding);
    const providerIdHex = nonzeroHex32('retained BAT V2 provider ID', input.providerIdHex);
    if (!input.session || typeof input.session.verifyRetainedBatV2ClassMember !== 'function') {
      throw new Error('retained BAT V2 resolution requires a provider admission session');
    }
    const catalog = await this.catalog();
    const bindingMatches = catalog.entries.filter((entry) => sameBinding(entry, input.binding));
    if (bindingMatches.length !== 1) {
      throw new Error('retained BAT V2 wallet binding has no unique trusted class');
    }
    const entry = bindingMatches[0];
    assertActive(entry, this.nowUnix(), 'retained BAT V2 class');
    const members = entry.members.filter((member) => member.providerIdHex === providerIdHex);
    if (members.length !== 1) {
      throw new Error('retained BAT V2 provider has no unique exact class member');
    }
    const member = { ...members[0] };
    const classArtifact = await this.artifact(entry);
    let verifiedRedemption: WasmVerifiedBatV2RedemptionV2 | null = null;
    try {
      verifiedRedemption = await input.session.verifyRetainedBatV2ClassMember(
        member,
        classArtifact,
      );
      return { member, classArtifact, verifiedRedemption };
    } catch (error) {
      verifiedRedemption?.free();
      classArtifact.classBytes.fill(0);
      throw error;
    }
  };

  private nowUnix(): bigint {
    const value = this.options.nowUnix?.() ?? trustedNowUnixV1();
    if (typeof value !== 'bigint' || value < 0n || value > U64_MAX) {
      throw new Error('BAT V2 catalog time must be a canonical u64');
    }
    return value;
  }

  private catalog(): Promise<BatV2PublicClassCatalogV2> {
    this.catalogPromise ??= this.fetchCatalog();
    return this.catalogPromise;
  }

  private async fetchCatalog(): Promise<BatV2PublicClassCatalogV2> {
    const bytes = await fetchProofArtifactBytesV1(this.trusted.path, {
      baseHref: this.options.baseHref,
      fetchImpl: this.options.fetchImpl,
      maxBytes: MAX_BAT_V2_PUBLIC_CLASS_CATALOG_BYTES_V2,
      requireStreaming: true,
    });
    requireSha256('BAT V2 public class catalog', bytes, this.trusted.sha256Hex);
    let serialized: string;
    try { serialized = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch {
      throw new Error('BAT V2 public class catalog is not canonical UTF-8');
    }
    return parseBatV2PublicClassCatalogV2(serialized);
  }

  private async artifact(entry: BatV2PublicClassEntryV2): Promise<BatV2ClassArtifactV2> {
    const cacheKey = `${entry.artifact.path}:${entry.artifact.sha256Hex}`;
    let pending = this.artifactPromises.get(cacheKey);
    if (!pending) {
      pending = this.fetchArtifact(entry);
      this.artifactPromises.set(cacheKey, pending);
    }
    const classBytes = await pending;
    return { classBytes: classBytes.slice(), binding: bindingFromEntry(entry) };
  }

  private async fetchArtifact(entry: BatV2PublicClassEntryV2): Promise<Uint8Array> {
    const bytes = await fetchProofArtifactBytesV1(entry.artifact.path, {
      baseHref: this.options.baseHref,
      fetchImpl: this.options.fetchImpl,
      maxBytes: MAX_BAT_V2_PUBLIC_CLASS_BYTES_V2,
      requireStreaming: true,
    });
    if (bytes.length === 0) throw new Error('BAT V2 class artifact is empty');
    requireSha256('BAT V2 class artifact', bytes, entry.artifact.sha256Hex);
    return bytes;
  }
}

function parseEntry(value: unknown, index: number): BatV2PublicClassEntryV2 {
  const entry = exactRecord(value, [
    'issuerIdHex', 'classIdHex', 'classKeyEpoch', 'classDigestHex', 'batKeyIdHex',
    'keyNotBeforeUnix', 'keyNotAfterUnix', 'status', 'artifact', 'members',
  ], `BAT V2 class entry ${index}`);
  const binding: BatV2ClassBindingV2 = {
    issuerIdHex: nonzeroHex32(`BAT V2 class entry ${index} issuer ID`, entry.issuerIdHex),
    classIdHex: nonzeroHex32(`BAT V2 class entry ${index} class ID`, entry.classIdHex),
    classKeyEpoch: positiveU64(`BAT V2 class entry ${index} key epoch`, entry.classKeyEpoch),
    classDigestHex: nonzeroHex32(`BAT V2 class entry ${index} class digest`, entry.classDigestHex),
    batKeyIdHex: nonzeroHex32(`BAT V2 class entry ${index} BAT key ID`, entry.batKeyIdHex),
  };
  validateBatV2ClassBindingV2(binding);
  const keyNotBeforeUnix = u64Decimal(
    `BAT V2 class entry ${index} key not-before`, entry.keyNotBeforeUnix,
  );
  const keyNotAfterUnix = u64Decimal(
    `BAT V2 class entry ${index} key not-after`, entry.keyNotAfterUnix,
  );
  if (BigInt(keyNotBeforeUnix) > BigInt(keyNotAfterUnix)) {
    throw new Error(`BAT V2 class entry ${index} has an invalid key window`);
  }
  if (entry.status !== 'current' && entry.status !== 'retained') {
    throw new Error(`BAT V2 class entry ${index} status is invalid`);
  }
  const artifactRecord = exactRecord(
    entry.artifact, ['path', 'sha256Hex'], `BAT V2 class entry ${index} artifact`,
  );
  const artifactSha256Hex = nonzeroHex32(
    `BAT V2 class entry ${index} artifact SHA-256`, artifactRecord.sha256Hex,
  );
  const artifact = Object.freeze({
    path: immutablePath(
      `BAT V2 class entry ${index} artifact`,
      artifactRecord.path,
      CLASS_PATH,
      artifactSha256Hex,
    ),
    sha256Hex: artifactSha256Hex,
  });
  if (!Array.isArray(entry.members) || entry.members.length === 0
      || entry.members.length > MAX_BAT_V2_PUBLIC_CLASS_MEMBERS_V2) {
    throw new Error(`BAT V2 class entry ${index} has an invalid member count`);
  }
  const members = entry.members.map((member, memberIndex) => Object.freeze(parseMember(
    member, index, memberIndex,
  )));
  requireStrictOrder(members, compareMembers, `BAT V2 class entry ${index} members`);
  return Object.freeze({
    ...binding,
    keyNotBeforeUnix,
    keyNotAfterUnix,
    status: entry.status,
    artifact,
    members: Object.freeze(members),
  });
}

function parseMember(value: unknown, entryIndex: number, memberIndex: number): BatV2PublicClassMemberV2 {
  const member = exactRecord(value, [
    'providerIdHex', 'policyDigestHex', 'scopeIdHex', 'offerId',
  ], `BAT V2 class entry ${entryIndex} member ${memberIndex}`);
  if (!Number.isSafeInteger(member.offerId) || (member.offerId as number) <= 0
      || (member.offerId as number) > 0xffff_ffff) {
    throw new Error(`BAT V2 class entry ${entryIndex} member ${memberIndex} offer ID is invalid`);
  }
  return {
    providerIdHex: nonzeroHex32('BAT V2 member provider ID', member.providerIdHex),
    policyDigestHex: nonzeroHex32('BAT V2 member policy digest', member.policyDigestHex),
    scopeIdHex: nonzeroHex32('BAT V2 member scope ID', member.scopeIdHex),
    offerId: member.offerId as number,
  };
}

function exactCurrentSelector(
  selector: ProductBatV2ClassMemberSelectorV2,
): ProductBatV2ClassMemberSelectorV2 {
  if (!selector || typeof selector !== 'object' || !selector.offer) {
    throw new Error('BAT V2 current selector is malformed');
  }
  const member = parseMember({
    providerIdHex: selector.providerIdHex,
    policyDigestHex: selector.policyDigestHex,
    scopeIdHex: selector.scopeIdHex,
    offerId: selector.offerId,
  }, 0, 0);
  const offer = selector.offer;
  if (offer.offerId !== member.offerId
      || offer.acquisition !== 'bolt11'
      || offer.authorization !== 'cashu-bat-v2'
      || offer.verification !== 'shared-issuer-online') {
    throw new Error('selected signed offer is not a current BAT V2 class offer');
  }
  nonzeroHex32('BAT V2 offer issuer ID', offer.issuerIdHex);
  nonzeroHex32('BAT V2 offer class ID', offer.keyIdHex);
  return { ...selector, ...member, offer: { ...offer, price: { ...offer.price } } };
}

function uniqueCurrentEntry(
  matches: readonly BatV2PublicClassEntryV2[],
  nowUnix: bigint,
): BatV2PublicClassEntryV2 {
  const active = matches.filter((entry) => isActive(entry, nowUnix));
  if (active.length !== 1) {
    if (active.length > 1) throw new Error('current BAT V2 member matches multiple active classes');
    if (matches.length > 0) throw new Error('current BAT V2 class key window is inactive');
    throw new Error('current BAT V2 member is absent from the trusted class catalog');
  }
  return active[0];
}

function assertActive(entry: BatV2PublicClassEntryV2, nowUnix: bigint, label: string): void {
  if (!isActive(entry, nowUnix)) throw new Error(`${label} key window is inactive`);
}

function isActive(entry: BatV2PublicClassEntryV2, nowUnix: bigint): boolean {
  return BigInt(entry.keyNotBeforeUnix) <= nowUnix && nowUnix <= BigInt(entry.keyNotAfterUnix);
}

function sameMember(
  member: BatV2PublicClassMemberV2,
  selector: Pick<ProductBatV2ClassMemberSelectorV2,
    'providerIdHex' | 'policyDigestHex' | 'scopeIdHex' | 'offerId'>,
): boolean {
  return member.providerIdHex === selector.providerIdHex
    && member.policyDigestHex === selector.policyDigestHex
    && member.scopeIdHex === selector.scopeIdHex
    && member.offerId === selector.offerId;
}

function sameBinding(
  entry: BatV2PublicClassEntryV2,
  binding: BatV2ClassBindingV2,
): boolean {
  return entry.issuerIdHex === binding.issuerIdHex
    && entry.classIdHex === binding.classIdHex
    && entry.classDigestHex === binding.classDigestHex
    && entry.classKeyEpoch === binding.classKeyEpoch
    && entry.batKeyIdHex === binding.batKeyIdHex;
}

function bindingFromEntry(entry: BatV2PublicClassEntryV2): BatV2ClassBindingV2 {
  return {
    issuerIdHex: entry.issuerIdHex,
    classIdHex: entry.classIdHex,
    classDigestHex: entry.classDigestHex,
    classKeyEpoch: entry.classKeyEpoch,
    batKeyIdHex: entry.batKeyIdHex,
  };
}

function compareMembers(left: BatV2PublicClassMemberV2, right: BatV2PublicClassMemberV2): number {
  return compareAscii(left.providerIdHex, right.providerIdHex)
    || compareAscii(left.policyDigestHex, right.policyDigestHex)
    || compareAscii(left.scopeIdHex, right.scopeIdHex)
    || left.offerId - right.offerId;
}

function compareEntries(left: BatV2PublicClassEntryV2, right: BatV2PublicClassEntryV2): number {
  return compareAscii(left.issuerIdHex, right.issuerIdHex)
    || compareAscii(left.classIdHex, right.classIdHex)
    || compareBigInt(BigInt(left.classKeyEpoch), BigInt(right.classKeyEpoch));
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareBigInt(left: bigint, right: bigint): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requireStrictOrder<T>(
  values: readonly T[],
  compare: (left: T, right: T) => number,
  label: string,
): void {
  for (let index = 1; index < values.length; index += 1) {
    if (compare(values[index - 1], values[index]) >= 0) {
      throw new Error(`${label} must be strictly canonical-sorted without duplicates`);
    }
  }
}

function requireUnique(values: readonly string[], label: string): void {
  if (new Set(values).size !== values.length) throw new Error(`duplicate ${label}`);
}

function requireExactlyOneCurrentHead(entries: readonly BatV2PublicClassEntryV2[]): void {
  const groups = new Map<string, number>();
  for (const entry of entries) {
    const key = `${entry.issuerIdHex}:${entry.classIdHex}`;
    const count = groups.get(key) ?? 0;
    groups.set(key, count + (entry.status === 'current' ? 1 : 0));
  }
  for (const count of groups.values()) {
    if (count !== 1) {
      throw new Error('each BAT V2 issuer/class must have exactly one explicit current head');
    }
  }
}

function immutablePath(
  label: string,
  value: unknown,
  pattern: RegExp,
  expectedDigest: string,
): string {
  if (typeof value !== 'string') throw new Error(`${label} path is invalid`);
  const match = pattern.exec(value);
  if (!match || match[1] !== expectedDigest) {
    throw new Error(`${label} path must be immutable and named by its SHA-256`);
  }
  return value;
}

function positiveU64(field: string, value: unknown): string {
  const canonical = u64Decimal(field, value);
  if (canonical === '0') throw new Error(`${field} must be non-zero`);
  return canonical;
}

function u64Decimal(field: string, value: unknown): string {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${field} must be a canonical u64 decimal`);
  }
  const parsed = BigInt(value);
  if (parsed > U64_MAX) throw new Error(`${field} exceeds u64`);
  return value;
}

function nonzeroHex32(field: string, value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value) || /^0{64}$/.test(value)) {
    throw new Error(`${field} must be non-zero lowercase 32-byte hex`);
  }
  return value;
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw new Error(`${label} has unknown, missing, or non-canonical fields`);
  }
  return value as Record<string, unknown>;
}

function requireSha256(label: string, bytes: Uint8Array, expectedHex: string): void {
  if (bytesToHex(sha256(bytes)) !== expectedHex) throw new Error(`${label} SHA-256 mismatch`);
}

function freezeCatalog(catalog: BatV2PublicClassCatalogV2): BatV2PublicClassCatalogV2 {
  return Object.freeze({ version: 2, entries: Object.freeze([...catalog.entries]) });
}
