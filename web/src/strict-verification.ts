import {
  databaseProofUnavailable,
  verifiedDatabaseProofFromWasm,
  verifyDatabaseProofAgainstPin,
  type DatabaseProofPin,
  type DatabaseProofStatus,
  type VerifiedDatabaseProof,
} from './db-proof.js';
import type { WasmDatabaseProof } from './sdk-bridge.js';

/**
 * The small WASM surface needed by the strict database-root gate.  Keeping the
 * type structural lets both DPF and HarmonyPIR use exactly the same sequence.
 */
export interface StrictDatabaseProofClient {
  verifyDatabaseProof(
    dbId: number,
    expectedParamsHashHex?: string | null,
    allowedBuilderBinarySha256Hex?: string | null,
    allowedBuilderGitCommit?: string | null,
  ): Promise<WasmDatabaseProof>;
  /** Consumes `proof`; callers must not call `free()` after this transfer. */
  installVerifiedDatabaseProof(proof: WasmDatabaseProof): void;
  preflightDatabase(dbId: number): Promise<void>;
}

export type DatabaseProofStatusCallback = (
  dbId: number,
  status: DatabaseProofStatus,
) => void;

export interface StrictDatabaseProofOptions {
  client: StrictDatabaseProofClient;
  pins: readonly DatabaseProofPin[];
  onStatus?: DatabaseProofStatusCallback;
  /**
   * Re-check the transport/session owner around every asynchronous boundary.
   * A staged leg passes a closure bound to its generation, WASM client and
   * configured endpoint.  If disconnect/replacement wins the race, the proof
   * handle is freed before it can be installed and no late status is emitted.
   */
  assertCurrent?: () => void;
}

/** Proof material that has passed the Rust verifier, matched the browser's
 * production pin, and transferred into the native root store. Tree-top
 * preflight is deliberately separate so two independently connected PIR legs
 * can both prove the same root before either leg is admitted for a real query. */
export interface InstalledDatabaseProof {
  pin: DatabaseProofPin;
  proof: VerifiedDatabaseProof;
  status: DatabaseProofStatus;
}

/** Require a one-to-one production pin for every database advertised by the
 * authenticated catalog. Duplicate or unexpected IDs are rejected so the
 * install/preflight sequence has one unambiguous trust anchor per DB. */
export function assertStrictDatabasePinCoverage(
  catalogDbIds: readonly number[],
  pins: readonly DatabaseProofPin[],
): void {
  const duplicateIds = (ids: readonly number[]) =>
    [...new Set(ids.filter((id, index) => ids.indexOf(id) !== index))];
  const pinIds = pins.map((pin) => pin.dbId);
  const duplicateCatalog = duplicateIds(catalogDbIds);
  const duplicatePins = duplicateIds(pinIds);
  if (duplicateCatalog.length > 0) {
    throw new Error(`strict catalog contains duplicate db ids: ${duplicateCatalog.join(', ')}`);
  }
  if (duplicatePins.length > 0) {
    throw new Error(`strict database proof pins contain duplicate db ids: ${duplicatePins.join(', ')}`);
  }

  const catalog = new Set(catalogDbIds);
  const pinned = new Set(pinIds);
  const missing = catalogDbIds.filter((dbId) => !pinned.has(dbId));
  const unexpected = pinIds.filter((dbId) => !catalog.has(dbId));
  if (missing.length > 0 || unexpected.length > 0) {
    const details = [
      missing.length > 0 ? `missing pins for db ${missing.join(', ')}` : '',
      unexpected.length > 0 ? `pins for unknown db ${unexpected.join(', ')}` : '',
    ].filter(Boolean).join('; ');
    throw new Error(`strict database proof pin coverage failed: ${details}`);
  }
}

function errorMessage(error: unknown): string {
  return (error as Error)?.message ?? String(error);
}

function operationFailureStatus(
  pin: DatabaseProofPin,
  proof: VerifiedDatabaseProof,
  operation: 'install' | 'preflight',
  error: unknown,
): DatabaseProofStatus {
  return {
    state: 'unverified',
    dbId: pin.dbId,
    pin,
    proof,
    error: `${operation} failed: ${errorMessage(error)}`,
  };
}

/**
 * Verify and install trusted database roots for one authenticated transport:
 *
 * 1. Rust/WASM verifies the signed database proof.
 * 2. TypeScript compares every proof field with the production pin.
 * 3. The same live proof handle is transferred into the native client.
 *
 * `installVerifiedDatabaseProof` is an ownership boundary.  Once invoked, the
 * handle is considered consumed even if the binding reports an error; freeing
 * it in JS afterwards could double-free a wasm-bindgen by-value argument.
 */
export async function verifyAndInstallDatabaseProofs(
  options: StrictDatabaseProofOptions,
): Promise<InstalledDatabaseProof[]> {
  const { client, pins, onStatus, assertCurrent } = options;
  assertCurrent?.();
  if (pins.length === 0) {
    throw new Error('strict database verification requires at least one pinned database proof');
  }

  const installed: InstalledDatabaseProof[] = [];

  for (const pin of pins) {
    let proofHandle: WasmDatabaseProof | null = null;
    try {
      proofHandle = await client.verifyDatabaseProof(
        pin.dbId,
        pin.paramsHashHex,
        pin.builderBinarySha256Hex,
        pin.builderGitCommit,
      );
    } catch (error) {
      assertCurrent?.();
      const status = databaseProofUnavailable(pin, error);
      onStatus?.(pin.dbId, status);
      throw new Error(
        `database proof verification failed for db ${pin.dbId}: ${errorMessage(error)}`,
        { cause: error },
      );
    }

    try {
      assertCurrent?.();
      const proof = verifiedDatabaseProofFromWasm(proofHandle);
      assertCurrent?.();
      const status = verifyDatabaseProofAgainstPin(proof, pin);
      if (status.state !== 'verified') {
        onStatus?.(pin.dbId, status);
        throw new Error(
          `database proof pin mismatch for db ${pin.dbId}: ${status.mismatches?.join('; ') ?? 'unknown mismatch'}`,
        );
      }

      try {
        // wasm-bindgen consumes by-value arguments before entering Rust. Clear
        // our local ownership first, because even a Rust-side install error
        // leaves the JavaScript handle destroyed.
        assertCurrent?.();
        const movedProof = proofHandle;
        proofHandle = null;
        client.installVerifiedDatabaseProof(movedProof);
        assertCurrent?.();
      } catch (error) {
        assertCurrent?.();
        const failure = operationFailureStatus(pin, proof, 'install', error);
        onStatus?.(pin.dbId, failure);
        throw new Error(
          `database proof installation failed for db ${pin.dbId}: ${errorMessage(error)}`,
          { cause: error },
        );
      }

      installed.push({ pin, proof, status });
    } finally {
      // Conversion or pin failures happen before ownership transfer.
      proofHandle?.free();
    }
  }

  return installed;
}

/** Complete the expensive-query gate after every independently selected leg
 * has authenticated the same catalog/root set. */
export async function preflightInstalledDatabaseProofs(
  client: Pick<StrictDatabaseProofClient, 'preflightDatabase'>,
  installed: readonly InstalledDatabaseProof[],
  onStatus?: DatabaseProofStatusCallback,
  assertCurrent?: () => void,
): Promise<DatabaseProofStatus[]> {
  const verified: DatabaseProofStatus[] = [];
  assertCurrent?.();
  for (const item of installed) {
    try {
      await client.preflightDatabase(item.pin.dbId);
      assertCurrent?.();
    } catch (error) {
      assertCurrent?.();
      const failure = operationFailureStatus(item.pin, item.proof, 'preflight', error);
      onStatus?.(item.pin.dbId, failure);
      throw new Error(
        `database tree-tops preflight failed for db ${item.pin.dbId}: ${errorMessage(error)}`,
        { cause: error },
      );
    }
    verified.push(item.status);
    onStatus?.(item.pin.dbId, item.status);
  }

  return verified;
}

export async function verifyInstallAndPreflightDatabaseProofs(
  options: StrictDatabaseProofOptions,
): Promise<DatabaseProofStatus[]> {
  const installed = await verifyAndInstallDatabaseProofs(options);
  options.assertCurrent?.();
  return preflightInstalledDatabaseProofs(
    options.client,
    installed,
    options.onStatus,
    options.assertCurrent,
  );
}

/** Validate and defensively copy one operator pin. */
export function exactOperatorPinV1(field: string, value: Uint8Array | undefined): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error(`${field} must be exactly 32 bytes`);
  }
  if (value.every((byte) => byte === 0)) throw new Error(`${field} must be non-zero`);
  return value.slice();
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

/**
 * Local-only two-provider independence gate.  It deliberately consumes no
 * server identity or endpoint and therefore never reveals the peer choice.
 */
export function assertIndependentOperatorPinsV1(options: {
  first?: Uint8Array;
  second?: Uint8Array;
}): readonly [Uint8Array, Uint8Array] {
  const first = exactOperatorPinV1('first operator pin', options.first);
  const second = exactOperatorPinV1('second operator pin', options.second);
  if (equalBytes(first, second)) {
    throw new Error('strict two-provider verification requires distinct operator pins');
  }
  return [first, second];
}

/** Resolve strict independent pins or the legacy advisory shared fallback. */
export function resolveIndependentOperatorPinsV1(options: {
  strictVerification: boolean;
  first?: Uint8Array;
  second?: Uint8Array;
  legacyShared?: Uint8Array;
}): readonly [Uint8Array, Uint8Array] {
  if (options.strictVerification) return assertIndependentOperatorPinsV1(options);
  const fallback = options.legacyShared;
  return [
    exactOperatorPinV1('first operator pin', options.first ?? fallback),
    exactOperatorPinV1('second operator pin', options.second ?? fallback),
  ];
}

export interface StrictAttestationSummary {
  state: 'unattested' | 'verified' | 'verified-vcek' | 'plaintext' | 'mismatch';
  sevStatus?: string;
  pinStatus?: 'no-pin' | 'match' | 'measurement-mismatch' | 'binary-mismatch';
}

export interface StrictOperatorIdentitySummary {
  state: 'not-checked' | 'unconfigured' | 'verified' | 'unverified' | 'error';
  serverId?: string;
  binarySha256Hex?: string;
}

export interface StrictServerPin {
  measurementHex?: string;
  binarySha256Hex?: string;
}

export interface StrictTransportOptions {
  secureChannelEstablished: boolean;
  attestations: readonly [StrictAttestationSummary, StrictAttestationSummary];
  expectedPins: readonly [StrictServerPin | undefined, StrictServerPin | undefined];
  expectedServerIds: readonly [string | undefined, string | undefined];
  requireOperatorIdentity?: boolean;
  operatorIdentities?: readonly [
    StrictOperatorIdentitySummary,
    StrictOperatorIdentitySummary,
  ];
  /** Browser-local pins only; never serialized to either provider. */
  operatorPins?: readonly [Uint8Array | undefined, Uint8Array | undefined];
}

function configured(value: string | undefined): boolean {
  return value !== undefined && value.trim().length > 0;
}

/** Return every reason the strict transport gate would reject the session. */
export function collectStrictTransportFailures(options: StrictTransportOptions): string[] {
  const failures: string[] = [];
  try {
    assertIndependentOperatorPinsV1({
      first: options.operatorPins?.[0],
      second: options.operatorPins?.[1],
    });
  } catch (error) {
    failures.push((error as Error)?.message ?? String(error));
  }
  if (!options.secureChannelEstablished) {
    failures.push('secure-channel upgrade did not complete');
  }

  const expectedServerIds = options.expectedServerIds;
  for (let index = 0; index < 2; index++) {
    if (!configured(expectedServerIds[index])) {
      failures.push(`server ${index}: no expected server id is configured`);
    }
  }
  if (
    configured(expectedServerIds[0])
    && configured(expectedServerIds[1])
    && expectedServerIds[0] === expectedServerIds[1]
  ) {
    failures.push(
      `expected server ids must be distinct, both endpoints are configured as ${expectedServerIds[0]}`,
    );
  }

  for (let index = 0; index < 2; index++) {
    const attestation = options.attestations[index];
    const pin = options.expectedPins[index];
    const hasMeasurementPin = configured(pin?.measurementHex);
    const hasBinaryPin = configured(pin?.binarySha256Hex);

    if (!pin || (!hasMeasurementPin && !hasBinaryPin)) {
      failures.push(`server ${index}: no attestation pin is configured`);
    }
    if (attestation.pinStatus !== 'match') {
      failures.push(
        `server ${index}: attestation pin status is ${attestation.pinStatus ?? 'missing'}, expected match`,
      );
    }
    if (attestation.state !== 'verified' && attestation.state !== 'verified-vcek') {
      failures.push(
        `server ${index}: attestation state is ${attestation.state}, expected verified or verified-vcek`,
      );
    }

    if (hasMeasurementPin) {
      if (attestation.state !== 'verified-vcek') {
        failures.push(
          `server ${index}: a measurement pin requires verified-vcek attestation`,
        );
      }
      if (attestation.sevStatus !== 'reportDataMatch') {
        failures.push(
          `server ${index}: a measurement pin requires SEV-SNP reportDataMatch`,
        );
      }
    } else if (attestation.sevStatus === 'noSevHost') {
      // A non-SEV host is not hardware-attested. Strict mode can still bind it
      // to the operator-published binary, but must never accept an unpinned
      // self-report as a trust root.
      if (!hasBinaryPin) {
        failures.push(`server ${index}: a no-SEV host requires a binary pin`);
      }
    } else if (attestation.sevStatus !== 'reportDataMatch') {
      failures.push(
        `server ${index}: SEV status is ${attestation.sevStatus ?? 'missing'}, expected reportDataMatch or noSevHost`,
      );
    }
  }

  for (let index = 0; index < 2; index++) {
    const attestation = options.attestations[index];
    const pin = options.expectedPins[index];
    const identity = options.operatorIdentities?.[index];
    // On a no-SEV host the runtime's binary hash is not hardware-attested.
    // Require the signed announce identity even if a caller tries to disable
    // the optional operator check, and below bind that signed manifest's
    // binary claim to the configured pin. This remains an operator-identity
    // trust tier, not hardware attestation. Hardware-attested endpoints require
    // operator identity when configured.
    const operatorRequired =
      options.requireOperatorIdentity === true || attestation.sevStatus === 'noSevHost';
    if (operatorRequired && identity?.state !== 'verified') {
      failures.push(
        `server ${index}: operator identity is ${identity?.state ?? 'missing'}, expected verified`,
      );
      continue;
    }

    if (identity?.state === 'verified') {
      const expectedServerId = expectedServerIds[index];
      if (!configured(identity.serverId)) {
        failures.push(`server ${index}: verified operator identity has no server id`);
      } else if (configured(expectedServerId) && identity.serverId !== expectedServerId) {
        failures.push(
          `server ${index}: operator server id is ${identity.serverId}, expected ${expectedServerId}`,
        );
      }

      if (attestation.sevStatus === 'noSevHost') {
        const expectedBinary = pin?.binarySha256Hex;
        if (!configured(identity.binarySha256Hex)) {
          failures.push(`server ${index}: verified operator identity has no binary sha256`);
        } else if (
          configured(expectedBinary)
          && identity.binarySha256Hex!.toLowerCase() !== expectedBinary!.toLowerCase()
        ) {
          failures.push(
            `server ${index}: operator binary sha256 does not match the configured binary pin`,
          );
        }
      }
    }
  }

  return failures;
}

/** Throw unless the complete two-server transport trust gate is satisfied. */
export function assertStrictTransportReady(options: StrictTransportOptions): void {
  const failures = collectStrictTransportFailures(options);
  if (failures.length > 0) {
    throw new Error(`strict transport verification failed: ${failures.join('; ')}`);
  }
}

export interface StrictServerLegOptions {
  serverIndex: 0 | 1;
  secureChannelEstablished: boolean;
  attestation: StrictAttestationSummary;
  expectedPin?: StrictServerPin;
  expectedServerId?: string;
  requireOperatorIdentity?: boolean;
  operatorIdentity?: StrictOperatorIdentitySummary;
  /** Browser-local pin for this exact leg. */
  operatorPin?: Uint8Array;
}

/** Validate one provider before its policy or capability is requested. This
 * intentionally does not inspect, name, or require the peer provider. */
export function collectStrictServerLegFailures(options: StrictServerLegOptions): string[] {
  const failures: string[] = [];
  const prefix = `server ${options.serverIndex}`;
  try {
    exactOperatorPinV1(`${prefix} operator pin`, options.operatorPin);
  } catch (error) {
    failures.push((error as Error)?.message ?? String(error));
  }
  if (!options.secureChannelEstablished) {
    failures.push(`${prefix}: secure-channel upgrade did not complete`);
  }
  if (!configured(options.expectedServerId)) {
    failures.push(`${prefix}: no expected server id is configured`);
  }

  const hasMeasurementPin = configured(options.expectedPin?.measurementHex);
  const hasBinaryPin = configured(options.expectedPin?.binarySha256Hex);
  if (!options.expectedPin || (!hasMeasurementPin && !hasBinaryPin)) {
    failures.push(`${prefix}: no attestation pin is configured`);
  }
  if (options.attestation.pinStatus !== 'match') {
    failures.push(
      `${prefix}: attestation pin status is ${options.attestation.pinStatus ?? 'missing'}, expected match`,
    );
  }
  if (
    options.attestation.state !== 'verified'
    && options.attestation.state !== 'verified-vcek'
  ) {
    failures.push(
      `${prefix}: attestation state is ${options.attestation.state}, expected verified or verified-vcek`,
    );
  }

  if (hasMeasurementPin) {
    if (options.attestation.state !== 'verified-vcek') {
      failures.push(`${prefix}: a measurement pin requires verified-vcek attestation`);
    }
    if (options.attestation.sevStatus !== 'reportDataMatch') {
      failures.push(`${prefix}: a measurement pin requires SEV-SNP reportDataMatch`);
    }
  } else if (options.attestation.sevStatus === 'noSevHost') {
    if (!hasBinaryPin) failures.push(`${prefix}: a no-SEV host requires a binary pin`);
  } else if (options.attestation.sevStatus !== 'reportDataMatch') {
    failures.push(
      `${prefix}: SEV status is ${options.attestation.sevStatus ?? 'missing'}, expected reportDataMatch or noSevHost`,
    );
  }

  const identity = options.operatorIdentity;
  const operatorRequired =
    options.requireOperatorIdentity === true || options.attestation.sevStatus === 'noSevHost';
  if (operatorRequired && identity?.state !== 'verified') {
    failures.push(
      `${prefix}: operator identity is ${identity?.state ?? 'missing'}, expected verified`,
    );
  } else if (identity?.state === 'verified') {
    if (!configured(identity.serverId)) {
      failures.push(`${prefix}: verified operator identity has no server id`);
    } else if (configured(options.expectedServerId) && identity.serverId !== options.expectedServerId) {
      failures.push(
        `${prefix}: operator server id is ${identity.serverId}, expected ${options.expectedServerId}`,
      );
    }
    if (options.attestation.sevStatus === 'noSevHost') {
      const expectedBinary = options.expectedPin?.binarySha256Hex;
      if (!configured(identity.binarySha256Hex)) {
        failures.push(`${prefix}: verified operator identity has no binary sha256`);
      } else if (
        configured(expectedBinary)
        && identity.binarySha256Hex!.toLowerCase() !== expectedBinary!.toLowerCase()
      ) {
        failures.push(`${prefix}: operator binary sha256 does not match the configured binary pin`);
      }
    }
  }
  return failures;
}

export function assertStrictServerLegReady(options: StrictServerLegOptions): void {
  const failures = collectStrictServerLegFailures(options);
  if (failures.length > 0) {
    throw new Error(`strict transport verification failed: ${failures.join('; ')}`);
  }
}

export interface StrictSingleTransportOptions {
  secureChannelEstablished: boolean;
  attestation: StrictAttestationSummary;
  expectedPin?: StrictServerPin;
  expectedServerId?: string;
  operatorIdentity?: StrictOperatorIdentitySummary;
}

/** Single-provider equivalent used by OnionPIR and TEE-style transports.
 * Unlike the legacy optional two-server identity display, strict standalone
 * mode always requires an operator-signed endpoint identity. */
export function collectStrictSingleTransportFailures(
  options: StrictSingleTransportOptions,
): string[] {
  const failures: string[] = [];
  if (!options.secureChannelEstablished) {
    failures.push('secure-channel upgrade did not complete');
  }
  if (!configured(options.expectedServerId)) {
    failures.push('no expected server id is configured');
  }
  const hasMeasurementPin = configured(options.expectedPin?.measurementHex);
  const hasBinaryPin = configured(options.expectedPin?.binarySha256Hex);
  if (!options.expectedPin || (!hasMeasurementPin && !hasBinaryPin)) {
    failures.push('no attestation pin is configured');
  }
  if (options.attestation.pinStatus !== 'match') {
    failures.push(
      `attestation pin status is ${options.attestation.pinStatus ?? 'missing'}, expected match`,
    );
  }
  if (
    options.attestation.state !== 'verified'
    && options.attestation.state !== 'verified-vcek'
  ) {
    failures.push(
      `attestation state is ${options.attestation.state}, expected verified or verified-vcek`,
    );
  }
  if (hasMeasurementPin) {
    if (options.attestation.state !== 'verified-vcek') {
      failures.push('a measurement pin requires verified-vcek attestation');
    }
    if (options.attestation.sevStatus !== 'reportDataMatch') {
      failures.push('a measurement pin requires SEV-SNP reportDataMatch');
    }
  } else if (
    options.attestation.sevStatus !== 'reportDataMatch'
    && options.attestation.sevStatus !== 'noSevHost'
  ) {
    failures.push(
      `SEV status is ${options.attestation.sevStatus ?? 'missing'}, expected reportDataMatch or noSevHost`,
    );
  }

  const identity = options.operatorIdentity;
  if (identity?.state !== 'verified') {
    failures.push(`operator identity is ${identity?.state ?? 'missing'}, expected verified`);
  } else {
    if (identity.serverId !== options.expectedServerId) {
      failures.push(
        `operator server id is ${identity.serverId ?? 'missing'}, expected ${options.expectedServerId}`,
      );
    }
    if (options.attestation.sevStatus === 'noSevHost') {
      const expectedBinary = options.expectedPin?.binarySha256Hex;
      if (!configured(identity.binarySha256Hex)) {
        failures.push('verified operator identity has no binary sha256');
      } else if (
        configured(expectedBinary)
        && identity.binarySha256Hex!.toLowerCase() !== expectedBinary!.toLowerCase()
      ) {
        failures.push('operator binary sha256 does not match the configured binary pin');
      }
    }
  }
  return failures;
}

export function assertStrictSingleTransportReady(
  options: StrictSingleTransportOptions,
): void {
  const failures = collectStrictSingleTransportFailures(options);
  if (failures.length > 0) {
    throw new Error(`strict transport verification failed: ${failures.join('; ')}`);
  }
}
