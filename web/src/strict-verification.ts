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
 * Establish trusted database roots before a query is allowed:
 *
 * 1. Rust/WASM verifies the signed database proof.
 * 2. TypeScript compares every proof field with the production pin.
 * 3. The same live proof handle is transferred into the native client.
 * 4. After all roots are installed, every database's tree-tops are fetched and
 *    checked against the installed root.
 *
 * `installVerifiedDatabaseProof` is an ownership boundary.  Once invoked, the
 * handle is considered consumed even if the binding reports an error; freeing
 * it in JS afterwards could double-free a wasm-bindgen by-value argument.
 */
export async function verifyInstallAndPreflightDatabaseProofs(
  options: StrictDatabaseProofOptions,
): Promise<DatabaseProofStatus[]> {
  const { client, pins, onStatus } = options;
  if (pins.length === 0) {
    throw new Error('strict database verification requires at least one pinned database proof');
  }

  const installed: Array<{
    pin: DatabaseProofPin;
    proof: VerifiedDatabaseProof;
    status: DatabaseProofStatus;
  }> = [];

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
      const status = databaseProofUnavailable(pin, error);
      onStatus?.(pin.dbId, status);
      throw new Error(
        `database proof verification failed for db ${pin.dbId}: ${errorMessage(error)}`,
        { cause: error },
      );
    }

    try {
      const proof = verifiedDatabaseProofFromWasm(proofHandle);
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
        const movedProof = proofHandle;
        proofHandle = null;
        client.installVerifiedDatabaseProof(movedProof);
      } catch (error) {
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

  const verified: DatabaseProofStatus[] = [];
  for (const item of installed) {
    try {
      await client.preflightDatabase(item.pin.dbId);
    } catch (error) {
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
}

function configured(value: string | undefined): boolean {
  return value !== undefined && value.trim().length > 0;
}

/** Return every reason the strict transport gate would reject the session. */
export function collectStrictTransportFailures(options: StrictTransportOptions): string[] {
  const failures: string[] = [];
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
