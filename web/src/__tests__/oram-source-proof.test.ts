import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import {
  MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN,
} from '../attest-pin.js';
import {
  DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH,
  directOramManifestBindingMismatches,
  paramsHashV2ForAttestedBuildEvidence,
  parseAttestedBuildEvidence,
  parseDirectOramManifestBinding,
  reportDataForBuildEvidence,
  verifyOramSourceProof,
} from '../oram-source-proof.js';
import { bytesToHex, sha256 } from '../hash.js';

const publicRoot = new URL('../../public/', import.meta.url);
const legacyFixtureRoot = new URL(
  './fixtures/oram-source-proof-v1-leaked/',
  import.meta.url,
);
const LEGACY_V1_MANIFEST_PATH = '/proofs/oram-source/mainnet_948454.json';
// This forensic fixture documents the superseded ORAM deployment. It must not
// follow the current DPF-only VPSBG runtime pin.
const LEGACY_V1_PIR2_BINARY_SHA256 =
  'cc4ec24b9ecf54c962d20843a374a8235d9b71954adf05bdb4d6bb3155e16b1e';
const LEGACY_V1_PIR2_MEASUREMENT_HEX =
  'd7ae6fb895380b1408b5ba7640a2eaa091754fc6279b62eb96f4bd1eee5532e95bc1df3b1485a06b3f43d648d05d3245';

async function publicArtifactLoader(path: string): Promise<Uint8Array> {
  const clean = path.startsWith('/') ? path.slice(1) : path;
  return new Uint8Array(await readFile(new URL(clean, publicRoot)));
}

async function legacyArtifactLoader(path: string): Promise<Uint8Array> {
  const clean = path.startsWith('/') ? path.slice(1) : path;
  return new Uint8Array(await readFile(new URL(clean, legacyFixtureRoot)));
}

async function readBase64Fixture(name: string): Promise<Uint8Array> {
  const encoded = await readFile(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
  return new Uint8Array(Buffer.from(encoded.trim(), 'base64'));
}

describe('ORAM source-binding proof', () => {
  it('rejects the relocated forensic v1 proof even when all historical artifacts match', async () => {
    const status = await verifyOramSourceProof({
      manifestPath: LEGACY_V1_MANIFEST_PATH,
      artifactLoader: legacyArtifactLoader,
      expectedDbPin: MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN,
      verifyAmdSignature: false,
    });

    expect(status.state).toBe('unverified');
    expect(status.verified).toBeUndefined();
    expect(
      status.mismatches.some((m) => m.includes('requires evidence v2')),
    ).toBe(true);
    expect(status.mismatches).toContain(
      'liveDatabaseProof is required before an ORAM source proof can be trusted',
    );
    expect(status.manifest?.anchor.height).toBe(948454);
    expect(status.manifest?.oramBuild.commit).toBe(
      '5f366492504d8e853cbd60d25a6adbf021a78746',
    );
    expect(status.manifest?.oramBuild.params.indexSeedDecimal).toBe(
      '8030603977422561841',
    );
    expect(status.manifest?.liveDeployment.status).toBe(
      'strict-source-bound-boot-regeneration-live-on-pir2',
    );
    expect(status.manifest?.liveDeployment.pir2BinarySha256).toBe(
      LEGACY_V1_PIR2_BINARY_SHA256,
    );
    expect(status.manifest?.liveDeployment.pir2MeasurementHex).toBe(
      LEGACY_V1_PIR2_MEASUREMENT_HEX,
    );
    expect(status.manifest?.liveDeployment.pir2UkiSha256).toBe(
      '34b04d1bfc0501c0cc222aff446a55de0a74d4e5218a21a05bf8756f8293b681',
    );
    expect(status.manifest?.liveDeployment.currentPir2RuntimeBitcoinPirCommit).toBe(
      '81dd96d442d39200fee7e6c97f5c308f38126756',
    );
  });

  it('parses and verifies the exact typed direct_oram manifest binding without rounding u64', async () => {
    const manifest = JSON.parse(
      new TextDecoder().decode(await legacyArtifactLoader(LEGACY_V1_MANIFEST_PATH)),
    );
    const directOram = `
[manifest]
version = 1

[direct_oram]
version = 1
index_sha256 = "${manifest.directInputs.index.sha256}"
index_bytes = ${manifest.directInputs.index.bytes}
index_records = ${manifest.directInputs.index.records}
chunk_sha256 = "${manifest.directInputs.chunks.sha256}"
chunk_bytes = ${manifest.directInputs.chunks.bytes}
chunk_records = ${manifest.directInputs.chunks.records}
index_slots_per_bin = ${manifest.oramBuild.params.indexSlotsPerBin}
index_hash_fns = ${manifest.oramBuild.params.indexHashFns}
index_load_factor_ppb = ${Math.round(manifest.oramBuild.params.indexLoadFactor * 1_000_000_000)}
index_seed = ${manifest.oramBuild.params.indexSeedDecimal}

[files]
"ignored.bin" = "${'0'.repeat(64)}"
`;

    expect(parseDirectOramManifestBinding(directOram).index_seed).toBe(
      '8030603977422561841',
    );
    expect(directOramManifestBindingMismatches(directOram, manifest)).toEqual([]);
    expect(
      directOramManifestBindingMismatches(
        directOram.replace('index_seed = 8030603977422561841', 'index_seed = 8030603977422561842'),
        manifest,
      ).some((m) => m.includes('index seed')),
    ).toBe(true);
  });

  it('rejects ambiguous or extended direct_oram manifest tables', () => {
    const valid = `
[direct_oram]
version = 1
index_sha256 = "${'1'.repeat(64)}"
index_bytes = 25
index_records = 1
chunk_sha256 = "${'2'.repeat(64)}"
chunk_bytes = 40
chunk_records = 1
index_slots_per_bin = 4
index_hash_fns = 2
index_load_factor_ppb = 950000000
index_seed = 9223372036854775807
`;

    expect(() => parseDirectOramManifestBinding(`${valid}\n${valid}`)).toThrow(
      'duplicate [direct_oram] section',
    );
    expect(() => parseDirectOramManifestBinding(`${valid}extra = 1\n`)).toThrow(
      'unknown [direct_oram] key extra',
    );
    expect(() =>
      parseDirectOramManifestBinding(valid.replace('index_records = 1\n', '')),
    ).toThrow('missing [direct_oram] key index_records');
    expect(() =>
      parseDirectOramManifestBinding(valid.replace('index_seed = 9223372036854775807', 'index_seed = "123"')),
    ).toThrow('must be canonical unquoted decimal');
    expect(() =>
      parseDirectOramManifestBinding(valid.replace('index_seed = 9223372036854775807', 'index_seed = 18446744073709551615')),
    ).toThrow('exceeds its integer range');
    expect(() =>
      parseDirectOramManifestBinding(valid.replace('index_bytes = 25', 'index_bytes = 26')),
    ).toThrow('INDEX bytes/records mismatch');
  });

  it('reports unverified when the manifest MuHash is changed', async () => {
    const original = JSON.parse(
      new TextDecoder().decode(await legacyArtifactLoader(LEGACY_V1_MANIFEST_PATH)),
    );
    original.anchor.muhashHex =
      '00' + original.anchor.muhashHex.slice(2);
    const mutatedManifest = new TextEncoder().encode(JSON.stringify(original));

    const status = await verifyOramSourceProof({
      manifestPath: LEGACY_V1_MANIFEST_PATH,
      expectedDbPin: MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN,
      verifyAmdSignature: false,
      artifactLoader: async (path) => (
        path === LEGACY_V1_MANIFEST_PATH ? mutatedManifest : legacyArtifactLoader(path)
      ),
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => m.includes('DB certification MuHash'))).toBe(true);
    expect(status.mismatches.some((m) => m.includes('manifest DB pin'))).toBe(true);
  });

  it('recomputes the SNP REPORT_DATA binding from build-evidence.bin', async () => {
    const manifest = JSON.parse(
      new TextDecoder().decode(await legacyArtifactLoader(LEGACY_V1_MANIFEST_PATH)),
    );
    const evidence = await legacyArtifactLoader(
      manifest.attestedBuilder.artifacts.buildEvidence.path,
    );

    expect(bytesToHex(reportDataForBuildEvidence(evidence))).toBe(
      manifest.attestedBuilder.sevSnp.reportDataHex,
    );

    const parsed = parseAttestedBuildEvidence(evidence);
    expect(parsed.version).toBe(1);
    expect(parsed.snapshotBytesDecimal).toBe('9422874286');
    expect(parsed.anchor.height).toBe(948454);
    expect(parsed.anchor.blockHashHex).toBe(manifest.anchor.blockHashHex);
    expect(parsed.serverDbManifestSha256Hex).toBe(
      manifest.attestedBuilder.manifests.serverDbManifestSha256,
    );

    expect(() => parseAttestedBuildEvidence(evidence.slice(0, -1))).toThrow('truncated');
    expect(() =>
      parseAttestedBuildEvidence(Uint8Array.from([...evidence, 0])),
    ).toThrow('trailing bytes');
    const badOptionTag = evidence.slice();
    badOptionTag[badOptionTag.length - 97] = 2;
    expect(() => parseAttestedBuildEvidence(badOptionTag)).toThrow('bad signed_root_bundle');

    const syntheticV2 = {
      ...parsed,
      version: 2 as const,
      paramsHashHex: 'a600f33fa0e644aab533a050eabf9c03882aa00f1b293ddf9d7f4bf7c8142563',
      onionLayoutV2: {
        totalPackedEntries: 948640,
        indexBinsPerTable: 10273,
        chunkBinsPerTable: 37954,
      },
    };
    expect(paramsHashV2ForAttestedBuildEvidence(syntheticV2)).toBe(
      syntheticV2.paramsHashHex,
    );
  });

  it('matches the Rust producer v2 parser, params hash, and REPORT_DATA golden', async () => {
    const evidence = await readBase64Fixture('build-evidence-v2-reattest.base64');
    const reportData = await readBase64Fixture(
      'build-evidence-v2-reattest.report-data.base64',
    );
    const parsed = parseAttestedBuildEvidence(evidence);

    expect(bytesToHex(sha256(evidence))).toBe(
      'e9795887805769525d484824d85d8b3fcda008340c1b2332de7b46a59f055517',
    );
    expect(parsed.version).toBe(2);
    expect(parsed.evidenceMode).toBe('reattest-existing');
    expect(parsed.utxoMuhashHex).toBe(
      'cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee',
    );
    expect(paramsHashV2ForAttestedBuildEvidence(parsed)).toBe(parsed.paramsHashHex);
    expect(reportDataForBuildEvidence(evidence)).toEqual(reportData);
  });

  it('rejects a consistent outer substitution of the server manifest and every JSON pin', async () => {
    const manifest = JSON.parse(
      new TextDecoder().decode(await legacyArtifactLoader(LEGACY_V1_MANIFEST_PATH)),
    );
    const serverManifestPath = manifest.attestedBuilder.artifacts.serverDbManifest.path;
    const originalServerManifest = await legacyArtifactLoader(serverManifestPath);
    const suffix = new TextEncoder().encode('\n# attacker-controlled consistent substitution\n');
    const substituted = new Uint8Array(originalServerManifest.length + suffix.length);
    substituted.set(originalServerManifest);
    substituted.set(suffix, originalServerManifest.length);
    const substitutedSha256 = bytesToHex(sha256(substituted));
    manifest.attestedBuilder.artifacts.serverDbManifest.sha256 = substitutedSha256;
    manifest.attestedBuilder.artifacts.serverDbManifest.size = substituted.length;
    manifest.attestedBuilder.manifests.serverDbManifestSha256 = substitutedSha256;
    const substitutedOuterManifest = new TextEncoder().encode(JSON.stringify(manifest));

    const status = await verifyOramSourceProof({
      manifestPath: LEGACY_V1_MANIFEST_PATH,
      expectedDbPin: MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN,
      verifyAmdSignature: false,
      artifactLoader: async (path) => {
        if (path === LEGACY_V1_MANIFEST_PATH) return substitutedOuterManifest;
        if (path === serverManifestPath) return substituted;
        return legacyArtifactLoader(path);
      },
    });

    expect(status.state).toBe('unverified');
    expect(
      status.mismatches.some((m) => m.includes('attested server DB manifest bytes sha256')),
    ).toBe(true);
  });

  it('does not call an unpinned source proof verified', async () => {
    const status = await verifyOramSourceProof({
      manifestPath: LEGACY_V1_MANIFEST_PATH,
      artifactLoader: legacyArtifactLoader,
      verifyAmdSignature: false,
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches).toContain(
      'expectedDbPin is required before an ORAM source proof can be trusted',
    );
  });

  it('keeps the production current proof unavailable until a v2 ceremony publishes it', async () => {
    expect(DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH).toBe('/proofs/oram-source/current.json');
    const status = await verifyOramSourceProof({ artifactLoader: publicArtifactLoader });
    expect(status.state).toBe('unavailable');
    expect(status.verified).toBeUndefined();
    await expect(publicArtifactLoader(LEGACY_V1_MANIFEST_PATH)).rejects.toThrow();
  });

  it('requires AMD certificate artifacts by default even for a byte-consistent fixture', async () => {
    const status = await verifyOramSourceProof({
      manifestPath: LEGACY_V1_MANIFEST_PATH,
      artifactLoader: legacyArtifactLoader,
      expectedDbPin: MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN,
    });
    expect(status.state).toBe('unavailable');
    expect(status.error).toContain('attestedBuilder.arkPem');
    expect(status.verified).toBeUndefined();
  });

  it('binds the current live DB proof to the exact attested server manifest root', async () => {
    const manifest = JSON.parse(
      new TextDecoder().decode(await legacyArtifactLoader(LEGACY_V1_MANIFEST_PATH)),
    );
    const evidence = parseAttestedBuildEvidence(
      await legacyArtifactLoader(manifest.attestedBuilder.artifacts.buildEvidence.path),
    );
    const status = await verifyOramSourceProof({
      manifestPath: LEGACY_V1_MANIFEST_PATH,
      artifactLoader: legacyArtifactLoader,
      expectedDbPin: MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN,
      verifyAmdSignature: false,
      liveDatabaseProof: {
        dbId: manifest.anchor.dbId,
        manifestRootHex: '00'.repeat(32),
        buildKind: manifest.anchor.buildKind,
        fromHeight: manifest.anchor.fromHeight,
        fromBlockHashHex: manifest.anchor.fromBlockHashHex,
        height: manifest.anchor.height,
        blockHashHex: manifest.anchor.blockHashHex,
        muhashHex: manifest.anchor.muhashHex,
        bucketSuperRootHex: manifest.anchor.bucketSuperRootHex,
        onionSuperRootHex: manifest.anchor.onionSuperRootHex,
        paramsHashHex: manifest.anchor.paramsHashHex,
        networkMagicHex: manifest.anchor.networkMagicHex,
        builderBinarySha256Hex: manifest.attestedBuilder.builderBinarySha256Hex,
        builderGitCommit: manifest.attestedBuilder.builderGitCommit,
        onionEntrySize: evidence.onionEntrySize,
        proofVersion: evidence.version,
      },
    });
    expect(status.state).toBe('unverified');
    expect(
      status.mismatches.some((m) => m.includes('live ORAM DB proof: manifestRootHex')),
    ).toBe(true);
  });

  it('keeps the 64-bit ORAM index seed exact instead of rounding in JavaScript', async () => {
    const original = JSON.parse(
      new TextDecoder().decode(await legacyArtifactLoader(LEGACY_V1_MANIFEST_PATH)),
    );
    original.oramBuild.params.indexSeedDecimal = '8030603977422561842';
    const mutatedManifest = new TextEncoder().encode(JSON.stringify(original));

    const status = await verifyOramSourceProof({
      manifestPath: LEGACY_V1_MANIFEST_PATH,
      verifyAmdSignature: false,
      artifactLoader: async (path) => (
        path === LEGACY_V1_MANIFEST_PATH ? mutatedManifest : legacyArtifactLoader(path)
      ),
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => m.includes('index_seed decimal'))).toBe(true);
  });
});
