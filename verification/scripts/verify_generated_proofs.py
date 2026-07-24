#!/usr/bin/env python3
"""Verify the production database-proof-v2 consumer lock.

The registry records are useful audit evidence, but are not themselves a
trust decision. This checker pins an exact registry commit, validates the
content-addressed records, then replays the proof-directory verifier from the
current BitcoinPIR source and compares every frontend pin field.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK = ROOT / "verification/locks/generated-proofs.json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
PROOF_FIELDS = {
    "proofVersion",
    "buildKind",
    "fromHeight",
    "fromBlockHashHex",
    "height",
    "blockHashHex",
    "muhashHex",
    "bucketSuperRootHex",
    "onionSuperRootHex",
    "paramsHashHex",
    "networkMagicHex",
    "builderBinarySha256Hex",
    "builderGitCommit",
    "onionEntrySize",
    "onionTotalPackedEntries",
    "onionIndexBinsPerTable",
    "onionChunkBinsPerTable",
    "onionIndexSlotsPerBin",
    "onionIndexSlotSize",
}


def fail(message: str) -> None:
    print(f"generated proof lock check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key}")
        result[key] = value
    return result


def load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        fail(f"cannot load {label} at {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value, raw


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(
            f"{label} keys differ: missing={sorted(expected - set(value))}, "
            f"unexpected={sorted(set(value) - expected)}"
        )


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def require_hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        fail(f"{label} is not a canonical digest/commit")
    return value


def run(command: list[str], cwd: Path, label: str) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if result.returncode != 0:
        fail(f"{label} failed:\n{result.stdout}{result.stderr}")
    return result.stdout.strip()


def record_path(registry: Path, kind: str, sha: str) -> Path:
    if kind == "deployment":
        return registry / "deployments" / "production" / "sha256" / f"{sha}.json"
    fail(f"unknown record kind {kind}")


def verify_bundle(
    registry: Path,
    bundle: dict[str, Any],
    profile: str,
    accepted_verifier: dict[str, Any],
    verifier_binary: Path,
) -> None:
    exact_keys(
        bundle,
        {"dbId", "manifestSha256", "verificationRecordSha256", "deploymentRecordSha256", "proofFields"},
        "lock bundle",
    )
    db_id = bundle["dbId"]
    if type(db_id) is not int or db_id < 0 or db_id > 255:
        fail("lock bundle dbId must be a byte")
    manifest_sha = require_hex(bundle["manifestSha256"], HEX64, f"db {db_id} manifestSha256")
    verification_sha = require_hex(
        bundle["verificationRecordSha256"], HEX64, f"db {db_id} verificationRecordSha256"
    )
    deployment_sha = require_hex(
        bundle["deploymentRecordSha256"], HEX64, f"db {db_id} deploymentRecordSha256"
    )
    proof_fields = bundle["proofFields"]
    if not isinstance(proof_fields, dict):
        fail(f"db {db_id} proofFields must be an object")
    exact_keys(proof_fields, PROOF_FIELDS, f"db {db_id} proofFields")

    bundle_dir = registry / "bundles" / "sha256" / manifest_sha[:2] / manifest_sha
    manifest, manifest_raw = load_json(bundle_dir / "manifest.json", f"db {db_id} manifest")
    if digest(manifest_raw) != manifest_sha:
        fail(f"db {db_id} manifest content hash drifted")
    subject = manifest.get("subject", {})
    identifiers = subject.get("identifiers", {}) if isinstance(subject, dict) else {}
    claims = manifest.get("claims", {})
    if not isinstance(identifiers, dict) or not isinstance(claims, dict):
        fail(f"db {db_id} manifest subject/claims are malformed")
    manifest_expectations = {
        "dbId": db_id,
        "buildKind": proof_fields["buildKind"],
        "fromHeight": proof_fields["fromHeight"],
        "height": proof_fields["height"],
        "blockHash": proof_fields["blockHashHex"],
    }
    if proof_fields["buildKind"] == "delta":
        manifest_expectations["fromBlockHash"] = proof_fields["fromBlockHashHex"]
    for key, expected in manifest_expectations.items():
        if identifiers.get(key) != expected:
            fail(f"db {db_id} manifest identifier {key} does not match the lock")
    claim_expectations = {
        "evidenceVersion": proof_fields["proofVersion"],
        "builderBinarySha256": proof_fields["builderBinarySha256Hex"],
        "paramsHashV2": proof_fields["paramsHashHex"],
        "muhash": proof_fields["muhashHex"],
        "bucketSuperRoot": proof_fields["bucketSuperRootHex"],
        "onionSuperRoot": proof_fields["onionSuperRootHex"],
        "onionTotalPackedEntries": proof_fields["onionTotalPackedEntries"],
        "onionIndexBinsPerTable": proof_fields["onionIndexBinsPerTable"],
        "onionChunkBinsPerTable": proof_fields["onionChunkBinsPerTable"],
    }
    for key, expected in claim_expectations.items():
        if claims.get(key) != expected:
            fail(f"db {db_id} manifest claim {key} does not match the lock")

    verifier_commit = accepted_verifier["commit"]
    verification_path = (
        registry / "verifications" / "sha256" / manifest_sha / verifier_commit / f"{verification_sha}.json"
    )
    verification, verification_raw = load_json(verification_path, f"db {db_id} verification record")
    if digest(verification_raw) != verification_sha:
        fail(f"db {db_id} verification record content hash drifted")
    if verification.get("bundleManifestSha256") != manifest_sha:
        fail(f"db {db_id} verification record points to another bundle")
    if verification.get("verificationProfile") != profile:
        fail(f"db {db_id} verification profile drifted")
    if verification.get("verifier") != accepted_verifier:
        fail(f"db {db_id} accepted verifier tuple drifted")
    checks = verification.get("checks")
    if verification.get("overallOutcome") != "pass" or not isinstance(checks, list) or not checks:
        fail(f"db {db_id} verification record is not a non-empty pass")
    if any(
        not isinstance(check, dict)
        or check.get("required") is not True
        or check.get("outcome") != "pass"
        or check.get("exitCode") != 0
        for check in checks
    ):
        fail(f"db {db_id} verification record contains a non-passing required check")

    deployment_path = record_path(registry, "deployment", deployment_sha)
    deployment, deployment_raw = load_json(deployment_path, f"db {db_id} deployment record")
    if digest(deployment_raw) != deployment_sha:
        fail(f"db {db_id} deployment record content hash drifted")
    if deployment.get("environment") != "production":
        fail(f"db {db_id} deployment is not production")
    if deployment.get("bundleManifestSha256") != manifest_sha:
        fail(f"db {db_id} deployment points to another bundle")
    if deployment.get("verificationRecordSha256") != verification_sha:
        fail(f"db {db_id} deployment points to another verification")

    revocations = registry / "revocations" / "sha256" / manifest_sha
    if revocations.exists() and any(revocations.glob("*.json")):
        fail(f"db {db_id} locked bundle has a revocation record")

    output = run([str(verifier_binary), str(bundle_dir / "artifacts")], ROOT, f"db {db_id} proof replay")
    replayed: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in replayed:
            fail(f"db {db_id} proof replay returned malformed output")
        replayed[key] = value
    if set(replayed) != PROOF_FIELDS:
        fail(f"db {db_id} proof replay field set drifted")
    for key, expected in proof_fields.items():
        if replayed[key] != str(expected):
            fail(f"db {db_id} replayed {key}: expected {expected}, got {replayed[key]}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--registry-root", type=Path, required=True)
    args = parser.parse_args()

    lock, _ = load_json(args.lock.resolve(), "generated proof lock")
    exact_keys(lock, {"schemaVersion", "registry", "verificationProfile", "acceptedVerifier", "bundles"}, "lock")
    if lock["schemaVersion"] != 1:
        fail("unsupported lock schemaVersion")
    registry_config = lock["registry"]
    accepted_verifier = lock["acceptedVerifier"]
    bundles = lock["bundles"]
    if not isinstance(registry_config, dict) or not isinstance(accepted_verifier, dict):
        fail("registry and acceptedVerifier must be objects")
    exact_keys(registry_config, {"repository", "commit"}, "registry lock")
    exact_keys(accepted_verifier, {"repository", "commit", "tool", "toolSha256"}, "acceptedVerifier")
    registry_commit = require_hex(registry_config["commit"], HEX40, "registry commit")
    require_hex(accepted_verifier["commit"], HEX40, "accepted verifier commit")
    require_hex(accepted_verifier["toolSha256"], HEX64, "accepted verifier toolSha256")
    if registry_config["repository"] != "https://github.com/Bitcoin-PIR/proof-registry":
        fail("unexpected registry repository")
    if not isinstance(bundles, list) or [item.get("dbId") for item in bundles if isinstance(item, dict)] != [0, 1]:
        fail("lock must contain exactly the sorted production database IDs 0 and 1")

    registry = args.registry_root.resolve()
    actual_commit = run(["git", "rev-parse", "HEAD"], registry, "registry commit lookup")
    if actual_commit != registry_commit:
        fail(f"registry checkout is {actual_commit}, lock requires {registry_commit}")
    run([sys.executable, "tools/validate_registry.py", "--root", "."], registry, "registry integrity validator")

    run(["cargo", "build", "--quiet", "-p", "pir-db-attest", "--bin", "verify-proof-directory"], ROOT, "proof replay verifier build")
    verifier_binary = ROOT / "target" / "debug" / "verify-proof-directory"
    for bundle in bundles:
        if not isinstance(bundle, dict):
            fail("lock bundles must be objects")
        verify_bundle(
            registry,
            bundle,
            lock["verificationProfile"],
            accepted_verifier,
            verifier_binary,
        )
    print(f"generated proof lock verified: registry={registry_commit}, bundles=2")


if __name__ == "__main__":
    main()
