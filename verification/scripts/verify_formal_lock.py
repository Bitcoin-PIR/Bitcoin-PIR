#!/usr/bin/env python3
"""Validate the product-to-formal-proof lock before proof execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK = ROOT / "verification/locks/formal-proofs.json"
HEX_256 = re.compile(r"[0-9a-f]{64}")
GIT_COMMIT = re.compile(r"[0-9a-f]{40}")
DIGITS = re.compile(r"[0-9]+")
PROOF_MANIFEST_PATH = Path("proof-manifest.json")
IMPLEMENTATION_CONTRACT_PATH = Path("verification/contracts/wire-shape-v1.json")
TRUSTED_VERIFIER_COMMAND = ["easycrypt", "compile", "-I", ".", "Theorem.ec"]
TRUSTED_VERIFIER_DOCKERFILE = Path("verification/toolchains/easycrypt.Dockerfile")
TRUSTED_VERIFIER_SCHEMA = "BitcoinPIR/product-owned-easycrypt-verifier/v2"
TRUSTED_VERIFIER_IMAGE = "ghcr.io/bitcoin-pir/bitcoinpir-easycrypt-verifier"
TRUSTED_VERIFIER_SOURCE_REPOSITORY = "Bitcoin-PIR/Bitcoin-PIR"
TRUSTED_VERIFIER_PUBLISH_WORKFLOW = (
    ".github/workflows/publish-easycrypt-verifier.yml"
)
TRUSTED_VERIFIER_SOURCE_REF = "refs/heads/main"
OCI_IMAGE_DIGEST = re.compile(
    r"ghcr\.io/bitcoin-pir/bitcoinpir-easycrypt-verifier@sha256:[0-9a-f]{64}"
)
COMPILED_PROOF_SUFFIXES = {".eco", ".ecpc", ".ecaut"}
FORBIDDEN_PROOF_FILENAMES = {"easycrypt.project"}
FORBIDDEN_PROOF_SUFFIXES = {".eca"}
TRUSTED_PROOF_TOOLCHAIN = {
    "dockerfile": "toolchain/Dockerfile",
    "base_image": "ghcr.io/easycrypt/ec-build-box@sha256:5a46a4d816e763ad5de9ee9502d52158c742b9b98cc1f60c443d135a270fdb6a",
    "platform": "linux/amd64",
    "easycrypt_repository": "https://github.com/EasyCrypt/easycrypt",
    "easycrypt_commit": "dd9bd930d45e81980e546fc835ed2022418644be",
    "ocaml_version": "4.14.1",
    "why3_version": "1.8.2",
    "solvers": [{"name": "alt-ergo", "version": "2.6.3"}],
}


def fail(message: str) -> None:
    print(f"formal proof lock check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot load {label} at {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value, raw


def require_exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        fail(
            f"{label} keys must be exactly {sorted(expected)}; "
            f"got {sorted(actual)}"
        )


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def proof_sources_digest(manifest: dict[str, object]) -> str:
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        fail("proof manifest sources must be a non-empty array")
    normalized: list[tuple[str, str]] = []
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            fail(f"proof manifest sources[{index}] must be an object")
        path = string_field(source, "path")
        digest = digest_field(source, "sha256")
        normalized.append((path, digest))
    if len({path for path, _ in normalized}) != len(normalized):
        fail("proof manifest contains duplicate source paths")

    aggregate = hashlib.sha256()
    for path, digest in sorted(normalized):
        aggregate.update(path.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(bytes.fromhex(digest))
    return aggregate.hexdigest()


def strip_easycrypt_comments(text: str) -> str:
    """Remove nested EasyCrypt/OCaml comments before structural checks."""
    result: list[str] = []
    depth = 0
    index = 0
    while index < len(text):
        pair = text[index : index + 2]
        if pair == "(*":
            depth += 1
            index += 2
            continue
        if pair == "*)":
            if depth == 0:
                fail("proof source contains an unmatched comment terminator")
            depth -= 1
            index += 2
            continue
        if depth == 0:
            result.append(text[index])
        index += 1
    if depth:
        fail("proof source contains an unterminated comment")
    return "".join(result)


def verify_proof_sources(proof_dir: Path, manifest: dict[str, object]) -> str:
    """Check the locked proof tree without trusting proof-repository scripts."""
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        fail("proof manifest sources must be a non-empty array")

    declared_paths: set[str] = set()
    source_text: dict[str, str] = {}
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            fail(f"proof manifest sources[{index}] must be an object")
        relative = string_field(source, "path")
        path = Path(relative)
        if path.is_absolute() or len(path.parts) != 1 or path.suffix != ".ec":
            fail(f"proof source must be a root-level .ec file: {relative}")
        if relative in declared_paths:
            fail(f"proof manifest contains duplicate source path {relative}")
        declared_paths.add(relative)

        full_path = proof_dir / path
        if not full_path.is_file() or full_path.is_symlink():
            fail(f"proof source is missing, not regular, or a symlink: {relative}")
        raw = full_path.read_bytes()
        expected = digest_field(source, "sha256")
        actual = sha256(raw)
        if actual != expected:
            fail(f"proof source digest drifted for {relative}: {actual}")
        try:
            source_text[relative] = strip_easycrypt_comments(raw.decode("utf-8"))
        except UnicodeDecodeError as error:
            fail(f"proof source is not UTF-8: {relative}: {error}")

    actual_paths: set[str] = set()
    for full_path in proof_dir.rglob("*.ec"):
        relative = full_path.relative_to(proof_dir)
        if ".git" in relative.parts:
            continue
        if not full_path.is_file() or full_path.is_symlink():
            fail(f"proof tree contains a non-regular .ec entry: {relative}")
        actual_paths.add(relative.as_posix())
    if actual_paths != declared_paths:
        fail(
            "proof source set drifted: "
            f"undeclared={sorted(actual_paths - declared_paths)}, "
            f"missing={sorted(declared_paths - actual_paths)}"
        )

    forbidden_actual: list[str] = []
    for full_path in proof_dir.rglob("*"):
        relative = full_path.relative_to(proof_dir)
        if ".git" in relative.parts:
            continue
        if (
            full_path.name in FORBIDDEN_PROOF_FILENAMES
            or full_path.suffix.lower() in FORBIDDEN_PROOF_SUFFIXES
            or full_path.suffix.lower() in COMPILED_PROOF_SUFFIXES
        ):
            forbidden_actual.append(relative.as_posix())
    if forbidden_actual:
        fail(
            "proof tree contains unreviewed EasyCrypt inputs: "
            f"{sorted(forbidden_actual)}"
        )

    tracked_files = git_tracked_files(proof_dir)
    tracked_sources = {path for path in tracked_files if Path(path).suffix == ".ec"}
    if tracked_sources != declared_paths:
        fail(
            "tracked EasyCrypt source set differs from the manifest: "
            f"extra={sorted(tracked_sources - declared_paths)}, "
            f"missing={sorted(declared_paths - tracked_sources)}"
        )
    tracked_compiled = sorted(
        path for path in tracked_files if Path(path).suffix in COMPILED_PROOF_SUFFIXES
    )
    if tracked_compiled:
        fail(f"proof commit contains precompiled EasyCrypt artifacts: {tracked_compiled}")
    tracked_forbidden = sorted(
        path
        for path in tracked_files
        if Path(path).name in FORBIDDEN_PROOF_FILENAMES
        or Path(path).suffix.lower() in FORBIDDEN_PROOF_SUFFIXES
    )
    if tracked_forbidden:
        fail(
            "proof commit contains unreviewed EasyCrypt inputs: "
            f"{tracked_forbidden}"
        )

    code = "\n".join(source_text.values())
    holes = sorted(set(re.findall(r"\b(?:admit|sorry|abort)\b", code)))
    if holes:
        fail(f"proof-hole commands found outside comments: {holes}")
    lemmas = re.findall(r"\blemma\s+([A-Za-z_][A-Za-z0-9_']*)", code)
    expected_lemma_count = manifest.get("expected_lemma_count")
    if type(expected_lemma_count) is not int or expected_lemma_count <= 0:
        fail("proof manifest expected_lemma_count must be a positive integer")
    if len(lemmas) != expected_lemma_count:
        fail(f"expected {expected_lemma_count} lemmas, found {len(lemmas)}")
    if len(set(lemmas)) != len(lemmas):
        fail("proof tree contains duplicate lemma names")

    extracted_axioms: list[dict[str, str]] = []
    for source_path, text in source_text.items():
        for match in re.finditer(
            r"\baxiom\s+([A-Za-z_][A-Za-z0-9_']*)\s*:(.*?\.)", text, re.DOTALL
        ):
            canonical = re.sub(r"\s+", " ", match.group(0)).strip()
            extracted_axioms.append(
                {
                    "name": match.group(1),
                    "source": source_path,
                    "statement_sha256": sha256(canonical.encode("utf-8")),
                }
            )
    extracted_axioms.sort(key=lambda item: (item["source"], item["name"]))
    declared_axioms = manifest.get("axioms")
    if declared_axioms != extracted_axioms:
        fail("proof axiom inventory or statement digest does not match the manifest")

    claims = manifest.get("claims")
    if not isinstance(claims, list) or not claims:
        fail("proof manifest claims must be a non-empty array")
    assumptions = manifest.get("assumptions")
    if not isinstance(assumptions, list):
        fail("proof manifest assumptions must be an array")
    assumption_ids = {
        item.get("id")
        for item in assumptions
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if len(assumption_ids) != len(assumptions):
        fail("proof manifest assumption ids must be present and unique")
    claim_ids: set[str] = set()
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            fail(f"proof manifest claims[{index}] must be an object")
        claim_id = string_field(claim, "id")
        if claim_id in claim_ids:
            fail(f"proof manifest contains duplicate claim id {claim_id}")
        claim_ids.add(claim_id)
        theorem = string_field(claim, "theorem")
        if theorem not in lemmas:
            fail(f"claim {claim_id} names missing theorem {theorem}")
        dependencies = claim.get("depends_on_assumptions")
        if not isinstance(dependencies, list) or not all(
            isinstance(item, str) for item in dependencies
        ):
            fail(f"claim {claim_id} assumption dependencies must be strings")
        unknown = set(dependencies) - assumption_ids
        if unknown:
            fail(f"claim {claim_id} names unknown assumptions {sorted(unknown)}")

    non_claims = manifest.get("explicit_non_claims")
    if not isinstance(non_claims, list) or not non_claims:
        fail("proof manifest explicit_non_claims must be a non-empty array")

    manifest_verification = object_field(manifest, "verification")
    if string_field(manifest_verification, "top_level") != "Theorem.ec":
        fail("trusted verifier requires Theorem.ec as the proof top level")
    theorem_source = source_text.get("Theorem.ec")
    if theorem_source is None:
        fail("proof source set does not contain Theorem.ec")
    imported_modules: set[str] = set()
    for import_list in re.findall(r"\brequire\s+import\s+([^.]+)\.", theorem_source):
        imported_modules.update(import_list.split())
    expected_imports = {Path(path).stem for path in declared_paths - {"Theorem.ec"}}
    missing_imports = expected_imports - imported_modules
    if missing_imports:
        fail(f"Theorem.ec does not import declared proof modules {sorted(missing_imports)}")

    return proof_sources_digest(manifest)


def object_field(value: dict[str, object], name: str) -> dict[str, object]:
    field = value.get(name)
    if not isinstance(field, dict):
        fail(f"{name} must be an object")
    return field


def string_field(value: dict[str, object], name: str) -> str:
    field = value.get(name)
    if not isinstance(field, str) or not field:
        fail(f"{name} must be a non-empty string")
    return field


def digest_field(value: dict[str, object], name: str) -> str:
    field = string_field(value, name)
    if not HEX_256.fullmatch(field):
        fail(f"{name} must be a lowercase SHA-256 digest")
    return field


def safe_relative_path(value: dict[str, object], name: str) -> Path:
    raw = string_field(value, name)
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        fail(f"{name} is not a safe relative path: {raw}")
    return path


def string_list_field(value: dict[str, object], name: str) -> list[str]:
    field = value.get(name)
    if not isinstance(field, list) or not field or not all(
        isinstance(item, str) and item for item in field
    ):
        fail(f"{name} must be a non-empty array of strings")
    return field


def int_field(value: dict[str, object], name: str) -> int:
    field = value.get(name)
    if type(field) is not int:
        fail(f"{name} must be an integer")
    return field


def bool_field(value: dict[str, object], name: str) -> bool:
    field = value.get(name)
    if type(field) is not bool:
        fail(f"{name} must be a boolean")
    return field


def int_list_field(value: dict[str, object], name: str) -> list[int]:
    field = value.get(name)
    if not isinstance(field, list) or not field or not all(
        type(item) is int for item in field
    ):
        fail(f"{name} must be a non-empty array of integers")
    return field


def render_contract_binding(contract: dict[str, object], contract_digest: str) -> bytes:
    """Render the EasyCrypt module whose exact bytes bind contract semantics."""
    binding = object_field(contract, "proofBinding")
    if string_field(binding, "format") != "BitcoinPIR/easycrypt-contract-binding/v1":
        fail("wire contract uses an unsupported EasyCrypt binding format")
    if string_field(binding, "source") != "ContractBinding.ec":
        fail("wire contract binding source must remain ContractBinding.ec")

    parameters = object_field(contract, "parameters")
    index_groups = int_field(parameters, "indexGroups")
    chunk_groups = int_field(parameters, "chunkGroups")
    cuckoo_hashes = int_field(parameters, "indexCuckooHashes")

    backends = object_field(contract, "backends")
    if set(backends) != {"dpf", "harmony", "onion"}:
        fail("wire contract must define exactly dpf, harmony, and onion backends")
    backend_ids: dict[str, list[int]] = {}
    for name in ("dpf", "harmony", "onion"):
        backend = object_field(backends, name)
        if int_field(backend, "deploymentServerCount") <= 0:
            fail(f"{name} deploymentServerCount must be positive")
        backend_ids[name] = int_list_field(backend, "formalPirRoundServerIds")

    round_kind_map = {
        "index": "RIndex",
        "chunk": "RChunk",
        "index_merkle_siblings": "RIndexMerkleSiblings 0",
        "chunk_merkle_siblings": "RChunkMerkleSiblings 0",
        "harmony_hint_refresh": "RHarmonyHintRefresh",
        "onion_key_register": "ROnionKeyRegister",
        "info": "RInfo",
        "merkle_tree_tops": "RMerkleTreeTops",
    }
    round_kinds = string_list_field(contract, "roundKinds")
    if len(round_kinds) != len(set(round_kinds)):
        fail("wire contract roundKinds contains duplicates")
    try:
        easycrypt_round_kinds = [round_kind_map[kind] for kind in round_kinds]
    except KeyError as error:
        fail(f"wire contract contains an unsupported round kind: {error.args[0]}")
    if set(round_kinds) != set(round_kind_map):
        fail("wire contract roundKinds must cover the complete v1 round-kind set")

    leakage_axes = string_list_field(contract, "admittedLeakage")
    expected_leakage_axes = [
        "index_max_items_per_group_per_level",
        "chunk_max_items_per_group_per_level",
        "session_query_index",
        "query_db_id",
    ]
    if leakage_axes != expected_leakage_axes:
        fail("wire contract admittedLeakage drifted from the post-payment PIR projection")

    def ec_int_list(values: list[int]) -> str:
        return "[" + "; ".join(str(value) for value in values) + "]"

    rendered = f"""(* @generated from BitcoinPIR/wire-shape-contract/v1; do not edit. *)
(* contract-sha256: {contract_digest} *)

require import Common Leakage Protocol Protocol_DPF Protocol_Harmony Protocol_Onion.
require import AllCore List Int.

op contract_round_kinds : round_kind list =
  [{'; '.join(easycrypt_round_kinds)}].

op contract_leakage (q : query) : leakage =
  {{| index_max_items_per_group_per_level = query_index_max q;
     chunk_max_items_per_group_per_level = query_chunk_max q;
     session_query_index                 = query_session_query_index q;
     query_db_id                         = query_db_id q; |}}.

lemma contract_index_groups : K = {index_groups}.
proof. by trivial. qed.

lemma contract_chunk_groups : K_chunk = {chunk_groups}.
proof. by trivial. qed.

lemma contract_index_cuckoo_hashes : index_cuckoo_num_hashes = {cuckoo_hashes}.
proof. by trivial. qed.

lemma contract_dpf_server_ids : pir_server_ids BDpf = {ec_int_list(backend_ids['dpf'])}.
proof. exact pir_server_ids_dpf. qed.

lemma contract_harmony_server_ids : pir_server_ids BHarmony = {ec_int_list(backend_ids['harmony'])}.
proof. exact pir_server_ids_harmony. qed.

lemma contract_onion_server_ids : pir_server_ids BOnion = {ec_int_list(backend_ids['onion'])}.
proof. exact pir_server_ids_onion. qed.

lemma contract_round_kind_count : size contract_round_kinds = {len(round_kinds)}.
proof. by trivial. qed.

lemma contract_leakage_matches (q : query) : L q = contract_leakage q.
proof. by rewrite /contract_leakage L_factors. qed.
"""
    return rendered.encode("utf-8")


def verify_contract_manifest_binding(
    contract: dict[str, object],
    contract_digest: str,
    manifest: dict[str, object],
    proof_dir: Path,
) -> None:
    """Bind manifest metadata and a compiled EasyCrypt module to the contract."""
    model = object_field(manifest, "model")
    parameters = object_field(contract, "parameters")
    expected_public_parameters = {
        "index_groups": int_field(parameters, "indexGroups"),
        "chunk_groups": int_field(parameters, "chunkGroups"),
        "index_cuckoo_hashes": int_field(parameters, "indexCuckooHashes"),
    }
    if model.get("public_parameters") != expected_public_parameters:
        fail("proof manifest public parameters do not match the wire contract")
    expected_backends = ["dpf", "harmonypir", "onionpir"]
    if model.get("backends") != expected_backends:
        fail("proof manifest backend list does not match the wire contract")
    if model.get("admitted_leakage") != contract.get("admittedLeakage"):
        fail("proof manifest admitted leakage does not match the wire contract")

    contract_non_claims = string_list_field(contract, "explicitNonClaims")
    manifest_non_claims = manifest.get("explicit_non_claims")
    if not isinstance(manifest_non_claims, list):
        fail("proof manifest explicit_non_claims must be an array")
    manifest_non_claim_ids = [
        item.get("id") if isinstance(item, dict) else None
        for item in manifest_non_claims
    ]
    if manifest_non_claim_ids != contract_non_claims:
        fail("proof manifest explicit non-claims do not match the wire contract")

    binding = object_field(contract, "proofBinding")
    source_path = Path(string_field(binding, "source"))
    if len(source_path.parts) != 1 or source_path.suffix != ".ec":
        fail("wire contract proof binding source must be a root-level .ec file")
    expected_source = render_contract_binding(contract, contract_digest)
    try:
        actual_source = (proof_dir / source_path).read_bytes()
    except OSError as error:
        fail(f"cannot read generated proof binding {source_path}: {error}")
    if actual_source != expected_source:
        fail("generated EasyCrypt contract binding does not match the wire contract")


def git_head(repository: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail(f"cannot read proof checkout HEAD: {result.stderr.strip()}")
    return result.stdout.strip()


def git_tracked_files(repository: Path) -> set[str]:
    result = subprocess.run(
        ["git", "-C", str(repository), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        fail(f"cannot list tracked proof files: {result.stderr.decode(errors='replace').strip()}")
    return {
        path.decode("utf-8")
        for path in result.stdout.split(b"\0")
        if path
    }


def write_github_output(
    path: Path,
    repository: str,
    commit: str,
    run_id: str,
    verifier_mode: str,
    verifier_image: str,
    verifier_source_commit: str,
) -> None:
    try:
        with path.open("a", encoding="utf-8") as output:
            output.write(f"repository={repository}\n")
            output.write(f"commit={commit}\n")
            output.write(f"run_id={run_id}\n")
            output.write(f"verifier_mode={verifier_mode}\n")
            output.write(f"verifier_image={verifier_image}\n")
            output.write(f"verifier_source_commit={verifier_source_commit}\n")
    except OSError as error:
        fail(f"cannot write GitHub output {path}: {error}")


def validate_trusted_verifier(
    trusted_verifier: dict[str, object], verifier_raw: bytes
) -> tuple[str, str, str]:
    """Validate the product-owned verifier and select its safe distribution mode.

    Bootstrap deliberately has no OCI reference: a PR keeps the old local build
    until a separately published, attested image digest has been reviewed into
    this lock.  A pinned distribution is always an immutable GHCR digest.
    """
    require_exact_keys(
        trusted_verifier,
        {
            "schema",
            "dockerfilePath",
            "dockerfileSha256",
            "baseImage",
            "easycryptRepository",
            "easycryptCommit",
            "ocamlVersion",
            "why3Version",
            "altErgoVersion",
            "platform",
            "command",
            "distribution",
        },
        "trustedVerifier",
    )
    if string_field(trusted_verifier, "schema") != TRUSTED_VERIFIER_SCHEMA:
        fail("trusted verifier schema is unsupported")
    verifier_dockerfile = safe_relative_path(trusted_verifier, "dockerfilePath")
    if verifier_dockerfile != TRUSTED_VERIFIER_DOCKERFILE:
        fail(f"trusted verifier Dockerfile must remain {TRUSTED_VERIFIER_DOCKERFILE}")
    expected_verifier_digest = digest_field(trusted_verifier, "dockerfileSha256")
    actual_verifier_digest = sha256(verifier_raw)
    if actual_verifier_digest != expected_verifier_digest:
        fail(
            "trusted verifier Dockerfile digest drifted: "
            f"expected {expected_verifier_digest}, got {actual_verifier_digest}"
        )

    expected_fields = {
        "baseImage": TRUSTED_PROOF_TOOLCHAIN["base_image"],
        "easycryptRepository": TRUSTED_PROOF_TOOLCHAIN["easycrypt_repository"],
        "easycryptCommit": TRUSTED_PROOF_TOOLCHAIN["easycrypt_commit"],
        "ocamlVersion": TRUSTED_PROOF_TOOLCHAIN["ocaml_version"],
        "why3Version": TRUSTED_PROOF_TOOLCHAIN["why3_version"],
        "altErgoVersion": TRUSTED_PROOF_TOOLCHAIN["solvers"][0]["version"],
        "platform": TRUSTED_PROOF_TOOLCHAIN["platform"],
    }
    for field, expected in expected_fields.items():
        if string_field(trusted_verifier, field) != expected:
            fail(f"trusted verifier {field} drifted from the reviewed toolchain")
    if string_list_field(trusted_verifier, "command") != TRUSTED_VERIFIER_COMMAND:
        fail("trusted verifier command drifted from the reviewed EasyCrypt invocation")

    dockerfile = verifier_raw.decode("utf-8", errors="strict")
    for required in [
        f"FROM {expected_fields['baseImage']}",
        f"ARG EASYCRYPT_COMMIT={expected_fields['easycryptCommit']}",
        f"ARG OCAML_VERSION={expected_fields['ocamlVersion']}",
        f"ARG WHY3_VERSION={expected_fields['why3Version']}",
        f"ARG ALT_ERGO_VERSION={expected_fields['altErgoVersion']}",
    ]:
        if required not in dockerfile:
            fail(f"trusted verifier Dockerfile no longer binds {required}")

    distribution = object_field(trusted_verifier, "distribution")
    require_exact_keys(distribution, {"mode", "image", "provenance"}, "trustedVerifier.distribution")
    mode = string_field(distribution, "mode")
    image = distribution.get("image")
    provenance = distribution.get("provenance")
    if mode == "bootstrap":
        if image is not None or provenance is not None:
            fail("bootstrap verifier distribution must not name an unpublished image")
        return mode, "", ""
    if mode != "pinned":
        fail("trusted verifier distribution mode must be bootstrap or pinned")
    if not isinstance(image, str) or not OCI_IMAGE_DIGEST.fullmatch(image):
        fail("pinned verifier image must be the reviewed GHCR immutable sha256 reference")
    provenance_object = object_field(distribution, "provenance")
    require_exact_keys(
        provenance_object,
        {"repository", "workflow", "ref", "commit", "dockerfileSha256"},
        "trustedVerifier.distribution.provenance",
    )
    if string_field(provenance_object, "repository") != TRUSTED_VERIFIER_SOURCE_REPOSITORY:
        fail("pinned verifier provenance repository drifted")
    if string_field(provenance_object, "workflow") != TRUSTED_VERIFIER_PUBLISH_WORKFLOW:
        fail("pinned verifier provenance workflow drifted")
    if string_field(provenance_object, "ref") != TRUSTED_VERIFIER_SOURCE_REF:
        fail("pinned verifier provenance ref must be main")
    source_commit = string_field(provenance_object, "commit")
    if not GIT_COMMIT.fullmatch(source_commit):
        fail("pinned verifier provenance commit must be a full lowercase Git commit")
    if digest_field(provenance_object, "dockerfileSha256") != expected_verifier_digest:
        fail("pinned verifier provenance Dockerfile digest drifted")
    return mode, image, source_commit


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--proof-dir", type=Path)
    parser.add_argument("--github-output", type=Path)
    arguments = parser.parse_args()

    lock_path = arguments.lock.resolve()
    lock, _ = load_json(lock_path, "formal proof lock")
    if lock.get("schema") != "BitcoinPIR/formal-proof-lock/v1":
        fail("unexpected formal proof lock schema")

    proofs = object_field(lock, "protocolProofs")
    repository = string_field(proofs, "repository")
    if repository != "Bitcoin-PIR/protocol-proofs":
        fail(f"unexpected proof repository: {repository}")
    commit = string_field(proofs, "commit")
    if not GIT_COMMIT.fullmatch(commit):
        fail("protocolProofs.commit must be a full lowercase Git commit")
    manifest_path = safe_relative_path(proofs, "manifestPath")
    if manifest_path != PROOF_MANIFEST_PATH:
        fail(f"proof manifest must remain {PROOF_MANIFEST_PATH}")
    expected_manifest_digest = digest_field(proofs, "manifestSha256")
    verification_record_path = safe_relative_path(
        proofs, "verificationRecordPath"
    )
    expected_record_digest = digest_field(proofs, "verificationRecordSha256")
    expected_record_path = (
        Path("verification/records/formal")
        / f"{expected_record_digest}.json"
    )
    if verification_record_path != expected_record_path:
        fail(
            "verificationRecordPath must be content-addressed as "
            f"{expected_record_path}"
        )

    contract_lock = object_field(lock, "implementationContract")
    if string_field(contract_lock, "schema") != "BitcoinPIR/wire-shape-contract/v1":
        fail("unexpected implementation contract schema")
    contract_path = safe_relative_path(contract_lock, "path")
    if contract_path != IMPLEMENTATION_CONTRACT_PATH:
        fail(f"implementation contract must remain {IMPLEMENTATION_CONTRACT_PATH}")
    expected_contract_digest = digest_field(contract_lock, "sha256")
    contract, contract_raw = load_json(ROOT / contract_path, "wire contract")
    if contract.get("schema") != contract_lock["schema"]:
        fail("wire contract schema does not match the lock")
    if int_field(contract, "contractVersion") != 2:
        fail("wire contract must use contractVersion 2 for Payment V1 authorization")
    actual_contract_digest = sha256(contract_raw)
    if actual_contract_digest != expected_contract_digest:
        fail(
            "wire contract digest drifted: "
            f"expected {expected_contract_digest}, got {actual_contract_digest}"
        )

    verification = object_field(lock, "verification")
    if string_field(verification, "command") != "make check":
        fail("proof-repository evidence command must remain make check")

    trusted_verifier = object_field(lock, "trustedVerifier")
    verifier_dockerfile = safe_relative_path(trusted_verifier, "dockerfilePath")
    try:
        verifier_raw = (ROOT / verifier_dockerfile).read_bytes()
    except OSError as error:
        fail(f"cannot read trusted verifier Dockerfile: {error}")
    verifier_mode, verifier_image, verifier_source_commit = validate_trusted_verifier(
        trusted_verifier, verifier_raw
    )

    record, record_raw = load_json(
        ROOT / verification_record_path, "formal proof verification record"
    )
    actual_record_digest = sha256(record_raw)
    if actual_record_digest != expected_record_digest:
        fail(
            "verification record digest drifted: "
            f"expected {expected_record_digest}, got {actual_record_digest}"
        )
    if record.get("schema_version") != 1:
        fail("unexpected verification record schema version")
    if record.get("result") != "passed" or type(record.get("exit_code")) is not int:
        fail("verification record must derive a passed result from an integer exit code")
    if record.get("exit_code") != 0:
        fail("verification record exit code is not zero")
    string_field(record, "result_derivation")
    generated_at = string_field(record, "generated_at")
    if not generated_at.endswith("Z"):
        fail("verification record generated_at must be a UTC timestamp")
    if string_field(record, "repository") != repository:
        fail("verification record repository does not match the lock")
    if string_field(record, "commit") != commit:
        fail("verification record commit does not match the lock")
    run_id = string_field(record, "run_id")
    if not DIGITS.fullmatch(run_id):
        fail("verification record run_id must contain only decimal digits")
    expected_run_url = (
        f"https://github.com/{repository}/actions/runs/{run_id}"
    )
    if string_field(record, "run_url") != expected_run_url:
        fail("verification record run_url does not match repository and run_id")
    if digest_field(record, "manifest_sha256") != expected_manifest_digest:
        fail("verification record manifest digest does not match the lock")
    recorded_sources_digest = digest_field(record, "proof_sources_sha256")
    if string_field(record, "command") != verification["command"]:
        fail("verification record command does not match the lock")
    record_toolchain = object_field(record, "toolchain")
    if record_toolchain != TRUSTED_PROOF_TOOLCHAIN:
        fail("verification record toolchain does not match the trusted toolchain")

    if arguments.github_output:
        write_github_output(
            arguments.github_output,
            repository,
            commit,
            run_id,
            verifier_mode,
            verifier_image,
            verifier_source_commit,
        )

    if arguments.proof_dir:
        proof_dir = arguments.proof_dir.resolve()
        if git_head(proof_dir) != commit:
            fail(f"proof checkout HEAD does not match locked commit {commit}")
        manifest, manifest_raw = load_json(
            proof_dir / manifest_path, "proof manifest"
        )
        actual_manifest_digest = sha256(manifest_raw)
        if actual_manifest_digest != expected_manifest_digest:
            fail(
                "proof manifest digest drifted: "
                f"expected {expected_manifest_digest}, got {actual_manifest_digest}"
            )

        binding = object_field(manifest, "implementation_binding")
        if binding.get("status") != "contract-hash-bound":
            fail("proof manifest is not contract-hash-bound")
        if binding.get("contract_schema") != contract_lock["schema"]:
            fail("proof manifest contract schema does not match the lock")
        if binding.get("contract_path") != contract_path.as_posix():
            fail("proof manifest contract path does not match the lock")
        if binding.get("wire_contract_sha256") != expected_contract_digest:
            fail("proof manifest is bound to a different wire contract")
        if binding.get("generated_source") != "ContractBinding.ec":
            fail("proof manifest does not identify the generated contract binding")

        verify_contract_manifest_binding(
            contract, expected_contract_digest, manifest, proof_dir
        )

        toolchain = object_field(manifest, "toolchain")
        if record_toolchain != toolchain:
            fail("verification record toolchain does not match the proof manifest")
        base_image = string_field(toolchain, "base_image")
        if not re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", base_image):
            fail("proof toolchain base image is not digest-pinned")
        easycrypt_commit = string_field(toolchain, "easycrypt_commit")
        if not GIT_COMMIT.fullmatch(easycrypt_commit):
            fail("EasyCrypt must be pinned to a full commit")
        manifest_verification = object_field(manifest, "verification")
        if manifest_verification.get("command") != verification["command"]:
            fail("proof manifest verification command does not match the lock")
        actual_sources_digest = verify_proof_sources(proof_dir, manifest)
        if recorded_sources_digest != actual_sources_digest:
            fail(
                "verification record proof-source digest does not match the manifest"
            )

    print(
        "formal proof lock check passed: "
        f"{repository}@{commit}, run {run_id}, contract {actual_contract_digest}"
    )


if __name__ == "__main__":
    main()
