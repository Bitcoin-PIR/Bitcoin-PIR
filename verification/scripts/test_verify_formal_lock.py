#!/usr/bin/env python3
"""Focused mutation tests for the formal verifier-distribution lock policy."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "verification/scripts/verify_formal_lock.py"
SPEC = importlib.util.spec_from_file_location("verify_formal_lock", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class TrustedVerifierDistributionTests(unittest.TestCase):
    def setUp(self) -> None:
        lock = json.loads(
            (ROOT / "verification/locks/formal-proofs.json").read_text(encoding="utf-8")
        )
        self.verifier = lock["trustedVerifier"]
        self.dockerfile = (ROOT / "verification/toolchains/easycrypt.Dockerfile").read_bytes()

    def test_bootstrap_keeps_the_local_build_until_a_real_digest_exists(self) -> None:
        self.assertEqual(
            VERIFY.validate_trusted_verifier(self.verifier, self.dockerfile),
            ("bootstrap", "", ""),
        )

    def test_pinned_distribution_requires_an_immutable_ghcr_digest_and_main_provenance(self) -> None:
        verifier = copy.deepcopy(self.verifier)
        verifier["distribution"] = {
            "mode": "pinned",
            "image": "ghcr.io/bitcoin-pir/bitcoinpir-easycrypt-verifier@sha256:" + "a" * 64,
            "provenance": {
                "repository": "Bitcoin-PIR/Bitcoin-PIR",
                "workflow": ".github/workflows/publish-easycrypt-verifier.yml",
                "ref": "refs/heads/main",
                "commit": "b" * 40,
                "dockerfileSha256": verifier["dockerfileSha256"],
            },
        }
        self.assertEqual(
            VERIFY.validate_trusted_verifier(verifier, self.dockerfile),
            ("pinned", verifier["distribution"]["image"], "b" * 40),
        )

    def test_rejects_mutable_image_tag_in_pinned_distribution(self) -> None:
        verifier = copy.deepcopy(self.verifier)
        verifier["distribution"] = {
            "mode": "pinned",
            "image": "ghcr.io/bitcoin-pir/bitcoinpir-easycrypt-verifier:latest",
            "provenance": {
                "repository": "Bitcoin-PIR/Bitcoin-PIR",
                "workflow": ".github/workflows/publish-easycrypt-verifier.yml",
                "ref": "refs/heads/main",
                "commit": "b" * 40,
                "dockerfileSha256": verifier["dockerfileSha256"],
            },
        }
        with self.assertRaises(SystemExit):
            VERIFY.validate_trusted_verifier(verifier, self.dockerfile)

    def test_rejects_bootstrap_placeholder_digest(self) -> None:
        verifier = copy.deepcopy(self.verifier)
        verifier["distribution"]["image"] = (
            "ghcr.io/bitcoin-pir/bitcoinpir-easycrypt-verifier@sha256:" + "a" * 64
        )
        with self.assertRaises(SystemExit):
            VERIFY.validate_trusted_verifier(verifier, self.dockerfile)

    def test_rejects_provenance_that_is_not_the_protected_main_publisher(self) -> None:
        verifier = copy.deepcopy(self.verifier)
        verifier["distribution"] = {
            "mode": "pinned",
            "image": "ghcr.io/bitcoin-pir/bitcoinpir-easycrypt-verifier@sha256:" + "a" * 64,
            "provenance": {
                "repository": "Bitcoin-PIR/Bitcoin-PIR",
                "workflow": ".github/workflows/other.yml",
                "ref": "refs/pull/1/merge",
                "commit": "b" * 40,
                "dockerfileSha256": verifier["dockerfileSha256"],
            },
        }
        with self.assertRaises(SystemExit):
            VERIFY.validate_trusted_verifier(verifier, self.dockerfile)


if __name__ == "__main__":
    unittest.main()
