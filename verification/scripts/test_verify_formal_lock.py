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

    def test_current_pinned_distribution_uses_the_published_attested_verifier(self) -> None:
        self.assertEqual(
            VERIFY.validate_trusted_verifier(self.verifier, self.dockerfile),
            (
                "pinned",
                "ghcr.io/bitcoin-pir/bitcoinpir-easycrypt-verifier@sha256:"
                "bc174b56c1e59cfa3e8e0385fcf2dbc3332a1e433d99a59992562e56284b2d48",
                "aab4e4ccf65a94969be34b65ab0f23c2623ee5a6",
            ),
        )

    def test_bootstrap_remains_an_explicit_local_build_rollback(self) -> None:
        verifier = copy.deepcopy(self.verifier)
        verifier["distribution"] = {
            "mode": "bootstrap",
            "image": None,
            "provenance": None,
        }
        self.assertEqual(
            VERIFY.validate_trusted_verifier(verifier, self.dockerfile),
            ("bootstrap", "", ""),
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
        verifier["distribution"] = {
            "mode": "bootstrap",
            "image": "ghcr.io/bitcoin-pir/bitcoinpir-easycrypt-verifier@sha256:" + "a" * 64,
            "provenance": None,
        }
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
