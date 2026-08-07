#!/usr/bin/env python3
"""Regression tests for the offline-only MCO drill harness."""

from __future__ import annotations

import ast
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_mco_drills as drills  # noqa: E402


class McoDrillHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture, _ = drills.load_fixture(drills.DEFAULT_FIXTURE)

    def test_all_synthetic_scenarios_pass(self) -> None:
        results = [drills.run_scenario(case) for case in self.fixture["scenarios"]]
        self.assertEqual(set(drills.EVALUATORS), {result["id"] for result in results})
        self.assertTrue(all(result["passed"] for result in results))
        self.assertTrue(all(result["before"]["state"] == "CRITICAL" for result in results))
        self.assertTrue(all(result["after"]["state"] == "HEALTHY" for result in results))

    def test_runbooks_meet_structure_and_security_contract(self) -> None:
        self.assertEqual([], drills.validate_runbooks())

    def test_fixture_rejects_network_permission(self) -> None:
        unsafe = copy.deepcopy(self.fixture)
        unsafe["controls"]["network_access_allowed"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.json"
            path.write_text(json.dumps(unsafe), encoding="utf-8")
            with self.assertRaises(drills.DrillError):
                drills.load_fixture(path)

    def test_fixture_rejects_live_target(self) -> None:
        unsafe = copy.deepcopy(self.fixture)
        unsafe["provenance"]["live_target"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.json"
            path.write_text(json.dumps(unsafe), encoding="utf-8")
            with self.assertRaises(drills.DrillError):
                drills.load_fixture(path)

    def test_fixture_rejects_private_address(self) -> None:
        unsafe = copy.deepcopy(self.fixture)
        unsafe["provenance"]["description"] = "synthetic target 192.168.50.7"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.json"
            path.write_text(json.dumps(unsafe), encoding="utf-8")
            with self.assertRaises(drills.DrillError):
                drills.load_fixture(path)

    def test_forbidden_patterns_detect_unsafe_examples(self) -> None:
        samples = {
            "TLS verification disabled": "curl -k https://example.invalid",
            "literal RFC1918 address": "target=192.168.50.7",
            "secret assignment": "token=not-a-real-value",
            "destructive REST delete": "curl --request DELETE https://example.invalid",
            "recursive deletion": "rm -rf /var/tmp/example",
            "Splunk data cleanup": "splunk clean eventdata",
            "search-time deletion": "search index=example | delete",
        }
        for label, sample in samples.items():
            with self.subTest(label=label):
                self.assertIsNotNone(drills.FORBIDDEN_PATTERNS[label].search(sample))

    def test_harness_has_no_network_or_process_import(self) -> None:
        tree = ast.parse((ROOT / "scripts" / "run_mco_drills.py").read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue({"socket", "subprocess", "urllib", "http", "requests", "httpx"}.isdisjoint(imported))


if __name__ == "__main__":
    unittest.main()
