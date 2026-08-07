#!/usr/bin/env python3
"""Offline tests for the periodic MCO/CIM reporting contract."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import validate_periodic_reporting as validator  # noqa: E402


class PeriodicReportingValidationTests(unittest.TestCase):
    def copy_contract(self, target: Path) -> None:
        shutil.copytree(ROOT / "conf" / "splunk", target / "conf" / "splunk")
        templates = target / "artifacts" / "templates"
        templates.mkdir(parents=True)
        shutil.copy2(
            ROOT / "artifacts" / "templates" / "periodic-reporting-row.schema.json",
            templates / "periodic-reporting-row.schema.json",
        )

    def test_repository_contract_passes(self) -> None:
        errors, evidence = validator.validate_repository(ROOT)
        self.assertEqual(errors, [])
        self.assertEqual(evidence["status"], "PASS")
        self.assertTrue(all(evidence["checks"].values()))

    def test_offline_evidence_does_not_claim_live_history(self) -> None:
        _errors, evidence = validator.validate_repository(ROOT)
        self.assertEqual(evidence["live_execution"], "NOT_PERFORMED")
        self.assertEqual(evidence["historical_periods_observed"], 0)
        self.assertFalse(evidence["trend_claimed"])
        canonical = json.dumps(evidence, sort_keys=True)
        self.assertNotRegex(canonical, r"192\.168\.|https://(?!example\.invalid)")

    def test_endpoint_scanner_requires_a_complete_private_ipv4(self) -> None:
        safe_values = (
            '"generated_at": "2026-08-07T16:10:11.123456+00:00"',
            '"version": "10.2.1"',
            '"sha256": "10.127.192.168-fragment"',
            '"uri": "https://example.invalid/path"',
        )
        for value in safe_values:
            with self.subTest(value=value):
                self.assertIsNone(validator.SECRET_OR_ENDPOINT.search(value))

        private_values = (
            '"host": "10.2.1.7"',
            '"host": "127.0.0.1"',
            '"host": "172.31.255.254"',
            '"host": "192.168.1.10"',
        )
        for value in private_values:
            with self.subTest(value=value):
                self.assertIsNotNone(validator.SECRET_OR_ENDPOINT.search(value))

    def test_keyed_upsert_is_mandatory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            self.copy_contract(target)
            path = target / "conf" / "splunk" / "local" / "savedsearches.conf"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "outputlookup append=true key_field=_key mco_cim_periodic_history",
                    "outputlookup mco_cim_periodic_history",
                    1,
                ),
                encoding="utf-8",
            )
            errors, _evidence = validator.validate_repository(target)
        self.assertTrue(any("keyed upsert" in error for error in errors))

    def test_each_trend_panel_requires_two_periods(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            self.copy_contract(target)
            path = (
                target
                / "conf"
                / "splunk"
                / "local"
                / "data"
                / "ui"
                / "views"
                / "periodic_mco_cim_reporting.xml"
            )
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "where periods&gt;=2", "where periods&gt;=1", 1
                ),
                encoding="utf-8",
            )
            errors, _evidence = validator.validate_repository(target)
        self.assertTrue(any("trend panel" in error for error in errors))

    def test_schema_rejects_identifying_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            self.copy_contract(target)
            path = (
                target
                / "artifacts"
                / "templates"
                / "periodic-reporting-row.schema.json"
            )
            schema = json.loads(path.read_text(encoding="utf-8"))
            schema["properties"]["host"] = {"type": "string"}
            path.write_text(json.dumps(schema), encoding="utf-8")
            errors, _evidence = validator.validate_repository(target)
        self.assertTrue(any("properties" in error for error in errors))
        self.assertTrue(any("forbidden" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
