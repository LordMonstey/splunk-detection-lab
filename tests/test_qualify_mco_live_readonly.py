#!/usr/bin/env python3
"""Tests for the non-mutating Splunk MCO live qualification gate."""

from __future__ import annotations

import ast
import copy
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import qualify_mco_live_readonly as live  # noqa: E402


def feed(content: dict, name: str = "entry") -> dict:
    return {"entry": [{"name": name, "content": content}]}


class LiveReadOnlyQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.server_info = {
            "version": "10.2.1",
            "build": "build-placeholder",
            "product_type": "enterprise",
            "licenseState": "OK",
            "kvStoreStatus": "ready",
        }
        self.health_kv = live.observe_health_and_kv(
            self.server_info,
            feed({"health": "green"}),
        )
        self.license = live.observe_license(
            feed({"quota": 1000, "peers_usage_bytes": 100}),
            {"entry": [{"content": {"severity": "WARN"}}]},
            self.server_info,
            90.0,
        )
        self.scheduler = live.observe_scheduler(
            {"entry": [{"content": {"is_scheduled": True, "disabled": False, "next_scheduled_time": now}}]}
        )
        self.capacity = live.observe_capacity_and_freshness(
            {
                "entry": [
                    {
                        "name": "public-example",
                        "content": {
                            "currentDBSizeMB": 10,
                            "maxTotalDataSizeMB": 1000,
                            "totalEventCount": 50,
                            "maxTime": now,
                        },
                    },
                    {"name": "_internal", "content": {"totalEventCount": 100}},
                ]
            },
            {
                "freshest_event_age_seconds": 60,
                "stalest_event_age_seconds": 120,
                "observed_index_count": 1,
                "future_clock_anomaly_count": 0,
            },
            80.0,
            86400,
        )
        self.certificate = {
            "protocol": "TLSv1.2",
            "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "days_remaining": 365,
            "dns_sans": [live.EXPECTED_FQDN],
            "sha256_fingerprint": "a" * 64,
            "chain_verified": True,
            "hostname_verified": True,
        }

    def build_safe_artifact(self, ca_bundle: Path) -> dict:
        return live.build_artifact(
            live.EXPECTED_FQDN,
            self.server_info,
            list(live.ALLOWED_ENDPOINTS),
            self.certificate,
            self.health_kv,
            self.license,
            self.scheduler,
            self.capacity,
            ca_bundle,
            True,
        )

    def test_synthetic_observations_pass_public_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.pem"
            ca.write_bytes(b"public-ca-placeholder")
            artifact = self.build_safe_artifact(ca)
            self.assertEqual("PASS", artifact["status"])
            self.assertTrue(artifact["proof_boundary"]["live_observation"])
            self.assertFalse(artifact["proof_boundary"]["proves_incident_remediation"])
            live.assert_public_safe(artifact)

    def test_public_writer_refuses_failed_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.pem"
            ca.write_bytes(b"public-ca-placeholder")
            artifact = self.build_safe_artifact(ca)
            artifact["status"] = "FAIL"
            output = Path(directory) / "public.json"
            with self.assertRaises(live.QualificationError):
                live.write_public_artifact(artifact, output)
            self.assertFalse(output.exists())

    def test_public_writer_uses_sanitized_pass_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.pem"
            ca.write_bytes(b"public-ca-placeholder")
            artifact = self.build_safe_artifact(ca)
            output = Path(directory) / "public.json"
            live.write_public_artifact(artifact, output)
            self.assertTrue(output.is_file())
            self.assertFalse(output.with_suffix(".json.tmp").exists())

    def test_sanitizer_rejects_private_address(self) -> None:
        with self.assertRaises(live.QualificationError):
            live.assert_public_safe({"detail": "route 192.168.50.7"})

    def test_sanitizer_rejects_non_lab_hostname(self) -> None:
        with self.assertRaises(live.QualificationError):
            live.assert_public_safe({"fqdn": "internal.example.com"})

    def test_sanitizer_rejects_secret_key(self) -> None:
        with self.assertRaises(live.QualificationError):
            live.assert_public_safe({"token": "redacted"})

    def test_read_only_client_rejects_unknown_endpoint(self) -> None:
        client = live.ReadOnlySplunkClient.__new__(live.ReadOnlySplunkClient)
        client.observed_endpoints = []
        with self.assertRaises(live.QualificationError):
            client.get("/services/configs/conf-server")

    def test_source_contains_no_mutating_client_call(self) -> None:
        source = (ROOT / "scripts" / "qualify_mco_live_readonly.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"post", "post_bytes", "delete", "run_search_job"}:
                    forbidden.append(node.func.attr)
        self.assertEqual([], forbidden)

    def test_capacity_output_never_contains_index_names(self) -> None:
        self.assertNotIn("public-example", repr(self.capacity))
        self.assertFalse(self.capacity["index_names_included"])

    def test_failed_control_prevents_global_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.pem"
            ca.write_bytes(b"public-ca-placeholder")
            failed_capacity = copy.deepcopy(self.capacity)
            failed_capacity["status"] = "FAIL"
            artifact = live.build_artifact(
                live.EXPECTED_FQDN,
                self.server_info,
                list(live.ALLOWED_ENDPOINTS),
                self.certificate,
                self.health_kv,
                self.license,
                self.scheduler,
                failed_capacity,
                ca,
                True,
            )
            self.assertEqual("FAIL", artifact["status"])

    def test_failure_summary_excludes_names_and_routes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.pem"
            ca.write_bytes(b"public-ca-placeholder")
            artifact = self.build_safe_artifact(ca)
            artifact["controls"]["scheduler"]["status"] = "FAIL"
            summary = live.safe_failure_summary(artifact, ["scheduler"])
            self.assertIn("scheduled_count", summary)
            self.assertNotIn("public-example", summary)
            live.assert_public_safe(summary)

    def test_scheduler_without_scheduled_objects_is_not_applicable(self) -> None:
        observation = live.observe_scheduler({"entry": []})
        self.assertEqual("NOT_APPLICABLE", observation["status"])
        self.assertEqual("OBSERVED", observation["disposition"])

    def test_not_applicable_control_is_published_with_limitations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.pem"
            ca.write_bytes(b"public-ca-placeholder")
            scheduler = live.observe_scheduler({"entry": []})
            artifact = live.build_artifact(
                live.EXPECTED_FQDN,
                self.server_info,
                list(live.ALLOWED_ENDPOINTS),
                self.certificate,
                self.health_kv,
                self.license,
                scheduler,
                self.capacity,
                ca,
                True,
            )
            self.assertEqual("PASS_WITH_LIMITATIONS", artifact["status"])
            output = Path(directory) / "public.json"
            live.write_public_artifact(artifact, output)
            self.assertTrue(output.is_file())

    def test_unknown_control_blocks_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.pem"
            ca.write_bytes(b"public-ca-placeholder")
            artifact = self.build_safe_artifact(ca)
            artifact["status"] = "INCOMPLETE"
            artifact["controls"]["capacity_and_freshness"]["status"] = "UNKNOWN"
            output = Path(directory) / "public.json"
            with self.assertRaises(live.QualificationError):
                live.write_public_artifact(artifact, output)
            self.assertFalse(output.exists())

    def test_freshness_search_is_aggregate_and_non_mutating(self) -> None:
        self.assertIn("| tstats", live.FRESHNESS_AGGREGATE_SEARCH)
        self.assertIn("| stats", live.FRESHNESS_AGGREGATE_SEARCH)
        self.assertNotRegex(
            live.FRESHNESS_AGGREGATE_SEARCH,
            r"(?i)\b(?:collect|delete|outputlookup|sendalert|script)\b",
        )

    def test_only_one_post_exists_and_it_targets_export(self) -> None:
        source = (ROOT / "scripts" / "qualify_mco_live_readonly.py").read_text(encoding="utf-8")
        self.assertEqual(1, source.count('method="POST"'))
        self.assertEqual("/services/search/jobs/export", live.READ_ONLY_EXPORT_ENDPOINT)
        self.assertTrue(live.READ_ONLY_EXPORT_ENDPOINT.endswith("/export"))
        self.assertNotIn("{sid}", live.READ_ONLY_EXPORT_ENDPOINT)


if __name__ == "__main__":
    unittest.main()
