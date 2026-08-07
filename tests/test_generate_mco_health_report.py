from __future__ import annotations

import sys
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import generate_mco_health_report as mco


class ClassificationTests(unittest.TestCase):
    def test_health_requires_two_green_signals_for_pass(self) -> None:
        self.assertEqual(mco.classify_health("green", "green")[0], "PASS")
        self.assertEqual(mco.classify_health("yellow", "green")[0], "WATCH")
        self.assertEqual(mco.classify_health("green", "unknown")[0], "WATCH")
        self.assertEqual(mco.classify_health("red", "green")[0], "FAIL")

    def test_kv_store_has_explicit_three_state_mapping(self) -> None:
        self.assertEqual(mco.classify_kv_store("ready")[0], "PASS")
        self.assertEqual(mco.classify_kv_store("starting")[0], "WATCH")
        self.assertEqual(mco.classify_kv_store("failed")[0], "FAIL")

    def test_license_warns_on_warning_or_unavailable_message_feed(self) -> None:
        self.assertEqual(mco.classify_license("OK", Counter())[0], "PASS")
        self.assertEqual(
            mco.classify_license("OK", Counter({"WARN": 1}))[0], "WATCH"
        )
        self.assertEqual(
            mco.classify_license("OK", Counter(), "failed")[0], "WATCH"
        )
        self.assertEqual(mco.classify_license("VIOLATION", Counter())[0], "FAIL")

    def test_scheduler_never_passes_skipped_or_failed_execution(self) -> None:
        all_success = {
            "executions": 8,
            "success": 8,
            "skipped": 0,
            "failed": 0,
            "other_status": 0,
        }
        self.assertEqual(mco.classify_scheduler("success", all_success)[0], "PASS")
        self.assertEqual(
            mco.classify_scheduler("success", {**all_success, "skipped": 1})[0],
            "WATCH",
        )
        self.assertEqual(
            mco.classify_scheduler("success", {**all_success, "failed": 1})[0],
            "FAIL",
        )
        self.assertEqual(
            mco.classify_scheduler("success", {**all_success, "executions": 0})[0],
            "WATCH",
        )
        self.assertEqual(
            mco.classify_scheduler("success", {**all_success, "success": 7})[0],
            "WATCH",
        )
        self.assertEqual(mco.classify_scheduler("failed", all_success)[0], "FAIL")

    def test_splunk_boolean_parser_handles_api_strings_and_booleans(self) -> None:
        self.assertTrue(mco.splunk_truthy(True))
        self.assertTrue(mco.splunk_truthy("1"))
        self.assertTrue(mco.splunk_truthy("true"))
        self.assertFalse(mco.splunk_truthy(False))
        self.assertFalse(mco.splunk_truthy("0"))

    def test_queue_and_index_thresholds(self) -> None:
        self.assertEqual(mco.classify_queue_health("success", 0, 0)[0], "WATCH")
        self.assertEqual(mco.classify_queue_health("success", 2, 69.9)[0], "PASS")
        self.assertEqual(mco.classify_queue_health("success", 2, 70)[0], "WATCH")
        self.assertEqual(mco.classify_queue_health("success", 2, 90)[0], "FAIL")
        self.assertEqual(mco.classify_index_capacity(1, 69.9, 0)[0], "PASS")
        self.assertEqual(mco.classify_index_capacity(1, 70, 0)[0], "WATCH")
        self.assertEqual(mco.classify_index_capacity(1, 20, 1)[0], "WATCH")
        self.assertEqual(mco.classify_index_capacity(1, 90, 0)[0], "FAIL")

    def test_overall_status_uses_only_explicit_model(self) -> None:
        self.assertEqual(mco.overall_status([{"status": "PASS"}]), "PASS")
        self.assertEqual(
            mco.overall_status([{"status": "PASS"}, {"status": "WATCH"}]),
            "WATCH",
        )
        self.assertEqual(
            mco.overall_status([{"status": "WATCH"}, {"status": "FAIL"}]),
            "FAIL",
        )
        with self.assertRaises(ValueError):
            mco.overall_status([{"status": "N/A"}])


class PublicOutputTests(unittest.TestCase):
    def test_custom_names_are_anonymized(self) -> None:
        self.assertEqual(mco.public_index_label("main", 0), "main")
        self.assertEqual(mco.public_index_label("customer_alpha", 1), "custom-index-01")
        self.assertEqual(mco.public_queue_label("indexqueue", 0), "indexqueue")
        self.assertEqual(
            mco.public_queue_label("customer_alpha_queue", 1), "custom-queue-01"
        )

    def test_security_scan_rejects_sensitive_or_corrupt_text(self) -> None:
        self.assertIn("private IPv4 address", mco.scan_public_text("host=192.168.1.2"))
        self.assertIn("private IPv4 address", mco.scan_public_text("host=127.0.0.1"))
        self.assertIn("URI or endpoint", mco.scan_public_text("https://internal.invalid"))
        self.assertIn("secret-like assignment", mco.scan_public_text("password=hunter2"))
        self.assertIn(
            "secret-like assignment",
            mco.scan_public_text('{"password": "hunter2"}'),
        )
        self.assertIn(
            "fully qualified host name",
            mco.scan_public_text("splunk-probe.lab.test"),
        )
        self.assertIn(
            "credential or private-key material",
            mco.scan_public_text("Authorization: Bearer abcdefghijklmnop"),
        )
        self.assertIn("mojibake marker", mco.scan_public_report({}, "Ã©"))

    def test_security_scan_accepts_sanitized_french(self) -> None:
        report = {
            "overall_status": "WATCH",
            "checks": [],
            "scheduler": {},
            "index_capacity": [],
            "queues": {"top_queues": []},
            "limitations": ["Instance autonome, preuve ponctuelle."],
            "generated_at": "2026-08-07T00:00:00+00:00",
            "environment": {"version": "9.4.13", "build": "public-build"},
            "verdict": {"summary": "Point à surveiller."},
        }
        rendered = mco.render_html(report, "0" * 64)
        self.assertEqual(mco.scan_public_report(report, rendered), [])
        self.assertIn("État de santé opérationnel", rendered)
        self.assertNotIn("PASS_WITH_WARNINGS", rendered)
        self.assertNotIn("N/A", rendered)


if __name__ == "__main__":
    unittest.main()
