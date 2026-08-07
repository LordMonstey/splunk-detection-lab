import configparser
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import qualify_custom_datamodel_live as qualification  # noqa: E402


MODEL_PATH = (
    ROOT
    / "conf"
    / "splunk"
    / "default"
    / "data"
    / "models"
    / "Security_Telemetry_Qualification.json"
)
EVENTTYPES_PATH = ROOT / "conf" / "splunk" / "default" / "eventtypes.conf"


def definition():
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def eventtype_searches():
    parser = configparser.RawConfigParser(interpolation=None)
    parser.read(EVENTTYPES_PATH, encoding="utf-8")
    return {section: parser.get(section, "search") for section in parser.sections()}


def full_acceptance():
    return qualification.build_acceptance(
        server_version="10.2.1",
        app_version="0.7.3",
        health="green",
        kv_status="ready",
        definition_checks={"a": True, "b": True},
        acl={
            "sharing": "global",
            "perms": {"read": ["*"], "write": ["admin"]},
        },
        acceleration={
            "enabled": True,
            "earliest_time": "-7d",
            "allow_old_summaries": False,
        },
        summary={
            "complete": True,
            "in_progress": False,
            "last_error_present": False,
            "bucket_count": 1,
        },
        raw_count=3,
        summary_count=3,
        latest_delta_seconds=0,
        freshness_age_seconds=12,
        freshness_sla_seconds=900,
        cim_installed=False,
        es_installed=False,
    )


class CustomDataModelQualificationTests(unittest.TestCase):
    def test_public_writer_rejects_a_failed_gate_without_writing(self):
        report = {"overall_pass": False, "security": {"credentials_written": False}}
        qualification.PUBLIC_EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=qualification.PUBLIC_EVIDENCE_ROOT) as temp_dir:
            output = Path(temp_dir) / "failed.json"
            with self.assertRaisesRegex(ValueError, "not publishable"):
                qualification.write_public_evidence(report, output)
            self.assertFalse(output.exists())

    def test_publication_path_is_restricted_to_json_under_public_artifacts(self):
        accepted = qualification.PUBLIC_EVIDENCE_ROOT / "custom-model.json"
        self.assertTrue(qualification.is_public_evidence_path(accepted))
        self.assertFalse(
            qualification.is_public_evidence_path(ROOT / "artifacts" / "private" / "model.json")
        )
        self.assertFalse(
            qualification.is_public_evidence_path(
                qualification.PUBLIC_EVIDENCE_ROOT / "custom-model.txt"
            )
        )

    def test_summary_status_refreshes_details_in_the_exact_app_namespace(self):
        class SummaryClient:
            def __init__(self):
                self.calls = []

            def get(self, path, **params):
                self.calls.append((path, params))
                if path.endswith("/details"):
                    return {"entry": []}
                return {"entry": [{"content": {"summary.complete": 1}}]}

        client = SummaryClient()
        summary = qualification.get_summary(client)
        self.assertEqual(1, summary["summary.complete"])
        self.assertEqual(
            f"{qualification.SUMMARY_PATH}/details",
            client.calls[0][0],
        )
        self.assertEqual({"count": 0}, client.calls[0][1])
        self.assertIn("/servicesNS/nobody/splunk-detection-lab/", qualification.SUMMARY_PATH)

    def test_linux_eventtypes_are_safe_for_native_acceleration(self):
        searches = eventtype_searches()
        derived_field_predicate = re.compile(r"\b(?:action|status)\s*(?:=|IN\b)", re.I)
        for eventtype in (
            "linux_authentication",
            "linux_account_change",
            "linux_privileged_endpoint_change",
        ):
            with self.subTest(eventtype=eventtype):
                self.assertNotRegex(searches[eventtype], derived_field_predicate)
        self.assertIn("app=sshd", searches["linux_authentication"])
        self.assertIn('app="useradd"', searches["linux_account_change"])
        self.assertIn('app="sudo"', searches["linux_privileged_endpoint_change"])

    def test_repository_model_has_the_exact_custom_contract(self):
        profile, checks = qualification.model_contract(definition())
        self.assertTrue(all(checks.values()), checks)
        self.assertEqual(7, profile["dataset_count"])
        self.assertEqual(16, profile["root_field_count"])
        self.assertEqual(20, profile["eventtype_dependency_count"])
        self.assertEqual(7, profile["tag_dependency_count"])
        self.assertRegex(profile["definition_sha256"], qualification.SHA256)
        self.assertRegex(profile["root_constraint_sha256"], qualification.SHA256)

    def test_non_cim_boundary_is_fail_closed(self):
        model = definition()
        model["description"] = "Generic security telemetry"
        _, checks = qualification.model_contract(model)
        self.assertFalse(checks["non_cim_boundary_explicit"])

    def test_constraint_pipeline_is_rejected(self):
        model = definition()
        model["objects"][0]["constraints"][0]["search"] += " | head 1"
        _, checks = qualification.model_contract(model)
        self.assertFalse(checks["root_constraint_is_streaming_event_constraint"])

    def test_acceleration_contract_is_typed(self):
        parsed = qualification.acceleration_contract(
            json.dumps(
                {
                    "enabled": True,
                    "earliest_time": "-7d",
                    "cron_schedule": "*/5 * * * *",
                    "max_time": 600,
                    "allow_old_summaries": False,
                    "schedule_priority": "default",
                }
            )
        )
        self.assertTrue(parsed["enabled"])
        self.assertEqual(600, parsed["max_time_seconds"])
        self.assertFalse(parsed["allow_old_summaries"])

    def test_summary_contract_does_not_expose_sid_or_error_text(self):
        parsed = qualification.summary_contract(
            {
                "summary.complete": 1,
                "summary.is_inprogress": False,
                "summary.buckets": 2,
                "summary.size": 512,
                "summary.time_range": 604800,
                "summary.latest_run_duration": 1.25,
                "summary.last_error": "",
                "summary.last_sid": "private-sid",
            }
        )
        self.assertTrue(parsed["complete"])
        self.assertEqual(2, parsed["bucket_count"])
        self.assertNotIn("sid", json.dumps(parsed).lower())
        self.assertNotIn("private-sid", json.dumps(parsed))

    def test_acceptance_requires_an_honest_custom_boundary(self):
        accepted = full_acceptance()
        self.assertTrue(all(accepted.values()), accepted)
        rejected = qualification.build_acceptance(
            server_version="10.2.1",
            app_version="0.7.3",
            health="green",
            kv_status="ready",
            definition_checks={"definition": True},
            acl={
                "sharing": "global",
                "perms": {"read": ["*"], "write": ["admin"]},
            },
            acceleration={
                "enabled": True,
                "earliest_time": "-7d",
                "allow_old_summaries": False,
            },
            summary={
                "complete": True,
                "in_progress": False,
                "last_error_present": False,
                "bucket_count": 1,
            },
            raw_count=1,
            summary_count=1,
            latest_delta_seconds=0,
            freshness_age_seconds=1,
            freshness_sla_seconds=900,
            cim_installed=True,
            es_installed=False,
        )
        self.assertFalse(rejected["custom_non_cim_boundary_honest"])

    def test_public_scanner_accepts_aggregate_only_evidence(self):
        sample = {
            "classification": {"claim_boundary": "custom non-CIM qualification only"},
            "data_quality": {"raw_event_count": 1, "summary_event_count": 1},
            "security": {"raw_events_persisted": False},
        }
        self.assertEqual([], qualification.sensitive_findings(sample))

    def test_public_scanner_rejects_endpoints_raw_data_and_search_text(self):
        samples = (
            {"detail": "192.168.1.5"},
            {"detail": "https://example.invalid"},
            {"raw": "event"},
            {"search": "index=private"},
            {"detail": "password=example"},
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(qualification.sensitive_findings(sample))

    def test_canonical_hash_is_order_independent(self):
        first = qualification.canonical_hash({"a": 1, "b": 2})
        second = qualification.canonical_hash({"b": 2, "a": 1})
        self.assertEqual(first, second)
        self.assertRegex(first, qualification.SHA256)


if __name__ == "__main__":
    unittest.main()
