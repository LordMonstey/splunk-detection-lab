#!/usr/bin/env python3
"""Offline tests for the final live-upgrade evidence builder."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_upgrade_live_evidence as builder  # noqa: E402
import validate_upgrade_evidence as validator  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def smoke_tests(phase: str) -> list[dict[str, Any]]:
    return [
        {
            "id": test_id,
            "status": "passed",
            "duration_ms": 10 + index,
            "evidence_sha256": digest(f"{phase}:{test_id}"),
            "private_output": "sid=scheduler__fixture and _raw={fixture}",
        }
        for index, test_id in enumerate(sorted(validator.REQUIRED_SMOKE_TESTS))
    ]


def phase_capture(
    name: str,
    sequence: int,
    captured_at: str,
    version: str,
    build: str,
    inventory_label: str,
    hash_label: str,
) -> dict[str, Any]:
    installed = 15 if inventory_label == "baseline" else 16
    phase = {
        "captured_at": captured_at,
        "version": version,
        "build": build,
        "health": {
            "status": "green",
            "splunkd_status": "running",
            "searchable": True,
            "fatal_error_count": 0,
            "skipped_search_count": 0,
            "private_endpoint": "https://splunk-node.private.local:8089",
        },
        "inventory": {
            "installed_app_count": installed,
            "custom_app_count": 3,
            "saved_search_count": 42,
            "enabled_saved_search_count": 18,
            "private_app_names": ["do-not-publish"],
        },
        "kv_store": {"status": "ready", "collection_count": 4},
        "license": {"state": "OK", "violation_count": 0},
        "hashes": {
            field: digest(f"{hash_label}:{field}") for field in sorted(validator.HASH_FIELDS)
        },
        "smoke_tests": smoke_tests(name),
        "raw_events": [{"_raw": "fixture event that must never be copied"}],
    }
    return {
        "phase_name": name,
        "sequence": sequence,
        "phase": phase,
        "private_auth": "password=fixture-only",
    }


def valid_inputs() -> dict[str, Any]:
    phases = {
        "pre_upgrade": phase_capture(
            "pre_upgrade", 1, "2026-08-07T00:02:00Z", "9.4.13", "build9413", "baseline", "v9"
        ),
        "post_upgrade": phase_capture(
            "post_upgrade", 2, "2026-08-07T00:03:00Z", "10.2.1", "build1021", "target", "v10"
        ),
        "rollback": phase_capture(
            "rollback", 3, "2026-08-07T00:04:00Z", "9.4.13", "build9413", "baseline", "v9"
        ),
        "final": phase_capture(
            "final", 4, "2026-08-07T00:05:00Z", "10.2.1", "build1021", "target", "v10"
        ),
    }
    backup = {
        "backup": {
            "captured_at": "2026-08-07T00:01:00Z",
            "restore_tested_at": "2026-08-07T00:04:30Z",
            "snapshot_alias": "snapshot-baseline-20260807",
            "snapshot_metadata_sha256": digest("snapshot metadata"),
            "configuration_archive_sha256": digest("configuration archive"),
            "custom_apps_archive_sha256": digest("custom apps archive"),
            "kv_store_archive_sha256": digest("kv store archive"),
            "manifest_sha256": digest("backup manifest"),
            "restore_test_status": "verified",
            "private_storage": "192.168.10.20",
        }
    }
    chronology = {
        "run_id": "upgrade-20260807T000000Z-abc123",
        "project": {
            "source_version": "9.4.13",
            "target_version": "10.2.1",
            "topology": "standalone",
            "environment_alias": "lab-upgrade-main",
            "host_os": "Debian GNU/Linux 13",
            "os_evidence_boundary": "lab-method-validation-not-vendor-support-certification",
            "enterprise_security_layer": {
                "status": "not-installed",
                "version_before": None,
                "version_after": None,
                "compatibility_matrix_checked": False,
            },
            "private_hostname": "splunk-node.private.local",
        },
        "change": {
            "started_at": "2026-08-07T00:00:00Z",
            "completed_at": "2026-08-07T00:06:00Z",
            "execution_mode": "live-lab",
            "upgrade_strategy": "in-place-upgrade-with-restorable-baseline",
            "rollback_method": "snapshot-and-backup-restoration",
            "direct_path_checked_against_vendor_documentation": True,
            "compatibility_matrix_reviewed": True,
        },
        "decisions": {
            "pre_upgrade": {
                "decision": "GO",
                "reason": "Baseline healthy and qualified for the controlled upgrade",
            },
            "post_upgrade": {
                "decision": "GO-ROLLBACK-DRILL",
                "reason": "Target passed every gate before the restoration drill",
            },
            "rollback": {
                "decision": "GO-FINAL-UPGRADE",
                "reason": "Restored baseline matched its inventories and manifests",
            },
            "final": {
                "decision": "CLOSE",
                "reason": "Final target reproduced the qualified post upgrade state",
            },
        },
    }
    return {"phases": phases, "backup": backup, "chronology": chronology}


class UpgradeEvidenceBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output = self.root / "artifacts" / "public" / "upgrade-evidence-20260807.json"
        self.schema = ROOT / "artifacts" / "templates" / "upgrade-evidence.schema.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_inputs(self, data: dict[str, Any]) -> dict[str, Path]:
        paths: dict[str, Path] = {}
        private_dir = self.root / "artifacts" / "private" / "upgrade"
        private_dir.mkdir(parents=True, exist_ok=True)
        for name, capture in data["phases"].items():
            path = private_dir / f"{name}.json"
            path.write_text(json.dumps(capture), encoding="utf-8")
            paths[name] = path
        for name in ("backup", "chronology"):
            path = private_dir / f"{name}.json"
            path.write_text(json.dumps(data[name]), encoding="utf-8")
            paths[name] = path
        return paths

    def execute(self, data: dict[str, Any]) -> dict[str, Any]:
        paths = self.write_inputs(data)
        return builder.build_and_write(
            pre_upgrade=paths["pre_upgrade"],
            post_upgrade=paths["post_upgrade"],
            rollback=paths["rollback"],
            final=paths["final"],
            backup=paths["backup"],
            chronology=paths["chronology"],
            output=self.output,
            schema_path=self.schema,
        )

    def assert_rejected(self, mutate: Callable[[dict[str, Any]], None]) -> None:
        data = valid_inputs()
        mutate(data)
        with self.assertRaises(builder.EvidenceBuildError):
            self.execute(data)
        self.assertFalse(self.output.exists(), "a failed gate must not create public evidence")

    def test_builds_schema_valid_atomic_public_evidence(self) -> None:
        evidence = self.execute(valid_inputs())
        self.assertTrue(self.output.is_file())
        on_disk = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(evidence, on_disk)

        schema = json.loads(self.schema.read_text(encoding="utf-8"))
        self.assertEqual([], validator.validate_schema_node(on_disk, schema, schema))
        self.assertTrue(all(item["status"] == "passed" for item in validator.semantic_checks(on_disk)))

        serialized = json.dumps(on_disk)
        for forbidden in (
            "192.168.10.20",
            "splunk-node.private.local",
            "password=fixture-only",
            "fixture event that must never be copied",
            "scheduler__fixture",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual([], builder.public_safety_findings(on_disk))
        for phase in validator.REQUIRED_PHASES:
            self.assertEqual(8, len(on_disk["phases"][phase]["smoke_tests"]))

    def test_rejects_phase_identity_version_order_and_decision_drift(self) -> None:
        mutations = (
            lambda data: data["phases"]["pre_upgrade"].update(phase_name="rollback"),
            lambda data: data["phases"]["post_upgrade"].update(sequence=4),
            lambda data: data["phases"]["final"]["phase"].update(version="10.2.0"),
            lambda data: data["phases"]["rollback"]["phase"].update(
                captured_at="2026-08-07T00:02:30Z"
            ),
            lambda data: data["chronology"]["decisions"]["final"].update(decision="NO-GO"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assert_rejected(mutate)

    def test_rejects_inventory_and_hash_restoration_drift(self) -> None:
        mutations = (
            lambda data: data["phases"]["rollback"]["phase"]["inventory"].update(
                saved_search_count=41
            ),
            lambda data: data["phases"]["final"]["phase"]["hashes"].update(
                kv_store_export_sha256=digest("drifted final kv")
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assert_rejected(mutate)

    def test_rejects_placeholder_hashes_and_incoherent_backup_timeline(self) -> None:
        def placeholder_hash(data: dict[str, Any]) -> None:
            field = "managed_configuration_manifest_sha256"
            data["phases"]["pre_upgrade"]["phase"]["hashes"][field] = "a" * 64
            data["phases"]["rollback"]["phase"]["hashes"][field] = "a" * 64

        mutations = (
            placeholder_hash,
            lambda data: data["backup"]["backup"].update(
                captured_at="2026-08-07T00:02:30Z"
            ),
            lambda data: data["backup"]["backup"].update(
                restore_tested_at="2026-08-07T00:03:30Z"
            ),
            lambda data: data["chronology"]["change"].update(
                direct_path_checked_against_vendor_documentation=False
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assert_rejected(mutate)

    def test_rejects_incomplete_duplicate_or_failed_smoke_tests(self) -> None:
        def remove_test(data: dict[str, Any]) -> None:
            data["phases"]["pre_upgrade"]["phase"]["smoke_tests"].pop()

        def duplicate_test(data: dict[str, Any]) -> None:
            tests = data["phases"]["post_upgrade"]["phase"]["smoke_tests"]
            tests[-1]["id"] = tests[0]["id"]

        def fail_test(data: dict[str, Any]) -> None:
            data["phases"]["final"]["phase"]["smoke_tests"][0]["status"] = "failed"

        for mutate in (remove_test, duplicate_test, fail_test):
            with self.subTest(mutate=mutate):
                self.assert_rejected(mutate)

    def test_rejects_non_green_health_kv_store_and_license(self) -> None:
        mutations = (
            lambda data: data["phases"]["pre_upgrade"]["phase"]["health"].update(status="yellow"),
            lambda data: data["phases"]["post_upgrade"]["phase"]["kv_store"].update(
                status="degraded"
            ),
            lambda data: data["phases"]["rollback"]["phase"]["license"].update(state="WARN"),
            lambda data: data["phases"]["final"]["phase"]["license"].update(
                violation_count=1
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assert_rejected(mutate)

    def test_rejects_es_claim_and_os_boundary_expansion(self) -> None:
        def claim_es(data: dict[str, Any]) -> None:
            data["chronology"]["project"]["enterprise_security_layer"] = {
                "status": "installed-and-validated",
                "version_before": "8.0",
                "version_after": "8.1",
                "compatibility_matrix_checked": True,
            }

        mutations = (
            claim_es,
            lambda data: data["chronology"]["project"].update(host_os="Debian GNU/Linux 12"),
            lambda data: data["chronology"]["project"].update(
                os_evidence_boundary="vendor-supported-production-platform"
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assert_rejected(mutate)

    def test_rejects_sensitive_values_in_public_free_text(self) -> None:
        forbidden_reasons = (
            "Decision recorded for 203.0.113.10 after all gates passed",
            "Decision recorded on search-node.corp.example after all gates passed",
            "Decision recorded with password=TopSecret after all gates passed",
            "Decision recorded with _raw={event} after all gates passed",
            "Decision recorded with sid=scheduler__admin__search__name after all gates passed",
        )
        for reason in forbidden_reasons:
            with self.subTest(reason=reason):
                self.assert_rejected(
                    lambda data, reason=reason: data["chronology"]["decisions"]["final"].update(
                        reason=reason
                    )
                )

    def test_rejects_output_outside_artifacts_public(self) -> None:
        data = valid_inputs()
        paths = self.write_inputs(data)
        wrong_output = self.root / "upgrade-evidence-20260807.json"
        with self.assertRaises(builder.EvidenceBuildError):
            builder.build_and_write(
                pre_upgrade=paths["pre_upgrade"],
                post_upgrade=paths["post_upgrade"],
                rollback=paths["rollback"],
                final=paths["final"],
                backup=paths["backup"],
                chronology=paths["chronology"],
                output=wrong_output,
                schema_path=self.schema,
            )
        self.assertFalse(wrong_output.exists())


if __name__ == "__main__":
    unittest.main()
