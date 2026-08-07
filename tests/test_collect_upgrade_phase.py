#!/usr/bin/env python3
"""Offline tests for the upgrade phase collector; no VM or network is used."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import collect_upgrade_phase as collector  # noqa: E402
import build_upgrade_live_evidence as evidence_builder  # noqa: E402
import validate_upgrade_evidence as evidence_validator  # noqa: E402


FIXED_NOW = datetime(2026, 8, 7, 12, 0, 0, tzinfo=timezone.utc)


class FakeResponse:
    status = 200

    def __init__(self, body: bytes = b"<html>dashboard</html>") -> None:
        self.body = body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def read(self, _size: int = -1) -> bytes:
        return self.body


class FakeClient:
    def __init__(self) -> None:
        self.base_url = "https://splunk-lab.example.invalid:8089"
        self.headers = {"Authorization": "Basic private", "X-Splunk-Form-Key": "private"}
        self.opener = object()
        self.searches: list[str] = []

    def _open(self, _request: object, *, timeout: int) -> FakeResponse:
        if timeout <= 0:
            raise AssertionError("invalid timeout")
        return FakeResponse()

    def get(self, path: str, **_params: object):
        if path == "/services/server/info":
            return {
                "entry": [
                    {
                        "content": {
                            "version": "9.4.13",
                            "build": "deadbeef1234",
                            "kvStoreStatus": "ready",
                            "licenseState": "OK",
                        }
                    }
                ]
            }
        if path == "/services/apps/local":
            return {
                "entry": [
                    {"name": "search", "content": {"disabled": False}},
                    {
                        "name": collector.DEFAULT_APP,
                        "content": {"disabled": False},
                    },
                ]
            }
        if path == "/services/saved/searches":
            return {
                "entry": [
                    {
                        "name": collector.DEFAULT_SAVED_SEARCH,
                        "content": {"is_scheduled": True, "disabled": False},
                    },
                    {
                        "name": "disabled_probe",
                        "content": {"is_scheduled": True, "disabled": True},
                    },
                ]
            }
        if path == "/services/kvstore/status":
            return {"entry": [{"content": {"current": {"status": "ready"}}}]}
        if path == (
            f"/servicesNS/nobody/{collector.DEFAULT_APP}/storage/collections/config"
        ):
            return {"entry": [{"name": collector.DEFAULT_COLLECTION, "content": {}}]}
        if path == "/services/licenser/messages":
            return {"entry": []}
        if path == "/services/server/health/splunkd":
            return {"entry": [{"content": {"health": "green"}}]}
        if path == "/services/authentication/current-context":
            return {
                "entry": [
                    {
                        "name": "admin",
                        "content": {"username": "admin", "roles": ["admin"]},
                    }
                ]
            }
        if path.endswith("/history"):
            return {
                "entry": [
                    {
                        "published": collector.utc_z(FIXED_NOW),
                        "content": {
                            "isDone": True,
                            "isFailed": False,
                            "dispatchState": "DONE",
                        },
                    }
                ]
            }
        if "/storage/collections/data/" in path:
            return [{"_key": "private-checkpoint", "expected_value": "ready"}]
        if "/data/ui/views/" in path:
            return {
                "entry": [
                    {
                        "content": {
                            "eai:data": (
                                '<dashboard version="1.1"><row><panel><single>'
                                "<search><query>| makeresults</query></search>"
                                "</single></panel></row></dashboard>"
                            )
                        }
                    }
                ]
            }
        raise AssertionError(f"unexpected GET path: {path}")

    def run_search_job(self, search: str):
        self.searches.append(search)
        result: dict[str, str]
        if "fatal_count" in search:
            result = {"fatal_count": "0"}
        elif "skipped_count" in search:
            result = {"skipped_count": "0"}
        elif "qualification_control_id" in search:
            result = {
                "matched_count": "1",
                "latest_epoch": str(FIXED_NOW.timestamp()),
            }
        elif "savedsearch_name" in search:
            result = {
                "execution_count": "1",
                "success_count": "1",
                "bad_count": "0",
                "latest_epoch": str(FIXED_NOW.timestamp()),
            }
        else:
            result = {"probe_count": "1"}
        return {
            "sid": "private-sid-never-persisted",
            "metrics": {
                "isDone": True,
                "isFailed": False,
                "dispatchState": "DONE",
            },
            "results": [result],
            "messages": [],
        }


def make_attestation(path: Path, *, status: str = "passed") -> None:
    path.write_text(
        json.dumps(
            {
                "kind": "splunk-btool-check",
                "status": status,
                "exit_code": 0,
                "blocking_error_count": 0,
                "captured_at": collector.utc_z(FIXED_NOW),
            }
        ),
        encoding="utf-8",
    )


def make_config(attestation: Path, *, transport: str = "management") -> collector.CollectorConfig:
    return collector.CollectorConfig(
        phase="pre_upgrade",
        transport=transport,
        username="admin",
        custom_apps=(collector.DEFAULT_APP,),
        scheduled_search_owner="nobody",
        scheduled_search_app=collector.DEFAULT_APP,
        scheduled_search_name=collector.DEFAULT_SAVED_SEARCH,
        scheduler_lookback_minutes=10,
        control_index="qualification",
        control_field="qualification_control_id",
        control_event_id="private-control-id",
        freshness_sla_seconds=900,
        kv_owner="nobody",
        kv_app=collector.DEFAULT_APP,
        kv_collection=collector.DEFAULT_COLLECTION,
        kv_checkpoint_key="private-checkpoint",
        kv_expected_field="expected_value",
        kv_expected_value="ready",
        dashboard_owner="nobody",
        dashboard_app=collector.DEFAULT_APP,
        dashboard_view=collector.DEFAULT_DASHBOARD,
        configuration_attestation=attestation,
        configuration_attestation_max_age_seconds=3600,
        health_lookback_minutes=15,
    )


def hashes() -> dict[str, str]:
    return {
        name: hashlib.sha256(name.encode("ascii")).hexdigest()
        for name in collector.HASH_ARGUMENTS
    }


class UpgradePhaseCollectorTests(unittest.TestCase):
    def test_tls_requires_https_ca_and_dns_hostname(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            ca = Path(folder) / "ca.pem"
            ca.write_text("test-ca", encoding="utf-8")
            collector.validate_tls_endpoint("https://splunk.example.invalid:8089", ca)
            with self.assertRaises(ValueError):
                collector.validate_tls_endpoint("http://splunk.example.invalid:8089", ca)
            with self.assertRaises(ValueError):
                collector.validate_tls_endpoint("https://192.168.1.10:8089", ca)
            with self.assertRaises(ValueError):
                collector.validate_tls_endpoint("https://splunk.example.invalid:8089/path", ca)
            with self.assertRaises(ValueError):
                collector.validate_tls_endpoint(
                    "https://splunk.example.invalid:8089", Path(folder) / "missing.pem"
                )

    def test_connect_ip_is_strict_and_never_changes_tls_hostname(self) -> None:
        self.assertEqual("192.0.2.189", collector.validate_connect_ip("192.0.2.189"))
        self.assertEqual("2001:db8::1", collector.validate_connect_ip("2001:db8::1"))
        self.assertIsNone(collector.validate_connect_ip(None))
        for invalid in ("", " 192.0.2.189", "192.0.002.189", "splunk.example.invalid"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    collector.validate_connect_ip(invalid)

    def test_pinned_resolver_targets_one_hostname_and_restores_on_exception(self) -> None:
        calls: list[tuple[object, object]] = []

        def original(host: object, port: object, *_args: object, **_kwargs: object):
            calls.append((host, port))
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (str(host), port))]

        with patch.object(socket, "getaddrinfo", original):
            saved = socket.getaddrinfo
            with self.assertRaisesRegex(RuntimeError, "probe failed"):
                with collector.pinned_resolver(
                    "splunk-probe.lab.test", "192.0.2.189"
                ):
                    socket.getaddrinfo("splunk-probe.lab.test", 8089)
                    socket.getaddrinfo("unrelated.example.invalid", 443)
                    self.assertIsNot(socket.getaddrinfo, saved)
                    raise RuntimeError("probe failed")
            self.assertIs(socket.getaddrinfo, saved)
        self.assertEqual(
            [("192.0.2.189", 8089), ("unrelated.example.invalid", 443)],
            calls,
        )

    def test_hash_inputs_use_nonempty_private_files_only(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            paths: dict[str, Path] = {}
            for index, name in enumerate(collector.HASH_ARGUMENTS, start=1):
                path = root / f"private-{index}.bin"
                path.write_bytes(f"private-input-{index}".encode("ascii"))
                paths[name] = path
            output = collector.hash_inputs(paths)
            self.assertEqual(set(collector.HASH_ARGUMENTS), set(output))
            self.assertTrue(all(collector.SHA256.fullmatch(value) for value in output.values()))
            empty = root / "empty.bin"
            empty.touch()
            with self.assertRaises(ValueError):
                collector.hash_private_input(empty)

    def test_configuration_attestation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "btool.json"
            make_attestation(path)
            passed = collector.load_configuration_attestation(
                path, now=FIXED_NOW, max_age_seconds=3600
            )
            self.assertTrue(passed.passed)
            make_attestation(path, status="failed")
            failed = collector.load_configuration_attestation(
                path, now=FIXED_NOW, max_age_seconds=3600
            )
            self.assertFalse(failed.passed)
            missing = collector.load_configuration_attestation(
                Path(folder) / "missing.json", now=FIXED_NOW, max_age_seconds=3600
            )
            self.assertFalse(missing.passed)

    def test_probe_exception_never_becomes_pass(self) -> None:
        clock = iter((10.0, 10.015))

        def explode() -> collector.ProbeOutcome:
            raise URLError("private endpoint detail")

        result = collector.smoke_result("authentication", explode, monotonic=lambda: next(clock))
        self.assertEqual("failed", result["status"])
        self.assertEqual(15, result["duration_ms"])
        self.assertNotIn("private endpoint detail", json.dumps(result))

    def test_full_phase_contains_exactly_eight_real_passes_and_no_sensitive_data(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            attestation = Path(folder) / "btool.json"
            make_attestation(attestation)
            phase_collector = collector.UpgradePhaseCollector(
                FakeClient(),
                make_config(attestation),
                hashes(),
                now=lambda: FIXED_NOW,
            )
            fragment = phase_collector.collect()
            tests = fragment["phase"]["smoke_tests"]
            self.assertEqual(list(collector.REQUIRED_SMOKE_TESTS), [item["id"] for item in tests])
            self.assertTrue(all(item["status"] == "passed" for item in tests))
            self.assertTrue(fragment["collection_control"]["phase_ready"])
            self.assertEqual(1, fragment["sequence"])
            sanitized = evidence_builder.sanitize_phase_capture(
                fragment, "pre_upgrade", 1
            )
            schema = json.loads(
                (ROOT / "artifacts/templates/upgrade-evidence.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                [],
                evidence_validator.validate_schema_node(
                    sanitized, schema["$defs"]["phase"], schema
                ),
            )
            self.assertEqual([], collector.sensitive_output_findings(fragment))
            rendered = json.dumps(fragment, sort_keys=True)
            self.assertNotIn("private-control-id", rendered)
            self.assertNotIn("private-checkpoint", rendered)
            self.assertNotIn("private-sid", rendered)
            self.assertNotIn("makeresults", rendered)
            self.assertNotIn("splunk-lab.example.invalid", rendered)

    def test_scheduled_search_fails_when_history_and_scheduler_signal_are_absent(self) -> None:
        class MissingSchedulerClient(FakeClient):
            def get(self, path: str, **params: object):
                if path.endswith("/history"):
                    return {"entry": []}
                return super().get(path, **params)

            def run_search_job(self, search: str):
                job = super().run_search_job(search)
                if "savedsearch_name" in search:
                    job["results"] = [
                        {
                            "execution_count": "0",
                            "success_count": "0",
                            "bad_count": "0",
                            "latest_epoch": "0",
                        }
                    ]
                return job

        with tempfile.TemporaryDirectory() as folder:
            attestation = Path(folder) / "btool.json"
            make_attestation(attestation)
            phase_collector = collector.UpgradePhaseCollector(
                MissingSchedulerClient(),
                make_config(attestation),
                hashes(),
                now=lambda: FIXED_NOW,
            )
            outcome = phase_collector._probe_scheduled_search()
            self.assertFalse(outcome.passed)

    def test_scheduled_search_accepts_recent_success_before_running_dispatch(self) -> None:
        class RunningLatestClient(FakeClient):
            def get(self, path: str, **params: object):
                if path.endswith("/history"):
                    return {
                        "entry": [
                            {
                                "published": collector.utc_z(FIXED_NOW),
                                "content": {
                                    "isDone": False,
                                    "isFailed": False,
                                    "dispatchState": "RUNNING",
                                },
                            },
                            {
                                "published": collector.utc_z(
                                    FIXED_NOW - timedelta(minutes=1)
                                ),
                                "content": {
                                    "isDone": True,
                                    "isFailed": False,
                                    "dispatchState": "DONE",
                                },
                            },
                            {
                                "published": collector.utc_z(
                                    FIXED_NOW - timedelta(minutes=2)
                                ),
                                "content": {
                                    "isDone": True,
                                    "isFailed": True,
                                    "dispatchState": "FAILED",
                                },
                            },
                        ]
                    }
                return super().get(path, **params)

            def run_search_job(self, search: str):
                if "savedsearch_name" in search:
                    raise AssertionError("history success must not require scheduler fallback")
                return super().run_search_job(search)

        with tempfile.TemporaryDirectory() as folder:
            attestation = Path(folder) / "btool.json"
            make_attestation(attestation)
            phase_collector = collector.UpgradePhaseCollector(
                RunningLatestClient(),
                make_config(attestation),
                hashes(),
                now=lambda: FIXED_NOW,
            )
            outcome = phase_collector._probe_scheduled_search()
            self.assertTrue(outcome.passed)

    def test_freshness_requires_the_identified_control_event(self) -> None:
        class MissingControlEventClient(FakeClient):
            def run_search_job(self, search: str):
                job = super().run_search_job(search)
                if "qualification_control_id" in search:
                    job["results"] = [{"matched_count": "0", "latest_epoch": "0"}]
                return job

        with tempfile.TemporaryDirectory() as folder:
            attestation = Path(folder) / "btool.json"
            make_attestation(attestation)
            phase_collector = collector.UpgradePhaseCollector(
                MissingControlEventClient(),
                make_config(attestation),
                hashes(),
                now=lambda: FIXED_NOW,
            )
            outcome = phase_collector._probe_ingestion_freshness()
            self.assertFalse(outcome.passed)

    def test_web_transport_requires_the_dashboard_page_and_rest_definition(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            attestation = Path(folder) / "btool.json"
            make_attestation(attestation)
            phase_collector = collector.UpgradePhaseCollector(
                FakeClient(),
                make_config(attestation, transport="web"),
                hashes(),
                now=lambda: FIXED_NOW,
            )
            self.assertTrue(phase_collector._probe_dashboard().passed)

    def test_sensitive_scanner_rejects_endpoint_sid_query_and_secret(self) -> None:
        samples = (
            {"uri": "redacted"},
            {"detail": "https://splunk.example.invalid"},
            {"detail": "host=192.168.10.4"},
            {"detail": "host=203.0.113.7"},
            {"detail": "host=2001:db8::7"},
            {"sid": "123"},
            {"query": "search index=main"},
            {"detail": "password=example"},
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(collector.sensitive_output_findings(sample))

    def test_disconnected_fragment_has_no_fabricated_pass(self) -> None:
        fragment = collector.disconnected_fragment(
            "pre_upgrade", "management", hashes(), captured_at=FIXED_NOW
        )
        self.assertFalse(fragment["collection_control"]["phase_ready"])
        self.assertTrue(
            all(item["status"] == "failed" for item in fragment["phase"]["smoke_tests"])
        )
        self.assertEqual([], collector.sensitive_output_findings(fragment))

    def test_main_pops_environment_password_and_clears_client_headers(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ca = root / "ca.pem"
            ca.write_text("mocked-ca", encoding="utf-8")
            attestation = root / "btool.json"
            make_attestation(attestation)
            inputs = []
            for index in range(4):
                path = root / f"private-{index}.json"
                path.write_text(f"private-{index}", encoding="utf-8")
                inputs.append(path)
            output = root / "phase.json"
            fake = FakeClient()
            argv = [
                "--phase",
                "pre_upgrade",
                "--uri",
                "https://splunk.example.invalid:8089",
                "--ca-bundle",
                str(ca),
                "--connect-ip",
                "192.0.2.189",
                "--output",
                str(output),
                "--control-index",
                "qualification",
                "--control-event-id",
                "private-control-id",
                "--kv-checkpoint-key",
                "private-checkpoint",
                "--kv-expected-value",
                "ready",
                "--configuration-attestation",
                str(attestation),
                "--managed-configuration-manifest",
                str(inputs[0]),
                "--custom-apps-manifest",
                str(inputs[1]),
                "--saved-searches-export",
                str(inputs[2]),
                "--kv-store-export",
                str(inputs[3]),
            ]
            os.environ["SPLUNK_PASSWORD"] = "not-persisted"
            original_collector = collector.UpgradePhaseCollector
            with patch.object(collector, "SplunkAudit", return_value=fake):
                with patch.object(
                    collector,
                    "UpgradePhaseCollector",
                    side_effect=lambda client, config, input_hashes: original_collector(
                        client,
                        config,
                        input_hashes,
                        now=lambda: FIXED_NOW,
                    ),
                ):
                    result = collector.main(argv)
            self.assertEqual(0, result)
            self.assertNotIn("SPLUNK_PASSWORD", os.environ)
            self.assertNotIn("Authorization", fake.headers)
            self.assertNotIn("X-Splunk-Form-Key", fake.headers)
            self.assertIsNone(fake.opener)
            persisted = output.read_text(encoding="utf-8")
            self.assertNotIn("not-persisted", persisted)
            self.assertNotIn("private-control-id", persisted)
            self.assertNotIn("192.0.2.189", persisted)


if __name__ == "__main__":
    unittest.main()
