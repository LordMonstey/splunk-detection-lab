from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_parsing_canary_evidence as evidence  # noqa: E402
import build_parsing_canary_packages as packages  # noqa: E402
import assemble_parsing_canary_run as assembler  # noqa: E402
import collect_parsing_canary_phase as collector  # noqa: E402
import ingest_parsing_canary_fixture as ingester  # noqa: E402
import render_parsing_canary_fixture as renderer  # noqa: E402


def digest(character: str) -> str:
    return character * 64


def phase(run_id: str, name: str, *, fields: int = 5, timestamps: int = 5, lag: float = 300.0, digest_char: str) -> dict:
    return {
        "run_id": f"{run_id}-{name}",
        "captured_at": {
            "baseline": "2026-08-07T12:01:00Z",
            "candidate": "2026-08-07T12:02:00Z",
            "rollback": "2026-08-07T12:03:00Z",
        }[name],
        "expected_event_count": 5,
        "observed_event_count": 5,
        "distinct_event_count": 5,
        "required_field_counts": {"user": fields, "src": fields, "action": fields},
        "timestamp_within_tolerance_count": timestamps,
        "duplicate_count": 0,
        "truncated_event_count": 0,
        "p95_index_lag_seconds": lag,
        "aggregate_evidence_sha256": digest(digest_char),
    }


def source_fixture() -> dict:
    run_id = "parsing-20260807T120000Z-abc123"
    baseline_package = {
        "version": "1.0.0",
        "archive_sha256": digest("a"),
        "effective_config_sha256": digest("b"),
    }
    return {
        "schema_version": 1,
        "evidence_kind": "synthetic-offline-test",
        "run_id": run_id,
        "project": {
            "environment_alias": "lab-parsing-canary",
            "topology": "standalone",
            "index_alias": "idx-recette-parsing",
            "sourcetype_alias": "canary-auth",
            "app_id": "splunk_parsing_canary_qualification",
        },
        "change": {
            "started_at": "2026-08-07T12:00:00Z",
            "completed_at": "2026-08-07T12:04:00Z",
            "controlled_failure": True,
            "execution_mode": "canary-recipe-only",
        },
        "packages": {
            "baseline": baseline_package,
            "candidate": {
                "version": "1.1.0-rc1",
                "archive_sha256": digest("c"),
                "effective_config_sha256": digest("d"),
            },
            "rollback": copy.deepcopy(baseline_package),
        },
        "phases": {
            "baseline": phase(run_id, "baseline", lag=300, digest_char="e"),
            "candidate": phase(run_id, "candidate", fields=0, timestamps=0, lag=2, digest_char="f"),
            "rollback": phase(run_id, "rollback", lag=310, digest_char="0"),
        },
    }


class ParsingCanaryPackageTests(unittest.TestCase):
    def test_both_packages_are_deterministic_and_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first = packages.build(Path(first_dir))
            second = packages.build(Path(second_dir))
            for variant in ("baseline", "candidate"):
                first_archive, first_manifest = first[variant]
                second_archive, second_manifest = second[variant]
                self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
                self.assertEqual(first_manifest.read_bytes(), second_manifest.read_bytes())
                manifest = json.loads(first_manifest.read_text(encoding="utf-8"))
                self.assertEqual("idx_recette_parsing", manifest["scope"]["index"])
                self.assertEqual("canary:auth", manifest["scope"]["sourcetype"])
                with tarfile.open(first_archive, "r:gz") as archive:
                    names = {member.name for member in archive.getmembers() if member.isfile()}
                self.assertEqual(
                    {f"{packages.APP_ID}/{name}" for name in packages.REQUIRED_MEMBERS},
                    names,
                )
            candidate_manifest = json.loads(first["candidate"][1].read_text(encoding="utf-8"))
            self.assertFalse(candidate_manifest["promotion_eligible"])
            self.assertEqual("controlled-no-go", candidate_manifest["intended_outcome"])

    def test_candidate_diff_boundary_is_exact(self) -> None:
        baseline = packages.validate_variant("baseline")
        candidate = packages.validate_variant("candidate")
        packages.validate_variant_boundary(baseline, candidate)
        changed = {
            name for name in packages.REQUIRED_MEMBERS if baseline[name].read_bytes() != candidate[name].read_bytes()
        }
        self.assertEqual(packages.ALLOWED_VARIANT_DIFFS, changed)
        for variant_files in (baseline, candidate):
            props_text = variant_files["default/props.conf"].read_text(encoding="utf-8")
            self.assertIn("KV_MODE = none", props_text)

    def test_fixture_renderer_emits_only_synthetic_documentation_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "phase.log"
            rendered, manifest_path = renderer.render(
                "parsing-20260807T120000Z-abc123-baseline",
                "baseline",
                output,
                300,
            )
            lines = rendered.read_text(encoding="utf-8").splitlines()
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(5, len(lines))
        self.assertTrue(all("192.0.2." in line for line in lines))
        self.assertTrue(all(line.endswith("end_marker=CANARY_END") for line in lines))
        self.assertFalse(manifest["raw_events_in_manifest"])
        self.assertEqual(hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest(), manifest["payload_sha256"])


class ParsingCanaryEvidenceTests(unittest.TestCase):
    def build(self, source: dict) -> dict:
        raw = json.dumps(source, sort_keys=True)
        return evidence.build_evidence(source, raw, allow_synthetic=True)

    def test_pass_no_go_pass_sequence_and_parity(self) -> None:
        output = self.build(source_fixture())
        self.assertEqual("PASS", output["phases"]["baseline"]["gate"])
        self.assertEqual("NO-GO", output["phases"]["candidate"]["gate"])
        self.assertIn("required_field_coverage", output["phases"]["candidate"]["failed_checks"])
        self.assertIn("timestamp_conformance", output["phases"]["candidate"]["failed_checks"])
        self.assertEqual("PASS", output["phases"]["rollback"]["gate"])
        self.assertEqual("RESTORED", output["rollback_parity"]["status"])
        self.assertTrue(all(output["rollback_parity"]["checks"].values()))
        self.assertTrue(output["public_redaction"]["raw_events_excluded"])

    def test_cli_contract_rejects_synthetic_claim(self) -> None:
        source = source_fixture()
        with self.assertRaises(evidence.EvidenceError):
            evidence.build_evidence(source, json.dumps(source, sort_keys=True))

    def test_candidate_that_passes_is_rejected(self) -> None:
        source = source_fixture()
        source["phases"]["candidate"] = phase(
            source["run_id"], "candidate", lag=300, digest_char="f"
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "candidate must trigger"):
            self.build(source)

    def test_rollback_artifact_drift_is_rejected(self) -> None:
        source = source_fixture()
        source["packages"]["rollback"]["archive_sha256"] = digest("9")
        with self.assertRaisesRegex(evidence.EvidenceError, "exact baseline artifact"):
            self.build(source)

    def test_rollback_metric_drift_is_rejected(self) -> None:
        source = source_fixture()
        source["phases"]["rollback"]["required_field_counts"]["src"] = 4
        with self.assertRaisesRegex(evidence.EvidenceError, "rollback phase must pass"):
            self.build(source)

    def test_private_address_and_secret_like_text_are_rejected(self) -> None:
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_privacy("host=192.168.10.7")
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_privacy("password=example")

    def test_public_schema_is_valid_json_and_live_only(self) -> None:
        schema = json.loads(
            (ROOT / "artifacts" / "templates" / "parsing-canary-evidence.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual("live-isolated-lab", schema["properties"]["evidence_kind"]["const"])
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("rollback_parity", schema["required"])

    def test_published_live_evidence_is_canonical_sanitized_and_closed(self) -> None:
        path = ROOT / "artifacts" / "public" / "parsing-canary-rollback-evidence-20260807.json"
        raw = path.read_text(encoding="utf-8")
        published = json.loads(raw)
        schema = json.loads(
            (ROOT / "artifacts" / "templates" / "parsing-canary-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        evidence.validate_privacy(raw)
        self.assertEqual(path.name, path.name.lower())
        self.assertEqual(set(schema["required"]), set(published))
        self.assertEqual("live-isolated-lab", published["evidence_kind"])
        self.assertEqual("PASS", published["phases"]["baseline"]["gate"])
        self.assertEqual("NO-GO", published["phases"]["candidate"]["gate"])
        self.assertEqual("PASS", published["phases"]["rollback"]["gate"])
        self.assertEqual("RESTORED", published["rollback_parity"]["status"])
        self.assertEqual(published["packages"]["baseline"], published["packages"]["rollback"])
        self.assertTrue(all(published["public_redaction"].values()))

    def test_publication_paths_are_fail_closed(self) -> None:
        public_path = ROOT / "artifacts" / "public" / "parsing-canary-proof.json"
        private_path = ROOT / "artifacts" / "private" / "parsing-canary" / "assembled.json"
        self.assertEqual(public_path.resolve(), evidence.validate_public_output(public_path))
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_public_output(private_path)
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_private_input(public_path)


class ParsingCanaryCollectorTests(unittest.TestCase):
    def test_search_is_strictly_scoped_and_aggregate_only(self) -> None:
        search = collector.build_search("parsing-20260807T120000Z-abc123", "baseline")
        self.assertIn("index=idx_recette_parsing", search)
        self.assertIn('sourcetype="canary:auth"', search)
        self.assertIn('canary_run_id="parsing-20260807T120000Z-abc123-baseline"', search)
        self.assertIn('replace(expected_event_time, "Z", "+0000")', search)
        self.assertIn('%Y-%m-%dT%H:%M:%S%z', search)
        self.assertNotIn('%Y-%m-%dT%H:%M:%SZ', search)
        self.assertIn("| stats", search)
        self.assertNotIn("| table _raw", search)

    def test_normalizer_excludes_raw_fields(self) -> None:
        aggregate = {
            "observed_event_count": "5",
            "distinct_event_count": "5",
            "user_present_count": "5",
            "src_present_count": "5",
            "action_present_count": "5",
            "timestamp_within_tolerance_count": "5",
            "duplicate_count": "0",
            "truncated_event_count": "0",
            "p95_index_lag_seconds": "301.2",
        }
        normalized = collector.normalize_phase(
            "parsing-20260807T120000Z-abc123", "baseline", aggregate
        )
        self.assertEqual(5, normalized["required_field_counts"]["src"])
        self.assertNotIn("_raw", normalized)
        self.assertRegex(normalized["aggregate_evidence_sha256"], r"^[a-f0-9]{64}$")

    def test_management_url_requires_verified_https_shape(self) -> None:
        self.assertEqual(
            "https://splunk.example.invalid:8089",
            collector.validate_management_url("https://splunk.example.invalid:8089/"),
        )
        for unsafe in (
            "http://splunk.example.invalid:8089",
            "https://user:pass@splunk.example.invalid:8089",
            "https://splunk.example.invalid:8089/services",
        ):
            with self.subTest(url=unsafe), self.assertRaises(collector.CollectionError):
                collector.validate_management_url(unsafe)

    def test_output_is_forced_under_private_artifacts(self) -> None:
        accepted = ROOT / "artifacts" / "private" / "parsing-canary" / "baseline.json"
        self.assertEqual(accepted.resolve(), collector.validate_private_output(accepted))
        with self.assertRaises(collector.CollectionError):
            collector.validate_private_output(ROOT / "artifacts" / "public" / "unsafe.json")

    def test_collector_has_no_tls_bypass_or_password_argument(self) -> None:
        source = (ROOT / "scripts" / "collect_parsing_canary_phase.py").read_text(encoding="utf-8")
        self.assertNotIn("_create_unverified_context", source)
        self.assertNotIn('add_argument("--password"', source)
        self.assertIn("ssl.create_default_context", source)


class ParsingCanaryAssemblyTests(unittest.TestCase):
    def test_assembler_requires_effective_rollback_parity(self) -> None:
        run_id = "parsing-20260807T120000Z-abc123"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            built = packages.build(root / "build")
            phase_paths = {}
            for name, digest_char in zip(("baseline", "candidate", "rollback"), ("e", "f", "0")):
                payload = phase(
                    run_id,
                    name,
                    fields=0 if name == "candidate" else 5,
                    timestamps=0 if name == "candidate" else 5,
                    lag=2 if name == "candidate" else 300,
                    digest_char=digest_char,
                )
                path = root / f"{name}.json"
                path.write_text(json.dumps(payload), encoding="utf-8")
                phase_paths[name] = path

            baseline_effective = (
                "[canary:auth]\nTIME_PREFIX = event_time\n"
                "[canary_control_fields]\nREGEX = control\n"
                "[canary_auth_fields]\nREGEX = src\n"
            )
            candidate_effective = baseline_effective.replace("event_time", "occurred_at").replace("src", "source_ip")
            effective_paths = {}
            for name, content in {
                "baseline": baseline_effective,
                "candidate": candidate_effective,
                "rollback": baseline_effective,
            }.items():
                path = root / f"{name}.effective.txt"
                path.write_text(content, encoding="utf-8")
                effective_paths[name] = path

            assembled = assembler.assemble(
                run_id,
                "2026-08-07T12:00:00Z",
                "2026-08-07T12:04:00Z",
                built["baseline"][1],
                built["candidate"][1],
                phase_paths,
                effective_paths,
            )
            self.assertEqual(
                assembled["packages"]["baseline"],
                assembled["packages"]["rollback"],
            )
            effective_paths["rollback"].write_text(candidate_effective, encoding="utf-8")
            with self.assertRaisesRegex(assembler.AssemblyError, "differs from baseline"):
                assembler.assemble(
                    run_id,
                    "2026-08-07T12:00:00Z",
                    "2026-08-07T12:04:00Z",
                    built["baseline"][1],
                    built["candidate"][1],
                    phase_paths,
                    effective_paths,
                )


class ParsingCanaryIngestTests(unittest.TestCase):
    def test_rendered_fixture_passes_strict_ingest_preflight(self) -> None:
        run_id = "parsing-20260807T120000Z-abc123-baseline"
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "baseline.log"
            renderer.render(run_id, "baseline", fixture, 300)
            payload, count, payload_sha = ingester.validate_fixture(fixture, run_id)
        self.assertEqual(5, count)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), payload_sha)

    def test_ingest_preflight_rejects_scope_and_fixture_drift(self) -> None:
        run_id = "parsing-20260807T120000Z-abc123-baseline"
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "baseline.log"
            renderer.render(run_id, "baseline", fixture, 300)
            drifted = fixture.read_text(encoding="utf-8").replace("192.0.2.10", "10.1.2.3")
            fixture.write_text(drifted, encoding="utf-8", newline="\n")
            with self.assertRaises(ingester.IngestError):
                ingester.validate_fixture(fixture, run_id)

    def test_raw_fixture_paths_are_forced_under_private_artifacts(self) -> None:
        accepted = ROOT / "artifacts" / "private" / "parsing-canary" / "baseline.log"
        self.assertEqual(accepted.resolve(), renderer.validate_private_output(accepted))
        with self.assertRaises(ValueError):
            renderer.validate_private_output(ROOT / "artifacts" / "public" / "raw.log")
        with self.assertRaises(ingester.IngestError):
            ingester.validate_private_fixture(ROOT / "datasets" / "parsing-canary" / "canary-auth.template.log")

    def test_ingester_uses_verified_tls_and_has_no_password_argument(self) -> None:
        source = (ROOT / "scripts" / "ingest_parsing_canary_fixture.py").read_text(encoding="utf-8")
        self.assertIn("ssl.create_default_context", source)
        self.assertNotIn("_create_unverified_context", source)
        self.assertNotIn('add_argument("--password"', source)
        self.assertIn('"index": "idx_recette_parsing"', source)
        self.assertIn('"sourcetype": "canary:auth"', source)


if __name__ == "__main__":
    unittest.main()
