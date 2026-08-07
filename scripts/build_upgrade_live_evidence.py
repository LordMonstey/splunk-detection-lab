#!/usr/bin/env python3
"""Build public upgrade evidence from private live captures.

The builder consumes six JSON inputs: four phase captures, one backup record,
and one chronology/change record.  Phase captures must use this private wrapper::

    {
      "phase_name": "pre_upgrade",
      "sequence": 1,
      "phase": { ... fields from the public phase schema ... }
    }

Private inputs may contain additional diagnostic fields.  Only schema-backed,
aggregate fields are copied to the public artifact; raw events and identifiers
are never copied.  No timestamps, observations, hashes, or decisions are
invented by this program.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from validate_upgrade_evidence import (  # noqa: E402
    EXPECTED_DECISIONS,
    EXPECTED_VERSIONS,
    HASH_FIELDS,
    REQUIRED_PHASES,
    REQUIRED_SMOKE_TESTS,
    ROLLBACK_INVENTORY_FIELDS,
    schema_contract_errors,
    semantic_checks,
    validate_schema_node,
)


DEFAULT_SCHEMA = SCRIPT_DIR.parent / "artifacts" / "templates" / "upgrade-evidence.schema.json"
MAX_INPUT_BYTES = 16 * 1024 * 1024
OUTPUT_NAME = re.compile(r"^upgrade-evidence-[a-z0-9][a-z0-9-]{2,80}\.json$")
FQDN = re.compile(
    r"(?i)(?<![a-z0-9_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|local|lan|internal|home|test)(?![a-z0-9_-])"
)
CREDENTIAL = re.compile(
    r"(?i)(?:\b(?:password|passwd|secret|token|session_key|api_key|credential)"
    r"\s*[:=]\s*\S+|\bauthorization\s+(?:basic|bearer|splunk)\s+\S+|"
    r"\bsplunk\s+[a-z0-9+/=_-]{8,})"
)
RAW_EVENT = re.compile(
    r"(?i)(?:\b_raw\s*[:=]|\braw[_ -]?events?\s*[:=]|"
    r"\bevent\s*[:=]\s*[\[{])"
)
SID = re.compile(
    r"(?i)(?:\bS-\d-\d+(?:-\d+){1,}\b|"
    r"\b(?:sid|search_id|session_id)\s*[:=]\s*\S+|"
    r"\bscheduler__(?:[a-z0-9_-]+__){2,}[a-z0-9_.-]+|"
    r"\brt_[a-z0-9._-]{6,})"
)
IP_TOKEN = re.compile(r"(?<![0-9a-f:.%])[0-9a-f:.%]{3,}(?![0-9a-f:.%])", re.I)

PHASE_FIELDS = (
    "captured_at",
    "version",
    "build",
    "health",
    "inventory",
    "kv_store",
    "license",
    "hashes",
    "smoke_tests",
)
HEALTH_FIELDS = (
    "status",
    "splunkd_status",
    "searchable",
    "fatal_error_count",
    "skipped_search_count",
)
INVENTORY_FIELDS = tuple(sorted(ROLLBACK_INVENTORY_FIELDS))
KV_STORE_FIELDS = ("status", "collection_count")
LICENSE_FIELDS = ("state", "violation_count")
SMOKE_FIELDS = ("id", "status", "duration_ms", "evidence_sha256")
BACKUP_FIELDS = (
    "captured_at",
    "restore_tested_at",
    "snapshot_alias",
    "snapshot_metadata_sha256",
    "configuration_archive_sha256",
    "custom_apps_archive_sha256",
    "kv_store_archive_sha256",
    "manifest_sha256",
    "restore_test_status",
)
PROJECT_FIELDS = (
    "source_version",
    "target_version",
    "topology",
    "environment_alias",
    "host_os",
    "os_evidence_boundary",
    "enterprise_security_layer",
)
CHANGE_FIELDS = (
    "started_at",
    "completed_at",
    "execution_mode",
    "upgrade_strategy",
    "rollback_method",
    "direct_path_checked_against_vendor_documentation",
    "compatibility_matrix_reviewed",
)


class EvidenceBuildError(ValueError):
    """Raised when a private capture cannot safely become public evidence."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise EvidenceBuildError(f"duplicate JSON key rejected: {key}")
        value[key] = child
    return value


def read_json_object(path: Path) -> dict[str, Any]:
    """Read one bounded JSON object without exposing its contents in errors."""

    try:
        size = path.stat().st_size
    except OSError as error:
        raise EvidenceBuildError(f"unable to inspect input {path.name}: {error}") from error
    if size > MAX_INPUT_BYTES:
        raise EvidenceBuildError(f"input exceeds {MAX_INPUT_BYTES} bytes: {path.name}")
    try:
        payload = path.read_bytes()
        if payload.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = payload.decode("utf-16")
        else:
            text = payload.decode("utf-8-sig")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceBuildError(f"invalid JSON input {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceBuildError(f"JSON input must be an object: {path.name}")
    return value


def require_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceBuildError(f"{path} must be an object")
    return value


def require_fields(source: dict[str, Any], fields: Iterable[str], path: str) -> None:
    missing = [field for field in fields if field not in source]
    if missing:
        raise EvidenceBuildError(f"{path} is missing required fields: {', '.join(missing)}")


def select_fields(source: dict[str, Any], fields: Iterable[str], path: str) -> dict[str, Any]:
    require_fields(source, fields, path)
    return {field: source[field] for field in fields}


def sanitize_phase_capture(
    capture: dict[str, Any], expected_name: str, expected_sequence: int
) -> dict[str, Any]:
    """Allowlist one private phase capture and enforce its declared identity."""

    require_fields(capture, ("phase_name", "sequence", "phase"), f"capture.{expected_name}")
    if capture["phase_name"] != expected_name:
        raise EvidenceBuildError(f"capture identity mismatch for {expected_name}")
    if capture["sequence"] != expected_sequence:
        raise EvidenceBuildError(f"capture sequence mismatch for {expected_name}")
    source = require_object(capture["phase"], f"capture.{expected_name}.phase")
    require_fields(source, PHASE_FIELDS, f"capture.{expected_name}.phase")

    health_source = require_object(source["health"], f"{expected_name}.health")
    inventory_source = require_object(source["inventory"], f"{expected_name}.inventory")
    kv_source = require_object(source["kv_store"], f"{expected_name}.kv_store")
    license_source = require_object(source["license"], f"{expected_name}.license")
    hashes_source = require_object(source["hashes"], f"{expected_name}.hashes")
    tests_source = source["smoke_tests"]
    if not isinstance(tests_source, list):
        raise EvidenceBuildError(f"{expected_name}.smoke_tests must be an array")

    smoke_tests: list[dict[str, Any]] = []
    for index, test in enumerate(tests_source):
        test_source = require_object(test, f"{expected_name}.smoke_tests[{index}]")
        smoke_tests.append(
            select_fields(test_source, SMOKE_FIELDS, f"{expected_name}.smoke_tests[{index}]")
        )

    phase = {
        "captured_at": source["captured_at"],
        "version": source["version"],
        "build": source["build"],
        "health": select_fields(health_source, HEALTH_FIELDS, f"{expected_name}.health"),
        "inventory": select_fields(
            inventory_source, INVENTORY_FIELDS, f"{expected_name}.inventory"
        ),
        "kv_store": select_fields(kv_source, KV_STORE_FIELDS, f"{expected_name}.kv_store"),
        "license": select_fields(
            license_source, LICENSE_FIELDS, f"{expected_name}.license"
        ),
        "hashes": select_fields(hashes_source, sorted(HASH_FIELDS), f"{expected_name}.hashes"),
        "smoke_tests": smoke_tests,
    }

    if phase["version"] != EXPECTED_VERSIONS[expected_name]:
        raise EvidenceBuildError(f"unexpected Splunk version in {expected_name}")
    test_ids = [item.get("id") for item in smoke_tests]
    if len(smoke_tests) != len(REQUIRED_SMOKE_TESTS):
        raise EvidenceBuildError(f"{expected_name} must contain exactly eight smoke tests")
    if len(set(test_ids)) != len(test_ids) or set(test_ids) != REQUIRED_SMOKE_TESTS:
        raise EvidenceBuildError(f"{expected_name} smoke-test identities are incomplete or duplicated")
    if any(item.get("status") != "passed" for item in smoke_tests):
        raise EvidenceBuildError(f"{expected_name} contains a failed smoke test")
    if not (
        phase["health"].get("status") == "green"
        and phase["health"].get("splunkd_status") == "running"
        and phase["health"].get("searchable") is True
        and phase["health"].get("fatal_error_count") == 0
        and phase["health"].get("skipped_search_count") == 0
        and phase["kv_store"].get("status") == "ready"
        and phase["license"].get("state") == "OK"
        and phase["license"].get("violation_count") == 0
    ):
        raise EvidenceBuildError(f"{expected_name} did not pass health, KV Store, and license gates")
    return phase


def sanitize_backup(payload: dict[str, Any]) -> dict[str, Any]:
    source = payload.get("backup", payload)
    source = require_object(source, "backup")
    return select_fields(source, BACKUP_FIELDS, "backup")


def sanitize_chronology(payload: dict[str, Any]) -> dict[str, Any]:
    source = payload.get("chronology", payload)
    source = require_object(source, "chronology")
    require_fields(source, ("run_id", "project", "change", "decisions"), "chronology")

    project_source = require_object(source["project"], "chronology.project")
    project = select_fields(project_source, PROJECT_FIELDS, "chronology.project")
    es_source = require_object(project["enterprise_security_layer"], "enterprise_security_layer")
    project["enterprise_security_layer"] = select_fields(
        es_source,
        ("status", "version_before", "version_after", "compatibility_matrix_checked"),
        "enterprise_security_layer",
    )
    if not re.search(r"(?i)\bdebian(?:\s+gnu/linux)?\s+13\b", str(project["host_os"])):
        raise EvidenceBuildError("host_os must identify Debian 13 for this laboratory proof")
    if project["os_evidence_boundary"] != "lab-method-validation-not-vendor-support-certification":
        raise EvidenceBuildError("Debian 13 must remain bounded to lab method validation")
    if project["enterprise_security_layer"] != {
        "status": "not-installed",
        "version_before": None,
        "version_after": None,
        "compatibility_matrix_checked": False,
    }:
        raise EvidenceBuildError("Enterprise Security must be declared not-installed")

    change_source = require_object(source["change"], "chronology.change")
    change = select_fields(change_source, CHANGE_FIELDS, "chronology.change")
    decisions_source = require_object(source["decisions"], "chronology.decisions")
    decisions: dict[str, dict[str, Any]] = {}
    for name in REQUIRED_PHASES:
        decision_source = require_object(
            decisions_source.get(name), f"chronology.decisions.{name}"
        )
        decision = select_fields(
            decision_source, ("decision", "reason"), f"chronology.decisions.{name}"
        )
        if decision["decision"] != EXPECTED_DECISIONS[name]:
            raise EvidenceBuildError(f"incoherent decision for {name}")
        decisions[name] = decision
    return {
        "run_id": source["run_id"],
        "project": project,
        "change": change,
        "decisions": decisions,
    }


def _contains_ip(value: str) -> bool:
    for match in IP_TOKEN.finditer(value):
        candidate = match.group(0).strip(".:")
        if not candidate:
            continue
        candidate = candidate.split("%", 1)[0]
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return True
    return False


def public_safety_findings(value: Any, path: str = "$") -> list[str]:
    """Find data classes forbidden from the public artifact."""

    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            findings.extend(public_safety_findings(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(public_safety_findings(child, f"{path}[{index}]"))
    elif isinstance(value, str):
        checks = (
            ("ip_address", _contains_ip(value)),
            ("fqdn", bool(FQDN.search(value))),
            ("credential", bool(CREDENTIAL.search(value))),
            ("raw_event", bool(RAW_EVENT.search(value))),
            ("sid", bool(SID.search(value))),
        )
        findings.extend(f"{path}:{name}" for name, found in checks if found)
    return findings


def ensure_output_target(path: Path) -> None:
    resolved = path.resolve(strict=False)
    if not OUTPUT_NAME.fullmatch(resolved.name):
        raise EvidenceBuildError("output filename must match upgrade-evidence-*.json")
    if resolved.parent.name.lower() != "public" or resolved.parent.parent.name.lower() != "artifacts":
        raise EvidenceBuildError("output must be located under artifacts/public")


def load_schema(path: Path) -> dict[str, Any]:
    schema = read_json_object(path)
    errors = schema_contract_errors(schema)
    if errors:
        raise EvidenceBuildError(f"schema contract failed with {len(errors)} error(s)")
    return schema


def build_public_evidence(
    phase_captures: dict[str, dict[str, Any]],
    backup_payload: dict[str, Any],
    chronology_payload: dict[str, Any],
    schema: dict[str, Any],
) -> dict[str, Any]:
    """Build and fully gate the in-memory public artifact."""

    if set(phase_captures) != set(REQUIRED_PHASES):
        raise EvidenceBuildError("exactly four named phase captures are required")
    phases = {
        name: sanitize_phase_capture(phase_captures[name], name, index)
        for index, name in enumerate(REQUIRED_PHASES, start=1)
    }
    chronology = sanitize_chronology(chronology_payload)
    evidence = {
        "schema_version": "1.0",
        "evidence_kind": "live-isolated-lab",
        "run_id": chronology["run_id"],
        "project": chronology["project"],
        "change": chronology["change"],
        "backup": sanitize_backup(backup_payload),
        "phases": phases,
        "decisions": chronology["decisions"],
        "public_redaction": {
            "private_addresses_removed": True,
            "credentials_removed": True,
            "hostnames_replaced_with_aliases": True,
            "raw_events_excluded": True,
        },
    }

    if phases["pre_upgrade"]["inventory"] != phases["rollback"]["inventory"]:
        raise EvidenceBuildError("pre_upgrade and rollback inventories differ")
    if phases["post_upgrade"]["inventory"] != phases["final"]["inventory"]:
        raise EvidenceBuildError("post_upgrade and final inventories differ")
    if phases["pre_upgrade"]["hashes"] != phases["rollback"]["hashes"]:
        raise EvidenceBuildError("pre_upgrade and rollback hashes differ")
    if phases["post_upgrade"]["hashes"] != phases["final"]["hashes"]:
        raise EvidenceBuildError("post_upgrade and final hashes differ")

    schema_errors = validate_schema_node(evidence, schema, schema)
    if schema_errors:
        raise EvidenceBuildError(f"public evidence violates schema in {len(schema_errors)} place(s)")
    failed_checks = [check["name"] for check in semantic_checks(evidence) if check["status"] != "passed"]
    if failed_checks:
        raise EvidenceBuildError(f"semantic gates failed: {', '.join(failed_checks)}")
    findings = public_safety_findings(evidence)
    if findings:
        raise EvidenceBuildError(f"public safety scan failed: {', '.join(findings)}")
    return evidence


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    serialized = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def build_and_write(
    *,
    pre_upgrade: Path,
    post_upgrade: Path,
    rollback: Path,
    final: Path,
    backup: Path,
    chronology: Path,
    output: Path,
    schema_path: Path = DEFAULT_SCHEMA,
) -> dict[str, Any]:
    """Read private inputs, pass all gates, then atomically publish once."""

    ensure_output_target(output)
    schema = load_schema(schema_path)
    phase_captures = {
        "pre_upgrade": read_json_object(pre_upgrade),
        "post_upgrade": read_json_object(post_upgrade),
        "rollback": read_json_object(rollback),
        "final": read_json_object(final),
    }
    evidence = build_public_evidence(
        phase_captures,
        read_json_object(backup),
        read_json_object(chronology),
        schema,
    )
    atomic_write_json(output, evidence)
    return evidence


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pre-upgrade", type=Path, required=True)
    parser.add_argument("--post-upgrade", type=Path, required=True)
    parser.add_argument("--rollback", type=Path, required=True)
    parser.add_argument("--final", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--chronology", type=Path, required=True)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        build_and_write(
            pre_upgrade=args.pre_upgrade,
            post_upgrade=args.post_upgrade,
            rollback=args.rollback,
            final=args.final,
            backup=args.backup,
            chronology=args.chronology,
            output=args.output,
            schema_path=args.schema,
        )
    except (EvidenceBuildError, OSError) as error:
        print(f"ERROR: upgrade evidence not written: {error}", file=sys.stderr)
        return 1
    print(f"PASS: wrote sanitized upgrade evidence to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
