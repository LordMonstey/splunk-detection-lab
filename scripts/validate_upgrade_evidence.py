#!/usr/bin/env python3
"""Validate sanitized live evidence for the Splunk 9.4.13 to 10.2.1 drill.

The validator uses only the Python standard library. It checks the published
JSON Schema contract, validates an evidence file against the supported schema
keywords, and applies upgrade-specific semantic controls that JSON Schema
cannot express clearly (chronology, rollback equivalence, and smoke coverage).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_PHASES = ("pre_upgrade", "post_upgrade", "rollback", "final")
EXPECTED_VERSIONS = {
    "pre_upgrade": "9.4.13",
    "post_upgrade": "10.2.1",
    "rollback": "9.4.13",
    "final": "10.2.1",
}
EXPECTED_DECISIONS = {
    "pre_upgrade": "GO",
    "post_upgrade": "GO-ROLLBACK-DRILL",
    "rollback": "GO-FINAL-UPGRADE",
    "final": "CLOSE",
}
REQUIRED_SMOKE_TESTS = {
    "authentication",
    "interactive_search",
    "scheduled_search",
    "ingestion_freshness",
    "kv_store",
    "license",
    "dashboard_load",
    "configuration_check",
}
ROLLBACK_INVENTORY_FIELDS = {
    "installed_app_count",
    "custom_app_count",
    "saved_search_count",
    "enabled_saved_search_count",
}
HASH_FIELDS = {
    "managed_configuration_manifest_sha256",
    "custom_apps_manifest_sha256",
    "saved_searches_export_sha256",
    "kv_store_export_sha256",
}
PRIVATE_IPV4 = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
)
CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|token|secret|session_key)\s*[:=]\s*[^\s,;]+"
)
PLACEHOLDER = re.compile(r"(?i)\b(?:todo|tbd|fixme|lorem ipsum|replace-me)\b")
SHA256 = re.compile(r"^[a-f0-9]{64}$")


def parse_timestamp(value: str) -> datetime:
    """Parse a UTC RFC 3339 timestamp and reject naive/non-UTC values."""

    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp must use UTC Z notation")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("timestamp must be UTC")
    return parsed


def resolve_ref(root_schema: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise ValueError(f"external reference is not supported: {reference}")
    node: Any = root_schema
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise ValueError(f"unresolved schema reference: {reference}")
        node = node[part]
    if not isinstance(node, dict):
        raise ValueError(f"schema reference is not an object: {reference}")
    return node


def matches_type(value: Any, expected: str) -> bool:
    mapping = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }
    return expected in mapping and mapping[expected](value)


def validate_schema_node(
    value: Any,
    schema: dict[str, Any],
    root_schema: dict[str, Any],
    path: str = "$",
) -> list[str]:
    """Validate the JSON Schema subset used by the checked-in contract."""

    errors: list[str] = []
    if "$ref" in schema:
        try:
            referenced = resolve_ref(root_schema, schema["$ref"])
        except ValueError as error:
            return [f"{path}: {error}"]
        errors.extend(validate_schema_node(value, referenced, root_schema, path))

    for part in schema.get("allOf", []):
        errors.extend(validate_schema_node(value, part, root_schema, path))

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value {value!r} is not in {schema['enum']!r}")

    expected_type = schema.get("type")
    if expected_type is not None:
        expected_types = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(matches_type(value, item) for item in expected_types):
            errors.append(f"{path}: expected type {expected_types!r}, got {type(value).__name__}")
            return errors

    if isinstance(value, dict):
        required = schema.get("required", [])
        for field in required:
            if field not in value:
                errors.append(f"{path}: missing required property {field!r}")
        properties = schema.get("properties", {})
        for field, child in value.items():
            child_path = f"{path}.{field}"
            if field in properties:
                errors.extend(validate_schema_node(child, properties[field], root_schema, child_path))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{child_path}: additional property is not allowed")

    if isinstance(value, list):
        minimum = schema.get("minItems")
        if minimum is not None and len(value) < minimum:
            errors.append(f"{path}: expected at least {minimum} items, got {len(value)}")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(
                    validate_schema_node(item, item_schema, root_schema, f"{path}[{index}]")
                )

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: string is shorter than {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: string is longer than {schema['maxLength']} characters")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append(f"{path}: value does not match {schema['pattern']!r}")
        if schema.get("format") == "date-time":
            try:
                parse_timestamp(value)
            except (TypeError, ValueError) as error:
                errors.append(f"{path}: invalid date-time ({error})")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: value is below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: value is above maximum {schema['maximum']}")
    return errors


def schema_contract_errors(schema: dict[str, Any]) -> list[str]:
    """Verify that the schema still encodes the mandatory upgrade contract."""

    errors: list[str] = []
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append("schema must declare JSON Schema draft 2020-12")
    for definition in ("timestamp", "sha256", "phase", "smoke_test", "decision"):
        if definition not in schema.get("$defs", {}):
            errors.append(f"missing schema definition: {definition}")
    try:
        phase_properties = schema["properties"]["phases"]["properties"]
        for phase, version in EXPECTED_VERSIONS.items():
            rules = phase_properties[phase]["allOf"]
            declared = [
                item.get("properties", {}).get("version", {}).get("const") for item in rules
            ]
            if version not in declared:
                errors.append(f"{phase} does not enforce version {version}")
    except (KeyError, TypeError):
        errors.append("phase version contract is incomplete")
    return errors


def semantic_checks(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: str) -> None:
        checks.append(
            {"name": name, "status": "passed" if passed else "failed", "detail": detail}
        )

    phases = evidence.get("phases", {})
    versions = {name: phases.get(name, {}).get("version") for name in REQUIRED_PHASES}
    record("phase_versions", versions == EXPECTED_VERSIONS, json.dumps(versions, sort_keys=True))

    timeline_values: list[tuple[str, datetime]] = []
    try:
        change = evidence["change"]
        backup = evidence["backup"]
        timeline_values = [
            ("change.started_at", parse_timestamp(change["started_at"])),
            *[
                (f"phases.{name}.captured_at", parse_timestamp(phases[name]["captured_at"]))
                for name in REQUIRED_PHASES
            ],
            ("change.completed_at", parse_timestamp(change["completed_at"])),
        ]
        ordered = all(
            timeline_values[index][1] < timeline_values[index + 1][1]
            for index in range(len(timeline_values) - 1)
        )
        backup_before_pre = parse_timestamp(backup["captured_at"]) <= timeline_values[1][1]
        restore_after_rollback = (
            timeline_values[3][1]
            <= parse_timestamp(backup["restore_tested_at"])
            <= timeline_values[4][1]
        )
        record(
            "utc_chronology",
            ordered and backup_before_pre and restore_after_rollback,
            " < ".join(name for name, _ in timeline_values),
        )
    except (KeyError, TypeError, ValueError) as error:
        record("utc_chronology", False, str(error))

    healthy_phases: list[str] = []
    for name in REQUIRED_PHASES:
        health = phases.get(name, {}).get("health", {})
        if (
            health.get("status") == "green"
            and health.get("splunkd_status") == "running"
            and health.get("searchable") is True
            and health.get("fatal_error_count") == 0
            and health.get("skipped_search_count") == 0
        ):
            healthy_phases.append(name)
    record("phase_health", healthy_phases == list(REQUIRED_PHASES), f"healthy={healthy_phases}")

    compliant_services: list[str] = []
    for name in REQUIRED_PHASES:
        phase = phases.get(name, {})
        kv_store = phase.get("kv_store", {})
        license_state = phase.get("license", {})
        if (
            kv_store.get("status") == "ready"
            and license_state.get("state") == "OK"
            and license_state.get("violation_count") == 0
        ):
            compliant_services.append(name)
    record(
        "kv_store_and_license",
        compliant_services == list(REQUIRED_PHASES),
        f"compliant={compliant_services}",
    )

    smoke_details: dict[str, Any] = {}
    smoke_pass = True
    for name in REQUIRED_PHASES:
        tests = phases.get(name, {}).get("smoke_tests", [])
        test_ids = [item.get("id") for item in tests if isinstance(item, dict)]
        passed_ids = {
            item.get("id")
            for item in tests
            if isinstance(item, dict) and item.get("status") == "passed"
        }
        missing = sorted(REQUIRED_SMOKE_TESTS - passed_ids)
        duplicate_ids = sorted({item for item in test_ids if test_ids.count(item) > 1})
        smoke_details[name] = {"missing_or_failed": missing, "duplicates": duplicate_ids}
        smoke_pass = smoke_pass and not missing and not duplicate_ids
    record("smoke_test_coverage", smoke_pass, json.dumps(smoke_details, sort_keys=True))

    inventory_drift: dict[str, Any] = {}
    inventory_pass = True
    for reference, restored in (("pre_upgrade", "rollback"), ("post_upgrade", "final")):
        left = phases.get(reference, {}).get("inventory", {})
        right = phases.get(restored, {}).get("inventory", {})
        differences = {
            field: [left.get(field), right.get(field)]
            for field in sorted(ROLLBACK_INVENTORY_FIELDS)
            if left.get(field) != right.get(field)
        }
        inventory_drift[f"{reference}_vs_{restored}"] = differences
        inventory_pass = inventory_pass and not differences
    record("inventory_restoration", inventory_pass, json.dumps(inventory_drift, sort_keys=True))

    hash_drift: dict[str, Any] = {}
    hashes_pass = True
    for reference, restored in (("pre_upgrade", "rollback"), ("post_upgrade", "final")):
        left = phases.get(reference, {}).get("hashes", {})
        right = phases.get(restored, {}).get("hashes", {})
        differences = {
            field: [left.get(field), right.get(field)]
            for field in sorted(HASH_FIELDS)
            if left.get(field) != right.get(field)
        }
        hash_drift[f"{reference}_vs_{restored}"] = differences
        hashes_pass = hashes_pass and not differences
    record("manifest_restoration", hashes_pass, json.dumps(hash_drift, sort_keys=True))

    decisions = {
        name: evidence.get("decisions", {}).get(name, {}).get("decision")
        for name in REQUIRED_PHASES
    }
    record(
        "go_no_go_decisions",
        decisions == EXPECTED_DECISIONS,
        json.dumps(decisions, sort_keys=True),
    )

    enterprise_security = evidence.get("project", {}).get("enterprise_security_layer", {})
    es_status = enterprise_security.get("status")
    es_consistent = (
        es_status == "not-installed"
        and enterprise_security.get("version_before") is None
        and enterprise_security.get("version_after") is None
        and enterprise_security.get("compatibility_matrix_checked") is False
    ) or (
        es_status == "installed-and-validated"
        and bool(enterprise_security.get("version_before"))
        and bool(enterprise_security.get("version_after"))
        and enterprise_security.get("compatibility_matrix_checked") is True
    )
    record("enterprise_security_claim_boundary", es_consistent, f"status={es_status!r}")

    canonical = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
    redaction_findings = {
        "private_ipv4": len(PRIVATE_IPV4.findall(canonical)),
        "credential_assignment": len(CREDENTIAL_ASSIGNMENT.findall(canonical)),
        "placeholder": len(PLACEHOLDER.findall(canonical)),
    }
    record(
        "public_evidence_redaction",
        not any(redaction_findings.values()),
        json.dumps(redaction_findings, sort_keys=True),
    )

    all_hashes = re.findall(r'\b[a-f0-9]{64}\b', canonical)
    bad_hashes = [value for value in all_hashes if not SHA256.fullmatch(value) or len(set(value)) < 8]
    record(
        "non_placeholder_hashes",
        bool(all_hashes) and not bad_hashes,
        f"hashes={len(all_hashes)} rejected={len(bad_hashes)}",
    )
    return checks


def build_report(evidence_path: Path, schema_errors: list[str], checks: list[dict[str, Any]]) -> dict[str, Any]:
    semantic_failures = sum(item["status"] != "passed" for item in checks)
    valid = not schema_errors and semantic_failures == 0
    return {
        "schema_version": 1,
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "splunk-upgrade-9.4.13-to-10.2.1-evidence",
        "input": evidence_path.name,
        "summary": {
            "status": "passed" if valid else "failed",
            "schema_errors": len(schema_errors),
            "semantic_checks": len(checks),
            "semantic_passed": len(checks) - semantic_failures,
            "semantic_failed": semantic_failures,
        },
        "schema_errors": schema_errors,
        "checks": checks,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", nargs="?", type=Path, help="sanitized live evidence JSON")
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path("artifacts/templates/upgrade-evidence.schema.json"),
        help="JSON Schema contract",
    )
    parser.add_argument("--check-schema", action="store_true", help="validate the schema contract")
    parser.add_argument("--output", type=Path, help="optional machine-readable validation report")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: unable to read schema: {error}", file=sys.stderr)
        return 2

    contract_errors = schema_contract_errors(schema)
    if args.check_schema:
        if contract_errors:
            for error in contract_errors:
                print(f"SCHEMA ERROR: {error}", file=sys.stderr)
            return 1
        print(f"SCHEMA OK: {args.schema}")
        if args.evidence is None:
            return 0

    if args.evidence is None:
        print("ERROR: provide an evidence JSON or use --check-schema", file=sys.stderr)
        return 2

    try:
        evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: unable to read evidence: {error}", file=sys.stderr)
        return 2

    schema_errors = contract_errors + validate_schema_node(evidence, schema, schema)
    checks = semantic_checks(evidence) if isinstance(evidence, dict) else []
    report = build_report(args.evidence, schema_errors, checks)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    summary = report["summary"]
    print(
        f"{summary['status'].upper()}: schema_errors={summary['schema_errors']} "
        f"semantic_passed={summary['semantic_passed']}/{summary['semantic_checks']}"
    )
    for error in schema_errors:
        print(f"SCHEMA ERROR: {error}")
    for item in checks:
        print(f"{item['status'].upper()}: {item['name']} - {item['detail']}")
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
