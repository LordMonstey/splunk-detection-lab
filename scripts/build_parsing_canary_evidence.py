#!/usr/bin/env python3
"""Build sanitized public evidence for the live parsing canary rollback drill."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_ROOT = (ROOT / "artifacts" / "public").resolve()
PRIVATE_ROOT = (ROOT / "artifacts" / "private").resolve()
PHASES = ("baseline", "candidate", "rollback")
REQUIRED_FIELDS = ("user", "src", "action")
RUN_ID = re.compile(r"^parsing-[0-9]{8}T[0-9]{6}Z-[a-z0-9]{6,16}$")
ALIAS = re.compile(r"^lab-[a-z0-9-]{3,48}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?$")
SECRET = re.compile(
    r"(?i)(?:password|passwd|token|secret|api[_-]?key|sessionkey|authorization)\s*[:=]"
)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )
)
TOP_LEVEL_KEYS = {
    "schema_version",
    "evidence_kind",
    "run_id",
    "project",
    "change",
    "packages",
    "phases",
}
PROJECT_KEYS = {
    "environment_alias",
    "topology",
    "index_alias",
    "sourcetype_alias",
    "app_id",
}
CHANGE_KEYS = {"started_at", "completed_at", "controlled_failure", "execution_mode"}
PACKAGE_KEYS = {"version", "archive_sha256", "effective_config_sha256"}
PHASE_KEYS = {
    "run_id",
    "captured_at",
    "expected_event_count",
    "observed_event_count",
    "distinct_event_count",
    "required_field_counts",
    "timestamp_within_tolerance_count",
    "duplicate_count",
    "truncated_event_count",
    "p95_index_lag_seconds",
    "aggregate_evidence_sha256",
}


class EvidenceError(ValueError):
    """Raised when an input cannot support the public canary claim."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    actual = set(value)
    require(actual == expected, f"{label} keys mismatch: missing={sorted(expected - actual)}, extra={sorted(actual - expected)}")
    return value


def integer(value: Any, label: str, minimum: int = 0) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    require(value >= minimum, f"{label} must be >= {minimum}")
    return value


def number(value: Any, label: str, minimum: float = 0.0) -> float:
    require(isinstance(value, (int, float)) and not isinstance(value, bool), f"{label} must be numeric")
    result = float(value)
    require(result >= minimum, f"{label} must be >= {minimum}")
    return result


def timestamp(value: Any, label: str) -> str:
    require(isinstance(value, str) and value.endswith("Z"), f"{label} must be UTC and end with Z")
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise EvidenceError(f"{label} is not an ISO-8601 timestamp") from exc
    return value


def sha256(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256.fullmatch(value) is not None, f"{label} must be a lowercase SHA-256")
    return value


def validate_privacy(raw_text: str) -> None:
    require("-----BEGIN " not in raw_text, "PEM material is forbidden")
    require(SECRET.search(raw_text) is None, "secret-like assignment is forbidden")
    for raw_ip in IPV4.findall(raw_text):
        try:
            address = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise EvidenceError(f"invalid IPv4 literal: {raw_ip}") from exc
        require(not any(address in network for network in PRIVATE_NETWORKS), f"private or local address is forbidden: {address}")


def validate_public_output(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(PUBLIC_ROOT)
    except ValueError as exc:
        raise EvidenceError("public evidence output must remain under artifacts/public") from exc
    require(resolved.suffix.lower() == ".json", "public evidence output must be JSON")
    return resolved


def validate_private_input(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(PRIVATE_ROOT)
    except ValueError as exc:
        raise EvidenceError("source evidence input must remain under artifacts/private") from exc
    require(resolved.is_file(), "source evidence input is missing")
    return resolved


def phase_metrics(name: str, raw: Any, base_run_id: str) -> dict[str, Any]:
    phase = exact_keys(raw, PHASE_KEYS, f"phases.{name}")
    require(phase["run_id"] == f"{base_run_id}-{name}", f"phases.{name}.run_id does not match the change run")
    captured_at = timestamp(phase["captured_at"], f"phases.{name}.captured_at")
    expected = integer(phase["expected_event_count"], f"phases.{name}.expected_event_count", 1)
    observed = integer(phase["observed_event_count"], f"phases.{name}.observed_event_count")
    distinct = integer(phase["distinct_event_count"], f"phases.{name}.distinct_event_count")
    require(expected == 5, f"phases.{name}: the controlled fixture must contain exactly five events")
    require(observed <= expected, f"phases.{name}: observed count exceeds the scoped fixture")
    require(distinct <= observed, f"phases.{name}: distinct count exceeds observed count")

    field_counts = exact_keys(phase["required_field_counts"], set(REQUIRED_FIELDS), f"phases.{name}.required_field_counts")
    normalized_counts: dict[str, int] = {}
    coverage: dict[str, float] = {}
    for field in REQUIRED_FIELDS:
        count = integer(field_counts[field], f"phases.{name}.required_field_counts.{field}")
        require(count <= observed, f"phases.{name}: {field} count exceeds observed events")
        normalized_counts[field] = count
        coverage[field] = round(100.0 * count / observed, 2) if observed else 0.0

    timestamp_count = integer(
        phase["timestamp_within_tolerance_count"],
        f"phases.{name}.timestamp_within_tolerance_count",
    )
    require(timestamp_count <= observed, f"phases.{name}: timestamp count exceeds observed events")
    duplicates = integer(phase["duplicate_count"], f"phases.{name}.duplicate_count")
    truncated = integer(phase["truncated_event_count"], f"phases.{name}.truncated_event_count")
    lag = number(phase["p95_index_lag_seconds"], f"phases.{name}.p95_index_lag_seconds")
    evidence_digest = sha256(phase["aggregate_evidence_sha256"], f"phases.{name}.aggregate_evidence_sha256")

    timestamp_pct = round(100.0 * timestamp_count / observed, 2) if observed else 0.0
    checks = {
        "event_count": observed == expected,
        "event_uniqueness": distinct == observed and duplicates == 0,
        "required_field_coverage": observed > 0 and all(count == observed for count in normalized_counts.values()),
        "timestamp_conformance": observed > 0 and timestamp_count == observed,
        "event_integrity": truncated == 0,
        "index_lag": lag <= 900.0,
    }
    failed_checks = [check for check, passed in checks.items() if not passed]
    gate = "PASS" if not failed_checks else "NO-GO"
    return {
        "run_id": phase["run_id"],
        "captured_at": captured_at,
        "expected_event_count": expected,
        "observed_event_count": observed,
        "distinct_event_count": distinct,
        "required_field_coverage_pct": coverage,
        "minimum_required_field_coverage_pct": min(coverage.values()),
        "timestamp_conformance_pct": timestamp_pct,
        "duplicate_count": duplicates,
        "truncated_event_count": truncated,
        "p95_index_lag_seconds": round(lag, 3),
        "gate": gate,
        "failed_checks": failed_checks,
        "aggregate_evidence_sha256": evidence_digest,
    }


def validate_package(name: str, raw: Any) -> dict[str, str]:
    package = exact_keys(raw, PACKAGE_KEYS, f"packages.{name}")
    version = package["version"]
    require(isinstance(version, str) and VERSION.fullmatch(version) is not None, f"packages.{name}.version is invalid")
    return {
        "version": version,
        "archive_sha256": sha256(package["archive_sha256"], f"packages.{name}.archive_sha256"),
        "effective_config_sha256": sha256(
            package["effective_config_sha256"],
            f"packages.{name}.effective_config_sha256",
        ),
    }


def build_evidence(source: dict[str, Any], raw_text: str, allow_synthetic: bool = False) -> dict[str, Any]:
    validate_privacy(raw_text)
    exact_keys(source, TOP_LEVEL_KEYS, "root")
    require(source["schema_version"] == 1, "unsupported source schema")
    allowed_kinds = {"live-isolated-lab"}
    if allow_synthetic:
        allowed_kinds.add("synthetic-offline-test")
    require(source["evidence_kind"] in allowed_kinds, "CLI publication requires live-isolated-lab evidence")

    run_id = source["run_id"]
    require(isinstance(run_id, str) and RUN_ID.fullmatch(run_id) is not None, "run_id is invalid")

    project = exact_keys(source["project"], PROJECT_KEYS, "project")
    require(isinstance(project["environment_alias"], str) and ALIAS.fullmatch(project["environment_alias"]), "environment alias is invalid")
    require(project["topology"] == "standalone", "only the qualified standalone topology is supported")
    require(project["index_alias"] == "idx-recette-parsing", "public index alias must remain sanitized and stable")
    require(project["sourcetype_alias"] == "canary-auth", "public sourcetype alias must remain sanitized and stable")
    require(project["app_id"] == "splunk_parsing_canary_qualification", "unexpected qualification app")

    change = exact_keys(source["change"], CHANGE_KEYS, "change")
    started_at = timestamp(change["started_at"], "change.started_at")
    completed_at = timestamp(change["completed_at"], "change.completed_at")
    require(started_at < completed_at, "change chronology is invalid")
    require(change["controlled_failure"] is True, "candidate failure must be declared controlled")
    require(change["execution_mode"] == "canary-recipe-only", "execution must remain canary-recipe-only")

    packages_raw = exact_keys(source["packages"], set(PHASES), "packages")
    packages = {name: validate_package(name, packages_raw[name]) for name in PHASES}
    require(packages["baseline"]["version"] == "1.0.0", "baseline version must be 1.0.0")
    require(packages["candidate"]["version"] == "1.1.0-rc1", "candidate version must be 1.1.0-rc1")
    require(packages["rollback"] == packages["baseline"], "rollback must reinstall the exact baseline artifact and effective config")
    require(packages["candidate"]["archive_sha256"] != packages["baseline"]["archive_sha256"], "candidate archive must differ from baseline")
    require(packages["candidate"]["effective_config_sha256"] != packages["baseline"]["effective_config_sha256"], "candidate effective config must differ from baseline")

    phases_raw = exact_keys(source["phases"], set(PHASES), "phases")
    phases = {name: phase_metrics(name, phases_raw[name], run_id) for name in PHASES}
    require(phases["baseline"]["gate"] == "PASS", "baseline must pass before candidate deployment")
    require(phases["candidate"]["gate"] == "NO-GO", "candidate must trigger the quality gate")
    require(
        bool({"required_field_coverage", "timestamp_conformance"} & set(phases["candidate"]["failed_checks"])),
        "candidate NO-GO must be caused by a field or timestamp regression",
    )
    require(phases["rollback"]["gate"] == "PASS", "rollback phase must pass")
    phase_times = [phases[name]["captured_at"] for name in PHASES]
    require(phase_times == sorted(phase_times) and len(set(phase_times)) == 3, "phase chronology must be strict")
    require(started_at <= phase_times[0] and phase_times[-1] <= completed_at, "phase timestamps must be inside the change window")
    require(
        len({phases[name]["aggregate_evidence_sha256"] for name in PHASES}) == 3,
        "each phase must carry independent aggregate evidence",
    )

    baseline = phases["baseline"]
    rollback = phases["rollback"]
    coverage_delta = {
        field: round(
            rollback["required_field_coverage_pct"][field]
            - baseline["required_field_coverage_pct"][field],
            2,
        )
        for field in REQUIRED_FIELDS
    }
    timestamp_delta = round(
        rollback["timestamp_conformance_pct"] - baseline["timestamp_conformance_pct"],
        2,
    )
    lag_delta = round(
        rollback["p95_index_lag_seconds"] - baseline["p95_index_lag_seconds"],
        3,
    )
    parity_checks = {
        "same_baseline_artifact": packages["rollback"] == packages["baseline"],
        "event_count_restored": rollback["observed_event_count"] == baseline["observed_event_count"],
        "field_coverage_restored": all(abs(value) <= 0.01 for value in coverage_delta.values()),
        "timestamp_conformance_restored": abs(timestamp_delta) <= 0.01,
        "event_integrity_restored": rollback["duplicate_count"] == baseline["duplicate_count"] == 0
        and rollback["truncated_event_count"] == baseline["truncated_event_count"] == 0,
        "index_lag_comparable": abs(lag_delta) <= 60.0,
    }
    require(all(parity_checks.values()), "rollback parity was not restored")

    output = {
        "schema_version": "1.0",
        "evidence_kind": "live-isolated-lab" if source["evidence_kind"] == "live-isolated-lab" else "synthetic-offline-test",
        "run_id": run_id,
        "project": {
            "environment_alias": project["environment_alias"],
            "topology": project["topology"],
            "scoped_index_alias": project["index_alias"],
            "scoped_sourcetype_alias": project["sourcetype_alias"],
            "app_id": project["app_id"],
            "failure_injection": "controlled-field-and-timestamp-regression",
        },
        "change": {
            "started_at": started_at,
            "completed_at": completed_at,
            "execution_mode": change["execution_mode"],
            "promotion_boundary": "candidate-not-promotion-eligible",
        },
        "packages": packages,
        "phases": phases,
        "decisions": {
            "baseline": {"decision": "GO-CANARY", "reason": "baseline quality gate passed"},
            "candidate": {"decision": "NO-GO", "reason": "controlled parsing regression was detected before promotion"},
            "rollback": {"decision": "CLOSE", "reason": "baseline artifact and data-quality parity were restored"},
        },
        "rollback_parity": {
            "status": "RESTORED",
            "checks": parity_checks,
            "field_coverage_delta_percentage_points": coverage_delta,
            "timestamp_conformance_delta_percentage_points": timestamp_delta,
            "p95_index_lag_delta_seconds": lag_delta,
        },
        "public_redaction": {
            "credentials_removed": True,
            "private_addresses_removed": True,
            "hostnames_replaced_with_aliases": True,
            "raw_events_excluded": True,
            "search_identifiers_excluded": True,
        },
    }
    output["source_contract_sha256"] = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="private aggregate input JSON")
    parser.add_argument("--output", type=Path, required=True, help="sanitized public evidence JSON")
    args = parser.parse_args()
    try:
        source_path = validate_private_input(args.input)
        raw_text = source_path.read_text(encoding="utf-8")
        source = json.loads(raw_text)
        evidence = build_evidence(source, raw_text)
        output = validate_public_output(args.output)
        require(not output.exists(), "refusing to overwrite existing public evidence")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except (OSError, json.JSONDecodeError, EvidenceError) as error:
        print(f"FAIL: {error}")
        return 1
    print(f"PASS: wrote {output}")
    print("DECISION: candidate=NO-GO rollback=CLOSE parity=RESTORED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
