#!/usr/bin/env python3
"""Run deterministic, offline MCO decision drills against synthetic fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = ROOT / "tests" / "fixtures" / "mco_drill_cases.json"
RUNBOOKS = {
    "license_quota": ROOT / "docs" / "runbooks" / "license-quota-incident.md",
    "scheduler_skipped_searches": ROOT / "docs" / "runbooks" / "scheduler-skipped-searches.md",
    "kv_store_unavailable": ROOT / "docs" / "runbooks" / "kv-store-unavailable.md",
    "index_capacity_pressure": ROOT / "docs" / "runbooks" / "index-capacity-pressure.md",
    "source_silence": ROOT / "docs" / "runbooks" / "source-silence.md",
    "parsing_cim_regression": ROOT / "docs" / "runbooks" / "parsing-cim-regression.md",
    "certificate_expiry": ROOT / "docs" / "runbooks" / "certificate-expiry-incident.md",
    "indexer_peer_loss": ROOT / "docs" / "runbooks" / "indexer-peer-loss.md",
}
SUPPORT_DOCUMENTS = (
    ROOT / "docs" / "runbooks" / "mco-operations-index.md",
    ROOT / "docs" / "runbooks" / "mco-drill-harness.md",
    ROOT / "docs" / "runbooks" / "mco-live-read-only-qualification.md",
)

REQUIRED_HEADINGS = (
    "## Symptomes et declenchement",
    "## Diagnostic",
    "### SPL",
    "### REST",
    "### CLI",
    "## Decision",
    "## Remediation",
    "## Rollback et retour arriere",
    "## Criteres de sortie",
    "## Preuves",
)

FORBIDDEN_PATTERNS = {
    "TLS verification disabled": re.compile(r"(?:curl\s+-k\b|--insecure\b)", re.IGNORECASE),
    "literal RFC1918 address": re.compile(
        r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
    ),
    "secret assignment": re.compile(
        r"(?i)[\"']?(?:password|passwd|token|secret)[\"']?\s*[:=]\s*[\"']?[^<\s\"'][^\s,}]*"
    ),
    "destructive REST delete": re.compile(
        r"(?i)curl[^\n]*(?:-X|--request)\s+DELETE\b"
    ),
    "recursive deletion": re.compile(r"(?i)\brm\s+-[a-z]*r[a-z]*f?\b"),
    "Splunk data cleanup": re.compile(r"(?i)\bsplunk\s+clean\s+(?:eventdata|all)\b"),
    "search-time deletion": re.compile(r"(?i)\|\s*delete\b"),
}


class DrillError(ValueError):
    """Raised when a fixture violates the offline drill contract."""


def number(observation: dict[str, Any], key: str) -> float:
    value = observation.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DrillError(f"{key} must be numeric")
    return float(value)


def boolean(observation: dict[str, Any], key: str) -> bool:
    value = observation.get(key)
    if not isinstance(value, bool):
        raise DrillError(f"{key} must be boolean")
    return value


def text_value(observation: dict[str, Any], key: str) -> str:
    value = observation.get(key)
    if not isinstance(value, str) or not value:
        raise DrillError(f"{key} must be a non-empty string")
    return value


def verdict(state: str, decision: str, *reasons: str) -> dict[str, Any]:
    return {"state": state, "decision": decision, "reasons": list(reasons)}


def evaluate_license(observation: dict[str, Any]) -> dict[str, Any]:
    usage = number(observation, "usage_pct")
    critical = number(observation, "critical_messages")
    search_available = boolean(observation, "search_available")
    contact_age = number(observation, "manager_contact_age_s")
    if not search_available or critical > 0 or usage >= 100 or contact_age >= 86400:
        return verdict("CRITICAL", "CONTAIN_AND_ESCALATE_LICENSE", "quota, message, search, or manager contact is critical")
    if usage >= 80 or contact_age >= 3600:
        return verdict("WARNING", "ANALYZE_LICENSE_GROWTH", "preventive threshold crossed")
    return verdict("HEALTHY", "CLOSE_AFTER_OBSERVATION", "license margin and search are healthy")


def evaluate_scheduler(observation: dict[str, Any]) -> dict[str, Any]:
    executions = number(observation, "executions")
    skipped = number(observation, "skipped")
    critical_skipped = number(observation, "critical_skipped")
    saturated = boolean(observation, "concurrency_saturated")
    skip_pct = 100 * skipped / executions if executions else 0.0
    if critical_skipped > 0 or skip_pct >= 5:
        return verdict("CRITICAL", "PROTECT_CRITICAL_SCHEDULES", f"skip ratio is {skip_pct:.2f}%")
    if skipped > 0 or saturated:
        return verdict("WARNING", "STAGGER_AND_OPTIMIZE_SEARCHES", f"skip ratio is {skip_pct:.2f}%")
    return verdict("HEALTHY", "CLOSE_AFTER_OBSERVATION", "no skipped execution")


def evaluate_kv_store(observation: dict[str, Any]) -> dict[str, Any]:
    status = text_value(observation, "status").lower()
    replication = text_value(observation, "replication_status").lower()
    quorum = boolean(observation, "quorum")
    canary = boolean(observation, "canary_valid")
    if status in {"failed", "disabled", "shuttingdown"} or not quorum:
        return verdict("CRITICAL", "ISOLATE_KV_FAILURE", "KV Store failed or quorum is unavailable")
    if status != "ready" or replication in {"down", "rollback", "recovering", "unknown"} or not canary:
        return verdict("WARNING", "OBSERVE_OR_RESYNC_ONE_MEMBER", "KV Store is not fully ready")
    return verdict("HEALTHY", "CLOSE_AFTER_OBSERVATION", "KV Store and canary are healthy")


def evaluate_capacity(observation: dict[str, Any]) -> dict[str, Any]:
    free = number(observation, "disk_free_pct")
    min_free_hit = boolean(observation, "min_free_space_hit")
    queue = number(observation, "max_queue_pct")
    index_fill = number(observation, "highest_index_fill_pct")
    if min_free_hit or free <= 5 or queue >= 90 or index_fill >= 95:
        return verdict("CRITICAL", "RESTORE_CAPACITY_MARGIN", "indexing or storage margin is critical")
    if free < 20 or queue >= 70 or index_fill >= 80:
        return verdict("WARNING", "PLAN_CAPACITY_CHANGE", "preventive capacity threshold crossed")
    return verdict("HEALTHY", "CLOSE_AFTER_OBSERVATION", "capacity and queues have margin")


def evaluate_source_silence(observation: dict[str, Any]) -> dict[str, Any]:
    age = number(observation, "age_s")
    sla = number(observation, "sla_s")
    maintenance = boolean(observation, "maintenance")
    duplicates = number(observation, "duplicate_pct")
    if sla <= 0:
        raise DrillError("sla_s must be greater than zero")
    if not maintenance and age > 3 * sla:
        return verdict("CRITICAL", "RESTORE_SOURCE_PATH", "source exceeds three freshness intervals")
    if age > sla or duplicates > 0:
        return verdict("WARNING", "INVESTIGATE_SOURCE_FRESHNESS", "freshness or duplication threshold crossed")
    return verdict("HEALTHY", "CLOSE_AFTER_OBSERVATION", "source freshness and duplicates are healthy")


def evaluate_parsing(observation: dict[str, Any]) -> dict[str, Any]:
    parsing = number(observation, "parse_success_pct")
    cim = number(observation, "cim_coverage_pct")
    duplicates = number(observation, "duplicate_count")
    truncations = number(observation, "truncation_count")
    if parsing < 95 or cim < 80 or duplicates > 0 or truncations > 0:
        return verdict("CRITICAL", "ROLL_BACK_PARSING_PACKAGE", "parsing integrity or CIM coverage failed")
    if parsing < 99 or cim < 95:
        return verdict("WARNING", "HOLD_CANARY_AND_TUNE", "coverage remains below target")
    return verdict("HEALTHY", "CLOSE_AFTER_OBSERVATION", "parsing and CIM contract passed")


def evaluate_certificate(observation: dict[str, Any]) -> dict[str, Any]:
    days = number(observation, "days_remaining")
    chain = boolean(observation, "chain_valid")
    hostname = boolean(observation, "hostname_valid")
    tls = number(observation, "tls_min_version")
    if not chain or not hostname or tls < 1.2 or days <= 7:
        return verdict("CRITICAL", "ROTATE_CERTIFICATE_URGENTLY", "certificate trust, name, protocol, or expiry is critical")
    if days <= 60:
        return verdict("WARNING", "SCHEDULE_CERTIFICATE_ROTATION", "renewal threshold crossed")
    return verdict("HEALTHY", "CLOSE_AFTER_OBSERVATION", "certificate controls passed")


def evaluate_peer(observation: dict[str, Any]) -> dict[str, Any]:
    peer_up = boolean(observation, "peer_up")
    valid = boolean(observation, "cluster_valid")
    complete = boolean(observation, "cluster_complete")
    rf_met = boolean(observation, "rf_met")
    sf_met = boolean(observation, "sf_met")
    fixup = number(observation, "fixup_pending")
    if not valid or not peer_up or not rf_met or not sf_met:
        return verdict("CRITICAL", "RECOVER_PEER_AND_RF", "peer or cluster redundancy failed")
    if not complete or fixup > 0:
        return verdict("WARNING", "MONITOR_CLUSTER_FIXUP", "cluster is valid but not complete")
    return verdict("HEALTHY", "CLOSE_AFTER_OBSERVATION", "cluster is valid and complete")


EVALUATORS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "license_quota": evaluate_license,
    "scheduler_skipped_searches": evaluate_scheduler,
    "kv_store_unavailable": evaluate_kv_store,
    "index_capacity_pressure": evaluate_capacity,
    "source_silence": evaluate_source_silence,
    "parsing_cim_regression": evaluate_parsing,
    "certificate_expiry": evaluate_certificate,
    "indexer_peer_loss": evaluate_peer,
}


def load_fixture(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    decoded = raw.decode("utf-8")
    for label, pattern in FORBIDDEN_PATTERNS.items():
        if pattern.search(decoded):
            raise DrillError(f"fixture security violation: {label}")
    fixture = json.loads(decoded)
    if fixture.get("schema_version") != 1:
        raise DrillError("unsupported fixture schema")
    provenance = fixture.get("provenance", {})
    if provenance.get("kind") != "synthetic" or provenance.get("live_target") is not False:
        raise DrillError("fixture must be synthetic and must not target a live system")
    if provenance.get("contains_real_identifiers") is not False:
        raise DrillError("fixture must explicitly exclude real identifiers")
    controls = fixture.get("controls", {})
    for key in ("network_access_allowed", "change_execution_allowed", "destructive_actions_allowed"):
        if controls.get(key) is not False:
            raise DrillError(f"offline safety control {key} must be false")
    scenarios = fixture.get("scenarios")
    if not isinstance(scenarios, list):
        raise DrillError("scenarios must be a list")
    identifiers = [item.get("id") for item in scenarios if isinstance(item, dict)]
    if len(identifiers) != len(set(identifiers)):
        raise DrillError("scenario identifiers must be unique")
    unknown = set(identifiers) - set(EVALUATORS)
    if unknown:
        raise DrillError(f"unknown scenarios: {', '.join(sorted(unknown))}")
    missing = set(EVALUATORS) - set(identifiers)
    if missing:
        raise DrillError(f"missing scenarios: {', '.join(sorted(missing))}")
    return fixture, hashlib.sha256(raw).hexdigest()


def validate_runbooks() -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []
    for scenario, path in RUNBOOKS.items():
        if not path.is_file():
            failures.append({"scenario": scenario, "check": "file", "detail": "missing runbook"})
            continue
        content = path.read_text(encoding="utf-8")
        for heading in REQUIRED_HEADINGS:
            if heading not in content:
                failures.append({"scenario": scenario, "check": "heading", "detail": f"missing {heading}"})
        if "```spl" not in content or "```bash" not in content:
            failures.append({"scenario": scenario, "check": "commands", "detail": "SPL and Bash fences are required"})
        if "aucune execution live" not in content.lower():
            failures.append({"scenario": scenario, "check": "claim", "detail": "offline validation disclaimer missing"})
        for label, pattern in FORBIDDEN_PATTERNS.items():
            if pattern.search(content):
                failures.append({"scenario": scenario, "check": "security", "detail": label})
    for path in SUPPORT_DOCUMENTS:
        document = path.relative_to(ROOT).as_posix()
        if not path.is_file():
            failures.append({"scenario": document, "check": "file", "detail": "missing support document"})
            continue
        content = path.read_text(encoding="utf-8")
        for label, pattern in FORBIDDEN_PATTERNS.items():
            if pattern.search(content):
                failures.append({"scenario": document, "check": "security", "detail": label})
    return failures


def run_scenario(case: dict[str, Any]) -> dict[str, Any]:
    scenario = case.get("id")
    if scenario not in EVALUATORS:
        raise DrillError(f"unknown scenario: {scenario}")
    before = case.get("before")
    after = case.get("after")
    expected = case.get("expected")
    if not isinstance(before, dict) or not isinstance(after, dict) or not isinstance(expected, dict):
        raise DrillError(f"{scenario}: before, after, and expected must be objects")
    before_result = EVALUATORS[scenario](before)
    after_result = EVALUATORS[scenario](after)
    exit_pass = after_result["state"] == "HEALTHY"
    assertions = {
        "before_state": before_result["state"] == expected.get("before_state"),
        "before_decision": before_result["decision"] == expected.get("before_decision"),
        "after_state": after_result["state"] == expected.get("after_state"),
        "exit_pass": exit_pass is expected.get("exit_pass"),
    }
    return {
        "id": scenario,
        "runbook": RUNBOOKS[scenario].relative_to(ROOT).as_posix(),
        "before": before_result,
        "after": after_result,
        "exit_pass": exit_pass,
        "assertions": assertions,
        "passed": all(assertions.values()),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--scenario", choices=sorted(EVALUATORS))
    parser.add_argument("--list", action="store_true", help="list scenario identifiers and exit")
    parser.add_argument("--validate-docs", action="store_true", help="validate all runbook contracts")
    parser.add_argument("--output", type=Path, help="write a simulation-only JSON report")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.list:
        for name in sorted(EVALUATORS):
            print(name)
        return 0
    try:
        fixture, fixture_sha256 = load_fixture(args.fixture.resolve())
        selected = [case for case in fixture["scenarios"] if not args.scenario or case["id"] == args.scenario]
        results = [run_scenario(case) for case in selected]
        doc_failures = validate_runbooks() if args.validate_docs or not args.scenario else []
    except (OSError, json.JSONDecodeError, DrillError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_class": "synthetic_offline_drill",
        "live_execution": False,
        "claimable_as_live_proof": False,
        "network_access": False,
        "change_execution": False,
        "destructive_actions": False,
        "fixture_sha256": fixture_sha256,
        "scenario_count": len(results),
        "passed_count": sum(result["passed"] for result in results),
        "runbook_validation": {
            "performed": bool(args.validate_docs or not args.scenario),
            "failure_count": len(doc_failures),
            "failures": doc_failures,
        },
        "results": results,
    }
    passed = all(result["passed"] for result in results) and not doc_failures
    report["overall_status"] = "PASS" if passed else "FAIL"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"REPORT: {args.output}")
    print(
        f"SUMMARY: status={report['overall_status']} scenarios={len(results)} "
        f"passed={report['passed_count']} doc_failures={len(doc_failures)} "
        "live_execution=false claimable_as_live_proof=false"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
