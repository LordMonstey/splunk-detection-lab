#!/usr/bin/env python3
"""Qualify the custom non-CIM security telemetry data model on live Splunk."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError

from audit_splunk_live import SplunkAudit, entries


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_EVIDENCE_ROOT = (REPOSITORY_ROOT / "artifacts" / "public").resolve()
APP_ID = "splunk-detection-lab"
MODEL_ID = "Security_Telemetry_Qualification"
MODEL_DISPLAY_NAME = "Security Telemetry Qualification"
ROOT_DATASET = "Security_Telemetry"
EXPECTED_DATASETS = (
    "Security_Telemetry",
    "Authentication_Activity",
    "Change_Activity",
    "Process_Activity",
    "Network_Activity",
    "File_Registry_Activity",
    "Service_Activity",
)
EXPECTED_ROOT_FIELDS = {
    "_time",
    "action",
    "dest",
    "file_path",
    "host",
    "parent_process_name",
    "process_id",
    "process_name",
    "process_path",
    "query",
    "service_name",
    "source",
    "sourcetype",
    "src",
    "user",
    "vendor_product",
}
SUMMARY_ID = f"DM_{APP_ID}_{MODEL_ID}"
SUMMARY_PATH = f"/servicesNS/nobody/{APP_ID}/admin/summarization/tstats:{SUMMARY_ID}"
NATIVE_CIM_APP = "Splunk_SA_CIM"
ENTERPRISE_SECURITY_APP = "SplunkEnterpriseSecuritySuite"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
SECRET_TEXT = re.compile(
    r"(?i)(?:password|passwd|secret|authorization|session[_-]?key|private[_-]?key)\s*[:=]"
)
URI_TEXT = re.compile(r"(?i)https?://")
FORBIDDEN_KEYS = {"host", "hostname", "ip", "raw", "_raw", "query", "search", "sid", "uri"}


def utc_z(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def numeric(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def integer(value: Any, default: int = 0) -> int:
    return int(numeric(value, float(default)))


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_json_object(value: Any, label: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{label} is not a JSON object")
    decoded = json.loads(value)
    if not isinstance(decoded, dict):
        raise ValueError(f"{label} is not a JSON object")
    return decoded


def _root_object(definition: dict[str, Any]) -> dict[str, Any]:
    for obj in definition.get("objects", []):
        if isinstance(obj, dict) and obj.get("objectName") == ROOT_DATASET:
            return obj
    raise ValueError(f"root dataset {ROOT_DATASET} is missing")


def model_contract(definition: dict[str, Any]) -> tuple[dict[str, Any], dict[str, bool]]:
    objects = [item for item in definition.get("objects", []) if isinstance(item, dict)]
    object_names = tuple(str(item.get("objectName", "")) for item in objects)
    root = _root_object(definition)
    constraints = [
        str(item.get("search", ""))
        for item in root.get("constraints", [])
        if isinstance(item, dict)
    ]
    root_constraint = constraints[0] if constraints else ""
    root_fields = {
        str(item.get("fieldName", ""))
        for item in root.get("fields", [])
        if isinstance(item, dict)
        and item.get("type") not in {"objectCount", "childCount"}
        and str(item.get("fieldName", ""))
    }
    description = str(definition.get("description", ""))
    indexes = sorted(set(re.findall(r"\bindex=([A-Za-z0-9_-]+)", root_constraint)))
    eventtypes = sorted(set(re.findall(r"\beventtype=([A-Za-z0-9_-]+)", root_constraint)))
    tags = sorted(set(re.findall(r"\btag=([A-Za-z0-9_-]+)", root_constraint)))
    child_constraints = {
        str(item.get("objectName")): [
            str(constraint.get("search", ""))
            for constraint in item.get("constraints", [])
            if isinstance(constraint, dict)
        ]
        for item in objects
        if item.get("objectName") != ROOT_DATASET
    }
    stable_contract = {
        "model_id": definition.get("modelName"),
        "display_name": definition.get("displayName"),
        "description": description,
        "datasets": list(object_names),
        "root_fields": sorted(root_fields),
        "root_constraints": constraints,
        "child_constraints": child_constraints,
    }
    checks = {
        "model_id_exact": definition.get("modelName") == MODEL_ID,
        "display_name_exact": definition.get("displayName") == MODEL_DISPLAY_NAME,
        "dataset_hierarchy_exact": object_names == EXPECTED_DATASETS,
        "root_parent_is_base_event": root.get("parentName") == "BaseEvent",
        "root_fields_complete": EXPECTED_ROOT_FIELDS.issubset(root_fields),
        "root_constraint_is_streaming_event_constraint": bool(root_constraint)
        and "|" not in root_constraint,
        "index_scope_explicit": set(indexes) == {"os_linux", "sysmon", "windows"},
        "eventtype_contract_present": len(eventtypes) == 20,
        "tag_contract_present": set(tags)
        == {"authentication", "change", "filesystem", "network", "process", "registry", "service"},
        "child_datasets_use_tags": bool(child_constraints)
        and all(
            values and all("tag=" in value and "|" not in value for value in values)
            for values in child_constraints.values()
        ),
        "non_cim_boundary_explicit": "not a native splunk cim data model" in description.lower(),
    }
    profile = {
        "model_id": MODEL_ID,
        "display_name": MODEL_DISPLAY_NAME,
        "root_dataset": ROOT_DATASET,
        "dataset_count": len(object_names),
        "datasets": list(object_names),
        "root_field_count": len(root_fields),
        "index_scope_count": len(indexes),
        "eventtype_dependency_count": len(eventtypes),
        "tag_dependency_count": len(tags),
        "definition_sha256": canonical_hash(stable_contract),
        "root_constraint_sha256": canonical_hash(root_constraint),
    }
    return profile, checks


def acceleration_contract(value: Any) -> dict[str, Any]:
    config = parse_json_object(value, "data model acceleration")
    return {
        "enabled": bool_value(config.get("enabled")),
        "earliest_time": str(config.get("earliest_time", "")),
        "cron_schedule": str(config.get("cron_schedule", "")),
        "max_time_seconds": integer(config.get("max_time")),
        "allow_old_summaries": bool_value(config.get("allow_old_summaries")),
        "schedule_priority": str(config.get("schedule_priority", "")),
    }


def summary_contract(content: dict[str, Any]) -> dict[str, Any]:
    error_text = str(content.get("summary.last_error", "")).strip()
    return {
        "available": bool(content),
        "complete": bool_value(content.get("summary.complete")),
        "in_progress": bool_value(content.get("summary.is_inprogress")),
        "bucket_count": integer(content.get("summary.buckets")),
        "size_bytes": integer(content.get("summary.size")),
        "time_range_seconds": integer(content.get("summary.time_range")),
        "latest_run_duration_seconds": round(
            numeric(content.get("summary.latest_run_duration")), 3
        ),
        "last_error_present": bool(error_text),
    }


def sensitive_findings(value: Any, path: str = "$.") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            child = f"{path}{key}"
            if lowered in FORBIDDEN_KEYS:
                findings.append(f"forbidden key at {child}")
            findings.extend(sensitive_findings(item, child + "."))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(sensitive_findings(item, f"{path}[{index}]."))
    elif isinstance(value, str):
        if IPV4.search(value):
            findings.append(f"IP address at {path}")
        if SECRET_TEXT.search(value):
            findings.append(f"credential assignment at {path}")
        if URI_TEXT.search(value):
            findings.append(f"URI at {path}")
    return findings


def run_aggregate(
    client: SplunkAudit, search: str, earliest_time: str
) -> tuple[dict[str, Any], int]:
    started = time.monotonic()
    job = client.run_search_job(
        search, earliest_time=earliest_time, latest_time="now", timeout=180
    )
    duration_ms = max(1, round((time.monotonic() - started) * 1000))
    rows = job.get("results", [])
    return (rows[0] if rows else {}), duration_ms


def get_summary(client: SplunkAudit) -> dict[str, Any]:
    try:
        # The aggregate endpoint can retain stale zero metrics immediately after
        # a native rebuild. Fetching its detail resource first refreshes Splunk's
        # own bucket inventory; no bucket paths or server identities are retained.
        client.get(f"{SUMMARY_PATH}/details", count=0)
        result = entries(client.get(SUMMARY_PATH))
    except HTTPError as error:
        if error.code == 404:
            return {}
        raise
    return result[0].get("content", {}) if result else {}


def is_public_evidence_path(path: Path) -> bool:
    resolved = path.resolve()
    return resolved.suffix.lower() == ".json" and resolved.is_relative_to(PUBLIC_EVIDENCE_ROOT)


def write_public_evidence(report: dict[str, Any], output: Path) -> None:
    if not is_public_evidence_path(output):
        raise ValueError("public evidence output must be a JSON file under artifacts/public")
    if report.get("overall_pass") is not True:
        raise ValueError("failed qualification is not publishable")
    findings = sensitive_findings(report)
    if findings:
        raise ValueError("public evidence sanitization failed: " + "; ".join(findings[:5]))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def build_acceptance(
    *,
    server_version: str,
    app_version: str,
    health: str,
    kv_status: str,
    definition_checks: dict[str, bool],
    acl: dict[str, Any],
    acceleration: dict[str, Any],
    summary: dict[str, Any],
    raw_count: int,
    summary_count: int,
    latest_delta_seconds: float,
    freshness_age_seconds: float,
    freshness_sla_seconds: int,
    cim_installed: bool,
    es_installed: bool,
) -> dict[str, bool]:
    perms = acl.get("perms", {}) if isinstance(acl.get("perms"), dict) else {}
    return {
        "splunk_10_2_1": server_version == "10.2.1",
        "application_0_7_3": app_version == "0.7.3",
        "platform_health_green": health.lower() == "green",
        "kv_store_ready": kv_status.lower() == "ready",
        "live_definition_contract": bool(definition_checks)
        and all(definition_checks.values()),
        "global_read_admin_write_acl": acl.get("sharing") == "global"
        and perms.get("read") == ["*"]
        and perms.get("write") == ["admin"],
        "acceleration_policy_active": acceleration.get("enabled") is True
        and acceleration.get("earliest_time") == "-7d"
        and acceleration.get("allow_old_summaries") is False,
        "summary_complete_and_error_free": summary.get("complete") is True
        and summary.get("in_progress") is False
        and summary.get("last_error_present") is False
        and integer(summary.get("bucket_count")) > 0,
        "summariesonly_t_nonempty": summary_count > 0,
        "raw_summary_count_parity": raw_count > 0 and raw_count == summary_count,
        "raw_summary_latest_parity": latest_delta_seconds <= 1.0,
        "summary_freshness_within_sla": 0 <= freshness_age_seconds <= freshness_sla_seconds,
        "custom_non_cim_boundary_honest": not cim_installed and not es_installed,
    }


def collect(
    client: SplunkAudit,
    *,
    expected_app_version: str,
    earliest_time: str,
    freshness_sla_seconds: int,
    max_wait_seconds: int,
    poll_seconds: float,
    package_path: Path | None,
    now: Callable[[], float] = time.time,
) -> dict[str, Any]:
    server_entries = entries(client.get("/services/server/info"))
    if len(server_entries) != 1:
        raise ValueError("Splunk server information is unavailable")
    server = server_entries[0].get("content", {})
    server_version = str(server.get("version", ""))
    kv_status = str(server.get("kvStoreStatus", ""))
    health_entries = entries(client.get("/services/server/health/splunkd"))
    health = str(health_entries[0].get("content", {}).get("health", "")) if health_entries else ""

    app_entries = entries(client.get("/services/apps/local", count=0))
    app_versions = {
        str(item.get("name")): str(item.get("content", {}).get("version", ""))
        for item in app_entries
    }
    app_version = app_versions.get(APP_ID, "")
    cim_installed = NATIVE_CIM_APP in app_versions
    es_installed = ENTERPRISE_SECURITY_APP in app_versions

    model_entries = entries(
        client.get(f"/servicesNS/nobody/{APP_ID}/datamodel/model/{MODEL_ID}")
    )
    if len(model_entries) != 1:
        raise ValueError("custom data model endpoint is unavailable")
    model_entry = model_entries[0]
    model_content = model_entry.get("content", {})
    acl = model_entry.get("acl", {}) if isinstance(model_entry.get("acl"), dict) else {}
    acceleration = acceleration_contract(model_content.get("acceleration"))

    command_row, definition_duration_ms = run_aggregate(
        client, f"| datamodel {MODEL_ID}", "0"
    )
    definition = parse_json_object(command_row.get("_raw"), "live data model command output")
    definition_profile, definition_checks = model_contract(definition)
    root_constraint = _root_object(definition).get("constraints", [{}])[0].get("search", "")
    if not definition_checks["root_constraint_is_streaming_event_constraint"]:
        raise ValueError("root data model constraint is unsafe for direct parity validation")

    raw_search = (
        f"search {root_constraint} "
        "| stats count as event_count latest(_time) as latest_epoch"
    )
    summary_search = (
        "| tstats summariesonly=t count as event_count latest(_time) as latest_epoch "
        f"from datamodel={MODEL_ID}.{ROOT_DATASET} "
        f"where nodename={ROOT_DATASET}"
    )
    deadline = time.monotonic() + max_wait_seconds
    raw_row: dict[str, Any] = {}
    summary_row: dict[str, Any] = {}
    raw_duration_ms = 0
    summary_duration_ms = 0
    summary_state: dict[str, Any] = {}
    while True:
        raw_row, raw_duration_ms = run_aggregate(client, raw_search, earliest_time)
        summary_row, summary_duration_ms = run_aggregate(client, summary_search, earliest_time)
        summary_state = summary_contract(get_summary(client))
        raw_count = integer(raw_row.get("event_count"))
        summary_count = integer(summary_row.get("event_count"))
        raw_latest = numeric(raw_row.get("latest_epoch"))
        summary_latest = numeric(summary_row.get("latest_epoch"))
        if (
            raw_count > 0
            and raw_count == summary_count
            and raw_latest > 0
            and abs(raw_latest - summary_latest) <= 1.0
            and summary_state.get("complete") is True
            and summary_state.get("in_progress") is False
            and summary_state.get("last_error_present") is False
            and integer(summary_state.get("bucket_count")) > 0
        ):
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(poll_seconds)

    raw_count = integer(raw_row.get("event_count"))
    summary_count = integer(summary_row.get("event_count"))
    raw_latest = numeric(raw_row.get("latest_epoch"))
    summary_latest = numeric(summary_row.get("latest_epoch"))
    latest_delta_seconds = abs(raw_latest - summary_latest) if raw_latest and summary_latest else 10**9
    freshness_age_seconds = max(0.0, now() - summary_latest) if summary_latest else 10**9
    parity_percent = round(100.0 * summary_count / raw_count, 2) if raw_count else 0.0
    acceptance = build_acceptance(
        server_version=server_version,
        app_version=app_version,
        health=health,
        kv_status=kv_status,
        definition_checks=definition_checks,
        acl=acl,
        acceleration=acceleration,
        summary=summary_state,
        raw_count=raw_count,
        summary_count=summary_count,
        latest_delta_seconds=latest_delta_seconds,
        freshness_age_seconds=freshness_age_seconds,
        freshness_sla_seconds=freshness_sla_seconds,
        cim_installed=cim_installed,
        es_installed=es_installed,
    )
    package_sha256 = None
    if package_path is not None:
        package_sha256 = hashlib.sha256(package_path.read_bytes()).hexdigest()
    report = {
        "schema_version": 1,
        "generated_at": utc_z(),
        "scope": "isolated-lab-custom-security-telemetry-data-model",
        "classification": {
            "custom_data_model": True,
            "native_cim_data_model": False,
            "splunk_sa_cim_installed": cim_installed,
            "enterprise_security_app_installed": es_installed,
            "claim_boundary": "custom non-CIM qualification only",
        },
        "environment": {
            "splunk_version": server_version,
            "product_type": str(server.get("product_type", "")),
            "application_version": app_version,
            "expected_application_version": expected_app_version,
            "splunkd_health": health.lower(),
            "kv_store_status": kv_status.lower(),
            "topology": "standalone",
        },
        "definition": {
            **definition_profile,
            "loaded_through_datamodel_command": True,
            "command_duration_ms": definition_duration_ms,
            "checks": definition_checks,
        },
        "access_control": {
            "owner": str(acl.get("owner", "")),
            "application": str(acl.get("app", "")),
            "sharing": str(acl.get("sharing", "")),
            "read_roles": list(acl.get("perms", {}).get("read", [])),
            "write_roles": list(acl.get("perms", {}).get("write", [])),
        },
        "acceleration": {
            **acceleration,
            "summary": summary_state,
            "mode_qualified": "tstats summariesonly=t",
        },
        "data_quality": {
            "window": earliest_time,
            "raw_event_count": raw_count,
            "summary_event_count": summary_count,
            "count_delta": summary_count - raw_count,
            "parity_percent": parity_percent,
            "latest_delta_seconds": round(latest_delta_seconds, 3),
            "summary_freshness_age_seconds": round(freshness_age_seconds, 3),
            "freshness_sla_seconds": freshness_sla_seconds,
            "raw_aggregate_duration_ms": raw_duration_ms,
            "summary_aggregate_duration_ms": summary_duration_ms,
            "aggregate_result_sha256": canonical_hash(
                {
                    "raw_count": raw_count,
                    "summary_count": summary_count,
                    "latest_delta_seconds": round(latest_delta_seconds, 3),
                }
            ),
        },
        "package": {
            "sha256": package_sha256,
            "matches_live_version": app_version == expected_app_version,
        },
        "acceptance": acceptance,
        "overall_pass": all(acceptance.values()),
        "limitations": [
            "The model is custom and does not represent native Splunk CIM or Enterprise Security content.",
            "The live qualification uses synthetic lab telemetry and does not evidence production data volume.",
            "The standalone topology proves the knowledge-object and acceleration lifecycle, not distributed DMA behavior.",
        ],
        "security": {
            "credentials_written": False,
            "endpoint_persisted": False,
            "private_addresses_persisted": False,
            "raw_events_persisted": False,
            "event_sources_persisted": False,
            "search_text_persisted": False,
        },
    }
    findings = sensitive_findings(report)
    if findings:
        raise ValueError("public evidence sanitization failed: " + "; ".join(findings[:5]))
    if package_sha256 is not None and not SHA256.fullmatch(package_sha256):
        raise ValueError("application package hash is invalid")
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", required=True)
    parser.add_argument("--connect-ip")
    parser.add_argument("--transport", choices=("management", "web"), default="web")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--ca-bundle", type=Path, required=True)
    parser.add_argument("--expected-app-version", default="0.7.3")
    parser.add_argument("--earliest-time", default="-60m")
    parser.add_argument("--freshness-sla-seconds", type=int, default=900)
    parser.add_argument("--max-wait-seconds", type=int, default=360)
    parser.add_argument("--poll-seconds", type=float, default=10.0)
    parser.add_argument("--app-package", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.max_wait_seconds < 0 or args.poll_seconds <= 0:
        print("ERROR: wait settings must be positive", file=sys.stderr)
        return 2
    if args.app_package is not None and not args.app_package.is_file():
        print("ERROR: application package is unavailable", file=sys.stderr)
        return 2
    if not is_public_evidence_path(args.output):
        print("ERROR: public evidence output must be a JSON file under artifacts/public", file=sys.stderr)
        return 2
    password = os.environ.pop("SPLUNK_PASSWORD", "")
    if not password:
        password = getpass.getpass(f"Splunk password for {args.username}: ")
    original_getaddrinfo = socket.getaddrinfo
    uri_host = args.uri.split("://", 1)[-1].split(":", 1)[0].split("/", 1)[0]

    def pinned(host, port, family=0, type=0, proto=0, flags=0):
        target = args.connect_ip if args.connect_ip and host == uri_host else host
        return original_getaddrinfo(target, port, family, type, proto, flags)

    socket.getaddrinfo = pinned
    try:
        client = SplunkAudit(
            args.uri,
            args.username,
            password,
            transport=args.transport,
            verify_tls=True,
            ca_bundle=str(args.ca_bundle.resolve()),
        )
        report = collect(
            client,
            expected_app_version=args.expected_app_version,
            earliest_time=args.earliest_time,
            freshness_sla_seconds=args.freshness_sla_seconds,
            max_wait_seconds=args.max_wait_seconds,
            poll_seconds=args.poll_seconds,
            package_path=args.app_package,
        )
    except (HTTPError, URLError, TimeoutError, ValueError, IndexError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: custom data model qualification failed: {error}", file=sys.stderr)
        return 1
    finally:
        password = ""
        socket.getaddrinfo = original_getaddrinfo

    passed = sum(1 for value in report["acceptance"].values() if value)
    total = len(report["acceptance"])
    try:
        write_public_evidence(report, args.output)
    except ValueError as error:
        print(f"ERROR: custom data model evidence was not published: {error}", file=sys.stderr)
        print(
            f"SUMMARY: model={MODEL_DISPLAY_NAME} / acceptance={passed}/{total} / "
            f"parity={report['data_quality']['parity_percent']:.2f}% / pass=False"
        )
        return 1
    print(f"OK: public custom data model evidence written to {args.output}")
    print(
        f"SUMMARY: model={MODEL_DISPLAY_NAME} / acceptance={passed}/{total} / "
        f"parity={report['data_quality']['parity_percent']:.2f}% / pass={report['overall_pass']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
