#!/usr/bin/env python3
"""Validate the MCO/CIM periodic-reporting contract without contacting Splunk."""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
LOOKUP_NAME = "mco_cim_periodic_history"
COLLECTION_NAME = "mco_cim_periodic_history"
DASHBOARD_NAME = "periodic_mco_cim_reporting"
SEARCH_CONTRACT = {
    "report_mco_daily_aggregate": {
        "family": "mco_daily",
        "cron": "15 1 * * *",
        "earliest": "-1d@d",
        "latest": "@d",
        "threshold_profile": "mco-v1",
    },
    "report_cim_weekly_aggregate": {
        "family": "cim_weekly",
        "cron": "45 1 * * 1",
        "earliest": "-1w@w",
        "latest": "@w",
        "threshold_profile": "cim-process-v1",
    },
}
STORED_FIELDS = (
    "_key",
    "schema_version",
    "report_key",
    "report_family",
    "period_start",
    "period_end",
    "generated_at",
    "metric_id",
    "metric_value",
    "metric_unit",
    "status",
    "sample_state",
    "threshold_profile",
)
FORBIDDEN_STORED_FIELDS = {
    "host",
    "source",
    "sourcetype",
    "index",
    "user",
    "uri",
    "sid",
    "search_id",
    "event",
    "raw",
    "_raw",
}
IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
PRIVATE_IPV4 = (
    rf"(?<![A-Za-z0-9.])(?:10(?:\.{IPV4_OCTET}){{3}}|"
    rf"127(?:\.{IPV4_OCTET}){{3}}|"
    rf"192\.168(?:\.{IPV4_OCTET}){{2}}|"
    rf"172\.(?:1[6-9]|2\d|3[01])(?:\.{IPV4_OCTET}){{2}})"
    rf"(?![A-Za-z0-9.-])"
)
SECRET_OR_ENDPOINT = re.compile(
    rf"(?i)(?:password|passwd|secret|token|authorization|private[_ -]?key|"
    rf"https?://(?!example\.invalid)|{PRIVATE_IPV4})"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_conf(path: Path) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    with path.open(encoding="utf-8") as handle:
        parser.read_file(handle)
    return parser


def normalized_stanza(parser: configparser.RawConfigParser, name: str) -> dict[str, str]:
    if not parser.has_section(name):
        return {}
    return {key.lower(): value.strip() for key, value in parser.items(name)}


def metric_contract(schema: dict[str, Any], family: str) -> set[str]:
    for rule in schema.get("allOf", []):
        condition = rule.get("if", {}).get("properties", {}).get("report_family", {})
        if condition.get("const") != family:
            continue
        return set(
            rule.get("then", {})
            .get("properties", {})
            .get("metric_id", {})
            .get("enum", [])
        )
    return set()


def extract_metric_ids(search: str, family: str) -> set[str]:
    prefix = "ingestion.|scheduler.|queues." if family == "mco_daily" else "cim."
    quoted = set(re.findall(r'"([a-z][a-z0-9_.]+)"', search))
    if family == "mco_daily":
        return {
            value
            for value in quoted
            if value.startswith(("ingestion.", "scheduler.", "queues."))
        }
    return {value for value in quoted if value.startswith(prefix)}


def extract_final_fields(search: str) -> tuple[str, ...]:
    match = re.search(
        rf"\|\s*fields\s+([^|]+?)\s*\|\s*outputlookup\s+"
        rf"append=true\s+key_field=_key\s+{re.escape(LOOKUP_NAME)}\s*$",
        search,
    )
    if not match:
        return ()
    return tuple(match.group(1).split())


def validate_repository(root: Path = ROOT) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    conf_root = root / "conf" / "splunk"
    searches_path = conf_root / "local" / "savedsearches.conf"
    collections_path = conf_root / "default" / "collections.conf"
    transforms_path = conf_root / "default" / "transforms.conf"
    dashboard_path = (
        conf_root / "local" / "data" / "ui" / "views" / f"{DASHBOARD_NAME}.xml"
    )
    nav_path = conf_root / "local" / "data" / "ui" / "nav" / "default.xml"
    schema_path = root / "artifacts" / "templates" / "periodic-reporting-row.schema.json"
    required_files = (
        searches_path,
        collections_path,
        transforms_path,
        dashboard_path,
        nav_path,
        schema_path,
    )
    for path in required_files:
        if not path.is_file():
            errors.append(f"missing required file: {path.relative_to(root)}")
    if errors:
        return errors, {}

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema_required = tuple(schema.get("required", []))
    if schema.get("additionalProperties") is not False:
        errors.append("row schema must reject additional properties")
    if schema_required != STORED_FIELDS:
        errors.append("row schema required fields do not match the V1 stored-field order")
    schema_properties = schema.get("properties", {})
    if set(schema_properties) != set(STORED_FIELDS):
        errors.append("row schema properties do not exactly match the V1 contract")
    if FORBIDDEN_STORED_FIELDS & set(schema_properties):
        errors.append("row schema exposes a forbidden identifying or raw field")

    collections = read_conf(collections_path)
    collection = normalized_stanza(collections, COLLECTION_NAME)
    expected_types = {
        "schema_version": "number",
        "report_key": "string",
        "report_family": "string",
        "period_start": "time",
        "period_end": "time",
        "generated_at": "time",
        "metric_id": "string",
        "metric_value": "number",
        "metric_unit": "string",
        "status": "string",
        "sample_state": "string",
        "threshold_profile": "string",
    }
    if collection.get("enforcetypes", "").lower() != "true":
        errors.append("KV Store collection must enforce field types")
    observed_types = {
        key.removeprefix("field."): value
        for key, value in collection.items()
        if key.startswith("field.")
    }
    if observed_types != expected_types:
        errors.append("collections.conf field types do not exactly match the V1 contract")

    transforms = read_conf(transforms_path)
    lookup = normalized_stanza(transforms, LOOKUP_NAME)
    if lookup.get("external_type") != "kvstore":
        errors.append("lookup definition is not KV Store-backed")
    if lookup.get("collection") != COLLECTION_NAME:
        errors.append("lookup definition points to the wrong collection")
    lookup_fields = tuple(
        item.strip() for item in lookup.get("fields_list", "").split(",") if item.strip()
    )
    if lookup_fields != STORED_FIELDS:
        errors.append("lookup fields_list does not exactly match the V1 field order")

    saved_searches = read_conf(searches_path)
    schedules: dict[str, str] = {}
    metrics_by_family: dict[str, list[str]] = {}
    for name, contract in SEARCH_CONTRACT.items():
        stanza = normalized_stanza(saved_searches, name)
        if not stanza:
            errors.append(f"missing saved search: {name}")
            continue
        schedules[name] = stanza.get("cron_schedule", "")
        for setting, expected in (
            ("disabled", "0"),
            ("enablesched", "1"),
            ("cron_schedule", contract["cron"]),
            ("schedule_window", "auto"),
            ("dispatch.earliest_time", contract["earliest"]),
            ("dispatch.latest_time", contract["latest"]),
        ):
            if stanza.get(setting) != expected:
                errors.append(f"[{name}] {setting} must be {expected!r}")
        search = stanza.get("search", "")
        if "&gt;" in search or "&lt;" in search:
            errors.append(f"[{name}] contains XML entities in SPL")
        if f'report_family="{contract["family"]}"' not in search:
            errors.append(f"[{name}] does not stamp its report family")
        if f'threshold_profile="{contract["threshold_profile"]}"' not in search:
            errors.append(f"[{name}] does not stamp its threshold profile")
        if "_key=sha256(report_key)" not in search:
            errors.append(f"[{name}] does not derive a deterministic KV key")
        if extract_final_fields(search) != STORED_FIELDS:
            errors.append(f"[{name}] final output fields or keyed upsert are invalid")
        expected_metrics = metric_contract(schema, contract["family"])
        observed_metrics = extract_metric_ids(search, contract["family"])
        if observed_metrics != expected_metrics:
            errors.append(f"[{name}] metric set does not match the JSON schema")
        metrics_by_family[contract["family"]] = sorted(observed_metrics)

    if len(set(schedules.values())) != len(SEARCH_CONTRACT):
        errors.append("daily and weekly collectors must not share a schedule")

    dashboard = ElementTree.parse(dashboard_path).getroot()
    dashboard_queries = [
        (element.text or "").strip() for element in dashboard.findall(".//query")
    ]
    if not dashboard_queries:
        errors.append("periodic-reporting dashboard has no searches")
    for query in dashboard_queries:
        if not query.startswith(f"| inputlookup {LOOKUP_NAME}"):
            errors.append("dashboard query bypasses the sanitized aggregate")
            break
        if re.search(r"(?i)\b(?:index|host|source|sourcetype|_raw)\s*=", query):
            errors.append("dashboard query accesses a raw or identifying data field")
            break
    dashboard_text = dashboard_path.read_text(encoding="utf-8")
    if "BASELINE SEULEMENT" not in dashboard_text:
        errors.append("dashboard does not label the one-period baseline state")
    trend_queries = [query for query in dashboard_queries if "timechart" in query]
    if not trend_queries or any(
        "eventstats dc(period_start) as periods" not in query or "where periods>=2" not in query
        for query in trend_queries
    ):
        errors.append("every trend panel must require at least two observed periods")

    nav = ElementTree.parse(nav_path).getroot()
    nav_views = {element.get("name") for element in nav.findall(".//view")}
    if DASHBOARD_NAME not in nav_views:
        errors.append("periodic-reporting dashboard is absent from app navigation")

    checks = {
        "required_files_present": all(path.is_file() for path in required_files),
        "schema_closed_and_versioned": (
            schema.get("additionalProperties") is False
            and schema.get("properties", {}).get("schema_version", {}).get("const") == 1
        ),
        "kv_types_enforced": collection.get("enforcetypes", "").lower() == "true",
        "lookup_is_kv_store": lookup.get("external_type") == "kvstore",
        "collectors_enabled": all(
            normalized_stanza(saved_searches, name).get("disabled") == "0"
            for name in SEARCH_CONTRACT
        ),
        "keyed_upsert_present": all(
            "key_field=_key" in normalized_stanza(saved_searches, name).get("search", "")
            for name in SEARCH_CONTRACT
        ),
        "non_overlapping_schedules": len(set(schedules.values())) == len(SEARCH_CONTRACT),
        "dashboard_aggregate_only": bool(dashboard_queries)
        and all(query.startswith(f"| inputlookup {LOOKUP_NAME}") for query in dashboard_queries),
        "trend_requires_two_periods": bool(trend_queries)
        and all("where periods>=2" in query for query in trend_queries),
        "forbidden_stored_fields_absent": not (
            FORBIDDEN_STORED_FIELDS & set(schema_properties)
        ),
    }
    evidence = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_type": "offline-design-qualification",
        "scope": "periodic-mco-cim-reporting-scaffold",
        "status": "PASS" if not errors and all(checks.values()) else "FAIL",
        "live_execution": "NOT_PERFORMED",
        "historical_periods_observed": 0,
        "trend_claimed": False,
        "storage": {
            "type": "kvstore_lookup",
            "collection": COLLECTION_NAME,
            "enforce_types": True,
            "schema_version": 1,
            "stored_field_count": len(STORED_FIELDS),
        },
        "collectors": [
            {
                "name": name,
                "family": contract["family"],
                "cron": contract["cron"],
                "closed_period": {
                    "earliest": contract["earliest"],
                    "latest": contract["latest"],
                },
                "metric_count": len(metrics_by_family.get(contract["family"], [])),
                "idempotent_keyed_upsert": True,
            }
            for name, contract in SEARCH_CONTRACT.items()
        ],
        "dashboard": {
            "name": DASHBOARD_NAME,
            "query_count": len(dashboard_queries),
            "aggregate_only": True,
            "trend_minimum_periods": 2,
            "baseline_labelled": True,
        },
        "checks": checks,
        "source_hashes": {
            path.relative_to(root).as_posix(): sha256(path) for path in required_files
        },
        "security": {
            "credentials_included": False,
            "management_endpoint_included": False,
            "private_addresses_included": False,
            "raw_events_included": False,
            "host_or_source_names_stored": False,
        },
        "limitations": [
            "This artifact qualifies the offline scaffold only.",
            "No live collector execution or historical trend is claimed.",
            "Late-dataset counts cover datasets observed during the closed period only.",
        ],
    }
    canonical = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
    if SECRET_OR_ENDPOINT.search(canonical):
        errors.append("generated evidence contains a secret or non-example endpoint marker")
        evidence["status"] = "FAIL"
    return errors, evidence


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        errors, evidence = validate_repository(ROOT)
    except (OSError, ValueError, configparser.Error, json.JSONDecodeError) as error:
        print(f"ERROR: periodic-reporting validation failed: {error}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"OK: wrote {args.output}")
    print(f"OK: periodic-reporting scaffold passed {len(evidence['checks'])} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
