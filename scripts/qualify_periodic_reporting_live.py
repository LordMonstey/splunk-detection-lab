#!/usr/bin/env python3
"""Run the first MCO/CIM aggregate cycle and emit sanitized live evidence.

The script dispatches only the two reporting searches, then validates the
resulting KV Store through aggregate counts. Credentials, endpoints, search
identifiers and metric values are never written to the evidence file.
"""

from __future__ import annotations

import argparse
import configparser
import getpass
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from xml.etree import ElementTree

from audit_splunk_live import SplunkAudit, entries


ROOT = Path(__file__).resolve().parents[1]
APP_ID = "splunk-detection-lab"
LOOKUP_NAME = "mco_cim_periodic_history"
COLLECTION_NAME = "mco_cim_periodic_history"
SAVED_SEARCHES = (
    "report_mco_daily_aggregate",
    "report_cim_weekly_aggregate",
)
SEARCH_CONTRACT = {
    "report_mco_daily_aggregate": {
        "cron_schedule": "15 1 * * *",
        "dispatch.earliest_time": "-1d@d",
        "dispatch.latest_time": "@d",
    },
    "report_cim_weekly_aggregate": {
        "cron_schedule": "45 1 * * 1",
        "dispatch.earliest_time": "-1w@w",
        "dispatch.latest_time": "@w",
    },
}
KV_FIELD_CONTRACT = {
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
SCHEMA_PATH = ROOT / "artifacts" / "templates" / "periodic-reporting-row.schema.json"
PRIVATE_MARKER = re.compile(
    r"(?i)(?:https?://(?!example\.invalid)|"
    r"\b(?:10(?:\.\d{1,3}){3}|127(?:\.\d{1,3}){3}|"
    r"192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])"
    r"(?:\.\d{1,3}){2})\b|"
    r"(?:password|passwd|secret|token|authorization|private[_ -]?key)\s*[:=])"
)


def schema_sha256() -> str:
    return hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes"}


def integer(value: Any) -> int:
    return int(float(value or 0))


def current_app_version() -> str:
    parser = configparser.RawConfigParser(interpolation=None)
    parser.read(ROOT / "conf" / "splunk" / "default" / "app.conf", encoding="utf-8")
    return parser.get("launcher", "version")


def single_entry(client: SplunkAudit, path: str) -> dict[str, Any]:
    found = entries(client.get(path))
    return found[0] if found else {}


def acl_contract(entry: dict[str, Any], app: str) -> dict[str, Any]:
    acl = entry.get("acl", entry.get("content", {}).get("eai:acl", {}))
    if not isinstance(acl, dict):
        acl = {}
    perms = acl.get("perms", {}) if isinstance(acl.get("perms"), dict) else {}
    read = sorted(str(value) for value in perms.get("read", []) or [])
    write = sorted(str(value) for value in perms.get("write", []) or [])
    sharing = str(acl.get("sharing", ""))
    policy_passed = (
        str(acl.get("app", "")) == app
        and str(acl.get("owner", "")) == "nobody"
        and sharing in {"app", "global"}
        and read == ["*"]
        and write == ["admin"]
    )
    return {
        "app_context_match": str(acl.get("app", "")) == app,
        "owner_is_nobody": str(acl.get("owner", "")) == "nobody",
        "sharing": sharing,
        "read_all": read == ["*"],
        "write_admin_only": write == ["admin"],
        "policy_passed": policy_passed,
    }


def saved_search_state(client: SplunkAudit, app: str, name: str) -> dict[str, Any]:
    path = (
        f"/servicesNS/nobody/{quote(app, safe='')}/saved/searches/"
        f"{quote(name, safe='')}"
    )
    entry = single_entry(client, path)
    if not entry:
        raise ValueError(f"saved search is unavailable: {name}")
    content = entry.get("content", {})
    expected = SEARCH_CONTRACT.get(name, {})
    deployed_search = str(content.get("search", ""))
    schedule_match = all(str(content.get(key, "")) == value for key, value in expected.items())
    search_contract_match = (
        "_key=sha256(report_key)" in deployed_search
        and f"outputlookup append=true key_field=_key {LOOKUP_NAME}" in deployed_search
        and "| fields _key schema_version report_key report_family" in deployed_search
    )
    return {
        "name": name,
        "disabled": bool_value(content.get("disabled")),
        "scheduled": bool_value(content.get("is_scheduled", content.get("enableSched"))),
        "cron_schedule": str(content.get("cron_schedule", "")),
        "closed_period": {
            "earliest": str(content.get("dispatch.earliest_time", "")),
            "latest": str(content.get("dispatch.latest_time", "")),
        },
        "next_run_present": bool(content.get("next_scheduled_time")),
        "schedule_match": schedule_match,
        "search_contract_match": search_contract_match,
        "acl": acl_contract(entry, app),
    }


def dispatch_saved_search(
    client: SplunkAudit,
    app: str,
    name: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    state = saved_search_state(client, app, name)
    if state["disabled"]:
        raise ValueError(f"saved search is disabled: {name}")
    if not state["scheduled"]:
        raise ValueError(f"saved search is not scheduled: {name}")
    if not state["schedule_match"] or not state["search_contract_match"]:
        raise ValueError(f"saved search contract drifted: {name}")
    if not state["acl"]["policy_passed"]:
        raise ValueError(f"saved search ACL drifted: {name}")
    namespace = f"/servicesNS/nobody/{quote(app, safe='')}"
    payload = client.post(
        f"{namespace}/saved/searches/{quote(name, safe='')}/dispatch",
        {"trigger_actions": "0"},
    )
    sid = str(payload.get("sid", ""))
    if not sid:
        raise ValueError(f"Splunk did not return a search identifier for {name}")
    started = time.monotonic()
    content: dict[str, Any] = {}
    try:
        deadline = started + timeout_seconds
        while time.monotonic() < deadline:
            job = entries(client.get(f"/services/search/jobs/{quote(sid, safe='')}"))
            if not job:
                raise ValueError(f"dispatched search is unavailable: {name}")
            content = job[0].get("content", {})
            if bool_value(content.get("isDone")):
                break
            time.sleep(0.35)
        else:
            raise TimeoutError(f"saved search did not finish in {timeout_seconds}s: {name}")
        dispatch_state = str(content.get("dispatchState", "UNKNOWN")).upper()
        if bool_value(content.get("isFailed")) or dispatch_state not in {"DONE", "FINALIZING"}:
            raise ValueError(f"saved search ended in {dispatch_state}: {name}")
        fatal_messages = [
            message
            for message in content.get("messages", []) or []
            if isinstance(message, dict)
            and str(message.get("type", "")).upper() in {"FATAL", "ERROR"}
        ]
        if fatal_messages:
            raise ValueError(f"saved search returned an error message: {name}")
        return {
            "name": name,
            "dispatch_state": dispatch_state,
            "duration_seconds": round(float(content.get("runDuration", 0) or 0), 3),
            "result_count": integer(content.get("resultCount")),
        }
    finally:
        try:
            client.delete(f"/services/search/jobs/{quote(sid, safe='')}")
        except HTTPError:
            pass


def kv_store_ready(client: SplunkAudit, app: str) -> dict[str, bool]:
    server = entries(client.get("/services/server/info"))
    if not server:
        raise ValueError("server information is unavailable")
    kv_status = str(server[0].get("content", {}).get("kvStoreStatus", "")).lower()
    collection_path = (
        f"/servicesNS/nobody/{quote(app, safe='')}/storage/collections/config/"
        f"{quote(COLLECTION_NAME, safe='')}"
    )
    collection_exists = bool(entries(client.get(collection_path)))
    return {
        "service_ready": kv_status == "ready",
        "collection_configured": collection_exists,
    }


def inspect_runtime_contract(
    client: SplunkAudit,
    app: str,
    expected_app_version: str,
) -> dict[str, Any]:
    server_entry = single_entry(client, "/services/server/info")
    health_entry = single_entry(client, "/services/server/health/splunkd")
    app_entry = single_entry(client, f"/services/apps/local/{quote(app, safe='')}")
    if not server_entry or not health_entry or not app_entry:
        raise ValueError("platform or application identity is unavailable")
    server = server_entry.get("content", {})
    health = health_entry.get("content", {})
    application = app_entry.get("content", {})

    collectors = [saved_search_state(client, app, name) for name in SAVED_SEARCHES]

    collection_entry = single_entry(
        client,
        f"/servicesNS/nobody/{quote(app, safe='')}/storage/collections/config/"
        f"{quote(COLLECTION_NAME, safe='')}",
    )
    collection = collection_entry.get("content", {})
    observed_types = {
        key.removeprefix("field."): str(value)
        for key, value in collection.items()
        if key.startswith("field.")
    }
    collection_schema_match = (
        bool(collection_entry)
        and bool_value(collection.get("enforceTypes"))
        and observed_types == KV_FIELD_CONTRACT
    )

    lookup_entry = single_entry(
        client,
        f"/servicesNS/nobody/{quote(app, safe='')}/configs/conf-transforms/"
        f"{quote(LOOKUP_NAME, safe='')}",
    )
    lookup = lookup_entry.get("content", {})
    lookup_fields = {
        field.strip()
        for field in str(lookup.get("fields_list", "")).split(",")
        if field.strip()
    }
    lookup_contract_match = (
        bool(lookup_entry)
        and str(lookup.get("external_type", "")) == "kvstore"
        and str(lookup.get("collection", "")) == COLLECTION_NAME
        and lookup_fields == {"_key", *KV_FIELD_CONTRACT}
    )

    dashboard_entry = single_entry(
        client,
        f"/servicesNS/nobody/{quote(app, safe='')}/data/ui/views/"
        "periodic_mco_cim_reporting",
    )
    dashboard_xml = str(dashboard_entry.get("content", {}).get("eai:data", ""))
    dashboard_query_count = 0
    dashboard_aggregate_only = False
    try:
        dashboard_root = ElementTree.fromstring(dashboard_xml)
        queries = [
            (query.text or "").strip() for query in dashboard_root.findall(".//query")
        ]
        dashboard_query_count = len(queries)
        dashboard_aggregate_only = bool(queries) and all(
            query.startswith(f"| inputlookup {LOOKUP_NAME}") for query in queries
        )
    except ElementTree.ParseError:
        dashboard_aggregate_only = False

    acl_by_object = {
        "collection": acl_contract(collection_entry, app),
        "lookup": acl_contract(lookup_entry, app),
        "dashboard": acl_contract(dashboard_entry, app),
    }
    acl_by_object.update({item["name"]: item["acl"] for item in collectors})
    acl_policy_passed = all(value["policy_passed"] for value in acl_by_object.values())
    collector_contract_passed = all(
        not item["disabled"]
        and item["scheduled"]
        and item["next_run_present"]
        and item["schedule_match"]
        and item["search_contract_match"]
        and item["acl"]["policy_passed"]
        for item in collectors
    )
    contract = {
        "platform": {
            "version": str(server.get("version", "")),
            "health_green": str(health.get("health", "")).lower() == "green",
            "kv_store_ready": str(server.get("kvStoreStatus", "")).lower() == "ready",
        },
        "application": {
            "expected_version": expected_app_version,
            "observed_version": str(application.get("version", "")),
            "version_match": str(application.get("version", "")) == expected_app_version,
            "enabled": not bool_value(application.get("disabled")),
            "configured": bool_value(application.get("configured")),
        },
        "collectors": collectors,
        "collection": {
            "configured": bool(collection_entry),
            "typed_schema_match": collection_schema_match,
            "acl_policy_passed": acl_by_object["collection"]["policy_passed"],
        },
        "lookup": {
            "configured": bool(lookup_entry),
            "contract_match": lookup_contract_match,
            "acl_policy_passed": acl_by_object["lookup"]["policy_passed"],
        },
        "dashboard": {
            "configured": bool(dashboard_entry),
            "query_count": dashboard_query_count,
            "aggregate_only": dashboard_aggregate_only,
            "acl_policy_passed": acl_by_object["dashboard"]["policy_passed"],
        },
        "acl": {
            "objects_checked": len(acl_by_object),
            "read_scope": "all-roles",
            "write_scope": "admin-only",
            "policy_passed": acl_policy_passed,
        },
    }
    contract["all_passed"] = (
        contract["platform"]["health_green"]
        and contract["platform"]["kv_store_ready"]
        and contract["application"]["version_match"]
        and contract["application"]["enabled"]
        and contract["application"]["configured"]
        and collector_contract_passed
        and collection_schema_match
        and lookup_contract_match
        and dashboard_aggregate_only
        and acl_policy_passed
    )
    return contract


def aggregate_validation(client: SplunkAudit) -> dict[str, int]:
    search = (
        f"| inputlookup {LOOKUP_NAME} "
        "| eval row_valid=if(schema_version=1 AND match(_key,\"^[a-f0-9]{64}$\") "
        "AND report_key=report_family.\":\".strftime(period_start,\"%Y-%m-%d\").\":\".metric_id "
        "AND period_end>period_start AND generated_at>=period_end "
        "AND in(report_family,\"mco_daily\",\"cim_weekly\") "
        "AND in(metric_unit,\"count\",\"percent\") "
        "AND in(status,\"GREEN\",\"WATCH\",\"ACTION\",\"NO_DATA\") "
        "AND in(sample_state,\"OBSERVED\",\"NO_DATA\"),1,0) "
        "| stats count as row_count sum(row_valid) as valid_rows dc(report_key) as unique_keys "
        "dc(report_family) as family_count "
        "dc(eval(if(report_family=\"mco_daily\",period_start,null()))) as mco_daily_periods "
        "dc(eval(if(report_family=\"cim_weekly\",period_start,null()))) as cim_weekly_periods "
        "| eval invalid_rows=row_count-valid_rows, duplicate_keys=row_count-unique_keys "
        "| fields row_count valid_rows invalid_rows duplicate_keys family_count "
        "mco_daily_periods cim_weekly_periods"
    )
    result = client.run_search_job(search, earliest_time="0", latest_time="now")
    rows = result.get("results", [])
    if len(rows) != 1:
        raise ValueError("aggregate validation did not return one summary row")
    fields = (
        "row_count",
        "valid_rows",
        "invalid_rows",
        "duplicate_keys",
        "family_count",
        "mco_daily_periods",
        "cim_weekly_periods",
    )
    return {field: integer(rows[0].get(field)) for field in fields}


def build_evidence(
    dispatches: list[dict[str, Any]],
    preflight: dict[str, Any],
    postflight: dict[str, Any],
    aggregate_before: dict[str, int],
    aggregate_first: dict[str, int],
    aggregate_replay: dict[str, int],
    *,
    tls_verified: bool,
) -> dict[str, Any]:
    first_dispatches = [item for item in dispatches if item.get("cycle") == "first"]
    replay_dispatches = [item for item in dispatches if item.get("cycle") == "replay"]
    stable_fields = (
        "row_count",
        "valid_rows",
        "invalid_rows",
        "duplicate_keys",
        "family_count",
        "mco_daily_periods",
        "cim_weekly_periods",
    )
    replay_stable = all(
        aggregate_first[field] == aggregate_replay[field] for field in stable_fields
    )
    trend_eligible = (
        aggregate_replay["mco_daily_periods"] >= 2
        and aggregate_replay["cim_weekly_periods"] >= 2
    )
    checks = {
        "tls_chain_and_hostname_verified": tls_verified,
        "preflight_contract_passed": bool(preflight.get("all_passed")),
        "first_cycle_completed": len(first_dispatches) == 2
        and all(
            item["dispatch_state"] in {"DONE", "FINALIZING"}
            for item in first_dispatches
        ),
        "idempotence_replay_completed": len(replay_dispatches) == 2
        and all(
            item["dispatch_state"] in {"DONE", "FINALIZING"}
            for item in replay_dispatches
        ),
        "postflight_contract_passed": bool(postflight.get("all_passed")),
        "kv_store_preserved": preflight.get("platform", {}).get("kv_store_ready") is True
        and postflight.get("platform", {}).get("kv_store_ready") is True,
        "scheduler_contract_verified": all(
            item["scheduled"]
            and item["next_run_present"]
            and item["schedule_match"]
            and item["search_contract_match"]
            for item in postflight.get("collectors", [])
        ),
        "acl_policy_verified": postflight.get("acl", {}).get("policy_passed") is True,
        "dashboard_aggregate_only": postflight.get("dashboard", {}).get("aggregate_only")
        is True,
        "both_families_present": aggregate_replay["family_count"] == 2,
        "minimum_expected_rows_present": aggregate_replay["row_count"] >= 16,
        "schema_rows_valid": aggregate_replay["invalid_rows"] == 0,
        "report_keys_unique": aggregate_replay["duplicate_keys"] == 0,
        "mco_baseline_present": aggregate_replay["mco_daily_periods"] >= 1,
        "cim_baseline_present": aggregate_replay["cim_weekly_periods"] >= 1,
        "keyed_replay_is_idempotent": replay_stable,
    }
    first_execution = aggregate_before["row_count"] == 0
    evidence = {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_type": (
            "live-aggregate-first-execution-and-idempotence"
            if first_execution
            else "live-aggregate-controlled-replay-and-idempotence"
        ),
        "scope": "periodic-mco-cim-reporting",
        "application": APP_ID,
        "status": "PASS" if all(checks.values()) else "FAIL",
        "runtime_contract": postflight,
        "preservation": {
            "tls_verified": tls_verified,
            "kv_ready_before": preflight.get("platform", {}).get("kv_store_ready") is True,
            "kv_ready_after": postflight.get("platform", {}).get("kv_store_ready") is True,
            "platform_health_green_after": postflight.get("platform", {}).get("health_green")
            is True,
        },
        "dispatches": dispatches,
        "aggregate_execution": {
            "before": aggregate_before,
            "after_first_cycle": aggregate_first,
            "after_idempotence_replay": aggregate_replay,
            "first_execution_from_empty_collection": first_execution,
            "keyed_replay_stable": replay_stable,
        },
        "historical_periods_observed": {
            "mco_daily": aggregate_replay["mco_daily_periods"],
            "cim_weekly": aggregate_replay["cim_weekly_periods"],
        },
        "trend_eligible": trend_eligible,
        "trend_claimed": False,
        "row_schema_sha256": schema_sha256(),
        "checks": checks,
        "security": {
            "credentials_included": False,
            "management_endpoint_included": False,
            "search_identifiers_included": False,
            "raw_events_included": False,
            "metric_values_included": False,
            "host_source_or_index_names_included": False,
        },
        "limitations": [
            "Only aggregate row counts, object contracts and execution metadata are published.",
            "No historical trend is claimed by this controlled qualification.",
            "Late-dataset counts cover datasets observed during the closed period only.",
        ],
    }
    if PRIVATE_MARKER.search(json.dumps(evidence, sort_keys=True)):
        raise ValueError("sanitized evidence contains a private marker")
    return evidence


def qualify(
    client: SplunkAudit,
    app: str,
    timeout_seconds: int,
    *,
    expected_app_version: str,
    tls_verified: bool,
) -> dict[str, Any]:
    preflight = inspect_runtime_contract(client, app, expected_app_version)
    if not preflight["all_passed"]:
        raise ValueError("periodic-reporting preflight contract failed")
    aggregate_before = aggregate_validation(client)
    first_dispatches = [
        {
            **dispatch_saved_search(client, app, name, timeout_seconds),
            "cycle": "first",
        }
        for name in SAVED_SEARCHES
    ]
    aggregate_first = aggregate_validation(client)
    replay_dispatches = [
        {
            **dispatch_saved_search(client, app, name, timeout_seconds),
            "cycle": "replay",
        }
        for name in SAVED_SEARCHES
    ]
    aggregate_replay = aggregate_validation(client)
    postflight = inspect_runtime_contract(client, app, expected_app_version)
    return build_evidence(
        [*first_dispatches, *replay_dispatches],
        preflight,
        postflight,
        aggregate_before,
        aggregate_first,
        aggregate_replay,
        tls_verified=tls_verified,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", required=True, help="Splunk management URI")
    parser.add_argument("--transport", choices=("management", "web"), default="management")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--app", default=APP_ID)
    parser.add_argument("--expected-app-version", default=current_app_version())
    parser.add_argument("--ca-bundle")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    password = os.environ.pop("SPLUNK_PASSWORD", "")
    if not password:
        password = getpass.getpass(f"Splunk password for {args.username}: ")
    client: SplunkAudit | None = None
    try:
        client = SplunkAudit(
            args.uri,
            args.username,
            password,
            transport=args.transport,
            verify_tls=not args.insecure,
            ca_bundle=args.ca_bundle,
        )
        evidence = qualify(
            client,
            args.app,
            args.timeout,
            expected_app_version=args.expected_app_version,
            tls_verified=not args.insecure,
        )
    except (HTTPError, URLError, TimeoutError, ValueError, IndexError, OSError) as error:
        print(f"ERROR: periodic-reporting qualification failed: {error}", file=sys.stderr)
        return 1
    finally:
        password = ""
        if client is not None:
            client.headers.pop("Authorization", None)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"OK: 2 collectors completed across {len(evidence['dispatches'])} controlled dispatches, "
        f"{evidence['aggregate_execution']['after_idempotence_replay']['row_count']} aggregate rows, "
        f"status={evidence['status']}; report={args.output}"
    )
    return 0 if evidence["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
