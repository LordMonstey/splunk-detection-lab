#!/usr/bin/env python3
"""Replay the synthetic Linux contract and validate live Splunk normalization."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

from audit_splunk_live import SplunkAudit, entries, select


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "datasets" / "linux"
APP_ID = "splunk-detection-lab"
SOURCES = {
    "auditd": (DATASET_DIR / "auditd.log", "linux:auditd"),
    "journald": (DATASET_DIR / "journald.ndjson", "linux:journald"),
    "rsyslog": (DATASET_DIR / "rsyslog.log", "linux:rsyslog"),
}


def number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def run_results(client: SplunkAudit, search: str) -> list[dict[str, Any]]:
    return client.run_search_job(search).get("results", [])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", required=True)
    parser.add_argument("--transport", choices=("management", "web"), default="management")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--ca-bundle")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--batch-id", default="20260807")
    parser.add_argument("--expected-app-version", default="0.7.2")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    expected_counts = {
        sourcetype: sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
        for path, sourcetype in SOURCES.values()
    }
    expected_total = sum(expected_counts.values())
    dataset_hashes = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path, _ in SOURCES.values()
    }
    source_prefix = f"synthetic://linux-onboarding/{args.batch_id}"
    source_filter = f'source="{source_prefix}/*"'

    password = os.environ.pop("SPLUNK_PASSWORD", "")
    if not password:
        password = getpass.getpass(f"Splunk password for {args.username}: ")
    try:
        client = SplunkAudit(
            args.uri,
            args.username,
            password,
            transport=args.transport,
            verify_tls=not args.insecure,
            ca_bundle=args.ca_bundle,
        )
        server_entry = entries(client.get("/services/server/info"))[0]
        server = select(server_entry.get("content", {}), ("version", "build", "product_type"))
        app_entry = entries(client.get(f"/services/apps/local/{APP_ID}"))[0]
        app_version = str(app_entry.get("content", {}).get("version", ""))

        index_names = {
            str(entry.get("name")) for entry in entries(client.get("/services/data/indexes", count=0))
        }
        if "os_linux" not in index_names:
            client.post(
                "/services/data/indexes",
                {
                    "name": "os_linux",
                    "datatype": "event",
                    "frozenTimePeriodInSecs": "7776000",
                    "maxTotalDataSizeMB": "5000",
                },
            )

        existing_rows = run_results(
            client,
            f"search index=os_linux {source_filter} earliest=0 | stats count as event_count",
        )
        existing_count = int(number(existing_rows[0].get("event_count"))) if existing_rows else 0
        if existing_count not in {0, expected_total}:
            raise ValueError(
                f"batch {args.batch_id} is partial ({existing_count}/{expected_total}); use a new batch id"
            )
        replayed = existing_count == 0
        if replayed:
            for label, (path, sourcetype) in SOURCES.items():
                payload = path.read_bytes()
                if not payload.endswith(b"\n"):
                    payload += b"\n"
                client.post_bytes(
                    "/services/receivers/simple",
                    payload,
                    content_type="text/plain; charset=utf-8",
                    index="os_linux",
                    sourcetype=sourcetype,
                    host="lab-linux-01",
                    source=f"{source_prefix}/{label}",
                )

        deadline = time.monotonic() + 60
        inventory_rows: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            inventory_rows = run_results(
                client,
                f"search index=os_linux {source_filter} earliest=0 "
                "| stats count as event_count min(_time) as first_event max(_time) as last_event "
                "latest(_indextime) as latest_ingest by sourcetype | sort sourcetype",
            )
            if sum(int(number(row.get("event_count"))) for row in inventory_rows) >= expected_total:
                break
            time.sleep(1)

        completeness_rows = run_results(
            client,
            f"search index=os_linux {source_filter} earliest=0 "
            "| eval cim_scope=case("
            "audit_type=\"USER_AUTH\" OR app=\"sshd\", \"Authentication\", "
            "audit_type IN (\"USER_MGMT\",\"CONFIG_CHANGE\") OR app IN (\"useradd\",\"sudo\"), \"Change\", "
            "audit_type=\"SYSCALL\", \"Endpoint.Processes\", "
            "isnotnull(service), \"Endpoint.Services\") "
            "| eval required_ok=case("
            "cim_scope=\"Authentication\", if(isnotnull(action) AND action!=\"unknown\" AND isnotnull(app) AND app!=\"unknown\" AND isnotnull(dest) AND dest!=\"unknown\" AND isnotnull(src) AND isnotnull(user) AND user!=\"unknown\",1,0), "
            "cim_scope=\"Change\", if(isnotnull(action) AND action!=\"unknown\" AND isnotnull(change_type) AND change_type!=\"unknown\" AND isnotnull(command) AND command!=\"unknown\" AND isnotnull(dest) AND dest!=\"unknown\" AND isnotnull(object_id) AND isnotnull(status) AND status!=\"unknown\" AND isnotnull(user) AND user!=\"unknown\",1,0), "
            "cim_scope=\"Endpoint.Processes\", if(isnotnull(action) AND action!=\"unknown\" AND isnotnull(dest) AND dest!=\"unknown\" AND isnotnull(process_id) AND isnotnull(process_path) AND process_path!=\"unknown\" AND isnotnull(user) AND user!=\"unknown\",1,0), "
            "cim_scope=\"Endpoint.Services\", if(isnotnull(dest) AND dest!=\"unknown\" AND isnotnull(service) AND service!=\"unknown\" AND isnotnull(service_path) AND service_path!=\"unknown\" AND isnotnull(status) AND status!=\"unknown\" AND isnotnull(user) AND user!=\"unknown\",1,0), "
            "true(), 0) "
            "| stats count as events sum(required_ok) as complete by cim_scope "
            "| eval completeness_percent=round(100*complete/events,2) | sort cim_scope",
        )
        duplicate_rows = run_results(
            client,
            f"search index=os_linux {source_filter} earliest=0 "
            "| eval event_fingerprint=sha256(_raw) | stats count by event_fingerprint "
            "| where count>1 | stats count as duplicate_groups sum(count) as duplicate_events",
        )
        quality_rows = run_results(
            client,
            f"search index=os_linux {source_filter} earliest=0 "
            "| eval commit_age_seconds=now()-_indextime, raw_length=len(_raw) "
            "| stats perc95(commit_age_seconds) as p95_commit_age_seconds "
            "max(commit_age_seconds) as max_commit_age_seconds max(raw_length) as max_raw_length "
            "count(eval(raw_length>=20000)) as truncation_risk_events",
        )
        quality = quality_rows[0] if quality_rows else {}

        eventtype_queries = {
            "Authentication": "eventtype=linux_authentication",
            "Change.account": "eventtype=linux_account_change",
            "Change.audit": "eventtype=linux_audit_change",
            "Change.privileged": "eventtype=linux_privileged_endpoint_change",
            "Endpoint.Processes": "eventtype=linux_process_start",
            "Endpoint.Services": "eventtype=linux_service_state",
        }
        eventtype_counts = {}
        for name, constraint in eventtype_queries.items():
            rows = run_results(
                client,
                f"search index=os_linux {source_filter} {constraint} earliest=0 "
                "| stats count as event_count",
            )
            eventtype_counts[name] = int(number(rows[0].get("event_count"))) if rows else 0

        observed_counts = {
            str(row.get("sourcetype")): int(number(row.get("event_count")))
            for row in inventory_rows
        }
        completeness = {
            str(row.get("cim_scope")): {
                "events": int(number(row.get("events"))),
                "complete": int(number(row.get("complete"))),
                "completeness_percent": number(row.get("completeness_percent")),
            }
            for row in completeness_rows
            if row.get("cim_scope")
        }
        duplicate_events = int(number(duplicate_rows[0].get("duplicate_events"))) if duplicate_rows else 0
        required_scopes = {"Authentication", "Change", "Endpoint.Processes", "Endpoint.Services"}
        acceptance = {
            "app_version_matches": app_version == args.expected_app_version,
            "expected_event_total": sum(observed_counts.values()) == expected_total,
            "sourcetype_counts_match": observed_counts == expected_counts,
            "four_cim_scopes_present": set(completeness) == required_scopes,
            "cim_completeness_at_least_95_percent": bool(completeness)
            and all(item["completeness_percent"] >= 95 for item in completeness.values()),
            "eventtypes_operational": all(count > 0 for count in eventtype_counts.values()),
            "no_duplicate_events": duplicate_events == 0,
            "no_truncation_risk": int(number(quality.get("truncation_risk_events"))) == 0,
            "recent_index_commit": number(quality.get("p95_commit_age_seconds")) <= 120,
        }
        report = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": "isolated-lab-synthetic-linux-onboarding",
            "environment": {**server, "application_version": app_version},
            "batch": {
                "id": args.batch_id,
                "replayed_during_run": replayed,
                "dataset_sha256": dataset_hashes,
                "expected_events": expected_total,
            },
            "inventory": {
                "expected_by_sourcetype": expected_counts,
                "observed_by_sourcetype": observed_counts,
            },
            "cim_field_contract": completeness,
            "eventtype_counts": eventtype_counts,
            "quality": {
                "duplicate_events": duplicate_events,
                "p95_commit_age_seconds": round(number(quality.get("p95_commit_age_seconds")), 3),
                "max_commit_age_seconds": round(number(quality.get("max_commit_age_seconds")), 3),
                "max_raw_length": int(number(quality.get("max_raw_length"))),
                "truncation_risk_events": int(number(quality.get("truncation_risk_events"))),
            },
            "acceptance": acceptance,
            "overall_pass": all(acceptance.values()),
            "limitations": [
                "Events are synthetic and prove the parsing contract, not a production source volume.",
                "The host label is fictional and raw events are excluded from this public artifact.",
                "Native CIM data-model acceleration requires the compatible CIM Add-on on the target search tier.",
            ],
            "security": {
                "credentials_written": False,
                "management_uri_persisted": False,
                "raw_events_persisted_in_artifact": False,
                "private_addresses_persisted": False,
            },
        }
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:1000]
        print(f"ERROR: Linux replay HTTP {error.code}: {detail}", file=sys.stderr)
        return 1
    except (URLError, TimeoutError, ValueError, IndexError, OSError) as error:
        print(f"ERROR: Linux replay failed: {error}", file=sys.stderr)
        return 1
    finally:
        password = ""

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"OK: Linux onboarding evidence written to {args.output}")
    print(
        f"SUMMARY: events={sum(observed_counts.values())}/{expected_total} / "
        f"scopes={len(completeness)}/4 / pass={report['overall_pass']}"
    )
    if not report["overall_pass"]:
        failed = [name for name, passed in acceptance.items() if not passed]
        print("FAILED CHECKS: " + ", ".join(failed))
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
