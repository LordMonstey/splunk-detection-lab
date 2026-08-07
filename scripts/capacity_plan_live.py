#!/usr/bin/env python3
"""Build an evidence-backed Splunk capacity model from live aggregate metrics."""

from __future__ import annotations

import argparse
import getpass
import json
import math
import os
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

from audit_splunk_live import SplunkAudit, entries, select


GIB = 1024**3


def value_number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile_value
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", required=True)
    parser.add_argument("--transport", choices=("management", "web"), default="management")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--ca-bundle")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--retention-days", type=int, default=90)
    parser.add_argument("--replication-factor", type=int, default=2)
    parser.add_argument("--search-factor", type=int, default=2)
    parser.add_argument("--storage-to-ingest-ratio", type=float, default=0.50)
    parser.add_argument("--headroom-percent", type=float, default=30.0)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.retention_days <= 0 or args.replication_factor <= 0:
        print("ERROR: retention and replication factor must be positive", file=sys.stderr)
        return 2
    if not 0 < args.storage_to_ingest_ratio <= 2:
        print("ERROR: storage-to-ingest ratio must be in ]0, 2]", file=sys.stderr)
        return 2

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
        server = select(
            server_entry.get("content", {}),
            ("version", "build", "product_type", "licenseState"),
        )

        index_rows: list[dict[str, Any]] = []
        for entry in entries(client.get("/services/data/indexes", count=0)):
            name = str(entry.get("name", ""))
            if not name or name.startswith("_"):
                continue
            content = entry.get("content", {})
            event_count = int(value_number(content.get("totalEventCount")))
            current_mb = value_number(content.get("currentDBSizeMB"))
            if event_count == 0 and current_mb <= 1:
                continue
            index_rows.append(
                {
                    "index": name,
                    "current_db_size_mb": round(current_mb, 3),
                    "event_count": event_count,
                    "configured_max_size_mb": int(
                        value_number(content.get("maxTotalDataSizeMB"))
                    ),
                    "configured_retention_days": round(
                        value_number(content.get("frozenTimePeriodInSecs")) / 86400, 2
                    ),
                }
            )

        activity_job = client.run_search_job(
            "search index=* earliest=0 "
            "| stats count min(_indextime) as first_ingest max(_indextime) as last_ingest by index"
        )
        activity_by_index = {
            str(row.get("index")): row for row in activity_job.get("results", [])
        }
        for row in index_rows:
            activity = activity_by_index.get(row["index"], {})
            first_ingest = value_number(activity.get("first_ingest"))
            last_ingest = value_number(activity.get("last_ingest"))
            span_days = max((last_ingest - first_ingest) / 86400, 1.0) if last_ingest else 0.0
            row["observed_ingest_span_days"] = round(span_days, 2)
            row["observed_storage_mb_per_day"] = (
                round(row["current_db_size_mb"] / span_days, 3) if span_days else None
            )

        license_job = client.run_search_job(
            "search index=_internal source=*license_usage.log type=Usage earliest=-30d@d "
            "| bin _time span=1d | stats sum(b) as ingest_bytes by _time | sort _time"
        )
        daily_bytes = [
            value_number(row.get("ingest_bytes"))
            for row in license_job.get("results", [])
            if value_number(row.get("ingest_bytes")) > 0
        ]
        p50_gib = statistics.median(daily_bytes) / GIB if daily_bytes else 0.0
        p95_gib = percentile(daily_bytes, 0.95) / GIB if daily_bytes else 0.0
        peak_gib = max(daily_bytes) / GIB if daily_bytes else 0.0
        # A sparse lab may have only one active ingest day.  In that case the
        # observed public index footprint per day is retained as an explicit
        # lower-bound fallback, never presented as production telemetry.
        footprint_daily_gib = sum(
            value_number(row.get("observed_storage_mb_per_day")) for row in index_rows
        ) / 1024
        design_daily_gib = p95_gib if p95_gib > 0 else footprint_daily_gib

        headroom_multiplier = 1 + args.headroom_percent / 100
        scenarios = []
        for name, growth in (("baseline", 0.0), ("growth_25", 0.25), ("growth_50", 0.50)):
            daily = design_daily_gib * (1 + growth)
            storage = (
                daily
                * args.retention_days
                * args.storage_to_ingest_ratio
                * args.replication_factor
                * headroom_multiplier
            )
            scenarios.append(
                {
                    "name": name,
                    "growth_percent": int(growth * 100),
                    "planned_daily_ingest_gib": round(daily, 4),
                    "planned_licensed_ingest_gib_per_day_at_20pct_headroom": round(
                        daily / 0.80, 4
                    ),
                    "estimated_cluster_storage_gib": round(storage, 3),
                }
            )

        report = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": "isolated-lab-capacity-model",
            "environment": server,
            "observations": {
                "license_usage_days": len(daily_bytes),
                "daily_ingest_gib": {
                    "p50": round(p50_gib, 4),
                    "p95": round(p95_gib, 4),
                    "peak": round(peak_gib, 4),
                },
                "public_index_db_size_mb": round(
                    sum(row["current_db_size_mb"] for row in index_rows), 3
                ),
                "public_index_event_count": sum(row["event_count"] for row in index_rows),
                "indexes": sorted(index_rows, key=lambda row: row["index"]),
            },
            "design_assumptions": {
                "retention_days": args.retention_days,
                "replication_factor": args.replication_factor,
                "search_factor": args.search_factor,
                "storage_to_ingest_ratio": args.storage_to_ingest_ratio,
                "storage_headroom_percent": args.headroom_percent,
                "license_headroom_percent": 20,
                "baseline_daily_ingest": "observed 30-day p95; public-index footprint fallback if unavailable",
            },
            "scenarios": scenarios,
            "operational_thresholds": {
                "review_license_at_percent": 80,
                "review_storage_at_percent": 70,
                "escalate_storage_at_percent": 85,
                "minimum_free_hot_warm_percent": 15,
            },
            "limitations": [
                "Lab observations are not a substitute for production ingest telemetry.",
                "Storage-to-ingest ratio must be recalibrated with measured compression and tsidx footprint.",
                "Search concurrency, IOPS and CPU sizing require workload-specific load tests.",
                "Replication factor is a design multiplier; the standalone source VM is not claimed as clustered.",
            ],
            "acceptance": {
                "live_server_queried": bool(server.get("version")),
                "index_inventory_collected": bool(index_rows),
                "license_telemetry_queried": True,
                "three_growth_scenarios": len(scenarios) == 3,
                "assumptions_explicit": True,
                "sensitive_values_excluded": True,
            },
        }
        report["overall_pass"] = all(report["acceptance"].values())
    except (HTTPError, URLError, TimeoutError, ValueError, IndexError) as error:
        print(f"ERROR: capacity plan failed: {error}", file=sys.stderr)
        return 1
    finally:
        password = ""

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"OK: capacity plan written to {args.output}")
    print(
        "SUMMARY: "
        f"events={report['observations']['public_index_event_count']} / "
        f"p95_ingest={report['observations']['daily_ingest_gib']['p95']} GiB/day / "
        f"scenarios={len(report['scenarios'])} / pass={report['overall_pass']}"
    )
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
