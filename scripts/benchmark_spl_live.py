#!/usr/bin/env python3
"""Benchmark equivalent SPL variants on a live Splunk lab.

Credentials are read interactively.  The public report contains only aggregate
job metrics and result fingerprints; it excludes the URI, SID, host names and
event contents.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

from audit_splunk_live import SplunkAudit, entries, select


BENCHMARKS = {
    "indexed_sourcetype_constraint": {
        "purpose": "Move an indexed sourcetype constraint into the base search.",
        "baseline": (
            "search index=winlab earliest=0 "
            "| eval keep=if(sourcetype=\"WinEventLog:Security\",1,0) "
            "| where keep=1 | stats count as event_count"
        ),
        "optimized": (
            "search index=winlab sourcetype=\"WinEventLog:Security\" earliest=0 "
            "| stats count as event_count"
        ),
    }
}


def fingerprint(results: list[dict[str, Any]]) -> str:
    canonical = json.dumps(results, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def summarize(runs: list[dict[str, Any]]) -> dict[str, Any]:
    durations = [number(run["metrics"].get("runDuration")) for run in runs]
    scans = [number(run["metrics"].get("scanCount")) for run in runs]
    events = [number(run["metrics"].get("eventCount")) for run in runs]
    return {
        "iterations": len(runs),
        "median_run_duration_seconds": round(statistics.median(durations), 6),
        "min_run_duration_seconds": round(min(durations), 6),
        "max_run_duration_seconds": round(max(durations), 6),
        "median_scan_count": int(statistics.median(scans)),
        "median_event_count": int(statistics.median(events)),
        "result_sha256": runs[0]["result_sha256"],
        "all_runs_completed": all(
            str(run["metrics"].get("dispatchState", "")).upper() == "DONE"
            and not bool(run["metrics"].get("isFailed"))
            for run in runs
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", required=True)
    parser.add_argument("--transport", choices=("management", "web"), default="management")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--ca-bundle")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.iterations < 3:
        print("ERROR: at least three iterations are required", file=sys.stderr)
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
        server = select(server_entry.get("content", {}), ("version", "build", "product_type"))
        reports: list[dict[str, Any]] = []
        for benchmark_id, definition in BENCHMARKS.items():
            runs: dict[str, list[dict[str, Any]]] = {"baseline": [], "optimized": []}
            for iteration in range(args.iterations):
                order = ("baseline", "optimized") if iteration % 2 == 0 else ("optimized", "baseline")
                for variant in order:
                    job = client.run_search_job(definition[variant])
                    runs[variant].append(
                        {
                            "iteration": iteration + 1,
                            "metrics": job["metrics"],
                            "result_sha256": fingerprint(job["results"]),
                            "result_count": len(job["results"]),
                        }
                    )

            baseline = summarize(runs["baseline"])
            optimized = summarize(runs["optimized"])
            equivalent = baseline["result_sha256"] == optimized["result_sha256"]
            baseline_duration = number(baseline["median_run_duration_seconds"])
            optimized_duration = number(optimized["median_run_duration_seconds"])
            baseline_scan = number(baseline["median_scan_count"])
            optimized_scan = number(optimized["median_scan_count"])
            reports.append(
                {
                    "id": benchmark_id,
                    "purpose": definition["purpose"],
                    "searches": {
                        "baseline": definition["baseline"],
                        "optimized": definition["optimized"],
                    },
                    "baseline": baseline,
                    "optimized": optimized,
                    "result_equivalence": equivalent,
                    "duration_reduction_percent": round(
                        (1 - optimized_duration / baseline_duration) * 100, 2
                    )
                    if baseline_duration
                    else None,
                    "scan_reduction_percent": round(
                        (1 - optimized_scan / baseline_scan) * 100, 2
                    )
                    if baseline_scan
                    else None,
                    "acceptance": {
                        "equivalent_results": equivalent,
                        "all_runs_completed": baseline["all_runs_completed"]
                        and optimized["all_runs_completed"],
                        "scan_count_not_increased": optimized_scan <= baseline_scan,
                    },
                }
            )

        report = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": "isolated-lab-aggregate-metrics",
            "environment": server,
            "method": {
                "iterations_per_variant": args.iterations,
                "execution_order": "alternating AB/BA to limit warm-cache bias",
                "results": "SHA-256 fingerprints of aggregate result rows",
                "excluded": ["credentials", "URI", "search SID", "host names", "raw events"],
            },
            "benchmarks": reports,
            "overall_pass": all(all(item["acceptance"].values()) for item in reports),
        }
    except (HTTPError, URLError, TimeoutError, ValueError, IndexError) as error:
        print(f"ERROR: benchmark failed: {error}", file=sys.stderr)
        return 1
    finally:
        password = ""

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"OK: benchmark written to {args.output}")
    for item in report["benchmarks"]:
        print(
            f"SUMMARY: {item['id']} / equivalent={item['result_equivalence']} / "
            f"scan_reduction={item['scan_reduction_percent']}% / "
            f"duration_reduction={item['duration_reduction_percent']}%"
        )
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
