#!/usr/bin/env python3
"""Execute every Simple XML dashboard query and report fatal search errors."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from xml.etree import ElementTree

from validate_live_detections import SplunkClient


def normalized_query(query: str, replay_id: str) -> str:
    query = query.replace("$replay$", replay_id).strip()
    if query.startswith("|") or query.lower().startswith("search "):
        return query
    return "search " + query


def validate(
    client: SplunkClient,
    views_dir: Path,
    replay_id: str,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for view in sorted(views_dir.glob("*.xml")):
        root = ElementTree.parse(view).getroot()
        for ordinal, element in enumerate(root.findall(".//query"), start=1):
            query = normalized_query(element.text or "", replay_id)
            try:
                payload = client.request(
                    "/services/search/jobs",
                    method="POST",
                    params={
                        "search": query,
                        "exec_mode": "oneshot",
                        "earliest_time": "0",
                        "latest_time": "now",
                        "output_mode": "json",
                    },
                )
                messages = [
                    {
                        "type": str(message.get("type", "")),
                        "text": str(message.get("text", ""))[:300],
                    }
                    for message in payload.get("messages", [])
                    if str(message.get("type", "")).upper() in {"FATAL", "ERROR"}
                ]
                results.append(
                    {
                        "view": view.stem,
                        "query": ordinal,
                        "status": "failed" if messages else "passed",
                        "result_count": len(payload.get("results", [])),
                        "messages": messages,
                    }
                )
            except HTTPError as error:
                results.append(
                    {
                        "view": view.stem,
                        "query": ordinal,
                        "status": "failed",
                        "http_status": error.code,
                        "messages": [
                            {
                                "type": "HTTP",
                                "text": error.read().decode("utf-8", errors="replace")[:300],
                            }
                        ],
                    }
                )
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--views", type=Path, required=True)
    parser.add_argument("--replay-id", default="campaign-20260806-a")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    password = os.environ.pop("SPLUNK_PASSWORD", "")
    if not password:
        password = getpass.getpass(f"Splunk password for {args.username}: ")
    try:
        client = SplunkClient(args.uri, args.username, password)
        validations = validate(client, args.views, args.replay_id)
    except (URLError, TimeoutError, ValueError, ElementTree.ParseError) as error:
        print(f"ERROR: dashboard validation failed: {error}", file=sys.stderr)
        return 1
    finally:
        password = ""

    failures = [item for item in validations if item["status"] != "passed"]
    summary = {
        "queries": len(validations),
        "passed": len(validations) - len(failures),
        "failed": len(failures),
        "views": len({str(item["view"]) for item in validations}),
    }
    report = {
        "schema_version": 1,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "queries": validations,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"OK: views={summary['views']} queries={summary['queries']} "
        f"passed={summary['passed']} failed={summary['failed']} report={args.output}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
