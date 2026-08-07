#!/usr/bin/env python3
"""Dispatch and measure detection searches without exporting event content.

The validator targets the installed Splunk app and records only execution
metadata: state, result count, scan count, duration and scheduler messages.
Credentials are read from ``SPLUNK_PASSWORD`` (or an interactive prompt) and
are never written to disk.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


class SplunkClient:
    """Minimal Splunk REST client for credential-safe validation."""

    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url.rstrip("/")
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        self.headers = {
            "Authorization": f"Basic {token}",
            "User-Agent": "splunk-detection-lab-validator/1.0",
        }
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        query = {"output_mode": "json"}
        body = None
        headers = self.headers
        if method == "GET":
            query.update(params or {})
        else:
            body = urlencode(params or {}).encode("utf-8")
            headers = {**headers, "Content-Type": "application/x-www-form-urlencoded"}
        request = Request(
            f"{self.base_url}{path}?{urlencode(query)}",
            headers=headers,
            data=body,
            method=method,
        )
        with urlopen(request, timeout=30, context=self.ssl_context) as response:
            return json.loads(response.read().decode("utf-8"))


def get_entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    entries = payload.get("entry", [])
    return entries if isinstance(entries, list) else []


def dispatch_all(
    client: SplunkClient,
    app: str,
    name_prefix: str,
    timeout_seconds: int,
) -> list[dict[str, Any]]:
    namespace = f"/servicesNS/nobody/{quote(app, safe='')}"
    saved = client.request(f"{namespace}/saved/searches", params={"count": 0})
    names = sorted(
        str(entry.get("name"))
        for entry in get_entries(saved)
        if str(entry.get("name", "")).startswith(name_prefix)
    )
    if not names:
        raise ValueError(f"No saved searches found with prefix {name_prefix!r}")

    results: list[dict[str, Any]] = []
    for name in names:
        payload = client.request(
            f"{namespace}/saved/searches/{quote(name, safe='')}/dispatch",
            method="POST",
            params={
                "dispatch.earliest_time": "0",
                "dispatch.latest_time": "now",
                "trigger_actions": "0",
            },
        )
        sid = str(payload.get("sid", ""))
        if not sid:
            raise ValueError(f"Splunk did not return a SID for {name}")
        deadline = time.monotonic() + timeout_seconds
        content: dict[str, Any] = {}
        while time.monotonic() < deadline:
            job_payload = client.request(f"/services/search/jobs/{quote(sid, safe='')}")
            entries = get_entries(job_payload)
            if entries:
                content = entries[0].get("content", {})
                if content.get("isDone"):
                    break
            time.sleep(0.35)

        timed_out = not content.get("isDone")
        dispatch_state = (
            "TIMEOUT" if timed_out else str(content.get("dispatchState", "UNKNOWN"))
        )
        messages = []
        for message in content.get("messages", []) or []:
            if isinstance(message, dict):
                messages.append(
                    {
                        "type": message.get("type"),
                        "text": str(message.get("text", ""))[:300],
                    }
                )
        results.append(
            {
                "name": name,
                "dispatch_state": dispatch_state,
                "result_count": int(content.get("resultCount", 0) or 0),
                "event_count": int(content.get("eventCount", 0) or 0),
                "scan_count": int(content.get("scanCount", 0) or 0),
                "run_duration_seconds": round(float(content.get("runDuration", 0) or 0), 3),
                "messages": messages,
            }
        )
    return sorted(results, key=lambda item: item["name"])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", required=True, help="Splunk management URI")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--app", default="splunk-detection-lab")
    parser.add_argument("--prefix", default="detect_")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    password = os.environ.pop("SPLUNK_PASSWORD", "")
    if not password:
        password = getpass.getpass(f"Splunk password for {args.username}: ")
    try:
        client = SplunkClient(args.uri, args.username, password)
        validations = dispatch_all(client, args.app, args.prefix, args.timeout)
    except (HTTPError, URLError, TimeoutError, ValueError, IndexError) as error:
        print(f"ERROR: validation failed: {error}", file=sys.stderr)
        return 1
    finally:
        password = ""

    completed = sum(item["dispatch_state"] == "DONE" for item in validations)
    positive = sum(item["result_count"] > 0 for item in validations)
    errors = sum(
        item["dispatch_state"] not in {"DONE", "FINALIZING"}
        or any(message.get("type") in {"FATAL", "ERROR"} for message in item["messages"])
        for item in validations
    )
    report = {
        "schema_version": 1,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "app": args.app,
        "time_window": {"earliest": "0", "latest": "now"},
        "summary": {
            "detections": len(validations),
            "completed": completed,
            "positive": positive,
            "errors": errors,
        },
        "detections": validations,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        f"OK: {completed}/{len(validations)} completed, "
        f"{positive} positive, {errors} error(s); report={args.output}"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
