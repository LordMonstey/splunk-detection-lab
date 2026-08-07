#!/usr/bin/env python3
"""Deploy a versioned Splunk app package and record sanitized smoke-test evidence."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

from audit_splunk_live import SplunkAudit, entries, select


APP_ID = "splunk-detection-lab"
SMOKE_VIEW = "splunk_es_admin_operations_center"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_archive(path: Path, expected_version: str) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"package not found: {path}")
    with tarfile.open(path, "r:gz") as bundle:
        members = {member.name: member for member in bundle.getmembers()}
        app_conf_name = f"{APP_ID}/default/app.conf"
        if app_conf_name not in members:
            raise ValueError(f"package is missing {app_conf_name}")
        extracted = bundle.extractfile(members[app_conf_name])
        if extracted is None:
            raise ValueError("package app.conf cannot be read")
        app_conf = extracted.read().decode("utf-8")
        if f"version = {expected_version}" not in app_conf:
            raise ValueError("package version does not match --expected-version")
        unsafe = [
            name
            for name in members
            if name.startswith("/")
            or ".." in Path(name).parts
            or (name != APP_ID and not name.startswith(f"{APP_ID}/"))
        ]
        if unsafe:
            raise ValueError(f"unsafe package members detected: {unsafe[:3]}")
        return {
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
            "member_count": len(members),
            "safe_paths": True,
        }


def app_state(client: SplunkAudit) -> dict[str, Any]:
    try:
        app_entries = entries(client.get(f"/services/apps/local/{APP_ID}"))
    except HTTPError as error:
        if error.code == 404:
            return {"installed": False}
        raise
    if not app_entries:
        return {"installed": False}
    entry = app_entries[0]
    return {
        "installed": True,
        **select(
            entry.get("content", {}),
            ("version", "disabled", "configured", "visible", "label"),
        ),
    }


def smoke_tests(client: SplunkAudit, expected_version: str) -> dict[str, Any]:
    state = app_state(client)
    view_available = False
    try:
        view_available = bool(
            entries(
                client.get(
                    f"/servicesNS/nobody/{APP_ID}/data/ui/views/{SMOKE_VIEW}",
                )
            )
        )
    except HTTPError:
        pass
    health = entries(client.get("/services/server/health/splunkd"))[0].get("content", {})
    search_job = client.run_search_job(
        "| rest /services/server/info | head 1 | stats count as server_count"
    )
    result_count = int(search_job.get("results", [{}])[0].get("server_count", 0))
    tests = {
        "version_matches": str(state.get("version")) == expected_version,
        "app_enabled": state.get("disabled") is False,
        "app_configured": state.get("configured") is True,
        "admin_dashboard_available": view_available,
        "splunkd_health_green": str(health.get("health", "")).lower() == "green",
        "search_execution_ok": result_count == 1,
    }
    return {"tests": tests, "all_passed": all(tests.values()), "state": state}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", required=True)
    parser.add_argument("--transport", choices=("management", "web"), default="management")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--ca-bundle")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--package-url", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--phase", choices=("candidate", "rollback", "final"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        package = validate_archive(args.archive, args.expected_version)
    except (OSError, tarfile.TarError, ValueError) as error:
        print(f"ERROR: package preflight failed: {error}", file=sys.stderr)
        return 2

    password = os.environ.pop("SPLUNK_PASSWORD", "")
    if not password:
        password = getpass.getpass(f"Splunk password for {args.username}: ")
    started = time.monotonic()
    try:
        client = SplunkAudit(
            args.uri,
            args.username,
            password,
            transport=args.transport,
            verify_tls=not args.insecure,
            ca_bundle=args.ca_bundle,
        )
        before = app_state(client)
        install_response = client.post(
            "/services/apps/local",
            {
                "name": args.package_url,
                "filename": "true",
                "update": "true" if before.get("installed") else "false",
            },
        )
        install_messages = [
            {"type": item.get("type"), "text": item.get("text")}
            for item in install_response.get("messages", [])
        ]

        deadline = time.monotonic() + 120
        current = app_state(client)
        while str(current.get("version")) != args.expected_version and time.monotonic() < deadline:
            time.sleep(1)
            current = app_state(client)
        smoke = smoke_tests(client, args.expected_version)
        elapsed = round(time.monotonic() - started, 3)
        report = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": "isolated-lab-change-lifecycle",
            "application": APP_ID,
            "phase": args.phase,
            "package": package,
            "before": before,
            "target_version": args.expected_version,
            "after": smoke["state"],
            "install_messages": install_messages,
            "elapsed_seconds": elapsed,
            "smoke_tests": smoke["tests"],
            "overall_pass": smoke["all_passed"],
            "security": {
                "credentials_written": False,
                "package_url_persisted": False,
                "management_uri_persisted": False,
                "raw_events_collected": False,
            },
        }
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:1000]
        print(f"ERROR: deployment HTTP {error.code}: {detail}", file=sys.stderr)
        return 1
    except (URLError, TimeoutError, ValueError, IndexError) as error:
        print(f"ERROR: deployment failed: {error}", file=sys.stderr)
        return 1
    finally:
        password = ""

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"OK: deployment evidence written to {args.output}")
    print(
        f"SUMMARY: phase={args.phase} / before={before.get('version')} / "
        f"after={report['after'].get('version')} / pass={report['overall_pass']}"
    )
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
