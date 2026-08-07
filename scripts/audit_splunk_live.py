#!/usr/bin/env python3
"""Collect a credential-free administrative snapshot from a Splunk instance.

The password is read interactively and is never written to disk.  The resulting
JSON intentionally excludes raw searches, tokens, passwords and indexed event
content so it can be used as an internal audit input before public sanitisation.
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
from http.cookiejar import CookieJar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlencode
from urllib.request import HTTPSHandler, HTTPCookieProcessor, Request, build_opener, urlopen


def entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return payload.get("entry", []) if isinstance(payload, dict) else []


def select(content: dict[str, Any], names: tuple[str, ...]) -> dict[str, Any]:
    return {name: content.get(name) for name in names if name in content}


class SplunkAudit:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        transport: str = "management",
        verify_tls: bool = True,
        ca_bundle: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.transport = transport
        self.headers = {"User-Agent": "splunk-detection-lab-audit/2.0"}
        if verify_tls:
            self.ssl_context = ssl.create_default_context(cafile=ca_bundle)
        else:
            self.ssl_context = ssl._create_unverified_context()
        self.opener = None

        if transport == "management":
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            self.headers["Authorization"] = f"Basic {token}"
            return
        if transport != "web":
            raise ValueError(f"unsupported transport: {transport}")

        handlers: list[Any] = [HTTPCookieProcessor(CookieJar())]
        if self.base_url.lower().startswith("https://"):
            handlers.append(HTTPSHandler(context=self.ssl_context))
        self.opener = build_opener(*handlers)
        login_url = f"{self.base_url}/en-US/account/login"
        login_page = Request(login_url, headers=self.headers)
        with self.opener.open(login_page, timeout=20):
            pass
        cookie_jar = next(
            (handler.cookiejar for handler in handlers if isinstance(handler, HTTPCookieProcessor)),
            None,
        )
        if cookie_jar is None:
            raise ValueError("Splunk Web login did not create a cookie jar")
        cval = next((cookie.value for cookie in cookie_jar if cookie.name == "cval"), "")
        if not cval:
            raise ValueError("Splunk Web login challenge cookie is missing")
        login_body = urlencode(
            {
                "username": username,
                "password": password,
                "cval": cval,
                "return_to": "/en-US/",
            }
        ).encode("utf-8")
        login_request = Request(
            login_url,
            headers={**self.headers, "Content-Type": "application/x-www-form-urlencoded"},
            data=login_body,
            method="POST",
        )
        # Splunk Free keeps the browser on /account/login even when the Web
        # session is usable because the authentication feature is disabled.
        # The first JSON API request below is therefore the authoritative
        # authentication/authorisation check; licensed instances still fail
        # closed when the credentials are rejected.
        with self.opener.open(login_request, timeout=30):
            pass
        csrf_token = next(
            (
                cookie.value
                for cookie in cookie_jar
                if cookie.name.startswith("splunkweb_csrf_token_")
            ),
            "",
        )
        if not csrf_token:
            raise ValueError("Splunk Web session did not issue a CSRF token")
        self.headers["X-Splunk-Form-Key"] = unquote(csrf_token)
        self.headers["X-Requested-With"] = "XMLHttpRequest"

    def _url(self, path: str, query: str) -> str:
        prefix = "/en-US/splunkd/__raw" if self.transport == "web" else ""
        return f"{self.base_url}{prefix}{path}?{query}"

    def _open(self, request: Request, *, timeout: int):
        if self.opener is not None:
            return self.opener.open(request, timeout=timeout)
        return urlopen(request, timeout=timeout, context=self.ssl_context)

    def get(self, path: str, **params: Any) -> dict[str, Any]:
        query = urlencode({"output_mode": "json", **params})
        request = Request(self._url(path, query), headers=self.headers)
        with self._open(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))

    def post(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        body = urlencode(data).encode("utf-8")
        headers = {**self.headers, "Content-Type": "application/x-www-form-urlencoded"}
        request = Request(
            self._url(path, "output_mode=json"),
            headers=headers,
            data=body,
            method="POST",
        )
        with self._open(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))

    def post_bytes(
        self,
        path: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        **params: Any,
    ) -> bytes:
        """POST an opaque payload, for example to the simple receiver."""
        query = urlencode({"output_mode": "json", **params})
        headers = {**self.headers, "Content-Type": content_type}
        request = Request(
            self._url(path, query),
            headers=headers,
            data=data,
            method="POST",
        )
        with self._open(request, timeout=30) as response:
            return response.read()

    def delete(self, path: str) -> None:
        request = Request(
            self._url(path, "output_mode=json"),
            headers=self.headers,
            method="DELETE",
        )
        with self._open(request, timeout=20):
            pass

    def run_search_job(
        self,
        search: str,
        *,
        earliest_time: str = "0",
        latest_time: str = "now",
        timeout: float = 180.0,
    ) -> dict[str, Any]:
        """Run an asynchronous search and return job metrics plus results."""
        created = self.post(
            "/services/search/jobs",
            {
                "search": search,
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "exec_mode": "normal",
            },
        )
        sid = str(created.get("sid", ""))
        if not sid:
            raise ValueError("Splunk did not return a search job identifier")

        deadline = time.monotonic() + timeout
        job_content: dict[str, Any] = {}
        try:
            while time.monotonic() < deadline:
                payload = self.get(f"/services/search/jobs/{sid}")
                job_entries = entries(payload)
                if not job_entries:
                    raise ValueError(f"search job {sid} is unavailable")
                job_content = job_entries[0].get("content", {})
                if bool(job_content.get("isDone")):
                    break
                time.sleep(0.25)
            else:
                raise TimeoutError(f"search job {sid} did not finish in {timeout:.0f}s")

            result_payload = self.get(
                f"/services/search/jobs/{sid}/results",
                count=0,
            )
            return {
                "sid": sid,
                "metrics": select(
                    job_content,
                    (
                        "dispatchState",
                        "isDone",
                        "isFailed",
                        "runDuration",
                        "scanCount",
                        "eventCount",
                        "resultCount",
                        "resultPreviewCount",
                        "doneProgress",
                    ),
                ),
                "results": result_payload.get("results", []),
                "messages": result_payload.get("messages", []),
            }
        finally:
            try:
                self.delete(f"/services/search/jobs/{sid}")
            except HTTPError:
                pass

    def collect(self) -> dict[str, Any]:
        server_entry = entries(self.get("/services/server/info"))[0]
        server = select(
            server_entry.get("content", {}),
            (
                "version",
                "build",
                "product_type",
                "serverName",
                "os_name",
                "os_version",
                "cpu_arch",
                "numberOfVirtualCores",
                "physicalMemoryMB",
                "server_roles",
                "kvStoreStatus",
                "health_info",
                "activeLicenseGroup",
                "licenseState",
                "isTrial",
            ),
        )
        try:
            health_entry = entries(self.get("/services/server/health/splunkd"))[0]
            server["splunkdHealth"] = health_entry.get("content", {}).get("health")
        except (HTTPError, IndexError):
            server["splunkdHealth"] = "unavailable"

        apps = []
        for entry in entries(self.get("/services/apps/local", count=0)):
            content = entry.get("content", {})
            apps.append(
                {
                    "name": entry.get("name"),
                    **select(content, ("label", "version", "disabled", "visible", "configured")),
                }
            )

        indexes = []
        for entry in entries(self.get("/services/data/indexes", count=0)):
            content = entry.get("content", {})
            indexes.append(
                {
                    "name": entry.get("name"),
                    **select(
                        content,
                        (
                            "datatype",
                            "disabled",
                            "currentDBSizeMB",
                            "maxTotalDataSizeMB",
                            "totalEventCount",
                            "frozenTimePeriodInSecs",
                        ),
                    ),
                }
            )

        searches = []
        for entry in entries(self.get("/services/saved/searches", count=0)):
            content = entry.get("content", {})
            searches.append(
                {
                    "name": entry.get("name"),
                    **select(
                        content,
                        (
                            "disabled",
                            "is_scheduled",
                            "cron_schedule",
                            "alert_type",
                            "alert.track",
                            "action.summary_index",
                            "action.notable",
                            "action.risk",
                        ),
                    ),
                }
            )

        license_messages = []
        try:
            for entry in entries(self.get("/services/licenser/messages", count=0)):
                content = entry.get("content", {})
                license_messages.append(
                    {
                        "name": entry.get("name"),
                        **select(content, ("category", "severity", "message", "create_time")),
                    }
                )
        except HTTPError as error:
            license_messages.append({"collection_error": str(error)})

        search_probe: dict[str, Any]
        aggregate_probes: dict[str, Any] = {}
        try:
            result = self.post(
                "/services/search/jobs",
                {
                    "search": "| rest /services/server/info | head 1 | fields version build",
                    "exec_mode": "oneshot",
                    "output_mode": "json",
                },
            )
            search_probe = {"status": "success", "result_count": len(result.get("results", []))}
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:500]
            search_probe = {
                "status": "failed",
                "http_status": error.code,
                "detail": detail,
            }

        aggregate_searches = {
            "winlab_inventory": (
                "search index=winlab earliest=0 "
                "| stats count by sourcetype source host | sort - count | head 50"
            ),
            "index_activity": (
                "search (index=sysmon OR index=windows OR index=risk OR index=notable) earliest=0 "
                "| stats count min(_time) as first_seen max(_time) as last_seen by index sourcetype "
                "| convert ctime(first_seen) ctime(last_seen)"
            ),
            "sysmon_event_codes": (
                "search index=sysmon earliest=0 "
                "| eval event_code=coalesce(EventCode, EventID) "
                "| stats count by event_code | sort - count | head 25"
            ),
            "cim_process_quality": (
                "search index=sysmon earliest=0 "
                "sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" "
                "| eval event_code=coalesce(EventCode, EventID) | where event_code=1 "
                "| eval process_ok=if(isnotnull(process) OR isnotnull(Image),1,0), "
                "user_ok=if(isnotnull(user) OR isnotnull(User),1,0), "
                "dest_ok=if(isnotnull(dest) OR isnotnull(host),1,0), "
                "cmd_ok=if(isnotnull(process_cmdline) OR isnotnull(CommandLine),1,0), "
                "parent_ok=if(isnotnull(parent_process_path) OR isnotnull(ParentImage),1,0) "
                "| stats count sum(process_ok) as process_ok sum(user_ok) as user_ok "
                "sum(dest_ok) as dest_ok sum(cmd_ok) as cmd_ok sum(parent_ok) as parent_ok"
            ),
        }
        if search_probe.get("status") == "success":
            for name, search in aggregate_searches.items():
                try:
                    result = self.post(
                        "/services/search/jobs",
                        {"search": search, "exec_mode": "oneshot", "output_mode": "json"},
                    )
                    aggregate_probes[name] = {
                        "status": "success",
                        "results": result.get("results", []),
                        "messages": result.get("messages", []),
                    }
                except HTTPError as error:
                    aggregate_probes[name] = {
                        "status": "failed",
                        "http_status": error.code,
                        "detail": error.read().decode("utf-8", errors="replace")[:500],
                    }

        return {
            "schema_version": 1,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "source": self.base_url,
            "server": server,
            "apps": sorted(apps, key=lambda item: str(item.get("name", "")).lower()),
            "indexes": sorted(indexes, key=lambda item: str(item.get("name", "")).lower()),
            "saved_searches": sorted(searches, key=lambda item: str(item.get("name", "")).lower()),
            "license_messages": license_messages,
            "search_probe": search_probe,
            "aggregate_probes": aggregate_probes,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--uri",
        required=True,
        help="Splunk management URI (8089) or Splunk Web URI (8000)",
    )
    parser.add_argument(
        "--transport",
        choices=("management", "web"),
        default="management",
        help="Use Basic Auth on 8089 or an authenticated Splunk Web proxy session",
    )
    parser.add_argument("--username", default="admin")
    parser.add_argument("--ca-bundle", help="CA bundle for a TLS-protected endpoint")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification for an isolated lab only",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    password = os.environ.pop("SPLUNK_PASSWORD", "")
    if not password:
        password = getpass.getpass(f"Splunk password for {args.username}: ")
    try:
        audit = SplunkAudit(
            args.uri,
            args.username,
            password,
            transport=args.transport,
            verify_tls=not args.insecure,
            ca_bundle=args.ca_bundle,
        ).collect()
    except (HTTPError, URLError, TimeoutError, ValueError, IndexError) as error:
        print(f"ERROR: live audit failed: {error}", file=sys.stderr)
        return 1
    finally:
        password = ""

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(audit, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"OK: live audit written to {args.output}")
    print(
        "SUMMARY: "
        f"Splunk {audit['server'].get('version')} / "
        f"license={audit['server'].get('licenseState')} / "
        f"apps={len(audit['apps'])} / indexes={len(audit['indexes'])} / "
        f"saved_searches={len(audit['saved_searches'])} / "
        f"search_probe={audit['search_probe'].get('status')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
