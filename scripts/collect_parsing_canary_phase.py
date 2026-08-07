#!/usr/bin/env python3
"""Collect one sanitized aggregate phase for the live parsing canary drill."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = (ROOT / "artifacts" / "private").resolve()
PHASES = ("baseline", "candidate", "rollback")
RUN_ID = re.compile(r"^parsing-[0-9]{8}T[0-9]{6}Z-[a-z0-9]{6,16}$")
USERNAME = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
AGGREGATE_FIELDS = {
    "observed_event_count",
    "distinct_event_count",
    "user_present_count",
    "src_present_count",
    "action_present_count",
    "timestamp_within_tolerance_count",
    "duplicate_count",
    "truncated_event_count",
    "p95_index_lag_seconds",
}


class CollectionError(ValueError):
    """Raised when live aggregate collection cannot satisfy the phase contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CollectionError(message)


def validate_management_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "https", "management URL must use HTTPS")
    require(bool(parsed.hostname) and parsed.port is not None, "management URL must include host and port")
    require(parsed.username is None and parsed.password is None, "credentials are forbidden in the management URL")
    require(not parsed.query and not parsed.fragment, "management URL must not include query or fragment")
    path = parsed.path.rstrip("/")
    require(path in {"", "/"}, "management URL must not include an API path")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")


def validate_private_output(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(PRIVATE_ROOT)
    except ValueError as exc:
        raise CollectionError("phase output must remain under artifacts/private") from exc
    return resolved


def build_search(run_id: str, phase: str) -> str:
    scoped_run_id = f"{run_id}-{phase}"
    return (
        'search index=idx_recette_parsing sourcetype="canary:auth" '
        f'canary_run_id="{scoped_run_id}" earliest=-2h latest=now '
        '| eval expected_epoch=strptime(replace(expected_event_time, "Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z") '
        '| eval timestamp_ok=if(isnotnull(expected_epoch) AND abs(_time-expected_epoch)<=5, 1, 0) '
        '| eval complete_event=if(match(_raw, "end_marker=CANARY_END\\\\s*$"), 1, 0) '
        '| stats count as observed_event_count '
        'dc(canary_event_id) as distinct_event_count '
        'count(eval(isnotnull(user) AND len(user)>0)) as user_present_count '
        'count(eval(isnotnull(src) AND len(src)>0)) as src_present_count '
        'count(eval(isnotnull(action) AND len(action)>0)) as action_present_count '
        'sum(timestamp_ok) as timestamp_within_tolerance_count '
        'sum(complete_event) as complete_event_count '
        'perc95(eval(abs(_indextime-_time))) as p95_index_lag_seconds '
        '| eval duplicate_count=observed_event_count-distinct_event_count '
        '| eval truncated_event_count=observed_event_count-complete_event_count '
        '| fields observed_event_count distinct_event_count user_present_count '
        'src_present_count action_present_count timestamp_within_tolerance_count '
        'duplicate_count truncated_event_count p95_index_lag_seconds'
    )


def export_search(
    management_url: str,
    username: str,
    password: str,
    ca_cert: Path,
    search: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    endpoint = management_url + "/services/search/jobs/export"
    body = urllib.parse.urlencode(
        {
            "search": search,
            "output_mode": "json",
            "enable_lookups": "true",
            "adhoc_search_level": "fast",
        }
    ).encode("utf-8")
    authorization = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Basic {authorization}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    context = ssl.create_default_context(cafile=str(ca_cert))
    with urllib.request.urlopen(request, context=context, timeout=timeout_seconds) as response:
        require(response.status == 200, f"unexpected REST status {response.status}")
        raw_payload = response.read(1048577)
        require(len(raw_payload) <= 1048576, "aggregate REST response exceeds one MiB")
        payload = raw_payload.decode("utf-8")

    results = []
    for line in payload.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if isinstance(item, dict) and isinstance(item.get("result"), dict):
            results.append(item["result"])
    require(len(results) == 1, f"aggregate search returned {len(results)} result rows")
    require(set(results[0]) == AGGREGATE_FIELDS, "aggregate search returned unexpected fields")
    return results[0]


def nonnegative_integer(value: Any, label: str) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError) as exc:
        raise CollectionError(f"{label} is not an integer") from exc
    require(parsed >= 0, f"{label} must be non-negative")
    return parsed


def nonnegative_float(value: Any, label: str) -> float:
    try:
        parsed = float(str(value))
    except (TypeError, ValueError) as exc:
        raise CollectionError(f"{label} is not numeric") from exc
    require(parsed >= 0, f"{label} must be non-negative")
    return parsed


def normalize_phase(run_id: str, phase: str, aggregate: dict[str, Any]) -> dict[str, Any]:
    require(set(aggregate) == AGGREGATE_FIELDS, "aggregate field contract mismatch")
    normalized_counts = {
        key: nonnegative_integer(aggregate[key], key)
        for key in AGGREGATE_FIELDS
        if key != "p95_index_lag_seconds"
    }
    lag = nonnegative_float(aggregate["p95_index_lag_seconds"], "p95_index_lag_seconds")
    observed = normalized_counts["observed_event_count"]
    for key in (
        "distinct_event_count",
        "user_present_count",
        "src_present_count",
        "action_present_count",
        "timestamp_within_tolerance_count",
    ):
        require(normalized_counts[key] <= observed, f"{key} exceeds observed_event_count")

    canonical = json.dumps(aggregate, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "run_id": f"{run_id}-{phase}",
        "captured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "expected_event_count": 5,
        "observed_event_count": observed,
        "distinct_event_count": normalized_counts["distinct_event_count"],
        "required_field_counts": {
            "user": normalized_counts["user_present_count"],
            "src": normalized_counts["src_present_count"],
            "action": normalized_counts["action_present_count"],
        },
        "timestamp_within_tolerance_count": normalized_counts["timestamp_within_tolerance_count"],
        "duplicate_count": normalized_counts["duplicate_count"],
        "truncated_event_count": normalized_counts["truncated_event_count"],
        "p95_index_lag_seconds": round(lag, 3),
        "aggregate_evidence_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def read_password(from_stdin: bool) -> str:
    password = sys.stdin.readline().rstrip("\r\n") if from_stdin else getpass.getpass("Splunk password: ")
    require(bool(password), "empty password is forbidden")
    return password


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--management-url", required=True)
    parser.add_argument("--ca-cert", type=Path, required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password-stdin", action="store_true")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()

    try:
        require(RUN_ID.fullmatch(args.run_id) is not None, "run_id is invalid")
        require(USERNAME.fullmatch(args.username) is not None, "username contains unsupported characters")
        management_url = validate_management_url(args.management_url)
        require(args.ca_cert.is_file(), "CA certificate file is missing")
        output = validate_private_output(args.output)
        require(not output.exists(), "refusing to overwrite an existing phase artifact")
        require(1 <= args.timeout_seconds <= 300, "timeout must be between 1 and 300 seconds")
        password = read_password(args.password_stdin)
        search = build_search(args.run_id, args.phase)
        aggregate = export_search(
            management_url,
            args.username,
            password,
            args.ca_cert.resolve(),
            search,
            args.timeout_seconds,
        )
        phase = normalize_phase(args.run_id, args.phase, aggregate)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(phase, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ssl.SSLError, urllib.error.URLError, json.JSONDecodeError, CollectionError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    finally:
        if "password" in locals():
            password = ""

    print(f"PASS: wrote private aggregate phase {output}")
    print("RAW EVENTS: excluded; credentials: excluded; TLS verification: enforced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
