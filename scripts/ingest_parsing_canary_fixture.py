#!/usr/bin/env python3
"""Ingest one validated synthetic fixture into the isolated parsing recipe scope."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import ipaddress
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = (ROOT / "artifacts" / "private").resolve()
RUN_ID = re.compile(r"^parsing-[0-9]{8}T[0-9]{6}Z-[a-z0-9]{6,16}-(baseline|candidate|rollback)$")
USERNAME = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DOCUMENTATION_NETWORK = ipaddress.ip_network("192.0.2.0/24")


class IngestError(ValueError):
    """Raised when fixture ingestion would violate the controlled scope."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise IngestError(message)


def validate_management_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "https", "management URL must use HTTPS")
    require(bool(parsed.hostname) and parsed.port is not None, "management URL must include host and port")
    require(parsed.username is None and parsed.password is None, "credentials are forbidden in the management URL")
    require(not parsed.query and not parsed.fragment, "management URL must not include query or fragment")
    require(parsed.path.rstrip("/") in {"", "/"}, "management URL must not include an API path")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")


def validate_private_output(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(PRIVATE_ROOT)
    except ValueError as exc:
        raise IngestError("receipt output must remain under artifacts/private") from exc
    return resolved


def validate_private_fixture(path: Path) -> Path:
    resolved = validate_private_output(path)
    require(resolved.is_file(), "fixture is missing")
    return resolved


def validate_fixture(path: Path, run_id: str) -> tuple[bytes, int, str]:
    require(RUN_ID.fullmatch(run_id) is not None, "phase run_id is invalid")
    raw = path.read_bytes()
    require(0 < len(raw) <= 32768, "fixture size is outside the controlled bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IngestError("fixture must be UTF-8") from exc
    require("\r" not in text, "fixture must use canonical LF line endings")
    lines = [line for line in text.splitlines() if line]
    require(len(lines) == 5 and len(set(lines)) == 5, "fixture must contain five unique events")
    expected_ids = {f"evt-{number:02d}" for number in range(1, 6)}
    observed_ids: set[str] = set()
    for line in lines:
        require(f"run_id={run_id}" in line, "fixture contains an event from another run")
        require(line.endswith("end_marker=CANARY_END"), "fixture integrity marker is missing")
        event_id = re.search(r"\bevent_id=(evt-[0-9]{2})\b", line)
        require(event_id is not None, "fixture event ID is missing")
        observed_ids.add(event_id.group(1))
        addresses = IPV4.findall(line)
        require(len(addresses) == 1, "each event must contain one source address")
        address = ipaddress.ip_address(addresses[0])
        require(address in DOCUMENTATION_NETWORK, "fixture may use only the RFC 5737 documentation subnet")
    require(observed_ids == expected_ids, "fixture event ID set is incomplete")
    canonical = ("\n".join(lines) + "\n").encode("utf-8")
    require(raw == canonical, "fixture bytes are not canonical")
    return raw, len(lines), hashlib.sha256(raw).hexdigest()


def ingest(
    management_url: str,
    username: str,
    password: str,
    ca_cert: Path,
    payload: bytes,
    timeout_seconds: int,
) -> int:
    query = urllib.parse.urlencode(
        {
            "index": "idx_recette_parsing",
            "sourcetype": "canary:auth",
            "source": "parsing_canary_fixture",
            "host": "lab-parsing-canary",
        }
    )
    endpoint = management_url + "/services/receivers/simple?" + query
    authorization = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        endpoint,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Basic {authorization}",
            "Content-Type": "text/plain; charset=utf-8",
            "Accept": "application/json",
        },
    )
    context = ssl.create_default_context(cafile=str(ca_cert))
    with urllib.request.urlopen(request, context=context, timeout=timeout_seconds) as response:
        response_payload = response.read(65537)
        require(len(response_payload) <= 65536, "ingest REST response exceeds 64 KiB")
        require(response.status in {200, 201}, f"unexpected REST status {response.status}")
        return response.status


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
    parser.add_argument("--run-id", required=True, help="phase run ID ending in baseline, candidate, or rollback")
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    args = parser.parse_args()

    try:
        management_url = validate_management_url(args.management_url)
        require(USERNAME.fullmatch(args.username) is not None, "username contains unsupported characters")
        require(args.ca_cert.is_file(), "CA certificate file is missing")
        receipt_path = validate_private_output(args.receipt)
        require(not receipt_path.exists(), "refusing to overwrite an existing receipt")
        require(1 <= args.timeout_seconds <= 120, "timeout must be between 1 and 120 seconds")
        fixture_path = validate_private_fixture(args.fixture)
        payload, event_count, payload_sha = validate_fixture(fixture_path, args.run_id)
        password = read_password(args.password_stdin)
        status = ingest(
            management_url,
            args.username,
            password,
            args.ca_cert.resolve(),
            payload,
            args.timeout_seconds,
        )
        receipt = {
            "schema_version": 1,
            "captured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "run_id": args.run_id,
            "event_count": event_count,
            "fixture_sha256": payload_sha,
            "http_status": status,
            "scope": {"index_alias": "idx-recette-parsing", "sourcetype_alias": "canary-auth"},
            "raw_events_in_receipt": False,
            "credentials_in_receipt": False,
        }
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, ssl.SSLError, urllib.error.URLError, IngestError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    finally:
        if "password" in locals():
            password = ""

    print(f"PASS: ingested five synthetic canary events; private receipt {receipt_path}")
    print("SCOPE: idx_recette_parsing / canary:auth only; TLS verification enforced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
