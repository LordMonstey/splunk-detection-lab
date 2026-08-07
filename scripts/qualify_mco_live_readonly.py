#!/usr/bin/env python3
"""Qualify safe Splunk MCO observations over verified TLS using GET requests only."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request

from audit_splunk_live import SplunkAudit, entries


EXPECTED_FQDN = "splunk-probe.lab.test"
READ_ONLY_EXPORT_ENDPOINT = "/services/search/jobs/export"
FRESHNESS_AGGREGATE_SEARCH = (
    "| tstats latest(_time) as latest where index=* by index "
    "| where NOT match(index, \"^_\") "
    "| eval age_seconds=now()-latest "
    "| stats min(age_seconds) as freshest_event_age_seconds "
    "max(age_seconds) as stalest_event_age_seconds "
    "count as observed_index_count "
    "count(eval(age_seconds < -300)) as future_clock_anomaly_count"
)
ALLOWED_ENDPOINTS = frozenset(
    {
        "/services/server/info",
        "/services/server/health/splunkd",
        "/services/licenser/usage",
        "/services/licenser/messages",
        "/services/saved/searches",
        "/services/data/indexes",
    }
)
FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "credential",
        "host",
        "hostname",
        "ip",
        "password",
        "raw",
        "server_name",
        "servername",
        "sid",
        "source",
        "token",
        "uri",
        "url",
        "username",
    }
)
PRIVATE_IP_RE = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
)
HOSTNAME_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9-])"
)


class QualificationError(RuntimeError):
    """Raised when a live observation cannot satisfy the publication contract."""


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def number(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if math.isfinite(result) else default


def first_content(payload: dict[str, Any], label: str) -> dict[str, Any]:
    payload_entries = entries(payload)
    if not payload_entries:
        raise QualificationError(f"{label} returned no entry")
    content = payload_entries[0].get("content", {})
    if not isinstance(content, dict):
        raise QualificationError(f"{label} returned invalid content")
    return content


def parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@contextmanager
def pinned_resolution(fqdn: str, connect_address: str) -> Iterator[None]:
    address = ipaddress.ip_address(connect_address)
    if not address.is_private:
        raise QualificationError("the pinned address must belong to the private lab")
    original = socket.getaddrinfo

    def resolver(
        host: str,
        port: int | str | None,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ):
        target = str(address) if host == fqdn else host
        return original(target, port, family, type, proto, flags)

    socket.getaddrinfo = resolver
    try:
        yield
    finally:
        socket.getaddrinfo = original


class ReadOnlySplunkClient:
    """Expose only allowlisted GET requests after the authenticated Web session."""

    def __init__(self, fqdn: str, port: int, username: str, password: str, ca_bundle: Path) -> None:
        self._client = SplunkAudit(
            f"https://{fqdn}:{port}",
            username,
            password,
            transport="web",
            verify_tls=True,
            ca_bundle=str(ca_bundle),
        )
        self.observed_endpoints: list[str] = []

    def get(self, endpoint: str, **params: Any) -> dict[str, Any]:
        if endpoint not in ALLOWED_ENDPOINTS:
            raise QualificationError(f"endpoint is not read-only allowlisted: {endpoint}")
        payload = self._client.get(endpoint, **params)
        self.observed_endpoints.append(endpoint)
        return payload

    def export_freshness_aggregate(self) -> dict[str, Any]:
        search = FRESHNESS_AGGREGATE_SEARCH
        if re.search(r"(?i)\b(?:collect|delete|outputlookup|sendalert|script)\b", search):
            raise QualificationError("aggregate search contains a modifying command")
        body = urlencode(
            {
                "search": search,
                "earliest_time": "0",
                "latest_time": "now",
                "output_mode": "json",
            }
        ).encode("utf-8")
        request = Request(
            self._client._url(READ_ONLY_EXPORT_ENDPOINT, "output_mode=json"),
            headers={**self._client.headers, "Content-Type": "application/x-www-form-urlencoded"},
            data=body,
            method="POST",
        )
        with self._client._open(request, timeout=60) as response:
            raw = response.read().decode("utf-8")
        results: list[dict[str, Any]] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            result = item.get("result")
            if isinstance(result, dict):
                results.append(result)
        if len(results) != 1:
            raise QualificationError("freshness export did not return exactly one aggregate row")
        return results[0]


def observe_certificate(fqdn: str, port: int, ca_bundle: Path) -> dict[str, Any]:
    context = ssl.create_default_context(cafile=str(ca_bundle))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    with socket.create_connection((fqdn, port), timeout=15) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=fqdn) as tls_socket:
            peer = tls_socket.getpeercert()
            der = tls_socket.getpeercert(binary_form=True)
            protocol = tls_socket.version() or "unknown"
            cipher_info = tls_socket.cipher()
    if not der:
        raise QualificationError("TLS peer did not present a certificate")
    not_after_text = str(peer.get("notAfter", ""))
    if not not_after_text:
        raise QualificationError("TLS certificate expiration is unavailable")
    not_after_epoch = ssl.cert_time_to_seconds(not_after_text)
    now_epoch = datetime.now(timezone.utc).timestamp()
    days_remaining = int((not_after_epoch - now_epoch) // 86400)
    dns_sans = sorted(
        value
        for kind, value in peer.get("subjectAltName", ())
        if kind == "DNS" and isinstance(value, str)
    )
    if fqdn not in dns_sans:
        raise QualificationError("expected DNS SAN is absent")
    if any(not name.endswith(".lab.test") for name in dns_sans):
        raise QualificationError("certificate contains a DNS SAN outside lab.test")
    if protocol not in {"TLSv1.2", "TLSv1.3"}:
        raise QualificationError("TLS protocol is below 1.2")
    return {
        "protocol": protocol,
        "cipher": cipher_info[0] if cipher_info else "unknown",
        "days_remaining": days_remaining,
        "dns_sans": dns_sans,
        "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
        "chain_verified": True,
        "hostname_verified": True,
    }


def observe_health_and_kv(
    server_info: dict[str, Any],
    health_payload: dict[str, Any],
) -> dict[str, Any]:
    health = str(first_content(health_payload, "splunkd health").get("health", "unknown")).lower()
    status = str(server_info.get("kvStoreStatus") or "unknown")
    passed = health == "green" and status.lower() == "ready"
    return {
        "status": "PASS" if passed else "FAIL",
        "splunkd_health": health,
        "kv_store_status": status,
        "kv_status_source": "server_info",
        "kv_replication_observed": False,
        "limitation": "The standalone Web proxy exposes KV readiness but not replication introspection.",
    }


def observe_license(
    usage_payload: dict[str, Any],
    messages_payload: dict[str, Any],
    server_info: dict[str, Any],
    maximum_usage_pct: float,
) -> dict[str, Any]:
    usage = first_content(usage_payload, "license usage")
    quota = number(usage.get("quota"))
    consumed = number(usage.get("peers_usage_bytes"))
    usage_pct = round(100 * consumed / quota, 3) if quota > 0 else None
    severity_counts: dict[str, int] = {}
    for item in entries(messages_payload):
        content = item.get("content", {})
        severity = str(content.get("severity", "UNKNOWN")).upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    critical_messages = severity_counts.get("ERROR", 0) + severity_counts.get("FATAL", 0)
    license_state = str(server_info.get("licenseState", "unknown"))
    passed = (
        quota > 0
        and usage_pct is not None
        and usage_pct < maximum_usage_pct
        and critical_messages == 0
        and license_state.upper() == "OK"
    )
    return {
        "status": "PASS" if passed else "FAIL",
        "license_state": license_state,
        "usage_percent": usage_pct,
        "maximum_allowed_percent": maximum_usage_pct,
        "message_severity_counts": dict(sorted(severity_counts.items())),
        "critical_message_count": critical_messages,
    }


def observe_scheduler(payload: dict[str, Any]) -> dict[str, Any]:
    scheduled = 0
    enabled = 0
    with_next_time = 0
    for item in entries(payload):
        content = item.get("content", {})
        is_scheduled = truthy(content.get("is_scheduled"))
        if not is_scheduled:
            continue
        scheduled += 1
        if not truthy(content.get("disabled")):
            enabled += 1
            if content.get("next_scheduled_time") not in (None, ""):
                with_next_time += 1
    if scheduled == 0:
        status = "NOT_APPLICABLE"
        disposition = "OBSERVED"
        limitation = "No scheduled saved search is configured on this standalone instance."
    elif enabled > 0:
        status = "PASS"
        disposition = "OBSERVED"
        limitation = "Historical skips require search dispatch and are outside this control."
    else:
        status = "FAIL"
        disposition = "OBSERVED"
        limitation = "Scheduled objects exist but none is enabled."
    return {
        "status": status,
        "disposition": disposition,
        "scope": "configuration_inventory_only",
        "scheduled_count": scheduled,
        "enabled_scheduled_count": enabled,
        "enabled_with_next_time_count": with_next_time,
        "skip_history_observed": False,
        "limitation": limitation,
    }


def observe_capacity_and_freshness(
    payload: dict[str, Any],
    freshness_aggregate: dict[str, Any] | None,
    maximum_index_fill_pct: float,
    maximum_freshness_age_seconds: int,
) -> dict[str, Any]:
    public_indexes = 0
    populated_indexes = 0
    maximum_fill = 0.0
    for item in entries(payload):
        name = str(item.get("name", ""))
        if not name or name.startswith("_"):
            continue
        public_indexes += 1
        content = item.get("content", {})
        current_mb = number(content.get("currentDBSizeMB"))
        maximum_mb = number(content.get("maxTotalDataSizeMB"))
        if maximum_mb > 0:
            maximum_fill = max(maximum_fill, 100 * current_mb / maximum_mb)
        event_count = number(content.get("totalEventCount"))
        if event_count <= 0:
            continue
        populated_indexes += 1
    freshness_available = isinstance(freshness_aggregate, dict)
    freshest_age = (
        max(0, int(number(freshness_aggregate.get("freshest_event_age_seconds"))))
        if freshness_available
        else None
    )
    observed_freshness_indexes = (
        int(number(freshness_aggregate.get("observed_index_count")))
        if freshness_available
        else 0
    )
    future_clock_anomalies = (
        int(number(freshness_aggregate.get("future_clock_anomaly_count")))
        if freshness_available
        else 0
    )
    passed = (
        public_indexes > 0
        and populated_indexes > 0
        and freshness_available
        and observed_freshness_indexes > 0
        and freshest_age is not None
        and freshest_age <= maximum_freshness_age_seconds
        and maximum_fill < maximum_index_fill_pct
        and future_clock_anomalies == 0
    )
    return {
        "status": "PASS" if passed else "UNKNOWN" if not freshness_available else "FAIL",
        "public_index_count": public_indexes,
        "populated_index_count": populated_indexes,
        "freshness_observed_index_count": observed_freshness_indexes,
        "freshest_event_age_seconds": freshest_age,
        "maximum_freshness_age_seconds": maximum_freshness_age_seconds,
        "maximum_index_fill_percent": round(maximum_fill, 3),
        "maximum_allowed_index_fill_percent": maximum_index_fill_pct,
        "future_clock_anomaly_count": future_clock_anomalies,
        "index_names_included": False,
        "raw_events_read": False,
        "freshness_method": "aggregate_tstats_export_no_sid" if freshness_available else "unavailable",
    }


def assert_public_safe(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in FORBIDDEN_PUBLIC_KEYS:
                raise QualificationError(f"forbidden public key at {'.'.join((*path, str(key)))}")
            assert_public_safe(item, (*path, str(key)))
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            assert_public_safe(item, (*path, str(index)))
        return
    if not isinstance(value, str):
        return
    if PRIVATE_IP_RE.search(value):
        raise QualificationError("private IP found in public artifact")
    if "-----BEGIN " in value or re.search(r"(?i)\b(?:password|bearer|session[_ -]?key)\b", value):
        raise QualificationError("secret-like material found in public artifact")
    if re.search(r"(?i)https?://", value):
        raise QualificationError("URL found in public artifact")
    for hostname in HOSTNAME_RE.findall(value):
        if not hostname.lower().endswith(".lab.test"):
            raise QualificationError("hostname outside lab.test found in public artifact")


def build_artifact(
    fqdn: str,
    server_info: dict[str, Any],
    observed_endpoints: list[str],
    certificate: dict[str, Any],
    health_kv: dict[str, Any],
    license_observation: dict[str, Any],
    scheduler: dict[str, Any],
    capacity: dict[str, Any],
    ca_bundle: Path,
    freshness_export_used: bool,
) -> dict[str, Any]:
    controls = {
        "health_and_kv": health_kv,
        "license": license_observation,
        "scheduler": scheduler,
        "capacity_and_freshness": capacity,
        "certificate": {
            **certificate,
            "status": "PASS" if certificate["days_remaining"] >= 30 else "FAIL",
            "minimum_days_required": 30,
        },
    }
    statuses = [str(control.get("status")) for control in controls.values()]
    if any(status == "FAIL" for status in statuses):
        global_status = "FAIL"
    elif any(status == "UNKNOWN" for status in statuses):
        global_status = "INCOMPLETE"
    elif any(status == "NOT_APPLICABLE" for status in statuses):
        global_status = "PASS_WITH_LIMITATIONS"
    else:
        global_status = "PASS"
    artifact = {
        "schema_version": 1,
        "artifact_type": "splunk_mco_live_read_only_qualification",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": global_status,
        "evidence_class": "live_read_only_observation",
        "target": {
            "fqdn": fqdn,
            "platform": "Splunk Enterprise",
            "version": str(server_info.get("version", "unknown")),
            "build": str(server_info.get("build", "unknown")),
            "product_type": str(server_info.get("product_type", "unknown")),
        },
        "transport": {
            "https": True,
            "ca_verified": True,
            "hostname_verified": True,
            "ca_certificate_sha256": hashlib.sha256(ca_bundle.read_bytes()).hexdigest(),
            "splunk_api_methods_after_authentication": ["GET", "POST_EXPORT"],
            "read_only_endpoint_allowlist_enforced": True,
        },
        "collection": {
            "endpoint_count": len(observed_endpoints) + int(freshness_export_used),
            "all_allowlisted_endpoints_observed": set(observed_endpoints) == set(ALLOWED_ENDPOINTS),
            "aggregate_search_exported": freshness_export_used,
            "search_dispatched": freshness_export_used,
            "search_job_created": False,
            "configuration_changed": False,
            "incident_injected": False,
            "raw_events_read": False,
            "mutating_spl_commands_allowed": False,
        },
        "controls": controls,
        "proof_boundary": {
            "live_observation": True,
            "simulation_fixture": False,
            "proves_incident_remediation": False,
            "proves_scheduler_skip_history": False,
            "native_enterprise_security_claimed": False,
            "standalone_laboratory_scope": True,
        },
        "security": {
            "excluded": [
                "credentials",
                "cookies",
                "private addresses",
                "real host names",
                "index names",
                "saved search names",
                "raw events",
                "search text",
            ],
            "only_lab_test_dns_names_allowed": True,
        },
    }
    assert_public_safe(artifact)
    return artifact


def write_public_artifact(artifact: dict[str, Any], output: Path) -> None:
    if artifact.get("status") not in {"PASS", "PASS_WITH_LIMITATIONS"}:
        raise QualificationError("public artifact gate rejected a failed qualification")
    control_statuses = {str(control.get("status")) for control in artifact.get("controls", {}).values()}
    if control_statuses - {"PASS", "NOT_APPLICABLE"}:
        raise QualificationError("public artifact contains a failed or unknown control")
    assert_public_safe(artifact)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(output)


def safe_failure_summary(artifact: dict[str, Any], failed_controls: list[str]) -> str:
    controls = artifact.get("controls", {})
    summary: dict[str, Any] = {}
    if "health_and_kv" in failed_controls:
        control = controls.get("health_and_kv", {})
        summary["health_and_kv"] = {
            "splunkd_health": control.get("splunkd_health"),
            "kv_store_status": control.get("kv_store_status"),
        }
    if "scheduler" in failed_controls:
        control = controls.get("scheduler", {})
        summary["scheduler"] = {
            "scheduled_count": control.get("scheduled_count"),
            "enabled_scheduled_count": control.get("enabled_scheduled_count"),
            "enabled_with_next_time_count": control.get("enabled_with_next_time_count"),
        }
    if "capacity_and_freshness" in failed_controls:
        control = controls.get("capacity_and_freshness", {})
        summary["capacity_and_freshness"] = {
            "public_index_count": control.get("public_index_count"),
            "populated_index_count": control.get("populated_index_count"),
            "freshness_observed_index_count": control.get("freshness_observed_index_count"),
            "freshest_event_age_seconds": control.get("freshest_event_age_seconds"),
            "maximum_index_fill_percent": control.get("maximum_index_fill_percent"),
            "future_clock_anomaly_count": control.get("future_clock_anomaly_count"),
        }
    assert_public_safe(summary)
    return json.dumps(summary, sort_keys=True, separators=(",", ":"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fqdn", default=EXPECTED_FQDN)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--connect-address", required=True, help="private route target; never written to output")
    parser.add_argument("--ca-bundle", type=Path, required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--maximum-license-usage-pct", type=float, default=90.0)
    parser.add_argument("--maximum-index-fill-pct", type=float, default=80.0)
    parser.add_argument("--maximum-freshness-age-seconds", type=int, default=86400)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main(password_override: str | None = None) -> int:
    args = parse_args()
    if args.fqdn != EXPECTED_FQDN or not args.fqdn.endswith(".lab.test"):
        print("ERROR: only the approved lab.test endpoint is accepted", file=sys.stderr)
        return 2
    ca_bundle = args.ca_bundle.resolve()
    if not ca_bundle.is_file():
        print("ERROR: CA bundle is unavailable", file=sys.stderr)
        return 2
    password = password_override or os.environ.pop("SPLUNK_PASSWORD", "")
    if not password:
        password = getpass.getpass(f"Splunk password for {args.username}: ")
    stage = "initialization"
    try:
        with pinned_resolution(args.fqdn, args.connect_address):
            stage = "certificate"
            certificate = observe_certificate(args.fqdn, args.port, ca_bundle)
            stage = "authentication"
            client = ReadOnlySplunkClient(args.fqdn, args.port, args.username, password, ca_bundle)
            stage = "server_info"
            server_info = first_content(client.get("/services/server/info"), "server info")
            stage = "health"
            health_payload = client.get("/services/server/health/splunkd")
            health_kv = observe_health_and_kv(server_info, health_payload)
            stage = "license_usage"
            license_usage_payload = client.get("/services/licenser/usage")
            stage = "license_messages"
            license_messages_payload = client.get("/services/licenser/messages", count=0)
            license_observation = observe_license(
                license_usage_payload,
                license_messages_payload,
                server_info,
                args.maximum_license_usage_pct,
            )
            stage = "scheduler"
            scheduler = observe_scheduler(client.get("/services/saved/searches", count=0))
            stage = "freshness_export"
            freshness_aggregate = client.export_freshness_aggregate()
            stage = "capacity_freshness"
            capacity = observe_capacity_and_freshness(
                client.get("/services/data/indexes", count=0),
                freshness_aggregate,
                args.maximum_index_fill_pct,
                args.maximum_freshness_age_seconds,
            )
            stage = "publication_gate"
            artifact = build_artifact(
                args.fqdn,
                server_info,
                client.observed_endpoints,
                certificate,
                health_kv,
                license_observation,
                scheduler,
                capacity,
                ca_bundle,
                True,
            )
    except HTTPError as error:
        password = ""
        print(
            f"ERROR: live read-only qualification failed stage={stage} http_status={error.code}",
            file=sys.stderr,
        )
        return 1
    except (URLError, OSError, ssl.SSLError, ValueError, QualificationError) as error:
        password = ""
        print(
            f"ERROR: live read-only qualification failed stage={stage} type={type(error).__name__}",
            file=sys.stderr,
        )
        return 1
    finally:
        password = ""

    if artifact["status"] not in {"PASS", "PASS_WITH_LIMITATIONS"}:
        failed = [
            name
            for name, control in artifact["controls"].items()
            if control.get("status") not in {"PASS", "NOT_APPLICABLE"}
        ]
        print(
            f"FAIL: public artifact not written; failed_controls={','.join(failed)} "
            f"summary={safe_failure_summary(artifact, failed)}",
            file=sys.stderr,
        )
        return 1
    try:
        write_public_artifact(artifact, args.output.resolve())
    except (OSError, QualificationError) as error:
        print(f"ERROR: public artifact gate failed ({type(error).__name__})", file=sys.stderr)
        return 1
    print(
        "PASS: live read-only qualification published; "
        f"controls={len(artifact['controls'])} endpoints={artifact['collection']['endpoint_count']} "
        "tls_verified=true changes=false raw_events=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
