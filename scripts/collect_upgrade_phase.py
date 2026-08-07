#!/usr/bin/env python3
"""Collect one private, sanitizable phase of the Splunk upgrade drill.

The collector deliberately writes only the phase fields accepted by
``upgrade-evidence.schema.json`` plus non-sensitive collection controls.  It
never persists credentials, endpoint details, search identifiers, raw SPL,
raw events, KV values, host names, or private input paths.

All live requests require HTTPS, an explicit CA bundle, and Python's default
hostname verification.  The script supports both the management API and the
authenticated Splunk Web proxy implemented by :mod:`audit_splunk_live`.
"""

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
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request

from audit_splunk_live import SplunkAudit, entries


PHASE_VERSIONS = {
    "pre_upgrade": "9.4.13",
    "post_upgrade": "10.2.1",
    "rollback": "9.4.13",
    "final": "10.2.1",
}
PHASE_SEQUENCE = {
    "pre_upgrade": 1,
    "post_upgrade": 2,
    "rollback": 3,
    "final": 4,
}
REQUIRED_SMOKE_TESTS = (
    "authentication",
    "interactive_search",
    "scheduled_search",
    "ingestion_freshness",
    "kv_store",
    "license",
    "dashboard_load",
    "configuration_check",
)
HASH_ARGUMENTS = {
    "managed_configuration_manifest_sha256": "managed_configuration_manifest",
    "custom_apps_manifest_sha256": "custom_apps_manifest",
    "saved_searches_export_sha256": "saved_searches_export",
    "kv_store_export_sha256": "kv_store_export",
}
DEFAULT_APP = "splunk_upgrade_qualification"
DEFAULT_SAVED_SEARCH = "upgrade_qualification_heartbeat"
DEFAULT_COLLECTION = "upgrade_checkpoint"
DEFAULT_DASHBOARD = "upgrade_qualification"
SPLUNK_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
REFERENCE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{5,127}$")
IP_TOKEN = re.compile(r"(?<![0-9a-f:.%])[0-9a-f:.%]{3,}(?![0-9a-f:.%])", re.I)
URI = re.compile(r"(?i)\b(?:https?|splunk)://")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|token|secret|session_key|authorization)\s*[:=]"
)
FORBIDDEN_OUTPUT_KEYS = {
    "authorization",
    "endpoint",
    "host",
    "hostname",
    "password",
    "query",
    "raw",
    "search",
    "secret",
    "session_key",
    "sid",
    "token",
    "uri",
    "url",
    "username",
}


@dataclass(frozen=True)
class CollectorConfig:
    phase: str
    transport: str
    username: str
    custom_apps: tuple[str, ...]
    scheduled_search_owner: str
    scheduled_search_app: str
    scheduled_search_name: str
    scheduler_lookback_minutes: int
    control_index: str
    control_field: str
    control_event_id: str
    freshness_sla_seconds: int
    kv_owner: str
    kv_app: str
    kv_collection: str
    kv_checkpoint_key: str
    kv_expected_field: str
    kv_expected_value: str
    dashboard_owner: str
    dashboard_app: str
    dashboard_view: str
    configuration_attestation: Path
    configuration_attestation_max_age_seconds: int
    health_lookback_minutes: int


@dataclass(frozen=True)
class ProbeOutcome:
    passed: bool
    signals: Mapping[str, Any]


def utc_z(moment: datetime | None = None) -> str:
    value = moment or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_utc_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return None
    return parsed


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def hash_private_input(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"private hash input is not a regular file: {path.name}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    if size == 0:
        raise ValueError(f"private hash input is empty: {path.name}")
    return digest.hexdigest()


def hash_inputs(paths: Mapping[str, Path]) -> dict[str, str]:
    missing = set(HASH_ARGUMENTS) - set(paths)
    extra = set(paths) - set(HASH_ARGUMENTS)
    if missing or extra:
        raise ValueError(
            f"hash input contract mismatch: missing={sorted(missing)} extra={sorted(extra)}"
        )
    return {name: hash_private_input(paths[name]) for name in HASH_ARGUMENTS}


def validate_identifier(value: str, label: str) -> str:
    if not SPLUNK_IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} is not a safe Splunk identifier")
    return value


def validate_secret_reference(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError(f"{label} must contain between 1 and 512 characters")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise ValueError(f"{label} contains a forbidden control character")
    return value


def validate_reference_token(value: str, label: str) -> str:
    if not isinstance(value, str) or not REFERENCE_TOKEN.fullmatch(value):
        raise ValueError(
            f"{label} must be a 6-128 character alphanumeric reference token"
        )
    return value


def validate_tls_endpoint(uri: str, ca_bundle: Path) -> str:
    parsed = urlsplit(uri)
    if parsed.scheme.lower() != "https":
        raise ValueError("Splunk endpoint must use HTTPS")
    if parsed.username or parsed.password:
        raise ValueError("credentials are forbidden in the endpoint URI")
    if not parsed.hostname:
        raise ValueError("Splunk endpoint must include a hostname")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise ValueError("use a DNS hostname so certificate hostname verification is explicit")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Splunk endpoint must be an origin URI without path, query, or fragment")
    try:
        parsed.port
    except ValueError as error:
        raise ValueError("Splunk endpoint has an invalid port") from error
    if not ca_bundle.is_file() or ca_bundle.stat().st_size == 0:
        raise ValueError("an explicit non-empty CA bundle is required")
    return parsed.hostname.rstrip(".").lower()


def validate_connect_ip(value: str | None) -> str | None:
    if value is None:
        return None
    if value != value.strip() or not value:
        raise ValueError("connect IP must be a strict IP literal")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise ValueError("connect IP must be a strict IP literal") from error


@contextmanager
def pinned_resolver(hostname: str, connect_ip: str | None):
    """Temporarily resolve one TLS hostname to an explicitly pinned address.

    The original URI hostname remains untouched, so urllib still sends that
    hostname for SNI and verifies it against the certificate SAN.  Only the
    socket address lookup is replaced, and the global resolver is restored in
    ``finally`` before the context exits.
    """

    if connect_ip is None:
        yield
        return
    target = hostname.rstrip(".").lower()
    pinned_ip = validate_connect_ip(connect_ip)
    original = socket.getaddrinfo

    def resolve(host: Any, port: Any, *args: Any, **kwargs: Any):
        candidate = host.decode("ascii") if isinstance(host, bytes) else str(host)
        lookup_host = pinned_ip if candidate.rstrip(".").lower() == target else host
        return original(lookup_host, port, *args, **kwargs)

    socket.getaddrinfo = resolve
    try:
        yield
    finally:
        socket.getaddrinfo = original


def splunk_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def to_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return default


def to_float(value: Any, default: float = -1.0) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def escape_splunk_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def quote_segment(value: str) -> str:
    return quote(value, safe="")


def first_content(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    values = entries(payload)
    if not values:
        return {}
    content = values[0].get("content", {})
    return content if isinstance(content, dict) else {}


def job_succeeded(job: Mapping[str, Any]) -> bool:
    metrics = job.get("metrics", {})
    if not isinstance(metrics, Mapping):
        return False
    is_done = splunk_truthy(metrics.get("isDone"))
    is_failed = splunk_truthy(metrics.get("isFailed"))
    dispatch = str(metrics.get("dispatchState", "")).strip().upper()
    return is_done and not is_failed and dispatch not in {"FAILED", "ERROR"}


def stats_result(job: Mapping[str, Any]) -> dict[str, Any]:
    if not job_succeeded(job):
        return {}
    results = job.get("results", [])
    if not isinstance(results, list) or not results or not isinstance(results[0], dict):
        return {}
    return results[0]


def load_configuration_attestation(
    path: Path,
    *,
    now: datetime,
    max_age_seconds: int,
) -> ProbeOutcome:
    try:
        raw = path.read_bytes()
        if not raw:
            return ProbeOutcome(False, {"attestation_present": False})
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ProbeOutcome(False, {"attestation_present": False})
    if not isinstance(payload, dict):
        return ProbeOutcome(False, {"attestation_present": True, "structured": False})
    captured = parse_utc_timestamp(payload.get("captured_at"))
    age_seconds = (now - captured).total_seconds() if captured is not None else -1.0
    timestamp_valid = captured is not None and -300 <= age_seconds <= max_age_seconds
    passed = (
        payload.get("kind") in {"splunk-btool-check", "splunk-config-validation"}
        and payload.get("status") == "passed"
        and payload.get("exit_code") == 0
        and payload.get("blocking_error_count") == 0
        and timestamp_valid
    )
    return ProbeOutcome(
        passed,
        {
            "attestation_present": True,
            "structured": True,
            "success_status": payload.get("status") == "passed",
            "zero_exit": payload.get("exit_code") == 0,
            "zero_blocking_errors": payload.get("blocking_error_count") == 0,
            "timestamp_valid": timestamp_valid,
            "attestation_sha256": hashlib.sha256(raw).hexdigest(),
        },
    )


def smoke_result(
    test_id: str,
    probe: Callable[[], ProbeOutcome],
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    started = monotonic()
    try:
        outcome = probe()
        if not isinstance(outcome, ProbeOutcome):
            raise TypeError("probe did not return ProbeOutcome")
    except Exception as error:  # fail closed; no exception text is persisted
        outcome = ProbeOutcome(
            False,
            {
                "signal_present": False,
                "failure_class": type(error).__name__,
            },
        )
    duration_ms = max(0, int(round((monotonic() - started) * 1000)))
    status = "passed" if outcome.passed else "failed"
    evidence = {
        "id": test_id,
        "status": status,
        "signals": dict(outcome.signals),
    }
    return {
        "id": test_id,
        "status": status,
        "duration_ms": duration_ms,
        "evidence_sha256": canonical_sha256(evidence),
    }


def failed_smoke_result(test_id: str, failure_code: str) -> dict[str, Any]:
    return {
        "id": test_id,
        "status": "failed",
        "duration_ms": 0,
        "evidence_sha256": canonical_sha256(
            {"id": test_id, "status": "failed", "failure_code": failure_code}
        ),
    }


class UpgradePhaseCollector:
    def __init__(
        self,
        client: SplunkAudit,
        config: CollectorConfig,
        hashes: Mapping[str, str],
        *,
        now: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.client = client
        self.config = config
        self.hashes = dict(hashes)
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.monotonic = monotonic

    def _server_info(self) -> tuple[dict[str, Any], bool]:
        try:
            content = first_content(self.client.get("/services/server/info"))
        except Exception:
            return {}, False
        complete = bool(content.get("version")) and bool(content.get("build"))
        return content, complete

    def _inventory(self) -> tuple[dict[str, int], bool]:
        apps_complete = False
        searches_complete = False
        app_entries: list[dict[str, Any]] = []
        search_entries: list[dict[str, Any]] = []
        try:
            payload = self.client.get("/services/apps/local", count=0)
            app_entries = entries(payload)
            apps_complete = isinstance(payload, dict) and "entry" in payload
        except Exception:
            pass
        try:
            payload = self.client.get("/services/saved/searches", count=0)
            search_entries = entries(payload)
            searches_complete = isinstance(payload, dict) and "entry" in payload
        except Exception:
            pass

        installed_names = {
            str(item.get("name"))
            for item in app_entries
            if isinstance(item, dict) and item.get("name")
        }
        enabled_saved = 0
        for item in search_entries:
            content = item.get("content", {}) if isinstance(item, dict) else {}
            if not isinstance(content, dict):
                continue
            scheduled = splunk_truthy(
                content.get("is_scheduled", content.get("enableSched", False))
            )
            disabled = splunk_truthy(content.get("disabled", False))
            if scheduled and not disabled:
                enabled_saved += 1
        inventory = {
            "installed_app_count": len(app_entries),
            "custom_app_count": sum(
                1 for app in set(self.config.custom_apps) if app in installed_names
            ),
            "saved_search_count": len(search_entries),
            "enabled_saved_search_count": enabled_saved,
        }
        return inventory, apps_complete and searches_complete

    def _kv_state(self, server_info: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
        raw_status: Any = server_info.get("kvStoreStatus")
        status_signal = bool(raw_status)
        try:
            payload = self.client.get("/services/kvstore/status")
            content = first_content(payload)
            current = content.get("current", {}) if isinstance(content, dict) else {}
            if isinstance(current, dict) and current.get("status"):
                raw_status = current.get("status")
                status_signal = True
            elif content.get("status"):
                raw_status = content.get("status")
                status_signal = True
        except Exception:
            pass
        normalized = str(raw_status or "").strip().lower()
        status = "ready" if normalized == "ready" else (
            "degraded" if normalized in {"starting", "degraded"} else "failed"
        )

        collection_count = 0
        collection_signal = False
        try:
            payload = self.client.get(
                f"/servicesNS/{quote_segment(self.config.kv_owner)}/"
                f"{quote_segment(self.config.kv_app)}/storage/collections/config",
                count=0,
            )
            if isinstance(payload, dict) and "entry" in payload:
                collection_count = len(entries(payload))
                collection_signal = True
        except Exception:
            pass
        return {
            "status": status,
            "collection_count": collection_count,
        }, status_signal and collection_signal

    def _license_state(self, server_info: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
        raw_state = str(server_info.get("licenseState", "")).strip().upper()
        state_signal = bool(raw_state)
        violation_count = 0
        message_signal = False
        try:
            payload = self.client.get("/services/licenser/messages", count=0)
            if isinstance(payload, dict) and "entry" in payload:
                message_signal = True
                for item in entries(payload):
                    content = item.get("content", {}) if isinstance(item, dict) else {}
                    combined = " ".join(
                        str(content.get(field, ""))
                        for field in ("category", "severity", "message")
                    ).lower()
                    if "violation" in combined:
                        violation_count += 1
        except Exception:
            pass
        if not state_signal or not message_signal:
            state = "ERROR"
        elif raw_state == "OK" and violation_count == 0:
            state = "OK"
        elif raw_state in {"WARN", "WARNING"}:
            state = "WARN"
        else:
            state = "ERROR"
        return {"state": state, "violation_count": violation_count}, state_signal and message_signal

    def _stats_search(self, search: str) -> tuple[dict[str, Any], bool]:
        try:
            job = self.client.run_search_job(search)
        except Exception:
            return {}, False
        result = stats_result(job)
        return result, bool(result)

    def _health(
        self,
        *,
        server_complete: bool,
        interactive_passed: bool,
    ) -> tuple[dict[str, Any], bool]:
        api_health = ""
        health_signal = False
        try:
            content = first_content(self.client.get("/services/server/health/splunkd"))
            raw = content.get("health")
            if isinstance(raw, dict):
                raw = raw.get("status") or raw.get("health")
            api_health = str(raw or "").strip().lower()
            health_signal = bool(api_health)
        except Exception:
            pass

        lookback = self.config.health_lookback_minutes
        fatal_result, fatal_signal = self._stats_search(
            "search index=_internal source=*splunkd.log "
            f"earliest=-{lookback}m (log_level=FATAL OR log_level=CRITICAL) "
            "| stats count as fatal_count"
        )
        skipped_result, skipped_signal = self._stats_search(
            "search index=_internal source=*scheduler.log "
            f"earliest=-{lookback}m (status=skipped OR status=continued) "
            "| stats count as skipped_count"
        )
        fatal_count = max(0, to_int(fatal_result.get("fatal_count"), 0))
        skipped_count = max(0, to_int(skipped_result.get("skipped_count"), 0))
        complete = health_signal and fatal_signal and skipped_signal and server_complete
        green = (
            complete
            and api_health == "green"
            and interactive_passed
            and fatal_count == 0
            and skipped_count == 0
        )
        return {
            "status": "green" if green else ("yellow" if complete else "red"),
            "splunkd_status": "running" if server_complete else "stopped",
            "searchable": interactive_passed,
            "fatal_error_count": fatal_count,
            "skipped_search_count": skipped_count,
        }, complete

    def _probe_authentication(self) -> ProbeOutcome:
        payload = self.client.get("/services/authentication/current-context")
        values = entries(payload)
        if len(values) != 1:
            return ProbeOutcome(False, {"context_entry_count": len(values)})
        content = values[0].get("content", {})
        principal = content.get("username") or values[0].get("name")
        roles = content.get("roles", [])
        capabilities = content.get("capabilities", [])
        if isinstance(roles, str):
            roles = [item for item in roles.split(";") if item]
        if isinstance(capabilities, str):
            capabilities = [item for item in capabilities.split(";") if item]
        principal_match = str(principal) == self.config.username
        access_context_present = (
            (isinstance(roles, list) and bool(roles))
            or (isinstance(capabilities, list) and bool(capabilities))
        )
        return ProbeOutcome(
            principal_match and access_context_present,
            {
                "context_entry_count": 1,
                "principal_match": principal_match,
                "role_count": len(roles) if isinstance(roles, list) else 0,
                "capability_count": (
                    len(capabilities) if isinstance(capabilities, list) else 0
                ),
            },
        )

    def _probe_interactive_search(self) -> ProbeOutcome:
        job = self.client.run_search_job("| makeresults count=1 | stats count as probe_count")
        result = stats_result(job)
        count = to_int(result.get("probe_count"), 0)
        succeeded = job_succeeded(job) and count == 1
        return ProbeOutcome(
            succeeded,
            {"job_completed": job_succeeded(job), "result_count": count},
        )

    def _history_timestamp(self, item: Mapping[str, Any]) -> datetime | None:
        for value in (
            item.get("published"),
            item.get("updated"),
            item.get("content", {}).get("published")
            if isinstance(item.get("content"), dict)
            else None,
        ):
            parsed = parse_utc_timestamp(value)
            if parsed is not None:
                return parsed
        return None

    def _probe_scheduled_search(self) -> ProbeOutcome:
        path = (
            f"/servicesNS/{quote_segment(self.config.scheduled_search_owner)}/"
            f"{quote_segment(self.config.scheduled_search_app)}/saved/searches/"
            f"{quote_segment(self.config.scheduled_search_name)}/history"
        )
        try:
            payload = self.client.get(path, count=10)
            values = entries(payload)
        except Exception:
            values = []
        if values:
            history_present = False
            recent_success = False
            completed_count = 0
            for item in values:
                if not isinstance(item, dict):
                    continue
                observed_at = self._history_timestamp(item)
                if observed_at is None:
                    continue
                history_present = True
                age = (self.now() - observed_at).total_seconds()
                recent = 0 <= age <= self.config.scheduler_lookback_minutes * 60
                content = item.get("content", {})
                if not isinstance(content, dict):
                    content = {}
                done = splunk_truthy(content.get("isDone"))
                failed = splunk_truthy(content.get("isFailed"))
                dispatch = str(content.get("dispatchState", "")).strip().upper()
                terminal_failure = failed or dispatch in {"FAILED", "ERROR"}
                if done:
                    completed_count += 1
                if recent and done and not terminal_failure:
                    recent_success = True
            if recent_success:
                return ProbeOutcome(
                    True,
                    {
                        "history_present": history_present,
                        "completed": completed_count > 0,
                        "failed": False,
                        "recent": True,
                    },
                )

        name = escape_splunk_literal(self.config.scheduled_search_name)
        result, signal = self._stats_search(
            "search index=_internal source=*scheduler.log "
            f"earliest=-{self.config.scheduler_lookback_minutes}m "
            f'savedsearch_name="{name}" '
            "| stats count as execution_count "
            'count(eval(status="success")) as success_count '
            'count(eval(status="skipped" OR status="continued" OR status="failed")) as bad_count '
            "max(_time) as latest_epoch"
        )
        execution_count = to_int(result.get("execution_count"), 0)
        success_count = to_int(result.get("success_count"), 0)
        bad_count = to_int(result.get("bad_count"), 0)
        latest_epoch = to_float(result.get("latest_epoch"), -1.0)
        age = self.now().timestamp() - latest_epoch if latest_epoch >= 0 else -1.0
        recent = 0 <= age <= self.config.scheduler_lookback_minutes * 60
        return ProbeOutcome(
            signal
            and execution_count > 0
            and success_count > 0
            and bad_count == 0
            and recent,
            {
                "scheduler_log_signal": signal,
                "execution_present": execution_count > 0,
                "success_present": success_count > 0,
                "bad_execution_present": bad_count > 0,
                "recent": recent,
            },
        )

    def _probe_ingestion_freshness(self) -> ProbeOutcome:
        event_id = escape_splunk_literal(self.config.control_event_id)
        window_minutes = max(2, math.ceil((self.config.freshness_sla_seconds * 2) / 60))
        search = (
            f"search index={self.config.control_index} earliest=-{window_minutes}m "
            f'{self.config.control_field}="{event_id}" '
            "| stats count as matched_count max(_time) as latest_epoch"
        )
        result, signal = self._stats_search(search)
        matched = to_int(result.get("matched_count"), 0)
        latest_epoch = to_float(result.get("latest_epoch"), -1.0)
        age = self.now().timestamp() - latest_epoch if latest_epoch >= 0 else -1.0
        fresh = -300 <= age <= self.config.freshness_sla_seconds
        return ProbeOutcome(
            signal and matched > 0 and fresh,
            {
                "aggregate_signal": signal,
                "identified_event_present": matched > 0,
                "within_sla": fresh,
            },
        )

    def _probe_kv_checkpoint(self) -> ProbeOutcome:
        path = (
            f"/servicesNS/{quote_segment(self.config.kv_owner)}/"
            f"{quote_segment(self.config.kv_app)}/storage/collections/data/"
            f"{quote_segment(self.config.kv_collection)}"
        )
        query = json.dumps(
            {"_key": self.config.kv_checkpoint_key},
            ensure_ascii=True,
            separators=(",", ":"),
        )
        payload = self.client.get(path, query=query, limit=2)
        rows = payload if isinstance(payload, list) else []
        exact_row = len(rows) == 1 and isinstance(rows[0], dict)
        expected_match = (
            exact_row
            and str(rows[0].get(self.config.kv_expected_field, ""))
            == self.config.kv_expected_value
        )
        return ProbeOutcome(
            exact_row and expected_match,
            {
                "checkpoint_row_count": len(rows),
                "single_checkpoint": exact_row,
                "expected_value_match": expected_match,
            },
        )

    def _probe_license(self, license_state: Mapping[str, Any], signal: bool) -> ProbeOutcome:
        passed = (
            signal
            and license_state.get("state") == "OK"
            and license_state.get("violation_count") == 0
        )
        return ProbeOutcome(
            passed,
            {
                "license_signal_complete": signal,
                "state_ok": license_state.get("state") == "OK",
                "zero_violations": license_state.get("violation_count") == 0,
            },
        )

    def _probe_dashboard(self) -> ProbeOutcome:
        path = (
            f"/servicesNS/{quote_segment(self.config.dashboard_owner)}/"
            f"{quote_segment(self.config.dashboard_app)}/data/ui/views/"
            f"{quote_segment(self.config.dashboard_view)}"
        )
        values = entries(self.client.get(path))
        if len(values) != 1:
            return ProbeOutcome(False, {"rest_definition_count": len(values)})
        content = values[0].get("content", {})
        source = str(content.get("eai:data", "")) if isinstance(content, dict) else ""
        normalized = source.lower()
        definition_valid = (
            ("<dashboard" in normalized or "<form" in normalized)
            and "<search" in normalized
        )
        web_loaded = True
        if self.config.transport == "web":
            page_url = (
                f"{self.client.base_url}/en-US/app/"
                f"{quote_segment(self.config.dashboard_app)}/"
                f"{quote_segment(self.config.dashboard_view)}"
            )
            request = Request(page_url, headers=self.client.headers)
            with self.client._open(request, timeout=30) as response:
                raw_status = getattr(response, "status", None)
                status = int(raw_status if raw_status is not None else response.getcode())
                body = response.read(4096)
            web_loaded = status == 200 and bool(body)
        return ProbeOutcome(
            definition_valid and web_loaded,
            {
                "rest_definition_present": True,
                "search_definition_present": "<search" in normalized,
                "web_surface_required": self.config.transport == "web",
                "web_surface_loaded": web_loaded,
            },
        )

    def _probe_configuration(self) -> ProbeOutcome:
        return load_configuration_attestation(
            self.config.configuration_attestation,
            now=self.now(),
            max_age_seconds=self.config.configuration_attestation_max_age_seconds,
        )

    def collect(self) -> dict[str, Any]:
        server_info, server_complete = self._server_info()
        inventory, inventory_complete = self._inventory()
        kv_state, kv_complete = self._kv_state(server_info)
        license_state, license_complete = self._license_state(server_info)

        probes: dict[str, Callable[[], ProbeOutcome]] = {
            "authentication": self._probe_authentication,
            "interactive_search": self._probe_interactive_search,
            "scheduled_search": self._probe_scheduled_search,
            "ingestion_freshness": self._probe_ingestion_freshness,
            "kv_store": self._probe_kv_checkpoint,
            "license": lambda: self._probe_license(license_state, license_complete),
            "dashboard_load": self._probe_dashboard,
            "configuration_check": self._probe_configuration,
        }
        smoke_tests = [
            smoke_result(test_id, probes[test_id], monotonic=self.monotonic)
            for test_id in REQUIRED_SMOKE_TESTS
        ]
        smoke_status = {item["id"]: item["status"] for item in smoke_tests}
        health, health_complete = self._health(
            server_complete=server_complete,
            interactive_passed=smoke_status.get("interactive_search") == "passed",
        )

        version = str(server_info.get("version") or "unavailable")
        build = str(server_info.get("build") or "unavailable")
        expected_version_match = version == PHASE_VERSIONS[self.config.phase]
        all_smoke_passed = all(item["status"] == "passed" for item in smoke_tests)
        phase_ready = (
            expected_version_match
            and inventory_complete
            and health_complete
            and kv_complete
            and license_complete
            and health["status"] == "green"
            and kv_state["status"] == "ready"
            and license_state["state"] == "OK"
            and license_state["violation_count"] == 0
            and all_smoke_passed
        )
        phase = {
            "captured_at": utc_z(self.now()),
            "version": version,
            "build": build,
            "health": health,
            "inventory": inventory,
            "kv_store": kv_state,
            "license": license_state,
            "hashes": dict(self.hashes),
            "smoke_tests": smoke_tests,
        }
        return {
            "schema_version": "1.0",
            "evidence_kind": "private-upgrade-phase-fragment",
            "phase_name": self.config.phase,
            "sequence": PHASE_SEQUENCE[self.config.phase],
            "phase": phase,
            "collection_control": {
                "transport": self.config.transport,
                "tls_ca_verification_enforced": True,
                "tls_hostname_verification_enforced": True,
                "expected_version_match": expected_version_match,
                "inventory_signals_complete": inventory_complete,
                "health_signals_complete": health_complete,
                "kv_signals_complete": kv_complete,
                "license_signals_complete": license_complete,
                "required_smoke_tests": len(REQUIRED_SMOKE_TESTS),
                "passed_smoke_tests": sum(
                    item["status"] == "passed" for item in smoke_tests
                ),
                "phase_ready": phase_ready,
            },
        }


def disconnected_fragment(
    phase_name: str,
    transport: str,
    hashes: Mapping[str, str],
    *,
    captured_at: datetime | None = None,
) -> dict[str, Any]:
    smoke_tests = [failed_smoke_result(item, "connection_unavailable") for item in REQUIRED_SMOKE_TESTS]
    return {
        "schema_version": "1.0",
        "evidence_kind": "private-upgrade-phase-fragment",
        "phase_name": phase_name,
        "sequence": PHASE_SEQUENCE[phase_name],
        "phase": {
            "captured_at": utc_z(captured_at),
            "version": "unavailable",
            "build": "unavailable",
            "health": {
                "status": "red",
                "splunkd_status": "stopped",
                "searchable": False,
                "fatal_error_count": 0,
                "skipped_search_count": 0,
            },
            "inventory": {
                "installed_app_count": 0,
                "custom_app_count": 0,
                "saved_search_count": 0,
                "enabled_saved_search_count": 0,
            },
            "kv_store": {"status": "failed", "collection_count": 0},
            "license": {"state": "ERROR", "violation_count": 0},
            "hashes": dict(hashes),
            "smoke_tests": smoke_tests,
        },
        "collection_control": {
            "transport": transport,
            "tls_ca_verification_enforced": True,
            "tls_hostname_verification_enforced": True,
            "expected_version_match": False,
            "inventory_signals_complete": False,
            "health_signals_complete": False,
            "kv_signals_complete": False,
            "license_signals_complete": False,
            "required_smoke_tests": len(REQUIRED_SMOKE_TESTS),
            "passed_smoke_tests": 0,
            "phase_ready": False,
        },
    }


def sensitive_output_findings(fragment: Mapping[str, Any]) -> list[str]:
    findings: list[str] = []

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key).strip().lower()
                if normalized in FORBIDDEN_OUTPUT_KEYS:
                    findings.append(f"forbidden key at {path}.{key}")
                walk(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")

    walk(fragment, "$")
    canonical = json.dumps(fragment, ensure_ascii=True, sort_keys=True)
    for candidate in IP_TOKEN.findall(canonical):
        normalized = candidate.strip("[](){}<>,;\"'")
        if "%" in normalized:
            normalized = normalized.split("%", 1)[0]
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            continue
        findings.append("IP address")
        break
    if URI.search(canonical):
        findings.append("URI")
    if SECRET_ASSIGNMENT.search(canonical):
        findings.append("secret-like assignment")
    if re.search(r"(?i)\b(?:sid|search)\s*=", canonical):
        findings.append("search identifier or raw query marker")
    return sorted(set(findings))


def write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    findings = sensitive_output_findings(payload)
    if findings:
        raise ValueError("refusing to write sensitive fragment: " + ", ".join(findings))
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def clear_client_credentials(client: SplunkAudit | None) -> None:
    if client is None:
        return
    for name in ("Authorization", "X-Splunk-Form-Key"):
        client.headers.pop(name, None)
    client.opener = None


def validate_output_target(output: Path, private_sources: Sequence[Path]) -> None:
    target = output.resolve(strict=False)
    for source in private_sources:
        if target == source.resolve(strict=False):
            raise ValueError("output path must not overwrite a private input")


def build_config(args: argparse.Namespace) -> CollectorConfig:
    identifier_fields = (
        (args.control_index, "control index"),
        (args.control_field, "control field"),
        (args.scheduled_search_owner, "scheduled-search owner"),
        (args.scheduled_search_app, "scheduled-search app"),
        (args.scheduled_search_name, "scheduled-search name"),
        (args.kv_owner, "KV owner"),
        (args.kv_app, "KV app"),
        (args.kv_collection, "KV collection"),
        (args.kv_expected_field, "KV expected field"),
        (args.dashboard_owner, "dashboard owner"),
        (args.dashboard_app, "dashboard app"),
        (args.dashboard_view, "dashboard view"),
    )
    for value, label in identifier_fields:
        validate_identifier(value, label)
    custom_apps = tuple(args.custom_app or [DEFAULT_APP])
    for app in custom_apps:
        validate_identifier(app, "custom app")
    return CollectorConfig(
        phase=args.phase,
        transport=args.transport,
        username=args.username,
        custom_apps=custom_apps,
        scheduled_search_owner=args.scheduled_search_owner,
        scheduled_search_app=args.scheduled_search_app,
        scheduled_search_name=args.scheduled_search_name,
        scheduler_lookback_minutes=args.scheduler_lookback_minutes,
        control_index=args.control_index,
        control_field=args.control_field,
        control_event_id=validate_reference_token(args.control_event_id, "control event id"),
        freshness_sla_seconds=args.freshness_sla_seconds,
        kv_owner=args.kv_owner,
        kv_app=args.kv_app,
        kv_collection=args.kv_collection,
        kv_checkpoint_key=validate_reference_token(args.kv_checkpoint_key, "KV checkpoint key"),
        kv_expected_field=args.kv_expected_field,
        kv_expected_value=validate_secret_reference(args.kv_expected_value, "KV expected value"),
        dashboard_owner=args.dashboard_owner,
        dashboard_app=args.dashboard_app,
        dashboard_view=args.dashboard_view,
        configuration_attestation=args.configuration_attestation,
        configuration_attestation_max_age_seconds=args.configuration_attestation_max_age_seconds,
        health_lookback_minutes=args.health_lookback_minutes,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=tuple(PHASE_VERSIONS), required=True)
    parser.add_argument("--uri", required=True, help="HTTPS Splunk origin; never persisted")
    parser.add_argument("--transport", choices=("management", "web"), default="management")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--ca-bundle", type=Path, required=True)
    parser.add_argument(
        "--connect-ip",
        help=(
            "optional strict IP literal used only for an ephemeral socket resolver pin; "
            "the HTTPS hostname remains the TLS/SAN identity and the IP is never persisted"
        ),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--custom-app", action="append")
    parser.add_argument("--scheduled-search-owner", default="nobody")
    parser.add_argument("--scheduled-search-app", default=DEFAULT_APP)
    parser.add_argument("--scheduled-search-name", default=DEFAULT_SAVED_SEARCH)
    parser.add_argument("--scheduler-lookback-minutes", type=int, default=10)
    parser.add_argument("--control-index", required=True)
    parser.add_argument("--control-field", default="qualification_control_id")
    parser.add_argument("--control-event-id", required=True)
    parser.add_argument("--freshness-sla-seconds", type=int, default=900)
    parser.add_argument("--kv-owner", default="nobody")
    parser.add_argument("--kv-app", default=DEFAULT_APP)
    parser.add_argument("--kv-collection", default=DEFAULT_COLLECTION)
    parser.add_argument("--kv-checkpoint-key", required=True)
    parser.add_argument("--kv-expected-field", default="expected_value")
    parser.add_argument("--kv-expected-value", required=True)
    parser.add_argument("--dashboard-owner", default="nobody")
    parser.add_argument("--dashboard-app", default=DEFAULT_APP)
    parser.add_argument("--dashboard-view", default=DEFAULT_DASHBOARD)
    parser.add_argument(
        "--configuration-attestation",
        type=Path,
        required=True,
        help=(
            "private JSON attestation with kind, status=passed, exit_code=0, "
            "blocking_error_count=0, and a recent captured_at UTC Z timestamp"
        ),
    )
    parser.add_argument("--configuration-attestation-max-age-seconds", type=int, default=21600)
    parser.add_argument("--health-lookback-minutes", type=int, default=15)
    parser.add_argument("--managed-configuration-manifest", type=Path, required=True)
    parser.add_argument("--custom-apps-manifest", type=Path, required=True)
    parser.add_argument("--saved-searches-export", type=Path, required=True)
    parser.add_argument("--kv-store-export", type=Path, required=True)
    args = parser.parse_args(argv)
    positive_fields = (
        "scheduler_lookback_minutes",
        "freshness_sla_seconds",
        "configuration_attestation_max_age_seconds",
        "health_lookback_minutes",
    )
    for field in positive_fields:
        if getattr(args, field) <= 0:
            parser.error(f"--{field.replace('_', '-')} must be greater than zero")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    password = os.environ.pop("SPLUNK_PASSWORD", "")
    try:
        args = parse_args(argv)
    except SystemExit:
        password = ""
        raise
    try:
        endpoint_hostname = validate_tls_endpoint(args.uri, args.ca_bundle)
        connect_ip = validate_connect_ip(args.connect_ip)
        config = build_config(args)
        private_sources = (
            args.ca_bundle,
            args.configuration_attestation,
            args.managed_configuration_manifest,
            args.custom_apps_manifest,
            args.saved_searches_export,
            args.kv_store_export,
        )
        validate_output_target(args.output, private_sources)
        hashes = hash_inputs(
            {
                "managed_configuration_manifest_sha256": args.managed_configuration_manifest,
                "custom_apps_manifest_sha256": args.custom_apps_manifest,
                "saved_searches_export_sha256": args.saved_searches_export,
                "kv_store_export_sha256": args.kv_store_export,
            }
        )
    except (OSError, ValueError) as error:
        password = ""
        print(f"ERROR: collection preflight failed: {error}", file=sys.stderr)
        return 2

    if not password:
        password = getpass.getpass(f"Splunk password for {args.username}: ")
    client: SplunkAudit | None = None
    connection_error = False
    try:
        with pinned_resolver(endpoint_hostname, connect_ip):
            client = SplunkAudit(
                args.uri,
                args.username,
                password,
                transport=args.transport,
                verify_tls=True,
                ca_bundle=str(args.ca_bundle),
            )
            fragment = UpgradePhaseCollector(client, config, hashes).collect()
    except (HTTPError, URLError, TimeoutError, ValueError, IndexError, OSError):
        connection_error = True
        fragment = disconnected_fragment(args.phase, args.transport, hashes)
    finally:
        os.environ.pop("SPLUNK_PASSWORD", None)
        clear_client_credentials(client)
        password = ""

    try:
        write_json_atomic(args.output, fragment)
    except (OSError, ValueError) as error:
        print(f"ERROR: unable to write sanitized phase fragment: {error}", file=sys.stderr)
        return 2

    ready = bool(fragment["collection_control"]["phase_ready"])
    print(f"WROTE: {args.output}")
    print(
        "SUMMARY: "
        f"phase={args.phase} ready={str(ready).lower()} "
        f"smoke_passed={fragment['collection_control']['passed_smoke_tests']}/8"
    )
    return 0 if ready and not connection_error else 1


if __name__ == "__main__":
    raise SystemExit(main())
