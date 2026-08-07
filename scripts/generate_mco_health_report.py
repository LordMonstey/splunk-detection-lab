#!/usr/bin/env python3
"""Generate sanitized JSON and HTML MCO evidence from a live Splunk instance."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import html
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

from audit_splunk_live import SplunkAudit, entries, select


CHECK_STATUSES = {"PASS", "WATCH", "FAIL"}
PUBLIC_INDEX_NAMES = {
    "history",
    "main",
    "notable",
    "os_linux",
    "risk",
    "splunklogger",
    "summary",
    "sysmon",
    "windows",
    "winlab",
}
PUBLIC_QUEUE_NAMES = {
    "aggqueue",
    "auditqueue",
    "fschangemanager_queue",
    "indexqueue",
    "nullqueue",
    "parsingqueue",
    "typingqueue",
}
PRIVATE_IPV4 = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|127(?:\.\d{1,3}){3}|169\.254(?:\.\d{1,3}){2}|"
    r"192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
)
SECRET_ASSIGNMENT = re.compile(
    r"(?i)[\"']?\b(?:password|passwd|pwd|token|secret|authorization|session)\b"
    r"[\"']?[ \t]*[:=][ \t]*[\"']?[^,}\s<]+"
)
SECRET_MATERIAL = re.compile(
    r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\b(?:Bearer|Basic)[ \t]+[A-Za-z0-9_+/=-]{8,}"
)
URI_PATTERN = re.compile(r"(?i)\b(?:https?|splunk|file|ftp)://")
HOSTNAME_PATTERN = re.compile(
    r"(?i)\b(?=[a-z0-9.-]*[a-z])[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){2,}\b"
)


def number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def integer(value: Any) -> int:
    return int(number(value))


def text_status(value: Any) -> str:
    return str(value or "unknown").strip().lower()


def splunk_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def safe_search(client: SplunkAudit, search: str) -> dict[str, Any]:
    try:
        job = client.run_search_job(search)
        return {
            "status": "success",
            "metrics": select(
                job.get("metrics", {}),
                ("dispatchState", "runDuration", "scanCount", "resultCount"),
            ),
            "results": job.get("results", []),
        }
    except (HTTPError, URLError, TimeoutError, ValueError) as error:
        return {"status": "failed", "error_type": type(error).__name__}


def classify_health(server_health: Any, splunkd_health: Any) -> tuple[str, str]:
    server = text_status(server_health)
    splunkd = text_status(splunkd_health)
    observed = {server, splunkd}
    if observed.intersection({"red", "failed", "critical", "error"}):
        status = "FAIL"
    elif observed == {"green"}:
        status = "PASS"
    else:
        status = "WATCH"
    return status, f"Synthèse serveur={server}; service splunkd={splunkd}."


def classify_kv_store(kv_status: Any) -> tuple[str, str]:
    status = text_status(kv_status)
    if status in {"ready", "healthy"}:
        result = "PASS"
    elif status in {"failed", "error", "unavailable", "down"}:
        result = "FAIL"
    else:
        result = "WATCH"
    return result, f"État déclaré={status}."


def classify_license(
    license_state: Any,
    severity_counts: Counter[str],
    message_query_status: str = "success",
) -> tuple[str, str]:
    state = str(license_state or "unknown").strip().upper()
    critical = severity_counts.get("ERROR", 0) + severity_counts.get("FATAL", 0)
    warnings = severity_counts.get("WARN", 0) + severity_counts.get("WARNING", 0)
    if state != "OK" or critical:
        status = "FAIL"
    elif warnings or message_query_status != "success":
        status = "WATCH"
    else:
        status = "PASS"
    summary = (
        f"État={state}; avertissements={warnings}; critiques={critical}; "
        f"lecture des messages={message_query_status}."
    )
    return status, summary


def normalize_scheduler(result: dict[str, Any]) -> dict[str, int]:
    row = result.get("results", [{}])[0] if result.get("results") else {}
    normalized = {
        "log_events": integer(row.get("log_events")),
        "executions": integer(row.get("executions")),
        "success": integer(row.get("success")),
        "skipped": integer(row.get("skipped")),
        "failed": integer(row.get("failed")),
        "other_status": integer(row.get("other_status")),
        "events_without_status": integer(row.get("events_without_status")),
    }
    return normalized


def classify_scheduler(
    query_status: str,
    scheduler: dict[str, int],
) -> tuple[str, str]:
    executions = scheduler.get("executions", 0)
    success = scheduler.get("success", 0)
    skipped = scheduler.get("skipped", 0)
    failed = scheduler.get("failed", 0)
    other = scheduler.get("other_status", 0)
    without_status = scheduler.get("events_without_status", 0)
    accounted = success + skipped + failed + other
    if query_status != "success" or failed:
        status = "FAIL"
    elif skipped or other or executions == 0 or accounted != executions:
        status = "WATCH"
    else:
        status = "PASS"
    summary = (
        f"Exécutions statusées={executions}; succès={success}; "
        f"sautées={skipped}; échecs={failed}; autres statuts={other}; "
        f"comptabilisées={accounted}; lignes de log sans statut={without_status} "
        "(hors exécutions)."
    )
    return status, summary


def classify_queue_health(
    query_status: str,
    observed_rows: int,
    maximum_fill_percent: float,
) -> tuple[str, str]:
    if query_status != "success":
        status = "FAIL"
    elif observed_rows == 0:
        status = "WATCH"
    elif maximum_fill_percent >= 90:
        status = "FAIL"
    elif maximum_fill_percent >= 70:
        status = "WATCH"
    else:
        status = "PASS"
    summary = (
        f"Files observées={observed_rows}; remplissage maximal="
        f"{maximum_fill_percent:.2f}%."
    )
    return status, summary


def classify_index_capacity(
    observed_indexes: int,
    maximum_fill_percent: float,
    unknown_limits: int,
) -> tuple[str, str]:
    if observed_indexes == 0:
        status = "FAIL"
    elif maximum_fill_percent >= 90:
        status = "FAIL"
    elif maximum_fill_percent >= 70 or unknown_limits:
        status = "WATCH"
    else:
        status = "PASS"
    summary = (
        f"Indexes observés={observed_indexes}; occupation maximale="
        f"{maximum_fill_percent:.2f}%; limites inconnues={unknown_limits}."
    )
    return status, summary


def classify_license_coverage(
    query_status: str,
    observed_days: int,
) -> tuple[str, str]:
    if query_status != "success":
        status = "WATCH"
        summary = "Fenêtre de télémétrie licence non mesurable."
    elif observed_days < 7:
        status = "WATCH"
        summary = (
            f"Jours avec télémétrie licence={observed_days}; "
            "fenêtre trop courte pour une tendance robuste."
        )
    else:
        status = "PASS"
        summary = f"Jours avec télémétrie licence={observed_days}."
    return status, summary


def overall_status(checks: list[dict[str, Any]]) -> str:
    statuses = {str(check.get("status", "")) for check in checks}
    invalid = statuses.difference(CHECK_STATUSES)
    if invalid:
        raise ValueError(f"invalid check statuses: {sorted(invalid)}")
    if "FAIL" in statuses:
        return "FAIL"
    if "WATCH" in statuses:
        return "WATCH"
    return "PASS"


def public_index_label(index_name: str, custom_number: int) -> str:
    if index_name in PUBLIC_INDEX_NAMES:
        return index_name
    return f"custom-index-{custom_number:02d}"


def public_queue_label(queue_name: str, custom_number: int) -> str:
    if queue_name in PUBLIC_QUEUE_NAMES:
        return queue_name
    return f"custom-queue-{custom_number:02d}"


def load_capacity_context(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    observed_days = integer(payload.get("observations", {}).get("license_usage_days"))
    if observed_days < 0 or observed_days > 366:
        raise ValueError("capacity evidence contains an invalid license observation window")
    return {
        "license_usage_days": observed_days,
        "fitness": "illustrative_only" if observed_days < 30 else "trend_candidate",
        "relationship_to_live_collection": "separate_lab_evidence",
    }


def scan_public_text(value: str) -> list[str]:
    findings: list[str] = []
    if PRIVATE_IPV4.search(value):
        findings.append("private IPv4 address")
    if SECRET_ASSIGNMENT.search(value):
        findings.append("secret-like assignment")
    if SECRET_MATERIAL.search(value):
        findings.append("credential or private-key material")
    if URI_PATTERN.search(value):
        findings.append("URI or endpoint")
    if HOSTNAME_PATTERN.search(value):
        findings.append("fully qualified host name")
    for forbidden in ("serverName", "management_uri", "search SID", "raw_event"):
        if forbidden.lower() in value.lower():
            findings.append(f"forbidden field or phrase: {forbidden}")
    return sorted(set(findings))


def scan_public_report(report: dict[str, Any], rendered_html: str) -> list[str]:
    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
    findings = scan_public_text(serialized)
    findings.extend(scan_public_text(rendered_html))
    if "Ã" in serialized or "Ã" in rendered_html or "�" in serialized or "�" in rendered_html:
        findings.append("mojibake marker")
    return sorted(set(findings))


def render_html(report: dict[str, Any], json_sha256: str) -> str:
    status = str(report["overall_status"])
    status_class = {"PASS": "ok", "WATCH": "warn", "FAIL": "bad"}[status]
    cards = []
    for check in report["checks"]:
        check_status = str(check["status"])
        check_class = {"PASS": "ok", "WATCH": "warn", "FAIL": "bad"}[
            check_status
        ]
        cards.append(
            "<article class='check'>"
            f"<div class='check-top'><span>{html.escape(str(check['label']))}</span>"
            f"<b class='{check_class}'>{html.escape(check_status)}</b></div>"
            f"<p>{html.escape(str(check['summary']))}</p>"
            "</article>"
        )

    indexes = "".join(
        "<tr>"
        f"<td>{html.escape(str(row['index']))}</td>"
        f"<td>{number(row['current_db_size_mb']):.1f} MB</td>"
        f"<td>{number(row['configured_max_size_mb']):.0f} MB</td>"
        f"<td>{number(row['fill_percent']):.2f}%</td>"
        f"<td>{number(row['retention_days']):.0f} j</td>"
        "</tr>"
        for row in report["index_capacity"]
    ) or "<tr><td colspan='5'>Aucun index public observé.</td></tr>"

    queue_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(row.get('name', 'unknown')))}</td>"
        f"<td>{number(row.get('latest_fill_pct')):.2f}</td>"
        f"<td>{number(row.get('max_fill_pct')):.2f}</td>"
        "</tr>"
        for row in report["queues"]["top_queues"]
    ) or "<tr><td colspan='3'>Aucune mesure de queue dans la fenêtre.</td></tr>"

    scheduler = report["scheduler"]
    limitations = "".join(
        f"<li>{html.escape(str(item))}</li>" for item in report["limitations"]
    )
    generated = html.escape(str(report["generated_at"]))
    version = html.escape(str(report["environment"].get("version", "unknown")))
    build = html.escape(str(report["environment"].get("build", "unknown")))
    verdict = html.escape(str(report["verdict"]["summary"]))

    return f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <meta name="referrer" content="no-referrer">
  <title>Rapport MCO Splunk Enterprise</title>
  <style>
    :root{{--bg:#101317;--panel:#1b2026;--line:#343c45;--text:#f4f6f8;--muted:#9ba8b4;--green:#65a637;--amber:#f0b429;--red:#df5b5b}}
    *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Segoe UI,Arial,sans-serif}}
    main{{max-width:1180px;margin:auto;padding:32px}} header{{display:flex;justify-content:space-between;gap:24px;align-items:end;border-bottom:1px solid var(--line);padding-bottom:22px}}
    .eyebrow{{color:var(--green);font-weight:700;letter-spacing:.14em;text-transform:uppercase}} h1{{font-size:34px;margin:5px 0 0}} .stamp{{text-align:right;color:var(--muted)}}
    .hero{{display:grid;grid-template-columns:1.2fr repeat(3,1fr);gap:12px;margin:24px 0}} .metric,.check,section{{background:var(--panel);border:1px solid var(--line);border-radius:8px}}
    .metric{{padding:18px}} .metric b{{display:block;font-size:25px;margin-top:4px}} .metric span{{color:var(--muted)}} .overall{{border-left:4px solid currentColor}}
    .verdict{{margin:0 0 18px;color:var(--muted)}} .checks{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}} .check{{padding:16px}} .check-top{{display:flex;justify-content:space-between;gap:12px}} .check p{{color:var(--muted);margin:10px 0 0}}
    .ok{{color:var(--green)}} .warn{{color:var(--amber)}} .bad{{color:var(--red)}} section{{padding:20px;margin-top:18px}} h2{{font-size:17px;margin:0 0 14px}}
    table{{width:100%;border-collapse:collapse}} th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line)}} th{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}}
    li{{margin:7px 0}} footer{{color:var(--muted);font-size:12px;margin-top:20px}} code{{color:#d6e7cb;overflow-wrap:anywhere}}
    @media(max-width:800px){{main{{padding:18px}}header{{display:block}}.stamp{{text-align:left;margin-top:12px}}.hero,.checks{{grid-template-columns:1fr}}}}
  </style>
</head>
<body><main>
  <header><div><div class="eyebrow">Splunk Enterprise - MCO</div><h1>État de santé opérationnel</h1></div><div class="stamp">Collecte UTC<br>{generated}</div></header>
  <div class="hero">
    <div class="metric overall {status_class}"><span>Verdict</span><b>{html.escape(status)}</b></div>
    <div class="metric"><span>Version</span><b>{version}</b></div>
    <div class="metric"><span>Build</span><b>{build[:12]}</b></div>
    <div class="metric"><span>Exécutions statusées 24 h</span><b>{integer(scheduler.get('executions'))}</b></div>
  </div>
  <p class="verdict">{verdict}</p>
  <div class="checks">{''.join(cards)}</div>
  <section><h2>Scheduler, fenêtre 24 heures</h2><table><thead><tr><th>Lignes de log</th><th>Exécutions statusées</th><th>Succès</th><th>Sautées</th><th>Échecs</th><th>Autres</th><th>Sans champ status</th></tr></thead><tbody><tr><td>{integer(scheduler.get('log_events'))}</td><td>{integer(scheduler.get('executions'))}</td><td>{integer(scheduler.get('success'))}</td><td>{integer(scheduler.get('skipped'))}</td><td>{integer(scheduler.get('failed'))}</td><td>{integer(scheduler.get('other_status'))}</td><td>{integer(scheduler.get('events_without_status'))}</td></tr></tbody></table><p class="verdict">Les lignes sans champ status restent visibles, mais ne sont ni comptées comme exécutions ni assimilées à des recherches sautées.</p></section>
  <section><h2>Capacité des indexes publics</h2><table><thead><tr><th>Index</th><th>Occupé</th><th>Maximum</th><th>Taux</th><th>Rétention</th></tr></thead><tbody>{indexes}</tbody></table></section>
  <section><h2>Files d'attente, fenêtre 15 minutes</h2><table><thead><tr><th>Queue</th><th>Dernier remplissage (%)</th><th>Maximum (%)</th></tr></thead><tbody>{queue_rows}</tbody></table></section>
  <section><h2>Frontières de preuve</h2><ul>{limitations}</ul></section>
  <footer>Rapport statique agrégé, sans événement brut, identifiant, endpoint, adresse privée ni nom d'hôte. Empreinte JSON SHA-256 : <code>{json_sha256}</code>.</footer>
</main></body></html>"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", required=True)
    parser.add_argument("--transport", choices=("management", "web"), default="management")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--ca-bundle", type=Path, required=True)
    parser.add_argument("--capacity-evidence", type=Path)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--html-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.uri.lower().startswith("https://"):
        print("ERROR: verified HTTPS is mandatory for public MCO evidence", file=sys.stderr)
        return 2
    if not args.ca_bundle.is_file():
        print("ERROR: CA bundle is missing", file=sys.stderr)
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
            verify_tls=True,
            ca_bundle=str(args.ca_bundle),
        )
        password = ""
        server_entry = entries(client.get("/services/server/info"))[0]
        server_content = server_entry.get("content", {})
        health_content = entries(client.get("/services/server/health/splunkd"))[0].get(
            "content", {}
        )
        app_entries = entries(client.get("/services/apps/local", count=0))
        apps_by_id = {
            str(entry.get("name", "")): entry.get("content", {})
            for entry in app_entries
        }

        def app_active(app_id: str) -> bool:
            return app_id in apps_by_id and not splunk_truthy(
                apps_by_id[app_id].get("disabled")
            )

        server_roles = {str(role) for role in server_content.get("server_roles", [])}
        clustered = bool(server_roles.intersection({"cluster_master", "cluster_manager"}))
        environment = select(
            server_content,
            ("version", "build", "product_type", "licenseState"),
        )
        environment.update(
            {
                "deployment_scope": "cluster_manager" if clustered else "standalone",
                "native_enterprise_security_installed": (
                    "SplunkEnterpriseSecuritySuite" in apps_by_id
                ),
                "native_enterprise_security_active": app_active(
                    "SplunkEnterpriseSecuritySuite"
                ),
                "native_cim_addon_installed": "Splunk_SA_CIM" in apps_by_id,
                "native_cim_addon_active": app_active("Splunk_SA_CIM"),
            }
        )

        raw_indexes: list[dict[str, Any]] = []
        for entry in entries(client.get("/services/data/indexes", count=0)):
            name = str(entry.get("name", ""))
            if not name or name.startswith("_"):
                continue
            content = entry.get("content", {})
            current_mb = number(content.get("currentDBSizeMB"))
            maximum_mb = number(content.get("maxTotalDataSizeMB"))
            raw_indexes.append(
                {
                    "name": name,
                    "current_db_size_mb": current_mb,
                    "configured_max_size_mb": maximum_mb,
                    "fill_percent": round(100 * current_mb / maximum_mb, 3)
                    if maximum_mb
                    else 0.0,
                    "retention_days": round(
                        number(content.get("frozenTimePeriodInSecs")) / 86400, 2
                    ),
                }
            )

        raw_indexes.sort(key=lambda row: str(row["name"]))
        custom_counter = 0
        index_capacity: list[dict[str, Any]] = []
        for row in raw_indexes:
            name = str(row.pop("name"))
            if name not in PUBLIC_INDEX_NAMES:
                custom_counter += 1
            index_capacity.append(
                {"index": public_index_label(name, custom_counter), **row}
            )

        scheduler_query = safe_search(
            client,
            "search index=_internal sourcetype=scheduler earliest=-24h "
            "| eval normalized_status=lower(trim(coalesce(status,\"\"))) "
            "| stats count as log_events "
            "count(eval(normalized_status!=\"\")) as executions "
            "count(eval(normalized_status=\"success\")) as success "
            "count(eval(normalized_status=\"skipped\")) as skipped "
            "count(eval(match(normalized_status,\"error|failed|failure\"))) as failed "
            "count(eval(normalized_status!=\"\" AND normalized_status!=\"success\" "
            "AND normalized_status!=\"skipped\" "
            "AND NOT match(normalized_status,\"error|failed|failure\"))) as other_status "
            "count(eval(normalized_status=\"\")) as events_without_status",
        )
        scheduler = normalize_scheduler(scheduler_query)

        queues_query = safe_search(
            client,
            "search index=_internal source=*metrics.log group=queue earliest=-15m "
            "| eval fill_pct=if(max_size_kb>0,round(100*current_size_kb/max_size_kb,2),0) "
            "| stats latest(fill_pct) as latest_fill_pct max(fill_pct) as max_fill_pct by name "
            "| sort - max_fill_pct | head 20",
        )
        top_queues: list[dict[str, Any]] = []
        custom_queue_counter = 0
        for row in queues_query.get("results", []):
            queue_name = str(row.get("name", "unknown"))
            if queue_name not in PUBLIC_QUEUE_NAMES:
                custom_queue_counter += 1
            top_queues.append(
                {
                    "name": public_queue_label(queue_name, custom_queue_counter),
                    "latest_fill_pct": round(
                        number(row.get("latest_fill_pct")), 2
                    ),
                    "max_fill_pct": round(number(row.get("max_fill_pct")), 2),
                }
            )
        max_queue_fill = max(
            (number(row.get("max_fill_pct")) for row in top_queues),
            default=0.0,
        )

        license_usage_query = safe_search(
            client,
            "search index=_internal source=*license_usage.log type=Usage earliest=-30d "
            "| bin _time span=1d | stats sum(b) as bytes by _time "
            "| stats count as observed_days",
        )
        license_usage_days = integer(
            license_usage_query.get("results", [{}])[0].get("observed_days")
            if license_usage_query.get("results")
            else 0
        )

        license_messages: list[dict[str, Any]] = []
        license_message_query_status = "success"
        try:
            license_messages = entries(client.get("/services/licenser/messages", count=0))
        except (HTTPError, URLError, TimeoutError, ValueError):
            license_message_query_status = "failed"
            license_messages = []
        severity_counts = Counter(
            str(entry.get("content", {}).get("severity", "unknown")).upper()
            for entry in license_messages
        )

        max_index_fill = max(
            (number(row["fill_percent"]) for row in index_capacity),
            default=0.0,
        )
        unknown_index_limits = sum(
            number(row["configured_max_size_mb"]) <= 0 for row in index_capacity
        )

        health_status, health_summary = classify_health(
            server_content.get("health_info"), health_content.get("health")
        )
        kv_status, kv_summary = classify_kv_store(server_content.get("kvStoreStatus"))
        license_status, license_summary = classify_license(
            server_content.get("licenseState"),
            severity_counts,
            license_message_query_status,
        )
        license_coverage_status, license_coverage_summary = classify_license_coverage(
            license_usage_query["status"], license_usage_days
        )
        scheduler_status, scheduler_summary = classify_scheduler(
            scheduler_query["status"], scheduler
        )
        queues_status, queues_summary = classify_queue_health(
            queues_query["status"], len(top_queues), max_queue_fill
        )
        capacity_status, capacity_summary = classify_index_capacity(
            len(index_capacity), max_index_fill, unknown_index_limits
        )

        checks = [
            {
                "id": "splunkd_health",
                "label": "Santé Splunk",
                "status": health_status,
                "summary": health_summary,
            },
            {
                "id": "kv_store",
                "label": "KV Store",
                "status": kv_status,
                "summary": kv_summary,
            },
            {
                "id": "license_state",
                "label": "Licence",
                "status": license_status,
                "summary": license_summary,
            },
            {
                "id": "license_telemetry_window",
                "label": "Historique licence",
                "status": license_coverage_status,
                "summary": license_coverage_summary,
            },
            {
                "id": "scheduler",
                "label": "Scheduler 24 h",
                "status": scheduler_status,
                "summary": scheduler_summary,
            },
            {
                "id": "queues",
                "label": "Queues 15 min",
                "status": queues_status,
                "summary": queues_summary,
            },
            {
                "id": "index_capacity",
                "label": "Capacité indexes",
                "status": capacity_status,
                "summary": capacity_summary,
            },
        ]
        verdict_status = overall_status(checks)
        failing_labels = [
            str(check["label"]) for check in checks if check["status"] == "FAIL"
        ]
        watching_labels = [
            str(check["label"]) for check in checks if check["status"] == "WATCH"
        ]
        if failing_labels:
            verdict_summary = "Échec opérationnel sur : " + ", ".join(failing_labels) + "."
        elif watching_labels:
            verdict_summary = "Points à surveiller : " + ", ".join(watching_labels) + "."
        else:
            verdict_summary = "Tous les contrôles observables sont conformes."

        capacity_context = load_capacity_context(args.capacity_evidence)
        limitations = [
            "Instance standalone : aucun RF/SF, search head cluster, rolling restart ou test de continuité distribué n'est couvert par cette collecte.",
            "Splunk Enterprise Security natif et Splunk_SA_CIM ne sont pas actifs : ce rapport couvre Splunk Enterprise, pas les workflows ES.",
            f"La tendance licence live repose sur {license_usage_days} jour(s) observé(s) dans la fenêtre de 30 jours.",
            "Les métriques sont ponctuelles et ne constituent ni un SLO de production ni une preuve de dimensionnement.",
        ]
        if capacity_context is not None:
            limitations.append(
                "Un modèle de capacité public séparé repose sur "
                f"{capacity_context['license_usage_days']} jour(s) de télémétrie licence et reste illustratif."
            )

        report = {
            "schema_version": 2,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": "sanitized-live-splunk-enterprise-mco-evidence",
            "status_model": {
                "PASS": "contrôle observé et conforme",
                "WATCH": "dégradation, fenêtre insuffisante ou signal incomplet",
                "FAIL": "défaillance, état critique ou contrôle essentiel indisponible",
            },
            "environment": environment,
            "transport": {
                "mode": args.transport,
                "tls_enabled": True,
                "ca_validation": True,
                "hostname_verification": True,
                "csrf_protected_web_session": args.transport == "web",
            },
            "verdict": {
                "status": verdict_status,
                "summary": verdict_summary,
                "failed_checks": len(failing_labels),
                "watch_checks": len(watching_labels),
            },
            "checks": checks,
            "scheduler": {
                "query_status": scheduler_query["status"],
                **scheduler,
                "interpretation": (
                    "Seules les lignes portant un champ status non vide sont "
                    "comptées comme exécutions; les autres restent une catégorie "
                    "de journal distincte et ne sont pas assimilées à des recherches sautées."
                ),
            },
            "queues": {
                "query_status": queues_query["status"],
                "maximum_fill_percent": round(max_queue_fill, 2),
                "top_queues": top_queues,
            },
            "license": {
                "message_severity_counts": dict(sorted(severity_counts.items())),
                "message_query_status": license_message_query_status,
                "usage_query_status": license_usage_query["status"],
                "observed_usage_days": license_usage_days,
                "requested_window_days": 30,
            },
            "index_capacity": sorted(
                index_capacity,
                key=lambda row: number(row["fill_percent"]),
                reverse=True,
            ),
            "capacity_context": capacity_context,
            "limitations": limitations,
            "overall_status": verdict_status,
            "security": {
                "excluded": [
                    "credentials",
                    "tokens",
                    "URI",
                    "host name",
                    "private address",
                    "raw events",
                    "search identifiers",
                ],
                "standalone_html": True,
                "external_assets": False,
                "index_names_allowlisted_or_anonymized": True,
            },
        }
    except (HTTPError, URLError, TimeoutError, ValueError, IndexError, json.JSONDecodeError) as error:
        password = ""
        print(f"ERROR: MCO report failed ({type(error).__name__})", file=sys.stderr)
        return 1
    finally:
        password = ""

    canonical_json = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    html_report = render_html(report, digest)
    security_findings = scan_public_report(report, html_report)
    if security_findings:
        print(
            "ERROR: public MCO evidence rejected: " + ", ".join(security_findings),
            file=sys.stderr,
        )
        return 1

    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(canonical_json, encoding="utf-8", newline="\n")
    args.html_output.parent.mkdir(parents=True, exist_ok=True)
    args.html_output.write_text(html_report, encoding="utf-8", newline="\n")
    print(f"OK: MCO JSON written to {args.json_output}")
    print(f"OK: MCO HTML written to {args.html_output}")
    print(
        f"SUMMARY: status={verdict_status} / checks={len(checks)} / sha256={digest}"
    )
    return 0 if verdict_status != "FAIL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
